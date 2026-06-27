"""Shared pytest fixtures for OpenAI instrumentation and VCR testing."""

from __future__ import annotations

import os
import logging
import importlib
import sys
from collections.abc import Iterator

import pytest
from opentelemetry import trace as otel_trace
from opentelemetry._logs import _internal as otel_logs_internal
from opentelemetry.metrics import _internal as otel_metrics_internal
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


# FortifyRoot retry-attempt (2026-05-17): legacy SDK tests assert exact span names /
# counts (e.g. ``assert span.name == "anthropic.chat"``). FortifyRoot retry-attempt
# emits per-attempt ``fortifyroot.*.retry_attempt`` sibling spans
# under every direct-SDK LLM call. Filter those out of the standard
# ``span_exporter`` fixture so upstream assertions remain valid.
# Retry-attempt tests can read the raw exporter or filter by role
# themselves (e.g. ``_single_span`` in ``tests/openai/test_vcr.py``
# already filters retry_attempt by ``fortifyroot.span.role``).
# Mirrors the same pattern used by the fr-openllmetry-py per-package
# test conftests (added 2026-05-16 + 2026-05-17 for openai and
# anthropic upstream tests respectively).
class _NoFortifyRootSpanExporter(InMemorySpanExporter):
    """Filter spans by ROLE (not by name prefix) so that
    longstanding ``fortifyroot.litellm.safety`` etc. spans which
    upstream tests actually want to see remain visible; only
    FortifyRoot retry-attempt sibling spans are dropped."""

    def get_finished_spans(self):  # type: ignore[override]
        return tuple(
            s for s in super().get_finished_spans()
            if (s.attributes or {}).get("fortifyroot.span.role") != "llm_attempt"
        )
from opentelemetry.util._once import Once

from fortifyroot.ocelle import Instruments, init
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from fortifyroot._vendor.opentelemetry.instrumentation.openai import OpenAIInstrumentor
from fortifyroot._vendor.opentelemetry.instrumentation.openai.shared.config import (
    Config as OpenAIConfig,
)

# Import additional instrumentors for proper test isolation (T5+)
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.anthropic import AnthropicInstrumentor
    from fortifyroot._vendor.opentelemetry.instrumentation.anthropic.config import (
        Config as AnthropicConfig,
    )
except ImportError:
    AnthropicInstrumentor = None
    AnthropicConfig = None
if AnthropicConfig is not None:
    _ANTHROPIC_DEFAULTS = {
        name: getattr(AnthropicConfig, name)
        for name in (
            "enrich_token_usage",
            "exception_logger",
            "get_common_metrics_attributes",
            "upload_base64_image",
            "use_legacy_attributes",
        )
    }
else:
    _ANTHROPIC_DEFAULTS = {}
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.google_generativeai import GoogleGenerativeAiInstrumentor
except ImportError:
    GoogleGenerativeAiInstrumentor = None
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.bedrock import BedrockInstrumentor
except ImportError:
    BedrockInstrumentor = None
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.litellm import LiteLLMInstrumentor
except ImportError:
    LiteLLMInstrumentor = None
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.langchain import LangchainInstrumentor
except ImportError:
    LangchainInstrumentor = None
try:
    from fortifyroot._vendor.opentelemetry.instrumentation.llamaindex import LlamaIndexInstrumentor
except ImportError:
    LlamaIndexInstrumentor = None
from fortifyroot._internal.safety.engine import set_udf_detectors_enabled
from fortifyroot._internal.safety.runtime import shutdown_global_safety_runtime
from fortifyroot._vendor.tracer.sdk.logging.logging import LoggerWrapper
from fortifyroot._vendor.tracer.sdk.logging.logging import (
    is_fortifyroot_logging_handler,
)
from fortifyroot._vendor.tracer.sdk.metrics.metrics import MetricsWrapper
from fortifyroot._vendor.tracer.sdk.tracing.tracing import TracerWrapper


_ENV_PREFIXES = ("FORTIFYROOT_", "TRACELOOP_", "OTEL_")
_LOGGER = logging.getLogger(__name__)


def _is_test_env_key(key: str) -> bool:
    return key.startswith(_ENV_PREFIXES)


def _clear_test_env() -> None:
    for key in list(os.environ.keys()):
        if _is_test_env_key(key):
            os.environ.pop(key, None)


def _reset_singletons() -> None:
    tracer_provider = getattr(otel_trace, "_TRACER_PROVIDER", None)
    if tracer_provider and hasattr(tracer_provider, "shutdown"):
        try:
            tracer_provider.shutdown()
        except Exception:
            pass

    meter_provider = getattr(otel_metrics_internal, "_METER_PROVIDER", None)
    if meter_provider and hasattr(meter_provider, "shutdown"):
        try:
            meter_provider.shutdown()
        except Exception:
            pass

    logger_provider = getattr(otel_logs_internal, "_LOGGER_PROVIDER", None)
    if logger_provider and hasattr(logger_provider, "shutdown"):
        try:
            logger_provider.shutdown()
        except Exception:
            pass

    otel_trace._TRACER_PROVIDER = None
    otel_trace._TRACER_PROVIDER_SET_ONCE = Once()
    otel_metrics_internal._METER_PROVIDER = None
    otel_metrics_internal._METER_PROVIDER_SET_ONCE = Once()
    otel_logs_internal._LOGGER_PROVIDER = None
    otel_logs_internal._LOGGER_PROVIDER_SET_ONCE = Once()

    for instrumentor_cls in (
        OpenAIInstrumentor,
        AnthropicInstrumentor,
        GoogleGenerativeAiInstrumentor,
        BedrockInstrumentor,
        LiteLLMInstrumentor,
        LangchainInstrumentor,
        LlamaIndexInstrumentor,
    ):
        if instrumentor_cls is not None:
            instrumentor = instrumentor_cls()
            try:
                instrumentor.uninstrument()
            except Exception as exc:
                _LOGGER.debug(
                    "uninstrument failed for %s: %s", instrumentor_cls.__name__, exc
                )
            try:
                instrumentor._uninstrument()
            except Exception as exc:
                _LOGGER.debug(
                    "_uninstrument failed for %s: %s", instrumentor_cls.__name__, exc
                )
            # Instrumentor classes are singletons, so this resets the shared
            # instance state returned by future instrumentor_cls() calls.
            instrumentor._is_instrumented_by_opentelemetry = False

    # Anthropic instrumentor monkey-patches methods on these resource modules.
    # Plain uninstrument() does not always restore them when tests run in
    # order, so reload the concrete resources and client imports to drop
    # monkey-patched versions. Safe here because every test reconstructs its
    # instrumentor after the reset.
    for module_name in (
        "anthropic.resources.messages.messages",
        "anthropic.resources.messages",
        "anthropic.resources.completions",
        "anthropic.resources.beta.messages.messages",
        "anthropic._client",
        "anthropic",
    ):
        module = sys.modules.get(module_name)
        if module is not None:
            try:
                importlib.reload(module)
            except Exception:
                pass

    shutdown_global_safety_runtime()
    set_udf_detectors_enabled(False)

    for wrapper_cls in (TracerWrapper, MetricsWrapper, LoggerWrapper):
        if hasattr(wrapper_cls, "instance"):
            delattr(wrapper_cls, "instance")

    TracerWrapper.set_disabled(False)
    TracerWrapper.resource_attributes = {}
    TracerWrapper.enable_content_tracing = True
    TracerWrapper.endpoint = None
    TracerWrapper.headers = {}

    MetricsWrapper.resource_attributes = {}
    MetricsWrapper.endpoint = None
    MetricsWrapper.headers = {}

    LoggerWrapper.resource_attributes = {}
    LoggerWrapper.endpoint = None
    LoggerWrapper.headers = {}

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if is_fortifyroot_logging_handler(handler):
            root_logger.removeHandler(handler)

    OpenAIConfig.enrich_assistant = False
    OpenAIConfig.use_legacy_attributes = True
    if AnthropicConfig is not None:
        for name, value in _ANTHROPIC_DEFAULTS.items():
            setattr(AnthropicConfig, name, value)


@pytest.fixture(autouse=True)
def reset_sdk_state() -> Iterator[None]:
    """Reset all mutable global SDK state before and after each test."""
    original_env = {k: v for k, v in os.environ.items() if _is_test_env_key(k)}
    _clear_test_env()
    _reset_singletons()
    yield
    _clear_test_env()
    os.environ.update(original_env)
    _reset_singletons()


@pytest.fixture
def span_exporter() -> InMemorySpanExporter:
    return _NoFortifyRootSpanExporter()


@pytest.fixture
def init_openai_sdk(span_exporter: InMemorySpanExporter):
    """Initialize FortifyRoot with OpenAI instrumentation and in-memory spans."""

    def _init_openai_sdk(**kwargs):
        # Keep OpenAI tests focused on trace behavior and avoid external FR metric/log export.
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        processor = SimpleSpanProcessor(span_exporter)
        defaults = {
            "app_name": "fortifyroot-test",
            "enabled": True,
            "disable_batch": True,
            "processors": [processor],
            "instruments": {Instruments.OPENAI},
        }
        defaults.update(kwargs)
        apply_env_var_mapping()
        init(**defaults)
        return span_exporter

    return _init_openai_sdk


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": "tests/openai/cassettes",
        "filter_headers": [
            "authorization",
            "x-api-key",
            "openai-organization",
        ],
        "filter_query_parameters": ["api_key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }
