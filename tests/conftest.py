"""Shared pytest fixtures for OpenAI instrumentation and VCR testing."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from opentelemetry import trace as otel_trace
from opentelemetry._logs import _internal as otel_logs_internal
from opentelemetry.metrics import _internal as otel_metrics_internal
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.util._once import Once

from fortifyroot import Instruments, init
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from fortifyroot._vendor.opentelemetry.instrumentation.openai import OpenAIInstrumentor
from fortifyroot._vendor.opentelemetry.instrumentation.openai.shared.config import (
    Config as OpenAIConfig,
)
from fortifyroot._vendor.traceloop.sdk.logging.logging import LoggerWrapper
from fortifyroot._vendor.traceloop.sdk.metrics.metrics import MetricsWrapper
from fortifyroot._vendor.traceloop.sdk.tracing.tracing import TracerWrapper


_ENV_PREFIXES = ("FORTIFYROOT_", "TRACELOOP_", "OTEL_")


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

    try:
        OpenAIInstrumentor().uninstrument()
    except Exception:
        pass

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

    OpenAIConfig.enrich_assistant = False
    OpenAIConfig.use_legacy_attributes = True


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
    return InMemorySpanExporter()


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
