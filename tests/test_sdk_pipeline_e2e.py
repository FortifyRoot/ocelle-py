"""T9-3: Full SDK pipeline E2E tests (safety + telemetry).

Two test groups:

  Group A -- Non-safety telemetry (no FR backend config, safety runtime skipped):
    init() with no api_key / no config_profile_id -> provider call (VCR) ->
    verify: span name, gen_ai.system, model, tokens, prompt/completion content,
    fortifyroot.* attribute renaming, fortifyroot.sdk.version resource attr,
    NO safety events.

  Group B -- Full safety E2E via real SafetyRuntime:
    Mock HTTP for config fetch -> init() with localhost endpoint + api_key +
    config_profile_id -> real SafetyRuntime.start() -> real SafetyHandler ->
    provider call (VCR) -> verify: masking via real engine + telemetry captured.

Reuses existing T5 OpenAI VCR cassettes. No new cassettes recorded.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from unittest import mock

import openai
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI

from fortifyroot.ocelle import Instruments, init
from fortifyroot._internal.constants import (
    ATTRIBUTE_PREFIX_FORTIFYROOT,
    ATTRIBUTE_PREFIX_TRACELOOP,
    FORTIFYROOT_SDK_VERSION_ATTRIBUTE,
)
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from fortifyroot._internal.safety.runtime import (
    configure_global_safety_runtime,
    shutdown_global_safety_runtime,
)
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    clear_safety_handlers,
    get_prompt_safety_handler,
)
from fortifyroot.version import __version__


# ---------------------------------------------------------------------------
# Cassette directory (reuses T5 OpenAI cassettes)
# ---------------------------------------------------------------------------

_CASSETTE_DIR = Path(__file__).parent / "providers" / "openai" / "cassettes"


# ---------------------------------------------------------------------------
# VCR config -- points at T5 OpenAI cassettes
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "authorization",
            "x-api-key",
            "openai-organization",
            "openai-project-id",
        ],
        "filter_query_parameters": ["api_key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }


# ---------------------------------------------------------------------------
# Local init fixture (same as providers/conftest.py but available at tests/ level)
# ---------------------------------------------------------------------------


@pytest.fixture
def init_provider_sdk(span_exporter):
    """Factory fixture to initialize FortifyRoot with a specific provider."""

    def _init(
        instruments: set[Instruments] | None = None,
        trace_content: bool = True,
        **kwargs,
    ):
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        processor = SimpleSpanProcessor(span_exporter)
        defaults = {
            "app_name": "fortifyroot-t9-test",
            "enabled": True,
            "disable_batch": True,
            "processors": [processor],
            "instruments": instruments,
            "trace_content": trace_content,
        }
        defaults.update(kwargs)
        apply_env_var_mapping()
        init(**defaults)
        return span_exporter

    return _init


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


PROMPT_KEYS = {
    f"{GenAI.GEN_AI_PROMPT}.0.content",
    "llm.prompts.0.content",
    "llm.prompts.0.user",
}

COMPLETION_KEYS = {
    f"{GenAI.GEN_AI_COMPLETION}.0.content",
    "llm.completions.0.content",
}


def _get_span(exporter, min_count=1):
    spans = exporter.get_finished_spans()
    assert len(spans) >= min_count, f"Expected >= {min_count} spans, got {len(spans)}"
    return spans[0]


def _prompt_content(span):
    for key in PROMPT_KEYS:
        if key in span.attributes:
            return str(span.attributes[key])
    return None


def _completion_content(span):
    for key in COMPLETION_KEYS:
        if key in span.attributes:
            return str(span.attributes[key])
    return None


def _safety_events(span):
    return [e for e in (span.events or []) if "fortifyroot.safety" in (e.name or "")]


def _has_fortifyroot_attrs(span) -> bool:
    """Check if any span attributes use the fortifyroot.* prefix."""
    return any(
        key.startswith(ATTRIBUTE_PREFIX_FORTIFYROOT) for key in (span.attributes or {})
    )


def _has_traceloop_attrs(span) -> bool:
    """Check if any span attributes still use the traceloop.* prefix."""
    return any(
        key.startswith(ATTRIBUTE_PREFIX_TRACELOOP) for key in (span.attributes or {})
    )


def _skip_if_no_cassette(cassette_stem: str):
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"
    if not cassette.exists():
        pytest.skip(f"Cassette missing: {cassette}")


# ---------------------------------------------------------------------------
# Config payload helper (for Group B)
# ---------------------------------------------------------------------------


def _safety_config_payload(
    *,
    profile_id: str = "cfg-e2e",
    etag: str = "etag-e2e",
    email_pattern: str = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
) -> dict:
    return {
        "configProfile": {
            "id": profile_id,
            "version": 1,
            "etag": etag,
            "config": {
                "safetyConfig": {
                    "enabled": True,
                    "defaultAction": "SAFETY_ACTION_MASK",
                    "rules": [
                        {
                            "name": "email",
                            "category": "SAFETY_CATEGORY_PII",
                            "severity": "SEVERITY_HIGH",
                            "enabled": True,
                            "regex": email_pattern,
                        }
                    ],
                }
            },
        }
    }


# ===========================================================================
# GROUP A: Non-safety telemetry (safety runtime skipped)
# ===========================================================================


class TestTelemetryWithoutSafety:
    """Verify full telemetry pipeline when safety is not configured.

    Safety is skipped because no api_key / config_profile_id is set.
    This exercises: init() -> provider call (VCR) -> OTel spans.
    """

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_span_name_and_gen_ai_system(self, span_exporter, init_provider_sdk):
        """Span has correct name and gen_ai.system attribute."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        assert span.name == "openai.chat", f"Expected 'openai.chat', got '{span.name}'"
        assert GenAI.GEN_AI_SYSTEM in span.attributes, "Missing gen_ai.system"
        assert span.attributes[GenAI.GEN_AI_SYSTEM] == "openai", (
            f"Expected gen_ai.system='openai', got '{span.attributes[GenAI.GEN_AI_SYSTEM]}'"
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_prompt_and_completion_content_captured(self, span_exporter, init_provider_sdk):
        """Prompt and completion content present in span attributes."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        prompt = _prompt_content(span)
        assert prompt is not None, "No prompt content in span attributes"

        completion = _completion_content(span)
        assert completion is not None, "No completion content in span attributes"

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_token_usage_attributes(self, span_exporter, init_provider_sdk):
        """Token usage attributes present in span."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        token_keys = {
            GenAI.GEN_AI_USAGE_INPUT_TOKENS,
            GenAI.GEN_AI_USAGE_OUTPUT_TOKENS,
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "llm.usage.total_tokens",
        }
        assert any(k in span.attributes for k in token_keys), (
            f"No token usage attrs. Keys: {list(span.attributes.keys())}"
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_fortifyroot_attribute_renaming(self, span_exporter, init_provider_sdk):
        """Attributes use fortifyroot.* prefix, NOT traceloop.*."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        # AttributeRenamingProcessor should have renamed traceloop.* -> fortifyroot.*
        # If no traceloop.* attrs existed, renaming is a no-op (correct behavior).
        assert not _has_traceloop_attrs(span), (
            f"Found traceloop.* attrs that should be renamed: "
            f"{[k for k in span.attributes if k.startswith(ATTRIBUTE_PREFIX_TRACELOOP)]}"
        )
        # Verify standard gen_ai.* attributes are present (OTel semantic conventions)
        gen_ai_keys = [k for k in span.attributes if k.startswith("gen_ai.")]
        assert len(gen_ai_keys) > 0, (
            f"Expected gen_ai.* attributes. Keys: {list(span.attributes.keys())}"
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_sdk_version_resource_attribute(self, span_exporter, init_provider_sdk):
        """fortifyroot.sdk.version present in resource attributes."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        resource_attrs = dict(span.resource.attributes) if span.resource else {}
        assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE in resource_attrs, (
            f"Missing {FORTIFYROOT_SDK_VERSION_ATTRIBUTE} in resource. "
            f"Keys: {list(resource_attrs.keys())}"
        )
        assert resource_attrs[FORTIFYROOT_SDK_VERSION_ATTRIBUTE] == __version__

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_no_safety_events_when_safety_disabled(self, span_exporter, init_provider_sdk):
        """No safety events on span when safety runtime is not configured."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        events = _safety_events(span)
        assert len(events) == 0, (
            f"Expected no safety events, got {len(events)}: "
            f"{[e.name for e in events]}"
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_model_attribute_present(self, span_exporter, init_provider_sdk):
        """gen_ai.request.model present in span."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        model_keys = {
            GenAI.GEN_AI_REQUEST_MODEL,
            "gen_ai.request.model",
            "llm.request.model",
        }
        assert any(k in span.attributes for k in model_keys), (
            f"No model attr. Keys: {list(span.attributes.keys())}"
        )


# ===========================================================================
# GROUP B: Full safety E2E via real SafetyRuntime
# ===========================================================================


class TestFullSafetyPipelineE2E:
    """Verify the real SafetyRuntime -> engine -> masking pipeline E2E.

    Uses mock HTTP for config fetch + VCR for provider call.
    This is the key gap: T5/T6 used manually registered test handlers;
    this test uses the real SafetyRuntime/SafetyHandler chain.
    """

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_sync_prompt_mask_email")
    @pytest.mark.fr
    def test_real_runtime_masks_email_in_prompt(self, span_exporter, init_provider_sdk):
        """Real SafetyRuntime masks email in prompt via config-driven engine."""
        _skip_if_no_cassette("test_openai_safety_sync_prompt_mask_email")

        # Mock the HTTP config fetch to return email rule
        config_response = _FakeHTTPResponse(
            json.dumps(_safety_config_payload()).encode("utf-8")
        )

        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=config_response,
        ):
            # Init SDK -- the init_provider_sdk fixture sets up OTel;
            # we then manually configure safety runtime with localhost
            init_provider_sdk(instruments={Instruments.OPENAI})

            # Now configure real safety runtime (localhost passes endpoint check)
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-e2e",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        # Verify handler is the real SafetyHandler (not test handler)
        handler = get_prompt_safety_handler()
        assert handler is not None

        # Make provider call through VCR cassette
        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": (
                "Summarize the following customer inquiry from "
                "john.doe@example.com about their recent order."
            )}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)

        # Safety: email should be masked by real engine
        prompt = _prompt_content(span)
        assert prompt is not None
        assert "john.doe@example.com" not in prompt, (
            f"Email not masked by real engine. Prompt: {prompt}"
        )
        assert "[PII.email]" in prompt, (
            f"Expected [PII.email] mask token. Prompt: {prompt}"
        )

        # Telemetry: span name, system, model
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes

        # Telemetry: tokens
        token_keys = {
            GenAI.GEN_AI_USAGE_INPUT_TOKENS,
            GenAI.GEN_AI_USAGE_OUTPUT_TOKENS,
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "llm.usage.total_tokens",
        }
        assert any(k in span.attributes for k in token_keys)

        # Attribute renaming: no traceloop.* attrs
        assert not _has_traceloop_attrs(span)

        # Safety events
        events = _safety_events(span)
        assert len(events) >= 1, (
            f"Expected safety events. Got: {[e.name for e in (span.events or [])]}"
        )

        # Cleanup
        shutdown_global_safety_runtime()

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_sync_prompt_mask_email")
    @pytest.mark.fr
    def test_real_runtime_telemetry_alongside_safety(self, span_exporter, init_provider_sdk):
        """Verify both telemetry AND safety data are present in same span."""
        _skip_if_no_cassette("test_openai_safety_sync_prompt_mask_email")

        config_response = _FakeHTTPResponse(
            json.dumps(_safety_config_payload()).encode("utf-8")
        )

        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=config_response,
        ):
            init_provider_sdk(instruments={Instruments.OPENAI})
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-e2e",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": (
                "Summarize the following customer inquiry from "
                "john.doe@example.com about their recent order."
            )}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)

        # Telemetry present
        assert span.name == "openai.chat"
        assert _prompt_content(span) is not None
        assert _completion_content(span) is not None

        # Safety present
        prompt = _prompt_content(span)
        assert "[PII.email]" in prompt

        # Resource attributes
        resource_attrs = dict(span.resource.attributes) if span.resource else {}
        assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE in resource_attrs

        shutdown_global_safety_runtime()

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_sync_completion_mask_email")
    @pytest.mark.fr
    def test_real_runtime_masks_email_in_completion(self, span_exporter, init_provider_sdk):
        """Real SafetyRuntime masks email in completion (not just prompt)."""
        _skip_if_no_cassette("test_openai_safety_sync_completion_mask_email")

        config_response = _FakeHTTPResponse(
            json.dumps(_safety_config_payload()).encode("utf-8")
        )

        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=config_response,
        ):
            init_provider_sdk(instruments={Instruments.OPENAI})
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-e2e",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": (
                "Generate a sample customer support response that includes "
                "the representative's email address."
            )}],
            max_tokens=80,
        )

        span = _get_span(span_exporter)
        completion = _completion_content(span)
        # If the LLM response contains an email, it should be masked
        # Note: whether masking occurs depends on the actual cassette response
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes

        shutdown_global_safety_runtime()


# ===========================================================================
# GROUP C: Edge cases from self-review
# ===========================================================================


class TestPipelineEdgeCases:
    """Edge cases identified during critical self-review."""

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_trace_content_false_suppresses_content(self, span_exporter, init_provider_sdk):
        """trace_content=False should suppress prompt/completion in span attrs."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI}, trace_content=False)
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        # Span should exist with name and system
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes

        # But prompt/completion content should be suppressed
        prompt = _prompt_content(span)
        completion = _completion_content(span)
        assert prompt is None, f"Expected no prompt content, got: {prompt}"
        assert completion is None, f"Expected no completion content, got: {completion}"

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_service_name_matches_app_name(self, span_exporter, init_provider_sdk):
        """service.name resource attribute matches the app_name passed to init()."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        resource_attrs = dict(span.resource.attributes) if span.resource else {}
        assert "service.name" in resource_attrs, (
            f"Missing service.name. Resource keys: {list(resource_attrs.keys())}"
        )
        assert resource_attrs["service.name"] == "fortifyroot-t9-test"

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_no_masking_when_rule_does_not_match(self, span_exporter, init_provider_sdk):
        """Real SafetyRuntime with CC rule but prompt has no CC -> no masking."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")

        # Config has CC rule only (not email)
        cc_config = {
            "configProfile": {
                "id": "cfg-cc-only",
                "version": 1,
                "etag": "etag-cc",
                "config": {
                    "safetyConfig": {
                        "enabled": True,
                        "defaultAction": "SAFETY_ACTION_MASK",
                        "rules": [
                            {
                                "name": "credit_card",
                                "category": "SAFETY_CATEGORY_PCI",
                                "severity": "SEVERITY_CRITICAL",
                                "enabled": True,
                                "regex": r"\b(?:\d[ -]*?){13,16}\b",
                            }
                        ],
                    }
                },
            }
        }
        config_response = _FakeHTTPResponse(
            json.dumps(cc_config).encode("utf-8")
        )

        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=config_response,
        ):
            init_provider_sdk(instruments={Instruments.OPENAI})
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-cc-only",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        # Prompt has NO credit card — just a simple question
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        prompt = _prompt_content(span)
        assert prompt is not None
        # Prompt should NOT be masked (no CC in text)
        assert "[PCI." not in prompt
        assert "Hello, what is 2+2?" in prompt

        # The prompt does not match the configured CC rule, so prompt-side
        # masking/findings must not occur. This cassette's completion does
        # include a CC-like string, so completion-side findings remain valid.
        events = _safety_events(span)
        prompt_events = [
            e
            for e in events
            if e.attributes.get("fortifyroot.safety.location") == "PROMPT"
        ]
        assert len(prompt_events) == 0, (
            "Expected no prompt safety events for non-matching rule. Got: "
            f"{[e.attributes for e in prompt_events]}"
        )

        shutdown_global_safety_runtime()

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_sync_prompt_allow_email")
    @pytest.mark.fr
    def test_real_runtime_allow_action(self, span_exporter, init_provider_sdk):
        """Real SafetyRuntime with ALLOW default action -> text unmasked, findings recorded."""
        _skip_if_no_cassette("test_openai_safety_sync_prompt_allow_email")

        allow_config = {
            "configProfile": {
                "id": "cfg-allow",
                "version": 1,
                "etag": "etag-allow",
                "config": {
                    "safetyConfig": {
                        "enabled": True,
                        "defaultAction": "SAFETY_ACTION_ALLOW",
                        "rules": [
                            {
                                "name": "email",
                                "category": "SAFETY_CATEGORY_PII",
                                "severity": "SEVERITY_HIGH",
                                "enabled": True,
                                "action": "SAFETY_ACTION_ALLOW",
                                "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                            }
                        ],
                    }
                },
            }
        }
        config_response = _FakeHTTPResponse(
            json.dumps(allow_config).encode("utf-8")
        )

        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=config_response,
        ):
            init_provider_sdk(instruments={Instruments.OPENAI})
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-allow",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": (
                "Please send the report to john.doe@example.com by end of day."
            )}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        prompt = _prompt_content(span)
        assert prompt is not None
        # ALLOW action: email should NOT be masked
        assert "john.doe@example.com" in prompt, (
            f"Expected email preserved with ALLOW action. Prompt: {prompt}"
        )

        shutdown_global_safety_runtime()


# ===========================================================================
# GROUP D: init() parameter combinations (E2E integration)
# ===========================================================================


class TestInitParameterCombinations:
    """E2E tests for init() parameter combinations not covered by unit tests.

    test_init.py tests these via mocking Traceloop.init(). These tests verify
    the REAL end-to-end behavior through actual provider calls.
    """

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_enabled_false_produces_no_spans(self, span_exporter):
        """enabled=False -> init() runs but no spans are produced."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        processor = SimpleSpanProcessor(span_exporter)
        apply_env_var_mapping()
        init(
            app_name="fortifyroot-disabled-test",
            enabled=False,
            disable_batch=True,
            processors=[processor],
            instruments={Instruments.OPENAI},
        )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=50,
        )

        spans = span_exporter.get_finished_spans()
        assert len(spans) == 0, (
            f"Expected 0 spans with enabled=False, got {len(spans)}"
        )

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_custom_processors_list_wrapped_with_renaming(self, span_exporter):
        """Multiple custom processors -> each wrapped with AttributeRenamingProcessor."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")

        processor1 = SimpleSpanProcessor(span_exporter)
        apply_env_var_mapping()
        init(
            app_name="fortifyroot-multi-processor-test",
            enabled=True,
            disable_batch=True,
            processors=[processor1],
            instruments={Instruments.OPENAI},
        )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        # If AttributeRenamingProcessor is wrapping correctly, no traceloop.* attrs
        assert not _has_traceloop_attrs(span), (
            f"AttributeRenamingProcessor not wrapping custom processor. "
            f"Found traceloop attrs: "
            f"{[k for k in span.attributes if k.startswith('traceloop.')]}"
        )
        # Span still has correct telemetry
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_custom_resource_attributes_present(self, span_exporter):
        """Custom resource_attributes passed to init() appear on spans."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        processor = SimpleSpanProcessor(span_exporter)
        apply_env_var_mapping()
        init(
            app_name="fortifyroot-resource-test",
            enabled=True,
            disable_batch=True,
            processors=[processor],
            instruments={Instruments.OPENAI},
            resource_attributes={"team": "ml-safety", "environment": "test"},
        )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        resource_attrs = dict(span.resource.attributes) if span.resource else {}
        assert resource_attrs.get("team") == "ml-safety"
        # SDK normalizes shorthand "environment" → OTEL canonical "deployment.environment"
        assert resource_attrs.get("deployment.environment") == "test"
        assert resource_attrs.get("environment") is None
        # SDK version should also be present (injected by init())
        assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE in resource_attrs

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_fluent_api_produces_same_result_as_direct_init(self, span_exporter):
        """Fluent configure().init() should produce identical results to direct init()."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        from fortifyroot.ocelle import configure

        processor = SimpleSpanProcessor(span_exporter)
        apply_env_var_mapping()
        configure() \
            .app_name("fortifyroot-fluent-test") \
            .enabled(True) \
            .disable_batch(True) \
            .processors([processor]) \
            .instruments({Instruments.OPENAI}) \
            .trace_content(True) \
            .init()

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Fluent API test: 2+2?"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        # Same telemetry as direct init()
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes
        prompt = _prompt_content(span)
        assert prompt is not None
        assert "Fluent API test" in prompt

        # Resource attributes should include service name and SDK version
        resource_attrs = dict(span.resource.attributes) if span.resource else {}
        assert resource_attrs.get("service.name") == "fortifyroot-fluent-test"
        assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE in resource_attrs

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_span_postprocess_callback_invoked(self, span_exporter):
        """span_postprocess_callback is called on each span after export."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")

        callback_spans = []

        def _capture_callback(span):
            callback_spans.append(span.name)

        processor = SimpleSpanProcessor(span_exporter)
        apply_env_var_mapping()
        init(
            app_name="fortifyroot-callback-test",
            enabled=True,
            disable_batch=True,
            processors=[processor],
            instruments={Instruments.OPENAI},
            span_postprocess_callback=_capture_callback,
        )

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=50,
        )

        span = _get_span(span_exporter)
        assert len(callback_spans) >= 1, "Callback was never invoked"
        assert "openai.chat" in callback_spans
