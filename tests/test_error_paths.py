"""T9-5: Error path and safety-disabled tests.

Tests error handling, graceful degradation, and safety-disabled scenarios:

  1. Safety handler raises exception -> fail open (provider call succeeds)
  2. Config fetch error on initial start -> empty snapshot, handlers still work
  3. Config fetch error during poll -> stale config continues
  4. Provider timeout -> span still emitted with error status
  5. Invalid safety config JSON -> graceful degradation
  6. Safety disabled via enabled=False -> no handlers registered
  7. api_endpoint is non-FR URL -> safety skipped, telemetry works
  8. config_profile_id is None -> safety skipped, telemetry works
  9. api_key is None -> safety skipped, telemetry works
  10. poll_interval_seconds <= 0 -> safety skipped, telemetry works
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from unittest import mock

import openai
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI

from fortifyroot import Instruments, init
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from fortifyroot._internal.safety.runtime import (
    SafetyConfigFetchError,
    SafetyRuntime,
    configure_global_safety_runtime,
    shutdown_global_safety_runtime,
)
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyContext,
    SafetyLocation,
    clear_safety_handlers,
    get_completion_safety_handler,
    get_completion_safety_stream_factory,
    get_prompt_safety_handler,
    register_prompt_safety_handler,
)


# ---------------------------------------------------------------------------
# Cassette dir and VCR config (reuses T5 OpenAI cassettes)
# ---------------------------------------------------------------------------

_CASSETTE_DIR = Path(__file__).parent / "providers" / "openai" / "cassettes"


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
# Local init fixture (same as providers/conftest.py but at tests/ level)
# ---------------------------------------------------------------------------


@pytest.fixture
def init_provider_sdk(span_exporter):
    """Factory fixture to initialize FortifyRoot with a specific provider."""
    import os

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


def _get_span(exporter, min_count=1):
    spans = exporter.get_finished_spans()
    assert len(spans) >= min_count, f"Expected >= {min_count} spans, got {len(spans)}"
    return spans[0]


def _prompt_content(span):
    for key in PROMPT_KEYS:
        if key in span.attributes:
            return str(span.attributes[key])
    return None


def _skip_if_no_cassette(cassette_stem: str):
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"
    if not cassette.exists():
        pytest.skip(f"Cassette missing: {cassette}")


# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------


def setup_function():
    shutdown_global_safety_runtime()


def teardown_function():
    shutdown_global_safety_runtime()


# ===========================================================================
# T9-5.1: Safety handler raises exception -> fail open
# ===========================================================================


class TestSafetyHandlerException:
    """Provider call succeeds even when safety handler throws."""

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_handler_exception_fails_open(self, span_exporter, init_provider_sdk):
        """Exception in safety handler -> call succeeds, span emitted."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})

        # Register a handler that always raises
        def _exploding_handler(context):
            raise RuntimeError("safety handler exploded")

        clear_safety_handlers()
        register_prompt_safety_handler(_exploding_handler)

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        # Should NOT raise despite handler explosion
        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )
        assert response is not None

        # Span should still be emitted
        span = _get_span(span_exporter)
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes


# ===========================================================================
# T9-5.2: Config fetch error on initial start
# ===========================================================================


class TestConfigFetchErrorOnStart:
    """Initial config fetch failure -> empty snapshot, handlers registered but no-op."""

    def test_initial_fetch_error_empty_snapshot(self, caplog):
        import urllib.error

        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

        error = urllib.error.HTTPError(
            url="https://api.fortifyroot.com/v1/sdk/config/cfg-1",
            code=503,
            msg="Service Unavailable",
            hdrs=None,
            fp=None,
        )
        with (
            caplog.at_level(logging.WARNING),
            mock.patch(
                "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
                side_effect=error,
            ),
            mock.patch.object(runtime._thread, "start"),
        ):
            runtime.start()

        assert "Initial FortifyRoot safety config fetch failed" in caplog.text

        # Handlers registered but return None (no snapshot)
        handler = get_prompt_safety_handler()
        assert handler is not None
        result = handler(
            SafetyContext(
                provider="OpenAI",
                text="secret data jane@acme.com",
                location=SafetyLocation.PROMPT,
                span_name="openai.chat",
            )
        )
        assert result is None  # no masking, fail open

        runtime.stop()


# ===========================================================================
# T9-5.3: Config fetch error during poll -> stale config
# ===========================================================================


class TestConfigFetchErrorDuringPoll:
    """Error during subsequent poll -> stale snapshot continues working."""

    def test_stale_config_continues_after_poll_error(self):
        payload = {
            "configProfile": {
                "id": "cfg-1",
                "version": 1,
                "etag": "etag-1",
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
                                "regex": r"[a-z]+@[a-z]+\.com",
                            }
                        ],
                    }
                },
            }
        }

        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

        # Initial fetch succeeds
        with (
            mock.patch(
                "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
                return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
            ),
            mock.patch.object(runtime._thread, "start"),
        ):
            runtime.start()

        # Verify initial snapshot works
        handler = get_prompt_safety_handler()
        result = handler(
            SafetyContext(
                provider="OpenAI",
                text="email jane@acme.com",
                location=SafetyLocation.PROMPT,
                span_name="openai.chat",
            )
        )
        assert result is not None
        assert result.overall_action == "MASK"

        # Subsequent poll fails
        with mock.patch.object(
            runtime._client,
            "fetch",
            side_effect=SafetyConfigFetchError("Network error"),
        ):
            runtime._refresh_once()

        # Stale snapshot still works
        result = handler(
            SafetyContext(
                provider="OpenAI",
                text="email bob@corp.com",
                location=SafetyLocation.PROMPT,
                span_name="openai.chat",
            )
        )
        assert result is not None
        assert result.overall_action == "MASK"
        assert "[PII.email]" in result.text

        runtime.stop()


# ===========================================================================
# T9-5.4: Invalid safety config JSON -> graceful degradation
# ===========================================================================


class TestInvalidConfigJSON:
    """Invalid config payload -> snapshot not updated, no crash."""

    def test_invalid_json_structure(self):
        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

        # Invalid payload: missing configProfile
        invalid_payload = {"garbage": True}
        with (
            mock.patch(
                "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
                return_value=_FakeHTTPResponse(
                    json.dumps(invalid_payload).encode("utf-8")
                ),
            ),
            mock.patch.object(runtime._thread, "start"),
        ):
            # Should not raise; starts with empty snapshot
            runtime.start()

        # Handler registered but no snapshot
        handler = get_prompt_safety_handler()
        assert handler is not None
        result = handler(
            SafetyContext(
                provider="OpenAI",
                text="jane@acme.com",
                location=SafetyLocation.PROMPT,
                span_name="openai.chat",
            )
        )
        assert result is None  # no masking

        runtime.stop()


# ===========================================================================
# T9-5.5: Safety disabled via enabled=False
# ===========================================================================


class TestSafetyDisabled:
    """Safety disabled -> no handlers registered."""

    def test_disabled_clears_handlers(self):
        configure_global_safety_runtime(
            enabled=False,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert get_completion_safety_handler() is None
        assert get_completion_safety_stream_factory() is None


# ===========================================================================
# T9-5.6: Non-FR endpoint -> safety skipped, telemetry works
# ===========================================================================


class TestNonFREndpoint:
    """Non-FortifyRoot endpoint -> safety skipped but telemetry still works."""

    def test_non_fr_endpoint_skips_safety(self, caplog):
        caplog.set_level(logging.WARNING)

        with mock.patch(
            "fortifyroot._internal.safety.runtime.SafetyRuntime"
        ) as runtime_cls:
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="https://collector.example.com",
                api_key="fr-key",
                config_profile_id="cfg-1",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        runtime_cls.assert_not_called()
        assert get_prompt_safety_handler() is None
        assert "not a trusted FortifyRoot API host" in caplog.text

    @pytest.mark.parametrize(
        "endpoint,reason",
        [
            # HTTP (not HTTPS) to FR domain — must be rejected
            ("http://api.fortifyroot.com", "plain HTTP to FR domain"),
            # Subdomain impersonation — attacker.com is NOT *.fortifyroot.com
            ("https://api.fortifyroot.com.attacker.com", "subdomain impersonation"),
            # Wrong scheme entirely
            ("ftp://api.fortifyroot.com", "non-HTTP scheme"),
            # Random third-party HTTPS endpoint
            ("https://otel-collector.internal.corp.net", "third-party collector"),
            # Public IP (non-loopback)
            ("http://8.8.8.8:4318", "public IP address"),
            # Empty string
            ("", "empty endpoint"),
        ],
    )
    def test_non_fr_url_variants_skip_safety(self, caplog, endpoint, reason):
        """Safety skipped for various non-FR URL patterns: {reason}."""
        caplog.set_level(logging.WARNING)

        with mock.patch(
            "fortifyroot._internal.safety.runtime.SafetyRuntime"
        ) as runtime_cls:
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint=endpoint,
                api_key="fr-key",
                config_profile_id="cfg-1",
                poll_interval_seconds=60,
                stream_holdback_chars=128,
            )

        runtime_cls.assert_not_called()
        assert get_prompt_safety_handler() is None

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_telemetry_works_without_safety(self, span_exporter, init_provider_sdk):
        """Telemetry still works even when safety is skipped (non-FR endpoint)."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})

        # Configure safety with non-FR endpoint -> skipped
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://collector.example.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
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

        # Telemetry still captured
        span = _get_span(span_exporter)
        assert span.name == "openai.chat"
        assert GenAI.GEN_AI_SYSTEM in span.attributes


# ===========================================================================
# T9-5.7: config_profile_id is None -> safety skipped
# ===========================================================================


class TestMissingConfigProfileId:
    """config_profile_id=None -> safety skipped, telemetry works."""

    def test_none_profile_id_skips_safety(self, caplog):
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id=None,
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert "api_key, config_profile_id, and a positive poll interval" in caplog.text


# ===========================================================================
# T9-5.8: api_key is None -> safety skipped
# ===========================================================================


class TestMissingApiKey:
    """api_key=None -> safety skipped, telemetry works."""

    def test_none_api_key_skips_safety(self, caplog):
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key=None,
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert "api_key, config_profile_id, and a positive poll interval" in caplog.text

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_telemetry_works_without_api_key(self, span_exporter, init_provider_sdk):
        """Telemetry still works when no API key -> safety skipped."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})
        # No safety config -> no masking
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
        assert span.name == "openai.chat"
        prompt = _prompt_content(span)
        assert prompt is not None


# ===========================================================================
# T9-5.9: poll_interval_seconds <= 0 -> safety skipped
# ===========================================================================


class TestInvalidPollInterval:
    """poll_interval_seconds <= 0 -> safety skipped."""

    def test_zero_poll_interval_skips_safety(self, caplog):
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=0,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert "api_key, config_profile_id, and a positive poll interval" in caplog.text

    def test_negative_poll_interval_skips_safety(self, caplog):
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=-1,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None


# ===========================================================================
# T9-5.10: Provider timeout -> span still emitted
# ===========================================================================


class TestProviderTimeout:
    """Provider error/timeout -> span still emitted with error status."""

    def test_provider_error_still_emits_span(self, span_exporter, init_provider_sdk):
        """When provider raises ConnectionError, span is still emitted."""
        init_provider_sdk(instruments={Instruments.OPENAI})
        clear_safety_handlers()

        client = openai.OpenAI(
            api_key="test-key",
            base_url="http://localhost:1",  # unreachable port -> connection error
        )
        with pytest.raises(openai.APIConnectionError):
            client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "test"}],
                max_tokens=10,
            )

        # Span should still be recorded even though provider call failed
        spans = span_exporter.get_finished_spans()
        assert len(spans) >= 1, "No spans emitted after provider error"
        span = spans[0]
        assert span.name == "openai.chat"


# ===========================================================================
# T9-5.11: Empty string api_key/config_profile_id edge cases
# ===========================================================================


class TestEmptyStringConfig:
    """Empty string ("") should be treated same as None for safety config."""

    def test_empty_string_api_key_skips_safety(self, caplog):
        """api_key='' (empty string) -> safety skipped."""
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert "api_key, config_profile_id, and a positive poll interval" in caplog.text

    def test_empty_string_config_profile_id_skips_safety(self, caplog):
        """config_profile_id='' (empty string) -> safety skipped."""
        caplog.set_level(logging.WARNING)
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert get_prompt_safety_handler() is None
        assert "api_key, config_profile_id, and a positive poll interval" in caplog.text


# ===========================================================================
# T9-5.12: Completion handler exception -> fail open
# ===========================================================================


class TestCompletionHandlerException:
    """Completion handler exception should also fail open."""

    @pytest.mark.vcr
    @pytest.mark.default_cassette("test_openai_safety_no_config_passthrough")
    @pytest.mark.fr
    def test_completion_handler_exception_fails_open(self, span_exporter, init_provider_sdk):
        """Exception in completion safety handler -> call still succeeds."""
        _skip_if_no_cassette("test_openai_safety_no_config_passthrough")
        init_provider_sdk(instruments={Instruments.OPENAI})

        from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
            register_completion_safety_handler,
        )

        def _exploding_completion_handler(context):
            raise RuntimeError("completion handler exploded")

        clear_safety_handlers()
        register_completion_safety_handler(_exploding_completion_handler)

        client = openai.OpenAI(
            api_key="test-key-for-vcr-replay",
            base_url="https://api.openai.com/v1",
        )
        # Should NOT raise despite completion handler explosion
        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": "Hello, what is 2+2?"}],
            max_tokens=50,
        )
        assert response is not None

        span = _get_span(span_exporter)
        assert span.name == "openai.chat"
