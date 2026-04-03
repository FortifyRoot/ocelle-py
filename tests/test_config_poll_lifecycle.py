"""T9-1: Config poll lifecycle integration tests.

Tests the SafetyRuntime config polling loop end-to-end using mock HTTP:

  1. Initial fetch -> 200 + SafetyConfig -> snapshot compiled, handlers registered
  2. Second poll -> 304 Not Modified (ETag match) -> snapshot unchanged
  3. Third poll -> 200 + updated config -> atomic snapshot swap, new rule active
  4. Fourth poll -> 500 server error -> stale snapshot continues working
  5. Shutdown -> daemon thread stopped, handlers cleared

These tests go beyond the unit-level tests in test_safety_runtime.py by
exercising the full lifecycle sequence in order, verifying state transitions
across multiple poll cycles.
"""

from __future__ import annotations

import io
import json
import logging
import threading
from unittest import mock

import pytest

from fortifyroot._internal.safety.engine import compile_snapshot
from fortifyroot._internal.safety.models import (
    ConfigProfile,
    RegexMatcher,
    SafetyConfig,
    SafetyRule,
)
from fortifyroot._internal.safety.runtime import (
    SafetyConfigClient,
    SafetyConfigFetchError,
    SafetyFetchResult,
    SafetyRuntime,
    SafetySnapshotStore,
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
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeHTTPResponse(io.BytesIO):
    """Minimal file-like context manager to mock urllib.request.urlopen."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _config_payload(
    *,
    profile_id: str = "cfg-1",
    version: int = 1,
    etag: str = "etag-1",
    email_pattern: str = r"[a-z]+@[a-z]+\.com",
    extra_rules: list | None = None,
) -> dict:
    """Build a valid SDK config response payload."""
    rules = [
        {
            "name": "email",
            "category": "SAFETY_CATEGORY_PII",
            "severity": "SEVERITY_HIGH",
            "enabled": True,
            "regex": email_pattern,
        }
    ]
    if extra_rules:
        rules.extend(extra_rules)
    return {
        "configProfile": {
            "id": profile_id,
            "version": version,
            "etag": etag,
            "config": {
                "safetyConfig": {
                    "enabled": True,
                    "defaultAction": "SAFETY_ACTION_MASK",
                    "rules": rules,
                }
            },
        }
    }


def _not_modified_payload() -> dict:
    return {"notModified": True}


def _make_response(payload: dict) -> _FakeHTTPResponse:
    return _FakeHTTPResponse(json.dumps(payload).encode("utf-8"))


def _eval_prompt(text: str) -> object | None:
    handler = get_prompt_safety_handler()
    if handler is None:
        return None
    return handler(
        SafetyContext(
            provider="OpenAI",
            text=text,
            location=SafetyLocation.PROMPT,
            span_name="openai.chat",
        )
    )


# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------


def setup_function():
    shutdown_global_safety_runtime()


def teardown_function():
    shutdown_global_safety_runtime()


# ---------------------------------------------------------------------------
# T9-1.1: Full lifecycle sequence
# ---------------------------------------------------------------------------


class TestConfigPollLifecycle:
    """Exercises the full lifecycle: initial fetch -> 304 -> update -> error -> shutdown."""

    def test_full_lifecycle_sequence(self):
        """Step through all five lifecycle states in order."""
        # --- Build responses for each poll cycle ---
        initial_payload = _config_payload(etag="etag-v1", version=1)
        not_modified = _not_modified_payload()
        updated_payload = _config_payload(
            etag="etag-v2",
            version=2,
            extra_rules=[
                {
                    "name": "credit_card",
                    "category": "SAFETY_CATEGORY_PCI",
                    "severity": "SEVERITY_CRITICAL",
                    "enabled": True,
                    "regex": r"\b(?:\d[ -]*?){13,16}\b",
                }
            ],
        )

        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

        # Step 1: Initial fetch -> 200 with email rule
        with (
            mock.patch(
                "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
                return_value=_make_response(initial_payload),
            ),
            mock.patch.object(runtime._thread, "start"),
        ):
            runtime.start()

        # Handlers registered, email masking works
        result = _eval_prompt("contact jane@acme.com for details")
        assert result is not None
        assert result.overall_action == "MASK"
        assert "jane@acme.com" not in result.text
        assert "[PII.email]" in result.text

        # CC not detected yet (no CC rule in v1)
        result_cc = _eval_prompt("card 4111 1111 1111 1111")
        assert result_cc is None  # no CC rule -> no findings

        # Step 2: 304 Not Modified -> snapshot unchanged
        with mock.patch.object(
            runtime._client,
            "fetch",
            return_value=SafetyFetchResult(
                snapshot=None,
                not_modified=True,
                has_rule_definitions=False,
                has_enabled_rule_definitions=False,
            ),
        ):
            runtime._refresh_once()

        # Email still masked (stale snapshot continues)
        result = _eval_prompt("contact jane@acme.com again")
        assert result is not None
        assert "[PII.email]" in result.text

        # Step 3: Updated config -> new rules (email + CC)
        with mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_make_response(updated_payload),
        ):
            runtime._refresh_once()

        # Email still masked
        result = _eval_prompt("reach jane@acme.com")
        assert result is not None
        assert "[PII.email]" in result.text

        # CC now also detected
        result_cc = _eval_prompt("card 4111 1111 1111 1111")
        assert result_cc is not None
        assert result_cc.overall_action == "MASK"

        # Step 4: 500 error -> stale snapshot continues
        with mock.patch.object(
            runtime._client,
            "fetch",
            side_effect=SafetyConfigFetchError("HTTP 500"),
        ):
            runtime._refresh_once()

        # Both rules still active from v2
        result = _eval_prompt("jane@acme.com with card 4111 1111 1111 1111")
        assert result is not None
        assert "[PII.email]" in result.text

        # Step 5: Shutdown -> handlers cleared
        runtime.stop()
        assert get_prompt_safety_handler() is None
        assert get_completion_safety_handler() is None
        assert get_completion_safety_stream_factory() is None


# ---------------------------------------------------------------------------
# T9-1.2: Thread daemon status
# ---------------------------------------------------------------------------


class TestPollThreadProperties:
    """Verify the poller thread is a daemon and has the expected name."""

    def test_poll_thread_is_daemon_with_correct_name(self):
        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )
        assert runtime._thread.daemon is True
        assert runtime._thread.name == "fortifyroot-safety-poller"


# ---------------------------------------------------------------------------
# T9-1.3: ETag propagation across polls
# ---------------------------------------------------------------------------


class TestETagPropagation:
    """Verify that ETag from initial fetch is sent in subsequent polls."""

    def test_etag_sent_on_subsequent_poll(self):
        initial_payload = _config_payload(etag="etag-abc")
        runtime = SafetyRuntime(
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

        # Step 1: Initial fetch sets etag
        with (
            mock.patch(
                "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
                return_value=_make_response(initial_payload),
            ),
            mock.patch.object(runtime._thread, "start"),
        ):
            runtime.start()

        snapshot = runtime._snapshot_store.get()
        assert snapshot is not None
        assert snapshot.etag == "etag-abc"

        # Step 2: Next poll should send current_etag=etag-abc
        captured_etag = None

        def _capture_fetch(current_etag):
            nonlocal captured_etag
            captured_etag = current_etag
            return SafetyFetchResult(
                snapshot=None,
                not_modified=True,
                has_rule_definitions=False,
                has_enabled_rule_definitions=False,
            )

        with mock.patch.object(runtime._client, "fetch", side_effect=_capture_fetch):
            runtime._refresh_once()

        assert captured_etag == "etag-abc"
        runtime.stop()


# ---------------------------------------------------------------------------
# T9-1.4: Snapshot store thread safety
# ---------------------------------------------------------------------------


class TestSnapshotStoreThreadSafety:
    """Verify concurrent reads/writes to SafetySnapshotStore don't corrupt state."""

    def test_concurrent_access(self):
        store = SafetySnapshotStore()
        snapshot_a = compile_snapshot(
            ConfigProfile(
                config_profile_id="cfg-a",
                version=1,
                etag="a",
                safety=SafetyConfig(
                    enabled=True,
                    default_action="MASK",
                    rules=(
                        SafetyRule(
                            name="email",
                            category="PII",
                            severity="HIGH",
                            action="MASK",
                            enabled=True,
                            matcher=RegexMatcher(pattern=r"[a-z]+@[a-z]+\.com"),
                        ),
                    ),
                ),
            )
        )
        snapshot_b = compile_snapshot(
            ConfigProfile(
                config_profile_id="cfg-b",
                version=2,
                etag="b",
                safety=SafetyConfig(
                    enabled=True,
                    default_action="MASK",
                    rules=(
                        SafetyRule(
                            name="cc",
                            category="PCI",
                            severity="CRITICAL",
                            action="MASK",
                            enabled=True,
                            matcher=RegexMatcher(pattern=r"\d{16}"),
                        ),
                    ),
                ),
            )
        )

        errors: list[str] = []
        barrier = threading.Barrier(3)

        def writer_a():
            barrier.wait()
            for _ in range(100):
                store.set(snapshot_a)

        def writer_b():
            barrier.wait()
            for _ in range(100):
                store.set(snapshot_b)

        def reader():
            barrier.wait()
            for _ in range(200):
                s = store.get()
                if s is not None and s.config_profile_id not in ("cfg-a", "cfg-b"):
                    errors.append(f"corrupted: {s.config_profile_id}")

        threads = [
            threading.Thread(target=writer_a),
            threading.Thread(target=writer_b),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Thread safety violations: {errors}"


# ---------------------------------------------------------------------------
# T9-1.5: configure_global_safety_runtime via init() path
# ---------------------------------------------------------------------------


class TestConfigureGlobalRuntimeViaInit:
    """Verify configure_global_safety_runtime works with localhost endpoint."""

    def test_localhost_endpoint_starts_runtime(self):
        with mock.patch(
            "fortifyroot._internal.safety.runtime.SafetyRuntime"
        ) as runtime_cls:
            runtime_instance = runtime_cls.return_value
            configure_global_safety_runtime(
                enabled=True,
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-test",
                poll_interval_seconds=30,
                stream_holdback_chars=64,
            )
            runtime_cls.assert_called_once_with(
                api_endpoint="http://localhost:8080",
                api_key="fr-test-key",
                config_profile_id="cfg-test",
                poll_interval_seconds=30,
                stream_holdback_chars=64,
            )
            runtime_instance.start.assert_called_once()
