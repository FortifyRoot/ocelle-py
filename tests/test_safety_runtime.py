"""Tests for the safety runtime and backend config fetch path."""

import io
import json
import urllib.error
from unittest import mock

from fortifyroot._internal.safety.runtime import (
    SafetyConfigClient,
    SafetyRuntime,
    configure_global_safety_runtime,
    shutdown_global_safety_runtime,
)
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyContext,
    SafetyLocation,
    clear_safety_handlers,
    get_completion_safety_handler,
    get_prompt_safety_handler,
)


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def setup_function():
    shutdown_global_safety_runtime()


def teardown_function():
    shutdown_global_safety_runtime()


def test_safety_config_client_fetch_compiles_snapshot():
    payload = {
        "configProfile": {
            "id": "cfg-1",
            "version": 3,
            "etag": "etag-3",
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

    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
    ):
        snapshot = client.fetch("")

    assert snapshot is not None
    assert snapshot.config_profile_id == "cfg-1"
    assert snapshot.etag == "etag-3"
    assert snapshot.evaluate_text("reach me at jane@acme.com") is not None


def test_safety_config_client_fetch_sends_sdk_version_and_etag():
    payload = {"notModified": True}
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )

    captured_request = None

    def _fake_urlopen(request, timeout):
        nonlocal captured_request
        captured_request = request
        return _FakeHTTPResponse(json.dumps(payload).encode("utf-8"))

    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        side_effect=_fake_urlopen,
    ):
        snapshot = client.fetch("etag-current")

    assert snapshot is None
    assert captured_request is not None
    assert "sdk_version=" in captured_request.full_url
    assert "current_etag=etag-current" in captured_request.full_url
    assert captured_request.get_header("Authorization") == "Bearer fr-key"
    assert captured_request.get_header("X-fortifyroot-sdk-version") is not None


def test_safety_config_client_fetch_returns_none_on_http_error():
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )

    error = urllib.error.HTTPError(
        url="https://api.fortifyroot.com/v1/sdk/config/cfg-1",
        code=500,
        msg="boom",
        hdrs=None,
        fp=None,
    )
    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        side_effect=error,
    ):
        assert client.fetch("") is None


def test_safety_config_client_fetch_returns_none_on_generic_fetch_error():
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )

    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        side_effect=RuntimeError("boom"),
    ):
        assert client.fetch("") is None


def test_safety_config_client_fetch_returns_none_on_compile_failure():
    payload = {
        "configProfile": {
            "id": "cfg-1",
            "version": 1,
            "etag": "etag-1",
            "config": {"safetyConfig": {"enabled": True, "defaultAction": "ALLOW", "rules": []}},
        }
    }
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    with (
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
        ),
        mock.patch("fortifyroot._internal.safety.runtime.compile_snapshot", side_effect=RuntimeError("boom")),
    ):
        assert client.fetch("") is None


def test_safety_runtime_registers_prompt_handler_from_snapshot():
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
    )

    with (
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()

    handler = get_prompt_safety_handler()
    assert handler is not None
    result = handler(
        SafetyContext(
            provider="OpenAI",
            text="reach me at jane@acme.com",
            location=SafetyLocation.PROMPT,
            span_name="openai.chat",
        )
    )
    assert result is not None
    assert result.overall_action == "MASK"

    runtime.stop()
    clear_safety_handlers()


def test_safety_runtime_fail_open_when_initial_fetch_fails():
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )

    error = urllib.error.HTTPError(
        url="https://api.fortifyroot.com/v1/sdk/config/cfg-1",
        code=503,
        msg="unavailable",
        hdrs=None,
        fp=None,
    )
    with (
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            side_effect=error,
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()

    handler = get_prompt_safety_handler()
    assert handler is not None
    assert (
        handler(
            SafetyContext(
                provider="OpenAI",
                text="secret",
                location=SafetyLocation.PROMPT,
                span_name="openai.chat",
            )
        )
        is None
    )

    runtime.stop()


def test_configure_global_safety_runtime_clears_handlers_when_disabled():
    clear_safety_handlers()

    configure_global_safety_runtime(
        enabled=False,
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )

    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None


def test_safety_runtime_stop_joins_running_thread_and_clears_snapshot():
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )
    runtime._snapshot_store.set(mock.Mock())

    with (
        mock.patch.object(runtime._thread, "is_alive", return_value=True),
        mock.patch.object(runtime._thread, "join") as join_mock,
    ):
        runtime.stop()

    join_mock.assert_called_once_with(timeout=1.0)
    assert runtime._snapshot_store.get() is None


def test_safety_runtime_poll_loop_refreshes_until_stopped():
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )

    wait_results = iter([False, True])

    with (
        mock.patch.object(runtime._stop_event, "wait", side_effect=lambda _: next(wait_results)),
        mock.patch.object(runtime, "_refresh_once") as refresh_mock,
    ):
        runtime._poll_loop()

    refresh_mock.assert_called_once()


def test_configure_global_safety_runtime_replaces_existing_runtime_and_shutdown_stops_it():
    first_runtime = mock.Mock()
    second_runtime = mock.Mock()

    with mock.patch(
        "fortifyroot._internal.safety.runtime.SafetyRuntime",
        side_effect=[first_runtime, second_runtime],
    ):
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
        )
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-2",
            poll_interval_seconds=30,
        )

        first_runtime.start.assert_called_once()
        first_runtime.stop.assert_called_once()
        second_runtime.start.assert_called_once()

        shutdown_global_safety_runtime()

    second_runtime.stop.assert_called_once()
