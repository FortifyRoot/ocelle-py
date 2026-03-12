"""Tests for the safety runtime and backend config fetch path."""

import io
import json
import logging
import urllib.error
from unittest import mock

import pytest

from fortifyroot._internal.safety.engine import compile_snapshot
from fortifyroot._internal.safety.models import ConfigProfile, SafetyConfig, SafetyRule
from fortifyroot._internal.safety.runtime import (
    FORTIFYROOT_API_BASE_URL,
    LOCAL_FORTIFYROOT_DEV_HOSTS,
    SafetyConfigFetchError,
    SafetyConfigClient,
    SafetyFetchResult,
    SafetyRuntime,
    _is_fortifyroot_api_endpoint,
    configure_global_safety_runtime,
    shutdown_global_safety_runtime,
)
from fortifyroot._internal.safety.models import RegexMatcher
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
        result = client.fetch("")

    assert result.snapshot is not None
    assert result.not_modified is False
    assert result.has_rule_definitions is True
    assert result.has_enabled_rule_definitions is True
    assert result.snapshot.config_profile_id == "cfg-1"
    assert result.snapshot.etag == "etag-3"
    assert result.snapshot.evaluate_text("reach me at jane@acme.com") is not None


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
        result = client.fetch("etag-current")

    assert result.snapshot is None
    assert result.not_modified is True
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
        with pytest.raises(SafetyConfigFetchError, match="HTTP status 500"):
            client.fetch("")


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
        with pytest.raises(SafetyConfigFetchError, match="Safety config fetch failed"):
            client.fetch("")


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
        with pytest.raises(
            SafetyConfigFetchError,
            match="Safety config payload could not be parsed or compiled",
        ):
            client.fetch("")


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


def test_safety_runtime_raises_when_initial_fetch_fails():
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
        with pytest.raises(RuntimeError, match="Initial FortifyRoot safety config fetch failed"):
            runtime.start()

    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None


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


def test_configure_global_safety_runtime_skips_when_endpoint_is_not_fortifyroot(caplog):
    caplog.set_level(logging.WARNING)
    clear_safety_handlers()

    with mock.patch("fortifyroot._internal.safety.runtime.SafetyRuntime") as runtime_cls:
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://collector.example.com",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
        )

    runtime_cls.assert_not_called()
    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None
    assert (
        "api_endpoint is not a trusted FortifyRoot API host or local FortifyRoot dev endpoint"
        in caplog.text
    )


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (FORTIFYROOT_API_BASE_URL, True),
        ("https://api.fortifyroot.com/", True),
        ("https://dev-api.fortifyroot.com", True),
        ("https://staging-api.fortifyroot.com", True),
        ("http://localhost:8080", True),
        ("http://127.0.0.1:8080", True),
        ("http://[::1]:8080", True),
        ("https://localhost:8080", True),
        ("http://host.docker.internal:8080", True),
        ("http://api.fortifyroot.com", False),
        ("https://collector.example.com", False),
        ("http://collector.example.com", False),
    ],
)
def test_is_fortifyroot_api_endpoint_accepts_prod_and_local_dev_urls(endpoint, expected):
    assert _is_fortifyroot_api_endpoint(endpoint) is expected


@pytest.mark.parametrize("host", sorted(LOCAL_FORTIFYROOT_DEV_HOSTS))
def test_configure_global_safety_runtime_accepts_local_dev_endpoint(host):
    clear_safety_handlers()

    with mock.patch("fortifyroot._internal.safety.runtime.SafetyRuntime") as runtime_cls:
        runtime = runtime_cls.return_value
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint=f"http://{host}:8080",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
        )

    runtime_cls.assert_called_once_with(
        api_endpoint=f"http://{host}:8080",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )
    runtime.start.assert_called_once()


def test_configure_global_safety_runtime_warns_when_required_config_is_missing(caplog):
    caplog.set_level(logging.WARNING)
    clear_safety_handlers()

    with mock.patch("fortifyroot._internal.safety.runtime.SafetyRuntime") as runtime_cls:
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint=FORTIFYROOT_API_BASE_URL,
            api_key="",
            config_profile_id=None,
            poll_interval_seconds=60,
        )

    runtime_cls.assert_not_called()
    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None
    assert "api_key, config_profile_id, and a positive poll interval are required" in caplog.text


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


def test_safety_runtime_warns_once_when_no_rules_are_defined(caplog):
    runtime = SafetyRuntime(
        api_endpoint=FORTIFYROOT_API_BASE_URL,
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )
    snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
            safety=SafetyConfig(enabled=True, default_action="MASK", rules=()),
        )
    )

    with (
        caplog.at_level(logging.WARNING),
        mock.patch.object(
            runtime._client,
            "fetch",
            side_effect=[
                SafetyFetchResult(
                    snapshot=snapshot,
                    not_modified=False,
                    has_rule_definitions=False,
                    has_enabled_rule_definitions=False,
                ),
                SafetyFetchResult(
                    snapshot=snapshot,
                    not_modified=False,
                    has_rule_definitions=False,
                    has_enabled_rule_definitions=False,
                ),
            ],
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()
        runtime._refresh_once()

    assert get_prompt_safety_handler() is not None
    assert get_completion_safety_handler() is not None
    assert caplog.text.count("no safety rules are defined") == 1

    runtime.stop()


def test_safety_runtime_warns_once_when_no_enabled_configs_exist(caplog):
    runtime = SafetyRuntime(
        api_endpoint=FORTIFYROOT_API_BASE_URL,
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )
    snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
            safety=SafetyConfig(
                enabled=False,
                default_action="MASK",
                rules=(
                    SafetyRule(
                        name="email",
                        category="PII",
                        severity="HIGH",
                        action="MASK",
                        enabled=False,
                        matcher=RegexMatcher(pattern=r".+"),
                    ),
                ),
            ),
        )
    )

    with (
        caplog.at_level(logging.WARNING),
        mock.patch.object(
            runtime._client,
            "fetch",
            side_effect=[
                SafetyFetchResult(
                    snapshot=snapshot,
                    not_modified=False,
                    has_rule_definitions=True,
                    has_enabled_rule_definitions=False,
                ),
                SafetyFetchResult(
                    snapshot=snapshot,
                    not_modified=False,
                    has_rule_definitions=True,
                    has_enabled_rule_definitions=False,
                ),
            ],
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()
        runtime._refresh_once()

    assert get_prompt_safety_handler() is not None
    assert caplog.text.count("could not find any enabled safety configs") == 1

    runtime.stop()


def test_safety_runtime_keeps_last_good_snapshot_when_later_poll_fails(caplog):
    runtime = SafetyRuntime(
        api_endpoint=FORTIFYROOT_API_BASE_URL,
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
    )
    snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
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

    with (
        caplog.at_level(logging.WARNING),
        mock.patch.object(
            runtime._client,
            "fetch",
            side_effect=[
                SafetyFetchResult(
                    snapshot=snapshot,
                    not_modified=False,
                    has_rule_definitions=True,
                    has_enabled_rule_definitions=True,
                ),
                SafetyConfigFetchError("temporary failure"),
            ],
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()
        runtime._refresh_once()

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
    assert result.text == "reach me at [PII.email]"
    assert "temporary failure" in caplog.text

    runtime.stop()
