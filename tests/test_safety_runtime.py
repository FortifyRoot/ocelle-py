"""Tests for the safety runtime and backend config fetch path."""

import io
import json
import logging
import threading
import time
import urllib.error
from unittest import mock

import pytest

from fortifyroot._internal.safety import runtime as safety_runtime
from fortifyroot._internal.safety.engine import compile_snapshot
from fortifyroot._internal.safety.models import ConfigProfile, SafetyConfig, SafetyRule
from fortifyroot._internal.safety.runtime import (
    FORTIFYROOT_API_BASE_URL,
    LOCAL_FORTIFYROOT_DEV_HOSTS,
    SafetyConfigFetchError,
    SafetyConfigClient,
    SafetyFetchResult,
    SafetyHandler,
    SafetyRuntime,
    SafetySnapshotStore,
    SafetyStreamFactory,
    _is_fortifyroot_api_endpoint,
    _normalize_api_endpoint,
    configure_global_safety_runtime,
    shutdown_global_safety_runtime,
)
from fortifyroot._internal.safety.models import RegexMatcher
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    SafetyContext,
    SafetyLocation,
    clear_safety_handlers,
    get_completion_safety_handler,
    get_completion_safety_stream_factory,
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
    assert captured_request.get_header("X-api-key") == "fr-key"
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
        stream_holdback_chars=128,
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


def test_safety_runtime_registers_completion_stream_factory_from_snapshot():
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
        stream_holdback_chars=4,
    )

    with (
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
        ),
        mock.patch.object(runtime._thread, "start"),
    ):
        runtime.start()

    factory = get_completion_safety_stream_factory()
    assert factory is not None
    session = factory(
        mock.Mock(
            location=SafetyLocation.COMPLETION,
            provider="OpenAI",
            span_name="openai.chat",
            request_type="chat",
            segment_index=0,
            segment_role="assistant",
            metadata={},
        )
    )
    assert session is not None
    assert session.process_chunk("abc@") is None
    assert session.process_chunk("gmail.com") is None
    result = session.flush()
    assert result is not None
    assert result.text == "[PII.email]"

    runtime.stop()
    clear_safety_handlers()


def test_safety_runtime_starts_with_empty_snapshot_when_initial_fetch_fails(caplog):
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
        msg="unavailable",
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

    assert "Initial FortifyRoot safety config fetch failed; starting with empty safety snapshot" in caplog.text
    assert get_prompt_safety_handler() is not None
    assert get_completion_safety_handler() is not None
    assert get_completion_safety_stream_factory() is not None

    prompt_result = get_prompt_safety_handler()(
        SafetyContext(
            provider="OpenAI",
            text="secret",
            location=SafetyLocation.PROMPT,
            span_name="openai.chat",
        )
    )
    assert prompt_result is None

    runtime.stop()


def test_configure_global_safety_runtime_clears_handlers_when_disabled():
    clear_safety_handlers()

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
            stream_holdback_chars=128,
        )

    runtime_cls.assert_not_called()
    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None
    assert get_completion_safety_stream_factory() is None
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
            stream_holdback_chars=128,
        )

    runtime_cls.assert_called_once_with(
        api_endpoint=f"http://{host}:8080",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
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
            stream_holdback_chars=128,
        )

    runtime_cls.assert_not_called()
    assert get_prompt_safety_handler() is None
    assert get_completion_safety_handler() is None
    assert get_completion_safety_stream_factory() is None
    assert "api_key, config_profile_id, and a positive poll interval are required" in caplog.text


def test_safety_runtime_stop_joins_running_thread_and_clears_snapshot():
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
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
        stream_holdback_chars=128,
    )

    wait_results = iter([False, True])

    with (
        mock.patch.object(runtime._stop_event, "wait", side_effect=lambda _: next(wait_results)),
        mock.patch.object(runtime, "_refresh_once") as refresh_mock,
    ):
        runtime._poll_loop()

    refresh_mock.assert_called_once()


def test_safety_runtime_poll_loop_adds_jitter_to_wait_interval():
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )

    waits = []

    def _wait(seconds):
        waits.append(seconds)
        return True

    with (
        mock.patch.object(runtime._stop_event, "wait", side_effect=_wait),
        mock.patch("fortifyroot._internal.safety.runtime.random.uniform", return_value=6.0),
    ):
        runtime._poll_loop()

    assert waits == [66.0]


def test_configure_global_safety_runtime_replaces_existing_runtime_and_shutdown_stops_it():
    first_runtime = mock.Mock()
    second_runtime = mock.Mock()
    first_runtime.same_configuration.return_value = False

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
            stream_holdback_chars=128,
        )
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-2",
            poll_interval_seconds=30,
            stream_holdback_chars=128,
        )

        first_runtime.start.assert_called_once()
        first_runtime.stop.assert_called_once()
        second_runtime.start.assert_called_once()

        shutdown_global_safety_runtime()

    second_runtime.stop.assert_called_once()


def test_configure_global_safety_runtime_short_circuits_when_configuration_is_unchanged():
    existing_runtime = mock.Mock()
    existing_runtime.same_configuration.return_value = True

    with (
        mock.patch.object(safety_runtime, "_GLOBAL_SAFETY_RUNTIME", existing_runtime),
        mock.patch("fortifyroot._internal.safety.runtime.SafetyRuntime") as runtime_cls,
    ):
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com/",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

    existing_runtime.same_configuration.assert_called_once_with(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    existing_runtime.stop.assert_not_called()
    runtime_cls.assert_not_called()


def test_safety_runtime_warns_once_when_no_rules_are_defined(caplog):
    runtime = SafetyRuntime(
        api_endpoint=FORTIFYROOT_API_BASE_URL,
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
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
        stream_holdback_chars=128,
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
        stream_holdback_chars=128,
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


def test_safety_config_client_fetch_records_not_modified_metrics():
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    fetch_counter = mock.Mock()
    failure_counter = mock.Mock()

    with (
        mock.patch.object(safety_runtime, "_CONFIG_FETCH_COUNTER", mock.Mock(add=fetch_counter)),
        mock.patch.object(
            safety_runtime,
            "_CONFIG_FETCH_FAILURE_COUNTER",
            mock.Mock(add=failure_counter),
        ),
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(json.dumps({"notModified": True}).encode("utf-8")),
        ),
    ):
        result = client.fetch("")

    assert result.not_modified is True
    fetch_counter.assert_called_once_with(
        1,
        attributes={
            "fortifyroot.safety.config_profile_id": "cfg-1",
            "result": "not_modified",
        },
    )
    failure_counter.assert_not_called()


def test_safety_config_client_fetch_records_failure_metrics():
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    fetch_counter = mock.Mock()
    failure_counter = mock.Mock()

    with (
        mock.patch.object(safety_runtime, "_CONFIG_FETCH_COUNTER", mock.Mock(add=fetch_counter)),
        mock.patch.object(
            safety_runtime,
            "_CONFIG_FETCH_FAILURE_COUNTER",
            mock.Mock(add=failure_counter),
        ),
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            side_effect=RuntimeError("boom"),
        ),
    ):
        with pytest.raises(SafetyConfigFetchError, match="Safety config fetch failed"):
            client.fetch("")

    fetch_counter.assert_called_once_with(
        1,
        attributes={
            "fortifyroot.safety.config_profile_id": "cfg-1",
            "result": "failure",
        },
    )
    failure_counter.assert_called_once_with(
        1,
        attributes={
            "fortifyroot.safety.config_profile_id": "cfg-1",
            "error_type": "RuntimeError",
        },
    )


# --- Tests for previously uncovered lines ---


def test_safety_config_client_fetch_raises_when_config_profile_is_none():
    """Line 134: config_profile is None but not_modified is False."""
    payload = {"configProfile": None}
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
    ):
        with pytest.raises(
            SafetyConfigFetchError,
            match="Safety config payload did not include config_profile",
        ):
            client.fetch("")


def test_safety_config_client_fetch_reraises_safety_config_fetch_error():
    """Line 154: except SafetyConfigFetchError: raise (re-raise path)."""
    # Trigger SafetyConfigFetchError from parse_sdk_config_response so it
    # hits the inner try/except and re-raises without wrapping.
    payload = {"configProfile": None}
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )
    # parse_sdk_config_response itself won't raise SafetyConfigFetchError,
    # but the code on line 134 does. We already test that above. To confirm
    # the re-raise path (line 154) specifically, we mock parse_sdk_config_response
    # to raise SafetyConfigFetchError directly and verify it is NOT wrapped.
    with (
        mock.patch(
            "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload).encode("utf-8")),
        ),
        mock.patch(
            "fortifyroot._internal.safety.runtime.parse_sdk_config_response",
            side_effect=SafetyConfigFetchError("custom error from parse"),
        ),
    ):
        with pytest.raises(SafetyConfigFetchError, match="custom error from parse"):
            client.fetch("")


def test_safety_stream_factory_returns_none_when_snapshot_is_none():
    """Line 193: SafetyStreamFactory returns None when no snapshot."""
    store = SafetySnapshotStore()
    factory = SafetyStreamFactory(store, stream_holdback_chars=128)
    ctx = mock.Mock()
    assert factory(ctx) is None


def test_safety_stream_factory_returns_none_when_snapshot_disabled():
    """Line 193: SafetyStreamFactory returns None when snapshot.enabled is False."""
    store = SafetySnapshotStore()
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
                        enabled=True,
                        matcher=RegexMatcher(pattern=r".+"),
                    ),
                ),
            ),
        )
    )
    store.set(snapshot)
    factory = SafetyStreamFactory(store, stream_holdback_chars=128)
    ctx = mock.Mock()
    assert factory(ctx) is None


def test_safety_stream_factory_returns_none_when_snapshot_has_no_rules():
    """Line 193: SafetyStreamFactory returns None when snapshot has no rules."""
    store = SafetySnapshotStore()
    snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
            safety=SafetyConfig(enabled=True, default_action="MASK", rules=()),
        )
    )
    store.set(snapshot)
    factory = SafetyStreamFactory(store, stream_holdback_chars=128)
    ctx = mock.Mock()
    assert factory(ctx) is None


def test_refresh_once_returns_early_on_not_modified():
    """Line 271: _refresh_once returns early when result.not_modified is True."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    initial_snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
            safety=SafetyConfig(enabled=True, default_action="MASK", rules=()),
        )
    )
    runtime._snapshot_store.set(initial_snapshot)

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

    # Snapshot should be unchanged (not cleared)
    assert runtime._snapshot_store.get() is initial_snapshot


def test_refresh_once_returns_early_when_snapshot_is_none_and_not_not_modified():
    """Line 273: _refresh_once returns early when result.snapshot is None and not not_modified."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    initial_snapshot = compile_snapshot(
        ConfigProfile(
            config_profile_id="cfg-1",
            version=1,
            etag="etag-1",
            safety=SafetyConfig(enabled=True, default_action="MASK", rules=()),
        )
    )
    runtime._snapshot_store.set(initial_snapshot)

    with mock.patch.object(
        runtime._client,
        "fetch",
        return_value=SafetyFetchResult(
            snapshot=None,
            not_modified=False,
            has_rule_definitions=False,
            has_enabled_rule_definitions=False,
        ),
    ):
        runtime._refresh_once()

    # Snapshot should be unchanged (not cleared)
    assert runtime._snapshot_store.get() is initial_snapshot


def test_maybe_warn_about_snapshot_returns_early_when_snapshot_is_none():
    """Line 281: _maybe_warn_about_snapshot returns early when snapshot is None."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    result = SafetyFetchResult(
        snapshot=None,
        not_modified=False,
        has_rule_definitions=False,
        has_enabled_rule_definitions=False,
    )
    # Should not raise or log anything; just return
    runtime._maybe_warn_about_snapshot(result)
    assert not runtime._warned_no_rules
    assert not runtime._warned_no_enabled_rules


def test_same_configuration_returns_true_for_matching_config():
    """Line 307: same_configuration returns True when all params match."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    assert runtime.same_configuration(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    ) is True


def test_same_configuration_returns_false_for_different_config():
    """Line 307: same_configuration returns False when params differ."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    assert runtime.same_configuration(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-2",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    ) is False


def test_normalize_api_endpoint_returns_empty_for_empty_input():
    """Line 323: _normalize_api_endpoint returns '' for empty string."""
    assert _normalize_api_endpoint("") == ""
    assert _normalize_api_endpoint("  ") == ""


def test_normalize_api_endpoint_returns_stripped_raw_when_no_scheme():
    """Line 326: _normalize_api_endpoint returns raw.rstrip('/') when no scheme/netloc."""
    assert _normalize_api_endpoint("just-a-host/") == "just-a-host"
    assert _normalize_api_endpoint("some-path/trailing/") == "some-path/trailing"


def test_is_fortifyroot_api_endpoint_returns_false_when_host_is_none():
    """Line 339: _is_fortifyroot_api_endpoint returns False when host is None."""
    # A URL with no host (e.g. just a scheme) will have hostname=None
    assert _is_fortifyroot_api_endpoint("https://") is False
    assert _is_fortifyroot_api_endpoint("") is False


def test_concurrent_poll_and_handler_is_thread_safe():
    """D-27: Prove the immutable snapshot + lock pattern is thread-safe under
    concurrent writer/reader pressure."""
    store = SafetySnapshotStore()
    errors: list[str] = []
    duration = 0.5

    def _make_snapshot(version: int) -> "CompiledSafetySnapshot":
        from fortifyroot._internal.safety.engine import compile_snapshot as _compile

        return _compile(
            ConfigProfile(
                config_profile_id="cfg-1",
                version=version,
                etag=f"etag-{version}",
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

    # Seed the store so readers never see None before the writer starts.
    store.set(_make_snapshot(0))

    stop = threading.Event()

    def writer():
        v = 1
        while not stop.is_set():
            store.set(_make_snapshot(v))
            v += 1

    def reader(index: int):
        while not stop.is_set():
            snapshot = store.get()
            if snapshot is None:
                errors.append(f"reader-{index}: got None snapshot")
                continue
            try:
                snapshot.evaluate_text("reach me at jane@acme.com")
            except Exception as exc:
                errors.append(f"reader-{index}: {exc}")

    threads: list[threading.Thread] = []
    threads.append(threading.Thread(target=writer, daemon=True))
    for i in range(4):
        threads.append(threading.Thread(target=reader, args=(i,), daemon=True))

    for t in threads:
        t.start()

    time.sleep(duration)
    stop.set()

    for t in threads:
        t.join(timeout=2.0)

    assert errors == [], f"Thread-safety errors: {errors}"


def test_safety_config_client_fetch_raises_on_malformed_json_response():
    """D-28: Non-JSON response bytes should raise SafetyConfigFetchError."""
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )

    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        return_value=_FakeHTTPResponse(b"<html>error</html>"),
    ):
        with pytest.raises(SafetyConfigFetchError, match="Safety config fetch failed"):
            client.fetch("")


# ---- D-19: Unbounded response body read ----


def test_max_config_response_bytes_constant_exists():
    """D-19: MAX_CONFIG_RESPONSE_BYTES should be defined as 1MB."""
    from fortifyroot._internal.safety.runtime import MAX_CONFIG_RESPONSE_BYTES

    assert MAX_CONFIG_RESPONSE_BYTES == 1_048_576


def test_safety_config_client_fetch_raises_on_oversized_response():
    """D-19: Fetch should raise SafetyConfigFetchError if response exceeds 1MB."""
    client = SafetyConfigClient(
        "https://api.fortifyroot.com",
        "fr-key",
        "cfg-1",
    )

    # Create a response body larger than MAX_CONFIG_RESPONSE_BYTES
    from fortifyroot._internal.safety.runtime import MAX_CONFIG_RESPONSE_BYTES

    oversized_body = b"x" * (MAX_CONFIG_RESPONSE_BYTES + 100)

    with mock.patch(
        "fortifyroot._internal.safety.runtime.urllib.request.urlopen",
        return_value=_FakeHTTPResponse(oversized_body),
    ):
        with pytest.raises(SafetyConfigFetchError, match="exceeded"):
            client.fetch("")


def test_safety_config_client_fetch_reads_bounded_response():
    """D-19: Fetch should work normally for responses under 1MB."""
    payload = {
        "configProfile": {
            "id": "cfg-1",
            "version": 1,
            "etag": "etag-1",
            "config": {
                "safetyConfig": {
                    "enabled": True,
                    "defaultAction": "MASK",
                    "rules": [],
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


# ---- D-24: Case-sensitive endpoint comparison ----


def test_same_configuration_normalizes_endpoint_case():
    """D-24: same_configuration should normalize endpoints for comparison."""
    runtime = SafetyRuntime(
        api_endpoint="HTTPS://API.FORTIFYROOT.COM",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )

    # Same endpoint but with different casing
    assert runtime.same_configuration(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    ) is True


def test_same_configuration_normalizes_trailing_slash():
    """D-24: same_configuration should normalize trailing slashes."""
    runtime = SafetyRuntime(
        api_endpoint="https://api.fortifyroot.com/",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )

    assert runtime.same_configuration(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    ) is True


def test_configure_global_safety_runtime_normalizes_endpoint_before_same_configuration():
    """D-24: configure_global_safety_runtime should use _normalize_api_endpoint."""
    existing_runtime = mock.Mock()
    existing_runtime.same_configuration.return_value = True

    with (
        mock.patch.object(safety_runtime, "_GLOBAL_SAFETY_RUNTIME", existing_runtime),
        mock.patch("fortifyroot._internal.safety.runtime.SafetyRuntime") as runtime_cls,
    ):
        configure_global_safety_runtime(
            enabled=True,
            api_endpoint="HTTPS://API.FORTIFYROOT.COM/",
            api_key="fr-key",
            config_profile_id="cfg-1",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

    # Verify that same_configuration was called with normalized endpoint
    existing_runtime.same_configuration.assert_called_once_with(
        api_endpoint="https://api.fortifyroot.com",
        api_key="fr-key",
        config_profile_id="cfg-1",
        poll_interval_seconds=60,
        stream_holdback_chars=128,
    )
    runtime_cls.assert_not_called()


def test_safety_config_client_normalizes_base_url():
    """D-24: SafetyConfigClient should normalize base_url in __init__."""
    client = SafetyConfigClient(
        "HTTPS://API.FORTIFYROOT.COM/",
        "fr-key",
        "cfg-1",
    )
    assert client._base_url == "https://api.fortifyroot.com"
