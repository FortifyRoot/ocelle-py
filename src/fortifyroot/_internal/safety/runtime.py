"""Safety runtime bootstrap, polling, and handler registration."""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import random
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from opentelemetry.metrics import get_meter

from fortifyroot._internal.constants import (
    FORTIFYROOT_SDK_LANGUAGE,
    FORTIFYROOT_SDK_LANGUAGE_HEADER,
    FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER,
    FORTIFYROOT_SDK_VERSION_HEADER,
)
from fortifyroot._internal.safety.engine import CompiledSafetySnapshot, compile_snapshot
from fortifyroot._internal.safety.parser import parse_sdk_config_response
from fortifyroot._internal.safety.streaming import CompletionSafetyStream
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    clear_safety_handlers,
    register_completion_safety_handler,
    register_completion_safety_stream_factory,
    register_prompt_safety_handler,
)
from fortifyroot.version import __version__

logger = logging.getLogger(__name__)
_METER = get_meter("fortifyroot.safety")
_CONFIG_FETCH_COUNTER = _METER.create_counter(
    "fortifyroot.safety.config_fetches",
    description="Number of FortifyRoot safety config fetch attempts.",
)
_CONFIG_FETCH_FAILURE_COUNTER = _METER.create_counter(
    "fortifyroot.safety.config_fetch_failures",
    description="Number of FortifyRoot safety config fetch failures.",
)

MAX_CONFIG_RESPONSE_BYTES = 1_048_576  # 1 MB
DEFAULT_CONFIG_POLL_INTERVAL_SECONDS = 60
DEFAULT_STREAM_HOLDBACK_CHARS = 128
API_KEY_HEADER = "X-API-Key"
REQUEST_TIMEOUT_SECONDS = 5
FORTIFYROOT_API_BASE_URL = "https://api.fortifyroot.com"
LOCAL_FORTIFYROOT_DEV_HOSTS = {"localhost", "host.docker.internal"}
FORTIFYROOT_API_HOST_SUFFIX = "api.fortifyroot.com"
AUTH_HTTP_STATUS_CODES = {401, 403}


class SafetyConfigFetchError(RuntimeError):
    """Raised when the backend safety config fetch cannot be completed."""

    def __init__(
        self,
        message: str,
        *,
        auth_status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.auth_status_code = auth_status_code


@dataclass(frozen=True, slots=True)
class SafetyFetchResult:
    snapshot: CompiledSafetySnapshot | None
    not_modified: bool
    has_rule_definitions: bool
    has_enabled_rule_definitions: bool


@dataclass
class SafetySnapshotStore:
    _snapshot: CompiledSafetySnapshot | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def get(self) -> CompiledSafetySnapshot | None:
        with self._lock:
            return self._snapshot

    def set(self, snapshot: CompiledSafetySnapshot | None) -> None:
        with self._lock:
            self._snapshot = snapshot


class SafetyConfigClient:
    def __init__(self, base_url: str, api_key: str, config_profile_id: str) -> None:
        self._base_url = _normalize_api_endpoint(base_url)
        self._api_key = api_key
        self._config_profile_id = config_profile_id

    def fetch(self, current_etag: str) -> SafetyFetchResult:
        fetch_attributes = {
            "fortifyroot.safety.config_profile_id": self._config_profile_id,
        }
        params = {"sdk_version": __version__}
        if current_etag:
            params["current_etag"] = current_etag
        query = urllib.parse.urlencode(params)
        path = urllib.parse.quote(self._config_profile_id, safe="")
        url = f"{self._base_url}/v1/sdk/config/{path}?{query}"
        request = urllib.request.Request(
            url,
            headers={
                API_KEY_HEADER: self._api_key,
                FORTIFYROOT_SDK_VERSION_HEADER: __version__,
                FORTIFYROOT_SDK_LANGUAGE_HEADER: FORTIFYROOT_SDK_LANGUAGE,
                FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER: platform.python_version(),
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                body = response.read(MAX_CONFIG_RESPONSE_BYTES)
                if response.read(1):
                    raise SafetyConfigFetchError(
                        f"Safety config response exceeded {MAX_CONFIG_RESPONSE_BYTES} bytes"
                    )
                payload = json.loads(body.decode("utf-8"))
        except SafetyConfigFetchError:
            raise
        except urllib.error.HTTPError as exc:
            _CONFIG_FETCH_COUNTER.add(1, attributes={**fetch_attributes, "result": "failure"})
            _CONFIG_FETCH_FAILURE_COUNTER.add(
                1,
                attributes={**fetch_attributes, "error_type": "http_error"},
            )
            if exc.code in AUTH_HTTP_STATUS_CODES:
                raise SafetyConfigFetchError(
                    f"FortifyRoot SDK auth warning: safety config fetch was rejected with HTTP status {exc.code}. "
                    "The SDK API key may be invalid, revoked, deleted, or missing permissions. "
                    "Safety config updates will not be applied until a valid SDK API key is configured.",
                    auth_status_code=exc.code,
                ) from exc
            raise SafetyConfigFetchError(
                f"Safety config fetch failed with HTTP status {exc.code}"
            ) from exc
        except Exception as exc:
            _CONFIG_FETCH_COUNTER.add(1, attributes={**fetch_attributes, "result": "failure"})
            _CONFIG_FETCH_FAILURE_COUNTER.add(
                1,
                attributes={**fetch_attributes, "error_type": exc.__class__.__name__},
            )
            raise SafetyConfigFetchError("Safety config fetch failed") from exc

        try:
            parsed = parse_sdk_config_response(payload)
            if parsed.not_modified:
                _CONFIG_FETCH_COUNTER.add(
                    1,
                    attributes={**fetch_attributes, "result": "not_modified"},
                )
                return SafetyFetchResult(
                    snapshot=None,
                    not_modified=True,
                    has_rule_definitions=False,
                    has_enabled_rule_definitions=False,
                )
            if parsed.config_profile is None:
                raise SafetyConfigFetchError(
                    "Safety config payload did not include config_profile"
                )

            snapshot = compile_snapshot(parsed.config_profile)
            has_rule_definitions = bool(parsed.config_profile.safety.rules)
            has_enabled_rule_definitions = parsed.config_profile.safety.enabled and any(
                rule.enabled for rule in parsed.config_profile.safety.rules
            )
            _CONFIG_FETCH_COUNTER.add(
                1,
                attributes={**fetch_attributes, "result": "success"},
            )
            return SafetyFetchResult(
                snapshot=snapshot,
                not_modified=False,
                has_rule_definitions=has_rule_definitions,
                has_enabled_rule_definitions=has_enabled_rule_definitions,
            )
        except SafetyConfigFetchError:
            raise
        except Exception as exc:
            _CONFIG_FETCH_COUNTER.add(1, attributes={**fetch_attributes, "result": "failure"})
            _CONFIG_FETCH_FAILURE_COUNTER.add(
                1,
                attributes={**fetch_attributes, "error_type": exc.__class__.__name__},
            )
            raise SafetyConfigFetchError(
                "Safety config payload could not be parsed or compiled"
            ) from exc


class SafetyHandler:
    def __init__(self, snapshot_store: SafetySnapshotStore) -> None:
        self._snapshot_store = snapshot_store

    def __call__(self, context):
        snapshot = self._snapshot_store.get()
        if snapshot is None:
            return None
        return snapshot.evaluate_text(
            context.text,
            metric_attributes=_metric_attributes_from_context(context),
        )


class SafetyStreamFactory:
    def __init__(
        self,
        snapshot_store: SafetySnapshotStore,
        stream_holdback_chars: int,
    ) -> None:
        self._snapshot_store = snapshot_store
        self._stream_holdback_chars = stream_holdback_chars

    def __call__(self, context):
        snapshot = self._snapshot_store.get()
        if (
            snapshot is None
            or not snapshot.enabled
            or not snapshot.rules
        ):
            return None
        return CompletionSafetyStream(
            snapshot=snapshot,
            holdback_chars=self._stream_holdback_chars,
            metric_attributes=_metric_attributes_from_context(context),
        )


def _metric_attributes_from_context(context) -> dict[str, str]:
    metadata = getattr(context, "metadata", None) or {}
    attrs: dict[str, str] = {}
    provider = getattr(context, "provider", None)
    if provider is not None and str(provider).strip():
        attrs["gen_ai.system"] = str(provider).strip()
    for key in ("gen_ai.system", "gen_ai.request.model", "gen_ai.response.model"):
        value = metadata.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            attrs[key] = text
    return attrs


class SafetyRuntime:
    def __init__(
        self,
        *,
        api_endpoint: str,
        api_key: str,
        config_profile_id: str,
        poll_interval_seconds: int,
        stream_holdback_chars: int,
    ) -> None:
        self._snapshot_store = SafetySnapshotStore()
        self._client = SafetyConfigClient(api_endpoint, api_key, config_profile_id)
        self._poll_interval_seconds = poll_interval_seconds
        self._stream_holdback_chars = stream_holdback_chars
        self._stop_event = threading.Event()
        self._warning_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="fortifyroot-safety-poller",
            daemon=True,
        )
        self._warned_no_rules = False
        self._warned_no_enabled_rules = False
        self._warned_auth_fetch_status_codes: set[int] = set()
        handler = SafetyHandler(self._snapshot_store)
        self._prompt_handler = handler
        self._completion_handler = handler
        self._completion_stream_factory = SafetyStreamFactory(
            self._snapshot_store,
            stream_holdback_chars,
        )

    def start(self) -> None:
        self._refresh_once(initial=True)
        register_prompt_safety_handler(self._prompt_handler)
        register_completion_safety_handler(self._completion_handler)
        register_completion_safety_stream_factory(self._completion_stream_factory)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._snapshot_store.set(None)
        clear_safety_handlers()

    def _poll_loop(self) -> None:
        while True:
            wait_seconds = self._poll_interval_seconds + random.uniform(
                0,
                self._poll_interval_seconds * 0.1,
            )
            if self._stop_event.wait(wait_seconds):
                break
            self._refresh_once(initial=False)

    def _refresh_once(self, *, initial: bool = False) -> None:
        current = self._snapshot_store.get()
        current_etag = current.etag if current is not None else ""
        try:
            result = self._client.fetch(current_etag)
        except SafetyConfigFetchError as exc:
            self._log_fetch_error(exc, initial=initial)
            return

        if result.not_modified:
            return
        if result.snapshot is None:
            return

        self._snapshot_store.set(result.snapshot)
        self._maybe_warn_about_snapshot(result)

    def _log_fetch_error(
        self,
        exc: SafetyConfigFetchError,
        *,
        initial: bool,
    ) -> None:
        if exc.auth_status_code is not None:
            with self._warning_lock:
                already_warned = (
                    exc.auth_status_code in self._warned_auth_fetch_status_codes
                )
                if not already_warned:
                    self._warned_auth_fetch_status_codes.add(exc.auth_status_code)
            if already_warned:
                logger.debug("%s", exc)
                return

        if initial:
            logger.warning(
                "Initial FortifyRoot safety config fetch failed; starting with empty safety snapshot: %s",
                exc,
            )
            return
        logger.warning("%s", exc)

    def _maybe_warn_about_snapshot(self, result: SafetyFetchResult) -> None:
        snapshot = result.snapshot
        if snapshot is None:
            return

        with self._warning_lock:
            if not result.has_rule_definitions:
                if not self._warned_no_rules:
                    logger.warning("no safety rules are defined")
                    self._warned_no_rules = True
                return

            if (
                not result.has_enabled_rule_definitions
                or not snapshot.enabled
                or not snapshot.rules
            ) and not self._warned_no_enabled_rules:
                logger.warning("could not find any enabled safety configs")
                self._warned_no_enabled_rules = True

    def same_configuration(
        self,
        *,
        api_endpoint: str,
        api_key: str,
        config_profile_id: str,
        poll_interval_seconds: int,
        stream_holdback_chars: int,
    ) -> bool:
        return (
            self._client._base_url == _normalize_api_endpoint(api_endpoint)
            and self._client._api_key == api_key
            and self._client._config_profile_id == config_profile_id
            and self._poll_interval_seconds == poll_interval_seconds
            and self._stream_holdback_chars == stream_holdback_chars
        )


_GLOBAL_SAFETY_RUNTIME: SafetyRuntime | None = None
_GLOBAL_RUNTIME_LOCK = threading.Lock()


def _normalize_api_endpoint(api_endpoint: str) -> str:
    raw = (api_endpoint or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw.rstrip("/")
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, "", "")
    )


def _is_fortifyroot_api_endpoint(api_endpoint: str) -> bool:
    normalized = _normalize_api_endpoint(api_endpoint)
    parsed = urllib.parse.urlsplit(normalized)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        return False
    if host in LOCAL_FORTIFYROOT_DEV_HOSTS:
        return scheme in {"http", "https"}
    try:
        return scheme in {"http", "https"} and ipaddress.ip_address(host).is_loopback
    except ValueError:
        return scheme == "https" and host.endswith(FORTIFYROOT_API_HOST_SUFFIX)


def configure_global_safety_runtime(
    *,
    enabled: bool,
    api_endpoint: str,
    api_key: str | None,
    config_profile_id: str | None,
    poll_interval_seconds: int,
    stream_holdback_chars: int,
) -> None:
    global _GLOBAL_SAFETY_RUNTIME
    with _GLOBAL_RUNTIME_LOCK:
        normalized_endpoint = _normalize_api_endpoint(api_endpoint)
        if _GLOBAL_SAFETY_RUNTIME is not None:
            if enabled and _GLOBAL_SAFETY_RUNTIME.same_configuration(
                api_endpoint=normalized_endpoint,
                api_key=api_key or "",
                config_profile_id=config_profile_id or "",
                poll_interval_seconds=poll_interval_seconds,
                stream_holdback_chars=stream_holdback_chars,
            ):
                return
            _GLOBAL_SAFETY_RUNTIME.stop()
            _GLOBAL_SAFETY_RUNTIME = None

        if not enabled:
            clear_safety_handlers()
            return

        if not _is_fortifyroot_api_endpoint(api_endpoint):
            logger.warning(
                "Skipping FortifyRoot safety initialization because api_endpoint is not a trusted FortifyRoot API host or local FortifyRoot dev endpoint"
            )
            clear_safety_handlers()
            return

        if not api_key or not config_profile_id or poll_interval_seconds <= 0:
            logger.warning(
                "Skipping FortifyRoot safety initialization because api_key, config_profile_id, and a positive poll interval are required"
            )
            clear_safety_handlers()
            return

        runtime = SafetyRuntime(
            api_endpoint=normalized_endpoint,
            api_key=api_key,
            config_profile_id=config_profile_id,
            poll_interval_seconds=poll_interval_seconds,
            stream_holdback_chars=stream_holdback_chars,
        )
        runtime.start()
        _GLOBAL_SAFETY_RUNTIME = runtime


def shutdown_global_safety_runtime() -> None:
    global _GLOBAL_SAFETY_RUNTIME
    with _GLOBAL_RUNTIME_LOCK:
        if _GLOBAL_SAFETY_RUNTIME is not None:
            _GLOBAL_SAFETY_RUNTIME.stop()
            _GLOBAL_SAFETY_RUNTIME = None
        clear_safety_handlers()
