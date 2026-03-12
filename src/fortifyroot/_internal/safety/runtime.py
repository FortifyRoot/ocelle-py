"""Safety runtime bootstrap, polling, and handler registration."""

from __future__ import annotations

import json
import ipaddress
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from fortifyroot._internal.safety.engine import CompiledSafetySnapshot, compile_snapshot
from fortifyroot._internal.safety.parser import parse_sdk_config_response
from fortifyroot._vendor.opentelemetry.instrumentation.fortifyroot import (
    clear_safety_handlers,
    register_completion_safety_handler,
    register_prompt_safety_handler,
)
from fortifyroot.version import __version__

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_POLL_INTERVAL_SECONDS = 60
SDK_VERSION_HEADER = "X-FortifyRoot-SDK-Version"
AUTHORIZATION_HEADER = "Authorization"
REQUEST_TIMEOUT_SECONDS = 5
FORTIFYROOT_API_BASE_URL = "https://api.fortifyroot.com"
LOCAL_FORTIFYROOT_DEV_HOSTS = {"localhost", "host.docker.internal"}
FORTIFYROOT_API_HOST_SUFFIX = "api.fortifyroot.com"


class SafetyConfigFetchError(RuntimeError):
    """Raised when the backend safety config fetch cannot be completed."""


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
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._config_profile_id = config_profile_id

    def fetch(self, current_etag: str) -> SafetyFetchResult:
        params = {"sdk_version": __version__}
        if current_etag:
            params["current_etag"] = current_etag
        query = urllib.parse.urlencode(params)
        path = urllib.parse.quote(self._config_profile_id, safe="")
        url = f"{self._base_url}/v1/sdk/config/{path}?{query}"
        request = urllib.request.Request(
            url,
            headers={
                AUTHORIZATION_HEADER: f"Bearer {self._api_key}",
                SDK_VERSION_HEADER: __version__,
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SafetyConfigFetchError(
                f"Safety config fetch failed with HTTP status {exc.code}"
            ) from exc
        except Exception as exc:
            raise SafetyConfigFetchError("Safety config fetch failed") from exc

        try:
            parsed = parse_sdk_config_response(payload)
            if parsed.not_modified:
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
            return SafetyFetchResult(
                snapshot=snapshot,
                not_modified=False,
                has_rule_definitions=has_rule_definitions,
                has_enabled_rule_definitions=has_enabled_rule_definitions,
            )
        except SafetyConfigFetchError:
            raise
        except Exception as exc:
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
        return snapshot.evaluate_text(context.text)


class SafetyRuntime:
    def __init__(
        self,
        *,
        api_endpoint: str,
        api_key: str,
        config_profile_id: str,
        poll_interval_seconds: int,
    ) -> None:
        self._snapshot_store = SafetySnapshotStore()
        self._client = SafetyConfigClient(api_endpoint, api_key, config_profile_id)
        self._poll_interval_seconds = poll_interval_seconds
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="fortifyroot-safety-poller",
            daemon=True,
        )
        self._warned_no_rules = False
        self._warned_no_enabled_rules = False
        handler = SafetyHandler(self._snapshot_store)
        self._prompt_handler = handler
        self._completion_handler = handler

    def start(self) -> None:
        self._refresh_once(initial=True)
        register_prompt_safety_handler(self._prompt_handler)
        register_completion_safety_handler(self._completion_handler)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._snapshot_store.set(None)
        clear_safety_handlers()

    def _poll_loop(self) -> None:
        while not self._stop_event.wait(self._poll_interval_seconds):
            self._refresh_once(initial=False)

    def _refresh_once(self, *, initial: bool = False) -> None:
        current = self._snapshot_store.get()
        current_etag = current.etag if current is not None else ""
        try:
            result = self._client.fetch(current_etag)
        except SafetyConfigFetchError as exc:
            if initial:
                raise RuntimeError("Initial FortifyRoot safety config fetch failed") from exc
            logger.warning("%s", exc)
            return

        if result.not_modified:
            return
        if result.snapshot is None:
            return

        self._snapshot_store.set(result.snapshot)
        self._maybe_warn_about_snapshot(result)

    def _maybe_warn_about_snapshot(self, result: SafetyFetchResult) -> None:
        snapshot = result.snapshot
        if snapshot is None:
            return

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
) -> None:
    global _GLOBAL_SAFETY_RUNTIME
    with _GLOBAL_RUNTIME_LOCK:
        if _GLOBAL_SAFETY_RUNTIME is not None:
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
            api_endpoint=api_endpoint,
            api_key=api_key,
            config_profile_id=config_profile_id,
            poll_interval_seconds=poll_interval_seconds,
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
