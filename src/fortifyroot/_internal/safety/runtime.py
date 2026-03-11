"""Safety runtime bootstrap, polling, and handler registration."""

from __future__ import annotations

import json
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

    def fetch(self, current_etag: str) -> CompiledSafetySnapshot | None:
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
            logger.warning("Safety config fetch failed with HTTP status %s", exc.code)
            return None
        except Exception:
            logger.warning("Safety config fetch failed", exc_info=True)
            return None

        try:
            parsed = parse_sdk_config_response(payload)
            if parsed.not_modified or parsed.config_profile is None:
                return None
            return compile_snapshot(parsed.config_profile)
        except Exception:
            logger.warning("Safety config payload could not be parsed or compiled", exc_info=True)
            return None


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
        handler = SafetyHandler(self._snapshot_store)
        self._prompt_handler = handler
        self._completion_handler = handler

    def start(self) -> None:
        register_prompt_safety_handler(self._prompt_handler)
        register_completion_safety_handler(self._completion_handler)
        self._refresh_once()
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._snapshot_store.set(None)
        clear_safety_handlers()

    def _poll_loop(self) -> None:
        while not self._stop_event.wait(self._poll_interval_seconds):
            self._refresh_once()

    def _refresh_once(self) -> None:
        current = self._snapshot_store.get()
        current_etag = current.etag if current is not None else ""
        snapshot = self._client.fetch(current_etag)
        if snapshot is not None:
            self._snapshot_store.set(snapshot)


_GLOBAL_SAFETY_RUNTIME: SafetyRuntime | None = None
_GLOBAL_RUNTIME_LOCK = threading.Lock()


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

        if (
            not enabled
            or not api_key
            or not config_profile_id
            or poll_interval_seconds <= 0
        ):
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
