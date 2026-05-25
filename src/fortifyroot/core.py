"""Core FortifyRoot SDK functionality.

This module provides the main initialization and configuration functions
for the FortifyRoot SDK, including:
- init(): Initialize the SDK with tracing configuration
- set_association_properties(): Set context properties for traces
- FortifyRootConfig: Fluent API for configuration (builder pattern)
"""

import logging
import os
import platform
import sys
from urllib.parse import urlsplit
from typing import Callable, Dict, List, Optional, Set, TypedDict, cast

from opentelemetry.sdk.trace import SpanProcessor, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.sdk.trace.sampling import Sampler
from opentelemetry.sdk.metrics.export import MetricExporter
from opentelemetry.sdk._logs.export import LogExporter
from opentelemetry.propagators.textmap import TextMapPropagator

from fortifyroot._vendor.traceloop.sdk import Traceloop

from fortifyroot._internal.constants import (
    FORTIFYROOT_SDK_LANGUAGE,
    FORTIFYROOT_SDK_LANGUAGE_HEADER,
    FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER,
    FORTIFYROOT_SDK_VERSION_ATTRIBUTE,
    FORTIFYROOT_SDK_VERSION_HEADER,
)
from fortifyroot._internal.env_mapping import (
    FORTIFYROOT_ALLOW_UDF_DETECTORS,
    FORTIFYROOT_APP_NAME,
    FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS,
    FORTIFYROOT_CONFIG_PROFILE_ID,
    FORTIFYROOT_DISABLE_BATCH,
    FORTIFYROOT_ENABLED,
    FORTIFYROOT_ENRICH_METRICS,
    FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS,
)
from fortifyroot._internal.synthetic_logs import (
    compose_span_postprocess_callbacks,
    emit_synthetic_span_log,
)
from fortifyroot._internal.safety.engine import set_udf_detectors_enabled
from fortifyroot._internal.safety.runtime import (
    DEFAULT_CONFIG_POLL_INTERVAL_SECONDS,
    DEFAULT_STREAM_HOLDBACK_CHARS,
    configure_global_safety_runtime,
)
from fortifyroot.instruments import Instruments, _convert_to_tl_instruments
from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor
from fortifyroot.version import __version__


logger = logging.getLogger(__name__)

# Default API endpoint for FortifyRoot
DEFAULT_API_ENDPOINT = "https://api.fortifyroot.com"
AUTHORIZATION_HEADER = "Authorization"
SDK_METADATA_HEADERS = {
    FORTIFYROOT_SDK_VERSION_HEADER.lower(),
    FORTIFYROOT_SDK_LANGUAGE_HEADER.lower(),
    FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER.lower(),
}


def _resolve_api_endpoint(value: str) -> str:
    """Resolve the API endpoint from explicit arg or FortifyRoot env."""
    if value != DEFAULT_API_ENDPOINT:
        return value

    env_value = os.getenv("FORTIFYROOT_BASE_URL", "").strip()
    return env_value or value


def _resolve_config_poll_interval_seconds(value: Optional[int]) -> int:
    """Resolve the safety config poll interval from arg/env/defaults."""
    if value is not None:
        return value

    raw_value = os.getenv(FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS, "")
    if not raw_value.strip():
        return DEFAULT_CONFIG_POLL_INTERVAL_SECONDS

    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_CONFIG_POLL_INTERVAL_SECONDS


def _resolve_stream_holdback_chars(value: Optional[int]) -> int:
    """Resolve the streaming completion holdback size from arg/env/defaults."""
    if value is not None:
        resolved = max(int(value), 1)
    else:
        raw_value = os.getenv(FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS, "")
        if not raw_value.strip():
            resolved = DEFAULT_STREAM_HOLDBACK_CHARS
        else:
            try:
                resolved = max(int(raw_value), 1)
            except (TypeError, ValueError):
                resolved = DEFAULT_STREAM_HOLDBACK_CHARS

    if resolved < 16:
        logger.warning(
            "stream_holdback_chars=%d is below the minimum effective threshold; using 16",
            resolved,
        )
        resolved = 16

    return resolved


def _resolve_api_key(value: Optional[str]) -> Optional[str]:
    """Normalize API keys so blank values behave like missing values."""
    if value is None:
        return None

    resolved = value.strip()
    return resolved or None


def _is_enabled_from_env(env_var: str, default: bool) -> bool:
    """Resolve boolean FortifyRoot env flags at init time."""
    fallback = "true" if default else "false"
    return (os.getenv(env_var) or fallback).lower() == "true"


def _has_authorization_header(headers: Dict[str, str]) -> bool:
    """Check whether explicit headers already provide authorization."""
    return any(
        key.lower() == AUTHORIZATION_HEADER.lower()
        and value is not None
        and str(value).strip()
        for key, value in headers.items()
    )


def _get_authorization_header(headers: Dict[str, str]) -> Optional[tuple[str, str]]:
    """Return the first explicit Authorization header, preserving its original key."""
    for key, value in headers.items():
        if key.lower() == AUTHORIZATION_HEADER.lower() and str(value).strip():
            return key, str(value)
    return None


def _sdk_metadata_headers() -> Dict[str, str]:
    """Return SDK metadata headers for FortifyRoot backend observability."""
    return {
        FORTIFYROOT_SDK_VERSION_HEADER: __version__,
        FORTIFYROOT_SDK_LANGUAGE_HEADER: FORTIFYROOT_SDK_LANGUAGE,
        FORTIFYROOT_SDK_LANGUAGE_VERSION_HEADER: platform.python_version(),
    }


def _set_header_case_insensitive(
    headers: Dict[str, str],
    key: str,
    value: str,
) -> None:
    """Set a header while removing stale variants with different casing."""
    for existing_key in list(headers):
        if existing_key.lower() == key.lower() and existing_key != key:
            del headers[existing_key]
    headers[key] = value


def _with_sdk_metadata_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Attach SDK-owned metadata headers, overriding stale caller values."""
    resolved = dict(headers)
    for key, value in _sdk_metadata_headers().items():
        _set_header_case_insensitive(resolved, key, value)
    return resolved


def _without_sdk_metadata_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Remove SDK-owned metadata headers from a header set."""
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in SDK_METADATA_HEADERS
    }


def _resolve_export_headers(
    headers: Optional[Dict[str, str]],
    api_key: Optional[str],
    *,
    include_sdk_metadata: bool,
) -> Dict[str, str]:
    """Add bearer auth from the API key unless explicit auth headers are provided."""
    resolved = dict(headers or {})
    if api_key and not _has_authorization_header(resolved):
        resolved[AUTHORIZATION_HEADER] = f"Bearer {api_key}"
    if include_sdk_metadata:
        resolved = _with_sdk_metadata_headers(resolved)
    return resolved


def _resolve_signal_headers(
    headers: Optional[Dict[str, str]],
    fallback_headers: Dict[str, str],
    api_key: Optional[str],
    *,
    include_sdk_metadata: bool,
) -> Dict[str, str]:
    """Resolve signal-specific headers, inheriting trace auth by default."""
    if headers is None:
        resolved = dict(fallback_headers)
        if include_sdk_metadata:
            resolved = _with_sdk_metadata_headers(resolved)
        else:
            resolved = _without_sdk_metadata_headers(resolved)
        return resolved

    resolved = dict(headers)
    if not _has_authorization_header(resolved):
        inherited_authorization = _get_authorization_header(fallback_headers)
        if inherited_authorization is not None:
            key, value = inherited_authorization
            resolved[key] = value
    return _resolve_export_headers(
        resolved,
        api_key,
        include_sdk_metadata=include_sdk_metadata,
    )


def _is_managed_fortifyroot_endpoint(api_endpoint: str) -> bool:
    """Return True for hosted FortifyRoot API endpoints that require FortifyRoot auth."""
    parsed = urlsplit((api_endpoint or "").strip())
    host = (parsed.hostname or "").lower()
    return bool(host) and (host == "fortifyroot.com" or host.endswith(".fortifyroot.com"))


def _resolve_signal_endpoint(env_var: str, fallback_endpoint: str) -> str:
    """Resolve per-signal endpoints, falling back to the main API endpoint."""
    env_value = (os.getenv(env_var) or "").strip()
    return env_value or fallback_endpoint


def _normalize_http_otlp_endpoint(endpoint: str, suffix: str) -> str:
    """Append the OTLP HTTP suffix unless the caller already supplied it."""
    normalized = endpoint.strip().rstrip("/")
    if not normalized.endswith(suffix):
        normalized = f"{normalized}{suffix}"
    return normalized


def _cumulative_preferred_temporality() -> Dict[type, "AggregationTemporality"]:
    """Force CUMULATIVE temporality for Counter / Histogram / ObservableCounter.

    The FortifyRoot managed backend stores customer metrics in Prometheus /
    Grafana Mimir, whose OTLP receiver rejects Counter + Histogram data points
    arriving with DELTA temporality ("invalid temporality and type
    combination"). OpenTelemetry Python's OTLPMetricExporter defaults Counter
    and Histogram to DELTA, so every metric emitted via the SDK's default
    pipeline is silently dropped at the Prom ingester. Pinning these
    instruments to CUMULATIVE makes the on-wire temporality match what the
    backend's time-series store requires. UpDownCounter / ObservableGauge
    stay at their library defaults (CUMULATIVE) because those are already
    correct.
    """
    from opentelemetry.sdk.metrics import (
        Counter,
        Histogram,
        ObservableCounter,
        ObservableGauge,
        ObservableUpDownCounter,
        UpDownCounter,
    )
    from opentelemetry.sdk.metrics.export import AggregationTemporality

    return {
        Counter: AggregationTemporality.CUMULATIVE,
        Histogram: AggregationTemporality.CUMULATIVE,
        ObservableCounter: AggregationTemporality.CUMULATIVE,
        UpDownCounter: AggregationTemporality.CUMULATIVE,
        ObservableUpDownCounter: AggregationTemporality.CUMULATIVE,
        ObservableGauge: AggregationTemporality.CUMULATIVE,
    }


def _init_default_metrics_exporter(
    endpoint: str,
    headers: Dict[str, str],
) -> MetricExporter:
    """Create a scheme-aware default OTLP metrics exporter."""
    parsed = urlsplit(endpoint.strip())
    preferred_temporality = _cumulative_preferred_temporality()

    match parsed.scheme.lower():
        case "http" | "https":
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter as HTTPMetricExporter,
            )

            return cast(
                MetricExporter,
                HTTPMetricExporter(
                    endpoint=_normalize_http_otlp_endpoint(endpoint, "/v1/metrics"),
                    headers=headers,
                    preferred_temporality=preferred_temporality,
                ),
            )
        case "grpc":
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter as GRPCMetricExporter,
            )

            return cast(
                MetricExporter,
                GRPCMetricExporter(
                    endpoint=parsed.netloc,
                    headers=headers,
                    insecure=True,
                    preferred_temporality=preferred_temporality,
                ),
            )
        case "grpcs":
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter as GRPCMetricExporter,
            )

            return cast(
                MetricExporter,
                GRPCMetricExporter(
                    endpoint=parsed.netloc,
                    headers=headers,
                    insecure=False,
                    preferred_temporality=preferred_temporality,
                ),
            )
        case _:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter as GRPCMetricExporter,
            )

            return cast(
                MetricExporter,
                GRPCMetricExporter(
                    endpoint=endpoint.strip(),
                    headers=headers,
                    insecure=True,
                    preferred_temporality=preferred_temporality,
                ),
            )


def _init_default_logging_exporter(
    endpoint: str,
    headers: Dict[str, str],
) -> LogExporter:
    """Create a scheme-aware default OTLP logging exporter."""
    parsed = urlsplit(endpoint.strip())

    match parsed.scheme.lower():
        case "http" | "https":
            from opentelemetry.exporter.otlp.proto.http._log_exporter import (
                OTLPLogExporter as HTTPLogExporter,
            )

            return cast(
                LogExporter,
                HTTPLogExporter(
                    endpoint=_normalize_http_otlp_endpoint(endpoint, "/v1/logs"),
                    headers=headers,
                ),
            )
        case "grpc":
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
                OTLPLogExporter as GRPCLogExporter,
            )

            return cast(
                LogExporter,
                GRPCLogExporter(
                    endpoint=parsed.netloc,
                    headers=headers,
                    insecure=True,
                ),
            )
        case "grpcs":
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
                OTLPLogExporter as GRPCLogExporter,
            )

            return cast(
                LogExporter,
                GRPCLogExporter(
                    endpoint=parsed.netloc,
                    headers=headers,
                    insecure=False,
                ),
            )
        case _:
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
                OTLPLogExporter as GRPCLogExporter,
            )

            return cast(
                LogExporter,
                GRPCLogExporter(
                    endpoint=endpoint.strip(),
                    headers=headers,
                    insecure=True,
                ),
            )


def _validate_default_export_auth(
    *,
    enabled: bool,
    exporter: Optional[SpanExporter],
    processors: Optional[List[SpanProcessor]],
    metrics_exporter: Optional[MetricExporter],
    logging_exporter: Optional[LogExporter],
    trace_endpoint: str,
    metrics_endpoint: str,
    logging_endpoint: str,
    trace_headers: Dict[str, str],
    metrics_headers: Dict[str, str],
    logging_headers: Dict[str, str],
) -> None:
    """Fail fast when default FortifyRoot exporters would run without auth."""
    if not enabled or not _is_enabled_from_env("FORTIFYROOT_TRACING_ENABLED", True):
        return

    metrics_enabled = _is_enabled_from_env("FORTIFYROOT_METRICS_ENABLED", True)
    logging_enabled = _is_enabled_from_env("FORTIFYROOT_LOGGING_ENABLED", False)

    missing_signals: List[str] = []
    if (
        exporter is None
        and processors is None
        and _is_managed_fortifyroot_endpoint(trace_endpoint)
        and not _has_authorization_header(trace_headers)
    ):
        missing_signals.append("traces")
    if (
        exporter is None
        and metrics_exporter is None
        and metrics_enabled
        and _is_managed_fortifyroot_endpoint(metrics_endpoint)
        and not _has_authorization_header(metrics_headers)
    ):
        missing_signals.append("metrics")
    if (
        exporter is None
        and logging_exporter is None
        and logging_enabled
        and _is_managed_fortifyroot_endpoint(logging_endpoint)
        and not _has_authorization_header(logging_headers)
    ):
        missing_signals.append("logs")

    if missing_signals:
        joined_signals = ", ".join(missing_signals)
        raise ValueError(
            "FortifyRoot API key or explicit export headers are required for "
            f"default FortifyRoot {joined_signals} export"
        )


def init(
    app_name: str = sys.argv[0],
    api_endpoint: str = DEFAULT_API_ENDPOINT,
    api_key: Optional[str] = None,
    enabled: bool = True,
    headers: Optional[Dict[str, str]] = None,
    disable_batch: bool = False,
    trace_content: bool = True,
    exporter: Optional[SpanExporter] = None,
    metrics_exporter: Optional[MetricExporter] = None,
    metrics_headers: Optional[Dict[str, str]] = None,
    logging_exporter: Optional[LogExporter] = None,
    logging_headers: Optional[Dict[str, str]] = None,
    processors: Optional[List[SpanProcessor]] = None,
    propagator: Optional[TextMapPropagator] = None,
    sampler: Optional[Sampler] = None,
    should_enrich_metrics: bool = True,
    resource_attributes: Optional[Dict] = None,
    instruments: Optional[Set[Instruments]] = None,
    block_instruments: Optional[Set[Instruments]] = None,
    span_postprocess_callback: Optional[Callable[[ReadableSpan], None]] = None,
    config_profile_id: Optional[str] = None,
    config_poll_interval_seconds: Optional[int] = None,
    stream_holdback_chars: Optional[int] = None,
    allow_udf_detectors: bool = False,
) -> None:
    """
    Initialize FortifyRoot SDK for LLM observability.

    This function initializes the OpenTelemetry tracing infrastructure and
    auto-instruments supported LLM libraries (OpenAI, Anthropic, LangChain, etc.).

    Environment variable precedence:
        For all primitive-type parameters with a ``FORTIFYROOT_*`` counterpart,
        the environment variable **wins** over the init() parameter when set.
        This allows ops/CI to override SDK behavior without code changes.

    Args:
        app_name: Name of your application. Defaults to the script name.
            This becomes the service.name in OpenTelemetry.
            Can be overridden by FORTIFYROOT_APP_NAME environment variable.

        api_endpoint: FortifyRoot API endpoint URL.
            Defaults to "https://api.fortifyroot.com".
            Can be overridden by FORTIFYROOT_BASE_URL environment variable.

        api_key: FortifyRoot API key for authentication.
            Can be overridden by FORTIFYROOT_API_KEY environment variable.

        enabled: Whether to enable tracing. Set to False to disable all tracing.
            Defaults to True.
            Can be overridden by FORTIFYROOT_ENABLED environment variable.

        headers: Custom headers to send with trace exports.
            If api_key is provided and Authorization is missing, a bearer
            Authorization header is automatically added.

        disable_batch: If True, use SimpleSpanProcessor instead of BatchSpanProcessor.
            Useful for debugging. Defaults to False.
            Can be overridden by FORTIFYROOT_DISABLE_BATCH environment variable.

        trace_content: Whether to capture prompt/response content in traces.
            Set to False to only capture metadata without actual content.
            Defaults to True.
            Can be overridden by FORTIFYROOT_TRACE_CONTENT environment variable.

        exporter: Custom SpanExporter to use instead of the default OTLP exporter.
            Use this for custom export destinations.

        metrics_exporter: Custom MetricExporter for metrics export.

        metrics_headers: Custom headers for metrics export.
            Defaults to the same as trace headers if not specified.
            If api_key is provided and Authorization is missing, a bearer
            Authorization header is automatically added.

        logging_exporter: Custom LogExporter for log export.

        logging_headers: Custom headers for log export.
            Defaults to the same as trace headers if not specified.
            If api_key is provided and Authorization is missing, a bearer
            Authorization header is automatically added.

        processor: Custom SpanProcessor(s) to use.
            Can be a single processor or a list of processors.
            FortifyRoot's attribute renaming will be applied on top.

        propagator: Custom TextMapPropagator for context propagation.

        sampler: Custom Sampler for controlling which traces are recorded.
            Use this for head-based sampling strategies.

        should_enrich_metrics: Whether to add trace context to metrics.
            Defaults to True.
            Can be overridden by FORTIFYROOT_ENRICH_METRICS environment variable.

        resource_attributes: Additional OpenTelemetry resource attributes to attach
            to all telemetry. FortifyRoot SDK version is automatically added.

        instruments: Optional set of Instruments to enable. If None, all detected
            instruments are enabled. Use this to limit instrumentation to specific
            libraries.

        block_instruments: Optional set of Instruments to disable. Use this to
            exclude specific libraries from instrumentation.

        span_postprocess_callback: Optional callback function called on each span
            before export. Useful for custom span processing, filtering.

        config_profile_id: Optional immutable backend config profile ID used for
            safety config polling. Can also be provided through the
            FORTIFYROOT_CONFIG_PROFILE_ID environment variable.

        config_poll_interval_seconds: Optional polling interval for backend safety
            config refresh. Defaults to 60 seconds. Can also be provided through
            the FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS environment variable.

        stream_holdback_chars: Optional number of trailing completion characters to
            retain during streaming safety evaluation before releasing text to the
            caller. Defaults to 128. Can also be provided through the
            FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS environment variable.

        allow_udf_detectors: Whether to allow loading user-defined safety
            detectors via ``importlib.import_module``. Defaults to False for
            security. Can also be enabled via the
            FORTIFYROOT_ALLOW_UDF_DETECTORS environment variable (set to
            ``"true"``).

    Example:
        Basic usage::

            import fortifyroot

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
            )

        With specific instruments::

            from fortifyroot import Instruments

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                instruments={Instruments.OPENAI, Instruments.LANGCHAIN},
            )

        Disable content tracing for privacy::

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                trace_content=False,
            )

        With custom sampling::

            from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                sampler=TraceIdRatioBased(0.1),  # Sample 10% of traces
            )

        With custom span processors::

            from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

            console_processor = SimpleSpanProcessor(ConsoleSpanExporter())

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                processors=[console_processor],
            )

        With span postprocess callback::

            def span_callback(span):
                # Inspect span, log alerts, etc.
                pass

            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                span_postprocess_callback=span_callback,
            )
    """
    # ── Resolve env-wins-over-init for primitive params ──────────────
    # For each param with a FORTIFYROOT_* env var counterpart, the env var
    # takes precedence when set.  This allows ops/CI to override SDK init
    # without code changes.
    env_app_name = os.getenv(FORTIFYROOT_APP_NAME, "").strip()
    if env_app_name:
        app_name = env_app_name

    env_enabled = os.getenv(FORTIFYROOT_ENABLED, "").strip().lower()
    if env_enabled:
        enabled = env_enabled == "true"

    env_trace_content = os.getenv("FORTIFYROOT_TRACE_CONTENT", "").strip().lower()
    if env_trace_content:
        trace_content = env_trace_content == "true"

    env_disable_batch = os.getenv(FORTIFYROOT_DISABLE_BATCH, "").strip().lower()
    if env_disable_batch:
        disable_batch = env_disable_batch == "true"

    env_enrich_metrics = os.getenv(FORTIFYROOT_ENRICH_METRICS, "").strip().lower()
    if env_enrich_metrics:
        should_enrich_metrics = env_enrich_metrics == "true"

    env_allow_udf = os.getenv(FORTIFYROOT_ALLOW_UDF_DETECTORS, "").strip().lower()
    if env_allow_udf:
        allow_udf_detectors = env_allow_udf == "true"
    # ── End env resolution ────────────────────────────────────────────

    api_endpoint = _resolve_api_endpoint(api_endpoint)
    env_api_key = os.getenv("FORTIFYROOT_API_KEY", "").strip()
    if env_api_key:
        api_key = env_api_key
    api_key = _resolve_api_key(api_key)
    env_config_profile_id = os.getenv(FORTIFYROOT_CONFIG_PROFILE_ID, "").strip()
    if env_config_profile_id:
        config_profile_id = env_config_profile_id
    config_poll_interval_seconds = _resolve_config_poll_interval_seconds(
        config_poll_interval_seconds
    )
    stream_holdback_chars = _resolve_stream_holdback_chars(stream_holdback_chars)
    metrics_endpoint = _resolve_signal_endpoint(
        "FORTIFYROOT_METRICS_ENDPOINT",
        api_endpoint,
    )
    logging_endpoint = _resolve_signal_endpoint(
        "FORTIFYROOT_LOGGING_ENDPOINT",
        api_endpoint,
    )
    resolved_headers = _resolve_export_headers(
        headers,
        api_key,
        include_sdk_metadata=_is_managed_fortifyroot_endpoint(api_endpoint),
    )
    resolved_metrics_headers = _resolve_signal_headers(
        metrics_headers,
        resolved_headers,
        api_key,
        include_sdk_metadata=_is_managed_fortifyroot_endpoint(metrics_endpoint),
    )
    resolved_logging_headers = _resolve_signal_headers(
        logging_headers,
        resolved_headers,
        api_key,
        include_sdk_metadata=_is_managed_fortifyroot_endpoint(logging_endpoint),
    )
    _validate_default_export_auth(
        enabled=enabled,
        exporter=exporter,
        processors=processors,
        metrics_exporter=metrics_exporter,
        logging_exporter=logging_exporter,
        trace_endpoint=api_endpoint,
        metrics_endpoint=metrics_endpoint,
        logging_endpoint=logging_endpoint,
        trace_headers=resolved_headers,
        metrics_headers=resolved_metrics_headers,
        logging_headers=resolved_logging_headers,
    )

    # Propagate resolved trace_content to Traceloop (its only mechanism is env var).
    # May have been overridden by FORTIFYROOT_TRACE_CONTENT env above.
    os.environ["TRACELOOP_TRACE_CONTENT"] = str(trace_content).lower()

    # ── OTel BatchSpanProcessor schedule_delay default (ST-10 MVP stopgap) ──
    #
    # OpenTelemetry's BatchSpanProcessor reads OTEL_BSP_SCHEDULE_DELAY at
    # construction time (default = 5000 ms). With the upstream default,
    # any direct-SDK LLM retry chain whose total wall-clock exceeds ~5 s
    # (e.g. provider sends Retry-After: 10, customer has max_retries=4
    # with exponential backoff, slow-failing attempts) fragments its
    # spans across multiple OTLP batches → fr-backend's
    # ``proc_retry_detector.go`` is strictly per-batch and never sees ≥2
    # sibling retry_attempt events together → silent RetryLoopEvent miss.
    # Per-attempt LLMUsageEvent extraction is unaffected.
    #
    # The proper backend fix (DB-lookup cross-batch aggregator in
    # proc_retry_detector) is deferred post-MVP as
    # ``ST-10-FOLLOWUP-cross-batch-retry-detection``. As an MVP-side
    # stopgap (kapil 2026-05-19), we widen the default OTel schedule
    # delay to 15 s so nearly all real-world direct-SDK retry chains
    # (OpenAI / Anthropic max_retries up to 4-5 with typical
    # Retry-After ≤ 10 s) buffer into one OTLP batch and produce a
    # RetryLoopEvent reliably. Trade-off: up to 15 s additional trace-
    # ingestion latency for the rare span that lands just before the
    # buffer flushes; bounded memory at ~OTel-default max_export_batch_
    # size (512). Customers who need a different value can override
    # via the standard OTel env var, which we respect via ``setdefault``.
    #
    # See fr-backend/docs/development/RETRY_LOOP.md §1.1 for the full
    # MVP-scope summary including the documented behaviour around
    # disable_batch=True (which DISABLES RetryLoopEvent detection
    # entirely because every span ships as its own OTLP batch — that
    # is a documented MVP limitation pending the same backend
    # follow-up).
    os.environ.setdefault("OTEL_BSP_SCHEDULE_DELAY", "15000")

    # Prepare resource attributes with FR SDK version
    if resource_attributes is None:
        resource_attributes = {}
    else:
        resource_attributes = dict(resource_attributes)  # Make a copy

    # Normalize shorthand keys to OTEL canonical before building the resource.
    # Keeps older client code working without polluting the attribute cache with
    # non-standard keys.
    _RESOURCE_KEY_ALIASES = {"environment": "deployment.environment"}
    for shorthand, canonical in _RESOURCE_KEY_ALIASES.items():
        if shorthand in resource_attributes and canonical not in resource_attributes:
            resource_attributes[canonical] = resource_attributes.pop(shorthand)

    # Inject FortifyRoot SDK version into resource attributes
    resource_attributes[FORTIFYROOT_SDK_VERSION_ATTRIBUTE] = __version__

    # Convert FR Instruments to TL Instruments
    tl_instruments = _convert_to_tl_instruments(instruments)
    tl_block_instruments = _convert_to_tl_instruments(block_instruments)

    # Determine if we need to wrap the processor with attribute renaming
    final_processors: Optional[List[SpanProcessor]] = None

    if processors is not None:
        # User provided custom processor(s)
        if isinstance(processors, list):
            # Wrap each processor
            final_processors = [
                AttributeRenamingProcessor(p) for p in processors
            ]
        else:
            final_processors = AttributeRenamingProcessor(processors)
    elif exporter is None:
        # No custom processor or exporter, use default with renaming
        default_processor = Traceloop.get_default_span_processor(
            disable_batch=disable_batch,
            api_endpoint=api_endpoint,
            api_key=api_key,
            headers=resolved_headers,
        )
        final_processors = [AttributeRenamingProcessor(default_processor)]

    metrics_enabled = _is_enabled_from_env("FORTIFYROOT_METRICS_ENABLED", True)

    # FIX: When we create a default processor (final_processors), Traceloop interprets
    # this as a "custom pipeline" and requires a matching metrics_exporter.
    # If metrics are enabled but no metrics_exporter is provided, create a default one.
    if final_processors is not None and metrics_exporter is None:
        # Check if metrics are enabled via environment variable
        # Note: We read FORTIFYROOT_* vars directly for consistency; env_mapping.py
        # handles translation to TRACELOOP_* for the vendored SDK internals.
        if metrics_enabled:
            metrics_exporter = _init_default_metrics_exporter(
                metrics_endpoint,
                resolved_metrics_headers,
            )

    logging_enabled = _is_enabled_from_env("FORTIFYROOT_LOGGING_ENABLED", False)
    if exporter is None and logging_enabled and logging_exporter is None:
        logging_exporter = _init_default_logging_exporter(
            logging_endpoint,
            resolved_logging_headers,
        )
    logs_pipeline_enabled = logging_enabled and (logging_exporter is not None or exporter is None)
    internal_span_callback = emit_synthetic_span_log if logs_pipeline_enabled else None
    combined_span_callback = compose_span_postprocess_callbacks(
        internal_span_callback,
        span_postprocess_callback,
    )

    class _TraceloopOptionalInitKwargs(TypedDict, total=False):
        metrics_exporter: MetricExporter
        metrics_headers: Dict[str, str]
        logging_exporter: LogExporter
        logging_headers: Dict[str, str]
        propagator: TextMapPropagator

    tl_kwargs: _TraceloopOptionalInitKwargs = {}

    if metrics_exporter is not None:
        tl_kwargs["metrics_exporter"] = metrics_exporter
    if metrics_enabled and resolved_metrics_headers:
        tl_kwargs["metrics_headers"] = resolved_metrics_headers
    if logging_exporter is not None:
        tl_kwargs["logging_exporter"] = logging_exporter
    if logging_enabled and resolved_logging_headers:
        tl_kwargs["logging_headers"] = resolved_logging_headers
    if propagator is not None:
        tl_kwargs["propagator"] = propagator

    # Initialize Traceloop with our configuration
    Traceloop.init(
        app_name=app_name,
        api_endpoint=api_endpoint,
        api_key=api_key,
        enabled=enabled,
        headers=resolved_headers,
        disable_batch=disable_batch,
        exporter=exporter,
        processor=final_processors,
        sampler=sampler,
        should_enrich_metrics=should_enrich_metrics,
        resource_attributes=resource_attributes,
        instruments=tl_instruments,
        block_instruments=tl_block_instruments,
        span_postprocess_callback=combined_span_callback,
        # Disable Traceloop-specific sync features
        traceloop_sync_enabled=False,
        # Instead of following direct assignments, using **tl_kwargs to "fix" Pylance errors!
        # metrics_exporter=metrics_exporter,
        # metrics_headers=metrics_headers,
        # logging_exporter=logging_exporter,
        # logging_headers=logging_headers,
        # propagator=propagator,
        **tl_kwargs,
    )
    if allow_udf_detectors:
        set_udf_detectors_enabled(True)

    configure_global_safety_runtime(
        enabled=enabled,
        api_endpoint=api_endpoint,
        api_key=api_key,
        config_profile_id=config_profile_id,
        poll_interval_seconds=config_poll_interval_seconds,
        stream_holdback_chars=stream_holdback_chars,
    )


def set_association_properties(properties: Dict) -> None:
    """
    Set association properties for the current trace context.

    Association properties are key-value pairs that are attached to all spans
    in the current context. Use this to correlate traces with business entities
    like user IDs, session IDs, conversation IDs, etc.

    This function is thread-safe. Each thread maintains its own context, so
    properties set in one thread won't affect other threads.

    Args:
        properties: Dictionary of property names to values.

    Example:
        ::

            import fortifyroot

            fortifyroot.init(app_name="my-app", api_key="fr-xxx")

            # Set properties that will be attached to all subsequent spans
            fortifyroot.set_association_properties({
                "user_id": "user_12345",
                "session_id": "sess_abc",
                "conversation_id": "conv_xyz",
            })

            # Now make LLM calls - they will have these properties attached
            response = openai.chat.completions.create(...)

    Note:
        - Properties are scoped to the current thread/async context
        - Use resource_attributes in init() for static, service-level metadata
        - Use set_association_properties() for dynamic, request-level metadata
    """
    Traceloop.set_association_properties(properties)


class FortifyRootConfig:
    """
    Fluent configuration builder for FortifyRoot SDK.

    This provides an alternative way to configure the SDK using method chaining
    instead of passing all parameters to init().

    Example:
        ::

            import fortifyroot

            # Fluent API
            fortifyroot.configure() \\
                .app_name("my-llm-app") \\
                .api_key("fr-xxx") \\
                .trace_content(False) \\
                .sampler(TraceIdRatioBased(0.1)) \\
                .init()

            # Equivalent to:
            fortifyroot.init(
                app_name="my-llm-app",
                api_key="fr-xxx",
                trace_content=False,
                sampler=TraceIdRatioBased(0.1),
            )
    """

    class _FortifyRootInitKwargs(TypedDict, total=False):
        app_name: str
        api_endpoint: str
        api_key: Optional[str]
        enabled: bool
        headers: Optional[Dict[str, str]]
        disable_batch: bool
        trace_content: bool
        exporter: Optional[SpanExporter]
        metrics_exporter: Optional[MetricExporter]
        metrics_headers: Optional[Dict[str, str]]
        logging_exporter: Optional[LogExporter]
        logging_headers: Optional[Dict[str, str]]
        processors: Optional[List[SpanProcessor]]
        propagator: Optional[TextMapPropagator]
        sampler: Optional[Sampler]
        should_enrich_metrics: bool
        resource_attributes: Optional[Dict]
        instruments: Optional[Set[Instruments]]
        block_instruments: Optional[Set[Instruments]]
        span_postprocess_callback: Optional[Callable[[ReadableSpan], None]]
        config_profile_id: Optional[str]
        config_poll_interval_seconds: Optional[int]
        stream_holdback_chars: Optional[int]
        allow_udf_detectors: bool

    def __init__(self) -> None:
        """Initialize with default configuration."""
        self._config: FortifyRootConfig._FortifyRootInitKwargs = {}
        self._config["app_name"] = sys.argv[0]
        self._config["api_endpoint"] = DEFAULT_API_ENDPOINT

    def app_name(self, name: str) -> "FortifyRootConfig":
        """Set the application name."""
        self._config["app_name"] = name
        return self

    def api_endpoint(self, endpoint: str) -> "FortifyRootConfig":
        """Set the API endpoint URL."""
        self._config["api_endpoint"] = endpoint
        return self

    def api_key(self, key: str) -> "FortifyRootConfig":
        """Set the API key."""
        self._config["api_key"] = key
        return self

    def enabled(self, value: bool) -> "FortifyRootConfig":
        """Enable or disable tracing."""
        self._config["enabled"] = value
        return self

    def headers(self, headers: Dict[str, str]) -> "FortifyRootConfig":
        """Set custom headers for trace export."""
        self._config["headers"] = headers
        return self

    def disable_batch(self, value: bool = True) -> "FortifyRootConfig":
        """Disable batch processing (use SimpleSpanProcessor)."""
        self._config["disable_batch"] = value
        return self

    def trace_content(self, value: bool) -> "FortifyRootConfig":
        """Enable or disable content tracing."""
        self._config["trace_content"] = value
        return self

    def exporter(self, exporter: SpanExporter) -> "FortifyRootConfig":
        """Set a custom span exporter."""
        self._config["exporter"] = exporter
        return self

    def metrics_exporter(self, exporter: MetricExporter) -> "FortifyRootConfig":
        """Set a custom metrics exporter."""
        self._config["metrics_exporter"] = exporter
        return self

    def metrics_headers(self, headers: Dict[str, str]) -> "FortifyRootConfig":
        """Set custom headers for metrics export."""
        self._config["metrics_headers"] = headers
        return self

    def logging_exporter(self, exporter: LogExporter) -> "FortifyRootConfig":
        """Set a custom logging exporter."""
        self._config["logging_exporter"] = exporter
        return self

    def logging_headers(self, headers: Dict[str, str]) -> "FortifyRootConfig":
        """Set custom headers for logging export."""
        self._config["logging_headers"] = headers
        return self

    def processors(
        self, processors: List[SpanProcessor]
    ) -> "FortifyRootConfig":
        """Set custom span processors."""
        self._config["processors"] = processors
        return self

    def propagator(self, propagator: TextMapPropagator) -> "FortifyRootConfig":
        """Set a custom context propagator."""
        self._config["propagator"] = propagator
        return self

    def sampler(self, sampler: Sampler) -> "FortifyRootConfig":
        """Set a custom sampler."""
        self._config["sampler"] = sampler
        return self

    def should_enrich_metrics(self, value: bool) -> "FortifyRootConfig":
        """Enable or disable metric enrichment with trace context."""
        self._config["should_enrich_metrics"] = value
        return self

    def resource_attributes(self, attributes: Dict) -> "FortifyRootConfig":
        """Set additional resource attributes."""
        self._config["resource_attributes"] = attributes
        return self

    def instruments(self, instruments: Set[Instruments]) -> "FortifyRootConfig":
        """Set specific instruments to enable."""
        self._config["instruments"] = instruments
        return self

    def block_instruments(self, instruments: Set[Instruments]) -> "FortifyRootConfig":
        """Set specific instruments to block."""
        self._config["block_instruments"] = instruments
        return self

    def span_postprocess_callback(
        self, callback: Callable[[ReadableSpan], None]
    ) -> "FortifyRootConfig":
        """Set a callback for post-processing spans."""
        self._config["span_postprocess_callback"] = callback
        return self

    def config_profile_id(self, value: str) -> "FortifyRootConfig":
        """Set the backend config profile ID used for safety polling."""
        self._config["config_profile_id"] = value
        return self

    def config_poll_interval_seconds(self, value: int) -> "FortifyRootConfig":
        """Set the safety config polling interval in seconds."""
        self._config["config_poll_interval_seconds"] = value
        return self

    def stream_holdback_chars(self, value: int) -> "FortifyRootConfig":
        """Set the streaming safety completion holdback size in characters."""
        self._config["stream_holdback_chars"] = value
        return self

    def allow_udf_detectors(self, value: bool = True) -> "FortifyRootConfig":
        """Allow loading user-defined safety detectors via importlib."""
        self._config["allow_udf_detectors"] = value
        return self

    def init(self) -> None:
        """Initialize FortifyRoot with the configured settings."""
        from fortifyroot.core import init as _init
        _init(**self._config)


def configure() -> FortifyRootConfig:
    """
    Create a new FortifyRoot configuration builder.

    Returns a FortifyRootConfig instance that can be used to configure
    the SDK using method chaining (fluent API).

    Example:
        ::

            import fortifyroot

            fortifyroot.configure() \\
                .app_name("my-app") \\
                .api_key("fr-xxx") \\
                .trace_content(False) \\
                .init()

    Returns:
        FortifyRootConfig: A new configuration builder instance.
    """
    return FortifyRootConfig()
