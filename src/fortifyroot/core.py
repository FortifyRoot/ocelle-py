"""Core FortifyRoot SDK functionality.

This module provides the main initialization and configuration functions
for the FortifyRoot SDK, including:
- init(): Initialize the SDK with tracing configuration
- set_association_properties(): Set context properties for traces
- FortifyRootConfig: Fluent API for configuration (builder pattern)
"""

import os
import sys
from typing import Callable, Dict, List, Optional, Set, TypedDict

from opentelemetry.sdk.trace import SpanProcessor, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.sdk.trace.sampling import Sampler
from opentelemetry.sdk.metrics.export import MetricExporter
from opentelemetry.sdk._logs.export import LogExporter
from opentelemetry.propagators.textmap import TextMapPropagator

from fortifyroot._vendor.traceloop.sdk import Traceloop

from fortifyroot._internal.constants import FORTIFYROOT_SDK_VERSION_ATTRIBUTE
from fortifyroot.instruments import Instruments, _convert_to_tl_instruments
from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor
from fortifyroot.version import __version__


# Default API endpoint for FortifyRoot
DEFAULT_API_ENDPOINT = "https://api.fortifyroot.com"


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
) -> None:
    """
    Initialize FortifyRoot SDK for LLM observability.

    This function initializes the OpenTelemetry tracing infrastructure and
    auto-instruments supported LLM libraries (OpenAI, Anthropic, LangChain, etc.).

    Args:
        app_name: Name of your application. Defaults to the script name.
            This becomes the service.name in OpenTelemetry.

        api_endpoint: FortifyRoot API endpoint URL.
            Defaults to "https://api.fortifyroot.com".
            Can be overridden by FORTIFYROOT_BASE_URL environment variable.

        api_key: FortifyRoot API key for authentication.
            Can be overridden by FORTIFYROOT_API_KEY environment variable.

        enabled: Whether to enable tracing. Set to False to disable all tracing.
            Defaults to True.

        headers: Custom headers to send with trace exports.
            If api_key is provided and headers is None, Authorization header
            is automatically set.

        disable_batch: If True, use SimpleSpanProcessor instead of BatchSpanProcessor.
            Useful for debugging. Defaults to False.

        trace_content: Whether to capture prompt/response content in traces.
            Set to False to only capture metadata without actual content.
            Can be overridden by FORTIFYROOT_TRACE_CONTENT environment variable.
            Defaults to True.

        exporter: Custom SpanExporter to use instead of the default OTLP exporter.
            Use this for custom export destinations.

        metrics_exporter: Custom MetricExporter for metrics export.

        metrics_headers: Custom headers for metrics export.
            Defaults to the same as trace headers if not specified.

        logging_exporter: Custom LogExporter for log export.

        logging_headers: Custom headers for log export.
            Defaults to the same as trace headers if not specified.

        processor: Custom SpanProcessor(s) to use.
            Can be a single processor or a list of processors.
            FortifyRoot's attribute renaming will be applied on top.

        propagator: Custom TextMapPropagator for context propagation.

        sampler: Custom Sampler for controlling which traces are recorded.
            Use this for head-based sampling strategies.

        should_enrich_metrics: Whether to add trace context to metrics.
            Defaults to True.

        resource_attributes: Additional OpenTelemetry resource attributes to attach
            to all telemetry. FortifyRoot SDK version is automatically added.

        instruments: Optional set of Instruments to enable. If None, all detected
            instruments are enabled. Use this to limit instrumentation to specific
            libraries.

        block_instruments: Optional set of Instruments to disable. Use this to
            exclude specific libraries from instrumentation.

        span_postprocess_callback: Optional callback function called on each span
            before export. Useful for custom span processing, filtering.

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
    api_endpoint_via_env = os.getenv("FORTIFYROOT_BASE_URL", "")
    if api_endpoint == DEFAULT_API_ENDPOINT and api_endpoint_via_env:
        api_endpoint = api_endpoint_via_env

    # Set TRACELOOP_TRACE_CONTENT based on trace_content parameter
    # This needs to be set before Traceloop.init() is called
    if not trace_content:
        os.environ.setdefault("TRACELOOP_TRACE_CONTENT", "false")

    # Prepare resource attributes with FR SDK version
    if resource_attributes is None:
        resource_attributes = {}
    else:
        resource_attributes = dict(resource_attributes)  # Make a copy

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
            headers=headers,
        )
        final_processors = [AttributeRenamingProcessor(default_processor)]

    # FIX: When we create a default processor (final_processors), Traceloop interprets
    # this as a "custom pipeline" and requires a matching metrics_exporter.
    # If metrics are enabled but no metrics_exporter is provided, create a default one.
    if final_processors is not None and metrics_exporter is None:
        # Check if metrics are enabled via environment variable
        # Note: We read FORTIFYROOT_* vars directly for consistency; env_mapping.py
        # handles translation to TRACELOOP_* for the vendored SDK internals.
        metrics_enabled = (os.environ.get("FORTIFYROOT_METRICS_ENABLED") or "true").lower() == "true"
        if metrics_enabled:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            # Use the same endpoint pattern as traces
            metrics_endpoint = os.environ.get("FORTIFYROOT_METRICS_ENDPOINT") or api_endpoint
            # Ensure the endpoint includes /v1/metrics path for OTLP HTTP
            if not metrics_endpoint.endswith("/v1/metrics"):
                metrics_endpoint = f"{metrics_endpoint.rstrip('/')}/v1/metrics"
            metrics_exporter = OTLPMetricExporter(
                endpoint=metrics_endpoint,
                headers=metrics_headers or headers or {},
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
    if metrics_headers is not None:
        tl_kwargs["metrics_headers"] = metrics_headers
    if logging_exporter is not None:
        tl_kwargs["logging_exporter"] = logging_exporter
    if logging_headers is not None:
        tl_kwargs["logging_headers"] = logging_headers
    if propagator is not None:
        tl_kwargs["propagator"] = propagator

    # Initialize Traceloop with our configuration
    Traceloop.init(
        app_name=app_name,
        api_endpoint=api_endpoint,
        api_key=api_key,
        enabled=enabled,
        headers=headers or {},
        disable_batch=disable_batch,
        exporter=exporter,
        processor=final_processors,
        sampler=sampler,
        should_enrich_metrics=should_enrich_metrics,
        resource_attributes=resource_attributes,
        instruments=tl_instruments,
        block_instruments=tl_block_instruments,
        span_postprocess_callback=span_postprocess_callback,
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
