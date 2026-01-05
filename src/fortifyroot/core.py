"""Core FortifyRoot SDK functionality."""

import sys
from typing import Optional, Set

from traceloop.sdk import Traceloop

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
    disable_batch: bool = False,
    trace_content: bool = True,
    instruments: Optional[Set[Instruments]] = None,
    block_instruments: Optional[Set[Instruments]] = None,
    resource_attributes: Optional[dict] = None,
) -> None:
    """
    Initialize FortifyRoot SDK for LLM observability.

    This function initializes the OpenTelemetry tracing infrastructure and
    auto-instruments supported LLM libraries (OpenAI, Anthropic, LangChain, etc.).

    Args:
        app_name: Name of your application. Defaults to the script name.
        api_endpoint: FortifyRoot API endpoint URL.
            Defaults to "https://api.fortifyroot.com".
            Can be overridden by FORTIFYROOT_BASE_URL environment variable.
        api_key: FortifyRoot API key for authentication.
            Can be overridden by FORTIFYROOT_API_KEY environment variable.
        enabled: Whether to enable tracing. Set to False to disable all tracing.
            Defaults to True.
        disable_batch: If True, use SimpleSpanProcessor instead of BatchSpanProcessor.
            Useful for debugging. Defaults to False.
        trace_content: Whether to capture prompt/response content in traces.
            Set to False to only capture metadata without actual content.
            Can be overridden by FORTIFYROOT_TRACE_CONTENT environment variable.
            Defaults to True.
        instruments: Optional set of Instruments to enable. If None, all detected
            instruments are enabled. Use this to limit instrumentation to specific
            libraries.
        block_instruments: Optional set of Instruments to disable. Use this to
            exclude specific libraries from instrumentation.
        resource_attributes: Additional OpenTelemetry resource attributes to attach
            to all telemetry. FortifyRoot SDK version is automatically added.

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
    """
    import os

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

    # Get the default span processor from Traceloop
    # We need to do this before calling Traceloop.init() with our wrapped processor
    default_processor = Traceloop.get_default_span_processor(
        disable_batch=disable_batch,
        api_endpoint=api_endpoint,
        api_key=api_key,
    )

    # Wrap the default processor with our attribute renaming processor
    renaming_processor = AttributeRenamingProcessor(default_processor)

    # Convert FR Instruments to TL Instruments
    tl_instruments = _convert_to_tl_instruments(instruments)
    tl_block_instruments = _convert_to_tl_instruments(block_instruments)

    # Initialize Traceloop with our processor
    Traceloop.init(
        app_name=app_name,
        api_endpoint=api_endpoint,
        api_key=api_key,
        enabled=enabled,
        disable_batch=disable_batch,
        processor=renaming_processor,
        resource_attributes=resource_attributes,
        instruments=tl_instruments,
        block_instruments=tl_block_instruments,
        # Disable Traceloop-specific sync features (prompt management, etc.)
        traceloop_sync_enabled=False,
    )


def set_association_properties(properties: dict) -> None:
    """
    Set association properties for the current trace context.

    Association properties are key-value pairs that are attached to all spans
    in the current context. Use this to correlate traces with business entities
    like user IDs, session IDs, conversation IDs, etc.

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
    """
    Traceloop.set_association_properties(properties)
