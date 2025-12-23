"""
FortifyRoot SDK
LLM observability via OpenLLMetry + safety guardrails for PII/PCI/PHI/Secrets.
"""

import json
import logging
import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from wrapt import wrap_function_wrapper

from fortifyroot.safety import Action, Detection, SafetyEngine, SafetyResult

logger = logging.getLogger(__name__)


# ============================================================================
# Span Exporter Wrapper for Rebranding and PII Redaction
# ============================================================================

class FortifyRootSpanExporter:
    """
    OpenTelemetry SpanExporter wrapper that:
    1. Rebrands 'traceloop.*' attribute keys to 'fortifyroot.*'
    2. Recursively rebrands keys (not values) in JSON string attributes
    3. Redacts PII from sensitive attributes (gen_ai.prompt.*, entity.input, etc.)

    Wraps the actual exporter and processes spans before export.
    """

    # Attributes that may contain sensitive data requiring PII redaction
    PII_SENSITIVE_PATTERNS = [
        re.compile(r'^gen_ai\.prompt\.\d+\.content$'),
        re.compile(r'^gen_ai\.completion\.\d+\.content$'),
        re.compile(r'^fortifyroot\.entity\.input$'),
        re.compile(r'^fortifyroot\.entity\.output$'),
        re.compile(r'^traceloop\.entity\.input$'),
        re.compile(r'^traceloop\.entity\.output$'),
    ]

    def __init__(self, wrapped_exporter: Any):
        self._wrapped_exporter = wrapped_exporter
        self._safety_engine: Optional[SafetyEngine] = None
        self._policies: List[str] = []

    def set_safety_engine(self, engine: SafetyEngine, policies: List[str]) -> None:
        """Set or update the safety engine and policies."""
        self._safety_engine = engine
        self._policies = policies

    def export(self, spans: Any) -> Any:
        """Process spans and delegate to wrapped exporter."""
        processed_spans = [self._process_span(span) for span in spans]
        return self._wrapped_exporter.export(processed_spans)

    def shutdown(self) -> None:
        """Shutdown the wrapped exporter."""
        if hasattr(self._wrapped_exporter, 'shutdown'):
            self._wrapped_exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush the wrapped exporter."""
        if hasattr(self._wrapped_exporter, 'force_flush'):
            return self._wrapped_exporter.force_flush(timeout_millis)
        return True

    def _process_span(self, span: Any) -> Any:
        """Process a single span: rebrand attributes and redact PII."""
        try:
            # Create a modified copy of the span with processed attributes
            if hasattr(span, '_attributes') and span._attributes:
                new_attrs = {}
                for key, value in span._attributes.items():
                    new_key = self._rebrand_key(key)
                    new_value = self._process_value(new_key, value)
                    new_attrs[new_key] = new_value

                # Create a new span-like object with modified attributes
                return _ProcessedSpan(span, new_attrs)
        except Exception as e:
            logger.debug(f"FortifyRootSpanExporter processing error: {e}")

        return span

    def _rebrand_key(self, key: str) -> str:
        """Rebrand attribute key from traceloop.* to fortifyroot.*"""
        if key.startswith('traceloop.'):
            return 'fortifyroot.' + key[len('traceloop.'):]
        return key

    def _process_value(self, key: str, value: Any) -> Any:
        """Process attribute value: rebrand JSON keys and redact PII if needed."""
        if isinstance(value, str):
            # Try to parse as JSON and rebrand keys
            rebranded_value = self._rebrand_json_keys(value)

            # Check if this attribute needs PII redaction
            if self._should_redact_pii(key):
                return self._redact_pii(rebranded_value)

            return rebranded_value

        return value

    def _rebrand_json_keys(self, value: str) -> str:
        """
        If value is a JSON string, parse it, recursively rebrand keys
        containing 'traceloop' to 'fortifyroot', and re-serialize.
        """
        if 'traceloop' not in value:
            return value

        try:
            parsed = json.loads(value)
            rebranded = self._rebrand_keys_recursive(parsed)
            return json.dumps(rebranded, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return value

    def _rebrand_keys_recursive(self, obj: Any) -> Any:
        """Recursively rebrand dictionary keys containing 'traceloop' to 'fortifyroot'."""
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                new_key = k.replace('traceloop', 'fortifyroot') if isinstance(k, str) and 'traceloop' in k else k
                new_dict[new_key] = self._rebrand_keys_recursive(v)
            return new_dict
        elif isinstance(obj, list):
            return [self._rebrand_keys_recursive(item) for item in obj]
        else:
            return obj

    def _should_redact_pii(self, key: str) -> bool:
        """Check if attribute key matches patterns requiring PII redaction."""
        for pattern in self.PII_SENSITIVE_PATTERNS:
            if pattern.match(key):
                return True
        return False

    def _redact_pii(self, value: str) -> str:
        """Redact PII from a string value using the safety engine."""
        if not self._safety_engine or not self._policies:
            return value

        try:
            detections = self._safety_engine.detect(value, self._policies)
            if detections:
                return self._safety_engine.redact(value, detections)
        except Exception as e:
            logger.debug(f"PII redaction error: {e}")

        return value


class _ProcessedSpan:
    """
    Wrapper around a span that substitutes processed attributes.
    Delegates all other attribute access to the original span.
    """

    def __init__(self, original_span: Any, processed_attributes: Dict[str, Any]):
        self._original = original_span
        self._processed_attributes = processed_attributes

    @property
    def _attributes(self) -> Dict[str, Any]:
        return self._processed_attributes

    @property
    def attributes(self) -> Dict[str, Any]:
        return self._processed_attributes

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


# Global exporter wrapper instance
_exporter_wrapper: Optional[FortifyRootSpanExporter] = None


def _get_exporter_wrapper() -> Optional[FortifyRootSpanExporter]:
    """Get the global exporter wrapper instance."""
    return _exporter_wrapper


def _wrap_span_exporter() -> None:
    """Wrap the OpenTelemetry span exporter with FortifyRoot processing."""
    global _exporter_wrapper

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

        provider = trace.get_tracer_provider()
        if not isinstance(provider, TracerProvider):
            logger.debug("TracerProvider not available for exporter wrapping")
            return

        # Find and wrap existing span processors' exporters
        if hasattr(provider, '_active_span_processor'):
            processor = provider._active_span_processor

            # Handle composite processor (multiple processors)
            if hasattr(processor, '_span_processors'):
                for sp in processor._span_processors:
                    _wrap_processor_exporter(sp)
            else:
                _wrap_processor_exporter(processor)

        logger.debug("FortifyRoot span exporter wrapper installed")

    except ImportError:
        logger.debug("OpenTelemetry SDK not available")
    except Exception as e:
        logger.debug(f"Failed to wrap span exporter: {e}")


def _wrap_processor_exporter(processor: Any) -> None:
    """Wrap the exporter within a span processor."""
    global _exporter_wrapper

    if hasattr(processor, 'span_exporter'):
        original_exporter = processor.span_exporter
        _exporter_wrapper = FortifyRootSpanExporter(original_exporter)
        processor.span_exporter = _exporter_wrapper
        logger.debug(f"Wrapped exporter in {type(processor).__name__}")


# ============================================================================
# Exceptions
# ============================================================================

class FortifyRootBlocked(Exception):
    """Raised when content is blocked by safety policies."""

    def __init__(
        self,
        message: str,
        detections: Optional[List[Detection]] = None,
        direction: str = "input"
    ):
        super().__init__(message)
        self.detections = detections or []
        self.direction = direction
        self.message = message


class FortifyRootConfigError(Exception):
    """Raised when there's a configuration error."""
    pass


# ============================================================================
# Context Management
# ============================================================================

_context = threading.local()


def set_context(**kwargs: Any) -> None:
    """
    Set context attributes for the current thread.
    These are attached to telemetry spans.

    Example:
        fortifyroot.set_context(user_id="user-123", session_id="sess-456")
    """
    if not hasattr(_context, 'attributes'):
        _context.attributes = {}
    _context.attributes.update(kwargs)

    # Also set on Traceloop if available
    try:
        from traceloop.sdk import Traceloop
        for key, value in kwargs.items():
            Traceloop.set_association_properties({key: value})
    except ImportError:
        pass


def get_context() -> Dict[str, Any]:
    """Get current context attributes."""
    return getattr(_context, 'attributes', {})


def clear_context() -> None:
    """Clear all context attributes."""
    if hasattr(_context, 'attributes'):
        _context.attributes = {}


@contextmanager
def scoped_context(**kwargs: Any):
    """Context manager for temporary context."""
    old_context = get_context().copy()
    set_context(**kwargs)
    try:
        yield
    finally:
        clear_context()
        set_context(**old_context)


# ============================================================================
# Global State
# ============================================================================

@dataclass
class FortifyRootState:
    """Global state for FortifyRoot SDK."""
    initialized: bool = False
    observing: bool = False
    safety_engine: Optional[SafetyEngine] = None
    policies: List[str] = field(default_factory=list)
    enabled_providers: Set[str] = field(default_factory=set)
    wrapped_methods: Set[str] = field(default_factory=set)


_state = FortifyRootState()


# ============================================================================
# Span Event Helper
# ============================================================================

def _add_safety_span_event(
    event_name: str,
    result: SafetyResult,
    direction: str
) -> None:
    """Add a safety event to the current OpenTelemetry span."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span and span.is_recording():
            attributes = {
                "fortifyroot.direction": direction,
                "fortifyroot.action": result.action.value,
                "fortifyroot.detections.count": len(result.detections),
            }

            if result.detections:
                attributes["fortifyroot.detections.types"] = ",".join(
                    d.rule_name for d in result.detections
                )

            if result.message:
                attributes["fortifyroot.message"] = result.message

            span.add_event(event_name, attributes=attributes)
    except ImportError:
        # OpenTelemetry not available, skip
        pass
    except Exception as e:
        logger.debug(f"Failed to add span event: {e}")


# ============================================================================
# Content Extraction Helpers
# ============================================================================

def _extract_text_from_content(content: Any) -> str:
    """Extract text content from various message formats."""
    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict):
                if item.get('type') == 'text':
                    texts.append(item.get('text', ''))
                elif 'text' in item:
                    texts.append(item.get('text', ''))
            elif hasattr(item, 'text'):
                texts.append(str(item.text))
        return '\n'.join(texts)

    if isinstance(content, dict):
        if 'text' in content:
            return content['text']
        if 'content' in content:
            return _extract_text_from_content(content['content'])

    if hasattr(content, 'text'):
        return str(getattr(content, 'text'))

    return str(content)


def _extract_messages_text(messages: Any) -> str:
    """Extract all text from a messages array."""
    if not messages:
        return ""

    texts = []

    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get('content', '')
                texts.append(_extract_text_from_content(content))
                if 'message' in msg:
                    texts.append(_extract_text_from_content(msg['message']))
            elif isinstance(msg, str):
                texts.append(msg)
            elif hasattr(msg, 'content'):
                texts.append(_extract_text_from_content(msg.content))
    elif isinstance(messages, str):
        texts.append(messages)

    return '\n'.join(filter(None, texts))


# ============================================================================
# Provider Input/Output Extraction
# ============================================================================

def _extract_input_openai(kwargs: Dict[str, Any]) -> str:
    """Extract input text from OpenAI-style requests."""
    texts = []

    if 'messages' in kwargs:
        texts.append(_extract_messages_text(kwargs['messages']))
    if 'prompt' in kwargs:
        prompt = kwargs['prompt']
        if isinstance(prompt, list):
            texts.extend([str(p) for p in prompt])
        else:
            texts.append(str(prompt))
    if 'input' in kwargs:
        inp = kwargs['input']
        if isinstance(inp, list):
            texts.extend([str(i) for i in inp])
        else:
            texts.append(str(inp))

    return '\n'.join(filter(None, texts))


def _extract_output_openai(response: Any) -> str:
    """Extract output text from OpenAI-style responses."""
    texts = []

    try:
        if isinstance(response, dict):
            choices = response.get('choices', [])
            for choice in choices:
                msg = choice.get('message', {})
                if msg:
                    texts.append(_extract_text_from_content(msg.get('content', '')))
                if 'text' in choice:
                    texts.append(choice['text'])
        elif hasattr(response, 'choices'):
            for choice in response.choices:
                if hasattr(choice, 'message') and choice.message:
                    texts.append(_extract_text_from_content(choice.message.content))
                elif hasattr(choice, 'text'):
                    texts.append(choice.text)
    except Exception as e:
        logger.debug(f"Error extracting output: {e}")

    return '\n'.join(filter(None, texts))


def _extract_input_anthropic(kwargs: Dict[str, Any]) -> str:
    """Extract input text from Anthropic-style requests."""
    texts = []

    if 'system' in kwargs:
        texts.append(_extract_text_from_content(kwargs['system']))
    if 'messages' in kwargs:
        texts.append(_extract_messages_text(kwargs['messages']))
    if 'prompt' in kwargs:
        texts.append(str(kwargs['prompt']))

    return '\n'.join(filter(None, texts))


def _extract_output_anthropic(response: Any) -> str:
    """Extract output text from Anthropic-style responses."""
    texts = []

    try:
        if isinstance(response, dict):
            content = response.get('content', [])
            for block in content:
                if isinstance(block, dict) and block.get('type') == 'text':
                    texts.append(block.get('text', ''))
        elif hasattr(response, 'content'):
            for block in response.content:
                if hasattr(block, 'text'):
                    texts.append(block.text)
    except Exception as e:
        logger.debug(f"Error extracting Anthropic output: {e}")

    return '\n'.join(filter(None, texts))


def _extract_input_generic(kwargs: Dict[str, Any]) -> str:
    """Generic input extraction for various providers."""
    texts = []

    # Try common field names
    for fld in ['messages', 'prompt', 'input', 'contents', 'message', 'query_str']:
        if fld in kwargs:
            val = kwargs[fld]
            if fld == 'messages':
                texts.append(_extract_messages_text(val))
            elif isinstance(val, str):
                texts.append(val)
            elif isinstance(val, list):
                texts.append(_extract_messages_text(val))

    # Check json body (Ollama style)
    if 'json' in kwargs and isinstance(kwargs['json'], dict):
        texts.append(_extract_input_generic(kwargs['json']))

    return '\n'.join(filter(None, texts))


def _extract_output_generic(response: Any) -> str:
    """Generic output extraction for various providers."""
    texts = []

    try:
        # OpenAI-style
        if hasattr(response, 'choices'):
            return _extract_output_openai(response)

        # Anthropic-style
        if hasattr(response, 'content') and isinstance(response.content, list):
            return _extract_output_anthropic(response)

        # Dict response
        if isinstance(response, dict):
            if 'choices' in response:
                return _extract_output_openai(response)
            if 'content' in response:
                return _extract_output_anthropic(response)
            if 'message' in response:
                msg = response['message']
                if isinstance(msg, dict):
                    texts.append(msg.get('content', ''))
            if 'response' in response:
                texts.append(str(response['response']))
            if 'text' in response:
                texts.append(response['text'])

        # Direct text attribute
        if hasattr(response, 'text'):
            texts.append(str(getattr(response, 'text')))
        if hasattr(response, 'response'):
            texts.append(str(getattr(response, 'response')))
    except Exception as e:
        logger.debug(f"Error extracting output: {e}")

    return '\n'.join(filter(None, texts))


# ============================================================================
# Provider Configurations
# ============================================================================

# Provider-specific extractors: (input_fn, output_fn)
EXTRACTORS: Dict[str, Tuple[Callable, Callable]] = {
    'openai': (_extract_input_openai, _extract_output_openai),
    'anthropic': (_extract_input_anthropic, _extract_output_anthropic),
    'cohere': (_extract_input_generic, _extract_output_generic),
    'google_generativeai': (_extract_input_generic, _extract_output_generic),
    'vertexai': (_extract_input_generic, _extract_output_generic),
    'mistralai': (_extract_input_openai, _extract_output_openai),
    'ollama': (_extract_input_generic, _extract_output_generic),
    'groq': (_extract_input_openai, _extract_output_openai),
    'together': (_extract_input_openai, _extract_output_openai),
    'bedrock': (_extract_input_generic, _extract_output_generic),
    'replicate': (_extract_input_generic, _extract_output_generic),
    'watsonx': (_extract_input_generic, _extract_output_generic),
    'sagemaker': (_extract_input_generic, _extract_output_generic),
}

# Methods to wrap: (module_path, "Class.method", is_async)
PROVIDER_METHODS: Dict[str, List[Tuple[str, str, bool]]] = {
    'openai': [
        ("openai.resources.chat.completions", "Completions.create", False),
        ("openai.resources.chat.completions", "AsyncCompletions.create", True),
        ("openai.resources.completions", "Completions.create", False),
        ("openai.resources.completions", "AsyncCompletions.create", True),
    ],
    'anthropic': [
        ("anthropic.resources.messages", "Messages.create", False),
        ("anthropic.resources.messages", "AsyncMessages.create", True),
    ],
    'cohere': [
        ("cohere.base_client", "BaseCohere.chat", False),
        ("cohere.base_client", "AsyncBaseCohere.chat", True),
    ],
    'google_generativeai': [
        ("google.genai.models", "Models.generate_content", False),
        ("google.genai.models", "AsyncModels.generate_content", True),
    ],
    'mistralai': [
        ("mistralai.client", "MistralClient.chat", False),
        ("mistralai.async_client", "MistralAsyncClient.chat", True),
    ],
    'ollama': [
        ("ollama._client", "Client._request", False),
        ("ollama._client", "AsyncClient._request", True),
    ],
    'groq': [
        ("groq.resources.chat.completions", "Completions.create", False),
        ("groq.resources.chat.completions", "AsyncCompletions.create", True),
    ],
    'together': [
        ("together.resources.chat.completions", "Completions.create", False),
        ("together.resources.chat.completions", "AsyncCompletions.create", True),
    ],
    'bedrock': [
        ("botocore.client", "ClientCreator.create_client", False),
    ],
}


# ============================================================================
# Input Modification
# ============================================================================

def _modify_input(kwargs: Dict[str, Any], new_content: str) -> Dict[str, Any]:
    """Modify request kwargs with redacted content."""
    import copy
    modified = copy.deepcopy(kwargs)

    # Try messages (OpenAI/Anthropic style)
    if 'messages' in modified:
        for msg in reversed(modified['messages']):
            if isinstance(msg, dict) and msg.get('role') == 'user':
                msg['content'] = new_content
                return modified

    # Try json body (Ollama style)
    if 'json' in modified and isinstance(modified['json'], dict):
        if 'messages' in modified['json']:
            for msg in reversed(modified['json']['messages']):
                if isinstance(msg, dict) and msg.get('role') == 'user':
                    msg['content'] = new_content
                    return modified
        if 'prompt' in modified['json']:
            modified['json']['prompt'] = new_content
            return modified

    # Try direct fields
    if 'prompt' in modified:
        modified['prompt'] = new_content
    elif 'input' in modified:
        modified['input'] = new_content
    elif 'contents' in modified:
        modified['contents'] = new_content
    elif 'message' in modified:
        modified['message'] = new_content

    return modified


# ============================================================================
# Streaming Wrappers
# ============================================================================

class SafetyStreamWrapper:
    """Wraps a sync stream to accumulate and check output."""

    def __init__(
        self,
        stream: Iterator,
        engine: SafetyEngine,
        extract_output: Callable,
        policies: List[str]
    ):
        self._stream = stream
        self._engine = engine
        self._extract_output = extract_output
        self._policies = policies
        self._accumulated = ""
        self._finalized = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            chunk = next(self._stream)
            chunk_text = self._extract_output(chunk)
            if chunk_text:
                self._accumulated += chunk_text
            return chunk
        except StopIteration:
            self._finalize()
            raise

    def _finalize(self):
        """Called when stream ends - perform output safety check."""
        if self._finalized:
            return
        self._finalized = True

        if self._accumulated:
            result = self._engine.check(
                self._accumulated,
                self._policies,
                direction="output"
            )

            _add_safety_span_event("fortifyroot.safety.output", result, "output")

            if result.detections:
                logger.info(
                    f"FortifyRoot: Detected {len(result.detections)} items in output: "
                    f"{[d.rule_name for d in result.detections]}"
                )


class AsyncSafetyStreamWrapper:
    """Wraps an async stream to accumulate and check output."""

    def __init__(
        self,
        stream: AsyncIterator,
        engine: SafetyEngine,
        extract_output: Callable,
        policies: List[str]
    ):
        self._stream = stream
        self._engine = engine
        self._extract_output = extract_output
        self._policies = policies
        self._accumulated = ""
        self._finalized = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await self._stream.__anext__()
            chunk_text = self._extract_output(chunk)
            if chunk_text:
                self._accumulated += chunk_text
            return chunk
        except StopAsyncIteration:
            await self._finalize()
            raise

    async def _finalize(self):
        """Called when stream ends - perform output safety check."""
        if self._finalized:
            return
        self._finalized = True

        if self._accumulated:
            result = self._engine.check(
                self._accumulated,
                self._policies,
                direction="output"
            )

            _add_safety_span_event("fortifyroot.safety.output", result, "output")

            if result.detections:
                logger.info(
                    f"FortifyRoot: Detected {len(result.detections)} items in output"
                )


# ============================================================================
# Response Type Detection
# ============================================================================

def _is_streaming(response: Any) -> bool:
    """Check if response is a streaming response."""
    import types

    if isinstance(response, (types.GeneratorType, types.AsyncGeneratorType)):
        return True

    class_name = response.__class__.__name__.lower()
    if 'stream' in class_name:
        return True

    if hasattr(response, '__iter__') and hasattr(response, '__next__'):
        if not isinstance(response, (list, dict, str, bytes)):
            return True

    return False


def _is_async_streaming(response: Any) -> bool:
    """Check if response is an async streaming response."""
    import types

    if isinstance(response, types.AsyncGeneratorType):
        return True

    if hasattr(response, '__aiter__') and hasattr(response, '__anext__'):
        return True

    return False


# ============================================================================
# Safety Wrapper Factory
# ============================================================================

def _create_safety_wrapper(
    provider: str,
    is_async: bool
) -> Callable:
    """Create a safety wrapper for a provider method."""

    extract_input, extract_output = EXTRACTORS.get(
        provider,
        (_extract_input_generic, _extract_output_generic)
    )

    if is_async:
        async def async_wrapper(wrapped, instance, args, kwargs):
            if not _state.safety_engine:
                return await wrapped(*args, **kwargs)

            engine = _state.safety_engine
            policies = _state.policies

            # INPUT CHECK
            input_text = extract_input(kwargs)
            if input_text:
                result = engine.check(input_text, policies, direction="input")

                # Add span event for input safety
                _add_safety_span_event("fortifyroot.safety.input", result, "input")

                if result.action == Action.BLOCK:
                    raise FortifyRootBlocked(
                        result.message or "Input blocked by safety policy",
                        result.detections,
                        "input"
                    )
                elif result.action == Action.REDACT and result.modified_content:
                    kwargs = _modify_input(kwargs, result.modified_content)

            # CALL PROVIDER (OpenLLMetry span is active here)
            response = await wrapped(*args, **kwargs)

            # OUTPUT CHECK
            if _is_async_streaming(response):
                return AsyncSafetyStreamWrapper(
                    response, engine, extract_output, policies
                )
            elif _is_streaming(response):
                return SafetyStreamWrapper(
                    response, engine, extract_output, policies
                )
            else:
                output_text = extract_output(response)
                if output_text:
                    out_result = engine.check(output_text, policies, direction="output")

                    _add_safety_span_event("fortifyroot.safety.output", out_result, "output")

                    if out_result.action == Action.BLOCK:
                        raise FortifyRootBlocked(
                            out_result.message or "Output blocked by safety policy",
                            out_result.detections,
                            "output"
                        )

            return response

        return async_wrapper
    else:
        def sync_wrapper(wrapped, instance, args, kwargs):
            if not _state.safety_engine:
                return wrapped(*args, **kwargs)

            engine = _state.safety_engine
            policies = _state.policies

            # INPUT CHECK
            input_text = extract_input(kwargs)
            if input_text:
                result = engine.check(input_text, policies, direction="input")

                # Add span event for input safety
                _add_safety_span_event("fortifyroot.safety.input", result, "input")

                if result.action == Action.BLOCK:
                    raise FortifyRootBlocked(
                        result.message or "Input blocked by safety policy",
                        result.detections,
                        "input"
                    )
                elif result.action == Action.REDACT and result.modified_content:
                    kwargs = _modify_input(kwargs, result.modified_content)

            # CALL PROVIDER (OpenLLMetry span is active here)
            response = wrapped(*args, **kwargs)

            # OUTPUT CHECK
            if _is_streaming(response):
                return SafetyStreamWrapper(
                    response, engine, extract_output, policies
                )
            else:
                output_text = extract_output(response)
                if output_text:
                    out_result = engine.check(output_text, policies, direction="output")

                    _add_safety_span_event("fortifyroot.safety.output", out_result, "output")

                    if out_result.action == Action.BLOCK:
                        raise FortifyRootBlocked(
                            out_result.message or "Output blocked by safety policy",
                            out_result.detections,
                            "output"
                        )

            return response

        return sync_wrapper


# ============================================================================
# Public API
# ============================================================================

def observe(
    api_key: Optional[str] = None,
    app_name: Optional[str] = None,
    base_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    disable_batch: bool = False,
    **kwargs: Any
) -> None:
    """
    Enable observability via OpenLLMetry/traceloop-sdk.

    Traces and metrics are exported to the configured endpoint.

    Args:
        api_key: FortifyRoot API key. Can also be set via FORTIFYROOT_API_KEY env var.
        app_name: Application name for identification.
        base_url: Telemetry endpoint URL. Can also be set via FORTIFYROOT_BASE_URL env var.
        headers: Additional headers (e.g., for auth). Can also be set via FORTIFYROOT_HEADERS env var.
        disable_batch: If True, disable batching (useful for testing).
        **kwargs: Additional traceloop configuration options.
    """
    global _state

    if _state.observing:
        logger.debug("FortifyRoot observability already initialized")
        return

    # Read from env vars with fallback to arguments
    _api_key = api_key or os.environ.get('FORTIFYROOT_API_KEY')
    _base_url = base_url or os.environ.get('FORTIFYROOT_BASE_URL')
    _headers = headers

    # Parse headers from env var if provided
    if not _headers:
        headers_env = os.environ.get('FORTIFYROOT_HEADERS')
        if headers_env:
            _headers = {}
            for pair in headers_env.split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    _headers[k.strip()] = v.strip()

    try:
        from traceloop.sdk import Traceloop

        # Map FortifyRoot config to Traceloop config
        traceloop_kwargs: Dict[str, Any] = {
            'app_name': app_name or os.environ.get('FORTIFYROOT_APP_NAME', 'fortifyroot-app'),
            'disable_batch': disable_batch,
        }

        # Set API key if provided
        if _api_key:
            traceloop_kwargs['api_key'] = _api_key

        # Set custom endpoint if provided
        if _base_url:
            traceloop_kwargs['api_endpoint'] = _base_url

        # Set headers if provided
        if _headers:
            traceloop_kwargs['headers'] = _headers

        # Merge any additional kwargs
        traceloop_kwargs.update(kwargs)

        # Initialize Traceloop (which initializes all OpenLLMetry instrumentors)
        Traceloop.init(**traceloop_kwargs)

        # Wrap the span exporter for rebranding and PII redaction
        _wrap_span_exporter()

        _state.observing = True
        logger.info(f"FortifyRoot observability enabled for app: {traceloop_kwargs['app_name']}")

    except ImportError:
        logger.warning(
            "traceloop-sdk not installed. Install with: pip install traceloop-sdk\n"
            "Observability features will be disabled."
        )
    except Exception as e:
        logger.error(f"Failed to initialize observability: {e}")
        raise


def enforce(
    config_path: Optional[str] = None,
    config_dict: Optional[Dict[str, Any]] = None,
    policies: Optional[List[str]] = None,
    providers: Optional[List[str]] = None,
    api_key: Optional[str] = None,
    app_name: Optional[str] = None,
    base_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    disable_batch: bool = False,
    **kwargs: Any
) -> None:
    """
    Enable safety enforcement with implicit observability.

    This initializes both:
    1. Safety rules (PII/PCI/PHI/Secret detection, redaction, blocking)
    2. Observability via OpenLLMetry (traces and metrics)

    Args:
        config_path: Path to YAML configuration file.
        config_dict: Configuration dictionary (alternative to file).
        policies: List of policy groups to enforce (e.g., ["PII", "PCI", "SECRET"]).
                 If None, all policies from config are enabled.
        providers: List of providers to wrap (e.g., ["openai", "anthropic"]).
                  If None, all available providers are wrapped.
        api_key: FortifyRoot API key for telemetry.
        app_name: Application name for identification.
        base_url: Telemetry endpoint URL.
        headers: Additional headers for telemetry endpoint.
        disable_batch: If True, disable batching (useful for testing).
        **kwargs: Additional arguments passed to observe().
    """
    global _state

    if _state.initialized:
        logger.debug("FortifyRoot enforcement already initialized")
        return

    # 1. Initialize safety engine
    if config_path:
        _state.safety_engine = SafetyEngine(config_path=config_path)
    elif config_dict:
        _state.safety_engine = SafetyEngine(config_dict=config_dict)
    else:
        #raise FortifyRootConfigError("Must provide config_path or config_dict")
        _state.safety_engine = SafetyEngine()

    # 2. Set policies
    if policies:
        _state.policies = policies
    else:
        _state.policies = list(_state.safety_engine.policies)

    # 3. Wrap provider methods with safety wrappers FIRST
    # (Before OpenLLMetry, so safety wrappers are INNER)
    target_providers = providers or list(PROVIDER_METHODS.keys())

    for provider in target_providers:
        if provider not in PROVIDER_METHODS:
            logger.debug(f"Unknown provider: {provider}")
            continue

        for method_info in PROVIDER_METHODS[provider]:
            module_path, method_name, is_async = method_info

            wrapper_key = f"{module_path}.{method_name}"
            if wrapper_key in _state.wrapped_methods:
                continue

            try:
                wrapper = _create_safety_wrapper(provider, is_async)
                wrap_function_wrapper(module_path, method_name, wrapper)
                _state.wrapped_methods.add(wrapper_key)
                _state.enabled_providers.add(provider)
                logger.debug(f"Safety wrapper applied: {wrapper_key}")
            except (ImportError, AttributeError, ModuleNotFoundError) as e:
                logger.debug(f"Provider not available, skipping {wrapper_key}: {e}")
            except Exception as e:
                logger.warning(f"Failed to wrap {wrapper_key}: {e}")

    _state.initialized = True

    # 4. Initialize observability (OpenLLMetry wraps OUTSIDE safety wrappers)
    observe(
        api_key=api_key,
        app_name=app_name,
        base_url=base_url,
        headers=headers,
        disable_batch=disable_batch,
        **kwargs
    )

    # 5. Configure exporter wrapper with safety engine for PII redaction
    exporter_wrapper = _get_exporter_wrapper()
    if exporter_wrapper:
        exporter_wrapper.set_safety_engine(_state.safety_engine, _state.policies)

    logger.info(
        f"FortifyRoot enforcement enabled. "
        f"Policies: {_state.policies}. "
        f"Providers: {list(_state.enabled_providers)}"
    )


def is_enforcing() -> bool:
    """Check if safety enforcement is active."""
    return _state.initialized


def is_observing() -> bool:
    """Check if observability is active."""
    return _state.observing


def get_engine() -> Optional[SafetyEngine]:
    """Get the safety engine instance."""
    return _state.safety_engine


def check_text(
    text: str,
    policies: Optional[List[str]] = None,
    direction: str = "input"
) -> SafetyResult:
    """
    Manually check text content.

    Args:
        text: Text to check.
        policies: Policy groups (uses configured if None).
        direction: "input" or "output" - determines default action.

    Returns:
        SafetyResult with detections and action.
    """
    if not _state.safety_engine:
        raise FortifyRootConfigError("Safety engine not initialized. Call enforce() first.")

    return _state.safety_engine.check(
        text,
        policies or _state.policies,
        direction=direction
    )


def redact_text(text: str, policies: Optional[List[str]] = None) -> str:
    """
    Redact sensitive content from text.

    Args:
        text: Text to redact.
        policies: Policy groups (uses configured if None).

    Returns:
        Redacted text.
    """
    if not _state.safety_engine:
        raise FortifyRootConfigError("Safety engine not initialized. Call enforce() first.")

    detections = _state.safety_engine.detect(text, policies or _state.policies)
    return _state.safety_engine.redact(text, detections)


# ============================================================================
# Exports for backward compatibility
# ============================================================================

extract_text_from_content = _extract_text_from_content
extract_messages_text = _extract_messages_text
