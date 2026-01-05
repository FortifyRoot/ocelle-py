"""Span processor for renaming traceloop.* attributes to fortifyroot.*."""

from typing import Any, Dict, Mapping, Optional, Tuple

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
from opentelemetry.util.types import Attributes

from fortifyroot._internal.constants import (
    ATTRIBUTE_PREFIX_FORTIFYROOT,
    ATTRIBUTE_PREFIX_TRACELOOP,
)


def rename_attributes(
    attributes: Optional[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], bool]:
    """
    Rename traceloop.* attributes to fortifyroot.* attributes.

    Args:
        attributes: Original span attributes mapping.

    Returns:
        Tuple of (renamed_attributes_dict, was_modified_bool)
    """
    if attributes is None:
        return {}, False

    renamed: Dict[str, Any] = {}
    modified = False

    for key, value in attributes.items():
        if key.startswith(ATTRIBUTE_PREFIX_TRACELOOP):
            # Rename traceloop.* to fortifyroot.*
            new_key = ATTRIBUTE_PREFIX_FORTIFYROOT + key[len(ATTRIBUTE_PREFIX_TRACELOOP):]
            renamed[new_key] = value
            modified = True
        else:
            renamed[key] = value

    return renamed, modified


class RenamedSpan(ReadableSpan):
    """
    A ReadableSpan wrapper that presents renamed attributes.

    This class wraps an original ReadableSpan and copies all instance attributes
    from the original, then overrides only the attributes with renamed values.
    This approach is robust against OpenTelemetry SDK version changes.
    """

    def __init__(self, original: ReadableSpan, renamed_attributes: Attributes) -> None:
        """
        Initialize RenamedSpan by shallow-copying all attributes from original.

        Args:
            original: The original ReadableSpan to wrap.
            renamed_attributes: The renamed attributes to use.
        """
        # Shallow copy all instance attributes from original span
        # This ensures compatibility with any OTEL version without manually
        # tracking which properties exist
        for key, value in original.__dict__.items():
            self.__dict__[key] = value

        # Override _attributes with renamed version
        # The parent class's attributes property will return this value
        self._attributes = renamed_attributes


def create_renamed_span(original: ReadableSpan) -> ReadableSpan:
    """
    Create a new ReadableSpan with renamed attributes.

    Args:
        original: The original ReadableSpan.

    Returns:
        A ReadableSpan with traceloop.* attributes renamed to fortifyroot.*.
    """
    # Get original attributes as a dict
    original_attrs = dict(original.attributes) if original.attributes else {}

    # Rename attributes
    renamed_attrs, was_modified = rename_attributes(original_attrs)

    if not was_modified:
        # No changes needed, return original
        return original

    # Return a wrapper span with renamed attributes
    return RenamedSpan(original, renamed_attrs)


class AttributeRenamingProcessor(SpanProcessor):
    """
    SpanProcessor that renames traceloop.* attributes to fortifyroot.*.

    This processor wraps another SpanProcessor and intercepts spans
    in on_end to rename attributes before passing to the wrapped processor.
    """

    def __init__(self, wrapped_processor: SpanProcessor) -> None:
        """
        Initialize the AttributeRenamingProcessor.

        Args:
            wrapped_processor: The underlying SpanProcessor to delegate to.
        """
        self._wrapped_processor = wrapped_processor

    def on_start(
        self,
        span: Span,
        parent_context: Optional[Context] = None,
    ) -> None:
        """Called when a span is started. Delegates to wrapped processor."""
        self._wrapped_processor.on_start(span, parent_context)

    def on_end(self, span: ReadableSpan) -> None:
        """
        Called when a span ends. Renames attributes and delegates to wrapped processor.

        Args:
            span: The ReadableSpan that has ended.
        """
        renamed_span = create_renamed_span(span)
        self._wrapped_processor.on_end(renamed_span)

    def shutdown(self) -> None:
        """Shuts down the wrapped processor."""
        self._wrapped_processor.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Forces flush on the wrapped processor."""
        return self._wrapped_processor.force_flush(timeout_millis)
