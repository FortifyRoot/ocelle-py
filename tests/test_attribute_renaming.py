"""Tests for span attribute renaming."""

from typing import Any, Dict, Optional
from unittest import mock

import pytest


class TestRenameAttributes:
    """Tests for the rename_attributes function."""

    def test_renames_traceloop_prefix(self) -> None:
        """Test that traceloop.* attributes are renamed to fortifyroot.*."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        attributes: Dict[str, Any] = {
            "traceloop.span.kind": "workflow",
            "traceloop.workflow.name": "my_workflow",
            "traceloop.entity.name": "my_entity",
            "other.attribute": "value",
        }

        renamed, modified = rename_attributes(attributes)

        assert modified is True
        assert "fortifyroot.span.kind" in renamed
        assert "fortifyroot.workflow.name" in renamed
        assert "fortifyroot.entity.name" in renamed
        assert "other.attribute" in renamed
        assert renamed["fortifyroot.span.kind"] == "workflow"
        assert renamed["fortifyroot.workflow.name"] == "my_workflow"
        assert renamed["other.attribute"] == "value"

    def test_no_modification_when_no_traceloop_attrs(self) -> None:
        """Test that modified=False when no traceloop.* attributes exist."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        attributes: Dict[str, Any] = {
            "gen_ai.system": "openai",
            "gen_ai.request.model": "gpt-4",
            "http.method": "POST",
        }

        renamed, modified = rename_attributes(attributes)

        assert modified is False
        assert renamed == attributes

    def test_handles_none_attributes(self) -> None:
        """Test handling of None attributes."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        renamed, modified = rename_attributes(None)

        assert modified is False
        assert renamed == {}

    def test_handles_empty_attributes(self) -> None:
        """Test handling of empty attributes dict."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        renamed, modified = rename_attributes({})

        assert modified is False
        assert renamed == {}

    def test_preserves_attribute_values(self) -> None:
        """Test that attribute values are preserved during renaming."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        attributes: Dict[str, Any] = {
            "traceloop.entity.input": '{"key": "value"}',
            "traceloop.entity.output": "result string",
            "traceloop.entity.version": 42,
        }

        renamed, modified = rename_attributes(attributes)

        assert renamed["fortifyroot.entity.input"] == '{"key": "value"}'
        assert renamed["fortifyroot.entity.output"] == "result string"
        assert renamed["fortifyroot.entity.version"] == 42

    def test_handles_nested_traceloop_attributes(self) -> None:
        """Test renaming of nested traceloop attributes like traceloop.association.properties.*."""
        from fortifyroot.processors.attribute_renamer import rename_attributes

        attributes: Dict[str, Any] = {
            "traceloop.association.properties.user_id": "user_123",
            "traceloop.association.properties.session_id": "sess_456",
            "traceloop.prompt.template_variables.name": "John",
        }

        renamed, modified = rename_attributes(attributes)

        assert modified is True
        assert renamed["fortifyroot.association.properties.user_id"] == "user_123"
        assert renamed["fortifyroot.association.properties.session_id"] == "sess_456"
        assert renamed["fortifyroot.prompt.template_variables.name"] == "John"


def _create_mock_span(attributes: Optional[Dict[str, Any]] = None) -> mock.MagicMock:
    """Create a mock ReadableSpan for testing."""
    mock_span = mock.MagicMock()
    mock_span.name = mock_span._name = "test_span"
    mock_span.attributes = mock_span._attributes = attributes
    mock_span.context = mock_span._context = mock.MagicMock()
    mock_span.parent = mock_span._parent = None
    mock_span.resource = mock_span._resource = mock.MagicMock()
    mock_span.events = mock_span._events = ()
    mock_span.links = mock_span._links = ()
    mock_span.kind = mock_span._kind = mock.MagicMock()
    mock_span.status = mock_span._status = mock.MagicMock()
    mock_span.start_time = mock_span._start_time = 1000000000
    mock_span.end_time = mock_span._end_time = 2000000000
    mock_span.instrumentation_info = mock_span._instrumentation_info = None
    mock_span.instrumentation_scope = mock_span._instrumentation_scope = None
    return mock_span


class TestCreateRenamedSpan:
    """Tests for the create_renamed_span function."""

    def test_creates_new_span_with_renamed_attrs(self) -> None:
        """Test that a new span is created with renamed attributes."""
        from fortifyroot.processors.attribute_renamer import create_renamed_span

        original_span = _create_mock_span({
            "traceloop.span.kind": "task",
            "gen_ai.system": "openai",
        })

        renamed_span = create_renamed_span(original_span)

        # Should be a different object
        assert renamed_span is not original_span

        # Check attributes were renamed - use getattr to avoid type issues
        attrs = renamed_span.attributes
        assert "fortifyroot.span.kind" in attrs  # type: ignore[operator]
        assert "traceloop.span.kind" not in attrs  # type: ignore[operator]
        assert attrs["gen_ai.system"] == "openai"  # type: ignore[index]

    def test_returns_original_when_no_changes(self) -> None:
        """Test that original span is returned when no renaming needed."""
        from fortifyroot.processors.attribute_renamer import create_renamed_span

        original_span = _create_mock_span({
            "gen_ai.system": "openai",
            "http.method": "POST",
        })

        renamed_span = create_renamed_span(original_span)

        # Should return the same object
        assert renamed_span is original_span

    def test_preserves_span_metadata(self) -> None:
        """Test that span metadata (name, times, etc.) is preserved."""
        from fortifyroot.processors.attribute_renamer import create_renamed_span

        original_span = _create_mock_span({
            "traceloop.workflow.name": "test",
        })

        renamed_span = create_renamed_span(original_span)

        assert renamed_span.name == original_span.name
        assert renamed_span.start_time == original_span.start_time
        assert renamed_span.end_time == original_span.end_time

    def test_handles_none_attributes(self) -> None:
        """Test handling span with None attributes."""
        from fortifyroot.processors.attribute_renamer import create_renamed_span

        original_span = _create_mock_span(None)

        renamed_span = create_renamed_span(original_span)

        # Should return the same object (no changes needed)
        assert renamed_span is original_span

    def test_handles_empty_attributes(self) -> None:
        """Test handling span with empty attributes."""
        from fortifyroot.processors.attribute_renamer import create_renamed_span

        original_span = _create_mock_span({})

        renamed_span = create_renamed_span(original_span)

        # Should return the same object (no changes needed)
        assert renamed_span is original_span


class TestAttributeRenamingProcessor:
    """Tests for the AttributeRenamingProcessor class."""

    def test_processor_wraps_inner_processor(self) -> None:
        """Test that the processor correctly wraps another processor."""
        from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor

        mock_processor = mock.MagicMock()

        processor = AttributeRenamingProcessor(mock_processor)

        # Call shutdown
        processor.shutdown()
        mock_processor.shutdown.assert_called_once()

        # Call force_flush
        processor.force_flush(timeout_millis=5000)
        mock_processor.force_flush.assert_called_once_with(5000)

    def test_on_start_delegates_to_wrapped(self) -> None:
        """Test that on_start is delegated to wrapped processor."""
        from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor

        mock_processor = mock.MagicMock()
        processor = AttributeRenamingProcessor(mock_processor)

        mock_span = mock.MagicMock()
        mock_context = mock.MagicMock()

        processor.on_start(mock_span, mock_context)

        mock_processor.on_start.assert_called_once_with(mock_span, mock_context)

    def test_on_end_renames_and_delegates(self) -> None:
        """Test that on_end renames attributes before delegating."""
        from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor

        mock_processor = mock.MagicMock()
        processor = AttributeRenamingProcessor(mock_processor)

        # Create a mock span with traceloop attributes
        original_span = _create_mock_span({"traceloop.span.kind": "workflow"})

        processor.on_end(original_span)

        # Check that on_end was called
        mock_processor.on_end.assert_called_once()

        # Get the span that was passed to on_end
        call_args = mock_processor.on_end.call_args
        passed_span = call_args[0][0]

        # Check that attributes were renamed
        attrs = passed_span.attributes
        assert "fortifyroot.span.kind" in attrs  # type: ignore[operator]
        assert "traceloop.span.kind" not in attrs  # type: ignore[operator]

    def test_on_end_passes_original_when_no_changes(self) -> None:
        """Test that on_end passes original span when no renaming needed."""
        from fortifyroot.processors.attribute_renamer import AttributeRenamingProcessor

        mock_processor = mock.MagicMock()
        processor = AttributeRenamingProcessor(mock_processor)

        # Create a mock span without traceloop attributes
        original_span = _create_mock_span({"gen_ai.system": "openai"})

        processor.on_end(original_span)

        # Check that on_end was called with the original span
        mock_processor.on_end.assert_called_once_with(original_span)


class TestRenamedSpan:
    """Tests for the RenamedSpan wrapper class."""

    def test_renamed_span_returns_renamed_attributes(self) -> None:
        """Test that RenamedSpan returns the renamed attributes."""
        from fortifyroot.processors.attribute_renamer import RenamedSpan

        original_span = _create_mock_span({"traceloop.span.kind": "task"})
        renamed_attrs = {"fortifyroot.span.kind": "task"}

        renamed_span = RenamedSpan(original_span, renamed_attrs)

        assert renamed_span.attributes == renamed_attrs
        assert renamed_span.attributes["fortifyroot.span.kind"] == "task"  # type: ignore[index]

    def test_renamed_span_delegates_other_properties(self) -> None:
        """Test that RenamedSpan delegates other properties to original."""
        from fortifyroot.processors.attribute_renamer import RenamedSpan

        original_span = _create_mock_span({"traceloop.span.kind": "task"})
        renamed_attrs = {"fortifyroot.span.kind": "task"}

        renamed_span = RenamedSpan(original_span, renamed_attrs)

        assert renamed_span.name == original_span.name
        assert renamed_span.start_time == original_span.start_time
        assert renamed_span.end_time == original_span.end_time
        assert renamed_span.context == original_span.context
        assert renamed_span.resource == original_span.resource
