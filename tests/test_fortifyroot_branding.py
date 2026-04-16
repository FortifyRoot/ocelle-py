"""Tests verifying traceloop-to-fortifyroot attribute rebranding is complete.

After vendoring the rebranded fork, ALL telemetry signals (traces, metrics, logs)
must emit 'fortifyroot.*' attribute keys. No 'traceloop.*' attribute strings should
survive in the vendored SDK source code (except in the Traceloop API client, which
FR does not use).
"""

import os
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# 1. Semconv constants resolve to fortifyroot.* values
# ---------------------------------------------------------------------------

class TestSemconvConstants:
    """Verify vendored semconv_ai constants emit fortifyroot.* values."""

    def test_workflow_constants_use_fortifyroot_prefix(self):
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes

        assert SpanAttributes.FORTIFYROOT_SPAN_KIND == "fortifyroot.span.kind"
        assert SpanAttributes.FORTIFYROOT_WORKFLOW_NAME == "fortifyroot.workflow.name"
        assert SpanAttributes.FORTIFYROOT_ENTITY_NAME == "fortifyroot.entity.name"
        assert SpanAttributes.FORTIFYROOT_ENTITY_PATH == "fortifyroot.entity.path"
        assert SpanAttributes.FORTIFYROOT_ENTITY_VERSION == "fortifyroot.entity.version"
        assert SpanAttributes.FORTIFYROOT_ENTITY_INPUT == "fortifyroot.entity.input"
        assert SpanAttributes.FORTIFYROOT_ENTITY_OUTPUT == "fortifyroot.entity.output"
        assert SpanAttributes.FORTIFYROOT_ASSOCIATION_PROPERTIES == "fortifyroot.association.properties"

    def test_prompt_constants_use_fortifyroot_prefix(self):
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes

        assert SpanAttributes.FORTIFYROOT_PROMPT_MANAGED == "fortifyroot.prompt.managed"
        assert SpanAttributes.FORTIFYROOT_PROMPT_KEY == "fortifyroot.prompt.key"
        assert SpanAttributes.FORTIFYROOT_PROMPT_VERSION == "fortifyroot.prompt.version"
        assert SpanAttributes.FORTIFYROOT_PROMPT_VERSION_NAME == "fortifyroot.prompt.version_name"
        assert SpanAttributes.FORTIFYROOT_PROMPT_VERSION_HASH == "fortifyroot.prompt.version_hash"
        assert SpanAttributes.FORTIFYROOT_PROMPT_TEMPLATE == "fortifyroot.prompt.template"
        assert SpanAttributes.FORTIFYROOT_PROMPT_TEMPLATE_VARIABLES == "fortifyroot.prompt.template_variables"

    def test_correlation_constant_uses_fortifyroot_prefix(self):
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes

        assert SpanAttributes.FORTIFYROOT_CORRELATION_ID == "fortifyroot.correlation.id"

    def test_backward_compat_aliases_resolve_to_fortifyroot(self):
        """TRACELOOP_* aliases must resolve to fortifyroot.* values (not traceloop.*)."""
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes

        assert SpanAttributes.TRACELOOP_SPAN_KIND == "fortifyroot.span.kind"
        assert SpanAttributes.TRACELOOP_WORKFLOW_NAME == "fortifyroot.workflow.name"
        assert SpanAttributes.TRACELOOP_ENTITY_NAME == "fortifyroot.entity.name"
        assert SpanAttributes.TRACELOOP_ENTITY_PATH == "fortifyroot.entity.path"
        assert SpanAttributes.TRACELOOP_ENTITY_VERSION == "fortifyroot.entity.version"
        assert SpanAttributes.TRACELOOP_ENTITY_INPUT == "fortifyroot.entity.input"
        assert SpanAttributes.TRACELOOP_ENTITY_OUTPUT == "fortifyroot.entity.output"
        assert SpanAttributes.TRACELOOP_ASSOCIATION_PROPERTIES == "fortifyroot.association.properties"
        assert SpanAttributes.TRACELOOP_PROMPT_MANAGED == "fortifyroot.prompt.managed"
        assert SpanAttributes.TRACELOOP_PROMPT_KEY == "fortifyroot.prompt.key"
        assert SpanAttributes.TRACELOOP_PROMPT_VERSION == "fortifyroot.prompt.version"
        assert SpanAttributes.TRACELOOP_PROMPT_VERSION_NAME == "fortifyroot.prompt.version_name"
        assert SpanAttributes.TRACELOOP_PROMPT_VERSION_HASH == "fortifyroot.prompt.version_hash"
        assert SpanAttributes.TRACELOOP_PROMPT_TEMPLATE == "fortifyroot.prompt.template"
        assert SpanAttributes.TRACELOOP_PROMPT_TEMPLATE_VARIABLES == "fortifyroot.prompt.template_variables"
        assert SpanAttributes.TRACELOOP_CORRELATION_ID == "fortifyroot.correlation.id"

    def test_span_kind_enum_alias(self):
        from fortifyroot._vendor.opentelemetry.semconv_ai import (
            FortifyrootSpanKindValues,
            TraceloopSpanKindValues,
        )

        assert TraceloopSpanKindValues is FortifyrootSpanKindValues
        assert FortifyrootSpanKindValues.WORKFLOW.value == "workflow"
        assert FortifyrootSpanKindValues.TASK.value == "task"
        assert FortifyrootSpanKindValues.AGENT.value == "agent"
        assert FortifyrootSpanKindValues.TOOL.value == "tool"


# ---------------------------------------------------------------------------
# 2. metrics_common_attributes() returns fortifyroot.* keys
# ---------------------------------------------------------------------------

class TestMetricsCommonAttributes:
    """Verify metrics_common_attributes() emits fortifyroot.* attribute keys."""

    def test_workflow_name_uses_fortifyroot_key(self):
        from unittest.mock import patch
        from fortifyroot._vendor.traceloop.sdk.tracing.tracing import (
            metrics_common_attributes,
        )

        with patch(
            "fortifyroot._vendor.traceloop.sdk.tracing.tracing.get_value"
        ) as mock_get:
            mock_get.side_effect = lambda key: {
                "workflow_name": "test-wf",
                "entity_name": None,
                "association_properties": None,
            }.get(key)

            attrs = metrics_common_attributes()

        assert "fortifyroot.workflow.name" in attrs
        assert attrs["fortifyroot.workflow.name"] == "test-wf"
        assert not any(k.startswith("traceloop.") for k in attrs)

    def test_entity_name_uses_fortifyroot_key(self):
        from unittest.mock import patch
        from fortifyroot._vendor.traceloop.sdk.tracing.tracing import (
            metrics_common_attributes,
        )

        with patch(
            "fortifyroot._vendor.traceloop.sdk.tracing.tracing.get_value"
        ) as mock_get:
            mock_get.side_effect = lambda key: {
                "workflow_name": None,
                "entity_name": "test-entity",
                "association_properties": None,
            }.get(key)

            attrs = metrics_common_attributes()

        assert "fortifyroot.entity.name" in attrs
        assert attrs["fortifyroot.entity.name"] == "test-entity"
        assert not any(k.startswith("traceloop.") for k in attrs)

    def test_association_properties_use_fortifyroot_prefix(self):
        from unittest.mock import patch
        from fortifyroot._vendor.traceloop.sdk.tracing.tracing import (
            metrics_common_attributes,
        )

        with patch(
            "fortifyroot._vendor.traceloop.sdk.tracing.tracing.get_value"
        ) as mock_get:
            mock_get.side_effect = lambda key: {
                "workflow_name": None,
                "entity_name": None,
                "association_properties": {
                    "user_id": "u-123",
                    "session_id": "s-456",
                },
            }.get(key)

            attrs = metrics_common_attributes()

        assert "fortifyroot.association.properties.user_id" in attrs
        assert "fortifyroot.association.properties.session_id" in attrs
        assert attrs["fortifyroot.association.properties.user_id"] == "u-123"
        assert not any(k.startswith("traceloop.") for k in attrs)

    def test_all_attributes_combined(self):
        from unittest.mock import patch
        from fortifyroot._vendor.traceloop.sdk.tracing.tracing import (
            metrics_common_attributes,
        )

        with patch(
            "fortifyroot._vendor.traceloop.sdk.tracing.tracing.get_value"
        ) as mock_get:
            mock_get.side_effect = lambda key: {
                "workflow_name": "checkout",
                "entity_name": "process_payment",
                "association_properties": {"org": "acme"},
            }.get(key)

            attrs = metrics_common_attributes()

        assert len(attrs) == 3
        assert attrs["fortifyroot.workflow.name"] == "checkout"
        assert attrs["fortifyroot.entity.name"] == "process_payment"
        assert attrs["fortifyroot.association.properties.org"] == "acme"
        # No traceloop.* keys in ANY position
        for key in attrs:
            assert not key.startswith("traceloop."), f"Found traceloop key: {key}"


# ---------------------------------------------------------------------------
# 3. Vendor directory scan: no "traceloop. attribute strings survive
# ---------------------------------------------------------------------------

class TestVendorDirectoryScan:
    """Scan _vendor/ for surviving 'traceloop.' attribute string literals."""

    def _get_vendor_root(self) -> Path:
        import fortifyroot._vendor as vendor_pkg

        return Path(vendor_pkg.__file__).parent

    def test_no_traceloop_attribute_strings_in_semconv(self):
        """semconv_ai/ must have zero 'traceloop.' string literals."""
        vendor_root = self._get_vendor_root()
        semconv_dir = vendor_root / "opentelemetry" / "semconv_ai"

        violations = []
        for py_file in semconv_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(content.splitlines(), 1):
                if '"traceloop.' in line or "'traceloop." in line:
                    violations.append(f"{py_file.name}:{i}: {line.strip()}")

        assert violations == [], (
            f"Found 'traceloop.' strings in semconv_ai:\n"
            + "\n".join(violations)
        )

    def test_no_traceloop_attribute_strings_in_sdk_source(self):
        """traceloop/sdk/ source (excluding client/) must have zero 'traceloop.' string literals."""
        vendor_root = self._get_vendor_root()
        sdk_dir = vendor_root / "traceloop" / "sdk"

        violations = []
        for py_file in sdk_dir.rglob("*.py"):
            # Skip the Traceloop API client (FR does not use it)
            rel = py_file.relative_to(sdk_dir)
            if str(rel).startswith("client"):
                continue

            content = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(content.splitlines(), 1):
                if '"traceloop.' in line or "'traceloop." in line:
                    violations.append(
                        f"{rel}:{i}: {line.strip()}"
                    )

        assert violations == [], (
            f"Found 'traceloop.' attribute strings in SDK source:\n"
            + "\n".join(violations)
        )
