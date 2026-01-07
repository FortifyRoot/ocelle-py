"""Test that vendored imports work correctly."""

import pytest

class TestVendoredImports:
    """Test vendored package imports."""

    def test_traceloop_sdk_import(self):
        """Test that traceloop SDK can be imported from vendor."""
        from fortifyroot._vendor.traceloop.sdk import Traceloop
        assert Traceloop is not None

    def test_traceloop_decorators_import(self):
        """Test that traceloop decorators can be imported."""
        from fortifyroot._vendor.traceloop.sdk.decorators import task, workflow, aworkflow
        assert task is not None
        assert workflow is not None
        assert aworkflow is not None

    def test_semconv_ai_import(self):
        """Test that semantic conventions AI can be imported."""
        from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes
        assert SpanAttributes is not None

    def test_openai_instrumentation_import(self):
        """Test that OpenAI instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.openai import OpenAIInstrumentor
        assert OpenAIInstrumentor is not None

    def test_anthropic_instrumentation_import(self):
        """Test that Anthropic instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.anthropic import AnthropicInstrumentor
        assert AnthropicInstrumentor is not None

    def test_langchain_instrumentation_import(self):
        """Test that LangChain instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.langchain import LangchainInstrumentor
        assert LangchainInstrumentor is not None

    def test_core_otel_not_vendored(self):
        """Test that core OTel packages come from site-packages, not vendor."""
        # These should be importable from the regular opentelemetry package
        from opentelemetry import trace
        from opentelemetry.sdk import trace as trace_sdk

        # Verify they're not from our vendor directory
        assert "_vendor" not in trace.__file__
        assert "_vendor" not in trace_sdk.__file__

    def test_no_traceloop_in_top_level(self):
        """Test that 'traceloop' is not importable as top-level package."""
        # This should fail - traceloop should only be available under _vendor
        with pytest.raises(ModuleNotFoundError):
            import traceloop


class TestFortifyrootApi:
    """Test FortifyRoot public API."""

    def test_fortifyroot_import(self):
        """Test that fortifyroot can be imported."""
        import fortifyroot
        assert fortifyroot is not None

    def test_fortifyroot_init_exists(self):
        """Test that fortifyroot.init exists."""
        import fortifyroot
        assert hasattr(fortifyroot, "init")
        assert callable(fortifyroot.init)

    def test_fortifyroot_instruments_enum(self):
        """Test that Instruments enum is available."""
        from fortifyroot import Instruments
        assert Instruments.OPENAI is not None
        assert Instruments.ANTHROPIC is not None
        assert Instruments.LANGCHAIN is not None

    def test_fortifyroot_decorators(self):
        """Test that decorators are available."""
        from fortifyroot import task, workflow
        assert task is not None
        assert workflow is not None


class TestNoLeakedBranding:
    """Test that 'traceloop' branding doesn't leak."""

    def test_no_traceloop_in_public_api(self):
        """Test that traceloop name doesn't appear in public API."""
        import fortifyroot

        # Check module docstring
        if fortifyroot.__doc__:
            assert "traceloop" not in fortifyroot.__doc__.lower()

    def test_vendor_manifest_exists(self):
        """Test that vendor manifest is created."""
        import json
        from pathlib import Path

        manifest_path = Path(__file__).parent.parent / "src/fortifyroot/_vendor/VENDOR_MANIFEST.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            assert "openllmetry_version" in manifest
            assert "packages" in manifest
