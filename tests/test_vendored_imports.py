"""Test that vendored imports work correctly."""

import importlib
import json
import builtins
import sys
from pathlib import Path

import pytest


class TestVendoredImports:
    """Test vendored package imports."""

    def test_traceloop_sdk_import(self):
        """Test that traceloop SDK can be imported from vendor."""
        from fortifyroot._vendor.tracer.sdk import Traceloop
        assert Traceloop is not None

    def test_traceloop_decorators_import(self):
        """Test that traceloop decorators can be imported."""
        from fortifyroot._vendor.tracer.sdk.decorators import task, workflow, aworkflow
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

    def test_litellm_instrumentation_import(self):
        """Test that LiteLLM instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.litellm import LiteLLMInstrumentor
        assert LiteLLMInstrumentor is not None

    def test_bedrock_instrumentation_import(self):
        """Test that Bedrock instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.bedrock import BedrockInstrumentor
        assert BedrockInstrumentor is not None

    def test_bedrock_instrumentation_import_without_anthropic(self, monkeypatch):
        """Test that Bedrock import does not require the optional Anthropic package."""
        module_name = "fortifyroot._vendor.opentelemetry.instrumentation.bedrock.span_utils"
        sys.modules.pop(module_name, None)
        sys.modules.pop("anthropic", None)

        original_import = builtins.__import__

        def import_without_anthropic(name, *args, **kwargs):
            if name == "anthropic":
                raise ModuleNotFoundError("No module named 'anthropic'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", import_without_anthropic)

        module = importlib.import_module(module_name)

        assert module is not None

    def test_bedrock_init_does_not_crash_without_anthropic(self, monkeypatch):
        """Test default Bedrock init handles boto3-present/anthropic-absent envs."""
        from fortifyroot._vendor.opentelemetry.instrumentation.bedrock import (
            BedrockInstrumentor,
        )
        from fortifyroot._vendor.tracer.sdk.tracing import tracing

        monkeypatch.setattr(
            tracing,
            "is_package_installed",
            lambda package_name: package_name == "boto3",
        )
        monkeypatch.setattr(
            BedrockInstrumentor,
            "is_instrumented_by_opentelemetry",
            False,
            raising=False,
        )
        monkeypatch.setattr(BedrockInstrumentor, "instrument", lambda self: None)
        sys.modules.pop("anthropic", None)

        original_import = builtins.__import__

        def import_without_anthropic(name, *args, **kwargs):
            if name == "anthropic":
                raise ModuleNotFoundError("No module named 'anthropic'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", import_without_anthropic)

        assert tracing.init_bedrock_instrumentor(False) is True

    def test_google_generativeai_instrumentation_import(self):
        """Test that Google GenAI instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.google_generativeai import (
            GoogleGenerativeAiInstrumentor,
        )
        assert GoogleGenerativeAiInstrumentor is not None

    def test_llamaindex_instrumentation_import(self):
        """Test that LlamaIndex instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation.llamaindex import LlamaIndexInstrumentor
        assert LlamaIndexInstrumentor is not None

    def test_fortifyroot_instrumentation_import(self):
        """Test that the FortifyRoot safety bridge instrumentation can be imported."""
        from fortifyroot._vendor.opentelemetry.instrumentation import fortifyroot
        assert fortifyroot is not None

    def test_post_mvp_instrumentation_not_vendored(self):
        """Test that every disabled post-MVP instrumentation is not bundled."""
        vendor_manifest = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "fortifyroot"
            / "_vendor"
            / "VENDOR_MANIFEST.json"
        )
        policy = json.loads(vendor_manifest.read_text())[
            "instrumentation_package_policy"
        ]
        disabled_modules = [
            package.removeprefix("opentelemetry-instrumentation-").replace("-", "_")
            for package, should_vendor in policy.items()
            if not should_vendor
        ]

        assert disabled_modules
        for module_name in disabled_modules:
            with pytest.raises(ModuleNotFoundError):
                importlib.import_module(
                    f"fortifyroot._vendor.opentelemetry.instrumentation.{module_name}"
                )

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
            import traceloop  # noqa: F401

    def test_no_traceloop_vendor_package(self):
        """Test that the vendored tracer SDK is not stored under traceloop."""
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("fortifyroot._vendor.traceloop")


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

    def test_fortifyroot_configure_exists(self):
        """Test that fortifyroot.configure exists (fluent API)."""
        import fortifyroot
        assert hasattr(fortifyroot, "configure")
        assert callable(fortifyroot.configure)

    def test_fortifyroot_instruments_enum(self):
        """Test that Instruments enum is available."""
        from fortifyroot import Instruments
        assert Instruments.OPENAI is not None
        assert Instruments.ANTHROPIC is not None
        assert Instruments.LANGCHAIN is not None
        assert Instruments.LITELLM is not None

    def test_fortifyroot_decorators(self):
        """Test that decorators are available."""
        from fortifyroot import task, workflow
        assert task is not None
        assert workflow is not None


class TestNoLeakedBranding:
    """Test that 'traceloop' branding doesn't leak in public API."""

    def test_no_traceloop_in_public_api(self):
        """Test that traceloop name doesn't appear in public API docstrings."""
        import fortifyroot

        # Check module docstring
        if fortifyroot.__doc__:
            assert "traceloop" not in fortifyroot.__doc__.lower(), \
                "Module docstring should not mention 'traceloop'"

    def test_no_traceloop_in_init_docstring(self):
        """Test that init() docstring doesn't mention traceloop."""
        import fortifyroot

        if fortifyroot.init.__doc__:
            # Allow technical references but not branding
            doc_lower = fortifyroot.init.__doc__.lower()
            # "traceloop" as a brand should not appear
            # But internal references like "_vendor.tracer" are OK
            assert "traceloop sdk" not in doc_lower
            assert "traceloop api" not in doc_lower

    def test_vendor_manifest_exists(self):
        """Test that vendor manifest is created."""
        import json
        from pathlib import Path

        manifest_path = Path(__file__).parent.parent / "src/fortifyroot/_vendor/VENDOR_MANIFEST.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            assert "openllmetry_version" in manifest
            assert "packages" in manifest


class TestFluentApi:
    """Test the fluent configuration API."""

    def test_configure_returns_config_object(self):
        """Test that configure() returns a FortifyRootConfig object."""
        import fortifyroot

        config = fortifyroot.configure()
        assert config is not None
        assert isinstance(config, fortifyroot.FortifyRootConfig)

    def test_fluent_methods_return_self(self):
        """Test that fluent methods return self for chaining."""
        import fortifyroot

        config = fortifyroot.configure()

        # Each method should return the same config object
        result = config.app_name("test")
        assert result is config

        result = config.api_key("test-key")
        assert result is config

        result = config.trace_content(False)
        assert result is config

    def test_fluent_config_has_init(self):
        """Test that FortifyRootConfig has init() method."""
        import fortifyroot

        config = fortifyroot.configure()
        assert hasattr(config, "init")
        assert callable(config.init)


class TestInitParameters:
    """Test that init() has all expected parameters."""

    def test_init_has_basic_parameters(self):
        """Test init() has basic parameters."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        # Basic parameters
        assert "app_name" in params
        assert "api_endpoint" in params
        assert "api_key" in params
        assert "enabled" in params

    def test_init_has_tracing_parameters(self):
        """Test init() has tracing configuration parameters."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        # Tracing parameters
        assert "trace_content" in params
        assert "disable_batch" in params
        assert "exporter" in params
        assert "processors" in params
        assert "sampler" in params
        assert "propagator" in params

    def test_init_has_metrics_parameters(self):
        """Test init() has metrics configuration parameters."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        # Metrics parameters
        assert "metrics_exporter" in params
        assert "metrics_headers" in params
        assert "should_enrich_metrics" in params

    def test_init_has_logging_parameters(self):
        """Test init() has logging configuration parameters."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        # Logging parameters
        assert "logging_exporter" in params
        assert "logging_headers" in params

    def test_init_has_instrumentation_parameters(self):
        """Test init() has instrumentation parameters."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        # Instrumentation parameters
        assert "instruments" in params
        assert "block_instruments" in params
        assert "resource_attributes" in params

    def test_init_has_callback_parameter(self):
        """Test init() has span_postprocess_callback parameter."""
        import inspect
        import fortifyroot

        sig = inspect.signature(fortifyroot.init)
        params = sig.parameters

        assert "span_postprocess_callback" in params
        assert "stream_holdback_chars" in params
