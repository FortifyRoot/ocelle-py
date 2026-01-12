"""Tests for fortifyroot.init() function."""

import os
from unittest import mock

import pytest


class TestInit:
    """Tests for the init() function."""

    def test_init_function_exists(self):
        """Test that init function is exported from fortifyroot."""
        from fortifyroot import init

        assert callable(init)

    def test_init_has_expected_parameters(self):
        """Test that init has the expected parameter signature."""
        import inspect
        from fortifyroot import init

        sig = inspect.signature(init)
        params = sig.parameters

        # Check expected parameters exist
        assert "app_name" in params
        assert "api_endpoint" in params
        assert "api_key" in params
        assert "enabled" in params
        assert "disable_batch" in params
        assert "trace_content" in params
        assert "instruments" in params
        assert "block_instruments" in params
        assert "resource_attributes" in params

    def test_default_api_endpoint(self):
        """Test that default API endpoint is fortifyroot.com."""
        from fortifyroot.core import DEFAULT_API_ENDPOINT

        assert DEFAULT_API_ENDPOINT == "https://api.fortifyroot.com"

    def test_set_association_properties_exported(self):
        """Test that set_association_properties is exported."""
        from fortifyroot import set_association_properties

        assert callable(set_association_properties)


class TestVersion:
    """Tests for version handling."""

    def test_version_exported(self):
        """Test that __version__ is exported from fortifyroot."""
        from fortifyroot import __version__

        assert isinstance(__version__, str)
        # Should be semver-like
        parts = __version__.split(".")
        assert len(parts) >= 2

    def test_version_matches_module(self):
        """Test that exported version matches version module."""
        from fortifyroot import __version__
        from fortifyroot.version import __version__ as module_version

        assert __version__ == module_version


class TestPublicAPI:
    """Tests for public API completeness."""

    def test_all_exports_defined(self):
        """Test that __all__ is defined and contains expected items."""
        import fortifyroot

        assert hasattr(fortifyroot, "__all__")

        expected_exports = [
            "init",
            "set_association_properties",
            "configure",
            "FortifyRootConfig",
            "task",
            "workflow",
            "agent",
            "tool",
            "Instruments",
            "__version__",
        ]

        for export in expected_exports:
            assert export in fortifyroot.__all__, f"Missing export: {export}"

    def test_no_traceloop_in_public_api(self):
        """Test that 'traceloop' doesn't appear in public API names."""
        import fortifyroot

        for name in fortifyroot.__all__:
            assert "traceloop" not in name.lower(), f"Traceloop leak in: {name}"


class TestResourceAttributes:
    """Tests for resource attribute handling."""

    def test_sdk_version_attribute_constant(self):
        """Test that SDK version attribute constant is defined."""
        from fortifyroot._internal.constants import FORTIFYROOT_SDK_VERSION_ATTRIBUTE

        assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE == "fortifyroot.sdk.version"


class TestTraceContentParameter:
    """Tests for trace_content parameter handling."""

    def test_trace_content_default_is_true(self):
        """Test that trace_content defaults to True."""
        import inspect
        from fortifyroot import init

        sig = inspect.signature(init)
        trace_content_param = sig.parameters["trace_content"]

        assert trace_content_param.default is True
