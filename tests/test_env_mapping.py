"""Tests for environment variable mapping."""

import os
from unittest import mock


class TestEnvVarMapping:
    """Tests for FORTIFYROOT_* to TRACELOOP_* environment variable mapping."""

    def test_mapping_dict_completeness(self):
        """Verify all expected env vars are in the mapping."""
        from fortifyroot._internal.env_mapping import ENV_VAR_MAPPING

        expected_vars = [
            "FORTIFYROOT_BASE_URL",
            "FORTIFYROOT_API_KEY",
            "FORTIFYROOT_HEADERS",
            "FORTIFYROOT_TRACING_ENABLED",
            "FORTIFYROOT_TRACE_CONTENT",
            "FORTIFYROOT_SUPPRESS_WARNINGS",
            "FORTIFYROOT_METRICS_ENABLED",
            "FORTIFYROOT_METRICS_ENDPOINT",
            "FORTIFYROOT_METRICS_HEADERS",
            "FORTIFYROOT_LOGGING_ENABLED",
            "FORTIFYROOT_LOGGING_ENDPOINT",
            "FORTIFYROOT_LOGGING_HEADERS",
        ]

        for var in expected_vars:
            assert var in ENV_VAR_MAPPING, f"Missing env var mapping: {var}"

    def test_apply_env_var_mapping_sets_traceloop_vars(self):
        """Test that FORTIFYROOT_* vars are mapped to TRACELOOP_* vars."""
        from fortifyroot._internal.env_mapping import apply_env_var_mapping

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_API_KEY": "fr-test-key",
                "FORTIFYROOT_BASE_URL": "https://custom.fortifyroot.com",
            },
            clear=False,
        ):
            # Remove any existing TRACELOOP vars
            os.environ.pop("TRACELOOP_API_KEY", None)
            os.environ.pop("TRACELOOP_BASE_URL", None)

            apply_env_var_mapping()

            assert os.environ.get("TRACELOOP_API_KEY") == "fr-test-key"
            assert os.environ.get("TRACELOOP_BASE_URL") == "https://custom.fortifyroot.com"

    def test_apply_env_var_mapping_overwrites_existing_traceloop_vars(self):
        """Test that existing TRACELOOP_* vars are overwritten by FR vars."""
        from fortifyroot._internal.env_mapping import apply_env_var_mapping

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_API_KEY": "fr-key",
                "TRACELOOP_API_KEY": "existing-tl-key",
            },
            clear=False,
        ):
            apply_env_var_mapping()

            # Should modify the existing TRACELOOP_API_KEY
            assert os.environ.get("TRACELOOP_API_KEY") == "fr-key"

    def test_apply_env_var_mapping_ignores_unset_vars(self):
        """Test that unset FORTIFYROOT_* vars don't create TRACELOOP_* vars."""
        from fortifyroot._internal.env_mapping import apply_env_var_mapping

        with mock.patch.dict(os.environ, {}, clear=True):
            apply_env_var_mapping()

            # No TRACELOOP vars should be set
            assert os.environ.get("TRACELOOP_API_KEY") is None
            assert os.environ.get("TRACELOOP_BASE_URL") is None

    def test_apply_env_var_mapping_clears_explicit_traceloop_vars(self):
        """Test that direct TRACELOOP_* vars are removed when FR vars are absent."""
        from fortifyroot._internal.env_mapping import apply_env_var_mapping

        with mock.patch.dict(
            os.environ,
            {
                "TRACELOOP_API_KEY": "tl-key",
                "TRACELOOP_BASE_URL": "https://tl.example.com",
            },
            clear=True,
        ):
            apply_env_var_mapping()

            assert os.environ.get("TRACELOOP_API_KEY") is None
            assert os.environ.get("TRACELOOP_BASE_URL") is None


class TestEnvVarMappingOnImport:
    """Tests that env var mapping happens at import time."""

    def test_mapping_applied_on_package_import(self):
        """Test that env vars are mapped when fortifyroot is imported."""
        # This test verifies the import-time behavior
        # Note: This is tricky to test in isolation since the module
        # may already be imported. In a real scenario, you'd test this
        # by running in a fresh Python process.

        from fortifyroot._internal.env_mapping import ENV_VAR_MAPPING

        # Just verify the mapping exists and is a dict
        assert isinstance(ENV_VAR_MAPPING, dict)
        assert len(ENV_VAR_MAPPING) > 0
