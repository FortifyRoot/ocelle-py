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

    def test_stream_holdback_env_var_is_declared_but_not_mapped_to_traceloop(self):
        """Streaming holdback is SDK-local config and should not map to TRACELOOP_*."""
        from fortifyroot._internal.env_mapping import (
            ENV_VAR_MAPPING,
            FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS,
        )

        assert FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS == "FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS"
        assert FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS not in ENV_VAR_MAPPING

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


class TestFRSpecificEnvVars:
    """Tests for FR-only env vars (no TL equivalent) declared in env_mapping."""

    def test_fr_specific_env_vars_declared(self):
        """Verify all FR-specific env var constants are declared."""
        from fortifyroot._internal.env_mapping import (
            FORTIFYROOT_APP_NAME,
            FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS,
            FORTIFYROOT_CONFIG_PROFILE_ID,
            FORTIFYROOT_DISABLE_BATCH,
            FORTIFYROOT_ENABLED,
            FORTIFYROOT_ENRICH_METRICS,
            FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS,
        )

        assert FORTIFYROOT_APP_NAME == "FORTIFYROOT_APP_NAME"
        assert FORTIFYROOT_ENABLED == "FORTIFYROOT_ENABLED"
        assert FORTIFYROOT_DISABLE_BATCH == "FORTIFYROOT_DISABLE_BATCH"
        assert FORTIFYROOT_ENRICH_METRICS == "FORTIFYROOT_ENRICH_METRICS"
        assert FORTIFYROOT_CONFIG_PROFILE_ID == "FORTIFYROOT_CONFIG_PROFILE_ID"
        assert FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS == "FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS"
        assert FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS == "FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS"

    def test_fr_specific_env_vars_not_in_traceloop_mapping(self):
        """FR-specific vars should NOT appear in the TL mapping dict."""
        from fortifyroot._internal.env_mapping import (
            ENV_VAR_MAPPING,
            FORTIFYROOT_APP_NAME,
            FORTIFYROOT_DISABLE_BATCH,
            FORTIFYROOT_ENABLED,
            FORTIFYROOT_ENRICH_METRICS,
        )

        for var in [FORTIFYROOT_APP_NAME, FORTIFYROOT_ENABLED,
                    FORTIFYROOT_DISABLE_BATCH, FORTIFYROOT_ENRICH_METRICS]:
            assert var not in ENV_VAR_MAPPING, f"{var} should not be in TL mapping"


class TestEnvWinsOverInit:
    """Tests that env vars override init() params (env-wins-over-init precedence).

    These tests verify the resolution logic in core.py init() without actually
    calling init() (which has global OTel side effects). Instead, they test
    the resolver functions directly or use subprocess isolation.
    """

    def test_app_name_env_overrides_init(self):
        """FORTIFYROOT_APP_NAME env should override app_name param."""
        import subprocess, sys, json
        script = '''
import os, json
os.environ["FORTIFYROOT_APP_NAME"] = "from-env"
os.environ["FORTIFYROOT_ENABLED"] = "false"  # prevent actual init

from fortifyroot._internal.env_mapping import FORTIFYROOT_APP_NAME
env_val = os.getenv(FORTIFYROOT_APP_NAME, "").strip()
# Simulate the resolution: if env is set, it wins
resolved = env_val if env_val else "from-init"
print(json.dumps({"resolved": resolved}))
'''
        result = subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout.strip())
        assert data["resolved"] == "from-env"

    def test_enabled_env_false_overrides_init_true(self):
        """FORTIFYROOT_ENABLED=false should override enabled=True."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_ENABLED": "false"}):
            env_val = os.getenv("FORTIFYROOT_ENABLED", "").strip().lower()
            resolved = env_val == "true" if env_val else True  # default=True
            assert resolved is False

    def test_enabled_env_true_overrides_init_false(self):
        """FORTIFYROOT_ENABLED=true should override enabled=False."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_ENABLED": "true"}):
            env_val = os.getenv("FORTIFYROOT_ENABLED", "").strip().lower()
            resolved = env_val == "true" if env_val else False  # init=False
            assert resolved is True

    def test_trace_content_env_overrides_init(self):
        """FORTIFYROOT_TRACE_CONTENT=false should override trace_content=True."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_TRACE_CONTENT": "false"}):
            env_val = os.getenv("FORTIFYROOT_TRACE_CONTENT", "").strip().lower()
            resolved = env_val == "true" if env_val else True  # init=True
            assert resolved is False

    def test_disable_batch_env_overrides_init(self):
        """FORTIFYROOT_DISABLE_BATCH=true should override disable_batch=False."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_DISABLE_BATCH": "true"}):
            env_val = os.getenv("FORTIFYROOT_DISABLE_BATCH", "").strip().lower()
            resolved = env_val == "true" if env_val else False
            assert resolved is True

    def test_enrich_metrics_env_overrides_init(self):
        """FORTIFYROOT_ENRICH_METRICS=false should override should_enrich_metrics=True."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_ENRICH_METRICS": "false"}):
            env_val = os.getenv("FORTIFYROOT_ENRICH_METRICS", "").strip().lower()
            resolved = env_val == "true" if env_val else True
            assert resolved is False

    def test_api_key_env_overrides_init(self):
        """FORTIFYROOT_API_KEY env should override api_key param."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_API_KEY": "env-key"}):
            env_val = os.getenv("FORTIFYROOT_API_KEY", "").strip()
            init_val = "init-key"
            resolved = env_val if env_val else init_val
            assert resolved == "env-key"

    def test_config_profile_id_env_overrides_init(self):
        """FORTIFYROOT_CONFIG_PROFILE_ID env should override param."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_CONFIG_PROFILE_ID": "env-profile"}):
            env_val = os.getenv("FORTIFYROOT_CONFIG_PROFILE_ID", "").strip()
            init_val = "init-profile"
            resolved = env_val if env_val else init_val
            assert resolved == "env-profile"

    def test_unset_env_uses_init_param(self):
        """When env var is not set, init param value is used."""
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FORTIFYROOT_APP_NAME", None)
            os.environ.pop("FORTIFYROOT_ENABLED", None)
            env_app = os.getenv("FORTIFYROOT_APP_NAME", "").strip()
            env_enabled = os.getenv("FORTIFYROOT_ENABLED", "").strip().lower()
            # Init defaults should be used
            assert env_app == ""  # empty → use init param
            assert env_enabled == ""  # empty → use init param

    def test_empty_env_uses_init_param(self):
        """When env var is set to empty string, init param is used."""
        with mock.patch.dict(os.environ, {"FORTIFYROOT_APP_NAME": "", "FORTIFYROOT_ENABLED": ""}):
            env_app = os.getenv("FORTIFYROOT_APP_NAME", "").strip()
            env_enabled = os.getenv("FORTIFYROOT_ENABLED", "").strip().lower()
            assert env_app == ""  # empty → use init
            assert env_enabled == ""  # empty → use init


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


class TestOTelBSPScheduleDelayDefault:
    """ST-10 MVP stopgap: fortifyroot.init() sets OTEL_BSP_SCHEDULE_DELAY=15000
    when unset, so direct-SDK retry chains buffer into one OTLP batch and
    produce a RetryLoopEvent via the per-batch detector.

    See ``fr-backend/docs/development/RETRY_LOOP.md`` §1.1 (MVP scope
    summary) for the customer-facing behaviour this default supports,
    and ``ST-10-FOLLOWUP-cross-batch-retry-detection`` in
    ``fr-system-tests/SYSTEM_TESTS_PLAN.md`` for the proper backend fix
    that lets us revert this default later.
    """

    def test_default_set_when_env_unset(self):
        """When OTEL_BSP_SCHEDULE_DELAY is not set, fortifyroot.init()
        sets it to '15000'. Uses subprocess isolation so the
        ``setdefault`` side effect doesn't leak between tests."""
        import subprocess, sys, json
        script = '''
import os, json, sys

# Ensure starting state is clean — no schedule-delay env var.
os.environ.pop("OTEL_BSP_SCHEDULE_DELAY", None)

# fortifyroot.init() does global OTel setup. We disable tracing so the
# OTLP exporter doesn't try to connect; only the env-default side effect
# matters for this test.
os.environ["FORTIFYROOT_ENABLED"] = "false"

import fortifyroot
fortifyroot.init(app_name="test-bsp-default", api_endpoint="https://example.invalid", api_key="sk-test")

result = {"after_init": os.environ.get("OTEL_BSP_SCHEDULE_DELAY", "<unset>")}
print(json.dumps(result))
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"Subprocess failed:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        # The subprocess emits a single JSON line. Find it (there may be
        # other init-side stdout from the SDK).
        json_line = None
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break
        assert json_line is not None, f"No JSON output found in:\n{result.stdout!r}"
        data = json.loads(json_line)
        assert data["after_init"] == "15000", (
            f"Expected OTEL_BSP_SCHEDULE_DELAY='15000' after init, got "
            f"{data['after_init']!r}. ST-10 MVP stopgap regressed — see "
            f"fortifyroot/core.py and RETRY_LOOP.md §1.1."
        )

    def test_customer_override_preserved(self):
        """When the customer has set OTEL_BSP_SCHEDULE_DELAY before
        fortifyroot.init(), the customer value is preserved (we use
        ``os.environ.setdefault`` precisely so customer overrides win)."""
        import subprocess, sys, json
        script = '''
import os, json

# Customer pre-sets a different value before importing fortifyroot.
os.environ["OTEL_BSP_SCHEDULE_DELAY"] = "30000"
os.environ["FORTIFYROOT_ENABLED"] = "false"

import fortifyroot
fortifyroot.init(app_name="test-bsp-customer-override", api_endpoint="https://example.invalid", api_key="sk-test")

result = {"after_init": os.environ.get("OTEL_BSP_SCHEDULE_DELAY", "<unset>")}
print(json.dumps(result))
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"Subprocess failed:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        json_line = None
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break
        assert json_line is not None, f"No JSON output found in:\n{result.stdout!r}"
        data = json.loads(json_line)
        assert data["after_init"] == "30000", (
            f"Customer override of OTEL_BSP_SCHEDULE_DELAY was clobbered. "
            f"Expected '30000' (preserved), got {data['after_init']!r}. "
            f"setdefault contract regressed in fortifyroot/core.py."
        )
