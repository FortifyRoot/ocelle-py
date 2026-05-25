"""Tests for fortifyroot.init() function."""

import os
from unittest import mock

import pytest

from fortifyroot.core import (
    _cumulative_preferred_temporality,
    _get_authorization_header,
    _normalize_http_otlp_endpoint,
    _resolve_signal_headers,
    _resolve_stream_holdback_chars,
    _sdk_metadata_headers,
    _with_sdk_metadata_headers,
)


# Expected temporality mapping passed to every OTLP metrics exporter
# construction — see `fortifyroot.core._cumulative_preferred_temporality`
# and the Issue-I1 banner in st_phase_8.txt for why this must be
# CUMULATIVE across the board. Computed once here so all nine existing
# `metric_exporter_cls.assert_called_once_with(...)` sites stay consistent
# if the mapping ever legitimately changes.
_EXPECTED_TEMPORALITY = _cumulative_preferred_temporality()


def _headers_with_sdk_metadata(headers=None):
    return _with_sdk_metadata_headers(headers or {})


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
        assert "config_profile_id" in params
        assert "config_poll_interval_seconds" in params

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

    def test_version_matches_package_metadata_from_pyproject(self):
        """Test that __version__ resolves to pyproject's package version."""
        import re
        from pathlib import Path
        from fortifyroot import __version__

        pyproject = Path(__file__).parents[1] / "pyproject.toml"
        match = re.search(r'(?m)^version = "([^"]+)"', pyproject.read_text())
        assert match is not None
        assert __version__ == match.group(1)


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
            "TextSafetyDetector",
            "TextSafetyMatch",
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

    def test_stream_holdback_chars_has_minimum_of_sixteen(self):
        """Test that streaming holdback enforces a safety-meaningful minimum of 16."""
        assert _resolve_stream_holdback_chars(0) == 16
        assert _resolve_stream_holdback_chars(-5) == 16
        assert _resolve_stream_holdback_chars(1) == 16
        assert _resolve_stream_holdback_chars(15) == 16
        assert _resolve_stream_holdback_chars(16) == 16
        assert _resolve_stream_holdback_chars(17) == 17
        assert _resolve_stream_holdback_chars(128) == 128


class TestSafetyRuntimeBootstrap:
    """Tests for safety runtime bootstrap wiring from init()."""

    def test_init_configures_safety_runtime_with_explicit_values(self):
        """Test that init wires explicit safety runtime configuration."""
        from fortifyroot import init

        with (
            mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
            mock.patch("fortifyroot.core.Traceloop.init"),
            mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
        ):
            init(
                app_name="fortifyroot-test",
                api_endpoint="https://api.fortifyroot.com",
                api_key="fr-key",
                enabled=True,
                config_profile_id="cfg-123",
                config_poll_interval_seconds=15,
                stream_holdback_chars=256,
            )

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-123",
            poll_interval_seconds=15,
            stream_holdback_chars=256,
        )

    def test_init_configures_safety_runtime_from_environment(self):
        """Test that init resolves safety runtime config from environment."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_API_KEY": "env-key",
                "FORTIFYROOT_CONFIG_PROFILE_ID": "cfg-env",
                "FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS": "25",
                "FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS": "192",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
            ):
                init(app_name="fortifyroot-test")

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="env-key",
            config_profile_id="cfg-env",
            poll_interval_seconds=25,
            stream_holdback_chars=192,
        )

    def test_init_invalid_poll_interval_env_falls_back_to_default(self):
        """Test that invalid poll interval env values fall back to the default."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_API_KEY": "env-key",
                "FORTIFYROOT_CONFIG_PROFILE_ID": "cfg-env",
                "FORTIFYROOT_CONFIG_POLL_INTERVAL_SECONDS": "not-an-int",
                "FORTIFYROOT_SAFETY_STREAM_HOLDBACK_CHARS": "not-an-int",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
            ):
                init(app_name="fortifyroot-test")

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="env-key",
            config_profile_id="cfg-env",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

    def test_init_ignores_traceloop_base_url_when_fr_base_url_is_absent(self):
        """Test that init ignores direct TRACELOOP_BASE_URL fallback."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "TRACELOOP_BASE_URL": "https://collector.example.com",
                "FORTIFYROOT_API_KEY": "env-key",
                "FORTIFYROOT_CONFIG_PROFILE_ID": "cfg-env",
            },
            clear=False,
        ):
            os.environ.pop("FORTIFYROOT_BASE_URL", None)
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
            ):
                init(app_name="fortifyroot-test")

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="env-key",
            config_profile_id="cfg-env",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )

    def test_init_uses_fortifyroot_base_url_when_set(self):
        """Test that init honors FORTIFYROOT_BASE_URL."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_BASE_URL": "https://dev-api.fortifyroot.com",
                "FORTIFYROOT_API_KEY": "env-key",
                "FORTIFYROOT_CONFIG_PROFILE_ID": "cfg-env",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
            ):
                init(app_name="fortifyroot-test")

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://dev-api.fortifyroot.com",
            api_key="env-key",
            config_profile_id="cfg-env",
            poll_interval_seconds=60,
            stream_holdback_chars=128,
        )


class TestInitOptionalPaths:
    """Tests for less common init/configuration paths."""

    def test_init_uses_api_key_for_default_trace_metrics_and_logging_auth(self):
        """Test that api_key alone authenticates traces, metrics, and logs."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENABLED": "true",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        auth_headers = _headers_with_sdk_metadata({"Authorization": "Bearer fr-key"})
        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            headers=auth_headers,
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/metrics",
            headers=auth_headers,
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        logging_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/logs",
            headers=auth_headers,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["headers"] == auth_headers
        assert kwargs["metrics_headers"] == auth_headers
        assert kwargs["logging_headers"] == auth_headers
        assert kwargs["metrics_exporter"] is created_metrics_exporter
        assert kwargs["logging_exporter"] is created_logging_exporter

    def test_init_requires_auth_for_default_managed_fortifyroot_exports(self):
        """Test that hosted FortifyRoot exports fail fast without auth."""
        from fortifyroot import init

        with (
            mock.patch("fortifyroot.core.Traceloop.get_default_span_processor") as default_processor_mock,
            mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
            mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
        ):
            with pytest.raises(
                ValueError,
                match="default FortifyRoot traces, metrics export",
            ):
                init(app_name="fortifyroot-test")

        default_processor_mock.assert_not_called()
        traceloop_init_mock.assert_not_called()
        runtime_mock.assert_not_called()

    def test_init_rejects_x_api_key_as_managed_export_auth(self):
        """Test that managed FortifyRoot OTLP export requires Authorization auth."""
        from fortifyroot import init

        with (
            mock.patch("fortifyroot.core.Traceloop.get_default_span_processor") as default_processor_mock,
            mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
            mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
        ):
            with pytest.raises(
                ValueError,
                match="default FortifyRoot traces, metrics export",
            ):
                init(
                    app_name="fortifyroot-test",
                    headers={"X-API-Key": "fr-key"},
                )

        default_processor_mock.assert_not_called()
        traceloop_init_mock.assert_not_called()
        runtime_mock.assert_not_called()

    def test_init_allows_unauthenticated_custom_collector_endpoint(self):
        """Test that custom OTLP collectors can still be used without FortifyRoot auth."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENABLED": "false",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_endpoint="http://localhost:4318",
                )

        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="http://localhost:4318",
            api_key=None,
            headers={},
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="http://localhost:4318/v1/metrics",
            headers={},
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["headers"] == {}

    def test_init_inherits_trace_authorization_into_signal_headers(self):
        """Test that explicit trace Authorization is reused for metrics and logs by default."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENABLED": "true",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    headers={"Authorization": "Bearer explicit", "x-trace": "1"},
                    metrics_headers={"x-metrics": "2"},
                    logging_headers={"x-logs": "3"},
                )

        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="https://api.fortifyroot.com",
            api_key=None,
            headers=_headers_with_sdk_metadata(
                {"Authorization": "Bearer explicit", "x-trace": "1"}
            ),
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/metrics",
            headers=_headers_with_sdk_metadata(
                {"x-metrics": "2", "Authorization": "Bearer explicit"}
            ),
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        logging_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/logs",
            headers=_headers_with_sdk_metadata({"x-logs": "3", "Authorization": "Bearer explicit"}),
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["metrics_headers"] == _headers_with_sdk_metadata({
            "x-metrics": "2",
            "Authorization": "Bearer explicit",
        })
        assert kwargs["logging_headers"] == _headers_with_sdk_metadata({
            "x-logs": "3",
            "Authorization": "Bearer explicit",
        })

    def test_init_uses_api_key_for_custom_collector_trace_metrics_and_logging_auth(self):
        """Test that api_key bearer auth is applied consistently for non-FortifyRoot collectors."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "https://metrics.example.com",
                "FORTIFYROOT_LOGGING_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENDPOINT": "https://logs.example.com",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_endpoint="https://collector.example.com",
                    api_key="collector-key",
                )

        auth_headers = {"Authorization": "Bearer collector-key"}
        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="https://collector.example.com",
            api_key="collector-key",
            headers=auth_headers,
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://metrics.example.com/v1/metrics",
            headers=auth_headers,
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        logging_exporter_cls.assert_called_once_with(
            endpoint="https://logs.example.com/v1/logs",
            headers=auth_headers,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["headers"] == auth_headers
        assert kwargs["metrics_headers"] == auth_headers
        assert kwargs["logging_headers"] == auth_headers
        assert kwargs["logging_exporter"] is created_logging_exporter

    def test_init_requires_auth_for_managed_fortifyroot_metrics_endpoint(self):
        """Test that FortifyRoot metrics export requires auth even when traces go elsewhere."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "https://api.fortifyroot.com",
                "FORTIFYROOT_LOGGING_ENABLED": "false",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor") as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime") as runtime_mock,
            ):
                with pytest.raises(
                    ValueError,
                    match="default FortifyRoot metrics export",
                ):
                    init(
                        app_name="fortifyroot-test",
                        api_endpoint="https://collector.example.com",
                    )

        default_processor_mock.assert_not_called()
        traceloop_init_mock.assert_not_called()
        runtime_mock.assert_not_called()

    def test_init_allows_custom_metrics_endpoint_without_auth_when_traces_use_custom_processors(self):
        """Test that non-FortifyRoot metrics endpoints are not blocked by FortifyRoot auth checks."""
        from fortifyroot import init

        processor = mock.Mock()
        created_metrics_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "https://metrics.example.com",
                "FORTIFYROOT_LOGGING_ENABLED": "false",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_endpoint="https://api.fortifyroot.com",
                    processors=[processor],
                )

        metric_exporter_cls.assert_called_once_with(
            endpoint="https://metrics.example.com/v1/metrics",
            headers={},
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["metrics_exporter"] is created_metrics_exporter
        assert "metrics_headers" not in kwargs

    def test_init_uses_grpc_metrics_exporter_for_grpc_metrics_endpoint(self):
        """Test that gRPC metrics endpoints stay on the gRPC exporter path."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "grpcs://metrics.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        metric_exporter_cls.assert_called_once_with(
            endpoint="metrics.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=False,
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )

    def test_init_uses_grpc_logging_exporter_for_grpc_logging_endpoint(self):
        """Test that gRPC logging endpoints stay on the gRPC exporter path."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_LOGGING_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENDPOINT": "grpc://logs.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
                mock.patch(
                    "fortifyroot.core._init_default_metrics_exporter",
                    return_value=mock.Mock(),
                ),
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        logging_exporter_cls.assert_called_once_with(
            endpoint="logs.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=True,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["logging_exporter"] is created_logging_exporter

    def test_init_builds_default_processor_metrics_exporter_and_optional_kwargs(self):
        """Test default processor path, metrics exporter autowiring, and optional kwargs."""
        from fortifyroot import init

        default_processor = mock.Mock()
        logging_exporter = mock.Mock()
        propagator = mock.Mock()
        created_metrics_exporter = mock.Mock()
        trace_content_value = None

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_BASE_URL": "https://env.fortifyroot.com",
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "https://metrics.fortifyroot.com",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                    headers={"x-trace": "1"},
                    metrics_headers={"x-metrics": "2"},
                    logging_exporter=logging_exporter,
                    logging_headers={"x-logs": "3"},
                    propagator=propagator,
                    trace_content=False,
                )
                trace_content_value = os.environ["TRACELOOP_TRACE_CONTENT"]

        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="https://env.fortifyroot.com",
            api_key="fr-key",
            headers={
                "x-trace": "1",
                "Authorization": "Bearer fr-key",
            } | _sdk_metadata_headers(),
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://metrics.fortifyroot.com/v1/metrics",
            headers={
                "x-metrics": "2",
                "Authorization": "Bearer fr-key",
            } | _sdk_metadata_headers(),
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["api_endpoint"] == "https://env.fortifyroot.com"
        assert kwargs["headers"] == {
            "x-trace": "1",
            "Authorization": "Bearer fr-key",
        } | _sdk_metadata_headers()
        assert kwargs["logging_exporter"] is logging_exporter
        assert "logging_headers" not in kwargs
        assert kwargs["metrics_headers"] == {
            "x-metrics": "2",
            "Authorization": "Bearer fr-key",
        } | _sdk_metadata_headers()
        assert kwargs["metrics_exporter"] is created_metrics_exporter
        assert kwargs["propagator"] is propagator
        assert trace_content_value == "false"

    def test_init_wraps_single_custom_processor(self):
        """Test the single-processor path used for custom processor injection."""
        from fortifyroot import init

        processor = mock.Mock()

        with (
            mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
            mock.patch("fortifyroot.core.configure_global_safety_runtime"),
        ):
            init(
                app_name="fortifyroot-test",
                api_key="fr-key",
                exporter=mock.Mock(),
                processors=processor,
                metrics_exporter=mock.Mock(),
            )

        _, kwargs = traceloop_init_mock.call_args
        wrapped_processor = kwargs["processor"]
        assert wrapped_processor is not None
        assert wrapped_processor is not processor


class TestFluentConfig:
    """Tests for the fluent builder API."""

    def test_configure_builder_captures_values_and_calls_init(self):
        """Test that the fluent builder forwards all configured values to init()."""
        from fortifyroot import Instruments, configure

        exporter = mock.Mock()
        metrics_exporter = mock.Mock()
        logging_exporter = mock.Mock()
        processor = mock.Mock()
        propagator = mock.Mock()
        sampler = mock.Mock()
        callback = mock.Mock()

        with mock.patch("fortifyroot.core.init") as init_mock:
            (
                configure()
                .app_name("builder-app")
                .api_endpoint("https://api.fortifyroot.com")
                .api_key("fr-key")
                .enabled(False)
                .headers({"x-trace": "1"})
                .disable_batch(True)
                .trace_content(False)
                .exporter(exporter)
                .metrics_exporter(metrics_exporter)
                .metrics_headers({"x-metrics": "2"})
                .logging_exporter(logging_exporter)
                .logging_headers({"x-logs": "3"})
                .processors([processor])
                .propagator(propagator)
                .sampler(sampler)
                .should_enrich_metrics(False)
                .resource_attributes({"team": "ml"})
                .instruments({Instruments.OPENAI})
                .block_instruments({Instruments.COHERE})
                .span_postprocess_callback(callback)
                .config_profile_id("cfg-123")
                .config_poll_interval_seconds(15)
                .stream_holdback_chars(256)
                .allow_udf_detectors(True)
                .init()
            )

        init_mock.assert_called_once_with(
            app_name="builder-app",
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            enabled=False,
            headers={"x-trace": "1"},
            disable_batch=True,
            trace_content=False,
            exporter=exporter,
            metrics_exporter=metrics_exporter,
            metrics_headers={"x-metrics": "2"},
            logging_exporter=logging_exporter,
            logging_headers={"x-logs": "3"},
            processors=[processor],
            propagator=propagator,
            sampler=sampler,
            should_enrich_metrics=False,
            resource_attributes={"team": "ml"},
            instruments={Instruments.OPENAI},
            block_instruments={Instruments.COHERE},
            span_postprocess_callback=callback,
            config_profile_id="cfg-123",
            config_poll_interval_seconds=15,
            stream_holdback_chars=256,
            allow_udf_detectors=True,
        )


class TestGetAuthorizationHeader:
    """Tests for _get_authorization_header helper."""

    def test_returns_none_when_no_authorization_header(self):
        """Test that _get_authorization_header returns None when no auth header exists."""
        result = _get_authorization_header({"x-custom": "value", "content-type": "json"})
        assert result is None

    def test_returns_none_for_empty_headers(self):
        """Test that _get_authorization_header returns None for empty dict."""
        result = _get_authorization_header({})
        assert result is None

    def test_returns_none_when_auth_header_is_blank(self):
        """Test that blank Authorization values are treated as absent."""
        result = _get_authorization_header({"Authorization": "  "})
        assert result is None


class TestResolveSignalHeaders:
    """Tests for _resolve_signal_headers edge cases."""

    def test_signal_headers_with_own_auth_skips_inheritance(self):
        """Test that signal headers with explicit auth do not inherit from fallback."""
        result = _resolve_signal_headers(
            headers={"Authorization": "Bearer signal-key", "x-signal": "1"},
            fallback_headers={"Authorization": "Bearer fallback-key", "x-trace": "2"},
            api_key=None,
            include_sdk_metadata=True,
        )
        assert result["Authorization"] == "Bearer signal-key"
        assert result["x-signal"] == "1"
        assert result["X-FortifyRoot-SDK-Language"] == "python"
        # Fallback headers should NOT be merged in
        assert "x-trace" not in result

    def test_signal_headers_without_auth_and_fallback_without_auth(self):
        """Test signal headers when neither has auth and no api_key."""
        result = _resolve_signal_headers(
            headers={"x-signal": "1"},
            fallback_headers={"x-trace": "2"},
            api_key=None,
            include_sdk_metadata=True,
        )
        assert result == _headers_with_sdk_metadata({"x-signal": "1"})
        assert "Authorization" not in result

    def test_signal_headers_without_auth_inherits_from_fallback_and_applies_api_key(self):
        """Test that api_key fills in when neither signal nor fallback has auth."""
        result = _resolve_signal_headers(
            headers={"x-signal": "1"},
            fallback_headers={"x-trace": "2"},
            api_key="my-key",
            include_sdk_metadata=True,
        )
        assert result == _headers_with_sdk_metadata(
            {"x-signal": "1", "Authorization": "Bearer my-key"}
        )

    def test_signal_headers_strip_fallback_sdk_metadata_for_custom_endpoint(self):
        """Test custom signal endpoints inherit auth without leaking SDK metadata."""
        result = _resolve_signal_headers(
            headers=None,
            fallback_headers=_headers_with_sdk_metadata(
                {"Authorization": "Bearer trace-key", "x-trace": "2"}
            ),
            api_key=None,
            include_sdk_metadata=False,
        )

        assert result == {"Authorization": "Bearer trace-key", "x-trace": "2"}


class TestSDKMetadataHeaders:
    """Tests for SDK metadata export headers."""

    def test_sdk_metadata_headers_include_expected_values(self):
        import platform
        from fortifyroot import __version__

        assert _sdk_metadata_headers() == {
            "X-FortifyRoot-SDK-Version": __version__,
            "X-FortifyRoot-SDK-Language": "python",
            "X-FortifyRoot-SDK-Language-Version": platform.python_version(),
        }

    def test_sdk_metadata_headers_override_stale_values_case_insensitively(self):
        result = _with_sdk_metadata_headers(
            {
                "x-fortifyroot-sdk-version": "stale",
                "X-FortifyRoot-SDK-Language": "ruby",
                "X-FortifyRoot-SDK-Language-Version": "3.7.0",
            }
        )

        assert "x-fortifyroot-sdk-version" not in result
        assert result["X-FortifyRoot-SDK-Version"] != "stale"
        assert result["X-FortifyRoot-SDK-Language"] == "python"
        assert result["X-FortifyRoot-SDK-Language-Version"] != "3.7.0"

    def test_sdk_metadata_and_x_api_key_do_not_count_as_export_auth(self):
        from fortifyroot.core import _has_authorization_header

        assert not _has_authorization_header(_sdk_metadata_headers())
        assert _has_authorization_header(
            _headers_with_sdk_metadata({"Authorization": "Bearer fr-key"})
        )
        assert not _has_authorization_header(
            _headers_with_sdk_metadata({"X-API-Key": "fr-key"})
        )


class TestIsManagedFortifyRootEndpoint:
    """Boundary tests for managed-endpoint detection."""

    @pytest.mark.parametrize(
        "endpoint,expected",
        [
            ("https://api.fortifyroot.com", True),
            ("https://fortifyroot.com", True),
            ("https://metrics.fortifyroot.com/v1/metrics", True),
            ("https://evilfortifyroot.com", False),
            ("https://fortifyroot.com.attacker.net", False),
            ("https://fortifyroot.dev", False),
            ("https://api.fortifyroot.dev", False),
            ("http://localhost:4318", False),
            ("", False),
        ],
    )
    def test_managed_endpoint_boundaries(self, endpoint, expected):
        from fortifyroot.core import _is_managed_fortifyroot_endpoint

        assert _is_managed_fortifyroot_endpoint(endpoint) is expected


class TestNormalizeHttpOtlpEndpoint:
    """Tests for _normalize_http_otlp_endpoint edge cases."""

    def test_does_not_double_append_suffix(self):
        """Test that suffix is not appended when endpoint already has it."""
        result = _normalize_http_otlp_endpoint(
            "https://api.example.com/v1/metrics", "/v1/metrics"
        )
        assert result == "https://api.example.com/v1/metrics"

    def test_strips_trailing_slash_before_appending(self):
        """Test that trailing slashes are stripped before suffix check."""
        result = _normalize_http_otlp_endpoint(
            "https://api.example.com/", "/v1/logs"
        )
        assert result == "https://api.example.com/v1/logs"

    def test_appends_suffix_when_missing(self):
        """Test that suffix is appended when not already present."""
        result = _normalize_http_otlp_endpoint(
            "https://api.example.com", "/v1/metrics"
        )
        assert result == "https://api.example.com/v1/metrics"


class TestMetricsExporterSchemes:
    """Tests for _init_default_metrics_exporter scheme branches."""

    def test_grpc_scheme_creates_insecure_grpc_metrics_exporter(self):
        """Test that grpc:// scheme creates an insecure gRPC metrics exporter."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "grpc://metrics.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        metric_exporter_cls.assert_called_once_with(
            endpoint="metrics.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=True,
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )

    def test_unknown_scheme_creates_insecure_grpc_metrics_exporter(self):
        """Test that an unknown scheme falls back to insecure gRPC metrics exporter."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_metrics_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "custom://metrics.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter",
                    return_value=created_metrics_exporter,
                ) as metric_exporter_cls,
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        metric_exporter_cls.assert_called_once_with(
            endpoint="custom://metrics.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=True,
            preferred_temporality=_EXPECTED_TEMPORALITY,
        )


class TestLoggingExporterSchemes:
    """Tests for _init_default_logging_exporter scheme branches."""

    def test_grpcs_scheme_creates_secure_grpc_logging_exporter(self):
        """Test that grpcs:// scheme creates a secure gRPC logging exporter."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_LOGGING_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENDPOINT": "grpcs://logs.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
                mock.patch(
                    "fortifyroot.core._init_default_metrics_exporter",
                    return_value=mock.Mock(),
                ),
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        logging_exporter_cls.assert_called_once_with(
            endpoint="logs.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=False,
        )

    def test_unknown_scheme_creates_insecure_grpc_logging_exporter(self):
        """Test that an unknown scheme falls back to insecure gRPC logging exporter."""
        from fortifyroot import init

        default_processor = mock.Mock()
        created_logging_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_LOGGING_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENDPOINT": "custom://logs.example.com:4317",
            },
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                    return_value=default_processor,
                ),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
                mock.patch(
                    "opentelemetry.exporter.otlp.proto.grpc._log_exporter.OTLPLogExporter",
                    return_value=created_logging_exporter,
                ) as logging_exporter_cls,
                mock.patch(
                    "fortifyroot.core._init_default_metrics_exporter",
                    return_value=mock.Mock(),
                ),
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        logging_exporter_cls.assert_called_once_with(
            endpoint="custom://logs.example.com:4317",
            headers={"Authorization": "Bearer fr-key"},
            insecure=True,
        )


class TestValidateDefaultExportAuth:
    """Tests for _validate_default_export_auth edge cases."""

    def test_requires_auth_for_managed_fortifyroot_logging_endpoint(self):
        """Test that FortifyRoot logging export requires auth (line 343 coverage)."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "false",
                "FORTIFYROOT_LOGGING_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENDPOINT": "https://api.fortifyroot.com",
            },
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor"),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
            ):
                with pytest.raises(
                    ValueError,
                    match="default FortifyRoot.*logs export",
                ):
                    init(
                        app_name="fortifyroot-test",
                        api_endpoint="https://collector.example.com",
                    )

    def test_requires_auth_for_all_managed_signals(self):
        """Test that all three signals appear when all go to FortifyRoot without auth."""
        from fortifyroot import init

        with mock.patch.dict(
            os.environ,
            {
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_LOGGING_ENABLED": "true",
            },
            clear=False,
        ):
            os.environ.pop("FORTIFYROOT_METRICS_ENDPOINT", None)
            os.environ.pop("FORTIFYROOT_LOGGING_ENDPOINT", None)
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor"),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
            ):
                with pytest.raises(
                    ValueError,
                    match="traces, metrics, logs export",
                ):
                    init(app_name="fortifyroot-test")


class TestInitExporterBranch:
    """Tests for init() when a custom exporter is provided (line 600 branch)."""

    def test_custom_exporter_skips_default_processor_creation(self):
        """Test that providing exporter skips default processor creation."""
        from fortifyroot import init

        custom_exporter = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {"FORTIFYROOT_METRICS_ENABLED": "false"},
            clear=False,
        ):
            with (
                mock.patch(
                    "fortifyroot.core.Traceloop.get_default_span_processor",
                ) as default_processor_mock,
                mock.patch("fortifyroot.core.Traceloop.init") as traceloop_init_mock,
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                    exporter=custom_exporter,
                )

        # Default processor should NOT be created when custom exporter is provided
        default_processor_mock.assert_not_called()
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["exporter"] is custom_exporter
        assert kwargs["processor"] is None


class TestAllowUdfDetectors:
    """Tests for allow_udf_detectors parameter in init()."""

    def test_init_allow_udf_detectors_enables_udf_loading(self):
        """Test that init(allow_udf_detectors=True) enables UDF detector loading."""
        from fortifyroot import init
        from fortifyroot._internal.safety import engine as safety_engine

        with (
            mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
            mock.patch("fortifyroot.core.Traceloop.init"),
            mock.patch("fortifyroot.core.configure_global_safety_runtime"),
        ):
            init(
                app_name="fortifyroot-test",
                api_key="fr-key",
                allow_udf_detectors=True,
            )

        assert safety_engine._udf_detectors_enabled is True

    def test_init_default_udf_detectors_disabled(self):
        """Test that init() does not enable UDF detectors by default."""
        from fortifyroot import init
        from fortifyroot._internal.safety import engine as safety_engine

        with (
            mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
            mock.patch("fortifyroot.core.Traceloop.init"),
            mock.patch("fortifyroot.core.configure_global_safety_runtime"),
        ):
            init(
                app_name="fortifyroot-test",
                api_key="fr-key",
            )

        assert safety_engine._udf_detectors_enabled is False

    def test_init_allow_udf_detectors_via_env_var(self):
        """Test that FORTIFYROOT_ALLOW_UDF_DETECTORS env var enables UDF loading."""
        from fortifyroot import init
        from fortifyroot._internal.safety import engine as safety_engine

        with mock.patch.dict(
            os.environ,
            {"FORTIFYROOT_ALLOW_UDF_DETECTORS": "true"},
            clear=False,
        ):
            with (
                mock.patch("fortifyroot.core.Traceloop.get_default_span_processor", return_value=mock.Mock()),
                mock.patch("fortifyroot.core.Traceloop.init"),
                mock.patch("fortifyroot.core.configure_global_safety_runtime"),
            ):
                init(
                    app_name="fortifyroot-test",
                    api_key="fr-key",
                )

        assert safety_engine._udf_detectors_enabled is True


class TestSetAssociationProperties:
    """Tests for set_association_properties (line 723 coverage)."""

    def test_delegates_to_traceloop(self):
        """Test that set_association_properties delegates to Traceloop."""
        from fortifyroot import set_association_properties

        with mock.patch(
            "fortifyroot.core.Traceloop.set_association_properties"
        ) as traceloop_mock:
            set_association_properties({"user_id": "u123", "session_id": "s456"})

        traceloop_mock.assert_called_once_with(
            {"user_id": "u123", "session_id": "s456"}
        )
