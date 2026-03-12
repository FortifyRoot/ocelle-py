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
            )

        runtime_mock.assert_called_once_with(
            enabled=True,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            config_profile_id="cfg-123",
            poll_interval_seconds=15,
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

        auth_headers = {"Authorization": "Bearer fr-key"}
        default_processor_mock.assert_called_once_with(
            disable_batch=False,
            api_endpoint="https://api.fortifyroot.com",
            api_key="fr-key",
            headers=auth_headers,
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/metrics",
            headers=auth_headers,
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
            headers={"Authorization": "Bearer explicit", "x-trace": "1"},
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/metrics",
            headers={"x-metrics": "2", "Authorization": "Bearer explicit"},
        )
        logging_exporter_cls.assert_called_once_with(
            endpoint="https://api.fortifyroot.com/v1/logs",
            headers={"x-logs": "3", "Authorization": "Bearer explicit"},
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["metrics_headers"] == {
            "x-metrics": "2",
            "Authorization": "Bearer explicit",
        }
        assert kwargs["logging_headers"] == {
            "x-logs": "3",
            "Authorization": "Bearer explicit",
        }

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
                "FORTIFYROOT_BASE_URL": "https://env.fortifyroot.dev",
                "FORTIFYROOT_METRICS_ENABLED": "true",
                "FORTIFYROOT_METRICS_ENDPOINT": "https://metrics.fortifyroot.dev",
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
            api_endpoint="https://env.fortifyroot.dev",
            api_key="fr-key",
            headers={
                "x-trace": "1",
                "Authorization": "Bearer fr-key",
            },
        )
        metric_exporter_cls.assert_called_once_with(
            endpoint="https://metrics.fortifyroot.dev/v1/metrics",
            headers={
                "x-metrics": "2",
                "Authorization": "Bearer fr-key",
            },
        )
        _, kwargs = traceloop_init_mock.call_args
        assert kwargs["api_endpoint"] == "https://env.fortifyroot.dev"
        assert kwargs["headers"] == {
            "x-trace": "1",
            "Authorization": "Bearer fr-key",
        }
        assert kwargs["logging_exporter"] is logging_exporter
        assert kwargs["logging_headers"] == {
            "x-logs": "3",
            "Authorization": "Bearer fr-key",
        }
        assert kwargs["metrics_headers"] == {
            "x-metrics": "2",
            "Authorization": "Bearer fr-key",
        }
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
                .api_endpoint("https://api.fortifyroot.dev")
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
                .init()
            )

        init_mock.assert_called_once_with(
            app_name="builder-app",
            api_endpoint="https://api.fortifyroot.dev",
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
        )
