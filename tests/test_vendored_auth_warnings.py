import pytest
from grpc import RpcError, StatusCode

from fortifyroot._vendor.tracer.sdk.exporters.auth_warnings import (
    _AuthWarningClientProxy,
    _endpoint_label,
    reset_auth_warning_state_for_tests,
)


class _FakeHTTPResponse:
    ok = False
    reason = "Unauthorized"
    text = "unauthorized"

    def __init__(self, status_code):
        self.status_code = status_code


class _FakeAuthRpcError(RpcError):
    def code(self):
        return StatusCode.PERMISSION_DENIED


def _rejecting_post(status_code):
    def post(*args, **kwargs):
        return _FakeHTTPResponse(status_code)

    return post


def _make_traces_http_exporter():
    from fortifyroot._vendor.tracer.sdk.tracing.tracing import init_spans_exporter

    return init_spans_exporter("http://localhost:4318", {})


def _make_metrics_http_exporter():
    from fortifyroot._vendor.tracer.sdk.metrics.metrics import init_metrics_exporter

    return init_metrics_exporter("http://localhost:4318", {})


def _make_logs_http_exporter():
    from fortifyroot._vendor.tracer.sdk.logging.logging import init_logging_exporter

    return init_logging_exporter("http://localhost:4318", {})


@pytest.mark.parametrize(
    "factory,signal,status_code",
    [
        (_make_traces_http_exporter, "traces", 401),
        (_make_metrics_http_exporter, "metrics", 403),
        (_make_logs_http_exporter, "logs", 401),
    ],
)
def test_vendored_http_exporters_warn_on_auth_failure_once(
    factory,
    signal,
    status_code,
    caplog,
):
    reset_auth_warning_state_for_tests()
    exporter = factory()
    assert hasattr(exporter, "_session")
    exporter._session.post = _rejecting_post(status_code)

    with caplog.at_level("WARNING"):
        exporter._export(b"payload")
        exporter._export(b"payload")

    auth_warnings = [
        record
        for record in caplog.records
        if "FortifyRoot Ocelle SDK auth warning" in record.getMessage()
    ]
    assert len(auth_warnings) == 1
    warning = auth_warnings[0].getMessage()
    assert signal in warning
    assert f"HTTP {status_code}" in warning
    assert "invalid, revoked, deleted, or missing permissions" in warning
    assert "Telemetry will not reach the OTLP endpoint" in warning
    assert "Telemetry will not reach FortifyRoot" not in warning


def test_vendored_endpoint_label_strips_userinfo():
    assert _endpoint_label("https://user:secret@collector.example.com:4318/v1/traces") == (
        "collector.example.com:4318"
    )


def test_vendored_endpoint_label_formats_ipv6_host():
    assert _endpoint_label("grpcs://[::1]:4317") == "[::1]:4317"


def test_vendored_endpoint_label_handles_invalid_port():
    endpoint = "https://collector.example.com:99999/v1/traces"
    assert _endpoint_label(endpoint) == endpoint


def test_vendored_grpc_exporter_warns_on_auth_failure(caplog):
    reset_auth_warning_state_for_tests()

    from fortifyroot._vendor.tracer.sdk.tracing.tracing import init_spans_exporter

    class FakeClient:
        def Export(self, *args, **kwargs):  # noqa: N802
            raise _FakeAuthRpcError()

    exporter = init_spans_exporter("grpc://localhost:4317", {})
    assert isinstance(exporter._client, _AuthWarningClientProxy)
    exporter._client._client = FakeClient()

    with caplog.at_level("WARNING"), pytest.raises(_FakeAuthRpcError):
        exporter._client.Export()

    assert "FortifyRoot Ocelle SDK auth warning" in caplog.text
    assert "traces" in caplog.text
    assert "gRPC PERMISSION_DENIED" in caplog.text
