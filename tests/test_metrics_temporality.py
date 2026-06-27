"""Regression tests for the OTLP metrics temporality pin.

Context: OpenTelemetry Python's OTLPMetricExporter (both HTTP and gRPC
variants) defaults ``preferred_temporality`` to ``DELTA`` for Counter,
Histogram, and ObservableCounter. Prometheus and Grafana Mimir — which
back FortifyRoot's customer-facing ``SearchMetrics`` / ``GetMetricStats``
query APIs — reject DELTA for those instrument types with HTTP 500
"invalid temporality and type combination" and drop the data point. The
result was a silent, end-to-end metric ingestion failure that surfaced
when ``SearchMetrics`` was exercised with SDK-emitted data.

Fix (in ``fortifyroot.core``): ``_init_default_metrics_exporter`` now
builds a ``preferred_temporality`` mapping via
``_cumulative_preferred_temporality`` that pins every numeric instrument
to CUMULATIVE, and threads it into all four construction paths (HTTP,
gRPC insecure via scheme=``grpc``, gRPC secure via scheme=``grpcs``,
fallback gRPC for unknown schemes).

These tests lock the fix in place so a future refactor cannot silently
regress back to the library default. If a legitimate reason arises to relax
the CUMULATIVE pin, update the assertion deliberately and document why,
because Prometheus-backed query paths will break without it.
"""

from __future__ import annotations

from unittest import mock

import pytest

from fortifyroot.core import (
    _cumulative_preferred_temporality,
    _init_default_metrics_exporter,
)


# ---------------------------------------------------------------------------
# Unit: temporality mapping itself
# ---------------------------------------------------------------------------


class TestCumulativeTemporalityMapping:
    """The mapping must cover every numeric instrument Prometheus touches."""

    def test_all_numeric_instruments_pinned_to_cumulative(self):
        from opentelemetry.sdk.metrics import (
            Counter,
            Histogram,
            ObservableCounter,
            ObservableGauge,
            ObservableUpDownCounter,
            UpDownCounter,
        )
        from opentelemetry.sdk.metrics.export import AggregationTemporality

        mapping = _cumulative_preferred_temporality()

        for instrument_cls in (
            Counter,
            Histogram,
            ObservableCounter,
            UpDownCounter,
            ObservableUpDownCounter,
            ObservableGauge,
        ):
            assert instrument_cls in mapping, (
                f"{instrument_cls.__name__} missing from temporality mapping"
            )
            assert mapping[instrument_cls] is AggregationTemporality.CUMULATIVE, (
                f"{instrument_cls.__name__} must be CUMULATIVE — "
                f"Prometheus rejects DELTA for this instrument type. "
                f"Got {mapping[instrument_cls]}."
            )

    def test_mapping_is_fresh_dict_per_call(self):
        """Callers should not be able to mutate a shared mapping by reference."""
        a = _cumulative_preferred_temporality()
        b = _cumulative_preferred_temporality()
        assert a is not b
        a.clear()
        assert len(b) > 0, "separate mapping instance was mutated"


# ---------------------------------------------------------------------------
# Unit: per-scheme exporter construction receives the mapping
# ---------------------------------------------------------------------------


class TestInitDefaultMetricsExporterPinsTemporality:
    """Every transport path must pass ``preferred_temporality`` through."""

    def test_http_scheme_passes_cumulative_mapping(self):
        with mock.patch(
            "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter"
        ) as cls:
            _init_default_metrics_exporter(
                "https://api.fortifyroot.com",
                headers={"Authorization": "Bearer key"},
            )
        _, kwargs = cls.call_args
        assert kwargs["preferred_temporality"] == _cumulative_preferred_temporality()

    def test_https_scheme_passes_cumulative_mapping(self):
        with mock.patch(
            "opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter"
        ) as cls:
            _init_default_metrics_exporter(
                "https://metrics.example.com",
                headers={},
            )
        _, kwargs = cls.call_args
        assert kwargs["preferred_temporality"] == _cumulative_preferred_temporality()

    def test_grpc_insecure_scheme_passes_cumulative_mapping(self):
        with mock.patch(
            "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter"
        ) as cls:
            _init_default_metrics_exporter(
                "grpc://metrics.example.com:4317",
                headers={"Authorization": "Bearer key"},
            )
        _, kwargs = cls.call_args
        assert kwargs["preferred_temporality"] == _cumulative_preferred_temporality()
        assert kwargs["insecure"] is True

    def test_grpcs_secure_scheme_passes_cumulative_mapping(self):
        with mock.patch(
            "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter"
        ) as cls:
            _init_default_metrics_exporter(
                "grpcs://metrics.example.com:4317",
                headers={"Authorization": "Bearer key"},
            )
        _, kwargs = cls.call_args
        assert kwargs["preferred_temporality"] == _cumulative_preferred_temporality()
        assert kwargs["insecure"] is False

    def test_unknown_scheme_falls_back_to_grpc_with_cumulative(self):
        """Fallback path for bare hostnames or uncommon schemes."""
        with mock.patch(
            "opentelemetry.exporter.otlp.proto.grpc.metric_exporter.OTLPMetricExporter"
        ) as cls:
            _init_default_metrics_exporter(
                "otlp://metrics.example.com:4317",
                headers={"Authorization": "Bearer key"},
            )
        _, kwargs = cls.call_args
        assert kwargs["preferred_temporality"] == _cumulative_preferred_temporality()


# ---------------------------------------------------------------------------
# Integration: build a real exporter and assert it's wired correctly
# ---------------------------------------------------------------------------


class TestRealExporterHasCumulativeTemporality:
    """The strongest regression test — no mocks.

    Constructs a real ``OTLPMetricExporter`` via the SDK's
    ``_init_default_metrics_exporter`` entry point and inspects its
    internal temporality table. This catches the case where the library
    default silently changes again (e.g., upstream OTel ships a new
    instrument type) and our ``_cumulative_preferred_temporality``
    mapping hasn't been updated to cover it.
    """

    @pytest.mark.parametrize(
        "endpoint,expected_exporter_module",
        [
            ("http://localhost:4318", "opentelemetry.exporter.otlp.proto.http.metric_exporter"),
            ("https://api.fortifyroot.com", "opentelemetry.exporter.otlp.proto.http.metric_exporter"),
            ("grpc://localhost:4317", "opentelemetry.exporter.otlp.proto.grpc.metric_exporter"),
            ("grpcs://localhost:4317", "opentelemetry.exporter.otlp.proto.grpc.metric_exporter"),
        ],
    )
    def test_live_exporter_counter_and_histogram_are_cumulative(
        self, endpoint, expected_exporter_module,
    ):
        from opentelemetry.sdk.metrics import Counter, Histogram, ObservableCounter
        from opentelemetry.sdk.metrics.export import AggregationTemporality

        exporter = _init_default_metrics_exporter(endpoint, headers={})

        # Sanity: constructed the transport we expected.
        assert type(exporter).__module__ == expected_exporter_module

        # The library stores the preference table at
        # ``_preferred_temporality`` — if upstream ever renames this, the
        # test surfaces the change immediately rather than in production.
        pref = getattr(exporter, "_preferred_temporality", None)
        assert pref is not None, (
            "OTLPMetricExporter no longer exposes _preferred_temporality; "
            "update this test to match the new public API."
        )

        for instrument_cls in (Counter, Histogram, ObservableCounter):
            assert pref[instrument_cls] is AggregationTemporality.CUMULATIVE, (
                f"{instrument_cls.__name__} temporality on live "
                f"{type(exporter).__name__} is {pref[instrument_cls]}, "
                f"expected CUMULATIVE. Prometheus/Mimir-backed query APIs "
                f"will drop data points silently."
            )

    def test_live_http_exporter_with_auth_header_preserves_temporality(self):
        """Regression for the default-auth code path used by hosted FR."""
        from opentelemetry.sdk.metrics import Counter
        from opentelemetry.sdk.metrics.export import AggregationTemporality

        exporter = _init_default_metrics_exporter(
            "https://api.fortifyroot.com",
            headers={"Authorization": "Bearer fr-sk-test"},
        )
        assert exporter._preferred_temporality[Counter] is AggregationTemporality.CUMULATIVE
