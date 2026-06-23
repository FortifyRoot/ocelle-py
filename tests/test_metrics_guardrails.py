from __future__ import annotations

import logging
import os
import uuid

from fortifyroot import core


def test_clamp_managed_metrics_export_interval_raises_low_env(monkeypatch, caplog):
    monkeypatch.setenv("OTEL_METRIC_EXPORT_INTERVAL", "5000")

    with caplog.at_level(logging.WARNING):
        core._clamp_managed_metrics_export_interval()

    assert core.MIN_MANAGED_METRICS_EXPORT_INTERVAL_MS == 60000
    assert os.environ["OTEL_METRIC_EXPORT_INTERVAL"] == str(
        core.MIN_MANAGED_METRICS_EXPORT_INTERVAL_MS
    )
    assert "below FortifyRoot's managed metrics minimum" in caplog.text


def test_default_service_instance_id_injected_once_per_process(monkeypatch):
    monkeypatch.delenv("OTEL_RESOURCE_ATTRIBUTES", raising=False)
    monkeypatch.setattr(core, "_PROCESS_SERVICE_INSTANCE_ID", None)

    first: dict[str, str] = {}
    second: dict[str, str] = {}
    core._ensure_default_service_instance_id(first)
    core._ensure_default_service_instance_id(second)

    assert uuid.UUID(first["service.instance.id"]).version == 4
    assert second["service.instance.id"] == first["service.instance.id"]


def test_default_service_instance_id_preserves_explicit_resource_attr(monkeypatch):
    monkeypatch.delenv("OTEL_RESOURCE_ATTRIBUTES", raising=False)
    attrs = {"service.instance.id": "customer-instance"}

    core._ensure_default_service_instance_id(attrs)

    assert attrs["service.instance.id"] == "customer-instance"


def test_default_service_instance_id_preserves_otel_env(monkeypatch):
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "service.instance.id=env-instance,team=ml")
    attrs: dict[str, str] = {}

    core._ensure_default_service_instance_id(attrs)

    assert "service.instance.id" not in attrs
