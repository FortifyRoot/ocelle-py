"""Tests for SDK logging bootstrap hardening."""

from __future__ import annotations

import logging
from unittest import mock

from fortifyroot._internal.safety.engine import compile_snapshot
from fortifyroot._internal.safety.parser import parse_sdk_config_response
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    TraceState,
    use_span,
)

from fortifyroot._vendor.tracer.sdk.logging.logging import (
    LoggerWrapper,
    init_logging_provider,
    is_fortifyroot_logging_handler,
)

try:
    from opentelemetry.sdk._logs.export import LogExportResult as _LogExportResult
except ImportError:  # pragma: no cover - future OTel may move log export APIs.
    _LogExportResult = None


def _restore_root_logger(
    original_handlers: list[logging.Handler],
    original_level: int,
) -> None:
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    for handler in original_handlers:
        root_logger.addHandler(handler)
    root_logger.setLevel(original_level)


class _CapturingLogExporter:
    def __init__(self) -> None:
        self.records = []

    def export(self, batch):
        for record in batch:
            self.records.append(record.log_record)
        if _LogExportResult is not None:
            return _LogExportResult.SUCCESS
        return None

    def shutdown(self):
        return None


def _sample_span_context() -> SpanContext:
    return SpanContext(
        trace_id=0x1234567890ABCDEF1234567890ABCDEF,
        span_id=0x1234567890ABCDEF,
        is_remote=False,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
        trace_state=TraceState(),
    )


def _email_masking_snapshot():
    profile = parse_sdk_config_response(
        {
            "config_profile": {
                "id": "cfg-log-body-contract",
                "version": 1,
                "etag": "etag-log-body-contract",
                "config": {
                    "safety_config": {
                        "enabled": True,
                        "default_action": "MASK",
                        "rules": [
                            {
                                "name": "email",
                                "category": "PII",
                                "severity": "HIGH",
                                "enabled": True,
                                "regex": r"[a-z]+@[a-z]+\.com",
                            }
                        ],
                    }
                },
            }
        }
    ).config_profile
    assert profile is not None
    return compile_snapshot(profile)


def test_init_logging_provider_preserves_existing_root_handlers_and_level():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    logger_provider = None

    try:
        existing_handler = logging.StreamHandler()
        root_logger.handlers = []
        root_logger.addHandler(existing_handler)
        root_logger.setLevel(logging.ERROR)

        logger_provider = init_logging_provider(mock.Mock())

        fortifyroot_handlers = [
            handler for handler in root_logger.handlers if is_fortifyroot_logging_handler(handler)
        ]
        assert existing_handler in root_logger.handlers
        assert len(fortifyroot_handlers) == 1
        assert root_logger.level == logging.ERROR
    finally:
        if logger_provider is not None:
            logger_provider.shutdown()
        _restore_root_logger(original_handlers, original_level)


def test_init_logging_provider_replaces_stale_fortifyroot_handler_without_duplicates():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    logger_provider_one = None
    logger_provider_two = None

    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.WARNING)

        logger_provider_one = init_logging_provider(mock.Mock())
        logger_provider_two = init_logging_provider(mock.Mock())

        fortifyroot_handlers = [
            handler for handler in root_logger.handlers if is_fortifyroot_logging_handler(handler)
        ]
        assert len(fortifyroot_handlers) == 1
        assert root_logger.level == logging.INFO
    finally:
        if logger_provider_one is not None:
            logger_provider_one.shutdown()
        if logger_provider_two is not None:
            logger_provider_two.shutdown()
        _restore_root_logger(original_handlers, original_level)


def test_logger_wrapper_skips_reinstrumenting_logging_when_already_instrumented():
    LoggerWrapper.set_static_params({}, "http://localhost:4318", {})

    with (
        mock.patch(
            "fortifyroot._vendor.tracer.sdk.logging.logging.init_logging_provider",
            return_value=mock.Mock(),
        ),
        mock.patch(
            "fortifyroot._vendor.tracer.sdk.logging.logging.LoggingInstrumentor"
        ) as instrumentor_cls,
    ):
        instrumentor = instrumentor_cls.return_value
        instrumentor.is_instrumented_by_opentelemetry = True

        LoggerWrapper(exporter=mock.Mock())

        instrumentor.instrument.assert_not_called()


def test_stdlib_logs_correlate_only_inside_active_span():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    logger_provider = None

    try:
        exporter = _CapturingLogExporter()
        logger_provider = init_logging_provider(exporter)

        app_logger = logging.getLogger("fortifyroot.tests.custom_logging")
        app_logger.setLevel(logging.INFO)

        app_logger.info("outside span")

        span_context = _sample_span_context()
        with use_span(NonRecordingSpan(span_context), end_on_exit=False):
            app_logger.info("inside span")

        logger_provider.force_flush()

        records_by_body = {record.body: record for record in exporter.records}
        outside = records_by_body["outside span"]
        inside = records_by_body["inside span"]

        assert outside.trace_id == 0
        assert outside.span_id == 0
        assert inside.trace_id == span_context.trace_id
        assert inside.span_id == span_context.span_id
    finally:
        if logger_provider is not None:
            logger_provider.shutdown()
        _restore_root_logger(original_handlers, original_level)


def test_stdlib_log_body_is_not_safety_masked():
    snapshot = _email_masking_snapshot()
    pii_message = "email me at jane@acme.com"
    safety_result = snapshot.evaluate_text(pii_message)
    assert safety_result is not None
    assert safety_result.text == "email me at [PII.email]"

    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    logger_provider = None

    try:
        exporter = _CapturingLogExporter()
        logger_provider = init_logging_provider(exporter)

        app_logger = logging.getLogger("fortifyroot.tests.custom_logging.safety")
        app_logger.setLevel(logging.INFO)

        with use_span(NonRecordingSpan(_sample_span_context()), end_on_exit=False):
            app_logger.info(pii_message)

        logger_provider.force_flush()

        records_by_body = {record.body: record for record in exporter.records}
        assert pii_message in records_by_body
        assert "email me at [PII.email]" not in records_by_body
    finally:
        if logger_provider is not None:
            logger_provider.shutdown()
        _restore_root_logger(original_handlers, original_level)
