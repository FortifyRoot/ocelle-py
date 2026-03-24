"""Tests for SDK logging bootstrap hardening."""

from __future__ import annotations

import logging
from unittest import mock

from fortifyroot._vendor.traceloop.sdk.logging.logging import (
    LoggerWrapper,
    init_logging_provider,
    is_fortifyroot_logging_handler,
)


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
            "fortifyroot._vendor.traceloop.sdk.logging.logging.init_logging_provider",
            return_value=mock.Mock(),
        ),
        mock.patch(
            "fortifyroot._vendor.traceloop.sdk.logging.logging.LoggingInstrumentor"
        ) as instrumentor_cls,
    ):
        instrumentor = instrumentor_cls.return_value
        instrumentor.is_instrumented_by_opentelemetry = True

        LoggerWrapper(exporter=mock.Mock())

        instrumentor.instrument.assert_not_called()
