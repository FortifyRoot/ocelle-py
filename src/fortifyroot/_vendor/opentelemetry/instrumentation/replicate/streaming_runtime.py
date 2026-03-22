from __future__ import annotations

from fortifyroot._vendor.opentelemetry.instrumentation.replicate.streaming_safety import (
    build_streaming_response,
)


def build_streaming_response_delegate(span, event_logger, response):
    from fortifyroot._vendor.opentelemetry.instrumentation.replicate import _handle_response

    yield from build_streaming_response(
        response,
        span=span,
        finalize_response=lambda complete_response: (
            _handle_response(span, event_logger, complete_response),
            span.end(),
        ),
    )
