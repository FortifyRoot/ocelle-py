"""Helpers for emitting FortifyRoot-owned synthetic logs for finished spans."""

from __future__ import annotations

import logging
from typing import Callable, Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.semconv._incubating.attributes import (
    gen_ai_attributes as GenAIAttributes,
)
from opentelemetry.trace import NonRecordingSpan

from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes


_LOGGER = logging.getLogger(__name__)
_SYNTHETIC_LOGGER = logging.getLogger("fortifyroot.synthetic")
_SYNTHETIC_LOGGER.setLevel(logging.INFO)


def compose_span_postprocess_callbacks(
    *callbacks: Optional[Callable[[ReadableSpan], None]]
) -> Optional[Callable[[ReadableSpan], None]]:
    active_callbacks = [callback for callback in callbacks if callback is not None]
    if not active_callbacks:
        return None

    def _composed(span: ReadableSpan) -> None:
        for callback in active_callbacks:
            callback(span)

    return _composed


def emit_synthetic_span_log(span: ReadableSpan) -> None:
    try:
        payload = _build_synthetic_payload(span)
        if payload is None:
            return

        level = logging.ERROR if payload["span_status"] == "ERROR" else logging.INFO
        span_context = span.context

        with trace.use_span(NonRecordingSpan(span_context), end_on_exit=False):
            _SYNTHETIC_LOGGER.log(
                level,
                "FortifyRoot synthetic span log",
                extra=payload,
            )
    except Exception:
        _LOGGER.exception(
            "failed to emit synthetic span log for span %s",
            getattr(span, "name", "<unknown>"),
        )


def _build_synthetic_payload(span: ReadableSpan) -> Optional[dict[str, object]]:
    span_context = getattr(span, "context", None)
    if span_context is None:
        return None

    trace_id = getattr(span_context, "trace_id", 0)
    span_id = getattr(span_context, "span_id", 0)
    if trace_id == 0 or span_id == 0:
        return None

    attrs = dict(span.attributes or {})
    resource_attrs = dict(getattr(getattr(span, "resource", None), "attributes", {}) or {})
    status = getattr(getattr(span, "status", None), "status_code", None)
    status_text = getattr(status, "name", str(status or "UNSET"))

    payload: dict[str, object] = {
        "fortifyroot.synthetic_log": True,
        "fortifyroot.synthetic_log.version": 1,
        "trace_id": f"{trace_id:032x}",
        "span_id": f"{span_id:016x}",
        "span_name": getattr(span, "name", ""),
        "span_kind": getattr(getattr(span, "kind", None), "name", ""),
        "span_status": status_text,
        "service_name": str(resource_attrs.get("service.name", "")),
    }

    duration_ms = _duration_ms(span)
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms

    for attr_key, payload_key in (
        (GenAIAttributes.GEN_AI_SYSTEM, "gen_ai.system"),
        (GenAIAttributes.GEN_AI_REQUEST_MODEL, "gen_ai.request.model"),
        (GenAIAttributes.GEN_AI_RESPONSE_MODEL, "gen_ai.response.model"),
        (GenAIAttributes.GEN_AI_USAGE_INPUT_TOKENS, "gen_ai.usage.input_tokens"),
        (GenAIAttributes.GEN_AI_USAGE_OUTPUT_TOKENS, "gen_ai.usage.output_tokens"),
        (SpanAttributes.LLM_USAGE_TOTAL_TOKENS, "llm.usage.total_tokens"),
    ):
        value = attrs.get(attr_key)
        if value is not None:
            payload[payload_key] = value

    status_description = getattr(getattr(span, "status", None), "description", None)
    if status_description:
        payload["error_summary"] = status_description

    return payload


def _duration_ms(span: ReadableSpan) -> Optional[float]:
    start_time = getattr(span, "start_time", None)
    end_time = getattr(span, "end_time", None)
    if start_time is None or end_time is None:
        return None
    if end_time < start_time:
        return 0.0
    return round((end_time - start_time) / 1_000_000, 3)
