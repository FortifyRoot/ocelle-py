"""Unit tests for OpenAI instrumentation using mocked responses."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import openai
import pytest
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from fortifyroot import Instruments, init
from fortifyroot._internal.constants import FORTIFYROOT_SDK_VERSION_ATTRIBUTE
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from fortifyroot._vendor.opentelemetry.instrumentation.openai.shared.config import (
    Config as OpenAIConfig,
)
from fortifyroot._vendor.opentelemetry.instrumentation.openai.utils import (
    should_send_prompts,
)
from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes
from fortifyroot._vendor.traceloop.sdk.logging.logging import LoggerWrapper
from fortifyroot._vendor.traceloop.sdk.metrics.metrics import MetricsWrapper
from fortifyroot._vendor.traceloop.sdk.tracing.tracing import TracerWrapper


class _FakeModel:
    def __init__(self, payload: dict):
        self._payload = payload
        self.choices = payload.get("choices")

    def model_dump(self) -> dict:
        return self._payload


class _FakeStream:
    def __init__(self, chunks: list[_FakeModel]):
        self._chunks = iter(chunks)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._chunks)


def _fake_chat_response(model: str = "gpt-4o-mini", content: str = "hello") -> _FakeModel:
    return _FakeModel(
        {
            "id": "chatcmpl-test",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        }
    )


def _fake_stream_response(model: str = "gpt-4o-mini") -> _FakeStream:
    return _FakeStream(
        [
            _FakeModel(
                {
                    "id": "chatcmpl-stream",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": "Hello"},
                            "finish_reason": None,
                        }
                    ],
                }
            ),
            _FakeModel(
                {
                    "id": "chatcmpl-stream",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": " world"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 3,
                        "completion_tokens": 2,
                        "total_tokens": 5,
                    },
                }
            ),
        ]
    )


def _run_chat_create(model: str = "gpt-4o-mini", messages: list[dict] | None = None, **kwargs):
    client = openai.OpenAI(api_key="test-key")
    return client.chat.completions.create(
        model=model,
        messages=messages or [{"role": "user", "content": "hello"}],
        **kwargs,
    )


def _single_span(span_exporter):
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0]


def _assert_token_usage_attributes(span) -> None:
    assert span.attributes[GenAI.GEN_AI_USAGE_INPUT_TOKENS] == 3
    assert span.attributes[GenAI.GEN_AI_USAGE_OUTPUT_TOKENS] == 2
    assert span.attributes[SpanAttributes.LLM_USAGE_TOTAL_TOKENS] == 5


def _prompt_attr_keys() -> set[str]:
    return {
        f"{GenAI.GEN_AI_PROMPT}.0.content",
        "llm.prompts.0.content",
        "llm.prompts.0.user",
    }


def _completion_attr_keys() -> set[str]:
    return {
        f"{GenAI.GEN_AI_COMPLETION}.0.content",
        "llm.completions.0.content",
    }


def _content_attr_keys() -> set[str]:
    return _prompt_attr_keys() | _completion_attr_keys()


def _assert_no_content_attrs(span) -> None:
    assert all(key not in span.attributes for key in _content_attr_keys())


def test_chat_completion_creates_span(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(),
    ):
        init_openai_sdk()
        _run_chat_create()

    span = _single_span(span_exporter)
    assert span.name == "openai.chat"
    assert span.attributes[GenAI.GEN_AI_SYSTEM] == "openai"


def test_chat_completion_streaming_creates_span(init_openai_sdk, span_exporter):
    with (
        patch(
            "openai.resources.chat.completions.Completions.create",
            return_value=_fake_stream_response(),
        ),
        patch(
            "fortifyroot._vendor.opentelemetry.instrumentation.openai.shared.chat_wrappers.is_streaming_response",
            return_value=True,
        ),
    ):
        init_openai_sdk()
        stream = _run_chat_create(stream=True)
        list(stream)

    span = _single_span(span_exporter)
    assert span.attributes[SpanAttributes.LLM_IS_STREAMING] is True
    assert any(
        event.name == SpanAttributes.LLM_CONTENT_COMPLETION_CHUNK for event in span.events
    )


@pytest.mark.parametrize("model_name", ["gpt-4o-mini", "gpt-4o"])
def test_multiple_models_are_captured(model_name, init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(model=model_name),
    ):
        init_openai_sdk()
        _run_chat_create(model=model_name)

    span = _single_span(span_exporter)
    assert span.attributes[GenAI.GEN_AI_REQUEST_MODEL] == model_name
    assert span.attributes[GenAI.GEN_AI_RESPONSE_MODEL] == model_name


def test_vision_request_creates_span(init_openai_sdk, span_exporter):
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {
                    "type": "image_url",
                    "image_url": {"url": "https://example.com/image.png"},
                },
            ],
        }
    ]

    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(content="It is a test image."),
    ) as mock_create:
        init_openai_sdk(trace_content=True)
        _run_chat_create(messages=messages)

    span = _single_span(span_exporter)
    assert span.attributes[GenAI.GEN_AI_SYSTEM] == "openai"
    called_messages = mock_create.call_args.kwargs["messages"]
    assert called_messages[0]["content"][1]["type"] == "image_url"


def test_disabled_sdk_creates_no_spans(span_exporter):
    init(
        app_name="fortifyroot-test",
        enabled=False,
        disable_batch=True,
        processors=[SimpleSpanProcessor(span_exporter)],
        instruments={Instruments.OPENAI},
    )
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(),
    ):
        _run_chat_create()

    assert span_exporter.get_finished_spans() == ()


def test_trace_content_true_captures_prompts(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(content="captured"),
    ):
        init_openai_sdk(trace_content=True)
        _run_chat_create()

    span = _single_span(span_exporter)
    assert bool(should_send_prompts()) is True
    assert span.attributes[GenAI.GEN_AI_RESPONSE_MODEL] == "gpt-4o-mini"


def test_trace_content_false_hides_prompts(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(content="hidden"),
    ):
        init_openai_sdk(trace_content=False)
        _run_chat_create()

    span = _single_span(span_exporter)
    assert bool(should_send_prompts()) is False
    _assert_no_content_attrs(span)


def test_enrich_metrics_true_sets_openai_enrichment(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(),
    ):
        init_openai_sdk(should_enrich_metrics=True)
        _run_chat_create()

    span = _single_span(span_exporter)
    assert OpenAIConfig.enrich_assistant is True
    _assert_token_usage_attributes(span)


def test_enrich_metrics_false_disables_openai_enrichment(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(),
    ):
        init_openai_sdk(should_enrich_metrics=False)
        _run_chat_create()

    span = _single_span(span_exporter)
    assert OpenAIConfig.enrich_assistant is False
    _assert_token_usage_attributes(span)


def test_custom_resource_attributes_in_spans(init_openai_sdk, span_exporter):
    with patch(
        "openai.resources.chat.completions.Completions.create",
        return_value=_fake_chat_response(),
    ):
        init_openai_sdk(resource_attributes={"team": "ml", "env": "test"})
        _run_chat_create()

    span = _single_span(span_exporter)
    assert span.resource.attributes["team"] == "ml"
    assert span.resource.attributes["env"] == "test"
    assert FORTIFYROOT_SDK_VERSION_ATTRIBUTE in span.resource.attributes


def test_tracing_toggle_disables_tracer_wrapper():
    os.environ["FORTIFYROOT_TRACING_ENABLED"] = "false"
    apply_env_var_mapping()
    init(
        app_name="fortifyroot-test",
        enabled=True,
        instruments={Instruments.OPENAI},
    )
    assert not hasattr(TracerWrapper, "instance")


def test_metrics_toggle_disables_metrics_wrapper():
    os.environ["FORTIFYROOT_METRICS_ENABLED"] = "false"
    apply_env_var_mapping()
    init(
        app_name="fortifyroot-test",
        enabled=True,
        api_endpoint="http://localhost:4318",
        api_key="dummy",
        instruments={Instruments.OPENAI},
    )
    assert not hasattr(MetricsWrapper, "instance")


def test_metrics_toggle_enables_metrics_wrapper():
    os.environ["FORTIFYROOT_METRICS_ENABLED"] = "true"
    apply_env_var_mapping()
    init(
        app_name="fortifyroot-test",
        enabled=True,
        api_endpoint="http://localhost:4318",
        api_key="dummy",
        metrics_exporter=MagicMock(),
        instruments={Instruments.OPENAI},
    )
    assert hasattr(MetricsWrapper, "instance")


def test_logging_toggle_disables_logging_wrapper():
    os.environ["FORTIFYROOT_LOGGING_ENABLED"] = "false"
    apply_env_var_mapping()
    init(
        app_name="fortifyroot-test",
        enabled=True,
        api_endpoint="http://localhost:4318",
        api_key="dummy",
        instruments={Instruments.OPENAI},
    )
    assert not hasattr(LoggerWrapper, "instance")


def test_logging_toggle_enables_logging_wrapper():
    os.environ["FORTIFYROOT_LOGGING_ENABLED"] = "true"
    apply_env_var_mapping()
    init(
        app_name="fortifyroot-test",
        enabled=True,
        api_endpoint="http://localhost:4318",
        api_key="dummy",
        instruments={Instruments.OPENAI},
    )
    assert hasattr(LoggerWrapper, "instance")
