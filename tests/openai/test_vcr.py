"""Integration tests for OpenAI using VCR record/replay.

These tests record real API interactions once, then replay them forever
without needing a network or API key.  Vision/multimodal is covered by
the mock unit tests in test_instrumentation.py instead.
"""

from __future__ import annotations

import os
from pathlib import Path

import openai
import pytest
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI

from fortifyroot import Instruments


_MODEL = os.getenv("OPENAI_TEST_MODEL", "openai/gpt-4o-mini")
_CASSETTE_DIR = Path("tests/openai/cassettes")

# Cassettes are recorded against this base URL.  Replay MUST use the same
# host+path, otherwise VCR cannot match the request to the cassette.
# Override via OPENAI_BASE_URL when recording against a different provider.
_RECORDED_BASE_URL = os.getenv(
    "OPENAI_BASE_URL", "https://openrouter.ai/api/v1"
)


def _ensure_key_or_cassette(pytestconfig: pytest.Config, cassette_stem: str) -> None:
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    api_key = os.getenv("OPENAI_API_KEY")
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"

    if record_mode in {"once", "all", "new_episodes", "rewrite"} and not api_key:
        pytest.skip("OPENAI_API_KEY is required when recording VCR cassettes.")

    if record_mode == "none" and not cassette.exists():
        pytest.skip(
            f"Cassette missing at {cassette}. Record once with --record-mode=once."
        )


def _openai_client() -> openai.OpenAI:
    """Create an OpenAI client pointing at the same base URL cassettes were recorded with."""
    api_key = os.getenv("OPENAI_API_KEY", "test-key-for-vcr-replay")
    return openai.OpenAI(api_key=api_key, base_url=_RECORDED_BASE_URL)


def _single_span(span_exporter):
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0]


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_non_streaming")
def test_chat_completion_non_streaming(pytestconfig, init_openai_sdk, span_exporter):
    _ensure_key_or_cassette(pytestconfig, "test_chat_completion_non_streaming")
    init_openai_sdk(instruments={Instruments.OPENAI})

    client = _openai_client()
    response = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": "Say hello in 4 words."}],
        max_tokens=20,
    )

    assert response.choices
    span = _single_span(span_exporter)
    assert span.name == "openai.chat"
    assert span.attributes[GenAI.GEN_AI_SYSTEM] in {"openai", "OpenAI", "OpenRouter"}


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_streaming")
def test_chat_completion_streaming(pytestconfig, init_openai_sdk, span_exporter):
    _ensure_key_or_cassette(pytestconfig, "test_chat_completion_streaming")
    init_openai_sdk(instruments={Instruments.OPENAI})

    client = _openai_client()
    stream = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": "Count from 1 to 3."}],
        max_tokens=30,
        stream=True,
    )
    chunks = list(stream)

    assert chunks
    span = _single_span(span_exporter)
    assert span.attributes["llm.is_streaming"] is True
