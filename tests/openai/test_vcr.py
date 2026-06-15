"""Integration tests for OpenAI using VCR record/replay.

These tests record real API interactions once, then replay them forever
without needing a network or API key.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import openai
import pytest
import yaml
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI

from fortifyroot.ocelle import Instruments


_DEFAULT_MODEL = "gpt-4.1"
_CASSETTE_DIR = Path("tests/openai/cassettes")
_VISION_TEST_IMAGE_URL = (
    "https://placehold.co/600x400/EEE/31343C.png"
)

# Cassettes are recorded against this base URL.  Replay MUST use the same
# host+path, otherwise VCR cannot match the request to the cassette.
# Override via OPENAI_BASE_URL when recording against a different provider.
_DEFAULT_BASE_URL = "https://api.openai.com/v1"

_PROMPT_KEYS = {
    f"{GenAI.GEN_AI_PROMPT}.0.content",
    "llm.prompts.0.content",
    "llm.prompts.0.user",
}
_COMPLETION_KEYS = {
    f"{GenAI.GEN_AI_COMPLETION}.0.content",
    "llm.completions.0.content",
}
_CONTENT_KEYS = _PROMPT_KEYS | _COMPLETION_KEYS


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


def _record_mode(pytestconfig: pytest.Config) -> str:
    return (pytestconfig.getoption("--record-mode") or "none").lower()


def _cassette_defaults(cassette_stem: str) -> tuple[str | None, str | None]:
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"
    if not cassette.exists():
        return None, None

    try:
        payload = yaml.safe_load(cassette.read_text())
        interactions = payload.get("interactions") or []
        if not interactions:
            return None, None
        request = interactions[0].get("request") or {}
        uri = request.get("uri")
        body = request.get("body")
        if not uri or not body:
            return None, None

        parsed = urlparse(uri)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base_url.endswith("/chat/completions"):
            base_url = base_url[: -len("/chat/completions")]

        body_json = json.loads(body)
        model = body_json.get("model")
        return base_url or None, model or None
    except Exception:
        return None, None


def _resolved_base_url(pytestconfig: pytest.Config, cassette_stem: str) -> str:
    env_url = os.getenv("OPENAI_BASE_URL")
    if env_url:
        return env_url
    if _record_mode(pytestconfig) == "none":
        cassette_url, _ = _cassette_defaults(cassette_stem)
        if cassette_url:
            return cassette_url
    return _DEFAULT_BASE_URL


def _resolved_model(pytestconfig: pytest.Config, cassette_stem: str) -> str:
    env_model = os.getenv("OPENAI_TEST_MODEL")
    if env_model:
        return env_model
    if _record_mode(pytestconfig) == "none":
        _, cassette_model = _cassette_defaults(cassette_stem)
        if cassette_model:
            return cassette_model
    return _DEFAULT_MODEL


def _openai_client(pytestconfig: pytest.Config, cassette_stem: str) -> openai.OpenAI:
    """Create an OpenAI client pointing at the same base URL cassettes were recorded with."""
    api_key = os.getenv("OPENAI_API_KEY", "test-key-for-vcr-replay")
    return openai.OpenAI(
        api_key=api_key,
        base_url=_resolved_base_url(pytestconfig, cassette_stem),
    )


# ST-10.4 (review-driven 2026-05-16): filter ``fortifyroot.*.retry_attempt``
# sibling spans out of legacy single-span assertions. ST-10.4 added
# per-attempt retry_attempt siblings under every openai/anthropic/bedrock
# logical call; these tests pre-date that and assume the only span in
# the exporter is the logical ``openai.chat`` span. Role-based filter
# so every provider's retry_attempt is dropped uniformly. See
# fr-system-tests/docs/development/ai-logs/st_phase_10.txt addendum
# 2026-05-16 for context.
_FR_SPAN_ROLE_KEY = "fortifyroot.span.role"
_FR_SPAN_ROLE_LLM_ATTEMPT = "llm_attempt"


def _single_span(span_exporter):
    spans = [
        s for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get(_FR_SPAN_ROLE_KEY) != _FR_SPAN_ROLE_LLM_ATTEMPT
    ]
    assert len(spans) == 1, (
        f"expected exactly 1 logical span (after filtering fortifyroot retry_attempt "
        f"siblings); got {len(spans)} — names: {[s.name for s in spans]}"
    )
    return spans[0]


def _is_provider_vision_fetch_error(err: Exception) -> bool:
    message = str(err).lower()
    return (
        "image url can not be accessed" in message
        or "provider returned error" in message
        or "invalid_image_format" in message
        or "invalid_image_url" in message
    )


def _content_values(span, keys: set[str]) -> list[str]:
    return [str(span.attributes[key]) for key in keys if key in span.attributes]


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_non_streaming")
def test_chat_completion_non_streaming(pytestconfig, init_openai_sdk, span_exporter):
    cassette_stem = "test_chat_completion_non_streaming"
    _ensure_key_or_cassette(pytestconfig, cassette_stem)
    init_openai_sdk(instruments={Instruments.OPENAI})

    client = _openai_client(pytestconfig, cassette_stem)
    model = _resolved_model(pytestconfig, cassette_stem)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Say hello in 4 words."}],
        max_tokens=20,
    )

    assert response.choices
    span = _single_span(span_exporter)
    assert span.name == "openai.chat"
    assert span.attributes[GenAI.GEN_AI_SYSTEM] in {"openai", "OpenAI", "OpenRouter"}
    prompt_values = _content_values(span, _PROMPT_KEYS)
    assert prompt_values
    assert any("Say hello in 4 words." in value for value in prompt_values)


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_non_streaming")
def test_chat_completion_non_streaming_trace_content_false(
    pytestconfig, init_openai_sdk, span_exporter
):
    cassette_stem = "test_chat_completion_non_streaming"
    _ensure_key_or_cassette(pytestconfig, cassette_stem)
    init_openai_sdk(trace_content=False, instruments={Instruments.OPENAI})

    client = _openai_client(pytestconfig, cassette_stem)
    model = _resolved_model(pytestconfig, cassette_stem)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Say hello in 4 words."}],
        max_tokens=20,
    )

    assert response.choices
    span = _single_span(span_exporter)
    assert span.name == "openai.chat"
    assert all(key not in span.attributes for key in _CONTENT_KEYS)


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_streaming")
def test_chat_completion_streaming(pytestconfig, init_openai_sdk, span_exporter):
    cassette_stem = "test_chat_completion_streaming"
    _ensure_key_or_cassette(pytestconfig, cassette_stem)
    init_openai_sdk(instruments={Instruments.OPENAI})

    client = _openai_client(pytestconfig, cassette_stem)
    model = _resolved_model(pytestconfig, cassette_stem)
    stream = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Count from 1 to 3."}],
        max_tokens=30,
        stream=True,
    )
    chunks = list(stream)

    assert chunks
    span = _single_span(span_exporter)
    assert span.attributes["llm.is_streaming"] is True


@pytest.mark.vcr
@pytest.mark.default_cassette("test_chat_completion_with_vision")
def test_chat_completion_with_vision(pytestconfig, init_openai_sdk, span_exporter):
    cassette_stem = "test_chat_completion_with_vision"
    _ensure_key_or_cassette(pytestconfig, cassette_stem)
    init_openai_sdk(instruments={Instruments.OPENAI})

    client = _openai_client(pytestconfig, cassette_stem)
    model = _resolved_model(pytestconfig, cassette_stem)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What is shown in this image?"},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": _VISION_TEST_IMAGE_URL,
                            },
                        },
                    ],
                }
            ],
            max_tokens=40,
        )
    except openai.BadRequestError as err:
        if _is_provider_vision_fetch_error(err):
            pytest.skip(f"Provider-side vision image fetch error: {err}")
        raise

    assert response.choices
    span = _single_span(span_exporter)
    assert any(key in span.attributes for key in _PROMPT_KEYS)
