"""OpenAI-specific fixtures for provider safety cassette tests.

Cassettes are stored in tests/providers/openai/cassettes/.
These tests are implemented in Phase T5 (SDK Safety Cassettes — OpenAI + Anthropic).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import openai
import pytest
import yaml

_DEFAULT_MODEL = "gpt-4.1"
_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_CASSETTE_DIR = Path(__file__).parent / "cassettes"


@pytest.fixture(autouse=True)
def openai_environment():
    """Set dummy API key so OpenAI client doesn't fail during cassette replay."""
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = "test-key-for-vcr-replay"


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "authorization",
            "x-api-key",
            "openai-organization",
            "openai-project-id",
        ],
        "filter_query_parameters": ["api_key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }


def ensure_key_or_cassette(pytestconfig: pytest.Config, cassette_stem: str) -> None:
    """Skip test if no API key (recording) or no cassette (replay)."""
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    api_key = os.getenv("OPENAI_API_KEY")
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"

    if record_mode in {"once", "all", "new_episodes", "rewrite"} and (
        not api_key or api_key == "test-key-for-vcr-replay"
    ):
        pytest.skip("OPENAI_API_KEY is required when recording VCR cassettes.")

    if record_mode == "none" and not cassette.exists():
        pytest.skip(
            f"Cassette missing at {cassette}. Record with --record-mode=once."
        )


def cassette_defaults(cassette_stem: str) -> tuple[str | None, str | None]:
    """Extract base_url and model from a recorded cassette."""
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


def resolved_base_url(pytestconfig: pytest.Config, cassette_stem: str) -> str:
    """Resolve the OpenAI base URL: env var > cassette > default."""
    env_url = os.getenv("OPENAI_BASE_URL")
    if env_url:
        return env_url
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    if record_mode == "none":
        cassette_url, _ = cassette_defaults(cassette_stem)
        if cassette_url:
            return cassette_url
    return _DEFAULT_BASE_URL


def resolved_model(pytestconfig: pytest.Config, cassette_stem: str) -> str:
    """Resolve the model: env var > cassette > default."""
    env_model = os.getenv("OPENAI_TEST_MODEL")
    if env_model:
        return env_model
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    if record_mode == "none":
        _, cassette_model = cassette_defaults(cassette_stem)
        if cassette_model:
            return cassette_model
    return _DEFAULT_MODEL


def make_openai_client(
    pytestconfig: pytest.Config, cassette_stem: str
) -> openai.OpenAI:
    """Create an OpenAI client pointing at the base URL cassettes were recorded with."""
    api_key = os.getenv("OPENAI_API_KEY", "test-key-for-vcr-replay")
    return openai.OpenAI(
        api_key=api_key,
        base_url=resolved_base_url(pytestconfig, cassette_stem),
    )
