"""Anthropic-specific fixtures for provider safety cassette tests.

Cassettes are stored in tests/providers/anthropic/cassettes/.
These tests are implemented in Phase T5-B (SDK Safety Cassettes — Anthropic).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import anthropic
import pytest
import yaml

_DEFAULT_MODEL = "claude-3-haiku-20240307"
_CASSETTE_DIR = Path(__file__).parent / "cassettes"


@pytest.fixture(autouse=True)
def anthropic_environment():
    """Set dummy API key so Anthropic client doesn't fail during cassette replay."""
    if "ANTHROPIC_API_KEY" not in os.environ:
        os.environ["ANTHROPIC_API_KEY"] = "test-key-for-vcr-replay"


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "x-api-key",
            "authorization",
            "anthropic-api-key",
        ],
        "filter_query_parameters": ["api_key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }


def ensure_key_or_cassette(pytestconfig: pytest.Config, cassette_stem: str) -> None:
    """Skip test if no API key (recording) or no cassette (replay)."""
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    api_key = os.getenv("ANTHROPIC_API_KEY")
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"

    if record_mode in {"once", "all", "new_episodes", "rewrite"} and (
        not api_key or api_key == "test-key-for-vcr-replay"
    ):
        pytest.skip("ANTHROPIC_API_KEY is required when recording VCR cassettes.")

    if record_mode == "none" and not cassette.exists():
        pytest.skip(
            f"Cassette missing at {cassette}. Record with --record-mode=once."
        )


def cassette_defaults(cassette_stem: str) -> str | None:
    """Extract model from a recorded cassette."""
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"
    if not cassette.exists():
        return None
    try:
        payload = yaml.safe_load(cassette.read_text())
        interactions = payload.get("interactions") or []
        if not interactions:
            return None
        request = interactions[0].get("request") or {}
        body = request.get("body")
        if not body:
            return None
        body_json = json.loads(body)
        return body_json.get("model") or None
    except Exception:
        return None


def resolved_model(pytestconfig: pytest.Config, cassette_stem: str) -> str:
    """Resolve the model: env var > cassette > default."""
    env_model = os.getenv("ANTHROPIC_TEST_MODEL")
    if env_model:
        return env_model
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    if record_mode == "none":
        cassette_model = cassette_defaults(cassette_stem)
        if cassette_model:
            return cassette_model
    return _DEFAULT_MODEL


def make_anthropic_client(
    pytestconfig: pytest.Config, cassette_stem: str
) -> anthropic.Anthropic:
    """Create an Anthropic client for cassette tests."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "test-key-for-vcr-replay")
    return anthropic.Anthropic(api_key=api_key)
