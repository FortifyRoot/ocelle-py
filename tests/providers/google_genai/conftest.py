"""Google GenAI-specific fixtures for provider safety cassette tests.

Cassettes are stored in tests/providers/google_genai/cassettes/.
These tests are implemented in Phase T5-C (SDK Safety Cassettes -- Google GenAI).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_DEFAULT_MODEL = "gemini-2.5-flash"
_CASSETTE_DIR = Path(__file__).parent / "cassettes"


@pytest.fixture(autouse=True)
def google_genai_environment():
    """Set dummy API key so Google GenAI client doesn't fail during cassette replay."""
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = "test-key-for-vcr-replay"


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "authorization",
            "x-goog-api-key",
        ],
        "filter_query_parameters": ["key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }


def ensure_key_or_cassette(pytestconfig: pytest.Config, cassette_stem: str) -> None:
    """Skip test if no API key (recording) or no cassette (replay)."""
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    api_key = os.getenv("GOOGLE_API_KEY")
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"

    if record_mode in {"once", "all", "new_episodes", "rewrite"} and (
        not api_key or api_key == "test-key-for-vcr-replay"
    ):
        pytest.skip("GOOGLE_API_KEY is required when recording VCR cassettes.")

    if record_mode == "none" and not cassette.exists():
        pytest.skip(
            f"Cassette missing at {cassette}. Record with --record-mode=once."
        )


def resolved_model() -> str:
    """Resolve the model: env var > default."""
    env_model = os.getenv("GOOGLE_GENAI_TEST_MODEL")
    if env_model:
        return env_model
    return _DEFAULT_MODEL
