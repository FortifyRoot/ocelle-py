"""Anthropic-specific fixtures for provider safety cassette tests.

Placeholder — actual tests implemented in Phase T5.
Cassettes will be stored in tests/providers/anthropic/cassettes/.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

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
