"""LiteLLM-specific fixtures for provider safety cassette tests.

Placeholder — actual tests implemented in Phase T6.
Cassettes will be stored in tests/providers/litellm/cassettes/.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_CASSETTE_DIR = Path(__file__).parent / "cassettes"


@pytest.fixture(autouse=True)
def litellm_environment():
    """Set dummy API key so LiteLLM doesn't fail during cassette replay."""
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = "test-key-for-vcr-replay"


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "authorization",
            "x-api-key",
            "api-key",
        ],
        "filter_query_parameters": ["api_key"],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }
