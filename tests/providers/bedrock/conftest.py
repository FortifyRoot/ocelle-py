"""Bedrock-specific fixtures for provider safety cassette tests.

Cassettes are stored in tests/providers/bedrock/cassettes/.
These tests are implemented in Phase T5-D (SDK Safety Cassettes -- Bedrock).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_DEFAULT_MODEL = "anthropic.claude-3-haiku-20240307-v1:0"
_DEFAULT_REGION = "us-east-1"
_CASSETTE_DIR = Path(__file__).parent / "cassettes"


@pytest.fixture(autouse=True)
def bedrock_environment():
    """Map FR_TEST_AWS_* env vars to AWS_* so boto3 picks them up.

    When no real credentials are available (VCR replay), set dummy values so
    boto3 client construction does not fail.
    """
    key_id = os.getenv("FR_TEST_AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("FR_TEST_AWS_SECRET_ACCESS_KEY")
    region = os.getenv("FR_TEST_AWS_DEFAULT_REGION", _DEFAULT_REGION)

    if key_id:
        os.environ["AWS_ACCESS_KEY_ID"] = key_id
    elif "AWS_ACCESS_KEY_ID" not in os.environ:
        os.environ["AWS_ACCESS_KEY_ID"] = "testing-only-not-a-real-key"

    if secret_key:
        os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
    elif "AWS_SECRET_ACCESS_KEY" not in os.environ:
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-only-not-a-real-secret"

    os.environ["AWS_DEFAULT_REGION"] = region


@pytest.fixture(scope="module")
def vcr_config():
    return {
        "cassette_library_dir": str(_CASSETTE_DIR),
        "filter_headers": [
            "authorization",
            "x-amz-security-token",
            "x-amz-date",
            "x-amz-content-sha256",
        ],
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
    }


def ensure_key_or_cassette(pytestconfig: pytest.Config, cassette_stem: str) -> None:
    """Skip test if no API key (recording) or no cassette (replay)."""
    record_mode = (pytestconfig.getoption("--record-mode") or "none").lower()
    api_key = os.getenv("FR_TEST_AWS_ACCESS_KEY_ID")
    cassette = _CASSETTE_DIR / f"{cassette_stem}.yaml"

    if record_mode in {"once", "all", "new_episodes", "rewrite"} and not api_key:
        pytest.skip(
            "FR_TEST_AWS_ACCESS_KEY_ID is required when recording VCR cassettes."
        )

    if record_mode == "none" and not cassette.exists():
        pytest.skip(
            f"Cassette missing at {cassette}. Record with --record-mode=once."
        )


def resolved_model() -> str:
    """Resolve the Bedrock model: env var > default."""
    return os.getenv("FR_TEST_BEDROCK_MODEL", _DEFAULT_MODEL)


def resolved_region() -> str:
    """Resolve the AWS region: env var > default."""
    return os.getenv("FR_TEST_AWS_DEFAULT_REGION", _DEFAULT_REGION)


def make_bedrock_client():
    """Create a boto3 bedrock-runtime client for the resolved region."""
    import boto3

    return boto3.client(
        "bedrock-runtime",
        region_name=resolved_region(),
    )
