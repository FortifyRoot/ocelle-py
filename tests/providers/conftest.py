"""Shared fixtures for provider safety cassette tests.

This module provides the common test infrastructure used by all provider-specific
safety cassette tests (T5, T6, and beyond). It sets up:

- FortifyRoot SDK initialization with in-memory span export
- Mock safety configuration (regex rules for email, credit card, phone)
- VCR cassette integration for recording and replay
- Helper functions for span inspection and content extraction

Each provider subdirectory (openai/, anthropic/, litellm/) has its own conftest.py
for provider-specific fixtures (client creation, VCR filter config, etc.).
"""

from __future__ import annotations

import os
import re
from typing import Any

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as GenAI

from fortifyroot import Instruments, init
from fortifyroot._internal.env_mapping import apply_env_var_mapping


# ---------------------------------------------------------------------------
# Span attribute key sets (legacy + semconv)
# ---------------------------------------------------------------------------

PROMPT_KEYS = {
    f"{GenAI.GEN_AI_PROMPT}.0.content",
    "llm.prompts.0.content",
    "llm.prompts.0.user",
}

COMPLETION_KEYS = {
    f"{GenAI.GEN_AI_COMPLETION}.0.content",
    "llm.completions.0.content",
}

CONTENT_KEYS = PROMPT_KEYS | COMPLETION_KEYS


# ---------------------------------------------------------------------------
# Mock safety configuration
# ---------------------------------------------------------------------------

# Realistic rules matching the proto SafetyRule structure from
# fr-proto/proto/config/v1/config.proto.  Used to test the full safety
# pipeline: init() -> provider call (VCR) -> safety engine -> masked spans.
#
# Masking replacement is NOT a rule field — the engine always computes it as
# [<Category>.<RuleName>], e.g. [PII.email-detector].

MOCK_SAFETY_RULES: list[dict[str, Any]] = [
    {
        "name": "email-detector",
        "category": "PII",
        "severity": "HIGH",
        "action": "MASK",
        "enabled": True,
        "matcher": {"type": "regex", "pattern": r"[\w.+-]+@[\w-]+\.[\w.]+"},
        # Expected mask: [PII.email-detector]
    },
    {
        "name": "credit-card-detector",
        "category": "PCI",
        "severity": "CRITICAL",
        "action": "MASK",
        "enabled": True,
        "matcher": {"type": "regex", "pattern": r"\b(?:\d[ -]*?){13,16}\b"},
        # Expected mask: [PCI.credit-card-detector]
    },
    {
        "name": "phone-detector",
        "category": "PII",
        "severity": "MEDIUM",
        "action": "MASK",
        "enabled": True,
        "matcher": {"type": "regex", "pattern": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"},
        # Expected mask: [PII.phone-detector]
    },
]


@pytest.fixture
def mock_safety_rules() -> list[dict[str, Any]]:
    """Provide mock safety rules for tests that need to customize them."""
    return MOCK_SAFETY_RULES.copy()


# ---------------------------------------------------------------------------
# SDK initialization factory
# ---------------------------------------------------------------------------


class _NoFortifyRootSpanExporter(InMemorySpanExporter):
    """ST-10.4 (2026-05-17): filter ST-10.4 retry_attempt sibling
    spans (role=retry_attempt) from upstream provider-test exporter.
    Role-based, NOT name-prefix-based, so legitimate
    ``fortifyroot.litellm.safety`` etc. spans that tests actually
    inspect remain visible. Mirrors top-level conftest's filter."""

    def get_finished_spans(self):  # type: ignore[override]
        return tuple(
            s for s in super().get_finished_spans()
            if (s.attributes or {}).get("fortifyroot.span.role") != "llm_attempt"
        )


@pytest.fixture
def span_exporter() -> InMemorySpanExporter:
    """Fresh in-memory span exporter for each test."""
    return _NoFortifyRootSpanExporter()


@pytest.fixture
def init_provider_sdk(span_exporter: InMemorySpanExporter):
    """Factory fixture to initialize FortifyRoot with a specific provider.

    Usage in tests:
        def test_something(init_provider_sdk, span_exporter):
            init_provider_sdk(instruments={Instruments.OPENAI})
            # ... make provider call ...
            spans = span_exporter.get_finished_spans()
    """

    def _init(
        instruments: set[Instruments] | None = None,
        trace_content: bool = True,
        **kwargs,
    ):
        os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
        os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
        processor = SimpleSpanProcessor(span_exporter)
        defaults = {
            "app_name": "fortifyroot-provider-test",
            "enabled": True,
            "disable_batch": True,
            "processors": [processor],
            "instruments": instruments,
            "trace_content": trace_content,
        }
        defaults.update(kwargs)
        apply_env_var_mapping()
        init(**defaults)
        return span_exporter

    return _init


# ---------------------------------------------------------------------------
# Span inspection helpers
# ---------------------------------------------------------------------------


def single_span(span_exporter: InMemorySpanExporter):
    """Extract exactly one span from the exporter, asserting count == 1."""
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1, f"Expected 1 span, got {len(spans)}"
    return spans[0]


def content_values(span, keys: set[str]) -> list[str]:
    """Extract attribute values from a span for the given key set."""
    return [str(span.attributes[key]) for key in keys if key in span.attributes]


def assert_content_masked(span, pattern: str, replacement: str) -> None:
    """Assert that content in span attributes has been masked.

    The replacement string follows the engine format: [<Category>.<RuleName>],
    e.g. ``[PII.email-detector]``.
    """
    for key in CONTENT_KEYS:
        if key in span.attributes:
            value = str(span.attributes[key])
            assert not re.search(
                pattern, value
            ), f"Found unmasked content matching '{pattern}' in {key}: {value}"
            if replacement:
                assert (
                    replacement in value
                ), f"Expected replacement '{replacement}' in {key}: {value}"


def assert_safety_event_present(span, category: str = "PII") -> None:
    """Assert that a safety violation event was recorded on the span."""
    events = span.events or []
    safety_events = [e for e in events if "safety" in e.name.lower()]
    assert (
        len(safety_events) > 0
    ), f"No safety events found on span. Events: {[e.name for e in events]}"
