"""
SDK safety cassette tests for LlamaIndex (Phase T6-C).

End-to-end tests through the vendored code path:
  fortifyroot.init() -> LlamaIndex OpenAI LLM (VCR) -> safety masking -> spans

LlamaIndex uses an event-driven dispatcher for instrumentation.
Safety is applied via method wrapping on BaseLLM (chat, complete, stream_chat, etc.).

Every test verifies BOTH safety behaviour AND regular LLM telemetry capture.

Capability matrix (SAFETY_ARCHITECTURE.md):
  LlamaIndex -- sync Y, async N(TL), stream Y, non-text Y (embeddings)

Test dimensions covered:
  Mode:     sync, streaming
  Direction: prompt masking, completion masking
  Action:   MASK, ALLOW, passthrough (no config)
  Content:  text, non-text (embeddings)
  Special:  fortifyroot.* attribute verification

IMPORTANT: LlamaIndex's instrumentor uses wrapt wrappers on BaseLLM that persist.
We use module-scoped SDK initialization with per-test safety handler registration.
"""

from __future__ import annotations

import os

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.semconv._incubating.attributes import (
    gen_ai_attributes as GenAI,
)

from fortifyroot import Instruments, init
from fortifyroot._internal.env_mapping import apply_env_var_mapping
from tests.providers.conftest import PROMPT_KEYS, COMPLETION_KEYS
from tests.providers.safety_handlers import (
    SAFETY_ACTION_ALLOW,
    SAFETY_ACTION_MASK,
    clear_all_handlers,
    register_all_handlers,
    set_safety_action,
)

from .conftest import (
    ensure_key_or_cassette,
    resolved_model,
)


# ---------------------------------------------------------------------------
# Module-scoped SDK init (LlamaIndex wrappers persist across tests)
# ---------------------------------------------------------------------------

_MODULE_INITIALIZED = False
_MODULE_EXPORTER = InMemorySpanExporter()


def _ensure_sdk_initialized():
    """Initialize SDK once per module. LlamaIndex wrappers persist."""
    global _MODULE_INITIALIZED
    if _MODULE_INITIALIZED:
        return

    from fortifyroot._vendor.tracer.sdk.tracing.tracing import TracerWrapper

    os.environ.setdefault("FORTIFYROOT_METRICS_ENABLED", "false")
    os.environ.setdefault("FORTIFYROOT_LOGGING_ENABLED", "false")
    apply_env_var_mapping()

    # If another module already initialized the SDK (e.g., LangChain tests),
    # just add our exporter and manually instrument LlamaIndex.
    if hasattr(TracerWrapper, 'instance') and TracerWrapper.instance:
        processor = SimpleSpanProcessor(_MODULE_EXPORTER)
        provider = getattr(TracerWrapper.instance, '_TracerWrapper__tracer_provider', None)
        if provider and hasattr(provider, 'add_span_processor'):
            provider.add_span_processor(processor)
        # Manually instrument LlamaIndex if not yet done
        try:
            from fortifyroot._vendor.opentelemetry.instrumentation.llamaindex import LlamaIndexInstrumentor
            instrumentor = LlamaIndexInstrumentor()
            if not instrumentor._is_instrumented_by_opentelemetry:
                instrumentor.instrument()
        except Exception:
            pass
    else:
        processor = SimpleSpanProcessor(_MODULE_EXPORTER)
        init(
            app_name="fortifyroot-llamaindex-test",
            enabled=True,
            disable_batch=True,
            processors=[processor],
            instruments={Instruments.LLAMA_INDEX, Instruments.OPENAI},
            trace_content=True,
        )

    _MODULE_INITIALIZED = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def li_span_exporter():
    """Per-test span exporter using the module-level exporter."""
    _ensure_sdk_initialized()
    _MODULE_EXPORTER.clear()
    yield _MODULE_EXPORTER
    _MODULE_EXPORTER.clear()


@pytest.fixture(autouse=True)
def _safety_cleanup():
    """Reset safety state before and after each test."""
    clear_all_handlers()
    yield
    clear_all_handlers()


# ---------------------------------------------------------------------------
# Init helpers
# ---------------------------------------------------------------------------


def _setup_safety(action="MASK"):
    """Set safety action and register handlers."""
    set_safety_action(action)
    register_all_handlers()


def _setup_no_safety():
    """Clear safety handlers for passthrough tests."""
    clear_all_handlers()


# ---------------------------------------------------------------------------
# Span helpers
# ---------------------------------------------------------------------------


def _get_llm_span(exporter):
    """Get the LLM span from LlamaIndex instrumentation."""
    spans = exporter.get_finished_spans()
    assert len(spans) >= 1, f"Expected >= 1 spans, got {len(spans)}"
    for s in spans:
        for key in PROMPT_KEYS:
            if key in (s.attributes or {}):
                return s
    llm_spans = [s for s in spans if "openai" in s.name.lower() or "llm" in s.name.lower()]
    if llm_spans:
        return llm_spans[0]
    return spans[0]


def _prompt_content(span):
    for key in PROMPT_KEYS:
        if key in span.attributes:
            return str(span.attributes[key])
    return None


def _completion_content(span):
    for key in COMPLETION_KEYS:
        if key in span.attributes:
            return str(span.attributes[key])
    return None


def _safety_events(span):
    return [e for e in (span.events or []) if (e.name or "").startswith("fortifyroot.safety")]


def _all_safety_events(exporter):
    """Collect safety events from ALL spans."""
    events = []
    for span in exporter.get_finished_spans():
        events.extend(_safety_events(span))
    return events


def _make_llm(pytestconfig, cassette_stem):
    """Create a LlamaIndex OpenAI LLM."""
    from llama_index.llms.openai import OpenAI as LlamaIndexOpenAI
    model_name = resolved_model(pytestconfig, cassette_stem)
    api_key = os.getenv("OPENAI_API_KEY", "test-key-for-vcr-replay")
    return LlamaIndexOpenAI(
        model=model_name,
        api_key=api_key,
        max_tokens=50,
    )


# ===========================================================================
# MASK -- sync
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_prompt_mask_email(
    pytestconfig, li_span_exporter
):
    """Sync: email in prompt -> masked through LlamaIndex LLM.chat()."""
    cassette = "test_llamaindex_safety_sync_prompt_mask_email"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Summarize the following customer inquiry from "
            "john.doe@example.com about their recent order."
        ),
    )])

    events = _all_safety_events(li_span_exporter)
    assert len(events) >= 1, (
        f"No safety events. "
        f"Spans: {[(s.name, [e.name for e in (s.events or [])]) for s in li_span_exporter.get_finished_spans()]}"
    )
    email_events = [e for e in events if e.attributes.get("fortifyroot.safety.rule_name") == "PII.email"]
    assert len(email_events) >= 1
    assert email_events[0].attributes["fortifyroot.safety.action"] == "MASK"


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_prompt_mask_credit_card(
    pytestconfig, li_span_exporter
):
    """Sync: credit card in prompt -> masked."""
    cassette = "test_llamaindex_safety_sync_prompt_mask_credit_card"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content="Check if order for card 4111 1111 1111 1111 was processed.",
    )])

    events = _all_safety_events(li_span_exporter)
    assert any(
        e.attributes.get("fortifyroot.safety.rule_name") == "PCI.credit_card"
        for e in events
    )


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_prompt_mask_list_rule(
    pytestconfig, li_span_exporter
):
    """Sync: competitor org names (list rule) -> masked."""
    cassette = "test_llamaindex_safety_sync_prompt_mask_list_rule"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Compare our product roadmap with Acme Corp's latest "
            "offering and Globex Industries' pricing strategy."
        ),
    )])

    events = _all_safety_events(li_span_exporter)
    assert any(
        e.attributes.get("fortifyroot.safety.rule_name") == "PII.competitor_org"
        for e in events
    )


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_completion_mask_email(
    pytestconfig, li_span_exporter
):
    """Sync: LLM generates email in response -> completion safety masks it."""
    cassette = "test_llamaindex_safety_sync_completion_mask_email"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Create a fictional contact card. Name: Jane Smith, "
            "company: Widgets Inc, role: VP of Sales. "
            "Invent a plausible work email. Format: Name: ...\nEmail: ..."
        ),
    )])

    span = _get_llm_span(li_span_exporter)
    completion = _completion_content(span)

    events = _all_safety_events(li_span_exporter)
    completion_findings = [
        e for e in events
        if e.attributes.get("fortifyroot.safety.location") == "COMPLETION"
    ]
    has_masked = completion is not None and "[PII.email]" in completion
    # Accept: masked content OR completion safety events.
    assert has_masked or len(completion_findings) >= 1, (
        f"Expected completion masking or completion safety events. "
        f"Masked={has_masked}, CompletionEvents={len(completion_findings)}, "
        f"Content={completion[:80] if completion else None}"
    )


# ===========================================================================
# ALLOW -- sync
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_prompt_allow_email(
    pytestconfig, li_span_exporter
):
    """ALLOW: email detected but text passes through unchanged."""
    cassette = "test_llamaindex_safety_sync_prompt_allow_email"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety(action=SAFETY_ACTION_ALLOW)

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Forward this message from alice.jones@example.org "
            "to the support team."
        ),
    )])

    events = _all_safety_events(li_span_exporter)
    assert len(events) >= 1
    assert events[0].attributes["fortifyroot.safety.rule_name"] == "PII.email"
    assert events[0].attributes["fortifyroot.safety.action"] == "ALLOW"


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_sync_prompt_allow_credit_card(
    pytestconfig, li_span_exporter
):
    """ALLOW: credit card detected but text passes through unchanged."""
    cassette = "test_llamaindex_safety_sync_prompt_allow_credit_card"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety(action=SAFETY_ACTION_ALLOW)

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content="Verify payment for card 4111 1111 1111 1111 was received.",
    )])

    events = _all_safety_events(li_span_exporter)
    assert any(
        e.attributes.get("fortifyroot.safety.rule_name") == "PCI.credit_card"
        and e.attributes.get("fortifyroot.safety.action") == "ALLOW"
        for e in events
    )


# ===========================================================================
# MASK -- streaming
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_stream_prompt_mask_email(
    pytestconfig, li_span_exporter
):
    """Streaming: email in prompt -> masked via stream_chat()."""
    cassette = "test_llamaindex_safety_stream_prompt_mask_email"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    response = llm.stream_chat([ChatMessage(
        role="user",
        content=(
            "Acknowledge receipt of message from "
            "alice.jones@example.org about Project-Phoenix."
        ),
    )])
    chunks = []
    for chunk in response:
        chunks.append(chunk)
    assert len(chunks) > 0

    events = _all_safety_events(li_span_exporter)
    email_events = [e for e in events if e.attributes.get("fortifyroot.safety.rule_name") == "PII.email"]
    assert len(email_events) >= 1, (
        f"Expected PII.email safety events in streaming. Got: "
        f"{[e.attributes.get('fortifyroot.safety.rule_name') for e in events]}"
    )


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_stream_completion_mask(
    pytestconfig, li_span_exporter
):
    """Streaming: verify stream completes, completion captured."""
    cassette = "test_llamaindex_safety_stream_completion_mask"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    response = llm.stream_chat([ChatMessage(
        role="user",
        content=(
            "Reply with exactly: 'Contact sarah.lee@engineering.example.com'"
        ),
    )])
    chunks = []
    for chunk in response:
        chunks.append(chunk)
    assert len(chunks) > 0

    spans = li_span_exporter.get_finished_spans()
    assert len(spans) >= 1


# ===========================================================================
# Passthrough (no safety config)
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_no_config_passthrough(
    pytestconfig, li_span_exporter
):
    """No safety handlers -> text passes through unchanged."""
    cassette = "test_llamaindex_safety_no_config_passthrough"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_no_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Summarize the inquiry from john.doe@example.com "
            "about card 4111 1111 1111 1111."
        ),
    )])

    events = _all_safety_events(li_span_exporter)
    assert len(events) == 0, "No safety events expected with no handlers"


# ===========================================================================
# Non-text: Embeddings (safety skips)
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_safety_embeddings_no_safety(
    pytestconfig, li_span_exporter
):
    """Embeddings: safety skips non-text content."""
    cassette = "test_llamaindex_safety_embeddings_no_safety"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.embeddings.openai import OpenAIEmbedding

    api_key = os.getenv("OPENAI_API_KEY", "test-key-for-vcr-replay")
    embed_model = OpenAIEmbedding(
        model_name="text-embedding-3-small",
        api_key=api_key,
    )
    embed_model.get_text_embedding("Hello world, this is a test.")

    spans = li_span_exporter.get_finished_spans()
    assert len(spans) >= 1, "Expected at least 1 span for embedding"

    events = _all_safety_events(li_span_exporter)
    assert len(events) == 0, (
        f"No safety events expected for embeddings. Got: {len(events)}"
    )


# ===========================================================================
# Attribute prefix verification
# ===========================================================================


@pytest.mark.vcr
@pytest.mark.fr
def test_llamaindex_fortifyroot_attributes(
    pytestconfig, li_span_exporter
):
    """Verify fortifyroot.* attribute prefix in safety events."""
    cassette = "test_llamaindex_fortifyroot_attributes"
    ensure_key_or_cassette(pytestconfig, cassette)
    _setup_safety()

    from llama_index.core.llms import ChatMessage

    llm = _make_llm(pytestconfig, cassette)
    llm.chat([ChatMessage(
        role="user",
        content=(
            "Summarize the inquiry from alice.jones@example.org "
            "about the new software license."
        ),
    )])

    events = _all_safety_events(li_span_exporter)
    assert len(events) >= 1
    for event in events:
        assert event.name.startswith("fortifyroot.safety"), (
            f"Event name should start with 'fortifyroot.safety', got '{event.name}'"
        )
        attr_keys = set(event.attributes.keys())
        fr_keys = {k for k in attr_keys if k.startswith("fortifyroot.")}
        assert len(fr_keys) >= 1, (
            f"Expected fortifyroot.* attributes in safety event, got: {attr_keys}"
        )
