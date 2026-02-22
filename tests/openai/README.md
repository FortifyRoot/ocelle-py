# OpenAI Test Suite Guide

This folder contains OpenAI-focused test coverage for FortifyRoot SDK.
It combines deterministic mocked tests with VCR replay tests.

## What Is Implemented

1. `tests/conftest.py`
   - Shared fixture layer for all tests.
   - Resets env and OTel/FortifyRoot singleton state between tests.
   - Provides `init_openai_sdk`, `span_exporter`, and VCR config.

2. `tests/openai/test_instrumentation.py`
   - Mocked OpenAI instrumentation tests (no network).
   - Uses patched OpenAI SDK methods to validate span behavior.

3. `tests/openai/test_vcr.py`
   - VCR-backed integration tests (record once, replay by default).
   - Supports OpenAI direct and OpenAI-compatible providers via env vars.

4. `tests/openai/cassettes/`
   - Recorded YAML interactions used in replay mode.
   - Safe to commit when VCR filtering is enabled.

5. `tests/openai/__init__.py`
   - Makes `tests/openai` an explicit Python package.

## Test Strategy

1. Mocked tests validate SDK telemetry behavior in isolation.
2. VCR tests validate real request/response API shape with replay stability.
3. Assertions focus on telemetry output shape (span name/attributes/events), not model prose.

## Coverage Checklist

| Dimension | Coverage | Test(s) |
|---|---|---|
| Non-streaming chat | Mock + VCR | `test_chat_completion_creates_span`, `test_chat_completion_non_streaming` |
| Streaming chat | Mock + VCR | `test_chat_completion_streaming_creates_span`, `test_chat_completion_streaming` |
| Multi-model coverage | Mock | `test_multiple_models_are_captured` |
| Vision/multimodal request | Mock + VCR | `test_vision_request_creates_span`, `test_chat_completion_with_vision` |
| Global SDK disable | Mock | `test_disabled_sdk_creates_no_spans` |
| `trace_content=True` | Mock + VCR | `test_trace_content_true_captures_prompts`, `test_chat_completion_non_streaming` |
| `trace_content=False` | Mock + VCR | `test_trace_content_false_hides_prompts`, `test_chat_completion_non_streaming_trace_content_false` |
| `should_enrich_metrics=True` | Mock | `test_enrich_metrics_true_sets_openai_enrichment` |
| `should_enrich_metrics=False` | Mock | `test_enrich_metrics_false_disables_openai_enrichment` |
| `resource_attributes` propagation | Mock | `test_custom_resource_attributes_in_spans` |
| Per-telemetry toggles | Mock | `test_tracing_toggle_disables_tracer_wrapper`, `test_metrics_toggle_*`, `test_logging_toggle_*` |

## Why 4 VCR Tests But 3 Cassettes

Two tests intentionally share one cassette stem:

1. `test_chat_completion_non_streaming`
2. `test_chat_completion_non_streaming_trace_content_false`

Both use:

`@pytest.mark.default_cassette("test_chat_completion_non_streaming")`

Reason: both tests exercise the same HTTP request shape and only validate different tracing behavior, so one cassette is sufficient.

## Local Setup

```bash
cd "/Users/arnavdutta/FortifyRoot - Meta/fr-meta/fortifyroot-sdk-py"
poetry install --with test
```

## Run Commands

1. Run only mocked OpenAI tests:

```bash
poetry run pytest tests/openai/test_instrumentation.py -q
```

2. Run VCR tests in replay mode:

```bash
poetry run pytest tests/openai/test_vcr.py -q --record-mode=none
```

3. Run all OpenAI tests:

```bash
poetry run pytest tests/openai -q
```

## Record/Refresh Cassettes

Use rewrite mode only when intentionally updating recorded fixtures.

1. OpenAI direct:

```bash
OPENAI_API_KEY="<openai-key>" \
OPENAI_BASE_URL="https://api.openai.com/v1" \
OPENAI_TEST_MODEL="gpt-4.1" \
poetry run pytest tests/openai/test_vcr.py -q --record-mode=rewrite -rs
```

2. OpenRouter override:

```bash
OPENAI_API_KEY="<openrouter-key>" \
OPENAI_BASE_URL="https://openrouter.ai/api/v1" \
OPENAI_TEST_MODEL="openai/gpt-4o-mini" \
poetry run pytest tests/openai/test_vcr.py -q --record-mode=rewrite -rs
```

## Authoring Rules For New OpenAI Tests

1. Use `init_openai_sdk` fixture for initialization consistency and in-memory span capture.
2. Do not bypass shared fixture reset behavior from `tests/conftest.py`.
3. Use `@pytest.mark.default_cassette(...)` for every VCR test.
4. Keep tests resilient to provider-side vision fetch instability by asserting telemetry shape and using skip guards where appropriate.

## Troubleshooting

1. `OPENAI_API_KEY is required when recording VCR cassettes`
   - You ran `--record-mode=once|rewrite` without `OPENAI_API_KEY`.

2. `Cassette missing ... Record once with --record-mode=once`
   - Replay mode could not find the required cassette.
   - Record with:

```bash
OPENAI_API_KEY="<openai-key>" \
OPENAI_BASE_URL="https://api.openai.com/v1" \
OPENAI_TEST_MODEL="gpt-4.1" \
poetry run pytest tests/openai/test_vcr.py -q --record-mode=once -rs
```

3. `CannotOverwriteExistingCassetteException`
   - Record and replay settings are mismatched.
   - Use the same `OPENAI_BASE_URL` and `OPENAI_TEST_MODEL` used during recording, or intentionally rewrite.

4. Vision test is skipped
   - Some providers/models intermittently reject remote image URLs (`invalid_image_format`, `invalid_image_url`, provider fetch errors).
   - This is expected behavior in guarded cases; mocked vision coverage still validates instrumentation.

## Security Notes

1. Never commit real API keys.
2. Use placeholder values in docs/scripts.
3. Keep VCR auth filtering enabled.
