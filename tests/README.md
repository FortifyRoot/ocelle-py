# FortifyRoot Ocelle SDK Test Suite

This document is the high-level guide for everything under `tests/` in `ocelle-py`.
It explains test structure, execution flow, CI behavior, and security expectations.

## Goals

The test suite verifies:

1. Public SDK API behavior and backward compatibility.
2. Internal behavior that must remain stable (env mapping, attribute renaming, vendored import boundaries).
3. Provider instrumentation behavior with two layers:
   1. Mocked unit tests (fast, deterministic, no network).
   2. VCR-backed integration tests (record once, replay by default).

## Directory Overview

Current layout:

1. `tests/conftest.py`
   - Shared fixtures and test-state reset.
   - Resets relevant env vars and OTel/FortifyRoot singleton state between tests.
   - Provides `init_openai_sdk`, `span_exporter`, and VCR config fixtures.

2. `tests/test_init.py`
   - Public `init()`/version/API surface sanity checks.

3. `tests/test_decorators.py`
   - Decorator wrappers (`task`, `workflow`, `agent`, `tool`) and `Instruments` enum behavior.

4. `tests/test_env_mapping.py`
   - `FORTIFYROOT_*` -> `TRACELOOP_*` env var mapping behavior.

5. `tests/test_attribute_renaming.py`
   - Span attribute remapping from `traceloop.*` to `fortifyroot.*`.

6. `tests/test_vendored_imports.py`
   - Vendor boundary checks and public API branding checks.

7. `tests/openai/`
   - Provider-specific OpenAI tests and cassettes.
   - See `tests/openai/README.md` for provider-specific details.

## Shared Fixture Contract

`tests/conftest.py` is the shared stability layer for this suite.

1. It resets SDK and OpenTelemetry global state around each test.
2. It isolates env vars used by FortifyRoot and test runs.
3. Provider tests should prefer shared fixtures (for example `init_openai_sdk`) instead of custom ad-hoc init logic.

## Test Layers

Use these layers intentionally:

1. Core tests (`tests/test_*.py`)
   - No provider network.
   - Verify FortifyRoot Ocelle SDK contract and internal behavior.

2. Provider mocked tests (`tests/openai/test_instrumentation.py`)
   - Patch provider SDK calls.
   - Validate telemetry/span behavior deterministically.

3. Provider VCR tests (`tests/openai/test_vcr.py`)
   - Validate real request/response shape.
   - Replay cassettes in normal runs.
   - Record only when intentionally refreshing cassettes.

## Local Setup

```bash
cd "/Users/arnavdutta/FortifyRoot - Meta/fr-meta/ocelle-py"
poetry install --with test
```

## Common Commands

1. Run full test suite:

```bash
poetry run pytest tests -q
```

2. Run only core SDK tests:

```bash
poetry run pytest tests/test_*.py -q
```

3. Run only OpenAI tests:

```bash
poetry run pytest tests/openai -q
```

4. Run OpenAI VCR in replay mode (CI-like):

```bash
poetry run pytest tests/openai/test_vcr.py -q --record-mode=none
```

5. Record or refresh OpenAI cassettes intentionally:

```bash
OPENAI_API_KEY="<provider-key>" \
OPENAI_BASE_URL="https://api.openai.com/v1" \
OPENAI_TEST_MODEL="gpt-4.1" \
poetry run pytest tests/openai/test_vcr.py -q --record-mode=rewrite -rs
```

For OpenRouter or another OpenAI-compatible endpoint, override `OPENAI_BASE_URL` and `OPENAI_TEST_MODEL` accordingly.

## Pytest Markers And VCR Behavior

Configured in `pyproject.toml`:

1. `vcr`
   - Marks tests using cassette record/replay via `pytest-recording`.

2. `default_cassette(name)`
   - Pins a VCR test to a specific cassette file stem.

VCR matching is strict (`method`, `scheme`, `host`, `port`, `path`, `query`), so replay must use the same request shape as recording.

## CI Behavior

CI workflow: `.github/workflows/tests-ci.yml`

On every pull request:

1. `Secret Policy Check`
   - Fails if provider key patterns are hardcoded in tracked files.

2. `Run Test Suite`
   - Installs dependencies and runs `poetry run pytest tests -q`.
   - Uses OpenAI-compatible defaults for VCR replay envs:
     1. `OPENAI_BASE_URL=https://api.openai.com/v1`
     2. `OPENAI_TEST_MODEL=gpt-4.1`

## Secrets And Public-Repo Policy

Rules for all tests, docs, scripts, and workflows:

1. Never commit real API keys or bearer tokens.
2. Use placeholder values in examples.
3. Keep cassette sanitization enabled for auth headers/query params.
4. Store runtime credentials only in local env or GitHub Actions secrets.
5. If a key leak is suspected, rotate immediately and invalidate the old key.

## Key Rotation (High-Level)

1. Generate a new provider key.
2. Update the corresponding GitHub repository secret.
3. Re-run CI and any recording flows that require live credentials.
4. Revoke the old key.
5. Confirm no leaked values remain in history or open diffs.

## Adding New Provider Test Suites

When introducing another provider (for example Anthropic), use this contract checklist:

1. Create `tests/<provider>/test_instrumentation.py` for mocked behavior tests.
2. Create `tests/<provider>/test_vcr.py` for integration record/replay tests.
3. Create `tests/<provider>/cassettes/` and commit sanitized cassette fixtures.
4. Add `tests/<provider>/README.md` with local run, replay, record, and troubleshooting instructions.
5. Reuse shared fixtures from `tests/conftest.py` for state reset and exporter wiring.
6. Keep replay-first behavior for CI stability (`--record-mode=none`).
7. Register and use explicit pytest markers/cassette naming where required.
8. Ensure secret filtering covers auth headers and API key query params before any cassette commit.

## Troubleshooting Quick Reference

1. `OPENAI_API_KEY is required when recording VCR cassettes`
   - You used record mode (`once` or `rewrite`) without a key.

2. `CannotOverwriteExistingCassetteException`
   - Replay request does not match recorded cassette host/path/query/method.
   - Re-run with matching base URL/model or intentionally re-record.

3. Unexpected cross-test state leakage
   - Usually means state reset fixtures were bypassed.
   - Use shared fixtures and avoid direct one-off global setup in tests.

## Further Reading

1. OpenAI-specific details:
   - `tests/openai/README.md`
