# FortifyRoot SDK

**LLM observability + safety guardrails in one SDK.**

FortifyRoot provides:
1. **Observability** - Traces and metrics for all LLM calls via OpenLLMetry
2. **Safety** - Detect and redact PII, PCI, PHI, Secrets, and block jailbreak attempts

## Installation

```bash
pip install pyyaml wrapt traceloop-sdk
```

## Quick Start

```python
import fortifyroot

# Option 1: Observability only (traces/metrics via OpenLLMetry)
fortifyroot.observe(
    api_key="fr-xxx",           # or FORTIFYROOT_API_KEY env var
    app_name="my-app",
    base_url="https://...",     # or FORTIFYROOT_BASE_URL env var
)

# Option 2: Safety enforcement (includes observability automatically)
fortifyroot.enforce(
    config_path="config.yaml",
    policies=["PII", "PCI", "SECRET", "JAILBREAK"],
    providers=["openai", "anthropic"],
    api_key="fr-xxx",           # Telemetry API key
    app_name="my-app",
)

# Set context for tracing
fortifyroot.set_context(user_id="user-123", session_id="sess-456")

# All LLM calls are now protected and traced automatically!
import openai
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "My email is test@example.com"}]
)
# - Input is checked and redacted before sending to OpenAI
# - Trace spans are emitted with safety events attached
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                         │
├─────────────────────────────────────────────────────────────┤
│                  FortifyRoot SDK                            │
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │   Safety Wrapper    │    │   OpenLLMetry (traceloop)   │ │
│  │  - Input check      │    │  - Traces                   │ │
│  │  - Redact/Block     │    │  - Metrics                  │ │
│  │  - Output check     │    │  - Span events              │ │
│  └─────────────────────┘    └─────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│              LLM Providers (OpenAI, Anthropic, etc.)        │
└─────────────────────────────────────────────────────────────┘
```

When you call `enforce()`:
1. Safety wrappers are applied to LLM provider methods
2. OpenLLMetry is initialized (via traceloop-sdk)
3. On each LLM call:
   - Input is checked for sensitive content
   - Safety span events are attached to the OpenLLMetry trace
   - Content is redacted/blocked per policy
   - LLM is called
   - Output is checked
   - Results are traced

## Configuration (config.yaml)

```yaml
settings:
  redaction_template: "[REDACTED{type}]"
  suffix_type: true
  input_action: redact    # Action for input: allow, redact, block
  output_action: allow    # Action for output: allow, redact, block
  block_on_jailbreak: true

rules:
  # Regex mode
  - group: PII
    type: EMAIL
    mode: regex
    pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

  # List mode
  - group: PHI
    type: BLOOD_GROUP
    mode: list
    values: ["A+", "A-", "B+", "B-", "O+", "O-"]

  # Hybrid mode (with validator)
  - group: PCI
    type: CREDIT_CARD
    mode: hybrid
    pattern: '\b\d{16}\b'
    validator: fortifyroot.validators.luhn
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `FORTIFYROOT_API_KEY` | API key for telemetry endpoint |
| `FORTIFYROOT_BASE_URL` | Telemetry endpoint URL |
| `FORTIFYROOT_HEADERS` | Extra headers (format: `key1=val1,key2=val2`) |
| `FORTIFYROOT_APP_NAME` | Application name |

## Supported Providers

**Direct LLM Providers:**
- OpenAI (chat, completions)
- Anthropic (messages)
- Google Gemini
- Cohere
- Mistral AI
- Ollama
- Groq
- Together AI
- AWS Bedrock

## Manual Checking

```python
# Check text manually
result = fortifyroot.check_text("My SSN is 123-45-6789", direction="input")
print(result.action)       # Action.REDACT
print(result.detections)   # List of Detection objects

# Redact text
clean = fortifyroot.redact_text("Card: 4532015112830366")
print(clean)  # "Card: [REDACTED-PCI.CREDIT_CARD]"
```

## Span Events

Safety events are attached to OpenLLMetry spans:

```
Span: "openai.chat"
  ├─ Event: "fortifyroot.safety.input"
  │    - fortifyroot.action: "redact"
  │    - fortifyroot.detections.count: 2
  │    - fortifyroot.detections.types: "PII.EMAIL,PCI.CREDIT_CARD"
  │
  └─ Event: "fortifyroot.safety.output"
       - fortifyroot.action: "allow"
       - fortifyroot.detections.count: 0
```

## Exception Handling

```python
try:
    response = client.chat.completions.create(...)
except fortifyroot.FortifyRootBlocked as e:
    print(f"Blocked: {e.message}")
    print(f"Direction: {e.direction}")  # "input" or "output"
    print(f"Detections: {e.detections}")
```

## Running Tests

```bash
python -m fortifyroot.tests
```

## Files

| File | Description |
|------|-------------|
| `__init__.py` | Public API exports |
| `safety.py` | Rule engine, detection, redaction |
| `sdk.py` | Provider wrappers, traceloop integration |
| `validators.py` | Built-in validators (Luhn, IBAN, etc.) |
| `config.yaml` | Default rule definitions (54 rules) |
| `tests.py` | Unit tests (44 tests) |

## License

MIT
