# FortifyRoot Ocelle

FortifyRoot Ocelle is the Python SDK for FortifyRoot LLM observability and runtime safety. Add one initialization call to your application and Ocelle will instrument supported LLM providers and frameworks, emit OpenTelemetry traces/metrics/logs to FortifyRoot, and apply configured prompt/completion safety rules before sensitive content leaves or enters your application flow.

Ocelle is built on a FortifyRoot-maintained OpenLLMetry fork, vendored into this repository for dependency isolation, safety extensions, and stable FortifyRoot packaging.

## What Ocelle Captures

- LLM request/response traces with provider, model, span hierarchy, token usage, latency, retry-attempt, and streaming timing metadata.
- Framework spans for workflows, tasks, agents, and tools through decorators and supported framework integrations.
- Optional prompt and completion content when content tracing is enabled.
- Safety findings for prompt and completion content, including masking decisions and rule metadata.
- OTLP traces, metrics, and correlated logs for FortifyRoot ingestion.

## Installation

Ocelle supports Python 3.10 and newer.

```bash
pip install fortifyroot-ocelle
```

Install only the provider/framework extras your application uses:

```bash
pip install "fortifyroot-ocelle[openai]"
pip install "fortifyroot-ocelle[openai,anthropic,langchain]"
pip install "fortifyroot-ocelle[bedrock,litellm,llamaindex]"
```

## Quick Start

```python
import fortifyroot.ocelle as ocelle

ocelle.init(
    app_name="my-llm-app",
    api_key="fr_sk_...",
    resource_attributes={"environment": "prod"},
)

from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

The canonical SDK import is:

```python
import fortifyroot.ocelle as ocelle
```

The package also exposes a convenience alias:

```python
import ocelle
```

## Supported Providers And Frameworks

This table lists the launch-supported instrumentation exposed through `fortifyroot.ocelle.Instruments` and SDK extras. Package ranges are the ranges declared by this SDK; they are not a claim about the latest upstream release.

| Library / framework | Instrument | Extra | Declared package range | Sync | Async | Streaming | Safety |
|---|---|---|---|---:|---:|---:|---|
| OpenAI | `Instruments.OPENAI` | `openai` | `openai >=1.31.1,<3` | Yes | Yes | Yes | Prompt + completion, including streaming paths |
| Anthropic | `Instruments.ANTHROPIC` | `anthropic` | `anthropic >=0.49,<1.0.0` | Yes | Yes | Yes | Prompt + completion, including streaming paths |
| Google GenAI / Gemini | `Instruments.GOOGLE_GENERATIVEAI` | `google-generativeai` | `google-genai >=1.0.0,<2` | Yes | Yes | Yes | Prompt + completion, including streaming paths |
| AWS Bedrock Runtime | `Instruments.BEDROCK` | `bedrock` | `boto3 >=1.34.120,<2` | Yes | No native async client path | Yes | Prompt + completion for invoke/converse paths, including stream wrappers |
| LiteLLM | `Instruments.LITELLM` | `litellm` | `litellm >=1.71.2,<2,!=1.82.7,!=1.82.8` | Yes | Yes | Yes | Prompt + completion, including streaming paths |
| LangChain | `Instruments.LANGCHAIN` | `langchain` | `langchain >=0.2.5,<2.0.0`, `langchain-openai >=0.1.15,<2.0.0` | Yes | Yes | Provider-dependent | Prompt + completion for supported chat/LLM paths |
| LangGraph | via `Instruments.LANGCHAIN` | install with app | Covered through LangChain/OpenAI launch path | Yes | Yes | Provider-dependent | Same supported path as LangChain |
| LlamaIndex | `Instruments.LLAMA_INDEX` | `llamaindex` | `llama-index >=0.14.12,<0.15.0` | Yes | Yes | Yes | Prompt + completion, including streaming paths |

For provider-role behavior, routed providers such as OpenRouter, LiteLLM, Bedrock, Azure OpenAI, and planned/mapper-supported providers, see [Provider Support](docs/PROVIDERS.md). That document is the source of truth for what is launch-certified versus planned.

## Runtime Safety

Ocelle can poll a FortifyRoot SDK config profile and apply configured safety rules locally in the SDK. Rules can inspect prompt and completion text and currently resolve to `ALLOW` or `MASK`.

Supported safety categories are:

`PII`, `PCI`, `PHI`, `API_KEY`, `SECRET`, `PROMPT_INJECTION`, `PROFANITY`, `TOXICITY`, `VIOLENCE`, `SELF_HARM`, `CONFIDENTIAL`, and `CUSTOM`.

Rules can be backed by regex matchers, string-list matchers, or approved user-defined detectors. Masking is applied before the instrumented provider/framework returns the text to application code where the integration can safely mutate the response object or stream chunk.

Because Ocelle is open source, the SDK's enforcement flow is visible by design. Organization-specific safety policy is fetched at runtime from your FortifyRoot SDK config profile, so public code review exposes the engine and built-in defaults, not customer-specific rules.

## Configuration

### Environment Variables

| Environment variable | Description | Default |
|---|---|---|
| `FORTIFYROOT_API_KEY` | FortifyRoot API key | None |
| `FORTIFYROOT_BASE_URL` | FortifyRoot API endpoint | `https://api.fortifyroot.com` |
| `FORTIFYROOT_TRACE_CONTENT` | Capture prompt/response content | `true` |
| `FORTIFYROOT_TRACING_ENABLED` | Enable trace export | `true` |
| `FORTIFYROOT_METRICS_ENABLED` | Enable metric export | `true` |
| `FORTIFYROOT_LOGGING_ENABLED` | Enable OTLP log export and synthetic span-end logs | `false` |

When `FORTIFYROOT_LOGGING_ENABLED=true`, Python `logging` records emitted inside active spans are exported with trace/span correlation. `print(...)`, stdout, and stderr capture are not included; use Python `logging` for application logs.

### Programmatic Configuration

```python
import fortifyroot.ocelle as ocelle
from fortifyroot.ocelle import Instruments

ocelle.init(
    app_name="my-llm-app",
    api_key="fr_sk_...",
    api_endpoint="https://api.fortifyroot.com",
    trace_content=True,
    instruments={Instruments.OPENAI, Instruments.LANGCHAIN},
)
```

### Fluent API

```python
import fortifyroot.ocelle as ocelle
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

ocelle.configure() \
    .app_name("my-llm-app") \
    .api_key("fr_sk_...") \
    .trace_content(False) \
    .sampler(TraceIdRatioBased(0.1)) \
    .init()
```

## Decorators

Use decorators to add trace structure around your own application logic:

```python
from fortifyroot.ocelle import agent, task, tool, workflow

@workflow(name="document_qa")
def answer_question(document: str, question: str):
    chunks = split_document(document)
    relevant = find_relevant_chunks(chunks, question)
    return generate_answer(relevant, question)

@task(name="split_document")
def split_document(document: str):
    return chunks

@task(name="find_relevant")
def find_relevant_chunks(chunks, question):
    return relevant_chunks

@task(name="generate_answer")
def generate_answer(context, question):
    return answer
```

## Association Properties

Attach properties to traces for filtering and correlation:

```python
import fortifyroot.ocelle as ocelle

ocelle.init(app_name="my-app", api_key="fr_sk_...")

ocelle.set_association_properties({
    "user_id": "user_12345",
    "session_id": "sess_abc",
    "conversation_id": "conv_xyz",
})
```

## Network Requirements

If your app runs in a private subnet, VPC, Kubernetes cluster, or locked-down runtime, allow outbound HTTPS egress on TCP 443 to `api.fortifyroot.com`.

Ocelle exports telemetry over OTLP/HTTP to:

- `https://api.fortifyroot.com/v1/traces`
- `https://api.fortifyroot.com/v1/metrics`
- `https://api.fortifyroot.com/v1/logs`

If safety enforcement is enabled with `config_profile_id`, the SDK also polls:

- `https://api.fortifyroot.com/v1/sdk/config/{config_profile_id}`

No inbound firewall rule is required. Hosted FortifyRoot usage does not require opening OTLP ports `4317` or `4318`. Your workload still needs separate egress to whichever LLM providers it calls.

## Privacy And Content Tracing

Disable prompt and response content capture with:

```bash
export FORTIFYROOT_TRACE_CONTENT=false
```

or programmatically:

```python
import fortifyroot.ocelle as ocelle

ocelle.init(
    app_name="my-app",
    api_key="fr_sk_...",
    trace_content=False,
)
```

Safety rules can still run when configured; content tracing controls what is exported as telemetry content.

## License And Attribution

Apache License, Version 2.0.

FortifyRoot Ocelle includes code derived from [OpenLLMetry](https://github.com/traceloop/openllmetry) and `traceloop-sdk` by Traceloop, licensed under the Apache License, Version 2.0. The license text and attribution are retained in [LICENSE](LICENSE).
