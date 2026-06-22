# FortifyRoot Ocelle

FortifyRoot Ocelle is a Python SDK for LLM observability, safety, and auditability. With a single initialization call, Ocelle instruments supported LLM providers and frameworks, captures traces, records token/latency metadata, and applies FortifyRoot safety callbacks for prompt and completion content.

## Installation

Ocelle supports Python 3.10 and newer.

```bash
pip install fortifyroot-ocelle
```

Install provider extras as needed:

```bash
pip install "fortifyroot-ocelle[openai]"
pip install "fortifyroot-ocelle[openai,anthropic,langchain]"
```

## Quick Start

```python
import fortifyroot.ocelle as ocelle

ocelle.init(
    app_name="my-llm-app",  # any name you choose for this service
    api_key="fr_sk_...",
    resource_attributes={"environment": "dev"},  # dev / prod / testing — or any label you choose
)

import openai

response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

The canonical import is:

```python
import fortifyroot.ocelle as ocelle
```

The package also exposes a convenience alias:

```python
import ocelle
```

The root `fortifyroot` package is reserved for internal namespaces such as vendored instrumentation. Public SDK code should use `fortifyroot.ocelle` or the `ocelle` convenience alias.

## Auto-Instrumented LLM Libraries

The MVP SDK vendors and exposes the following supported instrumentation packages:

- **LLM providers**: OpenAI, Anthropic, Google Generative AI, AWS Bedrock, LiteLLM
- **Frameworks**: LangChain, LlamaIndex

For the current launch-certified provider-role matrix and support tiers, see [Provider Support](docs/PROVIDERS.md).

## Configuration

### Environment Variables

Ocelle keeps the FortifyRoot environment variable namespace stable:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `FORTIFYROOT_API_KEY` | FortifyRoot API key | None |
| `FORTIFYROOT_BASE_URL` | API endpoint URL | `https://api.fortifyroot.com` |
| `FORTIFYROOT_TRACE_CONTENT` | Capture prompt/response content | `true` |
| `FORTIFYROOT_TRACING_ENABLED` | Enable/disable tracing | `true` |
| `FORTIFYROOT_METRICS_ENABLED` | Enable/disable metrics | `true` |
| `FORTIFYROOT_LOGGING_ENABLED` | Enable OTLP log export and synthetic span-end logs | `false` |

When `FORTIFYROOT_LOGGING_ENABLED=true`:

- stdlib Python `logging` records keep using the app's existing handlers and formatting
- stdlib Python `logging` records emitted inside active spans are exported with trace/span correlation
- stdlib Python `logging` records emitted outside active spans can still be exported, but they remain uncorrelated
- Ocelle emits one synthetic correlated log for each completed instrumented span
- `print(...)`, stdout, and stderr capture are not included in MVP; use Python `logging` for application logs

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

### Advanced Configuration

```python
import fortifyroot.ocelle as ocelle
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

ocelle.init(
    app_name="my-app",
    api_key="fr_sk_...",
    sampler=TraceIdRatioBased(0.1),
)

ocelle.init(
    app_name="my-app",
    processors=[SimpleSpanProcessor(ConsoleSpanExporter())],
)

def span_callback(span):
    # Inspect span attributes, log alerts, etc.
    pass

ocelle.init(
    app_name="my-app",
    api_key="fr_sk_...",
    span_postprocess_callback=span_callback,
)
```

## Decorators

Use decorators to trace custom functions and create hierarchical traces:

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

Attach custom properties to traces for filtering and correlation:

```python
import fortifyroot.ocelle as ocelle

ocelle.init(app_name="my-app", api_key="fr_sk_...")

ocelle.set_association_properties({
    "user_id": "user_12345",
    "session_id": "sess_abc",
    "conversation_id": "conv_xyz",
})
```

## Privacy And Content Tracing

To disable prompt and response content capture:

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

## Attribution

FortifyRoot Ocelle includes code derived from [OpenLLMetry](https://github.com/traceloop/openllmetry) and `traceloop-sdk` by Traceloop, licensed under the Apache License, Version 2.0. The SDK retains the Apache 2.0 license text and attribution in [LICENSE](LICENSE).

## License

Apache License, Version 2.0.
