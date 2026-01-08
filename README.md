# FortifyRoot SDK

FortifyRoot SDK provides automatic instrumentation and observability for LLM applications. With a single line of code, get complete visibility into your LLM calls, including prompts, responses, token usage, and latency.

## Installation

```bash
pip install fortifyroot-sdk
```

## Quick Start

```python
import fortifyroot

# Initialize FortifyRoot - that's it!
fortifyroot.init(
    app_name="my-llm-app",
    api_key="fr-xxx",  # Get your API key from https://app.fortifyroot.com
)

# Your LLM calls are now automatically traced
import openai

response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

## Supported LLM Libraries

FortifyRoot automatically instruments the following libraries when they are installed:

- **LLM Providers**: OpenAI, Anthropic, Cohere, Google Generative AI, Mistral AI, Groq, Ollama, AWS Bedrock, Azure OpenAI, Vertex AI, Replicate, Together AI, Watsonx
- **Frameworks**: LangChain, LlamaIndex, Haystack, CrewAI, OpenAI Agents
- **Vector Databases**: Pinecone, Chroma, Milvus, Qdrant, Weaviate, LanceDB, Marqo

## Configuration

### Environment Variables

You can configure FortifyRoot using environment variables:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `FORTIFYROOT_API_KEY` | Your FortifyRoot API key | None |
| `FORTIFYROOT_BASE_URL` | API endpoint URL | `https://api.fortifyroot.com` |
| `FORTIFYROOT_TRACE_CONTENT` | Capture prompt/response content | `true` |
| `FORTIFYROOT_TRACING_ENABLED` | Enable/disable tracing | `true` |
| `FORTIFYROOT_METRICS_ENABLED` | Enable/disable metrics | `true` |

### Programmatic Configuration

```python
import fortifyroot
from fortifyroot import Instruments

fortifyroot.init(
    app_name="my-llm-app",
    api_key="fr-xxx",
    api_endpoint="https://api.fortifyroot.com",
    trace_content=True,  # Set to False to disable content capture
    instruments={Instruments.OPENAI, Instruments.LANGCHAIN},  # Only instrument specific libraries
)
```

### Fluent API

For more complex configurations, use the fluent API:

```python
import fortifyroot
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

fortifyroot.configure() \
    .app_name("my-llm-app") \
    .api_key("fr-xxx") \
    .trace_content(False) \
    .sampler(TraceIdRatioBased(0.1)) \
    .init()
```

### Advanced Configuration

```python
import fortifyroot
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

# Custom sampling (10% of traces)
fortifyroot.init(
    app_name="my-app",
    api_key="fr-xxx",
    sampler=TraceIdRatioBased(0.1),
)

# Custom exporter
fortifyroot.init(
    app_name="my-app",
    processor=SimpleSpanProcessor(ConsoleSpanExporter()),
)

# Span postprocess callback (for safety/PII detection)
def safety_callback(span):
    # Inspect span attributes for PII, log alerts, etc.
    pass

fortifyroot.init(
    app_name="my-app",
    api_key="fr-xxx",
    span_postprocess_callback=safety_callback,
)
```

## Decorators

Use decorators to trace custom functions and create hierarchical traces:

```python
from fortifyroot import workflow, task, agent, tool

@workflow(name="document_qa")
def answer_question(document: str, question: str):
    chunks = split_document(document)
    relevant = find_relevant_chunks(chunks, question)
    return generate_answer(relevant, question)

@task(name="split_document")
def split_document(document: str):
    # Your logic here
    return chunks

@task(name="find_relevant")
def find_relevant_chunks(chunks, question):
    # Your logic here
    return relevant_chunks

@task(name="generate_answer")
def generate_answer(context, question):
    # LLM call here
    return answer
```

## Association Properties

Attach custom properties to traces for filtering and correlation:

```python
import fortifyroot

fortifyroot.init(app_name="my-app", api_key="fr-xxx")

# Set properties that will be attached to all subsequent spans
fortifyroot.set_association_properties({
    "user_id": "user_12345",
    "session_id": "sess_abc",
    "conversation_id": "conv_xyz",
})

# Now make LLM calls - they will have these properties attached
response = openai.chat.completions.create(...)
```

## Privacy & Content Tracing

To disable capturing of prompt and response content (for privacy compliance):

```python
# Via environment variable
# export FORTIFYROOT_TRACE_CONTENT=false

# Or programmatically
fortifyroot.init(
    app_name="my-app",
    api_key="fr-xxx",
    trace_content=False,  # Only metadata, no content
)
```

## Attribution

This SDK is built on top of [OpenLLMetry](https://github.com/traceloop/openllmetry) by Traceloop, licensed under Apache 2.0.

## License

Apache 2.0
