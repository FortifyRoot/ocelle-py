# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-XX-XX

### Added

- Initial release of FortifyRoot SDK
- `fortifyroot.init()` function for initializing LLM observability
- Automatic instrumentation for 25+ LLM libraries and frameworks
- Decorator support: `@workflow`, `@task`, `@agent`, `@tool`
- `fortifyroot.set_association_properties()` for trace correlation
- Environment variable configuration with `FORTIFYROOT_*` prefix
- Automatic attribute renaming from `traceloop.*` to `fortifyroot.*`
- SDK version injection into telemetry via resource attributes
- Simplified API compared to underlying traceloop-sdk

### Supported Libraries

- **LLM Providers**: OpenAI, Anthropic, Cohere, Google Generative AI, Mistral AI, Groq, Ollama, AWS Bedrock, Azure OpenAI, Vertex AI, Replicate, Together AI, Watsonx, Aleph Alpha
- **Frameworks**: LangChain, LlamaIndex, Haystack, CrewAI, OpenAI Agents
- **Vector Databases**: Pinecone, Chroma, Milvus, Qdrant, Weaviate, LanceDB, Marqo
