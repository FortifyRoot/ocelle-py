# FortifyRoot Provider Support

This page is the current launch-certified support matrix for FortifyRoot Ocelle SDK provider and framework instrumentation.

The MVP SDK vendors and exposes only launch-supported instrumentation packages. Planned rows below document roadmap/provider-role direction, not libraries currently exposed by `fortifyroot.ocelle.Instruments` or SDK extras.

## Status Terms

| Status | Meaning |
|---|---|
| `live-tested` | Verified with live provider traffic in the launch validation suite. |
| `fixture-tested` | Covered by recorded or deterministic test fixtures, but not claimed as live-tested in the launch matrix. |
| `mapper-supported` | FortifyRoot recognizes the provider role, but full live coverage is not part of the current launch matrix. |
| `planned` | Planned or broader-direction support; do not describe as launch-certified. |

## Provider Roles

FortifyRoot separates provider identity into three product-facing roles:

| Role | Meaning | Example |
|---|---|---|
| Model Provider | Whose model was used. | Claude via OpenRouter has model provider `anthropic`. |
| Routing Provider | Gateway, proxy, or platform the call passed through. | OpenRouter-routed traffic has routing provider `openrouter`. |
| Billing Provider | Pricing/billed-via provider used for cost attribution. | OpenRouter-routed traffic bills via `openrouter` when FortifyRoot can identify that route. |

Raw SDK/request values can differ from these roles. FortifyRoot keeps raw values for debugging, but product filters and cost cards use the normalized roles above.

## Model Providers

| Provider | Current status | Model provider | Routing provider | Billing provider | Notes |
|---|---:|---:|---:|---:|---|
| OpenAI | `live-tested` | Yes | Direct calls: none | Direct calls: `openai` | OpenAI-compatible routes can change routing/billing provider; see OpenRouter. |
| Anthropic | `live-tested` | Yes | Direct calls: none | Direct calls: `anthropic` | Also appears as model provider for Claude models routed through OpenRouter or LiteLLM. |
| Google GenAI | `live-tested` | Yes | Direct calls: none | Direct calls: `google` | Launch validation covers Gemini-style traffic. |
| xAI | `live-tested` | Yes | Direct calls: none in current launch matrix | Direct calls: `xai`; OpenRouter-routed calls: `openrouter` | Recognized through OpenAI-compatible/OpenRouter paths and provider-role mapping; not a dedicated vendored instrument. |
| AWS Bedrock | `live-tested` | Yes | `bedrock` where Bedrock is the platform route | `bedrock` where Bedrock pricing applies | Includes Bedrock-native and Bedrock-routed provider-role behavior in the launch validation path. |
| Azure OpenAI | `mapper-supported` | Usually `openai` | `azure` | `azure` where Azure pricing applies | Recognized through the OpenAI-compatible instrumentation path and provider-role mapping; not a dedicated vendored instrument. |
| Cohere | `planned` | Planned | Direct calls: none | Provider pricing when certified | Not bundled or exposed in the MVP SDK. |
| Mistral AI | `planned` | Planned | Direct calls: none | Provider pricing when certified | Not bundled or exposed in the MVP SDK. |
| Groq | `planned` | Planned | Direct calls: none | Provider pricing when certified | Future certification item. |
| Ollama | `planned` | Planned | Direct calls: none | Local/provider-specific pricing when supported | Future certification item. |
| Vertex AI | `planned` | Planned | Platform route when supported | Provider/platform pricing when certified | Future certification item. |
| Replicate | `planned` | Planned | Platform route when supported | Provider/platform pricing when certified | Future certification item. |
| Together AI | `planned` | Planned | Direct calls: none | Provider pricing when certified | Future certification item. |
| Watsonx | `planned` | Planned | Platform route when supported | Provider/platform pricing when certified | Future certification item. |
| Aleph Alpha | `planned` | Planned | Direct calls: none | Provider pricing when certified | Future certification item. |
| SageMaker | `planned` | Planned | Platform route when supported | Provider/platform pricing when certified | Future certification item. |
| Writer | `planned` | Planned | Direct calls: none | Provider pricing when certified | Future certification item. |

## Routing And Billing Providers

| Provider | Current status | Routing provider behavior | Billing provider behavior | Notes |
|---|---:|---|---|---|
| OpenRouter | `live-tested` | `routing_provider=openrouter` when traffic is sent through OpenRouter. | `billing_provider=openrouter` when the route is identified and pricing data is available. | Model provider remains the underlying vendor, such as `anthropic`, `openai`, `google`, or `xai`. |
| LiteLLM self-hosted | `live-tested` | `routing_provider=litellm`. | Defaults to the underlying model provider unless another routed billing provider is explicitly identified. | FortifyRoot does not infer LiteLLM Cloud billing from self-hosted LiteLLM traffic. |
| LiteLLM Cloud | `planned` | Needs an explicit Cloud/self-hosted signal. | Planned; requires LiteLLM Cloud pricing and an org/config signal before `billing_provider=litellm` is emitted. | Do not describe LiteLLM Cloud billing as launch-certified. |
| Azure | `mapper-supported` | `routing_provider=azure` for Azure-routed OpenAI traffic. | `billing_provider=azure` where Azure pricing applies. | Supported by provider-role mapping; validate live for launch claims. |
| AWS Bedrock | `live-tested` | `routing_provider=bedrock` for Bedrock-platform traffic. | `billing_provider=bedrock` where Bedrock pricing applies. | Model provider can be Bedrock-native or an underlying third-party model provider depending on the model. |

## Frameworks

| Framework | Current status | Provider-role behavior | Notes |
|---|---:|---|---|
| LangChain | `live-tested` | Preserves the underlying provider for supported OpenAI/Anthropic-backed paths. | Includes LangGraph/OpenAI-path validation in the launch work. |
| LangGraph | `live-tested` | Same provider-role behavior as the LangChain/OpenAI path in the launch matrix. | Treated as part of the LangChain framework path for launch validation. |
| LlamaIndex | `live-tested` | Preserves the underlying provider for supported OpenAI-backed paths. | Launch matrix covers the certified LlamaIndex paths, not every possible LlamaIndex model integration. |
| LiteLLM | `live-tested` | Preserves `routing_provider=litellm` and identifies model/billing provider deterministically. | Unknown routed providers are not guessed. |
| Haystack | `planned` | Planned | Not bundled or exposed in the MVP SDK. |
| CrewAI | `planned` | Planned | Not bundled or exposed in the MVP SDK. |
| OpenAI Agents | `planned` | Planned | Not bundled or exposed in the MVP SDK. |
| MCP | `planned` | Planned | Not bundled or exposed in the MVP SDK. |
| Agno | `planned` | Planned | Not bundled or exposed in the MVP SDK. |

## Vector Databases

Vector database instrumentation is separate from LLM provider-role attribution and is not bundled in the MVP SDK.

## Caveats

- This page is a launch-certified support matrix, not an exhaustive list of every library that can be imported or partially instrumented.
- Provider-role behavior requires telemetry emitted by a current SDK and FortifyRoot service version. Older telemetry can lack newer role labels.
- Pricing support depends on available pricing data and deterministic billing-provider identification.
- LiteLLM Cloud billing is planned, not launch-certified.
- OpenRouter via the OpenAI SDK is still OpenRouter-routed traffic; the OpenAI SDK itself is not the routing provider when the base URL points to OpenRouter.
