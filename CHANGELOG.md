# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Pruned post-MVP provider extras before the SDK's first PyPI publication. The
  MVP package exposes extras only for launch-supported instrumentation paths,
  so no compatibility aliases are needed.

### Fixed

- **Metrics initialization bug**: Fixed an issue where metrics were unintentionally
  disabled when using the default span processor. The SDK now automatically creates
  a default `OTLPMetricExporter` when a processor is configured but no explicit
  `metrics_exporter` is provided. This ensures metrics work out-of-the-box with
  `FORTIFYROOT_METRICS_ENABLED=true`.

---

## [0.1.0] - 2026-01-DD

### Added

- Initial public release of the FortifyRoot SDK
- Core initialization APIs:
  - `fortifyroot.init()`
  - `fortifyroot.configure()` fluent API
- Vendored OpenLLMetry (Traceloop) auto-instrumentation framework
- Automatic instrumentation for MVP-supported providers and frameworks:
  OpenAI, Anthropic, Google GenAI, Bedrock, LiteLLM, LangChain, and LlamaIndex
- Decorator support: `@workflow`, `@task`, `@agent`, `@tool`
- Trace correlation via `fortifyroot.set_association_properties()`
- Environment variable configuration using `FORTIFYROOT_*` namespace
- Automatic attribute renaming from `traceloop.*` to `fortifyroot.*`
- Injection of FortifyRoot SDK version into OpenTelemetry resource attributes
- Simplified, FortifyRoot-branded API layered on top of `traceloop-sdk`


### Vendored Dependencies

- OpenLLMetry (Traceloop) v0.50.1
