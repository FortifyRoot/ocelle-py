# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-DD

### Added

- Initial public release of the FortifyRoot SDK
- Core initialization APIs:
  - `fortifyroot.init()`
  - `fortifyroot.configure()` fluent API
- Vendored OpenLLMetry (Traceloop) auto-instrumentation framework
- Automatic instrumentation for 25+ LLM libraries and frameworks via OpenLLMetry
- Decorator support: `@workflow`, `@task`, `@agent`, `@tool`
- Trace correlation via `fortifyroot.set_association_properties()`
- Environment variable configuration using `FORTIFYROOT_*` namespace
- Automatic attribute renaming from `traceloop.*` to `fortifyroot.*`
- Injection of FortifyRoot SDK version into OpenTelemetry resource attributes
- Simplified, FortifyRoot-branded API layered on top of `traceloop-sdk`


### Vendored Dependencies

- OpenLLMetry (Traceloop) v0.50.1
