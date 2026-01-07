# FortifyRoot SDK - OpenLLMetry Vendoring Solution

## Executive Summary

This document provides a complete solution for vendoring OpenLLMetry into the FortifyRoot SDK. The solution addresses:

1. **Import Resolution Issues** - All vendored code works correctly under `_vendor/`
2. **Selective Vendoring** - Only OpenLLMetry packages are vendored; core OTel packages remain external
3. **Maintainable Version Upgrades** - Clear SOP for upgrading to newer OpenLLMetry versions
4. **No Namespace Conflicts** - Vendored packages don't conflict with user-installed OTel packages

## Key Architecture Decisions

### What Gets Vendored (bundled in `_vendor/`)

| Package | Reason |
|---------|--------|
| `traceloop-sdk` | Main SDK - needs rebranding & callbacks |
| `opentelemetry-semantic-conventions-ai` | AI-specific semantic conventions |
| `opentelemetry-instrumentation-openai` | LLM provider instrumentation |
| `opentelemetry-instrumentation-anthropic` | LLM provider instrumentation |
| `opentelemetry-instrumentation-langchain` | LLM provider instrumentation |
| ... (30+ provider packages) | LLM provider instrumentations |

### What Stays External (from PyPI)

| Package | Reason |
|---------|--------|
| `opentelemetry-api` | Core API - no changes needed |
| `opentelemetry-sdk` | Core SDK - no changes needed |
| `opentelemetry-instrumentation` | Base classes for instrumentors |
| `opentelemetry-instrumentation-*` (std lib) | Standard library instrumentation |
| `opentelemetry-semantic-conventions` | Core semantic conventions |
| `opentelemetry-exporter-*` | Exporters |

### Why This Split?

1. **Core OTel packages are stable** - No need to modify them
2. **Avoid conflicts** - Users might use OTel directly; we don't want version conflicts
3. **Smaller package size** - Only bundle what needs modification
4. **Easier upgrades** - Core OTel packages upgrade independently

## The Import Rewriting Solution

### The Problem

When you move packages under `_vendor/`, absolute imports break:

```python
# Original (breaks when vendored)
from traceloop.sdk import Traceloop

# After vendoring, Python can't find 'traceloop' as top-level package
```

### The Solution: Automated Import Rewriting

The `vendor_openllmetry.py` script automatically rewrites imports:

```python
# Before rewriting
from traceloop.sdk.datasets import Dataset
from opentelemetry.semconv_ai import SpanAttributes
from opentelemetry.instrumentation.openai import OpenAIInstrumentor

# After rewriting
from fortifyroot._vendor.traceloop.sdk.datasets import Dataset
from fortifyroot._vendor.opentelemetry.semconv_ai import SpanAttributes
from fortifyroot._vendor.opentelemetry.instrumentation.openai import OpenAIInstrumentor
```

### What's NOT Rewritten

Core OpenTelemetry imports are left unchanged:

```python
# These stay as-is (resolved from site-packages)
from opentelemetry.trace import get_tracer
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap
```

### Why Not sys.path Manipulation?

Alternative approaches like `sys.path` manipulation or import hooks were considered but rejected:

| Approach | Problem |
|----------|---------|
| `sys.path.insert(0, _vendor_path)` | Conflicts with installed packages |
| Import hooks (PEP 302) | Complex, fragile, hard to debug |
| `sys.modules` manipulation | Risk of subtle bugs with shared state |

**Import rewriting is the cleanest solution** - it's explicit, debuggable, and used by major projects like `pip` (see `pip/_vendor/`).

## Answering Your Specific Questions

### Q: Should core OTel packages be vendored?

**No.** Keep them as external dependencies. If you vendor them:
- Package size grows significantly (~5MB+)
- Conflicts if user also uses OTel directly
- No benefit since we don't modify them

The solution keeps them in `pyproject.toml` as regular dependencies.

### Q: Can there be conflicts with same namespace packages?

**No, with our approach.** Here's why:

- We vendor: `fortifyroot._vendor.opentelemetry.instrumentation.openai`
- Site-packages has: `opentelemetry.instrumentation` (base classes only)
- These are **different namespaces** - no conflict

If a user installs `opentelemetry-instrumentation-openai` from PyPI, it would coexist because our package is under a different namespace (`fortifyroot._vendor`).

### Q: How to handle version bumps (e.g., v0.50.1 → v0.50.2)?

Follow this workflow:

```bash
# 1. In your fork (fr-openllmetry-py)
git fetch upstream --tags
git checkout tags/v0.50.2
git checkout -b fr-v0.50.2
git cherry-pick <fr-specific-commits>  # From fr-v0.50.1
# Resolve conflicts, test

# 2. In FR SDK
./scripts/vendor.sh /path/to/fr-openllmetry-py
# Test, commit
```

### Q: How to freeze versions (prevent drift)?

Tag your FR branches:

```bash
# After making all FR changes
git tag fr-v0.50.1-final
git push origin fr-v0.50.1-final
```

Use tags as source of truth for vendoring:

```bash
cd /path/to/fr-openllmetry-py
git checkout fr-v0.50.1-final
# Then vendor
```

### Q: What are "chore" commits in upstream?

Chore commits are housekeeping changes:
- Version bumps in `pyproject.toml`
- Changelog updates
- CI/CD configuration
- Dependency updates

**You don't need to cherry-pick these.** Your version is determined by:
1. The upstream tag you branch from (e.g., `v0.50.1`)
2. Your FR-specific modifications

### Q: How to extract dependencies for pyproject.toml?

Script to extract dependencies from OpenLLMetry:

```bash
cd /path/to/openllmetry/packages/traceloop-sdk
grep -A 100 "\[tool.poetry.dependencies\]" pyproject.toml | \
    grep -E "^[a-zA-Z]" | \
    grep -v "python" | \
    grep -v "path ="
```

Then manually translate to pyproject.toml format.

## File Structure

```
fortifyroot-sdk-py/
├── pyproject.toml              # Dependencies & build config
├── src/fortifyroot/
│   ├── __init__.py             # Public API
│   ├── core.py                 # init() implementation
│   ├── decorators.py           # @task, @workflow
│   ├── instruments.py          # Instruments enum
│   ├── version.py              # SDK version
│   ├── OPENLLMETRY_VERSION     # Vendored version metadata
│   ├── _internal/              # Internal helpers
│   ├── _vendor/                # Vendored packages
│   │   ├── VENDOR_MANIFEST.json
│   │   ├── traceloop/sdk/
│   │   └── opentelemetry/
│   │       ├── instrumentation/
│   │       └── semconv_ai/
│   └── processors/
├── scripts/
│   ├── vendor_openllmetry.py   # Vendoring automation
│   └── vendor.sh               # Shell wrapper
├── tests/
└── docs/
    └── VENDORING_SOP.md        # Detailed procedures
```

## Running the Vendoring

```bash
# Option 1: Python script directly
python scripts/vendor_openllmetry.py \
    --ol-repo /path/to/fr-openllmetry-py \
    --clean

# Option 2: Shell wrapper
./scripts/vendor.sh /path/to/fr-openllmetry-py
```

## Testing After Vendoring

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/test_vendored_imports.py -v

# Quick smoke test
python -c "from fortifyroot._vendor.traceloop.sdk import Traceloop; print('OK')"
```

## What the ChatGPT Solution Got Wrong

The original ChatGPT solution failed because:

1. **No import rewriting** - Just copied files without changing imports
2. **Missing namespace `__init__.py`** - Namespace packages need proper setup
3. **Wrong expectations** - Assumed vendored code would "just work"

Our solution fixes all these issues with automated import rewriting.

## Summary

| Concern | Solution |
|---------|----------|
| Import resolution | Automated import rewriting in vendor script |
| OTel conflicts | Only vendor OpenLLMetry packages, not core OTel |
| Version tracking | `OPENLLMETRY_VERSION` file + manifest |
| Upgrade process | Clear SOP with cherry-pick workflow |
| Version freezing | Tags on FR branches |
| Dependencies | Extract from OL pyproject.toml to FR pyproject.toml |
