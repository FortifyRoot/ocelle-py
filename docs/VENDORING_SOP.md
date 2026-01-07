# OpenLLMetry Vendoring SOP for FortifyRoot SDK

## Overview

This document describes the Standard Operating Procedure (SOP) for vendoring the OpenLLMetry fork into the FortifyRoot SDK. Vendoring allows us to:

1. Make modifications to OpenLLMetry (rebrand, callbacks) without waiting for upstream PRs
2. Bundle a specific version with our SDK
3. Hide the "traceloop" brand from logs and imports
4. Keep easy upgrade path to newer OpenLLMetry versions

## Architecture

```
fortifyroot-sdk-py/
├── src/fortifyroot/
│   ├── __init__.py          # Public API (init, decorators)
│   ├── core.py               # Main init() implementation
│   ├── decorators.py         # @task, @workflow wrappers
│   ├── instruments.py        # FortifyRoot Instruments enum
│   ├── version.py            # SDK version
│   ├── OPENLLMETRY_VERSION   # Vendored OL version metadata
│   ├── _internal/            # Internal helpers
│   │   ├── constants.py
│   │   └── env_mapping.py
│   ├── _vendor/              # Vendored OpenLLMetry packages
│   │   ├── __init__.py
│   │   ├── VENDOR_MANIFEST.json
│   │   ├── traceloop/        # Vendored traceloop-sdk
│   │   │   └── sdk/
│   │   └── opentelemetry/    # Vendored OL instrumentation packages
│   │       ├── instrumentation/
│   │       │   ├── openai/
│   │       │   ├── anthropic/
│   │       │   ├── langchain/
│   │       │   └── ... (other providers)
│   │       └── semconv_ai/
│   └── processors/           # Custom span processors
└── scripts/
    └── vendor_openllmetry.py # Vendoring automation script
```

## What Gets Vendored vs. External Dependencies

### Vendored (bundled in `_vendor/`)
- `traceloop-sdk` → `fortifyroot._vendor.traceloop.sdk`
- `opentelemetry-semantic-conventions-ai` → `fortifyroot._vendor.opentelemetry.semconv_ai`
- All `opentelemetry-instrumentation-*` from OpenLLMetry → `fortifyroot._vendor.opentelemetry.instrumentation.*`

### NOT Vendored (PyPI dependencies)
These are listed in `pyproject.toml` and installed from PyPI:
- `opentelemetry-api` - Core OTel API
- `opentelemetry-sdk` - Core OTel SDK  
- `opentelemetry-exporter-otlp-proto-http` - OTLP exporter
- `opentelemetry-exporter-otlp-proto-grpc` - OTLP exporter
- `opentelemetry-instrumentation` - Base instrumentation classes
- `opentelemetry-instrumentation-logging` - Logging instrumentation
- `opentelemetry-instrumentation-requests` - Requests instrumentation
- `opentelemetry-instrumentation-sqlalchemy` - SQLAlchemy instrumentation
- `opentelemetry-instrumentation-urllib3` - urllib3 instrumentation
- `opentelemetry-instrumentation-threading` - Threading instrumentation
- `opentelemetry-instrumentation-redis` - Redis instrumentation
- `opentelemetry-semantic-conventions` - Core semantic conventions

### Why This Split?
- OpenLLMetry's LLM provider instrumentations are what we need to modify (rebrand, add callbacks)
- Core OpenTelemetry packages are stable APIs that we shouldn't modify
- Keeping OTel packages external avoids version conflicts with other OTel users

## Repository Setup

### 1. Fork OpenLLMetry

```bash
# Fork https://github.com/traceloop/openllmetry to fortifyroot org
# Then clone locally:
git clone git@github.com:fortifyroot/fr-openllmetry-py.git
cd fr-openllmetry-py

# Add upstream remote
git remote add upstream https://github.com/traceloop/openllmetry.git
git fetch upstream --tags
```

### 2. Create FortifyRoot Branch from Tag

```bash
# Checkout the latest stable tag
git checkout tags/v0.50.1

# Create FR branch for modifications
git checkout -b fr-v0.50.1

# Push the branch
git push -u origin fr-v0.50.1
```

### 3. Make FortifyRoot-specific Modifications

In the `fr-v0.50.1` branch, make these changes:

#### a) Rebrand Logging (required)
Edit `packages/traceloop-sdk/traceloop/sdk/logging/logging.py`:
```python
# Change logger name from "traceloop" to "fortifyroot"
LOGGER_NAME = "fortifyroot"  # was "traceloop"
```

#### b) Add Callbacks (future enhancement)
Add pre/post LLM call callbacks for safety layer integration.

#### c) Commit Changes
```bash
git add -A
git commit -m "FR: Rebrand logging and add callback hooks"
git push
```

### 4. Freeze the Version (Optional but Recommended)

To prevent drift, create a tag on the FR branch:

```bash
git tag fr-v0.50.1-final
git push origin fr-v0.50.1-final
```

## Vendoring Process

### Initial Vendoring

```bash
cd /path/to/fortifyroot-sdk-py

# Run the vendoring script
python scripts/vendor_openllmetry.py \
    --ol-repo /path/to/fr-openllmetry-py \
    --clean

# Verify
ls -la src/fortifyroot/_vendor/
cat src/fortifyroot/OPENLLMETRY_VERSION

# Test
pip install -e ".[dev]"
pytest tests/

# Commit
git add src/fortifyroot/_vendor/ src/fortifyroot/OPENLLMETRY_VERSION
git commit -m "Vendor OpenLLMetry v0.50.1 (fr-v0.50.1)"
```

### Version Bump Procedure

When upgrading from v0.50.1 to v0.50.2:

#### Step 1: Update Fork
```bash
cd /path/to/fr-openllmetry-py

# Fetch upstream changes
git fetch upstream --tags

# Create new branch from new tag
git checkout tags/v0.50.2
git checkout -b fr-v0.50.2

# Cherry-pick FR modifications from previous branch
git cherry-pick <commit-hash-of-FR-changes>

# Resolve any conflicts
# ... edit files as needed ...
git add -A
git commit -m "FR: Rebrand and callback hooks (rebased on v0.50.2)"

# Push
git push -u origin fr-v0.50.2

# Optional: Tag the freeze point
git tag fr-v0.50.2-final
git push origin fr-v0.50.2-final
```

#### Step 2: Re-vendor in FR SDK
```bash
cd /path/to/fortifyroot-sdk-py

# Run vendoring script
python scripts/vendor_openllmetry.py \
    --ol-repo /path/to/fr-openllmetry-py \
    --clean

# Update pyproject.toml dependencies if needed
# (Check traceloop-sdk/pyproject.toml for any new deps)

# Test thoroughly
pip install -e ".[dev]"
pytest tests/

# Commit
git add .
git commit -m "Upgrade vendored OpenLLMetry to v0.50.2"
```

#### Step 3: Update Dependencies
Check if OpenLLMetry added new dependencies:

```bash
# In the fr-openllmetry-py repo
cat packages/traceloop-sdk/pyproject.toml | grep -A 50 "\[tool.poetry.dependencies\]"
```

Update `fortifyroot-sdk-py/pyproject.toml` if new dependencies were added.

## Import Rewriting Details

The vendoring script automatically rewrites imports:

| Original Import | Rewritten Import |
|-----------------|------------------|
| `from traceloop.sdk import X` | `from fortifyroot._vendor.traceloop.sdk import X` |
| `from opentelemetry.semconv_ai import X` | `from fortifyroot._vendor.opentelemetry.semconv_ai import X` |
| `from opentelemetry.instrumentation.openai import X` | `from fortifyroot._vendor.opentelemetry.instrumentation.openai import X` |

**NOT rewritten** (external packages):
| Import | Reason |
|--------|--------|
| `from opentelemetry.trace import X` | Core OTel API (from PyPI) |
| `from opentelemetry.sdk import X` | Core OTel SDK (from PyPI) |
| `from opentelemetry.instrumentation.instrumentor import X` | Base class (from PyPI) |
| `from opentelemetry.instrumentation.utils import X` | Utils (from PyPI) |

## Troubleshooting

### Import Errors After Vendoring

**Symptom:** `ImportError: cannot import name 'X' from 'traceloop.sdk'`

**Solution:** The code is trying to import from non-vendored path. Check:
1. Your code should import from `fortifyroot._vendor.traceloop.sdk`
2. Run the vendoring script with `--clean` flag
3. Verify imports were rewritten: `grep -r "from traceloop\." src/fortifyroot/_vendor/`

### Circular Import Issues

**Symptom:** `ImportError: circular import`

**Solution:** The vendored packages may have circular dependencies. Check the import order and consider lazy imports.

### Version Mismatch

**Symptom:** Features missing or different behavior

**Solution:** 
1. Check `OPENLLMETRY_VERSION` file
2. Verify the correct branch is checked out in the fork
3. Re-run vendoring script

### Namespace Package Conflicts

**Symptom:** `ModuleNotFoundError` for vendored opentelemetry packages

**Solution:** Ensure `__init__.py` files exist and have correct namespace package declaration:
```python
__path__ = __import__("pkgutil").extend_path(__path__, __name__)
```

## Testing Checklist

After vendoring, verify:

- [ ] `import fortifyroot` succeeds
- [ ] `fortifyroot.init()` initializes without errors
- [ ] OpenAI instrumentation works
- [ ] Anthropic instrumentation works
- [ ] LangChain instrumentation works
- [ ] Log messages show "fortifyroot" not "traceloop"
- [ ] Spans are exported correctly
- [ ] All existing tests pass

## Chore Commits in Upstream

You asked about "chore commits" in the upstream repo. These are typically:
- Version bumps in `pyproject.toml`
- Changelog updates
- Dependency updates
- CI/CD changes

They're created by maintainers during release process. For your fork:
- Don't cherry-pick these unless needed
- Your version is defined by the tag you branch from
- Your modifications are separate commits on the FR branch

## Best Practices

1. **Always branch from tags**, not `main`
2. **Minimize changes** in the fork for easier rebasing
3. **Document all FR-specific changes** in commit messages
4. **Test after every vendoring** operation
5. **Keep OPENLLMETRY_VERSION** updated
6. **Review upstream changelog** before upgrading
