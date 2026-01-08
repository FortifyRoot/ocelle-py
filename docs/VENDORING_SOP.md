# OpenLLMetry Vendoring SOP for FortifyRoot SDK

## Overview

This document describes the Standard Operating Procedure (SOP) for vendoring the OpenLLMetry fork into the FortifyRoot SDK. Vendoring allows us to:

1. Make modifications to OpenLLMetry (rebrand, callbacks) without waiting for upstream PRs
2. Bundle a specific version with our SDK
3. Hide the "traceloop" brand from logs, traces, and imports
4. Keep easy upgrade path to newer OpenLLMetry versions

## Architecture

```
fortifyroot-sdk-py/
├── src/fortifyroot/
│   ├── __init__.py          # Public API (init, decorators, configure)
│   ├── core.py               # Main init() and fluent API implementation
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

## Fork Versioning Strategy

### Branch Naming Convention

For each upstream OpenLLMetry version, create a branch named `fr-v{VERSION}.x`:

```
fr-v0.50.1.x    # Development branch for modifications to TL OL v0.50.1
fr-v0.50.2.x    # Development branch for modifications to TL OL v0.50.2
```

The `.x` suffix indicates this is a development branch that may receive multiple commits.

### Tag Naming Convention

When ready to "cut" a release, create a tag with a patch number:

```
fr-v0.50.1.0    # First release based on TL OL v0.50.1
fr-v0.50.1.1    # Bug fix release (still based on TL OL v0.50.1)
fr-v0.50.1.2    # Another bug fix (still based on TL OL v0.50.1)
```

### Example Workflow

```bash
# Initial setup for v0.50.1
git checkout tags/v0.50.1
git checkout -b fr-v0.50.1.x
# Make FR modifications...
git commit -m "FR: Rebrand tracer and logging"
git push -u origin fr-v0.50.1.x
git tag fr-v0.50.1.0
git push origin fr-v0.50.1.0

# Later, if bug fix is needed (still v0.50.1)
git checkout fr-v0.50.1.x
# Make fixes...
git commit -m "FR: Fix callback invocation order"
git push
git tag fr-v0.50.1.1
git push origin fr-v0.50.1.1

# Upgrading to v0.50.2
git fetch upstream --tags
git checkout tags/v0.50.2
git checkout -b fr-v0.50.2.x
git cherry-pick <commits from fr-v0.50.1.x>
# Resolve conflicts...
git push -u origin fr-v0.50.2.x
git tag fr-v0.50.2.0
git push origin fr-v0.50.2.0
```

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

# Create FR development branch (note the .x suffix)
git checkout -b fr-v0.50.1.x

# Push the branch
git push -u origin fr-v0.50.1.x
```

### 3. Make FortifyRoot-specific Modifications

In the `fr-v0.50.1.x` branch, make these changes. See `docs/FORK_BRANDING.md` for the complete list.

Key modifications:

#### a) Rebrand Tracer Name (required)
Edit `packages/traceloop-sdk/traceloop/sdk/tracing/tracing.py`:
```python
# Line 43: Change tracer name
TRACER_NAME = "fortifyroot.tracer"  # was "traceloop.tracer"
```

#### b) Rebrand Warning Messages (required)
Edit `packages/traceloop-sdk/traceloop/sdk/tracing/tracing.py`:
```python
# Line ~210: Change warning message
print(
    Fore.RED
    + "Warning: FortifyRoot not initialized, make sure you call fortifyroot.init()"
)
```

#### c) Update Default Endpoint (recommended)
Edit `packages/traceloop-sdk/traceloop/sdk/__init__.py`:
```python
# Change default endpoint
api_endpoint: str = "https://api.fortifyroot.com",  # was "https://api.traceloop.com"
```

#### d) Commit Changes
```bash
git add -A
git commit -m "FR: Rebrand tracer, logging, and endpoints"
git push
```

### 4. Tag the Release

```bash
git tag fr-v0.50.1.0
git push origin fr-v0.50.1.0
```

## Vendoring Process

### Initial Vendoring

```bash
cd /path/to/fortifyroot-sdk-py

# Run the vendoring script (use the tag)
./scripts/vendor.sh /path/to/fr-openllmetry-py fr-v0.50.1.0

# Or directly with Python
python scripts/vendor_openllmetry.py \
    --ol-repo /path/to/fr-openllmetry-py \
    --tag fr-v0.50.1.0 \
    --clean

# Verify
ls -la src/fortifyroot/_vendor/
cat src/fortifyroot/OPENLLMETRY_VERSION

# Test
poetry install
poetry run pytest tests/

# Commit
git add src/fortifyroot/_vendor/ src/fortifyroot/OPENLLMETRY_VERSION
git commit -m "Vendor OpenLLMetry v0.50.1 (fr-v0.50.1.0)"
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
git checkout -b fr-v0.50.2.x

# Cherry-pick FR modifications from previous branch
git cherry-pick <commit-hash-of-FR-changes>

# Resolve any conflicts
# ... edit files as needed ...
git add -A
git commit -m "FR: Rebrand and callback hooks (rebased on v0.50.2)"

# Push
git push -u origin fr-v0.50.2.x

# Tag the release
git tag fr-v0.50.2.0
git push origin fr-v0.50.2.0
```

#### Step 2: Re-vendor in FR SDK
```bash
cd /path/to/fortifyroot-sdk-py

# Run vendoring script with new tag
./scripts/vendor.sh /path/to/fr-openllmetry-py fr-v0.50.2.0

# Test thoroughly
poetry install
poetry run pytest tests/

# Commit
git add .
git commit -m "Upgrade vendored OpenLLMetry to v0.50.2 (fr-v0.50.2.0)"
```

#### Step 3: Dependencies Update

The vendoring script now automatically extracts and updates dependencies from
all vendored packages. After vendoring, review `pyproject.toml` for any changes.

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

### "traceloop.tracer" Appearing in Traces

**Symptom:** Jaeger/traces show `otel.scope.name: traceloop.tracer`

**Solution:** The `TRACER_NAME` constant wasn't changed in the fork:
1. Edit `packages/traceloop-sdk/traceloop/sdk/tracing/tracing.py`
2. Change `TRACER_NAME = "traceloop.tracer"` to `TRACER_NAME = "fortifyroot.tracer"`
3. Commit, tag, and re-vendor

### Version Mismatch

**Symptom:** Features missing or different behavior

**Solution:** 
1. Check `OPENLLMETRY_VERSION` file
2. Verify the correct tag is checked out in the fork
3. Re-run vendoring script with explicit `--tag` argument

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
- [ ] `fortifyroot.configure().app_name("test").init()` works (fluent API)
- [ ] OpenAI instrumentation works
- [ ] Anthropic instrumentation works
- [ ] LangChain instrumentation works
- [ ] Log messages show "fortifyroot" not "traceloop"
- [ ] Traces show `otel.scope.name: fortifyroot.tracer` not `traceloop.tracer`
- [ ] Spans are exported correctly
- [ ] All existing tests pass

## Best Practices

1. **Always branch from tags**, not `main`
2. **Use the `.x` branch naming** for development branches
3. **Tag releases** before vendoring (use `fr-vX.Y.Z.N` format)
4. **Minimize changes** in the fork for easier rebasing
5. **Document all FR-specific changes** in commit messages
6. **Test after every vendoring** operation
7. **Keep OPENLLMETRY_VERSION** updated
8. **Review upstream changelog** before upgrading
9. **Run the import test** to verify no brand leakage
