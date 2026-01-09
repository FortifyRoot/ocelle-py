# FortifyRoot Fork Branding Guide

This document lists all the places in the OpenLLMetry fork that need to be modified
to rebrand from "Traceloop" to "FortifyRoot".

## Why Rebrand?

When vendoring OpenLLMetry, we want to:
1. Present a consistent "FortifyRoot" brand to users
2. Avoid confusion with Traceloop's own service
3. Ensure logs, traces, and errors reference FortifyRoot

## Critical Changes (Required)

### 1. Tracer Name

**File:** `packages/traceloop-sdk/traceloop/sdk/tracing/tracing.py`

**Line ~43:**
```python
# Before
TRACER_NAME = "traceloop.tracer"

# After
TRACER_NAME = "fortifyroot.tracer"
```

**Impact:** This affects the `otel.scope.name` attribute in all traces.

---

### 2. Warning Messages

**File:** `packages/traceloop-sdk/traceloop/sdk/tracing/tracing.py`

```python
# Before
print(
    Fore.RED
    + "Warning: Traceloop not initialized, make sure you call Traceloop.init()"
)

# After
print(
    Fore.RED
    + "Warning: FortifyRoot not initialized, make sure you call fortifyroot.init()"
)
```

---

### 3. Default API Endpoint

**File:** `packages/traceloop-sdk/traceloop/sdk/__init__.py`

```python
# Before
api_endpoint: str = "https://api.traceloop.com",

# After
api_endpoint: str = "https://api.fortifyroot.com",
```

---

### 4. Error Messages

**File:** `packages/traceloop-sdk/traceloop/sdk/__init__.py`

```python
# Before
print(
    Fore.RED
    + "Error: Missing Traceloop API key,"
    + " go to https://app.traceloop.com/settings/api-keys to create one"
)
print("Set the TRACELOOP_API_KEY environment variable to the key")

# After
print(
    Fore.RED
    + "Error: Missing FortifyRoot API key,"
    + " please obtain one from your FortifyRoot dashboard"
)
print("Set the FORTIFYROOT_API_KEY environment variable to the key")
```

---

### 5. Status Messages

**File:** `packages/traceloop-sdk/traceloop/sdk/__init__.py`

```python
# Before
print(Fore.YELLOW + "Traceloop instrumentation is disabled via init flag")
print(Fore.GREEN + "Traceloop exporting traces to a custom exporter")
print(Fore.GREEN + f"Traceloop exporting traces to {api_endpoint}")

# After
print(Fore.YELLOW + "FortifyRoot instrumentation is disabled via init flag")
print(Fore.GREEN + "FortifyRoot exporting traces to a custom exporter")
print(Fore.GREEN + f"FortifyRoot exporting traces to {api_endpoint}")
```

---

### 6. Cache Directory

**File:** `packages/traceloop-sdk/traceloop/sdk/__init__.py`

**Lines ~37-40:**
```python
# Before
AUTO_CREATED_KEY_PATH = str(Path.home() / ".cache" / "traceloop" / "auto_created_key")
AUTO_CREATED_URL = str(Path.home() / ".cache" / "traceloop" / "auto_created_url")

# After
AUTO_CREATED_KEY_PATH = str(Path.home() / ".cache" / "fortifyroot" / "auto_created_key")
AUTO_CREATED_URL = str(Path.home() / ".cache" / "fortifyroot" / "auto_created_url")
```

---

## Changes NOT Required

The following do NOT need to be changed because they are handled dynamically:

### Environment Variables
- `TRACELOOP_API_KEY` - Mapped via `_internal/env_mapping.py`
- `TRACELOOP_BASE_URL` - Mapped via `_internal/env_mapping.py`
- `TRACELOOP_TRACE_CONTENT` - Mapped via `_internal/env_mapping.py`

### Import Paths
- `from traceloop.sdk import X` - Rewritten by vendor script
- Module names - Rewritten by vendor script

### Class Names
- `Traceloop` class - Wrapped by `fortifyroot.core.init()`
- Internal classes - Not user-facing

---

## Verification Script [IMPORTANT]

After making changes, run this in the fork to find any remaining "traceloop" references
(case-insensitive) that might leak to users - inspect each finding carefully (not everything requires rebranding though e.g. Traceloop Client side of things):

```bash
# Find remaining user-facing traceloop references
grep -rni "traceloop" packages/traceloop-sdk/traceloop/sdk/ \
    --include="*.py" \
    | grep -v "__pycache__" \
    | grep -vE "(from traceloop|import traceloop)" \
    | grep -iE "(print|logging|logger|error|warning|tracer_name|endpoint|api)"
```

---

## Commit Template

When committing branding changes to the fork:

```bash
git commit -m "FR: Rebrand Traceloop to FortifyRoot

Changes:
- TRACER_NAME: traceloop.tracer -> fortifyroot.tracer
- Default endpoint: api.traceloop.com -> api.fortifyroot.com
- Warning/error messages updated
```

---

## Testing Branding Changes

After rebranding and vendoring, verify:

1. **Traces**: Check Jaeger/OTLP collector for `otel.scope.name: fortifyroot.tracer`
2. **Logs**: Run with `FORTIFYROOT_API_KEY` missing and verify error message
3. **Startup**: Run `init()` and check console output for "FortifyRoot" branding
4. **Tests**: Run `pytest tests/` in FR SDK to verify no leakage

```bash
# Quick check in FR SDK
python -c "
import fortifyroot
# Should print 'FortifyRoot' messages, not 'Traceloop'
fortifyroot.init(app_name='test', api_endpoint='http://localhost:4318')
"
```
