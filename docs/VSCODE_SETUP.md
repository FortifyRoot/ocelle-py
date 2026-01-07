# VSCode Setup for FortifyRoot SDK

## Why You See Import Errors (Red Squiggles)

If you see import errors in VSCode even after running `pip install -e .`, the issue is almost certainly:

**VSCode is using a different Python interpreter than your virtual environment.**

## How to Fix

### Step 1: Check Your Python Interpreter

Look at the bottom-right of VSCode. If it shows something like "Python 3.12.12 (homebrew)" instead of your venv, that's the problem.

### Step 2: Select the Correct Interpreter

1. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
2. Type "Python: Select Interpreter"
3. Choose the interpreter from your `.venv` folder:
   - It should look like: `.venv/bin/python` or `./venv/bin/python`
   - Or: `Python 3.10.x ('.venv': venv)`

### Step 3: Reload Window

After selecting the interpreter:
1. Press `Cmd+Shift+P` / `Ctrl+Shift+P`
2. Type "Developer: Reload Window"
3. Press Enter

## Verifying the Fix

After selecting the correct interpreter, most import errors should disappear. 

To verify everything works at runtime:

```bash
# Make sure you're in the venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Run the import test
python scripts/test_imports.py
```

## Expected Remaining Warnings

Some warnings may remain even after fixing the interpreter:

### 1. `opentelemetry.semconv._incubating.attributes`

This is an **internal/experimental** module in OpenTelemetry. Pylance may not recognize it because:
- It starts with `_` (private module)
- It's part of incubating/experimental APIs

**This is safe to ignore** - the code works at runtime.

### 2. Warnings in `_vendor/` Directory

The vendored code may show some Pylance warnings. These are **intentionally suppressed** in the VSCode settings (`.vscode/settings.json`), but some may still appear.

**This is safe to ignore** - vendored code is tested separately.

## VSCode Settings Included

This project includes `.vscode/settings.json` with:

```json
{
    "python.analysis.extraPaths": ["${workspaceFolder}/src"],
    "python.analysis.exclude": ["**/src/fortifyroot/_vendor/**"],
    "python.analysis.ignore": ["**/src/fortifyroot/_vendor/**"],
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python"
}
```

These settings:
- Tell Pylance where to find our source code
- Exclude vendored code from analysis
- Set the default interpreter to the venv

## Still Having Issues?

1. **Clear Pylance cache**: 
   - Delete the `.vscode/.ropeproject` folder if it exists
   - Press `Cmd+Shift+P` → "Python: Clear Cache and Reload Window"

2. **Reinstall packages**:
   ```bash
   pip uninstall fortifyroot-sdk -y
   pip install -e .
   ```

3. **Check pip list**:
   ```bash
   pip list | grep -E "opentelemetry|pydantic|wrapt"
   ```
   
   You should see packages like:
   - opentelemetry-api (1.39.x)
   - opentelemetry-sdk (1.39.x)
   - opentelemetry-instrumentation (0.60bx)
   - pydantic (2.x)
   - wrapt (1.x)

4. **Run the test script**:
   ```bash
   python scripts/test_imports.py
   ```
   
   If this passes but VSCode still shows errors, it's purely a Pylance/VSCode issue.
