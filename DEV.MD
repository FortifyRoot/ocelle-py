# FortifyRoot Ocelle SDK – Developer Guide (DEV.md)

This document is intended for FortifyRoot maintainers and contributors.
It describes how to set up a local development environment, manage the
FortifyRoot fork of OpenLLMetry (Traceloop), vendor OpenLLMetry into the
FortifyRoot Ocelle SDK, and work effectively with Poetry and VS Code.

This file is internal-facing and intentionally separate from README.md.

---

## 1. Local Development Environment Setup (macOS)

### 1.1 Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

### 1.2 Install and Configure pyenv

```bash
brew install pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc
source ~/.zshrc
```

Install and select Python 3.10:

```bash
pyenv install 3.10.19
pyenv local 3.10.19
```

---

### 1.3 Install Poetry

```bash
curl -sSL https://install.python-poetry.org | python3 -
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

---

## 2. Workspace Layout

```bash
cd <workspace-root>
```

Typical layout:

```
<workspace-root>/
├── fr-openllmetry-py/
└── ocelle-py/
```

---

## 3. FortifyRoot Fork of OpenLLMetry (fr-openllmetry-py)

### 3.1 Clone the Fork and Set Up Upstream

```bash
git clone git@github.com:FortifyRoot/openllmetry-py.git fr-openllmetry-py
cd fr-openllmetry-py
git remote add upstream https://github.com/traceloop/openllmetry.git
git fetch upstream --tags
git remote -v
```

---

### 3.2 Example Fork Workflow

```bash
cd fr-openllmetry-py
git fetch upstream --tags
git checkout tags/v0.50.1
git checkout -b fr-v0.50.1.x

# Make FR modifications...
git commit -m "FR: Rebrand tracer and logging"
git push -u origin fr-v0.50.1.x
git tag fr-v0.50.1.0
git push origin fr-v0.50.1.0

# Later, if bug fix is needed (still v0.50.1 of OpenLLMetry)
git checkout fr-v0.50.1.x
git commit -m "FR: Fix callback invocation order"
git push
git tag fr-v0.50.1.1
git push origin fr-v0.50.1.1

# Upgrading to v0.50.2
git fetch upstream --tags
git checkout tags/v0.50.2
git checkout -b fr-v0.50.2.x
git cherry-pick <commits-from-fr-v0.50.1.x>
git push -u origin fr-v0.50.2.x
git tag fr-v0.50.2.0
git push origin fr-v0.50.2.0
```

---

## 4. FortifyRoot Ocelle SDK Setup

```bash
git clone https://github.com/FortifyRoot/ocelle-py
cd ocelle-py
deactivate || true
rm -rf .venv
poetry config virtualenvs.in-project true
poetry install
source ./.venv/bin/activate
```

---

## 5. Running Tests

```bash
pytest
pytest tests/test_vendored_imports.py
pytest tests/test_vendored_imports.py::TestVendoredImports::test_traceloop_sdk_import
```

Without activating venv:

```bash
poetry run pytest
```

---

## 6. Dependency Management

```bash
poetry add httpx
poetry add --group dev pytest-httpx
poetry env info
```

---

## 7. Vendoring OpenLLMetry into the SDK

```bash
Usage: vendor.sh <path to fork> <path to fortifyroot SDK> <tag of fork>
```
Example:

```bash
./scripts/vendor.sh ../fr-openllmetry-py . fr-v0.50.1.1
```

---

## 8. VS Code Setup

Enable code command:

- Cmd + Shift + P
- Shell Command: Install 'code' command in PATH
- Restart terminal

Open project:

```bash
cd ocelle-py
code .
```

Select interpreter:

- Cmd + Shift + P → Python: Select Interpreter
- Choose ./.venv/bin/python

Recommended extensions (the Microsoft ones):

- Python
- Python Debugger
- Pylance
- Python Environments
