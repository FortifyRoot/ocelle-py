#!/usr/bin/env python3
"""
Script to extract OpenTelemetry dependencies from OpenLLMetry packages.

This helps when bumping OpenLLMetry versions - it shows what dependencies
need to be listed in FR SDK's pyproject.toml.

Usage:
    python scripts/extract_otel_deps.py /path/to/openllmetry

Output:
    Lists all OpenTelemetry dependencies used by traceloop-sdk and instrumentation packages.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Set


def extract_deps_from_pyproject(pyproject_path: Path) -> Set[str]:
    """Extract dependencies from a pyproject.toml file."""
    deps = set()
    
    if not pyproject_path.exists():
        return deps
    
    content = pyproject_path.read_text()
    
    # Match opentelemetry-* packages
    otel_pattern = re.compile(r'(opentelemetry-[a-zA-Z0-9-]+)')
    deps.update(otel_pattern.findall(content))
    
    # Match other common dependencies
    other_patterns = [
        r'(wrapt)',
        r'(pydantic)',
        r'(colorama)',
        r'(tenacity)',
        r'(jinja2)',
        r'(deprecated)',
        r'(aiohttp)',
        r'(cuid)',
    ]
    
    for pattern in other_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        deps.update(m.lower() for m in matches)
    
    return deps


def main():
    parser = argparse.ArgumentParser(description='Extract OTel dependencies from OpenLLMetry')
    parser.add_argument('ol_repo', type=Path, help='Path to OpenLLMetry repository')
    args = parser.parse_args()
    
    ol_repo = args.ol_repo
    if not ol_repo.exists():
        print(f"ERROR: OpenLLMetry repo not found: {ol_repo}")
        sys.exit(1)
    
    all_deps = set()
    
    # Check traceloop-sdk
    traceloop_pyproject = ol_repo / 'packages' / 'traceloop-sdk' / 'pyproject.toml'
    if traceloop_pyproject.exists():
        print(f"Checking: {traceloop_pyproject}")
        deps = extract_deps_from_pyproject(traceloop_pyproject)
        all_deps.update(deps)
    
    # Check all instrumentation packages
    packages_dir = ol_repo / 'packages'
    for pkg_dir in packages_dir.iterdir():
        if pkg_dir.name.startswith('opentelemetry-instrumentation-'):
            pyproject = pkg_dir / 'pyproject.toml'
            if pyproject.exists():
                deps = extract_deps_from_pyproject(pyproject)
                all_deps.update(deps)
    
    print("\n=== Dependencies Found ===\n")
    
    # Categorize
    otel_core = sorted([d for d in all_deps if d.startswith('opentelemetry-') and 'instrumentation' not in d])
    otel_instr = sorted([d for d in all_deps if 'instrumentation' in d])
    other = sorted([d for d in all_deps if not d.startswith('opentelemetry-')])
    
    print("Core OpenTelemetry:")
    for d in otel_core:
        print(f"  - {d}")
    
    print("\nOpenTelemetry Instrumentation:")
    for d in otel_instr:
        print(f"  - {d}")
    
    print("\nOther Dependencies:")
    for d in other:
        print(f"  - {d}")


if __name__ == '__main__':
    main()
