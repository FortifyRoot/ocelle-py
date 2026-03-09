#!/usr/bin/env python3
"""
OpenLLMetry Vendoring Script for FortifyRoot SDK

This script vendors a forked OpenLLMetry repository into the FortifyRoot SDK,
rewriting imports to work under the fortifyroot._vendor namespace.

Usage:
    python scripts/vendor_openllmetry.py --ol-repo /path/to/fr-openllmetry-py

The script will:
1. Copy traceloop-sdk and OpenLLMetry instrumentation packages into _vendor/
2. Rewrite import paths for namespace isolation (mechanical, non-functional)
3. Extract and mirror required runtime dependencies
4. Generate a manifest file for tracking vendored OpenLLMetry versions

IMPORTANT:
- Import rewrites performed by this script are mechanical and packaging-related.
- Substantive source modifications, if any, are made only in the OpenLLMetry fork
  (fr-openllmetry) and are marked at the file level there, in accordance with
  the Apache License, Version 2.0.
- CNCF OpenTelemetry core packages (opentelemetry-api, opentelemetry-sdk, exporters)
  are NOT vendored and must be declared as dependencies in pyproject.toml.
"""


import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Optional, List, Tuple, Dict
import json
from datetime import datetime

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[import-not-found]


# OpenLLMetry instrumentation packages (these will be vendored)
OL_INSTRUMENTATION_PACKAGES = {
    "agno", "alephalpha", "anthropic", "bedrock", "chromadb", "cohere",
    "crewai", "google_generativeai", "groq", "haystack", "lancedb",
    "langchain", "llamaindex", "marqo", "mcp", "milvus", "mistralai",
    "ollama", "openai", "openai_agents", "pinecone", "qdrant", "replicate",
    "sagemaker", "together", "transformers", "vertexai", "watsonx",
    "weaviate", "writer"
}

# Package directory name to Python module name mapping
PKG_DIR_TO_MODULE = {
    "google-generativeai": "google_generativeai",
    "openai-agents": "openai_agents",
}

# Dependencies that should NOT be added (they are vendored or internal)
SKIP_DEPS = {
    "traceloop-sdk",
    "opentelemetry-semantic-conventions-ai",
    "python",
}

# Add prefix for all OL instrumentation packages
for pkg in OL_INSTRUMENTATION_PACKAGES:
    SKIP_DEPS.add(f"opentelemetry-instrumentation-{pkg}")
    SKIP_DEPS.add(f"opentelemetry-instrumentation-{pkg.replace('_', '-')}")


def get_import_rewrite_rules(vendor_prefix: str) -> List[Tuple[re.Pattern, str]]:
    """Generate import rewrite rules based on vendor prefix."""

    rules = []

    # Rule 1: Rewrite traceloop imports
    rules.append((
        re.compile(r'^(\s*)(from|import)\s+traceloop\.'),
        rf'\1\2 {vendor_prefix}.traceloop.'
    ))

    # Rule 2: Rewrite opentelemetry.semconv_ai imports (OL package)
    rules.append((
        re.compile(r'^(\s*)(from|import)\s+opentelemetry\.semconv_ai'),
        rf'\1\2 {vendor_prefix}.opentelemetry.semconv_ai'
    ))

    # Rule 3: Rewrite OpenLLMetry instrumentation imports
    ol_packages_pattern = '|'.join(sorted(OL_INSTRUMENTATION_PACKAGES))
    rules.append((
        re.compile(rf'^(\s*)(from|import)\s+opentelemetry\.instrumentation\.({ol_packages_pattern})'),
        rf'\1\2 {vendor_prefix}.opentelemetry.instrumentation.\3'
    ))

    return rules


def rewrite_imports_in_file(filepath: Path, rules: List[Tuple[re.Pattern, str]]) -> bool:
    """Rewrite imports in a single Python file. Returns True if changes were made."""
    try:
        content = filepath.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        print(f"  Warning: Skipping non-UTF8 file: {filepath}")
        return False

    original_content = content
    lines = content.split('\n')
    modified_lines = []

    for line in lines:
        modified_line = line
        for pattern, replacement in rules:
            modified_line = pattern.sub(replacement, modified_line)
        modified_lines.append(modified_line)

    new_content = '\n'.join(modified_lines)

    if new_content != original_content:
        filepath.write_text(new_content, encoding='utf-8')
        return True
    return False


def copy_package(src: Path, dest: Path, exclude_patterns: Optional[List[str]] = None) -> None:
    """Copy a package directory, excluding specified patterns."""
    exclude_patterns = exclude_patterns or []

    if dest.exists():
        shutil.rmtree(dest)

    def ignore_patterns(directory, files):
        ignored = set()
        for f in files:
            full_path = os.path.join(directory, f)
            if f == '__pycache__' or f.endswith('.pyc'):
                ignored.add(f)
            elif f == 'tests' and os.path.isdir(full_path):
                ignored.add(f)
            elif any(re.match(p, f) for p in exclude_patterns):
                ignored.add(f)
        return ignored

    shutil.copytree(src, dest, ignore=ignore_patterns)


def create_namespace_init(path: Path) -> None:
    """Create a namespace package __init__.py file."""
    init_file = path / '__init__.py'
    if not init_file.exists():
        init_file.write_text(
            '# Namespace package - see PEP 420\n'
            '__path__ = __import__("pkgutil").extend_path(__path__, __name__)\n'
        )


def parse_poetry_deps(pyproject_path: Path) -> Dict[str, Dict]:
    """
    Parse dependencies from pyproject.toml.

    Supports both legacy Poetry tables and modern PEP621/PEP735 layout:
    - [tool.poetry.dependencies], [tool.poetry.group.*.dependencies]
    - [project].dependencies, [dependency-groups]

    Returns dict with keys: 'main', 'dev', 'test'
    Each value is a dict of {package_name: version_spec}
    """
    deps = {'main': {}, 'dev': {}, 'test': {}}

    if not pyproject_path.exists():
        return deps

    content = pyproject_path.read_text(encoding='utf-8')

    try:
        parsed = tomllib.loads(content)
    except Exception:
        return _parse_deps_legacy_regex(content)

    project = parsed.get('project', {})
    if isinstance(project, dict):
        deps['main'].update(_parse_dependency_list(project.get('dependencies', [])))

    dependency_groups = parsed.get('dependency-groups', {})
    if isinstance(dependency_groups, dict):
        deps['dev'].update(_parse_dependency_list(dependency_groups.get('dev', [])))
        deps['test'].update(_parse_dependency_list(dependency_groups.get('test', [])))

    tool = parsed.get('tool', {})
    if isinstance(tool, dict):
        poetry = tool.get('poetry', {})
        if isinstance(poetry, dict):
            deps['main'].update(_parse_poetry_dep_table(poetry.get('dependencies', {})))
            groups = poetry.get('group', {})
            if isinstance(groups, dict):
                dev_group = groups.get('dev', {})
                if isinstance(dev_group, dict):
                    deps['dev'].update(_parse_poetry_dep_table(dev_group.get('dependencies', {})))
                test_group = groups.get('test', {})
                if isinstance(test_group, dict):
                    deps['test'].update(_parse_poetry_dep_table(test_group.get('dependencies', {})))

    return deps


def _parse_poetry_dep_table(dep_table: Any) -> Dict[str, str]:
    """Parse [tool.poetry.*.dependencies] mapping format."""
    deps = {}
    if not isinstance(dep_table, dict):
        return deps

    for pkg, spec in dep_table.items():
        pkg_name = str(pkg).lower()

        if isinstance(spec, str):
            deps[pkg_name] = spec
            continue

        if isinstance(spec, dict):
            # Skip path-based local deps.
            if 'path' in spec:
                continue
            version = spec.get('version')
            if isinstance(version, str):
                deps[pkg_name] = version
                continue

    return deps


def _parse_dependency_list(dep_entries: Any) -> Dict[str, str]:
    """Parse [project].dependencies or [dependency-groups].<group> list format."""
    deps = {}
    if not isinstance(dep_entries, list):
        return deps

    for entry in dep_entries:
        if isinstance(entry, str):
            parsed = _parse_pep508_dependency(entry)
            if parsed:
                pkg_name, version = parsed
                deps[pkg_name] = version
            continue

        # PEP735 allows table entries like { include-group = "dev" }.
        if isinstance(entry, dict) and 'include-group' in entry:
            continue

    return deps


def _parse_pep508_dependency(dep: str) -> Optional[Tuple[str, str]]:
    """Extract package name + spec from a PEP508 dependency string."""
    raw = dep.strip()
    if not raw:
        return None

    match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', raw)
    if not match:
        return None

    pkg_name = match.group(1).lower()
    remainder = raw[match.end():].strip()

    # Drop extras when present, keep only version/direct-reference segment.
    if remainder.startswith('['):
        closing = remainder.find(']')
        if closing != -1:
            remainder = remainder[closing + 1:].strip()

    # Drop environment markers for dependency manifest readability.
    if ';' in remainder:
        remainder = remainder.split(';', 1)[0].strip()

    return pkg_name, remainder or "*"


def _parse_deps_legacy_regex(content: str) -> Dict[str, Dict[str, str]]:
    """Fallback parser for older Poetry-only pyproject.toml files."""
    deps: Dict[str, Dict[str, str]] = {'main': {}, 'dev': {}, 'test': {}}

    main_match = re.search(
        r'\[tool\.poetry\.dependencies\](.*?)(?=\[tool\.|$)',
        content, re.DOTALL
    )
    if main_match:
        deps['main'] = _parse_legacy_dep_section(main_match.group(1))

    dev_match = re.search(
        r'\[tool\.poetry\.group\.dev\.dependencies\](.*?)(?=\[tool\.|$)',
        content, re.DOTALL
    )
    if dev_match:
        deps['dev'] = _parse_legacy_dep_section(dev_match.group(1))

    test_match = re.search(
        r'\[tool\.poetry\.group\.test\.dependencies\](.*?)(?=\[tool\.|$)',
        content, re.DOTALL
    )
    if test_match:
        deps['test'] = _parse_legacy_dep_section(test_match.group(1))

    return deps


def _parse_legacy_dep_section(section: str) -> Dict[str, str]:
    """Parse a legacy Poetry dependency section with regexes."""
    deps: Dict[str, str] = {}

    for line in section.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('['):
            continue

        # Skip path dependencies (local packages)
        if 'path =' in line:
            continue

        # Parse simple deps: package = "version" or package = "^version"
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
        if match:
            pkg, version = match.groups()
            deps[pkg.lower()] = version
            continue

        # Parse complex deps: package = { version = "x", ... }
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"', line)
        if match:
            pkg, version = match.groups()
            deps[pkg.lower()] = version

    return deps


def extract_all_deps(ol_repo: Path) -> Dict[str, Dict[str, str]]:
    """
    Extract all dependencies from all vendored packages.

    Returns merged dependencies for main, dev, and test.
    """
    all_deps = {'main': {}, 'dev': {}, 'test': {}}
    packages_dir = ol_repo / 'packages'

    # List of packages to scan
    packages_to_scan = ['traceloop-sdk', 'opentelemetry-semantic-conventions-ai']
    packages_to_scan.extend(
        f"opentelemetry-instrumentation-{pkg.replace('_', '-')}"
        for pkg in OL_INSTRUMENTATION_PACKAGES
    )

    for pkg_name in packages_to_scan:
        pyproject = packages_dir / pkg_name / 'pyproject.toml'
        if not pyproject.exists():
            continue

        pkg_deps = parse_poetry_deps(pyproject)

        for dep_type in ['main', 'dev', 'test']:
            for pkg, version in pkg_deps[dep_type].items():
                # Skip vendored/internal packages
                if pkg in SKIP_DEPS or pkg.lower() in SKIP_DEPS:
                    continue

                # Merge: keep most restrictive version (simplistic approach)
                if pkg not in all_deps[dep_type]:
                    all_deps[dep_type][pkg] = version
                # Could add more sophisticated version merging here

    return all_deps


def write_deps_manifest(vendor_root: Path, deps: Dict[str, Dict[str, str]]) -> None:
    """Write extracted dependencies to a manifest file."""
    manifest_file = vendor_root / 'VENDOR_DEPENDENCIES.json'
    manifest_file.write_text(json.dumps(deps, indent=2, sort_keys=True))
    print(f"    Dependencies manifest written to: {manifest_file}")


def vendor_traceloop_sdk(ol_repo: Path, vendor_root: Path) -> None:
    """Vendor the traceloop-sdk package."""
    print("==> Vendoring traceloop-sdk")

    src = ol_repo / 'packages' / 'traceloop-sdk' / 'traceloop'
    dest = vendor_root / 'traceloop'

    if not src.exists():
        raise FileNotFoundError(f"traceloop-sdk not found at {src}")

    copy_package(src, dest)
    print(f"    Copied: {src} -> {dest}")


def vendor_instrumentation_packages(ol_repo: Path, vendor_root: Path) -> List[str]:
    """Vendor all OpenLLMetry instrumentation packages."""
    print("==> Vendoring OpenTelemetry instrumentation packages")

    vendored = []
    otel_dest = vendor_root / 'opentelemetry' / 'instrumentation'
    otel_dest.mkdir(parents=True, exist_ok=True)

    packages_dir = ol_repo / 'packages'

    for pkg_dir in sorted(packages_dir.iterdir()):
        if not pkg_dir.name.startswith('opentelemetry-instrumentation-'):
            continue

        pkg_name = pkg_dir.name.replace('opentelemetry-instrumentation-', '')
        module_name = PKG_DIR_TO_MODULE.get(pkg_name, pkg_name.replace('-', '_'))

        if module_name not in OL_INSTRUMENTATION_PACKAGES:
            print(f"    Skipping unknown package: {pkg_name}")
            continue

        src = pkg_dir / 'opentelemetry' / 'instrumentation' / module_name
        if not src.exists():
            print(f"    Warning: Source not found: {src}")
            continue

        dest = otel_dest / module_name
        copy_package(src, dest)
        vendored.append(pkg_name)
        print(f"    Vendored: {pkg_name}")

    return vendored


def vendor_semconv_ai(ol_repo: Path, vendor_root: Path) -> None:
    """Vendor the semantic conventions AI package."""
    print("==> Vendoring opentelemetry-semantic-conventions-ai")

    src = ol_repo / 'packages' / 'opentelemetry-semantic-conventions-ai' / 'opentelemetry' / 'semconv_ai'
    dest = vendor_root / 'opentelemetry' / 'semconv_ai'

    if not src.exists():
        print(f"    Warning: semconv_ai not found at {src}")
        return

    copy_package(src, dest)
    print(f"    Copied: {src} -> {dest}")


def create_vendor_init_files(vendor_root: Path) -> None:
    """Create necessary __init__.py files for the vendor namespace."""
    print("==> Creating namespace __init__.py files")

    vendor_init = vendor_root / '__init__.py'
    vendor_init.write_text(
        '"""Vendored dependencies for FortifyRoot SDK."""\n'
        '# This package contains vendored copies of OpenLLMetry components.\n'
        '# Do not modify these files directly - they are generated by vendor_openllmetry.py\n'
    )

    otel_dir = vendor_root / 'opentelemetry'
    if otel_dir.exists():
        create_namespace_init(otel_dir)

        instr_dir = otel_dir / 'instrumentation'
        if instr_dir.exists():
            create_namespace_init(instr_dir)


def rewrite_all_imports(vendor_root: Path, vendor_prefix: str) -> int:
    """Rewrite imports in all vendored Python files."""
    print("==> Rewriting imports")

    rules = get_import_rewrite_rules(vendor_prefix)
    modified_count = 0

    for py_file in vendor_root.rglob('*.py'):
        if rewrite_imports_in_file(py_file, rules):
            modified_count += 1

    print(f"    Total files modified: {modified_count}")
    return modified_count


def get_ol_version(ol_repo: Path) -> str:
    """Extract version from OpenLLMetry repository."""
    pyproject = ol_repo / 'packages' / 'traceloop-sdk' / 'pyproject.toml'
    if pyproject.exists():
        content = pyproject.read_text()
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        if match:
            return match.group(1)
    return "unknown"


def get_git_info(ol_repo: Path) -> dict:
    """Get git commit info from OpenLLMetry repository."""
    import subprocess

    info = {"commit": "unknown", "branch": "unknown", "tag": "unknown"}

    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=ol_repo, capture_output=True, text=True
        )
        if result.returncode == 0:
            info["commit"] = result.stdout.strip()[:12]

        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=ol_repo, capture_output=True, text=True
        )
        if result.returncode == 0:
            info["branch"] = result.stdout.strip()

        result = subprocess.run(
            ['git', 'describe', '--tags', '--exact-match'],
            cwd=ol_repo, capture_output=True, text=True
        )
        if result.returncode == 0:
            info["tag"] = result.stdout.strip()
    except FileNotFoundError:
        pass

    return info


def write_manifest(vendor_root: Path, ol_repo: Path, vendored_packages: List[str]) -> None:
    """Write a manifest file documenting what was vendored."""
    print("==> Writing manifest")

    version = get_ol_version(ol_repo)
    git_info = get_git_info(ol_repo)

    manifest = {
        "vendored_at": datetime.now().isoformat(),
        "openllmetry_version": version,
        "git_commit": git_info["commit"],
        "git_branch": git_info["branch"],
        "git_tag": git_info["tag"],
        "packages": {
            "traceloop-sdk": version,
            "opentelemetry-semantic-conventions-ai": version,
            **{f"opentelemetry-instrumentation-{p}": version for p in vendored_packages}
        }
    }

    manifest_file = vendor_root / 'VENDOR_MANIFEST.json'
    manifest_file.write_text(json.dumps(manifest, indent=2))

    print(f"    Manifest: {manifest_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Vendor OpenLLMetry into FortifyRoot SDK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--ol-repo',
        type=Path,
        required=True,
        help='Path to the forked OpenLLMetry repository'
    )
    parser.add_argument(
        '--fr-sdk',
        type=Path,
        required=True,
        help='Path to FortifyRoot SDK'
    )
    parser.add_argument(
        '--vendor-prefix',
        default='fortifyroot._vendor',
        help='Import prefix for vendored packages'
    )
    parser.add_argument(
        '--tag',
        type=str,
        default=None,
        help='Git tag to checkout in OpenLLMetry repo before vendoring'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean vendor directory before vendoring'
    )
    parser.add_argument(
        '--extract-deps',
        action='store_true',
        default=True,
        help='Extract and output dependencies from vendored packages'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )

    args = parser.parse_args()

    ol_repo = args.ol_repo.resolve()

    if args.fr_sdk:
        fr_sdk = args.fr_sdk.resolve()
    else:
        script_dir = Path(__file__).resolve().parent
        fr_sdk = script_dir.parent
        if not (fr_sdk / 'src' / 'fortifyroot').exists():
            fr_sdk = script_dir.parent.parent

    vendor_root = fr_sdk / 'src' / 'fortifyroot' / '_vendor'

    # Validate paths
    if not ol_repo.exists():
        print(f"ERROR: OpenLLMetry repo not found: {ol_repo}")
        sys.exit(1)

    if not (ol_repo / 'packages').exists():
        print(f"ERROR: Invalid OpenLLMetry repo: {ol_repo}")
        sys.exit(1)

    if not (fr_sdk / 'src' / 'fortifyroot').exists():
        print(f"ERROR: FortifyRoot SDK not found: {fr_sdk}")
        sys.exit(1)

    print(f"OpenLLMetry repo: {ol_repo}")
    print(f"FortifyRoot SDK: {fr_sdk}")
    print(f"Vendor directory: {vendor_root}")
    print()

    # Checkout tag if specified
    if args.tag:
        import subprocess
        print(f"==> Checking out tag: {args.tag}")
        result = subprocess.run(
            ['git', 'checkout', 'tags/' + args.tag],
            cwd=ol_repo, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"ERROR: Failed to checkout {args.tag}: {result.stderr}")
            sys.exit(1)
        print(f"    Checked out: {args.tag}")

    if args.dry_run:
        print("=== DRY RUN MODE ===")
        return

    # Clean if requested
    if args.clean and vendor_root.exists():
        print("==> Cleaning vendor directory")
        shutil.rmtree(vendor_root)

    vendor_root.mkdir(parents=True, exist_ok=True)

    # Vendor packages
    vendor_traceloop_sdk(ol_repo, vendor_root)
    vendored_packages = vendor_instrumentation_packages(ol_repo, vendor_root)
    vendor_semconv_ai(ol_repo, vendor_root)

    # Create __init__.py files
    create_vendor_init_files(vendor_root)

    # Rewrite imports
    rewrite_all_imports(vendor_root, args.vendor_prefix)

    # Extract dependencies
    if args.extract_deps:
        print("==> Extracting dependencies")
        deps = extract_all_deps(ol_repo)
        write_deps_manifest(vendor_root, deps)

        print("\n    Main dependencies found:")
        for pkg, ver in sorted(deps['main'].items()):
            print(f"      {pkg} = \"{ver}\"")

    # Write manifest
    write_manifest(vendor_root, ol_repo, vendored_packages)

    print()
    print("==> Vendoring complete!")
    print()
    print("Next steps:")
    print("  1. Review VENDOR_DEPENDENCIES.json for any new dependencies")
    print("  2. Update pyproject.toml if needed")
    print("  3. Run: poetry install && poetry run pytest tests/")
    print("  4. Commit the changes")


if __name__ == '__main__':
    main()
