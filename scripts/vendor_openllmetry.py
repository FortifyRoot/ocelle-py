#!/usr/bin/env python3
"""
OpenLLMetry Vendoring Script for FortifyRoot SDK

This script vendors a forked OpenLLMetry repository into the FortifyRoot SDK,
rewriting imports to work under the _vendor namespace.

Usage:
    python scripts/vendor_openllmetry.py --ol-repo /path/to/fr-openllmetry-py

The script will:
1. Copy traceloop-sdk and all instrumentation packages to _vendor/
2. Rewrite imports to use fortifyroot._vendor.* prefix where appropriate
3. Generate a manifest file for tracking vendored versions

IMPORTANT: Only OpenLLMetry-specific packages are vendored. External OpenTelemetry
packages (opentelemetry-api, opentelemetry-sdk, etc.) are NOT vendored and must
be listed as dependencies in pyproject.toml.
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Optional, List, Tuple
import json
from datetime import datetime


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
# (handles cases like google-generativeai -> google_generativeai)
PKG_DIR_TO_MODULE = {
    "google-generativeai": "google_generativeai",
    "openai-agents": "openai_agents",
}

# Import patterns that need rewriting
# Format: (regex_pattern, replacement_template)
# The replacement uses {vendor_prefix} placeholder


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
    # Build a pattern for all OL instrumentation packages
    ol_packages_pattern = '|'.join(sorted(OL_INSTRUMENTATION_PACKAGES))
    rules.append((
        re.compile(rf'^(\s*)(from|import)\s+opentelemetry\.instrumentation\.({ol_packages_pattern})'),
        rf'\1\2 {vendor_prefix}.opentelemetry.instrumentation.\3'
    ))
    
    return rules


def rewrite_imports_in_file(filepath: Path, rules: List[Tuple[re.Pattern, str]]) -> bool:
    """
    Rewrite imports in a single Python file.
    
    Returns True if any changes were made.
    """
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
            # Skip __pycache__, .pyc, tests, etc.
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
        # Use pkgutil-style namespace package for compatibility
        init_file.write_text(
            '# Namespace package - see PEP 420\n'
            '# This file intentionally left minimal for namespace package support\n'
            '__path__ = __import__("pkgutil").extend_path(__path__, __name__)\n'
        )


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
    
    # Create root _vendor __init__.py
    vendor_init = vendor_root / '__init__.py'
    vendor_init.write_text(
        '"""Vendored dependencies for FortifyRoot SDK."""\n'
        '# This package contains vendored copies of OpenLLMetry components.\n'
        '# Do not modify these files directly - they are generated by vendor_openllmetry.py\n'
    )
    
    # Create opentelemetry namespace package
    otel_dir = vendor_root / 'opentelemetry'
    if otel_dir.exists():
        create_namespace_init(otel_dir)
        
        # Create instrumentation namespace
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
            print(f"    Modified: {py_file.relative_to(vendor_root)}")
    
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
        pass  # git not available
    
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
        "source_repo": str(ol_repo),
        "packages": {
            "traceloop-sdk": version,
            "opentelemetry-semantic-conventions-ai": version,
            **{f"opentelemetry-instrumentation-{p}": version for p in vendored_packages}
        }
    }
    
    manifest_file = vendor_root / 'VENDOR_MANIFEST.json'
    manifest_file.write_text(json.dumps(manifest, indent=2))
    
    # Also write a simple version file
    version_file = vendor_root.parent / 'OPENLLMETRY_VERSION'
    version_file.write_text(
        f"# Vendored OpenLLMetry Version\n"
        f"VERSION={version}\n"
        f"COMMIT={git_info['commit']}\n"
        f"BRANCH={git_info['branch']}\n"
        f"TAG={git_info['tag']}\n"
        f"VENDORED_AT={datetime.now().isoformat()}\n"
    )
    
    print(f"    Manifest written to: {manifest_file}")
    print(f"    Version file written to: {version_file}")


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
        default=None,
        help='Path to FortifyRoot SDK (default: auto-detect from script location)'
    )
    parser.add_argument(
        '--vendor-prefix',
        default='fortifyroot._vendor',
        help='Import prefix for vendored packages (default: fortifyroot._vendor)'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean vendor directory before vendoring'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    ol_repo = args.ol_repo.resolve()
    
    if args.fr_sdk:
        fr_sdk = args.fr_sdk.resolve()
    else:
        # Auto-detect: assume script is in scripts/ or scripts/
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
        print(f"ERROR: Invalid OpenLLMetry repo (no packages/ dir): {ol_repo}")
        sys.exit(1)
    
    if not (fr_sdk / 'src' / 'fortifyroot').exists():
        print(f"ERROR: FortifyRoot SDK not found: {fr_sdk}")
        sys.exit(1)
    
    print(f"OpenLLMetry repo: {ol_repo}")
    print(f"FortifyRoot SDK: {fr_sdk}")
    print(f"Vendor directory: {vendor_root}")
    print(f"Vendor prefix: {args.vendor_prefix}")
    print()
    
    if args.dry_run:
        print("=== DRY RUN MODE ===")
        print("Would perform the following actions:")
        print(f"  1. Clean {vendor_root}" if args.clean else "  1. (Skip clean)")
        print(f"  2. Copy traceloop-sdk to {vendor_root / 'traceloop'}")
        print(f"  3. Copy instrumentation packages to {vendor_root / 'opentelemetry' / 'instrumentation'}")
        print(f"  4. Copy semconv_ai to {vendor_root / 'opentelemetry' / 'semconv_ai'}")
        print(f"  5. Rewrite imports with prefix: {args.vendor_prefix}")
        print(f"  6. Write manifest files")
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
    
    # Write manifest
    write_manifest(vendor_root, ol_repo, vendored_packages)
    
    print()
    print("==> Vendoring complete!")
    print()
    print("Next steps:")
    print("  1. Review the changes in src/fortifyroot/_vendor/")
    print("  2. Run tests to verify imports work correctly")
    print("  3. Commit the vendored files")


if __name__ == '__main__':
    main()
