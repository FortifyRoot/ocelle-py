#!/usr/bin/env bash
#
# Vendor OpenLLMetry into FortifyRoot SDK
#
# Usage:
#   ./scripts/vendor.sh /path/to/fr-openllmetry-py
#
# This is a convenience wrapper around vendor_openllmetry.py
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <openllmetry-repo-path>"
    echo ""
    echo "Example:"
    echo "  $0 /path/to/fr-openllmetry-py"
    exit 1
fi

OL_REPO="$1"

if [[ ! -d "$OL_REPO/packages" ]]; then
    echo "ERROR: Invalid OpenLLMetry repo path: $OL_REPO"
    echo "       Expected to find packages/ directory"
    exit 1
fi

echo "==> Running vendoring script..."
if [[ $# -gt 1 ]]; then
    OL_TAG="$2"
    python3 "$SCRIPT_DIR/vendor_openllmetry.py" \
        --ol-repo "$OL_REPO" \
        --fr-sdk "$PROJECT_ROOT" \
        --tag "$OL_TAG" \
        --clean
else
    python3 "$SCRIPT_DIR/vendor_openllmetry.py" \
        --ol-repo "$OL_REPO" \
        --fr-sdk "$PROJECT_ROOT" \
        --clean
fi

echo ""
echo "==> Vendoring complete!"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff src/fortifyroot/_vendor/"
echo "  2. Run tests: pytest tests/"
echo "  3. Commit: git add . && git commit -m 'Update vendored OpenLLMetry'"
