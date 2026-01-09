#!/usr/bin/env bash
#
# Vendor OpenLLMetry into FortifyRoot SDK
#
# Usage:
#   ./scripts/vendor.sh <path to openllmetry fork> <path to FR SDK> [<git tag of fork>]
#
# This is a convenience wrapper around vendor_openllmetry.py
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <openllmetry-forked-repo-path> <fr-sdk-repo-path>"
    exit 1
fi

OL_REPO="$1"
FR_SDK_REPO="$2"

if [[ ! -d "$OL_REPO/packages" ]]; then
    echo "ERROR: Invalid OpenLLMetry repo path: $OL_REPO"
    echo "       Expected to find packages/ directory"
    exit 1
fi

if [[ ! -d "$FR_SDK_REPO/src/fortifyroot" ]]; then
    echo "ERROR: Invalid FortifyRoot SDK repo path: $FR_SDK_REPO"
    echo "       Expected to find src/fortifyroot/ directory"
    exit 1
fi

echo "==> Running vendoring script..."
if [[ $# -gt 2 ]]; then
    OL_TAG="$3"
    python3 "$SCRIPT_DIR/vendor_openllmetry.py" \
        --ol-repo "$OL_REPO" \
        --fr-sdk "$FR_SDK_REPO" \
        --tag "$OL_TAG" \
        --clean
else
    python3 "$SCRIPT_DIR/vendor_openllmetry.py" \
        --ol-repo "$OL_REPO" \
        --fr-sdk "$FR_SDK_REPO" \
        --clean
fi

echo ""
echo "==> Vendoring complete!"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff src/fortifyroot/_vendor/"
echo "  2. Run tests: pytest tests/"
echo "  3. Commit: git add . && git commit -m 'Update vendored OpenLLMetry'"
