#!/bin/bash
# prepare_build_repo.sh - Prepare a build repository with RustDesk source and patches
# Usage: ./prepare_build_repo.sh <version> <output_dir>

set -e

VERSION="${1:-1.4.2}"
OUTPUT_DIR="${2:-./build_workspace}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_DIR="$SCRIPT_DIR/../patches"

echo "=== RDGen Build Repository Preparation ==="
echo "RustDesk Version: $VERSION"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Clean and create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Clone RustDesk repository
echo "Cloning RustDesk repository..."
if [ "$VERSION" = "master" ] || [ "$VERSION" = "nightly" ]; then
    git clone --recursive https://github.com/rustdesk/rustdesk.git .
else
    git clone --recursive --branch "$VERSION" --depth 1 https://github.com/rustdesk/rustdesk.git .
fi

echo ""
echo "Applying patches..."

# Copy patches to repository
mkdir -p .github/patches
cp "$PATCH_DIR"/* .github/patches/ 2>/dev/null || true

# Apply base patches
"$SCRIPT_DIR/apply_patches.sh" "." "$PATCH_DIR"

echo ""
echo "=== Build repository prepared at: $OUTPUT_DIR ==="
echo ""
echo "Next steps:"
echo "1. Configure your custom settings in the build workflow"
echo "2. Push to your GitHub repository"
echo "3. Trigger the build workflow"
