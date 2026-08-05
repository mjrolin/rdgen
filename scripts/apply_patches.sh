#!/bin/bash
# apply_patches.sh - Apply RDGen patches to RustDesk source code
# Usage: ./apply_patches.sh <rustdesk_source_dir> [patch_dir]

set -e

RUSTDESK_DIR="${1:-.}"
PATCH_DIR="${2:-$(dirname "$0")/../patches}"

echo "=== RDGen Patch Application Script ==="
echo "RustDesk directory: $RUSTDESK_DIR"
echo "Patches directory: $PATCH_DIR"
echo ""

if [ ! -d "$RUSTDESK_DIR" ]; then
    echo "ERROR: RustDesk directory not found: $RUSTDESK_DIR"
    exit 1
fi

if [ ! -d "$PATCH_DIR" ]; then
    echo "ERROR: Patches directory not found: $PATCH_DIR"
    exit 1
fi

cd "$RUSTDESK_DIR"

# Apply allowCustom.py script (removes signature verification)
if [ -f "$PATCH_DIR/allowCustom.py" ]; then
    echo "Applying allowCustom.py..."
    python3 "$PATCH_DIR/allowCustom.py" || {
        echo "WARNING: allowCustom.py failed, trying alternative method..."
        # Fallback: apply diff directly
        if [ -f "$PATCH_DIR/allowCustom.diff" ]; then
            git apply --ignore-whitespace "$PATCH_DIR/allowCustom.diff" 2>/dev/null || \
            patch -p1 < "$PATCH_DIR/allowCustom.diff" || true
        fi
    }
fi

# Apply removeSetupServerTip.diff
if [ -f "$PATCH_DIR/removeSetupServerTip.diff" ]; then
    echo "Applying removeSetupServerTip.diff..."
    git apply --ignore-whitespace "$PATCH_DIR/removeSetupServerTip.diff" 2>/dev/null || \
    patch -p1 < "$PATCH_DIR/removeSetupServerTip.diff" || {
        echo "WARNING: Failed to apply removeSetupServerTip.diff"
    }
fi

# Optional patches based on config
apply_optional_patch() {
    local patch_name="$1"
    local patch_file="$PATCH_DIR/${patch_name}.diff"

    if [ -f "$patch_file" ]; then
        echo "Applying optional patch: $patch_name..."
        git apply --ignore-whitespace "$patch_file" 2>/dev/null || \
        patch -p1 < "$patch_file" || {
            echo "WARNING: Failed to apply $patch_name"
        }
    fi
}

# Check environment variables for optional patches
if [ "$APPLY_CYCLE_MONITOR" = "true" ]; then
    apply_optional_patch "cycle_monitor"
fi

if [ "$APPLY_X_OFFLINE" = "true" ]; then
    apply_optional_patch "xoffline"
fi

if [ "$APPLY_HIDE_CM" = "true" ]; then
    apply_optional_patch "hidecm"
fi

if [ "$APPLY_REMOVE_NEW_VERSION_NOTIF" = "true" ]; then
    apply_optional_patch "removeNewVersionNotif"
fi

echo ""
echo "=== Patch application complete ==="
