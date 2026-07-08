#!/usr/bin/env bash
# Boot the HuesOS ISO in QEMU under UEFI (OVMF).
#
# The OVMF firmware image is vendored directly in this repo under
# third_party/ovmf/, so this always uses the same known-good firmware
# regardless of the host distro's OVMF package layout (which varies a lot:
# Debian/Ubuntu, Arch, and Fedora all install to different paths, some
# split CODE/VARS into separate files, etc). Set OVMF_PATH to override.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${1:-debug}"
ISO="build/huesos.iso"
OVMF="${OVMF_PATH:-third_party/ovmf/OVMF.fd}"

if [ ! -f "$ISO" ]; then
    echo "error: $ISO not found. Run 'make iso' (or 'make iso PROFILE=$PROFILE') first." >&2
    exit 1
fi

if [ ! -f "$OVMF" ]; then
    echo "error: OVMF firmware not found at $OVMF" >&2
    echo "       (set OVMF_PATH=/path/to/OVMF.fd to use a different one)" >&2
    exit 1
fi

exec qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 256M \
    -bios "$OVMF" \
    -cdrom "$ISO" \
    -net none \
    -serial stdio \
    -display none \
    -no-reboot -no-shutdown
