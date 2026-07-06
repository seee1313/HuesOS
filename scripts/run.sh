#!/usr/bin/env bash
# Boot the HuesOS ISO in QEMU under UEFI (OVMF).
set -euo pipefail

PROFILE="${1:-debug}"
ISO="build/huesos.iso"

if [ ! -f "$ISO" ]; then
    echo "error: $ISO not found. Run 'make iso' (or 'make iso PROFILE=$PROFILE') first." >&2
    exit 1
fi

# Try a handful of common OVMF firmware locations across distros.
OVMF_CANDIDATES=(
    "/usr/share/ovmf/OVMF.fd"
    "/usr/share/OVMF/OVMF_CODE.fd"
    "/usr/share/OVMF/OVMF_CODE_4M.fd"
    "/usr/share/qemu/OVMF.fd"
)
OVMF=""
for c in "${OVMF_CANDIDATES[@]}"; do
    if [ -f "$c" ]; then
        OVMF="$c"
        break
    fi
done
if [ -z "$OVMF" ]; then
    echo "error: could not find an OVMF UEFI firmware image. Install 'ovmf'." >&2
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
    -no-reboot -no-shutdown
