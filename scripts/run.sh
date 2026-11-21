#!/usr/bin/env bash
# Boot the HuesOS ISO in QEMU under UEFI (OVMF).
#
# Storage: build/nvme.img (see scripts/mknvme-image.sh) is attached as an NVMe
# namespace unless HUESOS_NO_NVME=1.
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
NVME="${HUESOS_NVME_IMAGE:-build/nvme.img}"

if [ ! -f "$ISO" ]; then
    echo "error: $ISO not found. Run 'make iso' (or 'make iso PROFILE=$PROFILE') first." >&2
    exit 1
fi

if [ ! -f "$OVMF" ]; then
    echo "error: OVMF firmware not found at $OVMF" >&2
    echo "       (set OVMF_PATH=/path/to/OVMF.fd to use a different one)" >&2
    exit 1
fi

# The boot disk: a GPT volume with a single HxFS v7 partition. Without it the
# OS comes up with no storage capability at all, so `lsblk`, `df` and `fdisk`
# would have nothing real to report. `HUESOS_NVME_SIZE` (e.g. 200G, 1T)
# sizes the disk; big sizes stay sparse on the host.
disk_args=()
if [[ -n "${HUESOS_NVME_IMAGE:-}" || "${HUESOS_NO_NVME:-0}" != "1" ]]; then
    bash scripts/mknvme-image.sh "${HUESOS_NVME_SIZE:-96M}" "$NVME" >&2
    disk_args=(
        -drive "id=nvme0,if=none,format=raw,file=$NVME"
        -device "nvme,serial=huesosnvme,drive=nvme0"
    )
fi

exec qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -smp 2 \
    -m 512M \
    -bios "$OVMF" \
    -cdrom "$ISO" \
    "${disk_args[@]}" \
    -net none \
    -serial stdio \
    -no-reboot -no-shutdown
