#!/usr/bin/env bash
# Build a bootable hybrid BIOS+UEFI ISO for HuesOS.
#
# Limine's prebuilt binary files (bootloader stages + BOOTX64.EFI/etc) are
# vendored directly into this repo under third_party/limine/, so this
# script works out of the box after a fresh `git clone` with no extra
# downloads. Set LIMINE_BIN to point elsewhere if you want to use a
# different/newer Limine release instead.
set -euo pipefail

# Resolve paths relative to the repo root regardless of the caller's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${1:-debug}"
KERNEL="target/x86_64-huesos/${PROFILE}/huesos-boot"
LIMINE_BIN="${LIMINE_BIN:-$REPO_ROOT/third_party/limine}"
ISO_DIR="build/iso"
ISO_FILE="build/huesos.iso"

if [ ! -f "$KERNEL" ]; then
    echo "error: kernel not found at $KERNEL (run 'make build' first)" >&2
    exit 1
fi

for f in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI BOOTIA32.EFI; do
    if [ ! -f "$LIMINE_BIN/$f" ]; then
        echo "error: missing $LIMINE_BIN/$f" >&2
        echo "       (expected vendored Limine binaries under third_party/limine/;" >&2
        echo "       set LIMINE_BIN=/path/to/limine to use a different copy)" >&2
        exit 1
    fi
done

# Generate HBI image
bash scripts/mkhbi.sh "$PROFILE"

rm -rf "$ISO_DIR"
mkdir -p "$ISO_DIR/boot/limine"
mkdir -p "$ISO_DIR/EFI/BOOT"

cp "$KERNEL" "$ISO_DIR/boot/huesos-boot"
cp "build/huesos.hbi" "$ISO_DIR/boot/huesos.hbi"
cp "scripts/limine.conf" "$ISO_DIR/boot/limine/limine.conf"
cp "$LIMINE_BIN/limine-bios.sys" "$ISO_DIR/boot/limine/"
cp "$LIMINE_BIN/limine-bios-cd.bin" "$ISO_DIR/boot/limine/"
cp "$LIMINE_BIN/limine-uefi-cd.bin" "$ISO_DIR/boot/limine/"
cp "$LIMINE_BIN/BOOTX64.EFI" "$ISO_DIR/EFI/BOOT/"
cp "$LIMINE_BIN/BOOTIA32.EFI" "$ISO_DIR/EFI/BOOT/"

mkdir -p build
xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
    -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    "$ISO_DIR" -o "$ISO_FILE" 2>&1 | tail -20

echo "[ISO] Created $ISO_FILE"
