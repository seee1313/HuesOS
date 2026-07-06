#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-debug}"
KERNEL="target/x86_64-huesos/${PROFILE}/huesos-boot"
LIMINE_BIN="${LIMINE_BIN:-$HOME/limine-bin}"
ISO_DIR="build/iso"
ISO_FILE="build/huesos.iso"

if [ ! -f "$KERNEL" ]; then
    echo "error: kernel not found at $KERNEL (build it first)" >&2
    exit 1
fi

rm -rf "$ISO_DIR"
mkdir -p "$ISO_DIR/boot/limine"
mkdir -p "$ISO_DIR/EFI/BOOT"

cp "$KERNEL" "$ISO_DIR/boot/huesos-boot"
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
