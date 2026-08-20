#!/usr/bin/env bash
# Enrol the generated limine.conf digest into Limine EFI binaries, sign those
# binaries with an owner-provided UEFI db key/certificate, and replace the
# copies inside Limine's FAT El Torito image used for optical UEFI boot.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
EFI_DIR="${1:-build/iso/EFI/BOOT}"
CONFIG="${2:-build/iso/boot/limine/limine.conf}"
UEFI_CD_IMAGE="${3:-build/iso/boot/limine/limine-uefi-cd.bin}"
DB_KEY="${HUESOS_UEFI_DB_KEY:-}"
DB_CERT="${HUESOS_UEFI_DB_CERT:-}"

[[ -n "$DB_KEY" && -f "$DB_KEY" ]] || { echo "HUESOS_UEFI_DB_KEY is required" >&2; exit 1; }
[[ -n "$DB_CERT" && -f "$DB_CERT" ]] || { echo "HUESOS_UEFI_DB_CERT is required" >&2; exit 1; }
command -v sbsign >/dev/null || { echo "sbsign is required" >&2; exit 1; }
command -v sbverify >/dev/null || { echo "sbverify is required" >&2; exit 1; }
command -v mcopy >/dev/null || { echo "mcopy (mtools) is required" >&2; exit 1; }

# Keep the version-matched Limine host utility reproducible instead of relying
# on a distribution package with potentially different enrollment offsets.
LIMINE_TOOL="${HUESOS_LIMINE_TOOL:-}"
if [[ -z "$LIMINE_TOOL" ]]; then
    LIMINE_TOOL="build/limine"
    if [[ ! -x "$LIMINE_TOOL" || third_party/limine/limine.c -nt "$LIMINE_TOOL" ]]; then
        mkdir -p build
        "${CC:-cc}" -O2 -std=c99 third_party/limine/limine.c -o "$LIMINE_TOOL"
    fi
elif [[ "$LIMINE_TOOL" == */* ]]; then
    [[ -x "$LIMINE_TOOL" ]] || { echo "Limine host tool not executable: $LIMINE_TOOL" >&2; exit 1; }
else
    command -v "$LIMINE_TOOL" >/dev/null || { echo "Limine host tool not found: $LIMINE_TOOL" >&2; exit 1; }
fi

CONFIG_B2="$(b2sum "$CONFIG" | awk '{print $1}')"
signed_count=0
for efi in "$EFI_DIR"/BOOTX64.EFI "$EFI_DIR"/BOOTIA32.EFI; do
    [[ -f "$efi" ]] || continue
    "$LIMINE_TOOL" enroll-config "$efi" "$CONFIG_B2"
    signed="${efi}.signed"
    sbsign --key "$DB_KEY" --cert "$DB_CERT" --output "$signed" "$efi"
    mv "$signed" "$efi"
    sbverify --cert "$DB_CERT" "$efi" >/dev/null
    # xorriso boots this FAT image on optical media; signing only the duplicate
    # /EFI/BOOT file in the ISO filesystem would leave firmware executing the
    # original unsigned embedded copy.
    mcopy -o -i "$UEFI_CD_IMAGE" "$efi" "::/EFI/BOOT/$(basename "$efi")"
    signed_count=$((signed_count + 1))
    echo "[secure-boot] enrolled config, signed, and patched $(basename "$efi")"
done
[[ "$signed_count" -gt 0 ]] || { echo "no Limine EFI binaries found to sign" >&2; exit 1; }
