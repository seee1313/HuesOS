#!/usr/bin/env bash
# Enforced UEFI Secure Boot smoke: an owner-enrolled, signed/config-locked
# Limine boots; the same firmware variable store rejects unsigned Limine.
set -euo pipefail
profile="${1:-debug}"
seconds="${2:-45}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
work="build/secure-boot-smoke"
positive_log="$artifact_dir/qemu-secure-boot-${profile}.log"
negative_log="$artifact_dir/qemu-secure-boot-unsigned-${profile}.log"
code="${OVMF_SECBOOT_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
vars_template="${OVMF_VARS_TEMPLATE:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
owner_guid="7f3b1884-8f65-4dd7-9f20-0c0c5e2b1912"
mkdir -p "$work" "$artifact_dir"
rm -f "$work"/* "$positive_log" "$negative_log"
for tool in openssl virt-fw-vars sbsign sbverify mcopy qemu-system-x86_64; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
[[ -f "$code" && -f "$vars_template" ]] || { echo "Secure Boot OVMF pflash files missing" >&2; exit 1; }
cleanup() {
    if [[ -f "$work/db.key" ]]; then
        python3 - "$work/db.key" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
p.write_bytes(bytes(p.stat().st_size))
p.unlink()
PY
    fi
}
trap cleanup EXIT
openssl req -new -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=HuesOS CI Secure Boot/' \
    -keyout "$work/db.key" -out "$work/db.crt" >/dev/null 2>&1
virt-fw-vars -i "$vars_template" \
    --set-pk "$owner_guid" "$work/db.crt" \
    --add-kek "$owner_guid" "$work/db.crt" \
    --add-db "$owner_guid" "$work/db.crt" --sb \
    -o "$work/enrolled-vars.fd" >/dev/null

run_qemu() {
    local vars="$1" log="$2" limit="$3"
    set +e
    timeout "${limit}s" qemu-system-x86_64 \
        -machine q35,smm=on \
        -global driver=cfi.pflash01,property=secure,value=on \
        -cpu qemu64 -smp 2 -m 512M \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
        -drive "if=pflash,format=raw,unit=1,file=$vars" \
        -cdrom build/huesos.iso -net none -display none \
        -serial "file:$log" -no-reboot -no-shutdown
    local status=$?
    set -e
    [[ "$status" == 0 || "$status" == 124 ]]
}

HUESOS_SECURE_BOOT=1 \
HUESOS_UEFI_DB_KEY="$work/db.key" \
HUESOS_UEFI_DB_CERT="$work/db.crt" \
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE="$profile"
sbverify --cert "$work/db.crt" build/iso/EFI/BOOT/BOOTX64.EFI >/dev/null
cp "$work/enrolled-vars.fd" "$work/positive-vars.fd"
run_qemu "$work/positive-vars.fd" "$positive_log" "$seconds"
grep -Fq '[HuesOS] Bootloader handed over control' "$positive_log"
grep -Fq '[HBI] Ed25519 signature verified (v2.2)' "$positive_log"

# Rebuild with the same kernel/HBI but an unsigned Limine. The enrolled db and
# SecureBootEnable stay identical; OVMF must reject before HuesOS gains control.
HUESOS_SECURE_BOOT=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE="$profile"
if sbverify --list build/iso/EFI/BOOT/BOOTX64.EFI 2>&1 | grep -vq 'No signature table present'; then
    echo "negative Secure Boot image unexpectedly has a signature" >&2
    exit 1
fi
cp "$work/enrolled-vars.fd" "$work/negative-vars.fd"
run_qemu "$work/negative-vars.fd" "$negative_log" 20
grep -Fq 'Access Denied' "$negative_log"
! grep -Fq '[HuesOS] Bootloader handed over control' "$negative_log"
echo "UEFI Secure Boot signed/unsigned enforcement smoke passed: profile=$profile"
