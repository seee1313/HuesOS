#!/usr/bin/env bash
set -euo pipefail
profile="${1:-release}"
seconds="${2:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
log="$artifact_dir/qemu-smep-smap-${profile}.log"
mkdir -p "$artifact_dir"
rm -f "$log"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE="$profile"
set +e
timeout "${seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu max -smp 4 -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -net none -display none -serial "file:$log" -no-reboot -no-shutdown
status=$?
set -e
if [[ "$status" != 0 && "$status" != 124 ]]; then
    exit 1
fi
grep -Fq '[security] BSP SMEP=on SMAP=on' "$log"
grep -Eq '\[security\] AP [0-9]+ SMEP=on SMAP=on' "$log"
grep -Fq '[init] user pointer guard smoke OK' "$log"
! grep -Fq 'KERNEL PANIC' "$log"
echo "SMEP/SMAP SMP4 smoke passed: profile=$profile"
