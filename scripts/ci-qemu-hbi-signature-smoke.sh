#!/usr/bin/env bash
set -euo pipefail

profile="${1:-release}"
seconds="${2:-90}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
log="$artifact_dir/qemu-hbi-signature-${profile}.log"
mkdir -p "$artifact_dir"
rm -f "$log"

HBI_TAMPER_AFTER_SIGN=1 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    make iso PROFILE="$profile"
set +e
timeout "${seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp 2 -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -net none -display none -serial "file:$log" -no-reboot -no-shutdown
status=$?
set -e
if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "tampered-HBI QEMU exited unexpectedly: $status" >&2
    exit 1
fi
grep -Fq '[HBI] signature verification failed: InvalidSignature' "$log" || {
    echo "kernel did not reject the tampered HBI signature" >&2
    tail -200 "$log" >&2
    exit 1
}
if grep -Fq '[init] hello from ring3' "$log"; then
    echo "userspace started after HBI signature failure" >&2
    exit 1
fi
echo "HBI signature negative smoke passed: profile=$profile"
