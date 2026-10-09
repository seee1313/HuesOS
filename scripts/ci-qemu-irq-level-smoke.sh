#!/usr/bin/env bash
# QEMU raw-GSI level-interrupt smoke.
#
# Boots with an HBI cmdline that asks the kernel to run the irq_probe
# self-test (`irq_test=1`) and a QEMU `edu` PCI device, which raises a real
# level-triggered INTx line. The probe proves, on the target:
#   - a non-keyboard GSI route is acquired and bound to a Port;
#   - the first assertion is delivered to the Port;
#   - the route stays masked while the line is asserted and unacknowledged;
#   - after deassert + Interrupt::acknowledge, a new assertion is delivered.
#
# Usage: ci-qemu-irq-level-smoke.sh [profile=debug] [cpus=2] [timeout=120]
#
# Exit codes:
#   0  all probe markers present, no kernel panic
#   1  ISO / QEMU / kernel-panic problem, or a marker was missing
#   2  bad usage
set -euo pipefail

profile="${1:-debug}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir"
log="$artifact_dir/qemu-irq-level-${profile}-smp${cpus}.log"
rm -f "$log"

# Install the irq_test=1 cmdline BEFORE building the HBI image, and restore
# the regular placeholder afterwards so later smokes are not affected.
mkdir -p build
echo "irq_test=1" > build/cmdline.txt
trap 'echo "init_args=foo" > build/cmdline.txt' EXIT

case "$profile" in
    debug)   CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug ;;
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release ;;
    *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac

set +e
timeout "${timeout_seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -net none -display none -serial "file:$log" \
    -device edu \
    -no-reboot -no-shutdown
status=$?
set -e

if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU exited unexpectedly with status $status" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi

if grep -q 'KERNEL PANIC' "$log"; then
    echo "kernel panic detected during irq-level probe" >&2
    tail -200 "$log" >&2
    exit 1
fi

markers=(
    '[irq-test] raw GSI route acquired and bound to Port'
    '[irq-test] level IRQ delivered to Port'
    '[irq-test] level route stayed masked until acknowledge'
    '[irq-test] level re-enable after acknowledge OK'
    '[irq-test] raw GSI level route self-test OK'
)
for marker in "${markers[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing irq-level marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

if grep -Fq '[irq-test] FAILED' "$log"; then
    echo "irq-level probe reported explicit failure" >&2
    grep -F '[irq-test]' "$log" >&2 || true
    exit 1
fi

echo "QEMU irq-level smoke passed: profile=$profile smp=$cpus"
