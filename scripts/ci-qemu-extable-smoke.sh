#!/usr/bin/env bash
# Extable recoverable-copy smoke: boot QEMU with an HBI cmdline that
# asks the kernel to trigger the synthetic user-copy fault probe, and
# verify the serial log contains the "recovered" marker.
#
# This is the CI-side proof that the extable populate + wire-up
# actually redirects a ring-0 #PF to the fixup landing pad on the
# real target, instead of taking the fatal panic path. It complements
# scripts/ci-qemu-smoke.sh (which only proves a normal boot).
#
# Usage: ci-qemu-extable-smoke.sh [profile=release] [cpus=2] [timeout=120]
#
# Exit codes:
#   0  the marker appeared, extable recovery works
#   1  ISO / QEMU / kernel-panic problem, or the marker was missing
#   2  bad usage
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir"
log="$artifact_dir/qemu-extable-${profile}-smp${cpus}.log"
rm -f "$log"

# Install the extable_test=1 cmdline BEFORE building the HBI image.
# mkhbi.sh reads build/cmdline.txt; the file is normally created with
# a placeholder init_args=foo. We overwrite it here so this smoke does
# not interfere with the regular boot smoke's HBI.
mkdir -p build
echo "extable_test=1" > build/cmdline.txt
trap 'echo "init_args=foo" > build/cmdline.txt' EXIT

# Force a fresh HBI build (the ISO recipe rebuilds if inputs change,
# but the cmdline.txt input was just rewritten — mkiso.sh will
# regenerate the image).
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
    -no-reboot -no-shutdown
status=$?
set -e

if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU exited unexpectedly with status $status" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi

# The whole point of the extable path is that the fault DOES NOT
# escalate to a kernel panic, so the presence of the panic marker
# proves the mechanism failed.
if grep -q 'KERNEL PANIC' "$log"; then
    echo "kernel panic detected during extable probe — recovery failed" >&2
    tail -200 "$log" >&2
    exit 1
fi

# Positive marker: the probe recovered as expected.
recovered_marker='[extable-test] recovered synthetic user-copy fault OK'
if ! grep -Fq "$recovered_marker" "$log"; then
    echo "missing extable recovery marker: $recovered_marker" >&2
    tail -200 "$log" >&2
    exit 1
fi

# Negative marker: the probe explicitly reported a failure. Belt-and-
# braces guard against a partial log where the recovered marker is
# absent but the failure line is present.
if grep -Fq '[extable-test] FAILED' "$log"; then
    echo "extable probe reported explicit failure" >&2
    tail -200 "$log" >&2
    exit 1
fi

echo "QEMU extable smoke passed: profile=$profile smp=$cpus"
