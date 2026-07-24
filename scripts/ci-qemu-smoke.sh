#!/usr/bin/env bash
# Deterministic serial-only QEMU boot smoke for CI.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-360}"
stress="${4:-32}"
case "$stress" in 32|256) ;; *) echo "unsupported lifecycle stress: $stress" >&2; exit 2 ;; esac
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir"
log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
rm -f "$log"

case "$profile" in
    debug) HUESOS_LIFECYCLE_WAIT_STRESS="$stress" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug ;;
    release) HUESOS_LIFECYCLE_WAIT_STRESS="$stress" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release ;;
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

# A healthy OS intentionally keeps running, so timeout(1)'s 124 is expected.
if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU exited unexpectedly with status $status" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi
if grep -q 'KERNEL PANIC' "$log"; then
    echo "kernel panic detected" >&2
    tail -200 "$log" >&2
    exit 1
fi
for marker in \
    '[uACPI] validated ACPI table graph and MADT' \
    '[uACPI] built immutable Ring-3 table archive' \
    '[uACPI] derived bounded FADT SystemIO policy' \
    '[acpi-manager] validated ' \
    '[acpi-manager] broker deny-by-default self-test OK' \
    '[driver-manager] ACPI manager archive validation ready' \
    '[init] user fault isolation OK' \
    "[init] ProcessWait lifecycle $( [[ "$stress" == 256 ]] && echo soak || echo smoke ) OK ($stress blocked wakes)" \
    '[init] terminal says terminal:ready' \
    '[terminal] keyboard service online'; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing boot marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "QEMU smoke passed: profile=$profile smp=$cpus stress=$stress"
