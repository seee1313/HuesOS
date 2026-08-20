#!/usr/bin/env bash
# Deterministic serial-only QEMU boot smoke for CI.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir"
log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
rm -f "$log"

case "$profile" in
    debug) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug ;;
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
# Boot markers that must appear in the QEMU log for the test to pass.
# These cover the critical boot path: bootloader → kernel → userspace init.
# Additional service markers (acpi-manager, driver-manager, terminal) are
# commented out pending service launch integration — see docs/ROADMAP.md.
#
# Boot markers that must appear in the QEMU log for the test to pass.
# These now cover the full happy-path boot chain, kernel → init →
# DriverManager → DriverHosts → shutdown-broker → terminal shell
# ready, so a regression that leaves any of them stranded (e.g. the
# manifest-grants-race-with-BOOTFS-VMO delivery bug that shipped in
# PR-D and was fixed in this PR) turns CI red instead of merging
# green under a broken user experience.
for marker in \
    '[HBI] Ed25519 signature verified (v2.2)' \
    '[uACPI] validated ACPI table graph and MADT' \
    '[uACPI] built immutable Ring-3 table archive v2' \
    '[uACPI] derived bounded FADT SystemIO policy' \
    '[acpi-manager] validated ACPI archive v2:' \
    '[init] hello from ring3 userspace, via libcanvas' \
    '[init] VMO read/write round-trip OK' \
    '[init] channel IPC round-trip OK' \
    '[init] monotonic clock OK' \
    '[init] waitset self-test OK' \
    '[key-broker] kernel key moved; state=plain-only' \
    '[init] delegated unique KeyBroker authority to DriverManager' \
    '[driver-manager] received unique KeyBroker generation authority' \
    '[driver-manager] BOOTFS hash manifest verified and mounted' \
    '[driver-manager] launched DriverHost input-host' \
    '[driver-host:input] started' \
    '[driver-host:input] retained' \
    '[driver-host:input] keyboard IRQ bound to Port' \
    '[shutdown-broker] ready' \
    '[acpi-manager] broker deny-by-default self-test OK' \
    '[driver-manager] ACPI manager ready generation' \
    '[pci-manager] ready without root descriptors; fail-closed' \
    '[driver-manager] PCI manager ready (no roots; fail-closed)' \
    '[init] launched terminal' \
    '[terminal] keyboard service online, starting shell' \
    '[init] stage selftest ok' \
    '[init] stage summary ok selftest' \
    '[init] stage summary ok terminal' \
    '[init] boot stages complete:'; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing boot marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

# The stage markers above are the boot-progress model's own output: a
# stage that never settles, or a splash that stops driving the progress
# bar, no longer hides behind an otherwise green log. 'boot stages
# complete:' is matched without its verdict because a serial-only smoke
# legitimately reports 'degraded' (no framebuffer, no NVMe).

# Regressions that must NOT appear on the happy path. These messages
# indicate a subsystem the user-visible flow depends on failed silently
# — the historical bug shape where CI stayed green because we only
# checked positive early-boot markers.
for regression in \
    '[driver-manager] input DriverHost did not become ready in time' \
    '[driver-manager] keyboard service requested before ready' \
    '[driver-manager] ACPI manager restart budget exhausted' \
    '[driver-manager] malformed ACPI manager control message' \
    '[acpi-manager] PANIC' \
    '[driver-manager] PCI manager restart budget exhausted' \
    '[driver-manager] malformed PCI manager control message' \
    '[pci-manager] PANIC' \
    '[init] shutdown-broker: IoPort resource mint failed' \
    '[init] shutdown-broker: PowerControl mint failed' \
    '[terminal] failed to open keyboard service' \
    '[init] waitset self-test FAILED' \
    '[init] stage selftest FAILED' \
    '[init] stage terminal FAILED' \
    '[init] stage shutdown-broker FAILED' \
    '[init] stage storage FAILED'; do
    if grep -Fq "$regression" "$log"; then
        echo "regression marker present: $regression" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "QEMU smoke passed: profile=$profile smp=$cpus"
