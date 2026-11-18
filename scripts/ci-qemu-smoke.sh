#!/usr/bin/env bash
# Deterministic serial-only QEMU boot smoke for CI.
#
# Usage: ci-qemu-smoke.sh [profile] [cpus] [timeout] [ecam|legacy]
# The optional scenario selects which PCI-manager readiness markers the
# happy-path boot gate requires. It defaults to `legacy` when
# HUESOS_PCI_FORCE_LEGACY=1 is set, and to `ecam` otherwise. Explicitly
# requesting a scenario that disagrees with that build knob is an error.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
scenario="${4:-}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"

if [[ -z "$scenario" ]]; then
    if [[ "${HUESOS_PCI_FORCE_LEGACY:-}" == "1" ]]; then
        scenario="legacy"
    else
        scenario="ecam"
    fi
fi

case "$scenario" in
    ecam|legacy) ;;
    *)
        echo "unsupported PCI scenario: $scenario (expected ecam|legacy)" >&2
        exit 2
        ;;
esac

if [[ "$scenario" == "legacy" && "${HUESOS_PCI_FORCE_LEGACY:-}" != "1" ]]; then
    echo "legacy PCI scenario requires HUESOS_PCI_FORCE_LEGACY=1" >&2
    exit 2
fi
if [[ "$scenario" == "ecam" && "${HUESOS_PCI_FORCE_LEGACY:-}" == "1" ]]; then
    echo "ecam PCI scenario conflicts with HUESOS_PCI_FORCE_LEGACY=1" >&2
    exit 2
fi

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
# Require stable markers for the full happy-path boot chain, from bootloader
# through the terminal shell. These checks catch stalled service launches.
# Ring-3 and kernel serial writes can interleave on SMP. Check ACPI validation
# with stable fragments; terminal readiness below replaces its splittable
# "[init] launched terminal" line as proof of successful startup.
#
# The PCI readiness pair is scenario-specific: the ECAM build reports mapped
# read-only windows, while the conformance-only forced-legacy build reports
# the CF8/CFC common subset. Requiring the ECAM strings in the legacy smoke
# made `qemu-pci-mediation` fail even though the legacy boot was healthy.
required=(
    '[HBI] Ed25519 signature verified (v2.2)'
    '[uACPI] validated ACPI table graph and MADT'
    '[uACPI] built immutable Ring-3 table archive v2'
    '[uACPI] derived bounded FADT SystemIO policy'
    '[acpi-manager] validated ACPI archive v'
    'physical mappings, snapshot'
    '[init] hello from ring3 userspace, via libcanvas'
    '[init] VMO read/write round-trip OK'
    '[init] channel IPC round-trip OK'
    '[init] monotonic clock OK'
    '[init] ProcessWait lifecycle smoke OK (32 blocked wakes)'
    '[init] ProcessWait repeated observation OK'
    '[init] waitset self-test OK'
    '[key-broker] kernel key moved; state=plain-only'
    '[init] delegated unique KeyBroker authority to DriverManager'
    '[driver-manager] received unique KeyBroker generation authority'
    '[driver-manager] BOOTFS hash manifest verified and mounted'
    '[driver-manager] launched DriverHost input-host'
    '[driver-host:input] started'
    '[driver-host:input] retained'
    '[driver-host:input] keyboard IRQ bound to Port'
    '[shutdown-broker] ready'
    '[acpi-manager] broker deny-by-default self-test OK'
    '[acpi-manager] AML namespace loaded (snapshot'
    '[acpi-manager] AML namespace initialized (snapshot'
    '[acpi-manager] published HPCI:'
    '[driver-manager] retained HPCI:'
    '[driver-manager] ACPI manager ready generation'
    '[driver-manager] ACPI namespace initialized generation'
    '[driver-manager] forwarded HPCI root table to PCI manager'
    '[pci-manager] accepted HPCI root table:'
    '[driver-manager] PCI manager accepted HPCI root table:'
    '[acpi-manager] published HMCF'
    '[driver-manager] retained HMCF'
    '[acpi] config mint authority installed: snapshot'
    '[init] installed PciConfigMint capability (handle 8)'
    '[init] delegated unique PciConfigMint authority to DriverManager'
    '[driver-manager] received unique PciConfigMint authority'
)

case "$scenario" in
    ecam)
        required+=(
            '[driver-manager] PCI manager ready (read-only config authority'
            '[pci-manager] read-only config authority ready'
        )
        ;;
    legacy)
        required+=(
            '[driver-manager] PCI manager ready (legacy CF8/CFC backend)'
            '[pci-manager] legacy CF8/CFC config reads ready'
        )
        ;;
esac

required+=(
    '[pci-manager] ready without root descriptors; fail-closed'
    '[driver-manager] PCI manager ready (no roots; fail-closed)'
    '[terminal] keyboard service online, starting shell'
    '[init] stage selftest ok'
    '[init] stage summary ok selftest'
    '[init] stage summary ok terminal'
    '[init] boot stages complete:'
)

for marker in "${required[@]}"; do
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
regressions=(
    '[driver-manager] input DriverHost did not become ready in time'
    '[driver-manager] keyboard service requested before ready'
    '[driver-manager] ACPI manager restart budget exhausted'
    '[driver-manager] malformed ACPI manager control message'
    '[driver-manager] HMCF rejected'
    '[driver-manager] HPCI rejected'
    '[driver-manager] HPCI consistency rejected'
    '[pci-manager] rejected HPCI root table'
    '[acpi] config mint authority disabled:'
    '[init] failed to install PciConfigMint capability'
    '[init] config mint authority transfer failed'
    '[driver-manager] duplicate PciConfigMint authority rejected'
    '[driver-manager] config capability mint rejected'
    '[driver-manager] config authority transfer failed'
    '[pci-manager] HMCF rejected'
    '[pci-manager] no firmware snapshot'
    '[pci-manager] read-only config authority map rejected'
    '[acpi-manager] PANIC'
    '[driver-manager] PCI manager restart budget exhausted'
    '[driver-manager] malformed PCI manager control message'
    '[pci-manager] PANIC'
    '[init] shutdown-broker: IoPort resource mint failed'
    '[init] shutdown-broker: PowerControl mint failed'
    '[terminal] failed to open keyboard service'
    '[init] waitset self-test FAILED'
    '[init] stage selftest FAILED'
    '[init] stage terminal FAILED'
    '[init] stage shutdown-broker FAILED'
    '[init] stage storage FAILED'
)

# A scenario must not silently boot with the other backend's readiness
# markers: that would mean the nested userspace builds got out of sync with
# the kernel build knob.
case "$scenario" in
    ecam)
        regressions+=(
            '[driver-manager] PCI manager ready (legacy CF8/CFC backend)'
            '[pci-manager] legacy CF8/CFC config reads ready'
            '[pci-manager] obs backend=legacy-cf8-cfc'
        )
        ;;
    legacy)
        regressions+=(
            '[driver-manager] PCI manager ready (read-only config authority'
            '[pci-manager] read-only config authority ready'
            '[pci-manager] obs backend=ecam'
        )
        ;;
esac

for regression in "${regressions[@]}"; do
    if grep -Fq "$regression" "$log"; then
        echo "regression marker present: $regression" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "QEMU smoke passed: profile=$profile smp=$cpus scenario=$scenario"
