#!/usr/bin/env bash
# Prove the dedicated ACPI ↔ PCI mediation channel on Q35/OVMF.
#
#   ecam (default) — normal boot: the retained HMCF snapshot, the
#       read-only ECAM authority handoff, the mediation pair established
#       by DriverManager, and the bounded self-test probe issued through
#       the channel by the ACPI manager.
#   legacy — conformance-only boot with HUESOS_PCI_FORCE_LEGACY=1: both
#       managers are built with the legacy backend; DriverManager mints
#       the CF8/CFC common-subset authority (no ECAM windows), and the
#       self-test probe must succeed through CF8/CFC.
#
# The probe is evidence of a real physical read. The no-inventory
# contract holds: nothing publishes a device table.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
scenario="${4:-ecam}"

case "$scenario" in
    ecam)
        artifact_dir="${ARTIFACT_DIR:-ci-artifacts/pci-mediation}"
        ;;
    legacy)
        artifact_dir="${ARTIFACT_DIR:-ci-artifacts/pci-mediation-legacy}"
        ;;
    *)
        echo "unsupported scenario: $scenario (expected ecam|legacy)" >&2
        exit 2
        ;;
esac

mkdir -p "$artifact_dir"
# Both scenarios reuse the plain boot gate; pass the scenario so its required
# PCI readiness markers match the backend actually built into the ISO.
if [[ "$scenario" == "legacy" ]]; then
    HUESOS_PCI_FORCE_LEGACY=1 ARTIFACT_DIR="$artifact_dir" \
        bash "$(dirname "$0")/ci-qemu-smoke.sh" "$profile" "$cpus" "$timeout_seconds" "$scenario"
else
    ARTIFACT_DIR="$artifact_dir" \
        bash "$(dirname "$0")/ci-qemu-smoke.sh" "$profile" "$cpus" "$timeout_seconds" "$scenario"
fi

log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
case "$scenario" in
    ecam)
        required=(
            '[driver-manager] minted'
            'read-only config capability(ies) for PCI manager generation'
            '[driver-manager] PCI manager ready (read-only config authority'
            '[pci-manager] obs backend=ecam'
            '[driver-manager] mediation channel pair established'
            '[acpi-manager] pci-mediation self-test: read=ok vendor-nonzero=true'
            '[acpi-manager] pci-mediation self-test: write=denied'
        )
        forbidden=(
            '[pci-manager] obs backend=legacy-cf8-cfc'
            '[acpi-manager] pci-mediation self-test: read=timeout'
            '[acpi-manager] pci-mediation self-test: read=peer_closed'
            '[pci-manager] obs mediation peer-closed'
            '[pci-manager] PANIC'
            '[acpi-manager] PANIC'
            'KERNEL PANIC'
        )
        ;;
    legacy)
        required=(
            '[driver-manager] PCI manager ready (legacy CF8/CFC backend)'
            '[driver-manager] minted legacy CF8/CFC capability for PCI manager generation'
            '[pci-manager] legacy CF8/CFC config reads ready'
            '[pci-manager] obs backend=legacy-cf8-cfc'
            '[driver-manager] mediation channel pair established'
            '[acpi-manager] pci-mediation self-test: read=ok vendor-nonzero=true'
            '[acpi-manager] pci-mediation self-test: write=denied'
        )
        forbidden=(
            '[pci-manager] obs backend=ecam'
            '[pci-manager] read-only config authority map rejected'
            '[acpi-manager] pci-mediation self-test: read=timeout'
            '[acpi-manager] pci-mediation self-test: read=peer_closed'
            '[pci-manager] obs mediation peer-closed'
            '[pci-manager] PANIC'
            '[acpi-manager] PANIC'
            'KERNEL PANIC'
        )
        ;;
esac

for marker in "${required[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing mediation $scenario marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

for marker in "${forbidden[@]}"; do
    if grep -Fq "$marker" "$log"; then
        echo "forbidden mediation $scenario marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "PCI mediation smoke passed: scenario=$scenario profile=$profile smp=$cpus"
