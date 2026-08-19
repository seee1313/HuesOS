#!/usr/bin/env bash
# Prove DriverManager can relaunch ACPI Manager from retained capabilities after
# a generation-one pre-ready exit, while the ordinary DriverHosts keep running.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts/acpi-restart}"
mkdir -p "$artifact_dir"

HUESOS_ACPI_RESTART_SMOKE=1 \
ARTIFACT_DIR="$artifact_dir" \
    bash "$(dirname "$0")/ci-qemu-smoke.sh" "$profile" "$cpus" "$timeout_seconds"

log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
for marker in \
    '[acpi-manager] injected pre-ready exit generation 1' \
    '[driver-manager] ACPI manager unavailable; frozen restart 1/2 scheduled' \
    '[driver-manager] launched restartable ACPI manager generation 2' \
    '[driver-manager] ACPI manager ready generation 2' \
    '[driver-host:input] retained'; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing ACPI restart marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

for forbidden in \
    '[driver-manager] ACPI manager restart budget exhausted' \
    '[acpi-manager] PANIC' \
    'KERNEL PANIC'; do
    if grep -Fq "$forbidden" "$log"; then
        echo "forbidden ACPI restart marker: $forbidden" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "ACPI manager restart smoke passed: profile=$profile smp=$cpus"
