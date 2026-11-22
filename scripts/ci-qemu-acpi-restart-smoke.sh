#!/usr/bin/env bash
# Prove DriverManager supervision of the ACPI Manager across crashes, on Q35/OVMF.
#
# Scenarios:
#   restart (default) — full crash cascade in one boot:
#       generation 1 exits before readiness (crash-before-archive-accept),
#       generation 2 exits right after readiness (crash-after-ready),
#       generation 3 becomes ready and then emits one foreign-generation
#       heartbeat that DriverManager must ignore (stale control bytes).
#   budget — every generation exits before readiness, exhausting the bounded
#       restart budget into the explicit degraded state; unrelated DriverHosts
#       keep running and no ready marker may appear.
#
# Both scenarios require the ordinary input DriverHost to survive and the
# terminal/init chain to complete; neither enables AML execution or PCI
# authority.
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
scenario="${4:-restart}"

case "$scenario" in
    restart)
        artifact_dir="${ARTIFACT_DIR:-ci-artifacts/acpi-restart}"
        mkdir -p "$artifact_dir"
        HUESOS_ACPI_RESTART_SMOKE=1 \
        ARTIFACT_DIR="$artifact_dir" \
            bash "$(dirname "$0")/ci-qemu-smoke.sh" "$profile" "$cpus" "$timeout_seconds"
        ;;
    budget)
        artifact_dir="${ARTIFACT_DIR:-ci-artifacts/acpi-budget}"
        mkdir -p "$artifact_dir"
        log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
        rm -f "$log"
        case "$profile" in
            debug) HUESOS_BOOT_SELFTEST=1 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" HUESOS_ACPI_BUDGET_SMOKE=1 make iso PROFILE=debug ;;
            release) HUESOS_BOOT_SELFTEST=1 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" HUESOS_ACPI_BUDGET_SMOKE=1 make iso-release ;;
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
        if grep -q 'KERNEL PANIC' "$log"; then
            echo "kernel panic detected" >&2
            tail -200 "$log" >&2
            exit 1
        fi
        ;;
    *)
        echo "unsupported scenario: $scenario (expected restart|budget)" >&2
        exit 2
        ;;
esac

log="$artifact_dir/qemu-${profile}-smp${cpus}.log"
case "$scenario" in
    restart)
        required=(
            '[acpi-manager] injected pre-ready exit generation 1'
            '[driver-manager] ACPI manager unavailable; frozen restart 1/2 scheduled'
            '[driver-manager] launched restartable ACPI manager generation 2'
            '[acpi-manager] injected post-ready exit generation 2'
            '[driver-manager] ACPI manager ready generation 2'
            '[driver-manager] launched restartable ACPI manager generation 3'
            '[driver-manager] ACPI manager ready generation 3'
            '[acpi-manager] injected foreign-generation heartbeat 2 (self 3)'
            '[driver-manager] stale ACPI manager generation ignored'
            '[driver-manager] dropped stale HMCF from generation 2'
            '[driver-host:input] retained'
            '[init] boot stages complete:'
        )
        forbidden=(
            '[driver-manager] ACPI manager restart budget exhausted'
            '[acpi-manager] PANIC'
            'KERNEL PANIC'
        )
        ;;
    budget)
        required=(
            '[acpi-manager] injected pre-ready exit generation 1'
            '[acpi-manager] injected pre-ready exit generation 2'
            '[acpi-manager] injected pre-ready exit generation 3'
            '[driver-manager] ACPI manager unavailable; frozen restart 1/2 scheduled'
            '[driver-manager] ACPI manager unavailable; frozen restart 2/2 scheduled'
            '[driver-manager] ACPI manager restart budget exhausted; runtime ACPI degraded'
            '[driver-host:input] retained'
            # Prefix only: the suffix names the shell binary and has
            # already drifted once (`starting shell` -> `starting
            # /bin/hsh.elf session`), which turned this gate red on `main`
            # after a message-only refactor.
            '[terminal] keyboard service online'
            '[init] boot stages complete:'
        )
        forbidden=(
            '[driver-manager] ACPI manager ready generation'
            '[acpi-manager] PANIC'
            'KERNEL PANIC'
        )
        ;;
esac

for marker in "${required[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing ACPI $scenario marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

for marker in "${forbidden[@]}"; do
    if grep -Fq "$marker" "$log"; then
        echo "forbidden ACPI $scenario marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

echo "ACPI manager restart smoke passed: scenario=$scenario profile=$profile smp=$cpus"
