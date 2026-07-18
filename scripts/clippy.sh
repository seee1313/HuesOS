#!/usr/bin/env bash
# Run Clippy over the kernel workspace and every standalone userspace program.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo clippy --workspace --lib --bins -- -D warnings

# Standalone userspace crates use include_bytes!(env!(...)) paths normally
# supplied by huesos-kernel/build.rs. Clippy only type-checks these binaries, so
# empty, short-lived placeholders are sufficient and avoid rebuilding all
# dependency ELFs merely to lint source.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
for name in driver-manager terminal doom fault-probe bootfs input-host; do
    : > "$TMP/$name"
done

(
    cd crates/huesos-userspace/init
    HUESOS_DRIVER_MANAGER_PATH="$TMP/driver-manager" \
    HUESOS_TERMINAL_PATH="$TMP/terminal" \
    HUESOS_FAULT_PROBE_PATH="$TMP/fault-probe" \
        cargo clippy --release -- -D warnings
)

(
    cd crates/huesos-userspace/driver-manager
    HUESOS_INPUT_DRIVER_HOST_PATH="$TMP/input-host" \
        cargo clippy --release -- -D warnings
)

for program in driver-host-input terminal doom fault-probe; do
    (
        cd "crates/huesos-userspace/$program"
        cargo clippy --release -- -D warnings
    )
done
