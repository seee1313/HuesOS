#!/usr/bin/env bash
# Run Clippy over the kernel workspace and every standalone userspace program.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
LOG="$TMP/clippy.log"

cleanup_and_report() {
    local status=$?
    if [[ $status -ne 0 && "${GITHUB_ACTIONS:-}" == "true" && -f "$LOG" ]]; then
        python3 - "$LOG" << 'PY' || true
import re, sys
lines = open(sys.argv[1], errors="replace").read().splitlines()
blocks, cur = [], []
for line in lines:
    if line.startswith("error"):
        if cur:
            blocks.append(cur)
        cur = [line]
    elif cur:
        if line.startswith((" ", "\t", "-->", "=")) or re.match(r"^\d+\s*\|", line) or line == "":
            cur.append(line)
        else:
            blocks.append(cur)
            cur = []
if cur:
    blocks.append(cur)
if blocks:
    for b in blocks[-5:]:
        text = "\n".join(b[:25])
        m = re.search(r"-->\s+([^:\s]+):(\d+):(\d+)", text)
        esc = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        if m:
            print(f"::error file={m.group(1)},line={m.group(2)},col={m.group(3)},title=clippy::{esc}")
        else:
            print(f"::error title=clippy::{esc}")
else:
    tail = "\n".join(lines[-25:]).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title=clippy::{tail}")
PY
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup_and_report EXIT

run_clippy_suite() {
    set -euo pipefail

    # Standalone userspace crates are linted explicitly below; skip rebuilding
    # and linking all 20+ userspace ELF/PE images inside huesos-kernel/build.rs
    # while type-checking the kernel workspace.
    export HUESOS_CLIPPY_PLACEHOLDER_USERSPACE=1

    cargo clippy --workspace --lib --bins \
        -Z build-std=core,compiler_builtins,alloc \
        -Z build-std-features=compiler-builtins-mem -- -D warnings

    cargo clippy -p huesos-boot --features boot-selftest \
        -Z build-std=core,compiler_builtins,alloc \
        -Z build-std-features=compiler-builtins-mem -- -D warnings

    cargo clippy -p huesos-rtw88 --features boot-selftest \
        -Z build-std=core,compiler_builtins,alloc \
        -Z build-std-features=compiler-builtins-mem -- -D warnings

    # Production-only Clippy does not compile integration/unit test targets.
    # Keep a separate rustc warning gate for host-testable targets so unused
    # imports and other ordinary warnings in tests cannot hide behind a green
    # Clippy run.
    RUSTFLAGS="-D warnings" cargo check --workspace --tests --exclude huesos-boot \
        --target x86_64-unknown-linux-gnu

    # Standalone userspace crates use include_bytes!(env!(...)) paths normally
    # supplied by huesos-kernel/build.rs. Clippy only type-checks these
    # binaries, so empty, short-lived placeholders are sufficient and avoid
    # rebuilding all dependency ELFs merely to lint source.
    for name in driver-manager terminal doom fault-probe dyn-c-smoke dyn-rust-smoke bootfs input-host nvme-host hxfs-service acpi-manager shutdown-broker key-broker; do
        : > "$TMP/$name"
    done

    (
        cd crates/huesos-userspace/libcanvas
        cargo clippy --release --target ../x86_64-huesos-userspace.json \
            -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem -Z json-target-spec -- -D warnings
        cargo clippy --release --no-default-features --features dyn-client \
            --target ../x86_64-huesos-userspace-dyn.json \
            -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem -Z json-target-spec -- -D warnings
        cargo clippy --release --features c-abi \
            --target ../x86_64-huesos-userspace-dyn.json \
            -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem -Z json-target-spec -- -D warnings
    )

    (
        cd crates/huesos-userspace/init
        HUESOS_DRIVER_MANAGER_PATH="$TMP/driver-manager" \
        HUESOS_TERMINAL_PATH="$TMP/terminal" \
        HUESOS_ACPI_MANAGER_PATH="$TMP/acpi-manager" \
        HUESOS_SHUTDOWN_BROKER_PATH="$TMP/shutdown-broker" \
        HUESOS_KEY_BROKER_PATH="$TMP/key-broker" \
            cargo clippy --release -- -D warnings
        HUESOS_DRIVER_MANAGER_PATH="$TMP/driver-manager" \
        HUESOS_TERMINAL_PATH="$TMP/terminal" \
        HUESOS_FAULT_PROBE_PATH="$TMP/fault-probe" \
        HUESOS_DYN_C_SMOKE_PATH="$TMP/dyn-c-smoke" \
        HUESOS_DYN_RUST_SMOKE_PATH="$TMP/dyn-rust-smoke" \
        HUESOS_ACPI_MANAGER_PATH="$TMP/acpi-manager" \
        HUESOS_SHUTDOWN_BROKER_PATH="$TMP/shutdown-broker" \
        HUESOS_KEY_BROKER_PATH="$TMP/key-broker" \
            cargo clippy --release --features boot-selftest -- -D warnings
    )

    (
        cd crates/huesos-userspace/driver-manager
        HUESOS_INPUT_DRIVER_HOST_PATH="$TMP/input-host" \
            cargo clippy --release -- -D warnings
        HUESOS_INPUT_DRIVER_HOST_PATH="$TMP/input-host" \
            cargo clippy --release --features acpi-restart-smoke -- -D warnings
        HUESOS_INPUT_DRIVER_HOST_PATH="$TMP/input-host" \
            cargo clippy --release --features acpi-restart-budget-smoke -- -D warnings
        HUESOS_INPUT_DRIVER_HOST_PATH="$TMP/input-host" \
            cargo clippy --release --features pci-force-legacy -- -D warnings
    )

    for program in driver-host-input driver-host-nvme driver-host-xhci hxfs-service net-service wlan-service terminal doom fdisk hsh-bin huesos-std coreutils fault-probe dyn-rust-smoke acpi-manager uacpi-runtime pci-manager shutdown-broker key-broker ld-huesos ld-pe; do
        (
            cd "crates/huesos-userspace/$program"
            cargo clippy --release -- -D warnings
        )
    done

    (
        cd crates/huesos-userspace/win64-runtime
        cargo clippy --release --workspace -- -D warnings
    )

    (
        cd crates/huesos-userspace/pci-manager
        cargo clippy --release --features force-legacy -- -D warnings
    )

    (
        cd crates/huesos-userspace/acpi-manager
        cargo clippy --release --features restart-smoke -- -D warnings
    )

    (
        cd crates/huesos-userspace/wlan-service
        cargo clippy --release --features boot-selftest -- -D warnings
    )

    (
        cd crates/huesos-userspace/hsh-bin
        cargo clippy --release --features boot-selftest -- -D warnings
    )
}

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    ( run_clippy_suite ) 2>&1 | tee "$LOG"
else
    run_clippy_suite
fi
