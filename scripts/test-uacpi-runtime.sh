#!/usr/bin/env bash
# Link and execute the complete AP-3 userspace uACPI source set under host
# sanitizers. The scaffold must expose every host symbol while denying every
# privileged callback and refusing successful subsystem initialization.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/third_party/uacpi"
RUNTIME="$ROOT/crates/huesos-userspace/uacpi-runtime"
CC_BIN="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sources=(
    tables.c
    types.c
    uacpi.c
    utilities.c
    interpreter.c
    opcodes.c
    namespace.c
    stdlib.c
    shareable.c
    opregion.c
    default_handlers.c
    io.c
    notify.c
    sleep.c
    registers.c
    resources.c
    event.c
    mutex.c
    osi.c
)
args=()
for source in "${sources[@]}"; do
    args+=("$VENDOR/source/$source")
done

"$CC_BIN" \
    -std=c11 -O1 -g -Wall -Wextra -Werror \
    -fno-omit-frame-pointer -fsanitize=address,undefined \
    -DUACPI_USE_BUILTIN_STRING \
    -DUACPI_DEFAULT_LOG_LEVEL=UACPI_LOG_INFO \
    -I"$VENDOR/include" \
    "${args[@]}" \
    "$RUNTIME/src/host_stubs.c" \
    "$RUNTIME/tests/fail_closed_smoke.c" \
    -o "$TMP/uacpi-runtime-smoke"

ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    "$TMP/uacpi-runtime-smoke"

echo "uACPI full-runtime fail-closed ASan/UBSan smoke passed"

# AP-10: the Rust PCI_CONFIG callback family replaces the C stubs in the
# userspace target. Assert each symbol is defined exactly once in the
# compiled Rust rlib so a signature drift cannot hide behind an
# unresolved-at-link error two AP stages later.
export PATH="$HOME/.cargo/bin:$PATH"
(
    cd "$RUNTIME"
    cargo build --release >/dev/null
)
RLIB="$(ls -t "$RUNTIME"/target/x86_64-huesos-userspace/release/deps/libhuesos_uacpi_runtime-*.rlib | head -1)"
for symbol in \
    uacpi_kernel_pci_device_open \
    uacpi_kernel_pci_device_close \
    uacpi_kernel_pci_read8 \
    uacpi_kernel_pci_read16 \
    uacpi_kernel_pci_read32 \
    uacpi_kernel_pci_write8 \
    uacpi_kernel_pci_write16 \
    uacpi_kernel_pci_write32; do
    count="$(nm "$RLIB" 2>/dev/null | grep -c " T $symbol")"
    if [ "$count" != "1" ]; then
        echo "uacpi-runtime symbol gate failed: $symbol defined $count times" >&2
        exit 1
    fi
done
echo "uacpi-runtime PCI callback symbol gate passed"
