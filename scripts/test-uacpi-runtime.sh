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
