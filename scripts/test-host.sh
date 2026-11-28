#!/usr/bin/env bash
# Run the host unit test suite across all host-testable workspace crates and
# surface any failure details as GitHub Actions annotations when running in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
LOG="$TMP/host-tests.log"

cleanup_and_report() {
    local status=$?
    if [[ $status -ne 0 && "${GITHUB_ACTIONS:-}" == "true" && -f "$LOG" ]]; then
        python3 - "$LOG" << 'PY' || true
import re, sys
lines = open(sys.argv[1], errors="replace").read().splitlines()

hits = []
for i, line in enumerate(lines):
    if (
        "panicked at" in line
        or line.startswith("error")
        or line.endswith("... FAILED")
        or line.startswith("---- ")
        or "failures:" in line
    ):
        start = max(0, i - 2)
        end = min(len(lines), i + 12)
        hits.append("\n".join(lines[start:end]))

if hits:
    for chunk in hits[-15:]:
        esc = chunk.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=host-tests::{esc}")

tail = "\n".join(lines[-40:]).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title=host-tests-tail::{tail}")
PY
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup_and_report EXIT

run_host_tests() {
    # The 16 MiB host test mounts a writer with an 8192-extent fixed
    # array on the stack; the default test-thread stack overflows
    # when the hxblob index field is also present. 16 MiB is enough.
    RUST_MIN_STACK=16777216 cargo test --no-fail-fast \
        -p huesos-abi -p huesos-arch -p huesos-sync -p huesos-elf -p huesos-pmm -p huesos-object -p huesos-fb \
        -p huesos-syscalls -p huesos-fat -p huesos-alloc -p huesos-uacpi -p huesos-kernel \
        -p huesos-scudo \
        -p huesos-scudo-fuzz \
        -p huesos-blobfs \
        -p huesos-bootux \
        -p huesos-lifecycle \
        -p huesos-sched \
        -p huesos-iommu \
        -p huesos-ioapic \
        -p huesos-extable \
        -p huesos-waitset \
        -p huesos-proclife \
        -p huesos-handlemove \
        -p hues-async \
        -p huesos-nvme \
        -p huesos-usb \
        -p huesos-hxfs \
        -p huesos-hxfs-proto \
        -p huesos-pci \
        -p huesos-quota \
        -p huesos-tpm \
        -p huesos-hsh \
        -p huesos-gpt \
        -p huesos-pe \
        -p huesos-net \
        -p huesos-ieee80211 \
        -p huesos-wpa \
        -p huesos-rtw88 \
        -p huesos-tls \
        -p huesos-bt \
        -p huesos-audio \
        --target x86_64-unknown-linux-gnu
}

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    ( run_host_tests ) 2>&1 | tee "$LOG"
else
    run_host_tests
fi
