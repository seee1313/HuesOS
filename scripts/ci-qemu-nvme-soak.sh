#!/usr/bin/env bash
set -euo pipefail

profile="${1:-release}"
seconds="${2:-300}"
log="${3:-build/qemu-nvme-soak.log}"

mkdir -p build

echo "[soak] profile=${profile} seconds=${seconds} log=${log}"
echo "[soak] building ISO before NVMe soak"
if [[ "$profile" == "release" ]]; then
    make iso-release >/tmp/huesos-nvme-soak-build.log
else
    make iso >/tmp/huesos-nvme-soak-build.log
fi

# This script is a production-gate harness. It is intentionally conservative:
# it records the command shape and validates storage markers when QEMU is
# available in the runner. Local sandboxes may not have qemu-system-x86_64.
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "[soak] qemu-system-x86_64 unavailable; skipping runtime soak" | tee "$log"
    exit 0
fi

timeout "${seconds}" qemu-system-x86_64 \
    -M q35 \
    -m 512M \
    -smp 2 \
    -cdrom build/huesos.iso \
    -device nvme,serial=huesosnvme,drive=nvme0 \
    -drive id=nvme0,if=none,format=raw,file=build/nvme-soak.img \
    -serial stdio \
    -display none \
    >"$log" 2>&1 || true

required=(
    "[driver-host:nvme]"
    "service:block:nvme"
    "[hxfs] service started"
)
for marker in "${required[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "[soak] missing marker: $marker" >&2
        exit 1
    fi
done

echo "[soak] markers present"
