#!/usr/bin/env bash
set -euo pipefail

profile="${1:-release}"
seconds="${2:-300}"
log="${3:-build/qemu-nvme-soak.log}"
nvme_img="${NVME_IMG:-build/nvme-soak.img}"
nvme_size="${NVME_IMG_SIZE:-4G}"
ovmf="${OVMF_PATH:-third_party/ovmf/OVMF.fd}"
nvme_layout="${QEMU_NVME_LAYOUT:-split}"

mkdir -p build "$(dirname "$log")" "$(dirname "$nvme_img")"
rm -f "$log"

echo "[soak] profile=${profile} seconds=${seconds} log=${log} nvme_img=${nvme_img} layout=${nvme_layout}"
echo "[soak] building ISO before NVMe soak"
case "$profile" in
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release >/tmp/huesos-nvme-soak-build.log ;;
    debug) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug >/tmp/huesos-nvme-soak-build.log ;;
    *) echo "[soak] unsupported profile: $profile" >&2; exit 2 ;;
esac

# This script is a production-gate harness. It is intentionally conservative:
# it records the command shape and validates storage markers when QEMU is
# available in the runner. Local sandboxes may not have qemu-system-x86_64.
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "[soak] qemu-system-x86_64 unavailable; skipping runtime soak" | tee "$log"
    exit 0
fi

if [[ ! -f "$ovmf" ]]; then
    echo "[soak] OVMF firmware missing at $ovmf" >&2
    echo "[soak] set OVMF_PATH=/path/to/OVMF.fd if your distro uses another path" >&2
    exit 1
fi

if [[ ! -f "$nvme_img" ]]; then
    echo "[soak] creating NVMe raw image: $nvme_img ($nvme_size)"
    if command -v qemu-img >/dev/null 2>&1; then
        qemu-img create -f raw "$nvme_img" "$nvme_size" >/dev/null
    else
        truncate -s "$nvme_size" "$nvme_img"
    fi
fi

qemu_common=(
    -machine q35
    -cpu qemu64
    -smp 2
    -m 512M
    -bios "$ovmf"
    -cdrom build/huesos.iso
    -drive id=nvme0,if=none,format=raw,file="$nvme_img"
    -net none
    -display none
    -serial "file:$log"
    -no-reboot -no-shutdown
)

qemu_nvme=()
case "$nvme_layout" in
    split)
        # Modern QEMU model: create controller and namespace explicitly. This
        # avoids booting a controller with no active namespace on hosts where
        # the legacy `drive=` shortcut is not accepted as a namespace.
        qemu_nvme=(-device nvme,serial=huesosnvme,id=nvme-ctrl -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1)
        ;;
    legacy)
        qemu_nvme=(-device nvme,serial=huesosnvme,drive=nvme0)
        ;;
    *)
        echo "[soak] unsupported QEMU_NVME_LAYOUT=$nvme_layout (use split or legacy)" >&2
        exit 2
        ;;
esac

set +e
timeout "${seconds}s" qemu-system-x86_64 "${qemu_common[@]}" "${qemu_nvme[@]}"
status=$?
set -e

# A healthy OS intentionally keeps running, so timeout(1)'s 124 is expected.
if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "[soak] QEMU exited unexpectedly with status $status" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi

if grep -Fq 'KERNEL PANIC' "$log" || grep -Fq '[hxfs] PANIC' "$log"; then
    echo "[soak] panic marker detected" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi

required=(
    "[driver-host:nvme]"
    "service:block:nvme"
    "[hxfs] service started"
)
for marker in "${required[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "[soak] missing marker: $marker" >&2
        echo "[soak] last 200 serial lines:" >&2
        tail -200 "$log" >&2 || true
        exit 1
    fi
done

echo "[soak] markers present"
