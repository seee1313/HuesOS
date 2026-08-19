#!/usr/bin/env bash
# Storage kill-switch smoke: boot QEMU with a real NVMe device AND
# `init.storage=off` in the HBI command line. The kernel must not
# program the controller; the backing image must be bit-identical
# after the guest runs; userspace must still reach the terminal.
#
# Usage: ci-qemu-storage-off-smoke.sh [profile=release] [cpus=2] [timeout=120]
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir" build
log="$artifact_dir/qemu-storage-off-${profile}-smp${cpus}.log"
img="${NVME_IMG:-build/storage-off-nvme.img}"
rm -f "$log"

# Fresh 64 MiB raw namespace. Small enough to hash quickly; large
# enough for QEMU's NVMe device to accept it.
dd if=/dev/zero of="$img" bs=1M count=64 status=none
sha_before="$(sha256sum "$img" | awk '{print $1}')"

# Same cmdline pattern as the extable smoke: write the token, restore
# the placeholder so a later `make iso` does not inherit the switch.
echo "init.storage=off" > build/cmdline.txt
trap 'echo "init_args=foo" > build/cmdline.txt' EXIT

case "$profile" in
    debug)   CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug ;;
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release ;;
    *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac

set +e
timeout "${timeout_seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -drive id=nvme0,if=none,format=raw,file="$img" \
    -device nvme,serial=huesosnvme,drive=nvme0 \
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
    echo "kernel panic detected during storage-off smoke" >&2
    tail -200 "$log" >&2
    exit 1
fi

for marker in \
    '[storage] disabled by init.storage=off' \
    '[init] storage disabled by init.storage=off' \
    '[init] hello from ring3 userspace, via libcanvas' \
    '[init] launched terminal'; do
    if ! grep -Fq "$marker" "$log"; then
        echo "missing storage-off marker: $marker" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

for regression in \
    '[storage] nvme0 ' \
    '[driver-host:nvme] identified' \
    '[init] NVMe boot grants: pci='; do
    if grep -Fq "$regression" "$log"; then
        echo "storage-off regression marker present: $regression" >&2
        tail -200 "$log" >&2
        exit 1
    fi
done

sha_after="$(sha256sum "$img" | awk '{print $1}')"
if [[ "$sha_before" != "$sha_after" ]]; then
    echo "NVMe image changed under init.storage=off" >&2
    echo "  before $sha_before" >&2
    echo "  after  $sha_after" >&2
    exit 1
fi

echo "QEMU storage-off smoke passed: profile=$profile smp=$cpus image=$sha_after"
