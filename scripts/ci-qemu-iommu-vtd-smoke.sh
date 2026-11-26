#!/usr/bin/env bash
# End-to-end Intel VT-d hardware IOMMU (`PCI Isolated Profile`) QEMU smoke.
#
# Builds the HBI ISO once with `iommu_test=1` (`HUESOS_BOOT_SELFTEST=1`), seeds
# a 64 MiB HxFS v7 NVMe disk image, and runs two boots on the same artifact:
#
#   1. `vtd-isolated`: Q35 + `-device intel-iommu,intremap=off,caching-mode=on`
#      + `-device edu,dma_mask=0xffffffffffffffff` + NVMe + modern VirtIO 1.0
#      (`iommu_platform=on`). Verifies:
#        - Ring-0 VT-d bring-up (`[iommu] Intel VT-d active: ... mode=Isolated`)
#        - Live `edu` hardware DMA probe: authorized SLPT DMA succeeds,
#          unmapped IOVA write is blocked by VT-d (`FRCD` fault logged, canary
#          untouched), and post-`DeviceLease::revoke()` DMA is blocked (`FRCD`
#          fault logged)
#        - `acpi-manager` `HIOM` `active_mode=Isolated`
#        - `pci-manager` `obs i2-dma ... isolation=IommuDomain`
#        - `driver-manager` `bound DMA grant to IOMMU domain=`
#        - Ring-3 NVMe + `hxfs-service` mount and VirtIO 1.0 modern MMIO DMA
#          over live VT-d SLPT translation
#
#   2. `trusted-fallback`: same Q35 guest without `-device intel-iommu`.
#      Verifies clean fail-closed fallback to `Trusted` mode (`vtd` inactive,
#      `obs i2-dma ... isolation=Trusted`, NVMe + VirtIO-Net healthy).
#
# Usage: ci-qemu-iommu-vtd-smoke.sh [profile=release] [cpus=2] [timeout=150]
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-150}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir" build

vtd_log="$artifact_dir/qemu-iommu-vtd-${profile}-smp${cpus}.log"
amdvi_log="$artifact_dir/qemu-iommu-amdvi-${profile}-smp${cpus}.log"
fallback_log="$artifact_dir/qemu-iommu-fallback-${profile}-smp${cpus}.log"
nvme_img="build/nvme-iommu-vtd.img"
rm -f "$vtd_log" "$amdvi_log" "$fallback_log" "$nvme_img"

annotate_failure() {
    local leg="$1"
    local reason="$2"
    local log_path="$3"
    printf '::error::ci-qemu-iommu-vtd-smoke (%s): %s (profile=%s smp=%s)\n' \
        "$leg" "$reason" "$profile" "$cpus"
    while IFS= read -r line; do
        printf '::error::serial| %s\n' "$line"
    done < <(tail -n 12 "$log_path" 2>/dev/null || true)
}

echo "iommu_test=1" > build/cmdline.txt
trap 'echo "init_args=foo" > build/cmdline.txt' EXIT

build_log="build/iommu-smoke-build.log"
set +e
case "$profile" in
    debug)   HUESOS_BOOT_SELFTEST=1 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug >"$build_log" 2>&1 ;;
    release) HUESOS_BOOT_SELFTEST=1 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release >"$build_log" 2>&1 ;;
    *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac
build_status=$?
set -e
if [[ "$build_status" != 0 ]]; then
    cat "$build_log" >&2 || true
    while IFS= read -r line; do
        printf '::error::build| %s\n' "$line"
    done < <(grep -E 'error(\[E[0-9]+\])?:|-->' "$build_log" | head -n 25 || tail -n 20 "$build_log")
    exit "$build_status"
fi

# Create a 64 MiB (16384 * 4 KiB blocks) plain HxFS volume for NVMe DMA smoke.
python3 tools/mkhxfs.py --output "$nvme_img" --blocks 16384 >/dev/null

echo "[iommu-smoke] Leg 1/2: booting Q35 with intel-iommu (caching-mode=on) + edu + NVMe + virtio-net (iommu_platform=on)"
set +e
timeout "${timeout_seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -device intel-iommu,intremap=off,caching-mode=on \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -device edu,dma_mask=0xffffffffffffffff \
    -drive "id=nvme0,if=none,format=raw,file=${nvme_img}" \
    -device nvme,serial=huesosnvme,id=nvme-ctrl \
    -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1 \
    -netdev user,id=n0 \
    -device virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off,iommu_platform=on \
    -display none -serial "file:$vtd_log" \
    -no-reboot -no-shutdown
status=$?
set -e

if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU (vtd-isolated) exited unexpectedly with status $status" >&2
    annotate_failure "vtd-isolated" "QEMU exited with status $status" "$vtd_log"
    tail -200 "$vtd_log" >&2 || true
    exit 1
fi
if grep -Fq 'KERNEL PANIC' "$vtd_log" || grep -Fq '[iommu-test] FAILED:' "$vtd_log"; then
    echo "panic or iommu-test failure detected in vtd-isolated leg" >&2
    annotate_failure "vtd-isolated" "panic or [iommu-test] FAILED detected" "$vtd_log"
    tail -200 "$vtd_log" >&2
    exit 1
fi

vtd_markers=(
    '[iommu] Intel VT-d active:'
    'mode=Isolated'
    '[iommu-test] authorized DeviceLease DMA read/write OK'
    '[iommu-test] unmapped canary DMA blocked by hardware VT-d OK'
    '[iommu-test] post-revoke DMA blocked after synchronous IOTLB flush OK'
    '[iommu-test] Intel VT-d hardware isolation self-test OK'
    '[acpi-manager] published HIOM'
    'active_isolation=Isolated'
    'isolation=IommuDomain'
    '[driver-manager] attached DmaPool to DeviceLease for'
    '[hxfs] service started'
    '[net-service] virtio-net 1.0 modern MMIO online'
)

for marker in "${vtd_markers[@]}"; do
    if ! grep -Fq "$marker" "$vtd_log"; then
        echo "missing vtd-isolated marker: $marker" >&2
        annotate_failure "vtd-isolated" "missing marker: $marker" "$vtd_log"
        tail -200 "$vtd_log" >&2
        exit 1
    fi
done
echo "[iommu-smoke] Leg 1/3 PASS ($vtd_log)"

# Recreate clean HxFS image for Leg 2 (AMD-Vi hardware isolation).
rm -f "$nvme_img"
python3 tools/mkhxfs.py --output "$nvme_img" --blocks 16384 >/dev/null

echo "[iommu-smoke] Leg 2/3: booting Q35 with amd-iommu (intremap=off) + edu + NVMe + virtio-net (iommu_platform=on)"
set +e
timeout "${timeout_seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -device amd-iommu,intremap=off \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -device edu,dma_mask=0xffffffffffffffff \
    -drive "id=nvme0,if=none,format=raw,file=${nvme_img}" \
    -device nvme,serial=huesosnvme,id=nvme-ctrl \
    -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1 \
    -netdev user,id=n0 \
    -device virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off,iommu_platform=on \
    -display none -serial "file:$amdvi_log" \
    -no-reboot -no-shutdown
status=$?
set -e

if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU (amd-vi-isolated) exited unexpectedly with status $status" >&2
    annotate_failure "amd-vi-isolated" "QEMU exited with status $status" "$amdvi_log"
    tail -200 "$amdvi_log" >&2 || true
    exit 1
fi
if grep -Fq 'KERNEL PANIC' "$amdvi_log" || grep -Fq '[iommu-test] FAILED:' "$amdvi_log"; then
    echo "panic or iommu-test failure detected in amd-vi-isolated leg" >&2
    annotate_failure "amd-vi-isolated" "panic or [iommu-test] FAILED detected" "$amdvi_log"
    tail -200 "$amdvi_log" >&2
    exit 1
fi

amdvi_markers=(
    '[iommu] AMD-Vi active:'
    'mode=Isolated'
    '[iommu-test] authorized DeviceLease DMA read/write OK'
    '[iommu-test] unmapped canary DMA blocked by hardware AMD-Vi OK'
    '[iommu-test] post-revoke DMA blocked after synchronous IOTLB flush OK'
    '[iommu-test] AMD-Vi hardware isolation self-test OK'
    '[acpi-manager] published HIOM'
    'active_isolation=Isolated'
    'isolation=IommuDomain'
    '[driver-manager] attached DmaPool to DeviceLease for'
    '[hxfs] service started'
    '[net-service] virtio-net 1.0 modern MMIO online'
)

for marker in "${amdvi_markers[@]}"; do
    if ! grep -Fq "$marker" "$amdvi_log"; then
        echo "missing amd-vi-isolated marker: $marker" >&2
        annotate_failure "amd-vi-isolated" "missing marker: $marker" "$amdvi_log"
        tail -200 "$amdvi_log" >&2
        exit 1
    fi
done
echo "[iommu-smoke] Leg 2/3 PASS ($amdvi_log)"

# Recreate clean HxFS image for Leg 3 so journal/mount state starts fresh.
rm -f "$nvme_img"
python3 tools/mkhxfs.py --output "$nvme_img" --blocks 16384 >/dev/null

echo "[iommu-smoke] Leg 3/3: booting Q35 without IOMMU (Trusted fallback verification)"
set +e
timeout "${timeout_seconds}s" qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -drive "id=nvme0,if=none,format=raw,file=${nvme_img}" \
    -device nvme,serial=huesosnvme,id=nvme-ctrl \
    -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1 \
    -netdev user,id=n0 \
    -device virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off \
    -display none -serial "file:$fallback_log" \
    -no-reboot -no-shutdown
status=$?
set -e

if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "QEMU (trusted-fallback) exited unexpectedly with status $status" >&2
    annotate_failure "trusted-fallback" "QEMU exited with status $status" "$fallback_log"
    tail -200 "$fallback_log" >&2 || true
    exit 1
fi
if grep -Fq 'KERNEL PANIC' "$fallback_log"; then
    echo "kernel panic detected in trusted-fallback leg" >&2
    annotate_failure "trusted-fallback" "kernel panic detected" "$fallback_log"
    tail -200 "$fallback_log" >&2
    exit 1
fi
if grep -Fq '[iommu] Intel VT-d active:' "$fallback_log" || grep -Fq '[iommu] AMD-Vi active:' "$fallback_log"; then
    echo "unexpected IOMMU activation without DMAR/IVRS in trusted-fallback leg" >&2
    annotate_failure "trusted-fallback" "IOMMU reported active without DMAR/IVRS" "$fallback_log"
    tail -200 "$fallback_log" >&2
    exit 1
fi

fallback_markers=(
    '[iommu-test] FAILED: hardware IOMMU translation is not active'
    'active_isolation=Trusted'
    'isolation=Trusted'
    '[hxfs] service started'
    '[net-service] virtio-net 1.0 modern MMIO online'
)

for marker in "${fallback_markers[@]}"; do
    if ! grep -Fq "$marker" "$fallback_log"; then
        echo "missing trusted-fallback marker: $marker" >&2
        annotate_failure "trusted-fallback" "missing marker: $marker" "$fallback_log"
        tail -200 "$fallback_log" >&2
        exit 1
    fi
done

echo "[iommu-smoke] Leg 3/3 PASS ($fallback_log)"
echo "ci-qemu-iommu-vtd-smoke PASS ($profile, smp=$cpus)"
