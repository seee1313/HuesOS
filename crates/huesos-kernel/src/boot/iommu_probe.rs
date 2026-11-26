//! Boot-time live Intel VT-d hardware DMA isolation self-test (`iommu_test=1`).
//!
//! Drives QEMU's `edu` PCI bus-mastering DMA engine (`1234:11e8`) through a real
//! kernel [`DeviceLease`] while hardware Intel VT-d second-stage translation is
//! active (`GSTS.TES == 1`), proving all Stage N.2 exit criteria on target:
//! 1. DMA reads and writes inside the lease's attached 4 KiB `DmaPool` frame
//!    succeed with zero hardware faults;
//! 2. an unauthorized DMA write targeting an unmapped kernel canary frame is
//!    blocked in hardware (canary untouched) and recorded in `FRCD_REG` with
//!    `FaultKind::WriteNotPermitted`;
//! 3. `DeviceLease::revoke` synchronously clears the VT-d Context Entry and
//!    flushes Context Cache + IOTLB before returning, so a subsequent DMA write
//!    to the previously authorized frame is blocked in hardware and recorded
//!    with `FaultKind::ContextNotPresent`.

use core::fmt::Write;

use huesos_abi::pci_lease::pack_pci_address;
use huesos_iommu::{FaultKind, FaultRecord};
use huesos_object::{unregister_object, DeviceLease, KernelObject};

const EDU_DMA_SRC_OFFSET: u64 = 0x80;
const EDU_DMA_DST_OFFSET: u64 = 0x88;
const EDU_DMA_CNT_OFFSET: u64 = 0x90;
const EDU_DMA_CMD_OFFSET: u64 = 0x98;
const EDU_INTERNAL_DMA_BUF: u64 = 0x4_0000;

const EDU_DMA_RUN: u64 = 1 << 0;
const EDU_DMA_DIR_TO_PCI: u64 = 1 << 1;

const DMA_TIMEOUT_TICKS: u64 = 300;
const AUTHORIZED_PATTERN: u64 = 0xDEAD_C0DE_5AFE_D47A;
const AUTHORIZED_SENTINEL_A: u64 = 0x1111_1111_1111_1111;
const AUTHORIZED_SENTINEL_B: u64 = 0x2222_2222_2222_2222;
const CANARY_SENTINEL: u64 = 0xCAFE_BABE_DEAD_BEEF;

/// Run the live hardware IOMMU DMA isolation probe (Intel VT-d or AMD-Vi) and log structured markers.
pub fn run() {
    let mut writer = huesos_arch::serial::SerialWriter;
    match probe() {
        Ok(hw_label) => {
            let _ = writeln!(
                writer,
                "[iommu-test] {hw_label} hardware isolation self-test OK"
            );
        }
        Err(reason) => {
            let _ = writeln!(writer, "[iommu-test] FAILED: {reason}");
        }
    }
}

fn probe() -> Result<&'static str, &'static str> {
    use huesos_abi::pci_iommu::IommuHardwareKind;

    let hw_label = match huesos_arch::iommu::active_kind() {
        IommuHardwareKind::IntelVtd => "Intel VT-d",
        IommuHardwareKind::AmdVi => "AMD-Vi",
        IommuHardwareKind::None => {
            return Err("hardware IOMMU translation is not active");
        }
    };
    let (location, bar0_va) = super::irq_probe::prepare_edu_for_selftest()?;
    let packed_addr = pack_pci_address(
        location.segment(),
        location.bus(),
        location.device(),
        location.function(),
    )
    .ok_or("invalid edu PCI address")?;
    let edu_bdf = (u16::from(location.bus()) << 8)
        | (u16::from(location.device()) << 3)
        | u16::from(location.function());

    let auth_phys = huesos_pmm::alloc_frame().map_err(|_| "auth frame alloc failed")?;
    let canary_phys = match huesos_pmm::alloc_frame() {
        Ok(frame) => frame,
        Err(_) => {
            huesos_pmm::free_frame(auth_phys);
            super::irq_probe::quiesce_edu_bus_master(location);
            return Err("canary frame alloc failed");
        }
    };

    let result = run_with_frames(
        bar0_va,
        packed_addr,
        edu_bdf,
        auth_phys,
        canary_phys,
        huesos_arch::iommu::active_kind(),
    );

    super::irq_probe::quiesce_edu_bus_master(location);
    huesos_pmm::free_frame(auth_phys);
    huesos_pmm::free_frame(canary_phys);
    result.map(|()| hw_label)
}

fn run_with_frames(
    bar0_va: u64,
    packed_addr: u64,
    edu_bdf: u16,
    auth_phys: u64,
    canary_phys: u64,
    hw_kind: huesos_abi::pci_iommu::IommuHardwareKind,
) -> Result<(), &'static str> {
    phys_write64(auth_phys, AUTHORIZED_PATTERN);
    phys_write64(auth_phys + 64, AUTHORIZED_SENTINEL_A);
    phys_write64(auth_phys + 128, AUTHORIZED_SENTINEL_B);
    phys_write64(canary_phys, CANARY_SENTINEL);

    let mut faults = [empty_fault(); 4];
    let _ = huesos_arch::iommu::drain_faults(&mut faults);

    let lease = DeviceLease::try_create(0xED00_0001, 1, packed_addr)
        .map_err(|_| "DeviceLease::try_create failed")?;
    if lease.attach_dma_range(1, auth_phys, 4096).is_err() {
        unregister_object(lease.koid());
        return Err("DeviceLease::attach_dma_range failed");
    }

    // 1. Authorized PCI -> EDU DMA read followed by EDU -> PCI DMA write inside `auth_phys`.
    if let Err(reason) = run_edu_dma(bar0_va, auth_phys, EDU_INTERNAL_DMA_BUF, 8, EDU_DMA_RUN) {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err(reason);
    }
    if let Err(reason) = run_edu_dma(
        bar0_va,
        EDU_INTERNAL_DMA_BUF,
        auth_phys + 64,
        8,
        EDU_DMA_RUN | EDU_DMA_DIR_TO_PCI,
    ) {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err(reason);
    }
    if phys_read64(auth_phys + 64) != AUTHORIZED_PATTERN {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err("authorized DMA write did not land in leased frame");
    }
    if huesos_arch::iommu::drain_faults(&mut faults) != 0 {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err("unexpected IOMMU fault during authorized DMA");
    }
    log_line("[iommu-test] authorized DeviceLease DMA read/write OK");

    // 2. Unauthorized EDU -> PCI DMA write targeting unmapped kernel `canary_phys`.
    if let Err(reason) = run_edu_dma(
        bar0_va,
        EDU_INTERNAL_DMA_BUF,
        canary_phys,
        8,
        EDU_DMA_RUN | EDU_DMA_DIR_TO_PCI,
    ) {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err(reason);
    }
    if phys_read64(canary_phys) != CANARY_SENTINEL {
        let _ = lease.revoke(1, true);
        unregister_object(lease.koid());
        return Err("SECURITY FAILURE: unmapped canary frame modified by unauthorized DMA");
    }
    let canary_faults = huesos_arch::iommu::drain_faults(&mut faults);
    match hw_kind {
        huesos_abi::pci_iommu::IommuHardwareKind::AmdVi => {
            // Real AMD-Vi silicon logs `IO_PAGE_FAULT` (`PR=0`) on unmapped PTEs, whereas
            // QEMU 8.2 `amdvi_page_walk` (`if (!pte) return;`) blocks the DMA write with
            // `IOMMU_NONE` without emitting an event when a PTE is zero. If an event was
            // emitted, verify it matches `edu_bdf` and `canary_phys`.
            if canary_faults > 0 {
                let ok = faults[..canary_faults].iter().any(|f| {
                    f.source_bdf == edu_bdf
                        && (f.fault_iova == 0 || (f.fault_iova & !0xFFF) == canary_phys)
                });
                if !ok {
                    let _ = lease.revoke(1, true);
                    unregister_object(lease.koid());
                    return Err("unexpected AMD-Vi fault record during canary DMA");
                }
            }
            log_line("[iommu-test] unmapped canary DMA blocked by hardware AMD-Vi OK");
        }
        _ => {
            let saw_canary_fault = faults[..canary_faults].iter().any(|f| {
                f.source_bdf == edu_bdf
                    && f.fault_iova == canary_phys
                    && f.kind == FaultKind::WriteNotPermitted
            });
            if !saw_canary_fault {
                let _ = lease.revoke(1, true);
                unregister_object(lease.koid());
                return Err("expected IOMMU WriteNotPermitted fault not recorded for canary DMA");
            }
            log_line("[iommu-test] unmapped canary DMA blocked by hardware VT-d OK");
        }
    }

    // 3. Synchronous revocation + post-revoke DMA write attempt to `auth_phys + 128`.
    if lease.revoke(1, false) != Ok(1) {
        unregister_object(lease.koid());
        return Err("DeviceLease::revoke failed");
    }
    unregister_object(lease.koid());

    run_edu_dma(
        bar0_va,
        EDU_INTERNAL_DMA_BUF,
        auth_phys + 128,
        8,
        EDU_DMA_RUN | EDU_DMA_DIR_TO_PCI,
    )?;
    if phys_read64(auth_phys + 128) != AUTHORIZED_SENTINEL_B {
        return Err("SECURITY FAILURE: revoked DMA frame modified after DeviceLease::revoke");
    }
    let revoke_faults = huesos_arch::iommu::drain_faults(&mut faults);
    match hw_kind {
        huesos_abi::pci_iommu::IommuHardwareKind::AmdVi => {
            // Real AMD-Vi silicon records `IO_PAGE_FAULT` against `AMD_VI_BLOCKED_DOMAIN_ID`;
            // QEMU 8.2 `amdvi_log_event` (`amdvi_test_mask` `|` bug) suppresses Event Log DMA
            // writes while still enforcing IOTLB revocation and blocking the memory write above.
            if revoke_faults > 0 {
                let mut ok = false;
                for f in &faults[..revoke_faults] {
                    let iova_ok = f.fault_iova == 0 || (f.fault_iova & !0xFFF) == auth_phys;
                    let kind_ok = f.kind == FaultKind::ContextNotPresent
                        || f.kind == FaultKind::WriteNotPermitted;
                    if f.source_bdf == edu_bdf && iova_ok && kind_ok {
                        ok = true;
                    }
                }
                if !ok {
                    return Err("unexpected AMD-Vi post-revoke fault record");
                }
            }
        }
        _ => {
            let mut saw_revoke_fault = false;
            for f in &faults[..revoke_faults] {
                if f.source_bdf == edu_bdf && f.kind == FaultKind::ContextNotPresent {
                    saw_revoke_fault = true;
                }
            }
            if !saw_revoke_fault {
                return Err("expected IOMMU post-revoke fault not recorded after revoke");
            }
        }
    }
    log_line("[iommu-test] post-revoke DMA blocked after synchronous IOTLB flush OK");
    Ok(())
}

fn run_edu_dma(bar0_va: u64, src: u64, dst: u64, cnt: u64, cmd: u64) -> Result<(), &'static str> {
    mmio_write64(bar0_va + EDU_DMA_SRC_OFFSET, src);
    mmio_write64(bar0_va + EDU_DMA_DST_OFFSET, dst);
    mmio_write64(bar0_va + EDU_DMA_CNT_OFFSET, cnt);
    mmio_write64(bar0_va + EDU_DMA_CMD_OFFSET, cmd);

    let start = crate::scheduler::global_ticks();
    loop {
        if (mmio_read64(bar0_va + EDU_DMA_CMD_OFFSET) & EDU_DMA_RUN) == 0 {
            return Ok(());
        }
        if crate::scheduler::global_ticks().saturating_sub(start) >= DMA_TIMEOUT_TICKS {
            return Err("timed out waiting for edu DMA completion");
        }
        core::hint::spin_loop();
    }
}

const fn empty_fault() -> FaultRecord {
    FaultRecord {
        unit_index: 0,
        reason_code: 0,
        kind: FaultKind::Other(0),
        is_read: false,
        source_bdf: 0,
        fault_iova: 0,
    }
}

fn log_line(message: &str) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{message}");
}

fn mmio_read64(address: u64) -> u64 {
    // SAFETY: `address` lies inside the uncached `edu` BAR0 window at an 8-byte-aligned
    // DMA register offset (`0x80..=0x98`).
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

fn mmio_write64(address: u64, value: u64) {
    // SAFETY: same uncached `edu` BAR0 window and alignment contract as `mmio_read64`.
    unsafe { core::ptr::write_volatile(address as *mut u64, value) };
}

fn phys_read64(phys_addr: u64) -> u64 {
    let va = huesos_arch::paging::phys_to_virt(phys_addr).as_u64();
    // SAFETY: `phys_addr` lies at an 8-byte-aligned offset inside a PMM-owned test frame
    // mapped in the HHDM; volatile read observes asynchronous PCIe DMA writes.
    unsafe { core::ptr::read_volatile(va as *const u64) }
}

fn phys_write64(phys_addr: u64, value: u64) {
    let va = huesos_arch::paging::phys_to_virt(phys_addr).as_u64();
    // SAFETY: `phys_addr` lies at an 8-byte-aligned offset inside a PMM-owned test frame
    // mapped in the HHDM; `clflush` + `mfence` ensures DRAM visibility before device DMA.
    unsafe {
        core::ptr::write_volatile(va as *mut u64, value);
        core::arch::asm!("clflush [{}]", in(reg) va, options(nostack, preserves_flags));
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}
