//! Ring-0 Intel VT-d hardware DMA remapping engine (`Stage N.2`).
//!
//! [`huesos_iommu`] holds the `#![forbid(unsafe_code)]` capability parser,
//! Root/Context/SLPT codecs, command builders, fault decoder, and per-lease
//! domain state machine. This module owns only the privileged hardware
//! integration boundary:
//! - uncached MMIO mapping and register I/O for validated `DRHD` units,
//! - physical 4 KiB frame allocation/reclamation via [`huesos_pmm`] with
//!   explicit `clflush` + `mfence` eviction when `ECAP.C == 0`,
//! - firmware `RMRR` unity pre-population prior to `GCMD.TE = 1`, and
//! - synchronous `DeviceLease` DMA domain binding and teardown.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use huesos_abi::pci_iommu::{
    IommuHardwareKind, IommuMode, KernelIommuStatus, RUNTIME_FLAG_CACHING_MODE,
    RUNTIME_FLAG_INTR_REMAP_HW,
};
use huesos_abi::pci_lease::unpack_pci_address;
use huesos_iommu::{
    build_gcmd, ccmd_device_invalidate, ccmd_global_invalidate, derive_isolation_group,
    iova_level_index, AddressWidth, ContextEntry, DomainTable, FaultRecord, MappedDmaRange,
    RootEntry, SlPte, VtdCapabilities, VtdError, FECTL_IM, FRCD_HI_F, FSTS_CLEAR_MASK, FSTS_PFO,
    FSTS_PPF, GCMD_SRTP, GCMD_TE, GCMD_WBF, IOTLB_IVT, PAGE_OFFSET_MASK, PAGE_SIZE_4K, REG_CAP,
    REG_CCMD, REG_ECAP, REG_FECTL, REG_FSTS, REG_GCMD, REG_GSTS, REG_RTADDR, REG_VER,
};
use x86_64::structures::paging::PageTableFlags;

use crate::x86_64::paging::KernelPageError;
use crate::{LockRank, RankedIrqSafeTicketLock};

/// Maximum `DRHD` hardware remapping units managed concurrently.
pub const MAX_DRHD_UNITS: usize = 4;
/// Maximum firmware `RMRR` reserved unity regions retained by the kernel.
pub const MAX_RESERVED_REGIONS: usize = 16;
/// Bounded MMIO poll iterations before failing closed (`~1M` pauses).
const HW_POLL_BUDGET: usize = 1_000_000;
/// Domain ID `1` is reserved for firmware-mandated `RMRR` fallback scopes;
/// lease domains allocate above `1` (or `1` when no `RMRR` fallback exists on that unit).
const RMRR_FALLBACK_DOMAIN_ID: u16 = 1;

static VTD_ACTIVE: AtomicBool = AtomicBool::new(false);
static VTD_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static VTD_STATE: RankedIrqSafeTicketLock<VtdManager> =
    RankedIrqSafeTicketLock::new(VtdManager::new(), LockRank::ARCHITECTURE);

/// Validated `DRHD` unit descriptor supplied by kernel `DMAR` discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdUnitInit {
    /// PCI segment group covered by this `DRHD` unit.
    pub segment: u16,
    /// True if `INCLUDE_PCI_ALL` is set on this unit.
    pub include_pci_all: bool,
    /// Number of explicit BDF scope targets in [`Self::scope_bdfs`].
    pub scope_bdf_count: u8,
    /// 4 KiB-aligned MMIO register base physical address.
    pub register_base: u64,
    /// Explicit `(bus << 8) | devfn` scope targets.
    pub scope_bdfs: [u16; 4],
}

/// Validated ACPI `RMRR` reserved memory region supplied by kernel `DMAR` discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtdReservedRegion {
    /// PCI segment group.
    pub segment: u16,
    /// Target requester `(bus << 8) | devfn` (`0xFFFF` for segment-wide).
    pub requester_bdf: u16,
    /// Inclusive physical start address.
    pub base_address: u64,
    /// Inclusive physical end address (`>= base_address`).
    pub limit_address: u64,
}

impl VtdReservedRegion {
    const EMPTY: Self = Self {
        segment: 0,
        requester_bdf: 0,
        base_address: 0,
        limit_address: 0,
    };
}

/// Errors returned while initializing or programming Intel VT-d hardware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtdHwError {
    /// No usable `DRHD` descriptors were supplied.
    NoUnits,
    /// More `DRHD` units were supplied than [`MAX_DRHD_UNITS`].
    TooManyUnits,
    /// Hardware VT-d was already initialized.
    AlreadyInitialized,
    /// Hardware VT-d is not active on this machine.
    NotActive,
    /// Uncached kernel MMIO mapping for a `DRHD` unit failed.
    MmioMappingFailed,
    /// Physical 4 KiB frame allocation from [`huesos_pmm`] failed.
    OutOfMemory,
    /// Hardware `GSTS` / `CCMD` / `IOTLB` acknowledgement timed out.
    HardwareTimeout,
    /// Packed PCI address was invalid or matched no `DRHD` unit on its segment.
    NoMatchingUnit,
    /// Underlying capability/codec/domain policy error.
    Policy(VtdError),
}

impl From<VtdError> for VtdHwError {
    fn from(value: VtdError) -> Self {
        Self::Policy(value)
    }
}

#[derive(Clone, Copy)]
struct DrhdEngine {
    active: bool,
    segment: u16,
    include_pci_all: bool,
    scope_bdf_count: u8,
    scope_bdfs: [u16; 4],
    register_base: u64,
    caps: VtdCapabilities,
    root_table_phys: u64,
    rmrr_fallback_slpt_phys: u64,
    bus_ctx_phys: [u64; 256],
}

impl DrhdEngine {
    const EMPTY: Self = Self {
        active: false,
        segment: 0,
        include_pci_all: false,
        scope_bdf_count: 0,
        scope_bdfs: [0; 4],
        register_base: 0,
        caps: VtdCapabilities {
            ver_major: 0,
            ver_minor: 0,
            address_width: AddressWidth::Aw39Bit3Level,
            mgaw_bits: 39,
            max_domains: 16,
            caching_mode: false,
            rwbf: false,
            drain_reads: false,
            drain_writes: false,
            page_walk_coherent: true,
            interrupt_remapping_supported: false,
            iva_reg_offset: 0x80,
            iotlb_reg_offset: 0x88,
            frcd_reg_offset: 0x100,
            num_fault_regs: 1,
        },
        root_table_phys: 0,
        rmrr_fallback_slpt_phys: 0,
        bus_ctx_phys: [0; 256],
    };
}

struct VtdManager {
    initialized: bool,
    unit_count: usize,
    units: [DrhdEngine; MAX_DRHD_UNITS],
    reserved_count: usize,
    reserved: [VtdReservedRegion; MAX_RESERVED_REGIONS],
    domains: DomainTable,
}

impl VtdManager {
    const fn new() -> Self {
        Self {
            initialized: false,
            unit_count: 0,
            units: [DrhdEngine::EMPTY; MAX_DRHD_UNITS],
            reserved_count: 0,
            reserved: [VtdReservedRegion::EMPTY; MAX_RESERVED_REGIONS],
            domains: DomainTable::new(),
        }
    }

    fn select_unit(&self, segment: u16, bdf: u16) -> Option<usize> {
        let mut idx = 0usize;
        while idx < self.unit_count {
            let u = &self.units[idx];
            if u.active && u.segment == segment && !u.include_pci_all {
                let mut s = 0usize;
                while s < usize::from(u.scope_bdf_count) {
                    if u.scope_bdfs[s] == bdf {
                        return Some(idx);
                    }
                    s += 1;
                }
            }
            idx += 1;
        }
        let mut catch_idx = 0usize;
        while catch_idx < self.unit_count {
            let u = &self.units[catch_idx];
            if u.active && u.segment == segment && u.include_pci_all {
                return Some(catch_idx);
            }
            catch_idx += 1;
        }
        None
    }
}

/// True when Intel VT-d hardware translation (`GSTS.TES == 1`) is active.
pub fn is_active() -> bool {
    VTD_ACTIVE.load(Ordering::Acquire)
}

/// Snapshot live Ring-0 IOMMU telemetry for `Syscall::SystemIommuStatus` and diagnostics.
pub fn status() -> KernelIommuStatus {
    if !is_active() {
        return KernelIommuStatus::TRUSTED_INACTIVE;
    }
    let guard = VTD_STATE.lock();
    let mut flags = 0u8;
    let mut active_units = 0u8;
    let mut i = 0usize;
    while i < guard.unit_count {
        let u = &guard.units[i];
        if u.active {
            active_units = active_units.saturating_add(1);
            if u.caps.caching_mode {
                flags |= RUNTIME_FLAG_CACHING_MODE;
            }
            if u.caps.interrupt_remapping_supported {
                flags |= RUNTIME_FLAG_INTR_REMAP_HW;
            }
        }
        i += 1;
    }
    if active_units == 0 {
        return KernelIommuStatus::TRUSTED_INACTIVE;
    }
    KernelIommuStatus {
        hardware_kind: IommuHardwareKind::IntelVtd as u8,
        active_mode: IommuMode::Isolated as u8,
        active_unit_count: active_units,
        runtime_flags: flags,
        active_domains: guard.domains.active_count(),
        mapped_pages: guard.domains.mapped_pages_total(),
        teardown_count: guard.domains.teardown_count(),
        fault_count: VTD_FAULT_COUNT.load(Ordering::Relaxed),
    }
}

/// Initialize all discovered `DRHD` units, pre-map firmware `RMRR` unity scopes,
/// and enable hardware second-stage DMA translation (`GCMD.TE = 1`).
pub fn initialize(
    units: &[VtdUnitInit],
    reserved_regions: &[VtdReservedRegion],
) -> Result<VtdCapabilities, VtdHwError> {
    if units.is_empty() {
        return Err(VtdHwError::NoUnits);
    }
    if units.len() > MAX_DRHD_UNITS {
        return Err(VtdHwError::TooManyUnits);
    }

    // Step 1: Map the initial 4 KiB header window of each DRHD unit outside `VTD_STATE`
    // so `KERNEL_PAGE_TABLE` is never nested inside `VTD_STATE`, read capabilities, and
    // extend the uncached MMIO mapping if `IOTLB_REG` / `FRCD_REG` exceed 4 KiB.
    let mut parsed_caps = [DrhdEngine::EMPTY.caps; MAX_DRHD_UNITS];
    for (idx, u) in units.iter().enumerate() {
        if u.register_base == 0 || (u.register_base & PAGE_OFFSET_MASK) != 0 {
            return Err(VtdHwError::Policy(VtdError::InvalidAddress));
        }
        map_uncached_mmio(u.register_base, PAGE_SIZE_4K)?;
        let ver = mmio_read32(u.register_base, REG_VER);
        let cap = mmio_read64(u.register_base, REG_CAP);
        let ecap = mmio_read64(u.register_base, REG_ECAP);
        let caps = VtdCapabilities::parse(ver, cap, ecap)?;
        let total_bytes = caps.required_mmio_bytes();
        if total_bytes > PAGE_SIZE_4K {
            map_uncached_mmio(u.register_base + PAGE_SIZE_4K, total_bytes - PAGE_SIZE_4K)?;
        }
        parsed_caps[idx] = caps;
    }

    let mut guard = VTD_STATE.lock();
    if guard.initialized {
        return Err(VtdHwError::AlreadyInitialized);
    }

    let keep_reserved = reserved_regions.len().min(MAX_RESERVED_REGIONS);
    guard.reserved[..keep_reserved].copy_from_slice(&reserved_regions[..keep_reserved]);
    guard.reserved_count = keep_reserved;

    for (idx, u) in units.iter().enumerate() {
        let caps = parsed_caps[idx];
        let root_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
        zero_frame_4k(root_phys, caps.page_walk_coherent);

        let mut engine = DrhdEngine {
            active: true,
            segment: u.segment,
            include_pci_all: u.include_pci_all,
            scope_bdf_count: u.scope_bdf_count,
            scope_bdfs: u.scope_bdfs,
            register_base: u.register_base,
            caps,
            root_table_phys: root_phys,
            rmrr_fallback_slpt_phys: 0,
            bus_ctx_phys: [0; 256],
        };

        // Pre-populate any firmware RMRR unity regions targeting specific BDFs on this
        // segment before enabling `GCMD.TE` (Intel VT-d Spec §8.4).
        let mut r_idx = 0usize;
        while r_idx < keep_reserved {
            let reg = guard.reserved[r_idx];
            if reg.segment == u.segment
                && reg.requester_bdf != 0xFFFF
                && reg.limit_address >= reg.base_address
            {
                if engine.rmrr_fallback_slpt_phys == 0 {
                    let slpt = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
                    zero_frame_4k(slpt, caps.page_walk_coherent);
                    engine.rmrr_fallback_slpt_phys = slpt;
                }
                let start_4k = reg.base_address & !PAGE_OFFSET_MASK;
                let end_4k = (reg.limit_address.saturating_add(PAGE_SIZE_4K)) & !PAGE_OFFSET_MASK;
                if end_4k > start_4k {
                    let fallback_slpt = engine.rmrr_fallback_slpt_phys;
                    map_range_in_slpt(
                        fallback_slpt,
                        caps.address_width,
                        start_4k,
                        end_4k - start_4k,
                        caps.page_walk_coherent,
                    )?;
                    program_context_entry(
                        &mut engine,
                        (reg.requester_bdf >> 8) as u8,
                        (reg.requester_bdf & 0xFF) as u8,
                        fallback_slpt,
                        RMRR_FALLBACK_DOMAIN_ID,
                    )?;
                }
            }
            r_idx += 1;
        }

        bring_up_drhd_hardware(&engine)?;
        guard.units[idx] = engine;
        guard.unit_count += 1;
    }

    guard.initialized = true;
    VTD_ACTIVE.store(true, Ordering::Release);
    Ok(parsed_caps[0])
}

/// Bind `[base, base + len)` (`IOVA == HPA`, `READ | WRITE`) into the hardware VT-d
/// domain owned by `(lease_koid, lease_generation)` for `pci_address_packed`.
///
/// If VT-d hardware is not active on this platform, returns `Ok(())` as a no-op so
/// `Trusted` platforms share the exact same `DeviceLease` capability lifecycle.
pub fn bind_lease_dma(
    pci_address_packed: u64,
    lease_koid: u64,
    lease_generation: u64,
    base: u64,
    len: u64,
) -> Result<(), VtdHwError> {
    if !is_active() {
        return Ok(());
    }
    let Some((segment, bus, device, function)) = unpack_pci_address(pci_address_packed) else {
        return Err(VtdHwError::NoMatchingUnit);
    };
    let devfn = (device << 3) | function;
    let bdf = (u16::from(bus) << 8) | u16::from(devfn);

    let mut guard = VTD_STATE.lock();
    let Some(unit_idx) = guard.select_unit(segment, bdf) else {
        return Err(VtdHwError::NoMatchingUnit);
    };
    let caps = guard.units[unit_idx].caps;
    let range = MappedDmaRange::try_new(base, len, caps.effective_iova_limit())?;

    let existing = guard.domains.find_by_lease(lease_koid, lease_generation);
    let (slot_idx, domain_id, slpt_root_phys, is_new_domain) = match existing {
        Some(existing_idx) => {
            let rec = guard.domains.slots()[existing_idx];
            if rec.pci_address_packed != pci_address_packed {
                return Err(VtdHwError::Policy(VtdError::IsolationGroupConflict));
            }
            (existing_idx, rec.domain_id, rec.slpt_root_phys, false)
        }
        None => {
            let slpt_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
            zero_frame_4k(slpt_phys, caps.page_walk_coherent);

            let group_id = derive_isolation_group(pci_address_packed, None);
            // Reserve DomainId 1 when RMRR fallback is active on this unit.
            let has_rmrr = guard.units[unit_idx].rmrr_fallback_slpt_phys != 0;
            let alloc_res = if has_rmrr {
                allocate_non_rmrr_domain(
                    &mut guard.domains,
                    unit_idx as u8,
                    caps.max_domains,
                    pci_address_packed,
                    group_id,
                    lease_koid,
                    lease_generation,
                    slpt_phys,
                )
            } else {
                guard.domains.allocate_domain(
                    unit_idx as u8,
                    caps.max_domains,
                    pci_address_packed,
                    group_id,
                    lease_koid,
                    lease_generation,
                    slpt_phys,
                )
            };
            let (idx, did) = match alloc_res {
                Ok(pair) => pair,
                Err(err) => {
                    huesos_pmm::free_frame(slpt_phys);
                    return Err(VtdHwError::Policy(err));
                }
            };

            // Preserve any firmware RMRR unity mappings required for this requester.
            let mut r_idx = 0usize;
            while r_idx < guard.reserved_count {
                let reg = guard.reserved[r_idx];
                if reg.segment == segment
                    && (reg.requester_bdf == bdf || reg.requester_bdf == 0xFFFF)
                    && reg.limit_address >= reg.base_address
                {
                    let start_4k = reg.base_address & !PAGE_OFFSET_MASK;
                    let end_4k =
                        (reg.limit_address.saturating_add(PAGE_SIZE_4K)) & !PAGE_OFFSET_MASK;
                    if end_4k > start_4k {
                        if let Err(err) = map_range_in_slpt(
                            slpt_phys,
                            caps.address_width,
                            start_4k,
                            end_4k - start_4k,
                            caps.page_walk_coherent,
                        ) {
                            let _ = guard.domains.release_lease(lease_koid, lease_generation);
                            free_slpt_tree(slpt_phys, caps.address_width.levels());
                            return Err(err);
                        }
                    }
                }
                r_idx += 1;
            }
            (idx, did, slpt_phys, true)
        }
    };

    let inserted = match guard.domains.record_range(slot_idx, range) {
        Ok(ins) => ins,
        Err(err) => {
            if is_new_domain {
                let _ = guard.domains.release_lease(lease_koid, lease_generation);
                free_slpt_tree(slpt_root_phys, caps.address_width.levels());
            }
            return Err(VtdHwError::Policy(err));
        }
    };

    if inserted {
        if let Err(err) = map_range_in_slpt(
            slpt_root_phys,
            caps.address_width,
            range.base,
            range.len,
            caps.page_walk_coherent,
        ) {
            if is_new_domain {
                let _ = guard.domains.release_lease(lease_koid, lease_generation);
                free_slpt_tree(slpt_root_phys, caps.address_width.levels());
            }
            return Err(err);
        }
    }

    let engine = &mut guard.units[unit_idx];
    if is_new_domain {
        program_context_entry(engine, bus, devfn, slpt_root_phys, domain_id)?;
    }
    flush_write_buffer_if_needed(engine)?;
    // Under Caching Mode (`CM == 1`, e.g. QEMU `intel-iommu,caching-mode=on`), negative
    // context/IOTLB entries under DID=0 may be cached prior to `0 -> Present` transitions;
    // flushing both global/device context cache and IOTLB guarantees immediate visibility.
    if engine.caps.caching_mode {
        invalidate_context_global(engine)?;
        invalidate_iotlb_global(engine)?;
    } else {
        invalidate_context_device(engine, domain_id, bdf)?;
        invalidate_iotlb_domain(engine, domain_id)?;
    }
    Ok(())
}

/// Synchronously unbind `pci_address_packed` for `(lease_koid, lease_generation)`,
/// flush Context Cache and IOTLB, and free all Second-Stage Page Table frames.
pub fn teardown_lease(pci_address_packed: u64, lease_koid: u64, lease_generation: u64) {
    if !is_active() {
        return;
    }
    let mut guard = VTD_STATE.lock();
    let Some(removed) = guard.domains.release_lease(lease_koid, lease_generation) else {
        return;
    };
    let unit_idx = usize::from(removed.unit_index);
    if unit_idx >= guard.unit_count || !guard.units[unit_idx].active {
        return;
    }

    let (segment, bus, device, function) =
        unpack_pci_address(pci_address_packed).unwrap_or((0, 0, 0, 0));
    let devfn = (device << 3) | function;
    let bdf = (u16::from(bus) << 8) | u16::from(devfn);

    let mut has_specific_rmrr = false;
    let mut r_idx = 0usize;
    while r_idx < guard.reserved_count {
        let reg = guard.reserved[r_idx];
        if reg.segment == segment && reg.requester_bdf == bdf {
            has_specific_rmrr = true;
            break;
        }
        r_idx += 1;
    }

    let levels = guard.units[unit_idx].caps.address_width.levels();
    {
        let engine = &mut guard.units[unit_idx];
        if has_specific_rmrr && engine.rmrr_fallback_slpt_phys != 0 {
            let _ = program_context_entry(
                engine,
                bus,
                devfn,
                engine.rmrr_fallback_slpt_phys,
                RMRR_FALLBACK_DOMAIN_ID,
            );
        } else {
            clear_context_entry(engine, bus, devfn);
        }
        let _ = flush_write_buffer_if_needed(engine);
        if engine.caps.caching_mode {
            let _ = invalidate_context_global(engine);
            let _ = invalidate_iotlb_global(engine);
        } else {
            let _ = invalidate_context_device(engine, removed.domain_id, bdf);
            let _ = invalidate_iotlb_domain(engine, removed.domain_id);
        }
    }

    free_slpt_tree(removed.slpt_root_phys, levels);
}

/// Drain and RW1C-clear pending hardware Primary Fault Recording entries across
/// all active `DRHD` units, incrementing the global fault counter and returning
/// up to `out.len()` decoded [`FaultRecord`]s.
pub fn drain_faults(out: &mut [FaultRecord]) -> usize {
    if !is_active() {
        return 0;
    }
    let guard = VTD_STATE.lock();
    let mut written = 0usize;
    let mut u_idx = 0usize;
    while u_idx < guard.unit_count {
        let engine = &guard.units[u_idx];
        if !engine.active {
            u_idx += 1;
            continue;
        }
        let fsts = mmio_read32(engine.register_base, REG_FSTS);
        if (fsts & (FSTS_PPF | FSTS_PFO | FSTS_CLEAR_MASK)) != 0 {
            let mut slot = 0usize;
            while slot < engine.caps.num_fault_regs {
                let off = engine.caps.frcd_reg_offset + slot * 16;
                let lo = mmio_read64(engine.register_base, off);
                let hi = mmio_read64(engine.register_base, off + 8);
                if let Some(record) = FaultRecord::decode(u_idx as u8, lo, hi) {
                    VTD_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
                    if written < out.len() {
                        out[written] = record;
                        written += 1;
                    }
                    // RW1C: write `FRCD_HI_F` to `FRCD + 8` to release this slot.
                    mmio_write64(engine.register_base, off + 8, FRCD_HI_F);
                }
                slot += 1;
            }
            mmio_write32(engine.register_base, REG_FSTS, FSTS_CLEAR_MASK);
        }
        u_idx += 1;
    }
    written
}

#[allow(clippy::too_many_arguments)]
fn allocate_non_rmrr_domain(
    table: &mut DomainTable,
    unit_index: u8,
    max_domains: u32,
    pci_address_packed: u64,
    group_id: u32,
    lease_koid: u64,
    lease_generation: u64,
    slpt_phys: u64,
) -> Result<(usize, u16), VtdError> {
    // Temporarily occupy DID=1 with a synthetic reservation if free so user leases start at DID>=2.
    let sentinel_koid = u64::MAX;
    let reserved_did1 = table
        .allocate_domain(
            unit_index,
            max_domains,
            u64::MAX,
            u32::MAX,
            sentinel_koid,
            1,
            slpt_phys,
        )
        .ok();
    let res = table.allocate_domain(
        unit_index,
        max_domains,
        pci_address_packed,
        group_id,
        lease_koid,
        lease_generation,
        slpt_phys,
    );
    if reserved_did1.is_some() {
        let _ = table.release_lease(sentinel_koid, 1);
    }
    res
}

fn bring_up_drhd_hardware(engine: &DrhdEngine) -> Result<(), VtdHwError> {
    // Mask asynchronous fault MSI generation; faults are polled/drained deterministically.
    mmio_write32(engine.register_base, REG_FECTL, FECTL_IM);
    clear_pending_fault_registers(engine);

    // Program legacy Root Table physical address (`TTM = 00`).
    mmio_write64(engine.register_base, REG_RTADDR, engine.root_table_phys);
    let gsts_before_srtp = mmio_read32(engine.register_base, REG_GSTS);
    mmio_write32(
        engine.register_base,
        REG_GCMD,
        build_gcmd(gsts_before_srtp, GCMD_SRTP, 0),
    );
    poll_u32_mask(engine.register_base, REG_GSTS, GCMD_SRTP, GCMD_SRTP)?;

    flush_write_buffer_if_needed(engine)?;
    invalidate_context_global(engine)?;
    invalidate_iotlb_global(engine)?;

    // Enable hardware DMA remapping (`GCMD.TE = 1`) and wait for `GSTS.TES == 1`.
    let gsts_before_te = mmio_read32(engine.register_base, REG_GSTS);
    mmio_write32(
        engine.register_base,
        REG_GCMD,
        build_gcmd(gsts_before_te, GCMD_TE, 0),
    );
    poll_u32_mask(engine.register_base, REG_GSTS, GCMD_TE, GCMD_TE)?;
    Ok(())
}

fn clear_pending_fault_registers(engine: &DrhdEngine) {
    let mut slot = 0usize;
    while slot < engine.caps.num_fault_regs {
        let off = engine.caps.frcd_reg_offset + slot * 16;
        let hi = mmio_read64(engine.register_base, off + 8);
        if (hi & FRCD_HI_F) != 0 {
            mmio_write64(engine.register_base, off + 8, FRCD_HI_F);
        }
        slot += 1;
    }
    mmio_write32(engine.register_base, REG_FSTS, FSTS_CLEAR_MASK);
}

fn flush_write_buffer_if_needed(engine: &DrhdEngine) -> Result<(), VtdHwError> {
    if !engine.caps.rwbf {
        return Ok(());
    }
    let gsts = mmio_read32(engine.register_base, REG_GSTS);
    mmio_write32(engine.register_base, REG_GCMD, build_gcmd(gsts, GCMD_WBF, 0));
    poll_u32_mask(engine.register_base, REG_GSTS, GCMD_WBF, 0)
}

fn invalidate_context_global(engine: &DrhdEngine) -> Result<(), VtdHwError> {
    mmio_write64(engine.register_base, REG_CCMD, ccmd_global_invalidate());
    poll_u64_clear(engine.register_base, REG_CCMD, huesos_iommu::CCMD_ICC)
}

fn invalidate_context_device(
    engine: &DrhdEngine,
    domain_id: u16,
    source_bdf: u16,
) -> Result<(), VtdHwError> {
    mmio_write64(
        engine.register_base,
        REG_CCMD,
        ccmd_device_invalidate(domain_id, source_bdf),
    );
    poll_u64_clear(engine.register_base, REG_CCMD, huesos_iommu::CCMD_ICC)
}

fn invalidate_iotlb_global(engine: &DrhdEngine) -> Result<(), VtdHwError> {
    mmio_write64(
        engine.register_base,
        engine.caps.iotlb_reg_offset,
        engine.caps.iotlb_global_invalidate_cmd(),
    );
    poll_u64_clear(engine.register_base, engine.caps.iotlb_reg_offset, IOTLB_IVT)
}

fn invalidate_iotlb_domain(engine: &DrhdEngine, domain_id: u16) -> Result<(), VtdHwError> {
    mmio_write64(
        engine.register_base,
        engine.caps.iotlb_reg_offset,
        engine.caps.iotlb_domain_invalidate_cmd(domain_id),
    );
    poll_u64_clear(engine.register_base, engine.caps.iotlb_reg_offset, IOTLB_IVT)
}

fn poll_u32_mask(base: u64, offset: usize, mask: u32, expected: u32) -> Result<(), VtdHwError> {
    let mut spins = 0usize;
    while spins < HW_POLL_BUDGET {
        if (mmio_read32(base, offset) & mask) == expected {
            return Ok(());
        }
        core::hint::spin_loop();
        spins += 1;
    }
    Err(VtdHwError::HardwareTimeout)
}

fn poll_u64_clear(base: u64, offset: usize, bit: u64) -> Result<(), VtdHwError> {
    let mut spins = 0usize;
    while spins < HW_POLL_BUDGET {
        if (mmio_read64(base, offset) & bit) == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
        spins += 1;
    }
    Err(VtdHwError::HardwareTimeout)
}

fn program_context_entry(
    engine: &mut DrhdEngine,
    bus: u8,
    devfn: u8,
    slpt_root_phys: u64,
    domain_id: u16,
) -> Result<(), VtdHwError> {
    let coherent = engine.caps.page_walk_coherent;
    let bus_idx = usize::from(bus);
    let ctx_table_phys = if engine.bus_ctx_phys[bus_idx] != 0 {
        engine.bus_ctx_phys[bus_idx]
    } else {
        let frame = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
        zero_frame_4k(frame, coherent);
        let root_entry = RootEntry::present(frame)?;
        phys_write64(engine.root_table_phys, bus_idx * 2 + 1, root_entry.hi, coherent);
        phys_write64(engine.root_table_phys, bus_idx * 2, root_entry.lo, coherent);
        engine.bus_ctx_phys[bus_idx] = frame;
        frame
    };

    let ctx_entry = ContextEntry::present(
        slpt_root_phys,
        engine.caps.address_width,
        domain_id,
        engine.caps.max_domains,
    )?;
    let slot = usize::from(devfn) * 2;
    // Write `hi` (DID + AW) before `lo` (`Present = 1`) so hardware never observes
    // a present context entry with stale upper fields.
    phys_write64(ctx_table_phys, slot + 1, ctx_entry.hi, coherent);
    phys_write64(ctx_table_phys, slot, ctx_entry.lo, coherent);
    Ok(())
}

fn clear_context_entry(engine: &DrhdEngine, bus: u8, devfn: u8) {
    let ctx_table_phys = engine.bus_ctx_phys[usize::from(bus)];
    if ctx_table_phys == 0 {
        return;
    }
    let coherent = engine.caps.page_walk_coherent;
    let slot = usize::from(devfn) * 2;
    // Clear `lo` (`Present = 0`) first so concurrent page-walks fault closed immediately.
    phys_write64(ctx_table_phys, slot, ContextEntry::EMPTY.lo, coherent);
    phys_write64(ctx_table_phys, slot + 1, ContextEntry::EMPTY.hi, coherent);
}

fn map_range_in_slpt(
    slpt_root_phys: u64,
    address_width: AddressWidth,
    base: u64,
    len: u64,
    coherent: bool,
) -> Result<(), VtdHwError> {
    let levels = address_width.levels();
    let end = base.saturating_add(len);
    let mut page = base;
    while page < end {
        let mut curr_table = slpt_root_phys;
        let mut lvl = levels;
        while lvl > 1 {
            let slot = iova_level_index(page, lvl)?;
            let existing = SlPte(phys_read64(curr_table, slot));
            curr_table = if let Some(next_phys) = existing.addr_4k() {
                next_phys
            } else {
                let next_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
                zero_frame_4k(next_phys, coherent);
                let dir = SlPte::directory(next_phys)?;
                phys_write64(curr_table, slot, dir.0, coherent);
                next_phys
            };
            lvl -= 1;
        }
        let leaf_slot = iova_level_index(page, 1)?;
        let leaf = SlPte::leaf_4k(page, true, true)?;
        phys_write64(curr_table, leaf_slot, leaf.0, coherent);
        page = page.saturating_add(PAGE_SIZE_4K);
    }
    Ok(())
}

fn free_slpt_tree(table_phys: u64, level: u8) {
    if table_phys == 0 {
        return;
    }
    if level > 1 {
        let mut slot = 0usize;
        while slot < 512 {
            let entry = SlPte(phys_read64(table_phys, slot));
            if entry.is_present() && !entry.is_superpage() {
                if let Some(child_phys) = entry.addr_4k() {
                    free_slpt_tree(child_phys, level - 1);
                }
            }
            slot += 1;
        }
    }
    huesos_pmm::free_frame(table_phys);
}

fn map_uncached_mmio(phys_base: u64, length: u64) -> Result<(), VtdHwError> {
    match super::paging::map_hhdm_range_flags(
        phys_base,
        length,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::NO_EXECUTE,
    ) {
        Ok(()) | Err(KernelPageError::AlreadyMapped) => Ok(()),
        Err(_) => Err(VtdHwError::MmioMappingFailed),
    }
}

fn mmio_read32(base: u64, offset: usize) -> u32 {
    let ptr = (super::paging::phys_to_virt(base + offset as u64).as_u64()) as *const u32;
    // SAFETY: `initialize` mapped the DRHD register window uncached (`NO_CACHE`),
    // and `offset` is bounded by `VtdCapabilities::parse` (`< required_mmio_bytes()`).
    unsafe { core::ptr::read_volatile(ptr) }
}

fn mmio_write32(base: u64, offset: usize, value: u32) {
    let ptr = (super::paging::phys_to_virt(base + offset as u64).as_u64()) as *mut u32;
    // SAFETY: `initialize` mapped the DRHD register window uncached (`NO_CACHE`),
    // `offset` is a valid 32-bit VT-d register, and writes are serialized by `VTD_STATE`.
    unsafe { core::ptr::write_volatile(ptr, value) };
}

fn mmio_read64(base: u64, offset: usize) -> u64 {
    let ptr = (super::paging::phys_to_virt(base + offset as u64).as_u64()) as *const u64;
    // SAFETY: `initialize` mapped the DRHD register window uncached (`NO_CACHE`),
    // and `offset` is an 8-byte-aligned 64-bit VT-d register within `required_mmio_bytes()`.
    unsafe { core::ptr::read_volatile(ptr) }
}

fn mmio_write64(base: u64, offset: usize, value: u64) {
    let ptr = (super::paging::phys_to_virt(base + offset as u64).as_u64()) as *mut u64;
    // SAFETY: `initialize` mapped the DRHD register window uncached (`NO_CACHE`),
    // `offset` is an 8-byte-aligned 64-bit VT-d register, and writes are serialized by `VTD_STATE`.
    unsafe { core::ptr::write_volatile(ptr, value) };
}

fn phys_read64(frame_phys: u64, index: usize) -> u64 {
    let va = super::paging::phys_to_virt(frame_phys + (index as u64) * 8).as_u64();
    // SAFETY: `frame_phys` is a PMM-owned 4 KiB Root/Context/SLPT frame mapped in
    // the HHDM, `index < 512`, and accesses are serialized by `VTD_STATE`.
    unsafe { core::ptr::read_volatile(va as *const u64) }
}

fn phys_write64(frame_phys: u64, index: usize, value: u64, coherent: bool) {
    let va = super::paging::phys_to_virt(frame_phys + (index as u64) * 8).as_u64();
    // SAFETY: `frame_phys` is a PMM-owned 4 KiB Root/Context/SLPT frame mapped in
    // the HHDM, `index < 512`, and accesses are serialized by `VTD_STATE`. When
    // `ECAP.C == 0`, `clflush` + `mfence` evicts the written 8-byte entry to DRAM
    // before hardware IOMMU page-walks can observe it.
    unsafe {
        core::ptr::write_volatile(va as *mut u64, value);
        if !coherent {
            core::arch::asm!("clflush [{}]", in(reg) va, options(nostack, preserves_flags));
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }
    }
}

fn zero_frame_4k(frame_phys: u64, coherent: bool) {
    let va = super::paging::phys_to_virt(frame_phys).as_u64();
    // SAFETY: `frame_phys` was freshly allocated by `huesos_pmm::alloc_frame`
    // (4096 bytes, 4 KiB-aligned) and is uniquely owned under `VTD_STATE`.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, 4096);
        if !coherent {
            let mut off = 0u64;
            while off < 4096 {
                let line = va + off;
                core::arch::asm!("clflush [{}]", in(reg) line, options(nostack, preserves_flags));
                off += 64;
            }
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }
    }
}
