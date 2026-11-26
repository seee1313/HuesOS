//! Ring-0 AMD-Vi (`I/O Virtualization`, `IVRS`) hardware DMA remapping engine (`Stage N.2`).
//!
//! Uses `#![forbid(unsafe_code)]` codecs in [`huesos_iommu::amd_vi`] and shares
//! the uncached MMIO and HHDM page-table primitives from [`super::vtd`], adding
//! zero new `unsafe` blocks while enforcing full hardware default-deny DMA,
//! per-lease 4-level (`48`-bit IOVA) page tables, synchronous Command Ring
//! invalidations (`INVALIDATE_DEVTAB_ENTRY` + `INVALIDATE_IOMMU_PAGES` +
//! `COMPLETION_WAIT`), and Event Log fault capture on AMD platforms.

use core::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

use huesos_abi::pci_iommu::{
    IommuHardwareKind, IommuMode, KernelIommuStatus, RUNTIME_FLAG_INTR_REMAP_HW,
};
use huesos_abi::pci_lease::unpack_pci_address;
use huesos_iommu::amd_vi::{
    advance_ring_offset_4k, decode_amd_vi_event, encode_devtab_base, encode_ring_base_4k,
    AmdViCommand, AmdViDte, AmdViPte, AMD_VI_BLOCKED_DOMAIN_ID, AMD_VI_DEVTAB_BYTES,
    AMD_VI_FIRST_LEASE_DOMAIN_ID, AMD_VI_IVMD_DOMAIN_ID, AMD_VI_MAX_DOMAINS, AMD_VI_MAX_IOVA_48BIT,
    AMD_VI_MMIO_BYTES, AMD_VI_RING_CAPACITY, AMD_VI_RING_OFFSET_MASK, CTRL_CMD_BUF_EN,
    CTRL_COHERENT, CTRL_EVENT_LOG_EN, CTRL_IOMMU_EN, MMIO_CMDBUF_BASE, MMIO_CMD_HEAD, MMIO_CMD_TAIL,
    MMIO_CONTROL, MMIO_DEVTAB_BASE, MMIO_EVTLOG_BASE, MMIO_EVT_HEAD, MMIO_EVT_TAIL, MMIO_EXCL_BASE,
    MMIO_EXCL_LIMIT, MMIO_EXT_FEATURES, MMIO_STATUS, STATUS_COM_WAIT_INT, STATUS_EVENT_LOG_INT,
    STATUS_EVENT_OVERFLOW, STATUS_RW1C_ALL,
};
use huesos_iommu::{
    derive_isolation_group, iova_level_index, DomainTable, FaultRecord, MappedDmaRange, VtdError,
    PAGE_OFFSET_MASK, PAGE_SIZE_4K,
};

use super::vtd::{
    map_uncached_mmio, mmio_read64, mmio_write64, phys_read64, phys_write64, zero_frame_4k,
    VtdHwError, VtdReservedRegion, VtdUnitInit, MAX_DRHD_UNITS, MAX_RESERVED_REGIONS,
    MAX_UNIT_SCOPE_BDFS,
};
use crate::{LockRank, RankedIrqSafeTicketLock};

/// Maximum `IVHD` hardware remapping units managed concurrently.
pub const MAX_IVHD_UNITS: usize = MAX_DRHD_UNITS;

const HW_POLL_BUDGET: usize = 1_000_000;

static AMD_VI_ACTIVE: AtomicBool = AtomicBool::new(false);
static AMD_VI_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static AMD_VI_STATE: RankedIrqSafeTicketLock<AmdViManager> =
    RankedIrqSafeTicketLock::new(AmdViManager::new(), LockRank::ARCHITECTURE);

/// Summary returned after enabling AMD-Vi hardware translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmdViBootSummary {
    /// Active hardware units initialized.
    pub unit_count: usize,
    /// Raw Extended Feature Register (`MMIO_EXT_FEATURES`) of unit 0.
    pub ext_features: u64,
}

#[derive(Clone, Copy)]
struct IvhdEngine {
    active: bool,
    segment: u16,
    include_pci_all: bool,
    scope_bdf_count: u8,
    scope_bdfs: [u16; MAX_UNIT_SCOPE_BDFS],
    register_base: u64,
    intr_remap_hw: bool,
    devtab_phys: u64,
    cmd_buf_phys: u64,
    evt_log_phys: u64,
    blocked_pt_phys: u64,
    ivmd_fallback_pt_phys: u64,
    cmd_tail: u64,
}

impl IvhdEngine {
    const EMPTY: Self = Self {
        active: false,
        segment: 0,
        include_pci_all: false,
        scope_bdf_count: 0,
        scope_bdfs: [0; MAX_UNIT_SCOPE_BDFS],
        register_base: 0,
        intr_remap_hw: false,
        devtab_phys: 0,
        cmd_buf_phys: 0,
        evt_log_phys: 0,
        blocked_pt_phys: 0,
        ivmd_fallback_pt_phys: 0,
        cmd_tail: 0,
    };
}

struct AmdViManager {
    initialized: bool,
    unit_count: usize,
    units: [IvhdEngine; MAX_IVHD_UNITS],
    reserved_count: usize,
    reserved: [VtdReservedRegion; MAX_RESERVED_REGIONS],
    domains: DomainTable,
}

impl AmdViManager {
    const fn new() -> Self {
        Self {
            initialized: false,
            unit_count: 0,
            units: [IvhdEngine::EMPTY; MAX_IVHD_UNITS],
            reserved_count: 0,
            reserved: [VtdReservedRegion {
                segment: 0,
                requester_bdf: 0,
                base_address: 0,
                limit_address: 0,
            }; MAX_RESERVED_REGIONS],
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

/// True when AMD-Vi hardware translation (`MMIO_CONTROL.IommuEn == 1`) is active.
pub fn is_active() -> bool {
    AMD_VI_ACTIVE.load(Ordering::Acquire)
}

/// Snapshot live Ring-0 AMD-Vi telemetry for `Syscall::SystemIommuStatus`.
pub fn status() -> KernelIommuStatus {
    if !is_active() {
        return KernelIommuStatus::TRUSTED_INACTIVE;
    }
    let guard = AMD_VI_STATE.lock();
    let mut flags = 0u8;
    let mut active_units = 0u8;
    let mut i = 0usize;
    while i < guard.unit_count {
        let u = &guard.units[i];
        if u.active {
            active_units = active_units.saturating_add(1);
            if u.intr_remap_hw {
                flags |= RUNTIME_FLAG_INTR_REMAP_HW;
            }
        }
        i += 1;
    }
    if active_units == 0 {
        return KernelIommuStatus::TRUSTED_INACTIVE;
    }
    KernelIommuStatus {
        hardware_kind: IommuHardwareKind::AmdVi as u8,
        active_mode: IommuMode::Isolated as u8,
        active_unit_count: active_units,
        runtime_flags: flags,
        active_domains: guard.domains.active_count(),
        mapped_pages: guard.domains.mapped_pages_total(),
        teardown_count: guard.domains.teardown_count(),
        fault_count: AMD_VI_FAULT_COUNT.load(Ordering::Relaxed),
    }
}

/// Initialize all discovered `IVHD` units, populate default-deny `DTE`s and
/// `IVMD` unity scopes, and enable AMD-Vi hardware translation (`IommuEn = 1`).
pub fn initialize(
    units: &[VtdUnitInit],
    reserved_regions: &[VtdReservedRegion],
    intr_remap_hw: bool,
) -> Result<AmdViBootSummary, VtdHwError> {
    if units.is_empty() {
        return Err(VtdHwError::NoUnits);
    }
    if units.len() > MAX_IVHD_UNITS {
        return Err(VtdHwError::TooManyUnits);
    }

    let mut ext_features_0 = 0u64;
    for (idx, u) in units.iter().enumerate() {
        if u.register_base == 0 || (u.register_base & PAGE_OFFSET_MASK) != 0 {
            return Err(VtdHwError::Policy(VtdError::InvalidAddress));
        }
        map_uncached_mmio(u.register_base, AMD_VI_MMIO_BYTES)?;
        if idx == 0 {
            ext_features_0 = mmio_read64(u.register_base, MMIO_EXT_FEATURES);
        }
    }

    let mut guard = AMD_VI_STATE.lock();
    if guard.initialized {
        return Err(VtdHwError::AlreadyInitialized);
    }

    let keep_reserved = reserved_regions.len().min(MAX_RESERVED_REGIONS);
    guard.reserved[..keep_reserved].copy_from_slice(&reserved_regions[..keep_reserved]);
    guard.reserved_count = keep_reserved;

    for (idx, u) in units.iter().enumerate() {
        let devtab_phys =
            huesos_pmm::alloc_contiguous_aligned(AMD_VI_DEVTAB_BYTES, PAGE_SIZE_4K, 0)
                .map_err(|_| VtdHwError::OutOfMemory)?;
        let cmd_buf_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
        let evt_log_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
        let blocked_pt_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;

        zero_frame_4k(cmd_buf_phys, true);
        zero_frame_4k(evt_log_phys, true);
        zero_frame_4k(blocked_pt_phys, true);

        let blocked_dte = AmdViDte::blocked(blocked_pt_phys)?;
        let mut bdf = 0usize;
        while bdf < 65_536 {
            write_dte(devtab_phys, bdf as u16, &blocked_dte);
            bdf += 1;
        }

        let mut engine = IvhdEngine {
            active: true,
            segment: u.segment,
            include_pci_all: u.include_pci_all,
            scope_bdf_count: u.scope_bdf_count,
            scope_bdfs: u.scope_bdfs,
            register_base: u.register_base,
            intr_remap_hw,
            devtab_phys,
            cmd_buf_phys,
            evt_log_phys,
            blocked_pt_phys,
            ivmd_fallback_pt_phys: 0,
            cmd_tail: 0,
        };

        // Pre-map firmware IVMD unity regions for specific requesters before `IommuEn = 1`.
        let mut r_idx = 0usize;
        while r_idx < keep_reserved {
            let reg = guard.reserved[r_idx];
            if reg.segment == u.segment
                && reg.requester_bdf != 0xFFFF
                && reg.limit_address >= reg.base_address
            {
                if engine.ivmd_fallback_pt_phys == 0 {
                    let pt = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
                    zero_frame_4k(pt, true);
                    engine.ivmd_fallback_pt_phys = pt;
                }
                let start_4k = reg.base_address & !PAGE_OFFSET_MASK;
                let end_4k = (reg.limit_address.saturating_add(PAGE_SIZE_4K)) & !PAGE_OFFSET_MASK;
                if end_4k > start_4k {
                    map_range_in_amd_pt(engine.ivmd_fallback_pt_phys, start_4k, end_4k - start_4k)?;
                    let dte =
                        AmdViDte::translated(engine.ivmd_fallback_pt_phys, AMD_VI_IVMD_DOMAIN_ID)?;
                    write_dte(engine.devtab_phys, reg.requester_bdf, &dte);
                }
            }
            r_idx += 1;
        }

        bring_up_ivhd_hardware(&mut engine)?;
        guard.units[idx] = engine;
        guard.unit_count += 1;
    }

    guard.initialized = true;
    AMD_VI_ACTIVE.store(true, Ordering::Release);
    Ok(AmdViBootSummary {
        unit_count: units.len(),
        ext_features: ext_features_0,
    })
}

/// Bind `[base, base + len)` (`IOVA == HPA`, `READ | WRITE`) into the hardware
/// AMD-Vi domain owned by `(lease_koid, lease_generation)` for `pci_address_packed`.
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

    let mut guard = AMD_VI_STATE.lock();
    let Some(unit_idx) = guard.select_unit(segment, bdf) else {
        return Err(VtdHwError::NoMatchingUnit);
    };
    let range = MappedDmaRange::try_new(base, len, AMD_VI_MAX_IOVA_48BIT)?;

    let existing = guard.domains.find_by_lease(lease_koid, lease_generation);
    let (slot_idx, domain_id, pt_root_phys, is_new_domain) = match existing {
        Some(existing_idx) => {
            let rec = guard.domains.slots()[existing_idx];
            if rec.pci_address_packed != pci_address_packed {
                return Err(VtdHwError::Policy(VtdError::IsolationGroupConflict));
            }
            (existing_idx, rec.domain_id, rec.slpt_root_phys, false)
        }
        None => {
            let pt_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
            zero_frame_4k(pt_phys, true);
            let group_id = derive_isolation_group(pci_address_packed, None);
            let (idx, did) = match guard.domains.allocate_domain_min(
                unit_idx as u8,
                AMD_VI_FIRST_LEASE_DOMAIN_ID,
                AMD_VI_MAX_DOMAINS,
                pci_address_packed,
                group_id,
                lease_koid,
                lease_generation,
                pt_phys,
            ) {
                Ok(pair) => pair,
                Err(err) => {
                    huesos_pmm::free_frame(pt_phys);
                    return Err(VtdHwError::Policy(err));
                }
            };

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
                        if let Err(err) = map_range_in_amd_pt(pt_phys, start_4k, end_4k - start_4k)
                        {
                            let _ = guard.domains.release_lease(lease_koid, lease_generation);
                            free_amd_pt_tree(pt_phys, 4);
                            return Err(err);
                        }
                    }
                }
                r_idx += 1;
            }
            (idx, did, pt_phys, true)
        }
    };

    let inserted = match guard.domains.record_range(slot_idx, range) {
        Ok(ins) => ins,
        Err(err) => {
            if is_new_domain {
                let _ = guard.domains.release_lease(lease_koid, lease_generation);
                free_amd_pt_tree(pt_root_phys, 4);
            }
            return Err(VtdHwError::Policy(err));
        }
    };

    if inserted {
        if let Err(err) = map_range_in_amd_pt(pt_root_phys, range.base, range.len) {
            if is_new_domain {
                let _ = guard.domains.release_lease(lease_koid, lease_generation);
                free_amd_pt_tree(pt_root_phys, 4);
            }
            return Err(err);
        }
    }

    let engine = &mut guard.units[unit_idx];
    if is_new_domain {
        let dte = AmdViDte::translated(pt_root_phys, domain_id)?;
        write_dte(engine.devtab_phys, bdf, &dte);
    }
    let cmds = [
        AmdViCommand::invalidate_devtab_entry(bdf),
        AmdViCommand::invalidate_domain_all(AMD_VI_BLOCKED_DOMAIN_ID),
        AmdViCommand::invalidate_domain_all(domain_id),
    ];
    submit_commands_and_wait(engine, &cmds)
}

/// Synchronously unbind `pci_address_packed` for `(lease_koid, lease_generation)`,
/// restore its default-deny `DTE`, flush DTE + IOTLB caches via `COMPLETION_WAIT`,
/// and free all 4-level I/O page-table frames.
pub fn teardown_lease(pci_address_packed: u64, lease_koid: u64, lease_generation: u64) {
    if !is_active() {
        return;
    }
    let mut guard = AMD_VI_STATE.lock();
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

    let mut has_specific_ivmd = false;
    let mut r_idx = 0usize;
    while r_idx < guard.reserved_count {
        let reg = guard.reserved[r_idx];
        if reg.segment == segment && reg.requester_bdf == bdf {
            has_specific_ivmd = true;
            break;
        }
        r_idx += 1;
    }

    {
        let engine = &mut guard.units[unit_idx];
        if has_specific_ivmd && engine.ivmd_fallback_pt_phys != 0 {
            if let Ok(dte) =
                AmdViDte::translated(engine.ivmd_fallback_pt_phys, AMD_VI_IVMD_DOMAIN_ID)
            {
                write_dte(engine.devtab_phys, bdf, &dte);
            }
        } else if let Ok(blocked) = AmdViDte::blocked(engine.blocked_pt_phys) {
            write_dte(engine.devtab_phys, bdf, &blocked);
        }
        let cmds = [
            AmdViCommand::invalidate_devtab_entry(bdf),
            AmdViCommand::invalidate_domain_all(removed.domain_id),
            AmdViCommand::invalidate_domain_all(AMD_VI_BLOCKED_DOMAIN_ID),
        ];
        let _ = submit_commands_and_wait(engine, &cmds);
    }

    free_amd_pt_tree(removed.slpt_root_phys, 4);
}

/// Drain pending AMD-Vi Event Log entries across all active `IVHD` units,
/// advancing `MMIO_EVT_HEAD` and returning up to `out.len()` [`FaultRecord`]s.
pub fn drain_faults(out: &mut [FaultRecord]) -> usize {
    if !is_active() {
        return 0;
    }
    let guard = AMD_VI_STATE.lock();
    let mut written = 0usize;
    let mut u_idx = 0usize;
    while u_idx < guard.unit_count {
        let engine = &guard.units[u_idx];
        if !engine.active {
            u_idx += 1;
            continue;
        }
        let tail = mmio_read64(engine.register_base, MMIO_EVT_TAIL) & AMD_VI_RING_OFFSET_MASK;
        let mut head = mmio_read64(engine.register_base, MMIO_EVT_HEAD) & AMD_VI_RING_OFFSET_MASK;
        let mut steps = 0usize;
        while head != tail && steps < AMD_VI_RING_CAPACITY {
            steps += 1;
            let word_idx = (head as usize) / 8;
            let w0 = phys_read64(engine.evt_log_phys, word_idx);
            let w1 = phys_read64(engine.evt_log_phys, word_idx + 1);
            phys_write64(engine.evt_log_phys, word_idx, 0, true);
            phys_write64(engine.evt_log_phys, word_idx + 1, 0, true);
            if let Some(rec) = decode_amd_vi_event(u_idx as u8, w0, w1) {
                AMD_VI_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
                if written < out.len() {
                    out[written] = rec;
                    written += 1;
                }
            }
            head = advance_ring_offset_4k(head);
        }
        if steps > 0 {
            mmio_write64(engine.register_base, MMIO_EVT_HEAD, head);
        }
        let status = mmio_read64(engine.register_base, MMIO_STATUS);
        if (status & (STATUS_EVENT_LOG_INT | STATUS_EVENT_OVERFLOW)) != 0 {
            mmio_write64(
                engine.register_base,
                MMIO_STATUS,
                STATUS_EVENT_LOG_INT | STATUS_EVENT_OVERFLOW,
            );
        }
        u_idx += 1;
    }
    written
}

fn bring_up_ivhd_hardware(engine: &mut IvhdEngine) -> Result<(), VtdHwError> {
    let base = engine.register_base;
    // Quiesce translation and rings prior to reprogramming base pointers.
    mmio_write64(base, MMIO_CONTROL, 0);
    mmio_write64(base, MMIO_EXCL_BASE, 0);
    mmio_write64(base, MMIO_EXCL_LIMIT, 0);

    let devtab_reg = encode_devtab_base(engine.devtab_phys)?;
    let cmdbuf_reg = encode_ring_base_4k(engine.cmd_buf_phys)?;
    let evtlog_reg = encode_ring_base_4k(engine.evt_log_phys)?;

    mmio_write64(base, MMIO_DEVTAB_BASE, devtab_reg);
    mmio_write64(base, MMIO_CMDBUF_BASE, cmdbuf_reg);
    mmio_write64(base, MMIO_EVTLOG_BASE, evtlog_reg);
    mmio_write64(base, MMIO_CMD_HEAD, 0);
    mmio_write64(base, MMIO_CMD_TAIL, 0);
    mmio_write64(base, MMIO_EVT_HEAD, 0);
    mmio_write64(base, MMIO_EVT_TAIL, 0);
    mmio_write64(base, MMIO_STATUS, STATUS_RW1C_ALL);
    engine.cmd_tail = 0;

    fence(Ordering::SeqCst);
    let ctrl = CTRL_IOMMU_EN | CTRL_EVENT_LOG_EN | CTRL_COHERENT | CTRL_CMD_BUF_EN;
    mmio_write64(base, MMIO_CONTROL, ctrl);

    let init_cmds = [AmdViCommand::invalidate_domain_all(
        AMD_VI_BLOCKED_DOMAIN_ID,
    )];
    submit_commands_and_wait(engine, &init_cmds)
}

fn submit_commands_and_wait(
    engine: &mut IvhdEngine,
    cmds: &[AmdViCommand],
) -> Result<(), VtdHwError> {
    let base = engine.register_base;
    mmio_write64(base, MMIO_STATUS, STATUS_COM_WAIT_INT);

    for cmd in cmds {
        enqueue_command(engine, *cmd);
    }
    enqueue_command(engine, AmdViCommand::completion_wait_status());

    fence(Ordering::SeqCst);
    mmio_write64(base, MMIO_CMD_TAIL, engine.cmd_tail);

    let mut spins = 0usize;
    while spins < HW_POLL_BUDGET {
        if (mmio_read64(base, MMIO_STATUS) & STATUS_COM_WAIT_INT) != 0 {
            mmio_write64(base, MMIO_STATUS, STATUS_COM_WAIT_INT);
            return Ok(());
        }
        core::hint::spin_loop();
        spins += 1;
    }
    Err(VtdHwError::HardwareTimeout)
}

fn enqueue_command(engine: &mut IvhdEngine, cmd: AmdViCommand) {
    let word_idx = (engine.cmd_tail as usize) / 8;
    phys_write64(engine.cmd_buf_phys, word_idx, cmd.lo, true);
    phys_write64(engine.cmd_buf_phys, word_idx + 1, cmd.hi, true);
    engine.cmd_tail = advance_ring_offset_4k(engine.cmd_tail);
}

fn write_dte(devtab_phys: u64, bdf: u16, dte: &AmdViDte) {
    let base_slot = usize::from(bdf) * 4;
    // Write upper words (`DomainID` in `words[1]`) before `words[0]` (`V=1, TV=1`).
    phys_write64(devtab_phys, base_slot + 3, dte.words[3], true);
    phys_write64(devtab_phys, base_slot + 2, dte.words[2], true);
    phys_write64(devtab_phys, base_slot + 1, dte.words[1], true);
    fence(Ordering::Release);
    phys_write64(devtab_phys, base_slot, dte.words[0], true);
}

fn map_range_in_amd_pt(pt_root_phys: u64, base: u64, len: u64) -> Result<(), VtdHwError> {
    let end = base.saturating_add(len);
    let mut page = base;
    while page < end {
        let mut curr_table = pt_root_phys;
        let mut lvl = 4u8;
        while lvl > 1 {
            let slot = iova_level_index(page, lvl)?;
            let existing = AmdViPte(phys_read64(curr_table, slot));
            curr_table = if let Some(next_phys) = existing.addr_4k() {
                next_phys
            } else {
                let next_phys = huesos_pmm::alloc_frame().map_err(|_| VtdHwError::OutOfMemory)?;
                zero_frame_4k(next_phys, true);
                let dir = AmdViPte::directory(next_phys, lvl - 1)?;
                phys_write64(curr_table, slot, dir.0, true);
                next_phys
            };
            lvl -= 1;
        }
        let leaf_slot = iova_level_index(page, 1)?;
        let leaf = AmdViPte::leaf_4k(page, true, true)?;
        phys_write64(curr_table, leaf_slot, leaf.0, true);
        page = page.saturating_add(PAGE_SIZE_4K);
    }
    Ok(())
}

fn free_amd_pt_tree(table_phys: u64, level: u8) {
    if table_phys == 0 {
        return;
    }
    if level > 1 {
        let mut slot = 0usize;
        while slot < 512 {
            let entry = AmdViPte(phys_read64(table_phys, slot));
            if entry.is_present() && entry.next_level() != 0 {
                if let Some(child_phys) = entry.addr_4k() {
                    free_amd_pt_tree(child_phys, level - 1);
                }
            }
            slot += 1;
        }
    }
    huesos_pmm::free_frame(table_phys);
}
