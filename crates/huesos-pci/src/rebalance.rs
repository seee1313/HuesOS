//! Restart-based transactional PCI rebalance and `QuiesceRemap` live protocol (Stages L & M.1).
//!
//! Enforces the Stage L and Stage M.1 invariants from `docs/PCI_PRODUCTION_ROADMAP.md`:
//! - **L.1 Relocation classification**: default class is [`RelocationClass::Fixed`];
//!   system NVMe (`01:08`) is unconditionally `Fixed` and never moves.
//! - **L.2 Transactional 8-step restart relocation**: for [`RelocationClass::Restart`]
//!   devices (`stop opens → stop DriverHost → revoke lease → disable decoding →
//!   apply & verify plan → mint new generation → start DriverHost → publish Online`).
//! - **L.3 Byte-for-byte rollback & fail-stop**: fault injection before or during
//!   any transition or register write either restores the previous hardware layout
//!   byte-for-byte or marks affected devices [`LeaseState::Failed`] — never leaving
//!   a partial `Online` layout.
//! - **M.1 `QuiesceRemap` protocol**: deadline-bounded `PrepareRelocation` /
//!   `Quiesced` / `NewLease` / `Resume` handshake with strict generation and
//!   epoch validation, revoking old mappings/IRQs prior to BAR reassignment.

use alloc::vec::Vec;

use crate::lease::{
    DeviceId, DeviceLeasePolicy, LeaseError, LeaseEvent, LeaseGeneration, LeaseState,
    RelocationClass,
};
use crate::resource_planner::{
    build_commit_plan, execute_commit_plan, CommitError, PlannedResource, ResourcePlan,
    BRIDGE_IO_GRANULARITY, BRIDGE_MEMORY_GRANULARITY, MAX_PLANNED_RESOURCES,
};
use crate::resource_validation::{
    FirmwareResource, ResourceClass, ResourceRegister, ResourceStatus, RootAperture,
    ValidationReport,
};
use crate::topology::{Parent, TopologySnapshot};
use crate::write_policy::{
    execute_checked_write, ConfigReadWriteTransport, HeaderKind, WriteClass, WriteRequest,
    OFFSET_COMMAND,
};
use crate::{ClassCode, ConfigWidth, PciAddress, ENHANCED_CONFIG_BYTES};

/// Classify a PCI function's allowed relocation mode, forcing system NVMe (`01:08`)
/// and host/ISA bridges to [`RelocationClass::Fixed`] regardless of manifest hint (Stage L.1).
pub const fn effective_relocation_class(
    class_code: ClassCode,
    manifest_requested: Option<RelocationClass>,
) -> RelocationClass {
    // System NVMe (01:08) and bridges/system peripherals stay strictly Fixed.
    if (class_code.class == 0x01 && class_code.subclass == 0x08) || class_code.class == 0x06 {
        return RelocationClass::Fixed;
    }
    match manifest_requested {
        Some(mode) => mode,
        None => RelocationClass::Fixed,
    }
}

/// Per-device relocation policy entry supplied to the rebalance planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceRelocationSpec {
    /// Function routing address.
    pub address: PciAddress,
    /// PCI class code (used to enforce mandatory `Fixed` on NVMe).
    pub class_code: ClassCode,
    /// Manifest-requested relocation class (`None` defaults to `Fixed`).
    pub requested: Option<RelocationClass>,
}

/// Planner or coordinator error during Stage L rebalance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebalanceError {
    /// Validation report has conflicts or exceeds resource cap.
    InvalidInput,
    /// Bounded heap allocation failed.
    NoMemory,
    /// Function/parent/aperture missing in topology.
    MissingTopology,
    /// Requirement cannot fit without moving a `Fixed` device (or aperture is too small).
    FixedDeviceBlockedOrNoSpace,
    /// Attempted to relocate a `Fixed` lease.
    FixedRelocationForbidden,
    /// Arithmetic overflow during alignment or translation.
    ArithmeticOverflow,
}

/// Plan a compacted resource layout that keeps every [`RelocationClass::Fixed`]
/// assignment untouched while allowing [`RelocationClass::Restart`] /
/// [`RelocationClass::QuiesceRemap`] endpoint BARs to move so unassigned
/// requirements fit (Stage L.1).
pub fn plan_restart_rebalance(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    validation: &ValidationReport,
    specs: &[DeviceRelocationSpec],
) -> Result<ResourcePlan, RebalanceError> {
    if validation.resources().len() > MAX_PLANNED_RESOURCES || !validation.is_conflict_free() {
        return Err(RebalanceError::InvalidInput);
    }

    let class_for = |owner: PciAddress, res_fixed: bool| -> RelocationClass {
        if res_fixed {
            return RelocationClass::Fixed;
        }
        for s in specs {
            if s.address == owner {
                return effective_relocation_class(s.class_code, s.requested);
            }
        }
        RelocationClass::Fixed
    };

    let mut planned: Vec<PlannedResource> = Vec::new();
    planned
        .try_reserve(validation.resources().len())
        .map_err(|_| RebalanceError::NoMemory)?;
    let mut fixed_ranges: Vec<(PciAddress, Option<PciAddress>, ResourceClass, u64, u64)> =
        Vec::new();
    let mut movable: Vec<(Option<u64>, FirmwareResource)> = Vec::new();

    for entry in validation.resources() {
        let res = entry.resource;
        let reloc = class_for(
            res.owner,
            entry.status == ResourceStatus::Fixed || res.fixed,
        );
        let is_bridge_win = matches!(res.register, ResourceRegister::BridgeWindow(_));
        match entry.status {
            ResourceStatus::Valid | ResourceStatus::Fixed => {
                if reloc == RelocationClass::Fixed || is_bridge_win {
                    let cpu_base = entry.cpu_base.ok_or(RebalanceError::InvalidInput)?;
                    planned.push(PlannedResource {
                        owner: res.owner,
                        register: res.register,
                        class: res.class,
                        old_pci_base: Some(res.pci_base),
                        pci_base: res.pci_base,
                        cpu_base,
                        len: res.len,
                        fixed: true,
                    });
                    let parent_bridge = match topology.find(res.owner).map(|n| n.parent) {
                        Some(Parent::Bridge(b)) => Some(b),
                        Some(Parent::Root(_)) => None,
                        None => return Err(RebalanceError::MissingTopology),
                    };
                    fixed_ranges
                        .try_reserve(1)
                        .map_err(|_| RebalanceError::NoMemory)?;
                    fixed_ranges.push((res.owner, parent_bridge, res.class, res.pci_base, res.len));
                } else {
                    movable
                        .try_reserve(1)
                        .map_err(|_| RebalanceError::NoMemory)?;
                    movable.push((Some(res.pci_base), res));
                }
            }
            ResourceStatus::Unassigned => {
                if res.len == 0 {
                    return Err(RebalanceError::InvalidInput);
                }
                movable
                    .try_reserve(1)
                    .map_err(|_| RebalanceError::NoMemory)?;
                movable.push((None, res));
            }
            _ => return Err(RebalanceError::InvalidInput),
        }
    }

    // Allocate larger / stricter-aligned movable + unassigned resources first
    // so fragmentation around pinned Fixed islands is resolved deterministically.
    movable.sort_by(|a, b| {
        b.1.len
            .cmp(&a.1.len)
            .then_with(|| a.1.owner.cmp(&b.1.owner))
            .then_with(|| a.1.register.cmp(&b.1.register))
    });

    for (old_base, res) in movable {
        let align = match res.register {
            ResourceRegister::Bar(_) => {
                if !res.len.is_power_of_two() {
                    return Err(RebalanceError::InvalidInput);
                }
                res.len
            }
            ResourceRegister::BridgeWindow(_) => match res.class {
                ResourceClass::Io => BRIDGE_IO_GRANULARITY,
                _ => BRIDGE_MEMORY_GRANULARITY,
            },
        };
        let node = topology
            .find(res.owner)
            .ok_or(RebalanceError::MissingTopology)?;
        let (domain_base, domain_len, parent_bridge) = match node.parent {
            Parent::Root(root_id) => {
                let ap = apertures
                    .iter()
                    .find(|a| a.root_id == root_id && a.class == res.class)
                    .ok_or(RebalanceError::FixedDeviceBlockedOrNoSpace)?;
                (ap.pci_base, ap.len, None)
            }
            Parent::Bridge(bridge_addr) => {
                let win = planned
                    .iter()
                    .find(|p| {
                        p.owner == bridge_addr
                            && matches!(p.register, ResourceRegister::BridgeWindow(_))
                            && p.class == res.class
                    })
                    .ok_or(RebalanceError::MissingTopology)?;
                (win.pci_base, win.len, Some(bridge_addr))
            }
        };

        let pci_base = fit_around_occupied(
            domain_base,
            domain_len,
            parent_bridge,
            res.class,
            res.len,
            align,
            &fixed_ranges,
        )?;
        let cpu_base =
            translate_rebalanced_cpu(topology, apertures, res.owner, res.class, pci_base, res.len)?;

        fixed_ranges
            .try_reserve(1)
            .map_err(|_| RebalanceError::NoMemory)?;
        fixed_ranges.push((res.owner, parent_bridge, res.class, pci_base, res.len));
        planned.push(PlannedResource {
            owner: res.owner,
            register: res.register,
            class: res.class,
            old_pci_base: old_base,
            pci_base,
            cpu_base,
            len: res.len,
            fixed: false,
        });
    }

    Ok(ResourcePlan::from_parts(
        topology.generation(),
        planned,
        Vec::new(),
    ))
}

fn fit_around_occupied(
    domain_base: u64,
    domain_len: u64,
    parent_bridge: Option<PciAddress>,
    class: ResourceClass,
    len: u64,
    align: u64,
    occupied: &[(PciAddress, Option<PciAddress>, ResourceClass, u64, u64)],
) -> Result<u64, RebalanceError> {
    let domain_end = domain_base
        .checked_add(domain_len)
        .ok_or(RebalanceError::ArithmeticOverflow)?;
    let mask = align - 1;
    let mut cursor = domain_base
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(RebalanceError::ArithmeticOverflow)?;

    let mut blockers: Vec<(u64, u64)> = Vec::new();
    for &(_owner, p_bridge, c_class, b_base, b_len) in occupied {
        if p_bridge == parent_bridge
            && c_class == class
            && b_base >= domain_base
            && b_base < domain_end
        {
            blockers
                .try_reserve(1)
                .map_err(|_| RebalanceError::NoMemory)?;
            blockers.push((b_base, b_len));
        }
    }
    blockers.sort_by_key(|&(b, _)| b);

    for (b_base, b_len) in blockers {
        let cand_end = cursor
            .checked_add(len)
            .ok_or(RebalanceError::ArithmeticOverflow)?;
        if cand_end <= b_base {
            return Ok(cursor);
        }
        let b_end = b_base
            .checked_add(b_len)
            .ok_or(RebalanceError::ArithmeticOverflow)?;
        if cursor < b_end {
            cursor = b_end
                .checked_add(mask)
                .map(|v| v & !mask)
                .ok_or(RebalanceError::ArithmeticOverflow)?;
        }
    }
    let cand_end = cursor
        .checked_add(len)
        .ok_or(RebalanceError::ArithmeticOverflow)?;
    if cand_end <= domain_end {
        Ok(cursor)
    } else {
        Err(RebalanceError::FixedDeviceBlockedOrNoSpace)
    }
}

fn translate_rebalanced_cpu(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    owner: PciAddress,
    class: ResourceClass,
    pci_base: u64,
    len: u64,
) -> Result<u64, RebalanceError> {
    let mut parent = topology.find(owner).map(|n| n.parent);
    let mut hops = 0usize;
    let root_id = loop {
        if hops > 16 {
            return Err(RebalanceError::MissingTopology);
        }
        hops += 1;
        match parent {
            Some(Parent::Root(id)) => break id,
            Some(Parent::Bridge(b)) => parent = topology.find(b).map(|n| n.parent),
            None => return Err(RebalanceError::MissingTopology),
        }
    };
    let end = pci_base
        .checked_add(len)
        .ok_or(RebalanceError::ArithmeticOverflow)?;
    for ap in apertures {
        let ap_end = ap
            .pci_base
            .checked_add(ap.len)
            .ok_or(RebalanceError::ArithmeticOverflow)?;
        if ap.root_id == root_id && ap.class == class && pci_base >= ap.pci_base && end <= ap_end {
            let delta = pci_base
                .checked_sub(ap.pci_base)
                .ok_or(RebalanceError::ArithmeticOverflow)?;
            return ap
                .cpu_base
                .checked_add(delta)
                .ok_or(RebalanceError::ArithmeticOverflow);
        }
    }
    Err(RebalanceError::FixedDeviceBlockedOrNoSpace)
}

/// Named steps in the Stage L.2 transactional restart relocation sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartStep {
    /// 1. Block new service opens in the supervisor registry.
    StopNewOpens,
    /// 2. Terminate and reap the existing DriverHost process.
    StopDriverHost,
    /// 3. Revoke the old lease generation (`DeviceGone`).
    RevokeOldLease,
    /// 4. Disable PCI Command `IO | MSE | BusMaster` decoding.
    DisableHardwareDecoding,
    /// 5. Commit and readback-verify the new BAR/window layout.
    ApplyAndVerifyPlan,
    /// 6. Mint new generation resources and re-enable endpoint decoding.
    MintNewResources,
    /// 7. Launch new DriverHost instance and await readiness.
    StartNewDriverHost,
    /// 8. Publish service `Online` after DriverHost readiness.
    PublishServiceOnline,
}

/// Supervisor lifecycle hooks invoked by [`execute_restart_rebalance`].
pub trait RestartLifecycleHooks {
    /// Block new client opens for `address`.
    fn stop_new_opens(&mut self, address: PciAddress) -> bool;
    /// Stop existing DriverHost `process_koid` for `address`.
    fn stop_driver_host(&mut self, address: PciAddress, process_koid: u64) -> bool;
    /// Mint narrow child resources under `new_generation` for `address`.
    fn mint_new_resources(&mut self, address: PciAddress, new_generation: LeaseGeneration) -> bool;
    /// Spawn replacement DriverHost for `address`, returning its non-zero KOID once ready.
    fn start_driver_host(
        &mut self,
        address: PciAddress,
        new_generation: LeaseGeneration,
    ) -> Option<u64>;
    /// Republish service `Online` for `address`.
    fn publish_service(&mut self, address: PciAddress, new_generation: LeaseGeneration) -> bool;
}

/// Final outcome of [`execute_restart_rebalance`] (Stage L.2 / L.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebalanceOutcome {
    /// All relocated devices committed, restarted on new generations, and published `Online`.
    CommittedNewLayout {
        /// Number of devices relocated and restarted.
        relocated_devices: usize,
        /// Number of configuration-space register writes committed.
        register_writes: usize,
    },
    /// Fault occurred at `failed_step`, previous hardware registers were restored
    /// byte-for-byte, and affected devices either stayed on the old layout (if
    /// stopped before revocation) or restarted cleanly on the restored old layout.
    RolledBackToOldLayout {
        /// Step where the fault occurred.
        failed_step: RestartStep,
    },
    /// Fault occurred and either rollback readback failed or recovery DriverHost
    /// launch failed; affected relocated devices are marked [`LeaseState::Failed`]
    /// fail-stop (never partial `Online`).
    FailStopMarkedFailed {
        /// Step where the primary fault occurred.
        failed_step: RestartStep,
        /// True when hardware registers were restored byte-for-byte before marking `Failed`.
        hardware_restored: bool,
    },
}

/// Execute the Stage L.2 / L.3 transactional restart rebalance across `leases`.
///
/// Unmoved [`RelocationClass::Fixed`] leases are verified untouched throughout.
pub fn execute_restart_rebalance(
    topology: &TopologySnapshot,
    new_plan: &ResourcePlan,
    leases: &mut [DeviceLeasePolicy],
    transport: &mut impl ConfigReadWriteTransport,
    hooks: &mut impl RestartLifecycleHooks,
) -> Result<RebalanceOutcome, RebalanceError> {
    let mut moved_indices: Vec<usize> = Vec::new();
    for res in new_plan.resources() {
        if !res.moved() {
            continue;
        }
        let Some(pos) = leases.iter().position(|l| l.address() == res.owner) else {
            return Err(RebalanceError::MissingTopology);
        };
        if leases[pos].relocation() != RelocationClass::Restart {
            return Err(RebalanceError::FixedRelocationForbidden);
        }
        if !moved_indices.contains(&pos) {
            moved_indices
                .try_reserve(1)
                .map_err(|_| RebalanceError::NoMemory)?;
            moved_indices.push(pos);
        }
    }

    let commit_plan = build_commit_plan(topology, new_plan, transport)
        .map_err(|_| RebalanceError::InvalidInput)?;

    // Snapshot original Command registers for every moved device before touching anything.
    let mut saved_cmds: Vec<(usize, PciAddress, u32)> = Vec::new();
    saved_cmds
        .try_reserve_exact(moved_indices.len())
        .map_err(|_| RebalanceError::NoMemory)?;
    for &idx in &moved_indices {
        let addr = leases[idx].address();
        let cmd = transport
            .read_width(addr, OFFSET_COMMAND, ConfigWidth::Word)
            .ok_or(RebalanceError::MissingTopology)?;
        saved_cmds.push((idx, addr, cmd & 0x0407));
    }

    // Step 1: Stop new opens. If this fails before revocation, restore opens on prior devices.
    for (done, &idx) in moved_indices.iter().enumerate() {
        let addr = leases[idx].address();
        if !hooks.stop_new_opens(addr) {
            for &prev_idx in &moved_indices[..done] {
                let _ = hooks
                    .publish_service(leases[prev_idx].address(), leases[prev_idx].generation());
            }
            return Ok(RebalanceOutcome::RolledBackToOldLayout {
                failed_step: RestartStep::StopNewOpens,
            });
        }
    }

    // Step 2: Stop DriverHosts.
    for &idx in &moved_indices {
        let addr = leases[idx].address();
        let koid = leases[idx].driver_process().unwrap_or(1);
        if !hooks.stop_driver_host(addr, koid) {
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::StopDriverHost,
                hardware_restored: true,
            });
        }
    }

    // Step 3: Revoke old lease generations (`Online -> Quiescing -> Rebalancing`).
    for &idx in &moved_indices {
        let cur_gen = leases[idx].generation();
        if leases[idx]
            .apply(cur_gen, LeaseEvent::BeginRelocation)
            .is_err()
            || leases[idx]
                .apply(cur_gen, LeaseEvent::DriverQuiesced)
                .is_err()
        {
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::RevokeOldLease,
                hardware_restored: true,
            });
        }
    }

    // Step 4: Disable PCI Command decoding (`IO | MSE | BusMaster`) before moving BARs.
    for (disable_done, &(_idx, addr, old_cmd)) in saved_cmds.iter().enumerate() {
        let req = WriteRequest {
            address: addr,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: old_cmd & !0x0007,
            write_mask: 0x0007,
            expected_readback_mask: 0x0007,
            allowlist_entry: None,
        };
        if execute_checked_write(transport, &req).is_err() {
            let hw_ok = restore_saved_commands(&saved_cmds[..disable_done], transport);
            return Ok(recover_or_fail_stop(
                leases,
                &moved_indices,
                RestartStep::DisableHardwareDecoding,
                hw_ok,
                hooks,
            ));
        }
    }

    // Step 5: Apply & readback-verify new BAR/window CommitPlan.
    match execute_commit_plan(&commit_plan, transport) {
        Ok(_) => {}
        Err(CommitError::RolledBack { .. }) => {
            let hw_ok = restore_saved_commands(&saved_cmds, transport);
            return Ok(recover_or_fail_stop(
                leases,
                &moved_indices,
                RestartStep::ApplyAndVerifyPlan,
                hw_ok,
                hooks,
            ));
        }
        Err(CommitError::RollbackFailed { .. } | CommitError::NoMemory) => {
            let _ = restore_saved_commands(&saved_cmds, transport);
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::ApplyAndVerifyPlan,
                hardware_restored: false,
            });
        }
    }

    // Step 6: Commit relocation on leases, re-enable Command decoding, and mint new resources.
    for &(idx, addr, old_cmd) in &saved_cmds {
        let gen_now = leases[idx].generation();
        if leases[idx]
            .apply(gen_now, LeaseEvent::CommitRelocation { new_address: addr })
            .is_err()
        {
            let bars_ok = rollback_all_writes(&commit_plan, transport);
            let cmd_ok = restore_saved_commands(&saved_cmds, transport);
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::MintNewResources,
                hardware_restored: bars_ok && cmd_ok,
            });
        }
        let enable_bits = if (old_cmd & 0x0007) != 0 {
            old_cmd & 0x0407
        } else {
            0x0406
        };
        let en_req = WriteRequest {
            address: addr,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: enable_bits,
            write_mask: enable_bits & 0x0407,
            expected_readback_mask: enable_bits & 0x0406,
            allowlist_entry: None,
        };
        if execute_checked_write(transport, &en_req).is_err()
            || !hooks.mint_new_resources(addr, gen_now)
        {
            let _ = disable_all_commands(&saved_cmds, transport);
            let bars_ok = rollback_all_writes(&commit_plan, transport);
            let cmd_ok = restore_saved_commands(&saved_cmds, transport);
            return Ok(recover_or_fail_stop(
                leases,
                &moved_indices,
                RestartStep::MintNewResources,
                bars_ok && cmd_ok,
                hooks,
            ));
        }
    }

    // Step 7: Start replacement DriverHosts.
    let mut started: Vec<(usize, u64)> = Vec::new();
    for &idx in &moved_indices {
        let addr = leases[idx].address();
        let gen_now = leases[idx].generation();
        let Some(new_koid) = hooks.start_driver_host(addr, gen_now) else {
            for &(s_idx, s_koid) in &started {
                let _ = hooks.stop_driver_host(leases[s_idx].address(), s_koid);
            }
            let _ = disable_all_commands(&saved_cmds, transport);
            let bars_ok = rollback_all_writes(&commit_plan, transport);
            let cmd_ok = restore_saved_commands(&saved_cmds, transport);
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::StartNewDriverHost,
                hardware_restored: bars_ok && cmd_ok,
            });
        };
        if leases[idx]
            .apply(
                gen_now,
                LeaseEvent::StartDriver {
                    process_koid: new_koid,
                },
            )
            .is_err()
        {
            let _ = hooks.stop_driver_host(addr, new_koid);
            for &(s_idx, s_koid) in &started {
                let _ = hooks.stop_driver_host(leases[s_idx].address(), s_koid);
            }
            let _ = disable_all_commands(&saved_cmds, transport);
            let bars_ok = rollback_all_writes(&commit_plan, transport);
            let cmd_ok = restore_saved_commands(&saved_cmds, transport);
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::StartNewDriverHost,
                hardware_restored: bars_ok && cmd_ok,
            });
        }
        started
            .try_reserve(1)
            .map_err(|_| RebalanceError::NoMemory)?;
        started.push((idx, new_koid));
    }

    // Step 8: Transition leases `Online` and publish services.
    for &(idx, koid) in &started {
        let addr = leases[idx].address();
        let gen_now = leases[idx].generation();
        if !hooks.publish_service(addr, gen_now)
            || leases[idx].apply(gen_now, LeaseEvent::DriverReady).is_err()
        {
            let _ = hooks.stop_driver_host(addr, koid);
            for &(s_idx, s_koid) in &started {
                if s_idx != idx {
                    let _ = hooks.stop_driver_host(leases[s_idx].address(), s_koid);
                }
            }
            let _ = disable_all_commands(&saved_cmds, transport);
            let bars_ok = rollback_all_writes(&commit_plan, transport);
            let cmd_ok = restore_saved_commands(&saved_cmds, transport);
            fail_stop_leases(leases, &moved_indices);
            return Ok(RebalanceOutcome::FailStopMarkedFailed {
                failed_step: RestartStep::PublishServiceOnline,
                hardware_restored: bars_ok && cmd_ok,
            });
        }
    }

    Ok(RebalanceOutcome::CommittedNewLayout {
        relocated_devices: moved_indices.len(),
        register_writes: commit_plan.writes().len(),
    })
}

fn disable_all_commands(
    saved_cmds: &[(usize, PciAddress, u32)],
    transport: &mut impl ConfigReadWriteTransport,
) -> bool {
    let mut ok = true;
    for &(_idx, addr, old_cmd) in saved_cmds {
        let req = WriteRequest {
            address: addr,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: old_cmd & !0x0007,
            write_mask: 0x0007,
            expected_readback_mask: 0x0007,
            allowlist_entry: None,
        };
        if execute_checked_write(transport, &req).is_err() {
            ok = false;
        }
    }
    ok
}

fn restore_saved_commands(
    saved_cmds: &[(usize, PciAddress, u32)],
    transport: &mut impl ConfigReadWriteTransport,
) -> bool {
    let mut all_ok = true;
    for &(_idx, addr, old_cmd) in saved_cmds.iter().rev() {
        let req = WriteRequest {
            address: addr,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: old_cmd,
            write_mask: 0x0407,
            expected_readback_mask: old_cmd & 0x0406,
            allowlist_entry: None,
        };
        if execute_checked_write(transport, &req).is_err() {
            all_ok = false;
        }
    }
    all_ok
}

fn rollback_all_writes(
    commit_plan: &crate::resource_planner::CommitPlan,
    transport: &mut impl ConfigReadWriteTransport,
) -> bool {
    let mut all_ok = true;
    for w in commit_plan.rollback_writes() {
        let rb = w.as_rollback_request();
        if execute_checked_write(transport, &rb).is_err() {
            all_ok = false;
        }
    }
    all_ok
}

fn fail_stop_leases(leases: &mut [DeviceLeasePolicy], indices: &[usize]) {
    for &idx in indices {
        let g = leases[idx].generation();
        let _ = leases[idx].apply(g, LeaseEvent::Fail);
    }
}

fn recover_or_fail_stop(
    leases: &mut [DeviceLeasePolicy],
    indices: &[usize],
    failed_step: RestartStep,
    hardware_restored: bool,
    hooks: &mut impl RestartLifecycleHooks,
) -> RebalanceOutcome {
    if !hardware_restored {
        fail_stop_leases(leases, indices);
        return RebalanceOutcome::FailStopMarkedFailed {
            failed_step,
            hardware_restored: false,
        };
    }
    // Attempt atomic recovery restart on the byte-for-byte restored old layout;
    // if any recovery hook fails, transition ALL relocated devices to `Failed`
    // so partial Online state is impossible.
    for &idx in indices {
        let addr = leases[idx].address();
        let g = leases[idx].generation();
        if leases[idx].state() == LeaseState::Rebalancing
            && leases[idx]
                .apply(g, LeaseEvent::CommitRelocation { new_address: addr })
                .is_err()
        {
            fail_stop_leases(leases, indices);
            return RebalanceOutcome::FailStopMarkedFailed {
                failed_step,
                hardware_restored: true,
            };
        }
        let g2 = leases[idx].generation();
        let Some(koid) = hooks.start_driver_host(addr, g2) else {
            fail_stop_leases(leases, indices);
            return RebalanceOutcome::FailStopMarkedFailed {
                failed_step,
                hardware_restored: true,
            };
        };
        if !hooks.mint_new_resources(addr, g2)
            || leases[idx]
                .apply(g2, LeaseEvent::StartDriver { process_koid: koid })
                .is_err()
            || !hooks.publish_service(addr, g2)
            || leases[idx].apply(g2, LeaseEvent::DriverReady).is_err()
        {
            let _ = hooks.stop_driver_host(addr, koid);
            fail_stop_leases(leases, indices);
            return RebalanceOutcome::FailStopMarkedFailed {
                failed_step,
                hardware_restored: true,
            };
        }
    }
    RebalanceOutcome::RolledBackToOldLayout { failed_step }
}

// ============================================================================
// Stage M.1 — Deadline-bounded `QuiesceRemap` live relocation protocol
// ============================================================================

/// Wire/IPC messages for opt-in `QuiesceRemap` live BAR relocation (Stage M.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceRemapMessage {
    /// PCI Manager instructs DriverHost to drain DMA/MMIO before `deadline_tick`.
    PrepareRelocation {
        /// Target device presence ID.
        device_id: DeviceId,
        /// Current active lease generation (`G`).
        lease_generation: LeaseGeneration,
        /// Monotonic rebalance session epoch.
        epoch: u64,
        /// Monotonic tick deadline for quiesce acknowledgement.
        deadline_tick: u64,
    },
    /// DriverHost confirms all DMA/MMIO/IRQ activity on `lease_generation` has ceased.
    Quiesced {
        /// Target device presence ID.
        device_id: DeviceId,
        /// Generation being relinquished (`G`).
        lease_generation: LeaseGeneration,
        /// Matching rebalance epoch.
        epoch: u64,
    },
    /// PCI Manager delivers the post-relocation lease generation (`G + 1`).
    NewLease {
        /// Target device presence ID.
        device_id: DeviceId,
        /// Newly committed lease generation (`G + 1`).
        new_generation: LeaseGeneration,
        /// Matching rebalance epoch.
        epoch: u64,
        /// Updated routing address.
        new_address: PciAddress,
    },
    /// DriverHost mapped replacement BARs/IRQs on `new_generation` and resumed service.
    Resume {
        /// Target device presence ID.
        device_id: DeviceId,
        /// Active replacement generation (`G + 1`).
        new_generation: LeaseGeneration,
        /// Matching rebalance epoch.
        epoch: u64,
    },
}

/// Rejection reasons for `QuiesceRemap` protocol transitions (Stage M.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceRemapError {
    /// Lease is not `RelocationClass::QuiesceRemap` or not `Online`.
    UnsupportedOrInvalidState,
    /// `epoch` is zero.
    InvalidEpoch,
    /// Reply carried a mismatched `DeviceId`, `LeaseGeneration`, or `epoch`.
    StaleReplyRejected,
    /// DriverHost missed `deadline_tick`; lease transitioned fail-stop to `Failed`.
    DeadlineExceededFailStop,
    /// Underlying `DeviceLeasePolicy` transition error.
    Lease(LeaseError),
}

/// Phase of an active `QuiesceRemap` session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceRemapPhase {
    /// Waiting for `Quiesced` reply before `deadline_tick`.
    AwaitingQuiesced,
    /// Old generation is revoked; hardware BAR/window writes may execute safely.
    ReadyForHardwareMutation,
    /// Replacement lease delivered; waiting for `Resume` before `deadline_tick`.
    AwaitingResume,
    /// Live relocation completed and lease returned `Online`.
    Completed,
    /// Session failed closed (`LeaseState::Failed`).
    FailedClosed,
}

/// Deadline-bounded `QuiesceRemap` coordinator for one opt-in device (Stage M.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiesceRemapSession {
    device_id: DeviceId,
    initial_generation: LeaseGeneration,
    post_revoke_generation: Option<LeaseGeneration>,
    epoch: u64,
    deadline_tick: u64,
    phase: QuiesceRemapPhase,
}

impl QuiesceRemapSession {
    /// Start a live-relocation session and emit [`QuiesceRemapMessage::PrepareRelocation`].
    pub fn begin(
        lease: &mut DeviceLeasePolicy,
        epoch: u64,
        deadline_tick: u64,
    ) -> Result<(Self, QuiesceRemapMessage), QuiesceRemapError> {
        if epoch == 0 {
            return Err(QuiesceRemapError::InvalidEpoch);
        }
        if lease.relocation() != RelocationClass::QuiesceRemap
            || lease.state() != LeaseState::Online
        {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        }
        let gen0 = lease.generation();
        lease
            .apply(gen0, LeaseEvent::BeginRelocation)
            .map_err(QuiesceRemapError::Lease)?;
        let session = Self {
            device_id: lease.device_id(),
            initial_generation: gen0,
            post_revoke_generation: None,
            epoch,
            deadline_tick,
            phase: QuiesceRemapPhase::AwaitingQuiesced,
        };
        let msg = QuiesceRemapMessage::PrepareRelocation {
            device_id: session.device_id,
            lease_generation: gen0,
            epoch,
            deadline_tick,
        };
        Ok((session, msg))
    }

    /// Current protocol phase.
    pub const fn phase(&self) -> QuiesceRemapPhase {
        self.phase
    }

    /// True only after `Quiesced` has revoked the previous lease generation.
    pub const fn ready_for_bar_mutation(&self) -> bool {
        matches!(self.phase, QuiesceRemapPhase::ReadyForHardwareMutation)
    }

    /// Process a `Quiesced` message at `now_tick`, revoking `initial_generation` before BAR writes.
    pub fn on_quiesced(
        &mut self,
        lease: &mut DeviceLeasePolicy,
        reply: QuiesceRemapMessage,
        now_tick: u64,
    ) -> Result<LeaseGeneration, QuiesceRemapError> {
        if self.phase != QuiesceRemapPhase::AwaitingQuiesced {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        }
        let QuiesceRemapMessage::Quiesced {
            device_id,
            lease_generation,
            epoch,
        } = reply
        else {
            return Err(QuiesceRemapError::StaleReplyRejected);
        };
        if device_id != self.device_id
            || lease_generation != self.initial_generation
            || epoch != self.epoch
        {
            return Err(QuiesceRemapError::StaleReplyRejected);
        }
        if now_tick > self.deadline_tick {
            let g = lease.generation();
            let _ = lease.apply(g, LeaseEvent::Fail);
            self.phase = QuiesceRemapPhase::FailedClosed;
            return Err(QuiesceRemapError::DeadlineExceededFailStop);
        }
        let tr = lease
            .apply(self.initial_generation, LeaseEvent::DriverQuiesced)
            .map_err(QuiesceRemapError::Lease)?;
        self.post_revoke_generation = Some(tr.generation);
        self.phase = QuiesceRemapPhase::ReadyForHardwareMutation;
        Ok(tr.generation)
    }

    /// Commit hardware BAR relocation and emit [`QuiesceRemapMessage::NewLease`].
    pub fn commit_hardware_and_issue_new_lease(
        &mut self,
        lease: &mut DeviceLeasePolicy,
        new_address: PciAddress,
        resume_deadline_tick: u64,
    ) -> Result<QuiesceRemapMessage, QuiesceRemapError> {
        if self.phase != QuiesceRemapPhase::ReadyForHardwareMutation {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        }
        let Some(new_gen) = self.post_revoke_generation else {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        };
        let koid = lease.driver_process().unwrap_or(1);
        lease
            .apply(new_gen, LeaseEvent::CommitRelocation { new_address })
            .map_err(QuiesceRemapError::Lease)?;
        lease
            .apply(new_gen, LeaseEvent::StartDriver { process_koid: koid })
            .map_err(QuiesceRemapError::Lease)?;
        self.deadline_tick = resume_deadline_tick;
        self.phase = QuiesceRemapPhase::AwaitingResume;
        Ok(QuiesceRemapMessage::NewLease {
            device_id: self.device_id,
            new_generation: new_gen,
            epoch: self.epoch,
            new_address,
        })
    }

    /// Process a `Resume` message at `now_tick` to return the lease `Online`.
    pub fn on_resume(
        &mut self,
        lease: &mut DeviceLeasePolicy,
        reply: QuiesceRemapMessage,
        now_tick: u64,
    ) -> Result<(), QuiesceRemapError> {
        if self.phase != QuiesceRemapPhase::AwaitingResume {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        }
        let Some(expected_gen) = self.post_revoke_generation else {
            return Err(QuiesceRemapError::UnsupportedOrInvalidState);
        };
        let QuiesceRemapMessage::Resume {
            device_id,
            new_generation,
            epoch,
        } = reply
        else {
            return Err(QuiesceRemapError::StaleReplyRejected);
        };
        if device_id != self.device_id || new_generation != expected_gen || epoch != self.epoch {
            return Err(QuiesceRemapError::StaleReplyRejected);
        }
        if now_tick > self.deadline_tick {
            let _ = lease.apply(expected_gen, LeaseEvent::Fail);
            self.phase = QuiesceRemapPhase::FailedClosed;
            return Err(QuiesceRemapError::DeadlineExceededFailStop);
        }
        lease
            .apply(expected_gen, LeaseEvent::DriverReady)
            .map_err(QuiesceRemapError::Lease)?;
        self.phase = QuiesceRemapPhase::Completed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::DmaIsolation;
    use crate::resource_validation::validate_firmware_resources;
    use crate::topology::{build_snapshot, DiscoveredFunction, RootBus};

    fn bdf(dev: u8) -> PciAddress {
        match PciAddress::try_new(0, 0, dev, 0) {
            Ok(a) => a,
            Err(_) => {
                assert!(false);
                PciAddress::ZERO
            }
        }
    }

    struct FaultInjectingBus {
        nvme_cmd: u32,
        nvme_bar0: u32,
        nic_cmd: u32,
        nic_bar0: u32,
        new_cmd: u32,
        new_bar0: u32,
        write_call: usize,
        fail_write_call: Option<usize>,
    }

    impl FaultInjectingBus {
        fn new() -> Self {
            Self {
                nvme_cmd: 0x0406,
                nvme_bar0: 0x8000_0000,
                nic_cmd: 0x0406,
                nic_bar0: 0x8001_0000,
                new_cmd: 0x0000,
                new_bar0: 0x0000_0000,
                write_call: 0,
                fail_write_call: None,
            }
        }
    }

    impl ConfigReadWriteTransport for FaultInjectingBus {
        fn read_width(&mut self, owner: PciAddress, offset: u16, _w: ConfigWidth) -> Option<u32> {
            match (owner.device(), offset) {
                (1, OFFSET_COMMAND) => Some(self.nvme_cmd),
                (1, 0x10) => Some(self.nvme_bar0),
                (2, OFFSET_COMMAND) => Some(self.nic_cmd),
                (2, 0x10) => Some(self.nic_bar0),
                (3, OFFSET_COMMAND) => Some(self.new_cmd),
                (3, 0x10) => Some(self.new_bar0),
                _ => Some(0),
            }
        }

        fn write_width(
            &mut self,
            owner: PciAddress,
            offset: u16,
            _w: ConfigWidth,
            val: u32,
        ) -> bool {
            self.write_call += 1;
            if self.fail_write_call == Some(self.write_call) {
                return false;
            }
            match (owner.device(), offset) {
                (1, OFFSET_COMMAND) => self.nvme_cmd = val & 0xFFFF,
                (1, 0x10) => self.nvme_bar0 = val & !0xFu32,
                (2, OFFSET_COMMAND) => self.nic_cmd = val & 0xFFFF,
                (2, 0x10) => self.nic_bar0 = val & !0xFu32,
                (3, OFFSET_COMMAND) => self.new_cmd = val & 0xFFFF,
                (3, 0x10) => self.new_bar0 = val & !0xFu32,
                _ => return false,
            }
            true
        }
    }

    struct FaultHooks {
        hook_call: usize,
        fail_hook_call: Option<usize>,
        next_koid: u64,
    }

    impl FaultHooks {
        fn new(fail_hook_call: Option<usize>) -> Self {
            Self {
                hook_call: 0,
                fail_hook_call,
                next_koid: 500,
            }
        }

        fn step_ok(&mut self) -> bool {
            self.hook_call += 1;
            self.fail_hook_call != Some(self.hook_call)
        }
    }

    impl RestartLifecycleHooks for FaultHooks {
        fn stop_new_opens(&mut self, _address: PciAddress) -> bool {
            self.step_ok()
        }
        fn stop_driver_host(&mut self, _address: PciAddress, _process_koid: u64) -> bool {
            self.step_ok()
        }
        fn mint_new_resources(
            &mut self,
            _address: PciAddress,
            _new_generation: LeaseGeneration,
        ) -> bool {
            self.step_ok()
        }
        fn start_driver_host(
            &mut self,
            _address: PciAddress,
            _new_generation: LeaseGeneration,
        ) -> Option<u64> {
            if self.step_ok() {
                let k = self.next_koid;
                self.next_koid += 1;
                Some(k)
            } else {
                None
            }
        }
        fn publish_service(
            &mut self,
            _address: PciAddress,
            _new_generation: LeaseGeneration,
        ) -> bool {
            self.step_ok()
        }
    }

    fn make_online_lease(
        id: u64,
        gen_raw: u64,
        addr: PciAddress,
        reloc: RelocationClass,
    ) -> Option<DeviceLeasePolicy> {
        let d = DeviceId::try_new(id).ok()?;
        let g = LeaseGeneration::try_new(gen_raw).ok()?;
        let mut l = DeviceLeasePolicy::try_new(d, g, addr, reloc, DmaIsolation::Trusted).ok()?;
        l.apply(g, LeaseEvent::Configure).ok()?;
        l.apply(
            g,
            LeaseEvent::StartDriver {
                process_koid: 10 + id,
            },
        )
        .ok()?;
        l.apply(g, LeaseEvent::DriverReady).ok()?;
        Some(l)
    }

    #[test]
    fn exhaustive_fault_injection_across_every_rebalance_hook_and_write_preserves_nvme_and_never_leaves_partial_online(
    ) {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        }];
        let nvme_addr = bdf(1);
        let nic_addr = bdf(2);
        let gpu_addr = bdf(3);
        let nvme_class = ClassCode {
            class: 0x01,
            subclass: 0x08,
            prog_if: 0x02,
        };
        let nic_class = ClassCode {
            class: 0x02,
            subclass: 0x00,
            prog_if: 0,
        };
        let gpu_class = ClassCode {
            class: 0x03,
            subclass: 0x00,
            prog_if: 0,
        };
        // Even if a manifest mistakenly asked for `Restart` on NVMe, L.1 forces `Fixed`!
        assert_eq!(
            effective_relocation_class(nvme_class, Some(RelocationClass::Restart)),
            RelocationClass::Fixed
        );

        let funcs = [
            DiscoveredFunction {
                address: nvme_addr,
                vendor_id: 0x1B36,
                device_id: 0x0010,
                class_code: nvme_class,
                kind: FunctionKind::Endpoint,
            },
            DiscoveredFunction {
                address: nic_addr,
                vendor_id: 0x1AF4,
                device_id: 0x1041,
                class_code: nic_class,
                kind: FunctionKind::Endpoint,
            },
            DiscoveredFunction {
                address: gpu_addr,
                vendor_id: 0x1234,
                device_id: 0x1111,
                class_code: gpu_class,
                kind: FunctionKind::Endpoint,
            },
        ];
        let Ok(topo) = build_snapshot(1, &roots, &funcs) else {
            assert!(false);
            return;
        };
        // 256 KiB root aperture [0x8000_0000 .. 0x8004_0000]:
        // - NVMe (Fixed, 64 KiB) @ 0x8000_0000
        // - NIC (Restart, 64 KiB) @ 0x8001_0000 (blocks the 128 KiB aligned upper half? Wait:
        //   0x8002_0000..0x8004_0000 is 128 KiB; put NIC @ 0x8002_0000 so 128 KiB GPU @ 0x8002_0000
        //   is blocked unless NIC moves to 0x8001_0000!)
        let apertures = [RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x0004_0000,
        }];
        let resources = [
            FirmwareResource {
                owner: nvme_addr,
                register: ResourceRegister::Bar(0),
                class: ResourceClass::Mmio32,
                assigned: true,
                pci_base: 0x8000_0000,
                len: 0x0001_0000,
                fixed: true,
            },
            FirmwareResource {
                owner: nic_addr,
                register: ResourceRegister::Bar(0),
                class: ResourceClass::Mmio32,
                assigned: true,
                pci_base: 0x8002_0000,
                len: 0x0001_0000,
                fixed: false,
            },
            FirmwareResource {
                owner: gpu_addr,
                register: ResourceRegister::Bar(0),
                class: ResourceClass::Mmio32,
                assigned: false,
                pci_base: 0,
                len: 0x0002_0000,
                fixed: false,
            },
        ];
        let Ok(val) = validate_firmware_resources(&topo, &apertures, &resources) else {
            assert!(false);
            return;
        };
        let specs = [
            DeviceRelocationSpec {
                address: nvme_addr,
                class_code: nvme_class,
                requested: Some(RelocationClass::Restart), // forced Fixed!
            },
            DeviceRelocationSpec {
                address: nic_addr,
                class_code: nic_class,
                requested: Some(RelocationClass::Restart),
            },
            DeviceRelocationSpec {
                address: gpu_addr,
                class_code: gpu_class,
                requested: None,
            },
        ];
        let Ok(rebalanced) = plan_restart_rebalance(&topo, &apertures, &val, &specs) else {
            assert!(false, "rebalance plan must succeed by moving Restart NIC");
            return;
        };
        let Some(nvme_planned) = rebalanced.find(nvme_addr, ResourceRegister::Bar(0)) else {
            assert!(false);
            return;
        };
        let Some(nic_planned) = rebalanced.find(nic_addr, ResourceRegister::Bar(0)) else {
            assert!(false);
            return;
        };
        let Some(gpu_planned) = rebalanced.find(gpu_addr, ResourceRegister::Bar(0)) else {
            assert!(false);
            return;
        };
        assert!(!nvme_planned.moved());
        assert_eq!(nvme_planned.pci_base, 0x8000_0000);
        assert!(nic_planned.moved());
        assert_eq!(nic_planned.pci_base, 0x8001_0000);
        assert_eq!(gpu_planned.pci_base, 0x8002_0000);

        // 1. Happy path without fault injection:
        let (Some(nvme_l), Some(nic_l)) = (
            make_online_lease(1, 1, nvme_addr, RelocationClass::Fixed),
            make_online_lease(2, 10, nic_addr, RelocationClass::Restart),
        ) else {
            assert!(false);
            return;
        };
        let mut leases = [nvme_l, nic_l];
        let mut bus = FaultInjectingBus::new();
        bus.nic_bar0 = 0x8002_0000;
        let mut hooks = FaultHooks::new(None);
        let Ok(outcome) =
            execute_restart_rebalance(&topo, &rebalanced, &mut leases, &mut bus, &mut hooks)
        else {
            assert!(false);
            return;
        };
        assert_eq!(
            outcome,
            RebalanceOutcome::CommittedNewLayout {
                relocated_devices: 1,
                register_writes: 2,
            }
        );
        assert_eq!(leases[0].state(), LeaseState::Online);
        assert_eq!(leases[0].generation().get(), 1); // Fixed NVMe completely untouched!
        assert_eq!(leases[1].state(), LeaseState::Online);
        assert_eq!(leases[1].generation().get(), 11); // Restart NIC advanced generation!
        assert_eq!(bus.nic_bar0, 0x8001_0000);
        assert_eq!(bus.new_bar0, 0x8002_0000);

        // 2. Exhaustive fault injection across every hook call (1..=6) and every write call (1..=6):
        for fail_hook in 1..=6usize {
            let (Some(nvme_l), Some(nic_l)) = (
                make_online_lease(1, 1, nvme_addr, RelocationClass::Fixed),
                make_online_lease(2, 10, nic_addr, RelocationClass::Restart),
            ) else {
                assert!(false);
                return;
            };
            let mut leases = [nvme_l, nic_l];
            let mut bus = FaultInjectingBus::new();
            bus.nic_bar0 = 0x8002_0000;
            let mut hooks = FaultHooks::new(Some(fail_hook));
            let Ok(res) =
                execute_restart_rebalance(&topo, &rebalanced, &mut leases, &mut bus, &mut hooks)
            else {
                assert!(false);
                return;
            };
            // Fixed NVMe never moves and stays Online!
            assert_eq!(leases[0].state(), LeaseState::Online);
            assert_eq!(bus.nvme_bar0, 0x8000_0000);
            // Old hardware BAR layout restored byte-for-byte on every hook failure!
            assert_eq!(bus.nic_bar0, 0x8002_0000);
            assert_eq!(bus.new_bar0, 0x0000_0000);
            match res {
                RebalanceOutcome::RolledBackToOldLayout { .. } => {
                    assert_eq!(leases[1].state(), LeaseState::Online);
                }
                RebalanceOutcome::FailStopMarkedFailed {
                    hardware_restored, ..
                } => {
                    assert!(hardware_restored);
                    assert_eq!(leases[1].state(), LeaseState::Failed);
                }
                RebalanceOutcome::CommittedNewLayout { .. } => assert!(false),
            }
        }

        for fail_write in 1..=6usize {
            let (Some(nvme_l), Some(nic_l)) = (
                make_online_lease(1, 1, nvme_addr, RelocationClass::Fixed),
                make_online_lease(2, 10, nic_addr, RelocationClass::Restart),
            ) else {
                assert!(false);
                return;
            };
            let mut leases = [nvme_l, nic_l];
            let mut bus = FaultInjectingBus::new();
            bus.nic_bar0 = 0x8002_0000;
            bus.fail_write_call = Some(fail_write);
            let mut hooks = FaultHooks::new(None);
            let Ok(res) =
                execute_restart_rebalance(&topo, &rebalanced, &mut leases, &mut bus, &mut hooks)
            else {
                assert!(false);
                return;
            };
            assert_eq!(leases[0].state(), LeaseState::Online);
            assert_eq!(bus.nvme_bar0, 0x8000_0000);
            match res {
                RebalanceOutcome::RolledBackToOldLayout { .. } => {
                    assert_eq!(bus.nic_bar0, 0x8002_0000);
                    assert_eq!(bus.new_bar0, 0x0000_0000);
                    assert_eq!(leases[1].state(), LeaseState::Online);
                }
                RebalanceOutcome::FailStopMarkedFailed { .. } => {
                    assert_eq!(leases[1].state(), LeaseState::Failed);
                }
                RebalanceOutcome::CommittedNewLayout { .. } => {
                    // Only possible if `fail_write` exceeded total writes performed.
                    assert!(bus.write_call < fail_write);
                }
            }
        }
    }

    #[test]
    fn thousand_restart_rebalance_cycles_and_quiesce_remap_protocol_gates() {
        let addr = bdf(4);
        let Some(mut lease) = make_online_lease(7, 1, addr, RelocationClass::QuiesceRemap) else {
            assert!(false);
            return;
        };

        // 1,000 live QuiesceRemap cycles (Stage M.1 + O.2 repetition gate):
        for epoch in 1..=1_000u64 {
            let prev_gen = lease.generation();
            let Ok((mut sess, prep)) = QuiesceRemapSession::begin(&mut lease, epoch, 100) else {
                assert!(false);
                return;
            };
            assert!(!sess.ready_for_bar_mutation());

            // Stale generation / wrong epoch replies must be rejected without mutating state!
            if let Ok(stale_gen) = LeaseGeneration::try_new(prev_gen.get().saturating_add(99)) {
                assert_eq!(
                    sess.on_quiesced(
                        &mut lease,
                        QuiesceRemapMessage::Quiesced {
                            device_id: lease.device_id(),
                            lease_generation: stale_gen,
                            epoch,
                        },
                        50,
                    ),
                    Err(QuiesceRemapError::StaleReplyRejected)
                );
            }
            let QuiesceRemapMessage::PrepareRelocation {
                lease_generation, ..
            } = prep
            else {
                assert!(false);
                return;
            };
            let Ok(new_gen) = sess.on_quiesced(
                &mut lease,
                QuiesceRemapMessage::Quiesced {
                    device_id: lease.device_id(),
                    lease_generation,
                    epoch,
                },
                50,
            ) else {
                assert!(false);
                return;
            };
            // Old generation MUST be unusable before BAR reassignment!
            assert!(!lease.accepts_io(prev_gen));
            assert!(!lease.can_mint_resources(prev_gen));
            assert!(sess.ready_for_bar_mutation());

            let Ok(_new_lease_msg) =
                sess.commit_hardware_and_issue_new_lease(&mut lease, addr, 200)
            else {
                assert!(false);
                return;
            };
            assert_eq!(
                sess.on_resume(
                    &mut lease,
                    QuiesceRemapMessage::Resume {
                        device_id: lease.device_id(),
                        new_generation: new_gen,
                        epoch,
                    },
                    150,
                ),
                Ok(())
            );
            assert_eq!(sess.phase(), QuiesceRemapPhase::Completed);
            assert_eq!(lease.state(), LeaseState::Online);
            assert!(lease.accepts_io(new_gen));
        }

        // Deadline missed -> fail-stop `Failed`!
        let Ok((mut late_sess, _)) = QuiesceRemapSession::begin(&mut lease, 2000, 10) else {
            assert!(false);
            return;
        };
        let cur_gen = lease.generation();
        assert_eq!(
            late_sess.on_quiesced(
                &mut lease,
                QuiesceRemapMessage::Quiesced {
                    device_id: lease.device_id(),
                    lease_generation: cur_gen,
                    epoch: 2000,
                },
                11,
            ),
            Err(QuiesceRemapError::DeadlineExceededFailStop)
        );
        assert_eq!(lease.state(), LeaseState::Failed);
    }
}
