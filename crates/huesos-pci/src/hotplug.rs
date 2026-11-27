//! Reserved-space PCIe hotplug event queue, subtree insertion, and removal (Stage K).
//!
//! Enforces the three Stage K invariants from `docs/PCI_PRODUCTION_ROADMAP.md`:
//! - **K.1 Bounded event ingestion**: ACPI (`BusCheck` / `DeviceCheck`) and
//!   native PCIe slot events enter [`HotplugEventQueue`] (`MAX_HOTPLUG_QUEUE`),
//!   coalescing storm duplicates without running enumeration in IRQ context.
//! - **K.2 Insertion without relocation**: newly inserted functions under a
//!   hotplug-capable bridge allocate strictly within the bridge's pre-reserved
//!   bus numbers and forwarding windows; no `Online` lease ever moves.
//! - **K.3 Orderly and surprise removal**: orderly removal drains I/O, disables
//!   hardware decoding/bus-mastering, revokes the lease generation, withdraws
//!   services, and emits [`DeviceGoneNotification`]; surprise removal (`0xFFFF`
//!   presence loss) revokes authority and withdraws services immediately without
//!   writing to vanished hardware, preventing BDF-reuse ABA across cycles.

use alloc::vec::Vec;

use crate::lease::{
    DeviceId, DeviceLeasePolicy, DmaIsolation, LeaseError, LeaseEvent, LeaseGeneration, LeaseState,
    RelocationClass,
};
use crate::resource_planner::{
    execute_commit_plan, CommitError, CommitPlan, PlannedResource, PlannedWrite, ResourcePlan,
};
use crate::resource_validation::{ResourceClass, ResourceRegister};
use crate::write_policy::{
    execute_checked_write, ConfigReadWriteTransport, HeaderKind, WriteClass, WritePolicyError,
    WriteRequest, OFFSET_BAR0, OFFSET_COMMAND,
};
use crate::{ConfigWidth, PciAddress, ENHANCED_CONFIG_BYTES};

/// Maximum distinct pending hotplug notifications queued at once.
pub const MAX_HOTPLUG_QUEUE: usize = 64;

/// Origin and kind of a hotplug event (Stage K.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotplugEventKind {
    /// ACPI Notify `0x00` (`BusCheck`) or native PCIe Presence Detect Changed (insert/rescan).
    RescanSubtree,
    /// Orderly removal request (attention button / eject request).
    OrderlyEject,
    /// Surprise link-down or `0xFFFF` vendor readback.
    SurpriseLinkDown,
}

/// Topology scope affected by a hotplug notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotplugTarget {
    /// Entire host bridge root (`root_id`).
    Root(u64),
    /// Downstream subtree of a Type-1 hotplug bridge port (`bridge_bdf`).
    BridgePort(PciAddress),
    /// Specific function address for orderly/surprise removal.
    Function(PciAddress),
}

/// One queued hotplug event decoupled from interrupt context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotplugEvent {
    /// Target root, bridge port, or function.
    pub target: HotplugTarget,
    /// Requested action.
    pub kind: HotplugEventKind,
    /// Firmware/manager generation that observed the event.
    pub manager_generation: u64,
}

/// Bounded, storm-coalescing hotplug event queue (Stage K.1).
#[derive(Clone, Debug)]
pub struct HotplugEventQueue {
    entries: [Option<HotplugEvent>; MAX_HOTPLUG_QUEUE],
    head: usize,
    len: usize,
    coalesced_count: u64,
    dropped_overflow_count: u64,
}

impl Default for HotplugEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugEventQueue {
    /// Construct an empty bounded queue.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_HOTPLUG_QUEUE],
            head: 0,
            len: 0,
            coalesced_count: 0,
            dropped_overflow_count: 0,
        }
    }

    /// Number of distinct queued events waiting to be processed.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when no events are pending.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total duplicate storm events coalesced into existing pending slots.
    pub const fn coalesced_count(&self) -> u64 {
        self.coalesced_count
    }

    /// Total events rejected because `MAX_HOTPLUG_QUEUE` distinct targets were full.
    pub const fn dropped_overflow_count(&self) -> u64 {
        self.dropped_overflow_count
    }

    /// Enqueue `event`, coalescing duplicates targeting the same scope.
    ///
    /// If a `SurpriseLinkDown` arrives for a target that had an `OrderlyEject`
    /// pending, the queued entry upgrades in-place to `SurpriseLinkDown`.
    pub fn push(&mut self, event: HotplugEvent) -> bool {
        for offset in 0..self.len {
            let idx = (self.head + offset) % MAX_HOTPLUG_QUEUE;
            if let Some(existing) = &mut self.entries[idx] {
                if existing.target == event.target {
                    let same_or_upgrade = existing.kind == event.kind
                        || matches!(
                            (existing.kind, event.kind),
                            (
                                HotplugEventKind::OrderlyEject,
                                HotplugEventKind::SurpriseLinkDown
                            ) | (
                                HotplugEventKind::SurpriseLinkDown,
                                HotplugEventKind::OrderlyEject
                            )
                        );
                    if same_or_upgrade {
                        // Surprise removal dominates an orderly request no
                        // matter which notification arrived first. This is
                        // both safer for vanished hardware and keeps a
                        // surprise/orderly storm in one bounded queue slot.
                        if event.kind == HotplugEventKind::SurpriseLinkDown {
                            existing.kind = HotplugEventKind::SurpriseLinkDown;
                        }
                        existing.manager_generation = event.manager_generation;
                        self.coalesced_count = self.coalesced_count.saturating_add(1);
                        return true;
                    }
                }
            }
        }
        if self.len >= MAX_HOTPLUG_QUEUE {
            self.dropped_overflow_count = self.dropped_overflow_count.saturating_add(1);
            return false;
        }
        let tail = (self.head + self.len) % MAX_HOTPLUG_QUEUE;
        self.entries[tail] = Some(event);
        self.len += 1;
        true
    }

    /// Pop the oldest queued event in FIFO order.
    pub fn pop(&mut self) -> Option<HotplugEvent> {
        if self.len == 0 {
            return None;
        }
        let item = self.entries[self.head].take();
        self.head = (self.head + 1) % MAX_HOTPLUG_QUEUE;
        self.len -= 1;
        item
    }
}

/// BAR requirement for one newly inserted hotplug endpoint function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotplugBarRequirement {
    /// BAR slot (`0..6`).
    pub bar_index: u8,
    /// Required resource class (`Io`, `Mmio32`, `PrefetchableMemory`, `Mmio64`).
    pub class: ResourceClass,
    /// Power-of-two byte size (`> 0`).
    pub len: u64,
    /// True when the BAR uses a 64-bit register pair.
    pub is_64bit: bool,
}

/// Candidate endpoint discovered during a subtree rescan below a hotplug bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotplugInsertionCandidate {
    /// Hotplug-capable parent bridge port.
    pub parent_bridge: PciAddress,
    /// Discovered routing address of the inserted endpoint.
    pub address: PciAddress,
    /// Declared relocation policy class for the bound driver.
    pub relocation: RelocationClass,
    /// DMA isolation mode for the new lease.
    pub dma_isolation: DmaIsolation,
    /// DriverHost process KOID to attach upon configuration. `None` keeps the
    /// lease in `Configured` until DriverManager completes the live binding
    /// handshake; it must never be replaced with a made-up KOID.
    pub driver_process_koid: Option<u64>,
    /// Sized BAR requirements (`0..=6`).
    pub bars: Vec<HotplugBarRequirement>,
}

/// Notification emitted when an active device is removed (Stage G.3 / K.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceGoneNotification {
    /// Retired stable device presence ID.
    pub device_id: DeviceId,
    /// Revoked lease generation (`old_generation`).
    pub revoked_generation: LeaseGeneration,
    /// Generation after revocation (`old_generation + 1`).
    pub new_generation: LeaseGeneration,
    /// Last routing address occupied by the device.
    pub last_address: PciAddress,
    /// True when removal was surprise (`0xFFFF` / link-down) rather than orderly.
    pub surprise: bool,
    /// True when the service registry withdrew the device prior to BDF release.
    pub service_withdrawn: bool,
}

/// Failure modes for Stage K hotplug insertion and removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotplugError {
    /// Inserted function address is already occupied by an active lease.
    AddressAlreadyActive,
    /// Inserted function bus lies outside the parent bridge's reserved bus range.
    BusOutsideReservedSubtree,
    /// BAR requirement is zero, non-power-of-two, or invalid index.
    InvalidBarRequirement,
    /// Parent bridge has no forwarding window for the requested BAR class.
    MissingBridgeWindow,
    /// Reserved space in the parent bridge window is exhausted; active leases are never moved.
    ReservedSpaceExhausted,
    /// Address translation or range arithmetic overflowed.
    ArithmeticOverflow,
    /// Bounded heap reservation failed.
    NoMemory,
    /// Hardware BAR/Command commit failed (with rollback status).
    HardwareCommitFailed(CommitError),
    /// Disabling hardware Command decoding failed during orderly removal.
    CommandDisableFailed(WritePolicyError),
    /// Target function has no active lease.
    DeviceNotFound,
    /// Lease state machine rejected transition or exhausted 64-bit IDs.
    Lease(LeaseError),
}

#[derive(Clone, Debug)]
struct ManagedSlot {
    policy: DeviceLeasePolicy,
    service_published: bool,
}

/// Stateful coordinator enforcing reserved-space hotplug without moving `Online` devices.
#[derive(Clone, Debug)]
pub struct HotplugCoordinator {
    next_device_id: u64,
    next_generation: u64,
    active_slots: Vec<ManagedSlot>,
    retired_lease_check: Option<DeviceLeasePolicy>,
    active_resources: Vec<PlannedResource>,
    bridge_windows: Vec<PlannedResource>,
    bridge_bus_ranges: Vec<(PciAddress, u8, u8)>,
}

impl HotplugCoordinator {
    /// Construct a coordinator seeded from the boot-time topology and [`ResourcePlan`].
    pub fn from_boot_plan(
        bridge_bus_ranges: &[(PciAddress, u8, u8)],
        plan: &ResourcePlan,
        initial_leases: &[(PciAddress, RelocationClass, DmaIsolation, Option<u64>)],
    ) -> Result<Self, HotplugError> {
        let mut bridge_windows = Vec::new();
        let mut active_resources = Vec::new();
        for res in plan.resources() {
            match res.register {
                ResourceRegister::BridgeWindow(_) => {
                    bridge_windows
                        .try_reserve(1)
                        .map_err(|_| HotplugError::NoMemory)?;
                    bridge_windows.push(*res);
                }
                ResourceRegister::Bar(_) => {
                    active_resources
                        .try_reserve(1)
                        .map_err(|_| HotplugError::NoMemory)?;
                    active_resources.push(*res);
                }
            }
        }
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(bridge_bus_ranges.len())
            .map_err(|_| HotplugError::NoMemory)?;
        ranges.extend_from_slice(bridge_bus_ranges);

        let mut next_device_id = 1u64;
        let mut next_generation = 1u64;
        let mut active_slots = Vec::new();
        active_slots
            .try_reserve_exact(initial_leases.len())
            .map_err(|_| HotplugError::NoMemory)?;

        for &(addr, reloc, dma, driver_process_koid) in initial_leases {
            let dev_id = DeviceId::try_new(next_device_id).map_err(HotplugError::Lease)?;
            next_device_id = next_device_id
                .checked_add(1)
                .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;
            let gen_id = LeaseGeneration::try_new(next_generation).map_err(HotplugError::Lease)?;
            next_generation = next_generation
                .checked_add(1)
                .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;

            let mut policy = DeviceLeasePolicy::try_new(dev_id, gen_id, addr, reloc, dma)
                .map_err(HotplugError::Lease)?;
            policy
                .apply(gen_id, LeaseEvent::Configure)
                .map_err(HotplugError::Lease)?;
            if let Some(process_koid) = driver_process_koid {
                if process_koid == 0 {
                    return Err(HotplugError::Lease(LeaseError::InvalidIdentity));
                }
                policy
                    .apply(gen_id, LeaseEvent::StartDriver { process_koid })
                    .map_err(HotplugError::Lease)?;
                policy
                    .apply(gen_id, LeaseEvent::DriverReady)
                    .map_err(HotplugError::Lease)?;
            }
            active_slots.push(ManagedSlot {
                policy,
                service_published: driver_process_koid.is_some(),
            });
        }

        Ok(Self {
            next_device_id,
            next_generation,
            active_slots,
            retired_lease_check: None,
            active_resources,
            bridge_windows,
            bridge_bus_ranges: ranges,
        })
    }

    /// Number of currently active leased functions.
    pub fn active_lease_count(&self) -> usize {
        self.active_slots.len()
    }

    /// Number of currently allocated endpoint BARs.
    pub fn active_resource_count(&self) -> usize {
        self.active_resources.len()
    }

    /// Number of currently published device services.
    pub fn published_service_count(&self) -> usize {
        self.active_slots
            .iter()
            .filter(|s| s.service_published)
            .count()
    }

    /// Inspect the active [`DeviceLeasePolicy`] at `address`, if present.
    pub fn lease_at(&self, address: PciAddress) -> Option<&DeviceLeasePolicy> {
        self.active_slots
            .iter()
            .find(|s| s.policy.address() == address)
            .map(|s| &s.policy)
    }

    /// Inspect the most recently retired [`DeviceLeasePolicy`] for negative stale-handle checks.
    pub const fn last_retired_lease(&self) -> Option<&DeviceLeasePolicy> {
        self.retired_lease_check.as_ref()
    }

    /// Insert one newly discovered endpoint into pre-reserved bridge capacity without
    /// moving any existing `Online` device (Stage K.2).
    pub fn insert_endpoint(
        &mut self,
        candidate: &HotplugInsertionCandidate,
        transport: &mut impl ConfigReadWriteTransport,
    ) -> Result<(DeviceLeasePolicy, Vec<PlannedResource>), HotplugError> {
        if self
            .active_slots
            .iter()
            .any(|s| s.policy.address() == candidate.address)
        {
            return Err(HotplugError::AddressAlreadyActive);
        }

        let Some(&(_bridge, sec_bus, sub_bus)) = self
            .bridge_bus_ranges
            .iter()
            .find(|&&(b, _, _)| b == candidate.parent_bridge)
        else {
            return Err(HotplugError::BusOutsideReservedSubtree);
        };
        let bus = candidate.address.bus();
        if candidate.address.segment() != candidate.parent_bridge.segment()
            || bus < sec_bus
            || bus > sub_bus
        {
            return Err(HotplugError::BusOutsideReservedSubtree);
        }

        let mut staged_bars: Vec<PlannedResource> = Vec::new();
        staged_bars
            .try_reserve_exact(candidate.bars.len())
            .map_err(|_| HotplugError::NoMemory)?;
        // Reserve all coordinator state before the first hardware write. A
        // bounded allocation failure after a BAR commit would otherwise leave
        // silicon configured without a lease record.
        self.active_resources
            .try_reserve(candidate.bars.len())
            .map_err(|_| HotplugError::NoMemory)?;
        self.active_slots
            .try_reserve(1)
            .map_err(|_| HotplugError::NoMemory)?;
        let write_capacity = candidate
            .bars
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(HotplugError::NoMemory)?;
        let mut staged_writes: Vec<PlannedWrite> = Vec::new();
        staged_writes
            .try_reserve_exact(write_capacity)
            .map_err(|_| HotplugError::NoMemory)?;

        for req in &candidate.bars {
            if req.bar_index >= 6 || req.len == 0 || !req.len.is_power_of_two() {
                return Err(HotplugError::InvalidBarRequirement);
            }
            if req.is_64bit && req.bar_index >= 5 {
                return Err(HotplugError::InvalidBarRequirement);
            }
            let Some(win) = self
                .bridge_windows
                .iter()
                .find(|w| w.owner == candidate.parent_bridge && w.class == req.class)
            else {
                return Err(HotplugError::MissingBridgeWindow);
            };
            let pci_base = self.find_free_in_window(win, &staged_bars, req.len)?;
            let delta = pci_base
                .checked_sub(win.pci_base)
                .ok_or(HotplugError::ArithmeticOverflow)?;
            let cpu_base = win
                .cpu_base
                .checked_add(delta)
                .ok_or(HotplugError::ArithmeticOverflow)?;

            let offset = OFFSET_BAR0 + u16::from(req.bar_index) * 4;
            let old_lo = transport
                .read_width(candidate.address, offset, ConfigWidth::Dword)
                .unwrap_or(0);
            let lo_mask = if req.class == ResourceClass::Io {
                !0x3u32
            } else {
                !0xFu32
            };
            let write_mask = if req.len <= u64::from(u32::MAX) {
                !((req.len as u32).wrapping_sub(1)) & lo_mask
            } else if req.is_64bit {
                // A BAR larger than 4 GiB still needs its low dword
                // programmed; only its size alignment, not the address
                // register, is absent from the 32-bit mask.
                lo_mask
            } else {
                0
            };
            if write_mask != 0 {
                staged_writes
                    .try_reserve(1)
                    .map_err(|_| HotplugError::NoMemory)?;
                staged_writes.push(PlannedWrite {
                    owner: candidate.address,
                    header_kind: HeaderKind::Type0Endpoint,
                    class: WriteClass::Bar,
                    offset,
                    width: ConfigWidth::Dword,
                    old_value: old_lo & lo_mask,
                    new_value: (pci_base as u32) & lo_mask,
                    write_mask,
                    expected_readback_mask: write_mask,
                });
            }
            if req.is_64bit {
                let hi_offset = offset + 4;
                let old_hi = transport
                    .read_width(candidate.address, hi_offset, ConfigWidth::Dword)
                    .unwrap_or(0);
                staged_writes
                    .try_reserve(1)
                    .map_err(|_| HotplugError::NoMemory)?;
                staged_writes.push(PlannedWrite {
                    owner: candidate.address,
                    header_kind: HeaderKind::Type0Endpoint,
                    class: WriteClass::Bar,
                    offset: hi_offset,
                    width: ConfigWidth::Dword,
                    old_value: old_hi,
                    new_value: (pci_base >> 32) as u32,
                    write_mask: u32::MAX,
                    expected_readback_mask: u32::MAX,
                });
            }

            staged_bars.push(PlannedResource {
                owner: candidate.address,
                register: ResourceRegister::Bar(req.bar_index),
                class: req.class,
                old_pci_base: None,
                pci_base,
                cpu_base,
                len: req.len,
                fixed: candidate.relocation == RelocationClass::Fixed,
            });
        }

        // Enable MSE/BusMaster on the newly inserted endpoint only after BARs commit.
        let old_cmd = transport
            .read_width(candidate.address, OFFSET_COMMAND, ConfigWidth::Word)
            .unwrap_or(0);
        staged_writes
            .try_reserve(1)
            .map_err(|_| HotplugError::NoMemory)?;
        staged_writes.push(PlannedWrite {
            owner: candidate.address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            old_value: old_cmd & 0x0407,
            new_value: (old_cmd | 0x0406) & 0x0407,
            write_mask: 0x0406,
            expected_readback_mask: 0x0406,
        });

        let dev_id = DeviceId::try_new(self.next_device_id).map_err(HotplugError::Lease)?;
        self.next_device_id = self
            .next_device_id
            .checked_add(1)
            .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;
        let gen_id = LeaseGeneration::try_new(self.next_generation).map_err(HotplugError::Lease)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;

        let mut policy = DeviceLeasePolicy::try_new(
            dev_id,
            gen_id,
            candidate.address,
            candidate.relocation,
            candidate.dma_isolation,
        )
        .map_err(HotplugError::Lease)?;
        policy
            .apply(gen_id, LeaseEvent::Configure)
            .map_err(HotplugError::Lease)?;
        if let Some(process_koid) = candidate.driver_process_koid {
            if process_koid == 0 {
                return Err(HotplugError::Lease(LeaseError::InvalidIdentity));
            }
            policy
                .apply(gen_id, LeaseEvent::StartDriver { process_koid })
                .map_err(HotplugError::Lease)?;
            policy
                .apply(gen_id, LeaseEvent::DriverReady)
                .map_err(HotplugError::Lease)?;
        }

        let commit_plan = build_direct_commit_plan(gen_id.get(), staged_writes);
        execute_commit_plan(&commit_plan, transport).map_err(HotplugError::HardwareCommitFailed)?;

        for bar in &staged_bars {
            self.active_resources.push(*bar);
        }
        let service_published = candidate.driver_process_koid.is_some();
        self.active_slots.push(ManagedSlot {
            policy,
            service_published,
        });

        Ok((policy, staged_bars))
    }

    /// Attach a real DriverHost identity to a configured hotplug lease.
    ///
    /// The caller must obtain the KOID from DriverManager; a zero or synthetic
    /// identity is rejected and the lease remains `Configured`.
    pub fn attach_driver(
        &mut self,
        address: PciAddress,
        process_koid: u64,
    ) -> Result<(), HotplugError> {
        if process_koid == 0 {
            return Err(HotplugError::Lease(LeaseError::InvalidIdentity));
        }
        let Some(slot) = self
            .active_slots
            .iter_mut()
            .find(|slot| slot.policy.address() == address)
        else {
            return Err(HotplugError::DeviceNotFound);
        };
        let generation = slot.policy.generation();
        slot.policy
            .apply(generation, LeaseEvent::StartDriver { process_koid })
            .map_err(HotplugError::Lease)?;
        Ok(())
    }

    /// Mark an attached hotplug DriverHost ready and publish its service.
    pub fn driver_ready(&mut self, address: PciAddress) -> Result<(), HotplugError> {
        let Some(slot) = self
            .active_slots
            .iter_mut()
            .find(|slot| slot.policy.address() == address)
        else {
            return Err(HotplugError::DeviceNotFound);
        };
        let generation = slot.policy.generation();
        slot.policy
            .apply(generation, LeaseEvent::DriverReady)
            .map_err(HotplugError::Lease)?;
        slot.service_published = true;
        Ok(())
    }

    /// Perform orderly hotplug removal: drain, disable decoding/bus-master, revoke
    /// generation, withdraw service, and release the BDF/BAR range (Stage K.3).
    pub fn remove_orderly(
        &mut self,
        address: PciAddress,
        transport: &mut impl ConfigReadWriteTransport,
    ) -> Result<DeviceGoneNotification, HotplugError> {
        let Some(pos) = self
            .active_slots
            .iter()
            .position(|s| s.policy.address() == address)
        else {
            return Err(HotplugError::DeviceNotFound);
        };

        let revoked_gen = self.active_slots[pos].policy.generation();
        let prior_state = self.active_slots[pos].policy.state();
        self.active_slots[pos]
            .policy
            .apply(revoked_gen, LeaseEvent::BeginRemoval)
            .map_err(HotplugError::Lease)?;
        // Withdraw service immediately so no new opens succeed while quiescing.
        self.active_slots[pos].service_published = false;

        // A live DriverHost must acknowledge quiesce. A newly inserted device
        // may still be `Configured` while the supervisor is waiting for its
        // binding decision; that state is removed directly after the same
        // command-disable transaction, without inventing a quiesce ACK.
        let removal_generation = if matches!(
            prior_state,
            LeaseState::DriverStarting | LeaseState::Online
        ) {
            self.active_slots[pos]
                .policy
                .apply(revoked_gen, LeaseEvent::DriverQuiesced)
                .map_err(HotplugError::Lease)?
                .generation
        } else {
            self.active_slots[pos].policy.generation()
        };

        // Disable I/O, Memory Space, and Bus Master in PCI Command register.
        let cur_cmd = transport
            .read_width(address, OFFSET_COMMAND, ConfigWidth::Word)
            .unwrap_or(0);
        let disable_req = WriteRequest {
            address,
            header_kind: HeaderKind::Type0Endpoint,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: cur_cmd & !0x0007,
            write_mask: 0x0007,
            expected_readback_mask: 0x0007,
            allowlist_entry: None,
        };
        execute_checked_write(transport, &disable_req)
            .map_err(HotplugError::CommandDisableFailed)?;

        self.active_slots[pos]
            .policy
            .apply(removal_generation, LeaseEvent::CompleteRemoval)
            .map_err(HotplugError::Lease)?;

        let slot = self.active_slots.remove(pos);
        self.active_resources.retain(|r| r.owner != address);
        // Advance coordinator generation past the revoked generation so
        // subsequent insertions at the same BDF never collide with the
        // retired lease's generation.
        if self.next_generation <= removal_generation.get() {
            self.next_generation = removal_generation
                .get()
                .checked_add(1)
                .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;
        }
        let dev_id = slot.policy.device_id();
        self.retired_lease_check = Some(slot.policy);

        Ok(DeviceGoneNotification {
            device_id: dev_id,
            revoked_generation: revoked_gen,
            new_generation: removal_generation,
            last_address: address,
            surprise: false,
            service_withdrawn: true,
        })
    }

    /// Handle surprise removal (`0xFFFF` vendor ID / link-down): immediately revoke
    /// lease generation, withdraw service, and skip config writes to vanished silicon (Stage K.3).
    pub fn remove_surprise(
        &mut self,
        address: PciAddress,
    ) -> Result<DeviceGoneNotification, HotplugError> {
        let Some(pos) = self
            .active_slots
            .iter()
            .position(|s| s.policy.address() == address)
        else {
            return Err(HotplugError::DeviceNotFound);
        };

        let revoked_gen = self.active_slots[pos].policy.generation();
        self.active_slots[pos].service_published = false;
        let tr = self.active_slots[pos]
            .policy
            .apply(revoked_gen, LeaseEvent::SurpriseRemove)
            .map_err(HotplugError::Lease)?;

        let slot = self.active_slots.remove(pos);
        self.active_resources.retain(|r| r.owner != address);
        if self.next_generation <= tr.generation.get() {
            self.next_generation = tr
                .generation
                .get()
                .checked_add(1)
                .ok_or(HotplugError::Lease(LeaseError::GenerationExhausted))?;
        }
        let dev_id = slot.policy.device_id();
        self.retired_lease_check = Some(slot.policy);

        Ok(DeviceGoneNotification {
            device_id: dev_id,
            revoked_generation: revoked_gen,
            new_generation: tr.generation,
            last_address: address,
            surprise: true,
            service_withdrawn: true,
        })
    }

    fn find_free_in_window(
        &self,
        win: &PlannedResource,
        staged_bars: &[PlannedResource],
        len: u64,
    ) -> Result<u64, HotplugError> {
        let win_end = win
            .pci_base
            .checked_add(win.len)
            .ok_or(HotplugError::ArithmeticOverflow)?;
        let mask = len - 1;
        let mut cursor = win
            .pci_base
            .checked_add(mask)
            .map(|v| v & !mask)
            .ok_or(HotplugError::ArithmeticOverflow)?;

        let mut blockers: Vec<(u64, u64)> = Vec::new();
        for existing in &self.active_resources {
            if existing.class == win.class
                && existing.pci_base >= win.pci_base
                && existing.pci_base < win_end
            {
                blockers
                    .try_reserve(1)
                    .map_err(|_| HotplugError::NoMemory)?;
                blockers.push((existing.pci_base, existing.len));
            }
        }
        for pending in staged_bars {
            if pending.class == win.class
                && pending.pci_base >= win.pci_base
                && pending.pci_base < win_end
            {
                blockers
                    .try_reserve(1)
                    .map_err(|_| HotplugError::NoMemory)?;
                blockers.push((pending.pci_base, pending.len));
            }
        }
        blockers.sort_by_key(|&(b, _)| b);

        for (b_base, b_len) in blockers {
            let cand_end = cursor
                .checked_add(len)
                .ok_or(HotplugError::ArithmeticOverflow)?;
            if cand_end <= b_base {
                return Ok(cursor);
            }
            let b_end = b_base
                .checked_add(b_len)
                .ok_or(HotplugError::ArithmeticOverflow)?;
            if cursor < b_end {
                cursor = b_end
                    .checked_add(mask)
                    .map(|v| v & !mask)
                    .ok_or(HotplugError::ArithmeticOverflow)?;
            }
        }
        let cand_end = cursor
            .checked_add(len)
            .ok_or(HotplugError::ArithmeticOverflow)?;
        if cand_end <= win_end {
            Ok(cursor)
        } else {
            Err(HotplugError::ReservedSpaceExhausted)
        }
    }
}

pub(crate) fn build_direct_commit_plan(
    topology_generation: u64,
    writes: Vec<PlannedWrite>,
) -> CommitPlan {
    CommitPlan::from_writes(topology_generation, writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::LeaseState;
    use crate::resource_planner::{plan_with_hotplug_reserves, HotplugReservePolicy};
    use crate::resource_validation::{validate_firmware_resources, FirmwareResource, RootAperture};
    use crate::topology::{build_snapshot, DiscoveredFunction, FunctionKind, RootBus};
    use crate::ClassCode;

    struct SlotTransport {
        cmd: u32,
        bar0_lo: u32,
        bar0_hi: u32,
        config_writes: usize,
    }

    impl SlotTransport {
        fn new_64bit_bar() -> Self {
            Self {
                cmd: 0,
                bar0_lo: 0x0000_0004, // 64-bit MMIO type indicator
                bar0_hi: 0,
                config_writes: 0,
            }
        }
    }

    impl ConfigReadWriteTransport for SlotTransport {
        fn read_width(
            &mut self,
            _owner: PciAddress,
            offset: u16,
            _width: ConfigWidth,
        ) -> Option<u32> {
            match offset {
                OFFSET_COMMAND => Some(self.cmd),
                0x10 => Some(self.bar0_lo),
                0x14 => Some(self.bar0_hi),
                _ => Some(0),
            }
        }

        fn write_width(
            &mut self,
            _owner: PciAddress,
            offset: u16,
            _width: ConfigWidth,
            value: u32,
        ) -> bool {
            self.config_writes += 1;
            match offset {
                OFFSET_COMMAND => {
                    self.cmd = value & 0xFFFF;
                    true
                }
                0x10 => {
                    self.bar0_lo = (value & !0xFu32) | 0x4;
                    true
                }
                0x14 => {
                    self.bar0_hi = value;
                    true
                }
                _ => false,
            }
        }
    }

    fn bdf(bus: u8, dev: u8) -> PciAddress {
        match PciAddress::try_new(0, bus, dev, 0) {
            Ok(a) => a,
            Err(_) => {
                assert!(false);
                PciAddress::ZERO
            }
        }
    }

    #[test]
    fn storm_of_ten_thousand_hotplug_events_coalesces_without_overflow() {
        let mut q = HotplugEventQueue::new();
        let bridge_a = bdf(0, 1);
        let bridge_b = bdf(0, 2);
        for i in 0..10_000u64 {
            let target = if i % 2 == 0 {
                HotplugTarget::BridgePort(bridge_a)
            } else {
                HotplugTarget::BridgePort(bridge_b)
            };
            assert!(q.push(HotplugEvent {
                target,
                kind: HotplugEventKind::RescanSubtree,
                manager_generation: 1 + (i / 1000),
            }));
        }
        assert_eq!(q.len(), 2);
        assert_eq!(q.coalesced_count(), 9_998);
        assert_eq!(q.dropped_overflow_count(), 0);
        let Some(first) = q.pop() else {
            assert!(false);
            return;
        };
        assert_eq!(first.target, HotplugTarget::BridgePort(bridge_a));
        assert_eq!(first.manager_generation, 10);
    }

    #[test]
    fn surprise_removal_dominates_orderly_storm_in_either_arrival_order() {
        let target = HotplugTarget::Function(bdf(2, 0));
        let mut queue = HotplugEventQueue::new();
        assert!(queue.push(HotplugEvent {
            target,
            kind: HotplugEventKind::OrderlyEject,
            manager_generation: 1,
        }));
        assert!(queue.push(HotplugEvent {
            target,
            kind: HotplugEventKind::SurpriseLinkDown,
            manager_generation: 2,
        }));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.coalesced_count(), 1);
        let Some(event) = queue.pop() else {
            assert!(false, "coalesced event must remain queued");
            return;
        };
        assert_eq!(event.kind, HotplugEventKind::SurpriseLinkDown);
        assert_eq!(event.manager_generation, 2);

        assert!(queue.push(HotplugEvent {
            target,
            kind: HotplugEventKind::SurpriseLinkDown,
            manager_generation: 3,
        }));
        assert!(queue.push(HotplugEvent {
            target,
            kind: HotplugEventKind::OrderlyEject,
            manager_generation: 4,
        }));
        let Some(event) = queue.pop() else {
            assert!(false, "reverse-order coalesced event must remain queued");
            return;
        };
        assert_eq!(event.kind, HotplugEventKind::SurpriseLinkDown);
        assert_eq!(event.manager_generation, 4);
    }

    #[test]
    fn thousand_add_remove_cycles_preserve_online_nvme_have_zero_leaks_and_reject_stale_handles() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 7,
        }];
        let bridge = bdf(0, 1);
        let nvme = bdf(1, 0);
        let hotplug_ep = bdf(2, 0);
        let funcs = [
            DiscoveredFunction {
                address: bridge,
                vendor_id: 0x8086,
                device_id: 0x2940,
                class_code: ClassCode {
                    class: 0x06,
                    subclass: 0x04,
                    prog_if: 0,
                },
                kind: FunctionKind::PciBridge {
                    secondary_bus: 1,
                    subordinate_bus: 4,
                },
            },
            DiscoveredFunction {
                address: nvme,
                vendor_id: 0x1B36,
                device_id: 0x0010,
                class_code: ClassCode {
                    class: 0x01,
                    subclass: 0x08,
                    prog_if: 0x02,
                },
                kind: FunctionKind::Endpoint,
            },
        ];
        let Ok(topo) = build_snapshot(1, &roots, &funcs) else {
            assert!(false);
            return;
        };
        let apertures = [RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x1000_0000,
        }];
        let nvme_bar = FirmwareResource {
            owner: nvme,
            register: ResourceRegister::Bar(0),
            class: ResourceClass::Mmio32,
            assigned: false,
            pci_base: 0,
            len: 0x4000,
            fixed: true,
        };
        let Ok(val) = validate_firmware_resources(&topo, &apertures, &[nvme_bar]) else {
            assert!(false);
            return;
        };
        let Ok(plan) = plan_with_hotplug_reserves(
            &topo,
            &apertures,
            &val,
            &[bridge],
            HotplugReservePolicy::STANDARD_PCIE_SLOT,
        ) else {
            assert!(false);
            return;
        };
        let Some(initial_nvme_bar) = plan.find(nvme, ResourceRegister::Bar(0)).copied() else {
            assert!(false);
            return;
        };

        let Ok(mut coord) = HotplugCoordinator::from_boot_plan(
            &[(bridge, 1, 4)],
            &plan,
            &[(nvme, RelocationClass::Fixed, DmaIsolation::Trusted, Some(100))],
        ) else {
            assert!(false);
            return;
        };
        let Some(nvme_lease_before) = coord.lease_at(nvme).copied() else {
            assert!(false);
            return;
        };
        let nvme_gen = nvme_lease_before.generation();

        let mut bars = Vec::new();
        bars.push(HotplugBarRequirement {
            bar_index: 0,
            class: ResourceClass::Mmio32,
            len: 0x1_0000,
            is_64bit: true,
        });
        let candidate = HotplugInsertionCandidate {
            parent_bridge: bridge,
            address: hotplug_ep,
            relocation: RelocationClass::Restart,
            dma_isolation: DmaIsolation::Trusted,
            driver_process_koid: Some(200),
            bars,
        };

        // Mandatory Stage K.3 / O.2 gate: 1,000 synthetic add/remove cycles!
        for cycle in 0..1_000usize {
            let mut transport = SlotTransport::new_64bit_bar();
            let Ok((inserted_lease, allocated_bars)) =
                coord.insert_endpoint(&candidate, &mut transport)
            else {
                assert!(false, "hotplug insert failed on cycle");
                return;
            };
            let inserted_gen = inserted_lease.generation();
            assert_eq!(inserted_lease.state(), LeaseState::Online);
            assert!(inserted_lease.accepts_io(inserted_gen));
            assert!(inserted_lease.can_mint_resources(inserted_gen));
            assert_eq!(allocated_bars.len(), 1);
            // Inserted endpoint never overlaps or displaces Online Fixed NVMe!
            assert_ne!(allocated_bars[0].pci_base, initial_nvme_bar.pci_base);
            assert_eq!(coord.lease_at(nvme), Some(&nvme_lease_before));
            assert!(nvme_lease_before.accepts_io(nvme_gen));
            assert_eq!(coord.active_lease_count(), 2);
            assert_eq!(coord.active_resource_count(), 2);
            assert_eq!(coord.published_service_count(), 2);

            if cycle % 2 == 0 {
                let Ok(gone) = coord.remove_orderly(hotplug_ep, &mut transport) else {
                    assert!(false, "orderly remove failed");
                    return;
                };
                assert!(!gone.surprise);
                assert!(gone.service_withdrawn);
                assert_eq!(gone.revoked_generation, inserted_gen);
                assert_eq!(transport.cmd & 0x0007, 0);
            } else {
                let writes_before = transport.config_writes;
                let Ok(gone) = coord.remove_surprise(hotplug_ep) else {
                    assert!(false, "surprise remove failed");
                    return;
                };
                assert!(gone.surprise);
                assert!(gone.service_withdrawn);
                assert_eq!(gone.revoked_generation, inserted_gen);
                // Surprise removal must NEVER write to vanished silicon!
                assert_eq!(transport.config_writes, writes_before);
            }

            // Zero leaks after every single cycle!
            assert_eq!(coord.active_lease_count(), 1);
            assert_eq!(coord.active_resource_count(), 1);
            assert_eq!(coord.published_service_count(), 1);

            // Stale handle negative test on the retired lease!
            let Some(mut retired) = coord.last_retired_lease().copied() else {
                assert!(false);
                return;
            };
            assert!(!retired.can_mint_resources(inserted_gen));
            assert!(!retired.accepts_io(inserted_gen));
            assert_eq!(
                retired.apply(inserted_gen, LeaseEvent::DriverReady),
                Err(LeaseError::StaleGeneration)
            );
        }
    }
}
