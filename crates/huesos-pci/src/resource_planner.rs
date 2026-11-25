//! Deterministic firmware-preserving PCI resource planner.
//!
//! The planner consumes an immutable topology and a conflict-free firmware
//! validation report. Valid/fixed assignments are never moved. Only explicitly
//! unassigned BARs/windows receive new addresses, first-fit within their direct
//! parent forwarding domain and ultimately within a declared root aperture.
//! No hardware writes occur here.

use alloc::vec::Vec;

use crate::resource_validation::{
    FirmwareResource, ResourceClass, ResourceRegister, ResourceStatus, RootAperture,
    ValidationReport,
};
use crate::topology::{FunctionKind, Parent, TopologySnapshot};
use crate::write_policy::{
    execute_checked_write, ConfigReadWriteTransport, HeaderKind, WriteClass, WritePolicyError,
    WriteRequest, WriteTransactionRecord, OFFSET_BAR0, OFFSET_BRIDGE_IO_BASE,
};
use crate::{ConfigWidth, PciAddress, ENHANCED_CONFIG_BYTES};

/// Maximum planned resources in one transaction.
pub const MAX_PLANNED_RESOURCES: usize = 2048;
/// PCI bridge I/O-window granularity.
pub const BRIDGE_IO_GRANULARITY: u64 = 1 << 12;
/// PCI bridge memory-window granularity.
pub const BRIDGE_MEMORY_GRANULARITY: u64 = 1 << 20;

/// One immutable firmware-preserving assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedResource {
    /// Owning function.
    pub owner: PciAddress,
    /// BAR/window identity.
    pub register: ResourceRegister,
    /// Address-space class.
    pub class: ResourceClass,
    /// Firmware address, absent when the requirement was unassigned.
    pub old_pci_base: Option<u64>,
    /// Planned PCI bus address.
    pub pci_base: u64,
    /// Translated CPU physical/I/O address.
    pub cpu_base: u64,
    /// Resource length.
    pub len: u64,
    /// Whether relocation is forbidden.
    pub fixed: bool,
}

impl PlannedResource {
    /// True when a previously assigned resource changes address.
    ///
    /// Firmware-preserving plans always return false; the field-level
    /// comparison is retained for later restart/live relocation planners.
    pub const fn moved(self) -> bool {
        match self.old_pci_base {
            Some(old) => old != self.pci_base,
            None => false,
        }
    }

    /// True when the planner assigned a previously empty requirement.
    pub const fn newly_assigned(self) -> bool {
        self.old_pci_base.is_none()
    }
}

/// Configurable hotplug capacity reserved below hotplug-capable PCIe ports (Stage F.3).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HotplugReservePolicy {
    /// Additional downstream bus numbers reserved when parent subordinate bus permits.
    pub extra_buses: u8,
    /// Additional I/O window bytes reserved (`BRIDGE_IO_GRANULARITY` aligned).
    pub io_bytes: u64,
    /// Additional 32-bit MMIO window bytes reserved (`BRIDGE_MEMORY_GRANULARITY` aligned).
    pub mmio32_bytes: u64,
    /// Additional 64-bit prefetchable window bytes reserved (`BRIDGE_MEMORY_GRANULARITY` aligned).
    pub prefetch_mmio64_bytes: u64,
}

impl HotplugReservePolicy {
    /// Zero hotplug reservation (stock firmware-preserving behavior).
    pub const NONE: Self = Self {
        extra_buses: 0,
        io_bytes: 0,
        mmio32_bytes: 0,
        prefetch_mmio64_bytes: 0,
    };

    /// Standard PCIe hotplug port reservation (`2` extra buses, `2 MiB` MMIO32, `4 MiB` pref64).
    pub const STANDARD_PCIE_SLOT: Self = Self {
        extra_buses: 2,
        io_bytes: 0,
        mmio32_bytes: 2 * BRIDGE_MEMORY_GRANULARITY,
        prefetch_mmio64_bytes: 4 * BRIDGE_MEMORY_GRANULARITY,
    };

    const fn reserve_for_class(self, class: ResourceClass) -> u64 {
        match class {
            ResourceClass::Io => self.io_bytes,
            ResourceClass::Mmio32 => self.mmio32_bytes,
            ResourceClass::Mmio64 | ResourceClass::PrefetchableMemory => self.prefetch_mmio64_bytes,
        }
    }
}

/// Bus-number hotplug slack recorded for one hotplug-capable bridge port (Stage F.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedBusReserve {
    /// Bridge routing address.
    pub bridge: PciAddress,
    /// Bridge secondary bus.
    pub secondary_bus: u8,
    /// Current highest occupied bus below `bridge`.
    pub used_subordinate_bus: u8,
    /// Planned subordinate bus ceiling including hotplug reserve.
    pub reserved_subordinate_bus: u8,
}

/// Complete deterministic plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePlan {
    topology_generation: u64,
    resources: Vec<PlannedResource>,
    bus_reserves: Vec<PlannedBusReserve>,
}

impl ResourcePlan {
    pub(crate) fn from_parts(
        topology_generation: u64,
        mut resources: Vec<PlannedResource>,
        bus_reserves: Vec<PlannedBusReserve>,
    ) -> Self {
        resources.sort_by_key(|r| (r.owner, r.register));
        Self {
            topology_generation,
            resources,
            bus_reserves,
        }
    }

    /// Topology generation this plan was calculated against.
    pub const fn topology_generation(&self) -> u64 {
        self.topology_generation
    }

    /// Resources ordered by owner/register.
    pub fn resources(&self) -> &[PlannedResource] {
        &self.resources
    }

    /// Reserved bus-number ranges for hotplug-capable bridge ports (Stage F.3).
    pub fn bus_reserves(&self) -> &[PlannedBusReserve] {
        &self.bus_reserves
    }

    /// Find one planned BAR/window.
    pub fn find(&self, owner: PciAddress, register: ResourceRegister) -> Option<&PlannedResource> {
        self.resources
            .binary_search_by_key(&(owner, register), |resource| {
                (resource.owner, resource.register)
            })
            .ok()
            .and_then(|index| self.resources.get(index))
    }
}

/// Planner failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// Report contains conflicting, unrouteable, or unsupported resources.
    InvalidValidationReport,
    /// Resource count exceeds the bounded planner profile.
    TooManyResources,
    /// Bounded allocation failed.
    NoMemory,
    /// Owner/parent/root cannot be resolved in the topology.
    MissingTopology,
    /// Child resource has no planned direct-parent forwarding window.
    MissingParentWindow,
    /// Requirement size/alignment/register shape cannot be allocated.
    InvalidRequirement,
    /// No matching parent range has sufficient free space.
    NoSpace,
    /// Checked range/alignment/translation arithmetic overflowed.
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Container {
    RootAperture(usize),
    RootClass(u64, ResourceClass),
    BridgeWindow(PciAddress, ResourceClass),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Occupied {
    container: Container,
    base: u64,
    len: u64,
}

/// Create a plan that preserves every valid firmware assignment and fills only
/// unassigned requirements (including bottom-up synthesis of missing bridge windows).
pub fn plan_firmware_preserving(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    validation: &ValidationReport,
) -> Result<ResourcePlan, PlanError> {
    plan_with_hotplug_reserves(
        topology,
        apertures,
        validation,
        &[],
        HotplugReservePolicy::NONE,
    )
}

/// Create a firmware-preserving plan with bottom-up bridge window aggregation
/// and configurable hotplug capacity below `hotplug_ports` (Stages F.1 & F.3).
pub fn plan_with_hotplug_reserves(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    validation: &ValidationReport,
    hotplug_ports: &[PciAddress],
    reserve_policy: HotplugReservePolicy,
) -> Result<ResourcePlan, PlanError> {
    if validation.resources().len() > MAX_PLANNED_RESOURCES {
        return Err(PlanError::TooManyResources);
    }
    if !validation.is_conflict_free() {
        return Err(PlanError::InvalidValidationReport);
    }
    validate_hotplug_reserve_policy(reserve_policy)?;

    let mut planned = Vec::new();
    planned
        .try_reserve(validation.resources().len().saturating_add(16))
        .map_err(|_| PlanError::NoMemory)?;
    let mut occupied = Vec::new();
    occupied
        .try_reserve(validation.resources().len().saturating_add(16))
        .map_err(|_| PlanError::NoMemory)?;

    // Preserve every firmware assignment before allocating anything new.
    // Sort by topological depth (parent BridgeWindow before child BAR/window)
    // so downstream buses work regardless of BDF ordering.
    let mut preserved = Vec::new();
    preserved
        .try_reserve_exact(validation.resources().len())
        .map_err(|_| PlanError::NoMemory)?;
    for validated in validation.resources() {
        if matches!(
            validated.status,
            ResourceStatus::Valid | ResourceStatus::Fixed
        ) {
            preserved.push(*validated);
        }
    }
    preserved.sort_by_key(|v| allocation_order(topology, v.resource));

    for validated in preserved {
        let resource = validated.resource;
        let container = direct_container(topology, apertures, &planned, resource)?;
        let cpu_base = validated
            .cpu_base
            .ok_or(PlanError::InvalidValidationReport)?;
        planned.push(PlannedResource {
            owner: resource.owner,
            register: resource.register,
            class: resource.class,
            old_pci_base: Some(resource.pci_base),
            pci_base: resource.pci_base,
            cpu_base,
            len: resource.len,
            fixed: validated.status == ResourceStatus::Fixed,
        });
        occupied.push(Occupied {
            container,
            base: resource.pci_base,
            len: resource.len,
        });
    }

    // Validate all explicit unassigned requirements first so malformed inputs
    // (such as unrounded bridge windows) are rejected before aggregation.
    let mut pending = Vec::new();
    pending
        .try_reserve(validation.resources().len().saturating_add(16))
        .map_err(|_| PlanError::NoMemory)?;
    for validated in validation.resources() {
        if validated.status == ResourceStatus::Unassigned {
            validate_requirement(topology, validated.resource)?;
            pending.push(validated.resource);
        }
    }

    // Stage F.1 + F.3: bottom-up bridge window sizing + hotplug reserve slack.
    aggregate_bottom_up_bridge_windows(
        topology,
        &planned,
        &mut pending,
        hotplug_ports,
        reserve_policy,
    )?;

    pending.sort_by_key(|resource| allocation_order(topology, *resource));

    for resource in pending {
        validate_requirement(topology, resource)?;
        let container = direct_container(topology, apertures, &planned, resource)?;
        let alignment = resource_alignment(resource)?;
        let ranges = container_ranges(container, apertures, &planned)?;
        let (base, assigned_container) = first_fit(&ranges, &occupied, resource.len, alignment)?;
        let cpu_base = translate_to_cpu(
            topology,
            apertures,
            resource.owner,
            resource.class,
            base,
            resource.len,
        )?;
        planned.push(PlannedResource {
            owner: resource.owner,
            register: resource.register,
            class: resource.class,
            old_pci_base: None,
            pci_base: base,
            cpu_base,
            len: resource.len,
            fixed: resource.fixed,
        });
        occupied.push(Occupied {
            container: assigned_container,
            base,
            len: resource.len,
        });
    }

    let bus_reserves = compute_hotplug_bus_reserves(topology, hotplug_ports, reserve_policy)?;

    planned.sort_by_key(|resource| (resource.owner, resource.register));
    Ok(ResourcePlan {
        topology_generation: topology.generation(),
        resources: planned,
        bus_reserves,
    })
}

fn validate_hotplug_reserve_policy(policy: HotplugReservePolicy) -> Result<(), PlanError> {
    if !policy.io_bytes.is_multiple_of(BRIDGE_IO_GRANULARITY)
        || !policy
            .mmio32_bytes
            .is_multiple_of(BRIDGE_MEMORY_GRANULARITY)
        || !policy
            .prefetch_mmio64_bytes
            .is_multiple_of(BRIDGE_MEMORY_GRANULARITY)
    {
        return Err(PlanError::InvalidRequirement);
    }
    Ok(())
}

fn window_index_for_class(class: ResourceClass) -> u8 {
    match class {
        ResourceClass::Io => 0,
        ResourceClass::Mmio32 => 1,
        ResourceClass::Mmio64 | ResourceClass::PrefetchableMemory => 2,
    }
}

fn aggregate_bottom_up_bridge_windows(
    topology: &TopologySnapshot,
    preserved: &[PlannedResource],
    pending: &mut Vec<FirmwareResource>,
    hotplug_ports: &[PciAddress],
    reserve_policy: HotplugReservePolicy,
) -> Result<(), PlanError> {
    let mut bridges = Vec::new();
    bridges
        .try_reserve(topology.nodes().len())
        .map_err(|_| PlanError::NoMemory)?;
    for node in topology.nodes() {
        if matches!(node.function.kind, FunctionKind::PciBridge { .. }) {
            bridges.push((node.depth, node.function.address));
        }
    }
    // Deepest bridges first so parent bridges see aggregated child bridge windows.
    bridges.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    const CLASSES: [ResourceClass; 4] = [
        ResourceClass::Io,
        ResourceClass::Mmio32,
        ResourceClass::Mmio64,
        ResourceClass::PrefetchableMemory,
    ];

    for &(_depth, bridge_addr) in &bridges {
        let is_hotplug = hotplug_ports.contains(&bridge_addr);
        for class in CLASSES {
            let has_preserved_window = preserved.iter().any(|r| {
                r.owner == bridge_addr
                    && matches!(r.register, ResourceRegister::BridgeWindow(_))
                    && r.class == class
            });
            if has_preserved_window {
                continue;
            }

            let mut child_reqs: Vec<u64> = Vec::new();
            for item in pending.iter() {
                if item.class != class {
                    continue;
                }
                let is_direct_child = topology
                    .find(item.owner)
                    .is_some_and(|n| n.parent == Parent::Bridge(bridge_addr));
                if is_direct_child {
                    child_reqs.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                    child_reqs.push(item.len);
                }
            }
            // Sort descending by natural alignment/size so packed sum has zero internal gaps.
            child_reqs.sort_by(|a, b| b.cmp(a));
            let mut needed = 0u64;
            for len in child_reqs {
                needed = needed
                    .checked_add(len)
                    .ok_or(PlanError::ArithmeticOverflow)?;
            }
            if is_hotplug {
                // Avoid double-reserving both Mmio64 and PrefetchableMemory unless child uses Mmio64;
                // standard PCIe prefetchable 64-bit window is ResourceClass::PrefetchableMemory.
                let reserve = if class == ResourceClass::Mmio64 && needed == 0 {
                    0
                } else {
                    reserve_policy.reserve_for_class(class)
                };
                needed = needed
                    .checked_add(reserve)
                    .ok_or(PlanError::ArithmeticOverflow)?;
            }
            if needed == 0 {
                continue;
            }
            let gran = bridge_granularity(class);
            let rounded = align_up(needed, gran)?;
            if let Some(existing) = pending.iter_mut().find(|r| {
                r.owner == bridge_addr
                    && matches!(r.register, ResourceRegister::BridgeWindow(_))
                    && r.class == class
            }) {
                if existing.len < rounded {
                    existing.len = rounded;
                }
            } else {
                if pending.len() >= MAX_PLANNED_RESOURCES {
                    return Err(PlanError::TooManyResources);
                }
                pending.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                pending.push(FirmwareResource {
                    owner: bridge_addr,
                    register: ResourceRegister::BridgeWindow(window_index_for_class(class)),
                    class,
                    assigned: false,
                    pci_base: 0,
                    len: rounded,
                    fixed: false,
                });
            }
        }
    }
    Ok(())
}

fn compute_hotplug_bus_reserves(
    topology: &TopologySnapshot,
    hotplug_ports: &[PciAddress],
    reserve_policy: HotplugReservePolicy,
) -> Result<Vec<PlannedBusReserve>, PlanError> {
    let mut out = Vec::new();
    if hotplug_ports.is_empty() || reserve_policy.extra_buses == 0 {
        return Ok(out);
    }
    out.try_reserve(hotplug_ports.len())
        .map_err(|_| PlanError::NoMemory)?;
    for &bridge_addr in hotplug_ports {
        let Some(node) = topology.find(bridge_addr) else {
            return Err(PlanError::MissingTopology);
        };
        let FunctionKind::PciBridge {
            secondary_bus,
            subordinate_bus,
        } = node.function.kind
        else {
            return Err(PlanError::InvalidRequirement);
        };
        let mut used_max = secondary_bus;
        for candidate in topology.nodes() {
            let bus = candidate.function.address.bus();
            if bus >= secondary_bus
                && bus <= subordinate_bus
                && candidate.function.address.segment() == bridge_addr.segment()
            {
                used_max = used_max.max(bus);
                if let FunctionKind::PciBridge {
                    subordinate_bus: child_sub,
                    ..
                } = candidate.function.kind
                {
                    used_max = used_max.max(child_sub);
                }
            }
        }
        let reserved = used_max
            .saturating_add(reserve_policy.extra_buses)
            .min(subordinate_bus);
        out.push(PlannedBusReserve {
            bridge: bridge_addr,
            secondary_bus,
            used_subordinate_bus: used_max,
            reserved_subordinate_bus: reserved,
        });
    }
    out.sort_by_key(|r| r.bridge);
    Ok(out)
}

fn allocation_order(
    topology: &TopologySnapshot,
    resource: FirmwareResource,
) -> (u8, u8, PciAddress, ResourceRegister) {
    let depth = topology
        .find(resource.owner)
        .map(|node| node.depth)
        .unwrap_or(u8::MAX);
    let kind_order = match resource.register {
        ResourceRegister::BridgeWindow(_) => 0,
        ResourceRegister::Bar(_) => 1,
    };
    (depth, kind_order, resource.owner, resource.register)
}

fn validate_requirement(
    topology: &TopologySnapshot,
    resource: FirmwareResource,
) -> Result<(), PlanError> {
    if resource.assigned || resource.len == 0 {
        return Err(PlanError::InvalidRequirement);
    }
    match resource.register {
        ResourceRegister::Bar(index) => {
            if index >= 6 || !resource.len.is_power_of_two() {
                return Err(PlanError::InvalidRequirement);
            }
        }
        ResourceRegister::BridgeWindow(index) => {
            let Some(node) = topology.find(resource.owner) else {
                return Err(PlanError::MissingTopology);
            };
            if index >= 3 || !matches!(node.function.kind, FunctionKind::PciBridge { .. }) {
                return Err(PlanError::InvalidRequirement);
            }
            let granularity = bridge_granularity(resource.class);
            if !resource.len.is_multiple_of(granularity) {
                return Err(PlanError::InvalidRequirement);
            }
        }
    }
    Ok(())
}

fn resource_alignment(resource: FirmwareResource) -> Result<u64, PlanError> {
    match resource.register {
        ResourceRegister::Bar(_) => Ok(resource.len),
        ResourceRegister::BridgeWindow(_) => Ok(bridge_granularity(resource.class)),
    }
}

fn bridge_granularity(class: ResourceClass) -> u64 {
    match class {
        ResourceClass::Io => BRIDGE_IO_GRANULARITY,
        ResourceClass::Mmio32 | ResourceClass::Mmio64 | ResourceClass::PrefetchableMemory => {
            BRIDGE_MEMORY_GRANULARITY
        }
    }
}

fn direct_container(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    planned: &[PlannedResource],
    resource: FirmwareResource,
) -> Result<Container, PlanError> {
    let node = topology
        .find(resource.owner)
        .ok_or(PlanError::MissingTopology)?;
    match node.parent {
        Parent::Root(root_id) => root_container_for_resource(apertures, root_id, resource),
        Parent::Bridge(parent) => {
            let exists = planned.iter().any(|candidate| {
                candidate.owner == parent
                    && matches!(candidate.register, ResourceRegister::BridgeWindow(_))
                    && candidate.class == resource.class
                    && range_contains(
                        candidate.pci_base,
                        candidate.len,
                        resource.pci_base,
                        resource.len,
                    )
            });
            if resource.assigned && !exists {
                return Err(PlanError::MissingParentWindow);
            }
            if !resource.assigned
                && !planned.iter().any(|candidate| {
                    candidate.owner == parent
                        && matches!(candidate.register, ResourceRegister::BridgeWindow(_))
                        && candidate.class == resource.class
                })
            {
                return Err(PlanError::MissingParentWindow);
            }
            Ok(Container::BridgeWindow(parent, resource.class))
        }
    }
}

fn root_container_for_resource(
    apertures: &[RootAperture],
    root_id: u64,
    resource: FirmwareResource,
) -> Result<Container, PlanError> {
    if resource.assigned {
        let mut found = None;
        for (index, aperture) in apertures.iter().enumerate() {
            if aperture.root_id == root_id
                && aperture.class == resource.class
                && range_contains(
                    aperture.pci_base,
                    aperture.len,
                    resource.pci_base,
                    resource.len,
                )
            {
                if found.is_some() {
                    return Err(PlanError::InvalidValidationReport);
                }
                found = Some(Container::RootAperture(index));
            }
        }
        found.ok_or(PlanError::NoSpace)
    } else {
        // Allocation tries all matching root apertures in canonical order.
        Ok(Container::RootClass(root_id, resource.class))
    }
}

fn container_ranges(
    container: Container,
    apertures: &[RootAperture],
    planned: &[PlannedResource],
) -> Result<Vec<(Container, u64, u64)>, PlanError> {
    let mut ranges = Vec::new();
    match container {
        Container::RootAperture(index) => {
            let aperture = apertures.get(index).ok_or(PlanError::MissingTopology)?;
            ranges
                .try_reserve_exact(1)
                .map_err(|_| PlanError::NoMemory)?;
            ranges.push((container, aperture.pci_base, aperture.len));
        }
        Container::RootClass(root_id, class) => {
            ranges
                .try_reserve_exact(apertures.len())
                .map_err(|_| PlanError::NoMemory)?;
            for (index, aperture) in apertures.iter().enumerate() {
                if aperture.root_id == root_id && aperture.class == class {
                    ranges.push((
                        Container::RootAperture(index),
                        aperture.pci_base,
                        aperture.len,
                    ));
                }
            }
            ranges.sort_by_key(|(_, base, len)| (*base, *len));
            if ranges.is_empty() {
                return Err(PlanError::NoSpace);
            }
        }
        Container::BridgeWindow(parent, class) => {
            let window = planned
                .iter()
                .find(|candidate| {
                    candidate.owner == parent
                        && matches!(candidate.register, ResourceRegister::BridgeWindow(_))
                        && candidate.class == class
                })
                .ok_or(PlanError::MissingParentWindow)?;
            ranges
                .try_reserve_exact(1)
                .map_err(|_| PlanError::NoMemory)?;
            ranges.push((container, window.pci_base, window.len));
        }
    }
    Ok(ranges)
}

fn first_fit(
    ranges: &[(Container, u64, u64)],
    occupied: &[Occupied],
    len: u64,
    alignment: u64,
) -> Result<(u64, Container), PlanError> {
    for (container, base, range_len) in ranges {
        if let Some(address) =
            first_fit_in_range(*container, *base, *range_len, occupied, len, alignment)?
        {
            return Ok((address, *container));
        }
    }
    Err(PlanError::NoSpace)
}

fn first_fit_in_range(
    container: Container,
    base: u64,
    range_len: u64,
    occupied: &[Occupied],
    len: u64,
    alignment: u64,
) -> Result<Option<u64>, PlanError> {
    let end = base
        .checked_add(range_len)
        .ok_or(PlanError::ArithmeticOverflow)?;
    let mut cursor = align_up(base, alignment)?;
    let mut blockers = Vec::new();
    blockers
        .try_reserve_exact(occupied.len())
        .map_err(|_| PlanError::NoMemory)?;
    for item in occupied {
        if item.container == container {
            blockers.push(*item);
        }
    }
    blockers.sort_by_key(|item| item.base);
    for blocker in blockers {
        let candidate_end = cursor
            .checked_add(len)
            .ok_or(PlanError::ArithmeticOverflow)?;
        if candidate_end <= blocker.base {
            return Ok(Some(cursor));
        }
        if cursor < blocker.base.saturating_add(blocker.len) {
            cursor = align_up(
                blocker
                    .base
                    .checked_add(blocker.len)
                    .ok_or(PlanError::ArithmeticOverflow)?,
                alignment,
            )?;
        }
    }
    let candidate_end = cursor
        .checked_add(len)
        .ok_or(PlanError::ArithmeticOverflow)?;
    Ok((candidate_end <= end).then_some(cursor))
}

fn align_up(value: u64, alignment: u64) -> Result<u64, PlanError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(PlanError::InvalidRequirement);
    }
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|aligned| aligned & !mask)
        .ok_or(PlanError::ArithmeticOverflow)
}

fn translate_to_cpu(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    owner: PciAddress,
    class: ResourceClass,
    pci_base: u64,
    len: u64,
) -> Result<u64, PlanError> {
    let root_id = root_id_of(topology, owner).ok_or(PlanError::MissingTopology)?;
    let mut translated = None;
    for aperture in apertures {
        if aperture.root_id == root_id
            && aperture.class == class
            && range_contains(aperture.pci_base, aperture.len, pci_base, len)
        {
            if translated.is_some() {
                return Err(PlanError::InvalidValidationReport);
            }
            let delta = pci_base
                .checked_sub(aperture.pci_base)
                .ok_or(PlanError::ArithmeticOverflow)?;
            translated = Some(
                aperture
                    .cpu_base
                    .checked_add(delta)
                    .ok_or(PlanError::ArithmeticOverflow)?,
            );
        }
    }
    translated.ok_or(PlanError::NoSpace)
}

fn root_id_of(topology: &TopologySnapshot, owner: PciAddress) -> Option<u64> {
    let mut parent = topology.find(owner).map(|node| node.parent);
    let mut remaining = crate::topology::MAX_TOPOLOGY_DEPTH + 1;
    while remaining != 0 {
        match parent {
            Some(Parent::Root(root_id)) => return Some(root_id),
            Some(Parent::Bridge(address)) => {
                parent = topology.find(address).map(|node| node.parent);
            }
            None => return None,
        }
        remaining -= 1;
    }
    None
}

fn range_contains(outer_base: u64, outer_len: u64, inner_base: u64, inner_len: u64) -> bool {
    inner_base >= outer_base
        && inner_base.saturating_add(inner_len) <= outer_base.saturating_add(outer_len)
}

/// One staged configuration-space register mutation with rollback metadata (Stage F.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedWrite {
    /// Target PCI routing address.
    pub owner: PciAddress,
    /// PCI header layout of `owner`.
    pub header_kind: HeaderKind,
    /// B.4 write policy class.
    pub class: WriteClass,
    /// Register offset.
    pub offset: u16,
    /// Access width.
    pub width: ConfigWidth,
    /// Original register value read before commit (used for rollback).
    pub old_value: u32,
    /// Planned new register value.
    pub new_value: u32,
    /// Bit mask modified in the register.
    pub write_mask: u32,
    /// Readback verification mask enforced after write.
    pub expected_readback_mask: u32,
}

impl PlannedWrite {
    /// Convert this planned mutation into an inverse rollback [`WriteRequest`].
    pub const fn as_rollback_request(self) -> WriteRequest {
        WriteRequest {
            address: self.owner,
            header_kind: self.header_kind,
            class: self.class,
            offset: self.offset,
            width: self.width,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: self.old_value,
            write_mask: self.write_mask,
            expected_readback_mask: self.expected_readback_mask,
            allowlist_entry: None,
        }
    }

    /// Convert this planned mutation into a forward [`WriteRequest`].
    pub const fn as_forward_request(self) -> WriteRequest {
        WriteRequest {
            address: self.owner,
            header_kind: self.header_kind,
            class: self.class,
            offset: self.offset,
            width: self.width,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: self.new_value,
            write_mask: self.write_mask,
            expected_readback_mask: self.expected_readback_mask,
            allowlist_entry: None,
        }
    }
}

/// Ordered hardware commit plan with explicit rollback sequence (Stage F.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPlan {
    topology_generation: u64,
    writes: Vec<PlannedWrite>,
}

impl CommitPlan {
    /// Topology generation this commit plan targets.
    pub const fn topology_generation(&self) -> u64 {
        self.topology_generation
    }

    /// Forward writes ordered parent-bridge-first, then endpoints.
    pub fn writes(&self) -> &[PlannedWrite] {
        &self.writes
    }

    /// Rollback writes for the entire plan (reverse execution order).
    pub fn rollback_writes(&self) -> impl Iterator<Item = PlannedWrite> + '_ {
        self.writes.iter().rev().copied()
    }
}

/// Result of executing a [`CommitPlan`] against hardware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    /// Step `failed_step` failed and all prior steps `0..failed_step` were cleanly rolled back.
    RolledBack {
        /// Zero-based index of the failing forward step.
        failed_step: usize,
        /// Underlying B.4 write error.
        error: WritePolicyError,
    },
    /// Step `failed_step` failed AND rolling back `rollback_step` also failed.
    RollbackFailed {
        /// Zero-based index of the failing forward step.
        failed_step: usize,
        /// Zero-based index of the step whose rollback failed.
        rollback_step: usize,
        /// Underlying B.4 write error on rollback.
        error: WritePolicyError,
    },
    /// Bounded buffer allocation failed.
    NoMemory,
}

/// Build an ordered [`CommitPlan`] for all newly-assigned or relocated entries in `plan` (Stages F.2 & L).
///
/// Unmoved firmware-preserved (`!newly_assigned() && !moved()`) resources are never mutated.
pub fn build_commit_plan(
    topology: &TopologySnapshot,
    plan: &ResourcePlan,
    transport: &mut impl ConfigReadWriteTransport,
) -> Result<CommitPlan, PlanError> {
    let mut staged: Vec<(u8, u8, PlannedWrite)> = Vec::new();

    for resource in plan.resources() {
        if !resource.newly_assigned() && !resource.moved() {
            continue;
        }
        let node = topology
            .find(resource.owner)
            .ok_or(PlanError::MissingTopology)?;
        let header_kind = match node.function.kind {
            FunctionKind::Endpoint => HeaderKind::Type0Endpoint,
            FunctionKind::PciBridge { .. } => HeaderKind::Type1Bridge,
        };
        let kind_order = match resource.register {
            ResourceRegister::BridgeWindow(_) => 0u8,
            ResourceRegister::Bar(_) => 1u8,
        };

        match resource.register {
            ResourceRegister::Bar(bar_idx) => {
                let offset = OFFSET_BAR0 + u16::from(bar_idx) * 4;
                let old_lo = transport
                    .read_width(resource.owner, offset, ConfigWidth::Dword)
                    .ok_or(PlanError::MissingTopology)?;
                let is_io = (old_lo & 1) == 1;
                let is_64bit = !is_io && ((old_lo >> 1) & 0x3) == 0x2;
                let lo_mask = if is_io { !0x3u32 } else { !0xFu32 };
                let new_lo = (resource.pci_base as u32) & lo_mask;

                let write_mask = if resource.len <= u64::from(u32::MAX) {
                    !((resource.len as u32).wrapping_sub(1)) & lo_mask
                } else {
                    0
                };
                if write_mask != 0 {
                    staged.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                    staged.push((
                        node.depth,
                        kind_order,
                        PlannedWrite {
                            owner: resource.owner,
                            header_kind,
                            class: WriteClass::Bar,
                            offset,
                            width: ConfigWidth::Dword,
                            old_value: old_lo & lo_mask,
                            new_value: new_lo,
                            write_mask,
                            expected_readback_mask: write_mask,
                        },
                    ));
                }

                if is_64bit {
                    let hi_offset = offset + 4;
                    let old_hi = transport
                        .read_width(resource.owner, hi_offset, ConfigWidth::Dword)
                        .ok_or(PlanError::MissingTopology)?;
                    let new_hi = (resource.pci_base >> 32) as u32;
                    staged.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                    staged.push((
                        node.depth,
                        kind_order,
                        PlannedWrite {
                            owner: resource.owner,
                            header_kind,
                            class: WriteClass::Bar,
                            offset: hi_offset,
                            width: ConfigWidth::Dword,
                            old_value: old_hi,
                            new_value: new_hi,
                            write_mask: u32::MAX,
                            expected_readback_mask: u32::MAX,
                        },
                    ));
                }
            }
            ResourceRegister::BridgeWindow(win_idx) => {
                let end = resource
                    .pci_base
                    .checked_add(resource.len)
                    .and_then(|v| v.checked_sub(1))
                    .ok_or(PlanError::ArithmeticOverflow)?;
                match win_idx {
                    0 => {
                        let old_io = transport
                            .read_width(resource.owner, OFFSET_BRIDGE_IO_BASE, ConfigWidth::Word)
                            .ok_or(PlanError::MissingTopology)?;
                        let base_nibble = ((resource.pci_base >> 12) & 0xF) as u32;
                        let limit_nibble = ((end >> 12) & 0xF) as u32;
                        let new_io = ((limit_nibble << 4) << 8) | (base_nibble << 4);
                        staged.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                        staged.push((
                            node.depth,
                            kind_order,
                            PlannedWrite {
                                owner: resource.owner,
                                header_kind,
                                class: WriteClass::BridgeWindow,
                                offset: OFFSET_BRIDGE_IO_BASE,
                                width: ConfigWidth::Word,
                                old_value: old_io & 0xF0F0,
                                new_value: new_io & 0xF0F0,
                                write_mask: 0xF0F0,
                                expected_readback_mask: 0xF0F0,
                            },
                        ));
                    }
                    1 => {
                        let old_mem = transport
                            .read_width(resource.owner, 0x20, ConfigWidth::Dword)
                            .ok_or(PlanError::MissingTopology)?;
                        let base_bits = ((resource.pci_base >> 16) & 0xFFF0) as u32;
                        let limit_bits = ((end >> 16) & 0xFFF0) as u32;
                        let new_mem = (limit_bits << 16) | base_bits;
                        staged.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                        staged.push((
                            node.depth,
                            kind_order,
                            PlannedWrite {
                                owner: resource.owner,
                                header_kind,
                                class: WriteClass::BridgeWindow,
                                offset: 0x20,
                                width: ConfigWidth::Dword,
                                old_value: old_mem & 0xFFF0_FFF0,
                                new_value: new_mem,
                                write_mask: 0xFFF0_FFF0,
                                expected_readback_mask: 0xFFF0_FFF0,
                            },
                        ));
                    }
                    2 => {
                        let old_pref = transport
                            .read_width(resource.owner, 0x24, ConfigWidth::Dword)
                            .ok_or(PlanError::MissingTopology)?;
                        let base_bits = ((resource.pci_base >> 16) & 0xFFF0) as u32;
                        let limit_bits = ((end >> 16) & 0xFFF0) as u32;
                        let new_pref = (limit_bits << 16) | base_bits;
                        staged.try_reserve(1).map_err(|_| PlanError::NoMemory)?;
                        staged.push((
                            node.depth,
                            kind_order,
                            PlannedWrite {
                                owner: resource.owner,
                                header_kind,
                                class: WriteClass::BridgeWindow,
                                offset: 0x24,
                                width: ConfigWidth::Dword,
                                old_value: old_pref & 0xFFF0_FFF0,
                                new_value: new_pref,
                                write_mask: 0xFFF0_FFF0,
                                expected_readback_mask: 0xFFF0_FFF0,
                            },
                        ));
                    }
                    _ => return Err(PlanError::InvalidRequirement),
                }
            }
        }
    }

    staged.sort_by_key(|(depth, kind_order, w)| (*depth, *kind_order, w.owner, w.offset));
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(staged.len())
        .map_err(|_| PlanError::NoMemory)?;
    for (_, _, w) in staged {
        writes.push(w);
    }
    Ok(CommitPlan {
        topology_generation: plan.topology_generation(),
        writes,
    })
}

/// Execute `commit_plan` step-by-step through B.4 `execute_checked_write`.
///
/// On any failure at step `i`, automatically rolls back steps `(i - 1)..=0` in
/// reverse order using each step's `old_value`.
pub fn execute_commit_plan(
    commit_plan: &CommitPlan,
    transport: &mut impl ConfigReadWriteTransport,
) -> Result<Vec<WriteTransactionRecord>, CommitError> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(commit_plan.writes().len())
        .map_err(|_| CommitError::NoMemory)?;

    for (step, write) in commit_plan.writes().iter().enumerate() {
        let req = write.as_forward_request();
        match execute_checked_write(transport, &req) {
            Ok(rec) => records.push(rec),
            Err(err) => {
                for rev_idx in (0..step).rev() {
                    let rb_req = commit_plan.writes()[rev_idx].as_rollback_request();
                    if let Err(rb_err) = execute_checked_write(transport, &rb_req) {
                        return Err(CommitError::RollbackFailed {
                            failed_step: step,
                            rollback_step: rev_idx,
                            error: rb_err,
                        });
                    }
                }
                return Err(CommitError::RolledBack {
                    failed_step: step,
                    error: err,
                });
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_validation::{validate_firmware_resources, FirmwareResource};
    use crate::topology::{build_snapshot, DiscoveredFunction, FunctionKind, RootBus};
    use crate::ClassCode;

    fn address(bus: u8, device: u8) -> PciAddress {
        match PciAddress::try_new(0, bus, device, 0) {
            Ok(address) => address,
            Err(_) => {
                assert!(false, "test address should be valid");
                PciAddress::ZERO
            }
        }
    }

    fn function(address: PciAddress, kind: FunctionKind) -> DiscoveredFunction {
        DiscoveredFunction {
            address,
            vendor_id: 0x1234,
            device_id: u16::from(address.device()),
            class_code: ClassCode {
                class: if matches!(kind, FunctionKind::PciBridge { .. }) {
                    0x06
                } else {
                    0x02
                },
                subclass: if matches!(kind, FunctionKind::PciBridge { .. }) {
                    0x04
                } else {
                    0
                },
                prog_if: 0,
            },
            kind,
        }
    }

    fn topology() -> Result<TopologySnapshot, crate::topology::TopologyError> {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 7,
        }];
        let functions = [
            function(
                address(0, 1),
                FunctionKind::PciBridge {
                    secondary_bus: 1,
                    subordinate_bus: 7,
                },
            ),
            function(address(1, 0), FunctionKind::Endpoint),
            function(address(1, 1), FunctionKind::Endpoint),
        ];
        build_snapshot(7, &roots, &functions)
    }

    fn aperture(len: u64) -> RootAperture {
        RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x9000_0000,
            len,
        }
    }

    fn window(assigned: bool) -> FirmwareResource {
        FirmwareResource {
            owner: address(0, 1),
            register: ResourceRegister::BridgeWindow(1),
            class: ResourceClass::Mmio32,
            assigned,
            pci_base: if assigned { 0x8000_0000 } else { 0 },
            len: 0x0100_0000,
            fixed: false,
        }
    }

    fn bar(owner: PciAddress, base: Option<u64>) -> FirmwareResource {
        FirmwareResource {
            owner,
            register: ResourceRegister::Bar(0),
            class: ResourceClass::Mmio32,
            assigned: base.is_some(),
            pci_base: base.unwrap_or(0),
            len: 0x1000,
            fixed: false,
        }
    }

    fn validated(
        topology: &TopologySnapshot,
        apertures: &[RootAperture],
        resources: &[FirmwareResource],
    ) -> Result<ValidationReport, crate::resource_validation::ValidationError> {
        validate_firmware_resources(topology, apertures, resources)
    }

    #[test]
    fn preserves_firmware_and_allocates_only_unassigned_bar() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let resources = [
            window(true),
            bar(address(1, 0), Some(0x8000_2000)),
            bar(address(1, 1), None),
        ];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            assert!(false, "firmware validation should run");
            return;
        };
        let Ok(plan) = plan_firmware_preserving(&topology, &apertures, &validation) else {
            assert!(false, "firmware-preserving plan should fit");
            return;
        };
        assert_eq!(plan.topology_generation(), 7);
        let Some(preserved) = plan.find(address(1, 0), ResourceRegister::Bar(0)) else {
            assert!(false, "preserved BAR should exist");
            return;
        };
        assert_eq!(preserved.pci_base, 0x8000_2000);
        assert_eq!(preserved.old_pci_base, Some(0x8000_2000));
        assert!(!preserved.moved());
        let Some(allocated) = plan.find(address(1, 1), ResourceRegister::Bar(0)) else {
            assert!(false, "allocated BAR should exist");
            return;
        };
        assert_eq!(allocated.pci_base, 0x8000_0000);
        assert_eq!(allocated.cpu_base, 0x9000_0000);
        assert!(allocated.newly_assigned());
    }

    #[test]
    fn allocates_parent_window_before_child_bar() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let resources = [window(false), bar(address(1, 0), None)];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            assert!(false, "unassigned resources should validate");
            return;
        };
        let Ok(plan) = plan_firmware_preserving(&topology, &apertures, &validation) else {
            assert!(false, "window and child should plan");
            return;
        };
        let Some(window) = plan.find(address(0, 1), ResourceRegister::BridgeWindow(1)) else {
            assert!(false, "planned window should exist");
            return;
        };
        let Some(bar) = plan.find(address(1, 0), ResourceRegister::Bar(0)) else {
            assert!(false, "planned child BAR should exist");
            return;
        };
        assert!(bar.pci_base >= window.pci_base);
        assert!(bar.pci_base + bar.len <= window.pci_base + window.len);
    }

    #[test]
    fn fixed_and_valid_assignments_never_move() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let mut fixed_bar = bar(address(1, 0), Some(0x8000_4000));
        fixed_bar.fixed = true;
        let resources = [window(true), fixed_bar];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            assert!(false, "fixed resource should validate");
            return;
        };
        let Ok(plan) = plan_firmware_preserving(&topology, &apertures, &validation) else {
            assert!(false, "fixed plan should build");
            return;
        };
        let Some(resource) = plan.find(address(1, 0), ResourceRegister::Bar(0)) else {
            assert!(false, "fixed BAR should exist");
            return;
        };
        assert_eq!(resource.old_pci_base, Some(resource.pci_base));
        assert!(resource.fixed);
        assert!(!resource.moved());
    }

    #[test]
    fn returns_no_space_without_stealing_firmware_assignment() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x0100_0000)];
        let mut full_window = window(true);
        full_window.len = BRIDGE_MEMORY_GRANULARITY;
        let mut full_bar = bar(address(1, 0), Some(0x8000_0000));
        full_bar.len = BRIDGE_MEMORY_GRANULARITY;
        let resources = [full_window, full_bar, bar(address(1, 1), None)];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            assert!(false, "firmware resources should validate");
            return;
        };
        assert_eq!(
            plan_firmware_preserving(&topology, &apertures, &validation),
            Err(PlanError::NoSpace)
        );
    }

    #[test]
    fn rejects_conflicting_validation_report() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let resources = [
            window(true),
            bar(address(1, 0), Some(0x8000_2000)),
            bar(address(1, 1), Some(0x8000_2000)),
        ];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            assert!(false, "conflicts should produce a report");
            return;
        };
        assert_eq!(
            plan_firmware_preserving(&topology, &apertures, &validation),
            Err(PlanError::InvalidValidationReport)
        );
    }

    #[test]
    fn rejects_unrounded_bridge_window_requirement() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let mut bad_window = window(false);
        bad_window.len = BRIDGE_MEMORY_GRANULARITY + 1;
        let Ok(validation) = validated(&topology, &apertures, &[bad_window]) else {
            assert!(false, "unassigned window should reach planner");
            return;
        };
        assert_eq!(
            plan_firmware_preserving(&topology, &apertures, &validation),
            Err(PlanError::InvalidRequirement)
        );
    }

    struct CommitMockTransport {
        bridge_mem_win: u32,
        bar0: u32,
        bar1: u32,
        fail_on_write_call: Option<usize>,
        write_calls: usize,
    }

    impl CommitMockTransport {
        fn new() -> Self {
            Self {
                bridge_mem_win: 0,
                bar0: 0,
                bar1: 0,
                fail_on_write_call: None,
                write_calls: 0,
            }
        }
    }

    impl ConfigReadWriteTransport for CommitMockTransport {
        fn read_width(
            &mut self,
            owner: PciAddress,
            offset: u16,
            _width: ConfigWidth,
        ) -> Option<u32> {
            match (owner.bus(), owner.device(), offset) {
                (0, 1, 0x20) => Some(self.bridge_mem_win),
                (1, 0, 0x10) => Some(self.bar0),
                (1, 1, 0x10) => Some(self.bar1),
                _ => Some(0),
            }
        }

        fn write_width(
            &mut self,
            owner: PciAddress,
            offset: u16,
            _width: ConfigWidth,
            value: u32,
        ) -> bool {
            self.write_calls += 1;
            if self.fail_on_write_call == Some(self.write_calls) {
                return false;
            }
            match (owner.bus(), owner.device(), offset) {
                (0, 1, 0x20) => {
                    self.bridge_mem_win = value & 0xFFF0_FFF0;
                    true
                }
                (1, 0, 0x10) => {
                    self.bar0 = value & 0xFFFF_F000;
                    true
                }
                (1, 1, 0x10) => {
                    self.bar1 = value & 0xFFFF_F000;
                    true
                }
                _ => false,
            }
        }
    }

    #[test]
    fn commit_plan_executes_and_rolls_back_cleanly_on_injected_fault() {
        let Ok(topology) = topology() else {
            return;
        };
        let apertures = [aperture(0x1000_0000)];
        let resources = [
            window(false),
            bar(address(1, 0), None),
            bar(address(1, 1), None),
        ];
        let Ok(validation) = validated(&topology, &apertures, &resources) else {
            return;
        };
        let Ok(plan) = plan_firmware_preserving(&topology, &apertures, &validation) else {
            return;
        };
        let mut transport = CommitMockTransport::new();
        let Ok(commit_plan) = build_commit_plan(&topology, &plan, &mut transport) else {
            assert!(false, "commit plan should build");
            return;
        };
        assert_eq!(commit_plan.writes().len(), 3);
        assert_eq!(commit_plan.writes()[0].offset, 0x20); // bridge window first!

        // Fault injection on step 3 (third write call): steps 1 and 2 must roll back to 0!
        transport.fail_on_write_call = Some(3);
        let err = execute_commit_plan(&commit_plan, &mut transport);
        assert_eq!(
            err,
            Err(CommitError::RolledBack {
                failed_step: 2,
                error: WritePolicyError::TransportWriteFailed,
            })
        );
        assert_eq!(transport.bridge_mem_win, 0);
        assert_eq!(transport.bar0, 0);
        assert_eq!(transport.bar1, 0);

        // Retry without fault injection succeeds completely.
        transport.fail_on_write_call = None;
        let Ok(recs) = execute_commit_plan(&commit_plan, &mut transport) else {
            assert!(false, "commit plan should succeed without fault injection");
            return;
        };
        assert_eq!(recs.len(), 3);
        assert_eq!(transport.bridge_mem_win, 0x80F0_8000);
        assert_eq!(transport.bar0, 0x8000_0000);
        assert_eq!(transport.bar1, 0x8000_1000);
    }

    #[test]
    fn bottom_up_bridge_aggregation_and_hotplug_reserves_size_nested_windows() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 15,
        }];
        let functions = [
            function(
                address(0, 1),
                FunctionKind::PciBridge {
                    secondary_bus: 1,
                    subordinate_bus: 10,
                },
            ),
            function(
                address(1, 0),
                FunctionKind::PciBridge {
                    secondary_bus: 2,
                    subordinate_bus: 6,
                },
            ),
            function(address(2, 0), FunctionKind::Endpoint),
        ];
        let Ok(nested_topo) = build_snapshot(9, &roots, &functions) else {
            assert!(false, "nested topology should build");
            return;
        };
        let apertures = [
            aperture(0x2000_0000),
            RootAperture {
                root_id: 1,
                class: ResourceClass::PrefetchableMemory,
                pci_base: 0xC000_0000,
                cpu_base: 0xC000_0000,
                len: 0x2000_0000,
            },
        ];
        // Endpoint at 02:00.0 has an unassigned 2 MiB BAR0, and NEITHER parent bridge
        // has a pre-declared BridgeWindow yet — bottom-up aggregation must synthesize
        // both 01:00.0's window (+ 2 MiB hotplug reserve = 4 MiB) and 00:01.0's outer window!
        let ep_bar = FirmwareResource {
            owner: address(2, 0),
            register: ResourceRegister::Bar(0),
            class: ResourceClass::Mmio32,
            assigned: false,
            pci_base: 0,
            len: 0x0020_0000,
            fixed: false,
        };
        let Ok(validation) = validated(&nested_topo, &apertures, &[ep_bar]) else {
            assert!(false, "unassigned child BAR should validate");
            return;
        };
        let hotplug_ports = [address(1, 0)];
        let Ok(plan) = plan_with_hotplug_reserves(
            &nested_topo,
            &apertures,
            &validation,
            &hotplug_ports,
            HotplugReservePolicy::STANDARD_PCIE_SLOT,
        ) else {
            assert!(false, "bottom-up + hotplug reserve plan should succeed");
            return;
        };
        let Some(inner_win) = plan.find(address(1, 0), ResourceRegister::BridgeWindow(1)) else {
            assert!(false, "inner bridge window must be synthesized");
            return;
        };
        let Some(outer_win) = plan.find(address(0, 1), ResourceRegister::BridgeWindow(1)) else {
            assert!(false, "outer bridge window must be synthesized");
            return;
        };
        let Some(planned_ep) = plan.find(address(2, 0), ResourceRegister::Bar(0)) else {
            assert!(false, "endpoint BAR must be allocated");
            return;
        };
        // 2 MiB child BAR + 2 MiB hotplug reserve = 4 MiB on inner & outer windows.
        assert_eq!(inner_win.len, 0x0040_0000);
        assert_eq!(outer_win.len, 0x0040_0000);
        assert!(planned_ep.pci_base >= inner_win.pci_base);
        assert!(planned_ep.pci_base + planned_ep.len <= inner_win.pci_base + inner_win.len);
        assert_eq!(plan.bus_reserves().len(), 1);
        assert_eq!(plan.bus_reserves()[0].used_subordinate_bus, 2);
        assert_eq!(plan.bus_reserves()[0].reserved_subordinate_bus, 4);
    }
}
