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
use crate::PciAddress;

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

/// Complete deterministic plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePlan {
    topology_generation: u64,
    resources: Vec<PlannedResource>,
}

impl ResourcePlan {
    /// Topology generation this plan was calculated against.
    pub const fn topology_generation(&self) -> u64 {
        self.topology_generation
    }

    /// Resources ordered by owner/register.
    pub fn resources(&self) -> &[PlannedResource] {
        &self.resources
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
/// unassigned requirements.
pub fn plan_firmware_preserving(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    validation: &ValidationReport,
) -> Result<ResourcePlan, PlanError> {
    if validation.resources().len() > MAX_PLANNED_RESOURCES {
        return Err(PlanError::TooManyResources);
    }
    if !validation.is_conflict_free() {
        return Err(PlanError::InvalidValidationReport);
    }

    let mut planned = Vec::new();
    planned
        .try_reserve_exact(validation.resources().len())
        .map_err(|_| PlanError::NoMemory)?;
    let mut occupied = Vec::new();
    occupied
        .try_reserve_exact(validation.resources().len())
        .map_err(|_| PlanError::NoMemory)?;

    // Preserve every firmware assignment before allocating anything new.
    for validated in validation.resources() {
        if !matches!(
            validated.status,
            ResourceStatus::Valid | ResourceStatus::Fixed
        ) {
            continue;
        }
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

    // Parent windows must exist before resources below them are allocated.
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(validation.resources().len())
        .map_err(|_| PlanError::NoMemory)?;
    for validated in validation.resources() {
        if validated.status == ResourceStatus::Unassigned {
            pending.push(validated.resource);
        }
    }
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

    planned.sort_by_key(|resource| (resource.owner, resource.register));
    Ok(ResourcePlan {
        topology_generation: topology.generation(),
        resources: planned,
    })
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
}
