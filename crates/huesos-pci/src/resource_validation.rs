//! Firmware-assigned PCI BAR and bridge-window validation.
//!
//! The validator never writes hardware. It classifies each supplied resource,
//! translates PCI bus addresses to CPU addresses through explicit root
//! apertures, detects collisions, and verifies forwarding through every parent
//! bridge before a firmware assignment can become a DeviceLease resource.

use alloc::vec::Vec;

use crate::topology::{FunctionKind, Parent, TopologySnapshot};
use crate::PciAddress;

/// Maximum root apertures accepted by one validation pass.
pub const MAX_VALIDATION_APERTURES: usize = 128;
/// Maximum BAR/window records accepted by one validation pass.
pub const MAX_VALIDATION_RESOURCES: usize = 2048;

/// Address-space class used by root apertures, bridge windows, and BARs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceClass {
    /// PCI I/O-port space.
    Io,
    /// Non-prefetchable memory constrained below 4 GiB in PCI bus space.
    Mmio32,
    /// Non-prefetchable 64-bit memory.
    Mmio64,
    /// Prefetchable memory.
    PrefetchableMemory,
}

/// One allocatable root-bridge aperture with explicit address translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootAperture {
    /// Owning topology root ID.
    pub root_id: u64,
    /// Address-space class.
    pub class: ResourceClass,
    /// Base address visible in PCI BARs/windows.
    pub pci_base: u64,
    /// Corresponding CPU physical/I/O base.
    pub cpu_base: u64,
    /// Aperture length.
    pub len: u64,
}

/// Resource register represented by one descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceRegister {
    /// Endpoint/bridge BAR (`0..5`).
    Bar(u8),
    /// Bridge forwarding window (`0..2`: I/O, memory, prefetchable memory).
    BridgeWindow(u8),
}

/// One firmware BAR/window assignment or unassigned requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareResource {
    /// Owning PCI function.
    pub owner: PciAddress,
    /// BAR/window identity within the function.
    pub register: ResourceRegister,
    /// Address-space class.
    pub class: ResourceClass,
    /// Whether firmware assigned an address.
    pub assigned: bool,
    /// PCI bus address when assigned.
    pub pci_base: u64,
    /// Required/assigned length.
    pub len: u64,
    /// Platform/driver policy forbids relocation.
    pub fixed: bool,
}

/// Result classification for one firmware resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceStatus {
    /// Assignment is valid and movable.
    Valid,
    /// Assignment is valid but fixed.
    Fixed,
    /// Requirement has no firmware address and needs allocation.
    Unassigned,
    /// Assignment overlaps another resource that cannot contain it legally.
    Conflicting,
    /// Assignment cannot be routed by a root aperture or parent window.
    Unrouteable,
    /// Descriptor shape/type/alignment is unsupported or malformed.
    Unsupported,
}

/// Validated resource plus translated CPU address when usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedResource {
    /// Original descriptor.
    pub resource: FirmwareResource,
    /// Validation status.
    pub status: ResourceStatus,
    /// Translated CPU base for [`ResourceStatus::Valid`] or
    /// [`ResourceStatus::Fixed`].
    pub cpu_base: Option<u64>,
}

/// Canonically ordered validation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    resources: Vec<ValidatedResource>,
}

impl ValidationReport {
    /// Resources ordered by owner and register.
    pub fn resources(&self) -> &[ValidatedResource] {
        &self.resources
    }

    /// True when every resource is valid/fixed or intentionally unassigned.
    pub fn is_conflict_free(&self) -> bool {
        self.resources.iter().all(|resource| {
            matches!(
                resource.status,
                ResourceStatus::Valid | ResourceStatus::Fixed | ResourceStatus::Unassigned
            )
        })
    }

    /// Find one resource result.
    pub fn find(
        &self,
        owner: PciAddress,
        register: ResourceRegister,
    ) -> Option<&ValidatedResource> {
        self.resources
            .binary_search_by_key(&(owner, register), |entry| {
                (entry.resource.owner, entry.resource.register)
            })
            .ok()
            .and_then(|index| self.resources.get(index))
    }
}

/// Whole-report validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Aperture/resource capacity exceeded.
    TooManyEntries,
    /// Bounded report allocation failed.
    NoMemory,
    /// Root aperture is malformed, overlaps another aperture of its class, or
    /// references no topology root.
    InvalidAperture,
    /// Resource owner is absent from the topology.
    UnknownOwner,
    /// Owner/register tuple occurs more than once.
    DuplicateResource,
}

/// Validate firmware BAR/window assignments against one topology snapshot.
pub fn validate_firmware_resources(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    resources: &[FirmwareResource],
) -> Result<ValidationReport, ValidationError> {
    if apertures.len() > MAX_VALIDATION_APERTURES || resources.len() > MAX_VALIDATION_RESOURCES {
        return Err(ValidationError::TooManyEntries);
    }
    validate_apertures(topology, apertures)?;

    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(resources.len())
        .map_err(|_| ValidationError::NoMemory)?;
    sorted.extend_from_slice(resources);
    sorted.sort_by_key(|resource| (resource.owner, resource.register));
    for (index, resource) in sorted.iter().enumerate() {
        if topology.find(resource.owner).is_none() {
            return Err(ValidationError::UnknownOwner);
        }
        if index != 0
            && sorted[index - 1].owner == resource.owner
            && sorted[index - 1].register == resource.register
        {
            return Err(ValidationError::DuplicateResource);
        }
    }

    let mut validated = Vec::new();
    validated
        .try_reserve_exact(sorted.len())
        .map_err(|_| ValidationError::NoMemory)?;
    for resource in sorted {
        validated.push(validate_one(topology, apertures, resource));
    }
    mark_conflicts(topology, &mut validated);
    validate_forwarding(topology, &mut validated);
    for entry in &mut validated {
        if !matches!(entry.status, ResourceStatus::Valid | ResourceStatus::Fixed) {
            entry.cpu_base = None;
        }
    }
    Ok(ValidationReport {
        resources: validated,
    })
}

fn validate_apertures(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
) -> Result<(), ValidationError> {
    for (index, aperture) in apertures.iter().enumerate() {
        if aperture.len == 0
            || aperture.pci_base.checked_add(aperture.len).is_none()
            || aperture.cpu_base.checked_add(aperture.len).is_none()
            || !topology
                .roots()
                .iter()
                .any(|root| root.root_id == aperture.root_id)
            || (aperture.class == ResourceClass::Mmio32
                && aperture.pci_base + aperture.len > 1u64 << 32)
        {
            return Err(ValidationError::InvalidAperture);
        }
        for previous in &apertures[..index] {
            if previous.root_id == aperture.root_id
                && previous.class == aperture.class
                && ranges_overlap(
                    previous.pci_base,
                    previous.len,
                    aperture.pci_base,
                    aperture.len,
                )
            {
                return Err(ValidationError::InvalidAperture);
            }
        }
    }
    Ok(())
}

fn validate_one(
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    resource: FirmwareResource,
) -> ValidatedResource {
    let mut result = ValidatedResource {
        resource,
        status: ResourceStatus::Unsupported,
        cpu_base: None,
    };
    if !resource_shape_valid(topology, resource) {
        return result;
    }
    if !resource.assigned {
        result.status = ResourceStatus::Unassigned;
        return result;
    }
    let Some(root_id) = root_id_of(topology, resource.owner) else {
        return result;
    };
    let mut matching = apertures.iter().filter(|aperture| {
        aperture.root_id == root_id
            && aperture.class == resource.class
            && range_contains(
                aperture.pci_base,
                aperture.len,
                resource.pci_base,
                resource.len,
            )
    });
    let Some(aperture) = matching.next() else {
        result.status = ResourceStatus::Unrouteable;
        return result;
    };
    if matching.next().is_some() {
        result.status = ResourceStatus::Conflicting;
        return result;
    }
    let Some(delta) = resource.pci_base.checked_sub(aperture.pci_base) else {
        result.status = ResourceStatus::Unrouteable;
        return result;
    };
    let Some(cpu_base) = aperture.cpu_base.checked_add(delta) else {
        result.status = ResourceStatus::Unrouteable;
        return result;
    };
    result.status = if resource.fixed {
        ResourceStatus::Fixed
    } else {
        ResourceStatus::Valid
    };
    result.cpu_base = Some(cpu_base);
    result
}

fn resource_shape_valid(topology: &TopologySnapshot, resource: FirmwareResource) -> bool {
    if resource.len == 0 || resource.pci_base.checked_add(resource.len).is_none() {
        return false;
    }
    match resource.register {
        ResourceRegister::Bar(index) => {
            if index >= 6 || !resource.len.is_power_of_two() {
                return false;
            }
            if resource.assigned && !resource.pci_base.is_multiple_of(resource.len) {
                return false;
            }
        }
        ResourceRegister::BridgeWindow(index) => {
            if index >= 3
                || !matches!(
                    topology.find(resource.owner).map(|node| node.function.kind),
                    Some(FunctionKind::PciBridge { .. })
                )
            {
                return false;
            }
        }
    }
    resource.class != ResourceClass::Mmio32 || resource.pci_base + resource.len <= 1u64 << 32
}

fn mark_conflicts(topology: &TopologySnapshot, resources: &mut [ValidatedResource]) {
    for left_index in 0..resources.len() {
        if !is_usable(resources[left_index].status) {
            continue;
        }
        for right_index in left_index + 1..resources.len() {
            if !is_usable(resources[right_index].status)
                || resources[left_index].resource.class != resources[right_index].resource.class
            {
                continue;
            }
            let Some(left_root) = root_id_of(topology, resources[left_index].resource.owner) else {
                continue;
            };
            let Some(right_root) = root_id_of(topology, resources[right_index].resource.owner)
            else {
                continue;
            };
            if left_root != right_root
                || !ranges_overlap(
                    resources[left_index].resource.pci_base,
                    resources[left_index].resource.len,
                    resources[right_index].resource.pci_base,
                    resources[right_index].resource.len,
                )
            {
                continue;
            }
            if legal_window_containment(
                topology,
                resources[left_index].resource,
                resources[right_index].resource,
            ) || legal_window_containment(
                topology,
                resources[right_index].resource,
                resources[left_index].resource,
            ) {
                continue;
            }
            resources[left_index].status = ResourceStatus::Conflicting;
            resources[right_index].status = ResourceStatus::Conflicting;
        }
    }
}

fn validate_forwarding(topology: &TopologySnapshot, resources: &mut [ValidatedResource]) {
    for index in 0..resources.len() {
        if !is_usable(resources[index].status) {
            continue;
        }
        let resource = resources[index].resource;
        let mut parent = topology.find(resource.owner).map(|node| node.parent);
        while let Some(Parent::Bridge(bridge)) = parent {
            let forwarded = resources.iter().any(|candidate| {
                is_usable(candidate.status)
                    && candidate.resource.owner == bridge
                    && matches!(
                        candidate.resource.register,
                        ResourceRegister::BridgeWindow(_)
                    )
                    && candidate.resource.class == resource.class
                    && range_contains(
                        candidate.resource.pci_base,
                        candidate.resource.len,
                        resource.pci_base,
                        resource.len,
                    )
            });
            if !forwarded {
                resources[index].status = ResourceStatus::Unrouteable;
                break;
            }
            parent = topology.find(bridge).map(|node| node.parent);
        }
    }
}

fn legal_window_containment(
    topology: &TopologySnapshot,
    possible_window: FirmwareResource,
    possible_child: FirmwareResource,
) -> bool {
    matches!(possible_window.register, ResourceRegister::BridgeWindow(_))
        && is_descendant(topology, possible_child.owner, possible_window.owner)
        && range_contains(
            possible_window.pci_base,
            possible_window.len,
            possible_child.pci_base,
            possible_child.len,
        )
}

fn is_descendant(topology: &TopologySnapshot, child: PciAddress, ancestor: PciAddress) -> bool {
    let mut parent = topology.find(child).map(|node| node.parent);
    let mut remaining = crate::topology::MAX_TOPOLOGY_DEPTH + 1;
    while remaining != 0 {
        match parent {
            Some(Parent::Bridge(address)) if address == ancestor => return true,
            Some(Parent::Bridge(address)) => {
                parent = topology.find(address).map(|node| node.parent);
            }
            _ => return false,
        }
        remaining -= 1;
    }
    false
}

fn root_id_of(topology: &TopologySnapshot, address: PciAddress) -> Option<u64> {
    let mut parent = topology.find(address).map(|node| node.parent);
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

fn is_usable(status: ResourceStatus) -> bool {
    matches!(status, ResourceStatus::Valid | ResourceStatus::Fixed)
}

fn ranges_overlap(a_base: u64, a_len: u64, b_base: u64, b_len: u64) -> bool {
    a_base < b_base.saturating_add(b_len) && b_base < a_base.saturating_add(a_len)
}

fn range_contains(outer_base: u64, outer_len: u64, inner_base: u64, inner_len: u64) -> bool {
    inner_base >= outer_base
        && inner_base.saturating_add(inner_len) <= outer_base.saturating_add(outer_len)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        build_snapshot(1, &roots, &functions)
    }

    fn aperture() -> RootAperture {
        RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x9000_0000,
            len: 0x1000_0000,
        }
    }

    fn window() -> FirmwareResource {
        FirmwareResource {
            owner: address(0, 1),
            register: ResourceRegister::BridgeWindow(1),
            class: ResourceClass::Mmio32,
            assigned: true,
            pci_base: 0x8000_0000,
            len: 0x0100_0000,
            fixed: false,
        }
    }

    fn bar(owner: PciAddress, base: u64) -> FirmwareResource {
        FirmwareResource {
            owner,
            register: ResourceRegister::Bar(0),
            class: ResourceClass::Mmio32,
            assigned: true,
            pci_base: base,
            len: 0x1000,
            fixed: false,
        }
    }

    #[test]
    fn validates_nested_bar_and_translates_cpu_address() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let resources = [window(), bar(address(1, 0), 0x8000_2000)];
        let Ok(report) = validate_firmware_resources(&topology, &[aperture()], &resources) else {
            assert!(false, "valid firmware resources should validate");
            return;
        };
        assert!(report.is_conflict_free());
        let Some(result) = report.find(address(1, 0), ResourceRegister::Bar(0)) else {
            assert!(false, "validated BAR should be present");
            return;
        };
        assert_eq!(result.status, ResourceStatus::Valid);
        assert_eq!(result.cpu_base, Some(0x9000_2000));
    }

    #[test]
    fn classifies_unassigned_and_fixed_resources() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let mut unassigned = bar(address(1, 0), 0);
        unassigned.assigned = false;
        let mut fixed = bar(address(1, 1), 0x8000_4000);
        fixed.fixed = true;
        let resources = [window(), unassigned, fixed];
        let Ok(report) = validate_firmware_resources(&topology, &[aperture()], &resources) else {
            assert!(false, "resource classifications should validate");
            return;
        };
        assert_eq!(
            report
                .find(address(1, 0), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Unassigned)
        );
        assert_eq!(
            report
                .find(address(1, 1), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Fixed)
        );
    }

    #[test]
    fn marks_overlapping_sibling_bars_conflicting() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let resources = [
            window(),
            bar(address(1, 0), 0x8000_2000),
            bar(address(1, 1), 0x8000_2000),
        ];
        let Ok(report) = validate_firmware_resources(&topology, &[aperture()], &resources) else {
            assert!(false, "overlaps should produce a report");
            return;
        };
        assert_eq!(
            report
                .find(address(1, 0), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Conflicting)
        );
        assert_eq!(
            report
                .find(address(1, 1), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Conflicting)
        );
        assert!(!report.is_conflict_free());
    }

    #[test]
    fn marks_child_outside_bridge_window_unrouteable() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let mut narrow = window();
        narrow.len = 0x1000;
        let resources = [narrow, bar(address(1, 0), 0x8000_2000)];
        let Ok(report) = validate_firmware_resources(&topology, &[aperture()], &resources) else {
            assert!(false, "routing failure should produce a report");
            return;
        };
        assert_eq!(
            report
                .find(address(1, 0), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Unrouteable)
        );
    }

    #[test]
    fn marks_assignment_outside_root_aperture_unrouteable() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let resources = [window(), bar(address(1, 0), 0x7000_0000)];
        let Ok(report) = validate_firmware_resources(&topology, &[aperture()], &resources) else {
            assert!(false, "out-of-aperture resource should produce a report");
            return;
        };
        assert_eq!(
            report
                .find(address(1, 0), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Unrouteable)
        );
    }

    #[test]
    fn rejects_unknown_owner_duplicate_resource_and_bad_aperture() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        assert_eq!(
            validate_firmware_resources(
                &topology,
                &[aperture()],
                &[bar(address(7, 0), 0x8000_0000)]
            ),
            Err(ValidationError::UnknownOwner)
        );
        let duplicate = bar(address(1, 0), 0x8000_2000);
        assert_eq!(
            validate_firmware_resources(&topology, &[aperture()], &[duplicate, duplicate]),
            Err(ValidationError::DuplicateResource)
        );
        let mut bad_aperture = aperture();
        bad_aperture.len = 0;
        assert_eq!(
            validate_firmware_resources(&topology, &[bad_aperture], &[]),
            Err(ValidationError::InvalidAperture)
        );
    }

    #[test]
    fn malformed_bar_and_window_are_unsupported() {
        let Ok(topology) = topology() else {
            assert!(false, "test topology should build");
            return;
        };
        let mut bad_bar = bar(address(1, 0), 0x8000_2001);
        bad_bar.len = 0x1000;
        let bad_window = FirmwareResource {
            owner: address(1, 1),
            register: ResourceRegister::BridgeWindow(1),
            class: ResourceClass::Mmio32,
            assigned: true,
            pci_base: 0x8000_0000,
            len: 0x1000,
            fixed: false,
        };
        let Ok(report) =
            validate_firmware_resources(&topology, &[aperture()], &[window(), bad_bar, bad_window])
        else {
            assert!(false, "malformed resources should produce a report");
            return;
        };
        assert_eq!(
            report
                .find(address(1, 0), ResourceRegister::Bar(0))
                .map(|entry| entry.status),
            Some(ResourceStatus::Unsupported)
        );
        assert_eq!(
            report
                .find(address(1, 1), ResourceRegister::BridgeWindow(1))
                .map(|entry| entry.status),
            Some(ResourceStatus::Unsupported)
        );
    }
}
