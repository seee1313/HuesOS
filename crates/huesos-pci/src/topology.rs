//! Immutable, generation-tagged PCI topology snapshots.
//!
//! Hardware access is intentionally absent. The builder consumes already-read
//! function descriptors, validates root/bridge geometry, assigns deterministic
//! parents, and rejects ambiguous or cyclic shapes before driver binding sees
//! them.

use alloc::vec::Vec;

use crate::{ClassCode, PciAddress};

/// Maximum root bridges accepted in one snapshot.
pub const MAX_TOPOLOGY_ROOTS: usize = 16;
/// Maximum functions accepted in one snapshot.
pub const MAX_TOPOLOGY_FUNCTIONS: usize = 4096;
/// Maximum parent-bridge depth.
pub const MAX_TOPOLOGY_DEPTH: usize = 32;

/// One root bus range supplied by validated firmware policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootBus {
    /// Stable root identity for this boot.
    pub root_id: u64,
    /// PCI segment group.
    pub segment: u16,
    /// First bus routed by the root.
    pub start_bus: u8,
    /// Last bus routed by the root, inclusive.
    pub end_bus: u8,
}

/// Function role relevant to topology construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionKind {
    /// Endpoint or a header type not traversed as a PCI-to-PCI bridge.
    Endpoint,
    /// Type-1 PCI-to-PCI bridge bus range.
    PciBridge {
        /// Secondary bus directly below the bridge.
        secondary_bus: u8,
        /// Highest subordinate bus routed by the bridge.
        subordinate_bus: u8,
    },
}

/// Hardware-independent function descriptor gathered during read-only scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveredFunction {
    /// Current routing address.
    pub address: PciAddress,
    /// Vendor ID (`0xffff` is rejected as absent).
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// PCI class/subclass/programming-interface triple.
    pub class_code: ClassCode,
    /// Endpoint or bridge role.
    pub kind: FunctionKind,
}

/// Parent of a topology node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parent {
    /// Function is attached directly to a root bridge.
    Root(u64),
    /// Function is below another PCI-to-PCI bridge.
    Bridge(PciAddress),
}

/// One validated node in an immutable topology snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopologyNode {
    /// Original discovered function metadata.
    pub function: DiscoveredFunction,
    /// Deterministically resolved parent.
    pub parent: Parent,
    /// Zero for a root-bus function, one for its children, and so on.
    pub depth: u8,
}

/// Canonically ordered topology snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologySnapshot {
    generation: u64,
    roots: Vec<RootBus>,
    nodes: Vec<TopologyNode>,
}

impl TopologySnapshot {
    /// Snapshot generation supplied by the manager.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Roots ordered by segment/start bus/root ID.
    pub fn roots(&self) -> &[RootBus] {
        &self.roots
    }

    /// Functions ordered by [`PciAddress`].
    pub fn nodes(&self) -> &[TopologyNode] {
        &self.nodes
    }

    /// Find a node by current routing address.
    pub fn find(&self, address: PciAddress) -> Option<&TopologyNode> {
        self.nodes
            .binary_search_by_key(&address, |node| node.function.address)
            .ok()
            .and_then(|index| self.nodes.get(index))
    }
}

/// Topology validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyError {
    /// Generation zero is reserved for "no snapshot".
    InvalidGeneration,
    /// Root/function count exceeds the bounded profile.
    TooManyEntries,
    /// Bounded snapshot allocation failed.
    NoMemory,
    /// Root ID is zero or repeated.
    InvalidRootId,
    /// Root bus range is inverted.
    InvalidRootRange,
    /// Two roots claim an overlapping bus in one segment.
    RootOverlap,
    /// Function address occurs more than once.
    DuplicateAddress,
    /// Input contains an absent (`vendor_id == 0xffff`) function.
    AbsentFunction,
    /// No root contains a function.
    MissingRoot,
    /// Bridge bus range is inverted, non-forward, or outside its root.
    InvalidBridgeRange,
    /// Bridge ranges overlap without strict containment.
    CrossingBridgeRanges,
    /// Two bridges are equally valid parents for a function.
    AmbiguousParent,
    /// Parent bridge could not be resolved in the final node set.
    MissingParent,
    /// Parent chain exceeds [`MAX_TOPOLOGY_DEPTH`].
    DepthExceeded,
}

/// Build a deterministic immutable topology snapshot.
pub fn build_snapshot(
    generation: u64,
    roots: &[RootBus],
    functions: &[DiscoveredFunction],
) -> Result<TopologySnapshot, TopologyError> {
    if generation == 0 {
        return Err(TopologyError::InvalidGeneration);
    }
    if roots.len() > MAX_TOPOLOGY_ROOTS || functions.len() > MAX_TOPOLOGY_FUNCTIONS {
        return Err(TopologyError::TooManyEntries);
    }

    let mut sorted_roots = Vec::new();
    sorted_roots
        .try_reserve_exact(roots.len())
        .map_err(|_| TopologyError::NoMemory)?;
    sorted_roots.extend_from_slice(roots);
    sorted_roots.sort_by_key(|root| (root.segment, root.start_bus, root.end_bus, root.root_id));
    validate_roots(&sorted_roots)?;

    let mut sorted_functions = Vec::new();
    sorted_functions
        .try_reserve_exact(functions.len())
        .map_err(|_| TopologyError::NoMemory)?;
    sorted_functions.extend_from_slice(functions);
    sorted_functions.sort_by_key(|function| function.address);
    validate_functions(&sorted_roots, &sorted_functions)?;
    validate_bridge_intervals(&sorted_functions)?;

    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(sorted_functions.len())
        .map_err(|_| TopologyError::NoMemory)?;
    for function in &sorted_functions {
        let root = root_for(&sorted_roots, function.address).ok_or(TopologyError::MissingRoot)?;
        let parent = resolve_parent(root, function.address, &sorted_functions)?;
        nodes.push(TopologyNode {
            function: *function,
            parent,
            depth: 0,
        });
    }
    assign_depths(&mut nodes)?;

    Ok(TopologySnapshot {
        generation,
        roots: sorted_roots,
        nodes,
    })
}

fn validate_roots(roots: &[RootBus]) -> Result<(), TopologyError> {
    for (index, root) in roots.iter().enumerate() {
        if root.root_id == 0 {
            return Err(TopologyError::InvalidRootId);
        }
        if root.start_bus > root.end_bus {
            return Err(TopologyError::InvalidRootRange);
        }
        for previous in &roots[..index] {
            if previous.root_id == root.root_id {
                return Err(TopologyError::InvalidRootId);
            }
            if previous.segment == root.segment
                && previous.start_bus <= root.end_bus
                && root.start_bus <= previous.end_bus
            {
                return Err(TopologyError::RootOverlap);
            }
        }
    }
    Ok(())
}

fn validate_functions(
    roots: &[RootBus],
    functions: &[DiscoveredFunction],
) -> Result<(), TopologyError> {
    for (index, function) in functions.iter().enumerate() {
        if function.vendor_id == 0xffff {
            return Err(TopologyError::AbsentFunction);
        }
        if index != 0 && functions[index - 1].address == function.address {
            return Err(TopologyError::DuplicateAddress);
        }
        let root = root_for(roots, function.address).ok_or(TopologyError::MissingRoot)?;
        if let FunctionKind::PciBridge {
            secondary_bus,
            subordinate_bus,
        } = function.kind
        {
            if secondary_bus <= function.address.bus()
                || secondary_bus > subordinate_bus
                || secondary_bus < root.start_bus
                || subordinate_bus > root.end_bus
            {
                return Err(TopologyError::InvalidBridgeRange);
            }
        }
    }
    Ok(())
}

fn validate_bridge_intervals(functions: &[DiscoveredFunction]) -> Result<(), TopologyError> {
    for (index, left) in functions.iter().enumerate() {
        let Some((left_start, left_end)) = bridge_range(*left) else {
            continue;
        };
        for right in &functions[index + 1..] {
            if left.address.segment() != right.address.segment() {
                continue;
            }
            let Some((right_start, right_end)) = bridge_range(*right) else {
                continue;
            };
            let overlaps = left_start <= right_end && right_start <= left_end;
            let left_contains = left_start <= right_start && left_end >= right_end;
            let right_contains = right_start <= left_start && right_end >= left_end;
            if overlaps && !(left_contains || right_contains) {
                return Err(TopologyError::CrossingBridgeRanges);
            }
            if left_start == right_start && left_end == right_end {
                return Err(TopologyError::AmbiguousParent);
            }
        }
    }
    Ok(())
}

fn root_for(roots: &[RootBus], address: PciAddress) -> Option<RootBus> {
    roots.iter().copied().find(|root| {
        root.segment == address.segment()
            && address.bus() >= root.start_bus
            && address.bus() <= root.end_bus
    })
}

fn resolve_parent(
    root: RootBus,
    address: PciAddress,
    functions: &[DiscoveredFunction],
) -> Result<Parent, TopologyError> {
    if address.bus() == root.start_bus {
        return Ok(Parent::Root(root.root_id));
    }

    let mut selected: Option<(PciAddress, u8, u8)> = None;
    for function in functions {
        if function.address.segment() != address.segment()
            || function.address.bus() >= address.bus()
        {
            continue;
        }
        let Some((secondary, subordinate)) = bridge_range(*function) else {
            continue;
        };
        if address.bus() < secondary || address.bus() > subordinate {
            continue;
        }
        match selected {
            None => selected = Some((function.address, secondary, subordinate)),
            Some((_, selected_secondary, selected_subordinate)) => {
                let candidate_is_deeper = secondary > selected_secondary
                    || (secondary == selected_secondary && subordinate < selected_subordinate);
                if candidate_is_deeper {
                    selected = Some((function.address, secondary, subordinate));
                } else if secondary == selected_secondary && subordinate == selected_subordinate {
                    return Err(TopologyError::AmbiguousParent);
                }
            }
        }
    }
    selected
        .map(|(parent, _, _)| Parent::Bridge(parent))
        .ok_or(TopologyError::MissingParent)
}

fn assign_depths(nodes: &mut [TopologyNode]) -> Result<(), TopologyError> {
    for index in 0..nodes.len() {
        let mut depth = 0usize;
        let mut parent = nodes[index].parent;
        while let Parent::Bridge(address) = parent {
            depth += 1;
            if depth > MAX_TOPOLOGY_DEPTH {
                return Err(TopologyError::DepthExceeded);
            }
            let parent_index = nodes
                .binary_search_by_key(&address, |node| node.function.address)
                .map_err(|_| TopologyError::MissingParent)?;
            parent = nodes[parent_index].parent;
        }
        nodes[index].depth = depth as u8;
    }
    Ok(())
}

fn bridge_range(function: DiscoveredFunction) -> Option<(u8, u8)> {
    match function.kind {
        FunctionKind::Endpoint => None,
        FunctionKind::PciBridge {
            secondary_bus,
            subordinate_bus,
        } => Some((secondary_bus, subordinate_bus)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(segment: u16, bus: u8, device: u8) -> PciAddress {
        match PciAddress::try_new(segment, bus, device, 0) {
            Ok(address) => address,
            Err(_) => {
                assert!(false, "test PCI address should be valid");
                PciAddress::ZERO
            }
        }
    }

    fn endpoint(segment: u16, bus: u8, device: u8) -> DiscoveredFunction {
        DiscoveredFunction {
            address: address(segment, bus, device),
            vendor_id: 0x1234,
            device_id: u16::from(device),
            class_code: ClassCode {
                class: 0x02,
                subclass: 0,
                prog_if: 0,
            },
            kind: FunctionKind::Endpoint,
        }
    }

    fn bridge(
        segment: u16,
        bus: u8,
        device: u8,
        secondary: u8,
        subordinate: u8,
    ) -> DiscoveredFunction {
        DiscoveredFunction {
            address: address(segment, bus, device),
            vendor_id: 0x8086,
            device_id: u16::from(device),
            class_code: ClassCode {
                class: 0x06,
                subclass: 0x04,
                prog_if: 0,
            },
            kind: FunctionKind::PciBridge {
                secondary_bus: secondary,
                subordinate_bus: subordinate,
            },
        }
    }

    #[test]
    fn builds_nested_multisegment_topology_deterministically() {
        let roots = [
            RootBus {
                root_id: 2,
                segment: 7,
                start_bus: 64,
                end_bus: 79,
            },
            RootBus {
                root_id: 1,
                segment: 0,
                start_bus: 0,
                end_bus: 31,
            },
        ];
        let functions = [
            endpoint(7, 64, 1),
            endpoint(0, 3, 0),
            bridge(0, 0, 1, 1, 7),
            bridge(0, 1, 2, 3, 4),
            endpoint(0, 1, 0),
        ];
        let Ok(snapshot) = build_snapshot(9, &roots, &functions) else {
            assert!(false, "valid topology should build");
            return;
        };
        assert_eq!(snapshot.generation(), 9);
        assert_eq!(snapshot.roots()[0].root_id, 1);
        let Some(root_bridge) = snapshot.find(address(0, 0, 1)) else {
            assert!(false, "root bridge should exist");
            return;
        };
        assert_eq!(root_bridge.parent, Parent::Root(1));
        assert_eq!(root_bridge.depth, 0);
        let Some(nested_bridge) = snapshot.find(address(0, 1, 2)) else {
            assert!(false, "nested bridge should exist");
            return;
        };
        assert_eq!(nested_bridge.parent, Parent::Bridge(address(0, 0, 1)));
        assert_eq!(nested_bridge.depth, 1);
        let Some(deep_endpoint) = snapshot.find(address(0, 3, 0)) else {
            assert!(false, "deep endpoint should exist");
            return;
        };
        assert_eq!(deep_endpoint.parent, Parent::Bridge(address(0, 1, 2)));
        assert_eq!(deep_endpoint.depth, 2);
    }

    #[test]
    fn input_order_does_not_change_snapshot() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 7,
        }];
        let forward = [bridge(0, 0, 1, 1, 7), endpoint(0, 1, 0)];
        let reverse = [endpoint(0, 1, 0), bridge(0, 0, 1, 1, 7)];
        assert_eq!(
            build_snapshot(1, &roots, &forward),
            build_snapshot(1, &roots, &reverse)
        );
    }

    #[test]
    fn rejects_duplicate_addresses_and_absent_functions() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        }];
        let duplicate = [endpoint(0, 0, 1), endpoint(0, 0, 1)];
        assert_eq!(
            build_snapshot(1, &roots, &duplicate),
            Err(TopologyError::DuplicateAddress)
        );
        let mut absent = endpoint(0, 0, 1);
        absent.vendor_id = 0xffff;
        assert_eq!(
            build_snapshot(1, &roots, &[absent]),
            Err(TopologyError::AbsentFunction)
        );
    }

    #[test]
    fn rejects_root_overlap_and_missing_root() {
        let overlapping = [
            RootBus {
                root_id: 1,
                segment: 0,
                start_bus: 0,
                end_bus: 10,
            },
            RootBus {
                root_id: 2,
                segment: 0,
                start_bus: 10,
                end_bus: 20,
            },
        ];
        assert_eq!(
            build_snapshot(1, &overlapping, &[]),
            Err(TopologyError::RootOverlap)
        );
        let root = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 1,
        }];
        assert_eq!(
            build_snapshot(1, &root, &[endpoint(7, 0, 0)]),
            Err(TopologyError::MissingRoot)
        );
    }

    #[test]
    fn rejects_invalid_and_crossing_bridge_ranges() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 31,
        }];
        assert_eq!(
            build_snapshot(1, &roots, &[bridge(0, 2, 0, 2, 4)]),
            Err(TopologyError::InvalidBridgeRange)
        );
        let crossing = [bridge(0, 0, 1, 1, 10), bridge(0, 0, 2, 8, 15)];
        assert_eq!(
            build_snapshot(1, &roots, &crossing),
            Err(TopologyError::CrossingBridgeRanges)
        );
    }

    #[test]
    fn rejects_equal_bridge_ranges_as_ambiguous() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 15,
        }];
        let bridges = [bridge(0, 0, 1, 1, 15), bridge(0, 0, 2, 1, 15)];
        assert_eq!(
            build_snapshot(1, &roots, &bridges),
            Err(TopologyError::AmbiguousParent)
        );
    }

    #[test]
    fn rejects_generation_zero_and_profile_capacity() {
        assert_eq!(
            build_snapshot(0, &[], &[]),
            Err(TopologyError::InvalidGeneration)
        );
        let root = RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        };
        let roots = [root; MAX_TOPOLOGY_ROOTS + 1];
        assert_eq!(
            build_snapshot(1, &roots, &[]),
            Err(TopologyError::TooManyEntries)
        );
    }

    #[test]
    fn rejects_parent_chain_beyond_depth_budget() {
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 63,
        }];
        let mut functions = Vec::new();
        assert!(functions.try_reserve_exact(MAX_TOPOLOGY_DEPTH + 2).is_ok());
        for depth in 0..=MAX_TOPOLOGY_DEPTH {
            functions.push(bridge(
                0,
                depth as u8,
                0,
                (depth + 1) as u8,
                (MAX_TOPOLOGY_DEPTH + 1) as u8,
            ));
        }
        functions.push(endpoint(0, (MAX_TOPOLOGY_DEPTH + 1) as u8, 0));
        assert_eq!(
            build_snapshot(1, &roots, &functions),
            Err(TopologyError::DepthExceeded)
        );
    }
}
