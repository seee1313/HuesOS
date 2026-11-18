//! Diagnostic read-only PCI bus enumeration, topology assembly, and
//! firmware-resource availability attachment (AP-16).
//!
//! Every hardware access in this module goes through [`ConfigReader`], which
//! exposes **only** aligned 32-bit reads (`offset < 256`, common subset). Config
//! writes, BAR sizing mutations (`0xFFFF_FFFF` probes), bus-master enables, IRQ
//! programming, and DMA configuration are structurally absent.

use alloc::vec::Vec;

use crate::resource_validation::{
    validate_firmware_resources, FirmwareResource, ResourceClass, ResourceRegister, RootAperture,
    ValidationReport, MAX_VALIDATION_RESOURCES,
};
use crate::topology::{
    build_snapshot, DiscoveredFunction, FunctionKind, RootBus, TopologyError, TopologySnapshot,
    MAX_TOPOLOGY_FUNCTIONS,
};
use crate::{ClassCode, PciAddress, CONVENTIONAL_CONFIG_BYTES};

/// Read-only configuration-space transport for diagnostic inventory.
pub trait ConfigReader {
    /// Read one aligned 32-bit dword from conventional configuration space
    /// (`offset < 256` and `offset & 3 == 0`). Returns `None` on transport
    /// failure or unmapped window.
    fn read_u32(
        &mut self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
    ) -> Option<u32>;
}

/// Firmware-resource availability attached to one diagnostic snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareResourceAvailability {
    /// Complete validated roots and conflict-free firmware resource decoding
    /// are attached.
    Available,
    /// Roots were absent/incomplete, had no apertures, or firmware resources
    /// could not be validated cleanly (`FirmwareResourcesUnavailable`).
    Unavailable,
}

impl FirmwareResourceAvailability {
    /// Stable diagnostic string used in serial logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "FirmwareResourcesAvailable",
            Self::Unavailable => "FirmwareResourcesUnavailable",
        }
    }
}

/// Immutable diagnostic read-only PCI inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticInventory {
    /// Monotonic inventory generation.
    pub generation: u64,
    /// Immutable bridge-aware topology snapshot.
    pub snapshot: TopologySnapshot,
    /// Whether validated firmware resources are available for this snapshot.
    pub availability: FirmwareResourceAvailability,
    /// Resource validation report when complete roots and apertures existed.
    pub validation: Option<ValidationReport>,
    /// Number of configuration-space writes issued (always zero).
    pub config_writes: u64,
}

/// Failure while constructing or publishing a diagnostic inventory snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryError {
    /// Inventory generation was frozen after an ACPI failure/crash.
    Frozen,
    /// No roots were provided to scan.
    EmptyRoots,
    /// Bounded function/resource capacity was exceeded.
    CapacityExceeded,
    /// Bounded heap allocation failed.
    NoMemory,
    /// Topology construction rejected the discovered graph.
    Topology(TopologyError),
}

/// Stateful diagnostic inventory tracker supporting crash-freeze retention.
#[derive(Clone, Debug)]
pub struct InventoryManager {
    last_good: Option<DiagnosticInventory>,
    frozen: bool,
    next_generation: u64,
}

impl Default for InventoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InventoryManager {
    /// Create an empty, unfrozen inventory manager.
    pub const fn new() -> Self {
        Self {
            last_good: None,
            frozen: false,
            next_generation: 1,
        }
    }

    /// Freeze new inventory generations while preserving the last-good snapshot.
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Whether new inventory generations are frozen.
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Return the preserved last-good diagnostic snapshot, if any.
    pub fn last_good(&self) -> Option<&DiagnosticInventory> {
        self.last_good.as_ref()
    }

    /// Scan validated `roots` read-only and publish a new diagnostic snapshot
    /// unless inventory generations are frozen.
    pub fn publish_from_roots<R: ConfigReader>(
        &mut self,
        reader: &mut R,
        roots: &[RootBus],
        apertures: &[RootAperture],
    ) -> Result<&DiagnosticInventory, InventoryError> {
        if self.frozen {
            return Err(InventoryError::Frozen);
        }
        let gen = self.next_generation;
        let inv = scan_roots(reader, gen, roots, apertures)?;
        self.next_generation = gen.saturating_add(1).max(1);
        self.last_good = Some(inv);
        match self.last_good.as_ref() {
            Some(stored) => Ok(stored),
            None => Err(InventoryError::NoMemory),
        }
    }

    /// Scan `fallback_roots` read-only when complete ACPI roots are absent,
    /// exposing visible devices strictly as `FirmwareResourcesUnavailable`.
    pub fn publish_unavailable<R: ConfigReader>(
        &mut self,
        reader: &mut R,
        fallback_roots: &[RootBus],
    ) -> Result<&DiagnosticInventory, InventoryError> {
        self.publish_from_roots(reader, fallback_roots, &[])
    }
}

/// Perform a strictly read-only scan across `roots`, assemble a
/// [`TopologySnapshot`], and attach [`FirmwareResourceAvailability`].
pub fn scan_roots<R: ConfigReader>(
    reader: &mut R,
    generation: u64,
    roots: &[RootBus],
    apertures: &[RootAperture],
) -> Result<DiagnosticInventory, InventoryError> {
    if roots.is_empty() {
        return Err(InventoryError::EmptyRoots);
    }

    let mut functions = Vec::new();
    let mut resources = Vec::new();

    for root in roots {
        if root.start_bus > root.end_bus {
            return Err(InventoryError::Topology(TopologyError::InvalidRootRange));
        }
        for bus in root.start_bus..=root.end_bus {
            for device in 0u8..32 {
                let Some(id0) = reader.read_u32(root.segment, bus, device, 0, 0x00) else {
                    continue;
                };
                if (id0 & 0xffff) == 0xffff {
                    continue;
                }
                let Some(bist_hdr0) = reader.read_u32(root.segment, bus, device, 0, 0x0c) else {
                    continue;
                };
                let multi_fn = ((bist_hdr0 >> 16) & 0x80) != 0;
                let max_fn = if multi_fn { 8u8 } else { 1u8 };

                for function in 0u8..max_fn {
                    let id = if function == 0 {
                        id0
                    } else {
                        let Some(val) = reader.read_u32(root.segment, bus, device, function, 0x00)
                        else {
                            continue;
                        };
                        if (val & 0xffff) == 0xffff {
                            continue;
                        }
                        val
                    };
                    let bist_hdr = if function == 0 {
                        bist_hdr0
                    } else {
                        let Some(val) = reader.read_u32(root.segment, bus, device, function, 0x0c)
                        else {
                            continue;
                        };
                        val
                    };
                    let Some(class_rev) =
                        reader.read_u32(root.segment, bus, device, function, 0x08)
                    else {
                        continue;
                    };
                    let Some(cmd_sts) = reader.read_u32(root.segment, bus, device, function, 0x04)
                    else {
                        continue;
                    };
                    let Ok(address) = PciAddress::try_new(root.segment, bus, device, function)
                    else {
                        continue;
                    };

                    let vendor_id = (id & 0xffff) as u16;
                    let device_id = ((id >> 16) & 0xffff) as u16;
                    let class_code = ClassCode {
                        class: ((class_rev >> 24) & 0xff) as u8,
                        subclass: ((class_rev >> 16) & 0xff) as u8,
                        prog_if: ((class_rev >> 8) & 0xff) as u8,
                    };
                    let header_layout = ((bist_hdr >> 16) & 0x7f) as u8;
                    let command = (cmd_sts & 0xffff) as u16;

                    let kind = if header_layout == 1 {
                        let Some(bus_nums) =
                            reader.read_u32(root.segment, bus, device, function, 0x18)
                        else {
                            continue;
                        };
                        let secondary = ((bus_nums >> 8) & 0xff) as u8;
                        let subordinate = ((bus_nums >> 16) & 0xff) as u8;
                        if secondary > bus
                            && secondary <= subordinate
                            && subordinate <= root.end_bus
                        {
                            FunctionKind::PciBridge {
                                secondary_bus: secondary,
                                subordinate_bus: subordinate,
                            }
                        } else {
                            FunctionKind::Endpoint
                        }
                    } else {
                        FunctionKind::Endpoint
                    };

                    if functions.len() >= MAX_TOPOLOGY_FUNCTIONS {
                        return Err(InventoryError::CapacityExceeded);
                    }
                    functions
                        .try_reserve(1)
                        .map_err(|_| InventoryError::NoMemory)?;
                    functions.push(DiscoveredFunction {
                        address,
                        vendor_id,
                        device_id,
                        class_code,
                        kind,
                    });

                    collect_function_resources(
                        reader,
                        address,
                        header_layout,
                        command,
                        &mut resources,
                    )?;
                }
            }
        }
    }

    let snapshot =
        build_snapshot(generation, roots, &functions).map_err(InventoryError::Topology)?;
    if apertures.is_empty() {
        return Ok(DiagnosticInventory {
            generation,
            snapshot,
            availability: FirmwareResourceAvailability::Unavailable,
            validation: None,
            config_writes: 0,
        });
    }

    match validate_firmware_resources(&snapshot, apertures, &resources) {
        Ok(report) => Ok(DiagnosticInventory {
            generation,
            snapshot,
            availability: FirmwareResourceAvailability::Available,
            validation: Some(report),
            config_writes: 0,
        }),
        Err(_) => Ok(DiagnosticInventory {
            generation,
            snapshot,
            availability: FirmwareResourceAvailability::Unavailable,
            validation: None,
            config_writes: 0,
        }),
    }
}

fn collect_function_resources<R: ConfigReader>(
    reader: &mut R,
    owner: PciAddress,
    header_layout: u8,
    command: u16,
    out: &mut Vec<FirmwareResource>,
) -> Result<(), InventoryError> {
    let bar_count: u8 = match header_layout {
        0 => 6,
        1 => 2,
        _ => return Ok(()),
    };

    let mut bar_idx = 0u8;
    while bar_idx < bar_count {
        let offset = 0x10u16 + u16::from(bar_idx) * 4;
        if offset >= CONVENTIONAL_CONFIG_BYTES {
            break;
        }
        let Some(raw) = reader.read_u32(
            owner.segment(),
            owner.bus(),
            owner.device(),
            owner.function(),
            offset,
        ) else {
            break;
        };

        if (raw & 1) == 1 {
            let base = u64::from(raw & !0x3);
            if base != 0 {
                push_resource(
                    out,
                    FirmwareResource {
                        owner,
                        register: ResourceRegister::Bar(bar_idx),
                        class: ResourceClass::Io,
                        assigned: true,
                        pci_base: base,
                        len: 4,
                        fixed: false,
                    },
                )?;
            }
            bar_idx += 1;
        } else {
            let mem_type = (raw >> 1) & 0x3;
            let prefetch = (raw & 0x8) != 0;
            if mem_type == 0x2 && bar_idx + 1 < bar_count {
                let Some(hi) = reader.read_u32(
                    owner.segment(),
                    owner.bus(),
                    owner.device(),
                    owner.function(),
                    offset + 4,
                ) else {
                    break;
                };
                let base = (u64::from(hi) << 32) | u64::from(raw & !0xf);
                let class = if prefetch {
                    ResourceClass::PrefetchableMemory
                } else if base < 0x1_0000_0000 {
                    ResourceClass::Mmio32
                } else {
                    ResourceClass::Mmio64
                };
                if base != 0 {
                    push_resource(
                        out,
                        FirmwareResource {
                            owner,
                            register: ResourceRegister::Bar(bar_idx),
                            class,
                            assigned: true,
                            pci_base: base,
                            len: 4096,
                            fixed: false,
                        },
                    )?;
                }
                bar_idx += 2;
            } else {
                let base = u64::from(raw & !0xf);
                let class = if prefetch {
                    ResourceClass::PrefetchableMemory
                } else {
                    ResourceClass::Mmio32
                };
                if base != 0 {
                    push_resource(
                        out,
                        FirmwareResource {
                            owner,
                            register: ResourceRegister::Bar(bar_idx),
                            class,
                            assigned: true,
                            pci_base: base,
                            len: 4096,
                            fixed: false,
                        },
                    )?;
                }
                bar_idx += 1;
            }
        }
    }

    if header_layout == 1 {
        let io_enabled = (command & 0x1) != 0;
        let mem_enabled = (command & 0x2) != 0;
        if io_enabled {
            if let Some(io_reg) = reader.read_u32(
                owner.segment(),
                owner.bus(),
                owner.device(),
                owner.function(),
                0x1c,
            ) {
                let io_base_lo = (io_reg & 0xff) as u8;
                let io_limit_lo = ((io_reg >> 8) & 0xff) as u8;
                let (base_hi, limit_hi) = if (io_base_lo & 0x0f) == 1 {
                    if let Some(upper) = reader.read_u32(
                        owner.segment(),
                        owner.bus(),
                        owner.device(),
                        owner.function(),
                        0x30,
                    ) {
                        (u64::from(upper & 0xffff), u64::from(upper >> 16))
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };
                let io_base = (base_hi << 16) | (u64::from(io_base_lo & 0xf0) << 8);
                let io_limit = (limit_hi << 16) | (u64::from(io_limit_lo & 0xf0) << 8) | 0x0fff;
                if io_base <= io_limit && (io_base != 0 || io_limit != 0x0fff) {
                    push_resource(
                        out,
                        FirmwareResource {
                            owner,
                            register: ResourceRegister::BridgeWindow(0),
                            class: ResourceClass::Io,
                            assigned: true,
                            pci_base: io_base,
                            len: io_limit - io_base + 1,
                            fixed: false,
                        },
                    )?;
                }
            }
        }
        if mem_enabled {
            if let Some(mem_reg) = reader.read_u32(
                owner.segment(),
                owner.bus(),
                owner.device(),
                owner.function(),
                0x20,
            ) {
                let mem_base = u64::from(mem_reg & 0xfff0) << 16;
                let mem_limit = (u64::from((mem_reg >> 16) & 0xfff0) << 16) | 0xf_ffff;
                if mem_base <= mem_limit && mem_base != 0 {
                    push_resource(
                        out,
                        FirmwareResource {
                            owner,
                            register: ResourceRegister::BridgeWindow(1),
                            class: ResourceClass::Mmio32,
                            assigned: true,
                            pci_base: mem_base,
                            len: mem_limit - mem_base + 1,
                            fixed: false,
                        },
                    )?;
                }
            }
            if let Some(pref_reg) = reader.read_u32(
                owner.segment(),
                owner.bus(),
                owner.device(),
                owner.function(),
                0x24,
            ) {
                let is_64 = (pref_reg & 0x0f) == 1;
                let (base_hi, limit_hi) = if is_64 {
                    let b_hi = reader
                        .read_u32(
                            owner.segment(),
                            owner.bus(),
                            owner.device(),
                            owner.function(),
                            0x28,
                        )
                        .unwrap_or(0);
                    let l_hi = reader
                        .read_u32(
                            owner.segment(),
                            owner.bus(),
                            owner.device(),
                            owner.function(),
                            0x2c,
                        )
                        .unwrap_or(0);
                    (u64::from(b_hi), u64::from(l_hi))
                } else {
                    (0, 0)
                };
                let pref_base = (base_hi << 32) | (u64::from(pref_reg & 0xfff0) << 16);
                let pref_limit =
                    (limit_hi << 32) | (u64::from((pref_reg >> 16) & 0xfff0) << 16) | 0xf_ffff;
                if pref_base <= pref_limit && pref_base != 0 {
                    push_resource(
                        out,
                        FirmwareResource {
                            owner,
                            register: ResourceRegister::BridgeWindow(2),
                            class: ResourceClass::PrefetchableMemory,
                            assigned: true,
                            pci_base: pref_base,
                            len: pref_limit - pref_base + 1,
                            fixed: false,
                        },
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn push_resource(
    out: &mut Vec<FirmwareResource>,
    resource: FirmwareResource,
) -> Result<(), InventoryError> {
    if out.len() >= MAX_VALIDATION_RESOURCES {
        return Err(InventoryError::CapacityExceeded);
    }
    out.try_reserve(1).map_err(|_| InventoryError::NoMemory)?;
    out.push(resource);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_validation::ResourceStatus;
    use crate::topology::Parent;

    struct MockConfigSpace {
        spaces: Vec<(u16, u8, u8, u8, [u8; 4096])>,
        legacy_mode: bool,
        reads: u64,
    }

    impl MockConfigSpace {
        fn new(legacy_mode: bool) -> Self {
            Self {
                spaces: Vec::new(),
                legacy_mode,
                reads: 0,
            }
        }

        fn insert_device(&mut self, seg: u16, bus: u8, dev: u8, fn_num: u8, bytes: [u8; 4096]) {
            self.spaces.push((seg, bus, dev, fn_num, bytes));
        }

        fn write_u32_fixture(buf: &mut [u8; 4096], off: usize, val: u32) {
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    impl ConfigReader for MockConfigSpace {
        fn read_u32(
            &mut self,
            segment: u16,
            bus: u8,
            device: u8,
            function: u8,
            offset: u16,
        ) -> Option<u32> {
            self.reads += 1;
            if self.legacy_mode && (segment != 0 || offset >= 256) {
                return None;
            }
            if offset & 3 != 0 || offset as usize + 4 > 4096 {
                return None;
            }
            let space = self.spaces.iter().find(|(s, b, d, f, _)| {
                *s == segment && *b == bus && *d == device && *f == function
            })?;
            let off = offset as usize;
            Some(u32::from_le_bytes([
                space.4[off],
                space.4[off + 1],
                space.4[off + 2],
                space.4[off + 3],
            ]))
        }
    }

    fn make_endpoint_space(
        vendor: u16,
        device: u16,
        class: u32,
        multi_fn: bool,
        bar0: u32,
    ) -> [u8; 4096] {
        let mut buf = [0xffu8; 4096];
        buf[0x04..0x40].fill(0);
        MockConfigSpace::write_u32_fixture(
            &mut buf,
            0x00,
            u32::from(vendor) | (u32::from(device) << 16),
        );
        MockConfigSpace::write_u32_fixture(&mut buf, 0x04, 0x0000_0006);
        MockConfigSpace::write_u32_fixture(&mut buf, 0x08, class << 8);
        let hdr = if multi_fn { 0x0080_0000 } else { 0x0000_0000 };
        MockConfigSpace::write_u32_fixture(&mut buf, 0x0c, hdr);
        MockConfigSpace::write_u32_fixture(&mut buf, 0x10, bar0);
        buf
    }

    fn make_bridge_space(
        vendor: u16,
        device: u16,
        primary: u8,
        secondary: u8,
        subordinate: u8,
        mem_base: u32,
        mem_limit: u32,
    ) -> [u8; 4096] {
        let mut buf = [0xffu8; 4096];
        buf[0x04..0x40].fill(0);
        MockConfigSpace::write_u32_fixture(
            &mut buf,
            0x00,
            u32::from(vendor) | (u32::from(device) << 16),
        );
        MockConfigSpace::write_u32_fixture(&mut buf, 0x04, 0x0000_0007);
        MockConfigSpace::write_u32_fixture(&mut buf, 0x08, 0x0604_0000);
        MockConfigSpace::write_u32_fixture(&mut buf, 0x0c, 0x0001_0000);
        MockConfigSpace::write_u32_fixture(
            &mut buf,
            0x18,
            u32::from(primary) | (u32::from(secondary) << 8) | (u32::from(subordinate) << 16),
        );
        let mb = (mem_base >> 16) & 0xfff0;
        let ml = (mem_limit >> 16) & 0xfff0;
        MockConfigSpace::write_u32_fixture(&mut buf, 0x20, mb | (ml << 16));
        buf
    }

    #[test]
    fn ecam_and_legacy_common_subset_and_nested_bridges_match() {
        let mut ecam = MockConfigSpace::new(false);
        let mut legacy = MockConfigSpace::new(true);

        // Multifunction device at 00:02.0 and 00:02.1
        let fn0 = make_endpoint_space(0x8086, 0x100e, 0x0200_00, true, 0x8000_0000);
        let fn1 = make_endpoint_space(0x8086, 0x100f, 0x0200_00, true, 0x8001_0000);
        // Nested Type-1 bridges: 00:01.0 -> bus 1..=2, 01:00.0 -> bus 2..=2, 02:00.0 endpoint
        let br0 = make_bridge_space(0x1b36, 0x000c, 0, 1, 2, 0x8100_0000, 0x81ff_ffff);
        let br1 = make_bridge_space(0x1b36, 0x000c, 1, 2, 2, 0x8110_0000, 0x811f_ffff);
        let ep2 = make_endpoint_space(0x144d, 0xa808, 0x0108_02, false, 0x8110_0000);

        for (b, d, f, bytes) in [
            (0, 2, 0, fn0),
            (0, 2, 1, fn1),
            (0, 1, 0, br0),
            (1, 0, 0, br1),
            (2, 0, 0, ep2),
        ] {
            ecam.insert_device(0, b, d, f, bytes);
            legacy.insert_device(0, b, d, f, bytes);
        }

        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 2,
        }];
        let apertures = [RootAperture {
            root_id: 1,
            class: ResourceClass::Mmio32,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x1000_0000,
        }];

        let mut mgr_ecam = InventoryManager::new();
        let mut mgr_legacy = InventoryManager::new();
        let inv_ecam = mgr_ecam
            .publish_from_roots(&mut ecam, &roots, &apertures)
            .is_ok();
        let inv_legacy = mgr_legacy
            .publish_from_roots(&mut legacy, &roots, &apertures)
            .is_ok();
        assert!(inv_ecam);
        assert!(inv_legacy);
        let (Some(a), Some(b)) = (mgr_ecam.last_good(), mgr_legacy.last_good()) else {
            return;
        };
        assert_eq!(a.snapshot, b.snapshot);
        assert_eq!(a.availability, FirmwareResourceAvailability::Available);
        assert_eq!(b.availability, FirmwareResourceAvailability::Available);
        assert_eq!(a.config_writes, 0);
        assert_eq!(b.config_writes, 0);
        assert_eq!(a.snapshot.nodes().len(), 5);

        let Ok(ep_addr) = PciAddress::try_new(0, 2, 0, 0) else {
            return;
        };
        let Ok(br1_addr) = PciAddress::try_new(0, 1, 0, 0) else {
            return;
        };
        if let Some(node) = a.snapshot.find(ep_addr) {
            assert_eq!(node.parent, Parent::Bridge(br1_addr));
            assert_eq!(node.depth, 2);
        }
        if let Some(report) = a.validation.as_ref() {
            let res = report.find(ep_addr, ResourceRegister::Bar(0));
            assert!(matches!(
                res.map(|entry| entry.status),
                Some(ResourceStatus::Valid)
            ));
        }
    }

    #[test]
    fn incomplete_roots_and_acpi_freeze_preserve_last_good() {
        let mut space = MockConfigSpace::new(false);
        space.insert_device(
            0,
            0,
            0,
            0,
            make_endpoint_space(0x8086, 0x29c0, 0x0600_00, false, 0),
        );
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        }];
        let mut mgr = InventoryManager::new();
        assert!(mgr.publish_unavailable(&mut space, &roots).is_ok());
        if let Some(first) = mgr.last_good() {
            assert_eq!(first.generation, 1);
            assert_eq!(
                first.availability,
                FirmwareResourceAvailability::Unavailable
            );
            assert_eq!(first.snapshot.nodes().len(), 1);
            assert_eq!(first.config_writes, 0);
        }

        mgr.freeze();
        assert!(mgr.is_frozen());
        assert_eq!(
            mgr.publish_from_roots(&mut space, &roots, &[]),
            Err(InventoryError::Frozen)
        );
        if let Some(preserved) = mgr.last_good() {
            assert_eq!(preserved.generation, 1);
        }
    }
}
