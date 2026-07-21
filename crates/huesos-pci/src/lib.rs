//! # huesos-pci — PCI configuration-space parsing and device discovery
//!
//! Foundation for userspace device drivers (the NVMe on-target plumbing needs
//! it to find the controller and read its BARs; ROADMAP Short-Term #7). This
//! crate parses a PCI configuration space, decodes Base Address Regions (BARs),
//! matches devices by class code, and provides a mock PCI bus so discovery is
//! host-tested. The actual config-space *access* (ECAM MMIO or port
//! `0xCF8`/`0xCFC`) is on-target and supplied by the kernel to a DriverHost.
//!
//! Pure `no_std` + `core`; budget-neutral (no unsafe/unwrap/expect/panic).

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;
use alloc::vec::Vec;

/// Standard PCI configuration-space register offsets.
#[allow(missing_docs)]
pub mod off {
    pub const VENDOR_ID: usize = 0x00;
    pub const DEVICE_ID: usize = 0x02;
    pub const COMMAND: usize = 0x04;
    pub const STATUS: usize = 0x06;
    pub const REVISION: usize = 0x08;
    pub const PROG_IF: usize = 0x09;
    pub const SUBCLASS: usize = 0x0A;
    pub const CLASS: usize = 0x0B;
    pub const HEADER_TYPE: usize = 0x0E;
    pub const BAR0: usize = 0x10;
}

/// Command register bits.
#[allow(missing_docs)]
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
}

/// A 256-byte conventional PCI configuration space.
#[derive(Clone, Copy)]
pub struct ConfigSpace(pub [u8; 256]);

impl ConfigSpace {
    /// An all-zero config space.
    pub const fn zeroed() -> Self {
        ConfigSpace([0; 256])
    }

    fn read_u16(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.0[off], self.0[off + 1]])
    }
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes([self.0[off], self.0[off + 1], self.0[off + 2], self.0[off + 3]])
    }
    fn write_u16(&mut self, off: usize, v: u16) {
        let b = v.to_le_bytes();
        self.0[off] = b[0];
        self.0[off + 1] = b[1];
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        let b = v.to_le_bytes();
        self.0[off] = b[0];
        self.0[off + 1] = b[1];
        self.0[off + 2] = b[2];
        self.0[off + 3] = b[3];
    }

    /// Vendor ID (`0xFFFF` = no device).
    pub fn vendor_id(&self) -> u16 {
        self.read_u16(off::VENDOR_ID)
    }
    /// Device ID.
    pub fn device_id(&self) -> u16 {
        self.read_u16(off::DEVICE_ID)
    }
    /// Command register.
    pub fn command(&self) -> u16 {
        self.read_u16(off::COMMAND)
    }
    /// Revision ID.
    pub fn revision(&self) -> u8 {
        self.0[off::REVISION]
    }
    /// Programming interface byte.
    pub fn prog_if(&self) -> u8 {
        self.0[off::PROG_IF]
    }
    /// Subclass code.
    pub fn subclass(&self) -> u8 {
        self.0[off::SUBCLASS]
    }
    /// Base class code.
    pub fn class(&self) -> u8 {
        self.0[off::CLASS]
    }
    /// Header type (0x00 = standard device).
    pub fn header_type(&self) -> u8 {
        self.0[off::HEADER_TYPE] & 0x7F
    }
    /// The class code triple.
    pub fn class_code(&self) -> ClassCode {
        ClassCode { class: self.class(), subclass: self.subclass(), prog_if: self.prog_if() }
    }
    /// Raw BAR register `n` (0..6).
    pub fn bar_raw(&self, n: usize) -> u32 {
        self.read_u32(off::BAR0 + n * 4)
    }
    /// True if a device is present (vendor ID is not all-ones).
    pub fn is_present(&self) -> bool {
        self.vendor_id() != 0xFFFF
    }

    // Builder helpers for tests / mock construction.
    /// Set vendor/device IDs.
    pub fn set_ids(&mut self, vendor: u16, device: u16) {
        self.write_u16(off::VENDOR_ID, vendor);
        self.write_u16(off::DEVICE_ID, device);
    }
    /// Set the class code triple.
    pub fn set_class(&mut self, class: u8, subclass: u8, prog_if: u8) {
        self.0[off::CLASS] = class;
        self.0[off::SUBCLASS] = subclass;
        self.0[off::PROG_IF] = prog_if;
    }
    /// Set a BAR register (raw value).
    pub fn set_bar_raw(&mut self, n: usize, v: u32) {
        self.write_u32(off::BAR0 + n * 4, v);
    }
    /// Set command-register bits.
    pub fn set_command(&mut self, bits: u16) {
        self.write_u16(off::COMMAND, self.command() | bits);
    }
}

/// A PCI class code (base class, subclass, programming interface).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassCode {
    /// Base class.
    pub class: u8,
    /// Subclass.
    pub subclass: u8,
    /// Programming interface.
    pub prog_if: u8,
}

impl ClassCode {
    /// NVM Express controller: Mass Storage (0x01) / NVM Controller (0x08) /
    /// NVM Express (0x02).
    pub const NVME: ClassCode = ClassCode { class: 0x01, subclass: 0x08, prog_if: 0x02 };

    /// True when this class code matches `other` exactly.
    pub fn matches(&self, other: ClassCode) -> bool {
        self.class == other.class && self.subclass == other.subclass && self.prog_if == other.prog_if
    }
}

/// A decoded Base Address Region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// Memory-mapped region.
    Memory {
        /// Physical base address.
        base: u64,
        /// Region size in bytes.
        size: u64,
        /// Prefetchable.
        prefetchable: bool,
        /// 64-bit (else 32-bit).
        is_64: bool,
    },
    /// I/O-port region.
    Io {
        /// I/O base address.
        base: u32,
        /// Region size in bytes.
        size: u32,
    },
    /// BAR not implemented (size 0 / unused).
    Unused,
}

/// Compute a memory BAR's size from its size mask (the value read back after
/// writing all-ones to the BAR).
pub fn memory_bar_size(mask: u32) -> u64 {
    (!(mask & 0xFFFF_FFF0)).wrapping_add(1) as u64
}

/// Compute an I/O BAR's size from its size mask.
pub fn io_bar_size(mask: u32) -> u32 {
    (!(mask & 0xFFFF_FFFC)).wrapping_add(1)
}

/// Decode a memory BAR from its raw register value(s) and decoded size.
pub fn decode_memory_bar(lo: u32, hi: u32, size: u64) -> Bar {
    let is_64 = ((lo >> 1) & 0x3) == 0b10;
    let prefetchable = (lo >> 3) & 1 == 1;
    let base32 = (lo & 0xFFFF_FFF0) as u64;
    let base = if is_64 { ((hi as u64) << 32) | base32 } else { base32 };
    Bar::Memory { base, size, prefetchable, is_64 }
}

/// Decode an I/O BAR from its raw register value and decoded size.
pub fn decode_io_bar(lo: u32, size: u32) -> Bar {
    Bar::Io { base: lo & 0xFFFF_FFFC, size }
}

/// A mock PCI device for host tests: a config space plus BAR size masks.
#[derive(Clone)]
pub struct MockPciDevice {
    /// Bus number.
    pub bus: u8,
    /// Device number.
    pub dev: u8,
    /// Function number.
    pub func: u8,
    /// Configuration space.
    pub config: ConfigSpace,
    /// BAR size masks (value read back after writing all-ones), used for sizing.
    pub bar_sizes: [u32; 6],
}

impl MockPciDevice {
    /// Decode BAR `n` from its raw register and the stored size mask.
    pub fn decode_bar(&self, n: usize) -> Bar {
        let lo = self.config.bar_raw(n);
        let mask = self.bar_sizes[n];
        if lo & 1 == 0 {
            let size = memory_bar_size(mask);
            if size == 0 {
                return Bar::Unused;
            }
            let is_64 = ((lo >> 1) & 0x3) == 0b10;
            let hi = if is_64 && n + 1 < 6 { self.config.bar_raw(n + 1) } else { 0 };
            decode_memory_bar(lo, hi, size)
        } else {
            let size = io_bar_size(mask);
            if size == 0 {
                return Bar::Unused;
            }
            decode_io_bar(lo, size)
        }
    }
}

/// A mock PCI bus: a set of devices with class-code discovery.
#[derive(Clone, Default)]
pub struct MockPciBus {
    /// The devices present on the bus.
    pub devices: Vec<MockPciDevice>,
}

impl MockPciBus {
    /// An empty bus.
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }
    /// Add a device to the bus.
    pub fn add(&mut self, dev: MockPciDevice) {
        self.devices.push(dev);
    }
    /// Find all present devices whose class code matches `class`.
    pub fn find_by_class(&self, class: ClassCode) -> Vec<&MockPciDevice> {
        self.devices
            .iter()
            .filter(|d| d.config.is_present() && d.config.class_code().matches(class))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nvme_device() -> MockPciDevice {
        let mut config = ConfigSpace::zeroed();
        config.set_ids(0x8086, 0x0A54); // Intel QEMU NVMe-ish
        config.set_class(0x01, 0x08, 0x02); // Mass Storage / NVM / NVM Express
        // BAR0: 64-bit memory, base 0xFE00_0000.
        config.set_bar_raw(0, 0xFE00_0000 | 0b0100); // memory, 64-bit (type 0b10 << 1)
        config.set_bar_raw(1, 0x0000_0000); // upper 32 bits
        let mut bar_sizes = [0u32; 6];
        // BAR0 size mask for a 16 KiB region: 0xFFFF_C000.
        bar_sizes[0] = 0xFFFF_C000;
        MockPciDevice { bus: 0, dev: 4, func: 0, config, bar_sizes }
    }

    #[test]
    fn config_space_accessors() {
        let dev = nvme_device();
        assert_eq!(dev.config.vendor_id(), 0x8086);
        assert_eq!(dev.config.device_id(), 0x0A54);
        assert!(dev.config.is_present());
        assert_eq!(dev.config.class_code(), ClassCode::NVME);
    }

    #[test]
    fn absent_device_vendor_is_all_ones() {
        let mut config = ConfigSpace::zeroed();
        config.set_ids(0xFFFF, 0xFFFF);
        assert!(!config.is_present());
    }

    #[test]
    fn memory_bar_size_computation() {
        // 4 KiB: mask 0xFFFF_F000 -> 0x1000.
        assert_eq!(memory_bar_size(0xFFFF_F000), 0x1000);
        // 16 KiB: mask 0xFFFF_C000 -> 0x4000.
        assert_eq!(memory_bar_size(0xFFFF_C000), 0x4000);
        // 1 MiB: mask 0xFFF0_0000 -> 0x10_0000.
        assert_eq!(memory_bar_size(0xFFF0_0000), 0x10_0000);
        // Unimplemented (mask 0) -> size 0 (wrapping).
        assert_eq!(memory_bar_size(0), 0);
    }

    #[test]
    fn io_bar_size_computation() {
        // 16 bytes: mask 0xFFFF_FFF0 -> 0x10.
        assert_eq!(io_bar_size(0xFFFF_FFF0), 0x10);
        assert_eq!(io_bar_size(0), 0);
    }

    #[test]
    fn decode_32bit_memory_bar() {
        // 32-bit memory BAR at 0xF000_0000, 64 KiB.
        let lo = 0xF000_0000u32; // memory, 32-bit (type bits 0)
        let bar = decode_memory_bar(lo, 0, 0x1_0000);
        assert_eq!(bar, Bar::Memory { base: 0xF000_0000, size: 0x1_0000, prefetchable: false, is_64: false });
    }

    #[test]
    fn decode_64bit_prefetchable_memory_bar() {
        // 64-bit prefetchable: type 0b10 (<<1 = 0b0100), prefetch bit 3 set.
        let lo = 0b0100u32 | 0b1000;
        let hi = 0x0000_0002u32; // base high = 0x2_0000_0000
        let bar = decode_memory_bar(lo, hi, 0x1000);
        assert_eq!(bar, Bar::Memory { base: 0x2_0000_0000, size: 0x1000, prefetchable: true, is_64: true });
    }

    #[test]
    fn decodes_an_io_bar() {
        let lo = 0x0000_C001u32; // I/O (bit 0 set), base 0xC000
        let bar = decode_io_bar(lo, 0x10);
        assert_eq!(bar, Bar::Io { base: 0xC000, size: 0x10 });
    }

    #[test]
    fn mock_device_decodes_its_bar() {
        let dev = nvme_device();
        let bar = dev.decode_bar(0);
        assert!(matches!(bar, Bar::Memory { .. }));
        if let Bar::Memory { base, size, is_64, .. } = bar {
            assert_eq!(base, 0xFE00_0000);
            assert_eq!(size, 0x4000); // 16 KiB from mask 0xFFFF_C000
            assert!(is_64);
        }
        // Unset BAR -> Unused.
        assert_eq!(dev.decode_bar(2), Bar::Unused);
    }

    #[test]
    fn bus_finds_nvme_by_class() {
        let mut bus = MockPciBus::new();
        // A non-NVMe device (e.g. a VGA controller).
        let mut vga = MockPciDevice {
            bus: 0, dev: 2, func: 0,
            config: ConfigSpace::zeroed(),
            bar_sizes: [0; 6],
        };
        vga.config.set_ids(0x1234, 0x1111);
        vga.config.set_class(0x03, 0x00, 0x00); // VGA
        bus.add(vga);
        bus.add(nvme_device());
        // An absent slot should not match.
        let mut absent = MockPciDevice { bus: 0, dev: 9, func: 0, config: ConfigSpace::zeroed(), bar_sizes: [0; 6] };
        absent.config.set_ids(0xFFFF, 0xFFFF);
        absent.config.set_class(0x01, 0x08, 0x02);
        bus.add(absent);

        let found = bus.find_by_class(ClassCode::NVME);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dev, 4);
        assert_eq!(found[0].config.device_id(), 0x0A54);
    }

    #[test]
    fn class_code_matching_is_exact() {
        let nvme = ClassCode::NVME;
        assert!(nvme.matches(ClassCode { class: 0x01, subclass: 0x08, prog_if: 0x02 }));
        assert!(!nvme.matches(ClassCode { class: 0x01, subclass: 0x08, prog_if: 0x01 }));
        assert!(!nvme.matches(ClassCode { class: 0x01, subclass: 0x06, prog_if: 0x02 }));
    }
}
