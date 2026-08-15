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

/// Bounded conventional and PCIe extended capability-list decoding.
pub mod capability;
/// ACPI MCFG allocation-table decoding and validation.
pub mod mcfg;
/// Deterministic firmware-preserving BAR/window allocation plans.
pub mod resource_planner;
/// Firmware BAR/bridge-window validation and bus-to-CPU translation.
pub mod resource_validation;
/// Immutable, generation-tagged PCI bridge topology snapshots.
pub mod topology;

/// Bytes in conventional PCI configuration space.
pub const CONVENTIONAL_CONFIG_BYTES: u16 = 256;
/// Bytes in PCI Express enhanced configuration space.
pub const ENHANCED_CONFIG_BYTES: u16 = 4096;

/// Error returned by checked PCI configuration-address operations.
///
/// Transport implementations may preserve a more detailed internal error, but
/// policy code uses these stable classes so malformed firmware, unsupported
/// access, device absence, and hardware failure are never conflated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Device number is outside the conventional `0..32` range.
    DeviceOutOfRange,
    /// Function number is outside the base-profile `0..8` range.
    FunctionOutOfRange,
    /// Bus range is inverted or otherwise malformed.
    InvalidBusRange,
    /// Addressed bus is not covered by the selected root/window.
    BusOutOfRange,
    /// Physical config-window base violates backend alignment.
    MisalignedBase,
    /// Access starts or ends outside the selected configuration space.
    OffsetOutOfRange,
    /// Offset is not naturally aligned for the access width.
    MisalignedAccess,
    /// The selected backend cannot represent this PCI segment.
    UnsupportedSegment,
    /// The selected backend cannot represent the requested operation.
    UnsupportedAccess,
    /// Checked address calculation overflowed.
    AddressOverflow,
    /// No function is present at the requested address.
    NotPresent,
    /// Firmware or a hardware-owned structure is malformed.
    MalformedFirmware,
    /// The physical configuration transport failed.
    Transport,
}

/// Current routing address of one PCI function.
///
/// This value is not a stable device identity: hotplug or bus-number
/// reallocation may move a device to another BDF. Long-lived authority uses a
/// separate DeviceId/lease generation as defined by
/// `docs/PCI_MANAGER_ARCHITECTURE.md`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PciAddress {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
}

impl PciAddress {
    /// Segment 0, bus 0, device 0, function 0.
    pub const ZERO: Self = Self {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };

    /// Construct a checked segment:bus:device.function address.
    pub const fn try_new(
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<Self, ConfigError> {
        if device >= 32 {
            return Err(ConfigError::DeviceOutOfRange);
        }
        if function >= 8 {
            return Err(ConfigError::FunctionOutOfRange);
        }
        Ok(Self {
            segment,
            bus,
            device,
            function,
        })
    }

    /// PCI segment group.
    pub const fn segment(self) -> u16 {
        self.segment
    }

    /// Bus number.
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// Device number (`0..31`).
    pub const fn device(self) -> u8 {
        self.device
    }

    /// Function number (`0..7` in the base profile).
    pub const fn function(self) -> u8 {
        self.function
    }
}

/// Width of one PCI configuration-space access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConfigWidth {
    /// One byte.
    Byte = 1,
    /// Two bytes.
    Word = 2,
    /// Four bytes.
    Dword = 4,
}

impl ConfigWidth {
    /// Width in bytes.
    pub const fn bytes(self) -> u16 {
        self as u16
    }

    /// Bit mask covering one value of this width.
    pub const fn value_mask(self) -> u32 {
        match self {
            Self::Byte => 0xff,
            Self::Word => 0xffff,
            Self::Dword => u32::MAX,
        }
    }
}

/// Addressable configuration-space profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigSpaceKind {
    /// Conventional PCI configuration space (`0..256`).
    Conventional,
    /// PCI Express enhanced configuration space (`0..4096`).
    Enhanced,
}

impl ConfigSpaceKind {
    /// Addressable byte length.
    pub const fn bytes(self) -> u16 {
        match self {
            Self::Conventional => CONVENTIONAL_CONFIG_BYTES,
            Self::Enhanced => ENHANCED_CONFIG_BYTES,
        }
    }
}

/// Checked offset and width for one configuration-space access.
///
/// Keeping width with the offset prevents a caller from validating one byte and
/// later issuing a four-byte access at the same numeric offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigOffset {
    value: u16,
    width: ConfigWidth,
}

impl ConfigOffset {
    /// Validate natural alignment and the complete half-open access range.
    pub const fn try_new(
        value: u16,
        width: ConfigWidth,
        space: ConfigSpaceKind,
    ) -> Result<Self, ConfigError> {
        let bytes = width.bytes();
        if !value.is_multiple_of(bytes) {
            return Err(ConfigError::MisalignedAccess);
        }
        let Some(end) = value.checked_add(bytes) else {
            return Err(ConfigError::OffsetOutOfRange);
        };
        if end > space.bytes() {
            return Err(ConfigError::OffsetOutOfRange);
        }
        Ok(Self { value, width })
    }

    /// Byte offset from the start of the function's configuration space.
    pub const fn value(self) -> u16 {
        self.value
    }

    /// Access width validated with this offset.
    pub const fn width(self) -> ConfigWidth {
        self.width
    }

    /// Exclusive end offset.
    pub const fn end(self) -> u16 {
        self.value + self.width.bytes()
    }
}

/// Bytes reserved by ECAM for one bus (32 devices × 8 functions × 4 KiB).
pub const ECAM_BUS_BYTES: u64 = 1 << 20;
/// Bytes reserved by ECAM for one device on a bus.
pub const ECAM_DEVICE_BYTES: u64 = 1 << 15;
/// Bytes reserved by ECAM for one function.
pub const ECAM_FUNCTION_BYTES: u64 = 1 << 12;
/// PCI Configuration Mechanism #1 address port.
pub const LEGACY_CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
/// PCI Configuration Mechanism #1 data port.
pub const LEGACY_CONFIG_DATA_PORT: u16 = 0x0cfc;

/// One validated PCI Express ECAM allocation window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamRegion {
    base: u64,
    segment: u16,
    start_bus: u8,
    end_bus: u8,
    end_exclusive: u64,
}

impl EcamRegion {
    /// Construct a checked ECAM region.
    ///
    /// `base` names configuration page zero for `start_bus`, matching the ACPI
    /// MCFG allocation record semantics.
    pub const fn try_new(
        base: u64,
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    ) -> Result<Self, ConfigError> {
        if start_bus > end_bus {
            return Err(ConfigError::InvalidBusRange);
        }
        if !base.is_multiple_of(ECAM_BUS_BYTES) {
            return Err(ConfigError::MisalignedBase);
        }
        let bus_count = (end_bus as u64) - (start_bus as u64) + 1;
        let Some(span) = bus_count.checked_mul(ECAM_BUS_BYTES) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(end_exclusive) = base.checked_add(span) else {
            return Err(ConfigError::AddressOverflow);
        };
        Ok(Self {
            base,
            segment,
            start_bus,
            end_bus,
            end_exclusive,
        })
    }

    /// Physical base of the ECAM window.
    pub const fn base(self) -> u64 {
        self.base
    }

    /// PCI segment group served by this region.
    pub const fn segment(self) -> u16 {
        self.segment
    }

    /// First bus served by this region.
    pub const fn start_bus(self) -> u8 {
        self.start_bus
    }

    /// Last bus served by this region, inclusive.
    pub const fn end_bus(self) -> u8 {
        self.end_bus
    }

    /// Exclusive physical end of the ECAM window.
    pub const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }

    /// Whether the region can address this PCI function.
    pub const fn contains(self, address: PciAddress) -> bool {
        address.segment() == self.segment
            && address.bus() >= self.start_bus
            && address.bus() <= self.end_bus
    }

    /// Plan one checked ECAM access without dereferencing physical memory.
    pub const fn plan(
        self,
        address: PciAddress,
        offset: ConfigOffset,
    ) -> Result<EcamAccessPlan, ConfigError> {
        if address.segment() != self.segment {
            return Err(ConfigError::UnsupportedSegment);
        }
        if address.bus() < self.start_bus || address.bus() > self.end_bus {
            return Err(ConfigError::BusOutOfRange);
        }
        if offset.end() > ENHANCED_CONFIG_BYTES {
            return Err(ConfigError::OffsetOutOfRange);
        }

        let bus_index = (address.bus() as u64) - (self.start_bus as u64);
        let Some(bus_offset) = bus_index.checked_mul(ECAM_BUS_BYTES) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(device_offset) = (address.device() as u64).checked_mul(ECAM_DEVICE_BYTES) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(function_offset) = (address.function() as u64).checked_mul(ECAM_FUNCTION_BYTES)
        else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(after_bus) = self.base.checked_add(bus_offset) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(after_device) = after_bus.checked_add(device_offset) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(after_function) = after_device.checked_add(function_offset) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(physical_address) = after_function.checked_add(offset.value() as u64) else {
            return Err(ConfigError::AddressOverflow);
        };
        let Some(access_end) = physical_address.checked_add(offset.width().bytes() as u64) else {
            return Err(ConfigError::AddressOverflow);
        };
        if access_end > self.end_exclusive {
            return Err(ConfigError::AddressOverflow);
        }
        Ok(EcamAccessPlan {
            physical_address,
            width: offset.width(),
        })
    }
}

/// Physical ECAM access produced by [`EcamRegion::plan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamAccessPlan {
    physical_address: u64,
    width: ConfigWidth,
}

impl EcamAccessPlan {
    /// Physical address to access through an uncached ECAM mapping.
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    /// Access width.
    pub const fn width(self) -> ConfigWidth {
        self.width
    }
}

/// One PCI Configuration Mechanism #1 cycle plan.
///
/// The hardware transport performs a dword access through CF8/CFC. Byte and
/// word operations use [`Self::extract`] and [`Self::merge`] so unrelated
/// lanes are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyConfigPlan {
    address_register: u32,
    shift: u8,
    width: ConfigWidth,
}

impl LegacyConfigPlan {
    /// Build a checked segment-0 conventional-config access plan.
    pub const fn try_new(address: PciAddress, offset: ConfigOffset) -> Result<Self, ConfigError> {
        if address.segment() != 0 {
            return Err(ConfigError::UnsupportedSegment);
        }
        if offset.end() > CONVENTIONAL_CONFIG_BYTES {
            return Err(ConfigError::UnsupportedAccess);
        }
        let aligned_offset = offset.value() & !0x3;
        let address_register = 0x8000_0000
            | ((address.bus() as u32) << 16)
            | ((address.device() as u32) << 11)
            | ((address.function() as u32) << 8)
            | (aligned_offset as u32);
        Ok(Self {
            address_register,
            shift: ((offset.value() & 0x3) * 8) as u8,
            width: offset.width(),
        })
    }

    /// Value written to port [`LEGACY_CONFIG_ADDRESS_PORT`].
    pub const fn address_register(self) -> u32 {
        self.address_register
    }

    /// Data port used for the aligned dword cycle.
    pub const fn data_port(self) -> u16 {
        LEGACY_CONFIG_DATA_PORT
    }

    /// Access width requested by the caller.
    pub const fn width(self) -> ConfigWidth {
        self.width
    }

    /// Extract the requested byte/word/dword from one CFC dword read.
    pub const fn extract(self, dword: u32) -> u32 {
        (dword >> self.shift) & self.width.value_mask()
    }

    /// Merge a byte/word/dword into a previously read CFC dword.
    pub const fn merge(self, original: u32, value: u32) -> u32 {
        let shifted_mask = self.width.value_mask() << self.shift;
        (original & !shifted_mask) | ((value << self.shift) & shifted_mask)
    }
}

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
    pub const CAPABILITY_POINTER: usize = 0x34;
    pub const INTERRUPT_LINE: usize = 0x3C;
    pub const INTERRUPT_PIN: usize = 0x3D;
}

/// Command register bits.
#[allow(missing_docs)]
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTX_DISABLE: u16 = 1 << 10;
}

/// Status register bits.
#[allow(missing_docs)]
pub mod status {
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
}

/// PCI capability IDs used by Stage-A storage discovery.
#[allow(missing_docs)]
pub mod capability_id {
    pub const MSI: u8 = 0x05;
    pub const MSIX: u8 = 0x11;
}

/// A 256-byte conventional PCI configuration space.
#[derive(Clone, Copy)]
pub struct ConfigSpace(pub [u8; 256]);

impl ConfigSpace {
    /// An all-zero config space.
    pub const fn zeroed() -> Self {
        ConfigSpace([0; 256])
    }

    /// Raw conventional configuration bytes.
    pub const fn as_bytes(&self) -> &[u8; 256] {
        &self.0
    }

    fn read_u16(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.0[off], self.0[off + 1]])
    }
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes([
            self.0[off],
            self.0[off + 1],
            self.0[off + 2],
            self.0[off + 3],
        ])
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
    /// Status register.
    pub fn status(&self) -> u16 {
        self.read_u16(off::STATUS)
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
    /// True when function 0 advertises additional functions.
    pub fn is_multifunction(&self) -> bool {
        self.0[off::HEADER_TYPE] & 0x80 != 0
    }
    /// Capability-list pointer, if advertised and in the conventional config
    /// header range.
    pub fn capability_pointer(&self) -> Option<u8> {
        if self.status() & status::CAPABILITIES_LIST == 0 {
            return None;
        }
        let ptr = self.0[off::CAPABILITY_POINTER] & 0xFC;
        if (0x40..=0xFC).contains(&ptr) {
            Some(ptr)
        } else {
            None
        }
    }
    /// Interrupt line byte (`0xff` means unknown/not routed by firmware).
    pub fn interrupt_line(&self) -> u8 {
        self.0[off::INTERRUPT_LINE]
    }
    /// Interrupt pin byte (1=A, 2=B, ...; zero means no pin).
    pub fn interrupt_pin(&self) -> u8 {
        self.0[off::INTERRUPT_PIN]
    }
    /// The class code triple.
    pub fn class_code(&self) -> ClassCode {
        ClassCode {
            class: self.class(),
            subclass: self.subclass(),
            prog_if: self.prog_if(),
        }
    }
    /// Raw BAR register `n` (0..6).
    pub fn bar_raw(&self, n: usize) -> Option<u32> {
        if n >= 6 {
            return None;
        }
        Some(self.read_u32(off::BAR0 + n * 4))
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
    /// Set a BAR register (raw value). Out-of-range indexes are ignored so
    /// malformed mock setup cannot panic.
    pub fn set_bar_raw(&mut self, n: usize, v: u32) {
        if n < 6 {
            self.write_u32(off::BAR0 + n * 4, v);
        }
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
    pub const NVME: ClassCode = ClassCode {
        class: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
    };

    /// True when this class code matches `other` exactly.
    pub fn matches(&self, other: ClassCode) -> bool {
        self.class == other.class
            && self.subclass == other.subclass
            && self.prog_if == other.prog_if
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

/// Parsed MSI-X capability metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsixCapability {
    /// Capability offset in conventional config space.
    pub offset: u8,
    /// Number of MSI-X table entries.
    pub table_size: u16,
    /// Table BAR indicator register.
    pub table_bir: u8,
    /// Table offset within the BAR.
    pub table_offset: u32,
}

/// Parsed MSI capability metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsiCapability {
    /// Capability offset in conventional config space.
    pub offset: u8,
    /// Maximum vector count encoded by the capability.
    pub vector_count: u16,
}

/// Interrupt capability summary relevant to NVMe Stage A.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterruptCapabilities {
    /// Legacy INTx line, if firmware routed one.
    pub intx_line: Option<u8>,
    /// Interrupt pin (1=A, 2=B, ...), if present.
    pub intx_pin: Option<u8>,
    /// MSI metadata, if present.
    pub msi: Option<MsiCapability>,
    /// MSI-X metadata, if present.
    pub msix: Option<MsixCapability>,
}

/// Parse legacy/MSI/MSI-X interrupt metadata from a conventional PCI config
/// space. The shared bounded capability decoder rejects cycles, malformed
/// pointers, duplicate singleton interrupt capabilities, and truncated bodies
/// instead of returning a partial interrupt view.
pub fn parse_interrupt_capabilities(
    config: &ConfigSpace,
) -> Result<InterruptCapabilities, capability::CapabilityError> {
    let mut out = InterruptCapabilities {
        intx_line: (config.interrupt_line() != 0xff).then_some(config.interrupt_line()),
        intx_pin: (config.interrupt_pin() != 0).then_some(config.interrupt_pin()),
        msi: None,
        msix: None,
    };

    for capability in capability::parse_conventional(config.as_bytes())? {
        let off = capability.offset as usize;
        match capability.id {
            capability_id::MSI => {
                if out.msi.is_some() {
                    return Err(capability::CapabilityError::DuplicateCapability);
                }
                if off.checked_add(4).is_none_or(|end| end > config.0.len()) {
                    return Err(capability::CapabilityError::Truncated);
                }
                let control = config.read_u16(off + 2);
                let mmc = (control >> 1) & 0x7;
                out.msi = Some(MsiCapability {
                    offset: capability.offset,
                    vector_count: 1u16 << mmc,
                });
            }
            capability_id::MSIX => {
                if out.msix.is_some() {
                    return Err(capability::CapabilityError::DuplicateCapability);
                }
                if off.checked_add(12).is_none_or(|end| end > config.0.len()) {
                    return Err(capability::CapabilityError::Truncated);
                }
                let control = config.read_u16(off + 2);
                let table = config.read_u32(off + 4);
                out.msix = Some(MsixCapability {
                    offset: capability.offset,
                    table_size: (control & 0x07ff).saturating_add(1),
                    table_bir: (table & 0x7) as u8,
                    table_offset: table & !0x7,
                });
            }
            _ => {}
        }
    }
    Ok(out)
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
    let base = if is_64 {
        ((hi as u64) << 32) | base32
    } else {
        base32
    };
    Bar::Memory {
        base,
        size,
        prefetchable,
        is_64,
    }
}

/// Decode an I/O BAR from its raw register value and decoded size.
pub fn decode_io_bar(lo: u32, size: u32) -> Bar {
    Bar::Io {
        base: lo & 0xFFFF_FFFC,
        size,
    }
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
        let Some(lo) = self.config.bar_raw(n) else {
            return Bar::Unused;
        };
        let Some(&mask) = self.bar_sizes.get(n) else {
            return Bar::Unused;
        };
        if lo & 1 == 0 {
            let size = memory_bar_size(mask);
            if size == 0 {
                return Bar::Unused;
            }
            let is_64 = ((lo >> 1) & 0x3) == 0b10;
            let hi = if is_64 && n + 1 < 6 {
                self.config.bar_raw(n + 1).unwrap_or_default()
            } else {
                0
            };
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
        Self {
            devices: Vec::new(),
        }
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

    #[test]
    fn pci_address_accepts_full_base_profile_boundaries() {
        let Ok(low) = PciAddress::try_new(0, 0, 0, 0) else {
            assert!(false, "lowest PCI address should be valid");
            return;
        };
        assert_eq!(
            (low.segment(), low.bus(), low.device(), low.function()),
            (0, 0, 0, 0)
        );

        let Ok(high) = PciAddress::try_new(u16::MAX, u8::MAX, 31, 7) else {
            assert!(false, "highest base-profile PCI address should be valid");
            return;
        };
        assert_eq!(high.segment(), u16::MAX);
        assert_eq!(high.bus(), u8::MAX);
        assert_eq!(high.device(), 31);
        assert_eq!(high.function(), 7);
    }

    #[test]
    fn pci_address_rejects_invalid_device_and_function() {
        assert_eq!(
            PciAddress::try_new(0, 0, 32, 0),
            Err(ConfigError::DeviceOutOfRange)
        );
        assert_eq!(
            PciAddress::try_new(0, 0, 0, 8),
            Err(ConfigError::FunctionOutOfRange)
        );
    }

    #[test]
    fn config_width_masks_match_wire_widths() {
        assert_eq!(ConfigWidth::Byte.bytes(), 1);
        assert_eq!(ConfigWidth::Byte.value_mask(), 0xff);
        assert_eq!(ConfigWidth::Word.bytes(), 2);
        assert_eq!(ConfigWidth::Word.value_mask(), 0xffff);
        assert_eq!(ConfigWidth::Dword.bytes(), 4);
        assert_eq!(ConfigWidth::Dword.value_mask(), u32::MAX);
    }

    #[test]
    fn conventional_offsets_cover_exact_last_accesses() {
        let Ok(byte) = ConfigOffset::try_new(
            CONVENTIONAL_CONFIG_BYTES - 1,
            ConfigWidth::Byte,
            ConfigSpaceKind::Conventional,
        ) else {
            assert!(false, "last conventional byte should be valid");
            return;
        };
        assert_eq!(byte.value(), 255);
        assert_eq!(byte.end(), 256);

        assert!(
            ConfigOffset::try_new(254, ConfigWidth::Word, ConfigSpaceKind::Conventional).is_ok()
        );
        assert!(
            ConfigOffset::try_new(252, ConfigWidth::Dword, ConfigSpaceKind::Conventional).is_ok()
        );
        assert_eq!(
            ConfigOffset::try_new(256, ConfigWidth::Byte, ConfigSpaceKind::Conventional),
            Err(ConfigError::OffsetOutOfRange)
        );
    }

    #[test]
    fn enhanced_offsets_cover_exact_last_accesses() {
        assert!(ConfigOffset::try_new(4095, ConfigWidth::Byte, ConfigSpaceKind::Enhanced).is_ok());
        assert!(ConfigOffset::try_new(4094, ConfigWidth::Word, ConfigSpaceKind::Enhanced).is_ok());
        let Ok(dword) = ConfigOffset::try_new(4092, ConfigWidth::Dword, ConfigSpaceKind::Enhanced)
        else {
            assert!(false, "last enhanced dword should be valid");
            return;
        };
        assert_eq!(dword.end(), ENHANCED_CONFIG_BYTES);
        assert_eq!(
            ConfigOffset::try_new(4096, ConfigWidth::Byte, ConfigSpaceKind::Enhanced),
            Err(ConfigError::OffsetOutOfRange)
        );
    }

    #[test]
    fn config_offsets_reject_misaligned_accesses() {
        assert_eq!(
            ConfigOffset::try_new(1, ConfigWidth::Word, ConfigSpaceKind::Conventional),
            Err(ConfigError::MisalignedAccess)
        );
        assert_eq!(
            ConfigOffset::try_new(2, ConfigWidth::Dword, ConfigSpaceKind::Enhanced),
            Err(ConfigError::MisalignedAccess)
        );
    }

    #[test]
    fn enhanced_only_offset_is_rejected_by_conventional_profile() {
        assert!(
            ConfigOffset::try_new(0x100, ConfigWidth::Dword, ConfigSpaceKind::Enhanced).is_ok()
        );
        assert_eq!(
            ConfigOffset::try_new(0x100, ConfigWidth::Dword, ConfigSpaceKind::Conventional),
            Err(ConfigError::OffsetOutOfRange)
        );
    }

    #[test]
    fn ecam_region_validates_alignment_range_and_overflow() {
        assert_eq!(
            EcamRegion::try_new(0xE000_0001, 0, 0, 0),
            Err(ConfigError::MisalignedBase)
        );
        assert_eq!(
            EcamRegion::try_new(0xE000_0000, 0, 8, 7),
            Err(ConfigError::InvalidBusRange)
        );
        let overflowing_base = u64::MAX & !(ECAM_BUS_BYTES - 1);
        assert_eq!(
            EcamRegion::try_new(overflowing_base, 0, 0, 0),
            Err(ConfigError::AddressOverflow)
        );
    }

    #[test]
    fn ecam_plan_uses_region_relative_bus_number() {
        let Ok(region) = EcamRegion::try_new(0x8000_0000, 7, 32, 47) else {
            assert!(false, "valid ECAM region should construct");
            return;
        };
        let Ok(address) = PciAddress::try_new(7, 34, 3, 4) else {
            assert!(false, "valid PCI address should construct");
            return;
        };
        let Ok(offset) =
            ConfigOffset::try_new(0x234, ConfigWidth::Dword, ConfigSpaceKind::Enhanced)
        else {
            assert!(false, "valid enhanced offset should construct");
            return;
        };
        let Ok(plan) = region.plan(address, offset) else {
            assert!(false, "address inside region should plan");
            return;
        };
        let expected = 0x8000_0000
            + 2 * ECAM_BUS_BYTES
            + 3 * ECAM_DEVICE_BYTES
            + 4 * ECAM_FUNCTION_BYTES
            + 0x234;
        assert_eq!(plan.physical_address(), expected);
        assert_eq!(plan.width(), ConfigWidth::Dword);
        assert!(region.contains(address));
    }

    #[test]
    fn ecam_plan_rejects_wrong_segment_and_bus() {
        let Ok(region) = EcamRegion::try_new(0x9000_0000, 3, 64, 79) else {
            assert!(false, "valid ECAM region should construct");
            return;
        };
        let Ok(offset) = ConfigOffset::try_new(0, ConfigWidth::Dword, ConfigSpaceKind::Enhanced)
        else {
            assert!(false, "zero dword offset should construct");
            return;
        };
        let Ok(wrong_segment) = PciAddress::try_new(4, 64, 0, 0) else {
            assert!(false, "valid address should construct");
            return;
        };
        assert_eq!(
            region.plan(wrong_segment, offset),
            Err(ConfigError::UnsupportedSegment)
        );
        let Ok(wrong_bus) = PciAddress::try_new(3, 80, 0, 0) else {
            assert!(false, "valid address should construct");
            return;
        };
        assert_eq!(
            region.plan(wrong_bus, offset),
            Err(ConfigError::BusOutOfRange)
        );
    }

    #[test]
    fn ecam_plan_reaches_exact_last_function_byte() {
        let Ok(region) = EcamRegion::try_new(0xA000_0000, 0, 0, 0) else {
            assert!(false, "single-bus ECAM region should construct");
            return;
        };
        let Ok(address) = PciAddress::try_new(0, 0, 31, 7) else {
            assert!(false, "last function should construct");
            return;
        };
        let Ok(offset) = ConfigOffset::try_new(4095, ConfigWidth::Byte, ConfigSpaceKind::Enhanced)
        else {
            assert!(false, "last enhanced byte should construct");
            return;
        };
        let Ok(plan) = region.plan(address, offset) else {
            assert!(false, "last ECAM byte should plan");
            return;
        };
        assert_eq!(plan.physical_address() + 1, region.end_exclusive());
    }

    #[test]
    fn legacy_plan_encodes_cf8_and_preserves_subdword_lanes() {
        let Ok(address) = PciAddress::try_new(0, 2, 3, 4) else {
            assert!(false, "valid legacy address should construct");
            return;
        };
        let Ok(offset) =
            ConfigOffset::try_new(0x12, ConfigWidth::Word, ConfigSpaceKind::Conventional)
        else {
            assert!(false, "aligned word offset should construct");
            return;
        };
        let Ok(plan) = LegacyConfigPlan::try_new(address, offset) else {
            assert!(false, "segment-zero conventional access should plan");
            return;
        };
        assert_eq!(
            plan.address_register(),
            0x8000_0000 | (2 << 16) | (3 << 11) | (4 << 8) | 0x10
        );
        assert_eq!(plan.data_port(), LEGACY_CONFIG_DATA_PORT);
        assert_eq!(plan.extract(0xAABB_CCDD), 0xAABB);
        assert_eq!(plan.merge(0x1122_3344, 0xABCD), 0xABCD_3344);
    }

    #[test]
    fn legacy_plan_rejects_nonzero_segment_and_extended_offset() {
        let Ok(offset) =
            ConfigOffset::try_new(0, ConfigWidth::Dword, ConfigSpaceKind::Conventional)
        else {
            assert!(false, "zero dword offset should construct");
            return;
        };
        let Ok(segment_one) = PciAddress::try_new(1, 0, 0, 0) else {
            assert!(false, "valid nonzero-segment address should construct");
            return;
        };
        assert_eq!(
            LegacyConfigPlan::try_new(segment_one, offset),
            Err(ConfigError::UnsupportedSegment)
        );

        let Ok(segment_zero) = PciAddress::try_new(0, 0, 0, 0) else {
            assert!(false, "valid segment-zero address should construct");
            return;
        };
        let Ok(extended) =
            ConfigOffset::try_new(0x100, ConfigWidth::Dword, ConfigSpaceKind::Enhanced)
        else {
            assert!(false, "enhanced offset should construct");
            return;
        };
        assert_eq!(
            LegacyConfigPlan::try_new(segment_zero, extended),
            Err(ConfigError::UnsupportedAccess)
        );
    }

    #[test]
    fn ecam_and_legacy_plans_agree_on_common_function_offset() {
        let Ok(address) = PciAddress::try_new(0, 5, 17, 2) else {
            assert!(false, "common-subset address should construct");
            return;
        };
        let Ok(offset) =
            ConfigOffset::try_new(0x3c, ConfigWidth::Dword, ConfigSpaceKind::Conventional)
        else {
            assert!(false, "common-subset offset should construct");
            return;
        };
        let Ok(ecam) = EcamRegion::try_new(0xB000_0000, 0, 0, 255) else {
            assert!(false, "full segment-zero ECAM region should construct");
            return;
        };
        let Ok(ecam_plan) = ecam.plan(address, offset) else {
            assert!(false, "ECAM common access should plan");
            return;
        };
        let Ok(legacy_plan) = LegacyConfigPlan::try_new(address, offset) else {
            assert!(false, "legacy common access should plan");
            return;
        };
        let ecam_relative = ecam_plan.physical_address() - ecam.base();
        assert_eq!(
            ecam_relative,
            u64::from(address.bus()) * ECAM_BUS_BYTES
                + u64::from(address.device()) * ECAM_DEVICE_BYTES
                + u64::from(address.function()) * ECAM_FUNCTION_BYTES
                + u64::from(offset.value())
        );
        let legacy = legacy_plan.address_register();
        assert_eq!(((legacy >> 16) & 0xff) as u8, address.bus());
        assert_eq!(((legacy >> 11) & 0x1f) as u8, address.device());
        assert_eq!(((legacy >> 8) & 0x7) as u8, address.function());
        assert_eq!((legacy & 0xfc) as u16, offset.value());
    }

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
        MockPciDevice {
            bus: 0,
            dev: 4,
            func: 0,
            config,
            bar_sizes,
        }
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
        assert_eq!(
            bar,
            Bar::Memory {
                base: 0xF000_0000,
                size: 0x1_0000,
                prefetchable: false,
                is_64: false
            }
        );
    }

    #[test]
    fn decode_64bit_prefetchable_memory_bar() {
        // 64-bit prefetchable: type 0b10 (<<1 = 0b0100), prefetch bit 3 set.
        let lo = 0b0100u32 | 0b1000;
        let hi = 0x0000_0002u32; // base high = 0x2_0000_0000
        let bar = decode_memory_bar(lo, hi, 0x1000);
        assert_eq!(
            bar,
            Bar::Memory {
                base: 0x2_0000_0000,
                size: 0x1000,
                prefetchable: true,
                is_64: true
            }
        );
    }

    #[test]
    fn decodes_an_io_bar() {
        let lo = 0x0000_C001u32; // I/O (bit 0 set), base 0xC000
        let bar = decode_io_bar(lo, 0x10);
        assert_eq!(
            bar,
            Bar::Io {
                base: 0xC000,
                size: 0x10
            }
        );
    }

    #[test]
    fn mock_device_decodes_its_bar() {
        let dev = nvme_device();
        let bar = dev.decode_bar(0);
        assert!(matches!(bar, Bar::Memory { .. }));
        if let Bar::Memory {
            base, size, is_64, ..
        } = bar
        {
            assert_eq!(base, 0xFE00_0000);
            assert_eq!(size, 0x4000); // 16 KiB from mask 0xFFFF_C000
            assert!(is_64);
        }
        // Unset BAR -> Unused.
        assert_eq!(dev.decode_bar(2), Bar::Unused);
    }

    #[test]
    fn parses_interrupt_capabilities() {
        let mut config = ConfigSpace::zeroed();
        config.set_ids(0x8086, 0x5845);
        config.set_class(0x01, 0x08, 0x02);
        config.write_u16(off::STATUS, status::CAPABILITIES_LIST);
        config.0[off::CAPABILITY_POINTER] = 0x40;
        config.0[off::INTERRUPT_LINE] = 11;
        config.0[off::INTERRUPT_PIN] = 1;
        config.0[0x40] = capability_id::MSI;
        config.0[0x41] = 0x50;
        // Multiple-message capable = 2^2 vectors.
        config.write_u16(0x42, 0b0100);
        config.0[0x50] = capability_id::MSIX;
        config.0[0x51] = 0;
        // Table size encoded as N-1, so 3 means 4 entries.
        config.write_u16(0x52, 3);
        config.write_u32(0x54, 0x2000 | 2);

        let Ok(caps) = parse_interrupt_capabilities(&config) else {
            assert!(false, "valid interrupt capabilities should parse");
            return;
        };
        assert_eq!(caps.intx_line, Some(11));
        assert_eq!(caps.intx_pin, Some(1));
        assert_eq!(caps.msi.map(|m| m.vector_count), Some(4));
        assert_eq!(
            caps.msix
                .map(|m| (m.table_size, m.table_bir, m.table_offset)),
            Some((4, 2, 0x2000))
        );
    }

    #[test]
    fn interrupt_capability_walk_rejects_self_cycle() {
        let mut config = ConfigSpace::zeroed();
        config.set_ids(0x8086, 0x5845);
        config.write_u16(off::STATUS, status::CAPABILITIES_LIST);
        config.0[off::CAPABILITY_POINTER] = 0x40;
        config.0[0x40] = capability_id::MSI;
        config.0[0x41] = 0x40;
        assert_eq!(
            parse_interrupt_capabilities(&config),
            Err(capability::CapabilityError::Cycle)
        );
    }

    #[test]
    fn interrupt_capability_walk_rejects_duplicate_and_truncated_bodies() {
        let mut duplicate = ConfigSpace::zeroed();
        duplicate.write_u16(off::STATUS, status::CAPABILITIES_LIST);
        duplicate.0[off::CAPABILITY_POINTER] = 0x40;
        duplicate.0[0x40] = capability_id::MSI;
        duplicate.0[0x41] = 0x50;
        duplicate.0[0x50] = capability_id::MSI;
        duplicate.0[0x51] = 0;
        assert_eq!(
            parse_interrupt_capabilities(&duplicate),
            Err(capability::CapabilityError::DuplicateCapability)
        );

        let mut truncated = ConfigSpace::zeroed();
        truncated.write_u16(off::STATUS, status::CAPABILITIES_LIST);
        truncated.0[off::CAPABILITY_POINTER] = 0xf8;
        truncated.0[0xf8] = capability_id::MSIX;
        truncated.0[0xf9] = 0;
        assert_eq!(
            parse_interrupt_capabilities(&truncated),
            Err(capability::CapabilityError::Truncated)
        );
    }

    #[test]
    fn bus_finds_nvme_by_class() {
        let mut bus = MockPciBus::new();
        // A non-NVMe device (e.g. a VGA controller).
        let mut vga = MockPciDevice {
            bus: 0,
            dev: 2,
            func: 0,
            config: ConfigSpace::zeroed(),
            bar_sizes: [0; 6],
        };
        vga.config.set_ids(0x1234, 0x1111);
        vga.config.set_class(0x03, 0x00, 0x00); // VGA
        bus.add(vga);
        bus.add(nvme_device());
        // An absent slot should not match.
        let mut absent = MockPciDevice {
            bus: 0,
            dev: 9,
            func: 0,
            config: ConfigSpace::zeroed(),
            bar_sizes: [0; 6],
        };
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
        assert!(nvme.matches(ClassCode {
            class: 0x01,
            subclass: 0x08,
            prog_if: 0x02
        }));
        assert!(!nvme.matches(ClassCode {
            class: 0x01,
            subclass: 0x08,
            prog_if: 0x01
        }));
        assert!(!nvme.matches(ClassCode {
            class: 0x01,
            subclass: 0x06,
            prog_if: 0x02
        }));
    }
}
