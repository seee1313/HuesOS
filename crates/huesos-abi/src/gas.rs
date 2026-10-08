//! Generic Address Structure (GAS) decoding for ACPI.
//!
//! A GAS describes a register block the firmware exposes through one of
//! several address spaces (SystemIO, SystemMemory, PCI config, ...). The
//! Ring-3 ACPI broker turns validated GAS fields from FADT/AML into
//! capability grants; this module provides the shared, host-testable decode
//! so the address-space routing is exercised without firmware tables.

/// ACPI address space encoding for a [`Gas`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpace {
    /// System memory (MMIO).
    SystemMemory,
    /// System I/O port space.
    SystemIo,
    /// PCI configuration space.
    PciConfig,
    /// Functional Fixed Hardware.
    FunctionalFixedHw,
    /// Any other/Reserved/legacy address space, carrying the raw id.
    Other(u8),
}

impl AddressSpace {
    /// Decode the one-byte address space identifier.
    pub const fn from_raw(id: u8) -> Self {
        match id {
            0 => Self::SystemMemory,
            1 => Self::SystemIo,
            2 => Self::PciConfig,
            0x7f => Self::FunctionalFixedHw,
            other => Self::Other(other),
        }
    }

    /// Whether this address space is firmware MMIO.
    pub fn is_system_memory(self) -> bool {
        matches!(self, Self::SystemMemory)
    }

    /// Whether this address space is x86 I/O port space.
    pub fn is_system_io(self) -> bool {
        matches!(self, Self::SystemIo)
    }
}

/// A decoded Generic Address Structure (12 raw bytes, packed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gas {
    /// Resolved address space.
    pub address_space: AddressSpace,
    /// Register width in bits.
    pub register_bit_width: u8,
    /// Register offset in bits.
    pub register_bit_offset: u8,
    /// Access size encoding (0=undefined, 1=byte, 2=word, 3=dword, 4=qword).
    pub access_size: u8,
    /// Register block base address.
    pub address: u64,
}

impl Gas {
    /// Decode a 12-byte packed GAS from raw firmware bytes.
    ///
    /// Returns `None` unless at least 12 bytes are supplied. Fields are read
    /// at their packed offsets (no struct padding) so this matches the on-wire
    /// ACPI layout exactly.
    pub fn decode(bytes: &[u8]) -> Option<Gas> {
        if bytes.len() < 12 {
            return None;
        }
        let address = u64::from_le_bytes([
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
        ]);
        Some(Gas {
            address_space: AddressSpace::from_raw(bytes[0]),
            register_bit_width: bytes[1],
            register_bit_offset: bytes[2],
            access_size: bytes[3],
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_packed_gas_layout() {
        // address_space=1 (SystemIo), width=0x20, offset=0, access=1 (byte),
        // address = 0x0000_0000_0000_00B2.
        let raw = [
            1u8, 0x20, 0x00, 0x01, 0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = Gas {
            address_space: AddressSpace::SystemIo,
            register_bit_width: 0x20,
            register_bit_offset: 0,
            access_size: 1,
            address: 0xB2,
        };
        assert_eq!(Gas::decode(&raw), Some(expected));
        assert!(expected.address_space.is_system_io());
        assert!(!expected.address_space.is_system_memory());
    }

    #[test]
    fn decodes_system_memory_address_space() {
        // address_space=0 (SystemMemory), address = 0xFEC0_0000.
        let raw = [
            0u8, 0x40, 0x00, 0x04, 0x00, 0x00, 0xC0, 0xFE, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = Gas {
            address_space: AddressSpace::SystemMemory,
            register_bit_width: 0x40,
            register_bit_offset: 0,
            access_size: 4,
            address: 0xFE_C0_0000,
        };
        assert_eq!(Gas::decode(&raw), Some(expected));
        assert!(expected.address_space.is_system_memory());
    }

    #[test]
    fn rejects_short_input() {
        assert!(Gas::decode(&[0u8; 11]).is_none());
        assert!(Gas::decode(&[]).is_none());
    }

    #[test]
    fn maps_unknown_address_space() {
        let raw = [
            0x42u8, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = Gas {
            address_space: AddressSpace::Other(0x42),
            register_bit_width: 0,
            register_bit_offset: 0,
            access_size: 0,
            address: 0x10,
        };
        assert_eq!(Gas::decode(&raw), Some(expected));
    }
}
