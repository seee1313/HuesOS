//! Bounded PCI and PCIe capability-list decoding.
//!
//! Unknown capability IDs are preserved. Structural corruption is returned as
//! an error instead of being treated as an empty/partial list, so callers never
//! configure a device from an ambiguous capability view.

use alloc::vec::Vec;

/// Conventional PCI configuration bytes required by the decoder.
const CONVENTIONAL_BYTES: usize = 256;
/// PCIe enhanced configuration bytes required by the decoder.
const ENHANCED_BYTES: usize = 4096;
/// Conventional status register.
const STATUS_OFFSET: usize = 0x06;
/// Conventional capabilities-list-present bit.
const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
/// Conventional capability-list head pointer.
const CAPABILITY_POINTER_OFFSET: usize = 0x34;
/// First valid conventional capability offset.
const FIRST_CONVENTIONAL_OFFSET: u16 = 0x40;
/// First PCIe extended capability offset.
const FIRST_EXTENDED_OFFSET: u16 = 0x100;
/// Maximum conventional capability records (0x40..0xff in dword slots).
pub const MAX_CONVENTIONAL_CAPABILITIES: usize = 48;
/// Maximum PCIe extended capability records (0x100..0xfff in dword slots).
pub const MAX_EXTENDED_CAPABILITIES: usize = 960;

/// Structural capability-list error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// Configuration byte slice is shorter than the required profile.
    ConfigTooShort,
    /// Capability pointer is outside its legal range.
    PointerOutOfRange,
    /// Capability pointer is not dword aligned.
    MisalignedPointer,
    /// A pointer revisits an already decoded record.
    Cycle,
    /// A singleton capability required by policy appears more than once.
    DuplicateCapability,
    /// A capability header or type-specific body is truncated.
    Truncated,
    /// Extended capability ID is an invalid zero/all-ones sentinel in a linked
    /// record.
    InvalidId,
    /// Walk exceeded the profile's bounded record capacity.
    TooManyCapabilities,
    /// Bounded result allocation failed.
    NoMemory,
}

/// One conventional PCI capability header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConventionalCapability {
    /// Capability ID.
    pub id: u8,
    /// Dword-aligned byte offset in conventional configuration space.
    pub offset: u8,
}

/// One PCI Express extended capability header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedCapability {
    /// Extended capability ID.
    pub id: u16,
    /// Capability version (`0..15`).
    pub version: u8,
    /// Dword-aligned byte offset in enhanced configuration space.
    pub offset: u16,
}

/// Decode the conventional linked capability list.
pub fn parse_conventional(config: &[u8]) -> Result<Vec<ConventionalCapability>, CapabilityError> {
    if config.len() < CONVENTIONAL_BYTES {
        return Err(CapabilityError::ConfigTooShort);
    }
    let status = read_u16(config, STATUS_OFFSET).ok_or(CapabilityError::ConfigTooShort)?;
    let mut capabilities = Vec::new();
    capabilities
        .try_reserve_exact(MAX_CONVENTIONAL_CAPABILITIES)
        .map_err(|_| CapabilityError::NoMemory)?;
    if status & STATUS_CAPABILITIES_LIST == 0 {
        return Ok(capabilities);
    }

    let mut pointer = u16::from(config[CAPABILITY_POINTER_OFFSET]);
    if pointer == 0 {
        return Ok(capabilities);
    }
    let mut visited = 0u64;
    while pointer != 0 {
        validate_conventional_pointer(pointer)?;
        let slot = (pointer / 4) as u32;
        let bit = 1u64 << slot;
        if visited & bit != 0 {
            return Err(CapabilityError::Cycle);
        }
        visited |= bit;
        if capabilities.len() >= MAX_CONVENTIONAL_CAPABILITIES {
            return Err(CapabilityError::TooManyCapabilities);
        }
        let offset = pointer as usize;
        let id = *config.get(offset).ok_or(CapabilityError::Truncated)?;
        let next = u16::from(*config.get(offset + 1).ok_or(CapabilityError::Truncated)?);
        capabilities.push(ConventionalCapability {
            id,
            offset: pointer as u8,
        });
        if next != 0 {
            validate_conventional_pointer(next)?;
        }
        pointer = next;
    }
    Ok(capabilities)
}

/// Decode the PCIe extended linked capability list.
pub fn parse_extended(config: &[u8]) -> Result<Vec<ExtendedCapability>, CapabilityError> {
    if config.len() < ENHANCED_BYTES {
        return Err(CapabilityError::ConfigTooShort);
    }
    let mut capabilities = Vec::new();
    capabilities
        .try_reserve_exact(MAX_EXTENDED_CAPABILITIES)
        .map_err(|_| CapabilityError::NoMemory)?;

    let first =
        read_u32(config, FIRST_EXTENDED_OFFSET as usize).ok_or(CapabilityError::ConfigTooShort)?;
    if first == 0 || first == u32::MAX {
        return Ok(capabilities);
    }

    let mut pointer = FIRST_EXTENDED_OFFSET;
    let mut visited = [0u64; 16];
    while pointer != 0 {
        validate_extended_pointer(pointer)?;
        let slot = (pointer / 4) as usize;
        let word = slot / 64;
        let bit = 1u64 << (slot % 64);
        if visited[word] & bit != 0 {
            return Err(CapabilityError::Cycle);
        }
        visited[word] |= bit;
        if capabilities.len() >= MAX_EXTENDED_CAPABILITIES {
            return Err(CapabilityError::TooManyCapabilities);
        }
        let header = read_u32(config, pointer as usize).ok_or(CapabilityError::Truncated)?;
        let id = (header & 0xffff) as u16;
        if id == 0 || id == u16::MAX {
            return Err(CapabilityError::InvalidId);
        }
        let version = ((header >> 16) & 0xf) as u8;
        let next = ((header >> 20) & 0xfff) as u16;
        capabilities.push(ExtendedCapability {
            id,
            version,
            offset: pointer,
        });
        if next != 0 {
            validate_extended_pointer(next)?;
        }
        pointer = next;
    }
    Ok(capabilities)
}

fn validate_conventional_pointer(pointer: u16) -> Result<(), CapabilityError> {
    if !pointer.is_multiple_of(4) {
        return Err(CapabilityError::MisalignedPointer);
    }
    if !(FIRST_CONVENTIONAL_OFFSET..=0xfc).contains(&pointer) {
        return Err(CapabilityError::PointerOutOfRange);
    }
    Ok(())
}

fn validate_extended_pointer(pointer: u16) -> Result<(), CapabilityError> {
    if !pointer.is_multiple_of(4) {
        return Err(CapabilityError::MisalignedPointer);
    }
    if !(FIRST_EXTENDED_OFFSET..=0xffc).contains(&pointer) {
        return Err(CapabilityError::PointerOutOfRange);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn conventional_config() -> [u8; CONVENTIONAL_BYTES] {
        let mut config = [0u8; CONVENTIONAL_BYTES];
        config[STATUS_OFFSET..STATUS_OFFSET + 2]
            .copy_from_slice(&STATUS_CAPABILITIES_LIST.to_le_bytes());
        config
    }

    fn extended_header(id: u16, version: u8, next: u16) -> u32 {
        u32::from(id) | (u32::from(version & 0xf) << 16) | (u32::from(next & 0xfff) << 20)
    }

    #[test]
    fn conventional_walk_preserves_unknown_ids() {
        let mut config = conventional_config();
        config[CAPABILITY_POINTER_OFFSET] = 0x40;
        config[0x40] = 0x05;
        config[0x41] = 0x80;
        config[0x80] = 0xee;
        config[0x81] = 0;
        assert_eq!(
            parse_conventional(&config),
            Ok(vec![
                ConventionalCapability {
                    id: 0x05,
                    offset: 0x40
                },
                ConventionalCapability {
                    id: 0xee,
                    offset: 0x80
                },
            ])
        );
    }

    #[test]
    fn conventional_walk_rejects_cycles_and_bad_pointers() {
        let mut cycle = conventional_config();
        cycle[CAPABILITY_POINTER_OFFSET] = 0x40;
        cycle[0x40] = 1;
        cycle[0x41] = 0x80;
        cycle[0x80] = 2;
        cycle[0x81] = 0x40;
        assert_eq!(parse_conventional(&cycle), Err(CapabilityError::Cycle));

        let mut misaligned = conventional_config();
        misaligned[CAPABILITY_POINTER_OFFSET] = 0x41;
        assert_eq!(
            parse_conventional(&misaligned),
            Err(CapabilityError::MisalignedPointer)
        );

        let mut low = conventional_config();
        low[CAPABILITY_POINTER_OFFSET] = 0x20;
        assert_eq!(
            parse_conventional(&low),
            Err(CapabilityError::PointerOutOfRange)
        );
    }

    #[test]
    fn conventional_walk_requires_full_profile() {
        assert_eq!(
            parse_conventional(&[0u8; 255]),
            Err(CapabilityError::ConfigTooShort)
        );
    }

    #[test]
    fn conventional_without_status_bit_is_empty() {
        assert_eq!(parse_conventional(&[0u8; 256]), Ok(Vec::new()));
    }

    #[test]
    fn extended_walk_preserves_unknown_ids_and_versions() {
        let mut config = vec![0u8; ENHANCED_BYTES];
        config[0x100..0x104].copy_from_slice(&extended_header(0x0001, 2, 0x240).to_le_bytes());
        config[0x240..0x244].copy_from_slice(&extended_header(0xbeef, 7, 0).to_le_bytes());
        assert_eq!(
            parse_extended(&config),
            Ok(vec![
                ExtendedCapability {
                    id: 0x0001,
                    version: 2,
                    offset: 0x100,
                },
                ExtendedCapability {
                    id: 0xbeef,
                    version: 7,
                    offset: 0x240,
                },
            ])
        );
    }

    #[test]
    fn extended_walk_rejects_cycle_alignment_range_and_invalid_id() {
        let mut cycle = vec![0u8; ENHANCED_BYTES];
        cycle[0x100..0x104].copy_from_slice(&extended_header(1, 1, 0x200).to_le_bytes());
        cycle[0x200..0x204].copy_from_slice(&extended_header(2, 1, 0x100).to_le_bytes());
        assert_eq!(parse_extended(&cycle), Err(CapabilityError::Cycle));

        let mut misaligned = vec![0u8; ENHANCED_BYTES];
        misaligned[0x100..0x104].copy_from_slice(&extended_header(1, 1, 0x202).to_le_bytes());
        assert_eq!(
            parse_extended(&misaligned),
            Err(CapabilityError::MisalignedPointer)
        );

        let mut low = vec![0u8; ENHANCED_BYTES];
        low[0x100..0x104].copy_from_slice(&extended_header(1, 1, 0x80).to_le_bytes());
        assert_eq!(
            parse_extended(&low),
            Err(CapabilityError::PointerOutOfRange)
        );

        let mut invalid_id = vec![0u8; ENHANCED_BYTES];
        invalid_id[0x100..0x104].copy_from_slice(&extended_header(1, 1, 0x200).to_le_bytes());
        invalid_id[0x200..0x204].copy_from_slice(&extended_header(0, 1, 0).to_le_bytes());
        assert_eq!(parse_extended(&invalid_id), Err(CapabilityError::InvalidId));
    }

    #[test]
    fn extended_empty_sentinels_and_short_profile() {
        assert_eq!(parse_extended(&[0u8; ENHANCED_BYTES]), Ok(Vec::new()));
        assert_eq!(parse_extended(&[0xffu8; ENHANCED_BYTES]), Ok(Vec::new()));
        assert_eq!(
            parse_extended(&[0u8; ENHANCED_BYTES - 1]),
            Err(CapabilityError::ConfigTooShort)
        );
    }
}
