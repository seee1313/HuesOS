//! ACPI MCFG allocation-table decoder.
//!
//! The ACPI archive is expected to validate table provenance and lifetime, but
//! this decoder independently validates the byte-level MCFG contract before an
//! ECAM physical range reaches PCI policy code.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::{ConfigError, EcamRegion};

/// ACPI System Description Table header bytes.
pub const SDT_HEADER_BYTES: usize = 36;
/// MCFG fixed header bytes (SDT header plus eight reserved bytes).
pub const MCFG_HEADER_BYTES: usize = 44;
/// Bytes in one MCFG allocation structure.
pub const MCFG_ALLOCATION_BYTES: usize = 16;
/// Maximum ECAM allocations accepted from one MCFG table.
pub const MAX_MCFG_ALLOCATIONS: usize = 64;

/// Rejection reason for an MCFG table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McfgError {
    /// Table signature is not `MCFG`.
    BadSignature,
    /// Declared length is inconsistent, truncated, or not entry aligned.
    BadLength,
    /// ACPI checksum does not sum to zero.
    BadChecksum,
    /// A reserved field is non-zero.
    ReservedNonZero,
    /// Allocation count exceeds [`MAX_MCFG_ALLOCATIONS`].
    TooManyAllocations,
    /// An allocation failed checked ECAM validation.
    InvalidAllocation(ConfigError),
    /// Two entries claim overlapping buses in one segment or overlapping
    /// physical ECAM memory.
    Overlap,
    /// Host allocation for the decoded result failed.
    NoMemory,
}

impl crate::EcamRegion {
    /// Uninitialised slot filler for the bounded decode buffer.
    ///
    /// Never observable outside this crate: every slot is overwritten
    /// with a validated region before any consumer reads it (the decode
    /// returns the written count and callers slice `..count`).
    pub(crate) const fn placeholder() -> Self {
        Self {
            base: 0,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            end_exclusive: 0,
        }
    }
}

/// Decode and validate one complete ACPI MCFG table without allocating.
///
/// Performs exactly the same checks as `parse()` (signature, length,
/// checksum, reserved fields, allocation bound, per-window validation and
/// overlap rejection), but writes the windows into a fixed buffer and
/// returns the count. This is the entry point for heap-less callers
/// (the Ring-3 `acpi-manager`, which is `no_std` and deliberately carries
/// no global allocator).
pub fn decode_all(
    bytes: &[u8],
) -> Result<(usize, [crate::EcamRegion; MAX_MCFG_ALLOCATIONS]), McfgError> {
    if bytes.len() < MCFG_HEADER_BYTES {
        return Err(McfgError::BadLength);
    }
    if bytes.get(0..4) != Some(b"MCFG".as_slice()) {
        return Err(McfgError::BadSignature);
    }
    let length = read_u32(bytes, 4).ok_or(McfgError::BadLength)? as usize;
    if length != bytes.len() || length < MCFG_HEADER_BYTES {
        return Err(McfgError::BadLength);
    }
    let payload_bytes = length - MCFG_HEADER_BYTES;
    if !payload_bytes.is_multiple_of(MCFG_ALLOCATION_BYTES) {
        return Err(McfgError::BadLength);
    }
    if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
        return Err(McfgError::BadChecksum);
    }
    if bytes[SDT_HEADER_BYTES..MCFG_HEADER_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(McfgError::ReservedNonZero);
    }

    let count = payload_bytes / MCFG_ALLOCATION_BYTES;
    if count > MAX_MCFG_ALLOCATIONS {
        return Err(McfgError::TooManyAllocations);
    }

    let mut regions = [crate::EcamRegion::placeholder(); MAX_MCFG_ALLOCATIONS];
    let mut index = 0usize;
    while index < count {
        let offset = MCFG_HEADER_BYTES + index * MCFG_ALLOCATION_BYTES;
        let base = read_u64(bytes, offset).ok_or(McfgError::BadLength)?;
        let segment = read_u16(bytes, offset + 8).ok_or(McfgError::BadLength)?;
        let start_bus = *bytes.get(offset + 10).ok_or(McfgError::BadLength)?;
        let end_bus = *bytes.get(offset + 11).ok_or(McfgError::BadLength)?;
        if read_u32(bytes, offset + 12).ok_or(McfgError::BadLength)? != 0 {
            return Err(McfgError::ReservedNonZero);
        }
        let region = crate::EcamRegion::try_new(base, segment, start_bus, end_bus)
            .map_err(McfgError::InvalidAllocation)?;
        for previous in regions.iter().take(index) {
            if regions_overlap(*previous, region) {
                return Err(McfgError::Overlap);
            }
        }
        regions[index] = region;
        index += 1;
    }
    Ok((count, regions))
}

/// Decode and validate one complete ACPI MCFG table.
#[cfg(feature = "alloc")]
pub fn parse(bytes: &[u8]) -> Result<Vec<EcamRegion>, McfgError> {
    let (count, regions) = decode_all(bytes)?;
    let mut vec = Vec::new();
    vec.try_reserve_exact(count)
        .map_err(|_| McfgError::NoMemory)?;
    vec.extend_from_slice(&regions[..count]);
    Ok(vec)
}

fn regions_overlap(a: EcamRegion, b: EcamRegion) -> bool {
    let physical = a.base() < b.end_exclusive() && b.base() < a.end_exclusive();
    let buses =
        a.segment() == b.segment() && a.start_bus() <= b.end_bus() && b.start_bus() <= a.end_bus();
    physical || buses
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

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
        *bytes.get(offset + 4)?,
        *bytes.get(offset + 5)?,
        *bytes.get(offset + 6)?,
        *bytes.get(offset + 7)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[derive(Clone, Copy)]
    struct Allocation {
        base: u64,
        segment: u16,
        start_bus: u8,
        end_bus: u8,
        reserved: u32,
    }

    fn table(allocations: &[Allocation]) -> Vec<u8> {
        let mut bytes = vec![0u8; MCFG_HEADER_BYTES + allocations.len() * MCFG_ALLOCATION_BYTES];
        bytes[0..4].copy_from_slice(b"MCFG");
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8] = 1;
        for (index, allocation) in allocations.iter().enumerate() {
            let offset = MCFG_HEADER_BYTES + index * MCFG_ALLOCATION_BYTES;
            bytes[offset..offset + 8].copy_from_slice(&allocation.base.to_le_bytes());
            bytes[offset + 8..offset + 10].copy_from_slice(&allocation.segment.to_le_bytes());
            bytes[offset + 10] = allocation.start_bus;
            bytes[offset + 11] = allocation.end_bus;
            bytes[offset + 12..offset + 16].copy_from_slice(&allocation.reserved.to_le_bytes());
        }
        fix_checksum(&mut bytes);
        bytes
    }

    fn fix_checksum(bytes: &mut [u8]) {
        bytes[9] = 0;
        let sum = bytes
            .iter()
            .fold(0u8, |value, byte| value.wrapping_add(*byte));
        bytes[9] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn parses_multiple_segments_and_nonzero_start_bus() {
        let bytes = table(&[
            Allocation {
                base: 0x8000_0000,
                segment: 0,
                start_bus: 0,
                end_bus: 63,
                reserved: 0,
            },
            Allocation {
                base: 0x9000_0000,
                segment: 7,
                start_bus: 128,
                end_bus: 143,
                reserved: 0,
            },
        ]);
        let Ok(regions) = parse(&bytes) else {
            assert!(false, "valid MCFG should parse");
            return;
        };
        assert_eq!(regions.len(), 2);
        let Ok(expected) = EcamRegion::try_new(0x8000_0000, 0, 0, 63) else {
            assert!(false, "expected ECAM region should construct");
            return;
        };
        assert_eq!(regions[0], expected);
        assert_eq!(regions[1].segment(), 7);
        assert_eq!(regions[1].start_bus(), 128);
        assert_eq!(regions[1].end_bus(), 143);
    }

    #[test]
    fn rejects_signature_length_and_checksum_errors() {
        let allocation = Allocation {
            base: 0x8000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            reserved: 0,
        };
        let mut bad_signature = table(&[allocation]);
        bad_signature[0] = b'X';
        assert_eq!(parse(&bad_signature), Err(McfgError::BadSignature));

        let mut bad_length = table(&[allocation]);
        bad_length[4..8].copy_from_slice(&44u32.to_le_bytes());
        assert_eq!(parse(&bad_length), Err(McfgError::BadLength));

        let mut bad_checksum = table(&[allocation]);
        bad_checksum[8] ^= 1;
        assert_eq!(parse(&bad_checksum), Err(McfgError::BadChecksum));
    }

    #[test]
    fn rejects_reserved_fields() {
        let allocation = Allocation {
            base: 0x8000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            reserved: 1,
        };
        assert_eq!(
            parse(&table(&[allocation])),
            Err(McfgError::ReservedNonZero)
        );

        let mut header_reserved = table(&[]);
        header_reserved[36] = 1;
        fix_checksum(&mut header_reserved);
        assert_eq!(parse(&header_reserved), Err(McfgError::ReservedNonZero));
    }

    #[test]
    fn rejects_invalid_allocation_geometry() {
        let inverted = Allocation {
            base: 0x8000_0000,
            segment: 0,
            start_bus: 2,
            end_bus: 1,
            reserved: 0,
        };
        assert_eq!(
            parse(&table(&[inverted])),
            Err(McfgError::InvalidAllocation(ConfigError::InvalidBusRange))
        );

        let misaligned = Allocation {
            base: 0x8000_1000,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            reserved: 0,
        };
        assert_eq!(
            parse(&table(&[misaligned])),
            Err(McfgError::InvalidAllocation(ConfigError::MisalignedBase))
        );
    }

    #[test]
    fn rejects_bus_and_physical_overlaps() {
        let bus_overlap = table(&[
            Allocation {
                base: 0x8000_0000,
                segment: 0,
                start_bus: 0,
                end_bus: 15,
                reserved: 0,
            },
            Allocation {
                base: 0x9000_0000,
                segment: 0,
                start_bus: 15,
                end_bus: 31,
                reserved: 0,
            },
        ]);
        assert_eq!(parse(&bus_overlap), Err(McfgError::Overlap));

        let physical_overlap = table(&[
            Allocation {
                base: 0xA000_0000,
                segment: 1,
                start_bus: 0,
                end_bus: 15,
                reserved: 0,
            },
            Allocation {
                base: 0xA080_0000,
                segment: 2,
                start_bus: 0,
                end_bus: 15,
                reserved: 0,
            },
        ]);
        assert_eq!(parse(&physical_overlap), Err(McfgError::Overlap));
    }

    #[test]
    fn accepts_adjacent_nonoverlapping_windows() {
        let bytes = table(&[
            Allocation {
                base: 0xB000_0000,
                segment: 0,
                start_bus: 0,
                end_bus: 7,
                reserved: 0,
            },
            Allocation {
                base: 0xB080_0000,
                segment: 0,
                start_bus: 8,
                end_bus: 15,
                reserved: 0,
            },
        ]);
        assert_eq!(parse(&bytes).map(|regions| regions.len()), Ok(2));
    }

    #[test]
    fn rejects_excessive_allocation_count_before_decoding() {
        let allocation = Allocation {
            base: 0x8000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            reserved: 0,
        };
        let allocations = vec![allocation; MAX_MCFG_ALLOCATIONS + 1];
        assert_eq!(
            parse(&table(&allocations)),
            Err(McfgError::TooManyAllocations)
        );
    }
}

#[cfg(test)]
mod decode_all_tests {
    use super::*;
    use alloc::vec;

    fn table(allocations: &[(u64, u16, u8, u8)]) -> alloc::vec::Vec<u8> {
        let mut bytes = vec![0u8; MCFG_HEADER_BYTES + allocations.len() * MCFG_ALLOCATION_BYTES];
        bytes[0..4].copy_from_slice(b"MCFG");
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8] = 1;
        for (index, (base, segment, start_bus, end_bus)) in allocations.iter().enumerate() {
            let offset = MCFG_HEADER_BYTES + index * MCFG_ALLOCATION_BYTES;
            bytes[offset..offset + 8].copy_from_slice(&base.to_le_bytes());
            bytes[offset + 8..offset + 10].copy_from_slice(&segment.to_le_bytes());
            bytes[offset + 10] = *start_bus;
            bytes[offset + 11] = *end_bus;
        }
        bytes[9] = 0;
        let sum = bytes
            .iter()
            .fold(0u8, |value, byte| value.wrapping_add(*byte));
        bytes[9] = 0u8.wrapping_sub(sum);
        bytes
    }

    #[test]
    fn decode_all_matches_parse_exactly() {
        let bytes = table(&[(0x8000_0000, 0, 0, 63), (0x9000_0000, 7, 128, 143)]);
        let Ok((count, windows)) = decode_all(&bytes) else {
            assert!(false, "valid MCFG must decode");
            return;
        };
        assert_eq!(count, 2);
        let Ok(regions) = parse(&bytes) else {
            assert!(false, "valid MCFG must parse");
            return;
        };
        assert_eq!(&windows[..count], regions.as_slice());
    }

    #[test]
    fn decode_all_reports_identical_failures() {
        let bytes = table(&[(0x8000_0000, 0, 0, 63)]);
        // Corrupted payload byte breaks the checksum identically.
        let mut corrupted = bytes.clone();
        corrupted[50] ^= 0x01;
        assert_eq!(
            decode_all(&corrupted).map(|_| ()),
            parse(&corrupted).map(|_| ())
        );
        // Truncated table fails the same way.
        let truncated = &bytes[..bytes.len() - 4];
        assert_eq!(
            decode_all(truncated).map(|_| ()),
            parse(truncated).map(|_| ())
        );
    }

    #[test]
    fn decode_all_accepts_empty_allocation_set() {
        let bytes = table(&[]);
        let Ok((count, _)) = decode_all(&bytes) else {
            assert!(false, "zero-allocation MCFG must decode");
            return;
        };
        assert_eq!(count, 0);
    }
}
