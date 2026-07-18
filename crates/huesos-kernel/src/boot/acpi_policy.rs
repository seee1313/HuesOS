//! Derive a minimal SystemIO allowlist from the uACPI-validated FADT.

use alloc::vec::Vec;
use huesos_object::SystemIoGrant;

const MAX_FADT_GRANTS: usize = 16;

/// Failure while deriving immutable broker policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// FADT was not installed by uACPI.
    MissingFadt,
    /// FADT was too short for its legacy block descriptors.
    InvalidFadt,
    /// Fixed-capacity policy storage could not be allocated.
    OutOfMemory,
}

/// Parse only fixed legacy SystemIO blocks from FADT/FACP.
///
/// Generic Address Structure fields and PCI configuration remain denied until
/// their address-space IDs and widths have dedicated validation.
pub fn fadt_system_io_grants() -> Result<Vec<SystemIoGrant>, PolicyError> {
    let table = huesos_uacpi::Table::find(b"FACP").map_err(|_| PolicyError::MissingFadt)?;
    let bytes = table.bytes().map_err(|_| PolicyError::InvalidFadt)?;
    parse_fadt_system_io(bytes)
}

fn parse_fadt_system_io(bytes: &[u8]) -> Result<Vec<SystemIoGrant>, PolicyError> {
    if bytes.len() < 94 {
        return Err(PolicyError::InvalidFadt);
    }
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(MAX_FADT_GRANTS)
        .map_err(|_| PolicyError::OutOfMemory)?;

    // SMI command: ACPI enable/disable bytes are written to this port.
    add_grant(&mut grants, read_u32(bytes, 48)?, 1, false, true);

    let pm1_event_len = bytes[88];
    add_grant(&mut grants, read_u32(bytes, 56)?, pm1_event_len, true, true);
    add_grant(&mut grants, read_u32(bytes, 60)?, pm1_event_len, true, true);

    let pm1_control_len = bytes[89];
    add_grant(&mut grants, read_u32(bytes, 64)?, pm1_control_len, true, true);
    add_grant(&mut grants, read_u32(bytes, 68)?, pm1_control_len, true, true);

    add_grant(&mut grants, read_u32(bytes, 72)?, bytes[90], true, true);
    add_grant(&mut grants, read_u32(bytes, 76)?, bytes[91], true, false);
    add_grant(&mut grants, read_u32(bytes, 80)?, bytes[92], true, true);
    add_grant(&mut grants, read_u32(bytes, 84)?, bytes[93], true, true);
    Ok(grants)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PolicyError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(PolicyError::InvalidFadt)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn add_grant(
    grants: &mut Vec<SystemIoGrant>,
    base: u32,
    length: u8,
    read: bool,
    write: bool,
) {
    if base == 0 || length == 0 || grants.len() == MAX_FADT_GRANTS {
        return;
    }
    let Ok(base) = u16::try_from(base) else {
        return;
    };
    if (base as u32).checked_add(length as u32).is_none_or(|end| end > 0x1_0000) {
        return;
    }
    grants.push(SystemIoGrant {
        base,
        length: length as u16,
        read,
        write,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_only_bounded_legacy_ranges() {
        let mut fadt = [0u8; 94];
        fadt[48..52].copy_from_slice(&0xb2u32.to_le_bytes());
        fadt[56..60].copy_from_slice(&0x400u32.to_le_bytes());
        fadt[64..68].copy_from_slice(&0x404u32.to_le_bytes());
        fadt[76..80].copy_from_slice(&0x408u32.to_le_bytes());
        fadt[80..84].copy_from_slice(&0xffffu32.to_le_bytes());
        fadt[88] = 4;
        fadt[89] = 2;
        fadt[91] = 4;
        fadt[92] = 2;

        let grants = parse_fadt_system_io(&fadt);
        assert_eq!(grants.as_ref().map(|ranges| ranges.len()), Ok(4));
        assert!(grants.as_ref().is_ok_and(|ranges| {
            ranges.iter().any(|range| range.base == 0x408 && range.read && !range.write)
        }));
        assert!(grants.as_ref().is_ok_and(|ranges| {
            ranges.iter().all(|range| range.base != 0xffff)
        }));
    }

    #[test]
    fn rejects_truncated_fadt() {
        assert_eq!(
            parse_fadt_system_io(&[0; 93]),
            Err(PolicyError::InvalidFadt)
        );
    }
}
