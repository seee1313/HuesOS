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

    // Do not grant SMI_CMD. Also filter all candidate blocks below so a
    // malicious overlapping descriptor cannot re-authorize that port.
    let smi_cmd = read_u32(bytes, 48)?;
    let reset_io = if bytes.len() >= 128 && bytes[116] == 1 {
        let address = u64::from_le_bytes([
            bytes[120], bytes[121], bytes[122], bytes[123], bytes[124], bytes[125], bytes[126],
            bytes[127],
        ]);
        // Cover bit offset and declared access size as well as bit width;
        // unknown encodings fail closed rather than underestimating the range.
        let access_bytes = match bytes[119] {
            0 => 1,
            1 => 1,
            2 => 2,
            3 => 4,
            4 => 8,
            _ => return Err(PolicyError::InvalidFadt),
        };
        let described_bytes = (u64::from(bytes[117]) + u64::from(bytes[118])).div_ceil(8);
        Some((address, described_bytes.max(access_bytes)))
    } else {
        None
    };

    let pm1_event_len = bytes[88];
    add_grant(&mut grants, read_u32(bytes, 56)?, pm1_event_len, true, true);
    add_grant(&mut grants, read_u32(bytes, 60)?, pm1_event_len, true, true);

    let pm1_control_len = bytes[89];
    add_grant(
        &mut grants,
        read_u32(bytes, 64)?,
        pm1_control_len,
        true,
        true,
    );
    add_grant(
        &mut grants,
        read_u32(bytes, 68)?,
        pm1_control_len,
        true,
        true,
    );

    add_grant(&mut grants, read_u32(bytes, 72)?, bytes[90], true, true);
    add_grant(&mut grants, read_u32(bytes, 76)?, bytes[91], true, false);
    add_grant(&mut grants, read_u32(bytes, 80)?, bytes[92], true, true);
    add_grant(&mut grants, read_u32(bytes, 84)?, bytes[93], true, true);
    // Fixed architectural exclusions. Reject the entire overlapping candidate,
    // never silently split it. Dynamic DriverHost resource conflicts still
    // require independent lifetime-aware enforcement before AP-11 is enabled.
    const DENY: [(u64, u64); 7] = [
        (0xcf8, 8),
        (0x60, 1),
        (0x64, 1),
        (0x3f8, 8),
        (0x20, 2),
        (0xa0, 2),
        (0x40, 4),
    ];
    grants.retain(|grant| {
        let start = u64::from(grant.base);
        let end = start + u64::from(grant.length);
        let intersects = |base: u64, len: u64| {
            base.checked_add(len)
                .is_none_or(|stop| start < stop && base < end)
        };
        !DENY.iter().any(|&(base, len)| intersects(base, len))
            && (smi_cmd == 0 || !intersects(u64::from(smi_cmd), 1))
            && reset_io.is_none_or(|(base, len)| !intersects(base, len))
    });
    Ok(grants)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PolicyError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(PolicyError::InvalidFadt)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn add_grant(grants: &mut Vec<SystemIoGrant>, base: u32, length: u8, read: bool, write: bool) {
    if base == 0 || length == 0 || grants.len() == MAX_FADT_GRANTS {
        return;
    }
    let Ok(base) = u16::try_from(base) else {
        return;
    };
    if (base as u32)
        .checked_add(length as u32)
        .is_none_or(|end| end > 0x1_0000)
    {
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
        assert_eq!(grants.as_ref().map(|ranges| ranges.len()), Ok(3));
        assert!(grants
            .as_ref()
            .is_ok_and(|ranges| ranges.iter().all(|range| range.base != 0xb2)));
        assert!(grants.as_ref().is_ok_and(|ranges| {
            ranges
                .iter()
                .any(|range| range.base == 0x408 && range.read && !range.write)
        }));
        assert!(grants
            .as_ref()
            .is_ok_and(|ranges| { ranges.iter().all(|range| range.base != 0xffff) }));
    }

    #[test]
    fn rejects_fixed_denies_and_aliases_of_smi_and_reset() {
        for forbidden in [0xcf8u32, 0x60, 0x64, 0x3f8, 0x20, 0xa0, 0x40, 0xb2, 0x500] {
            let mut fadt = [0u8; 128];
            fadt[48..52].copy_from_slice(&0xb2u32.to_le_bytes());
            fadt[56..60].copy_from_slice(&forbidden.to_le_bytes());
            fadt[88] = 1;
            fadt[116] = 1; // SystemIO reset GAS
            fadt[117] = 8;
            fadt[120..128].copy_from_slice(&0x500u64.to_le_bytes());
            assert!(parse_fadt_system_io(&fadt).is_ok_and(|ranges| ranges.is_empty()));
        }
    }

    #[test]
    fn rejects_truncated_fadt() {
        assert_eq!(
            parse_fadt_system_io(&[0; 93]),
            Err(PolicyError::InvalidFadt)
        );
    }
}
