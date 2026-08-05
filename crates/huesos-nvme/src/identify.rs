//! Host-testable NVMe Identify data parsing.

/// Maximum request size used by the first HuesOS NVMe BlockDevice protocol.
pub const HUESOS_MAX_IO_BYTES: u32 = 1024 * 1024;
/// Identify Controller / Namespace data structure size.
pub const IDENTIFY_BYTES: usize = 4096;

/// Identify parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifyError {
    /// Identify buffer was shorter than 4096 bytes.
    BufferTooSmall,
    /// Controller reported an unsupported MDTS value.
    InvalidMdts,
    /// Namespace has no blocks.
    EmptyNamespace,
    /// Namespace selected an invalid LBA format.
    InvalidLbaFormat,
    /// Namespace LBA size is not supported by the first BlockDevice contract.
    UnsupportedLbaSize,
}

/// Parsed Identify Controller subset needed before queue setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerInfo {
    /// Raw MDTS value from Identify Controller byte 77.
    pub mdts_raw: u8,
    /// Effective controller MDTS in bytes before HuesOS protocol clamping.
    pub mdts_bytes: u32,
    /// Effective HuesOS max request size: `min(MDTS, 1 MiB)`, with MDTS=0
    /// treated as no controller-imposed limit.
    pub max_request_bytes: u32,
}

/// Parsed Identify Namespace subset exposed by the block layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceInfo {
    /// Namespace identifier used in NVMe commands.
    pub nsid: u32,
    /// Namespace size in logical blocks.
    pub block_count: u64,
    /// Logical block size in bytes.
    pub block_size: u32,
}

/// Parse Identify Controller data.
pub fn parse_controller(
    data: &[u8],
    controller_page_size: u32,
) -> Result<ControllerInfo, IdentifyError> {
    if data.len() < IDENTIFY_BYTES {
        return Err(IdentifyError::BufferTooSmall);
    }
    if controller_page_size == 0 || !controller_page_size.is_power_of_two() {
        return Err(IdentifyError::InvalidMdts);
    }
    let mdts_raw = data[77];
    let mdts_bytes = if mdts_raw == 0 {
        HUESOS_MAX_IO_BYTES
    } else if mdts_raw >= 31 {
        return Err(IdentifyError::InvalidMdts);
    } else {
        let multiplier = 1u32
            .checked_shl(mdts_raw as u32)
            .ok_or(IdentifyError::InvalidMdts)?;
        controller_page_size
            .checked_mul(multiplier)
            .ok_or(IdentifyError::InvalidMdts)?
    };
    Ok(ControllerInfo {
        mdts_raw,
        mdts_bytes,
        max_request_bytes: mdts_bytes.min(HUESOS_MAX_IO_BYTES),
    })
}

/// Parse Identify Namespace data for `nsid`.
///
/// Falls back to LBAF0 when the FLBAS-selected LBAF reports an unsupported
/// `LBADS`. This keeps the bring-up path working on QEMU / older firmware
/// that reports a non-zero `NLBAF` but leaves the default format descriptor
/// with `LBADS = 0` (reserved). The NVMe spec reserves `LBADS = 0`, so the
/// fallback still rejects genuinely empty namespaces; it only rescues
/// namespaces whose chosen LBAF slot is malformed while LBAF0 is sane.
pub fn parse_namespace(nsid: u32, data: &[u8]) -> Result<NamespaceInfo, IdentifyError> {
    if data.len() < IDENTIFY_BYTES {
        return Err(IdentifyError::BufferTooSmall);
    }
    let block_count = read_le_u64(data, 0).ok_or(IdentifyError::BufferTooSmall)?;
    if block_count == 0 {
        return Err(IdentifyError::EmptyNamespace);
    }
    let flbas = data[26];
    let lbaf_index = (flbas & 0x0f) as usize;
    if lbaf_index >= 16 {
        return Err(IdentifyError::InvalidLbaFormat);
    }
    let lbads = *data
        .get(128 + lbaf_index * 4 + 2)
        .ok_or(IdentifyError::BufferTooSmall)?;
    // NVMe LBAF entry layout: MS[0..2], LBADS[2], RP[3].
    if !(9..=16).contains(&lbads) {
        // LBAF0 fallback: if the FLBAS-selected format is unusable but
        // LBAF0 has a valid LBADS, prefer LBAF0. This matches the policy
        // already used by the BlockDevice bring-up code: the first
        // namespace is always served as LBAF0 regardless of FLBAS.
        if let Some(fallback) = data.get(128 + 2) {
            if (9..=16).contains(fallback) {
                let block_size = 1u32
                    .checked_shl(u32::from(*fallback))
                    .ok_or(IdentifyError::UnsupportedLbaSize)?;
                return Ok(NamespaceInfo {
                    nsid,
                    block_count,
                    block_size,
                });
            }
        }
        return Err(IdentifyError::UnsupportedLbaSize);
    }
    let block_size = 1u32
        .checked_shl(lbads as u32)
        .ok_or(IdentifyError::UnsupportedLbaSize)?;
    Ok(NamespaceInfo {
        nsid,
        block_count,
        block_size,
    })
}

fn read_le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_mdts_zero_uses_huesos_clamp() {
        let data = [0u8; IDENTIFY_BYTES];
        let info = parse_controller(&data, 4096);
        assert_eq!(
            info,
            Ok(ControllerInfo {
                mdts_raw: 0,
                mdts_bytes: HUESOS_MAX_IO_BYTES,
                max_request_bytes: HUESOS_MAX_IO_BYTES,
            })
        );
    }

    #[test]
    fn controller_mdts_is_clamped_to_one_mib() {
        let mut data = [0u8; IDENTIFY_BYTES];
        data[77] = 12; // 4096 * 2^12 = 16 MiB
        let info = parse_controller(&data, 4096);
        assert_eq!(
            info.map(|info| info.max_request_bytes),
            Ok(HUESOS_MAX_IO_BYTES)
        );
        assert_eq!(info.map(|info| info.mdts_bytes), Ok(16 * 1024 * 1024));
    }

    #[test]
    fn controller_mdts_below_one_mib_is_respected() {
        let mut data = [0u8; IDENTIFY_BYTES];
        data[77] = 4; // 4096 * 2^4 = 64 KiB
        let info = parse_controller(&data, 4096);
        assert_eq!(info.map(|info| info.max_request_bytes), Ok(64 * 1024));
    }

    #[test]
    fn controller_rejects_oversized_shift() {
        let mut data = [0u8; IDENTIFY_BYTES];
        data[77] = 31;
        assert_eq!(
            parse_controller(&data, 4096),
            Err(IdentifyError::InvalidMdts)
        );
    }

    #[test]
    fn namespace_parses_selected_lba_format() {
        let mut data = [0u8; IDENTIFY_BYTES];
        data[0..8].copy_from_slice(&4096u64.to_le_bytes());
        data[26] = 1;
        data[128 + 4 + 2] = 12; // LBAF1.LBADS: 4096-byte blocks
        assert_eq!(
            parse_namespace(7, &data),
            Ok(NamespaceInfo {
                nsid: 7,
                block_count: 4096,
                block_size: 4096,
            })
        );
    }

    #[test]
    fn namespace_rejects_empty_or_bad_lba() {
        let mut data = [0u8; IDENTIFY_BYTES];
        assert_eq!(
            parse_namespace(1, &data),
            Err(IdentifyError::EmptyNamespace)
        );
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        data[128 + 2] = 8;
        assert_eq!(
            parse_namespace(1, &data),
            Err(IdentifyError::UnsupportedLbaSize)
        );
    }

    #[test]
    fn namespace_falls_back_to_lbaf0_when_flbas_is_unusable() {
        // FLBAS selects LBAF1 (lbaf_index=1) but LBAF1.LBADS=0 (reserved).
        // LBAF0.LBADS=9 is valid. The parser must fall back to LBAF0.
        let mut data = [0u8; IDENTIFY_BYTES];
        data[0..8].copy_from_slice(&2048u64.to_le_bytes());
        data[26] = 1; // FLBAS -> LBAF1
                      // LBAF0.LBADS=9 (byte 130).
        data[128 + 2] = 9;
        // LBAF1.LBADS=0 (byte 134) — reserved, would reject without fallback.
        data[128 + 4 + 2] = 0;
        assert_eq!(
            parse_namespace(1, &data),
            Ok(NamespaceInfo {
                nsid: 1,
                block_count: 2048,
                block_size: 512,
            })
        );
    }

    #[test]
    fn namespace_rejects_when_both_flbas_and_lbaf0_are_unusable() {
        // FLBAS=LBAF0 with LBADS=0, and LBAF0 itself has LBADS=0. The
        // fallback cannot rescue this case: the namespace has no usable
        // format descriptor and we must still reject.
        let mut data = [0u8; IDENTIFY_BYTES];
        data[0..8].copy_from_slice(&1024u64.to_le_bytes());
        data[26] = 0; // FLBAS -> LBAF0
                      // LBAF0.LBADS stays 0 (reserved).
        assert_eq!(
            parse_namespace(1, &data),
            Err(IdentifyError::UnsupportedLbaSize)
        );
    }
}
