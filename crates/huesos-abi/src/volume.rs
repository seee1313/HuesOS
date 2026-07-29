//! VolumeManager wire protocol.
//!
//! HuesOS volumes are handle-first views over block devices. Stage D is
//! deliberately NVMe/SSD focused: the initial system volume is the raw whole
//! NVMe namespace, with no rotational-media heuristics and no filesystem logic.

/// Size of an encoded volume request.
pub const VOLUME_REQUEST_BYTES: usize = 40;
/// Size of an encoded volume info response.
pub const VOLUME_INFO_BYTES: usize = 40;

/// Stable system volume id for the raw NVMe namespace.
pub const SYSTEM_VOLUME_ID: u64 = 1;

/// Volume kind: raw whole NVMe namespace.
pub const VOLUME_KIND_RAW_NVME_NAMESPACE: u32 = 1;

/// Volume flag: backed by NVMe.
pub const VOLUME_FLAG_NVME: u32 = 1 << 0;
/// Volume flag: optimized for SSD / non-rotational media.
pub const VOLUME_FLAG_SSD_OPTIMIZED: u32 = 1 << 1;
/// Volume flag: raw namespace, no partition table applied.
pub const VOLUME_FLAG_RAW_NAMESPACE: u32 = 1 << 2;
/// Volume flag: selected as the boot/system volume.
pub const VOLUME_FLAG_SYSTEM: u32 = 1 << 3;

/// Volume operation code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VolumeOp {
    /// Return [`VolumeInfo`].
    GetInfo = 0,
    /// Open a range-relative BlockDevice channel.
    OpenBlockRange = 1,
    /// Open the block range a filesystem should probe first.
    OpenFsCandidate = 2,
}

impl VolumeOp {
    /// Decode an operation byte.
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::GetInfo),
            1 => Some(Self::OpenBlockRange),
            2 => Some(Self::OpenFsCandidate),
            _ => None,
        }
    }
}

/// One VolumeManager request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeRequest {
    /// Operation.
    pub op: VolumeOp,
    /// Caller-chosen id for diagnostics/future async replies.
    pub request_id: u64,
    /// Starting block for [`VolumeOp::OpenBlockRange`].
    pub start_block: u64,
    /// Block count for [`VolumeOp::OpenBlockRange`].
    pub block_count: u64,
    /// Reserved for future rights/policy flags. Must be zero for now.
    pub flags: u32,
}

impl VolumeRequest {
    /// Encode to fixed wire format.
    pub fn encode(&self) -> [u8; VOLUME_REQUEST_BYTES] {
        let mut out = [0u8; VOLUME_REQUEST_BYTES];
        out[0] = self.op as u8;
        out[4..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.start_block.to_le_bytes());
        out[24..32].copy_from_slice(&self.block_count.to_le_bytes());
        out
    }

    /// Decode and validate from fixed wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != VOLUME_REQUEST_BYTES {
            return None;
        }
        let op = VolumeOp::from_byte(bytes[0])?;
        let flags = read_u32(bytes, 4)?;
        let request_id = read_u64(bytes, 8)?;
        let start_block = read_u64(bytes, 16)?;
        let block_count = read_u64(bytes, 24)?;
        if flags != 0 {
            return None;
        }
        match op {
            VolumeOp::GetInfo | VolumeOp::OpenFsCandidate => {
                if start_block != 0 || block_count != 0 {
                    return None;
                }
            }
            VolumeOp::OpenBlockRange => {
                if block_count == 0 {
                    return None;
                }
            }
        }
        Some(Self {
            op,
            request_id,
            start_block,
            block_count,
            flags,
        })
    }
}

/// Volume metadata returned by [`VolumeOp::GetInfo`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo {
    /// Stable volume id.
    pub volume_id: u64,
    /// Volume kind.
    pub kind: u32,
    /// Volume flags.
    pub flags: u32,
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Reserved for alignment/future use.
    pub reserved0: u32,
    /// Volume length in logical blocks.
    pub block_count: u64,
    /// Maximum request bytes forwarded to the backing NVMe service.
    pub max_request_bytes: u32,
}

impl VolumeInfo {
    /// Encode to fixed wire format.
    pub fn encode(&self) -> [u8; VOLUME_INFO_BYTES] {
        let mut out = [0u8; VOLUME_INFO_BYTES];
        out[0..8].copy_from_slice(&self.volume_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.kind.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..20].copy_from_slice(&self.block_size.to_le_bytes());
        out[20..24].copy_from_slice(&self.reserved0.to_le_bytes());
        out[24..32].copy_from_slice(&self.block_count.to_le_bytes());
        out[32..36].copy_from_slice(&self.max_request_bytes.to_le_bytes());
        out
    }

    /// Decode fixed wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != VOLUME_INFO_BYTES {
            return None;
        }
        Some(Self {
            volume_id: read_u64(bytes, 0)?,
            kind: read_u32(bytes, 8)?,
            flags: read_u32(bytes, 12)?,
            block_size: read_u32(bytes, 16)?,
            reserved0: read_u32(bytes, 20)?,
            block_count: read_u64(bytes, 24)?,
            max_request_bytes: read_u32(bytes, 32)?,
        })
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_request_round_trips() {
        let request = VolumeRequest {
            op: VolumeOp::OpenBlockRange,
            request_id: 9,
            start_block: 7,
            block_count: 11,
            flags: 0,
        };
        assert_eq!(VolumeRequest::decode(&request.encode()), Some(request));
    }

    #[test]
    fn rejects_bad_volume_requests() {
        assert_eq!(VolumeRequest::decode(&[0u8; 3]), None);
        let bad_range = VolumeRequest {
            op: VolumeOp::OpenBlockRange,
            request_id: 1,
            start_block: 0,
            block_count: 0,
            flags: 0,
        }
        .encode();
        assert_eq!(VolumeRequest::decode(&bad_range), None);
        let bad_info = VolumeRequest {
            op: VolumeOp::GetInfo,
            request_id: 1,
            start_block: 1,
            block_count: 0,
            flags: 0,
        }
        .encode();
        assert_eq!(VolumeRequest::decode(&bad_info), None);
    }

    #[test]
    fn volume_info_round_trips() {
        let info = VolumeInfo {
            volume_id: SYSTEM_VOLUME_ID,
            kind: VOLUME_KIND_RAW_NVME_NAMESPACE,
            flags: VOLUME_FLAG_NVME | VOLUME_FLAG_SSD_OPTIMIZED | VOLUME_FLAG_RAW_NAMESPACE,
            block_size: 4096,
            reserved0: 0,
            block_count: 1024,
            max_request_bytes: 1024 * 1024,
        };
        assert_eq!(VolumeInfo::decode(&info.encode()), Some(info));
    }
}
