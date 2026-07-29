//! Async BlockDevice wire protocol shared by DriverHosts and clients.
//!
//! Submission travels over a Channel as fixed-size records. Completion is a
//! `PortPacket` whose `data` array carries `(request_id, status, bytes, nvme_status)`.
//! The data path uses driver-managed DMA/shared-buffer identifiers rather than
//! embedding block payloads in the control message.

/// Size of an encoded async block request.
pub const ASYNC_REQUEST_BYTES: usize = 32;

/// Size of an encoded async block info response.
pub const ASYNC_INFO_RESPONSE_BYTES: usize = 24;

/// Async block operation code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AsyncBlockOp {
    /// Read blocks into a registered buffer.
    Read = 0,
    /// Write blocks from a registered buffer.
    Write = 1,
    /// Flush volatile media state.
    Flush = 2,
    /// Query namespace/device info.
    Info = 3,
}

impl AsyncBlockOp {
    /// Decode an operation byte.
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Flush),
            3 => Some(Self::Info),
            _ => None,
        }
    }
}

/// Completion status for the async block protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AsyncBlockStatus {
    /// Request completed successfully.
    Ok = 0,
    /// Request was malformed.
    InvalidArgs = 1,
    /// Device or namespace returned an I/O error.
    IoError = 2,
    /// Request timed out.
    Timeout = 3,
    /// Queue or buffer resources are exhausted.
    NoResources = 4,
}

impl AsyncBlockStatus {
    /// Decode a completion status.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidArgs),
            2 => Some(Self::IoError),
            3 => Some(Self::Timeout),
            4 => Some(Self::NoResources),
            _ => None,
        }
    }
}

/// One async block request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsyncBlockRequest {
    /// Operation.
    pub op: AsyncBlockOp,
    /// Caller-chosen request id echoed in the completion packet.
    pub request_id: u64,
    /// NVMe namespace id.
    pub namespace_id: u32,
    /// Starting logical block address.
    pub lba: u64,
    /// Number of logical blocks.
    pub block_count: u32,
    /// Driver-managed DMA/shared-buffer slot id.
    pub buffer_id: u32,
}

impl AsyncBlockRequest {
    /// Encode to the fixed wire format.
    pub fn encode(&self) -> [u8; ASYNC_REQUEST_BYTES] {
        let mut out = [0u8; ASYNC_REQUEST_BYTES];
        out[0] = self.op as u8;
        out[4..12].copy_from_slice(&self.request_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.namespace_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.lba.to_le_bytes());
        out[24..28].copy_from_slice(&self.block_count.to_le_bytes());
        out[28..32].copy_from_slice(&self.buffer_id.to_le_bytes());
        out
    }

    /// Decode from the fixed wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ASYNC_REQUEST_BYTES {
            return None;
        }
        let op = AsyncBlockOp::from_byte(bytes[0])?;
        let request_id = read_u64(bytes, 4)?;
        let namespace_id = read_u32(bytes, 12)?;
        let lba = read_u64(bytes, 16)?;
        let block_count = read_u32(bytes, 24)?;
        let buffer_id = read_u32(bytes, 28)?;
        match op {
            AsyncBlockOp::Read | AsyncBlockOp::Write if block_count == 0 => return None,
            AsyncBlockOp::Flush | AsyncBlockOp::Info if block_count != 0 || lba != 0 => {
                return None
            }
            AsyncBlockOp::Read | AsyncBlockOp::Write | AsyncBlockOp::Flush | AsyncBlockOp::Info => {
            }
        }
        Some(Self {
            op,
            request_id,
            namespace_id,
            lba,
            block_count,
            buffer_id,
        })
    }
}

/// Fixed response payload for an [`AsyncBlockOp::Info`] request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsyncBlockInfo {
    /// NVMe namespace identifier.
    pub namespace_id: u32,
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Namespace size in logical blocks.
    pub block_count: u64,
    /// Maximum request size accepted by this service.
    pub max_request_bytes: u32,
}

impl AsyncBlockInfo {
    /// Encode to the fixed wire format.
    pub fn encode(&self) -> [u8; ASYNC_INFO_RESPONSE_BYTES] {
        let mut out = [0u8; ASYNC_INFO_RESPONSE_BYTES];
        out[0..4].copy_from_slice(&self.namespace_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.block_size.to_le_bytes());
        out[8..16].copy_from_slice(&self.block_count.to_le_bytes());
        out[16..20].copy_from_slice(&self.max_request_bytes.to_le_bytes());
        out
    }

    /// Decode from the fixed wire format.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ASYNC_INFO_RESPONSE_BYTES {
            return None;
        }
        Some(Self {
            namespace_id: read_u32(bytes, 0)?,
            block_size: read_u32(bytes, 4)?,
            block_count: read_u64(bytes, 8)?,
            max_request_bytes: read_u32(bytes, 16)?,
        })
    }
}

/// Build the PortPacket data payload for a completion.
pub fn completion_data(
    request_id: u64,
    status: AsyncBlockStatus,
    bytes_transferred: u64,
    nvme_status: u16,
) -> [u64; 4] {
    [
        request_id,
        status as u64,
        bytes_transferred,
        u64::from(nvme_status),
    ]
}

/// Decode a completion data payload.
pub fn decode_completion_data(data: [u64; 4]) -> Option<(u64, AsyncBlockStatus, u64, u16)> {
    let status = AsyncBlockStatus::from_u64(data[1])?;
    let nvme_status = u16::try_from(data[3]).ok()?;
    Some((data[0], status, data[2], nvme_status))
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
    fn request_round_trips() {
        let req = AsyncBlockRequest {
            op: AsyncBlockOp::Read,
            request_id: 42,
            namespace_id: 1,
            lba: 99,
            block_count: 8,
            buffer_id: 3,
        };
        assert_eq!(AsyncBlockRequest::decode(&req.encode()), Some(req));
    }

    #[test]
    fn rejects_malformed_requests() {
        assert_eq!(AsyncBlockRequest::decode(&[0u8; 3]), None);
        let mut zero_count = AsyncBlockRequest {
            op: AsyncBlockOp::Write,
            request_id: 1,
            namespace_id: 1,
            lba: 0,
            block_count: 0,
            buffer_id: 0,
        }
        .encode();
        assert_eq!(AsyncBlockRequest::decode(&zero_count), None);
        zero_count[0] = 9;
        assert_eq!(AsyncBlockRequest::decode(&zero_count), None);
    }

    #[test]
    fn flush_has_no_lba_or_count() {
        let req = AsyncBlockRequest {
            op: AsyncBlockOp::Flush,
            request_id: 7,
            namespace_id: 1,
            lba: 0,
            block_count: 0,
            buffer_id: 0,
        };
        assert_eq!(AsyncBlockRequest::decode(&req.encode()), Some(req));
        let bad = AsyncBlockRequest { lba: 1, ..req }.encode();
        assert_eq!(AsyncBlockRequest::decode(&bad), None);
    }

    #[test]
    fn rejects_unknown_completion_status_or_wide_nvme_status() {
        assert_eq!(decode_completion_data([1, 99, 0, 0]), None);
        assert_eq!(
            decode_completion_data([1, 0, 0, u64::from(u16::MAX) + 1]),
            None
        );
    }

    #[test]
    fn completion_payload_round_trips() {
        let data = completion_data(55, AsyncBlockStatus::IoError, 4096, 0x1234);
        assert_eq!(
            decode_completion_data(data),
            Some((55, AsyncBlockStatus::IoError, 4096, 0x1234))
        );
    }

    #[test]
    fn info_response_round_trips() {
        let info = AsyncBlockInfo {
            namespace_id: 1,
            block_size: 4096,
            block_count: 1024,
            max_request_bytes: 1024 * 1024,
        };
        assert_eq!(AsyncBlockInfo::decode(&info.encode()), Some(info));
    }
}
