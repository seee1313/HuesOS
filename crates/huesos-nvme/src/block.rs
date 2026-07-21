//! Block device abstraction and the block-service wire protocol.
//!
//! The NVMe [`Controller`] implements [`BlockDevice`] (read/write/flush/info by
//! logical block). A ring-3 DriverHost exposes this over a Channel using the
//! small request/response wire format defined here ([`encode_request`],
//! [`decode_request`], [`encode_response`], [`decode_response`]); a future
//! FileSystemService / VFS mount consumes that service (the broader #7 goal).
//! The protocol encoding is host-tested; the Channel transport is on-target.

use alloc::vec::Vec;
use crate::controller::{Controller, NvmeError};
use crate::transport::NvmeTransport;

/// Static information about a block device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    /// Block (LBA) size in bytes.
    pub block_size: u32,
    /// Number of addressable blocks.
    pub block_count: u64,
}

/// Block-service operations (wire opcode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockOp {
    /// Read `count` blocks at `lba`.
    Read = 0,
    /// Write `count` blocks at `lba`.
    Write = 1,
    /// Flush volatile writes.
    Flush = 2,
    /// Query [`BlockInfo`].
    Info = 3,
}

impl BlockOp {
    /// Decode an opcode byte.
    pub fn from_byte(b: u8) -> Option<BlockOp> {
        match b {
            0 => Some(BlockOp::Read),
            1 => Some(BlockOp::Write),
            2 => Some(BlockOp::Flush),
            3 => Some(BlockOp::Info),
            _ => None,
        }
    }
}

/// A synchronous block device.
pub trait BlockDevice {
    /// Device geometry.
    fn info(&mut self) -> BlockInfo;
    /// Read `count` blocks starting at `lba` into `buf` (count * block_size bytes).
    fn read_blocks(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), NvmeError>;
    /// Write `count` blocks starting at `lba` from `buf`.
    fn write_blocks(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), NvmeError>;
    /// Flush.
    fn flush(&mut self) -> Result<(), NvmeError>;
}

impl<T: NvmeTransport> BlockDevice for Controller<T> {
    fn info(&mut self) -> BlockInfo {
        BlockInfo {
            block_size: self.lba_size(),
            block_count: self.namespace_size(),
        }
    }
    fn read_blocks(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), NvmeError> {
        self.read(lba, count, buf)
    }
    fn write_blocks(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), NvmeError> {
        self.write(lba, count, buf)
    }
    fn flush(&mut self) -> Result<(), NvmeError> {
        Controller::flush(self)
    }
}

// --- wire protocol ---
//
// Request:  [op:u8][lba:u64 LE][count:u16 LE][data: count*block_size bytes (Write only)]
// Response: [status:u32 LE][ payload ]
//   Read  payload: data bytes
//   Info  payload: [block_size:u32 LE][block_count:u64 LE]
//   Flush/Write payload: empty

/// Header size of an encoded request (op + lba + count).
pub const REQUEST_HEADER: usize = 1 + 8 + 2;

/// Encode a block request. `data` is the write payload (empty for Read/Flush/Info).
pub fn encode_request(op: BlockOp, lba: u64, count: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(REQUEST_HEADER + data.len());
    v.push(op as u8);
    v.extend_from_slice(&lba.to_le_bytes());
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// A decoded block request. `data` borrows the write payload (empty unless Write).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRequest<'a> {
    /// Operation.
    pub op: BlockOp,
    /// Starting LBA.
    pub lba: u64,
    /// Block count.
    pub count: u16,
    /// Write payload (empty for non-Write ops).
    pub data: &'a [u8],
}

/// Decode a block request. Returns `None` on a malformed/truncated message.
pub fn decode_request(msg: &[u8]) -> Option<DecodedRequest<'_>> {
    if msg.len() < REQUEST_HEADER {
        return None;
    }
    let op = BlockOp::from_byte(msg[0])?;
    let lba = u64::from_le_bytes([msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8]]);
    let count = u16::from_le_bytes([msg[9], msg[10]]);
    let data = &msg[REQUEST_HEADER..];
    Some(DecodedRequest { op, lba, count, data })
}

/// Encode a block response. `payload` is the read data or the Info body.
pub fn encode_response(status: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&status.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// Encode the Info response payload from a [`BlockInfo`].
pub fn encode_info(info: &BlockInfo) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&info.block_size.to_le_bytes());
    v.extend_from_slice(&info.block_count.to_le_bytes());
    v
}

/// Decode an Info response payload.
pub fn decode_info(payload: &[u8]) -> Option<BlockInfo> {
    if payload.len() < 12 {
        return None;
    }
    let block_size = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let block_count =
        u64::from_le_bytes([payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]]);
    Some(BlockInfo { block_size, block_count })
}

/// Decode a response status word.
pub fn decode_status(msg: &[u8]) -> Option<u32> {
    if msg.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockNvme;
    use alloc::vec;

    fn init_controller() -> Controller<MockNvme> {
        let mock = MockNvme::new(1 << 21, 2048, 9);
        let mut c = Controller::new(mock, 0, 1 << 21);
        assert!(c.init().is_ok());
        c
    }

    #[test]
    fn block_device_info() {
        let mut c = init_controller();
        let info = BlockDevice::info(&mut c);
        assert_eq!(info.block_size, 512);
        assert_eq!(info.block_count, 2048);
    }

    #[test]
    fn block_device_read_write() {
        let mut c = init_controller();
        let mut data = vec![0u8; 512];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        assert!(BlockDevice::write_blocks(&mut c, 7, 1, &data).is_ok());
        let mut read = vec![0u8; 512];
        assert!(BlockDevice::read_blocks(&mut c, 7, 1, &mut read).is_ok());
        assert_eq!(read, data);
        assert!(BlockDevice::flush(&mut c).is_ok());
    }

    #[test]
    fn request_round_trips() {
        let payload = [1u8, 2, 3, 4];
        let msg = encode_request(BlockOp::Write, 0x1234, 2, &payload);
        let d = decode_request(&msg);
        assert!(d.is_some());
        if let Some(d) = d {
            assert_eq!(d.op, BlockOp::Write);
            assert_eq!(d.lba, 0x1234);
            assert_eq!(d.count, 2);
            assert_eq!(d.data, &payload);
        }
    }

    #[test]
    fn request_read_has_empty_payload() {
        let msg = encode_request(BlockOp::Read, 99, 1, &[]);
        let d = decode_request(&msg);
        assert!(d.is_some());
        if let Some(d) = d {
            assert_eq!(d.op, BlockOp::Read);
            assert!(d.data.is_empty());
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_request(&[0u8; 5]).is_none());
        assert!(decode_request(&[9u8; REQUEST_HEADER]).is_none()); // bad opcode
    }

    #[test]
    fn info_response_round_trips() {
        let info = BlockInfo { block_size: 512, block_count: 1_000_000 };
        let payload = encode_info(&info);
        let resp = encode_response(0, &payload);
        assert_eq!(decode_status(&resp), Some(0));
        assert_eq!(decode_info(&resp[4..]), Some(info));
    }
}
