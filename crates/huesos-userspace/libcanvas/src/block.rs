//! Async BlockDevice client helper.
//!
//! The wire protocol is Channel submissions plus Port completions. This helper
//! keeps the early tools synchronous on top of that async contract.

use crate::{Channel, ErrorCode, Port, Result, Vmo};
use huesos_abi::block::{
    decode_completion_data, AsyncBlockInfo, AsyncBlockOp, AsyncBlockRequest, AsyncBlockStatus,
    ASYNC_INFO_RESPONSE_BYTES,
};
use huesos_abi::{rights, PORT_PACKET_BLOCK_COMPLETION};

const BUFFER_ID: u32 = 1;
const DEFAULT_NAMESPACE_ID: u32 = 1;

/// Opened NVMe BlockDevice service channel.
pub struct BlockDevice {
    channel: Channel,
    completion: Port,
    next_request_id: u64,
}

impl BlockDevice {
    /// Open the NVMe BlockDevice through a DriverManager registry channel.
    pub fn open_nvme(registry: &Channel) -> Result<Self> {
        let mut buf = [0u8; 64];
        registry.write(b"open:block:nvme")?;
        let channel = loop {
            match registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:block:nvme:channel" => {
                    break Channel::from_handle(handle);
                }
                Ok((n, None)) if &buf[..n] == b"err:block:nvme-unavailable" => {
                    return Err(ErrorCode::ShouldWait);
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => return Err(ErrorCode::InvalidArgs),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    crate::process::yield_now();
                }
                Err(error) => return Err(error),
            }
        };
        let completion = Port::create()?;
        channel
            .write_handle(
                b"block:completion-port",
                completion.handle().duplicate(rights::SAME_RIGHTS)?,
            )
            .map_err(|(error, _handle)| error)?;
        Ok(Self {
            channel,
            completion,
            next_request_id: 1,
        })
    }

    /// Query namespace/device information.
    pub fn info(&mut self) -> Result<AsyncBlockInfo> {
        let request_id = self.alloc_request_id();
        let request = AsyncBlockRequest {
            op: AsyncBlockOp::Info,
            request_id,
            namespace_id: DEFAULT_NAMESPACE_ID,
            lba: 0,
            block_count: 0,
            buffer_id: 0,
        };
        self.channel.write(&request.encode())?;
        self.wait_ok(request_id)?;
        let mut bytes = [0u8; ASYNC_INFO_RESPONSE_BYTES];
        let n = self.channel.read_into_blocking(&mut bytes)?;
        if n != bytes.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        AsyncBlockInfo::decode(&bytes).ok_or(ErrorCode::InvalidArgs)
    }

    /// Read blocks into `out`.
    pub fn read_blocks(&mut self, lba: u64, block_count: u32, out: &mut [u8]) -> Result<()> {
        let request_id = self.alloc_request_id();
        let vmo = Vmo::create(out.len() as u64)?;
        self.register_buffer(BUFFER_ID, &vmo)?;
        let request = AsyncBlockRequest {
            op: AsyncBlockOp::Read,
            request_id,
            namespace_id: DEFAULT_NAMESPACE_ID,
            lba,
            block_count,
            buffer_id: BUFFER_ID,
        };
        self.channel.write(&request.encode())?;
        self.wait_ok(request_id)?;
        let copied = vmo.read(0, out)?;
        if copied != out.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        Ok(())
    }

    /// Write blocks from `input`.
    pub fn write_blocks(&mut self, lba: u64, block_count: u32, input: &[u8]) -> Result<()> {
        let request_id = self.alloc_request_id();
        let vmo = Vmo::create(input.len() as u64)?;
        if vmo.write(0, input)? != input.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        self.register_buffer(BUFFER_ID, &vmo)?;
        let request = AsyncBlockRequest {
            op: AsyncBlockOp::Write,
            request_id,
            namespace_id: DEFAULT_NAMESPACE_ID,
            lba,
            block_count,
            buffer_id: BUFFER_ID,
        };
        self.channel.write(&request.encode())?;
        self.wait_ok(request_id)
    }

    /// Flush volatile write cache.
    pub fn flush(&mut self) -> Result<()> {
        let request_id = self.alloc_request_id();
        let request = AsyncBlockRequest {
            op: AsyncBlockOp::Flush,
            request_id,
            namespace_id: DEFAULT_NAMESPACE_ID,
            lba: 0,
            block_count: 0,
            buffer_id: 0,
        };
        self.channel.write(&request.encode())?;
        self.wait_ok(request_id)
    }

    fn alloc_request_id(&mut self) -> u64 {
        let id = self.next_request_id.max(1);
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        id
    }

    fn register_buffer(&self, buffer_id: u32, vmo: &Vmo) -> Result<()> {
        let duplicate = vmo.duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?;
        let mut label = [0u8; 32];
        let len = format_buffer_label(&mut label, buffer_id);
        self.channel
            .write_handle(&label[..len], duplicate.into_handle())
            .map_err(|(error, _handle)| error)
    }

    fn wait_ok(&self, request_id: u64) -> Result<()> {
        loop {
            let packet = self.completion.read_blocking()?;
            if packet.packet_type != PORT_PACKET_BLOCK_COMPLETION {
                continue;
            }
            let Some((completed_id, status, _bytes, _nvme_status)) =
                decode_completion_data(packet.data)
            else {
                return Err(ErrorCode::InvalidArgs);
            };
            if completed_id != request_id {
                continue;
            }
            return match status {
                AsyncBlockStatus::Ok => Ok(()),
                AsyncBlockStatus::InvalidArgs => Err(ErrorCode::InvalidArgs),
                AsyncBlockStatus::IoError => Err(ErrorCode::Internal),
                AsyncBlockStatus::Timeout => Err(ErrorCode::TimedOut),
                AsyncBlockStatus::NoResources => Err(ErrorCode::NoMemory),
            };
        }
    }
}

fn format_buffer_label(out: &mut [u8], id: u32) -> usize {
    let prefix = b"block:buffer:0x";
    let mut len = prefix.len().min(out.len());
    out[..len].copy_from_slice(&prefix[..len]);
    let mut tmp = [0u8; 8];
    let mut value = id;
    let mut idx = tmp.len();
    if value == 0 {
        idx -= 1;
        tmp[idx] = b'0';
    }
    while value != 0 {
        idx -= 1;
        let nibble = (value & 0xf) as u8;
        tmp[idx] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        value >>= 4;
    }
    for &byte in &tmp[idx..] {
        if len >= out.len() {
            break;
        }
        out[len] = byte;
        len += 1;
    }
    len
}
