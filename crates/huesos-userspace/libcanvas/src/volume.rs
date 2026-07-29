//! VolumeManager client helper.

use crate::{block::BlockDevice, Channel, ErrorCode, Result};
use huesos_abi::volume::{
    VolumeInfo, VolumeOp, VolumeRequest, VOLUME_INFO_BYTES, VOLUME_REQUEST_BYTES,
};

/// Opened system volume handle.
pub struct Volume {
    channel: Channel,
    next_request_id: u64,
}

impl Volume {
    /// Open the system volume through a DriverManager registry channel.
    pub fn open_system(registry: &Channel) -> Result<Self> {
        let mut buf = [0u8; 64];
        registry.write(b"open:volume:system")?;
        let channel = loop {
            match registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:volume:system:channel" => {
                    break Channel::from_handle(handle);
                }
                Ok((n, None)) if &buf[..n] == b"err:volume:system-unavailable" => {
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
        Ok(Self {
            channel,
            next_request_id: 1,
        })
    }

    /// Query volume information.
    pub fn info(&mut self) -> Result<VolumeInfo> {
        let request = VolumeRequest {
            op: VolumeOp::GetInfo,
            request_id: self.alloc_request_id(),
            start_block: 0,
            block_count: 0,
            flags: 0,
        };
        self.channel.write(&request.encode())?;
        let mut response = [0u8; VOLUME_INFO_BYTES];
        let n = self.channel.read_into_blocking(&mut response)?;
        if n != response.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        VolumeInfo::decode(&response).ok_or(ErrorCode::InvalidArgs)
    }

    /// Open a range-relative BlockDevice handle.
    pub fn open_block_range(&mut self, start_block: u64, block_count: u64) -> Result<BlockDevice> {
        let channel =
            self.open_block_channel(VolumeOp::OpenBlockRange, start_block, block_count)?;
        BlockDevice::from_channel(channel)
    }

    /// Open the first filesystem candidate BlockDevice handle.
    pub fn open_fs_candidate(&mut self) -> Result<BlockDevice> {
        let channel = self.open_block_channel(VolumeOp::OpenFsCandidate, 0, 0)?;
        BlockDevice::from_channel(channel)
    }

    fn open_block_channel(
        &mut self,
        op: VolumeOp,
        start_block: u64,
        block_count: u64,
    ) -> Result<Channel> {
        let request = VolumeRequest {
            op,
            request_id: self.alloc_request_id(),
            start_block,
            block_count,
            flags: 0,
        };
        let encoded = request.encode();
        if encoded.len() != VOLUME_REQUEST_BYTES {
            return Err(ErrorCode::Internal);
        }
        self.channel.write(&encoded)?;
        let expected = match op {
            VolumeOp::OpenBlockRange => b"service:volume:block-range:channel".as_slice(),
            VolumeOp::OpenFsCandidate => b"service:volume:fs-candidate:channel".as_slice(),
            VolumeOp::GetInfo => return Err(ErrorCode::InvalidArgs),
        };
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == expected => {
                    return Ok(Channel::from_handle(handle))
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if &buf[..n] == b"err:volume" => return Err(ErrorCode::InvalidArgs),
                Ok((_n, None)) => return Err(ErrorCode::InvalidArgs),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    crate::process::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn alloc_request_id(&mut self) -> u64 {
        let id = self.next_request_id.max(1);
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        id
    }
}
