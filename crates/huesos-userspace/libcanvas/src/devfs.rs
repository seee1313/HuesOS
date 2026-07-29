//! DevFS client helper.

use crate::{Channel, ErrorCode, Result, Volume};

/// Opened DevFS service.
pub struct DevFs {
    channel: Channel,
}

impl DevFs {
    /// Open DevFS through DriverManager registry.
    pub fn open(registry: &Channel) -> Result<Self> {
        let mut buf = [0u8; 64];
        registry.write(b"open:devfs")?;
        let channel = loop {
            match registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:devfs:channel" => {
                    break Channel::from_handle(handle);
                }
                Ok((n, None)) if &buf[..n] == b"err:devfs-unavailable" => {
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
        Ok(Self { channel })
    }

    /// List DevFS entries under `/dev`.
    pub fn list<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        self.channel.write(b"LIST /dev")?;
        let n = self.channel.read_into_blocking(out)?;
        Ok(&out[..n])
    }

    /// Open `/dev/block/system` as a Volume handle.
    pub fn open_system_volume(&self) -> Result<Volume> {
        self.channel.write(b"OPEN /dev/block/system")?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:volume:system:channel" => {
                    return Ok(Volume::from_channel(Channel::from_handle(handle)));
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if buf[..n].starts_with(b"err:devfs") => {
                    return Err(ErrorCode::NotFound);
                }
                Ok((_n, None)) => return Err(ErrorCode::InvalidArgs),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    crate::process::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
    }
}
