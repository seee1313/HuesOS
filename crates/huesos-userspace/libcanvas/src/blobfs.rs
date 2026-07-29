//! BlobFS client helper.

use crate::{Channel, ErrorCode, Result, Vmo};
use huesos_blobfs::{parse_hash_hex, BlobHash};

/// Opened read-only BlobFS service.
pub struct BlobFs {
    channel: Channel,
}

impl BlobFs {
    /// Open BlobFS through DriverManager registry.
    pub fn open(registry: &Channel) -> Result<Self> {
        let mut buf = [0u8; 64];
        registry.write(b"open:blobfs")?;
        let channel = loop {
            match registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:blobfs:channel" => {
                    break Channel::from_handle(handle);
                }
                Ok((n, None)) if &buf[..n] == b"err:blobfs-unavailable" => {
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

    /// Request a newline-separated hash listing.
    pub fn list<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        self.channel.write(b"LIST")?;
        let n = self.channel.read_into_blocking(out)?;
        Ok(&out[..n])
    }

    /// Open a blob by SHA-256 hash.
    pub fn open_blob(&self, hash: &BlobHash) -> Result<Vmo> {
        let mut request = [0u8; 69];
        request[..5].copy_from_slice(b"OPEN ");
        write_hash_hex(hash, &mut request[5..69]);
        self.channel.write(&request)?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:blobfs:blob-vmo" => {
                    return Ok(Vmo::from_handle(handle));
                }
                Ok((n, None)) if buf[..n].starts_with(b"err:blobfs") => {
                    return Err(ErrorCode::NotFound);
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => return Err(ErrorCode::InvalidArgs),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    crate::process::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Open a blob from a 64-byte hex digest.
    pub fn open_blob_hex(&self, hash_hex: &[u8]) -> Result<Vmo> {
        let Some(hash) = parse_hash_hex(hash_hex) else {
            return Err(ErrorCode::InvalidArgs);
        };
        self.open_blob(&hash)
    }
}

fn write_hash_hex(hash: &BlobHash, out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0usize;
    while i < hash.len() && i * 2 + 1 < out.len() {
        out[i * 2] = HEX[(hash[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(hash[i] & 0x0f) as usize];
        i += 1;
    }
}
