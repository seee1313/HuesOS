//! Hxfs read-only service client helper.

use crate::{Channel, ErrorCode, Result, Vmo};

/// Opened Hxfs service handle.
pub struct Hxfs {
    channel: Channel,
}

/// Hxfs directory handle.
pub struct HxfsDirectory {
    channel: Channel,
}

/// Hxfs file handle.
pub struct HxfsFile {
    channel: Channel,
}

impl Hxfs {
    /// Open Hxfs through DriverManager registry.
    pub fn open(registry: &Channel) -> Result<Self> {
        let mut buf = [0u8; 64];
        registry.write(b"open:hxfs")?;
        let channel = loop {
            match registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:channel" => {
                    break Channel::from_handle(handle);
                }
                Ok((n, None)) if &buf[..n] == b"err:hxfs-unavailable" => {
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

    /// Open the root directory.
    pub fn root(&self) -> Result<HxfsDirectory> {
        self.channel_to_dir(b"ROOT")
    }

    /// Open an absolute directory path.
    pub fn open_dir(&self, path: &str) -> Result<HxfsDirectory> {
        let mut request = [0u8; 320];
        let len = write_prefixed_path(&mut request, b"OPEN_DIR ", path)?;
        self.channel_to_dir(&request[..len])
    }

    /// Open an absolute file path.
    pub fn open_file(&self, path: &str) -> Result<HxfsFile> {
        let mut request = [0u8; 320];
        let len = write_prefixed_path(&mut request, b"OPEN_FILE ", path)?;
        self.channel_to_file(&request[..len])
    }

    fn channel_to_dir(&self, request: &[u8]) -> Result<HxfsDirectory> {
        self.channel.write(request)?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:dir:channel" => {
                    return Ok(HxfsDirectory {
                        channel: Channel::from_handle(handle),
                    });
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => {
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

    fn channel_to_file(&self, request: &[u8]) -> Result<HxfsFile> {
        self.channel.write(request)?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:file:channel" => {
                    return Ok(HxfsFile {
                        channel: Channel::from_handle(handle),
                    });
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => {
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

impl HxfsDirectory {
    /// List directory names into `out`.
    pub fn list<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        self.channel.write(b"LIST")?;
        let n = self.channel.read_into_blocking(out)?;
        Ok(&out[..n])
    }

    /// Open a child file by UTF-8 name.
    pub fn open_file(&self, name: &str) -> Result<HxfsFile> {
        let mut request = [0u8; 320];
        let len = write_prefixed_path(&mut request, b"OPEN_FILE ", name)?;
        self.channel.write(&request[..len])?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:file:channel" => {
                    return Ok(HxfsFile {
                        channel: Channel::from_handle(handle),
                    });
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => {
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

impl HxfsFile {
    /// Read small file contents inline into `out`.
    pub fn read<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8]> {
        self.channel.write(b"READ")?;
        let n = self.channel.read_into_blocking(out)?;
        if n >= 4 && &out[..4] == b"err:" {
            return Err(ErrorCode::InvalidArgs);
        }
        Ok(&out[..n])
    }

    /// Read file contents as a VMO handle.
    pub fn read_vmo(&self) -> Result<Vmo> {
        self.channel.write(b"READ_VMO")?;
        let mut buf = [0u8; 64];
        loop {
            match self.channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:file-vmo" => {
                    return Ok(Vmo::from_handle(handle));
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => {
                    return Err(ErrorCode::InvalidArgs);
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

fn write_prefixed_path(out: &mut [u8], prefix: &[u8], path: &str) -> Result<usize> {
    let bytes = path.as_bytes();
    let Some(total) = prefix.len().checked_add(bytes.len()) else {
        return Err(ErrorCode::InvalidArgs);
    };
    if total > out.len() {
        return Err(ErrorCode::InvalidArgs);
    }
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..total].copy_from_slice(bytes);
    Ok(total)
}
