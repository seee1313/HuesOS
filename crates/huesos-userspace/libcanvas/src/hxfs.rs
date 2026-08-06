//! Hxfs service client helper.

use crate::{Channel, ErrorCode, Result, Vmo};
use huesos_abi::hxfs as abi;

const NATIVE_MESSAGE_BYTES: usize = abi::HXFS_RESPONSE_BYTES + abi::HXFS_MAX_INLINE_WRITE_BYTES;

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

    /// Create a directory by absolute path through the native Hxfs ABI.
    pub fn mkdir(&self, path: &str) -> Result<HxfsDirectory> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Mkdir,
            abi::HxfsHandleKind::Directory,
            0,
            0,
            path.as_bytes(),
        )?;
        Ok(HxfsDirectory {
            channel: read_native_handle(&self.channel, abi::HxfsHandleKind::Directory)?,
        })
    }

    /// Create an empty file by absolute path through the native Hxfs ABI.
    pub fn create_file(&self, path: &str) -> Result<HxfsFile> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::CreateFile,
            abi::HxfsHandleKind::File,
            0,
            0,
            path.as_bytes(),
        )?;
        Ok(HxfsFile {
            channel: read_native_handle(&self.channel, abi::HxfsHandleKind::File)?,
        })
    }

    /// Rename an object by absolute paths. The operation is durable after
    /// [`Self::checkpoint`] or a file/directory `fsync` publishes a checkpoint.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut payload = [0u8; abi::HXFS_MAX_INLINE_WRITE_BYTES];
        let len = write_two_strings(&mut payload, from, to)?;
        write_native_request(
            &self.channel,
            abi::HxfsOp::Rename,
            abi::HxfsHandleKind::None,
            0,
            0,
            &payload[..len],
        )?;
        read_native_status(&self.channel).map(|_| ())
    }

    /// Unlink an object by absolute path.
    pub fn unlink(&self, path: &str) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Unlink,
            abi::HxfsHandleKind::None,
            0,
            0,
            path.as_bytes(),
        )?;
        read_native_status(&self.channel).map(|_| ())
    }

    /// Publish a dirty Hxfs checkpoint explicitly.
    pub fn checkpoint(&self) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Checkpoint,
            abi::HxfsHandleKind::Volume,
            0,
            0,
            &[],
        )?;
        read_native_status(&self.channel).map(|_| ())
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

    /// Open a child directory by UTF-8 name through the native Hxfs ABI.
    pub fn open_dir(&self, name: &str) -> Result<HxfsDirectory> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::OpenPath,
            abi::HxfsHandleKind::Directory,
            0,
            0,
            name.as_bytes(),
        )?;
        Ok(HxfsDirectory {
            channel: read_native_handle(&self.channel, abi::HxfsHandleKind::Directory)?,
        })
    }

    /// Create a child directory by UTF-8 name through the native Hxfs ABI.
    pub fn mkdir(&self, name: &str) -> Result<HxfsDirectory> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Mkdir,
            abi::HxfsHandleKind::Directory,
            0,
            0,
            name.as_bytes(),
        )?;
        Ok(HxfsDirectory {
            channel: read_native_handle(&self.channel, abi::HxfsHandleKind::Directory)?,
        })
    }

    /// Create an empty child file by UTF-8 name through the native Hxfs ABI.
    pub fn create_file(&self, name: &str) -> Result<HxfsFile> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::CreateFile,
            abi::HxfsHandleKind::File,
            0,
            0,
            name.as_bytes(),
        )?;
        Ok(HxfsFile {
            channel: read_native_handle(&self.channel, abi::HxfsHandleKind::File)?,
        })
    }

    /// Rename one child inside this directory.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut payload = [0u8; abi::HXFS_MAX_INLINE_WRITE_BYTES];
        let len = write_two_strings(&mut payload, from, to)?;
        write_native_request(
            &self.channel,
            abi::HxfsOp::Rename,
            abi::HxfsHandleKind::None,
            0,
            0,
            &payload[..len],
        )?;
        read_native_status(&self.channel).map(|_| ())
    }

    /// Unlink one child from this directory.
    pub fn unlink(&self, name: &str) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Unlink,
            abi::HxfsHandleKind::None,
            0,
            0,
            name.as_bytes(),
        )?;
        read_native_status(&self.channel).map(|_| ())
    }

    /// Publish pending directory mutations.
    pub fn fsync(&self) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Fsync,
            abi::HxfsHandleKind::Directory,
            0,
            0,
            &[],
        )?;
        read_native_status(&self.channel).map(|_| ())
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

    /// Read at most `out.len()` bytes starting at `offset` through the native ABI.
    pub fn read_at<'a>(&self, offset: u64, out: &'a mut [u8]) -> Result<&'a [u8]> {
        let requested = out.len().min(abi::HXFS_MAX_INLINE_WRITE_BYTES);
        write_native_request(
            &self.channel,
            abi::HxfsOp::ReadAt,
            abi::HxfsHandleKind::File,
            offset,
            requested as u64,
            &[],
        )?;
        let mut response = [0u8; NATIVE_MESSAGE_BYTES];
        let n = read_native_payload(&self.channel, &mut response)?;
        if n > out.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        out[..n].copy_from_slice(&response[..n]);
        Ok(&out[..n])
    }

    /// Write one inline payload at `offset` through the native ABI.
    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::WriteAt,
            abi::HxfsHandleKind::File,
            offset,
            0,
            input,
        )?;
        let response = read_native_status(&self.channel)?;
        usize::try_from(response.value).map_err(|_| ErrorCode::InvalidArgs)
    }

    /// Truncate or sparsely extend this file.
    pub fn truncate(&self, size: u64) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Truncate,
            abi::HxfsHandleKind::File,
            size,
            0,
            &[],
        )?;
        read_native_status(&self.channel).map(|_| ())
    }

    /// Publish pending file mutations.
    pub fn fsync(&self) -> Result<()> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::Fsync,
            abi::HxfsHandleKind::File,
            0,
            0,
            &[],
        )?;
        read_native_status(&self.channel).map(|_| ())
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

fn write_native_request(
    channel: &Channel,
    op: abi::HxfsOp,
    handle_kind: abi::HxfsHandleKind,
    arg0: u64,
    arg1: u64,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > abi::HXFS_MAX_INLINE_WRITE_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }
    let payload_len = payload.len() as u32;
    let request = abi::HxfsRequest {
        version: abi::HXFS_PROTOCOL_VERSION,
        reserved0: 0,
        op,
        flags: if payload.is_empty() {
            0
        } else {
            abi::request_flags::INLINE_PAYLOAD
        },
        request_id: 1,
        handle_id: 0,
        handle_kind,
        rights: abi::rights::ALL,
        arg0,
        arg1,
        payload_len,
        reserved1: 0,
    }
    .encode();
    let mut message = [0u8; NATIVE_MESSAGE_BYTES];
    message[..abi::HXFS_REQUEST_BYTES].copy_from_slice(&request);
    message[abi::HXFS_REQUEST_BYTES..abi::HXFS_REQUEST_BYTES + payload.len()]
        .copy_from_slice(payload);
    channel.write(&message[..abi::HXFS_REQUEST_BYTES + payload.len()])
}

fn read_native_handle(channel: &Channel, expected_kind: abi::HxfsHandleKind) -> Result<Channel> {
    let mut buf = [0u8; abi::HXFS_RESPONSE_BYTES];
    loop {
        match channel.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) => {
                let Some(response) = decode_response(&buf[..n]) else {
                    drop(handle);
                    return Err(ErrorCode::InvalidArgs);
                };
                if response.status != abi::HxfsStatus::Ok {
                    drop(handle);
                    return Err(status_to_error(response.status));
                }
                if response.handle_kind != expected_kind {
                    drop(handle);
                    return Err(ErrorCode::WrongType);
                }
                return Ok(Channel::from_handle(handle));
            }
            Ok((n, None)) => {
                if let Some(response) = decode_response(&buf[..n]) {
                    return Err(status_to_error(response.status));
                }
                return Err(ErrorCode::InvalidArgs);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => crate::process::yield_now(),
            Err(error) => return Err(error),
        }
    }
}

fn read_native_status(channel: &Channel) -> Result<abi::HxfsResponse> {
    let mut buf = [0u8; abi::HXFS_RESPONSE_BYTES];
    let n = channel.read_into_blocking(&mut buf)?;
    let Some(response) = decode_response(&buf[..n]) else {
        return Err(ErrorCode::InvalidArgs);
    };
    if response.status == abi::HxfsStatus::Ok {
        return Ok(response);
    }
    Err(status_to_error(response.status))
}

fn read_native_payload(channel: &Channel, out: &mut [u8]) -> Result<usize> {
    let mut message = [0u8; NATIVE_MESSAGE_BYTES];
    let n = channel.read_into_blocking(&mut message)?;
    if n < abi::HXFS_RESPONSE_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }
    let Some(response) = decode_response(&message[..abi::HXFS_RESPONSE_BYTES]) else {
        return Err(ErrorCode::InvalidArgs);
    };
    if response.status != abi::HxfsStatus::Ok {
        return Err(status_to_error(response.status));
    }
    let payload_len = response.payload_len as usize;
    if n != abi::HXFS_RESPONSE_BYTES + payload_len || payload_len > out.len() {
        return Err(ErrorCode::InvalidArgs);
    }
    out[..payload_len].copy_from_slice(
        &message[abi::HXFS_RESPONSE_BYTES..abi::HXFS_RESPONSE_BYTES + payload_len],
    );
    Ok(payload_len)
}

fn decode_response(bytes: &[u8]) -> Option<abi::HxfsResponse> {
    if bytes.len() != abi::HXFS_RESPONSE_BYTES {
        return None;
    }
    abi::HxfsResponse::decode(bytes)
}

fn status_to_error(status: abi::HxfsStatus) -> ErrorCode {
    match status {
        abi::HxfsStatus::Ok => ErrorCode::Internal,
        abi::HxfsStatus::Invalid => ErrorCode::InvalidArgs,
        abi::HxfsStatus::NotFound => ErrorCode::NotFound,
        abi::HxfsStatus::AlreadyExists => ErrorCode::InvalidArgs,
        abi::HxfsStatus::WrongType => ErrorCode::WrongType,
        abi::HxfsStatus::AccessDenied => ErrorCode::AccessDenied,
        abi::HxfsStatus::NeedsRecovery => ErrorCode::Busy,
        abi::HxfsStatus::IoError => ErrorCode::Internal,
        abi::HxfsStatus::NoSpace => ErrorCode::NoMemory,
        abi::HxfsStatus::Unsupported => ErrorCode::NotSupported,
        abi::HxfsStatus::EncryptedUnavailable => ErrorCode::AccessDenied,
    }
}

fn write_two_strings(out: &mut [u8], left: &str, right: &str) -> Result<usize> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let Some(with_nul) = left.len().checked_add(1) else {
        return Err(ErrorCode::InvalidArgs);
    };
    let Some(total) = with_nul.checked_add(right.len()) else {
        return Err(ErrorCode::InvalidArgs);
    };
    if total > out.len() || left.is_empty() || right.is_empty() {
        return Err(ErrorCode::InvalidArgs);
    }
    out[..left.len()].copy_from_slice(left);
    out[left.len()] = 0;
    out[left.len() + 1..total].copy_from_slice(right);
    Ok(total)
}
