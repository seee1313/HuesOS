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

/// Read-only view of an Hxblob content-addressed object.
///
/// There is deliberately no write path on this type. Blobs are named
/// by the hash of their contents, so a mutation would either change
/// the name or break it; callers that need different bytes create a
/// different blob.
pub struct HxfsBlobView {
    channel: Channel,
    hash: [u8; 32],
    size: u64,
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

    /// Open an existing blob by its 32-byte content hash.
    ///
    /// The service verifies the object against its hash before
    /// returning the handle, so a successful open means the bytes are
    /// intact, not merely present.
    pub fn open_blob(&self, hash: &[u8; 32]) -> Result<HxfsBlobView> {
        let request_id = write_native_request(
            &self.channel,
            abi::HxfsOp::OpenBlob,
            abi::HxfsHandleKind::BlobView,
            0,
            0,
            hash,
        )?;
        self.read_blob_view(*hash, request_id)
    }

    /// Store `data` as a content-addressed blob and return a view of
    /// it. Storing identical bytes twice yields the same blob rather
    /// than an error.
    pub fn create_blob(&self, data: &[u8]) -> Result<HxfsBlobView> {
        let request_id = write_native_request(
            &self.channel,
            abi::HxfsOp::CreateBlob,
            abi::HxfsHandleKind::None,
            0,
            0,
            data,
        )?;
        self.read_blob_view([0u8; 32], request_id)
    }

    fn read_blob_view(&self, hash: [u8; 32], request_id: u64) -> Result<HxfsBlobView> {
        read_blob_view_on(&self.channel, hash, request_id)
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

impl HxfsBlobView {
    /// Size of the blob in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Content hash the view was opened under.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Refresh size and hash from the service.
    pub fn info(&mut self) -> Result<u64> {
        write_native_request(
            &self.channel,
            abi::HxfsOp::GetInfo,
            abi::HxfsHandleKind::BlobView,
            0,
            0,
            &[],
        )?;
        let mut response = [0u8; NATIVE_MESSAGE_BYTES];
        let n = read_native_payload_bounded(&self.channel, &mut response)?;
        if n == 32 {
            self.hash.copy_from_slice(&response[..32]);
        }
        Ok(self.size)
    }

    /// Read at most `out.len()` bytes starting at `offset`.
    pub fn read_at<'a>(&self, offset: u64, out: &'a mut [u8]) -> Result<&'a [u8]> {
        let requested = out.len().min(abi::HXFS_MAX_INLINE_WRITE_BYTES);
        write_native_request(
            &self.channel,
            abi::HxfsOp::ReadAt,
            abi::HxfsHandleKind::BlobView,
            offset,
            requested as u64,
            &[],
        )?;
        let mut response = [0u8; NATIVE_MESSAGE_BYTES];
        let n = read_native_payload_bounded(&self.channel, &mut response)?;
        if n > out.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        out[..n].copy_from_slice(&response[..n]);
        Ok(&out[..n])
    }
}

/// Open a blob over a borrowed Hxfs client channel.
///
/// DriverManager keeps its Hxfs client channel inside its own service
/// state and cannot hand ownership to an [`Hxfs`], so the blob path is
/// also available as free functions over `&Channel`.
pub fn open_blob_on(channel: &Channel, hash: &[u8; 32]) -> Result<HxfsBlobView> {
    let request_id = write_native_request(
        channel,
        abi::HxfsOp::OpenBlob,
        abi::HxfsHandleKind::BlobView,
        0,
        0,
        hash,
    )?;
    read_blob_view_on(channel, *hash, request_id)
}

/// Send a CreateBlob request without waiting for the answer.
///
/// Returns the request id to poll with. Splitting send from receive
/// is what lets a caller with its own main loop wait across ticks
/// instead of spinning: re-sending the request on every tick creates
/// a fresh blob endpoint each time and exhausts the service's fixed
/// table, which is a self-inflicted NoSpace that looks like a
/// storage fault.
pub fn begin_create_blob_on(channel: &Channel, data: &[u8]) -> Result<u64> {
    write_native_request(
        channel,
        abi::HxfsOp::CreateBlob,
        abi::HxfsHandleKind::None,
        0,
        0,
        data,
    )
}

/// Send an OpenBlob request without waiting for the answer.
pub fn begin_open_blob_on(channel: &Channel, hash: &[u8; 32]) -> Result<u64> {
    write_native_request(
        channel,
        abi::HxfsOp::OpenBlob,
        abi::HxfsHandleKind::BlobView,
        0,
        0,
        hash,
    )
}

/// Check once for the answer to an already-sent blob request.
///
/// `Ok(None)` means "not yet" -- the caller should come back on its
/// next tick. Responses to other requests are discarded here, so a
/// slow answer to an abandoned request cannot be mistaken for this
/// one.
pub fn poll_blob_view_on(
    channel: &Channel,
    hash: [u8; 32],
    request_id: u64,
) -> Result<Option<HxfsBlobView>> {
    let mut buf = [0u8; NATIVE_MESSAGE_BYTES];
    loop {
        match channel.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) => {
                if n < abi::HXFS_RESPONSE_BYTES {
                    return Err(ErrorCode::InvalidArgs);
                }
                let Some(response) = decode_response(&buf[..abi::HXFS_RESPONSE_BYTES]) else {
                    return Err(ErrorCode::InvalidArgs);
                };
                if response.request_id != request_id {
                    drop(handle);
                    continue;
                }
                if response.status != abi::HxfsStatus::Ok {
                    return Err(status_to_error(response.status));
                }
                if response.handle_kind != abi::HxfsHandleKind::BlobView {
                    return Err(ErrorCode::WrongType);
                }
                if response.rights & abi::rights::WRITE != 0 {
                    return Err(ErrorCode::Internal);
                }
                let mut resolved = hash;
                if response.payload_len as usize == 32 {
                    let start = abi::HXFS_RESPONSE_BYTES;
                    let end = start + 32;
                    if n >= end {
                        resolved.copy_from_slice(&buf[start..end]);
                    }
                }
                return Ok(Some(HxfsBlobView {
                    channel: Channel::from_handle(handle),
                    hash: resolved,
                    size: response.value,
                }));
            }
            Ok((n, None)) => {
                if let Some(response) = decode_response(&buf[..n.min(abi::HXFS_RESPONSE_BYTES)]) {
                    if response.request_id != request_id {
                        continue;
                    }
                    return Err(status_to_error(response.status));
                }
                return Err(ErrorCode::InvalidArgs);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
}

/// Store a blob over a borrowed Hxfs client channel.
pub fn create_blob_on(channel: &Channel, data: &[u8]) -> Result<HxfsBlobView> {
    let request_id = write_native_request(
        channel,
        abi::HxfsOp::CreateBlob,
        abi::HxfsHandleKind::None,
        0,
        0,
        data,
    )?;
    read_blob_view_on(channel, [0u8; 32], request_id)
}

fn read_blob_view_on(
    channel: &Channel,
    hash: [u8; 32],
    request_id: u64,
) -> Result<HxfsBlobView> {
        let mut buf = [0u8; NATIVE_MESSAGE_BYTES];
        // Bounded wait, but deliberately a GENEROUS one, and the
        // caller must not retry on expiry.
        //
        // The native protocol has no request/response correlation:
        // `request_id` is a constant and nobody checks it. So a
        // caller that gives up on a request the service is still
        // going to answer leaves that answer queued, and the next
        // request on the same channel reads the stale one. With a
        // handle-carrying response that also means receiving a view
        // of the wrong object -- the failure looks like a storage
        // bug and is really a client bug.
        //
        // The budget therefore bounds a service that is genuinely
        // dead (so the supervisor cannot wedge), and expiry is
        // terminal for this channel rather than something to retry.
        let mut budget = 4_000_000u32;
        loop {
            budget = match budget.checked_sub(1) {
                Some(remaining) => remaining,
                None => return Err(ErrorCode::TimedOut),
            };
            match channel.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) => {
                    if n < abi::HXFS_RESPONSE_BYTES {
                        return Err(ErrorCode::InvalidArgs);
                    }
                    let Some(response) = decode_response(&buf[..abi::HXFS_RESPONSE_BYTES]) else {
                        return Err(ErrorCode::InvalidArgs);
                    };
                    if response.request_id != request_id {
                        // A response to an earlier request on this
                        // channel. Adopting it would hand back a view
                        // of the wrong object; drop the handle and
                        // keep waiting for ours.
                        drop(handle);
                        continue;
                    }
                    if response.status != abi::HxfsStatus::Ok {
                        return Err(status_to_error(response.status));
                    }
                    if response.handle_kind != abi::HxfsHandleKind::BlobView {
                        return Err(ErrorCode::WrongType);
                    }
                    // A blob view that arrived with write rights would
                    // mean the service disagrees with the ABI about
                    // blob immutability; refuse rather than paper over
                    // it.
                    if response.rights & abi::rights::WRITE != 0 {
                        return Err(ErrorCode::Internal);
                    }
                    // CreateBlob answers with the content hash in the
                    // payload, because only the service can compute
                    // it. OpenBlob already knows it (the caller asked
                    // by hash), so the request hash stands.
                    let mut resolved = hash;
                    let payload_len = response.payload_len as usize;
                    if payload_len == 32 {
                        let start = abi::HXFS_RESPONSE_BYTES;
                        let end = start + 32;
                        if n >= end {
                            resolved.copy_from_slice(&buf[start..end]);
                        }
                    }
                    return Ok(HxfsBlobView {
                        channel: Channel::from_handle(handle),
                        hash: resolved,
                        size: response.value,
                    });
                }
                Ok((n, None)) => {
                    if let Some(response) = decode_response(&buf[..n.min(abi::HXFS_RESPONSE_BYTES)])
                    {
                        if response.request_id != request_id {
                            continue;
                        }
                        return Err(status_to_error(response.status));
                    }
                    return Err(ErrorCode::InvalidArgs);
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    crate::process::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
}

/// Monotonic request id for the native protocol.
///
/// The service echoes `request_id` back, so a response whose id does
/// not match the request just sent is a leftover from an earlier
/// exchange on the same channel. Without this the two are
/// indistinguishable and a client that ever abandons a request reads
/// answers one message out of step from then on -- including handle
/// transfers, i.e. a view of the wrong object.
static NEXT_REQUEST_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

fn write_native_request(
    channel: &Channel,
    op: abi::HxfsOp,
    handle_kind: abi::HxfsHandleKind,
    arg0: u64,
    arg1: u64,
    payload: &[u8],
) -> Result<u64> {
    if payload.len() > abi::HXFS_MAX_INLINE_WRITE_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }
    let request_id = next_request_id();
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
        request_id,
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
    channel.write(&message[..abi::HXFS_REQUEST_BYTES + payload.len()])?;
    Ok(request_id)
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

/// Bounded variant of [`read_native_payload`].
///
/// The blob paths are reachable from DriverManager's boot path, where
/// a service that stops answering must surface as `TimedOut` rather
/// than parking the supervisor forever in a blocking read.
fn read_native_payload_bounded(channel: &Channel, out: &mut [u8]) -> Result<usize> {
    let mut message = [0u8; NATIVE_MESSAGE_BYTES];
    // Scheduler ticks, not wall time: generous enough for a device
    // read behind the service, short enough that a wedged service is
    // reported rather than waited on. One expiry is not a verdict --
    // the service may simply be busy with another client -- so retry
    // within a bounded budget and only then report TimedOut.
    // As in `read_blob_view_on`: keep waiting for the answer to the
    // request we already sent. Abandoning it would desynchronise the
    // channel, because responses carry no request correlation.
    let mut attempts = 4_000u32;
    let n = loop {
        match channel.read_into_timeout(&mut message, 1024) {
            Ok(n) => break n,
            Err(ErrorCode::TimedOut) | Err(ErrorCode::ShouldWait) => {
                attempts = match attempts.checked_sub(1) {
                    Some(remaining) => remaining,
                    None => return Err(ErrorCode::TimedOut),
                };
                crate::process::yield_now();
            }
            Err(error) => return Err(error),
        }
    };
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
        // Not `NotFound`: the object exists and the device read
        // succeeded, but its contents no longer hash to the name it
        // was requested under. Mapping it to a miss would let silent
        // corruption of an immutable object look routine.
        abi::HxfsStatus::CorruptObject => ErrorCode::Internal,
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
