//! Native Hxfs handle-first service ABI.
//!
//! This protocol is the canonical request/response contract between Hxfs
//! clients and the isolated `hxfs-service`. Paths are only resolver payloads:
//! once an object is opened, all further work uses a typed handle id plus
//! rights bits. The wire format is fixed-size little-endian headers followed by
//! optional operation-specific payload bytes in the same Channel message.

/// Current Hxfs service protocol version.
pub const HXFS_PROTOCOL_VERSION: u16 = 1;
/// Fixed encoded request header length.
pub const HXFS_REQUEST_BYTES: usize = 64;
/// Fixed encoded response header length.
pub const HXFS_RESPONSE_BYTES: usize = 64;
/// Maximum UTF-8 resolver path bytes accepted inline by the v1 protocol.
pub const HXFS_MAX_PATH_BYTES: usize = 255;
/// Maximum UTF-8 single directory-entry name bytes accepted by the v1 protocol.
pub const HXFS_MAX_NAME_BYTES: usize = 255;
/// Maximum inline write payload bytes carried in one request message.
pub const HXFS_MAX_INLINE_WRITE_BYTES: usize = 4096;

/// Hxfs typed handle kind.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsHandleKind {
    /// No handle / root service request.
    None = 0,
    /// Virtual volume handle.
    Volume = 1,
    /// Directory handle.
    Directory = 2,
    /// File handle.
    File = 3,
    /// Snapshot management handle.
    Snapshot = 4,
    /// Hxblob immutable blob-view handle.
    BlobView = 5,
}

impl HxfsHandleKind {
    /// Decode a stable handle-kind tag.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Volume),
            2 => Some(Self::Directory),
            3 => Some(Self::File),
            4 => Some(Self::Snapshot),
            5 => Some(Self::BlobView),
            _ => None,
        }
    }
}

/// Hxfs operation code.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsOp {
    /// Query service/handle information.
    GetInfo = 0,
    /// Open the root directory of a volume.
    OpenRoot = 1,
    /// Resolve an absolute path or handle-relative child path.
    OpenPath = 2,
    /// Create a regular file below a directory handle.
    CreateFile = 3,
    /// Create a directory below a directory handle.
    Mkdir = 4,
    /// Create a path-level symbolic link.
    Symlink = 5,
    /// Rename/move an object atomically.
    Rename = 6,
    /// Remove a file, symlink, or empty directory.
    Unlink = 7,
    /// Truncate a file handle to `arg0` bytes.
    Truncate = 8,
    /// Write inline payload bytes at file offset `arg0`.
    WriteAt = 9,
    /// Durably flush one file handle's dirty data/metadata dependency.
    Fsync = 10,
    /// Publish a volume checkpoint for already flushed dirty state.
    Checkpoint = 11,
    /// Create a read-only snapshot of a virtual volume.
    CreateSnapshot = 12,
    /// Delete a snapshot descriptor.
    DeleteSnapshot = 13,
    /// Read file bytes into an inline response or service-provided VMO path.
    ReadAt = 14,
    /// List a directory handle lexicographically.
    ListDirectory = 15,
    /// Open an existing Hxblob object by content hash, yielding a
    /// [`HxfsHandleKind::BlobView`] handle.
    ///
    /// The payload is the 32-byte raw content hash. Blobs are
    /// content-addressed and immutable, so the handle carries read
    /// rights only; there is no blob equivalent of `WriteAt`.
    OpenBlob = 16,
    /// Store an inline payload as an Hxblob object, returning its
    /// content hash and a read handle for it.
    ///
    /// Storing an identical payload twice is not an error: the hash
    /// is the identity, so the second call returns the same blob.
    CreateBlob = 17,
}

impl HxfsOp {
    /// Decode a stable operation tag.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::GetInfo),
            1 => Some(Self::OpenRoot),
            2 => Some(Self::OpenPath),
            3 => Some(Self::CreateFile),
            4 => Some(Self::Mkdir),
            5 => Some(Self::Symlink),
            6 => Some(Self::Rename),
            7 => Some(Self::Unlink),
            8 => Some(Self::Truncate),
            9 => Some(Self::WriteAt),
            10 => Some(Self::Fsync),
            11 => Some(Self::Checkpoint),
            12 => Some(Self::CreateSnapshot),
            13 => Some(Self::DeleteSnapshot),
            14 => Some(Self::ReadAt),
            15 => Some(Self::ListDirectory),
            16 => Some(Self::OpenBlob),
            17 => Some(Self::CreateBlob),
            _ => None,
        }
    }
}

/// Hxfs response status.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// Request encoding, version, flags, handle kind, or payload length is invalid.
    Invalid = 1,
    /// Referenced object/path does not exist.
    NotFound = 2,
    /// Referenced object already exists.
    AlreadyExists = 3,
    /// Handle/object kind does not match the requested operation.
    WrongType = 4,
    /// Caller lacks the required handle rights.
    AccessDenied = 5,
    /// Filesystem needs journal replay or fsck before the operation can continue.
    NeedsRecovery = 6,
    /// Underlying BlockDevice or media I/O failed.
    IoError = 7,
    /// Filesystem is out of allocatable blocks or service request slots.
    NoSpace = 8,
    /// Operation is not supported by the mounted volume/policy.
    Unsupported = 9,
    /// Encrypted volume is unavailable because no valid key provider exists.
    EncryptedUnavailable = 10,
    /// A content-addressed object failed its integrity check: the
    /// bytes read back do not hash to the requested content hash.
    ///
    /// Distinct from [`Self::IoError`]: the device returned data
    /// successfully, and distinct from [`Self::NotFound`]: the blob
    /// exists. Collapsing this into either would let silent
    /// corruption of an immutable object look like a routine miss.
    CorruptObject = 11,
}

impl HxfsStatus {
    /// Decode a stable status tag.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Invalid),
            2 => Some(Self::NotFound),
            3 => Some(Self::AlreadyExists),
            4 => Some(Self::WrongType),
            5 => Some(Self::AccessDenied),
            6 => Some(Self::NeedsRecovery),
            7 => Some(Self::IoError),
            8 => Some(Self::NoSpace),
            9 => Some(Self::Unsupported),
            10 => Some(Self::EncryptedUnavailable),
            11 => Some(Self::CorruptObject),
            _ => None,
        }
    }
}

/// Hxfs handle rights bits.
pub mod rights {
    /// Read file data or directory entries.
    pub const READ: u64 = 1 << 0;
    /// Modify existing file contents/size.
    pub const WRITE: u64 = 1 << 1;
    /// Create children below a directory or create snapshots below a volume.
    pub const CREATE: u64 = 1 << 2;
    /// Rename/unlink children below a directory.
    pub const MODIFY_DIRECTORY: u64 = 1 << 3;
    /// Publish fsync/checkpoint durability barriers.
    pub const SYNC: u64 = 1 << 4;
    /// Manage snapshots.
    pub const SNAPSHOT: u64 = 1 << 5;
    /// Transfer the handle over Channel IPC.
    pub const TRANSFER: u64 = 1 << 6;
    /// Duplicate the handle with equal or reduced rights.
    pub const DUPLICATE: u64 = 1 << 7;
    /// Store new content-addressed objects through a volume handle.
    ///
    /// Separate from [`CREATE`]: a caller allowed to create files in
    /// its own directory is not automatically allowed to add objects
    /// to the volume-wide blob store, which is shared across
    /// packages and deduplicated by hash.
    pub const BLOB_CREATE: u64 = 1 << 8;
    /// All rights currently defined by the v1 Hxfs ABI.
    pub const ALL: u64 = READ
        | WRITE
        | CREATE
        | MODIFY_DIRECTORY
        | SYNC
        | SNAPSHOT
        | TRANSFER
        | DUPLICATE
        | BLOB_CREATE;
}

/// Request flags.
pub mod request_flags {
    /// Resolve `OpenPath` payload as an absolute path below the virtual volume root.
    pub const ABSOLUTE_PATH: u32 = 1 << 0;
    /// Request must not create an object if it already exists.
    pub const EXCLUSIVE_CREATE: u32 = 1 << 1;
    /// Operation accepts an inline payload immediately following the request header.
    pub const INLINE_PAYLOAD: u32 = 1 << 2;
    /// Do not follow the final path component if it is a symlink.
    pub const NOFOLLOW_FINAL_SYMLINK: u32 = 1 << 3;
    /// Stage B.4: caller requests the O_DIRECT bypass of the
    /// page cache. The MVP denies the flag: the page cache
    /// is not yet production-grade and the kernel-side
    /// direct-IO alignment path is not in place, so the
    /// request is rejected with [`HxfsStatus::Unsupported`]
    /// rather than silently falling back to a cached
    /// read/write. The bit value matches the Linux
    /// `O_DIRECT` bit (0x4000) so an unmodified Linux
    /// client can pass the flag through without a
    /// translation layer.
    ///
    /// See `docs/PRODUCTION_ROADMAP.md` Stage B.4 for the
    /// exit criterion.
    pub const O_DIRECT: u32 = 0x4000;
}

/// Response flags.
pub mod response_flags {
    /// Response is followed by inline payload bytes in the same Channel message.
    pub const INLINE_PAYLOAD: u32 = 1 << 0;
    /// Service transferred a typed handle in the same Channel message.
    pub const HANDLE_TRANSFERRED: u32 = 1 << 1;
    /// Operation dirtied state that still needs explicit fsync/checkpoint.
    pub const DIRTY: u32 = 1 << 2;
}

/// Fixed Hxfs request header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxfsRequest {
    /// Protocol version, currently [`HXFS_PROTOCOL_VERSION`].
    pub version: u16,
    /// Reserved; must be zero.
    pub reserved0: u16,
    /// Operation code.
    pub op: HxfsOp,
    /// Request flags.
    pub flags: u32,
    /// Client-selected id echoed by the response.
    pub request_id: u64,
    /// Service-local handle id. `0` means service root for operations that allow it.
    pub handle_id: u64,
    /// Kind expected by the client for `handle_id` or newly returned handle.
    pub handle_kind: HxfsHandleKind,
    /// Rights requested for a newly returned handle or required by an operation.
    pub rights: u64,
    /// Operation-specific argument. For `WriteAt`/`ReadAt`, this is byte offset.
    pub arg0: u64,
    /// Operation-specific argument. For `Truncate`, this is new size when `arg0` is unused.
    pub arg1: u64,
    /// Payload bytes following this header.
    pub payload_len: u32,
    /// Reserved; must be zero.
    pub reserved1: u32,
}

impl HxfsRequest {
    /// Encode the request as a fixed little-endian wire header.
    pub fn encode(self) -> [u8; HXFS_REQUEST_BYTES] {
        let mut out = [0u8; HXFS_REQUEST_BYTES];
        write_u16(&mut out, 0, self.version);
        write_u16(&mut out, 2, self.reserved0);
        write_u32(&mut out, 4, self.op as u32);
        write_u32(&mut out, 8, self.flags);
        write_u64(&mut out, 16, self.request_id);
        write_u64(&mut out, 24, self.handle_id);
        write_u32(&mut out, 32, self.handle_kind as u32);
        write_u64(&mut out, 40, self.rights);
        write_u64(&mut out, 48, self.arg0);
        write_u64(&mut out, 56, self.arg1);
        write_u32(&mut out, 12, self.payload_len);
        write_u32(&mut out, 36, self.reserved1);
        out
    }

    /// Decode and validate the fixed request header.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HXFS_REQUEST_BYTES {
            return None;
        }
        let version = read_u16(bytes, 0)?;
        let reserved0 = read_u16(bytes, 2)?;
        let op = HxfsOp::from_u32(read_u32(bytes, 4)?)?;
        let flags = read_u32(bytes, 8)?;
        let payload_len = read_u32(bytes, 12)?;
        let request_id = read_u64(bytes, 16)?;
        let handle_id = read_u64(bytes, 24)?;
        let handle_kind = HxfsHandleKind::from_u32(read_u32(bytes, 32)?)?;
        let reserved1 = read_u32(bytes, 36)?;
        let rights = read_u64(bytes, 40)?;
        let arg0 = read_u64(bytes, 48)?;
        let arg1 = read_u64(bytes, 56)?;
        if version != HXFS_PROTOCOL_VERSION || reserved0 != 0 || reserved1 != 0 {
            return None;
        }
        if rights & !rights::ALL != 0 {
            return None;
        }
        if payload_len as usize > HXFS_MAX_INLINE_WRITE_BYTES {
            return None;
        }
        Some(Self {
            version,
            reserved0,
            op,
            flags,
            request_id,
            handle_id,
            handle_kind,
            rights,
            arg0,
            arg1,
            payload_len,
            reserved1,
        })
    }
}

/// Fixed Hxfs response header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxfsResponse {
    /// Protocol version, currently [`HXFS_PROTOCOL_VERSION`].
    pub version: u16,
    /// Reserved; must be zero.
    pub reserved0: u16,
    /// Response status.
    pub status: HxfsStatus,
    /// Response flags.
    pub flags: u32,
    /// Request id echoed from [`HxfsRequest::request_id`].
    pub request_id: u64,
    /// Returned or affected handle id.
    pub handle_id: u64,
    /// Returned or affected handle kind.
    pub handle_kind: HxfsHandleKind,
    /// Rights on the returned handle.
    pub rights: u64,
    /// Object id, snapshot id, or other operation-specific stable id.
    pub object_id: u64,
    /// File size, bytes read/written, or operation-specific count.
    pub value: u64,
    /// Inline payload bytes following this header.
    pub payload_len: u32,
    /// Reserved; must be zero.
    pub reserved1: u32,
}

impl HxfsResponse {
    /// Encode the response as a fixed little-endian wire header.
    pub fn encode(self) -> [u8; HXFS_RESPONSE_BYTES] {
        let mut out = [0u8; HXFS_RESPONSE_BYTES];
        write_u16(&mut out, 0, self.version);
        write_u16(&mut out, 2, self.reserved0);
        write_u32(&mut out, 4, self.status as u32);
        write_u32(&mut out, 8, self.flags);
        write_u32(&mut out, 12, self.payload_len);
        write_u64(&mut out, 16, self.request_id);
        write_u64(&mut out, 24, self.handle_id);
        write_u32(&mut out, 32, self.handle_kind as u32);
        write_u32(&mut out, 36, self.reserved1);
        write_u64(&mut out, 40, self.rights);
        write_u64(&mut out, 48, self.object_id);
        write_u64(&mut out, 56, self.value);
        out
    }

    /// Decode and validate the fixed response header.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HXFS_RESPONSE_BYTES {
            return None;
        }
        let version = read_u16(bytes, 0)?;
        let reserved0 = read_u16(bytes, 2)?;
        let status = HxfsStatus::from_u32(read_u32(bytes, 4)?)?;
        let flags = read_u32(bytes, 8)?;
        let payload_len = read_u32(bytes, 12)?;
        let request_id = read_u64(bytes, 16)?;
        let handle_id = read_u64(bytes, 24)?;
        let handle_kind = HxfsHandleKind::from_u32(read_u32(bytes, 32)?)?;
        let reserved1 = read_u32(bytes, 36)?;
        let rights = read_u64(bytes, 40)?;
        let object_id = read_u64(bytes, 48)?;
        let value = read_u64(bytes, 56)?;
        if version != HXFS_PROTOCOL_VERSION || reserved0 != 0 || reserved1 != 0 {
            return None;
        }
        if rights & !rights::ALL != 0 {
            return None;
        }
        if payload_len as usize > HXFS_MAX_INLINE_WRITE_BYTES {
            return None;
        }
        Some(Self {
            version,
            reserved0,
            status,
            flags,
            request_id,
            handle_id,
            handle_kind,
            rights,
            object_id,
            value,
            payload_len,
            reserved1,
        })
    }
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
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
        let request = HxfsRequest {
            version: HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            op: HxfsOp::WriteAt,
            flags: request_flags::INLINE_PAYLOAD,
            request_id: 42,
            handle_id: 7,
            handle_kind: HxfsHandleKind::File,
            rights: rights::WRITE | rights::SYNC,
            arg0: 4096,
            arg1: 0,
            payload_len: 128,
            reserved1: 0,
        };
        let bytes = request.encode();
        assert_eq!(HxfsRequest::decode(&bytes), Some(request));
    }

    #[test]
    fn response_round_trips() {
        let response = HxfsResponse {
            version: HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            status: HxfsStatus::Ok,
            flags: response_flags::DIRTY,
            request_id: 42,
            handle_id: 9,
            handle_kind: HxfsHandleKind::File,
            rights: rights::READ | rights::WRITE,
            object_id: 123,
            value: 64,
            payload_len: 0,
            reserved1: 0,
        };
        let bytes = response.encode();
        assert_eq!(HxfsResponse::decode(&bytes), Some(response));
    }

    #[test]
    fn rejects_unknown_tags_and_wide_rights() {
        let mut request = HxfsRequest {
            version: HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            op: HxfsOp::GetInfo,
            flags: 0,
            request_id: 1,
            handle_id: 0,
            handle_kind: HxfsHandleKind::None,
            rights: rights::ALL,
            arg0: 0,
            arg1: 0,
            payload_len: 0,
            reserved1: 0,
        }
        .encode();
        request[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(HxfsRequest::decode(&request), None);

        request[4..8].copy_from_slice(&(HxfsOp::GetInfo as u32).to_le_bytes());
        request[40..48].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert_eq!(HxfsRequest::decode(&request), None);
    }

    #[test]
    fn rejects_bad_version_and_reserved_fields() {
        let mut response = HxfsResponse {
            version: HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            status: HxfsStatus::Ok,
            flags: 0,
            request_id: 1,
            handle_id: 0,
            handle_kind: HxfsHandleKind::None,
            rights: 0,
            object_id: 0,
            value: 0,
            payload_len: 0,
            reserved1: 0,
        }
        .encode();
        response[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(HxfsResponse::decode(&response), None);

        response[0..2].copy_from_slice(&HXFS_PROTOCOL_VERSION.to_le_bytes());
        response[36..40].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(HxfsResponse::decode(&response), None);
    }
}
