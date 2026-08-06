//! Hxfs parser, recovery, and host-testable mutable foundations.
//!
//! The read path validates metadata CRC32C, parses a checkpoint, volume table,
//! object table, directory entries, and extent tables, then reads ordinary files
//! by ObjectId or path. Format v2 adds explicit feature flags and journal replay
//! state so a mutable userspace service can refuse unsafe mounts until recovery
//! is performed.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

pub mod alloc_tree;
pub mod allocator;
pub mod cache_policy;
pub mod compression;
pub mod crc32c;
pub mod crypto;
pub mod fixed_writer;
pub mod format;
pub mod fsck;
pub mod gpt;
pub mod hxblob;
pub mod hxblob_tree;
pub mod io_policy;
pub mod observability;
pub mod page_cache;
pub mod quota;
pub mod quota_tree;
pub mod reader;
pub mod recovery;
pub mod ref_tree;
pub mod scrub;
pub mod security_policy;
pub mod volume_topology;
#[cfg(any(test, feature = "writer"))]
pub mod writer;

use crate::crc32c::metadata_crc32c;
use crate::format::*;
use crate::reader::BlockReader;

/// Hxfs parser/read failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsError {
    /// Underlying storage rejected a read.
    Io,
    /// Caller-provided buffer was too small.
    BufferTooSmall,
    /// Requested data is outside the image/filesystem.
    OutOfRange,
    /// Metadata block checksum failed.
    BadChecksum,
    /// Metadata block type/self-lba/owner validation failed.
    BadBlock,
    /// Format GUID/version/block size is unsupported.
    UnsupportedFormat,
    /// Volume is encrypted (system volume has [`VOLUME_FLAG_ENCRYPTED`]
    /// set or a non-zero `encryption_policy_id`) but the mount-time
    /// gate has no key context. The caller must supply an
    /// `encryption_policies` table (or a [`crypto::CryptoKeyHandle`]
    /// in future revisions) that contains a descriptor for the
    /// volume's `encryption_policy_id`, and the key provider must
    /// be available. See [`Hxfs::mount_with_keys`].
    EncryptedVolumeKeyUnavailable,
    /// The volume's on-disk `encryption_policy_id` does not match
    /// any record in the caller-supplied `encryption_policies`
    /// table. The table must be built from the same root store /
    /// checkpoint the volume is mounted from; a mismatch usually
    /// means the caller is looking at a stale checkpoint copy.
    EncryptedPolicyUnknown,
    /// The encryption policy descriptor resolved from the
    /// volume's `encryption_policy_id` failed
    /// [`crypto::validate_for_mount`] (unsupported algorithm, wrong
    /// data-unit size, or the key provider is offline). The mount
    /// cannot proceed.
    EncryptedPolicyInvalid,
    /// Metadata tree/table is malformed.
    BadTree,
    /// Path or object was not found.
    NotFound,
    /// Requested object has a different type.
    WrongType,
    /// Path bytes are not valid UTF-8.
    BadName,
    /// Root store is in Recovering state and needs journal replay before mount.
    NeedsRecovery,
    /// Journal descriptor range or replay record is malformed.
    BadJournal,
    /// Mutation requested an object that already exists.
    AlreadyExists,
    /// Mutation would exceed a fixed-capacity or media-space limit.
    NoSpace,
    /// Mutation requested removing a non-empty directory.
    DirectoryNotEmpty,
    /// Operation is not supported by the current fixed-capacity stage.
    Unsupported,
    /// Compression codec rejected the on-disk payload. The
    /// extent has been marked bad and the read is aborted.
    Compression,
}

/// Mounted read-only Hxfs instance.
pub struct Hxfs<R: BlockReader> {
    reader: R,
    superblock: Superblock,
    checkpoint: Checkpoint,
    system_volume: VolumeDescriptor,
    /// Resolved encryption policy for this volume, or `None` for
    /// plain (unencrypted) volumes. Resolved at mount time from
    /// the caller-supplied encryption policy table; an encrypted
    /// volume that fails to resolve is rejected at mount with
    /// one of the [`HxfsError::Encrypted*`] variants.
    encryption: Option<crypto::EncryptionPolicy>,
    /// Caller-supplied per-volume compression policy table. An
    /// object whose `compression_policy_id` is non-zero is
    /// resolved through this table at read time; an object whose
    /// id is zero falls back to the system volume's
    /// `compression_policy_id`. The field is empty for callers
    /// that never set a non-plain volume policy.
    compression_policies: Vec<compression::CompressionPolicy>,
    /// Per-volume page cache for decompressed 4 KiB blocks
    /// (A.4 of PRODUCTION_ROADMAP.md). The cache is FIFO with
    /// a 16 MiB / 4096-entry working set; invalidation is by
    /// physical extent LBA on every write that touches an
    /// extent. The field is always present (the cache is
    /// cheap to construct) and the public read path consults
    /// it on every call so the cache always pays its way on
    /// the second read of the same block.
    page_cache: page_cache::PageCache,
}

impl<R: BlockReader> Hxfs<R> {
    /// Mount a read-only Hxfs instance, treating the volume as
    /// unencrypted. Convenience wrapper around
    /// [`Hxfs::mount_with_keys`] for callers that know the
    /// volume is plain.
    pub fn mount(reader: R) -> Result<Self, HxfsError> {
        Self::mount_with_keys(reader, &[])
    }

    /// Mount a read-only Hxfs instance, resolving the system
    /// volume's encryption policy from `encryption_policies`.
    ///
    /// If the volume's superblock indicates a non-clean state or
    /// a non-empty journal range, the mount returns
    /// `HxfsError::NeedsRecovery` without touching the data
    /// path. Callers that want to drive the replay themselves
    /// should first inspect the superblock via
    /// [`Hxfs::needs_recovery`] and, if it returns `true`,
    /// invoke `crate::recovery::replay_journal` before retrying
    /// the mount.
    ///
    /// If the volume's superblock indicates a non-clean state or
    /// a non-empty journal range, the mount returns
    /// [] without touching the data
    /// path. Callers that want to drive the replay themselves
    /// should first inspect the superblock via
    /// [] and, if it returns `true`,
    /// invoke [] before
    /// retrying the mount.
    ///
    /// An empty `encryption_policies` table is valid only for
    /// volumes that are not encrypted: a plain volume mounts
    /// successfully and [`Hxfs::encryption`] returns `None`. A
    /// volume that has the [`VOLUME_FLAG_ENCRYPTED`] flag set or
    /// a non-zero `encryption_policy_id` is rejected with one of:
    ///
    /// - [`HxfsError::EncryptedPolicyUnknown`] if the policy id
    ///   does not appear in the table (and is not the canonical
    ///   plain id 0);
    /// - [`HxfsError::EncryptedPolicyInvalid`] if the resolved
    ///   policy fails [`crypto::validate_for_mount`] (unsupported
    ///   algorithm, wrong data-unit size, or no key provider).
    ///
    /// The `key_provider_available` flag is `true` for the MVP
    /// because the software AES-XTS engine linked into this
    /// crate is the key provider; a future revision with a
    /// real TPM will thread the predicate through here.
    pub fn mount_with_keys(
        mut reader: R,
        encryption_policies: &[crypto::EncryptionPolicy],
    ) -> Result<Self, HxfsError> {
        let superblock = read_superblock(&mut reader, 0)?;
        if superblock.root_state != ROOT_STATE_CLEAN
            || superblock.journal_start_lba != 0
            || superblock.journal_end_lba != 0
        {
            return Err(HxfsError::NeedsRecovery);
        }
        let checkpoint = read_checkpoint(
            &mut reader,
            superblock.checkpoint_lba,
            superblock.sequence_number,
        )?;
        let system_volume = read_system_volume(&mut reader, checkpoint)?;
        let encryption = resolve_mount_encryption(&system_volume, encryption_policies)?;
        Ok(Self {
            reader,
            superblock,
            checkpoint,
            system_volume,
            encryption,
            compression_policies: Vec::new(),
            page_cache: page_cache::PageCache::new(),
        })
    }

    /// Mount a read-only Hxfs instance with both encryption
    /// and compression policy tables. The compression table
    /// is consulted for every object whose
    /// `compression_policy_id` is non-zero; see
    /// [`Hxfs::read_file`] for the wire-up.
    pub fn mount_with_policies(
        reader: R,
        encryption_policies: &[crypto::EncryptionPolicy],
        compression_policies: &[compression::CompressionPolicy],
    ) -> Result<Self, HxfsError> {
        let mut mounted = Self::mount_with_keys(reader, encryption_policies)?;
        mounted.compression_policies = compression_policies.to_vec();
        Ok(mounted)
    }

    /// Resolved encryption policy for this volume, or `None` for
    /// plain volumes. The policy is the same descriptor that
    /// would be used by the on-target encryption path; readers
    /// can inspect it for diagnostics without holding a key.
    pub const fn encryption(&self) -> Option<&crypto::EncryptionPolicy> {
        self.encryption.as_ref()
    }

    /// Superblock chosen at mount.
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Checkpoint chosen at mount.
    pub const fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    /// System volume descriptor.
    pub const fn volume_info(&self) -> VolumeDescriptor {
        self.system_volume
    }
}

/// Resolve a system volume's encryption policy for mount.
///
/// Returns `Ok(None)` for a plain volume (flag clear, policy id 0).
/// Returns `Ok(Some(policy))` once the policy has been resolved and
/// validated. Returns one of the [`HxfsError::Encrypted*`] variants
/// when the volume is encrypted but the caller-supplied table is
/// missing the descriptor, the descriptor fails validation, or the
/// key provider is offline.
fn resolve_mount_encryption(
    system_volume: &VolumeDescriptor,
    encryption_policies: &[crypto::EncryptionPolicy],
) -> Result<Option<crypto::EncryptionPolicy>, HxfsError> {
    let encrypted = system_volume.flags & VOLUME_FLAG_ENCRYPTED != 0;
    let policy_id = system_volume.encryption_policy_id;
    if !encrypted && policy_id == 0 {
        return Ok(None);
    }
    let resolved =
        crypto::resolve_encryption_policy(policy_id, encryption_policies).map_err(|error| {
            match error {
                crypto::CryptoError::UnknownPolicy => HxfsError::EncryptedPolicyUnknown,
                other => {
                    let _ = other;
                    HxfsError::EncryptedPolicyUnknown
                }
            }
        })?;
    crypto::validate_for_mount(resolved, true).map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
    Ok(Some(resolved))
}

/// Resolve the compression policy that applies to a given
/// object: the object's per-record policy if non-zero,
/// otherwise the system volume's per-volume policy. Returns
/// `None` for the plain (no-compression) algorithm; a non-None
/// result means the read path will call
/// [`compression::decompress_block`] on every 4 KiB block of
/// the extent.
fn resolve_compression_for_object(
    system_volume: &VolumeDescriptor,
    compression_policies: &[compression::CompressionPolicy],
    object: ObjectDescriptor,
) -> Option<compression::CompressionPolicy> {
    let policy_id = if object.compression_policy_id != 0 {
        object.compression_policy_id
    } else {
        system_volume.compression_policy_id
    };
    if policy_id == 0 {
        return None;
    }
    let resolved = compression::resolve_compression_policy(policy_id, compression_policies).ok()?;
    if resolved.algorithm == compression::COMPRESSION_NONE {
        return None;
    }
    Some(resolved)
}

/// Report whether a superblock indicates the volume needs
/// journal replay before mount.
///
/// The mount path itself refuses to mount an unclean volume
/// with [`HxfsError::NeedsRecovery`]. Operators that want to
/// drive the replay explicitly (e.g. a recovery tool, or the
/// hxfs-service production wiring in [`PRODUCTION_ROADMAP.md`]
/// Stage A.6) can call this helper *before* [`Hxfs::mount_with_keys`]
/// to decide whether to invoke
/// [`crate::recovery::replay_journal`] first.
///
/// A return value of `true` means **at least one of** the
/// following is true:
///
/// - the superblock's `root_state` is not
///   [`crate::format::ROOT_STATE_CLEAN`];
/// - the journal range is non-empty
///   (`journal_start_lba != 0 || journal_end_lba != 0`).
///
/// Both are required because a clean root state with a
/// non-zero journal range is a known-bad journal-image marker
/// (the previous run crashed before the journal was finalised);
/// a recovering root state with a zero journal range is a
/// stuck-recovery marker.
pub const fn needs_recovery(superblock: &Superblock) -> bool {
    superblock.root_state != ROOT_STATE_CLEAN
        || superblock.journal_start_lba != 0
        || superblock.journal_end_lba != 0
}

impl<R: BlockReader> Hxfs<R> {
    /// Root directory handle for the system volume.
    pub const fn root_directory(&self) -> DirectoryHandle {
        DirectoryHandle {
            object_id: self.system_volume.root_object_id,
        }
    }

    /// Open an absolute directory path inside the system volume.
    pub fn open_directory_path(&mut self, path: &str) -> Result<DirectoryHandle, HxfsError> {
        if path == "/" {
            return Ok(self.root_directory());
        }
        let mut current = self.system_volume.root_object_id;
        let mut rest = if let Some(stripped) = path.as_bytes().strip_prefix(b"/") {
            stripped
        } else {
            return Err(HxfsError::BadName);
        };
        loop {
            let slash = rest.iter().position(|&byte| byte == b'/');
            let (component, tail) = match slash {
                Some(pos) => (&rest[..pos], &rest[pos + 1..]),
                None => (rest, &[][..]),
            };
            if component.is_empty() || component.len() > MAX_NAME_BYTES {
                return Err(HxfsError::BadName);
            }
            let dir = self.find_object(current)?;
            if dir.object_type != OBJECT_TYPE_DIRECTORY {
                return Err(HxfsError::WrongType);
            }
            let next = self.lookup_in_directory(dir, component)?;
            let object = self.find_object(next)?;
            if object.object_type != OBJECT_TYPE_DIRECTORY {
                return Err(HxfsError::WrongType);
            }
            if tail.is_empty() {
                return Ok(DirectoryHandle { object_id: next });
            }
            current = next;
            rest = tail;
        }
    }

    /// List a directory into `out` as newline-separated UTF-8 names. Returns
    /// bytes written and truncates at `out.len()` without splitting safety
    /// invariants: the result is only a diagnostic/listing convenience for the
    /// Stage-G service.
    pub fn list_directory(
        &mut self,
        directory: DirectoryHandle,
        out: &mut [u8],
    ) -> Result<usize, HxfsError> {
        let dir = self.find_object(directory.object_id)?;
        if dir.object_type != OBJECT_TYPE_DIRECTORY {
            return Err(HxfsError::WrongType);
        }
        let mut writer = ListWriter::new(out);
        self.for_each_directory_entry(dir, |entry| {
            writer.write(entry.name.as_bytes());
            writer.write_byte(b'\n');
        })?;
        Ok(writer.len())
    }

    /// Open one child file by name from a directory handle.
    pub fn open_child_file(
        &mut self,
        directory: DirectoryHandle,
        name: &str,
    ) -> Result<FileHandle, HxfsError> {
        let dir = self.find_object(directory.object_id)?;
        if dir.object_type != OBJECT_TYPE_DIRECTORY {
            return Err(HxfsError::WrongType);
        }
        let object_id = self.lookup_in_directory(dir, name.as_bytes())?;
        let object = self.find_object(object_id)?;
        if object.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        Ok(FileHandle {
            object_id: object.object_id,
            size: object.size,
        })
    }

    /// Open an absolute path inside the system volume.
    pub fn open_path(&mut self, path: &str) -> Result<FileHandle, HxfsError> {
        if path.is_empty() || !path.as_bytes().starts_with(b"/") {
            return Err(HxfsError::BadName);
        }
        if path == "/" {
            return Err(HxfsError::WrongType);
        }
        let mut current = self.system_volume.root_object_id;
        let mut rest = &path.as_bytes()[1..];
        loop {
            let slash = rest.iter().position(|&byte| byte == b'/');
            let (component, tail) = match slash {
                Some(pos) => (&rest[..pos], &rest[pos + 1..]),
                None => (rest, &[][..]),
            };
            if component.is_empty() || component.len() > MAX_NAME_BYTES {
                return Err(HxfsError::BadName);
            }
            let dir = self.find_object(current)?;
            if dir.object_type != OBJECT_TYPE_DIRECTORY {
                return Err(HxfsError::WrongType);
            }
            let next = self.lookup_in_directory(dir, component)?;
            if tail.is_empty() {
                let object = self.find_object(next)?;
                return match object.object_type {
                    OBJECT_TYPE_FILE => Ok(FileHandle {
                        object_id: object.object_id,
                        size: object.size,
                    }),
                    OBJECT_TYPE_SYMLINK | OBJECT_TYPE_DIRECTORY | OBJECT_TYPE_BLOB_VIEW => {
                        Err(HxfsError::WrongType)
                    }
                    _ => Err(HxfsError::WrongType),
                };
            }
            current = next;
            rest = tail;
        }
    }

    /// Read a file object into `out`. Returns the number of bytes copied.
    pub fn read_file(&mut self, file: FileHandle, out: &mut [u8]) -> Result<usize, HxfsError> {
        let object = self.find_object(file.object_id)?;
        if object.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        let file_size = usize::try_from(object.size).map_err(|_| HxfsError::OutOfRange)?;
        if out.len() < file_size {
            return Err(HxfsError::BufferTooSmall);
        }
        out[..file_size].fill(0);
        self.copy_extents(object, &mut out[..file_size])?;
        Ok(file_size)
    }

    fn find_object(&mut self, object_id: u64) -> Result<ObjectDescriptor, HxfsError> {
        let object_count = self.system_volume.object_count;
        let mut block = [0u8; BLOCK_SIZE];
        self.read_metadata_block(
            self.system_volume.object_table_lba,
            BLOCK_TYPE_OBJECT_TABLE,
            1,
            &mut block,
        )?;
        let header = parse_header(&block)?;
        let count = read_u32(&block, header.header_bytes as usize)?;
        if count != object_count {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * OBJECT_RECORD_BYTES;
            let object = parse_object_record(&block, offset)?;
            if object.object_id == object_id {
                return Ok(object);
            }
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn lookup_in_directory(
        &mut self,
        dir: ObjectDescriptor,
        name: &[u8],
    ) -> Result<u64, HxfsError> {
        let mut block = [0u8; BLOCK_SIZE];
        self.read_metadata_block(
            dir.tree_lba,
            BLOCK_TYPE_DIRECTORY,
            dir.object_id,
            &mut block,
        )?;
        let header = parse_header(&block)?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != dir.object_id || count != dir.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut previous: Option<&str> = None;
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let entry = parse_dir_record(&block, offset)?;
            if let Some(prev) = previous {
                if prev.as_bytes() >= entry.name.as_bytes() {
                    return Err(HxfsError::BadTree);
                }
            }
            if entry.name.as_bytes() == name {
                return Ok(entry.object_id);
            }
            previous = Some(entry.name);
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn for_each_directory_entry(
        &mut self,
        dir: ObjectDescriptor,
        mut visit: impl FnMut(DirectoryEntry<'_>),
    ) -> Result<(), HxfsError> {
        let mut block = [0u8; BLOCK_SIZE];
        self.read_metadata_block(
            dir.tree_lba,
            BLOCK_TYPE_DIRECTORY,
            dir.object_id,
            &mut block,
        )?;
        let header = parse_header(&block)?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != dir.object_id || count != dir.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut previous: Option<&str> = None;
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let entry = parse_dir_record(&block, offset)?;
            if let Some(prev) = previous {
                if prev.as_bytes() >= entry.name.as_bytes() {
                    return Err(HxfsError::BadTree);
                }
            }
            visit(entry);
            previous = Some(entry.name);
            index += 1;
        }
        Ok(())
    }

    fn copy_extents(&mut self, object: ObjectDescriptor, out: &mut [u8]) -> Result<(), HxfsError> {
        if object.record_count == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        self.read_metadata_block(
            object.tree_lba,
            BLOCK_TYPE_EXTENT_TABLE,
            object.object_id,
            &mut block,
        )?;
        let header = parse_header(&block)?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != object.object_id || count != object.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut previous_logical_end = 0u64;
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * EXTENT_RECORD_BYTES;
            let extent = parse_extent_record(&block, offset)?;
            if extent.logical_block < previous_logical_end {
                return Err(HxfsError::BadTree);
            }
            previous_logical_end = extent
                .logical_block
                .checked_add(u64::from(extent.block_count))
                .ok_or(HxfsError::OutOfRange)?;
            let compression = resolve_compression_for_object(
                &self.system_volume,
                &self.compression_policies,
                object,
            );
            copy_extent(
                &mut self.reader,
                extent,
                compression,
                &mut self.page_cache,
                0,
                out,
            )?;
            index += 1;
        }
        Ok(())
    }

    fn read_metadata_block(
        &mut self,
        lba: u64,
        block_type: u32,
        owner_id: u64,
        out: &mut [u8; BLOCK_SIZE],
    ) -> Result<BlockHeader, HxfsError> {
        self.reader.read_blocks(lba, 1, out)?;
        validate_metadata_block(out, lba, block_type, owner_id)
    }
}

pub(crate) const HEADER_BYTES: usize = 40;
pub(crate) const VOLUME_RECORD_BYTES: usize = 96;
pub(crate) const OBJECT_RECORD_BYTES: usize = 64;
pub(crate) const DIR_RECORD_BYTES: usize = 272;
pub(crate) const EXTENT_RECORD_BYTES: usize = 32;

pub(crate) fn read_superblock<R: BlockReader>(
    reader: &mut R,
    lba: u64,
) -> Result<Superblock, HxfsError> {
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(lba, 1, &mut block)?;
    let header = validate_metadata_block(&block, lba, BLOCK_TYPE_SUPERBLOCK, 0)?;
    let base = header.header_bytes as usize;
    let mut format_guid = [0u8; 16];
    format_guid.copy_from_slice(block.get(base..base + 16).ok_or(HxfsError::BadBlock)?);
    if format_guid != FORMAT_GUID {
        return Err(HxfsError::UnsupportedFormat);
    }
    let format_version = read_u32(&block, base + 16)?;
    let type_system_version = read_u32(&block, base + 20)?;
    let mut instance_uuid = [0u8; 16];
    instance_uuid.copy_from_slice(block.get(base + 24..base + 40).ok_or(HxfsError::BadBlock)?);
    let sequence_number = read_u64(&block, base + 40)?;
    let block_size = read_u32(&block, base + 48)?;
    let checkpoint_lba = read_u64(&block, base + 56)?;
    let backup_checkpoint_lba = read_u64(&block, base + 64)?;
    let journal_start_lba = read_u64(&block, base + 72)?;
    let journal_end_lba = read_u64(&block, base + 80)?;
    let compatible_features = read_u64(&block, base + 88)?;
    let ro_compatible_features = read_u64(&block, base + 96)?;
    let incompatible_features = read_u64(&block, base + 104)?;
    let root_state = read_u32(&block, base + 112)?;
    let root_flags = read_u32(&block, base + 116)?;
    if format_version != FORMAT_VERSION
        || type_system_version != TYPE_SYSTEM_VERSION
        || block_size as usize != BLOCK_SIZE
    {
        return Err(HxfsError::UnsupportedFormat);
    }
    if compatible_features & !SUPPORTED_COMPAT_FEATURES != 0
        || ro_compatible_features & !SUPPORTED_RO_COMPAT_FEATURES != 0
        || incompatible_features & !SUPPORTED_INCOMPAT_FEATURES != 0
        || incompatible_features & BASE_INCOMPAT_FEATURES != BASE_INCOMPAT_FEATURES
    {
        return Err(HxfsError::UnsupportedFormat);
    }
    if !matches!(root_state, ROOT_STATE_CLEAN | ROOT_STATE_RECOVERING) || root_flags != 0 {
        return Err(HxfsError::BadBlock);
    }
    if (journal_start_lba == 0) != (journal_end_lba == 0) || journal_start_lba > journal_end_lba {
        return Err(HxfsError::BadJournal);
    }
    Ok(Superblock {
        format_guid,
        format_version,
        type_system_version,
        instance_uuid,
        sequence_number,
        block_size,
        checkpoint_lba,
        backup_checkpoint_lba,
        journal_start_lba,
        journal_end_lba,
        compatible_features,
        ro_compatible_features,
        incompatible_features,
        root_state,
        root_flags,
    })
}

pub(crate) fn read_checkpoint<R: BlockReader>(
    reader: &mut R,
    lba: u64,
    sequence_number: u64,
) -> Result<Checkpoint, HxfsError> {
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(lba, 1, &mut block)?;
    let header = validate_metadata_block(&block, lba, BLOCK_TYPE_CHECKPOINT, 0)?;
    let base = header.header_bytes as usize;
    let checkpoint_sequence = read_u64(&block, base)?;
    if checkpoint_sequence != sequence_number {
        return Err(HxfsError::BadTree);
    }
    let volume_table_lba = read_u64(&block, base + 8)?;
    let volume_count = read_u32(&block, base + 16)?;
    let mut system_volume_uuid = [0u8; 16];
    system_volume_uuid.copy_from_slice(block.get(base + 24..base + 40).ok_or(HxfsError::BadBlock)?);
    let allocation_tree_lba = read_u64(&block, base + 40)?;
    let refcount_tree_lba = read_u64(&block, base + 48)?;
    let backref_tree_lba = read_u64(&block, base + 56)?;
    let quota_tree_lba = read_u64(&block, base + 64)?;
    let encryption_policy_tree_lba = read_u64(&block, base + 72)?;
    let compression_policy_tree_lba = read_u64(&block, base + 80)?;
    let hxblob_index_tree_lba = read_u64(&block, base + 88)?;
    let hxblob_merkle_tree_lba = read_u64(&block, base + 96)?;
    let virtual_volume_tree_lba = read_u64(&block, base + 104)?;
    let gpt_summary_lba = read_u64(&block, base + 112)?;
    let install_manifest_lba = read_u64(&block, base + 120)?;
    Ok(Checkpoint {
        sequence_number: checkpoint_sequence,
        volume_table_lba,
        volume_count,
        system_volume_uuid,
        allocation_tree_lba,
        refcount_tree_lba,
        backref_tree_lba,
        quota_tree_lba,
        encryption_policy_tree_lba,
        compression_policy_tree_lba,
        hxblob_index_tree_lba,
        hxblob_merkle_tree_lba,
        virtual_volume_tree_lba,
        gpt_summary_lba,
        install_manifest_lba,
    })
}

pub(crate) fn read_system_volume<R: BlockReader>(
    reader: &mut R,
    checkpoint: Checkpoint,
) -> Result<VolumeDescriptor, HxfsError> {
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(checkpoint.volume_table_lba, 1, &mut block)?;
    let header = validate_metadata_block(
        &block,
        checkpoint.volume_table_lba,
        BLOCK_TYPE_VOLUME_TABLE,
        0,
    )?;
    let count = read_u32(&block, header.header_bytes as usize)?;
    if count != checkpoint.volume_count {
        return Err(HxfsError::BadTree);
    }
    let mut index = 0u32;
    while index < count {
        let offset = header.header_bytes as usize + 16 + index as usize * VOLUME_RECORD_BYTES;
        let volume = parse_volume_record(&block, offset)?;
        if volume.uuid == checkpoint.system_volume_uuid {
            return Ok(volume);
        }
        index += 1;
    }
    Err(HxfsError::NotFound)
}

pub(crate) fn validate_metadata_block(
    block: &[u8; BLOCK_SIZE],
    expected_lba: u64,
    expected_type: u32,
    expected_owner: u64,
) -> Result<BlockHeader, HxfsError> {
    let header = parse_header(block)?;
    if header.block_type != expected_type
        || header.type_version != 1
        || header.header_bytes as usize != HEADER_BYTES
        || header.self_lba != expected_lba
        || header.owner_id != expected_owner
        || header.payload_bytes as usize > BLOCK_SIZE - HEADER_BYTES
    {
        return Err(HxfsError::BadBlock);
    }
    if metadata_crc32c(block) != header.crc32c {
        return Err(HxfsError::BadChecksum);
    }
    Ok(header)
}

pub(crate) fn parse_header(block: &[u8]) -> Result<BlockHeader, HxfsError> {
    Ok(BlockHeader {
        block_type: read_u32(block, 0)?,
        type_version: read_u16(block, 4)?,
        header_bytes: read_u16(block, 6)?,
        generation: read_u64(block, 8)?,
        owner_id: read_u64(block, 16)?,
        self_lba: read_u64(block, 24)?,
        crc32c: read_u32(block, 32)?,
        payload_bytes: read_u32(block, 36)?,
    })
}

fn parse_volume_record(block: &[u8], offset: usize) -> Result<VolumeDescriptor, HxfsError> {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(block.get(offset..offset + 16).ok_or(HxfsError::BadTree)?);
    Ok(VolumeDescriptor {
        uuid,
        root_object_id: read_u64(block, offset + 16)?,
        object_table_lba: read_u64(block, offset + 24)?,
        object_count: read_u32(block, offset + 32)?,
        flags: read_u32(block, offset + 36)?,
        encryption_policy_id: read_u32(block, offset + 40)?,
        compression_policy_id: read_u32(block, offset + 44)?,
        quota_physical_bytes: read_u64(block, offset + 48)?,
        quota_objects: read_u64(block, offset + 56)?,
    })
}

pub(crate) fn parse_object_record(
    block: &[u8],
    offset: usize,
) -> Result<ObjectDescriptor, HxfsError> {
    Ok(ObjectDescriptor {
        object_id: read_u64(block, offset)?,
        object_type: read_u32(block, offset + 8)?,
        type_version: read_u32(block, offset + 12)?,
        size: read_u64(block, offset + 16)?,
        modified_unix_ns: read_i64(block, offset + 24)?,
        encryption_policy_id: read_u32(block, offset + 32)?,
        compression_policy_id: read_u32(block, offset + 36)?,
        tree_lba: read_u64(block, offset + 40)?,
        record_count: read_u32(block, offset + 48)?,
        flags: read_u32(block, offset + 52)?,
    })
}

pub(crate) fn parse_dir_record(
    block: &[u8],
    offset: usize,
) -> Result<DirectoryEntry<'_>, HxfsError> {
    let object_id = read_u64(block, offset)?;
    let name_len = read_u16(block, offset + 8)? as usize;
    if name_len == 0 || name_len > MAX_NAME_BYTES {
        return Err(HxfsError::BadName);
    }
    let name_bytes = block
        .get(offset + 10..offset + 10 + name_len)
        .ok_or(HxfsError::BadTree)?;
    let name = core::str::from_utf8(name_bytes).map_err(|_| HxfsError::BadName)?;
    Ok(DirectoryEntry { object_id, name })
}

pub(crate) fn parse_extent_record(block: &[u8], offset: usize) -> Result<ExtentRecord, HxfsError> {
    let record = ExtentRecord {
        logical_block: read_u64(block, offset)?,
        physical_block: read_u64(block, offset + 8)?,
        block_count: read_u32(block, offset + 16)?,
        flags: read_u32(block, offset + 20)?,
    };
    if record.block_count == 0 {
        return Err(HxfsError::BadTree);
    }
    Ok(record)
}

fn copy_extent<R: BlockReader>(
    reader: &mut R,
    extent: ExtentRecord,
    compression: Option<compression::CompressionPolicy>,
    page_cache: &mut page_cache::PageCache,
    volume_id: u64,
    out: &mut [u8],
) -> Result<(), HxfsError> {
    let start = usize::try_from(extent.logical_block)
        .ok()
        .and_then(|block| block.checked_mul(BLOCK_SIZE))
        .ok_or(HxfsError::OutOfRange)?;
    let bytes = usize::try_from(extent.block_count)
        .ok()
        .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE))
        .ok_or(HxfsError::OutOfRange)?;
    let end = start.checked_add(bytes).ok_or(HxfsError::OutOfRange)?;
    if start >= out.len() {
        return Ok(());
    }
    let copy_end = end.min(out.len());
    if extent.flags & EXTENT_FLAG_HOLE != 0 {
        out[start..copy_end].fill(0);
        return Ok(());
    }

    let mut scratch = [0u8; BLOCK_SIZE];
    let mut decompressed = [0u8; BLOCK_SIZE];
    let mut copied = start;
    while copied < copy_end {
        let logical_delta = copied - start;
        let extent_block = logical_delta / BLOCK_SIZE;
        let within = logical_delta % BLOCK_SIZE;
        let page_index = extent_block as u32;
        if let Some(cached) = page_cache.lookup(volume_id, extent.physical_block, page_index) {
            let chunk = (copy_end - copied).min(BLOCK_SIZE - within);
            out[copied..copied + chunk].copy_from_slice(&cached[within..within + chunk]);
            copied += chunk;
            continue;
        }
        reader.read_blocks(extent.physical_block + extent_block as u64, 1, &mut scratch)?;
        // A.3 wire: dispatch on the resolved compression policy
        // and decompress the just-read 4 KiB block into a
        // caller-bounded buffer. Plain and absent policies are
        // the no-op fast path; codec errors surface as
        // HxfsError::Compression at the read boundary.
        let block_slice: &[u8] = match compression {
            Some(policy) => match policy.algorithm {
                compression::COMPRESSION_NONE => &scratch[..],
                compression::COMPRESSION_LZ4 => {
                    #[cfg(feature = "compression-engines")]
                    {
                        compression::decompress_lz4(&scratch, &mut decompressed)
                            .map_err(|_| HxfsError::Compression)?;
                        &decompressed[..]
                    }
                    #[cfg(not(feature = "compression-engines"))]
                    {
                        let _ = (&scratch, &mut decompressed);
                        return Err(HxfsError::Compression);
                    }
                }
                _ => return Err(HxfsError::Compression),
            },
            None => &scratch[..],
        };
        let chunk = (copy_end - copied).min(BLOCK_SIZE - within);
        out[copied..copied + chunk].copy_from_slice(&block_slice[within..within + chunk]);
        copied += chunk;
        // A.4 wire: insert the just-read 4 KiB block (raw or
        // decompressed) into the per-volume page cache so the
        // next read of the same page skips the disk I/O and
        // the codec. The cache key is the physical block LBA
        // + the page index; collisions are handled by the
        // bounded walk inside PageCache.
        page_cache.insert(
            volume_id,
            extent.physical_block,
            page_index,
            block_slice.to_vec(),
        );
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, HxfsError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HxfsError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, HxfsError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, HxfsError> {
    Ok(i64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

struct ListWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> ListWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_byte(&mut self, byte: u8) {
        if self.len < self.out.len() {
            self.out[self.len] = byte;
            self.len += 1;
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_byte(byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32c::metadata_crc32c;
    use crate::reader::SliceBlockReader;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    const INSTANCE: Uuid = [0x11; 16];
    const VOLUME: Uuid = [0x22; 16];

    fn make_block(block_type: u32, owner: u64, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&block_type.to_le_bytes());
        block[4..6].copy_from_slice(&1u16.to_le_bytes());
        block[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        block[8..16].copy_from_slice(&1u64.to_le_bytes());
        block[16..24].copy_from_slice(&owner.to_le_bytes());
        block[24..32].copy_from_slice(&lba.to_le_bytes());
        block[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        block[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
        let crc = metadata_crc32c(&block);
        block[32..36].copy_from_slice(&crc.to_le_bytes());
        block
    }

    fn build_image(encrypted: bool) -> Vec<u8> {
        let mut image = vec![0u8; BLOCK_SIZE * 8];
        let mut super_payload = [0u8; 120];
        super_payload[0..16].copy_from_slice(&FORMAT_GUID);
        super_payload[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        super_payload[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
        super_payload[24..40].copy_from_slice(&INSTANCE);
        super_payload[40..48].copy_from_slice(&1u64.to_le_bytes());
        super_payload[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        super_payload[56..64].copy_from_slice(&1u64.to_le_bytes());
        super_payload[104..112].copy_from_slice(&BASE_INCOMPAT_FEATURES.to_le_bytes());
        super_payload[112..116].copy_from_slice(&ROOT_STATE_CLEAN.to_le_bytes());
        let superblock = make_block(BLOCK_TYPE_SUPERBLOCK, 0, 0, &super_payload);
        image[0..BLOCK_SIZE].copy_from_slice(&superblock);

        let mut checkpoint_payload = [0u8; 128];
        checkpoint_payload[0..8].copy_from_slice(&1u64.to_le_bytes());
        checkpoint_payload[8..16].copy_from_slice(&2u64.to_le_bytes());
        checkpoint_payload[16..20].copy_from_slice(&1u32.to_le_bytes());
        checkpoint_payload[24..40].copy_from_slice(&VOLUME);
        let checkpoint = make_block(BLOCK_TYPE_CHECKPOINT, 0, 1, &checkpoint_payload);
        image[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&checkpoint);

        let mut volume_payload = [0u8; 16 + VOLUME_RECORD_BYTES];
        volume_payload[0..4].copy_from_slice(&1u32.to_le_bytes());
        let record = 16usize;
        volume_payload[record..record + 16].copy_from_slice(&VOLUME);
        volume_payload[record + 16..record + 24].copy_from_slice(&1u64.to_le_bytes());
        volume_payload[record + 24..record + 32].copy_from_slice(&3u64.to_le_bytes());
        volume_payload[record + 32..record + 36].copy_from_slice(&2u32.to_le_bytes());
        let flags = VOLUME_FLAG_SYSTEM | if encrypted { VOLUME_FLAG_ENCRYPTED } else { 0 };
        volume_payload[record + 36..record + 40].copy_from_slice(&flags.to_le_bytes());
        let enc_policy = if encrypted { 7u32 } else { 0u32 };
        volume_payload[record + 40..record + 44].copy_from_slice(&enc_policy.to_le_bytes());
        let volume_block = make_block(BLOCK_TYPE_VOLUME_TABLE, 0, 2, &volume_payload);
        image[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&volume_block);

        let mut object_payload = [0u8; 16 + 2 * OBJECT_RECORD_BYTES];
        object_payload[0..4].copy_from_slice(&2u32.to_le_bytes());
        write_object(&mut object_payload, 16, 1, OBJECT_TYPE_DIRECTORY, 0, 4, 1);
        write_object(
            &mut object_payload,
            16 + OBJECT_RECORD_BYTES,
            2,
            OBJECT_TYPE_FILE,
            11,
            5,
            1,
        );
        let object_block = make_block(BLOCK_TYPE_OBJECT_TABLE, 1, 3, &object_payload);
        image[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&object_block);

        let mut dir_payload = [0u8; 16 + DIR_RECORD_BYTES];
        dir_payload[0..8].copy_from_slice(&1u64.to_le_bytes());
        dir_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        dir_payload[16..24].copy_from_slice(&2u64.to_le_bytes());
        dir_payload[24..26].copy_from_slice(&9u16.to_le_bytes());
        dir_payload[26..35].copy_from_slice(b"hello.txt");
        let dir_block = make_block(BLOCK_TYPE_DIRECTORY, 1, 4, &dir_payload);
        image[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&dir_block);

        let mut extent_payload = [0u8; 16 + EXTENT_RECORD_BYTES];
        extent_payload[0..8].copy_from_slice(&2u64.to_le_bytes());
        extent_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        extent_payload[16..24].copy_from_slice(&0u64.to_le_bytes());
        extent_payload[24..32].copy_from_slice(&6u64.to_le_bytes());
        extent_payload[32..36].copy_from_slice(&1u32.to_le_bytes());
        let extent_block = make_block(BLOCK_TYPE_EXTENT_TABLE, 2, 5, &extent_payload);
        image[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&extent_block);

        image[BLOCK_SIZE * 6..BLOCK_SIZE * 6 + 11].copy_from_slice(b"hello hxfs\n");
        image
    }

    fn write_object(
        out: &mut [u8],
        offset: usize,
        object_id: u64,
        object_type: u32,
        size: u64,
        tree_lba: u64,
        record_count: u32,
    ) {
        out[offset..offset + 8].copy_from_slice(&object_id.to_le_bytes());
        out[offset + 8..offset + 12].copy_from_slice(&object_type.to_le_bytes());
        out[offset + 12..offset + 16].copy_from_slice(&1u32.to_le_bytes());
        out[offset + 16..offset + 24].copy_from_slice(&size.to_le_bytes());
        out[offset + 24..offset + 32].copy_from_slice(&0i64.to_le_bytes());
        out[offset + 40..offset + 48].copy_from_slice(&tree_lba.to_le_bytes());
        out[offset + 48..offset + 52].copy_from_slice(&record_count.to_le_bytes());
    }

    #[test]
    fn mounts_and_reads_hello_file() {
        let image = build_image(false);
        let reader = SliceBlockReader::new(&image);
        let mounted = Hxfs::mount(reader);
        assert!(mounted.is_ok());
        let Ok(mut fs) = mounted else { return };
        assert_eq!(fs.root_directory().object_id, 1);
        let file = fs.open_path("/hello.txt");
        assert!(file.is_ok());
        let Ok(file) = file else { return };
        let mut buf = [0u8; 32];
        let read = fs.read_file(file, &mut buf);
        assert_eq!(read, Ok(11));
        assert_eq!(&buf[..11], b"hello hxfs\n");
    }

    #[test]
    fn directory_listing_and_child_open_work() {
        let image = build_image(false);
        let reader = SliceBlockReader::new(&image);
        let Ok(mut fs) = Hxfs::mount(reader) else {
            assert!(false, "test image should mount");
            return;
        };
        let root = fs.root_directory();
        let mut list = [0u8; 32];
        assert_eq!(fs.list_directory(root, &mut list), Ok(10));
        assert_eq!(&list[..10], b"hello.txt\n");
        let file = fs.open_child_file(root, "hello.txt");
        assert!(file.is_ok());
    }

    #[test]
    fn rejects_encrypted_volume_in_stage_g() {
        let image = build_image(true);
        let reader = SliceBlockReader::new(&image);
        assert_eq!(
            Hxfs::mount_with_keys(reader, &[]).err(),
            Some(HxfsError::EncryptedPolicyUnknown)
        );
    }

    #[test]
    fn rejects_bad_metadata_checksum() {
        let mut image = build_image(false);
        image[BLOCK_SIZE * 4 + HEADER_BYTES + 20] ^= 1;
        let reader = SliceBlockReader::new(&image);
        let mounted = Hxfs::mount(reader);
        assert!(mounted.is_ok());
        let Ok(mut fs) = mounted else { return };
        assert_eq!(
            fs.open_path("/hello.txt").err(),
            Some(HxfsError::BadChecksum)
        );
    }
}
