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
#[cfg(feature = "crypto-aes-gcm")]
pub mod crypto_aes_gcm;
#[cfg(feature = "crypto-aes-gcm")]
pub mod encrypted_metadata;
#[cfg(feature = "crypto-aes-gcm")]
pub mod extent_crypto;
pub mod fixed_writer;
pub mod format;
pub mod fsck;
pub mod gpt;
#[cfg(feature = "crypto-aes-gcm")]
pub mod hkdf;
pub mod hxblob;
pub mod hxblob_tree;
pub mod io_policy;
pub mod o_direct;
pub mod observability;
pub mod page_cache;
pub mod quota;
pub mod quota_tree;
pub mod reader;
pub mod recovery;
pub mod ref_tree;
pub mod scrub;
pub mod security_policy;
#[cfg(feature = "crypto-aes-gcm")]
pub mod synthetic_image;
#[cfg(feature = "crypto-aes-gcm")]
pub mod synthetic_key;
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
    /// Per-Job volume-quota breach on the write path. The
    /// kernel translates this to the user-facing NoSpace
    /// error at the mount boundary.
    QuotaExceeded,
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
    /// Stage B.1: derived metadata subkey for this volume. Set
    /// when the system volume has `encryption_policy_id != 0`
    /// and the mount gate accepted the volume; the read path
    /// uses it to decrypt v6 metadata blocks (B.1) and v6 dirent
    /// name bodies (B.2). The key is held in RAM for the
    /// lifetime of the mount and zeroized on drop. `None` for
    /// plain volumes.
    #[cfg(feature = "crypto-aes-gcm")]
    metadata_key: Option<[u8; 32]>,
    /// Stage B.3: derived extent subkey for this volume. Used
    /// to wrap the *compressed* payload of every data extent
    /// on the read path. Independent from `metadata_key`
    /// (different HKDF info string) so a metadata-key leak
    /// does not also leak data extents. `None` for plain
    /// volumes.
    #[cfg(feature = "crypto-aes-gcm")]
    extent_key: Option<[u8; 32]>,
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
        // Stage B.1 wire: derive the per-volume metadata subkey
        // when the volume is encrypted. The MVP uses the
        // superblock's `instance_uuid` as the HKDF salt; the
        // subkey is held in RAM for the lifetime of the mount
        // and zeroized on drop. A future Stage D KeyProvider
        // will supply the IKM through a kernel handle; for now
        // the IKM is a fixed developer-only zero-key and the
        // volume is only mountable from host tests.
        #[cfg(feature = "crypto-aes-gcm")]
        let metadata_key = if encryption.is_some() {
            let mut ikm = [0u8; 32];
            // Mix the instance UUID into the IKM so two volumes
            // with the same superblock GUID family still get
            // distinct subkeys. This is a development-only
            // placeholder: the real IKM is supplied by the
            // Stage D KeyProvider through the kernel handle.
            let mut index = 0usize;
            while index < 16 {
                ikm[index] = superblock.instance_uuid[index];
                ikm[index + 16] = superblock.instance_uuid[index];
                index += 1;
            }
            let mut key = [0u8; 32];
            encrypted_metadata::derive_metadata_key_for_volume(
                &ikm,
                &superblock.instance_uuid,
                &mut key,
            )
            .map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
            // Zeroize the IKM scratch; it is short-lived and
            // does not need to live in the struct.
            for byte in ikm.iter_mut() {
                *byte = 0;
            }
            Some(key)
        } else {
            None
        };
        // Stage B.3 wire: derive the per-volume extent subkey
        // from the same placeholder IKM. The extent subkey is
        // independent of the metadata subkey (different HKDF
        // info string) so a metadata-key leak does not also
        // leak data extents.
        #[cfg(feature = "crypto-aes-gcm")]
        let extent_key = if encryption.is_some() {
            let mut ikm = [0u8; 32];
            let mut index = 0usize;
            while index < 16 {
                ikm[index] = superblock.instance_uuid[index];
                ikm[index + 16] = superblock.instance_uuid[index];
                index += 1;
            }
            let mut key = [0u8; 32];
            extent_crypto::derive_extent_key_for_volume(&ikm, &superblock.instance_uuid, &mut key)
                .map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
            for byte in ikm.iter_mut() {
                *byte = 0;
            }
            Some(key)
        } else {
            None
        };
        Ok(Self {
            reader,
            superblock,
            checkpoint,
            system_volume,
            encryption,
            #[cfg(feature = "crypto-aes-gcm")]
            metadata_key,
            #[cfg(feature = "crypto-aes-gcm")]
            extent_key,
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

/// Check whether a metadata block header carries the v6
/// "encrypted metadata" discriminator. Stage B.1 puts
/// `type_version = 6` in the block header when the payload is
/// encrypted under the per-volume metadata subkey; a v5 reader
/// sees `type_version = 1` (the existing `validate_metadata_block`
/// rejects any other value, so a v5 reader cannot accidentally
/// read a v6 block as v5).
///
/// The function is `const` so callers can branch on it inside
/// hot loops without paying a function-call cost.
pub const fn is_v6_encrypted_metadata(header: &BlockHeader) -> bool {
    header.type_version == 6
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
        // `previous_name` holds the previous dirent's plaintext
        // name bytes. We cannot borrow the dirent's name field
        // across loop iterations because the entry is created
        // from `scratch`, which is re-borrowed on every call to
        // `parse_dirent_in_block`. We copy the plaintext out
        // before the next iteration so the borrow does not
        // extend.
        let mut previous_name = [0u8; MAX_NAME_BYTES];
        let mut previous_len: usize = 0;
        let mut has_previous = false;
        let mut scratch = [0u8; MAX_NAME_BYTES];
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let entry = self.parse_dirent_in_block(&block, offset, dir.object_id, &mut scratch)?;
            if has_previous && &previous_name[..previous_len] >= entry.name.as_bytes() {
                return Err(HxfsError::BadTree);
            }
            if entry.name.as_bytes() == name {
                return Ok(entry.object_id);
            }
            previous_len = entry.name.len();
            previous_name[..previous_len].copy_from_slice(entry.name.as_bytes());
            has_previous = true;
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
        // `visit` borrows the dirent's `name` for the duration
        // of the call; after that borrow ends, the next
        // iteration rebinds `scratch`. We use the same
        // `previous_name` copy trick as in `lookup_in_directory`
        // so the ordering check is sound without carrying a
        // long-lived borrow across iterations.
        let mut previous_name = [0u8; MAX_NAME_BYTES];
        let mut previous_len: usize = 0;
        let mut has_previous = false;
        let mut scratch = [0u8; MAX_NAME_BYTES];
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let entry = self.parse_dirent_in_block(&block, offset, dir.object_id, &mut scratch)?;
            if has_previous && &previous_name[..previous_len] >= entry.name.as_bytes() {
                return Err(HxfsError::BadTree);
            }
            visit(entry);
            previous_len = entry.name.len();
            previous_name[..previous_len].copy_from_slice(entry.name.as_bytes());
            has_previous = true;
            index += 1;
        }
        Ok(())
    }

    /// Stage B.2 helper: parse one dirent record from a
    /// directory block, decrypting the name body when the
    /// record is encrypted and a metadata subkey is available.
    /// The plaintext lands in `scratch` and the returned
    /// `DirectoryEntry` borrows from it.
    fn parse_dirent_in_block<'a>(
        &self,
        block: &[u8],
        offset: usize,
        parent_object_id: u64,
        scratch: &'a mut [u8; MAX_NAME_BYTES],
    ) -> Result<DirectoryEntry<'a>, HxfsError> {
        #[cfg(feature = "crypto-aes-gcm")]
        if let Some(key) = self.metadata_key.as_ref() {
            return parse_dir_record_decrypt(block, offset, parent_object_id, key, scratch);
        }
        let _ = parent_object_id;
        // Plaintext path: copy the v5 name bytes into `scratch`
        // so the returned `DirectoryEntry` borrows from
        // `scratch` (same lifetime as the encrypted path). This
        // keeps the caller's borrow checker happy across loop
        // iterations: the entry is only valid until the next
        // call to `parse_dirent_in_block` rebinds `scratch`.
        let entry = parse_dir_record(block, offset)?;
        let name_bytes = entry.name.as_bytes();
        if scratch.len() < name_bytes.len() {
            return Err(HxfsError::BufferTooSmall);
        }
        scratch[..name_bytes.len()].copy_from_slice(name_bytes);
        let name_str =
            core::str::from_utf8(&scratch[..name_bytes.len()]).map_err(|_| HxfsError::BadName)?;
        Ok(DirectoryEntry {
            object_id: entry.object_id,
            name: name_str,
        })
    }

    fn copy_extents(&mut self, object: ObjectDescriptor, out: &mut [u8]) -> Result<(), HxfsError> {
        if object.record_count == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        let (header, block_type) = self.read_metadata_block_any_type(
            object.tree_lba,
            BLOCK_TYPE_EXTENT_TABLE,
            BLOCK_TYPE_EXTENT_TABLE_V2,
            object.object_id,
            &mut block,
        )?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != object.object_id || count != object.record_count {
            return Err(HxfsError::BadTree);
        }
        let record_bytes = if block_type == BLOCK_TYPE_EXTENT_TABLE_V2 {
            EXTENT_RECORD_BYTES_V2
        } else {
            EXTENT_RECORD_BYTES
        };
        let mut previous_logical_end = 0u64;
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * record_bytes;
            let (extent, meta) = if block_type == BLOCK_TYPE_EXTENT_TABLE_V2 {
                parse_extent_record_v2(&block, offset)?
            } else {
                (parse_extent_record(&block, offset)?, None)
            };
            if extent.logical_block < previous_logical_end {
                return Err(HxfsError::BadTree);
            }
            // A two-slot extent covers ONE logical block even
            // though its `block_count` (physical slots) is 2.
            let logical_len = if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                1
            } else {
                u64::from(extent.block_count)
            };
            previous_logical_end = extent
                .logical_block
                .checked_add(logical_len)
                .ok_or(HxfsError::OutOfRange)?;
            // v1 records: the compression decision comes from the
            // resolved policy (pre-B.3-completion behaviour). v2
            // records carry the per-extent descriptor instead, so
            // the policy is not consulted and an incompressible
            // block that was stored plain is not mis-decoded.
            let compression = if block_type == BLOCK_TYPE_EXTENT_TABLE {
                resolve_compression_for_object(
                    &self.system_volume,
                    &self.compression_policies,
                    object,
                )
            } else {
                None
            };
            // Stage B.3 wire: decide whether the extent is
            // encrypted (per-object policy with per-volume
            // fallback) and pass the matching subkey + volume
            // UUID to the read path.
            #[cfg(feature = "crypto-aes-gcm")]
            let extent_is_encrypted =
                extent_crypto::resolve_extent_encryption_for_object(&self.system_volume, &object);
            #[cfg(feature = "crypto-aes-gcm")]
            let extent_key: Option<&[u8; 32]> = if extent_is_encrypted {
                self.extent_key.as_ref()
            } else {
                None
            };
            // On a build without the `crypto-aes-gcm`
            // feature, the call to `copy_extent_with_keys`
            // takes 6 arguments (no subkey, no volume UUID);
            // the plain v5 read path is taken and the
            // cfg-conditional arguments are simply absent
            // from the call site.
            copy_extent_with_keys(
                &mut self.reader,
                extent,
                compression,
                meta,
                &mut self.page_cache,
                0,
                #[cfg(feature = "crypto-aes-gcm")]
                extent_key,
                #[cfg(feature = "crypto-aes-gcm")]
                &self.superblock.instance_uuid,
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
        Ok(self
            .read_metadata_block_any_type(lba, block_type, block_type, owner_id, out)?
            .0)
    }

    /// Like [`Self::read_metadata_block`], but accepts either of
    /// two block types and returns the type that matched.
    ///
    /// Stage B.3 completion: the writer emits extent tables as
    /// [`BLOCK_TYPE_EXTENT_TABLE`] (v1 records, plain objects) or
    /// [`BLOCK_TYPE_EXTENT_TABLE_V2`] (v2 records, objects with at
    /// least one compressed extent); the read path validates
    /// against the actual header type so a v1 reader of a v2
    /// block (or vice versa) fails with a precise `BadBlock`
    /// instead of parsing with the wrong record stride.
    fn read_metadata_block_any_type(
        &mut self,
        lba: u64,
        block_type_a: u32,
        block_type_b: u32,
        owner_id: u64,
        out: &mut [u8; BLOCK_SIZE],
    ) -> Result<(BlockHeader, u32), HxfsError> {
        self.reader.read_blocks(lba, 1, out)?;
        let header = parse_header(out)?;
        if header.block_type != block_type_a && header.block_type != block_type_b {
            return Err(HxfsError::BadBlock);
        }
        let header = validate_metadata_block(out, lba, header.block_type, owner_id)?;
        // Stage B.1 wire: decrypt the payload in place if the
        // block header says v6. We do this *after* the
        // structural validation so a tampered v6 block surfaces
        // as `BadBlock` or `BadChecksum` from
        // `validate_metadata_block` first; only a structurally
        // valid v6 block reaches the AEAD. The plaintext is
        // placed back into the same buffer so the rest of the
        // read path is unchanged.
        #[cfg(feature = "crypto-aes-gcm")]
        if is_v6_encrypted_metadata(&header) {
            let key = self
                .metadata_key
                .as_ref()
                .ok_or(HxfsError::EncryptedPolicyInvalid)?;
            encrypted_metadata::decrypt_metadata_block_in_place(
                out,
                &header,
                key,
                &self.superblock.instance_uuid,
            )
            .map_err(|_| HxfsError::BadChecksum)?;
        }
        Ok((header, header.block_type))
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
    // Stage B.1 wire: allow `type_version` of 1 (plain v5) or 6
    // (encrypted v6). The header layout is identical between the
    // two; only the on-disk payload bytes differ (encrypted
    // ciphertext with GCM tag in the v6 case). The caller is
    // responsible for calling `decrypt_metadata_block_in_place`
    // after this returns when the header says v6.
    let type_version_ok = header.type_version == 1 || header.type_version == 6;
    if header.block_type != expected_type
        || !type_version_ok
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

/// Stage B.2 dirent-name variant: parse the on-disk record and
/// decrypt the body using `metadata_key` and the
/// `parent_object_id` provided by the caller.
///
/// The on-disk layout is identical to the v5 plaintext layout
/// (`object_id(8) + name_len(2) + body(name_len)`); the parent
/// dir's volume is what decides whether the body is plaintext
/// or encrypted ciphertext. For an encrypted parent, the body
/// is `nonce(12) || ciphertext(M) || tag(16)` and
/// `M = name_len - 28`.
///
/// The plaintext is written into `out` and the returned
/// `DirectoryEntry` borrows from it. `out` must be at least
/// `MAX_NAME_BYTES` long so a plaintext v5 name (up to 255
/// bytes) fits.
#[cfg(feature = "crypto-aes-gcm")]
pub(crate) fn parse_dir_record_decrypt<'a>(
    block: &[u8],
    offset: usize,
    parent_object_id: u64,
    metadata_key: &[u8; 32],
    out: &'a mut [u8],
) -> Result<DirectoryEntry<'a>, HxfsError> {
    let object_id = read_u64(block, offset)?;
    let body_len = read_u16(block, offset + 8)? as usize;
    if !(encrypted_metadata::ENCRYPTED_DIRENT_MIN_BODY..=MAX_NAME_BYTES).contains(&body_len) {
        // An encrypted dirent must be at least
        // `12 + 16 = 28` bytes long; a plaintext dirent has
        // `name_len >= 1`. The lower bound here rejects a
        // malformed short body.
        return Err(HxfsError::BadName);
    }
    let body = block
        .get(offset + 10..offset + 10 + body_len)
        .ok_or(HxfsError::BadTree)?;
    let mut enc = encrypted_metadata::EncryptedDirentName {
        body: [0u8; MAX_NAME_BYTES],
        body_len: body_len as u16,
    };
    enc.body[..body_len].copy_from_slice(body);
    let plaintext_len = enc
        .decrypt(parent_object_id, object_id, metadata_key, out)
        .map_err(|_| HxfsError::BadName)?;
    if out.len() < plaintext_len {
        return Err(HxfsError::BufferTooSmall);
    }
    let name_str = core::str::from_utf8(&out[..plaintext_len]).map_err(|_| HxfsError::BadName)?;
    Ok(DirectoryEntry {
        object_id,
        name: name_str,
    })
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

/// Byte width of a v2 extent-table record
/// ([`BLOCK_TYPE_EXTENT_TABLE_V2`]). The v1 record is 32 bytes;
/// the v2 record adds an optional per-extent compression
/// descriptor (algorithm, compressed payload length, payload
/// CRC32C) in the 8 bytes that v1 leaves unused.
pub(crate) const EXTENT_RECORD_BYTES_V2: usize = 40;

/// Per-extent compression descriptor carried by a v2
/// extent-table record. `Some` means the on-disk block is the
/// compressed payload (optionally inside the encrypted envelope);
/// the read path slices `compressed_bytes` out of the (decrypted)
/// block, decompresses it, and verifies `payload_crc32c` so a
/// corrupted compressed extent surfaces as
/// `CompressionError::BadChecksum` instead of garbage bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExtentCompressionMeta {
    /// Codec algorithm id ([`compression::COMPRESSION_LZ4`] or
    /// [`compression::COMPRESSION_ZSTD`]).
    pub algorithm: u32,
    /// Compressed payload length in bytes. The payload is the
    /// prefix of the (decrypted) on-disk block.
    pub compressed_bytes: u32,
    /// CRC32C over the compressed payload bytes.
    pub payload_crc32c: u32,
}

/// Parse one v2 extent-table record.
///
/// Returns the base [`ExtentRecord`] plus the compression
/// descriptor when [`EXTENT_FLAG_COMPRESSED`] is set. A record
/// that claims compression without a well-formed descriptor (or a
/// descriptor without the flag) is corrupt and rejected with
/// [`HxfsError::BadTree`]; a hole that also claims compression is
/// rejected the same way.
pub(crate) fn parse_extent_record_v2(
    block: &[u8],
    offset: usize,
) -> Result<(ExtentRecord, Option<ExtentCompressionMeta>), HxfsError> {
    let logical_block = read_u64(block, offset)?;
    let physical_block = read_u64(block, offset + 8)?;
    let block_count = read_u32(block, offset + 16)?;
    let flags = read_u32(block, offset + 20)?;
    let algorithm = read_u32(block, offset + 24)?;
    let compressed_bytes = read_u32(block, offset + 28)?;
    let payload_crc32c = read_u32(block, offset + 32)?;
    if block_count == 0 {
        return Err(HxfsError::BadTree);
    }
    let compressed = flags & EXTENT_FLAG_COMPRESSED != 0;
    if compressed && flags & EXTENT_FLAG_HOLE != 0 {
        return Err(HxfsError::BadTree);
    }
    let multi_slot = flags & EXTENT_FLAG_MULTI_SLOT != 0;
    if multi_slot {
        // A two-slot extent is one logical block over two physical
        // slots, is never compressed, never a hole, and never
        // carries descriptor bytes.
        if flags & (EXTENT_FLAG_HOLE | EXTENT_FLAG_COMPRESSED) != 0 || block_count != 2 {
            return Err(HxfsError::BadTree);
        }
        if algorithm != 0 || compressed_bytes != 0 || payload_crc32c != 0 {
            return Err(HxfsError::BadTree);
        }
    }
    let meta = if compressed {
        if !matches!(
            algorithm,
            compression::COMPRESSION_LZ4 | compression::COMPRESSION_ZSTD
        ) || compressed_bytes == 0
            || compressed_bytes as usize > BLOCK_SIZE
        {
            return Err(HxfsError::BadTree);
        }
        Some(ExtentCompressionMeta {
            algorithm,
            compressed_bytes,
            payload_crc32c,
        })
    } else {
        // A plain v2 record must not carry descriptor bytes;
        // they would be silently ignored otherwise.
        if algorithm != 0 || compressed_bytes != 0 || payload_crc32c != 0 {
            return Err(HxfsError::BadTree);
        }
        None
    };
    Ok((
        ExtentRecord {
            logical_block,
            physical_block,
            block_count,
            flags,
        },
        meta,
    ))
}

#[cfg(test)]
mod extent_record_v2_tests {
    use super::*;

    fn make_v2_record(flags: u32, algorithm: u32, compressed_bytes: u32, crc: u32) -> [u8; 40] {
        let mut record = [0u8; EXTENT_RECORD_BYTES_V2];
        record[0..8].copy_from_slice(&7u64.to_le_bytes());
        record[8..16].copy_from_slice(&42u64.to_le_bytes());
        record[16..20].copy_from_slice(&1u32.to_le_bytes());
        record[20..24].copy_from_slice(&flags.to_le_bytes());
        record[24..28].copy_from_slice(&algorithm.to_le_bytes());
        record[28..32].copy_from_slice(&compressed_bytes.to_le_bytes());
        record[32..36].copy_from_slice(&crc.to_le_bytes());
        record
    }

    #[test]
    fn v2_record_round_trip_with_compression_descriptor() {
        let record = make_v2_record(
            EXTENT_FLAG_COMPRESSED,
            compression::COMPRESSION_LZ4,
            1024,
            0xdead_beef,
        );
        let (extent, meta) = match parse_extent_record_v2(&record, 0) {
            Ok(parsed) => parsed,
            Err(e) => {
                assert!(false, "valid v2 record must parse: {:?}", e);
                return;
            }
        };
        assert_eq!(extent.logical_block, 7);
        assert_eq!(extent.physical_block, 42);
        assert_eq!(extent.block_count, 1);
        assert_eq!(extent.flags, EXTENT_FLAG_COMPRESSED);
        let meta = match meta {
            Some(meta) => meta,
            None => {
                assert!(false, "compressed record must carry a descriptor");
                return;
            }
        };
        assert_eq!(meta.algorithm, compression::COMPRESSION_LZ4);
        assert_eq!(meta.compressed_bytes, 1024);
        assert_eq!(meta.payload_crc32c, 0xdead_beef);
    }

    #[test]
    fn v2_plain_record_round_trip_without_descriptor() {
        let record = make_v2_record(0, 0, 0, 0);
        let (extent, meta) = match parse_extent_record_v2(&record, 0) {
            Ok(parsed) => parsed,
            Err(e) => {
                assert!(false, "valid plain v2 record must parse: {:?}", e);
                return;
            }
        };
        assert_eq!(extent.flags, 0);
        assert!(meta.is_none());
    }

    #[test]
    fn v2_multi_slot_record_round_trip() {
        let mut record = make_v2_record(EXTENT_FLAG_MULTI_SLOT, 0, 0, 0);
        record[16..20].copy_from_slice(&2u32.to_le_bytes());
        let (extent, meta) = match parse_extent_record_v2(&record, 0) {
            Ok(parsed) => parsed,
            Err(e) => {
                assert!(false, "valid multi-slot record must parse: {:?}", e);
                return;
            }
        };
        assert_eq!(extent.flags, EXTENT_FLAG_MULTI_SLOT);
        assert_eq!(extent.block_count, 2);
        assert!(meta.is_none());
    }

    #[test]
    fn v2_multi_slot_record_rejects_wrong_block_count() {
        let record = make_v2_record(EXTENT_FLAG_MULTI_SLOT, 0, 0, 0);
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree),
            "multi-slot without block_count == 2 must be rejected"
        );
    }

    #[test]
    fn v2_multi_slot_record_rejects_compression_combination() {
        let mut record = make_v2_record(
            EXTENT_FLAG_MULTI_SLOT | EXTENT_FLAG_COMPRESSED,
            compression::COMPRESSION_LZ4,
            1024,
            1,
        );
        record[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree),
            "multi-slot must not combine with compression"
        );
    }

    #[test]
    fn v2_record_rejects_zero_block_count() {
        let mut record = make_v2_record(0, 0, 0, 0);
        record[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_flag_without_descriptor() {
        let record = make_v2_record(EXTENT_FLAG_COMPRESSED, 0, 0, 0);
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_descriptor_without_flag() {
        let record = make_v2_record(0, compression::COMPRESSION_LZ4, 1024, 1);
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_unknown_algorithm() {
        let record = make_v2_record(EXTENT_FLAG_COMPRESSED, 99, 1024, 1);
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_oversized_compressed_bytes() {
        let record = make_v2_record(
            EXTENT_FLAG_COMPRESSED,
            compression::COMPRESSION_LZ4,
            (BLOCK_SIZE + 1) as u32,
            1,
        );
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_hole_claiming_compression() {
        let record = make_v2_record(
            EXTENT_FLAG_HOLE | EXTENT_FLAG_COMPRESSED,
            compression::COMPRESSION_LZ4,
            1024,
            1,
        );
        assert_eq!(
            parse_extent_record_v2(&record, 0).err(),
            Some(HxfsError::BadTree)
        );
    }

    #[test]
    fn v2_record_rejects_truncated_record() {
        let record = make_v2_record(
            EXTENT_FLAG_COMPRESSED,
            compression::COMPRESSION_LZ4,
            1024,
            1,
        );
        let truncated = &record[..24];
        assert_eq!(
            parse_extent_record_v2(truncated, 0).err(),
            Some(HxfsError::BadTree)
        );
    }
}

/// Stage B.3 wire: read a 4 KiB data extent into `out`.
/// The function takes an optional per-volume extent subkey
/// and the volume's `instance_uuid` for the AEAD nonce /
/// AAD. When `extent_key` is `Some`, each on-disk 4 KiB
/// block is decrypted with AES-256-GCM **before**
/// decompression; the page cache still holds the
/// *plaintext* (decompressed) so subsequent reads skip both
/// the AEAD work and the codec. A bad GCM tag surfaces as
/// `HxfsError::Compression` at the read boundary (matching
/// the existing compression-error reporting so the higher
/// layer can mark the extent bad).
///
/// `volume_uuid` is consumed as a `&[u8]` so callers can
/// pass `&self.superblock.instance_uuid` without first
/// copying into a `[u8; 16]`; the function truncates to
/// the first 16 bytes (the AEAD only mixes the first 8
/// bytes into the nonce and the full 16 into the AAD, so
/// anything past byte 15 is ignored).
#[allow(clippy::too_many_arguments)]
fn copy_extent_with_keys<R: BlockReader>(
    reader: &mut R,
    extent: ExtentRecord,
    compression: Option<compression::CompressionPolicy>,
    meta: Option<ExtentCompressionMeta>,
    page_cache: &mut page_cache::PageCache,
    volume_id: u64,
    #[cfg(feature = "crypto-aes-gcm")] extent_key: Option<&[u8; 32]>,
    #[cfg(feature = "crypto-aes-gcm")] volume_uuid: &[u8],
    out: &mut [u8],
) -> Result<(), HxfsError> {
    // Reinterpret the 16-byte volume UUID slice as a
    // `Uuid` for the AEAD nonce/AAD builder. The caller
    // passes the volume's `instance_uuid` bytes.
    #[cfg(feature = "crypto-aes-gcm")]
    let volume_uuid: [u8; 16] = {
        let mut id = [0u8; 16];
        let len = volume_uuid.len().min(16);
        id[..len].copy_from_slice(&volume_uuid[..len]);
        id
    };
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
    // A two-slot extent: one logical block stored as two encrypted
    // envelopes (slot 0 = first 4028 bytes, slot 1 = the rest).
    // The generic loop below walks `block_count` logical blocks,
    // which is wrong for a two-slot record, so handle it here.
    #[cfg(feature = "crypto-aes-gcm")]
    if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
        let key = extent_key.ok_or(HxfsError::BadTree)?;
        let mut slot0 = [0u8; BLOCK_SIZE];
        let mut slot1 = [0u8; BLOCK_SIZE];
        reader.read_blocks(extent.physical_block, 1, &mut slot0)?;
        reader.read_blocks(extent.physical_block + 1, 1, &mut slot1)?;
        let mut dec0 = [0u8; BLOCK_SIZE];
        let mut dec1 = [0u8; BLOCK_SIZE];
        extent_crypto::decrypt_extent_block(
            key,
            extent.physical_block,
            &volume_uuid,
            &slot0,
            &mut dec0,
        )
        .map_err(|_| HxfsError::Compression)?;
        extent_crypto::decrypt_extent_block(
            key,
            extent.physical_block + 1,
            &volume_uuid,
            &slot1,
            &mut dec1,
        )
        .map_err(|_| HxfsError::Compression)?;
        let mut composed = [0u8; BLOCK_SIZE];
        composed[..extent_crypto::EXTENT_PLAINTEXT_BYTES]
            .copy_from_slice(&dec0[..extent_crypto::EXTENT_PLAINTEXT_BYTES]);
        let tail = BLOCK_SIZE - extent_crypto::EXTENT_PLAINTEXT_BYTES;
        composed[extent_crypto::EXTENT_PLAINTEXT_BYTES..].copy_from_slice(&dec1[..tail]);
        let chunk = copy_end.min(start + BLOCK_SIZE) - start;
        out[start..start + chunk].copy_from_slice(&composed[..chunk]);
        page_cache.insert(volume_id, extent.physical_block, 0, composed.to_vec());
        return Ok(());
    }
    #[cfg(not(feature = "crypto-aes-gcm"))]
    if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
        // Two-slot extents are an encrypted-volume concept; a
        // volume without a key cannot produce or consume them.
        return Err(HxfsError::BadTree);
    }

    let mut scratch = [0u8; BLOCK_SIZE];
    // The intermediate buffer for decrypted-but-still-
    // compressed bytes. Only used when both encryption and
    // compression are present; for either single layer
    // (or none) we read straight into `scratch` and let the
    // existing compression path handle the data. The
    // buffer is `let mut` because the AEAD decrypt API
    // takes `&mut [u8]` for the output and we re-bind the
    // binding on each call.
    #[cfg(feature = "crypto-aes-gcm")]
    let mut compressed_after_decrypt = [0u8; BLOCK_SIZE];
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
        // A.3 + B.3 wire: the on-disk block is
        // `compressed-then-encrypted` (or just compressed, or
        // just encrypted, or plain). The plaintext is the
        // result of `decrypt(decompress(scratch))` when both
        // layers are present, `decompress(scratch)` for
        // compression-only, `decrypt(scratch)` for
        // encryption-only, or `scratch` itself for plain.
        //
        // We always end up with `block_slice: &[u8]` of
        // length `BLOCK_SIZE` (the decompressor pads short
        // compressed payloads to a fixed-size 4 KiB output).
        // Stage B.3 completion: a v2 extent record carries the
        // per-extent compression descriptor, so the codec and the
        // CRC verification come from the record itself; a v1
        // record keeps the policy-driven path (which is what old
        // volumes on disk contain). A compressed payload whose
        // CRC32C does not match is a corrupted extent and is
        // rejected with `HxfsError::Compression` at this boundary
        // (the internal `CompressionError::BadChecksum` is
        // observable from `decompress_block` directly).
        let block_slice: &[u8] = if let Some(meta) = meta {
            #[cfg(feature = "crypto-aes-gcm")]
            let payload: &[u8] = match extent_key {
                Some(key) => {
                    let physical_block = extent.physical_block + extent_block as u64;
                    extent_crypto::decrypt_extent_block(
                        key,
                        physical_block,
                        &volume_uuid,
                        &scratch,
                        &mut compressed_after_decrypt,
                    )
                    .map_err(|_| HxfsError::Compression)?;
                    &compressed_after_decrypt[..meta.compressed_bytes as usize]
                }
                None => &scratch[..meta.compressed_bytes as usize],
            };
            #[cfg(not(feature = "crypto-aes-gcm"))]
            let payload: &[u8] = &scratch[..meta.compressed_bytes as usize];
            let descriptor = compression::CompressedExtent {
                logical_block: extent.logical_block,
                physical_block: extent.physical_block,
                uncompressed_bytes: BLOCK_SIZE as u32,
                compressed_bytes: meta.compressed_bytes,
                algorithm: meta.algorithm,
                payload_crc32c: meta.payload_crc32c,
            };
            compression::decompress_block(&descriptor, payload, &mut decompressed)
                .map_err(|_| HxfsError::Compression)?;
            &decompressed[..]
        } else {
            #[cfg(feature = "crypto-aes-gcm")]
            let legacy: &[u8] = match (extent_key, compression) {
                (Some(key), Some(policy)) => {
                    // Encrypted + compressed.
                    let physical_block = extent.physical_block + extent_block as u64;
                    extent_crypto::decrypt_extent_block(
                        key,
                        physical_block,
                        &volume_uuid,
                        &scratch,
                        &mut compressed_after_decrypt,
                    )
                    .map_err(|_| HxfsError::Compression)?;
                    decompress_into(&policy, &compressed_after_decrypt, &mut decompressed)?
                }
                (Some(key), None) => {
                    // Encrypted, not compressed.
                    let physical_block = extent.physical_block + extent_block as u64;
                    extent_crypto::decrypt_extent_block(
                        key,
                        physical_block,
                        &volume_uuid,
                        &scratch,
                        &mut decompressed,
                    )
                    .map_err(|_| HxfsError::Compression)?;
                    &decompressed[..]
                }
                (None, Some(policy)) => {
                    // Compressed, not encrypted (existing A.3 path).
                    decompress_into(&policy, &scratch, &mut decompressed)?
                }
                (None, None) => &scratch[..],
            };
            #[cfg(not(feature = "crypto-aes-gcm"))]
            let legacy: &[u8] = match compression {
                Some(policy) => decompress_into(&policy, &scratch, &mut decompressed)?,
                None => &scratch[..],
            };
            legacy
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

/// Helper for `copy_extent_with_keys` / `copy_extent`: run
/// the resolved compression codec on `input` and write the
/// result into `output`. Returns a `&[u8]` of length
/// `BLOCK_SIZE` (the caller-supplied output buffer). Codec
/// errors surface as `HxfsError::Compression`.
fn decompress_into<'a>(
    policy: &compression::CompressionPolicy,
    input: &[u8],
    output: &'a mut [u8; BLOCK_SIZE],
) -> Result<&'a [u8], HxfsError> {
    match policy.algorithm {
        compression::COMPRESSION_NONE => {
            // Treat the input bytes as the plaintext
            // directly. The caller only ever feeds us a 4 KiB
            // scratch buffer here, so the output is also 4
            // KiB.
            output.copy_from_slice(input);
            Ok(&output[..])
        }
        compression::COMPRESSION_LZ4 => {
            #[cfg(feature = "compression-engines")]
            {
                compression::decompress_lz4(input, output).map_err(|_| HxfsError::Compression)?;
                Ok(&output[..])
            }
            #[cfg(not(feature = "compression-engines"))]
            {
                let _ = (input, output);
                Err(HxfsError::Compression)
            }
        }
        _ => Err(HxfsError::Compression),
    }
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

// A.7 wire: production-readiness host tests for the
// Stage A tracks. The tests are deliberately compact;
// the qemu-nvme-boot smoke harness covers the full
// end-to-end path.

#[test]
fn a4_page_cache_lookup_and_insert_round_trip() {
    // A.4 wire: insert a 4 KiB page, then look it up
    // by the same triple. The cache is FIFO with a
    // bounded walk; a populated entry is always hit.
    let mut cache = page_cache::PageCache::new();
    let page = vec![0xaau8; BLOCK_SIZE];
    cache.insert(1, 100, 3, page.clone());
    let got = match cache.lookup(1, 100, 3) {
        Some(p) => p,
        None => panic!("hit"),
    };
    assert_eq!(got, page);
    assert_eq!(cache.hits(), 1);
    // Miss for a different key.
    assert!(cache.lookup(1, 100, 4).is_none());
    // Invalidate the extent; the cached page is gone.
    cache.invalidate_extent(100);
    assert!(cache.lookup(1, 100, 3).is_none());
}

// B.1 + B.2 wire: end-to-end test for encrypted metadata
// I/O. The host test creates a fixed-capacity encrypted
// volume, writes a file, flushes the checkpoint, then
// re-mounts the volume with the same encryption policy
// table and reads the file back. The on-disk dirent block
// must carry the v6 header (type_version = 6) and the
// dirent name body must be ciphertext; the read path
// decrypts both.

#[cfg(feature = "crypto-aes-gcm")]
#[test]
fn b1_b2_encrypted_volume_write_then_read_round_trip() {
    use crate::fixed_writer::FixedHxfsWriter;
    use crate::reader::SliceBlockReader;
    use crate::recovery::BlockStore;
    use crate::writer::VecBlockStore;

    // Use `VecBlockStore` (in-memory, host-only) so we can
    // mount the writer, write a file, and grab the image
    // bytes back without a real block device. The block
    // store implements `BlockStore: BlockReader` so the
    // writer can call `read_blocks` to load the superblock.
    let mut store = VecBlockStore::with_blocks(128);
    // The writer needs a starting superblock; we drop the
    // boot image from `build_image(true)` into the store so
    // the mount gate sees a v5 superblock with
    // `VOLUME_FLAG_ENCRYPTED` and `encryption_policy_id = 7`.
    let boot_image = build_encrypted_boot_image();
    let boot_blocks = (boot_image.len() / BLOCK_SIZE) as u32;
    if let Err(e) = store.write_blocks(0, boot_blocks, &boot_image) {
        assert!(false, "boot write must succeed: {:?}", e);
        return;
    }

    // The encryption policy we resolve against at mount
    // time; must match the policy_id in the boot image.
    let policy = crate::crypto::EncryptionPolicy {
        policy_id: 7,
        algorithm: crate::crypto::ALGORITHM_AES_XTS,
        data_unit_bytes: crate::crypto::DATA_UNIT_BYTES_4K,
        provider: crate::crypto::KeyProvider::TpmOrBootloader,
    };

    let Ok(mut writer) =
        FixedHxfsWriter::<VecBlockStore, 16, 32, 32>::mount_with_keys(store, &[policy])
    else {
        assert!(false, "writer mount must succeed for encrypted volume");
        return;
    };
    // Write a tiny file at /hello.txt. The dirent block for
    // the root directory will be re-encrypted at publish time.
    // The boot image already has a `hello.txt` entry; we
    // open the existing child and overwrite its payload
    // rather than calling `create_file_child` (which would
    // fail with `AlreadyExists`).
    let root = writer.root_directory();
    let payload = b"hello hxfs\n";
    let file = match writer.open_child_file(root, "hello.txt") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_child_file must succeed: {:?}", e);
            return;
        }
    };
    let _ = match writer.write_file_at(file, 0, payload) {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "write_file_at must succeed: {:?}", e);
            return;
        }
    };
    // Publish the checkpoint; this re-encrypts the dirent
    // block and the extent table under the metadata subkey.
    let _ = match writer.publish_checkpoint() {
        Ok(_) => {}
        Err(e) => {
            assert!(false, "publish_checkpoint must succeed: {:?}", e);
            return;
        }
    };
    // Consume the writer and grab the image bytes.
    let store = writer.into_store();
    let image = store.image().to_vec();
    // The new dirent block written by `publish_checkpoint`
    // carries `type_version = 6` in its header. The LBA is
    // `next_lba` (the writer allocates fresh LBAs for
    // publish-time metadata, leaving the boot LBA 4 in
    // place as historical state). The fixed writer stores
    // the resulting checkpoint at a fresh LBA as well;
    // we look at the writer's own LBA counter to find the
    // new dirent block.
    //
    // The writer's publish path lays out blocks as:
    //   target_start_lba = next_lba (7 in this image),
    //   target_start_lba + 0 = dirent tree for root (object 1),
    //   target_start_lba + 1 = extent table for object 2.
    // So the encrypted dirent block lives at LBA 7.
    let dir_lba: u64 = 8;
    let dir_offset = (dir_lba as usize) * BLOCK_SIZE;
    let type_version = u16::from_le_bytes([image[dir_offset + 4], image[dir_offset + 5]]);
    assert_eq!(
        type_version, 6,
        "dirent block must be encrypted (type_version == 6)"
    );
    // The body bytes (after the header) must NOT contain the
    // plaintext name `hello.txt`. The AEAD tag would never
    // verify if an attacker flipped the bytes back, but
    // reading the bytes directly off disk shows the body is
    // ciphertext.
    let body_bytes = &image[dir_offset + HEADER_BYTES..dir_offset + 16 + DIR_RECORD_BYTES];
    let mut found = false;
    let mut index = 0usize;
    while index + 9 <= body_bytes.len() {
        if &body_bytes[index..index + 9] == b"hello.txt" {
            found = true;
            break;
        }
        index += 1;
    }
    assert!(
        !found,
        "dirent body must not contain plaintext 'hello.txt' on disk"
    );

    // Now remount the volume with the same policy table and
    // read the file back. The reader derives the same
    // metadata subkey from the placeholder IKM + the volume
    // UUID; the v6 block decrypts and the dirent name
    // decrypts into the plaintext `hello.txt`.
    let reader = SliceBlockReader::new(&image);
    let Ok(mut fs) = Hxfs::mount_with_keys(reader, &[policy]) else {
        assert!(false, "remount with key must succeed");
        return;
    };
    // `encryption` accessor must return the resolved policy.
    assert!(fs.encryption().is_some());
    // The file is at /hello.txt.
    let file = match fs.open_path("/hello.txt") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed for encrypted file: {:?}", e);
            return;
        }
    };
    let mut buf = [0u8; 32];
    let read = match fs.read_file(file, &mut buf) {
        Ok(n) => n,
        Err(e) => {
            assert!(false, "read_file must succeed: {:?}", e);
            return;
        }
    };
    assert_eq!(read, payload.len(), "read length must match payload");
    assert_eq!(&buf[..read], payload, "round-trip bytes must match");
}

#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn build_encrypted_boot_image() -> Vec<u8> {
    // Full v5 boot image: superblock, checkpoint, volume
    // table, object table, root dirent, child extent
    // table, and 11 bytes of file payload. Mirrors the
    // `build_image(true)` helper in the inner `tests`
    // module but is callable from this module.
    use alloc::vec;
    use alloc::vec::Vec;
    const INSTANCE_TEST: Uuid = [0x11; 16];
    const VOLUME_TEST: Uuid = [0x22; 16];
    fn mk(bt: u32, owner: u64, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&bt.to_le_bytes());
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
    let mut image: Vec<u8> = vec![0u8; BLOCK_SIZE * 8];
    let mut sp = [0u8; 120];
    sp[0..16].copy_from_slice(&FORMAT_GUID);
    sp[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    sp[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
    sp[24..40].copy_from_slice(&INSTANCE_TEST);
    sp[40..48].copy_from_slice(&1u64.to_le_bytes());
    sp[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    sp[56..64].copy_from_slice(&1u64.to_le_bytes());
    sp[104..112].copy_from_slice(&BASE_INCOMPAT_FEATURES.to_le_bytes());
    sp[112..116].copy_from_slice(&ROOT_STATE_CLEAN.to_le_bytes());
    image[0..BLOCK_SIZE].copy_from_slice(&mk(BLOCK_TYPE_SUPERBLOCK, 0, 0, &sp));
    let mut cp = [0u8; 128];
    cp[0..8].copy_from_slice(&1u64.to_le_bytes());
    cp[8..16].copy_from_slice(&2u64.to_le_bytes());
    cp[16..20].copy_from_slice(&1u32.to_le_bytes());
    cp[24..40].copy_from_slice(&VOLUME_TEST);
    image[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&mk(BLOCK_TYPE_CHECKPOINT, 0, 1, &cp));
    let mut vp = [0u8; 16 + VOLUME_RECORD_BYTES];
    vp[0..4].copy_from_slice(&1u32.to_le_bytes());
    vp[16..32].copy_from_slice(&VOLUME_TEST);
    vp[32..40].copy_from_slice(&1u64.to_le_bytes());
    vp[40..48].copy_from_slice(&3u64.to_le_bytes());
    vp[48..52].copy_from_slice(&2u32.to_le_bytes());
    vp[52..56].copy_from_slice(&(VOLUME_FLAG_SYSTEM | VOLUME_FLAG_ENCRYPTED).to_le_bytes());
    vp[56..60].copy_from_slice(&7u32.to_le_bytes());
    image[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&mk(BLOCK_TYPE_VOLUME_TABLE, 0, 2, &vp));
    let mut op = [0u8; 16 + 2 * OBJECT_RECORD_BYTES];
    op[0..4].copy_from_slice(&2u32.to_le_bytes());
    write_object(&mut op, 16, 1, OBJECT_TYPE_DIRECTORY, 0, 4, 1);
    write_object(
        &mut op,
        16 + OBJECT_RECORD_BYTES,
        2,
        OBJECT_TYPE_FILE,
        11,
        5,
        1,
    );
    image[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&mk(BLOCK_TYPE_OBJECT_TABLE, 1, 3, &op));
    let mut dp = [0u8; 16 + DIR_RECORD_BYTES];
    dp[0..8].copy_from_slice(&1u64.to_le_bytes());
    dp[8..12].copy_from_slice(&1u32.to_le_bytes());
    dp[16..24].copy_from_slice(&2u64.to_le_bytes());
    dp[24..26].copy_from_slice(&9u16.to_le_bytes());
    dp[26..35].copy_from_slice(b"hello.txt");
    image[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&mk(BLOCK_TYPE_DIRECTORY, 1, 4, &dp));
    let mut ep = [0u8; 16 + EXTENT_RECORD_BYTES];
    ep[0..8].copy_from_slice(&2u64.to_le_bytes());
    ep[8..12].copy_from_slice(&1u32.to_le_bytes());
    ep[16..24].copy_from_slice(&0u64.to_le_bytes());
    ep[24..32].copy_from_slice(&6u64.to_le_bytes());
    ep[32..36].copy_from_slice(&1u32.to_le_bytes());
    image[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&mk(BLOCK_TYPE_EXTENT_TABLE, 2, 5, &ep));
    image[BLOCK_SIZE * 6..BLOCK_SIZE * 6 + 11].copy_from_slice(b"hello hxfs\n");
    image
}

// ---------------------------------------------------------------------------
// Stage B.5: end-to-end encrypted + compressed I/O pipeline test
// (the Stage B exit criterion). The write path that Stage B.3
// completion wires is exercised for real: a file written through
// `FixedHxfsWriter` with encryption AND compression policies
// survives a remount and reads back byte-for-byte; an
// incompressible file falls back to plain extents and also round
// trips; a single-byte corruption in the encrypted envelope is
// rejected with the precise error; and a corrupted compressed
// payload on a plain volume is rejected instead of silently
// returned. The on-disk layout is asserted to reflect the policy
// tables: the compressed file's extent table is a v2 block with
// per-extent descriptors, the data blocks carry the GCM envelope,
// and no plaintext leaks into the envelope region.
// ---------------------------------------------------------------------------

/// Build the boot image the Stage B.5 test mounts, delegating to
/// the shared [`crate::synthetic_image`] builder with the test
/// instance/volume UUIDs and the synthetic policy id.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn build_seeded_boot_image(encrypted: bool, compression_policy_id: u32) -> Vec<u8> {
    let instance_uuid = [0x11; 16];
    let volume_uuid = [0x22; 16];
    let policy_id = if encrypted {
        crate::synthetic_key::POLICY_ID
    } else {
        0
    };
    crate::synthetic_image::build_boot_image(
        instance_uuid,
        volume_uuid,
        encrypted,
        policy_id,
        compression_policy_id,
    )
}

/// Host-only block store wrapper that records the (lba, blocks)
/// ranges written while `recording` is enabled. The Stage B.5
/// test uses it to locate the file's data extents on disk for the
/// on-disk layout and tamper assertions.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
struct RecordingStore {
    inner: crate::writer::VecBlockStore,
    recording: bool,
    ranges: Vec<(u64, u32)>,
}

#[cfg(all(test, feature = "crypto-aes-gcm"))]
impl RecordingStore {
    fn new(inner: crate::writer::VecBlockStore) -> Self {
        Self {
            inner,
            recording: false,
            ranges: Vec::new(),
        }
    }

    fn start_recording(&mut self) {
        self.recording = true;
    }

    fn stop_recording(&mut self) -> Vec<(u64, u32)> {
        self.recording = false;
        core::mem::take(&mut self.ranges)
    }
}

#[cfg(all(test, feature = "crypto-aes-gcm"))]
impl crate::reader::BlockReader for RecordingStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.inner.read_blocks(lba, blocks, out)
    }
}

#[cfg(all(test, feature = "crypto-aes-gcm"))]
impl crate::recovery::BlockStore for RecordingStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        if self.recording {
            self.ranges.push((lba, blocks));
        }
        self.inner.write_blocks(lba, blocks, input)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.inner.flush()
    }
}

/// Little-endian u32 read used by the on-disk assertions; returns
/// `None` instead of panicking on a short slice.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn le_u32_at(image: &[u8], offset: usize) -> Option<u32> {
    let bytes = image.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Count metadata blocks of the given `block_type` in the image.
///
/// Only blocks that carry a plausible metadata header (v1 or v6
/// `type_version`, `header_bytes == HEADER_BYTES`) are counted:
/// on encrypted volumes a data block starts with the AEAD nonce
/// (whose first 4 bytes are the physical LBA) and would otherwise
/// false-positive as a metadata block type.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn count_metadata_blocks(image: &[u8], block_type: u32) -> usize {
    let mut count = 0usize;
    let mut lba = 0usize;
    while (lba + 1) * BLOCK_SIZE <= image.len() {
        let base = lba * BLOCK_SIZE;
        if let Some(bt) = le_u32_at(image, base) {
            if bt == block_type {
                let tv =
                    u16::from_le_bytes(image[base + 4..base + 6].try_into().ok().unwrap_or([0, 0]));
                let hb =
                    u16::from_le_bytes(image[base + 6..base + 8].try_into().ok().unwrap_or([0, 0]));
                if matches!(tv, 1 | 6) && hb as usize == HEADER_BYTES {
                    count += 1;
                }
            }
        }
        lba += 1;
    }
    count
}

/// Fill a 4 KiB chunk with a deterministic, highly compressible
/// pattern; the first 8 bytes carry the block index so blocks are
/// distinguishable in the byte-for-byte assertion.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn fill_compressible_chunk(chunk: &mut [u8; BLOCK_SIZE], index: usize) {
    const LINE: &[u8] =
        b"HuesOS Stage B.5 encrypted+compressed I/O pipeline verification 0123456789\n";
    let mut pos = 0usize;
    while pos < chunk.len() {
        let n = (chunk.len() - pos).min(LINE.len());
        chunk[pos..pos + n].copy_from_slice(&LINE[..n]);
        pos += n;
    }
    chunk[0..8].copy_from_slice(&index.to_le_bytes());
}

/// Deterministic xorshift64 PRNG for the incompressible file.
#[cfg(all(test, feature = "crypto-aes-gcm"))]
fn next_random(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Stage B.5 end-to-end test. See the module comment above for the
/// full scope; the test is one function per the Stage B plan
/// (`write_then_read_encrypted_compressed_volume`) with the
/// tamper and fallback phases folded in.
#[cfg(all(test, feature = "crypto-aes-gcm", feature = "compression-engines"))]
#[test]
fn write_then_read_encrypted_compressed_volume() {
    use crate::fixed_writer::FixedHxfsWriter;
    use crate::reader::SliceBlockReader;
    use crate::recovery::BlockStore;
    use crate::writer::VecBlockStore;
    use alloc::vec;

    // 100 extents x 4 KiB = 400 KiB. This is the maximum file size
    // the single-block extent table supports with v2 records
    // ((4056 - 16) / 40 = 101 records per block); the multi-block
    // extent tree that lifts this limit is tracked as a Stage C+
    // known limitation.
    const CHUNKS: usize = 100;
    const FILE_BYTES: usize = CHUNKS * BLOCK_SIZE;

    let policies = [crate::synthetic_key::encryption_policy()];
    let comps = [crate::synthetic_key::compression_policy()];

    // ---- Phase 1: write seed.bin (compressible) + random.bin ----
    let boot_image = build_seeded_boot_image(true, crate::synthetic_key::COMPRESSION_POLICY_ID);
    let mut store = RecordingStore::new(VecBlockStore::with_blocks(512));
    let boot_blocks = (boot_image.len() / BLOCK_SIZE) as u32;
    if let Err(e) = store.write_blocks(0, boot_blocks, &boot_image) {
        assert!(false, "boot write must succeed: {:?}", e);
        return;
    }
    let Ok(mut writer) = FixedHxfsWriter::<RecordingStore, 16, 32, 256>::mount_with_policies(
        store, &policies, &comps,
    ) else {
        assert!(
            false,
            "writer mount must succeed for encrypted+compressed volume"
        );
        return;
    };
    let root = writer.root_directory();
    let file = match writer.open_child_file(root, crate::synthetic_key::SEED_FILE_NAME) {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_child_file must succeed: {:?}", e);
            return;
        }
    };
    let mut written = Vec::new();
    writer.store_mut().start_recording();
    let mut index = 0usize;
    while index < CHUNKS {
        let mut chunk = [0u8; BLOCK_SIZE];
        fill_compressible_chunk(&mut chunk, index);
        if let Err(e) = writer.write_file_at(file, (index * BLOCK_SIZE) as u64, &chunk) {
            assert!(false, "write_file_at must succeed: {:?}", e);
            return;
        }
        written.extend_from_slice(&chunk);
        index += 1;
    }
    let data_ranges = writer.store_mut().stop_recording();
    if data_ranges.is_empty() {
        assert!(false, "no data blocks recorded");
        return;
    }
    if let Err(e) = writer.publish_checkpoint() {
        assert!(false, "publish_checkpoint must succeed: {:?}", e);
        return;
    }
    let store = writer.into_store();
    let image = store.inner.image().to_vec();

    // ---- Phase 2: on-disk layout reflects the policy tables ----
    let v2_count = count_metadata_blocks(&image, BLOCK_TYPE_EXTENT_TABLE_V2);
    let v1_count = count_metadata_blocks(&image, BLOCK_TYPE_EXTENT_TABLE);
    assert!(
        v2_count >= 1,
        "the compressed seed.bin must have at least one v2 extent table (journal + final copies)"
    );
    assert!(
        v1_count >= 1,
        "the boot image's empty v1 extent table survives in the old checkpoint"
    );
    // Locate the v2 block and assert its header + first record.
    let mut v2_lba = None;
    let mut lba = 0usize;
    while (lba + 1) * BLOCK_SIZE <= image.len() {
        let base = lba * BLOCK_SIZE;
        if let Some(bt) = le_u32_at(&image, base) {
            if bt == BLOCK_TYPE_EXTENT_TABLE_V2 {
                let tv =
                    u16::from_le_bytes(image[base + 4..base + 6].try_into().ok().unwrap_or([0, 0]));
                let hb =
                    u16::from_le_bytes(image[base + 6..base + 8].try_into().ok().unwrap_or([0, 0]));
                if matches!(tv, 1 | 6) && hb as usize == HEADER_BYTES {
                    v2_lba = Some(lba);
                }
            }
        }
        lba += 1;
    }
    let v2_lba = match v2_lba {
        Some(v) => v,
        None => {
            assert!(false, "v2 extent table block not found");
            return;
        }
    };
    // The volume is encrypted, so every metadata block carries the
    // v6 discriminator in its (plaintext) header; the record
    // payload itself is ciphertext, so the record-level descriptor
    // assertions live in the plain-volume test where the records
    // are readable raw.
    let v2_tv = u16::from_le_bytes(
        image[v2_lba * BLOCK_SIZE + 4..v2_lba * BLOCK_SIZE + 6]
            .try_into()
            .ok()
            .unwrap_or([0, 0]),
    );
    assert_eq!(
        v2_tv, 6,
        "v2 extent table must be encrypted (type_version 6)"
    );
    // The first recorded data block is seed.bin chunk 0; its
    // envelope region must not contain the plaintext pattern.
    let first_data_lba = data_ranges[0].0;
    let envelope =
        &image[first_data_lba as usize * BLOCK_SIZE..first_data_lba as usize * BLOCK_SIZE + 4056];
    let mut probe = [0u8; BLOCK_SIZE];
    fill_compressible_chunk(&mut probe, 0);
    let needle = &probe[8..24];
    let mut found = false;
    let mut pos = 0usize;
    while pos + needle.len() <= envelope.len() {
        if &envelope[pos..pos + needle.len()] == needle {
            found = true;
            break;
        }
        pos += 1;
    }
    assert!(
        !found,
        "plaintext must not leak into the encrypted envelope"
    );

    // ---- Phase 3: remount and read back byte-for-byte ----
    let reader = SliceBlockReader::new(&image);
    let Ok(mut fs) = Hxfs::mount_with_policies(reader, &policies, &comps) else {
        assert!(false, "remount with policies must succeed");
        return;
    };
    assert!(fs.encryption().is_some());
    let file = match fs.open_path("/seed.bin") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed: {:?}", e);
            return;
        }
    };
    let mut buf = vec![0u8; FILE_BYTES];
    match fs.read_file(file, &mut buf) {
        Ok(n) => assert_eq!(n, FILE_BYTES, "read length must match"),
        Err(e) => {
            assert!(false, "read_file must succeed: {:?}", e);
            return;
        }
    }
    assert_eq!(
        &buf[..],
        &written[..],
        "compressible round trip must be byte-for-byte"
    );

    // ---- Phase 4: single-byte ciphertext corruption ----
    let mut tampered = image.clone();
    let flip = first_data_lba as usize * BLOCK_SIZE + 12 + 40;
    tampered[flip] ^= 0x01;
    let reader = SliceBlockReader::new(&tampered);
    let Ok(mut fs) = Hxfs::mount_with_policies(reader, &policies, &comps) else {
        assert!(false, "tampered volume must still mount (metadata intact)");
        return;
    };
    let file = match fs.open_path("/seed.bin") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed on tampered volume: {:?}", e);
            return;
        }
    };
    let mut buf = vec![0u8; FILE_BYTES];
    assert_eq!(
        fs.read_file(file, &mut buf).err(),
        Some(HxfsError::Compression),
        "a bad GCM tag must surface as the precise error, not a panic"
    );
}

/// Stage B.5 companion: a compressed-but-not-encrypted volume is
/// still protected by the descriptor CRC. Corrupting one payload
/// byte must fail the read with the precise error (the internal
/// `CompressionError::BadChecksum` is pinned by the existing
/// `compression` unit tests) instead of returning corrupted bytes.
#[cfg(all(test, feature = "crypto-aes-gcm", feature = "compression-engines"))]
#[test]
fn corrupted_compressed_plain_volume_fails_read_with_precise_error() {
    use crate::fixed_writer::FixedHxfsWriter;
    use crate::reader::SliceBlockReader;
    use crate::recovery::BlockStore;
    use crate::writer::VecBlockStore;

    let comps = [crate::synthetic_key::compression_policy()];
    let boot_image = build_seeded_boot_image(false, crate::synthetic_key::COMPRESSION_POLICY_ID);
    let mut store = RecordingStore::new(VecBlockStore::with_blocks(512));
    let boot_blocks = (boot_image.len() / BLOCK_SIZE) as u32;
    if let Err(e) = store.write_blocks(0, boot_blocks, &boot_image) {
        assert!(false, "boot write must succeed: {:?}", e);
        return;
    }
    let Ok(mut writer) =
        FixedHxfsWriter::<RecordingStore, 16, 32, 64>::mount_with_policies(store, &[], &comps)
    else {
        assert!(
            false,
            "writer mount must succeed for plain+compressed volume"
        );
        return;
    };
    let root = writer.root_directory();
    let file = match writer.open_child_file(root, crate::synthetic_key::SEED_FILE_NAME) {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_child_file must succeed: {:?}", e);
            return;
        }
    };
    writer.store_mut().start_recording();
    let mut index = 0usize;
    while index < 20 {
        let mut chunk = [0u8; BLOCK_SIZE];
        fill_compressible_chunk(&mut chunk, index);
        if let Err(e) = writer.write_file_at(file, (index * BLOCK_SIZE) as u64, &chunk) {
            assert!(false, "write_file_at must succeed: {:?}", e);
            return;
        }
        index += 1;
    }
    let ranges = writer.store_mut().stop_recording();
    if let Err(e) = writer.publish_checkpoint() {
        assert!(false, "publish_checkpoint must succeed: {:?}", e);
        return;
    }
    let store = writer.into_store();
    let mut image = store.inner.image().to_vec();
    // The v2 record must carry the compression descriptor
    // (plain volume: the record payload is readable raw).
    let mut descriptor_ok = false;
    let mut lba = 0usize;
    while (lba + 1) * BLOCK_SIZE <= image.len() {
        let base = lba * BLOCK_SIZE;
        if let Some(bt) = le_u32_at(&image, base) {
            if bt == BLOCK_TYPE_EXTENT_TABLE_V2 {
                let tv =
                    u16::from_le_bytes(image[base + 4..base + 6].try_into().ok().unwrap_or([0, 0]));
                let hb =
                    u16::from_le_bytes(image[base + 6..base + 8].try_into().ok().unwrap_or([0, 0]));
                if matches!(tv, 1 | 6) && hb as usize == HEADER_BYTES {
                    let record = base + HEADER_BYTES + 16;
                    let flags = le_u32_at(&image, record + 20).unwrap_or(0);
                    let algorithm = le_u32_at(&image, record + 24).unwrap_or(0);
                    let compressed_bytes = le_u32_at(&image, record + 28).unwrap_or(0);
                    let crc = le_u32_at(&image, record + 32).unwrap_or(0);
                    if flags & EXTENT_FLAG_COMPRESSED == EXTENT_FLAG_COMPRESSED
                        && algorithm == crate::compression::COMPRESSION_LZ4
                        && (0..BLOCK_SIZE as u32).contains(&compressed_bytes)
                        && crc != 0
                    {
                        descriptor_ok = true;
                    }
                }
            }
        }
        lba += 1;
    }
    assert!(
        descriptor_ok,
        "the v2 extent record must carry a well-formed compression descriptor"
    );
    let first_lba = ranges[0].0 as usize;
    // Corrupt one byte of the compressed payload (plain volume:
    // no envelope, payload starts at block offset 0).
    image[first_lba * BLOCK_SIZE + 10] ^= 0x40;
    let reader = SliceBlockReader::new(&image);
    let Ok(mut fs) = Hxfs::mount_with_policies(reader, &[], &comps) else {
        assert!(false, "tampered plain volume must still mount");
        return;
    };
    let file = match fs.open_path("/seed.bin") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed: {:?}", e);
            return;
        }
    };
    let mut buf = vec![0u8; 20 * BLOCK_SIZE];
    assert_eq!(
        fs.read_file(file, &mut buf).err(),
        Some(HxfsError::Compression),
        "corrupted compressed payload must fail with the precise error, not a panic"
    );
}

/// Phase-1 follow-up: an incompressible block larger than the
/// envelope capacity (4028 bytes) on an ENCRYPTED volume must be
/// stored as a two-slot extent (`EXTENT_FLAG_MULTI_SLOT`,
/// `block_count == 2`) instead of failing with `Unsupported`.
/// Media files, archives and already-compressed data are
/// incompressible by definition, so this is the case that makes
/// encrypted volumes usable for real workloads. The test writes a
/// full 4 KiB random block (and a 4050-byte near-full block),
/// asserts the two-slot on-disk shape via the recorded write
/// ranges, and round-trips both byte-for-byte through a remount.
#[cfg(all(test, feature = "crypto-aes-gcm", feature = "compression-engines"))]
#[test]
fn incompressible_full_block_on_encrypted_volume_uses_two_slot_extent() {
    use crate::fixed_writer::FixedHxfsWriter;
    use crate::reader::SliceBlockReader;
    use crate::recovery::BlockStore;
    use crate::writer::VecBlockStore;
    use alloc::vec;

    let policies = [crate::synthetic_key::encryption_policy()];
    let comps = [crate::synthetic_key::compression_policy()];
    let boot_image = build_seeded_boot_image(true, crate::synthetic_key::COMPRESSION_POLICY_ID);
    let mut store = RecordingStore::new(VecBlockStore::with_blocks(512));
    let boot_blocks = (boot_image.len() / BLOCK_SIZE) as u32;
    if let Err(e) = store.write_blocks(0, boot_blocks, &boot_image) {
        assert!(false, "boot write must succeed: {:?}", e);
        return;
    }
    let Ok(mut writer) = FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
        store, &policies, &comps,
    ) else {
        assert!(false, "writer mount must succeed");
        return;
    };
    let root = writer.root_directory();
    let file = match writer.open_child_file(root, crate::synthetic_key::SEED_FILE_NAME) {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_child_file must succeed: {:?}", e);
            return;
        }
    };
    // Full 4 KiB random block: incompressible, > envelope capacity.
    let mut full = [0u8; BLOCK_SIZE];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut pos = 0usize;
    while pos < full.len() {
        let value = next_random(&mut state).to_le_bytes();
        let n = (full.len() - pos).min(8);
        full[pos..pos + n].copy_from_slice(&value[..n]);
        pos += n;
    }
    writer.store_mut().start_recording();
    if let Err(e) = writer.write_file_at(file, 0, &full) {
        assert!(
            false,
            "full random block must write (two-slot), got {:?}",
            e
        );
        return;
    }
    let ranges = writer.store_mut().stop_recording();
    assert_eq!(
        ranges.len(),
        2,
        "an incompressible full block must occupy two physical slots"
    );
    assert_eq!(
        ranges[1].0,
        ranges[0].0 + 1,
        "the two slots must be consecutive"
    );
    // Near-full partial block (4050 bytes): still over the
    // envelope capacity, must also use two slots and round-trip.
    let mut near_full = [0u8; 4050];
    let mut pos = 0usize;
    while pos < near_full.len() {
        let value = next_random(&mut state).to_le_bytes();
        let n = (near_full.len() - pos).min(8);
        near_full[pos..pos + n].copy_from_slice(&value[..n]);
        pos += n;
    }
    writer.store_mut().start_recording();
    if let Err(e) = writer.write_file_at(file, BLOCK_SIZE as u64, &near_full) {
        assert!(false, "near-full random block must write, got {:?}", e);
        return;
    }
    let ranges2 = writer.store_mut().stop_recording();
    assert_eq!(ranges2.len(), 2, "near-full block must use two slots");
    if let Err(e) = writer.publish_checkpoint() {
        assert!(false, "publish_checkpoint must succeed: {:?}", e);
        return;
    }
    let store = writer.into_store();
    let image = store.inner.image().to_vec();
    // Reader round-trip: both writes must come back byte-for-byte.
    let reader = SliceBlockReader::new(&image);
    let Ok(mut fs) = Hxfs::mount_with_policies(reader, &policies, &comps) else {
        assert!(false, "remount must succeed");
        return;
    };
    let file = match fs.open_path("/seed.bin") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed: {:?}", e);
            return;
        }
    };
    let mut buf = vec![0u8; BLOCK_SIZE + 4050];
    match fs.read_file(file, &mut buf) {
        Ok(n) => assert_eq!(n, BLOCK_SIZE + 4050, "file length must match"),
        Err(e) => {
            assert!(false, "read_file must succeed: {:?}", e);
            return;
        }
    }
    assert_eq!(&buf[..BLOCK_SIZE], &full[..], "full block must round-trip");
    assert_eq!(
        &buf[BLOCK_SIZE..],
        &near_full[..],
        "near-full block must round-trip"
    );
}

/// Stage B.5 companion: the incompressible fallback on a PLAIN
/// volume. Random data written under an LZ4 volume policy must be
/// stored plain (no descriptor, no flag) and still round-trip
/// byte-for-byte after a remount; the read path must honour the
/// v2 record instead of trying to LZ4-decode the raw bytes. (On an
/// encrypted volume the same data takes the two-slot extent path,
/// covered by
/// `incompressible_full_block_on_encrypted_volume_uses_two_slot_extent`.)
#[cfg(all(test, feature = "crypto-aes-gcm", feature = "compression-engines"))]
#[test]
fn incompressible_fallback_round_trips_on_plain_volume() {
    use crate::fixed_writer::FixedHxfsWriter;
    use crate::reader::SliceBlockReader;
    use crate::recovery::BlockStore;
    use crate::writer::VecBlockStore;
    use alloc::vec;

    const CHUNKS: usize = 20;
    const FILE_BYTES: usize = CHUNKS * BLOCK_SIZE;
    let comps = [crate::synthetic_key::compression_policy()];
    let boot_image = build_seeded_boot_image(false, crate::synthetic_key::COMPRESSION_POLICY_ID);
    let mut store = RecordingStore::new(VecBlockStore::with_blocks(512));
    let boot_blocks = (boot_image.len() / BLOCK_SIZE) as u32;
    if let Err(e) = store.write_blocks(0, boot_blocks, &boot_image) {
        assert!(false, "boot write must succeed: {:?}", e);
        return;
    }
    let Ok(mut writer) =
        FixedHxfsWriter::<RecordingStore, 16, 32, 64>::mount_with_policies(store, &[], &comps)
    else {
        assert!(
            false,
            "writer mount must succeed for plain+compressed volume"
        );
        return;
    };
    let root = writer.root_directory();
    let file = match writer.open_child_file(root, crate::synthetic_key::SEED_FILE_NAME) {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_child_file must succeed: {:?}", e);
            return;
        }
    };
    let mut rand_written = Vec::new();
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut index = 0usize;
    while index < CHUNKS {
        let mut chunk = [0u8; BLOCK_SIZE];
        let mut pos = 0usize;
        while pos < chunk.len() {
            let value = next_random(&mut state).to_le_bytes();
            let n = (chunk.len() - pos).min(8);
            chunk[pos..pos + n].copy_from_slice(&value[..n]);
            pos += n;
        }
        if let Err(e) = writer.write_file_at(file, (index * BLOCK_SIZE) as u64, &chunk) {
            assert!(false, "random write_file_at must succeed: {:?}", e);
            return;
        }
        rand_written.extend_from_slice(&chunk);
        index += 1;
    }
    if let Err(e) = writer.publish_checkpoint() {
        assert!(false, "publish_checkpoint must succeed: {:?}", e);
        return;
    }
    let store = writer.into_store();
    let image = store.inner.image().to_vec();
    // The incompressible file is stored under the LZ4 volume
    // policy, so its extent table is a v2 block; every record must
    // carry `EXTENT_FLAG_COMPRESSED` clear (plain fallback), and
    // the read path must honour the descriptor instead of trying
    // to LZ4-decode the raw bytes.
    assert!(
        count_metadata_blocks(&image, BLOCK_TYPE_EXTENT_TABLE_V2) >= 1,
        "the policy-affected file must use a v2 extent table"
    );
    let mut compressed_records = 0usize;
    let mut lba = 0usize;
    while (lba + 1) * BLOCK_SIZE <= image.len() {
        let base = lba * BLOCK_SIZE;
        if let Some(bt) = le_u32_at(&image, base) {
            if bt == BLOCK_TYPE_EXTENT_TABLE_V2 {
                let tv =
                    u16::from_le_bytes(image[base + 4..base + 6].try_into().ok().unwrap_or([0, 0]));
                let hb =
                    u16::from_le_bytes(image[base + 6..base + 8].try_into().ok().unwrap_or([0, 0]));
                if matches!(tv, 1 | 6) && hb as usize == HEADER_BYTES {
                    let count = u32::from_le_bytes(
                        image[base + HEADER_BYTES + 8..base + HEADER_BYTES + 12]
                            .try_into()
                            .ok()
                            .unwrap_or([0, 0, 0, 0]),
                    );
                    let mut index = 0u32;
                    while index < count {
                        let record =
                            base + HEADER_BYTES + 16 + index as usize * EXTENT_RECORD_BYTES_V2;
                        if let Some(flags) = le_u32_at(&image, record + 20) {
                            if flags & EXTENT_FLAG_COMPRESSED != 0 {
                                compressed_records += 1;
                            }
                        }
                        index += 1;
                    }
                }
            }
        }
        lba += 1;
    }
    assert_eq!(
        compressed_records, 0,
        "random data must be stored plain (no compressed records)"
    );
    let reader = SliceBlockReader::new(&image);
    let Ok(mut fs) = Hxfs::mount_with_policies(reader, &[], &comps) else {
        assert!(false, "remount must succeed");
        return;
    };
    let file = match fs.open_path("/seed.bin") {
        Ok(f) => f,
        Err(e) => {
            assert!(false, "open_path must succeed: {:?}", e);
            return;
        }
    };
    let mut buf = vec![0u8; FILE_BYTES];
    match fs.read_file(file, &mut buf) {
        Ok(n) => assert_eq!(n, FILE_BYTES),
        Err(e) => {
            assert!(false, "read_file must succeed: {:?}", e);
            return;
        }
    }
    assert_eq!(
        &buf[..],
        &rand_written[..],
        "incompressible fallback round trip must be byte-for-byte"
    );
}
