//! Fixed-capacity, no-heap Hxfs mutable writer.
//!
//! This module is the Stage-K no-heap service foundation: it owns a writable
//! [`BlockStore`], mirrors the mounted metadata in fixed arrays, applies small
//! handle-first mutations without allocation, and publishes changes through the
//! v2 journal/root-store protocol.

use crate::alloc_tree::{AllocationBtree, AllocationRecord, AllocationState};
use crate::crc32c::{crc32c, metadata_crc32c};
use crate::format::*;
use crate::quota_tree::{QuotaBtree, QuotaRecord};
use crate::recovery::BlockStore;
use crate::ref_tree::{BackrefBtree, BackrefKind, BackrefRecord, RefcountBtree, RefcountRecord};
use crate::{
    parse_dir_record, parse_extent_record, parse_object_record, read_checkpoint, read_superblock,
    read_system_volume, validate_metadata_block, HxfsError, DIR_RECORD_BYTES, EXTENT_RECORD_BYTES,
    HEADER_BYTES, OBJECT_RECORD_BYTES,
};

/// Fixed writer mount/mutation result.
pub type FixedResult<T> = Result<T, HxfsError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedObject {
    descriptor: ObjectDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedDirEntry {
    parent_object_id: u64,
    object_id: u64,
    name_len: u16,
    name: [u8; MAX_NAME_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedExtent {
    object_id: u64,
    extent: ExtentRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectPlan {
    object_id: u64,
    tree_lba: u64,
    record_count: u32,
}

/// Fixed-capacity mutable Hxfs over a writable block store.
pub struct FixedHxfsWriter<
    S: BlockStore,
    const MAX_OBJECTS: usize,
    const MAX_DIR_ENTRIES: usize,
    const MAX_EXTENTS: usize,
> {
    store: S,
    superblock: Superblock,
    checkpoint: Checkpoint,
    system_volume: VolumeDescriptor,
    /// Resolved encryption policy for this volume, or `None` for
    /// plain volumes. Mirrors [`Hxfs::encryption`]: the policy is
    /// resolved at mount time from the caller-supplied
    /// `encryption_policies` table and held in the writer for
    /// later use by the on-target encryption path.
    encryption: Option<crate::crypto::EncryptionPolicy>,
    /// Stage B.1: per-volume metadata subkey used to encrypt v6
    /// metadata blocks and v6 dirent name bodies on the write
    /// path. `None` for plain volumes. Held in RAM for the
    /// lifetime of the mount; zeroized on drop. The same MVP
    /// placeholder key-derivation rules as the reader apply:
    /// a real Stage D KeyProvider will replace this.
    #[cfg(feature = "crypto-aes-gcm")]
    metadata_key: Option<[u8; crate::hkdf::SUBKEY_BYTES]>,
    /// Volume UUID used as the HKDF salt. Cached at mount time
    /// so the write path can re-derive the AEAD nonce and AAD
    /// without re-reading the superblock. The 16-byte UUID is
    /// mixed into the nonce and AAD so a ciphertext cannot be
    /// transplanted across volumes.
    #[cfg(feature = "crypto-aes-gcm")]
    volume_uuid: crate::format::Uuid,
    objects: [Option<FixedObject>; MAX_OBJECTS],
    dir_entries: [Option<FixedDirEntry>; MAX_DIR_ENTRIES],
    extents: [Option<FixedExtent>; MAX_EXTENTS],
    next_object_id: u64,
    next_lba: u64,
    dirty: bool,
}

impl<
        S: BlockStore,
        const MAX_OBJECTS: usize,
        const MAX_DIR_ENTRIES: usize,
        const MAX_EXTENTS: usize,
    > FixedHxfsWriter<S, MAX_OBJECTS, MAX_DIR_ENTRIES, MAX_EXTENTS>
{
    /// Mount a clean v2 Hxfs volume into fixed-capacity mutable
    /// state, treating the volume as unencrypted. Convenience
    /// wrapper around [`Self::mount_with_keys`].
    pub fn mount(store: S) -> FixedResult<Self> {
        Self::mount_with_keys(store, &[])
    }

    /// Mount a clean v2 Hxfs volume into fixed-capacity mutable
    /// state, resolving the system volume's encryption policy from
    /// `encryption_policies`. See [`Hxfs::mount_with_keys`] for the
    /// semantics of the table and the variants returned for an
    /// encrypted-but-unresolvable volume; the writer mirrors the
    /// reader's contract so a plain mount in either code path is
    /// interchangeable.
    /// Mount a clean v2 Hxfs volume into fixed-capacity
    /// mutable state with both encryption and compression
    /// policy tables. See [`Hxfs::mount_with_policies`] for
    /// the semantics of the table; the writer mirrors the
    /// reader. The compression table is accepted so the
    /// hxfs-service production wiring can call this entry
    /// point uniformly; the writer does not yet consult it
    /// for write-path policy resolution (the read path is
    /// the only consumer today, see A.3).
    pub fn mount_with_policies(
        store: S,
        encryption_policies: &[crate::crypto::EncryptionPolicy],
        _compression_policies: &[crate::compression::CompressionPolicy],
    ) -> FixedResult<Self> {
        Self::mount_with_keys(store, encryption_policies)
    }

    pub fn mount_with_keys(
        mut store: S,
        encryption_policies: &[crate::crypto::EncryptionPolicy],
    ) -> FixedResult<Self> {
        let superblock = read_superblock(&mut store, 0)?;
        if superblock.root_state != ROOT_STATE_CLEAN
            || superblock.journal_start_lba != 0
            || superblock.journal_end_lba != 0
        {
            return Err(HxfsError::NeedsRecovery);
        }
        let checkpoint = read_checkpoint(
            &mut store,
            superblock.checkpoint_lba,
            superblock.sequence_number,
        )?;
        let system_volume = read_system_volume(&mut store, checkpoint)?;
        let encryption = crate::resolve_mount_encryption(&system_volume, encryption_policies)?;
        // Stage B.1 wire: derive the per-volume metadata subkey
        // when the volume is encrypted. The placeholder IKM is
        // the same hash-of-instance-uuid pattern the reader
        // uses; a real Stage D KeyProvider will replace it.
        #[cfg(feature = "crypto-aes-gcm")]
        let metadata_key = if encryption.is_some() {
            let mut ikm = [0u8; 32];
            let mut index = 0usize;
            while index < 16 {
                ikm[index] = superblock.instance_uuid[index];
                ikm[index + 16] = superblock.instance_uuid[index];
                index += 1;
            }
            let mut key = [0u8; crate::hkdf::SUBKEY_BYTES];
            crate::encrypted_metadata::derive_metadata_key_for_volume(
                &ikm,
                &superblock.instance_uuid,
                &mut key,
            )
            .map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
            for byte in ikm.iter_mut() {
                *byte = 0;
            }
            Some(key)
        } else {
            None
        };
        let mut mounted = Self {
            store,
            superblock,
            checkpoint,
            system_volume,
            encryption,
            #[cfg(feature = "crypto-aes-gcm")]
            metadata_key,
            #[cfg(feature = "crypto-aes-gcm")]
            volume_uuid: superblock.instance_uuid,
            objects: [const { None }; MAX_OBJECTS],
            dir_entries: [const { None }; MAX_DIR_ENTRIES],
            extents: [const { None }; MAX_EXTENTS],
            next_object_id: 1,
            next_lba: 1,
            dirty: false,
        };
        mounted.load_object_tree()?;
        mounted.next_object_id = mounted.compute_next_object_id();
        mounted.next_lba = mounted.compute_next_lba()?;
        Ok(mounted)
    }

    /// Resolved encryption policy for this volume, or `None` for
    /// plain volumes. Mirrors [`Hxfs::encryption`].
    pub const fn encryption(&self) -> Option<&crate::crypto::EncryptionPolicy> {
        self.encryption.as_ref()
    }

    /// Consume the writer and return the underlying block store.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Immutable access to the underlying store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Mutable access to the underlying store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Current superblock snapshot.
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Current checkpoint snapshot.
    pub const fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    /// System volume descriptor.
    pub const fn volume_info(&self) -> VolumeDescriptor {
        self.system_volume
    }

    /// Whether dirty mutable state is waiting for an explicit checkpoint.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Current append-only media bytes charged by the fixed writer.
    pub fn charged_physical_bytes(&self) -> FixedResult<u64> {
        self.next_lba
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(HxfsError::OutOfRange)
    }

    /// Set per-volume quota limits for future allocator/object charges.
    pub fn set_quota_limits(&mut self, physical_bytes: u64, objects: u64) -> FixedResult<()> {
        self.system_volume.quota_physical_bytes = physical_bytes;
        self.system_volume.quota_objects = objects;
        self.quota_admits(0, 0)?;
        self.dirty = true;
        Ok(())
    }

    /// Root directory handle.
    pub const fn root_directory(&self) -> DirectoryHandle {
        DirectoryHandle {
            object_id: self.system_volume.root_object_id,
        }
    }

    /// Open an absolute directory path.
    pub fn open_directory_path(&self, path: &str) -> FixedResult<DirectoryHandle> {
        if path == "/" {
            return Ok(self.root_directory());
        }
        let object_id = self.resolve_path(path)?;
        let object = self.object(object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_DIRECTORY {
            return Err(HxfsError::WrongType);
        }
        Ok(DirectoryHandle { object_id })
    }

    /// Open an absolute file path.
    pub fn open_path(&self, path: &str) -> FixedResult<FileHandle> {
        let object_id = self.resolve_path(path)?;
        self.file_handle(object_id)
    }

    /// Open one child file by name from a directory handle.
    pub fn open_child_file(
        &self,
        directory: DirectoryHandle,
        name: &str,
    ) -> FixedResult<FileHandle> {
        let object_id = self.lookup_child(directory.object_id, name.as_bytes())?;
        self.file_handle(object_id)
    }

    /// Open one child directory by name from a directory handle.
    pub fn open_child_dir(
        &self,
        directory: DirectoryHandle,
        name: &str,
    ) -> FixedResult<DirectoryHandle> {
        let object_id = self.lookup_child(directory.object_id, name.as_bytes())?;
        let object = self.object(object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_DIRECTORY {
            return Err(HxfsError::WrongType);
        }
        Ok(DirectoryHandle { object_id })
    }

    /// Refresh a file handle's size after mutation.
    pub fn file_handle(&self, object_id: u64) -> FixedResult<FileHandle> {
        let object = self.object(object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        Ok(FileHandle {
            object_id,
            size: object.descriptor.size,
        })
    }

    /// List a directory into `out` as newline-separated UTF-8 names.
    pub fn list_directory(&self, directory: DirectoryHandle, out: &mut [u8]) -> FixedResult<usize> {
        let object = self.object(directory.object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_DIRECTORY {
            return Err(HxfsError::WrongType);
        }
        let mut written = 0usize;
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.parent_object_id == directory.object_id {
                    let name = entry.name_bytes();
                    for &byte in name {
                        if written < out.len() {
                            out[written] = byte;
                            written += 1;
                        }
                    }
                    if written < out.len() {
                        out[written] = b'\n';
                        written += 1;
                    }
                }
            }
            index += 1;
        }
        Ok(written)
    }

    /// Read a complete file into `out`.
    pub fn read_file(&mut self, file: FileHandle, out: &mut [u8]) -> FixedResult<usize> {
        let object = self.object(file.object_id)?.descriptor;
        if object.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        let size = usize::try_from(object.size).map_err(|_| HxfsError::OutOfRange)?;
        if out.len() < size {
            return Err(HxfsError::BufferTooSmall);
        }
        out[..size].fill(0);
        self.copy_extents(file.object_id, &mut out[..size])?;
        Ok(size)
    }

    /// Read part of a file into `out`.
    pub fn read_file_at(
        &mut self,
        file: FileHandle,
        offset: u64,
        out: &mut [u8],
    ) -> FixedResult<usize> {
        let object = self.object(file.object_id)?.descriptor;
        if object.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        if offset >= object.size {
            return Ok(0);
        }
        let remaining = object.size - offset;
        let count = out
            .len()
            .min(usize::try_from(remaining).map_err(|_| HxfsError::OutOfRange)?);
        let mut full = [0u8; BLOCK_SIZE];
        if object.size as usize > full.len() {
            return Err(HxfsError::Unsupported);
        }
        self.read_file(file, &mut full[..object.size as usize])?;
        let start = usize::try_from(offset).map_err(|_| HxfsError::OutOfRange)?;
        out[..count].copy_from_slice(&full[start..start + count]);
        Ok(count)
    }

    /// Create a directory at an absolute path.
    pub fn mkdir_path(&mut self, path: &str) -> FixedResult<DirectoryHandle> {
        let (parent, name) = self.parent_and_name(path)?;
        self.mkdir_child(DirectoryHandle { object_id: parent }, name)
    }

    /// Create a directory below an existing directory handle.
    pub fn mkdir_child(
        &mut self,
        parent: DirectoryHandle,
        name: &str,
    ) -> FixedResult<DirectoryHandle> {
        self.ensure_directory(parent.object_id)?;
        self.quota_admits(0, 1)?;
        if self.lookup_child(parent.object_id, name.as_bytes()).is_ok() {
            return Err(HxfsError::AlreadyExists);
        }
        let object_id = self.alloc_object_id()?;
        let descriptor = ObjectDescriptor {
            object_id,
            object_type: OBJECT_TYPE_DIRECTORY,
            type_version: 1,
            size: 0,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            tree_lba: 0,
            record_count: 0,
            flags: 0,
        };
        self.insert_object(descriptor)?;
        self.insert_dir_entry(parent.object_id, object_id, name.as_bytes())?;
        self.dirty = true;
        Ok(DirectoryHandle { object_id })
    }

    /// Create an empty file at an absolute path.
    pub fn create_file_path(&mut self, path: &str) -> FixedResult<FileHandle> {
        let (parent, name) = self.parent_and_name(path)?;
        self.create_file_child(DirectoryHandle { object_id: parent }, name)
    }

    /// Create an empty file below an existing directory handle.
    pub fn create_file_child(
        &mut self,
        parent: DirectoryHandle,
        name: &str,
    ) -> FixedResult<FileHandle> {
        self.ensure_directory(parent.object_id)?;
        self.quota_admits(0, 1)?;
        if self.lookup_child(parent.object_id, name.as_bytes()).is_ok() {
            return Err(HxfsError::AlreadyExists);
        }
        let object_id = self.alloc_object_id()?;
        let descriptor = ObjectDescriptor {
            object_id,
            object_type: OBJECT_TYPE_FILE,
            type_version: 1,
            size: 0,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            tree_lba: 0,
            record_count: 0,
            flags: 0,
        };
        self.insert_object(descriptor)?;
        self.insert_dir_entry(parent.object_id, object_id, name.as_bytes())?;
        self.dirty = true;
        Ok(FileHandle { object_id, size: 0 })
    }

    /// Write an inline payload to a file.
    ///
    /// The no-heap Stage-K service supports whole-file replacement at offset 0
    /// and block-aligned appends. More general overwrite/splitting is deferred
    /// until the persistent allocator/refcount stages own extent surgery.
    pub fn write_file_at(
        &mut self,
        file: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> FixedResult<FileHandle> {
        if data.len() > BLOCK_SIZE {
            return Err(HxfsError::Unsupported);
        }
        let object = self.object(file.object_id)?.descriptor;
        if object.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        // A.5 wire: per-Job quota enforcement on the write path.
        // The volume-level quota is the system volume descriptor
        // (VolumeDescriptor.quota_physical_bytes /
        // quota_objects) and the current usage is the volume's
        // computed usage; the delta is the bytes + one object
        // this write will commit. A breach returns
        // HxfsError::QuotaExceeded, which the kernel
        // translates to the user-facing NoSpace error at the
        // mount boundary.
        let delta_bytes = u64::try_from(data.len()).map_err(|_| HxfsError::OutOfRange)?;
        self.check_volume_quota(delta_bytes, 0)?;

        if offset == 0 {
            self.clear_extents(file.object_id);
        } else if offset != object.size || !offset.is_multiple_of(BLOCK_SIZE_U64) {
            return Err(HxfsError::Unsupported);
        }

        if !data.is_empty() {
            let logical_block = offset / BLOCK_SIZE_U64;
            let physical_block = self.write_data_blocks(data)?;
            self.insert_extent(FixedExtent {
                object_id: file.object_id,
                extent: ExtentRecord {
                    logical_block,
                    physical_block,
                    block_count: 1,
                    flags: 0,
                },
            })?;
        }
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| HxfsError::OutOfRange)?)
            .ok_or(HxfsError::OutOfRange)?;
        let new_size = if offset == 0 {
            end
        } else {
            object.size.max(end)
        };
        self.object_mut(file.object_id)?.descriptor.size = new_size;
        self.update_file_record_count(file.object_id)?;
        self.dirty = true;
        self.file_handle(file.object_id)
    }

    /// A.5 wire: per-Job volume-quota check on the write
    /// path. The check is volume-level (the system volume
    /// descriptor's `quota_physical_bytes` and `quota_objects`
    /// are the cap; the current usage is the volume's
    /// existing extent table). A breach returns
    /// [`HxfsError::QuotaExceeded`], which the kernel
    /// translates to the user-facing NoSpace error.
    ///
    /// `delta_bytes` is the number of physical bytes this
    /// write will commit; `delta_objects` is the number of
    /// new objects (the fixed-capacity MVP admits one object
    /// at a time, so the call sites pass 1 for new-file
    /// creation and 0 for overwrite).
    fn check_volume_quota(&self, delta_bytes: u64, delta_objects: u64) -> FixedResult<()> {
        use crate::quota::{check_quota, VolumeQuota, VolumeUsage};
        let quota = VolumeQuota {
            max_physical_bytes: self.system_volume.quota_physical_bytes,
            max_objects: self.system_volume.quota_objects,
        };
        let usage = VolumeUsage {
            physical_bytes: self.committed_physical_bytes(),
            objects: u64::from(self.object_count()),
        };
        check_quota(
            quota,
            usage,
            VolumeUsage {
                physical_bytes: delta_bytes,
                objects: delta_objects,
            },
        )
        .map_err(|_| HxfsError::QuotaExceeded)?;
        Ok(())
    }

    /// A.5 helper: return the number of live objects in the
    /// writer. Used by the per-Job quota check on the write
    /// path; the count is the persisted
    /// `system_volume.object_count` (i.e. the count of
    /// committed objects, not the in-flight new-object
    /// candidate).
    pub fn object_count(&self) -> u32 {
        self.system_volume.object_count
    }

    /// A.5 helper: return the number of physical bytes
    /// already committed to data blocks on the volume.
    /// Computed from the next-LBA pointer because the
    /// fixed-capacity MVP reserves contiguous LBAs for
    /// the volume table; the boundary is `next_lba - 1`
    /// (the last committed data LBA).
    pub fn committed_physical_bytes(&self) -> u64 {
        self.next_lba.saturating_sub(1) * BLOCK_SIZE_U64
    }

    /// Truncate or sparsely extend a file.
    pub fn truncate_file(&mut self, file: FileHandle, new_size: u64) -> FixedResult<FileHandle> {
        let object = self.object_mut(file.object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        object.descriptor.size = new_size;
        self.dirty = true;
        self.file_handle(file.object_id)
    }

    /// Rename an absolute path.
    pub fn rename_path(&mut self, from: &str, to: &str) -> FixedResult<()> {
        let (old_parent, old_name) = self.parent_and_name(from)?;
        let (new_parent, new_name) = self.parent_and_name(to)?;
        self.rename_child(
            DirectoryHandle {
                object_id: old_parent,
            },
            old_name,
            DirectoryHandle {
                object_id: new_parent,
            },
            new_name,
        )
    }

    /// Rename a child entry between directories.
    pub fn rename_child(
        &mut self,
        old_parent: DirectoryHandle,
        old_name: &str,
        new_parent: DirectoryHandle,
        new_name: &str,
    ) -> FixedResult<()> {
        self.ensure_directory(old_parent.object_id)?;
        self.ensure_directory(new_parent.object_id)?;
        if self
            .lookup_child(new_parent.object_id, new_name.as_bytes())
            .is_ok()
        {
            return Err(HxfsError::AlreadyExists);
        }
        let index = self.dir_entry_index(old_parent.object_id, old_name.as_bytes())?;
        let object_id = self.dir_entries[index]
            .ok_or(HxfsError::NotFound)?
            .object_id;
        self.dir_entries[index] = None;
        self.insert_dir_entry(new_parent.object_id, object_id, new_name.as_bytes())?;
        self.dirty = true;
        Ok(())
    }

    /// Unlink an absolute path.
    pub fn unlink_path(&mut self, path: &str) -> FixedResult<()> {
        let (parent, name) = self.parent_and_name(path)?;
        self.unlink_child(DirectoryHandle { object_id: parent }, name)
    }

    /// Unlink a child entry below a directory handle.
    pub fn unlink_child(&mut self, parent: DirectoryHandle, name: &str) -> FixedResult<()> {
        self.ensure_directory(parent.object_id)?;
        let index = self.dir_entry_index(parent.object_id, name.as_bytes())?;
        let object_id = self.dir_entries[index]
            .ok_or(HxfsError::NotFound)?
            .object_id;
        let object = self.object(object_id)?.descriptor;
        if object.object_type == OBJECT_TYPE_DIRECTORY && self.directory_has_children(object_id) {
            return Err(HxfsError::DirectoryNotEmpty);
        }
        self.dir_entries[index] = None;
        self.remove_object(object_id);
        self.clear_extents(object_id);
        self.dirty = true;
        Ok(())
    }

    /// Publish dirty state through a v2 journaled checkpoint.
    pub fn publish_checkpoint(&mut self) -> FixedResult<u64> {
        if !self.dirty {
            self.store.flush()?;
            return Ok(self.checkpoint.sequence_number);
        }
        let old_checkpoint_lba = self.superblock.checkpoint_lba;
        let sequence = self.superblock.sequence_number.saturating_add(1).max(1);
        let live_objects = self.live_object_count();
        let target_count = live_objects.checked_add(7).ok_or(HxfsError::NoSpace)?;
        if target_count == 0 {
            return Err(HxfsError::NoSpace);
        }
        let record_count = u32::try_from(target_count + 1).map_err(|_| HxfsError::NoSpace)?;
        let target_start_lba = self.next_lba;
        let object_table_lba = target_start_lba + live_objects as u64;
        let volume_table_lba = object_table_lba + 1;
        let allocation_tree_lba = volume_table_lba + 1;
        let refcount_tree_lba = allocation_tree_lba + 1;
        let backref_tree_lba = refcount_tree_lba + 1;
        let quota_tree_lba = backref_tree_lba + 1;
        let checkpoint_lba = quota_tree_lba + 1;
        let journal_start_lba = checkpoint_lba + 1;
        let journal_end_lba = journal_start_lba + u64::from(record_count) * 2;
        self.quota_allows_media_blocks(journal_end_lba)?;
        let mut plans = [const { None }; MAX_OBJECTS];

        let mut record_index = 0u32;
        let mut object_slot = 0usize;
        while object_slot < self.objects.len() {
            if let Some(object) = self.objects[object_slot] {
                let tree_lba = target_start_lba + u64::from(record_index);
                let block = self.build_object_tree_block(object.descriptor, tree_lba)?;
                plans[object_slot] = Some(ObjectPlan {
                    object_id: object.descriptor.object_id,
                    tree_lba,
                    record_count: self.record_count_for_object(object.descriptor.object_id),
                });
                self.write_journaled_target(
                    tree_lba,
                    &block,
                    sequence,
                    record_index,
                    record_count,
                    journal_start_lba,
                    checkpoint_lba,
                    0,
                )?;
                record_index += 1;
            }
            object_slot += 1;
        }

        let object_block = self.build_object_table_block(&plans, object_table_lba)?;
        self.write_journaled_target(
            object_table_lba,
            &object_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let volume_block =
            self.build_volume_table_block(object_table_lba, live_objects as u32, volume_table_lba)?;
        self.write_journaled_target(
            volume_table_lba,
            &volume_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let allocation_block = self.build_allocation_tree_block(allocation_tree_lba)?;
        self.write_journaled_target(
            allocation_tree_lba,
            &allocation_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let refcount_block = self.build_refcount_tree_block(refcount_tree_lba)?;
        self.write_journaled_target(
            refcount_tree_lba,
            &refcount_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let backref_block = self.build_backref_tree_block(backref_tree_lba, sequence)?;
        self.write_journaled_target(
            backref_tree_lba,
            &backref_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let quota_block = self.build_quota_tree_block(quota_tree_lba, journal_end_lba)?;
        self.write_journaled_target(
            quota_tree_lba,
            &quota_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let checkpoint_block = build_checkpoint_block(
            sequence,
            volume_table_lba,
            self.system_volume.uuid,
            allocation_tree_lba,
            refcount_tree_lba,
            backref_tree_lba,
            quota_tree_lba,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            checkpoint_lba,
        );
        self.write_journaled_target(
            checkpoint_lba,
            &checkpoint_block,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            0,
        )?;
        record_index += 1;

        let final_superblock = make_superblock_block(
            self.superblock.instance_uuid,
            sequence,
            checkpoint_lba,
            0,
            0,
            ROOT_STATE_CLEAN,
        );
        self.write_journaled_target(
            0,
            &final_superblock,
            sequence,
            record_index,
            record_count,
            journal_start_lba,
            checkpoint_lba,
            JOURNAL_RECORD_FLAG_FINAL_SUPERBLOCK,
        )?;

        self.store.flush()?;
        let recovering = make_superblock_block(
            self.superblock.instance_uuid,
            sequence,
            old_checkpoint_lba,
            journal_start_lba,
            journal_end_lba,
            ROOT_STATE_RECOVERING,
        );
        self.store.write_blocks(0, 1, &recovering)?;
        self.store.flush()?;
        self.store.write_blocks(0, 1, &final_superblock)?;
        self.store.flush()?;

        self.superblock = read_superblock(&mut self.store, 0)?;
        self.checkpoint = read_checkpoint(&mut self.store, checkpoint_lba, sequence)?;
        self.system_volume.object_table_lba = object_table_lba;
        self.system_volume.object_count = live_objects as u32;
        let mut slot = 0usize;
        while slot < self.objects.len() {
            if let Some(plan) = plans[slot] {
                if let Some(object) = self.objects[slot].as_mut() {
                    object.descriptor.tree_lba = plan.tree_lba;
                    object.descriptor.record_count = plan.record_count;
                }
            }
            slot += 1;
        }
        self.next_lba = journal_end_lba;
        self.dirty = false;
        Ok(sequence)
    }

    fn load_object_tree(&mut self) -> FixedResult<()> {
        let mut block = [0u8; BLOCK_SIZE];
        self.store
            .read_blocks(self.system_volume.object_table_lba, 1, &mut block)?;
        let header = validate_metadata_block(
            &block,
            self.system_volume.object_table_lba,
            BLOCK_TYPE_OBJECT_TABLE,
            1,
        )?;
        let count = read_u32(&block, header.header_bytes as usize)?;
        if count != self.system_volume.object_count {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * OBJECT_RECORD_BYTES;
            let object = parse_object_record(&block, offset)?;
            self.insert_object(object)?;
            match object.object_type {
                OBJECT_TYPE_DIRECTORY => self.load_directory(object)?,
                OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK => self.load_extents(object)?,
                OBJECT_TYPE_BLOB_VIEW => {}
                _ => return Err(HxfsError::BadTree),
            }
            index += 1;
        }
        Ok(())
    }

    fn load_directory(&mut self, object: ObjectDescriptor) -> FixedResult<()> {
        let mut block = [0u8; BLOCK_SIZE];
        self.store.read_blocks(object.tree_lba, 1, &mut block)?;
        let header = validate_metadata_block(
            &block,
            object.tree_lba,
            BLOCK_TYPE_DIRECTORY,
            object.object_id,
        )?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != object.object_id || count != object.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let entry = parse_dir_record(&block, offset)?;
            self.insert_dir_entry(object.object_id, entry.object_id, entry.name.as_bytes())?;
            index += 1;
        }
        Ok(())
    }

    fn load_extents(&mut self, object: ObjectDescriptor) -> FixedResult<()> {
        if object.record_count == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        self.store.read_blocks(object.tree_lba, 1, &mut block)?;
        let header = validate_metadata_block(
            &block,
            object.tree_lba,
            BLOCK_TYPE_EXTENT_TABLE,
            object.object_id,
        )?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != object.object_id || count != object.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * EXTENT_RECORD_BYTES;
            let extent = parse_extent_record(&block, offset)?;
            self.insert_extent(FixedExtent {
                object_id: object.object_id,
                extent,
            })?;
            index += 1;
        }
        Ok(())
    }

    fn resolve_path(&self, path: &str) -> FixedResult<u64> {
        if path.is_empty() || !path.as_bytes().starts_with(b"/") {
            return Err(HxfsError::BadName);
        }
        if path == "/" {
            return Ok(self.system_volume.root_object_id);
        }
        let mut current = self.system_volume.root_object_id;
        let mut rest = &path.as_bytes()[1..];
        loop {
            let slash = rest.iter().position(|&byte| byte == b'/');
            let (component, tail) = match slash {
                Some(pos) => (&rest[..pos], &rest[pos + 1..]),
                None => (rest, &[][..]),
            };
            if !valid_name(component) {
                return Err(HxfsError::BadName);
            }
            current = self.lookup_child(current, component)?;
            if tail.is_empty() {
                return Ok(current);
            }
            self.ensure_directory(current)?;
            rest = tail;
        }
    }

    fn parent_and_name<'a>(&self, path: &'a str) -> FixedResult<(u64, &'a str)> {
        if path == "/" || !path.as_bytes().starts_with(b"/") {
            return Err(HxfsError::BadName);
        }
        let Some(pos) = path.as_bytes().iter().rposition(|&byte| byte == b'/') else {
            return Err(HxfsError::BadName);
        };
        let name =
            core::str::from_utf8(&path.as_bytes()[pos + 1..]).map_err(|_| HxfsError::BadName)?;
        if !valid_name(name.as_bytes()) {
            return Err(HxfsError::BadName);
        }
        let parent_path = if pos == 0 { "/" } else { &path[..pos] };
        let parent = self.resolve_path(parent_path)?;
        self.ensure_directory(parent)?;
        Ok((parent, name))
    }

    fn lookup_child(&self, parent: u64, name: &[u8]) -> FixedResult<u64> {
        self.ensure_directory(parent)?;
        if !valid_name(name) {
            return Err(HxfsError::BadName);
        }
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.parent_object_id == parent && entry.name_bytes() == name {
                    return Ok(entry.object_id);
                }
            }
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn dir_entry_index(&self, parent: u64, name: &[u8]) -> FixedResult<usize> {
        if !valid_name(name) {
            return Err(HxfsError::BadName);
        }
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.parent_object_id == parent && entry.name_bytes() == name {
                    return Ok(index);
                }
            }
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn ensure_directory(&self, object_id: u64) -> FixedResult<()> {
        let object = self.object(object_id)?;
        if object.descriptor.object_type == OBJECT_TYPE_DIRECTORY {
            Ok(())
        } else {
            Err(HxfsError::WrongType)
        }
    }

    fn object(&self, object_id: u64) -> FixedResult<FixedObject> {
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                if object.descriptor.object_id == object_id {
                    return Ok(object);
                }
            }
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn object_mut(&mut self, object_id: u64) -> FixedResult<&mut FixedObject> {
        let mut index = 0usize;
        while index < self.objects.len() {
            if self.objects[index]
                .as_ref()
                .map(|object| object.descriptor.object_id == object_id)
                .unwrap_or(false)
            {
                return self.objects[index].as_mut().ok_or(HxfsError::NotFound);
            }
            index += 1;
        }
        Err(HxfsError::NotFound)
    }

    fn insert_object(&mut self, descriptor: ObjectDescriptor) -> FixedResult<()> {
        let mut index = 0usize;
        while index < self.objects.len() {
            if self.objects[index].is_none() {
                self.objects[index] = Some(FixedObject { descriptor });
                return Ok(());
            }
            index += 1;
        }
        Err(HxfsError::NoSpace)
    }

    fn remove_object(&mut self, object_id: u64) {
        let mut index = 0usize;
        while index < self.objects.len() {
            if self.objects[index]
                .map(|object| object.descriptor.object_id == object_id)
                .unwrap_or(false)
            {
                self.objects[index] = None;
                return;
            }
            index += 1;
        }
    }

    fn insert_dir_entry(&mut self, parent: u64, object_id: u64, name: &[u8]) -> FixedResult<()> {
        if !valid_name(name) {
            return Err(HxfsError::BadName);
        }
        let mut free = None;
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.parent_object_id == parent && entry.name_bytes() == name {
                    return Err(HxfsError::AlreadyExists);
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(HxfsError::NoSpace)?;
        let mut entry = FixedDirEntry {
            parent_object_id: parent,
            object_id,
            name_len: name.len() as u16,
            name: [0; MAX_NAME_BYTES],
        };
        entry.name[..name.len()].copy_from_slice(name);
        self.dir_entries[slot] = Some(entry);
        self.sort_directory(parent);
        self.update_directory_record_count(parent)?;
        Ok(())
    }

    fn insert_extent(&mut self, extent: FixedExtent) -> FixedResult<()> {
        let mut slot = None;
        let mut index = 0usize;
        while index < self.extents.len() {
            if self.extents[index].is_none() && slot.is_none() {
                slot = Some(index);
            }
            index += 1;
        }
        let slot = slot.ok_or(HxfsError::NoSpace)?;
        self.extents[slot] = Some(extent);
        self.sort_extents(extent.object_id);
        self.update_file_record_count(extent.object_id)?;
        Ok(())
    }

    fn clear_extents(&mut self, object_id: u64) {
        let mut index = 0usize;
        while index < self.extents.len() {
            if self.extents[index]
                .map(|extent| extent.object_id == object_id)
                .unwrap_or(false)
            {
                self.extents[index] = None;
            }
            index += 1;
        }
    }

    fn update_directory_record_count(&mut self, object_id: u64) -> FixedResult<()> {
        let count = self.directory_entry_count(object_id);
        self.object_mut(object_id)?.descriptor.record_count = count;
        Ok(())
    }

    fn update_file_record_count(&mut self, object_id: u64) -> FixedResult<()> {
        let count = self.extent_count(object_id);
        self.object_mut(object_id)?.descriptor.record_count = count;
        Ok(())
    }

    fn directory_entry_count(&self, object_id: u64) -> u32 {
        let mut count = 0u32;
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if self.dir_entries[index]
                .map(|entry| entry.parent_object_id == object_id)
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
            index += 1;
        }
        count
    }

    fn directory_has_children(&self, object_id: u64) -> bool {
        self.directory_entry_count(object_id) != 0
    }

    fn extent_count(&self, object_id: u64) -> u32 {
        let mut count = 0u32;
        let mut index = 0usize;
        while index < self.extents.len() {
            if self.extents[index]
                .map(|extent| extent.object_id == object_id)
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
            index += 1;
        }
        count
    }

    fn record_count_for_object(&self, object_id: u64) -> u32 {
        match self.object(object_id) {
            Ok(object) if object.descriptor.object_type == OBJECT_TYPE_DIRECTORY => {
                self.directory_entry_count(object_id)
            }
            Ok(_) => self.extent_count(object_id),
            Err(_) => 0,
        }
    }

    fn live_object_count(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.objects.len() {
            if self.objects[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    fn alloc_object_id(&mut self) -> FixedResult<u64> {
        let id = self.next_object_id;
        self.next_object_id = self
            .next_object_id
            .checked_add(1)
            .ok_or(HxfsError::NoSpace)?;
        Ok(id)
    }

    fn compute_next_object_id(&self) -> u64 {
        let mut next = 1u64;
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                next = next.max(object.descriptor.object_id.saturating_add(1));
            }
            index += 1;
        }
        next.max(2)
    }

    fn compute_next_lba(&self) -> FixedResult<u64> {
        let mut max_lba = self.superblock.checkpoint_lba;
        max_lba = max_lba.max(self.system_volume.object_table_lba);
        if self.superblock.journal_end_lba != 0 {
            max_lba = max_lba.max(self.superblock.journal_end_lba - 1);
        }
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                max_lba = max_lba.max(object.descriptor.tree_lba);
            }
            index += 1;
        }
        index = 0;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    let end = extent
                        .extent
                        .physical_block
                        .checked_add(u64::from(extent.extent.block_count))
                        .ok_or(HxfsError::OutOfRange)?;
                    max_lba = max_lba.max(end.saturating_sub(1));
                }
            }
            index += 1;
        }
        Ok(max_lba.saturating_add(1).max(1))
    }

    fn quota_admits(&self, additional_bytes: u64, additional_objects: u64) -> FixedResult<()> {
        let next_objects = (self.live_object_count() as u64)
            .checked_add(additional_objects)
            .ok_or(HxfsError::NoSpace)?;
        if self.system_volume.quota_objects != 0 && next_objects > self.system_volume.quota_objects
        {
            return Err(HxfsError::NoSpace);
        }
        let current_bytes = self
            .next_lba
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(HxfsError::OutOfRange)?;
        let next_bytes = current_bytes
            .checked_add(additional_bytes)
            .ok_or(HxfsError::OutOfRange)?;
        if self.system_volume.quota_physical_bytes != 0
            && next_bytes > self.system_volume.quota_physical_bytes
        {
            return Err(HxfsError::NoSpace);
        }
        Ok(())
    }

    fn quota_allows_media_blocks(&self, future_next_lba: u64) -> FixedResult<()> {
        if self.system_volume.quota_physical_bytes == 0 {
            return Ok(());
        }
        let bytes = future_next_lba
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(HxfsError::OutOfRange)?;
        if bytes > self.system_volume.quota_physical_bytes {
            return Err(HxfsError::NoSpace);
        }
        Ok(())
    }

    fn write_data_blocks(&mut self, data: &[u8]) -> FixedResult<u64> {
        let start = self.next_lba;
        self.quota_admits(BLOCK_SIZE_U64, 0)?;
        let mut block = [0u8; BLOCK_SIZE];
        block[..data.len()].copy_from_slice(data);
        self.store.write_blocks(start, 1, &block)?;
        self.next_lba = self.next_lba.checked_add(1).ok_or(HxfsError::NoSpace)?;
        Ok(start)
    }

    fn copy_extents(&mut self, object_id: u64, out: &mut [u8]) -> FixedResult<()> {
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id == object_id {
                    self.copy_extent(extent.extent, out)?;
                }
            }
            index += 1;
        }
        Ok(())
    }

    fn copy_extent(&mut self, extent: ExtentRecord, out: &mut [u8]) -> FixedResult<()> {
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
        let mut copied = start;
        while copied < copy_end {
            let logical_delta = copied - start;
            let extent_block = logical_delta / BLOCK_SIZE;
            let within = logical_delta % BLOCK_SIZE;
            self.store
                .read_blocks(extent.physical_block + extent_block as u64, 1, &mut scratch)?;
            let chunk = (copy_end - copied).min(BLOCK_SIZE - within);
            out[copied..copied + chunk].copy_from_slice(&scratch[within..within + chunk]);
            copied += chunk;
        }
        Ok(())
    }

    fn build_object_tree_block(
        &self,
        object: ObjectDescriptor,
        lba: u64,
    ) -> FixedResult<[u8; BLOCK_SIZE]> {
        match object.object_type {
            OBJECT_TYPE_DIRECTORY => self.build_directory_block(object.object_id, lba),
            OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK => {
                self.build_extent_block(object.object_id, lba)
            }
            _ => Err(HxfsError::WrongType),
        }
    }

    fn build_directory_block(&self, object_id: u64, lba: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = self.directory_entry_count(object_id);
        payload[0..8].copy_from_slice(&object_id.to_le_bytes());
        payload[8..12].copy_from_slice(&count.to_le_bytes());
        // Stage B.2 wire: when the parent directory is on an
        // encrypted volume we encrypt every dirent name body
        // before writing the block. The encrypted body is
        // `nonce(12) || ciphertext(M) || tag(16)`, written into
        // the same `name[N]` region the v5 plaintext layout
        // uses. The reader decides plaintext vs encrypted by
        // the volume's `encryption_policy_id` (resolved at
        // mount time), not by a per-record flag, so the on-disk
        // plaintext v5 layout is byte-for-byte unchanged.
        let parent_is_encrypted = self.is_volume_encrypted();
        let mut written = 0usize;
        let mut index = 0usize;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.parent_object_id == object_id {
                    let offset = 16 + written * DIR_RECORD_BYTES;
                    if offset + DIR_RECORD_BYTES > payload.len() {
                        return Err(HxfsError::NoSpace);
                    }
                    payload[offset..offset + 8].copy_from_slice(&entry.object_id.to_le_bytes());
                    if parent_is_encrypted {
                        #[cfg(feature = "crypto-aes-gcm")]
                        {
                            let key = self
                                .metadata_key
                                .as_ref()
                                .ok_or(HxfsError::EncryptedPolicyInvalid)?;
                            let name_str = core::str::from_utf8(entry.name_bytes())
                                .map_err(|_| HxfsError::BadName)?;
                            let enc = crate::encrypted_metadata::EncryptedDirentName::encrypt(
                                name_str,
                                object_id,
                                entry.object_id,
                                key,
                            )
                            .map_err(|_| HxfsError::NoSpace)?;
                            let body_len = enc.body_len as usize;
                            payload[offset + 8..offset + 10]
                                .copy_from_slice(&enc.body_len.to_le_bytes());
                            payload[offset + 10..offset + 10 + body_len]
                                .copy_from_slice(&enc.body[..body_len]);
                        }
                        #[cfg(not(feature = "crypto-aes-gcm"))]
                        {
                            return Err(HxfsError::EncryptedPolicyInvalid);
                        }
                    } else {
                        // Plain v5 layout. `name_len` is the
                        // UTF-8 byte length and the body is the
                        // raw name. Byte-for-byte compatible
                        // with the pre-B.2 writer.
                        let name = entry.name_bytes();
                        payload[offset + 8..offset + 10]
                            .copy_from_slice(&entry.name_len.to_le_bytes());
                        payload[offset + 10..offset + 10 + name.len()].copy_from_slice(name);
                    }
                    written += 1;
                }
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_DIRECTORY,
            object_id,
            lba,
            &payload[..16 + written * DIR_RECORD_BYTES],
            args.0,
            args.1,
            args.2,
        )?)
    }

    /// Convenience: pack the (volume_encrypted, metadata_key,
    /// volume_uuid) triple into a tuple for the
    /// `make_metadata_block_for_volume` call. On a build without
    /// the feature the encryption half is `None` and the UUID
    /// is a default; the wrapper falls through to the plain
    /// builder. Defined as a tuple expression so the cfg
    /// attributes can sit on the field values, not on the
    /// expression itself.
    #[cfg(feature = "crypto-aes-gcm")]
    fn encryption_args(
        &self,
    ) -> (
        bool,
        Option<&[u8; crate::hkdf::SUBKEY_BYTES]>,
        &crate::format::Uuid,
    ) {
        (
            self.metadata_key.is_some(),
            self.metadata_key.as_ref(),
            &self.volume_uuid,
        )
    }

    #[cfg(not(feature = "crypto-aes-gcm"))]
    fn encryption_args(&self) -> (bool, Option<&'static [u8; 32]>, &'static [u8; 16]) {
        (false, None, &[0u8; 16])
    }

    /// Stage B.2 helper: `true` when the volume has a non-zero
    /// `encryption_policy_id` and we therefore have a metadata
    /// subkey in RAM. Used by `build_directory_block` to decide
    /// whether to encrypt each dirent name body.
    fn is_volume_encrypted(&self) -> bool {
        #[cfg(feature = "crypto-aes-gcm")]
        {
            self.metadata_key.is_some()
        }
        #[cfg(not(feature = "crypto-aes-gcm"))]
        {
            false
        }
    }

    /// Return the metadata subkey and volume UUID for the
    /// `make_metadata_block_for_volume` wrapper. On a build
    /// without the `crypto-aes-gcm` feature both halves are
    /// `None`/default; the wrapper falls through to the plain
    /// v5 builder.

    fn build_extent_block(&self, object_id: u64, lba: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = self.extent_count(object_id);
        payload[0..8].copy_from_slice(&object_id.to_le_bytes());
        payload[8..12].copy_from_slice(&count.to_le_bytes());
        let mut written = 0usize;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id == object_id {
                    let offset = 16 + written * EXTENT_RECORD_BYTES;
                    if offset + EXTENT_RECORD_BYTES > payload.len() {
                        return Err(HxfsError::NoSpace);
                    }
                    payload[offset..offset + 8]
                        .copy_from_slice(&extent.extent.logical_block.to_le_bytes());
                    payload[offset + 8..offset + 16]
                        .copy_from_slice(&extent.extent.physical_block.to_le_bytes());
                    payload[offset + 16..offset + 20]
                        .copy_from_slice(&extent.extent.block_count.to_le_bytes());
                    payload[offset + 20..offset + 24]
                        .copy_from_slice(&extent.extent.flags.to_le_bytes());
                    written += 1;
                }
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_EXTENT_TABLE,
            object_id,
            lba,
            &payload[..16 + written * EXTENT_RECORD_BYTES],
            args.0,
            args.1,
            args.2,
        )?)
    }

    fn build_object_table_block(
        &self,
        plans: &[Option<ObjectPlan>; MAX_OBJECTS],
        lba: u64,
    ) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = self.live_object_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                let plan = plans[index].ok_or(HxfsError::BadTree)?;
                if plan.object_id != object.descriptor.object_id {
                    return Err(HxfsError::BadTree);
                }
                let offset = 16 + written * OBJECT_RECORD_BYTES;
                if offset + OBJECT_RECORD_BYTES > payload.len() {
                    return Err(HxfsError::NoSpace);
                }
                let mut descriptor = object.descriptor;
                descriptor.tree_lba = plan.tree_lba;
                descriptor.record_count = plan.record_count;
                write_object_record(&mut payload, offset, descriptor);
                written += 1;
            }
            index += 1;
        }
        Ok(make_metadata_block(
            BLOCK_TYPE_OBJECT_TABLE,
            1,
            lba,
            &payload[..16 + written * OBJECT_RECORD_BYTES],
        ))
    }

    fn build_allocation_tree_block(&self, lba: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut tree = AllocationBtree::<MAX_EXTENTS>::new();
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    tree.insert(AllocationRecord {
                        start_block: extent.extent.physical_block,
                        block_count: u64::from(extent.extent.block_count),
                        state: AllocationState::Allocated,
                        owner_object_id: extent.object_id,
                    })
                    .map_err(|_| HxfsError::BadTree)?;
                }
            }
            index += 1;
        }
        tree.validate().map_err(|_| HxfsError::BadTree)?;
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = tree.record_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < tree.records().len() {
            if let Some(record) = tree.records()[index] {
                let offset = 16 + written * 32;
                if offset + 32 > payload.len() {
                    return Err(HxfsError::NoSpace);
                }
                payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
                payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
                payload[offset + 16..offset + 20]
                    .copy_from_slice(&(record.state as u32).to_le_bytes());
                payload[offset + 24..offset + 32]
                    .copy_from_slice(&record.owner_object_id.to_le_bytes());
                written += 1;
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_ALLOCATION_TREE,
            self.system_volume.root_object_id,
            lba,
            &payload[..16 + written * 32],
            args.0,
            args.1,
            args.2,
        )?)
    }

    fn build_refcount_tree_block(&self, lba: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut tree = RefcountBtree::<MAX_EXTENTS>::new();
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    tree.insert(RefcountRecord {
                        start_block: extent.extent.physical_block,
                        block_count: u64::from(extent.extent.block_count),
                        refcount: 1,
                    })
                    .map_err(|_| HxfsError::BadTree)?;
                }
            }
            index += 1;
        }
        tree.validate().map_err(|_| HxfsError::BadTree)?;
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = tree.record_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < tree.records().len() {
            if let Some(record) = tree.records()[index] {
                let offset = 16 + written * 24;
                if offset + 24 > payload.len() {
                    return Err(HxfsError::NoSpace);
                }
                payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
                payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
                payload[offset + 16..offset + 20].copy_from_slice(&record.refcount.to_le_bytes());
                written += 1;
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_REFCOUNT_TREE,
            self.system_volume.root_object_id,
            lba,
            &payload[..16 + written * 24],
            args.0,
            args.1,
            args.2,
        )?)
    }

    fn build_backref_tree_block(&self, lba: u64, generation: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut tree = BackrefBtree::<MAX_EXTENTS>::new();
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    tree.insert(BackrefRecord {
                        start_block: extent.extent.physical_block,
                        block_count: u64::from(extent.extent.block_count),
                        owner_object_id: extent.object_id,
                        kind: BackrefKind::ObjectData,
                        generation,
                    })
                    .map_err(|_| HxfsError::BadTree)?;
                }
            }
            index += 1;
        }
        tree.validate().map_err(|_| HxfsError::BadTree)?;
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = tree.record_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < tree.records().len() {
            if let Some(record) = tree.records()[index] {
                let offset = 16 + written * 40;
                if offset + 40 > payload.len() {
                    return Err(HxfsError::NoSpace);
                }
                payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
                payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
                payload[offset + 16..offset + 24]
                    .copy_from_slice(&record.owner_object_id.to_le_bytes());
                payload[offset + 24..offset + 28]
                    .copy_from_slice(&(record.kind as u32).to_le_bytes());
                payload[offset + 32..offset + 40].copy_from_slice(&record.generation.to_le_bytes());
                written += 1;
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_BACKREF_TREE,
            self.system_volume.root_object_id,
            lba,
            &payload[..16 + written * 40],
            args.0,
            args.1,
            args.2,
        )?)
    }

    fn build_quota_tree_block(
        &self,
        lba: u64,
        future_next_lba: u64,
    ) -> FixedResult<[u8; BLOCK_SIZE]> {
        let physical_used_bytes = future_next_lba
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(HxfsError::OutOfRange)?;
        let mut tree = QuotaBtree::<1>::new();
        tree.upsert(QuotaRecord {
            volume_uuid: self.system_volume.uuid,
            physical_limit_bytes: self.system_volume.quota_physical_bytes,
            physical_used_bytes,
            object_limit: self.system_volume.quota_objects,
            object_count: self.live_object_count() as u64,
        })
        .map_err(|_| HxfsError::NoSpace)?;
        tree.validate().map_err(|_| HxfsError::BadTree)?;
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = tree.record_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        let mut index = 0usize;
        while index < tree.records().len() {
            if let Some(record) = tree.records()[index] {
                let offset = 16 + written * 56;
                if offset + 56 > payload.len() {
                    return Err(HxfsError::NoSpace);
                }
                payload[offset..offset + 16].copy_from_slice(&record.volume_uuid);
                payload[offset + 16..offset + 24]
                    .copy_from_slice(&record.physical_limit_bytes.to_le_bytes());
                payload[offset + 24..offset + 32]
                    .copy_from_slice(&record.physical_used_bytes.to_le_bytes());
                payload[offset + 32..offset + 40]
                    .copy_from_slice(&record.object_limit.to_le_bytes());
                payload[offset + 40..offset + 48]
                    .copy_from_slice(&record.object_count.to_le_bytes());
                written += 1;
            }
            index += 1;
        }
        let args = self.encryption_args();
        Ok(make_metadata_block_for_volume(
            BLOCK_TYPE_QUOTA_TREE,
            self.system_volume.root_object_id,
            lba,
            &payload[..16 + written * 56],
            args.0,
            args.1,
            args.2,
        )?)
    }

    fn build_volume_table_block(
        &self,
        object_table_lba: u64,
        object_count: u32,
        lba: u64,
    ) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut payload = [0u8; 16 + 96];
        payload[0..4].copy_from_slice(&1u32.to_le_bytes());
        let offset = 16usize;
        payload[offset..offset + 16].copy_from_slice(&self.system_volume.uuid);
        payload[offset + 16..offset + 24]
            .copy_from_slice(&self.system_volume.root_object_id.to_le_bytes());
        payload[offset + 24..offset + 32].copy_from_slice(&object_table_lba.to_le_bytes());
        payload[offset + 32..offset + 36].copy_from_slice(&object_count.to_le_bytes());
        payload[offset + 36..offset + 40].copy_from_slice(&self.system_volume.flags.to_le_bytes());
        payload[offset + 40..offset + 44]
            .copy_from_slice(&self.system_volume.encryption_policy_id.to_le_bytes());
        payload[offset + 44..offset + 48]
            .copy_from_slice(&self.system_volume.compression_policy_id.to_le_bytes());
        payload[offset + 48..offset + 56]
            .copy_from_slice(&self.system_volume.quota_physical_bytes.to_le_bytes());
        payload[offset + 56..offset + 64]
            .copy_from_slice(&self.system_volume.quota_objects.to_le_bytes());
        Ok(make_metadata_block(
            BLOCK_TYPE_VOLUME_TABLE,
            0,
            lba,
            &payload,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn write_journaled_target(
        &mut self,
        target_lba: u64,
        block: &[u8; BLOCK_SIZE],
        sequence: u64,
        record_index: u32,
        record_count: u32,
        journal_start_lba: u64,
        final_checkpoint_lba: u64,
        flags: u32,
    ) -> FixedResult<()> {
        self.store.write_blocks(target_lba, 1, block)?;
        let metadata_lba = journal_start_lba + u64::from(record_index) * 2;
        let data_lba = metadata_lba + 1;
        let journal = build_journal_record_block(
            sequence,
            record_index,
            record_count,
            target_lba,
            data_lba,
            crc32c(block),
            flags,
            final_checkpoint_lba,
            metadata_lba,
        );
        self.store.write_blocks(metadata_lba, 1, &journal)?;
        self.store.write_blocks(data_lba, 1, block)?;
        Ok(())
    }

    fn sort_directory(&mut self, parent: u64) {
        let mut i = 0usize;
        while i < self.dir_entries.len() {
            let mut j = i + 1;
            while j < self.dir_entries.len() {
                if should_swap_dir(self.dir_entries[i], self.dir_entries[j], parent) {
                    self.dir_entries.swap(i, j);
                }
                j += 1;
            }
            i += 1;
        }
    }

    fn sort_extents(&mut self, object_id: u64) {
        let mut i = 0usize;
        while i < self.extents.len() {
            let mut j = i + 1;
            while j < self.extents.len() {
                if should_swap_extent(self.extents[i], self.extents[j], object_id) {
                    self.extents.swap(i, j);
                }
                j += 1;
            }
            i += 1;
        }
    }
}

impl FixedDirEntry {
    fn name_bytes(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_BYTES && core::str::from_utf8(name).is_ok()
}

fn should_swap_dir(a: Option<FixedDirEntry>, b: Option<FixedDirEntry>, parent: u64) -> bool {
    match (a, b) {
        (Some(left), Some(right))
            if left.parent_object_id == parent && right.parent_object_id == parent =>
        {
            left.name_bytes() > right.name_bytes()
        }
        (None, Some(right)) if right.parent_object_id == parent => true,
        _ => false,
    }
}

fn should_swap_extent(a: Option<FixedExtent>, b: Option<FixedExtent>, object_id: u64) -> bool {
    match (a, b) {
        (Some(left), Some(right))
            if left.object_id == object_id && right.object_id == object_id =>
        {
            left.extent.logical_block > right.extent.logical_block
        }
        (None, Some(right)) if right.object_id == object_id => true,
        _ => false,
    }
}

fn write_object_record(out: &mut [u8], offset: usize, object: ObjectDescriptor) {
    out[offset..offset + 8].copy_from_slice(&object.object_id.to_le_bytes());
    out[offset + 8..offset + 12].copy_from_slice(&object.object_type.to_le_bytes());
    out[offset + 12..offset + 16].copy_from_slice(&object.type_version.to_le_bytes());
    out[offset + 16..offset + 24].copy_from_slice(&object.size.to_le_bytes());
    out[offset + 24..offset + 32].copy_from_slice(&object.modified_unix_ns.to_le_bytes());
    out[offset + 32..offset + 36].copy_from_slice(&object.encryption_policy_id.to_le_bytes());
    out[offset + 36..offset + 40].copy_from_slice(&object.compression_policy_id.to_le_bytes());
    out[offset + 40..offset + 48].copy_from_slice(&object.tree_lba.to_le_bytes());
    out[offset + 48..offset + 52].copy_from_slice(&object.record_count.to_le_bytes());
    out[offset + 52..offset + 56].copy_from_slice(&object.flags.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn build_checkpoint_block(
    sequence: u64,
    volume_table_lba: u64,
    volume_uuid: Uuid,
    allocation_tree_lba: u64,
    refcount_tree_lba: u64,
    backref_tree_lba: u64,
    quota_tree_lba: u64,
    encryption_policy_tree_lba: u64,
    compression_policy_tree_lba: u64,
    hxblob_index_tree_lba: u64,
    hxblob_merkle_tree_lba: u64,
    virtual_volume_tree_lba: u64,
    gpt_summary_lba: u64,
    install_manifest_lba: u64,
    lba: u64,
) -> [u8; BLOCK_SIZE] {
    let mut payload = [0u8; 128];
    payload[0..8].copy_from_slice(&sequence.to_le_bytes());
    payload[8..16].copy_from_slice(&volume_table_lba.to_le_bytes());
    payload[16..20].copy_from_slice(&1u32.to_le_bytes());
    payload[24..40].copy_from_slice(&volume_uuid);
    payload[40..48].copy_from_slice(&allocation_tree_lba.to_le_bytes());
    payload[48..56].copy_from_slice(&refcount_tree_lba.to_le_bytes());
    payload[56..64].copy_from_slice(&backref_tree_lba.to_le_bytes());
    payload[64..72].copy_from_slice(&quota_tree_lba.to_le_bytes());
    payload[72..80].copy_from_slice(&encryption_policy_tree_lba.to_le_bytes());
    payload[80..88].copy_from_slice(&compression_policy_tree_lba.to_le_bytes());
    payload[88..96].copy_from_slice(&hxblob_index_tree_lba.to_le_bytes());
    payload[96..104].copy_from_slice(&hxblob_merkle_tree_lba.to_le_bytes());
    payload[104..112].copy_from_slice(&virtual_volume_tree_lba.to_le_bytes());
    payload[112..120].copy_from_slice(&gpt_summary_lba.to_le_bytes());
    payload[120..128].copy_from_slice(&install_manifest_lba.to_le_bytes());
    make_metadata_block(BLOCK_TYPE_CHECKPOINT, 0, lba, &payload)
}

#[allow(clippy::too_many_arguments)]
fn build_journal_record_block(
    sequence: u64,
    record_index: u32,
    record_count: u32,
    target_lba: u64,
    data_lba: u64,
    data_crc32c: u32,
    flags: u32,
    final_checkpoint_lba: u64,
    metadata_lba: u64,
) -> [u8; BLOCK_SIZE] {
    let mut payload = [0u8; 48];
    payload[0..8].copy_from_slice(&sequence.to_le_bytes());
    payload[8..12].copy_from_slice(&record_index.to_le_bytes());
    payload[12..16].copy_from_slice(&record_count.to_le_bytes());
    payload[16..24].copy_from_slice(&target_lba.to_le_bytes());
    payload[24..32].copy_from_slice(&data_lba.to_le_bytes());
    payload[32..36].copy_from_slice(&data_crc32c.to_le_bytes());
    payload[36..40].copy_from_slice(&flags.to_le_bytes());
    payload[40..48].copy_from_slice(&final_checkpoint_lba.to_le_bytes());
    make_metadata_block(BLOCK_TYPE_JOURNAL_RECORD, 0, metadata_lba, &payload)
}

fn make_superblock_block(
    instance_uuid: Uuid,
    sequence: u64,
    checkpoint_lba: u64,
    journal_start_lba: u64,
    journal_end_lba: u64,
    root_state: u32,
) -> [u8; BLOCK_SIZE] {
    let mut payload = [0u8; 120];
    payload[0..16].copy_from_slice(&FORMAT_GUID);
    payload[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    payload[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
    payload[24..40].copy_from_slice(&instance_uuid);
    payload[40..48].copy_from_slice(&sequence.to_le_bytes());
    payload[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    payload[56..64].copy_from_slice(&checkpoint_lba.to_le_bytes());
    payload[72..80].copy_from_slice(&journal_start_lba.to_le_bytes());
    payload[80..88].copy_from_slice(&journal_end_lba.to_le_bytes());
    payload[104..112].copy_from_slice(
        &(BASE_INCOMPAT_FEATURES | FEATURE_INCOMPAT_QUOTA_ENFORCEMENT).to_le_bytes(),
    );
    payload[112..116].copy_from_slice(&root_state.to_le_bytes());
    make_metadata_block(BLOCK_TYPE_SUPERBLOCK, 0, 0, &payload)
}

fn make_metadata_block(block_type: u32, owner: u64, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
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

/// Stage B.1 wrapper: build a metadata block, encrypting the
/// payload when the block type belongs to the encrypted-on-disk
/// set and the volume is encrypted. Superblock, checkpoint,
/// volume table, and object table are *not* encrypted even on
/// an encrypted volume because they carry global state needed
/// to find the encryption key (per `docs/STAGE_B_PLAN.md` B.1).
#[cfg(feature = "crypto-aes-gcm")]
fn make_metadata_block_for_volume(
    block_type: u32,
    owner: u64,
    lba: u64,
    payload: &[u8],
    volume_encrypted: bool,
    metadata_key: Option<&[u8; crate::hkdf::SUBKEY_BYTES]>,
    volume_uuid: &crate::format::Uuid,
) -> FixedResult<[u8; BLOCK_SIZE]> {
    if volume_encrypted && is_encrypted_block_type(block_type) {
        let key = metadata_key.ok_or(HxfsError::EncryptedPolicyInvalid)?;
        return crate::encrypted_metadata::make_encrypted_metadata_block(
            block_type,
            owner,
            lba,
            payload,
            key,
            volume_uuid,
        )
        .map_err(|_| HxfsError::BadBlock);
    }
    Ok(make_metadata_block(block_type, owner, lba, payload))
}

/// Stage B.1 wrapper for builds without `crypto-aes-gcm`:
/// always falls through to the plain v5 builder. A mount of an
/// encrypted volume on a build without the feature is rejected
/// at the mount gate with `EncryptedPolicyInvalid`; the
/// `volume_encrypted` flag therefore never reaches `true` on
/// such a build and the encryption path is unreachable.
#[cfg(not(feature = "crypto-aes-gcm"))]
fn make_metadata_block_for_volume(
    block_type: u32,
    owner: u64,
    lba: u64,
    payload: &[u8],
    _volume_encrypted: bool,
    _metadata_key: Option<&[u8; 32]>,
    _volume_uuid: &crate::format::Uuid,
) -> FixedResult<[u8; BLOCK_SIZE]> {
    Ok(make_metadata_block(block_type, owner, lba, payload))
}

/// Stage B.1: which metadata block types carry the encrypted
/// payload on an encrypted volume. The superblock, checkpoint,
/// volume table, and object table stay plaintext because they
/// are needed to bootstrap the encryption key (see
/// `docs/STAGE_B_PLAN.md` B.1).
fn is_encrypted_block_type(block_type: u32) -> bool {
    matches!(
        block_type,
        BLOCK_TYPE_DIRECTORY
            | BLOCK_TYPE_EXTENT_TABLE
            | BLOCK_TYPE_ALLOCATION_TREE
            | BLOCK_TYPE_REFCOUNT_TREE
            | BLOCK_TYPE_BACKREF_TREE
            | BLOCK_TYPE_QUOTA_TREE
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> FixedResult<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> FixedResult<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(HxfsError::BadTree)?
            .try_into()
            .map_err(|_| HxfsError::BadTree)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{BlockReader, SliceBlockReader};
    use crate::writer::HxfsWriter;
    use crate::Hxfs;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    const INSTANCE: Uuid = [0x77; 16];
    const VOLUME: Uuid = [0x88; 16];
    const BLOCKS: usize = 256;

    struct MemStore {
        image: Vec<u8>,
        flushes: u64,
    }

    impl MemStore {
        fn from_image(image: &[u8]) -> Self {
            let mut store = Self {
                image: vec![0; BLOCK_SIZE * BLOCKS],
                flushes: 0,
            };
            store.image[..image.len()].copy_from_slice(image);
            store
        }

        fn as_slice(&self) -> &[u8] {
            &self.image
        }
    }

    impl BlockReader for MemStore {
        fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
            let start = lba as usize * BLOCK_SIZE;
            let len = blocks as usize * BLOCK_SIZE;
            out.get_mut(..len)
                .ok_or(HxfsError::BufferTooSmall)?
                .copy_from_slice(self.image.get(start..start + len).ok_or(HxfsError::Io)?);
            Ok(())
        }
    }

    impl BlockStore for MemStore {
        fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
            let start = lba as usize * BLOCK_SIZE;
            let len = blocks as usize * BLOCK_SIZE;
            self.image
                .get_mut(start..start + len)
                .ok_or(HxfsError::Io)?
                .copy_from_slice(input.get(..len).ok_or(HxfsError::BufferTooSmall)?);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), HxfsError> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn fixed_writer_creates_writes_checkpoints_and_remounts() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let mounted = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store);
        assert!(mounted.is_ok());
        let Ok(mut mounted) = mounted else { return };
        let home = mounted.mkdir_path("/home");
        assert!(home.is_ok());
        let file = mounted.create_file_path("/home/noheap.txt");
        assert!(file.is_ok());
        let Ok(file) = file else { return };
        let file = mounted.write_file_at(file, 0, b"fixed");
        assert!(file.is_ok());
        assert!(mounted.publish_checkpoint().is_ok());
        assert_ne!(mounted.checkpoint().allocation_tree_lba, 0);
        assert_ne!(mounted.checkpoint().refcount_tree_lba, 0);
        assert_ne!(mounted.checkpoint().backref_tree_lba, 0);
        assert_ne!(mounted.checkpoint().quota_tree_lba, 0);
        let store = mounted.into_store();

        let image: Vec<u8> = store.as_slice().to_vec();
        let reader = SliceBlockReader::new(&image);
        let fs = Hxfs::mount(reader);
        assert!(fs.is_ok());
        let Ok(mut fs) = fs else { return };
        let file = fs.open_path("/home/noheap.txt");
        assert!(file.is_ok());
        let Ok(file) = file else { return };
        let mut out = [0u8; 16];
        assert_eq!(fs.read_file(file, &mut out), Ok(5));
        assert_eq!(&out[..5], b"fixed");
    }

    #[test]
    fn fixed_writer_enforces_object_and_physical_quota() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        assert!(mounted.set_quota_limits(0, 1).is_ok());
        assert_eq!(mounted.create_file_path("/denied"), Err(HxfsError::NoSpace));

        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let limit = mounted.charged_physical_bytes();
        assert!(limit.is_ok());
        let Ok(limit) = limit else { return };
        assert!(mounted.set_quota_limits(limit, 0).is_ok());
        let file = mounted.create_file_path("/file");
        assert!(file.is_ok());
        let Ok(file) = file else { return };
        assert_eq!(
            mounted.write_file_at(file, 0, b"x"),
            Err(HxfsError::NoSpace)
        );
    }

    #[test]
    fn fixed_writer_renames_and_unlinks_without_heap() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        assert!(mounted.mkdir_path("/tmp").is_ok());
        let file = mounted.create_file_path("/tmp/a.txt");
        assert!(file.is_ok());
        assert!(mounted.rename_path("/tmp/a.txt", "/tmp/b.txt").is_ok());
        assert!(mounted.unlink_path("/tmp/b.txt").is_ok());
        assert!(mounted.publish_checkpoint().is_ok());
        let store = mounted.into_store();
        let image: Vec<u8> = store.as_slice().to_vec();
        let reader = SliceBlockReader::new(&image);
        let Ok(mut fs) = Hxfs::mount(reader) else {
            assert!(false, "remount should work");
            return;
        };
        assert_eq!(fs.open_path("/tmp/b.txt").err(), Some(HxfsError::NotFound));
    }
}
