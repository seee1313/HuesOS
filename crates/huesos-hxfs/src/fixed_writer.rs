//! Fixed-capacity, no-heap Hxfs mutable writer.
//!
//! This module is the Stage-K no-heap service foundation: it owns a writable
//! [`BlockStore`], mirrors the mounted metadata in fixed arrays, applies small
//! handle-first mutations without allocation, and publishes changes through the
//! v2 journal/root-store protocol.

use crate::alloc_tree::{AllocationBtree, AllocationRecord, AllocationState};
use crate::crc32c::{crc32c, metadata_crc32c};
use crate::format::*;
#[cfg(feature = "hxblob")]
use crate::hxblob::BlobHash;
#[cfg(feature = "hxblob")]
use crate::hxblob_tree::{HxblobIndexRecord, HxblobIndexTree, HxblobMerkleTree};
use crate::quota_tree::{QuotaBtree, QuotaRecord};
use crate::recovery::BlockStore;
use crate::ref_tree::{BackrefBtree, BackrefKind, BackrefRecord, RefcountBtree, RefcountRecord};
use crate::{
    parse_dir_record, parse_extent_record, parse_extent_record_v2, parse_extent_tree_root,
    parse_header, parse_object_record, read_checkpoint, read_superblock, read_system_volume,
    validate_metadata_block, ExtentCompressionMeta, HxfsError, DIR_RECORD_BYTES,
    EXTENT_RECORD_BYTES, EXTENT_RECORD_BYTES_V2, HEADER_BYTES, OBJECT_RECORD_BYTES,
};
use alloc::vec;
use alloc::vec::Vec;

/// Fixed writer mount/mutation result.
pub type FixedResult<T> = Result<T, HxfsError>;

/// Maximum Hxblob objects per volume (Stage F). One index block
/// holds 44 records; 32 keeps it single-block.
pub const MAX_HXBLOBS: usize = 128;
// 128 blobs = ~13 KiB of in-memory index; the on-disk index is a
// multi-block tree (root + leaves) with a 1936-record ceiling per
// volume. Sized so the writer's fixed arrays stay small enough for
// stack-resident writers in host tests (the service writer lives on
// the heap).
/// Maximum quota records (1 volume + per-job records).
pub const MAX_QUOTA_RECORDS: usize = 16;

/// Bounded per-mount registry of data extents whose read failed
/// (decrypt/CRC/decompress error). Subsequent reads of a marked
/// extent fail fast without touching the disk; other files keep
/// working. Stage C: the extent is "bad" for the lifetime of the
/// mount; persisting the marker on disk is a Stage C+ item.
pub const MAX_BAD_EXTENTS: usize = 16;

/// Decoded pages the mounted writer caches.
///
/// 256 * 4 KiB = 1 MiB, held inline in the mount. The service's user
/// heap is 18 MiB and the mount is already boxed, so this is the
/// largest cache that leaves comfortable headroom for request
/// buffers; the host-side `PageCache` default of 16 MiB would not
/// fit at all. Raising it is a heap-budget decision, not a free win.
pub const PAGE_CACHE_SLOTS: usize = 256;

/// Stage C: report-only live scrub summary.
///
/// The scrub walks every live object: it re-validates each
/// metadata tree block (header + CRC, through the same
/// decrypt-aware read path as the mount) and reads every data
/// extent through the full decrypt/decompress/CRC path into a
/// scratch buffer. Errors are counted and the offending extents
/// are marked bad, but scrub never repairs anything.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrubSummary {
    /// Metadata tree blocks re-validated.
    pub metadata_blocks: u64,
    /// Data extent blocks read and verified.
    pub data_blocks: u64,
    /// Data bytes read and verified.
    pub data_bytes: u64,
    /// Failures encountered (metadata or data).
    pub errors: u64,
}

/// Stage C: report-only structural fsck summary.
///
/// Re-validates the persisted superblock/checkpoint/volume table
/// and the in-memory object model: root presence, object-id
/// uniqueness, directory entries referencing live objects,
/// per-object extent monotonicity, and record counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsckSummary {
    /// Checks performed.
    pub checks: u64,
    /// Findings.
    pub errors: u64,
}

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
    /// Stage B.3 completion: per-extent compression descriptor
    /// carried by v2 extent-table records. `None` for plain
    /// extents (and for every record of a v1 extent table).
    compression: Option<ExtentCompressionMeta>,
}

/// How a data block was stored on disk, decided by
/// [`FixedHxfsWriter::write_data_blocks`] and serialized by the
/// extent-table builder.
///
/// The `MultiSlot` variant is only produced by the
/// `crypto-aes-gcm` build (the encrypted-volume two-slot path); on
/// a build without crypto the variant is never constructed and
/// dead-code analysis would flag it.
#[cfg_attr(not(feature = "crypto-aes-gcm"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtentWriteKind {
    /// Plaintext stored verbatim in one slot (plain volume, or an
    /// incompressible block small enough for the envelope).
    Plain,
    /// Compressed payload (optionally inside the envelope).
    Compressed(ExtentCompressionMeta),
    /// One logical block split across two encrypted envelopes
    /// ([`EXTENT_FLAG_MULTI_SLOT`]): the incompressible full-block
    /// case on an encrypted volume.
    MultiSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectPlan {
    object_id: u64,
    tree_lba: u64,
    record_count: u32,
}

/// A contiguous run of physical blocks that no live extent references.
///
/// Used for both halves of the reclaim path: the quarantine list of
/// blocks freed by the running transaction, and the pool of blocks
/// that are safe to hand out again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreeRange {
    /// First physical block of the run.
    start_block: u64,
    /// Length of the run in 4 KiB blocks.
    block_count: u64,
}

impl FreeRange {
    /// Exclusive end block, saturating rather than wrapping.
    fn end_block(self) -> u64 {
        self.start_block.saturating_add(self.block_count)
    }
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
    metadata_key: Option<[u8; 32]>,
    /// Stage B.3: per-volume extent subkey used to wrap the
    /// *compressed* payload of every data extent on the
    /// write path. Independent of `metadata_key` (different
    /// HKDF info string). `None` for plain volumes.
    #[cfg(feature = "crypto-aes-gcm")]
    extent_key: Option<[u8; 32]>,
    /// Volume UUID used as the HKDF salt. Cached at mount time
    /// so the write path can re-derive the AEAD nonce and AAD
    /// without re-reading the superblock. The 16-byte UUID is
    /// mixed into the nonce and AAD so a ciphertext cannot be
    /// transplanted across volumes.
    #[cfg(feature = "crypto-aes-gcm")]
    volume_uuid: crate::format::Uuid,
    /// Stage B.3 completion: per-volume compression policy table
    /// accepted at mount time. The write path resolves the codec
    /// for each object (per-object id with per-volume fallback)
    /// against this table, mirroring the reader's
    /// `resolve_compression_for_object` semantics, and stores the
    /// policy-consistent descriptor in the extent record. The
    /// table is mount-scoped configuration; it is copied once at
    /// mount (the reader does the same), and the fixed metadata
    /// arrays stay fixed-capacity.
    compression_policies: Vec<crate::compression::CompressionPolicy>,
    /// Stage C: per-mount registry of bad data extents (physical
    /// LBAs whose read failed). Bounded by [`MAX_BAD_EXTENTS`];
    /// `bad_extent_count` mirrors the used slots.
    bad_extents: [Option<u64>; MAX_BAD_EXTENTS],
    bad_extent_count: usize,
    /// Stage F: Hxblob immutable-object index (hash -> object).
    /// Bounded by [`MAX_HXBLOBS`]; one block holds 44 records so
    /// 32 keeps the on-disk index single-block.
    #[cfg(feature = "hxblob")]
    hxblob_index: HxblobIndexTree<MAX_HXBLOBS>,
    /// Stage F: Hxblob Merkle descriptors (empty for the MVP;
    /// single-chunk blobs store the hash directly).
    #[cfg(feature = "hxblob")]
    hxblob_merkle: HxblobMerkleTree<MAX_HXBLOBS>,
    /// Stage E (Phase-2): per-Job quota records (volume quota is
    /// record for the system volume UUID). Loaded at mount from the
    /// quota tree block; the active job's record is checked on every
    /// write.
    quota_tree: QuotaBtree<MAX_QUOTA_RECORDS>,
    /// Job id whose quota is enforced on writes; `None` = no per-job
    /// limit.
    active_job: Option<u64>,
    objects: [Option<FixedObject>; MAX_OBJECTS],
    dir_entries: [Option<FixedDirEntry>; MAX_DIR_ENTRIES],
    extents: [Option<FixedExtent>; MAX_EXTENTS],
    next_object_id: u64,
    next_lba: u64,
    /// Blocks whose last reference was dropped by the transaction that
    /// is still being built, and which are therefore *not* yet safe to
    /// reuse.
    ///
    /// A block sits here until the checkpoint that removes its last
    /// reference is published. Handing it out earlier would let one
    /// checkpoint both free and re-seal the same block, which breaks
    /// the generation scheme (both tenancies would derive the same
    /// nonce from the same sequence number) and would leave a crash
    /// before the checkpoint with the block claimed by two extents at
    /// once.
    /// Volume identity used as the page-cache key namespace.
    ///
    /// Derived from the superblock instance UUID at mount so the
    /// cache key survives remount of a *different* volume through
    /// the same service without aliasing.
    cache_volume_id: u64,
    /// Decoded-page cache for the read path.
    ///
    /// The service mounts through `FixedHxfsWriter`, so without this
    /// every read went to the device and paid decrypt+decompress
    /// again, even for a block just read. `Hxfs` (the read-only
    /// reader) had a cache; the writer, which is what production
    /// actually runs, did not.
    ///
    /// Boxed, not inline: 256 pages is 1 MiB, and the mount is
    /// constructed by value before being boxed by the caller, so an
    /// inline array of that size blows the 2 MiB test/thread stack on
    /// the way in. One allocation at mount keeps the property that
    /// actually matters -- zero allocation on the I/O path.
    page_cache: alloc::boxed::Box<crate::page_cache::FixedPageCache<PAGE_CACHE_SLOTS>>,
    pending_free: [Option<FreeRange>; MAX_EXTENTS],
    /// Blocks that survived quarantine and may be allocated again.
    free_space: [Option<FreeRange>; MAX_EXTENTS],
    /// Extents pinned by live snapshots.
    ///
    /// A snapshot is a second owner of every extent the volume held
    /// when it was taken. Unlinking a file drops the *live* reference
    /// but not the snapshot's, and without somewhere to record that,
    /// the free path would hand a snapshot's blocks back to the
    /// allocator and the snapshot would read whatever overwrote them.
    /// Boxed for the same reason as the page cache: this is sized by
    /// MAX_EXTENTS and must not sit on the construction stack.
    snapshot_refs: alloc::boxed::Box<RefcountBtree<MAX_EXTENTS>>,
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
        Self::mount_with_keys(store, &[], None)
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
    /// reader. The compression table is stored and consulted
    /// by the write path (Stage B.3 completion): the codec is
    /// resolved per object against the table and the on-disk
    /// extent record carries the resulting descriptor.
    pub fn mount_with_policies(
        store: S,
        encryption_policies: &[crate::crypto::EncryptionPolicy],
        compression_policies: &[crate::compression::CompressionPolicy],
        volume_key: Option<&[u8; 32]>,
    ) -> FixedResult<Self> {
        let mut mounted = Self::mount_with_keys(store, encryption_policies, volume_key)?;
        mounted.compression_policies = compression_policies.to_vec();
        Ok(mounted)
    }

    /// Mount a clean v5 Hxfs volume into fixed-capacity
    /// mutable state, resolving the system volume's
    /// encryption policy from `encryption_policies`. See
    /// [`Hxfs::mount_with_keys`] for the semantics of the
    /// table and the variants returned for an
    /// encrypted-but-unresolvable volume; the writer
    /// mirrors the reader's contract so a plain mount in
    /// either code path is interchangeable. The fixed
    /// capacity templates (`MAX_OBJECTS`, `MAX_DIR_ENTRIES`,
    /// `MAX_EXTENTS`) bound the on-memory metadata
    /// footprint and are tuned for the hxfs-service
    /// production mount path.
    ///
    /// `volume_key` (Stage D): see [`Hxfs::mount_with_keys`].
    /// An encrypted volume without a key context is rejected
    /// with [`HxfsError::EncryptedVolumeKeyUnavailable`].
    pub fn mount_with_keys(
        mut store: S,
        encryption_policies: &[crate::crypto::EncryptionPolicy],
        volume_key: Option<&[u8; 32]>,
    ) -> FixedResult<Self> {
        #[cfg(not(feature = "crypto-aes-gcm"))]
        let _ = volume_key;
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
        // Stage D: derive the per-volume AEAD subkeys from the
        // caller-supplied volume key (the bootloader/kernel key
        // path); an encrypted volume without a key context is
        // rejected up front. The old instance-uuid placeholder IKM
        // is gone.
        #[cfg(feature = "crypto-aes-gcm")]
        let metadata_key = if encryption.is_some() {
            let ikm = volume_key.ok_or(HxfsError::EncryptedVolumeKeyUnavailable)?;
            let mut key = [0u8; 32];
            crate::encrypted_metadata::derive_metadata_key_for_volume(
                ikm,
                &superblock.instance_uuid,
                &mut key,
            )
            .map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
            Some(key)
        } else {
            None
        };
        // Stage B.3 wire: derive the per-volume extent subkey from
        // the same volume key. Independent info string from the
        // metadata subkey.
        #[cfg(feature = "crypto-aes-gcm")]
        let extent_key = if encryption.is_some() {
            let ikm = volume_key.ok_or(HxfsError::EncryptedVolumeKeyUnavailable)?;
            let mut key = [0u8; 32];
            crate::extent_crypto::derive_extent_key_for_volume(
                ikm,
                &superblock.instance_uuid,
                &mut key,
            )
            .map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
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
            extent_key,
            #[cfg(feature = "crypto-aes-gcm")]
            volume_uuid: superblock.instance_uuid,
            compression_policies: Vec::new(),
            bad_extents: [const { None }; MAX_BAD_EXTENTS],
            bad_extent_count: 0,
            #[cfg(feature = "hxblob")]
            hxblob_index: HxblobIndexTree::new(),
            #[cfg(feature = "hxblob")]
            hxblob_merkle: HxblobMerkleTree::new(),
            quota_tree: QuotaBtree::new(),
            active_job: None,
            objects: [const { None }; MAX_OBJECTS],
            dir_entries: [const { None }; MAX_DIR_ENTRIES],
            extents: [const { None }; MAX_EXTENTS],
            next_object_id: 1,
            next_lba: 1,
            cache_volume_id: crate::page_cache::volume_id_of(&superblock.instance_uuid),
            page_cache: alloc::boxed::Box::new(crate::page_cache::FixedPageCache::new()),
            pending_free: [None; MAX_EXTENTS],
            snapshot_refs: alloc::boxed::Box::new(RefcountBtree::new()),
            free_space: [None; MAX_EXTENTS],
            dirty: false,
        };
        mounted.load_object_tree()?;
        #[cfg(feature = "hxblob")]
        mounted.load_hxblob_index()?;
        mounted.load_quota_tree()?;
        mounted.next_object_id = mounted.compute_next_object_id();
        mounted.next_lba = mounted.compute_next_lba()?;
        mounted.rebuild_free_space();
        Ok(mounted)
    }

    /// Resolved encryption policy for this volume, or `None` for
    /// plain volumes. Mirrors [`Hxfs::encryption`].
    pub const fn encryption(&self) -> Option<&crate::crypto::EncryptionPolicy> {
        self.encryption.as_ref()
    }

    /// Number of data extents marked bad on this mount (Stage C).
    pub const fn bad_extent_count(&self) -> usize {
        self.bad_extent_count
    }

    /// Whether `lba` is a known-bad data extent on this mount.
    fn is_bad_extent(&self, lba: u64) -> bool {
        let mut index = 0usize;
        while index < self.bad_extent_count {
            if self.bad_extents[index] == Some(lba) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Mark `lba` as a bad data extent (bounded, deduplicated).
    fn mark_bad_extent(&mut self, lba: u64) {
        if self.is_bad_extent(lba) || self.bad_extent_count >= MAX_BAD_EXTENTS {
            return;
        }
        self.bad_extents[self.bad_extent_count] = Some(lba);
        self.bad_extent_count += 1;
    }

    /// Stage C: report-only live scrub of the persisted volume.
    ///
    /// Walks every live object: re-validates each metadata tree
    /// block through the decrypt-aware read path and reads every
    /// data extent through the full decrypt/decompress/CRC path.
    /// Failures are counted and the offending extents are marked
    /// bad; scrub never repairs. The scrub checks the persisted
    /// state (the store), not un-published in-memory mutations.
    pub fn scrub(&mut self) -> FixedResult<ScrubSummary> {
        let mut summary = ScrubSummary::default();
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                let descriptor = object.descriptor;
                // Metadata tree block.
                let mut block = [0u8; BLOCK_SIZE];
                let metadata_ok = match descriptor.object_type {
                    OBJECT_TYPE_DIRECTORY => self
                        .read_mounted_metadata_block(
                            descriptor.tree_lba,
                            BLOCK_TYPE_DIRECTORY,
                            descriptor.object_id,
                            &mut block,
                        )
                        .is_ok(),
                    OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK => self
                        .read_mounted_metadata_block_any_type(
                            descriptor.tree_lba,
                            BLOCK_TYPE_EXTENT_TABLE,
                            BLOCK_TYPE_EXTENT_TABLE_V2,
                            descriptor.object_id,
                            &mut block,
                        )
                        .is_ok(),
                    _ => true,
                };
                if metadata_ok {
                    summary.metadata_blocks += 1;
                } else {
                    summary.errors += 1;
                }
                // Data extents.
                if matches!(
                    descriptor.object_type,
                    OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK
                ) {
                    let mut extent_index = 0usize;
                    while extent_index < self.extents.len() {
                        if let Some(extent) = self.extents[extent_index] {
                            if extent.object_id != descriptor.object_id {
                                extent_index += 1;
                                continue;
                            }
                            let logical = if extent.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                                1
                            } else {
                                u64::from(extent.extent.block_count)
                            };
                            let logical = match usize::try_from(logical) {
                                Ok(v) => v,
                                Err(_) => {
                                    summary.errors += 1;
                                    extent_index += 1;
                                    continue;
                                }
                            };
                            let mut buf = vec![0u8; logical * BLOCK_SIZE];
                            match self.copy_extent(extent.extent, extent.compression, &mut buf) {
                                Ok(()) => {
                                    summary.data_blocks += logical as u64;
                                    summary.data_bytes += buf.len() as u64;
                                }
                                Err(HxfsError::Compression) => {
                                    summary.errors += 1;
                                    self.mark_bad_extent(extent.extent.physical_block);
                                }
                                Err(_) => {
                                    summary.errors += 1;
                                }
                            }
                        }
                        extent_index += 1;
                    }
                }
            }
            index += 1;
        }
        Ok(summary)
    }

    /// Stage C: report-only structural fsck.
    ///
    /// Re-validates the persisted superblock/checkpoint/volume
    /// table and the in-memory object model. Structural damage
    /// (bad superblock, duplicate object ids, dangling directory
    /// entries, overlapping extents, count mismatches) is counted;
    /// fsck never repairs.
    pub fn fsck(&mut self) -> FsckSummary {
        let mut summary = FsckSummary::default();
        // Persisted roots.
        summary.checks += 1;
        if read_superblock(&mut self.store, 0).is_err() {
            summary.errors += 1;
        }
        summary.checks += 1;
        if read_checkpoint(
            &mut self.store,
            self.superblock.checkpoint_lba,
            self.superblock.sequence_number,
        )
        .is_err()
        {
            summary.errors += 1;
        }
        summary.checks += 1;
        if read_system_volume(&mut self.store, self.checkpoint).is_err() {
            summary.errors += 1;
        }
        // Root object present.
        summary.checks += 1;
        if self.object(self.system_volume.root_object_id).is_err() {
            summary.errors += 1;
        }
        // Object-id uniqueness.
        summary.checks += 1;
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                let mut other = index + 1;
                while other < self.objects.len() {
                    if let Some(peer) = self.objects[other] {
                        if peer.descriptor.object_id == object.descriptor.object_id {
                            summary.errors += 1;
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        // Directory entries: target exists, name non-empty, no
        // duplicate (parent, object).
        summary.checks += 1;
        index = 0;
        while index < self.dir_entries.len() {
            if let Some(entry) = self.dir_entries[index] {
                if entry.name_len == 0 || self.object(entry.object_id).is_err() {
                    summary.errors += 1;
                }
                let mut other = index + 1;
                while other < self.dir_entries.len() {
                    if let Some(peer) = self.dir_entries[other] {
                        if peer.parent_object_id == entry.parent_object_id
                            && peer.object_id == entry.object_id
                        {
                            summary.errors += 1;
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        // Extent monotonicity per object (logical ranges must not
        // overlap; multi-slot records cover one logical block).
        summary.checks += 1;
        index = 0;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                let end = extent.extent.logical_block
                    + if extent.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                        1
                    } else {
                        u64::from(extent.extent.block_count)
                    };
                let mut other = 0usize;
                while other < self.extents.len() {
                    if let Some(peer) = self.extents[other] {
                        if peer.object_id == extent.object_id
                            && peer.extent.logical_block >= extent.extent.logical_block
                            && peer.extent.logical_block < end
                            && !(peer.extent.physical_block == extent.extent.physical_block
                                && peer.extent.flags == extent.extent.flags)
                        {
                            summary.errors += 1;
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        // Record counts: live dir entries / extents per object
        // must match the object descriptor.
        summary.checks += 1;
        index = 0;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                let expected = object.descriptor.record_count;
                let actual = match object.descriptor.object_type {
                    OBJECT_TYPE_DIRECTORY => {
                        self.directory_entry_count(object.descriptor.object_id)
                    }
                    OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK => {
                        self.extent_count(object.descriptor.object_id)
                    }
                    _ => expected,
                };
                if actual != expected {
                    summary.errors += 1;
                }
            }
            index += 1;
        }
        summary
    }

    /// Stage C + E (Phase-2): full tree scrub. Walks every
    /// checkpoint root (allocation, refcount, backref, quota)
    /// ON DISK, validating each metadata block through the
    /// decrypt-aware read path. Multi-block trees are detected by
    /// trying the ROOT block type first and falling back to the
    /// single-block form; every leaf of a multi-block tree is
    /// validated. Returns (blocks validated, errors).
    pub fn scrub_all(&mut self) -> FixedResult<(u64, u64)> {
        let mut blocks = 0u64;
        let mut errors = 0u64;
        let mut check_root_or_single =
            |this: &mut Self, lba: u64, root_type: u32, single_type: u32| -> FixedResult<()> {
                if lba == 0 {
                    return Ok(());
                }
                let mut block = [0u8; BLOCK_SIZE];
                let header = match this.read_mounted_metadata_block(
                    lba,
                    root_type,
                    this.system_volume.root_object_id,
                    &mut block,
                ) {
                    Ok(header) => header,
                    Err(HxfsError::BadBlock) => {
                        // Not a multi-block root; try the single form.
                        match this.read_mounted_metadata_block(
                            lba,
                            single_type,
                            this.system_volume.root_object_id,
                            &mut block,
                        ) {
                            Ok(_) => blocks += 1,
                            Err(_) => errors += 1,
                        }
                        return Ok(());
                    }
                    Err(_) => {
                        errors += 1;
                        return Ok(());
                    }
                };
                blocks += 1;
                // Multi-block root: validate every leaf.
                let base = header.header_bytes as usize;
                let count = read_u32(&block, base + 8).unwrap_or(0) as usize;
                let leaf_type = match root_type {
                    BLOCK_TYPE_ALLOCATION_TREE_ROOT => BLOCK_TYPE_ALLOCATION_TREE_LEAF,
                    BLOCK_TYPE_REFCOUNT_TREE_ROOT => BLOCK_TYPE_REFCOUNT_TREE_LEAF,
                    _ => BLOCK_TYPE_BACKREF_TREE_LEAF,
                };
                let mut leaf_index = 0usize;
                while leaf_index < count {
                    let leaf_lba = read_u64(&block, base + 16 + leaf_index * 8).unwrap_or(0);
                    if leaf_lba == 0 {
                        errors += 1;
                    } else {
                        let mut leaf = [0u8; BLOCK_SIZE];
                        match this.read_mounted_metadata_block(
                            leaf_lba,
                            leaf_type,
                            this.system_volume.root_object_id,
                            &mut leaf,
                        ) {
                            Ok(_) => blocks += 1,
                            Err(_) => errors += 1,
                        }
                    }
                    leaf_index += 1;
                }
                Ok(())
            };
        check_root_or_single(
            self,
            self.checkpoint.allocation_tree_lba,
            BLOCK_TYPE_ALLOCATION_TREE_ROOT,
            BLOCK_TYPE_ALLOCATION_TREE,
        )?;
        check_root_or_single(
            self,
            self.checkpoint.refcount_tree_lba,
            BLOCK_TYPE_REFCOUNT_TREE_ROOT,
            BLOCK_TYPE_REFCOUNT_TREE,
        )?;
        check_root_or_single(
            self,
            self.checkpoint.backref_tree_lba,
            BLOCK_TYPE_BACKREF_TREE_ROOT,
            BLOCK_TYPE_BACKREF_TREE,
        )?;
        // Quota tree is always single-block.
        let mut block = [0u8; BLOCK_SIZE];
        if self.checkpoint.quota_tree_lba != 0 {
            match self.read_mounted_metadata_block(
                self.checkpoint.quota_tree_lba,
                BLOCK_TYPE_QUOTA_TREE,
                self.system_volume.root_object_id,
                &mut block,
            ) {
                Ok(_) => blocks += 1,
                Err(_) => errors += 1,
            }
        }
        Ok((blocks, errors))
    }

    /// Stage F: store `data` as an immutable Hxblob object.
    ///
    /// The content hash (SHA-256) is the object's identity: a
    /// duplicate hash is rejected with `AlreadyExists`. The bytes
    /// are stored as a normal file object named by the hex hash
    /// (write-once by convention), and the index record is kept in
    /// memory until `publish_checkpoint` serializes the Hxblob
    /// index block. Returns the content hash.
    #[cfg(feature = "hxblob")]
    /// Phase-2 packages: open (or lazily create) the `blobs/`
    /// base directory.
    #[cfg(feature = "hxblob")]
    fn blobs_directory(&mut self) -> FixedResult<DirectoryHandle> {
        const BLOBS_DIR: &str = "blobs";
        let root = self.root_directory();
        if let Ok(dir) = self.open_child_dir(root, BLOBS_DIR) {
            return Ok(dir);
        }
        self.mkdir_child(root, BLOBS_DIR)
    }

    /// Phase-2 packages: open (or lazily create) the shard directory
    /// `blobs/b{hash[0] % 8}` holding the payload file for `hash`.
    #[cfg(feature = "hxblob")]
    fn blob_shard_directory(&mut self, hash: &BlobHash) -> FixedResult<DirectoryHandle> {
        let base = self.blobs_directory()?;
        let shard_index = hash[0] % 8;
        let shard_name = alloc::format!("b{}", shard_index);
        if let Ok(dir) = self.open_child_dir(base, &shard_name) {
            return Ok(dir);
        }
        self.mkdir_child(base, &shard_name)
    }

    #[cfg(feature = "hxblob")]
    pub fn put_blob(&mut self, data: &[u8]) -> FixedResult<BlobHash> {
        let hash = sha256(data);
        if self.hxblob_index.lookup(&hash).is_ok() {
            return Err(HxfsError::AlreadyExists);
        }
        if self.hxblob_index.record_count() >= MAX_HXBLOBS {
            return Err(HxfsError::NoSpace);
        }
        let name = hex_encode(&hash);
        // Phase-2 packages: blobs live in a sharded directory tree
        // (blobs/b0..b7/<hash>) because directories are one block
        // (~14 entries). Sharding keeps each directory under the
        // limit: up to 8 shards x 14 entries = 112 blobs without a
        // multi-block directory (a later format feature).
        let blob_dir = self.blob_shard_directory(&hash)?;
        let file = self.create_file_child(blob_dir, &name)?;
        let mut offset = 0usize;
        while offset < data.len() {
            let n = (data.len() - offset).min(BLOCK_SIZE);
            self.write_file_at(file, offset as u64, &data[offset..offset + n])?;
            offset += n;
        }
        self.hxblob_index
            .insert(HxblobIndexRecord {
                hash,
                object_id: file.object_id,
                size: data.len() as u64,
                merkle_root: hash,
                merkle_tree_lba: 0,
                flags: 0,
            })
            .map_err(|_| HxfsError::NoSpace)?;
        Ok(hash)
    }

    /// Stage F: read an Hxblob object back by content hash.
    #[cfg(feature = "hxblob")]
    pub fn get_blob(&mut self, hash: &BlobHash) -> FixedResult<alloc::vec::Vec<u8>> {
        let record = self
            .hxblob_index
            .lookup(hash)
            .map_err(|_| HxfsError::NotFound)?;
        let name = hex_encode(hash);
        let blob_dir = self.blob_shard_directory(hash)?;
        let file = self
            .open_child_file(blob_dir, &name)
            .map_err(|_| HxfsError::NotFound)?;
        let mut out = alloc::vec![0u8; record.size as usize];
        // Phase-2 packages: read chunk-wise (read_file_at) so a
        // package-sized blob does not materialise through the
        // whole-object read path; the chunked path is the one the
        // 16 MiB on-target probe exercises.
        let mut offset = 0usize;
        while offset < out.len() {
            let n = (out.len() - offset).min(BLOCK_SIZE);
            self.read_file_at(file, offset as u64, &mut out[offset..offset + n])?;
            offset += n;
        }
        Ok(out)
    }

    /// Content hash of `data` under the volume's blob-hash function.
    ///
    /// Exposed so callers that need the identity of a payload (for
    /// example to answer "this blob already exists" with a handle
    /// rather than an error) do not have to carry a second copy of
    /// the hash function and risk it drifting from this one.
    #[cfg(feature = "hxblob")]
    pub fn content_hash(&self, data: &[u8]) -> BlobHash {
        sha256(data)
    }

    /// Metadata for a stored blob: its object id and byte length.
    ///
    /// Lets a caller size a read without materialising the payload,
    /// which `get_blob` must do because it returns an owned `Vec`.
    /// The native BlobView protocol path needs the size before it can
    /// answer `GetInfo` or bound a ranged read.
    #[cfg(feature = "hxblob")]
    pub fn blob_info(&self, hash: &BlobHash) -> FixedResult<(u64, u64)> {
        let record = self
            .hxblob_index
            .lookup(hash)
            .map_err(|_| HxfsError::NotFound)?;
        Ok((record.object_id, record.size))
    }

    /// Read a byte range of a blob into `out`, returning the number of
    /// bytes copied (short at end-of-blob, zero past the end).
    ///
    /// This is the read path behind a BlobView handle. It deliberately
    /// does not go through `get_blob`: a package-sized blob would be
    /// copied into a heap `Vec` on every request, which on an 18 MiB
    /// user heap is how the service dies serving a large package.
    #[cfg(feature = "hxblob")]
    pub fn read_blob_at(
        &mut self,
        hash: &BlobHash,
        offset: u64,
        out: &mut [u8],
    ) -> FixedResult<usize> {
        let record = self
            .hxblob_index
            .lookup(hash)
            .map_err(|_| HxfsError::NotFound)?;
        if offset >= record.size {
            return Ok(0);
        }
        let name = hex_encode(hash);
        let blob_dir = self.blob_shard_directory(hash)?;
        let file = self
            .open_child_file(blob_dir, &name)
            .map_err(|_| HxfsError::NotFound)?;
        let remaining = record.size - offset;
        let count = out.len().min(remaining as usize);
        let mut copied = 0usize;
        while copied < count {
            let chunk = (count - copied).min(BLOCK_SIZE);
            let n = self.read_file_at(
                file,
                offset + copied as u64,
                &mut out[copied..copied + chunk],
            )?;
            if n == 0 {
                break;
            }
            copied += n;
        }
        Ok(copied)
    }

    /// Verify a blob against its content hash by re-reading it.
    ///
    /// Hxblob objects are content-addressed, so the hash is not just a
    /// name: it is a checksum the volume promises. Re-hashing on
    /// demand is what turns "the extent decrypted" into "these are the
    /// bytes that were stored". Used by the native open path and by
    /// scrub.
    #[cfg(feature = "hxblob")]
    pub fn verify_blob(&mut self, hash: &BlobHash) -> FixedResult<bool> {
        use sha2::{Digest, Sha256};
        let (_, size) = self.blob_info(hash)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; BLOCK_SIZE];
        let mut offset = 0u64;
        while offset < size {
            let want = ((size - offset) as usize).min(BLOCK_SIZE);
            let n = self.read_blob_at(hash, offset, &mut buf[..want])?;
            if n == 0 {
                return Ok(false);
            }
            hasher.update(&buf[..n]);
            offset += n as u64;
        }
        let digest = hasher.finalize();
        Ok(digest.as_slice() == hash.as_slice())
    }

    /// Stage F: list all Hxblob content hashes.
    #[cfg(feature = "hxblob")]
    pub fn list_blobs(&self) -> alloc::vec::Vec<BlobHash> {
        let mut out = alloc::vec::Vec::new();
        for record in self.hxblob_index.records() {
            if let Some(record) = record {
                out.push(record.hash);
            }
        }
        out
    }

    /// Stage F: number of stored blobs.
    #[cfg(feature = "hxblob")]
    pub fn blob_count(&self) -> usize {
        self.hxblob_index.record_count()
    }

    /// Stage F: serialize the Hxblob index tree into one metadata
    /// block. Wire layout: `count(4)` then `count` records of 92
    /// bytes (`hash(32) + object_id(8) + size(8) + merkle_root(32)
    /// + merkle_tree_lba(8) + flags(4)`); one block holds 44
    /// records (bounded by MAX_HXBLOBS = 32).
    #[cfg(feature = "hxblob")]
    fn build_hxblob_index_block(
        &self,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        // Phase-2 packages: a large Hxblob index becomes a two-level
        // tree (root + leaves) with the same shape as the other
        // multi-block trees; small indexes stay single-block.
        let records: alloc::vec::Vec<HxblobIndexRecord> = self
            .hxblob_index
            .records()
            .iter()
            .filter_map(|record| *record)
            .collect();
        let count = records.len();
        if count > HXBLOB_LEAF_RECORDS {
            return self.build_hxblob_index_tree(records, lba);
        }
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        for record in &records {
            let offset = 4 + written * 92;
            if offset + 92 > payload.len() {
                return Err(HxfsError::NoSpace);
            }
            payload[offset..offset + 32].copy_from_slice(&record.hash);
            payload[offset + 32..offset + 40].copy_from_slice(&record.object_id.to_le_bytes());
            payload[offset + 40..offset + 48].copy_from_slice(&record.size.to_le_bytes());
            payload[offset + 48..offset + 80].copy_from_slice(&record.merkle_root);
            payload[offset + 80..offset + 88]
                .copy_from_slice(&record.merkle_tree_lba.to_le_bytes());
            payload[offset + 88..offset + 92].copy_from_slice(&record.flags.to_le_bytes());
            written += 1;
        }
        let args = self.encryption_args();
        let block = make_metadata_block_for_volume(
            BLOCK_TYPE_HXBLOB_INDEX_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..4 + written * 92],
            args.0,
            args.1,
            args.2,
        )?;
        Ok((block, alloc::vec::Vec::new()))
    }

    /// Phase-2 packages: build a two-level Hxblob index tree
    /// (root + leaves). Leaves are returned (not written); the
    /// publisher places them after the root.
    #[cfg(feature = "hxblob")]
    fn build_hxblob_index_tree(
        &self,
        records: alloc::vec::Vec<HxblobIndexRecord>,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        let count = records.len();
        let leaf_count = count.div_ceil(HXBLOB_LEAF_RECORDS);
        let mut root_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        root_payload[0..4].copy_from_slice(&HXBLOB_TREE_ROOT_MAGIC.to_le_bytes());
        root_payload[4..8].copy_from_slice(&HXBLOB_TREE_ROOT_VERSION.to_le_bytes());
        root_payload[8..12].copy_from_slice(&(leaf_count as u32).to_le_bytes());
        let mut leaf_index = 0usize;
        let mut leaf_lba = lba + 1;
        while leaf_index < leaf_count {
            root_payload[16 + leaf_index * 8..16 + leaf_index * 8 + 8]
                .copy_from_slice(&leaf_lba.to_le_bytes());
            leaf_lba += 1;
            leaf_index += 1;
        }
        let args = self.encryption_args();
        let root = make_metadata_block_for_volume(
            BLOCK_TYPE_HXBLOB_INDEX_TREE_ROOT,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &root_payload[..16 + leaf_count * 8],
            args.0,
            args.1,
            args.2,
        )?;
        let mut leaves: alloc::vec::Vec<[u8; BLOCK_SIZE]> =
            alloc::vec::Vec::with_capacity(leaf_count);
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let mut record_index = 0usize;
        leaf_lba = lba + 1;
        for record in &records {
            let within = record_index % HXBLOB_LEAF_RECORDS;
            if within == 0 {
                payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
                // The leaf records its own record count, like the
                // single-block index: min(44, remaining records).
                let this_leaf_count = (records.len() - record_index).min(HXBLOB_LEAF_RECORDS);
                payload[0..4].copy_from_slice(&(this_leaf_count as u32).to_le_bytes());
            }
            let offset = 4 + within * 92;
            payload[offset..offset + 32].copy_from_slice(&record.hash);
            payload[offset + 32..offset + 40].copy_from_slice(&record.object_id.to_le_bytes());
            payload[offset + 40..offset + 48].copy_from_slice(&record.size.to_le_bytes());
            payload[offset + 48..offset + 80].copy_from_slice(&record.merkle_root);
            payload[offset + 80..offset + 88]
                .copy_from_slice(&record.merkle_tree_lba.to_le_bytes());
            payload[offset + 88..offset + 92].copy_from_slice(&record.flags.to_le_bytes());
            record_index += 1;
            if within == HXBLOB_LEAF_RECORDS - 1 || record_index == count {
                let leaf_count_records = record_index.min(HXBLOB_LEAF_RECORDS);
                leaves.push(make_metadata_block_for_volume(
                    BLOCK_TYPE_HXBLOB_INDEX_TREE_LEAF,
                    self.system_volume.root_object_id,
                    MetadataBlockSite {
                        lba: leaf_lba,
                        generation: self.metadata_generation(),
                    },
                    &payload[..4 + leaf_count_records * 92],
                    args.0,
                    args.1,
                    args.2,
                )?);
                leaf_lba += 1;
            }
        }
        Ok((root, leaves))
    }

    /// Stage F: serialize the (empty for the MVP) Merkle block.
    #[cfg(feature = "hxblob")]
    fn build_hxblob_merkle_block(&self, lba: u64) -> FixedResult<[u8; BLOCK_SIZE]> {
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = self.hxblob_merkle.record_count();
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let args = self.encryption_args();
        make_metadata_block_for_volume(
            BLOCK_TYPE_HXBLOB_MERKLE_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..4],
            args.0,
            args.1,
            args.2,
        )
    }

    /// Stage E (Phase-2): set a per-Job physical/object quota. The
    /// job is identified by an opaque u64; the record is keyed in
    /// the quota tree by a synthetic UUID (job id in the first 8
    /// bytes). `0` limits mean unlimited.
    pub fn set_job_quota(
        &mut self,
        job_id: u64,
        physical_bytes: u64,
        objects: u64,
    ) -> FixedResult<()> {
        let uuid = job_uuid(job_id);
        let current = self.quota_tree.get(uuid).ok();
        self.quota_tree
            .upsert(QuotaRecord {
                volume_uuid: uuid,
                physical_limit_bytes: physical_bytes,
                physical_used_bytes: current.map_or(0, |r| r.physical_used_bytes),
                object_limit: objects,
                object_count: current.map_or(0, |r| r.object_count),
            })
            .map_err(|_| HxfsError::NoSpace)?;
        Ok(())
    }

    /// Stage E (Phase-2): select the job whose quota is enforced on
    /// subsequent writes.
    pub fn set_active_job(&mut self, job_id: Option<u64>) {
        self.active_job = job_id;
    }

    /// Stage E (Phase-2): current usage of a job quota.
    pub fn job_quota_usage(&self, job_id: u64) -> (u64, u64) {
        self.quota_tree
            .get(job_uuid(job_id))
            .map(|r| (r.physical_used_bytes, r.object_count))
            .unwrap_or((0, 0))
    }

    /// Stage E (Phase-2): enforce the active job's quota for a write
    /// of `delta_bytes` / `delta_objects`.
    fn check_job_quota(&mut self, delta_bytes: u64, delta_objects: u64) -> FixedResult<()> {
        let Some(job_id) = self.active_job else {
            return Ok(());
        };
        let uuid = job_uuid(job_id);
        let mut record = self
            .quota_tree
            .get(uuid)
            .map_err(|_| HxfsError::QuotaExceeded)?;
        if record.physical_limit_bytes != 0
            && record.physical_used_bytes.saturating_add(delta_bytes) > record.physical_limit_bytes
        {
            return Err(HxfsError::QuotaExceeded);
        }
        if record.object_limit != 0
            && record.object_count.saturating_add(delta_objects) > record.object_limit
        {
            return Err(HxfsError::QuotaExceeded);
        }
        record.physical_used_bytes = record.physical_used_bytes.saturating_add(delta_bytes);
        record.object_count = record.object_count.saturating_add(delta_objects);
        self.quota_tree
            .upsert(record)
            .map_err(|_| HxfsError::NoSpace)?;
        Ok(())
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
        // Stage E: range read for files of any size. Only the
        // extents overlapping [offset, offset+count) are copied,
        // so large files can be read in bounded chunks without
        // materialising the whole object.
        out[..count].fill(0);
        let start = offset;
        let end = offset
            .checked_add(count as u64)
            .ok_or(HxfsError::OutOfRange)?;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id != file.object_id {
                    index += 1;
                    continue;
                }
                let logical = if extent.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                    1
                } else {
                    u64::from(extent.extent.block_count)
                };
                let extent_start = extent.extent.logical_block * BLOCK_SIZE_U64;
                let extent_end = extent_start
                    .checked_add(logical * BLOCK_SIZE_U64)
                    .ok_or(HxfsError::OutOfRange)?;
                if extent_end <= start || extent_start >= end {
                    index += 1;
                    continue;
                }
                let copy_from = start.max(extent_start);
                let copy_to = end.min(extent_end);

                // Walk the window one logical block at a time.
                //
                // An extent may span many blocks: `write_file_data`
                // in `writer.rs` emits a single extent with
                // `block_count = N` for any file above 4 KiB, and
                // that is what `tools/hxfs-seed` and `mkhxfs.py`
                // write. The previous code assumed the window fell
                // inside one block and copied `window` bytes out of
                // a 4 KiB buffer, so a read crossing a block
                // boundary in a multi-block extent panicked with
                // "range end index 8192 out of range for slice of
                // length 4096" — reachable from an ordinary
                // unprivileged `read_at`, which takes the whole
                // filesystem service down with it.
                let mut cursor = copy_from;
                while cursor < copy_to {
                    let block_offset = (cursor - extent_start) / BLOCK_SIZE_U64;
                    let within = ((cursor - extent_start) % BLOCK_SIZE_U64) as usize;
                    // Bytes left in this block, clipped to the window.
                    let chunk =
                        core::cmp::min((BLOCK_SIZE - within) as u64, copy_to - cursor) as usize;
                    let out_off = (cursor - start) as usize;
                    // Defensive bound: `out` is `count` bytes and the
                    // window was clipped to `end`, so this holds, but
                    // a slice index is not the place to find out.
                    if out_off
                        .checked_add(chunk)
                        .is_none_or(|end_index| end_index > out.len())
                    {
                        return Err(HxfsError::OutOfRange);
                    }

                    let mut block = [0u8; BLOCK_SIZE];
                    self.read_extent_block(
                        extent.extent,
                        extent.compression,
                        block_offset,
                        &mut block,
                    )?;
                    out[out_off..out_off + chunk].copy_from_slice(&block[within..within + chunk]);
                    cursor += chunk as u64;
                }
            }
            index += 1;
        }
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

        // Release the extents this write replaces BEFORE charging the
        // quota. A full rewrite (`offset == 0`) drops every existing
        // extent of the file, so those blocks must not be counted as
        // still-in-use when deciding whether the new write fits;
        // charging first made an in-place rewrite of a file that
        // exactly filled its quota fail even though usage would not
        // change. Validation that can reject the write already
        // happened above, so dropping the extents here does not
        // discard data for a call that then fails.
        if offset == 0 {
            let released = self.clear_extents(file.object_id);
            self.release_job_bytes(released);
        } else if offset != object.size || !offset.is_multiple_of(BLOCK_SIZE_U64) {
            return Err(HxfsError::Unsupported);
        }

        self.check_volume_quota(delta_bytes, 0)?;
        // Stage E (Phase-2): per-Job quota enforcement.
        self.check_job_quota(delta_bytes, 0)?;

        if !data.is_empty() {
            let logical_block = offset / BLOCK_SIZE_U64;
            // Stage B.3 completion: the write path resolves the
            // object's compression policy and stores the resulting
            // descriptor (or `None` for a plain extent) with the
            // extent record; the v2 serialization at publish time
            // carries it and sets `EXTENT_FLAG_COMPRESSED`. An
            // incompressible full block on an encrypted volume is
            // stored as a two-slot extent
            // (`EXTENT_FLAG_MULTI_SLOT`, `block_count = 2`).
            let (physical_block, generation, kind) = self.write_data_blocks(data, object)?;
            let (flags, block_count, compression) = match kind {
                ExtentWriteKind::Plain => (0, 1, None),
                ExtentWriteKind::Compressed(meta) => (EXTENT_FLAG_COMPRESSED, 1, Some(meta)),
                ExtentWriteKind::MultiSlot => (EXTENT_FLAG_MULTI_SLOT, 2, None),
            };
            self.insert_extent(FixedExtent {
                object_id: file.object_id,
                extent: ExtentRecord {
                    logical_block,
                    physical_block,
                    block_count,
                    flags,
                    generation,
                },
                compression,
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
    ///
    /// This counts the blocks **currently referenced by live
    /// extents**, not the high-water mark of the append pointer.
    ///
    /// It used to be derived from `next_lba`, which only ever grows:
    /// an in-place rewrite calls `clear_extents` and then appends the
    /// new blocks at fresh LBAs, so every overwrite permanently
    /// inflated the reported usage even though the file's size never
    /// changed. Rewriting one 4 KiB file 32 times reported 168 KiB of
    /// usage for 4 KiB of data, and a volume with a quota eventually
    /// refused writes it had room for.
    ///
    /// Counting live extents makes the figure reflect what the volume
    /// actually holds. Space behind dropped extents is not yet
    /// reclaimed on the media (the MVP appends rather than reusing
    /// LBAs), but it is no longer charged to the quota, which is the
    /// user-visible contract.
    pub fn committed_physical_bytes(&self) -> u64 {
        let mut blocks = 0u64;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(entry) = self.extents[index] {
                // Hole extents describe unwritten logical range and
                // occupy no media.
                if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    let count = if entry.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                        1
                    } else {
                        u64::from(entry.extent.block_count)
                    };
                    blocks = blocks.saturating_add(count);
                }
            }
            index += 1;
        }
        blocks.saturating_mul(BLOCK_SIZE_U64)
    }

    /// Truncate or sparsely extend a file.
    pub fn truncate_file(&mut self, file: FileHandle, new_size: u64) -> FixedResult<FileHandle> {
        let object = self.object_mut(file.object_id)?;
        if object.descriptor.object_type != OBJECT_TYPE_FILE {
            return Err(HxfsError::WrongType);
        }
        object.descriptor.size = new_size;

        // Drop extents that now lie entirely past the new end of
        // file, and re-derive `record_count`.
        //
        // Previously this function touched only `descriptor.size`.
        // The orphaned extents stayed in the table, so they kept
        // being charged to the volume quota, kept being visited by
        // `fsck`/`scrub`, and left `record_count` disagreeing with
        // the number of extents `load_extents` would find after a
        // remount — the count the reader trusts to size its walk.
        let mut released_blocks = 0u64;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(entry) = self.extents[index] {
                if entry.object_id == file.object_id {
                    let logical = if entry.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                        1
                    } else {
                        u64::from(entry.extent.block_count)
                    };
                    let extent_start = entry.extent.logical_block * BLOCK_SIZE_U64;
                    // Keep any extent that still holds a live byte.
                    // A partially truncated extent is retained whole:
                    // the tail bytes are unreachable through
                    // `descriptor.size`, and splitting an extent here
                    // would need a fresh allocation on a path that
                    // must not fail.
                    if extent_start >= new_size && logical > 0 {
                        if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                            released_blocks = released_blocks.saturating_add(logical);
                        }
                        self.extents[index] = None;
                    }
                }
            }
            index += 1;
        }

        // Truncation frees media, so it must credit the per-Job
        // quota just like a delete or a full rewrite does.
        self.release_job_bytes(released_blocks.saturating_mul(BLOCK_SIZE_U64));

        self.update_file_record_count(file.object_id)?;
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
        let released = self.clear_extents(object_id);
        self.release_job_bytes(released);
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
        // The checkpoint is copy-on-write: the whole metadata region
        // (object trees, the volume/allocation/refcount/backref/quota
        // trees, the Hxblob blocks, the checkpoint and its journal) is
        // rebuilt at `next_lba` and the old copy is abandoned. Left
        // alone that marches upwards forever, which is the same
        // `NoSpace`-on-an-empty-volume defect as the data-block leak,
        // just with a bigger step. Remember where the outgoing region
        // lives so it can be recycled once it stops being the backup.
        let retired_metadata_start = self.metadata_region_start();
        let retired_metadata_end = self.next_lba.max(self.superblock.journal_end_lba);
        let sequence = self.superblock.sequence_number.saturating_add(1).max(1);
        let live_objects = self.live_object_count();
        let target_count = live_objects.checked_add(7).ok_or(HxfsError::NoSpace)?;
        if target_count == 0 {
            return Err(HxfsError::NoSpace);
        }
        let record_count = u32::try_from(target_count + 1).map_err(|_| HxfsError::NoSpace)?;
        // Stage E: the target area must account for extent-tree
        // leaves so the journal area starts after ALL target blocks.
        let mut extra_total = 0usize;
        let mut object_slot = 0usize;
        while object_slot < self.objects.len() {
            if let Some(object) = self.objects[object_slot] {
                if matches!(
                    object.descriptor.object_type,
                    OBJECT_TYPE_FILE | OBJECT_TYPE_SYMLINK
                ) {
                    extra_total += self.extent_blocks_for_object(object.descriptor.object_id) - 1;
                }
            }
            object_slot += 1;
        }
        // The allocation tree may also span multiple blocks; its
        // leaf blocks are part of the target area and must not
        // overlap the journal area.
        let mut alloc_count = 0usize;
        let mut alloc_slot = 0usize;
        while alloc_slot < self.extents.len() {
            if let Some(extent) = self.extents[alloc_slot] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    alloc_count += 1;
                }
            }
            alloc_slot += 1;
        }
        let alloc_leaf_blocks = if alloc_count > ALLOC_LEAF_RECORDS {
            alloc_count.div_ceil(ALLOC_LEAF_RECORDS)
        } else {
            0
        };
        let refcount_leaf_blocks = if alloc_count > REFCOUNT_LEAF_RECORDS {
            alloc_count.div_ceil(REFCOUNT_LEAF_RECORDS)
        } else {
            0
        };
        let backref_leaf_blocks = if alloc_count > BACKREF_LEAF_RECORDS {
            alloc_count.div_ceil(BACKREF_LEAF_RECORDS)
        } else {
            0
        };
        let extra_total =
            (extra_total + alloc_leaf_blocks + refcount_leaf_blocks + backref_leaf_blocks) as u64;
        let hxblob_count = {
            #[cfg(feature = "hxblob")]
            {
                self.hxblob_index.record_count()
            }
            #[cfg(not(feature = "hxblob"))]
            {
                0usize
            }
        };
        let hxblob_leaf_blocks = if hxblob_count > HXBLOB_LEAF_RECORDS {
            hxblob_count.div_ceil(HXBLOB_LEAF_RECORDS)
        } else {
            0
        };

        // Place the new metadata region in reclaimed space when a
        // large enough run exists, and only extend the volume when it
        // does not. Anchoring it at `next_lba` unconditionally is what
        // made the high-water mark climb forever even after the data
        // blocks themselves were being recycled: the metadata region
        // is rewritten wholesale on every checkpoint and dwarfs the
        // file data on a churning volume.
        let metadata_span = live_objects as u64
            + extra_total
            + 5
            + u64::from(record_count) * 2
            + hxblob_leaf_blocks as u64;
        let target_start_lba = self
            .take_free_blocks(metadata_span)
            .unwrap_or(self.next_lba);
        let object_table_lba = target_start_lba + live_objects as u64 + extra_total;
        let volume_table_lba = object_table_lba + 1;
        let allocation_tree_lba = volume_table_lba + 1;
        // Each multi-block tree's leaves live immediately after its
        // root; everything after them must be shifted.
        let alloc_leaves_end = allocation_tree_lba + 1 + alloc_leaf_blocks as u64;
        let refcount_tree_lba = alloc_leaves_end;
        let refcount_leaves_end = refcount_tree_lba + 1 + refcount_leaf_blocks as u64;
        let backref_tree_lba = refcount_leaves_end;
        let backref_leaves_end = backref_tree_lba + 1 + backref_leaf_blocks as u64;
        let quota_tree_lba = backref_leaves_end;
        // Stage F: the Hxblob index + Merkle blocks live between
        // the quota tree and the checkpoint.
        // Phase-2 packages: the Hxblob index may span multiple
        // blocks (root + leaves); reserve space for the leaves
        // between the index root and the Merkle block.
        let hxblob_index_tree_lba = quota_tree_lba + 1;
        let hxblob_leaves_end = hxblob_index_tree_lba + 1 + hxblob_leaf_blocks as u64;
        let hxblob_merkle_tree_lba = hxblob_leaves_end;
        let checkpoint_lba = hxblob_merkle_tree_lba + 1;
        let journal_start_lba = checkpoint_lba + 1;
        let journal_end_lba = journal_start_lba + u64::from(record_count) * 2;
        self.quota_allows_media_blocks(journal_end_lba)?;
        let mut plans = [const { None }; MAX_OBJECTS];

        let mut record_index = 0u32;
        let mut block_offset = 0u64;
        let mut object_slot = 0usize;
        while object_slot < self.objects.len() {
            if let Some(object) = self.objects[object_slot] {
                // `block_offset` is the per-block position of the
                // object's root inside the target area (1 + leaves
                // per object); `record_index` is the journal index.
                let tree_lba = target_start_lba + block_offset;
                let (block, leaves) = self.build_object_tree_block(object.descriptor, tree_lba)?;
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
                // Write the tree leaves plain after the root (they
                // are covered by the root's journal record).
                for (leaf_lba, leaf) in (tree_lba + 1..).zip(leaves.iter()) {
                    self.store.write_blocks(leaf_lba, 1, leaf)?;
                }
                block_offset += 1 + leaves.len() as u64;
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

        let (allocation_block, allocation_leaves) =
            self.build_allocation_tree_block(allocation_tree_lba)?;
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
        for (alloc_leaf_lba, leaf) in (allocation_tree_lba + 1..).zip(allocation_leaves.iter()) {
            self.store.write_blocks(alloc_leaf_lba, 1, leaf)?;
        }
        record_index += 1;

        let (refcount_block, refcount_leaves) =
            self.build_refcount_tree_block(refcount_tree_lba)?;
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
        for (refcount_leaf_lba, leaf) in (refcount_tree_lba + 1..).zip(refcount_leaves.iter()) {
            self.store.write_blocks(refcount_leaf_lba, 1, leaf)?;
        }
        record_index += 1;

        let (backref_block, backref_leaves) =
            self.build_backref_tree_block(backref_tree_lba, sequence)?;
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
        for (backref_leaf_lba, leaf) in (backref_tree_lba + 1..).zip(backref_leaves.iter()) {
            self.store.write_blocks(backref_leaf_lba, 1, leaf)?;
        }
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

        // Stage F: write the Hxblob index + Merkle blocks (they are
        // part of the target area and covered by the journal).
        #[cfg(feature = "hxblob")]
        let (hxblob_index_block, hxblob_index_leaves) =
            self.build_hxblob_index_block(hxblob_index_tree_lba)?;
        #[cfg(feature = "hxblob")]
        let hxblob_merkle_block = self.build_hxblob_merkle_block(hxblob_merkle_tree_lba)?;
        #[cfg(feature = "hxblob")]
        {
            self.write_journaled_target(
                hxblob_index_tree_lba,
                &hxblob_index_block,
                sequence,
                record_index,
                record_count,
                journal_start_lba,
                checkpoint_lba,
                0,
            )?;
            // Write the index leaves plain after the root.
            for (leaf_lba, leaf) in (hxblob_index_tree_lba + 1..).zip(hxblob_index_leaves.iter()) {
                self.store.write_blocks(leaf_lba, 1, leaf)?;
            }
            record_index += 1;
            self.write_journaled_target(
                hxblob_merkle_tree_lba,
                &hxblob_merkle_block,
                sequence,
                record_index,
                record_count,
                journal_start_lba,
                checkpoint_lba,
                0,
            )?;
            record_index += 1;
        }
        #[cfg(not(feature = "hxblob"))]
        let (hxblob_index_tree_lba, hxblob_merkle_tree_lba) = (0u64, 0u64);

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
            hxblob_index_tree_lba,
            hxblob_merkle_tree_lba,
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
        // The checkpoint that dropped the last reference to these
        // blocks is now durable, so they are safe to hand out again
        // and any new tenancy will carry a higher sequence number.
        // This also releases the metadata region retired by the
        // *previous* checkpoint, which has just stopped being the
        // backup.
        self.promote_pending_free();
        // Retire the region this checkpoint superseded. It is still
        // referenced by `backup_checkpoint_lba`, so it must survive
        // exactly one more checkpoint: quarantining it here means it
        // is promoted by the next `publish_checkpoint`, which is
        // precisely when it stops being the rollback target. The
        // one-checkpoint retention the format already guarantees is
        // therefore unchanged.
        if retired_metadata_end > retired_metadata_start {
            self.free_retired_metadata(retired_metadata_start, retired_metadata_end);
        }
        self.dirty = false;
        Ok(sequence)
    }

    fn load_object_tree(&mut self) -> FixedResult<()> {
        let mut block = [0u8; BLOCK_SIZE];
        let header = self.read_mounted_metadata_block(
            self.system_volume.object_table_lba,
            BLOCK_TYPE_OBJECT_TABLE,
            1,
            &mut block,
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
        let header = self.read_mounted_metadata_block(
            object.tree_lba,
            BLOCK_TYPE_DIRECTORY,
            object.object_id,
            &mut block,
        )?;
        let owner = read_u64(&block, header.header_bytes as usize)?;
        let count = read_u32(&block, header.header_bytes as usize + 8)?;
        if owner != object.object_id || count != object.record_count {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0u32;
        while index < count {
            let offset = header.header_bytes as usize + 16 + index as usize * DIR_RECORD_BYTES;
            let mut scratch = [0u8; MAX_NAME_BYTES];
            let entry =
                self.parse_mounted_dirent(&block, offset, object.object_id, &mut scratch)?;
            self.insert_dir_entry(object.object_id, entry.object_id, entry.name.as_bytes())?;
            index += 1;
        }
        Ok(())
    }

    /// Parse one dirent record at mount time, decrypting the name
    /// body when the volume is encrypted (Stage B.2 completion:
    /// the writer's mount path must mirror the reader, otherwise
    /// mounting an encrypted volume whose dirent names were
    /// encrypted at publish fails with `BadName`). The plaintext
    /// name lands in `scratch` and the returned entry borrows it.
    fn parse_mounted_dirent<'a>(
        &self,
        block: &[u8],
        offset: usize,
        parent_object_id: u64,
        scratch: &'a mut [u8; MAX_NAME_BYTES],
    ) -> FixedResult<crate::DirectoryEntry<'a>> {
        // The writer mounts volumes it is about to publish, whose
        // dirent names may still be plaintext (the boot image
        // produced by `synthetic_image` / `hxfs-seed`); after
        // publish every name on an encrypted volume is encrypted.
        // Encrypted bodies are always at least
        // `ENCRYPTED_DIRENT_MIN_BODY` (28) bytes long (nonce +
        // tag overhead), so the body length discriminates the two
        // states; a plaintext name at or above the threshold is
        // not representable on an encrypted volume (B.2 format
        // invariant).
        #[cfg(feature = "crypto-aes-gcm")]
        if let Some(key) = self.metadata_key.as_ref() {
            let body_len = u16::from_le_bytes(
                block
                    .get(offset + 8..offset + 10)
                    .ok_or(HxfsError::BadTree)?
                    .try_into()
                    .map_err(|_| HxfsError::BadTree)?,
            ) as usize;
            if body_len >= crate::encrypted_metadata::ENCRYPTED_DIRENT_MIN_BODY {
                return crate::parse_dir_record_decrypt(
                    block,
                    offset,
                    parent_object_id,
                    key,
                    scratch,
                );
            }
        }
        #[cfg(not(feature = "crypto-aes-gcm"))]
        {
            let _ = parent_object_id;
        }
        let entry = parse_dir_record(block, offset)?;
        let name_bytes = entry.name.as_bytes();
        if scratch.len() < name_bytes.len() {
            return Err(HxfsError::BufferTooSmall);
        }
        scratch[..name_bytes.len()].copy_from_slice(name_bytes);
        let name_str =
            core::str::from_utf8(&scratch[..name_bytes.len()]).map_err(|_| HxfsError::BadName)?;
        Ok(crate::DirectoryEntry {
            object_id: entry.object_id,
            name: name_str,
        })
    }

    fn load_extents(&mut self, object: ObjectDescriptor) -> FixedResult<()> {
        if object.record_count == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        // Stage E: try the single-block extent table first; a tree
        // object's root fails validation with BadBlock.
        let single = match self.read_mounted_metadata_block_any_type(
            object.tree_lba,
            BLOCK_TYPE_EXTENT_TABLE,
            BLOCK_TYPE_EXTENT_TABLE_V2,
            object.object_id,
            &mut block,
        ) {
            Ok((header, block_type)) => Some((header, block_type)),
            Err(HxfsError::BadBlock) => None,
            Err(error) => return Err(error),
        };
        let leaves = if let Some((header, _block_type)) = single {
            let owner = read_u64(&block, header.header_bytes as usize)?;
            if owner != object.object_id {
                return Err(HxfsError::BadTree);
            }
            None
        } else {
            let header = self.read_mounted_metadata_block(
                object.tree_lba,
                BLOCK_TYPE_EXTENT_TREE_ROOT,
                object.object_id,
                &mut block,
            )?;
            // The root's owner is the header's owner_id (validated
            // above); the payload starts with magic/version/count.
            Some(parse_extent_tree_root(
                &block[header.header_bytes as usize..],
            )?)
        };
        let record_bytes = match single {
            Some((_, BLOCK_TYPE_EXTENT_TABLE_V2)) | None => EXTENT_RECORD_BYTES_V2,
            _ => EXTENT_RECORD_BYTES,
        };
        let count = object.record_count;
        let mut index = 0u32;
        let mut leaf_buf = [0u8; BLOCK_SIZE];
        while index < count {
            let (block_ref, offset) = if let Some((header, _block_type)) = single {
                (
                    block.as_slice(),
                    header.header_bytes as usize + 16 + index as usize * record_bytes,
                )
            } else {
                let leaf_index = (index as usize) / EXTENT_LEAF_RECORDS;
                let within = (index as usize) % EXTENT_LEAF_RECORDS;
                let leaves = leaves.as_ref().ok_or(HxfsError::BadTree)?;
                if leaf_index >= leaves.len() {
                    return Err(HxfsError::BadTree);
                }
                let _ = self.read_mounted_metadata_block(
                    leaves[leaf_index],
                    BLOCK_TYPE_EXTENT_TREE_LEAF,
                    object.object_id,
                    &mut leaf_buf,
                )?;
                (
                    leaf_buf.as_slice(),
                    HEADER_BYTES + within * EXTENT_RECORD_BYTES_V2,
                )
            };
            let (extent, compression) = if record_bytes == EXTENT_RECORD_BYTES_V2 {
                parse_extent_record_v2(block_ref, offset)?
            } else {
                (parse_extent_record(block_ref, offset)?, None)
            };
            self.insert_extent(FixedExtent {
                object_id: object.object_id,
                extent,
                compression,
            })?;
            index += 1;
        }
        Ok(())
    }

    /// Stage F: load the Hxblob index from the checkpoint block at
    /// mount time so `get_blob`/`list_blobs` work after a remount.
    #[cfg(feature = "hxblob")]
    fn load_hxblob_index(&mut self) -> FixedResult<()> {
        let lba = self.checkpoint.hxblob_index_tree_lba;
        if lba == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        // Phase-2 packages: the index may be a single block
        // (BLOCK_TYPE_HXBLOB_INDEX_TREE) or a two-level tree
        // (BLOCK_TYPE_HXBLOB_INDEX_TREE_ROOT + leaves). Try the
        // root first; a single-block index fails validation with
        // BadBlock.
        let header = match self.read_mounted_metadata_block(
            lba,
            BLOCK_TYPE_HXBLOB_INDEX_TREE_ROOT,
            self.system_volume.root_object_id,
            &mut block,
        ) {
            Ok(header) => header,
            Err(HxfsError::BadBlock) => {
                let mut single = [0u8; BLOCK_SIZE];
                let header = self.read_mounted_metadata_block(
                    lba,
                    BLOCK_TYPE_HXBLOB_INDEX_TREE,
                    self.system_volume.root_object_id,
                    &mut single,
                )?;
                let base = header.header_bytes as usize;
                let count = read_u32(&single, base)? as usize;
                if count > MAX_HXBLOBS {
                    return Err(HxfsError::BadTree);
                }
                let mut index = 0usize;
                while index < count {
                    let offset = base + 4 + index * 92;
                    self.insert_hxblob_record(&single, offset)?;
                    index += 1;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        // Multi-block root: collect the leaf LBAs and load each leaf.
        let base = header.header_bytes as usize;
        let leaf_count = read_u32(&block, base + 8)? as usize;
        if leaf_count == 0 || leaf_count > MAX_HXBLOBS {
            return Err(HxfsError::BadTree);
        }
        let mut leaf_index = 0usize;
        let mut loaded = 0usize;
        while leaf_index < leaf_count {
            let leaf_lba = read_u64(&block, base + 16 + leaf_index * 8)?;
            let mut leaf = [0u8; BLOCK_SIZE];
            let leaf_header = self.read_mounted_metadata_block(
                leaf_lba,
                BLOCK_TYPE_HXBLOB_INDEX_TREE_LEAF,
                self.system_volume.root_object_id,
                &mut leaf,
            )?;
            let leaf_base = leaf_header.header_bytes as usize;
            let count = read_u32(&leaf, leaf_base)? as usize;
            if count > HXBLOB_LEAF_RECORDS {
                return Err(HxfsError::BadTree);
            }
            let mut index = 0usize;
            while index < count {
                let offset = leaf_base + 4 + index * 92;
                self.insert_hxblob_record(&leaf, offset)?;
                loaded += 1;
                index += 1;
            }
            leaf_index += 1;
        }
        if loaded != self.hxblob_index.record_count().min(loaded) && loaded == 0 && leaf_count > 0 {
            return Err(HxfsError::BadTree);
        }
        Ok(())
    }

    /// Insert one Hxblob index record parsed from `block` at
    /// `offset` (92-byte wire record).
    #[cfg(feature = "hxblob")]
    fn insert_hxblob_record(&mut self, block: &[u8], offset: usize) -> FixedResult<()> {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(block.get(offset..offset + 32).ok_or(HxfsError::BadTree)?);
        let object_id = read_u64(block, offset + 32)?;
        let size = read_u64(block, offset + 40)?;
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(
            block
                .get(offset + 48..offset + 80)
                .ok_or(HxfsError::BadTree)?,
        );
        let merkle_tree_lba = read_u64(block, offset + 80)?;
        let flags = read_u32(block, offset + 88)?;
        self.hxblob_index
            .insert(HxblobIndexRecord {
                hash,
                object_id,
                size,
                merkle_root,
                merkle_tree_lba,
                flags,
            })
            .map_err(|_| HxfsError::BadTree)
    }

    fn load_quota_tree(&mut self) -> FixedResult<()> {
        let lba = self.checkpoint.quota_tree_lba;
        if lba == 0 {
            return Ok(());
        }
        let mut block = [0u8; BLOCK_SIZE];
        let header = self.read_mounted_metadata_block(
            lba,
            BLOCK_TYPE_QUOTA_TREE,
            self.system_volume.root_object_id,
            &mut block,
        )?;
        let base = header.header_bytes as usize;
        let count = read_u32(&block, base)? as usize;
        if count > MAX_QUOTA_RECORDS {
            return Err(HxfsError::BadTree);
        }
        let mut index = 0usize;
        while index < count {
            let offset = base + 16 + index * 56;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(block.get(offset..offset + 16).ok_or(HxfsError::BadTree)?);
            let record = QuotaRecord {
                volume_uuid: uuid,
                physical_limit_bytes: read_u64(&block, offset + 16)?,
                physical_used_bytes: read_u64(&block, offset + 24)?,
                object_limit: read_u64(&block, offset + 32)?,
                object_count: read_u64(&block, offset + 40)?,
            };
            if uuid != self.system_volume.uuid {
                self.quota_tree
                    .upsert(record)
                    .map_err(|_| HxfsError::BadTree)?;
            }
            index += 1;
        }
        Ok(())
    }

    /// Read a metadata block at mount time, validating the header
    /// and decrypting the v6 payload in place when the volume is
    /// encrypted. Mirrors the reader's `read_metadata_block`; the
    /// writer's own mount paths use it so an encrypted volume can
    /// be mounted into mutable state (Stage B.1 completion).
    fn read_mounted_metadata_block(
        &mut self,
        lba: u64,
        block_type: u32,
        owner_id: u64,
        out: &mut [u8; BLOCK_SIZE],
    ) -> FixedResult<BlockHeader> {
        self.store.read_blocks(lba, 1, out)?;
        let header = parse_header(out)?;
        if header.block_type != block_type {
            return Err(HxfsError::BadBlock);
        }
        let header = validate_metadata_block(out, lba, block_type, owner_id)?;
        #[cfg(feature = "crypto-aes-gcm")]
        if crate::is_v6_encrypted_metadata(&header) {
            let key = self
                .metadata_key
                .as_ref()
                .ok_or(HxfsError::EncryptedPolicyInvalid)?;
            crate::encrypted_metadata::decrypt_metadata_block_in_place(
                out,
                &header,
                key,
                &self.superblock.instance_uuid,
            )
            .map_err(|_| HxfsError::BadChecksum)?;
        }
        Ok(header)
    }

    /// Like [`Self::read_mounted_metadata_block`], but accepts
    /// either of two block types and returns the matching one.
    /// Extent tables may be v1 ([`BLOCK_TYPE_EXTENT_TABLE`]) or v2
    /// ([`BLOCK_TYPE_EXTENT_TABLE_V2`]) depending on whether the
    /// object has compressed extents.
    fn read_mounted_metadata_block_any_type(
        &mut self,
        lba: u64,
        block_type_a: u32,
        block_type_b: u32,
        owner_id: u64,
        out: &mut [u8; BLOCK_SIZE],
    ) -> FixedResult<(BlockHeader, u32)> {
        self.store.read_blocks(lba, 1, out)?;
        let header = parse_header(out)?;
        if header.block_type != block_type_a && header.block_type != block_type_b {
            return Err(HxfsError::BadBlock);
        }
        let header = validate_metadata_block(out, lba, header.block_type, owner_id)?;
        #[cfg(feature = "crypto-aes-gcm")]
        if crate::is_v6_encrypted_metadata(&header) {
            let key = self
                .metadata_key
                .as_ref()
                .ok_or(HxfsError::EncryptedPolicyInvalid)?;
            crate::encrypted_metadata::decrypt_metadata_block_in_place(
                out,
                &header,
                key,
                &self.superblock.instance_uuid,
            )
            .map_err(|_| HxfsError::BadChecksum)?;
        }
        Ok((header, header.block_type))
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
        // Phase-2 (B): sorted insertion instead of insert-then-bubble.
        // The old path ran a full bubble sort on EVERY insert, making
        // a 4096-extent file O(n^2) per write and O(n^3) overall
        // (~68 billion compares) - the reason on-target files were
        // capped at 4 MiB. Inserting at the sorted position is O(n)
        // per write (shift at most one contiguous block of slots).
        let object_id = extent.object_id;
        let mut pos = self.extents.len();
        let mut free = self.extents.len();
        let mut index = 0usize;
        while index < self.extents.len() {
            match self.extents[index] {
                Some(e)
                    if e.object_id == object_id
                        && e.extent.logical_block > extent.extent.logical_block =>
                {
                    pos = index;
                    break;
                }
                Some(_) => {}
                None => {
                    if free == self.extents.len() {
                        free = index;
                    }
                }
            }
            index += 1;
        }
        // Find the last occupied slot.
        let mut last = self.extents.len();
        let mut i = self.extents.len();
        while i > 0 {
            i -= 1;
            if self.extents[i].is_some() {
                last = i;
                break;
            }
        }
        if last == self.extents.len() {
            // Empty array.
            self.extents[0] = Some(extent);
        } else if pos == self.extents.len() {
            // New extent is the largest for its object: place it in
            // the first free slot (must exist).
            if free == self.extents.len() {
                return Err(HxfsError::NoSpace);
            }
            self.extents[free] = Some(extent);
        } else {
            // Insert before `pos`, shifting [pos..=last] right by one.
            if last + 1 >= self.extents.len() {
                return Err(HxfsError::NoSpace);
            }
            let mut j = last + 1;
            while j > pos {
                self.extents[j] = self.extents[j - 1];
                j -= 1;
            }
            self.extents[pos] = Some(extent);
        }
        self.update_file_record_count(object_id)?;
        Ok(())
    }

    /// Drop every extent of `object_id`, returning the number of
    /// physical bytes those extents occupied, and quarantine the
    /// physical blocks for reuse after the next checkpoint.
    ///
    /// The caller uses the return value to credit the per-Job quota,
    /// which — unlike the volume counter — cannot be re-derived from
    /// the extent table because extents do not record which job
    /// wrote them.
    fn clear_extents(&mut self, object_id: u64) -> u64 {
        let mut blocks = 0u64;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(entry) = self.extents[index] {
                if entry.object_id == object_id {
                    if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                        let count = if entry.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                            1
                        } else {
                            u64::from(entry.extent.block_count)
                        };
                        blocks = blocks.saturating_add(count);
                        // Hand the physical blocks back. Dropping the
                        // slot alone is what made deletes never return
                        // space to the volume.
                        self.free_extent_range(entry.extent.physical_block, count);
                    }
                    self.extents[index] = None;
                }
            }
            index += 1;
        }
        blocks.saturating_mul(BLOCK_SIZE_U64)
    }

    /// Give `bytes` back to the active job's quota.
    ///
    /// `check_job_quota` only ever added, so a long-lived job that
    /// repeatedly wrote and deleted files marched towards its limit
    /// and was eventually refused writes on a volume that was in fact
    /// empty. Releasing extents has to reverse the charge.
    ///
    /// The credit goes to the job that is active at release time,
    /// which is the same job that is charged for a rewrite on this
    /// path. Extents carry no job id, so a file deleted under a
    /// different job than the one that wrote it credits the deleter;
    /// tracking per-extent ownership would need an on-disk format
    /// change and is out of scope here. The bound that matters —
    /// usage never diverging upwards from reality for a job that
    /// writes and deletes its own files — holds.
    fn release_job_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let Some(job_id) = self.active_job else {
            return;
        };
        let uuid = job_uuid(job_id);
        let Ok(mut record) = self.quota_tree.get(uuid) else {
            return;
        };
        record.physical_used_bytes = record.physical_used_bytes.saturating_sub(bytes);
        let _ = self.quota_tree.upsert(record);
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

    /// Rebuild the reusable pool from the live extent table.
    ///
    /// Everything between the metadata floor and the high-water mark
    /// that no live extent claims is free space: either a hole left by
    /// a delete whose checkpoint landed, or a block leaked by a crash
    /// between the free and the checkpoint. Deriving the pool from the
    /// live extents rather than from a persisted free list means a
    /// torn free list can never hand out a block that is still in use,
    /// and it recovers leaked blocks for free.
    ///
    /// This is why reclaim needs no on-disk free-list format: the
    /// truth is the extent table, and it is already checkpointed.
    fn rebuild_free_space(&mut self) {
        self.pending_free = [None; MAX_EXTENTS];
        self.free_space = [None; MAX_EXTENTS];
        let floor = self.reserved_block_floor();
        let limit = self.metadata_region_start();
        if limit <= floor {
            return;
        }
        // Collect the live runs, sorted, then emit the gaps.
        let mut live: [Option<FreeRange>; MAX_EXTENTS] = [None; MAX_EXTENTS];
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(entry) = self.extents[index] {
                if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    let blocks = if entry.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                        1
                    } else {
                        u64::from(entry.extent.block_count)
                    };
                    if blocks != 0 && count < live.len() {
                        live[count] = Some(FreeRange {
                            start_block: entry.extent.physical_block,
                            block_count: blocks,
                        });
                        count += 1;
                    }
                }
            }
            index += 1;
        }
        let mut i = 1usize;
        while i < count {
            let mut j = i;
            while j > 0 {
                let (prev, cur) = (live[j - 1], live[j]);
                match (prev, cur) {
                    (Some(a), Some(b)) if b.start_block < a.start_block => {
                        live[j - 1] = Some(b);
                        live[j] = Some(a);
                    }
                    _ => break,
                }
                j -= 1;
            }
            i += 1;
        }
        let mut cursor = floor;
        let mut slot = 0usize;
        while slot < count {
            if let Some(range) = live[slot] {
                if range.start_block > cursor {
                    let gap = range.start_block - cursor;
                    self.insert_free_range(FreeRange {
                        start_block: cursor,
                        block_count: gap,
                    });
                }
                cursor = cursor.max(range.end_block());
            }
            slot += 1;
        }
        if limit > cursor {
            self.insert_free_range(FreeRange {
                start_block: cursor,
                block_count: limit - cursor,
            });
        }
        self.coalesce_free_space();
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
        // Charge live extents, not the append high-water mark.
        // `next_lba` only grows, so deriving usage from it charged
        // the volume for every block an in-place rewrite had already
        // released — the same defect fixed in
        // `committed_physical_bytes`, which this path did not share.
        let current_bytes = self.committed_physical_bytes();
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

    /// Write one data block to fresh LBA(s), applying the object's
    /// resolved compression policy first and the volume encryption
    /// envelope second.
    ///
    /// Returns the physical LBA of the first slot plus the
    /// [`ExtentWriteKind`] describing how the block was stored.
    /// The plaintext is padded to a full 4 KiB block before
    /// compression so the read path always decompresses to exactly
    /// one block; the padding is authenticated (AEAD tag or
    /// descriptor CRC) and is never copied to the caller. An
    /// incompressible input falls back to a plain extent, which
    /// the read path stores verbatim.
    ///
    /// **Two-slot extents (incompressible on encrypted volumes).**
    /// The GCM envelope holds at most 4028 plaintext bytes per
    /// slot. An incompressible plaintext larger than that (a full
    /// 4 KiB block, or a near-full partial block) is stored as two
    /// envelopes in two consecutive physical slots: slot 0 carries
    /// the first 4028 bytes, slot 1 the remainder. The record is
    /// marked [`EXTENT_FLAG_MULTI_SLOT`] with `block_count = 2`.
    /// This is the encrypted-volume replacement for the previous
    /// loud `Unsupported` failure, which made media files,
    /// archives and already-compressed data unwritable on
    /// encrypted volumes.
    /// Reserve `count` physical blocks for file data and report the
    /// generation to seal them under.
    ///
    /// Every data block goes through here so that block reuse, when
    /// the allocator starts handing back freed extents, has exactly
    /// one place to become safe: the generation returned here is what
    /// the AES-GCM nonce is built from, and it must be strictly
    /// greater than any previous tenancy of the same block.
    ///
    /// Today allocation is still the append-only `next_lba` bump, so
    /// every block is fresh and generation 0 is correct by
    /// construction. `block_generation` is the seam that makes this
    /// honest rather than accidental.
    fn reserve_data_blocks(&mut self, count: u64) -> FixedResult<(u64, u64)> {
        if count == 0 {
            return Err(HxfsError::OutOfRange);
        }
        // Reuse before extending. Without this the volume only ever
        // grows and a create/delete service eventually fails with
        // `NoSpace` on a filesystem that is actually empty.
        if let Some(start) = self.take_free_blocks(count) {
            return Ok((start, self.block_generation(start)));
        }
        let start = self.next_lba;
        self.next_lba = self.next_lba.checked_add(count).ok_or(HxfsError::NoSpace)?;
        Ok((start, self.block_generation(start)))
    }

    /// The generation to seal a freshly reserved block under.
    ///
    /// This is the checkpoint sequence the block is being written
    /// under, i.e. one past the sequence currently on disk, which is
    /// exactly what `publish_checkpoint` will stamp.
    ///
    /// Correctness rests on the quarantine in `free_extent_range`: a
    /// block cannot be freed and re-handed-out within one checkpoint,
    /// so two tenancies of the same block always fall under different
    /// sequence numbers, and (key, nonce) is never repeated. See
    /// `docs/design/EXTENT_GENERATION_NONCE.md`.
    fn block_generation(&self, _physical_block: u64) -> u64 {
        self.superblock.sequence_number.saturating_add(1).max(1)
    }

    /// Carve `count` blocks out of the reusable pool, if any run is
    /// large enough. First fit, splitting the remainder back in.
    fn take_free_blocks(&mut self, count: u64) -> Option<u64> {
        let mut index = 0usize;
        while index < self.free_space.len() {
            if let Some(range) = self.free_space[index] {
                if range.block_count >= count {
                    let start = range.start_block;
                    if range.block_count == count {
                        self.free_space[index] = None;
                    } else {
                        self.free_space[index] = Some(FreeRange {
                            start_block: start.saturating_add(count),
                            block_count: range.block_count - count,
                        });
                    }
                    return Some(start);
                }
            }
            index += 1;
        }
        None
    }

    /// Quarantine a run of blocks released by the current transaction.
    ///
    /// Overflowing the quarantine is not an error: the blocks simply
    /// stay allocated and are recovered by the free-space rebuild on
    /// the next mount. Leaking space is recoverable, handing out a
    /// block that is still referenced is not.
    /// Drop cached pages for the physical range `[start, end)`.
    ///
    /// Every path that changes what a physical block holds must go
    /// through here. A page cache that misses one such path does not
    /// merely serve stale data: after a block is freed and handed to
    /// another file it serves the *previous file's* plaintext, which
    /// is a confidentiality bug, not a performance bug.
    /// Page-cache hit/miss counters since mount.
    ///
    /// Exposed so the service can print them in its telemetry line
    /// and so the soak harness can assert the cache is actually being
    /// hit -- a cache nobody can observe is a cache nobody can prove
    /// works.
    pub fn page_cache_stats(&self) -> (u64, u64) {
        (self.page_cache.hits(), self.page_cache.misses())
    }

    /// Number of pages the mounted cache can hold.
    pub fn page_cache_capacity(&self) -> usize {
        self.page_cache.capacity()
    }

    fn invalidate_cached_range(&mut self, start: u64, end: u64) {
        self.page_cache.invalidate_range(start, end);
    }

    fn free_extent_range(&mut self, start_block: u64, block_count: u64) {
        if block_count == 0 || start_block == 0 {
            return;
        }
        // Freed blocks may be re-handed out to a different object;
        // their cached plaintext must not survive the free.
        self.invalidate_cached_range(start_block, start_block.saturating_add(block_count));
        // A snapshot holding this extent is a second owner. Freeing
        // it here would let the allocator re-issue blocks the
        // snapshot still reads through, so the snapshot would quietly
        // return another object's data. The extent becomes reclaimable
        // again when the last snapshot referencing it is deleted.
        if self.snapshot_refs.covers(start_block, block_count) {
            return;
        }
        // Never reclaim into the metadata region: those blocks are
        // owned by the checkpoint/superblock layout, not by extents.
        if start_block < self.reserved_block_floor() {
            return;
        }
        if start_block.saturating_add(block_count) > self.metadata_region_start() {
            return;
        }
        let mut index = 0usize;
        while index < self.pending_free.len() {
            if self.pending_free[index].is_none() {
                self.pending_free[index] = Some(FreeRange {
                    start_block,
                    block_count,
                });
                return;
            }
            index += 1;
        }
    }

    /// Quarantine `[start, end)` minus every block a live extent still
    /// occupies.
    ///
    /// The retired checkpoint region is only *mostly* metadata: on a
    /// volume seeded by `HxfsWriter` the data blocks of existing files
    /// sit inside the same span, below the checkpoint. Freeing the
    /// span wholesale handed those live blocks to the next write and
    /// destroyed the file — the probe lost `/keep.bin` on cycle two.
    /// So punch the live extents out of the range and quarantine only
    /// the gaps.
    fn free_retired_metadata(&mut self, start: u64, end: u64) {
        let mut cursor = start;
        // Walk the range in ascending order, skipping over each live
        // extent that intersects it.
        while cursor < end {
            let mut next_live_start = end;
            let mut next_live_end = end;
            let mut index = 0usize;
            while index < self.extents.len() {
                if let Some(entry) = self.extents[index] {
                    if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                        let blocks = if entry.extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
                            1
                        } else {
                            u64::from(entry.extent.block_count)
                        };
                        let live_start = entry.extent.physical_block;
                        let live_end = live_start.saturating_add(blocks);
                        if live_end > cursor && live_start < next_live_start && live_start < end {
                            next_live_start = live_start.max(cursor);
                            next_live_end = live_end;
                        }
                    }
                }
                index += 1;
            }
            if next_live_start > cursor {
                self.free_extent_range(cursor, next_live_start - cursor);
            }
            cursor = if next_live_end > cursor {
                next_live_end
            } else {
                cursor.saturating_add(1)
            };
        }
    }

    /// First block that extent data may occupy. Block 0 is the
    /// superblock.
    fn reserved_block_floor(&self) -> u64 {
        1
    }

    /// First block of the contiguous metadata region, i.e. the
    /// exclusive upper bound of the reclaimable area.
    ///
    /// `publish_checkpoint` lays every metadata structure out from
    /// `target_start_lba` upwards -- object trees, the object/volume/
    /// allocation/refcount/backref/quota trees and their leaves, the
    /// Hxblob blocks, the checkpoint itself and the journal -- and
    /// data extents always sit below it. Several of those structures
    /// span a root plus a variable number of leaf blocks whose extent
    /// is not recorded anywhere the mount path can see, so rather than
    /// trying to enumerate them, reclaim stops at the lowest metadata
    /// LBA we know about and never looks inside that region.
    ///
    /// Being conservative here costs at worst some unreclaimed blocks;
    /// being wrong the other way hands a live metadata block to a data
    /// write, which is silent corruption. An earlier draft derived the
    /// pool from the gaps below `next_lba` and did exactly that: it
    /// leased out the refcount/backref/quota blocks and broke an
    /// encrypted round-trip test.
    fn metadata_region_start(&self) -> u64 {
        let mut ceiling = self.next_lba;
        let mut lower = |lba: u64| {
            if lba != 0 && lba < ceiling {
                ceiling = lba;
            }
        };
        lower(self.superblock.checkpoint_lba);
        lower(self.superblock.backup_checkpoint_lba);
        lower(self.superblock.journal_start_lba);
        lower(self.system_volume.object_table_lba);
        lower(self.checkpoint.volume_table_lba);
        lower(self.checkpoint.allocation_tree_lba);
        lower(self.checkpoint.refcount_tree_lba);
        lower(self.checkpoint.backref_tree_lba);
        lower(self.checkpoint.quota_tree_lba);
        lower(self.checkpoint.encryption_policy_tree_lba);
        lower(self.checkpoint.compression_policy_tree_lba);
        lower(self.checkpoint.hxblob_index_tree_lba);
        lower(self.checkpoint.hxblob_merkle_tree_lba);
        lower(self.checkpoint.virtual_volume_tree_lba);
        lower(self.checkpoint.gpt_summary_lba);
        lower(self.checkpoint.install_manifest_lba);
        let mut index = 0usize;
        while index < self.objects.len() {
            if let Some(object) = self.objects[index] {
                let tree_lba = object.descriptor.tree_lba;
                if tree_lba != 0 && tree_lba < ceiling {
                    ceiling = tree_lba;
                }
            }
            index += 1;
        }
        ceiling
    }

    /// Promote the quarantined blocks of a published checkpoint into
    /// the reusable pool, coalescing adjacent runs.
    ///
    /// Called only from `publish_checkpoint`, after the new checkpoint
    /// is durable: at that point no live extent references these
    /// blocks on disk, and any future tenancy is stamped with a
    /// strictly greater sequence number.
    fn promote_pending_free(&mut self) {
        let mut index = 0usize;
        while index < self.pending_free.len() {
            if let Some(range) = self.pending_free[index].take() {
                self.insert_free_range(range);
            }
            index += 1;
        }
        self.coalesce_free_space();
    }

    /// Add one run to the reusable pool, dropping it if the pool is
    /// full (see `free_extent_range` on why leaking is the safe way
    /// to fail).
    fn insert_free_range(&mut self, range: FreeRange) {
        let mut index = 0usize;
        while index < self.free_space.len() {
            if self.free_space[index].is_none() {
                self.free_space[index] = Some(range);
                return;
            }
            index += 1;
        }
    }

    /// Sort the pool by start block and merge touching runs, so that
    /// repeated small frees still satisfy a later multi-block request.
    fn coalesce_free_space(&mut self) {
        let len = self.free_space.len();
        // Compact the occupied slots to the front.
        let mut write = 0usize;
        let mut read = 0usize;
        while read < len {
            if let Some(range) = self.free_space[read] {
                self.free_space[read] = None;
                self.free_space[write] = Some(range);
                write += 1;
            }
            read += 1;
        }
        // Insertion sort by start block; the pool is small and mostly
        // ordered already.
        let mut i = 1usize;
        while i < write {
            let mut j = i;
            while j > 0 {
                let (prev, cur) = (self.free_space[j - 1], self.free_space[j]);
                match (prev, cur) {
                    (Some(a), Some(b)) if b.start_block < a.start_block => {
                        self.free_space[j - 1] = Some(b);
                        self.free_space[j] = Some(a);
                    }
                    _ => break,
                }
                j -= 1;
            }
            i += 1;
        }
        // Merge adjacent runs.
        let mut index = 0usize;
        while index + 1 < write {
            let merged = match (self.free_space[index], self.free_space[index + 1]) {
                (Some(a), Some(b)) if a.end_block() == b.start_block => Some(FreeRange {
                    start_block: a.start_block,
                    block_count: a.block_count.saturating_add(b.block_count),
                }),
                _ => None,
            };
            if let Some(merged) = merged {
                self.free_space[index] = Some(merged);
                let mut shift = index + 1;
                while shift + 1 < write {
                    self.free_space[shift] = self.free_space[shift + 1];
                    shift += 1;
                }
                self.free_space[shift] = None;
                write -= 1;
            } else {
                index += 1;
            }
        }
    }

    /// Pin every live extent under a new snapshot.
    ///
    /// Called when a snapshot is created. Each live extent gains one
    /// reference, so a later unlink drops the live owner without
    /// making the blocks reclaimable while the snapshot needs them.
    ///
    /// Returns the number of extents pinned.
    pub fn retain_extents_for_snapshot(&mut self) -> FixedResult<usize> {
        let mut pinned = 0usize;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.extent.flags & EXTENT_FLAG_HOLE == 0 {
                    let start = extent.extent.physical_block;
                    let count = u64::from(extent.extent.block_count);
                    match self.snapshot_refs.increment(start, count) {
                        Ok(_) => {}
                        Err(crate::ref_tree::RefTreeError::NotFound) => {
                            // First snapshot to pin this extent. The
                            // tree counts snapshot holders only -- the
                            // live tree tracks its own ownership -- so
                            // one snapshot is a count of one.
                            self.snapshot_refs
                                .insert(RefcountRecord {
                                    start_block: start,
                                    block_count: count,
                                    refcount: 1,
                                })
                                .map_err(|_| HxfsError::BadTree)?;
                        }
                        Err(_) => return Err(HxfsError::BadTree),
                    }
                    pinned += 1;
                }
            }
            index += 1;
        }
        self.snapshot_refs
            .validate()
            .map_err(|_| HxfsError::BadTree)?;
        Ok(pinned)
    }

    /// Release the extents a deleted snapshot was pinning.
    ///
    /// Extents whose last snapshot reference goes away become
    /// reclaimable, and those already unlinked by the live tree are
    /// handed to the free path here -- this is where the space a
    /// deleted snapshot was holding actually comes back.
    ///
    /// Returns the number of extents released to the free path.
    pub fn release_extents_for_snapshot(&mut self, pinned: &[(u64, u64)]) -> FixedResult<usize> {
        let mut released = 0usize;
        for (start, count) in pinned.iter().copied() {
            match self.snapshot_refs.decrement(start, count) {
                Ok(0) | Err(crate::ref_tree::RefTreeError::NotFound) => {
                    // No snapshot pins this extent any more. If the
                    // live tree still owns it the extent stays put;
                    // free_extent_range is the single place that
                    // decides, and it re-checks the barrier.
                    if !self.extent_is_live(start, count) {
                        self.free_extent_range(start, count);
                        released += 1;
                    }
                }
                Ok(_) => {}
                Err(_) => return Err(HxfsError::BadTree),
            }
        }
        self.snapshot_refs
            .validate()
            .map_err(|_| HxfsError::BadTree)?;
        Ok(released)
    }

    /// Whether a live extent still occupies exactly this range.
    fn extent_is_live(&self, start_block: u64, block_count: u64) -> bool {
        self.extents.iter().flatten().any(|extent| {
            extent.extent.flags & EXTENT_FLAG_HOLE == 0
                && extent.extent.physical_block == start_block
                && u64::from(extent.extent.block_count) == block_count
        })
    }

    /// Extents a snapshot taken now would pin.
    pub fn live_extent_ranges(&self) -> alloc::vec::Vec<(u64, u64)> {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| extent.extent.flags & EXTENT_FLAG_HOLE == 0)
            .map(|extent| {
                (
                    extent.extent.physical_block,
                    u64::from(extent.extent.block_count),
                )
            })
            .collect()
    }

    /// Whether any block of `[start, start + count)` sits in the
    /// reusable pool or is queued to join it.
    ///
    /// Total pool size is the wrong question for snapshot tests: the
    /// pool also absorbs retired checkpoint metadata, which moves for
    /// reasons that have nothing to do with snapshots.
    pub fn range_is_reclaimable(&self, start_block: u64, block_count: u64) -> bool {
        let end = start_block.saturating_add(block_count);
        let overlaps = |range: &FreeRange| {
            let range_end = range.start_block.saturating_add(range.block_count);
            range.start_block < end && start_block < range_end
        };
        self.free_space.iter().flatten().any(overlaps)
            || self.pending_free.iter().flatten().any(overlaps)
    }

    /// Physical bytes currently sitting in the reusable pool.
    pub fn reclaimable_physical_bytes(&self) -> u64 {
        let mut blocks = 0u64;
        let mut index = 0usize;
        while index < self.free_space.len() {
            if let Some(range) = self.free_space[index] {
                blocks = blocks.saturating_add(range.block_count);
            }
            index += 1;
        }
        blocks.saturating_mul(BLOCK_SIZE_U64)
    }

    fn write_data_blocks(
        &mut self,
        data: &[u8],
        object: ObjectDescriptor,
    ) -> FixedResult<(u64, u64, ExtentWriteKind)> {
        // The LZ4 worst-case output bound is
        // `16 + 4 + input_len * 110 / 100` (lz4_flex
        // `get_maximum_output_size`); a scratch the size of the
        // input alone makes the codec fail with `OutputTooSmall`
        // even for highly compressible data, silently falling
        // back to a plain extent. `+ 512` covers the 4 KiB worst
        // case (4525 bytes) with headroom.
        let mut compressed_scratch = [0u8; BLOCK_SIZE + 512];
        let mut compression = None;
        let block_bytes: &[u8] = {
            let policy = crate::resolve_compression_for_object(
                &self.system_volume,
                &self.compression_policies,
                object,
            );
            if let Some(policy) = policy {
                let mut padded = [0u8; BLOCK_SIZE];
                padded[..data.len()].copy_from_slice(data);
                match crate::compression::compress_block(policy, &padded, &mut compressed_scratch) {
                    Ok(crate::compression::CompressOutcome::Compressed {
                        payload,
                        algorithm,
                        payload_crc32c,
                    }) => {
                        compression = Some(ExtentCompressionMeta {
                            algorithm,
                            compressed_bytes: payload.len() as u32,
                            payload_crc32c,
                        });
                        payload
                    }
                    Ok(crate::compression::CompressOutcome::Plain) => data,
                    // Loud failure: a volume whose policy selects a
                    // codec that this build does not link must fail
                    // the write rather than store a plain extent
                    // that the read path cannot decode.
                    Err(_) => return Err(HxfsError::Compression),
                }
            } else {
                data
            }
        };
        #[cfg(feature = "crypto-aes-gcm")]
        let encrypted = self.extent_key.is_some();
        // Two-slot whenever the bytes that would go on disk exceed
        // the envelope capacity. This includes a "successful" LZ4
        // compression whose payload is still > 4028 bytes (e.g. a
        // near-full block of random data with a short zero tail):
        // such a payload would not fit the envelope either, and a
        // multi-slot record stores the ORIGINAL plaintext (the
        // read path concatenates, it does not decompress), so the
        // descriptor is dropped below.
        #[cfg(feature = "crypto-aes-gcm")]
        let multi_slot =
            encrypted && block_bytes.len() > crate::extent_crypto::EXTENT_PLAINTEXT_BYTES;
        #[cfg(not(feature = "crypto-aes-gcm"))]
        let multi_slot = false;
        if multi_slot {
            self.quota_admits(2 * BLOCK_SIZE_U64, 0)?;
        } else {
            self.quota_admits(BLOCK_SIZE_U64, 0)?;
        }
        let (start, generation) = self.reserve_data_blocks(if multi_slot { 2 } else { 1 })?;
        // Two-slot path: split the incompressible plaintext at the
        // envelope capacity and encrypt each half in its own slot.
        // (Only reachable with `crypto-aes-gcm`; `multi_slot` is
        // false on builds without it.)
        #[cfg(feature = "crypto-aes-gcm")]
        if multi_slot {
            let key = self
                .extent_key
                .as_ref()
                .ok_or(HxfsError::EncryptedPolicyInvalid)?;
            // Store the ORIGINAL plaintext, not the (useless)
            // oversized compressed payload: the read path
            // concatenates the two slots verbatim and never runs a
            // codec on a multi-slot record.
            let (head, tail) = data.split_at(crate::extent_crypto::EXTENT_PLAINTEXT_BYTES);
            let mut slot0 = [0u8; BLOCK_SIZE];
            crate::extent_crypto::encrypt_extent_block(
                key,
                start,
                generation,
                &self.volume_uuid,
                head,
                &mut slot0,
            )
            .map_err(|_| HxfsError::BadBlock)?;
            let mut slot1 = [0u8; BLOCK_SIZE];
            crate::extent_crypto::encrypt_extent_block(
                key,
                start + 1,
                generation,
                &self.volume_uuid,
                tail,
                &mut slot1,
            )
            .map_err(|_| HxfsError::BadBlock)?;
            self.store.write_blocks(start, 1, &slot0)?;
            self.store.write_blocks(start + 1, 1, &slot1)?;
            // The blocks just changed underneath any cached page.
            self.invalidate_cached_range(start, start + 2);
            return Ok((start, generation, ExtentWriteKind::MultiSlot));
        }
        // Stage B.3 wire: when the volume is encrypted,
        // the on-disk extent block is the AES-256-GCM
        // envelope around the (compressed) plaintext. We build
        // the envelope with the per-volume extent subkey
        // (derived once at mount time) so the read path's
        // decrypt step lands on a block with the matching
        // key. Plain volumes write the plaintext directly,
        // byte-for-byte compatible with the pre-B.3 layout.
        #[cfg(feature = "crypto-aes-gcm")]
        let block = if let Some(key) = self.extent_key.as_ref() {
            let mut ciphertext = [0u8; crate::extent_crypto::EXTENT_ENCRYPTED_BYTES];
            crate::extent_crypto::encrypt_extent_block(
                key,
                start,
                generation,
                &self.volume_uuid,
                block_bytes,
                &mut ciphertext,
            )
            .map_err(|_| HxfsError::BadBlock)?;
            // Pad the ciphertext to a full 4 KiB block so
            // the on-disk extent block keeps the same
            // shape it had before B.3 (a single 4 KiB
            // read). The high bytes after the GCM envelope
            // are zeros; they are not authenticated but
            // the read path ignores them.
            let mut block = [0u8; BLOCK_SIZE];
            block[..ciphertext.len()].copy_from_slice(&ciphertext);
            block
        } else {
            let mut block = [0u8; BLOCK_SIZE];
            block[..block_bytes.len()].copy_from_slice(block_bytes);
            block
        };
        #[cfg(not(feature = "crypto-aes-gcm"))]
        let block = {
            let mut block = [0u8; BLOCK_SIZE];
            block[..block_bytes.len()].copy_from_slice(block_bytes);
            block
        };
        self.store.write_blocks(start, 1, &block)?;
        // The block just changed underneath any cached page.
        self.invalidate_cached_range(start, start + 1);
        let kind = match compression {
            Some(meta) => ExtentWriteKind::Compressed(meta),
            None => ExtentWriteKind::Plain,
        };
        Ok((start, generation, kind))
    }

    fn copy_extents(&mut self, object_id: u64, out: &mut [u8]) -> FixedResult<()> {
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id == object_id {
                    self.copy_extent(extent.extent, extent.compression, out)?;
                }
            }
            index += 1;
        }
        Ok(())
    }

    fn copy_extent(
        &mut self,
        extent: ExtentRecord,
        compression: Option<ExtentCompressionMeta>,
        out: &mut [u8],
    ) -> FixedResult<()> {
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
        // Stage C: a known-bad extent fails fast without touching
        // the disk.
        if self.is_bad_extent(extent.physical_block) {
            return Err(HxfsError::Compression);
        }
        // Two-slot extent: one logical block across two encrypted
        // envelopes. Decrypt both slots and concatenate; the
        // writer-side mirror of the reader's MULTI_SLOT path.
        #[cfg(feature = "crypto-aes-gcm")]
        if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
            if self.extent_key.is_none() {
                // A two-slot record on a volume without a key is a
                // corrupt volume, not raw split plaintext.
                return Err(HxfsError::BadTree);
            }
            let mut slot0 = [0u8; BLOCK_SIZE];
            let mut slot1 = [0u8; BLOCK_SIZE];
            self.store
                .read_blocks(extent.physical_block, 1, &mut slot0)?;
            self.store
                .read_blocks(extent.physical_block + 1, 1, &mut slot1)?;
            let mut dec0 = [0u8; BLOCK_SIZE];
            let mut dec1 = [0u8; BLOCK_SIZE];
            let plain0 = match self.decrypt_extent_block_if_encrypted(
                extent.physical_block,
                extent.generation,
                &slot0,
                &mut dec0,
            ) {
                Ok(plain) => plain,
                Err(error) => {
                    self.mark_bad_extent(extent.physical_block);
                    return Err(error);
                }
            };
            let plain1 = match self.decrypt_extent_block_if_encrypted(
                extent.physical_block + 1,
                extent.generation,
                &slot1,
                &mut dec1,
            ) {
                Ok(plain) => plain,
                Err(error) => {
                    self.mark_bad_extent(extent.physical_block + 1);
                    return Err(error);
                }
            };
            let mut composed = [0u8; BLOCK_SIZE];
            composed[..crate::extent_crypto::EXTENT_PLAINTEXT_BYTES]
                .copy_from_slice(&plain0[..crate::extent_crypto::EXTENT_PLAINTEXT_BYTES]);
            let tail = BLOCK_SIZE - crate::extent_crypto::EXTENT_PLAINTEXT_BYTES;
            composed[crate::extent_crypto::EXTENT_PLAINTEXT_BYTES..]
                .copy_from_slice(&plain1[..tail]);
            let chunk = copy_end.min(start + BLOCK_SIZE) - start;
            out[start..start + chunk].copy_from_slice(&composed[..chunk]);
            return Ok(());
        }
        #[cfg(not(feature = "crypto-aes-gcm"))]
        if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
            // Two-slot extents are an encrypted-volume concept.
            return Err(HxfsError::BadTree);
        }
        // Whole-object read goes through the same per-block path as the
        // range read, so both share one decode path and one cache.
        // Duplicating the decrypt/decompress logic here is what let
        // the whole-file path bypass the page cache entirely.
        let mut block = [0u8; BLOCK_SIZE];
        let mut copied = start;
        while copied < copy_end {
            let logical_delta = copied - start;
            let extent_block = (logical_delta / BLOCK_SIZE) as u64;
            let within = logical_delta % BLOCK_SIZE;
            match self.read_extent_block(extent, compression, extent_block, &mut block) {
                Ok(()) => {}
                Err(error) => {
                    self.mark_bad_extent(extent.physical_block + extent_block);
                    return Err(error);
                }
            }
            let chunk = (copy_end - copied).min(BLOCK_SIZE - within);
            out[copied..copied + chunk].copy_from_slice(&block[within..within + chunk]);
            copied += chunk;
        }
        Ok(())
    }

    /// Read ONE logical block of an extent into a 4 KiB buffer,
    /// applying decrypt/decompress. `block_offset` selects the
    /// block within the extent (0 for single-block extents). Used
    /// by the chunked range read so a large file can be read
    /// without materialising the whole object.
    fn read_extent_block(
        &mut self,
        extent: ExtentRecord,
        compression: Option<ExtentCompressionMeta>,
        block_offset: u64,
        out: &mut [u8; BLOCK_SIZE],
    ) -> FixedResult<()> {
        // Cache lookup before any device access. The key is the
        // physical block actually read, not the logical one, so a
        // block that gets reallocated to another file cannot be
        // served from a stale slot as long as invalidation runs on
        // free (see `invalidate_cached_extent`).
        let cache_block = extent.physical_block + block_offset;
        if self
            .page_cache
            .lookup(self.cache_volume_id, cache_block, 0, out)
        {
            return Ok(());
        }
        // Two-slot extent: one logical block spans two encrypted
        // envelopes (`EXTENT_FLAG_MULTI_SLOT`, `block_count = 2`).
        // The single-slot path below would silently return only
        // slot 0 - the tail of the logical block would read back as
        // envelope padding instead of the second slot's plaintext.
        // Concatenate both slots exactly like `copy_extent` does.
        #[cfg(feature = "crypto-aes-gcm")]
        if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
            if block_offset != 0 {
                return Err(HxfsError::OutOfRange);
            }
            if self.extent_key.is_none() {
                // A two-slot record on a volume without a key is a
                // corrupt volume, not raw split plaintext.
                return Err(HxfsError::BadTree);
            }
            let mut slot0 = [0u8; BLOCK_SIZE];
            let mut slot1 = [0u8; BLOCK_SIZE];
            self.store
                .read_blocks(extent.physical_block, 1, &mut slot0)?;
            self.store
                .read_blocks(extent.physical_block + 1, 1, &mut slot1)?;
            let mut dec0 = [0u8; BLOCK_SIZE];
            let mut dec1 = [0u8; BLOCK_SIZE];
            let plain0 = self.decrypt_extent_block_if_encrypted(
                extent.physical_block,
                extent.generation,
                &slot0,
                &mut dec0,
            )?;
            let plain1 = self.decrypt_extent_block_if_encrypted(
                extent.physical_block + 1,
                extent.generation,
                &slot1,
                &mut dec1,
            )?;
            let tail = BLOCK_SIZE - crate::extent_crypto::EXTENT_PLAINTEXT_BYTES;
            out[..crate::extent_crypto::EXTENT_PLAINTEXT_BYTES]
                .copy_from_slice(&plain0[..crate::extent_crypto::EXTENT_PLAINTEXT_BYTES]);
            out[crate::extent_crypto::EXTENT_PLAINTEXT_BYTES..].copy_from_slice(&plain1[..tail]);
            self.page_cache
                .insert(self.cache_volume_id, cache_block, 0, out);
            return Ok(());
        }
        #[cfg(not(feature = "crypto-aes-gcm"))]
        if extent.flags & EXTENT_FLAG_MULTI_SLOT != 0 {
            // Two-slot extents are an encrypted-volume concept.
            return Err(HxfsError::BadTree);
        }
        let mut scratch = [0u8; BLOCK_SIZE];
        let mut decrypted = [0u8; BLOCK_SIZE];
        self.store
            .read_blocks(extent.physical_block + block_offset, 1, &mut scratch)?;
        let plain: &[u8] = self.decrypt_extent_block_if_encrypted(
            extent.physical_block + block_offset,
            extent.generation,
            &scratch,
            &mut decrypted,
        )?;
        if let Some(meta) = compression {
            let payload = &plain[..meta.compressed_bytes as usize];
            let descriptor = crate::compression::CompressedExtent {
                logical_block: extent.logical_block,
                physical_block: extent.physical_block,
                uncompressed_bytes: BLOCK_SIZE as u32,
                compressed_bytes: meta.compressed_bytes,
                algorithm: meta.algorithm,
                payload_crc32c: meta.payload_crc32c,
            };
            let mut decompressed = [0u8; BLOCK_SIZE];
            crate::compression::decompress_block(&descriptor, payload, &mut decompressed)
                .map_err(|_| HxfsError::Compression)?;
            out.copy_from_slice(&decompressed);
        } else {
            out.copy_from_slice(plain);
        }
        self.page_cache
            .insert(self.cache_volume_id, cache_block, 0, out);
        Ok(())
    }

    /// Decrypt one data block when the volume is encrypted.
    /// Returns a slice into `scratch` (plain volume) or
    /// `decrypted` (encrypted volume).
    fn decrypt_extent_block_if_encrypted<'a>(
        &self,
        physical_block: u64,
        generation: u64,
        scratch: &'a [u8; BLOCK_SIZE],
        decrypted: &'a mut [u8; BLOCK_SIZE],
    ) -> FixedResult<&'a [u8]> {
        #[cfg(feature = "crypto-aes-gcm")]
        if let Some(key) = self.extent_key.as_ref() {
            crate::extent_crypto::decrypt_extent_block(
                key,
                physical_block,
                generation,
                &self.volume_uuid,
                scratch,
                decrypted,
            )
            .map_err(|_| HxfsError::Compression)?;
            return Ok(&decrypted[..]);
        }
        #[cfg(not(feature = "crypto-aes-gcm"))]
        {
            let _ = (physical_block, generation, decrypted);
        }
        Ok(scratch)
    }

    fn build_object_tree_block(
        &mut self,
        object: ObjectDescriptor,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        // Returns (block, leaves): leaves are extent-tree leaf
        // blocks the publisher writes plain after the root; empty
        // for directories and single-block layouts.
        match object.object_type {
            OBJECT_TYPE_DIRECTORY => Ok((
                self.build_directory_block(object.object_id, lba)?,
                alloc::vec::Vec::new(),
            )),
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
        make_metadata_block_for_volume(
            BLOCK_TYPE_DIRECTORY,
            object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * DIR_RECORD_BYTES],
            args.0,
            args.1,
            args.2,
        )
    }

    /// Convenience: pack the (volume_encrypted, metadata_key,
    /// volume_uuid) triple into a tuple for the
    /// `make_metadata_block_for_volume` call. On a build without
    /// the feature the encryption half is `None` and the UUID
    /// is a default; the wrapper falls through to the plain
    /// builder. Defined as a tuple expression so the cfg
    /// attributes can sit on the field values, not on the
    /// expression itself.
    /// Generation to seal encrypted metadata blocks under.
    ///
    /// Metadata blocks are copy-on-write — a checkpoint writes them to
    /// freshly bumped LBAs rather than overwriting the previous copy —
    /// so today no metadata LBA is ever encrypted twice. Binding the
    /// checkpoint sequence anyway means that stops being an accident:
    /// if a future change ever rewrites a metadata block in place, the
    /// nonce moves with the sequence instead of silently repeating.
    ///
    /// The value is written into `BlockHeader::generation`, and the
    /// read path feeds that field back into the AEAD, so writer and
    /// reader cannot drift apart.
    fn metadata_generation(&self) -> u64 {
        self.superblock.sequence_number
    }

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
    /// Does any extent of `object_id` carry a non-zero generation?
    ///
    /// Such an object cannot be serialized as a v1 record without
    /// losing the generation, and losing the generation makes the
    /// extent undecryptable.
    fn object_needs_generation(&self, object_id: u64) -> bool {
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(entry) = self.extents[index] {
                if entry.object_id == object_id && entry.extent.generation != 0 {
                    return true;
                }
            }
            index += 1;
        }
        false
    }

    fn build_extent_block(
        &mut self,
        object_id: u64,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        // Stage E: objects with more extents than fit one extent
        // table become a two-level tree (root + leaves). The
        // leaves are returned (not written) so the publisher can
        // place them after the root without colliding with the
        // journal area.
        if self.extent_count(object_id) as usize > EXTENT_LEAF_RECORDS {
            return self.build_extent_tree(object_id, lba);
        }
        // Stage B.3 completion: emit a v2 block (40-byte records
        // with an optional per-record compression descriptor)
        // whenever the object's resolved compression policy selects
        // a codec. The v2 block type is what tells the read path
        // to use the per-record descriptors instead of the
        // policy-driven v1 semantics — an incompressible fallback
        // record stores plain bytes with `EXTENT_FLAG_COMPRESSED`
        // clear, and the reader must NOT try to decode it. Objects
        // outside any compression policy keep the v1 block type so
        // old-style volumes read exactly as before.
        let object = self.object(object_id)?.descriptor;
        // The v2 record is also required to carry a non-zero
        // generation: bytes [36..40) only exist in the 40-byte
        // layout. Choosing the record purely on the compression
        // policy silently dropped the generation of an encrypted
        // volume that compresses nothing, so the block was sealed
        // under generation N but read back under 0 and the AEAD tag
        // check failed. Caught by
        // `b1_b2_encrypted_volume_write_then_read_round_trip`.
        let v2 = crate::resolve_compression_for_object(
            &self.system_volume,
            &self.compression_policies,
            object,
        )
        .is_some()
            || self.object_needs_generation(object_id);
        let record_bytes = if v2 {
            EXTENT_RECORD_BYTES_V2
        } else {
            EXTENT_RECORD_BYTES
        };
        let block_type = if v2 {
            BLOCK_TYPE_EXTENT_TABLE_V2
        } else {
            BLOCK_TYPE_EXTENT_TABLE
        };
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let count = self.extent_count(object_id);
        payload[0..8].copy_from_slice(&object_id.to_le_bytes());
        payload[8..12].copy_from_slice(&count.to_le_bytes());
        let mut written = 0usize;
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id == object_id {
                    let offset = 16 + written * record_bytes;
                    if offset + record_bytes > payload.len() {
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
                    if v2 {
                        if let Some(meta) = extent.compression {
                            payload[offset + 24..offset + 28]
                                .copy_from_slice(&meta.algorithm.to_le_bytes());
                            payload[offset + 28..offset + 32]
                                .copy_from_slice(&meta.compressed_bytes.to_le_bytes());
                            payload[offset + 32..offset + 36]
                                .copy_from_slice(&meta.payload_crc32c.to_le_bytes());
                        }
                        // Bytes 36..40 were reserved-zero in the
                        // original v2 record, so writing the
                        // generation here keeps the record size and
                        // every tree geometry unchanged, and an old
                        // volume still reads back generation 0.
                        payload[offset + 36..offset + 40]
                            .copy_from_slice(&(extent.extent.generation as u32).to_le_bytes());
                    }
                    written += 1;
                }
            }
            index += 1;
        }
        let args = self.encryption_args();
        let block = make_metadata_block_for_volume(
            block_type,
            object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * record_bytes],
            args.0,
            args.1,
            args.2,
        )?;
        Ok((block, alloc::vec::Vec::new()))
    }

    /// Stage E: build a two-level extent tree (root + leaves).
    fn build_extent_tree(
        &self,
        object_id: u64,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        let count = self.extent_count(object_id) as usize;
        let leaf_count = count.div_ceil(EXTENT_LEAF_RECORDS);
        let root_payload_len = 16 + leaf_count * 8;
        let mut root_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        root_payload[0..4].copy_from_slice(&EXTENT_TREE_ROOT_MAGIC.to_le_bytes());
        root_payload[4..8].copy_from_slice(&EXTENT_TREE_ROOT_VERSION.to_le_bytes());
        root_payload[8..12].copy_from_slice(&(leaf_count as u32).to_le_bytes());
        let mut leaf_index = 0usize;
        let mut leaf_lba = lba + 1;
        while leaf_index < leaf_count {
            root_payload[16 + leaf_index * 8..16 + leaf_index * 8 + 8]
                .copy_from_slice(&leaf_lba.to_le_bytes());
            leaf_lba += 1;
            leaf_index += 1;
        }
        let args = self.encryption_args();
        let (args_enc, args_key, args_uuid) = (args.0, args.1.copied(), *args.2);
        let root = make_metadata_block_for_volume(
            BLOCK_TYPE_EXTENT_TREE_ROOT,
            object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &root_payload[..root_payload_len],
            args_enc,
            args_key.as_ref(),
            &args_uuid,
        )?;
        // Collect the object's extents in logical order.
        let mut records: alloc::vec::Vec<FixedExtent> = alloc::vec::Vec::new();
        let mut index = 0usize;
        while index < self.extents.len() {
            if let Some(extent) = self.extents[index] {
                if extent.object_id == object_id {
                    records.push(extent);
                }
            }
            index += 1;
        }
        records.sort_by_key(|extent| extent.extent.logical_block);
        let mut leaves: alloc::vec::Vec<[u8; BLOCK_SIZE]> =
            alloc::vec::Vec::with_capacity(leaf_count);
        let mut leaf_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let mut record_index = 0usize;
        leaf_lba = lba + 1;
        for record in &records {
            let within = record_index % EXTENT_LEAF_RECORDS;
            if within == 0 {
                leaf_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
            }
            self.serialize_extent_record(
                &mut leaf_payload,
                within * EXTENT_RECORD_BYTES_V2,
                record,
                true,
            );
            record_index += 1;
            if within == EXTENT_LEAF_RECORDS - 1 || record_index == records.len() {
                leaves.push(make_metadata_block_for_volume(
                    BLOCK_TYPE_EXTENT_TREE_LEAF,
                    object_id,
                    MetadataBlockSite {
                        lba: leaf_lba,
                        generation: self.metadata_generation(),
                    },
                    &leaf_payload[..EXTENT_LEAF_RECORDS * EXTENT_RECORD_BYTES_V2],
                    args_enc,
                    args_key.as_ref(),
                    &args_uuid,
                )?);
                leaf_lba += 1;
            }
        }
        Ok((root, leaves))
    }

    /// Stage E: serialize one extent record into `payload`.
    fn serialize_extent_record(
        &self,
        payload: &mut [u8],
        offset: usize,
        extent: &FixedExtent,
        v2: bool,
    ) {
        payload[offset..offset + 8].copy_from_slice(&extent.extent.logical_block.to_le_bytes());
        payload[offset + 8..offset + 16]
            .copy_from_slice(&extent.extent.physical_block.to_le_bytes());
        payload[offset + 16..offset + 20].copy_from_slice(&extent.extent.block_count.to_le_bytes());
        payload[offset + 20..offset + 24].copy_from_slice(&extent.extent.flags.to_le_bytes());
        if v2 {
            if let Some(meta) = extent.compression {
                payload[offset + 24..offset + 28].copy_from_slice(&meta.algorithm.to_le_bytes());
                payload[offset + 28..offset + 32]
                    .copy_from_slice(&meta.compressed_bytes.to_le_bytes());
                payload[offset + 32..offset + 36]
                    .copy_from_slice(&meta.payload_crc32c.to_le_bytes());
            }
            // See `build_extent_table_block`: the reserved tail of the
            // v2 record carries the generation.
            payload[offset + 36..offset + 40]
                .copy_from_slice(&(extent.extent.generation as u32).to_le_bytes());
        }
    }

    /// Stage E: number of blocks a file object's extent layout
    /// consumes at publish (1, or 1 + leaf_count for a tree).
    fn extent_blocks_for_object(&self, object_id: u64) -> usize {
        let count = self.extent_count(object_id) as usize;
        if count > EXTENT_LEAF_RECORDS {
            1 + count.div_ceil(EXTENT_LEAF_RECORDS)
        } else {
            1
        }
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

    fn build_allocation_tree_block(
        &self,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
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
        // Stage E: a volume with more allocation records than fit
        // one block gets a two-level allocation tree.
        let records: alloc::vec::Vec<AllocationRecord> =
            tree.records().iter().filter_map(|record| *record).collect();
        let count = records.len();
        if count > ALLOC_LEAF_RECORDS {
            return self.build_allocation_tree_multi(records, lba);
        }
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < records.len() {
            let record = records[index];
            let offset = 16 + written * 32;
            if offset + 32 > payload.len() {
                return Err(HxfsError::NoSpace);
            }
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 20].copy_from_slice(&(record.state as u32).to_le_bytes());
            payload[offset + 24..offset + 32]
                .copy_from_slice(&record.owner_object_id.to_le_bytes());
            written += 1;
            index += 1;
        }
        let args = self.encryption_args();
        let block = make_metadata_block_for_volume(
            BLOCK_TYPE_ALLOCATION_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * 32],
            args.0,
            args.1,
            args.2,
        )?;
        Ok((block, alloc::vec::Vec::new()))
    }

    /// Stage E: build a two-level allocation tree (root + leaves).
    fn build_allocation_tree_multi(
        &self,
        records: alloc::vec::Vec<AllocationRecord>,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        let count = records.len();
        let leaf_count = count.div_ceil(ALLOC_LEAF_RECORDS);
        let mut root_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        root_payload[0..4].copy_from_slice(&ALLOC_TREE_ROOT_MAGIC.to_le_bytes());
        root_payload[4..8].copy_from_slice(&ALLOC_TREE_ROOT_VERSION.to_le_bytes());
        root_payload[8..12].copy_from_slice(&(leaf_count as u32).to_le_bytes());
        let mut leaf_index = 0usize;
        let mut leaf_lba = lba + 1;
        while leaf_index < leaf_count {
            root_payload[16 + leaf_index * 8..16 + leaf_index * 8 + 8]
                .copy_from_slice(&leaf_lba.to_le_bytes());
            leaf_lba += 1;
            leaf_index += 1;
        }
        let args = self.encryption_args();
        let root = make_metadata_block_for_volume(
            BLOCK_TYPE_ALLOCATION_TREE_ROOT,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &root_payload[..16 + leaf_count * 8],
            args.0,
            args.1,
            args.2,
        )?;
        let mut leaves: alloc::vec::Vec<[u8; BLOCK_SIZE]> =
            alloc::vec::Vec::with_capacity(leaf_count);
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let mut record_index = 0usize;
        leaf_lba = lba + 1;
        for record in &records {
            let within = record_index % ALLOC_LEAF_RECORDS;
            if within == 0 {
                payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
            }
            let offset = within * 32;
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 20].copy_from_slice(&(record.state as u32).to_le_bytes());
            payload[offset + 24..offset + 32]
                .copy_from_slice(&record.owner_object_id.to_le_bytes());
            record_index += 1;
            if within == ALLOC_LEAF_RECORDS - 1 || record_index == count {
                leaves.push(make_metadata_block_for_volume(
                    BLOCK_TYPE_ALLOCATION_TREE_LEAF,
                    self.system_volume.root_object_id,
                    MetadataBlockSite {
                        lba: leaf_lba,
                        generation: self.metadata_generation(),
                    },
                    &payload[..ALLOC_LEAF_RECORDS * 32],
                    args.0,
                    args.1,
                    args.2,
                )?);
                leaf_lba += 1;
            }
        }
        Ok((root, leaves))
    }

    fn build_refcount_tree_block(
        &self,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
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
        let records: alloc::vec::Vec<RefcountRecord> =
            tree.records().iter().filter_map(|record| *record).collect();
        let count = records.len();
        if count > REFCOUNT_LEAF_RECORDS {
            return self.build_refcount_tree_multi(records, lba);
        }
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < records.len() {
            let record = records[index];
            let offset = 16 + written * 24;
            if offset + 24 > payload.len() {
                return Err(HxfsError::NoSpace);
            }
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 20].copy_from_slice(&record.refcount.to_le_bytes());
            written += 1;
            index += 1;
        }
        let args = self.encryption_args();
        let block = make_metadata_block_for_volume(
            BLOCK_TYPE_REFCOUNT_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * 24],
            args.0,
            args.1,
            args.2,
        )?;
        Ok((block, alloc::vec::Vec::new()))
    }

    /// Stage E: build a two-level refcount tree (root + leaves).
    fn build_refcount_tree_multi(
        &self,
        records: alloc::vec::Vec<RefcountRecord>,
        lba: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        let count = records.len();
        let leaf_count = count.div_ceil(REFCOUNT_LEAF_RECORDS);
        let mut root_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        root_payload[0..4].copy_from_slice(&REFCOUNT_TREE_ROOT_MAGIC.to_le_bytes());
        root_payload[4..8].copy_from_slice(&REFCOUNT_TREE_ROOT_VERSION.to_le_bytes());
        root_payload[8..12].copy_from_slice(&(leaf_count as u32).to_le_bytes());
        let mut leaf_index = 0usize;
        let mut leaf_lba = lba + 1;
        while leaf_index < leaf_count {
            root_payload[16 + leaf_index * 8..16 + leaf_index * 8 + 8]
                .copy_from_slice(&leaf_lba.to_le_bytes());
            leaf_lba += 1;
            leaf_index += 1;
        }
        let args = self.encryption_args();
        let root = make_metadata_block_for_volume(
            BLOCK_TYPE_REFCOUNT_TREE_ROOT,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &root_payload[..16 + leaf_count * 8],
            args.0,
            args.1,
            args.2,
        )?;
        let mut leaves: alloc::vec::Vec<[u8; BLOCK_SIZE]> =
            alloc::vec::Vec::with_capacity(leaf_count);
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let mut record_index = 0usize;
        leaf_lba = lba + 1;
        for record in &records {
            let within = record_index % REFCOUNT_LEAF_RECORDS;
            if within == 0 {
                payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
            }
            let offset = within * 24;
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 20].copy_from_slice(&record.refcount.to_le_bytes());
            record_index += 1;
            if within == REFCOUNT_LEAF_RECORDS - 1 || record_index == count {
                leaves.push(make_metadata_block_for_volume(
                    BLOCK_TYPE_REFCOUNT_TREE_LEAF,
                    self.system_volume.root_object_id,
                    MetadataBlockSite {
                        lba: leaf_lba,
                        generation: self.metadata_generation(),
                    },
                    &payload[..REFCOUNT_LEAF_RECORDS * 24],
                    args.0,
                    args.1,
                    args.2,
                )?);
                leaf_lba += 1;
            }
        }
        Ok((root, leaves))
    }

    fn build_backref_tree_block(
        &self,
        lba: u64,
        generation: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
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
        let records: alloc::vec::Vec<BackrefRecord> =
            tree.records().iter().filter_map(|record| *record).collect();
        let count = records.len();
        if count > BACKREF_LEAF_RECORDS {
            return self.build_backref_tree_multi(records, lba, generation);
        }
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        payload[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        let mut written = 0usize;
        index = 0;
        while index < records.len() {
            let record = records[index];
            let offset = 16 + written * 40;
            if offset + 40 > payload.len() {
                return Err(HxfsError::NoSpace);
            }
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 24]
                .copy_from_slice(&record.owner_object_id.to_le_bytes());
            payload[offset + 24..offset + 28].copy_from_slice(&(record.kind as u32).to_le_bytes());
            payload[offset + 32..offset + 40].copy_from_slice(&record.generation.to_le_bytes());
            written += 1;
            index += 1;
        }
        let args = self.encryption_args();
        let block = make_metadata_block_for_volume(
            BLOCK_TYPE_BACKREF_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * 40],
            args.0,
            args.1,
            args.2,
        )?;
        Ok((block, alloc::vec::Vec::new()))
    }

    /// Stage E: build a two-level backref tree (root + leaves).
    fn build_backref_tree_multi(
        &self,
        records: alloc::vec::Vec<BackrefRecord>,
        lba: u64,
        _generation: u64,
    ) -> FixedResult<([u8; BLOCK_SIZE], alloc::vec::Vec<[u8; BLOCK_SIZE]>)> {
        let count = records.len();
        let leaf_count = count.div_ceil(BACKREF_LEAF_RECORDS);
        let mut root_payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        root_payload[0..4].copy_from_slice(&BACKREF_TREE_ROOT_MAGIC.to_le_bytes());
        root_payload[4..8].copy_from_slice(&BACKREF_TREE_ROOT_VERSION.to_le_bytes());
        root_payload[8..12].copy_from_slice(&(leaf_count as u32).to_le_bytes());
        let mut leaf_index = 0usize;
        let mut leaf_lba = lba + 1;
        while leaf_index < leaf_count {
            root_payload[16 + leaf_index * 8..16 + leaf_index * 8 + 8]
                .copy_from_slice(&leaf_lba.to_le_bytes());
            leaf_lba += 1;
            leaf_index += 1;
        }
        let args = self.encryption_args();
        let root = make_metadata_block_for_volume(
            BLOCK_TYPE_BACKREF_TREE_ROOT,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &root_payload[..16 + leaf_count * 8],
            args.0,
            args.1,
            args.2,
        )?;
        let mut leaves: alloc::vec::Vec<[u8; BLOCK_SIZE]> =
            alloc::vec::Vec::with_capacity(leaf_count);
        let mut payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
        let mut record_index = 0usize;
        leaf_lba = lba + 1;
        for record in &records {
            let within = record_index % BACKREF_LEAF_RECORDS;
            if within == 0 {
                payload = [0u8; BLOCK_SIZE - HEADER_BYTES];
            }
            let offset = within * 40;
            payload[offset..offset + 8].copy_from_slice(&record.start_block.to_le_bytes());
            payload[offset + 8..offset + 16].copy_from_slice(&record.block_count.to_le_bytes());
            payload[offset + 16..offset + 24]
                .copy_from_slice(&record.owner_object_id.to_le_bytes());
            payload[offset + 24..offset + 28].copy_from_slice(&(record.kind as u32).to_le_bytes());
            payload[offset + 32..offset + 40].copy_from_slice(&record.generation.to_le_bytes());
            record_index += 1;
            if within == BACKREF_LEAF_RECORDS - 1 || record_index == count {
                leaves.push(make_metadata_block_for_volume(
                    BLOCK_TYPE_BACKREF_TREE_LEAF,
                    self.system_volume.root_object_id,
                    MetadataBlockSite {
                        lba: leaf_lba,
                        generation: self.metadata_generation(),
                    },
                    &payload[..BACKREF_LEAF_RECORDS * 40],
                    args.0,
                    args.1,
                    args.2,
                )?);
                leaf_lba += 1;
            }
        }
        Ok((root, leaves))
    }

    fn build_quota_tree_block(
        &self,
        lba: u64,
        future_next_lba: u64,
    ) -> FixedResult<[u8; BLOCK_SIZE]> {
        let physical_used_bytes = future_next_lba
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(HxfsError::OutOfRange)?;
        // Stage E (Phase-2): the quota tree block carries the volume
        // record PLUS every per-job record.
        let mut tree = QuotaBtree::<MAX_QUOTA_RECORDS>::new();
        tree.upsert(QuotaRecord {
            volume_uuid: self.system_volume.uuid,
            physical_limit_bytes: self.system_volume.quota_physical_bytes,
            physical_used_bytes,
            object_limit: self.system_volume.quota_objects,
            object_count: self.live_object_count() as u64,
        })
        .map_err(|_| HxfsError::NoSpace)?;
        for record in self.quota_tree.records().iter().flatten() {
            if record.volume_uuid != self.system_volume.uuid {
                tree.upsert(*record).map_err(|_| HxfsError::NoSpace)?;
            }
        }
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
        make_metadata_block_for_volume(
            BLOCK_TYPE_QUOTA_TREE,
            self.system_volume.root_object_id,
            MetadataBlockSite {
                lba,
                generation: self.metadata_generation(),
            },
            &payload[..16 + written * 56],
            args.0,
            args.1,
            args.2,
        )
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
/// Where a metadata block lives and which tenancy of that location
/// it is.
///
/// Grouped into one value because the LBA and the generation are
/// never meaningful apart: together they are what the AEAD nonce is
/// built from, so passing one without the other is always a bug.
#[derive(Clone, Copy)]
struct MetadataBlockSite {
    /// LBA the block will occupy.
    lba: u64,
    /// Checkpoint sequence this block is written under.
    ///
    /// Only read on builds with `crypto-aes-gcm`: a plaintext volume
    /// has no AEAD to feed it into. The field is still populated
    /// unconditionally so the two builds cannot drift apart.
    #[cfg_attr(not(feature = "crypto-aes-gcm"), allow(dead_code))]
    generation: u64,
}

#[cfg(feature = "crypto-aes-gcm")]
fn make_metadata_block_for_volume(
    block_type: u32,
    owner: u64,
    site: MetadataBlockSite,
    payload: &[u8],
    volume_encrypted: bool,
    metadata_key: Option<&[u8; 32]>,
    volume_uuid: &crate::format::Uuid,
) -> FixedResult<[u8; BLOCK_SIZE]> {
    let lba = site.lba;
    if volume_encrypted && is_encrypted_block_type(block_type) {
        let key = metadata_key.ok_or(HxfsError::EncryptedPolicyInvalid)?;
        return crate::encrypted_metadata::make_encrypted_metadata_block(
            block_type,
            owner,
            lba,
            site.generation,
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
    site: MetadataBlockSite,
    payload: &[u8],
    _volume_encrypted: bool,
    _metadata_key: Option<&[u8; 32]>,
    _volume_uuid: &crate::format::Uuid,
) -> FixedResult<[u8; BLOCK_SIZE]> {
    Ok(make_metadata_block(block_type, owner, site.lba, payload))
}

/// Stage B.1: which metadata block types carry the encrypted
/// payload on an encrypted volume. The superblock, checkpoint,
/// volume table, and object table stay plaintext because they
/// are needed to bootstrap the encryption key (see
/// `docs/STAGE_B_PLAN.md` B.1).
#[cfg(feature = "crypto-aes-gcm")]
fn is_encrypted_block_type(block_type: u32) -> bool {
    matches!(
        block_type,
        BLOCK_TYPE_DIRECTORY
            | BLOCK_TYPE_EXTENT_TABLE
            | BLOCK_TYPE_EXTENT_TABLE_V2
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
            Self::from_image_with_blocks(image, BLOCKS)
        }

        /// Same, but with an explicit device size. The churn tests
        /// need a device big enough that hitting the end of it cannot
        /// be mistaken for the allocator refusing to grow.
        fn from_image_with_blocks(image: &[u8], blocks: usize) -> Self {
            let mut store = Self {
                image: vec![0; BLOCK_SIZE * blocks],
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

    /// Churn a volume and assert the physical high-water mark stops
    /// growing.
    ///
    /// This is the Scope D defect in one test: before reclaim, every
    /// create/delete cycle leaked both the data block and the whole
    /// copy-on-write metadata region, so a long-lived service hit
    /// `NoSpace` on a filesystem that was actually empty.
    #[test]
    fn repeated_create_delete_stops_growing_the_volume() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/keep.bin", b"keep").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image_with_blocks(seed.image(), 4096);
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let mut charged = Vec::new();
        for i in 0..14u32 {
            let name = alloc::format!("/churn{i}.bin");
            let Ok(handle) = fs.create_file_path(&name) else {
                assert!(false, "create should succeed on cycle {i}");
                return;
            };
            if fs.write_file_at(handle, 0, &[0xABu8; BLOCK_SIZE]).is_err() {
                assert!(false, "write should succeed on cycle {i}");
                return;
            }
            if let Err(e) = fs.publish_checkpoint() {
                assert!(false, "checkpoint should succeed on cycle {i}: {e:?}");
                return;
            }
            if fs.unlink_path(&name).is_err() {
                assert!(false, "unlink should succeed on cycle {i}");
                return;
            }
            if let Err(e) = fs.publish_checkpoint() {
                assert!(false, "checkpoint should succeed on cycle {i}: {e:?}");
                return;
            }
            let Ok(bytes) = fs.charged_physical_bytes() else {
                assert!(false, "charged bytes should be computable");
                return;
            };
            charged.push(bytes);
        }
        // The volume reaches a steady state: the checkpoint region
        // ping-pongs between reclaimed runs, so usage oscillates
        // within a fixed band instead of climbing. Assert the band
        // itself is bounded -- the last cycles must not exceed the
        // peak of the early ones.
        let early_peak = charged[..6].iter().copied().max().unwrap_or_default();
        let late_peak = charged[6..].iter().copied().max().unwrap_or_default();
        assert!(
            late_peak <= early_peak,
            "physical high-water kept growing across churn: {charged:?}"
        );
        // And the very last cycle must be nowhere near a monotonic
        // append: 14 cycles of an append-only allocator would charge
        // well past 3 MiB (measured before the fix).
        assert!(
            charged[13] < 1_000_000,
            "volume still grows roughly linearly with churn: {charged:?}"
        );
    }

    /// The blocks of a deleted file must actually come back, and the
    /// file that was left alone must survive the reuse.
    #[test]
    fn repeated_reads_of_one_file_are_served_from_the_page_cache() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/cached.bin", b"cache-me").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let Ok(handle) = fs.open_path("/cached.bin") else {
            assert!(false, "open should succeed");
            return;
        };
        let mut out = [0u8; 8];
        assert!(fs.read_file_at(handle, 0, &mut out).is_ok());
        let (hits_after_first, misses_after_first) = fs.page_cache_stats();
        assert_eq!(hits_after_first, 0, "first read cannot hit an empty cache");
        assert!(misses_after_first > 0, "first read must record a miss");
        for _ in 0..4 {
            assert!(fs.read_file_at(handle, 0, &mut out).is_ok());
            assert_eq!(&out, b"cache-me");
        }
        let (hits, misses) = fs.page_cache_stats();
        assert!(hits >= 4, "repeat reads should hit: hits={hits}");
        assert_eq!(
            misses, misses_after_first,
            "repeat reads must not go back to the device"
        );
    }

    #[test]
    fn overwriting_a_block_invalidates_its_cached_page() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/rw.bin", b"first-content").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let Ok(handle) = fs.open_path("/rw.bin") else {
            assert!(false, "open should succeed");
            return;
        };
        let mut out = [0u8; 13];
        assert!(fs.read_file_at(handle, 0, &mut out).is_ok());
        assert_eq!(&out, b"first-content");
        // Read-after-write correctness across checkpoints.
        //
        // Note this test does NOT fail if invalidation is removed:
        // copy-on-write hands each overwrite a fresh physical block,
        // and the extent record follows it, so the read never asks
        // for the stale key. The invalidation guarantee itself is
        // pinned by
        // `a_recycled_block_never_serves_the_previous_tenants_bytes`,
        // which was verified to fail with invalidation disabled.
        // This test guards the ordinary path: overwrite, publish,
        // read back.
        if fs.write_file_at(handle, 0, b"second-conten").is_err() {
            assert!(false, "overwrite should succeed");
            return;
        }
        // Publish, so the pre-overwrite block is retired into the
        // free pool. hxfs is copy-on-write: without a checkpoint the
        // overwrite lands on a fresh block and the stale cached page
        // is never consulted, which would make this test pass even
        // with invalidation removed.
        if fs.publish_checkpoint().is_err() {
            assert!(false, "checkpoint should succeed");
            return;
        }
        let mut after = [0u8; 13];
        assert!(fs.read_file_at(handle, 0, &mut after).is_ok());
        assert_eq!(
            &after, b"second-conten",
            "read after write must not be served from a stale cached page"
        );
        // Second cycle. The first overwrite retired the original
        // block into the pool, so this write is handed that block
        // back -- the same physical block whose *first* contents are
        // still in the cache from the very first read. This is the
        // case that actually exercises invalidation.
        if fs.write_file_at(handle, 0, b"third-content").is_err() {
            assert!(false, "second overwrite should succeed");
            return;
        }
        if fs.publish_checkpoint().is_err() {
            assert!(false, "checkpoint should succeed");
            return;
        }
        let mut third = [0u8; 13];
        assert!(fs.read_file_at(handle, 0, &mut third).is_ok());
        assert_eq!(
            &third, b"third-content",
            "a rewritten block must not serve its earlier cached contents"
        );
    }

    #[test]
    fn a_recycled_block_never_serves_the_previous_tenants_bytes() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/keep.bin", b"keep").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        // Churn: create a file, read it (populating the cache),
        // delete it, then create another. Reclaim hands the freed
        // block back out, so the new file lands on a block whose
        // plaintext the cache may still hold. Leaking it across the
        // free would be a confidentiality bug.
        let mut leaked = false;
        for i in 0..6u32 {
            let victim = alloc::format!("/secret{i}.bin");
            let Ok(handle) = fs.create_file_path(&victim) else {
                assert!(false, "create should succeed");
                return;
            };
            let secret = [0xA5u8; 64];
            if fs.write_file_at(handle, 0, &secret).is_err() {
                assert!(false, "write should succeed");
                return;
            }
            let mut sink = [0u8; 64];
            assert!(fs.read_file_at(handle, 0, &mut sink).is_ok());
            assert_eq!(sink, secret);
            if fs.unlink_path(&victim).is_err() {
                assert!(false, "unlink should succeed");
                return;
            }
            // Publish so the unlinked file's blocks leave quarantine
            // and re-enter the allocation pool; that is the only way
            // the successor can land on the victim's block.
            if fs.publish_checkpoint().is_err() {
                assert!(false, "checkpoint should succeed");
                return;
            }
            let successor = alloc::format!("/public{i}.bin");
            let Ok(next) = fs.create_file_path(&successor) else {
                assert!(false, "create should succeed");
                return;
            };
            let public = [0x11u8; 64];
            if fs.write_file_at(next, 0, &public).is_err() {
                assert!(false, "write should succeed");
                return;
            }
            let mut read_back = [0u8; 64];
            assert!(fs.read_file_at(next, 0, &mut read_back).is_ok());
            if read_back != public {
                leaked = true;
            }
        }
        assert!(
            !leaked,
            "a recycled block served stale plaintext from the page cache"
        );
    }

    #[test]
    fn deleted_blocks_are_handed_out_again_without_corrupting_live_data() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/keep.bin", b"keep").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let mut seen = Vec::new();
        for i in 0..8u32 {
            let name = alloc::format!("/reuse{i}.bin");
            let Ok(handle) = fs.create_file_path(&name) else {
                assert!(false, "create should succeed");
                return;
            };
            if fs.write_file_at(handle, 0, &[0x5Au8; BLOCK_SIZE]).is_err() {
                assert!(false, "write should succeed");
                return;
            }
            // Track only the churn file's own block. Collecting every
            // live extent would also pick up `/keep.bin` on every
            // cycle and make "a block repeated" trivially true even
            // with reclaim disabled.
            let mut index = 0usize;
            while index < fs.extents.len() {
                if let Some(entry) = fs.extents[index] {
                    if entry.object_id == handle.object_id
                        && entry.extent.flags & EXTENT_FLAG_HOLE == 0
                    {
                        seen.push(entry.extent.physical_block);
                    }
                }
                index += 1;
            }
            let _ = fs.publish_checkpoint();
            let _ = fs.unlink_path(&name);
            let _ = fs.publish_checkpoint();
        }
        // Some physical block must have been handed out more than
        // once; an append-only allocator never repeats.
        let mut repeated = false;
        let mut i = 0usize;
        while i < seen.len() && !repeated {
            let mut j = i + 1;
            while j < seen.len() {
                if seen[i] == seen[j] {
                    repeated = true;
                    break;
                }
                j += 1;
            }
            i += 1;
        }
        assert!(repeated, "no physical block was ever reused: {seen:?}");

        // And the untouched file still reads back correctly.
        let store = fs.into_store();
        let image: Vec<u8> = store.as_slice().to_vec();
        let reader = SliceBlockReader::new(&image);
        let Ok(mut ro) = Hxfs::mount(reader) else {
            assert!(false, "read-only mount should succeed after churn");
            return;
        };
        let Ok(kept) = ro.open_path("/keep.bin") else {
            assert!(false, "the untouched file was destroyed by reuse");
            return;
        };
        let mut out = [0u8; 8];
        assert_eq!(ro.read_file(kept, &mut out), Ok(4));
        assert_eq!(&out[..4], b"keep");
    }

    /// A block freed by the running transaction must not be reissued
    /// before its checkpoint is durable.
    ///
    /// This is what keeps `generation = sequence + 1` sound: if one
    /// checkpoint could both free and re-seal a block, both tenancies
    /// would derive the same GCM nonce.
    #[test]
    fn freed_blocks_are_quarantined_until_the_checkpoint_lands() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/keep.bin", b"keep").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let Ok(handle) = fs.create_file_path("/doomed.bin") else {
            assert!(false, "create should succeed");
            return;
        };
        if fs.write_file_at(handle, 0, &[0x11u8; BLOCK_SIZE]).is_err() {
            assert!(false, "write should succeed");
            return;
        }
        let _ = fs.publish_checkpoint();
        let before = fs.reclaimable_physical_bytes();
        if fs.unlink_path("/doomed.bin").is_err() {
            assert!(false, "unlink should succeed");
            return;
        }
        assert_eq!(
            fs.reclaimable_physical_bytes(),
            before,
            "a block freed by the open transaction must stay quarantined"
        );
        let _ = fs.publish_checkpoint();
        assert!(
            fs.reclaimable_physical_bytes() > before,
            "the checkpoint is durable, so the block must now be reusable"
        );
    }

    /// Reclaim must never lease out a block that a live extent still
    /// occupies, even though those blocks sit inside the retired
    /// checkpoint region.
    #[test]
    fn live_extents_are_excluded_from_the_retired_metadata_region() {
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        assert!(seed.create_file("/a.bin", b"aaaa").is_ok());
        assert!(seed.create_file("/b.bin", b"bbbb").is_ok());
        assert!(seed.commit().is_ok());
        let store = MemStore::from_image(seed.image());
        let Ok(mut fs) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "mount should succeed");
            return;
        };
        let _ = fs.publish_checkpoint();
        let _ = fs.publish_checkpoint();
        // Every reusable run must be disjoint from every live extent.
        let mut slot = 0usize;
        while slot < fs.free_space.len() {
            if let Some(range) = fs.free_space[slot] {
                let mut index = 0usize;
                while index < fs.extents.len() {
                    if let Some(entry) = fs.extents[index] {
                        if entry.extent.flags & EXTENT_FLAG_HOLE == 0 {
                            let live_start = entry.extent.physical_block;
                            let live_end =
                                live_start.saturating_add(u64::from(entry.extent.block_count));
                            let overlaps =
                                range.start_block < live_end && live_start < range.end_block();
                            assert!(
                                !overlaps,
                                "free run {range:?} overlaps live extent [{live_start},{live_end})"
                            );
                        }
                    }
                    index += 1;
                }
            }
            slot += 1;
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

    /// Regression: reading across a block boundary inside a
    /// multi-block extent used to panic with an out-of-range slice
    /// index instead of returning data.
    ///
    /// `HxfsWriter::create_file` emits ONE extent with
    /// `block_count = N` for any file larger than 4 KiB — the same
    /// shape `tools/hxfs-seed` and `mkhxfs.py` produce — so this is
    /// the layout a real seeded image has. The read path assumed a
    /// window never spanned more than one block, so an ordinary
    /// unprivileged `read_at` crashed the filesystem service.
    #[test]
    fn read_file_at_spans_multi_block_extents() {
        const FILE_BYTES: usize = BLOCK_SIZE * 3;
        let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        // A recognisable pattern so a mis-copied block is visible.
        let mut payload = vec![0u8; FILE_BYTES];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        assert!(seed.create_file("/big.bin", &payload).is_ok());
        // The writer stages nodes in memory; commit lays the single
        // multi-block extent down into the image.
        assert!(seed.commit().is_ok());

        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.open_path("/big.bin") else {
            assert!(false, "seeded file should open");
            return;
        };

        // Whole-file read: the window covers all three blocks.
        let mut out = vec![0u8; FILE_BYTES];
        assert_eq!(mounted.read_file_at(file, 0, &mut out), Ok(FILE_BYTES));
        assert_eq!(out, payload, "full read must reproduce the file");

        // Unaligned read straddling two block boundaries.
        let offset = (BLOCK_SIZE - 100) as u64;
        let len = BLOCK_SIZE + 200;
        let mut partial = vec![0u8; len];
        assert_eq!(mounted.read_file_at(file, offset, &mut partial), Ok(len));
        assert_eq!(
            partial,
            payload[offset as usize..offset as usize + len],
            "unaligned cross-block read must reproduce the file"
        );

        // A read starting inside the last block still terminates at
        // the file's real end.
        let tail_offset = (BLOCK_SIZE * 2 + 4000) as u64;
        let mut tail = vec![0u8; BLOCK_SIZE];
        let expected_tail = FILE_BYTES - tail_offset as usize;
        assert_eq!(
            mounted.read_file_at(file, tail_offset, &mut tail),
            Ok(expected_tail)
        );
        assert_eq!(&tail[..expected_tail], &payload[tail_offset as usize..]);
    }

    /// Regression: truncation must release the extents it orphans
    /// and keep `record_count` consistent with the extent table.
    #[test]
    fn truncate_releases_extents_and_updates_record_count() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/trunc.bin") else {
            assert!(false, "file should be created");
            return;
        };

        // Three separate single-block extents.
        let block = [0x11u8; BLOCK_SIZE];
        let mut handle = file;
        for index in 0..3u64 {
            match mounted.write_file_at(handle, index * BLOCK_SIZE_U64, &block) {
                Ok(next) => handle = next,
                Err(error) => {
                    assert!(false, "write {index} failed: {error:?}");
                    return;
                }
            }
        }
        let full_usage = mounted.committed_physical_bytes();

        // Truncate to one block: the last two extents are orphaned.
        let Ok(handle) = mounted.truncate_file(handle, BLOCK_SIZE_U64) else {
            assert!(false, "truncate should succeed");
            return;
        };

        assert!(
            mounted.committed_physical_bytes() < full_usage,
            "truncation must release the blocks it orphans"
        );

        let Ok(object) = mounted.object(handle.object_id) else {
            assert!(false, "object should still exist");
            return;
        };
        assert_eq!(object.descriptor.size, BLOCK_SIZE_U64);
        assert_eq!(
            u64::from(object.descriptor.record_count),
            1,
            "record_count must match the surviving extent count"
        );

        // The surviving data is still readable.
        let mut out = [0u8; BLOCK_SIZE];
        assert_eq!(mounted.read_file_at(handle, 0, &mut out), Ok(BLOCK_SIZE));
        assert_eq!(out, block);
    }

    /// Regression: rewriting a file in place must not inflate the
    /// volume's reported physical usage.
    ///
    /// `committed_physical_bytes` used to be derived from the
    /// monotonic `next_lba`, so each overwrite charged the volume
    /// again for space the file had released. A quota'd volume
    /// eventually rejected writes that fit.
    #[test]
    fn in_place_rewrite_does_not_inflate_physical_usage() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/rewrite.bin") else {
            assert!(false, "file should be created");
            return;
        };

        let payload = [0xa5u8; 1024];
        let Ok(file) = mounted.write_file_at(file, 0, &payload) else {
            assert!(false, "first write should succeed");
            return;
        };
        let after_first = mounted.committed_physical_bytes();

        // Rewrite the same file many times. Usage must stay flat:
        // each rewrite drops the old extent and adds one of equal
        // size.
        let mut handle = file;
        for round in 0..32 {
            match mounted.write_file_at(handle, 0, &payload) {
                Ok(next) => handle = next,
                Err(error) => {
                    assert!(false, "rewrite {round} failed: {error:?}");
                    return;
                }
            }
        }
        assert_eq!(
            mounted.committed_physical_bytes(),
            after_first,
            "in-place rewrite must not grow reported physical usage"
        );
    }

    /// A volume whose quota exactly fits one copy of a file must
    /// still accept rewriting that file.
    #[test]
    fn rewrite_is_allowed_at_exact_quota() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/tight.bin") else {
            assert!(false, "file should be created");
            return;
        };
        let payload = [0x5au8; 2048];
        let Ok(file) = mounted.write_file_at(file, 0, &payload) else {
            assert!(false, "first write should succeed");
            return;
        };

        // Pin the byte quota to exactly what the volume now uses.
        // The object limit stays generous: this test is about the
        // physical-bytes charge, and a zero object limit would be
        // breached by the objects that already exist.
        let used = mounted.committed_physical_bytes();
        assert!(mounted.set_quota_limits(used, u64::MAX).is_ok());

        // Rewriting the same bytes needs no additional space: the
        // old extent is released before the new one is charged.
        assert!(
            mounted.write_file_at(file, 0, &payload).is_ok(),
            "rewrite at exact quota must be admitted"
        );
    }

    /// A job that writes and deletes its own files in a loop must
    /// not march towards its physical limit.
    ///
    /// `check_job_quota` only ever added to `physical_used_bytes`;
    /// nothing subtracted when `clear_extents` dropped the blocks.
    /// A long-lived job doing write/delete churn was therefore
    /// eventually refused writes on a volume that was in fact empty.
    /// Mirrors the on-target quota probe in hxfs-service: pin the
    /// volume limit one block above current usage, then write two
    /// 4 KiB blocks to the same file. The first must be admitted and
    /// the second refused.
    ///
    /// The NVMe soak asserts this as `[hxfs] quota-enforced-ok`.
    #[test]
    fn volume_quota_refuses_the_block_past_the_limit() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };

        let base = mounted.committed_physical_bytes();
        assert!(mounted.set_quota_limits(base + 4096, 0).is_ok());

        let root = mounted.root_directory();
        let Ok(file) = mounted.create_file_child(root, "probe-quota.bin") else {
            assert!(false, "create must succeed");
            return;
        };
        let chunk = [0x42u8; 4096];
        let first = mounted.write_file_at(file, 0, &chunk);
        assert!(first.is_ok(), "first block must fit: {first:?}");
        let Ok(file) = first else { return };

        let second = mounted.write_file_at(file, 4096, &chunk);
        assert!(
            matches!(
                second,
                Err(HxfsError::QuotaExceeded) | Err(HxfsError::NoSpace)
            ),
            "second block must breach the quota, got {second:?}"
        );
    }

    #[test]
    fn job_quota_is_credited_when_extents_are_released() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };

        const JOB: u64 = 7;
        // Room for a handful of blocks, far less than the churn below
        // would accumulate if releases were not credited.
        assert!(mounted.set_job_quota(JOB, 64 * 1024, u64::MAX).is_ok());
        mounted.set_active_job(Some(JOB));

        let payload = [0xa5u8; 4096];
        let mut round = 0;
        while round < 24 {
            let Ok(handle) = mounted.create_file_path("/churn.bin") else {
                assert!(false, "create must succeed on round {round}");
                return;
            };
            let written = mounted.write_file_at(handle, 0, &payload);
            assert!(written.is_ok(), "write must succeed on round {round}");
            assert!(
                mounted.unlink_path("/churn.bin").is_ok(),
                "unlink must succeed on round {round}"
            );
            round += 1;
        }

        // After deleting everything it wrote, the job's charge must be
        // back to zero rather than 24 blocks' worth.
        let (used, _objects) = mounted.job_quota_usage(JOB);
        assert_eq!(used, 0, "released extents must be credited back");
    }

    /// Truncation frees media, so it must credit the job quota too.
    #[test]
    fn job_quota_is_credited_on_truncate() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };

        const JOB: u64 = 11;
        assert!(mounted.set_job_quota(JOB, 0, u64::MAX).is_ok());
        mounted.set_active_job(Some(JOB));

        let Ok(handle) = mounted.create_file_path("/big.bin") else {
            assert!(false, "create must succeed");
            return;
        };
        // `write_file_at` takes at most one block per call, so build
        // a three-block file by appending.
        let payload = [0x5au8; 4096];
        let mut handle = handle;
        let mut block = 0u64;
        while block < 3 {
            let Ok(next) = mounted.write_file_at(handle, block * 4096, &payload) else {
                assert!(false, "write of block {block} must succeed");
                return;
            };
            handle = next;
            block += 1;
        }
        let (before, _) = mounted.job_quota_usage(JOB);
        assert!(before > 0, "a written file must charge the job");

        assert!(mounted.truncate_file(handle, 0).is_ok());
        let (after, _) = mounted.job_quota_usage(JOB);
        assert!(
            after < before,
            "truncation must return bytes to the job quota ({before} -> {after})"
        );
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
        // Physical quota: pin the limit to the volume's live usage
        // after one file has been written, then confirm a write that
        // genuinely adds blocks is refused.
        //
        // The limit is taken from `committed_physical_bytes` — the
        // same live-extent metric quota enforcement uses. It used to
        // be taken from `charged_physical_bytes` (the monotonic
        // append high-water mark); the two agreed only because usage
        // never went down, which was the quota-leak bug.
        let first = mounted.create_file_path("/file");
        assert!(first.is_ok());
        let Ok(first) = first else { return };
        assert!(mounted.write_file_at(first, 0, b"payload").is_ok());

        let limit = mounted.committed_physical_bytes();
        assert!(limit > 0, "a written file must consume physical bytes");
        assert!(mounted.set_quota_limits(limit, 0).is_ok());

        let second = mounted.create_file_path("/file2");
        assert!(second.is_ok());
        let Ok(second) = second else { return };
        // Either quota gate may fire first: `check_volume_quota`
        // reports `QuotaExceeded` and the allocator-level
        // `quota_admits` reports `NoSpace`. Both mean refused.
        assert!(
            matches!(
                mounted.write_file_at(second, 0, b"x"),
                Err(HxfsError::NoSpace) | Err(HxfsError::QuotaExceeded)
            ),
            "a write that adds blocks past the limit must be refused"
        );
    }

    /// A snapshot is a second owner of every extent live when it was
    /// taken. Unlinking the file drops the live reference, but the
    /// blocks must NOT return to the allocator: the snapshot still
    /// reads through them, and reissuing them would make it return
    /// whatever overwrote its data.
    #[test]
    fn snapshot_pinned_blocks_are_not_reclaimed_on_unlink() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/pinned") else {
            assert!(false, "file should be created");
            return;
        };
        assert!(mounted
            .write_file_at(file, 0, b"snapshot-visible-payload")
            .is_ok());
        assert!(mounted.publish_checkpoint().is_ok());

        let pinned = mounted.live_extent_ranges();
        assert!(!pinned.is_empty(), "the written file must own extents");
        assert!(mounted.retain_extents_for_snapshot().is_ok());

        assert!(mounted.unlink_path("/pinned").is_ok());
        assert!(mounted.publish_checkpoint().is_ok());
        for (start, count) in pinned.iter().copied() {
            assert!(
                !mounted.range_is_reclaimable(start, count),
                "blocks a live snapshot still reads must not become reusable"
            );
        }

        // Deleting the snapshot drops the last reference, and the
        // space the snapshot was holding finally comes back.
        let Ok(released) = mounted.release_extents_for_snapshot(&pinned) else {
            assert!(false, "snapshot release should succeed");
            return;
        };
        assert!(released > 0, "the deleted snapshot must release extents");
        assert!(mounted.publish_checkpoint().is_ok());
        for (start, count) in pinned.iter().copied() {
            assert!(
                mounted.range_is_reclaimable(start, count),
                "deleting the last snapshot must reclaim its blocks"
            );
        }
    }

    /// Deleting a snapshot must not free blocks the live tree still
    /// owns. The refcount, not the deletion, decides.
    #[test]
    fn snapshot_deletion_keeps_blocks_the_live_tree_still_owns() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/kept") else {
            assert!(false, "file should be created");
            return;
        };
        assert!(mounted.write_file_at(file, 0, b"still-referenced").is_ok());
        assert!(mounted.publish_checkpoint().is_ok());

        let pinned = mounted.live_extent_ranges();
        assert!(mounted.retain_extents_for_snapshot().is_ok());

        // The file is never unlinked, so releasing the snapshot must
        // reclaim nothing at all.
        let Ok(released) = mounted.release_extents_for_snapshot(&pinned) else {
            assert!(false, "snapshot release should succeed");
            return;
        };
        assert_eq!(released, 0, "a live file's blocks must not be released");
        assert!(mounted.publish_checkpoint().is_ok());
        for (start, count) in pinned.iter().copied() {
            assert!(!mounted.range_is_reclaimable(start, count));
        }
        // And the data is still readable.
        let mut buffer = [0u8; 32];
        let Ok(read) = mounted.read_file_at(file, 0, &mut buffer) else {
            assert!(false, "the live file must still be readable");
            return;
        };
        assert_eq!(&buffer[..read], b"still-referenced");
    }

    /// Two snapshots over the same extent need two releases. If one
    /// deletion freed the blocks, the surviving snapshot would read
    /// reissued space.
    #[test]
    fn blocks_are_reclaimed_only_after_the_last_snapshot_is_deleted() {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "seed writer should initialize");
            return;
        };
        let store = MemStore::from_image(seed.image());
        let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
            assert!(false, "fixed writer should mount");
            return;
        };
        let Ok(file) = mounted.create_file_path("/twice") else {
            assert!(false, "file should be created");
            return;
        };
        assert!(mounted.write_file_at(file, 0, b"two-snapshots").is_ok());
        assert!(mounted.publish_checkpoint().is_ok());

        let pinned = mounted.live_extent_ranges();
        assert!(mounted.retain_extents_for_snapshot().is_ok());
        assert!(mounted.retain_extents_for_snapshot().is_ok());

        assert!(mounted.unlink_path("/twice").is_ok());
        assert!(mounted.publish_checkpoint().is_ok());

        // First snapshot deleted: one reference remains.
        let Ok(released) = mounted.release_extents_for_snapshot(&pinned) else {
            assert!(false, "first release should succeed");
            return;
        };
        assert_eq!(released, 0, "one surviving snapshot must hold the blocks");
        assert!(mounted.publish_checkpoint().is_ok());
        for (start, count) in pinned.iter().copied() {
            assert!(!mounted.range_is_reclaimable(start, count));
        }

        // Second deleted: the last reference goes, the space returns.
        let Ok(released) = mounted.release_extents_for_snapshot(&pinned) else {
            assert!(false, "second release should succeed");
            return;
        };
        assert!(released > 0, "the last deletion must release the extents");
        assert!(mounted.publish_checkpoint().is_ok());
        for (start, count) in pinned.iter().copied() {
            assert!(mounted.range_is_reclaimable(start, count));
        }
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

#[cfg(feature = "hxblob")]
/// Stage F: SHA-256 of `data` (content hash for Hxblob).
fn sha256(data: &[u8]) -> BlobHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

#[cfg(feature = "hxblob")]
/// Stage F: lowercase hex encoding (used for blob file names).
fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Stage E (Phase-2): synthetic UUID for a job id (job id in the
/// first 8 bytes, rest zero).
fn job_uuid(job_id: u64) -> crate::format::Uuid {
    let mut uuid = [0u8; 16];
    uuid[..8].copy_from_slice(&job_id.to_le_bytes());
    uuid
}
