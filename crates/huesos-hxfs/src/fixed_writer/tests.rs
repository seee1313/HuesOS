use super::*;
use crate::reader::{BlockReader, SliceBlockReader};
#[cfg(feature = "hxblob")]
use crate::recovery::{replay_journal, ReplayOutcome};
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

/// Store that simulates power loss immediately before the final clean
/// superblock is republished.
///
/// `publish_checkpoint` writes LBA 0 twice: first as the durable
/// RECOVERING root, then as the clean commit point. Refusing the second
/// write leaves the exact image that a power cut after the RECOVERING flush
/// would leave.
struct FailFinalSuperblockStore {
    inner: MemStore,
    lba_zero_writes: u32,
}

impl FailFinalSuperblockStore {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            lba_zero_writes: 0,
        }
    }
}

impl BlockReader for FailFinalSuperblockStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.inner.read_blocks(lba, blocks, out)
    }
}

impl BlockStore for FailFinalSuperblockStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        if lba == 0 {
            self.lba_zero_writes = self.lba_zero_writes.saturating_add(1);
            if self.lba_zero_writes == 2 {
                return Err(HxfsError::Io);
            }
        }
        self.inner.write_blocks(lba, blocks, input)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.inner.flush()
    }
}

/// Records every superblock state submitted to LBA 0 during a
/// checkpoint. The initial image is installed before this wrapper is
/// created, so the trace contains publication writes only.
struct RootTraceStore {
    inner: MemStore,
    root_states: Vec<u32>,
}

impl RootTraceStore {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            root_states: Vec::new(),
        }
    }
}

impl BlockReader for RootTraceStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.inner.read_blocks(lba, blocks, out)
    }
}

impl BlockStore for RootTraceStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        if lba == 0 && blocks == 1 {
            let state_offset = HEADER_BYTES + 112;
            let state = input
                .get(state_offset..state_offset + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(HxfsError::BadBlock)?;
            self.root_states.push(state);
        }
        self.inner.write_blocks(lba, blocks, input)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.inner.flush()
    }
}

/// Fails before one selected checkpoint write/flush operation. Writes that
/// completed before the failure remain visible, modelling the strongest
/// persistence case; recovery must still produce a complete old or new
/// state rather than a mixture.
struct CrashStore {
    inner: MemStore,
    fail_at: Option<usize>,
    operation: usize,
}

impl CrashStore {
    fn new(inner: MemStore) -> Self {
        Self {
            inner,
            fail_at: None,
            operation: 0,
        }
    }

    fn arm(&mut self, fail_at: Option<usize>) {
        self.fail_at = fail_at;
        self.operation = 0;
    }

    fn before_operation(&mut self) -> FixedResult<()> {
        let current = self.operation;
        self.operation = self.operation.saturating_add(1);
        if self.fail_at == Some(current) {
            Err(HxfsError::Io)
        } else {
            Ok(())
        }
    }
}

impl BlockReader for CrashStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.inner.read_blocks(lba, blocks, out)
    }
}

impl BlockStore for CrashStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        self.before_operation()?;
        self.inner.write_blocks(lba, blocks, input)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.before_operation()?;
        self.inner.flush()
    }
}

#[test]
fn checkpoint_publishes_recovering_before_the_new_clean_root() {
    let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    let store = RootTraceStore::new(MemStore::from_image_with_blocks(seed.image(), 4096));
    let Ok(mut fs) = FixedHxfsWriter::<RootTraceStore, 16, 32, 32>::mount(store) else {
        assert!(false, "fixed writer should mount");
        return;
    };
    let Ok(file) = fs.create_file_path("/atomic.bin") else {
        assert!(false, "file creation should succeed");
        return;
    };
    assert!(fs.write_file_at(file, 0, b"new state").is_ok());
    assert!(fs.publish_checkpoint().is_ok());
    let store = fs.into_store();
    assert_eq!(
        store.root_states.as_slice(),
        &[ROOT_STATE_RECOVERING, ROOT_STATE_CLEAN],
        "the old clean root must remain authoritative until RECOVERING is published"
    );
}

#[test]
fn every_checkpoint_operation_failure_recovers_one_complete_version() {
    fn execute(
        image: &[u8],
        fail_at: Option<usize>,
    ) -> FixedResult<(FixedResult<u64>, CrashStore)> {
        let store = CrashStore::new(MemStore::from_image_with_blocks(image, 4096));
        let mut fs = FixedHxfsWriter::<CrashStore, 16, 32, 64>::mount(store)?;
        let state = fs.open_path("/state.bin")?;
        let _ = fs.write_file_at(state, 0, b"new-state")?;
        fs.unlink_path("/delete.bin")?;
        let created = fs.create_file_path("/new.bin")?;
        let _ = fs.write_file_at(created, 0, b"created")?;
        fs.store_mut().arm(fail_at);
        let result = fs.publish_checkpoint();
        Ok((result, fs.into_store()))
    }

    fn read_path(fs: &mut FixedHxfsWriter<MemStore, 16, 32, 64>, path: &str) -> Option<Vec<u8>> {
        let file = fs.open_path(path).ok()?;
        let mut buffer = [0u8; 32];
        let read = fs.read_file_at(file, 0, &mut buffer).ok()?;
        Some(buffer[..read].to_vec())
    }

    fn inspect(mut store: MemStore) -> FixedResult<(u32, u64, bool, bool)> {
        let root_before_recovery = read_superblock(&mut store, 0)?;
        if root_before_recovery.root_state == ROOT_STATE_RECOVERING {
            let _ = crate::recovery::replay_journal(&mut store)?;
        }
        let mut fs = FixedHxfsWriter::<MemStore, 16, 32, 64>::mount(store)?;
        let keep = read_path(&mut fs, "/keep.bin");
        let state = read_path(&mut fs, "/state.bin");
        let deleted = read_path(&mut fs, "/delete.bin");
        let created = read_path(&mut fs, "/new.bin");
        let stable_ok = keep.as_deref() == Some(b"stable".as_slice());
        let old = stable_ok
            && state.as_deref() == Some(b"old-state".as_slice())
            && deleted.as_deref() == Some(b"delete-me".as_slice())
            && created.is_none();
        let new = stable_ok
            && state.as_deref() == Some(b"new-state".as_slice())
            && deleted.is_none()
            && created.as_deref() == Some(b"created".as_slice());
        Ok((
            root_before_recovery.root_state,
            root_before_recovery.sequence_number,
            old,
            new,
        ))
    }

    let Ok(mut seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    assert!(seed.create_file("/keep.bin", b"stable").is_ok());
    assert!(seed.create_file("/state.bin", b"old-state").is_ok());
    assert!(seed.create_file("/delete.bin", b"delete-me").is_ok());
    assert!(seed.commit().is_ok());
    let image = seed.image().to_vec();
    let mut initial_store = MemStore::from_image_with_blocks(&image, 4096);
    let Ok(initial_root) = read_superblock(&mut initial_store, 0) else {
        assert!(false, "initial root should decode");
        return;
    };

    let Ok((successful, successful_store)) = execute(&image, None) else {
        assert!(false, "successful checkpoint setup should run");
        return;
    };
    assert!(successful.is_ok());
    let operation_count = successful_store.operation;
    let Ok((state, sequence, old, new)) = inspect(successful_store.inner) else {
        assert!(false, "successful checkpoint should inspect");
        return;
    };
    assert_eq!(state, ROOT_STATE_CLEAN);
    assert_eq!(sequence, initial_root.sequence_number + 1);
    assert!(!old && new, "successful checkpoint must publish only B");

    for fail_at in 0..operation_count {
        let Ok((result, failed_store)) = execute(&image, Some(fail_at)) else {
            assert!(false, "checkpoint setup failed at operation {fail_at}");
            return;
        };
        assert_eq!(
            result,
            Err(HxfsError::Io),
            "operation {fail_at} was not reached"
        );
        let Ok((root_state, sequence, old, new)) = inspect(failed_store.inner) else {
            assert!(false, "failure {fail_at} left an unrecoverable image");
            return;
        };
        assert!(
            old ^ new,
            "failure {fail_at} produced a mixed state: old={old} new={new}"
        );
        if root_state == ROOT_STATE_CLEAN && sequence == initial_root.sequence_number {
            assert!(old, "old clean root must expose A at failure {fail_at}");
        } else {
            assert!(
                new,
                "RECOVERING/new clean root must converge to B at failure {fail_at}"
            );
        }
    }
}

#[test]
fn legacy_v5_is_read_only_until_explicit_migration() {
    let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    let mut image = seed.image().to_vec();
    // Downgrade the empty fixture's root-store version and feature bit.
    // It has no versioned extents, so this is a valid minimal v5 image.
    image[56..60].copy_from_slice(&LEGACY_FORMAT_VERSION.to_le_bytes());
    image[60..64].copy_from_slice(&LEGACY_TYPE_SYSTEM_VERSION.to_le_bytes());
    let legacy_features =
        BASE_INCOMPAT_FEATURES & !FEATURE_INCOMPAT_V6_POLICY_TABLES_AND_GENERATION;
    image[144..152].copy_from_slice(&legacy_features.to_le_bytes());
    image[32..36].fill(0);
    let crc = metadata_crc32c(&image[..BLOCK_SIZE]);
    image[32..36].copy_from_slice(&crc.to_le_bytes());

    let store = MemStore::from_image(&image);
    let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 64>::mount(store) else {
        assert!(false, "legacy image should mount for compatibility");
        return;
    };
    assert!(mounted.is_legacy_read_only());
    assert_eq!(
        mounted.create_file_path("/forbidden"),
        Err(HxfsError::LegacyReadOnly)
    );
    assert!(mounted.migrate_legacy_to_v6(&[], &[]).is_ok());
    assert!(!mounted.is_legacy_read_only());
    assert_eq!(mounted.superblock().format_version, FORMAT_VERSION);
    assert_ne!(mounted.checkpoint().encryption_policy_tree_lba, 0);
    assert_ne!(mounted.checkpoint().compression_policy_tree_lba, 0);

    let migrated = mounted.into_store();
    let reader = SliceBlockReader::new(migrated.as_slice());
    assert!(Hxfs::mount_from_disk(reader, None).is_ok());
}

#[test]
fn every_migration_write_and_flush_recovers_complete_v5_or_v6() {
    fn legacy_image() -> Vec<u8> {
        let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
            return Vec::new();
        };
        let mut image = seed.image().to_vec();
        image[56..60].copy_from_slice(&LEGACY_FORMAT_VERSION.to_le_bytes());
        image[60..64].copy_from_slice(&LEGACY_TYPE_SYSTEM_VERSION.to_le_bytes());
        let features = BASE_INCOMPAT_FEATURES & !FEATURE_INCOMPAT_V6_POLICY_TABLES_AND_GENERATION;
        image[144..152].copy_from_slice(&features.to_le_bytes());
        image[32..36].fill(0);
        let crc = metadata_crc32c(&image[..BLOCK_SIZE]);
        image[32..36].copy_from_slice(&crc.to_le_bytes());
        image
    }

    fn execute(
        image: &[u8],
        fail_at: Option<usize>,
    ) -> FixedResult<(FixedResult<u64>, CrashStore)> {
        let store = CrashStore::new(MemStore::from_image_with_blocks(image, 4096));
        let mut fs = FixedHxfsWriter::<CrashStore, 16, 32, 64>::mount(store)?;
        fs.store_mut().arm(fail_at);
        let result = fs.migrate_legacy_to_v6(&[], &[]);
        Ok((result, fs.into_store()))
    }

    fn inspect(mut store: MemStore) -> FixedResult<(bool, bool)> {
        let root = read_superblock(&mut store, 0)?;
        if root.root_state == ROOT_STATE_RECOVERING {
            let _ = crate::recovery::replay_journal(&mut store)?;
        }
        let root = read_superblock(&mut store, 0)?;
        let old = root.format_version == LEGACY_FORMAT_VERSION
            && FixedHxfsWriter::<MemStore, 16, 32, 64>::mount(MemStore::from_image_with_blocks(
                store.as_slice(),
                4096,
            ))
            .is_ok_and(|fs| fs.is_legacy_read_only());
        let new = root.format_version == FORMAT_VERSION
            && Hxfs::mount_from_disk(SliceBlockReader::new(store.as_slice()), None).is_ok();
        Ok((old, new))
    }

    let image = legacy_image();
    assert!(!image.is_empty());
    let Ok((success, successful_store)) = execute(&image, None) else {
        assert!(false, "successful migration setup must run");
        return;
    };
    assert!(success.is_ok());
    let operation_count = successful_store.operation;
    let Ok((old, new)) = inspect(successful_store.inner) else {
        assert!(false, "successful migration must inspect");
        return;
    };
    assert!(!old && new);

    for fail_at in 0..operation_count {
        let Ok((result, failed_store)) = execute(&image, Some(fail_at)) else {
            assert!(false, "migration setup failed at operation {fail_at}");
            return;
        };
        assert_eq!(result, Err(HxfsError::Io));
        let Ok((old, new)) = inspect(failed_store.inner) else {
            assert!(false, "migration failure {fail_at} was unrecoverable");
            return;
        };
        assert!(
            old ^ new,
            "migration failure {fail_at} exposed mixed v5/v6 state"
        );
    }
}

#[test]
fn transaction_shape_accounts_for_optional_hxblob_targets() {
    let Ok(base) = TransactionShape::plan(3, 4, 5, false) else {
        assert!(false, "base shape should be representable");
        return;
    };
    assert_eq!(
        base,
        TransactionShape {
            target_blocks: 16,
            record_count: 13,
            total_blocks: 42,
        }
    );

    let Ok(hxblob) = TransactionShape::plan(3, 4, 5, true) else {
        assert!(false, "Hxblob shape should be representable");
        return;
    };
    assert_eq!(
        hxblob,
        TransactionShape {
            target_blocks: 23,
            record_count: 15,
            total_blocks: 53,
        }
    );
    assert_eq!(hxblob.record_count - base.record_count, 2);
    assert_eq!(hxblob.target_blocks - base.target_blocks, 7);
}

#[test]
fn journal_cursor_reserves_the_declared_last_record_for_final() {
    let mut journal = JournalCursor::new(3);
    assert_eq!(journal.final_record(), Err(HxfsError::BadJournal));
    assert_eq!(journal.regular(), Ok(0));
    assert_eq!(journal.regular(), Ok(1));
    assert_eq!(journal.regular(), Err(HxfsError::BadJournal));
    assert_eq!(journal.final_record(), Ok(2));
    assert_eq!(journal.finish(), Ok(()));
}

#[test]
fn plain_checkpoint_replays_after_recovering_root_power_loss() {
    let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    let backing = MemStore::from_image_with_blocks(seed.image(), 4096);
    let store = FailFinalSuperblockStore::new(backing);
    let Ok(mut fs) = FixedHxfsWriter::<FailFinalSuperblockStore, 16, 32, 32>::mount(store) else {
        assert!(false, "fixed writer should mount");
        return;
    };
    let Ok(file) = fs.create_file_path("/replay.bin") else {
        assert!(false, "file creation should succeed");
        return;
    };
    let payload = b"plain journal replay payload";
    assert!(fs.write_file_at(file, 0, payload).is_ok());

    assert_eq!(fs.publish_checkpoint(), Err(HxfsError::Io));
    let failed_store = fs.into_store();
    assert_eq!(failed_store.lba_zero_writes, 2);
    let mut store = failed_store.inner;
    let Ok(recovering) = read_superblock(&mut store, 0) else {
        assert!(false, "the durable recovering root should decode");
        return;
    };
    assert_eq!(recovering.root_state, ROOT_STATE_RECOVERING);
    assert!(matches!(
        crate::recovery::replay_journal(&mut store),
        Ok(crate::recovery::ReplayOutcome::Replayed { .. })
    ));

    let Ok(mut remounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
        assert!(false, "recovered volume should remount");
        return;
    };
    let Ok(file) = remounted.open_path("/replay.bin") else {
        assert!(false, "recovered file should exist");
        return;
    };
    let mut read_back = [0u8; 32];
    let Ok(read) = remounted.read_file_at(file, 0, &mut read_back) else {
        assert!(false, "recovered file should be readable");
        return;
    };
    assert_eq!(&read_back[..read], payload);
}

/// An Hxblob-enabled checkpoint must replay after power is lost with the
/// durable root in RECOVERING state.
///
/// Hxblob adds two journaled targets (the index and Merkle blocks). A
/// historical hand-maintained record count omitted both, so replay treated
/// the Merkle record as the declared final record and rejected it because
/// it did not carry FINAL_SUPERBLOCK. A normal clean checkpoint still
/// mounted, which is why ordinary round-trip tests did not expose the bug.
#[cfg(feature = "hxblob")]
#[test]
fn hxblob_checkpoint_replays_after_recovering_root_power_loss() {
    let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    let backing = MemStore::from_image_with_blocks(seed.image(), 4096);
    let store = FailFinalSuperblockStore::new(backing);
    let Ok(mut fs) = FixedHxfsWriter::<FailFinalSuperblockStore, 64, 128, 256>::mount(store) else {
        assert!(false, "fixed writer should mount");
        return;
    };
    // Cross the single-block Hxblob-index capacity so recovery also
    // covers the index root + leaf layout, not only an empty-leaf tree.
    let mut expected = [0u8; 16];
    let mut final_hash = None;
    let mut blob_index = 0usize;
    while blob_index <= HXBLOB_LEAF_RECORDS {
        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(&(blob_index as u64).to_le_bytes());
        payload[8..].copy_from_slice(b"hxreplay");
        let Ok(hash) = fs.put_blob(&payload) else {
            assert!(false, "blob {blob_index} creation should succeed");
            return;
        };
        if blob_index == HXBLOB_LEAF_RECORDS {
            expected = payload;
            final_hash = Some(hash);
        }
        blob_index += 1;
    }
    let Some(hash) = final_hash else {
        assert!(false, "the final blob hash should be recorded");
        return;
    };

    assert_eq!(
        fs.publish_checkpoint(),
        Err(HxfsError::Io),
        "the fault store must cut power before the final clean root"
    );
    let failed_store = fs.into_store();
    assert_eq!(failed_store.lba_zero_writes, 2);
    let mut store = failed_store.inner;
    let Ok(recovering) = read_superblock(&mut store, 0) else {
        assert!(false, "the durable recovering root should decode");
        return;
    };
    assert_eq!(recovering.root_state, ROOT_STATE_RECOVERING);

    let replay = replay_journal(&mut store);
    assert!(
        matches!(replay, Ok(ReplayOutcome::Replayed { .. })),
        "Hxblob journal must replay, got {replay:?}"
    );

    let Ok(mut remounted) = FixedHxfsWriter::<MemStore, 64, 128, 256>::mount(store) else {
        assert!(false, "recovered Hxblob volume should remount");
        return;
    };
    let Ok(read_back) = remounted.get_blob(&hash) else {
        assert!(false, "recovered blob should be readable");
        return;
    };
    assert_eq!(read_back.as_slice(), expected.as_slice());
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
                if entry.object_id == handle.object_id && entry.extent.flags & EXTENT_FLAG_HOLE == 0
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

/// The full tree scrub must cover every checkpoint root, not just
/// the four storage trees it started with. A corrupt policy or
/// index root is invisible to an object walk: reads served from
/// cache still succeed, and the volume looks healthy right up to
/// the first cold read.
#[test]
fn tree_scrub_reports_a_corrupt_non_storage_root() {
    let Ok(seed) = HxfsWriter::new(INSTANCE, VOLUME) else {
        assert!(false, "seed writer should initialize");
        return;
    };
    let store = MemStore::from_image(seed.image());
    let Ok(mut mounted) = FixedHxfsWriter::<MemStore, 16, 32, 32>::mount(store) else {
        assert!(false, "fixed writer should mount");
        return;
    };
    let Ok(file) = mounted.create_file_path("/data") else {
        assert!(false, "file should be created");
        return;
    };
    assert!(mounted.write_file_at(file, 0, b"payload").is_ok());
    assert!(mounted.publish_checkpoint().is_ok());

    let Ok((_, errors)) = mounted.scrub_all() else {
        assert!(false, "the tree scrub should run");
        return;
    };
    assert_eq!(errors, 0, "a freshly published volume must scrub clean");

    // Point a non-storage root at a block that is not the tree it
    // claims to be. Before every root was walked this scrubbed
    // clean, which is the failure this test exists to prevent.
    let victim = mounted.checkpoint.quota_tree_lba;
    assert!(victim != 0, "the volume must have a quota root to corrupt");
    mounted.checkpoint.encryption_policy_tree_lba = victim;

    let Ok((_, errors)) = mounted.scrub_all() else {
        assert!(false, "the tree scrub should run");
        return;
    };
    assert!(
        errors > 0,
        "a root that does not decode as its declared tree must be reported"
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
