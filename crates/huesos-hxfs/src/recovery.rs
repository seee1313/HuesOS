//! Hxfs journal replay and recovery helpers.
//!
//! The replay model is deliberately idempotent: a recovering root-store points
//! at a contiguous journal range. Each journal record references one full 4 KiB
//! data-copy block and the target LBA to rewrite. The final record must publish
//! the final clean superblock at LBA 0, so a crash during replay can safely run
//! replay again until the clean root-store is durable.

use crate::crc32c::crc32c;
use crate::format::*;
use crate::reader::BlockReader;
use crate::{read_superblock, validate_metadata_block, HxfsError};

/// Writable block store used by recovery and mutable Hxfs code.
pub trait BlockStore: BlockReader {
    /// Write `blocks` 4 KiB blocks at `lba` from `input`.
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError>;

    /// Flush volatile write cache for replay ordering.
    fn flush(&mut self) -> Result<(), HxfsError>;
}

/// Journal replay result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    /// Root store was already clean; no records were replayed.
    Clean,
    /// A recovering journal was fully replayed.
    Replayed {
        /// Replayed transaction sequence number.
        sequence_number: u64,
        /// Number of journal records replayed.
        records: u32,
        /// Final checkpoint LBA published by the final superblock record.
        final_checkpoint_lba: u64,
    },
}

/// Replay the journal if the root store is in Recovering state.
pub fn replay_journal<S: BlockStore>(store: &mut S) -> Result<ReplayOutcome, HxfsError> {
    let superblock = read_superblock(store, 0)?;
    if superblock.root_state == ROOT_STATE_CLEAN
        && superblock.journal_start_lba == 0
        && superblock.journal_end_lba == 0
    {
        return Ok(ReplayOutcome::Clean);
    }
    if superblock.root_state != ROOT_STATE_RECOVERING
        || superblock.journal_start_lba == 0
        || superblock.journal_end_lba <= superblock.journal_start_lba
    {
        return Err(HxfsError::BadJournal);
    }
    let span = superblock
        .journal_end_lba
        .checked_sub(superblock.journal_start_lba)
        .ok_or(HxfsError::BadJournal)?;
    if span % 2 != 0 {
        return Err(HxfsError::BadJournal);
    }
    let record_count = u32::try_from(span / 2).map_err(|_| HxfsError::BadJournal)?;
    if record_count == 0 {
        return Err(HxfsError::BadJournal);
    }

    let mut expected_final_checkpoint = 0u64;
    let mut index = 0u32;
    while index < record_count {
        let metadata_lba = superblock.journal_start_lba + u64::from(index) * 2;
        let record = read_journal_record(store, metadata_lba, superblock.sequence_number)?;
        if record.record_index != index || record.record_count != record_count {
            return Err(HxfsError::BadJournal);
        }
        if record.data_lba != metadata_lba + 1 {
            return Err(HxfsError::BadJournal);
        }
        let is_final = record.flags & JOURNAL_RECORD_FLAG_FINAL_SUPERBLOCK != 0;
        if is_final != (index + 1 == record_count) {
            return Err(HxfsError::BadJournal);
        }
        if record.flags & !JOURNAL_RECORD_FLAG_FINAL_SUPERBLOCK != 0 {
            return Err(HxfsError::BadJournal);
        }

        let mut data = [0u8; BLOCK_SIZE];
        store.read_blocks(record.data_lba, 1, &mut data)?;
        if crc32c(&data) != record.data_crc32c {
            return Err(HxfsError::BadChecksum);
        }
        if is_final && record.target_lba != 0 {
            return Err(HxfsError::BadJournal);
        }
        if is_final {
            expected_final_checkpoint = record.final_checkpoint_lba;
        }
        store.write_blocks(record.target_lba, 1, &data)?;
        if is_final {
            store.flush()?;
        }
        index += 1;
    }
    if expected_final_checkpoint == 0 {
        return Err(HxfsError::BadJournal);
    }
    store.flush()?;
    Ok(ReplayOutcome::Replayed {
        sequence_number: superblock.sequence_number,
        records: record_count,
        final_checkpoint_lba: expected_final_checkpoint,
    })
}

/// Read and validate one journal record metadata block.
pub fn read_journal_record<R: BlockReader>(
    reader: &mut R,
    lba: u64,
    sequence_number: u64,
) -> Result<JournalRecord, HxfsError> {
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(lba, 1, &mut block)?;
    let header = validate_metadata_block(&block, lba, BLOCK_TYPE_JOURNAL_RECORD, 0)?;
    let base = header.header_bytes as usize;
    let record = JournalRecord {
        sequence_number: read_u64(&block, base)?,
        record_index: read_u32(&block, base + 8)?,
        record_count: read_u32(&block, base + 12)?,
        target_lba: read_u64(&block, base + 16)?,
        data_lba: read_u64(&block, base + 24)?,
        data_crc32c: read_u32(&block, base + 32)?,
        flags: read_u32(&block, base + 36)?,
        final_checkpoint_lba: read_u64(&block, base + 40)?,
    };
    if record.sequence_number != sequence_number || record.record_count == 0 {
        return Err(HxfsError::BadJournal);
    }
    Ok(record)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HxfsError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(HxfsError::BadJournal)?
            .try_into()
            .map_err(|_| HxfsError::BadJournal)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, HxfsError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(HxfsError::BadJournal)?
            .try_into()
            .map_err(|_| HxfsError::BadJournal)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32c::metadata_crc32c;

    struct MemStore {
        image: [u8; BLOCK_SIZE * 8],
        flushes: u32,
    }

    impl MemStore {
        fn new(image: [u8; BLOCK_SIZE * 8]) -> Self {
            Self { image, flushes: 0 }
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

    fn make_block(block_type: u32, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&block_type.to_le_bytes());
        block[4..6].copy_from_slice(&1u16.to_le_bytes());
        block[6..8].copy_from_slice(&(40u16).to_le_bytes());
        block[8..16].copy_from_slice(&1u64.to_le_bytes());
        block[24..32].copy_from_slice(&lba.to_le_bytes());
        block[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        block[40..40 + payload.len()].copy_from_slice(payload);
        let crc = metadata_crc32c(&block);
        block[32..36].copy_from_slice(&crc.to_le_bytes());
        block
    }

    fn make_superblock(
        sequence: u64,
        checkpoint_lba: u64,
        journal_start: u64,
        journal_end: u64,
        state: u32,
    ) -> [u8; BLOCK_SIZE] {
        let mut payload = [0u8; 120];
        payload[0..16].copy_from_slice(&FORMAT_GUID);
        payload[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        payload[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
        payload[40..48].copy_from_slice(&sequence.to_le_bytes());
        payload[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        payload[56..64].copy_from_slice(&checkpoint_lba.to_le_bytes());
        payload[72..80].copy_from_slice(&journal_start.to_le_bytes());
        payload[80..88].copy_from_slice(&journal_end.to_le_bytes());
        payload[104..112].copy_from_slice(&BASE_INCOMPAT_FEATURES.to_le_bytes());
        payload[112..116].copy_from_slice(&state.to_le_bytes());
        make_block(BLOCK_TYPE_SUPERBLOCK, 0, &payload)
    }

    fn make_journal_record(
        lba: u64,
        index: u32,
        count: u32,
        target: u64,
        data_lba: u64,
        data_crc: u32,
        flags: u32,
        final_checkpoint: u64,
    ) -> [u8; BLOCK_SIZE] {
        let mut payload = [0u8; 48];
        payload[0..8].copy_from_slice(&2u64.to_le_bytes());
        payload[8..12].copy_from_slice(&index.to_le_bytes());
        payload[12..16].copy_from_slice(&count.to_le_bytes());
        payload[16..24].copy_from_slice(&target.to_le_bytes());
        payload[24..32].copy_from_slice(&data_lba.to_le_bytes());
        payload[32..36].copy_from_slice(&data_crc.to_le_bytes());
        payload[36..40].copy_from_slice(&flags.to_le_bytes());
        payload[40..48].copy_from_slice(&final_checkpoint.to_le_bytes());
        make_block(BLOCK_TYPE_JOURNAL_RECORD, lba, &payload)
    }

    #[test]
    fn clean_root_store_does_not_replay() {
        let mut image = [0u8; BLOCK_SIZE * 8];
        image[0..BLOCK_SIZE].copy_from_slice(&make_superblock(1, 1, 0, 0, ROOT_STATE_CLEAN));
        let mut store = MemStore::new(image);
        assert_eq!(replay_journal(&mut store), Ok(ReplayOutcome::Clean));
        assert_eq!(store.flushes, 0);
    }

    #[test]
    fn recovering_journal_replays_records_and_final_superblock() {
        let mut image = [0u8; BLOCK_SIZE * 8];
        let recovering = make_superblock(2, 1, 2, 6, ROOT_STATE_RECOVERING);
        let final_super = make_superblock(2, 7, 0, 0, ROOT_STATE_CLEAN);
        let mut target = [0x5au8; BLOCK_SIZE];
        target[0..8].copy_from_slice(b"target!!");
        image[0..BLOCK_SIZE].copy_from_slice(&recovering);
        image[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&make_journal_record(
            2,
            0,
            2,
            6,
            3,
            crc32c(&target),
            0,
            7,
        ));
        image[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&target);
        image[BLOCK_SIZE * 4..BLOCK_SIZE * 5].copy_from_slice(&make_journal_record(
            4,
            1,
            2,
            0,
            5,
            crc32c(&final_super),
            JOURNAL_RECORD_FLAG_FINAL_SUPERBLOCK,
            7,
        ));
        image[BLOCK_SIZE * 5..BLOCK_SIZE * 6].copy_from_slice(&final_super);
        let mut store = MemStore::new(image);

        assert_eq!(
            replay_journal(&mut store),
            Ok(ReplayOutcome::Replayed {
                sequence_number: 2,
                records: 2,
                final_checkpoint_lba: 7,
            })
        );
        assert_eq!(
            &store.image[BLOCK_SIZE * 6..BLOCK_SIZE * 6 + 8],
            b"target!!"
        );
        assert_eq!(&store.image[0..BLOCK_SIZE], &final_super);
        assert!(store.flushes >= 1);
    }

    #[test]
    fn bad_journal_crc_is_rejected_without_publish() {
        let mut image = [0u8; BLOCK_SIZE * 8];
        let recovering = make_superblock(2, 1, 2, 4, ROOT_STATE_RECOVERING);
        let final_super = make_superblock(2, 7, 0, 0, ROOT_STATE_CLEAN);
        image[0..BLOCK_SIZE].copy_from_slice(&recovering);
        image[BLOCK_SIZE * 2..BLOCK_SIZE * 3].copy_from_slice(&make_journal_record(
            2,
            0,
            1,
            0,
            3,
            0xdead_beef,
            JOURNAL_RECORD_FLAG_FINAL_SUPERBLOCK,
            7,
        ));
        image[BLOCK_SIZE * 3..BLOCK_SIZE * 4].copy_from_slice(&final_super);
        let mut store = MemStore::new(image);
        assert_eq!(replay_journal(&mut store), Err(HxfsError::BadChecksum));
        assert_eq!(&store.image[0..BLOCK_SIZE], &recovering);
    }
}
