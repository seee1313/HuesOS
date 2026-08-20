//! Checked checkpoint/journal transaction geometry.

use super::FixedResult;
use crate::HxfsError;

/// Checked geometry of one checkpoint transaction, relative to its first
/// target block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TransactionShape {
    /// Number of target blocks before the journal starts.
    pub(super) target_blocks: u64,
    /// Number of metadata/data record pairs in the journal.
    pub(super) record_count: u32,
    /// Complete transaction span: targets followed by the journal.
    pub(super) total_blocks: u64,
}

impl TransactionShape {
    /// Plan transaction geometry without assigning an absolute LBA.
    pub(super) fn plan(
        live_objects: usize,
        extra_tree_blocks: u64,
        hxblob_leaf_blocks: u64,
        hxblob_enabled: bool,
    ) -> FixedResult<Self> {
        // Object table, volume table, allocation/refcount/backref/quota roots,
        // two v6 policy roots, and checkpoint.
        const BASE_TARGET_BLOCKS: u64 = 9;
        // The nine roots above plus the final superblock record.
        const BASE_RECORDS: u64 = 10;
        const HXBLOB_TARGET_BLOCKS: u64 = 2;
        const HXBLOB_RECORDS: u64 = 2;

        let object_blocks = u64::try_from(live_objects).map_err(|_| HxfsError::NoSpace)?;
        let feature_target_blocks = if hxblob_enabled {
            HXBLOB_TARGET_BLOCKS
                .checked_add(hxblob_leaf_blocks)
                .ok_or(HxfsError::NoSpace)?
        } else {
            0
        };
        let target_blocks = object_blocks
            .checked_add(extra_tree_blocks)
            .and_then(|value| value.checked_add(BASE_TARGET_BLOCKS))
            .and_then(|value| value.checked_add(feature_target_blocks))
            .ok_or(HxfsError::NoSpace)?;
        let feature_records = if hxblob_enabled { HXBLOB_RECORDS } else { 0 };
        let record_count_u64 = object_blocks
            .checked_add(BASE_RECORDS)
            .and_then(|value| value.checked_add(feature_records))
            .ok_or(HxfsError::NoSpace)?;
        let record_count = u32::try_from(record_count_u64).map_err(|_| HxfsError::NoSpace)?;
        let journal_blocks = record_count_u64.checked_mul(2).ok_or(HxfsError::NoSpace)?;
        let total_blocks = target_blocks
            .checked_add(journal_blocks)
            .ok_or(HxfsError::NoSpace)?;
        Ok(Self {
            target_blocks,
            record_count,
            total_blocks,
        })
    }
}

/// Assign record indexes and reserve the declared last slot for publication.
pub(super) struct JournalCursor {
    next: u32,
    total: u32,
}

impl JournalCursor {
    pub(super) const fn new(total: u32) -> Self {
        Self { next: 0, total }
    }

    pub(super) fn regular(&mut self) -> FixedResult<u32> {
        if self.next >= self.total.saturating_sub(1) {
            return Err(HxfsError::BadJournal);
        }
        let index = self.next;
        self.next += 1;
        Ok(index)
    }

    pub(super) fn final_record(&mut self) -> FixedResult<u32> {
        if self.next.checked_add(1) != Some(self.total) {
            return Err(HxfsError::BadJournal);
        }
        let index = self.next;
        self.next += 1;
        Ok(index)
    }

    pub(super) fn finish(self) -> FixedResult<()> {
        if self.next == self.total {
            Ok(())
        } else {
            Err(HxfsError::BadJournal)
        }
    }
}
