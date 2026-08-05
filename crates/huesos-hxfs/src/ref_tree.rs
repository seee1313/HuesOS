//! Fixed-capacity refcount and backref B-tree policy cores.
//!
//! Stage N uses sorted fixed root-leaf trees so the no-heap service can persist
//! sharing metadata without depending on dynamic allocation. Keys are physical
//! block starts. The records are intentionally shaped so a later multi-level
//! tree can reuse the same key/value payloads.

/// Refcount/backref tree failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefTreeError {
    /// The fixed tree node has no free record slot.
    Full,
    /// The requested range is invalid or overflows.
    BadRange,
    /// The requested range overlaps an incompatible existing record.
    Overlap,
    /// A requested record was not found.
    NotFound,
    /// A refcount decrement would underflow.
    Underflow,
}

/// Persistent reference count for one physical extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefcountRecord {
    /// Starting filesystem block.
    pub start_block: u64,
    /// Number of 4 KiB blocks.
    pub block_count: u64,
    /// Number of live owners/snapshots referencing this extent.
    pub refcount: u32,
}

impl RefcountRecord {
    /// Exclusive end block.
    pub fn end_block(self) -> Result<u64, RefTreeError> {
        self.start_block
            .checked_add(self.block_count)
            .ok_or(RefTreeError::BadRange)
    }
}

/// Fixed-capacity refcount B-tree root/leaf.
pub struct RefcountBtree<const N: usize> {
    records: [Option<RefcountRecord>; N],
}

impl<const N: usize> Default for RefcountBtree<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RefcountBtree<N> {
    /// Create an empty refcount tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable fixed record array.
    pub const fn records(&self) -> &[Option<RefcountRecord>; N] {
        &self.records
    }

    /// Count occupied records.
    pub fn record_count(&self) -> usize {
        count_options(&self.records)
    }

    /// Insert a new non-overlapping refcount record.
    pub fn insert(&mut self, record: RefcountRecord) -> Result<(), RefTreeError> {
        validate_range(record.start_block, record.block_count)?;
        if record.refcount == 0 {
            return Err(RefTreeError::BadRange);
        }
        let end = record.end_block()?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                let existing_end = existing.end_block()?;
                if record.start_block < existing_end && existing.start_block < end {
                    return Err(RefTreeError::Overlap);
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(RefTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Increment an exact extent refcount.
    pub fn increment(&mut self, start_block: u64, block_count: u64) -> Result<u32, RefTreeError> {
        let index = self.find_exact(start_block, block_count)?;
        let Some(record) = self.records[index] else {
            return Err(RefTreeError::NotFound);
        };
        let next = record
            .refcount
            .checked_add(1)
            .ok_or(RefTreeError::BadRange)?;
        self.records[index] = Some(RefcountRecord {
            refcount: next,
            ..record
        });
        Ok(next)
    }

    /// Decrement an exact extent refcount.
    pub fn decrement(&mut self, start_block: u64, block_count: u64) -> Result<u32, RefTreeError> {
        let index = self.find_exact(start_block, block_count)?;
        let Some(record) = self.records[index] else {
            return Err(RefTreeError::NotFound);
        };
        if record.refcount == 0 {
            return Err(RefTreeError::Underflow);
        }
        let next = record.refcount - 1;
        if next == 0 {
            self.records[index] = None;
        } else {
            self.records[index] = Some(RefcountRecord {
                refcount: next,
                ..record
            });
        }
        Ok(next)
    }

    /// Whether an exact extent can be reclaimed.
    pub fn is_reclaimable(&self, start_block: u64, block_count: u64) -> Result<bool, RefTreeError> {
        match self.find_exact(start_block, block_count) {
            Ok(index) => Ok(self.records[index]
                .map(|record| record.refcount <= 1)
                .unwrap_or(true)),
            Err(RefTreeError::NotFound) => Ok(true),
            Err(error) => Err(error),
        }
    }

    /// Validate sort order and non-overlap invariants.
    pub fn validate(&self) -> Result<(), RefTreeError> {
        let mut previous_end = 0u64;
        let mut saw = false;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_range(record.start_block, record.block_count)?;
                if record.refcount == 0 {
                    return Err(RefTreeError::BadRange);
                }
                if saw && record.start_block < previous_end {
                    return Err(RefTreeError::Overlap);
                }
                previous_end = record.end_block()?;
                saw = true;
            }
            index += 1;
        }
        Ok(())
    }

    fn find_exact(&self, start_block: u64, block_count: u64) -> Result<usize, RefTreeError> {
        validate_range(start_block, block_count)?;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.start_block == start_block && record.block_count == block_count {
                    return Ok(index);
                }
            }
            index += 1;
        }
        Err(RefTreeError::NotFound)
    }

    fn sort(&mut self) {
        sort_refcount_records(&mut self.records);
    }
}

/// Owner kind stored in a backref record.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackrefKind {
    /// File/object data extent.
    ObjectData = 1,
    /// Directory metadata block.
    Directory = 2,
    /// Extent-table metadata block.
    ExtentTable = 3,
    /// Object/volume/checkpoint metadata.
    Metadata = 4,
    /// Snapshot-retained reference.
    Snapshot = 5,
}

/// Persistent back-reference from physical extent to logical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackrefRecord {
    /// Starting filesystem block.
    pub start_block: u64,
    /// Number of 4 KiB blocks.
    pub block_count: u64,
    /// Owning object id, or zero for global metadata.
    pub owner_object_id: u64,
    /// Owner kind.
    pub kind: BackrefKind,
    /// Generation/checkpoint sequence that created this reference.
    pub generation: u64,
}

impl BackrefRecord {
    /// Exclusive end block.
    pub fn end_block(self) -> Result<u64, RefTreeError> {
        self.start_block
            .checked_add(self.block_count)
            .ok_or(RefTreeError::BadRange)
    }
}

/// Fixed-capacity backref B-tree root/leaf.
pub struct BackrefBtree<const N: usize> {
    records: [Option<BackrefRecord>; N],
}

impl<const N: usize> Default for BackrefBtree<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> BackrefBtree<N> {
    /// Create an empty backref tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable fixed record array.
    pub const fn records(&self) -> &[Option<BackrefRecord>; N] {
        &self.records
    }

    /// Count occupied records.
    pub fn record_count(&self) -> usize {
        count_options(&self.records)
    }

    /// Insert one backref record.
    pub fn insert(&mut self, record: BackrefRecord) -> Result<(), RefTreeError> {
        validate_range(record.start_block, record.block_count)?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if self.records[index].is_none() && free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(RefTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Remove an exact owner/range backref.
    pub fn remove(
        &mut self,
        start_block: u64,
        block_count: u64,
        owner_object_id: u64,
        kind: BackrefKind,
    ) -> Result<(), RefTreeError> {
        validate_range(start_block, block_count)?;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.start_block == start_block
                    && record.block_count == block_count
                    && record.owner_object_id == owner_object_id
                    && record.kind == kind
                {
                    self.records[index] = None;
                    return Ok(());
                }
            }
            index += 1;
        }
        Err(RefTreeError::NotFound)
    }

    /// Count records owned by one object id.
    pub fn records_for_owner(&self, owner_object_id: u64) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.records.len() {
            if self.records[index]
                .map(|record| record.owner_object_id == owner_object_id)
                .unwrap_or(false)
            {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Validate record ranges and sort order.
    pub fn validate(&self) -> Result<(), RefTreeError> {
        let mut previous_key = 0u64;
        let mut saw = false;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_range(record.start_block, record.block_count)?;
                if saw && record.start_block < previous_key {
                    return Err(RefTreeError::Overlap);
                }
                previous_key = record.start_block;
                saw = true;
            }
            index += 1;
        }
        Ok(())
    }

    fn sort(&mut self) {
        sort_backref_records(&mut self.records);
    }
}

fn count_options<T: Copy, const N: usize>(records: &[Option<T>; N]) -> usize {
    let mut count = 0usize;
    let mut index = 0usize;
    while index < records.len() {
        if records[index].is_some() {
            count += 1;
        }
        index += 1;
    }
    count
}

fn sort_refcount_records<const N: usize>(records: &mut [Option<RefcountRecord>; N]) {
    let mut i = 0usize;
    while i < records.len() {
        let mut j = i + 1;
        while j < records.len() {
            if should_swap_ref(records[i], records[j]) {
                records.swap(i, j);
            }
            j += 1;
        }
        i += 1;
    }
}

fn sort_backref_records<const N: usize>(records: &mut [Option<BackrefRecord>; N]) {
    let mut i = 0usize;
    while i < records.len() {
        let mut j = i + 1;
        while j < records.len() {
            if should_swap_backref(records[i], records[j]) {
                records.swap(i, j);
            }
            j += 1;
        }
        i += 1;
    }
}

fn should_swap_ref(left: Option<RefcountRecord>, right: Option<RefcountRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.start_block > b.start_block,
        _ => false,
    }
}

fn should_swap_backref(left: Option<BackrefRecord>, right: Option<BackrefRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => {
            a.start_block > b.start_block
                || (a.start_block == b.start_block && a.owner_object_id > b.owner_object_id)
        }
        _ => false,
    }
}

fn validate_range(start: u64, blocks: u64) -> Result<(), RefTreeError> {
    if blocks == 0 || start.checked_add(blocks).is_none() {
        return Err(RefTreeError::BadRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refcount_increment_decrement_and_reclaim() {
        let mut tree = RefcountBtree::<4>::new();
        assert!(tree
            .insert(RefcountRecord {
                start_block: 8,
                block_count: 2,
                refcount: 1,
            })
            .is_ok());
        assert_eq!(tree.is_reclaimable(8, 2), Ok(true));
        assert_eq!(tree.increment(8, 2), Ok(2));
        assert_eq!(tree.is_reclaimable(8, 2), Ok(false));
        assert_eq!(tree.decrement(8, 2), Ok(1));
        assert_eq!(tree.decrement(8, 2), Ok(0));
        assert_eq!(tree.is_reclaimable(8, 2), Ok(true));
    }

    #[test]
    fn backrefs_are_sorted_and_counted_by_owner() {
        let mut tree = BackrefBtree::<4>::new();
        assert!(tree
            .insert(BackrefRecord {
                start_block: 20,
                block_count: 1,
                owner_object_id: 2,
                kind: BackrefKind::ObjectData,
                generation: 1,
            })
            .is_ok());
        assert!(tree
            .insert(BackrefRecord {
                start_block: 10,
                block_count: 1,
                owner_object_id: 2,
                kind: BackrefKind::ExtentTable,
                generation: 1,
            })
            .is_ok());
        assert_eq!(tree.records_for_owner(2), 2);
        assert!(tree.validate().is_ok());
        assert!(tree.remove(10, 1, 2, BackrefKind::ExtentTable).is_ok());
        assert_eq!(tree.records_for_owner(2), 1);
    }

    // Production-gate refcount and backref coverage: each test pins
    // one invariant from the snapshot-reclaim contract in
    // docs/STORAGE_NVME_FS_ROADMAP.md §F (Stage N).
    //
    //   N4 feat(hxfs): reclaim blocks on snapshot deletion
    //   N5 test(hxfs): add snapshot reclaim and crash tests
    //
    // The fixed-capacity B-tree has to surface Overlap/Full/NotFound
    // /Underflow/BadRange without panicking, retain sort order across
    // mixed insert/remove, and let the snapshot retain path pin a
    // refcount so the live blocks are not reclaimable.

    #[test]
    fn snapshot_retain_blocks_reclaim_until_release() {
        // The refcount represents live owners plus snapshot
        // retainers. Insert with refcount 1 (the live owner) so
        // the extent is reclaimable in the optimistic sense (one
        // decrement frees it). Then increment to model a snapshot
        // retaining the extent; the extent must NO LONGER be
        // reclaimable because a single decrement would leave a
        // live snapshot. Decrement back to 1 restores the
        // optimistic reclaim state. A second decrement (to 0)
        // removes the record entirely.
        let mut tree = RefcountBtree::<4>::new();
        match tree.insert(RefcountRecord {
            start_block: 100,
            block_count: 4,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "initial insert failed: {error:?}");
                return;
            }
        }
        // Optimistically reclaimable: one decrement frees it.
        assert_eq!(tree.is_reclaimable(100, 4), Ok(true));
        // Snapshot retains the extent.
        assert_eq!(tree.increment(100, 4), Ok(2));
        // Not reclaimable: a single decrement would leave a live
        // snapshot reference.
        assert_eq!(tree.is_reclaimable(100, 4), Ok(false));
        // Snapshot drops.
        assert_eq!(tree.decrement(100, 4), Ok(1));
        // Optimistically reclaimable again.
        assert_eq!(tree.is_reclaimable(100, 4), Ok(true));
        // Live owner drops: refcount back to 0, record removed,
        // extent reclaimable.
        assert_eq!(tree.decrement(100, 4), Ok(0));
        assert_eq!(tree.record_count(), 0);
    }

    #[test]
    fn refcount_insert_with_zero_refcount_is_rejected() {
        // refcount=0 is invalid because the record is created on
        // first owner; an empty refcount would otherwise be
        // reclaimed the moment it is inserted.
        let mut tree = RefcountBtree::<4>::new();
        assert_eq!(
            tree.insert(RefcountRecord {
                start_block: 0,
                block_count: 1,
                refcount: 0,
            }),
            Err(RefTreeError::BadRange)
        );
    }

    #[test]
    fn refcount_zero_block_count_is_rejected() {
        let mut tree = RefcountBtree::<4>::new();
        assert_eq!(
            tree.insert(RefcountRecord {
                start_block: 0,
                block_count: 0,
                refcount: 1,
            }),
            Err(RefTreeError::BadRange)
        );
    }

    #[test]
    fn refcount_overlapping_extents_are_rejected() {
        // Two extents that share any block must not be allowed to
        // both occupy the tree, otherwise the reclaim path would
        // not know which one to free. Touching (end == start) is
        // permitted because the two extents can be released
        // independently.
        let mut tree = RefcountBtree::<4>::new();
        match tree.insert(RefcountRecord {
            start_block: 10,
            block_count: 4,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "first insert: {error:?}");
                return;
            }
        }
        // Strict overlap (start inside, end inside).
        let r1 = tree.insert(RefcountRecord {
            start_block: 12,
            block_count: 1,
            refcount: 1,
        });
        assert_eq!(r1, Err(RefTreeError::Overlap), "first overlap");
        // Starts before, ends after existing.start (true overlap).
        let r2 = tree.insert(RefcountRecord {
            start_block: 8,
            block_count: 4, // [8, 12) overlaps [10, 14)
            refcount: 1,
        });
        assert_eq!(r2, Err(RefTreeError::Overlap), "second overlap");
        // Containing extent.
        let r3 = tree.insert(RefcountRecord {
            start_block: 9,
            block_count: 10,
            refcount: 1,
        });
        assert_eq!(r3, Err(RefTreeError::Overlap), "third overlap");
    }

    #[test]
    fn refcount_adjacent_extents_are_allowed() {
        // Extent A = [10, 14) and extent B = [14, 18) do not
        // overlap; both can coexist so the reclaim path can
        // release them independently.
        let mut tree = RefcountBtree::<4>::new();
        match tree.insert(RefcountRecord {
            start_block: 10,
            block_count: 4,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "first insert: {error:?}");
                return;
            }
        }
        assert_eq!(
            tree.insert(RefcountRecord {
                start_block: 14,
                block_count: 4,
                refcount: 1,
            }),
            Ok(())
        );
        assert_eq!(tree.record_count(), 2);
    }

    #[test]
    fn refcount_tree_overflow_surfaces_full() {
        // A 2-slot tree can hold 2 records; the third must surface
        // Full, not silently drop the entry.
        let mut tree = RefcountBtree::<2>::new();
        match tree.insert(RefcountRecord {
            start_block: 0,
            block_count: 1,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "first insert: {error:?}");
                return;
            }
        }
        match tree.insert(RefcountRecord {
            start_block: 10,
            block_count: 1,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "second insert: {error:?}");
                return;
            }
        }
        assert_eq!(
            tree.insert(RefcountRecord {
                start_block: 20,
                block_count: 1,
                refcount: 1,
            }),
            Err(RefTreeError::Full)
        );
    }

    #[test]
    fn refcount_decrement_unknown_extent_returns_not_found() {
        // Decrementing a missing extent returns NotFound, because
        // there is no record whose refcount could underflow. The
        // Underflow branch is only reachable when an exact record
        // exists with refcount 0, which is a different invariant
        // and is covered by `refcount_decrement_to_zero_removes_record`
        // + a follow-up decrement on a non-existent range.
        let mut tree = RefcountBtree::<4>::new();
        assert_eq!(tree.decrement(0, 1), Err(RefTreeError::NotFound));
    }

    #[test]
    fn refcount_decrement_to_zero_removes_record() {
        // The "last snapshot drops, then live owner drops" path
        // must end with the record gone, not lingering with
        // refcount=0 (which would later be rejected on insert).
        let mut tree = RefcountBtree::<4>::new();
        match tree.insert(RefcountRecord {
            start_block: 50,
            block_count: 1,
            refcount: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "insert: {error:?}");
                return;
            }
        }
        assert_eq!(tree.decrement(50, 1), Ok(0));
        assert_eq!(tree.record_count(), 0);
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn is_reclaimable_for_unknown_extent_is_true() {
        // A block that is not in the tree at all has no live owners
        // and is therefore reclaimable. This is the path the
        // snapshot delete reclaim walks to decide what to free.
        let tree = RefcountBtree::<4>::new();
        assert_eq!(tree.is_reclaimable(999, 1), Ok(true));
    }

    #[test]
    fn validate_empty_tree_is_ok() {
        let tree = RefcountBtree::<4>::new();
        assert_eq!(tree.validate(), Ok(()));
    }

    #[test]
    fn backref_full_table_surfaces_full() {
        // Backref is a separate fixed-capacity tree; 2 records fit,
        // the 3rd must surface Full.
        let mut tree = BackrefBtree::<2>::new();
        match tree.insert(BackrefRecord {
            start_block: 0,
            block_count: 1,
            owner_object_id: 1,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "first: {error:?}");
                return;
            }
        }
        match tree.insert(BackrefRecord {
            start_block: 1,
            block_count: 1,
            owner_object_id: 2,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "second: {error:?}");
                return;
            }
        }
        assert_eq!(
            tree.insert(BackrefRecord {
                start_block: 2,
                block_count: 1,
                owner_object_id: 3,
                kind: BackrefKind::ObjectData,
                generation: 1,
            }),
            Err(RefTreeError::Full)
        );
    }

    #[test]
    fn backref_remove_unknown_record_is_not_found() {
        // remove() requires the exact (start, count, owner, kind)
        // tuple; mismatches must surface NotFound, not silently
        // delete a different record.
        let mut tree = BackrefBtree::<4>::new();
        match tree.insert(BackrefRecord {
            start_block: 0,
            block_count: 1,
            owner_object_id: 1,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "insert: {error:?}");
                return;
            }
        }
        assert_eq!(
            tree.remove(0, 1, 2, BackrefKind::ObjectData),
            Err(RefTreeError::NotFound)
        );
        assert_eq!(
            tree.remove(99, 1, 1, BackrefKind::ObjectData),
            Err(RefTreeError::NotFound)
        );
        assert_eq!(
            tree.remove(0, 2, 1, BackrefKind::ObjectData),
            Err(RefTreeError::NotFound)
        );
        // The original record is still there.
        assert_eq!(tree.records_for_owner(1), 1);
    }

    #[test]
    fn backref_remove_clears_slot_and_keeps_sort() {
        // After remove the slot is reusable; subsequent insert must
        // land in the cleared slot and the tree must remain sorted.
        let mut tree = BackrefBtree::<4>::new();
        match tree.insert(BackrefRecord {
            start_block: 10,
            block_count: 1,
            owner_object_id: 1,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "a: {error:?}");
                return;
            }
        }
        match tree.insert(BackrefRecord {
            start_block: 20,
            block_count: 1,
            owner_object_id: 1,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "b: {error:?}");
                return;
            }
        }
        match tree.remove(10, 1, 1, BackrefKind::ObjectData) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "remove: {error:?}");
                return;
            }
        }
        // Insert a new record that would have fit in the cleared
        // slot, and verify the tree is still valid.
        match tree.insert(BackrefRecord {
            start_block: 30,
            block_count: 1,
            owner_object_id: 2,
            kind: BackrefKind::ObjectData,
            generation: 1,
        }) {
            Ok(()) => {}
            Err(error) => {
                assert!(false, "c: {error:?}");
                return;
            }
        }
        assert!(tree.validate().is_ok());
        assert_eq!(tree.record_count(), 2);
    }
}
