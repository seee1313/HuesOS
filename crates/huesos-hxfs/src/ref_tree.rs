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
}
