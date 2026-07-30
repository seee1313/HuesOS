//! Fixed-capacity allocation B-tree policy core.
//!
//! Stage M starts with a no-heap root-leaf B-tree representation: records are
//! kept sorted by start block in a fixed array and serialized by the filesystem
//! writer as a metadata tree root. The layout is intentionally compatible with a
//! future multi-level tree: keys are block starts and values are extent state.

use crate::format::BLOCK_SIZE_U64;

/// Allocation-tree operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocTreeError {
    /// The fixed tree node has no free record slot.
    Full,
    /// The requested range overlaps an existing record.
    Overlap,
    /// The requested range is empty or overflows block arithmetic.
    BadRange,
    /// No free range can satisfy an allocation.
    NoSpace,
    /// A requested record was not found.
    NotFound,
}

/// Allocation state stored in the allocation tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AllocationState {
    /// Extent is free and may be allocated.
    Free = 1,
    /// Extent is allocated and owned by live metadata/data.
    Allocated = 2,
    /// Extent was freed and should be discarded/TRIMed before reuse policy allows it.
    PendingTrim = 3,
}

/// One allocation-tree extent record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationRecord {
    /// Starting filesystem block.
    pub start_block: u64,
    /// Number of 4 KiB blocks covered by this record.
    pub block_count: u64,
    /// Record state.
    pub state: AllocationState,
    /// Owner object id, or zero for free/policy records.
    pub owner_object_id: u64,
}

impl AllocationRecord {
    /// Exclusive end block.
    pub fn end_block(self) -> Result<u64, AllocTreeError> {
        self.start_block
            .checked_add(self.block_count)
            .ok_or(AllocTreeError::BadRange)
    }

    /// Physical bytes covered by this record.
    pub fn bytes(self) -> Result<u64, AllocTreeError> {
        self.block_count
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or(AllocTreeError::BadRange)
    }
}

/// Fixed-capacity allocation B-tree root/leaf.
pub struct AllocationBtree<const N: usize> {
    records: [Option<AllocationRecord>; N],
}

impl<const N: usize> AllocationBtree<N> {
    /// Create an empty allocation tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable fixed record array.
    pub const fn records(&self) -> &[Option<AllocationRecord>; N] {
        &self.records
    }

    /// Count occupied records.
    pub fn record_count(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.records.len() {
            if self.records[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Insert a non-overlapping allocation record.
    pub fn insert(&mut self, record: AllocationRecord) -> Result<(), AllocTreeError> {
        validate_range(record.start_block, record.block_count)?;
        let end = record.end_block()?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                let existing_end = existing.end_block()?;
                if record.start_block < existing_end && existing.start_block < end {
                    return Err(AllocTreeError::Overlap);
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(AllocTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Allocate from the first free record that can satisfy `block_count`.
    pub fn allocate_first_fit(
        &mut self,
        block_count: u64,
        owner_object_id: u64,
    ) -> Result<u64, AllocTreeError> {
        validate_range(0, block_count)?;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.state == AllocationState::Free && record.block_count >= block_count {
                    let start = record.start_block;
                    if record.block_count == block_count {
                        self.records[index] = Some(AllocationRecord {
                            start_block: start,
                            block_count,
                            state: AllocationState::Allocated,
                            owner_object_id,
                        });
                    } else {
                        self.records[index] = Some(AllocationRecord {
                            start_block: start + block_count,
                            block_count: record.block_count - block_count,
                            state: AllocationState::Free,
                            owner_object_id: 0,
                        });
                        self.insert(AllocationRecord {
                            start_block: start,
                            block_count,
                            state: AllocationState::Allocated,
                            owner_object_id,
                        })?;
                    }
                    self.sort();
                    return Ok(start);
                }
            }
            index += 1;
        }
        Err(AllocTreeError::NoSpace)
    }

    /// Mark an allocated extent as pending TRIM/free.
    pub fn free(&mut self, start_block: u64, block_count: u64) -> Result<(), AllocTreeError> {
        validate_range(start_block, block_count)?;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.start_block == start_block && record.block_count == block_count {
                    if record.state != AllocationState::Allocated {
                        return Err(AllocTreeError::NotFound);
                    }
                    self.records[index] = Some(AllocationRecord {
                        start_block,
                        block_count,
                        state: AllocationState::PendingTrim,
                        owner_object_id: record.owner_object_id,
                    });
                    return Ok(());
                }
            }
            index += 1;
        }
        Err(AllocTreeError::NotFound)
    }

    /// Convert all pending-TRIM records into reusable free records and coalesce
    /// adjacent free ranges.
    pub fn complete_pending_trim(&mut self) -> Result<(), AllocTreeError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.state == AllocationState::PendingTrim {
                    self.records[index] = Some(AllocationRecord {
                        start_block: record.start_block,
                        block_count: record.block_count,
                        state: AllocationState::Free,
                        owner_object_id: 0,
                    });
                }
            }
            index += 1;
        }
        self.coalesce_free()
    }

    /// Sum allocated bytes.
    pub fn allocated_bytes(&self) -> Result<u64, AllocTreeError> {
        self.sum_state_bytes(AllocationState::Allocated)
    }

    /// Sum free bytes.
    pub fn free_bytes(&self) -> Result<u64, AllocTreeError> {
        self.sum_state_bytes(AllocationState::Free)
    }

    /// Validate sort order and non-overlap invariants.
    pub fn validate(&self) -> Result<(), AllocTreeError> {
        let mut previous_end = 0u64;
        let mut saw_record = false;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_range(record.start_block, record.block_count)?;
                if saw_record && record.start_block < previous_end {
                    return Err(AllocTreeError::Overlap);
                }
                previous_end = record.end_block()?;
                saw_record = true;
            }
            index += 1;
        }
        Ok(())
    }

    fn sum_state_bytes(&self, state: AllocationState) -> Result<u64, AllocTreeError> {
        let mut total = 0u64;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.state == state {
                    total = total
                        .checked_add(record.bytes()?)
                        .ok_or(AllocTreeError::BadRange)?;
                }
            }
            index += 1;
        }
        Ok(total)
    }

    fn coalesce_free(&mut self) -> Result<(), AllocTreeError> {
        self.sort();
        let mut index = 0usize;
        while index < self.records.len() {
            let Some(left) = self.records[index] else {
                index += 1;
                continue;
            };
            if left.state != AllocationState::Free {
                index += 1;
                continue;
            }
            let mut next = index + 1;
            while next < self.records.len() {
                let Some(right) = self.records[next] else {
                    next += 1;
                    continue;
                };
                if right.state == AllocationState::Free && left.end_block()? == right.start_block {
                    self.records[index] = Some(AllocationRecord {
                        start_block: left.start_block,
                        block_count: left
                            .block_count
                            .checked_add(right.block_count)
                            .ok_or(AllocTreeError::BadRange)?,
                        state: AllocationState::Free,
                        owner_object_id: 0,
                    });
                    self.records[next] = None;
                    self.sort();
                    index = 0;
                    break;
                }
                next += 1;
            }
            index += 1;
        }
        Ok(())
    }

    fn sort(&mut self) {
        let mut i = 0usize;
        while i < self.records.len() {
            let mut j = i + 1;
            while j < self.records.len() {
                if should_swap(self.records[i], self.records[j]) {
                    self.records.swap(i, j);
                }
                j += 1;
            }
            i += 1;
        }
    }
}

fn should_swap(left: Option<AllocationRecord>, right: Option<AllocationRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.start_block > b.start_block,
        _ => false,
    }
}

fn validate_range(start: u64, blocks: u64) -> Result<(), AllocTreeError> {
    if blocks == 0 || start.checked_add(blocks).is_none() {
        return Err(AllocTreeError::BadRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_fit_splits_and_reuses_free_extents() {
        let mut tree = AllocationBtree::<8>::new();
        assert!(tree
            .insert(AllocationRecord {
                start_block: 10,
                block_count: 10,
                state: AllocationState::Free,
                owner_object_id: 0,
            })
            .is_ok());
        assert_eq!(tree.allocate_first_fit(4, 7), Ok(10));
        assert_eq!(tree.allocate_first_fit(3, 8), Ok(14));
        assert!(tree.validate().is_ok());
        assert_eq!(tree.allocated_bytes(), Ok(7 * BLOCK_SIZE_U64));
        assert!(tree.free(10, 4).is_ok());
        assert!(tree.complete_pending_trim().is_ok());
        assert_eq!(tree.allocate_first_fit(2, 9), Ok(10));
    }

    #[test]
    fn rejects_overlaps_and_zero_ranges() {
        let mut tree = AllocationBtree::<4>::new();
        assert_eq!(
            tree.insert(AllocationRecord {
                start_block: 1,
                block_count: 0,
                state: AllocationState::Free,
                owner_object_id: 0,
            }),
            Err(AllocTreeError::BadRange)
        );
        assert!(tree
            .insert(AllocationRecord {
                start_block: 1,
                block_count: 4,
                state: AllocationState::Free,
                owner_object_id: 0,
            })
            .is_ok());
        assert_eq!(
            tree.insert(AllocationRecord {
                start_block: 3,
                block_count: 4,
                state: AllocationState::Allocated,
                owner_object_id: 1,
            }),
            Err(AllocTreeError::Overlap)
        );
    }
}
