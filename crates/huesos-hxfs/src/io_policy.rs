//! NVMe/SSD I/O policy helpers for Hxfs.
//!
//! These are pure planning helpers. Hxfs is intentionally not tuned for HDDs:
//! read-ahead is parallel and queue-depth aware, direct I/O is alignment based,
//! and write hints describe SSD/NVMe stream intent.

use crate::format::BLOCK_SIZE_U64;

/// SSD/NVMe write stream hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteHint {
    /// Checkpoint/root-store publication.
    Checkpoint,
    /// Metadata COW blocks.
    Metadata,
    /// Mutable user data blocks.
    UserData,
    /// Immutable Hxblob/package data.
    Hxblob,
    /// Discard/TRIM work.
    Trim,
}

impl WriteHint {
    /// Stable small stream id suitable for future NVMe write hints.
    pub const fn stream_id(self) -> u16 {
        match self {
            WriteHint::Checkpoint => 1,
            WriteHint::Metadata => 2,
            WriteHint::UserData => 3,
            WriteHint::Hxblob => 4,
            WriteHint::Trim => 5,
        }
    }
}

/// One read-ahead request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadAheadRequest {
    /// Starting logical block.
    pub start_block: u64,
    /// Block count.
    pub block_count: u32,
}

/// Parallel read-ahead plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadAheadPlan<const N: usize> {
    /// Planned requests.
    pub requests: [Option<ReadAheadRequest>; N],
    /// Number of live requests.
    pub count: usize,
}

impl<const N: usize> ReadAheadPlan<N> {
    /// Empty plan.
    pub const fn empty() -> Self {
        Self {
            requests: [const { None }; N],
            count: 0,
        }
    }
}

/// Plan async parallel read-ahead for a sequential access pattern.
pub fn plan_parallel_readahead<const N: usize>(
    next_block: u64,
    desired_blocks: u32,
    block_size: u32,
    max_request_bytes: u32,
    queue_count: usize,
) -> Option<ReadAheadPlan<N>> {
    if desired_blocks == 0 || block_size == 0 || max_request_bytes < block_size || queue_count == 0
    {
        return None;
    }
    let max_blocks_per_request = (max_request_bytes / block_size).max(1);
    let parallel = queue_count.min(N).max(1);
    let mut remaining = desired_blocks;
    let mut cursor = next_block;
    let mut plan = ReadAheadPlan::<N>::empty();
    while remaining != 0 && plan.count < parallel {
        let blocks = remaining.min(max_blocks_per_request);
        plan.requests[plan.count] = Some(ReadAheadRequest {
            start_block: cursor,
            block_count: blocks,
        });
        plan.count += 1;
        cursor = cursor.checked_add(u64::from(blocks))?;
        remaining -= blocks;
    }
    Some(plan)
}

/// Whether direct I/O is acceptable for a byte range.
pub const fn direct_io_aligned(offset: u64, length: u64, block_size: u32) -> bool {
    if length == 0 || block_size == 0 {
        return false;
    }
    let block = block_size as u64;
    offset.is_multiple_of(block) && length.is_multiple_of(block)
}

/// Convert bytes to a 4 KiB block count, rounded up.
pub const fn blocks_for_bytes(bytes: u64) -> u64 {
    bytes.div_ceil(BLOCK_SIZE_U64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_readahead_respects_request_limit_and_queues() {
        let plan = plan_parallel_readahead::<4>(10, 1024, 4096, 128 * 1024, 4);
        assert!(plan.is_some());
        let Some(plan) = plan else { return };
        assert_eq!(plan.count, 4);
        assert_eq!(
            plan.requests[0],
            Some(ReadAheadRequest {
                start_block: 10,
                block_count: 32,
            })
        );
        assert_eq!(
            plan.requests[3],
            Some(ReadAheadRequest {
                start_block: 106,
                block_count: 32,
            })
        );
    }

    #[test]
    fn direct_io_alignment_is_block_based() {
        assert!(direct_io_aligned(4096, 8192, 4096));
        assert!(!direct_io_aligned(1, 8192, 4096));
        assert!(!direct_io_aligned(4096, 1, 4096));
    }

    #[test]
    fn write_hints_have_stable_stream_ids() {
        assert_eq!(WriteHint::Checkpoint.stream_id(), 1);
        assert_eq!(WriteHint::Hxblob.stream_id(), 4);
    }
}
