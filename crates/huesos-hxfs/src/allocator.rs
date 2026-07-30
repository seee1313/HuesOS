//! NVMe/SSD-oriented per-zone allocation model for Hxfs.
//!
//! Stage I uses 16 GiB allocation zones and hybrid free-space tracking: a
//! sequential cursor for fresh COW writes plus a small extent list for reclaimed
//! ranges. This is a host-testable policy model, not yet the persistent free
//! space tree.

use crate::format::BLOCK_SIZE_U64;

/// Hxfs allocation zone size: 16 GiB.
pub const ZONE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Number of 4 KiB blocks per 16 GiB zone.
pub const ZONE_BLOCKS: u64 = ZONE_BYTES / BLOCK_SIZE_U64;

/// Free extent inside a zone, in filesystem block units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FreeExtent {
    /// Start block relative to zone base.
    pub start: u64,
    /// Block count.
    pub blocks: u64,
}

impl FreeExtent {
    const fn is_empty(&self) -> bool {
        self.blocks == 0
    }
}

/// One allocation zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneState<const FREE: usize> {
    /// Absolute first block of this zone.
    pub base_block: u64,
    /// Total blocks in this zone.
    pub total_blocks: u64,
    /// Sequential allocation cursor relative to `base_block`.
    pub cursor: u64,
    /// Reclaimed free extents.
    pub free_extents: [FreeExtent; FREE],
    /// Pending TRIM/discard extents.
    pub pending_trim: [FreeExtent; FREE],
}

impl<const FREE: usize> ZoneState<FREE> {
    /// Create an empty zone.
    pub const fn new(base_block: u64, total_blocks: u64) -> Self {
        Self {
            base_block,
            total_blocks,
            cursor: 0,
            free_extents: [FreeExtent {
                start: 0,
                blocks: 0,
            }; FREE],
            pending_trim: [FreeExtent {
                start: 0,
                blocks: 0,
            }; FREE],
        }
    }
}

/// Allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocError {
    /// Request was zero or overflowed.
    Invalid,
    /// No space remains.
    NoSpace,
    /// Free/trim side table is full.
    TableFull,
}

/// Fixed-zone allocator policy model.
pub struct HybridZoneAllocator<const ZONES: usize, const FREE: usize> {
    zones: [ZoneState<FREE>; ZONES],
}

impl<const ZONES: usize, const FREE: usize> HybridZoneAllocator<ZONES, FREE> {
    /// Create an allocator for `total_blocks`, split into 16 GiB zones.
    pub fn new(total_blocks: u64) -> Self {
        let mut zones = [const { ZoneState::new(0, 0) }; ZONES];
        let mut remaining = total_blocks;
        let mut base = 0u64;
        let mut index = 0usize;
        while index < ZONES {
            let blocks = remaining.min(ZONE_BLOCKS);
            zones[index] = ZoneState::new(base, blocks);
            base = base.saturating_add(blocks);
            remaining = remaining.saturating_sub(blocks);
            index += 1;
        }
        Self { zones }
    }

    /// Borrow a zone.
    pub fn zone(&self, index: usize) -> Option<&ZoneState<FREE>> {
        self.zones.get(index)
    }

    /// Allocate `blocks`, preferring reclaimed extents before the sequential
    /// cursor. Returns absolute start block.
    pub fn allocate(&mut self, blocks: u64) -> Result<u64, AllocError> {
        if blocks == 0 {
            return Err(AllocError::Invalid);
        }
        let mut zone_index = 0usize;
        while zone_index < self.zones.len() {
            if let Some(block) = alloc_from_zone(&mut self.zones[zone_index], blocks) {
                return Ok(block);
            }
            zone_index += 1;
        }
        Err(AllocError::NoSpace)
    }

    /// Release a range for future reuse and batched TRIM.
    pub fn free(&mut self, absolute_start: u64, blocks: u64) -> Result<(), AllocError> {
        if blocks == 0 {
            return Err(AllocError::Invalid);
        }
        let Some(zone) = self.zones.iter_mut().find(|zone| {
            absolute_start >= zone.base_block
                && absolute_start < zone.base_block + zone.total_blocks
        }) else {
            return Err(AllocError::Invalid);
        };
        let relative = absolute_start - zone.base_block;
        insert_extent(
            &mut zone.free_extents,
            FreeExtent {
                start: relative,
                blocks,
            },
        )?;
        insert_extent(
            &mut zone.pending_trim,
            FreeExtent {
                start: relative,
                blocks,
            },
        )?;
        Ok(())
    }

    /// Drain one pending TRIM extent.
    pub fn take_pending_trim(&mut self) -> Option<(u64, u64)> {
        for zone in &mut self.zones {
            for extent in &mut zone.pending_trim {
                if !extent.is_empty() {
                    let out = (zone.base_block + extent.start, extent.blocks);
                    *extent = FreeExtent::default();
                    return Some(out);
                }
            }
        }
        None
    }
}

fn alloc_from_zone<const FREE: usize>(zone: &mut ZoneState<FREE>, blocks: u64) -> Option<u64> {
    for extent in &mut zone.free_extents {
        if extent.blocks >= blocks {
            let start = extent.start;
            extent.start += blocks;
            extent.blocks -= blocks;
            return Some(zone.base_block + start);
        }
    }
    let end = zone.cursor.checked_add(blocks)?;
    if end <= zone.total_blocks {
        let start = zone.cursor;
        zone.cursor = end;
        return Some(zone.base_block + start);
    }
    None
}

fn insert_extent<const N: usize>(
    table: &mut [FreeExtent; N],
    extent: FreeExtent,
) -> Result<(), AllocError> {
    let Some(slot) = table.iter_mut().find(|slot| slot.is_empty()) else {
        return Err(AllocError::TableFull);
    };
    *slot = extent;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_across_zones() {
        let mut alloc = HybridZoneAllocator::<2, 4>::new(ZONE_BLOCKS + 8);
        assert_eq!(alloc.allocate(ZONE_BLOCKS), Ok(0));
        assert_eq!(alloc.allocate(4), Ok(ZONE_BLOCKS));
    }

    #[test]
    fn reuses_freed_extents_and_records_trim() {
        let mut alloc = HybridZoneAllocator::<1, 4>::new(128);
        assert_eq!(alloc.allocate(8), Ok(0));
        assert_eq!(alloc.allocate(8), Ok(8));
        assert_eq!(alloc.free(0, 4), Ok(()));
        assert_eq!(alloc.allocate(2), Ok(0));
        assert_eq!(alloc.take_pending_trim(), Some((0, 4)));
    }
}
