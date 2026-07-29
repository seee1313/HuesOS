//! BlockReader abstraction for Hxfs.

use crate::format::BLOCK_SIZE;
use crate::HxfsError;

/// Storage backend for Hxfs readers.
pub trait BlockReader {
    /// Read `blocks` 4 KiB blocks starting at `lba` into `out`.
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError>;
}

/// Byte-slice reader used by host tests and image builders.
pub struct SliceBlockReader<'a> {
    image: &'a [u8],
}

impl<'a> SliceBlockReader<'a> {
    /// Create a reader over a complete Hxfs image.
    pub const fn new(image: &'a [u8]) -> Self {
        Self { image }
    }
}

impl BlockReader for SliceBlockReader<'_> {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        let bytes = usize::try_from(blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE))
            .ok_or(HxfsError::OutOfRange)?;
        if out.len() < bytes {
            return Err(HxfsError::BufferTooSmall);
        }
        let start = usize::try_from(lba)
            .ok()
            .and_then(|lba| lba.checked_mul(BLOCK_SIZE))
            .ok_or(HxfsError::OutOfRange)?;
        let end = start.checked_add(bytes).ok_or(HxfsError::OutOfRange)?;
        let src = self.image.get(start..end).ok_or(HxfsError::OutOfRange)?;
        out[..bytes].copy_from_slice(src);
        Ok(())
    }
}
