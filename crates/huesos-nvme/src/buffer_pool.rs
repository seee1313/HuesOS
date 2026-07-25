//! Zero-alloc DMA buffer pool for I/O data transfers.
//!
//! [`DmaBufferPool`] pre-allocates a set of fixed-size DMA buffers from the
//! DMA region and reuses them across I/O operations. This eliminates per-I/O
//! DMA allocation overhead, providing truly zero-alloc I/O path.
//!
//! ## Buffer pool architecture
//!
//! ```text
//! DMA Region (kernel-provided VMO)
//! ┌─────────────────────────────────────────────────┐
//! │ Admin Queue (64B * admin_size)                  │
//! │ Completion Queue 1 (16B * io_size)              │
//! │ Submission Queue 1 (64B * io_size)              │
//! │ Completion Queue 2 (16B * io_size)              │
//! │ Submission Queue 2 (64B * io_size)              │
//! │ ...                                             │
//! │ Buffer Pool:                                    │
//! │   [Buffer 0: 4KB] [Buffer 1: 4KB] ...           │
//! │   [Buffer N: 4KB]                               │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! let mut pool = DmaBufferPool::new(dma_region, 4096, 16);
//! let (buf_addr, buf_idx) = pool.acquire().ok_or(NvmeError::OutOfDma)?;
//! // Use buf_addr for I/O (PRP setup, DMA read/write)
//! // ...
//! pool.release(buf_idx);
//! ```
//!
//! ## Future work
//!
//! - Multiple buffer sizes (small: 512B, medium: 4KB, large: 64KB)
//! - Buffer alignment guarantees
//! - NUMA-aware buffer placement
//! - Statistics (acquire/release counts, high-water mark)

/// A pool of pre-allocated DMA buffers for zero-alloc I/O.
pub struct DmaBufferPool {
    /// DMA addresses of buffers (device-visible physical addresses).
    buffer_addrs: [u64; 64],
    /// Free list: indices of available buffers.
    free_list: [u16; 64],
    /// Number of free buffers.
    free_count: u16,
    /// Buffer size in bytes.
    buffer_size: u64,
    /// Total number of buffers.
    total_buffers: u16,
}

impl DmaBufferPool {
    /// Maximum number of buffers in the pool.
    pub const MAX_BUFFERS: usize = 64;

    /// Create a buffer pool from a DMA region.
    ///
    /// Pre-allocates `num_buffers` buffers of `buffer_size` bytes each from
    /// the DMA region starting at `dma_base`.
    ///
    /// Returns None if the DMA region is too small or num_buffers > MAX_BUFFERS.
    pub fn new(dma_base: u64, dma_size: u64, buffer_size: u64, num_buffers: u16) -> Option<Self> {
        if num_buffers as usize > Self::MAX_BUFFERS {
            return None;
        }
        let total_size = buffer_size.checked_mul(num_buffers as u64)?;
        if total_size > dma_size {
            return None;
        }

        let mut pool = Self {
            buffer_addrs: [0; Self::MAX_BUFFERS],
            free_list: [0; Self::MAX_BUFFERS],
            free_count: num_buffers,
            buffer_size,
            total_buffers: num_buffers,
        };

        // Initialize buffer addresses and free list.
        // Free list is initialized in reverse order so acquire() returns
        // buffers 0, 1, 2, ... in order.
        for i in 0..num_buffers as usize {
            let addr = dma_base + (i as u64 * buffer_size);
            pool.buffer_addrs[i] = addr;
            pool.free_list[i] = (num_buffers as usize - 1 - i) as u16;
        }

        Some(pool)
    }

    /// Acquire a buffer from the pool. Returns (DMA address, buffer index) or
    /// None if the pool is exhausted.
    pub fn acquire(&mut self) -> Option<(u64, u16)> {
        if self.free_count == 0 {
            return None;
        }
        self.free_count -= 1;
        let idx = self.free_list[self.free_count as usize];
        Some((self.buffer_addrs[idx as usize], idx))
    }

    /// Release a buffer back to the pool.
    pub fn release(&mut self, idx: u16) {
        if idx >= self.total_buffers {
            return; // invalid index
        }
        if self.free_count as usize >= Self::MAX_BUFFERS {
            return; // pool full (should not happen)
        }
        self.free_list[self.free_count as usize] = idx;
        self.free_count += 1;
    }

    /// Number of available buffers.
    pub fn available(&self) -> u16 {
        self.free_count
    }

    /// Buffer size in bytes.
    pub fn buffer_size(&self) -> u64 {
        self.buffer_size
    }

    /// Total number of buffers in the pool.
    pub fn total_buffers(&self) -> u16 {
        self.total_buffers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: unpack an Option in a test without calling unwrap. CONTRIBUTING
    // rule 1 forbids the unwrap / expect / panic macros including in tests;
    // an assert!(false, ...) is the budget-allowed diagnostic, and `return`
    // after it keeps the types sound for the remainder of the test body.
    macro_rules! expect_some {
        ($opt:expr, $msg:literal) => {
            match $opt {
                Some(value) => value,
                None => {
                    assert!(false, concat!("expected Some: ", $msg));
                    return;
                }
            }
        };
    }

    #[test]
    fn buffer_pool_acquire_release() {
        let mut pool = expect_some!(
            DmaBufferPool::new(0x1000_0000, 0x10_0000, 4096, 4),
            "constructor with valid parameters"
        );
        assert_eq!(pool.available(), 4);
        let (addr0, idx0) = expect_some!(pool.acquire(), "first acquire on fresh pool");
        assert_eq!(addr0, 0x1000_0000);
        assert_eq!(idx0, 0);
        assert_eq!(pool.available(), 3);
        pool.release(idx0);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn buffer_pool_exhaustion() {
        let mut pool = expect_some!(
            DmaBufferPool::new(0x1000_0000, 0x10_0000, 4096, 2),
            "constructor with valid parameters"
        );
        let (_, idx0) = expect_some!(pool.acquire(), "first acquire");
        let (_, _idx1) = expect_some!(pool.acquire(), "second acquire");
        assert!(pool.acquire().is_none()); // exhausted
        pool.release(idx0);
        assert!(pool.acquire().is_some()); // can acquire again
    }

    #[test]
    fn buffer_pool_oversized_request() {
        assert!(DmaBufferPool::new(0, 0x10_0000, 4096, 128).is_none()); // > MAX_BUFFERS
    }
}
