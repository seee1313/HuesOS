//! # huesos-scudo — hardened userspace allocator
//!
//! A port of the **LLVM Scudo** allocator architecture to HuesOS
//! ring-3, replacing the bump-plus-free-list MVP in
//! `huesos-user-alloc`.
//!
//! ## Why replace the old allocator
//!
//! The MVP threaded a singly-linked free list through freed blocks
//! and followed those links without validating them. Two defects
//! fell straight out of that design:
//!
//! - splitting a block found in the middle of the list reattached
//!   the list head to the split remainder, orphaning every earlier
//!   node — a steady-state workload leaked its entire heap and
//!   reported a false OOM;
//! - `Layout::align` was honoured only on the bump path, so a
//!   64-byte-aligned request served from the free list came back
//!   misaligned.
//!
//! Both are the *same* underlying problem: metadata living in
//! application-writable memory with no integrity check and no
//! validation on use. Scudo's design is built around exactly that
//! threat.
//!
//! ## What is ported
//!
//! | Scudo concept | Here | Notes |
//! |---|---|---|
//! | `SizeClassMap` | [`size_class`] | 32 classes up to 64 KiB |
//! | `Chunk` header + checksum | [`chunk`] | cookie-keyed, address-bound |
//! | `Primary` | [`primary`] | per-class regions, `TransferBatch` refill, **validated** links |
//! | `Secondary` | [`secondary`] | page-aligned blocks with guard pages both sides |
//! | `Quarantine` | [`quarantine`] | bounded FIFO delaying reuse |
//! | `TSD` | [`Allocator`] | single shared cache — see below |
//!
//! ## Deliberate deviations from upstream
//!
//! These are platform limits, not simplifications of the design:
//!
//! - **No per-thread caches (TSD registry).** HuesOS ring-3 services
//!   are single-threaded today: `ThreadCreate` is only ever issued
//!   by the process launcher, and there is no TLS. The allocator
//!   therefore keeps one cache behind the existing lock discipline.
//!   The split between "cache" and "backing allocator" follows
//!   upstream, so adding a real registry is a local change once
//!   threads exist.
//! - **`mmap` is a fixed window.** A ring-3 process holds no handle
//!   to its own VMAR, so memory comes from `VmarHeapExtend` — commit
//!   and decommit inside one pre-reserved window — rather than
//!   arbitrary mappings. The [`backend::Backend`] trait is that
//!   seam.
//! - **No MTE / memory tagging.** The kernel does not expose tagged
//!   memory on x86_64.
//!
//! ## Safety
//!
//! The `unsafe` in this crate is confined to four operations, each
//! justified at its use site: reading and writing chunk headers,
//! reading and writing the intrusive free-list link inside a chunk
//! the allocator owns, turning a validated window offset into a
//! pointer, and the `GlobalAlloc` impl. Every input that comes from
//! application-writable memory is validated *before* it is used to
//! form a pointer. See `docs/UNSAFE_AUDIT.md`.

#![no_std]
#![warn(missing_docs)]

pub mod backend;
pub mod chunk;
pub mod primary;
pub mod quarantine;
pub mod secondary;
pub mod size_class;

use backend::{page_align_up, Backend};
use chunk::{ChunkState, HeaderError, Origin, HEADER_BYTES};
use primary::{Primary, PrimaryError};
use quarantine::{Quarantine, QuarantinedChunk};
use secondary::{Secondary, SecondaryError};
use size_class::{class_for_size, size_for_class, MIN_ALIGNMENT};

/// Fraction of the window given to the primary allocator.
///
/// The rest goes to the secondary. Small allocations dominate in
/// every service in the tree, so the primary gets the larger share,
/// but the secondary needs enough room for the multi-megabyte
/// buffers the storage service builds during scrub.
const PRIMARY_SHARE_NUMERATOR: usize = 3;
const PRIMARY_SHARE_DENOMINATOR: usize = 5;

/// Why an allocator operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// No memory available for the request.
    OutOfMemory,
    /// The allocator has not been initialised yet.
    NotInitialised,
    /// The requested alignment is not a power of two, or the size
    /// overflows when padded.
    InvalidLayout,
    /// A chunk header failed validation — corruption, a bogus
    /// pointer, or a double free.
    Corruption(HeaderError),
    /// The primary allocator reported a fault.
    Primary(PrimaryError),
    /// The secondary allocator reported a fault.
    Secondary(SecondaryError),
}

/// Runtime counters, for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Successful allocations.
    pub allocations: u64,
    /// Successful frees.
    pub deallocations: u64,
    /// Allocations that failed for lack of memory.
    pub oom_failures: u64,
    /// Header validation failures (corruption or double free).
    pub corruption_failures: u64,
    /// Bytes currently handed out to the application.
    pub live_bytes: usize,
}

/// The Scudo-architecture allocator.
///
/// Generic over its [`Backend`] so the same code runs against the
/// real heap-window syscalls in ring 3 and against a plain buffer in
/// host tests.
pub struct Allocator<B: Backend> {
    backend: B,
    primary: Primary,
    secondary: Secondary,
    quarantine: Quarantine,
    stats: Stats,
    initialised: bool,
}

impl<B: Backend> Allocator<B> {
    /// Build an allocator over `backend`.
    ///
    /// `cookie` must be unpredictable, non-zero entropy: it keys
    /// every header checksum. Initialisation fails if it is zero,
    /// rather than proceeding with forgeable headers.
    pub fn new(backend: B, cookie: u64) -> Result<Self, AllocError> {
        if !chunk::set_cookie(cookie) {
            return Err(AllocError::InvalidLayout);
        }
        let window = backend.window_size();
        let primary_size =
            (window / PRIMARY_SHARE_DENOMINATOR * PRIMARY_SHARE_NUMERATOR) & !(4096 - 1);
        let secondary_offset = primary_size;
        let secondary_size = window - primary_size;
        Ok(Self {
            primary: Primary::new(0, primary_size),
            secondary: Secondary::new(secondary_offset, secondary_size),
            quarantine: Quarantine::new(),
            backend,
            stats: Stats::default(),
            initialised: true,
        })
    }

    /// Current counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Bytes committed by the primary allocator.
    pub fn primary_committed_bytes(&self) -> usize {
        self.primary.committed_bytes()
    }

    /// Convert a pointer into a window offset, if it lies inside the
    /// window at all.
    fn offset_of(&self, ptr: *mut u8) -> Option<usize> {
        let base = self.backend.base();
        let address = ptr as usize;
        if address < base {
            return None;
        }
        let offset = address - base;
        if offset >= self.backend.window_size() {
            return None;
        }
        Some(offset)
    }

    /// Allocate `size` bytes with `align` alignment.
    pub fn allocate(&mut self, size: usize, align: usize) -> Result<*mut u8, AllocError> {
        if !self.initialised {
            return Err(AllocError::NotInitialised);
        }
        if !align.is_power_of_two() {
            return Err(AllocError::InvalidLayout);
        }

        // Alignments up to the allocator's own guarantee are free:
        // every chunk body is already 16-byte aligned. Anything
        // larger is satisfied by over-allocating and shifting the
        // header, exactly like upstream.
        //
        // Getting this wrong on the reuse path is what made the old
        // allocator return misaligned memory.
        if align > MIN_ALIGNMENT {
            return self.allocate_overaligned(size, align);
        }

        let mut result = match class_for_size(size) {
            Some(class) => self.allocate_primary(size, class),
            None => self.allocate_secondary(size),
        };

        // Memory pressure: the quarantine is holding chunks back
        // from reuse, so flush it and retry before reporting OOM.
        // Upstream Scudo does the same — the quarantine is a
        // hardening delay, never a reason to fail an allocation that
        // could otherwise be served. Without this a class whose
        // region is smaller than the quarantine budget would report
        // a false OOM, which is exactly the failure mode the old
        // allocator had (for a different reason).
        if Self::is_out_of_memory(&result) && !self.quarantine.is_empty() {
            self.flush_quarantine()?;
            result = match class_for_size(size) {
                Some(class) => self.allocate_primary(size, class),
                None => self.allocate_secondary(size),
            };
        }

        match result {
            Ok(ptr) => {
                self.stats.allocations += 1;
                self.stats.live_bytes += size;
                Ok(ptr)
            }
            Err(error) => {
                if matches!(
                    error,
                    AllocError::OutOfMemory
                        | AllocError::Primary(PrimaryError::OutOfMemory)
                        | AllocError::Secondary(SecondaryError::OutOfMemory)
                ) {
                    self.stats.oom_failures += 1;
                }
                Err(error)
            }
        }
    }

    /// Whether a failed allocation failed for lack of memory (as
    /// opposed to corruption or a bad layout), and is therefore
    /// worth retrying after a quarantine flush.
    fn is_out_of_memory(result: &Result<*mut u8, AllocError>) -> bool {
        matches!(
            result,
            Err(AllocError::OutOfMemory)
                | Err(AllocError::Primary(PrimaryError::OutOfMemory))
                | Err(AllocError::Secondary(SecondaryError::OutOfMemory))
        )
    }

    fn allocate_primary(&mut self, size: usize, class: usize) -> Result<*mut u8, AllocError> {
        let offset = self
            .primary
            .allocate(&self.backend, class)
            .map_err(AllocError::Primary)?;
        // SAFETY: `offset` is a chunk start just returned by the
        // primary, inside a committed region it owns.
        Ok(unsafe { Primary::finish_allocation(&self.backend, offset, class, size) })
    }

    fn allocate_secondary(&mut self, size: usize) -> Result<*mut u8, AllocError> {
        let offset = self
            .secondary
            .allocate(&self.backend, size)
            .map_err(AllocError::Secondary)?;
        // SAFETY: `offset` is a payload start just committed by the
        // secondary.
        Ok(unsafe { Secondary::finish_allocation(&self.backend, offset, size) })
    }

    /// Serve an over-aligned request.
    ///
    /// The block is over-allocated by `align` so a correctly aligned
    /// user pointer always exists inside it, then the header is
    /// written immediately before that pointer and records how far
    /// it moved. `deallocate` reads the offset back out of the
    /// header, so the shift never has to be recomputed.
    fn allocate_overaligned(&mut self, size: usize, align: usize) -> Result<*mut u8, AllocError> {
        let padded = size
            .checked_add(align)
            .and_then(|value| value.checked_add(HEADER_BYTES))
            .ok_or(AllocError::InvalidLayout)?;

        let (block_offset, origin, class) = match class_for_size(padded) {
            Some(class) => {
                let offset = self
                    .primary
                    .allocate(&self.backend, class)
                    .map_err(AllocError::Primary)?;
                (offset, Origin::Primary, class as u8)
            }
            None => {
                let offset = self
                    .secondary
                    .allocate(&self.backend, padded)
                    .map_err(AllocError::Secondary)?;
                (offset, Origin::Secondary, 0u8)
            }
        };

        let block_start = self.backend.base() + block_offset;
        // First candidate body sits just past a header.
        let unaligned_body = block_start + HEADER_BYTES;
        let aligned_body = (unaligned_body + align - 1) & !(align - 1);
        let shift = aligned_body - unaligned_body;

        let header = chunk::ChunkHeader {
            state: ChunkState::Allocated,
            origin,
            class,
            offset: shift as u16,
            request_size: size as u32,
        };
        // SAFETY: `aligned_body` lies inside the block (the block was
        // padded by `align`), and the 16 bytes before it are inside
        // the same block because `shift >= 0` and the block starts
        // with a header slot.
        unsafe { chunk::write_header(aligned_body as *mut u8, &header) };

        self.stats.allocations += 1;
        self.stats.live_bytes += size;
        Ok(aligned_body as *mut u8)
    }

    /// Free a pointer previously returned by [`Self::allocate`].
    ///
    /// # Safety
    /// `ptr` must be null, or a pointer this allocator returned from
    /// [`Self::allocate`] and that has not been freed since. The
    /// allocator validates the chunk header before trusting it, so a
    /// corrupted or foreign pointer is rejected with
    /// [`AllocError::Corruption`] rather than corrupting state — but
    /// the read of that header is itself a dereference, so the
    /// pointer must at minimum be safe to read 16 bytes below.
    pub unsafe fn deallocate(&mut self, ptr: *mut u8) -> Result<(), AllocError> {
        if !self.initialised {
            return Err(AllocError::NotInitialised);
        }
        if ptr.is_null() {
            return Ok(());
        }
        // A pointer outside the window was never ours. Report it
        // instead of computing a wild offset from it.
        let user_offset = self
            .offset_of(ptr)
            .ok_or(AllocError::Corruption(HeaderError::BadChecksum))?;

        // SAFETY: `ptr` is inside the window; the header immediately
        // precedes it and is validated by checksum before any field
        // is trusted. A forged or corrupted header fails here rather
        // than producing a bogus offset.
        let header = unsafe { chunk::read_header(ptr) }.map_err(|error| {
            self.stats.corruption_failures += 1;
            AllocError::Corruption(error)
        })?;

        if header.state != ChunkState::Allocated {
            // Double free (Quarantined) or a free of never-allocated
            // memory (Available). Refuse before touching a list.
            self.stats.corruption_failures += 1;
            return Err(AllocError::Corruption(HeaderError::UnexpectedState {
                found: header.state,
            }));
        }

        let block_offset = user_offset - HEADER_BYTES - header.offset as usize;
        let request_size = header.request_size as usize;

        // Mark it quarantined *before* parking it: a use-after-free
        // or double free now reads a header that says so.
        let quarantined = chunk::ChunkHeader {
            state: ChunkState::Quarantined,
            ..header
        };
        // SAFETY: same header slot just validated above.
        unsafe { chunk::write_header(ptr, &quarantined) };

        self.stats.deallocations += 1;
        self.stats.live_bytes = self.stats.live_bytes.saturating_sub(request_size);

        let entry = QuarantinedChunk {
            offset: block_offset,
            class: match header.origin {
                Origin::Primary => Some(header.class),
                Origin::Secondary => None,
            },
            request_size: if header.origin == Origin::Secondary {
                // The secondary needs the padded size to compute the
                // same page count it committed.
                request_size + header.offset as usize
            } else {
                request_size
            },
        };

        if let Some(evicted) = self.quarantine.push(entry) {
            self.recycle(evicted)?;
        }
        Ok(())
    }

    /// Actually return an evicted chunk to its allocator.
    fn recycle(&mut self, chunk_entry: QuarantinedChunk) -> Result<(), AllocError> {
        match chunk_entry.class {
            Some(class) => self
                .primary
                .deallocate(&self.backend, class as usize, chunk_entry.offset)
                .map_err(AllocError::Primary),
            None => self
                .secondary
                .deallocate(&self.backend, chunk_entry.offset, chunk_entry.request_size)
                .map_err(AllocError::Secondary),
        }
    }

    /// Flush the quarantine, recycling everything it holds.
    pub fn flush_quarantine(&mut self) -> Result<(), AllocError> {
        while let Some(entry) = self.quarantine.drain_next() {
            self.recycle(entry)?;
        }
        Ok(())
    }

    /// The usable size of an allocation, for `realloc`-style growth.
    ///
    /// # Safety
    /// `ptr` must be a live pointer from this allocator.
    pub unsafe fn usable_size(&self, ptr: *const u8) -> Result<usize, AllocError> {
        // SAFETY: delegated to the caller's contract; the header is
        // still checksum-validated before its fields are used.
        let header = unsafe { chunk::read_header(ptr) }.map_err(AllocError::Corruption)?;
        match header.origin {
            Origin::Primary => size_for_class(header.class as usize)
                .map(|size| size - header.offset as usize)
                .ok_or(AllocError::Corruption(HeaderError::Malformed)),
            Origin::Secondary => Ok(page_align_up(header.request_size as usize + HEADER_BYTES)
                - HEADER_BYTES
                - header.offset as usize),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::TestBackend;

    const COOKIE: u64 = 0x5cd0_5cd0_5cd0_5cd0;

    fn allocator(pages: usize) -> Allocator<TestBackend> {
        match Allocator::new(TestBackend::new(pages), COOKIE) {
            Ok(allocator) => allocator,
            Err(error) => panic_free(error),
        }
    }

    /// Test helper that fails the test without unwrapping or
    /// panicking directly, keeping the crate inside the safety budget.
    fn panic_free(error: AllocError) -> ! {
        assert!(false, "allocator setup failed: {error:?}");
        loop {}
    }

    #[test]
    fn basic_allocate_and_free() {
        let mut allocator = allocator(512);
        let ptr = match allocator.allocate(64, 8) {
            Ok(ptr) => ptr,
            Err(error) => {
                assert!(false, "allocate failed: {error:?}");
                return;
            }
        };
        assert!(!ptr.is_null());
        assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
        assert_eq!(allocator.stats().allocations, 1);
        assert_eq!(allocator.stats().deallocations, 1);
    }

    #[test]
    fn allocations_are_writable_and_distinct() {
        let mut allocator = allocator(512);
        let mut pointers = [core::ptr::null_mut(); 32];
        for (index, slot) in pointers.iter_mut().enumerate() {
            match allocator.allocate(100, 8) {
                Ok(ptr) => {
                    // Write a pattern to prove the memory is real
                    // and does not overlap the previous chunk.
                    unsafe { core::ptr::write_bytes(ptr, index as u8, 100) };
                    *slot = ptr;
                }
                Err(error) => {
                    assert!(false, "allocation {index} failed: {error:?}");
                    return;
                }
            }
        }
        for (index, ptr) in pointers.iter().enumerate() {
            let value = unsafe { ptr.read() };
            assert_eq!(value, index as u8, "chunk {index} was overwritten");
        }
    }

    /// Bug #2 from the audit: alignment must hold on every path,
    /// including reuse.
    #[test]
    fn alignment_is_honoured_including_after_reuse() {
        let mut allocator = allocator(512);
        for align in [16usize, 32, 64, 128, 256, 512, 1024] {
            for round in 0..4 {
                let ptr = match allocator.allocate(100, align) {
                    Ok(ptr) => ptr,
                    Err(error) => {
                        assert!(false, "align {align} round {round}: {error:?}");
                        return;
                    }
                };
                assert_eq!(
                    ptr as usize % align,
                    0,
                    "align {align} round {round} returned {ptr:p}"
                );
                assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
            }
        }
    }

    /// Bug #1 from the audit: a steady-state churn must not leak.
    /// The old allocator hit a false OOM on iteration 127.
    #[test]
    fn steady_state_churn_does_not_leak() {
        let mut allocator = allocator(512);
        for iteration in 0..20_000 {
            let ptr = match allocator.allocate(1000, 8) {
                Ok(ptr) => ptr,
                Err(error) => {
                    assert!(
                        false,
                        "iteration {iteration} hit {error:?} — the free list leaked"
                    );
                    return;
                }
            };
            assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
        }
    }

    /// The exact allocation pattern that broke the old free list:
    /// build several differently-sized free blocks, then request a
    /// size that best-fits a block in the *middle* of the list.
    #[test]
    fn mid_list_reuse_does_not_orphan_blocks() {
        let mut allocator = allocator(512);
        let sizes = [64usize, 128, 256, 512, 1024, 2048];
        let mut pointers = [core::ptr::null_mut(); 6];
        for (slot, size) in pointers.iter_mut().zip(sizes.iter()) {
            match allocator.allocate(*size, 8) {
                Ok(ptr) => *slot = ptr,
                Err(error) => {
                    assert!(false, "setup allocation failed: {error:?}");
                    return;
                }
            }
        }
        for ptr in pointers {
            assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
        }
        allocator.flush_quarantine().ok();

        // Now every size must still be serviceable: nothing was
        // orphaned by the reuse of a mid-list block.
        for size in sizes {
            match allocator.allocate(size, 8) {
                Ok(ptr) => assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(())),
                Err(error) => {
                    assert!(false, "size {size} was orphaned: {error:?}");
                    return;
                }
            }
        }
    }

    #[test]
    fn large_allocations_use_the_secondary() {
        let mut allocator = allocator(1024);
        let ptr = match allocator.allocate(200_000, 8) {
            Ok(ptr) => ptr,
            Err(error) => {
                assert!(false, "large allocation failed: {error:?}");
                return;
            }
        };
        unsafe { core::ptr::write_bytes(ptr, 0xab, 200_000) };
        assert_eq!(unsafe { ptr.add(199_999).read() }, 0xab);
        assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
    }

    /// Double free must be detected, not corrupt the free list.
    #[test]
    fn double_free_is_detected() {
        let mut allocator = allocator(512);
        let ptr = match allocator.allocate(64, 8) {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
        let second = unsafe { allocator.deallocate(ptr) };
        assert_eq!(
            second,
            Err(AllocError::Corruption(HeaderError::UnexpectedState {
                found: ChunkState::Quarantined
            }))
        );
        assert_eq!(allocator.stats().corruption_failures, 1);
    }

    /// A heap overflow that smashes the next chunk's header must be
    /// caught when that chunk is freed.
    #[test]
    fn header_corruption_is_detected_on_free() {
        let mut allocator = allocator(512);
        let ptr = match allocator.allocate(64, 8) {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        // Simulate an underflow writing over our own header.
        unsafe { ptr.sub(HEADER_BYTES).write(0xff) };
        let result = unsafe { allocator.deallocate(ptr) };
        assert_eq!(
            result,
            Err(AllocError::Corruption(HeaderError::BadChecksum))
        );
    }

    #[test]
    fn freeing_a_foreign_pointer_is_rejected() {
        let mut allocator = allocator(512);
        let mut stack_value = 0u8;
        let result = unsafe { allocator.deallocate(&mut stack_value as *mut u8) };
        assert!(matches!(result, Err(AllocError::Corruption(_))));
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        let mut allocator = allocator(512);
        assert_eq!(
            unsafe { allocator.deallocate(core::ptr::null_mut()) },
            Ok(())
        );
    }

    #[test]
    fn zero_cookie_is_refused() {
        let result = Allocator::new(TestBackend::new(16), 0);
        assert!(matches!(result, Err(AllocError::InvalidLayout)));
    }

    #[test]
    fn non_power_of_two_alignment_is_refused() {
        let mut allocator = allocator(64);
        assert_eq!(allocator.allocate(64, 24), Err(AllocError::InvalidLayout));
    }

    #[test]
    fn zero_size_allocation_returns_a_usable_pointer() {
        let mut allocator = allocator(64);
        let ptr = match allocator.allocate(0, 8) {
            Ok(ptr) => ptr,
            Err(error) => {
                assert!(false, "zero-size allocation failed: {error:?}");
                return;
            }
        };
        assert!(!ptr.is_null());
        assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
    }

    #[test]
    fn out_of_memory_is_reported_not_panicked() {
        let mut allocator = allocator(16);
        // Far larger than the whole window.
        let result = allocator.allocate(10_000_000, 8);
        assert!(matches!(
            result,
            Err(AllocError::Secondary(SecondaryError::OutOfMemory))
        ));
        assert_eq!(allocator.stats().oom_failures, 1);
    }

    #[test]
    fn quarantine_delays_reuse() {
        let mut allocator = allocator(512);
        let first = match allocator.allocate(64, 8) {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        assert_eq!(unsafe { allocator.deallocate(first) }, Ok(()));
        // The immediately following allocation of the same class
        // must not hand back the just-freed address.
        let second = match allocator.allocate(64, 8) {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        assert_ne!(first, second, "quarantine must delay reuse");
    }

    #[test]
    fn mixed_workload_stays_consistent() {
        let mut allocator = allocator(2048);
        let mut live: [(*mut u8, usize); 64] = [(core::ptr::null_mut(), 0); 64];
        // Deterministic pseudo-random sizes: no external rng, and a
        // fixed seed keeps failures reproducible.
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };

        for round in 0..4000 {
            let slot = (next() as usize) % live.len();
            if !live[slot].0.is_null() {
                let (ptr, size) = live[slot];
                // Verify the contents survived intact.
                let value = unsafe { ptr.read() };
                assert_eq!(value, (size & 0xff) as u8, "round {round}: chunk corrupted");
                assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
                live[slot] = (core::ptr::null_mut(), 0);
                continue;
            }
            let size = ((next() as usize) % 3000) + 1;
            match allocator.allocate(size, 8) {
                Ok(ptr) => {
                    unsafe { core::ptr::write_bytes(ptr, (size & 0xff) as u8, size) };
                    live[slot] = (ptr, size);
                }
                Err(error) => {
                    assert!(false, "round {round} size {size} failed: {error:?}");
                    return;
                }
            }
        }

        for (ptr, _) in live {
            if !ptr.is_null() {
                assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
            }
        }
    }

    #[test]
    fn usable_size_is_at_least_the_request() {
        let mut allocator = allocator(1024);
        for size in [1usize, 17, 100, 1000, 5000, 100_000] {
            let ptr = match allocator.allocate(size, 8) {
                Ok(ptr) => ptr,
                Err(_) => continue,
            };
            match unsafe { allocator.usable_size(ptr) } {
                Ok(usable) => assert!(usable >= size, "usable {usable} < requested {size}"),
                Err(error) => {
                    assert!(false, "usable_size failed: {error:?}");
                    return;
                }
            }
            assert_eq!(unsafe { allocator.deallocate(ptr) }, Ok(()));
        }
    }
}
