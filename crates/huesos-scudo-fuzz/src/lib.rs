//! Randomized robustness harness for the `huesos-scudo` allocator.
//!
//! The allocator's own unit tests check specific, hand-written
//! scenarios. This crate hammers it with long pseudo-random sequences
//! of allocate / free / usable_size / quarantine-flush operations and
//! asserts the invariants that must hold no matter the order:
//!
//! - a successful allocation is non-null, correctly aligned, inside
//!   the backend window, and does not overlap any other live block;
//! - memory written through a returned pointer keeps its contents
//!   until the block is freed (no aliasing between live blocks);
//! - freeing a pointer the allocator handed out succeeds exactly
//!   once, and a second free is reported as corruption rather than
//!   corrupting state;
//! - the allocator never panics, and reports out-of-memory as an
//!   error instead of misbehaving.
//!
//! Like `huesos-decoder-fuzz`, this uses a deterministic PRNG so a
//! failure reproduces exactly, runs as a plain `cargo test`, and is
//! wired into the AddressSanitizer job so the pointer arithmetic is
//! also checked under instrumentation.

#![no_std]

#[cfg(test)]
mod tests {
    use huesos_scudo::backend::{Backend, TestBackend};
    use huesos_scudo::Allocator;

    const COOKIE: u64 = 0x5cd0_5cd0_5cd0_5cd0;

    /// Deterministic LCG so a failing seed reproduces anywhere.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            (self.next() >> 33) as usize % bound
        }
    }

    /// One live allocation the harness is tracking.
    #[derive(Clone, Copy)]
    struct Live {
        ptr: *mut u8,
        size: usize,
        align: usize,
        /// Byte pattern written across the whole block, used to prove
        /// no other allocation aliases it.
        tag: u8,
    }

    const MAX_LIVE: usize = 64;

    /// Sizes spanning small size classes, class boundaries, and the
    /// secondary allocator's large-block path.
    fn pick_size(rng: &mut Lcg) -> usize {
        match rng.below(10) {
            0..=4 => 1 + rng.below(256),
            5..=6 => 1 + rng.below(4096),
            7 => 4096 - 1 + rng.below(3),
            8 => 1 + rng.below(64 * 1024),
            _ => 1 + rng.below(256 * 1024),
        }
    }

    fn pick_align(rng: &mut Lcg) -> usize {
        1usize << rng.below(8)
    }

    /// Assert `candidate` does not overlap any tracked block.
    fn assert_no_overlap(live: &[Live], count: usize, candidate: Live) {
        let new_start = candidate.ptr as usize;
        let new_end = new_start + candidate.size;
        let mut i = 0;
        while i < count {
            let other = live[i];
            let start = other.ptr as usize;
            let end = start + other.size;
            assert!(
                new_end <= start || new_start >= end,
                "allocation [{new_start:#x},{new_end:#x}) overlaps live block [{start:#x},{end:#x})"
            );
            i += 1;
        }
    }

    /// The core loop: random allocate/free churn with full invariant
    /// checking after every operation.
    fn churn(seed: u64, iterations: usize) {
        let backend = TestBackend::new(2048);
        let base = backend.base();
        let window = backend.window_size();
        let Ok(mut allocator) = Allocator::new(backend, COOKIE) else {
            assert!(false, "allocator must initialise");
            return;
        };

        let mut rng = Lcg::new(seed);
        let mut live = [Live {
            ptr: core::ptr::null_mut(),
            size: 0,
            align: 1,
            tag: 0,
        }; MAX_LIVE];
        let mut count = 0usize;
        let mut next_tag = 1u8;

        let mut step = 0usize;
        while step < iterations {
            let free_bias = if count >= MAX_LIVE { 10 } else { 4 };
            let action = rng.below(10);

            if action < free_bias && count > 0 {
                // Free a random live block, after re-checking that its
                // contents survived everything that happened since.
                let index = rng.below(count);
                let entry = live[index];
                let mut i = 0;
                while i < entry.size {
                    // SAFETY: `entry` is a live allocation this harness
                    // made and has not freed.
                    let byte = unsafe { entry.ptr.add(i).read() };
                    assert_eq!(
                        byte, entry.tag,
                        "block of size {} was modified by another allocation",
                        entry.size
                    );
                    i += 1;
                }
                // SAFETY: pointer came from this allocator and is live.
                let freed = unsafe { allocator.deallocate(entry.ptr) };
                assert_eq!(freed, Ok(()), "freeing a live pointer must succeed");

                // A second free must be refused, not silently accepted.
                // SAFETY: deliberately passing a just-freed pointer;
                // the allocator validates the header before trusting it.
                let again = unsafe { allocator.deallocate(entry.ptr) };
                assert!(again.is_err(), "double free must be reported, not accepted");

                live[index] = live[count - 1];
                count -= 1;
            } else if count < MAX_LIVE {
                let size = pick_size(&mut rng);
                let align = pick_align(&mut rng);
                match allocator.allocate(size, align) {
                    Ok(ptr) => {
                        assert!(!ptr.is_null(), "a successful allocation is never null");
                        let address = ptr as usize;
                        assert_eq!(address % align, 0, "alignment {align} not honoured");
                        assert!(
                            address >= base && address + size <= base + window,
                            "allocation escapes the backend window"
                        );

                        let tag = next_tag;
                        next_tag = next_tag.wrapping_add(1).max(1);
                        let entry = Live {
                            ptr,
                            size,
                            align,
                            tag,
                        };
                        assert_no_overlap(&live, count, entry);

                        // Write the whole block: catches overlap the
                        // address arithmetic alone would miss, and
                        // proves every byte is really writable.
                        // SAFETY: the allocator just returned `size`
                        // usable bytes at `ptr`.
                        unsafe { core::ptr::write_bytes(ptr, tag, size) };

                        // The reported usable size must cover the request.
                        // SAFETY: `ptr` is live.
                        match unsafe { allocator.usable_size(ptr) } {
                            Ok(usable) => assert!(
                                usable >= size,
                                "usable_size {usable} smaller than request {size}"
                            ),
                            Err(error) => {
                                assert!(false, "usable_size failed on a live pointer: {error:?}")
                            }
                        }

                        live[count] = entry;
                        count += 1;
                    }
                    Err(_) => {
                        // Out of memory is a legitimate outcome under
                        // pressure; the allocator must stay usable.
                        // Flushing the quarantine should reclaim.
                        let _ = allocator.flush_quarantine();
                    }
                }
            } else {
                let _ = allocator.flush_quarantine();
            }

            step += 1;
        }

        // Drain everything and confirm the accounting balances.
        while count > 0 {
            let entry = live[count - 1];
            // SAFETY: live pointer from this allocator.
            let freed = unsafe { allocator.deallocate(entry.ptr) };
            assert_eq!(freed, Ok(()));
            count -= 1;
        }
        let Ok(()) = allocator.flush_quarantine() else {
            assert!(false, "flushing the quarantine must succeed");
            return;
        };
        let stats = allocator.stats();
        assert_eq!(
            stats.live_bytes, 0,
            "every allocation was freed, so live_bytes must be zero"
        );
        assert_eq!(
            stats.allocations, stats.deallocations,
            "allocation and free counts must balance"
        );
    }

    #[test]
    fn random_churn_is_sound_across_seeds() {
        let mut seed = 1u64;
        while seed <= 12 {
            churn(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 400);
            seed += 1;
        }
    }

    #[test]
    fn long_run_single_seed() {
        churn(0xDEAD_BEEF_CAFE_F00D, 4000);
    }

    /// Steady-state churn must not leak: repeatedly allocating and
    /// freeing the same shapes must reach a plateau rather than
    /// committing more memory forever. This is the property the
    /// previous allocator violated (audit finding #1).
    ///
    /// Note the property is "bounded", not "constant from the first
    /// round". Random sizes keep touching size classes that have not
    /// been used yet, and each first use commits a region, so
    /// committed memory legitimately rises for a while before it
    /// settles. The check therefore warms up until the working set is
    /// covered and then requires the figure to stay put.
    #[test]
    fn steady_state_churn_does_not_grow_without_bound() {
        let backend = TestBackend::new(512);
        let Ok(mut allocator) = Allocator::new(backend, COOKIE) else {
            assert!(false, "allocator must initialise");
            return;
        };
        let mut rng = Lcg::new(0x1234_5678);

        // Warm up until every size class the loop can reach has been
        // touched, then require a flat line.
        const WARMUP_ROUNDS: usize = 25;
        const TOTAL_ROUNDS: usize = 60;
        let mut round = 0;
        let mut committed_after_warmup = 0usize;
        while round < TOTAL_ROUNDS {
            let mut batch = [core::ptr::null_mut(); 16];
            let mut i = 0;
            while i < batch.len() {
                let size = 1 + rng.below(2048);
                match allocator.allocate(size, 8) {
                    Ok(ptr) => batch[i] = ptr,
                    Err(_) => {
                        let _ = allocator.flush_quarantine();
                    }
                }
                i += 1;
            }
            i = 0;
            while i < batch.len() {
                if !batch[i].is_null() {
                    // SAFETY: pointer from this allocator, freed once.
                    let _ = unsafe { allocator.deallocate(batch[i]) };
                    batch[i] = core::ptr::null_mut();
                }
                i += 1;
            }
            let _ = allocator.flush_quarantine();
            if round == WARMUP_ROUNDS {
                committed_after_warmup = allocator.primary_committed_bytes();
            }
            round += 1;
        }

        let committed_at_end = allocator.primary_committed_bytes();
        assert!(
            committed_after_warmup > 0,
            "the warm-up must have committed something to compare against"
        );
        assert_eq!(
            committed_at_end,
            committed_after_warmup,
            "committed memory must plateau: churning the same shapes for \
             {} more rounds kept committing ({committed_after_warmup} -> \
             {committed_at_end})",
            TOTAL_ROUNDS - WARMUP_ROUNDS
        );
        assert_eq!(allocator.stats().live_bytes, 0);
    }
}
