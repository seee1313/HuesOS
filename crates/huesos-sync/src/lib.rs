//! Platform-neutral lock-order rank tracking for HuesOS.
//!
//! This crate holds the lock-rank state machine that is independent of any
//! particular architecture or interrupt-masking strategy. It is `no_std` and
//! free of `cli`/`sti`, so it can be unit-tested on the host — which is exactly
//! what the SMP lock-rank migration requires: the rank logic must be
//! exercisable in `cargo test` without executing architecture-specific
//! interrupt control.
//!
//! The architecture layer (`huesos-arch`) owns the per-CPU tracker storage,
//! the interrupt-masking lock wrappers, and the fail-stop violation handler;
//! it delegates the pure rank bookkeeping to this crate.

#![no_std]

/// Maximum number of locks that one CPU may nest.
pub const MAX_HELD_LOCKS: usize = 16;

/// Runtime lock-order rank. Locks must be acquired in non-decreasing rank
/// order. Equal-rank nesting is allowed for objects in the same domain, but
/// recursively acquiring the same lock is rejected.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LockRank(u8);

impl LockRank {
    /// Immutable boot and architecture state.
    pub const ARCHITECTURE: Self = Self(10);
    /// Global object registries and indexes.
    pub const REGISTRY: Self = Self(20);
    /// State local to one kernel object.
    pub const OBJECT: Self = Self(30);
    /// Process address-space and runtime state.
    pub const PROCESS: Self = Self(40);
    /// Wait queues and timeout metadata.
    pub const WAIT: Self = Self(50);
    /// Per-CPU scheduler state.
    pub const SCHEDULER: Self = Self(60);
    /// Deferred object and process teardown.
    pub const REAPER: Self = Self(70);
    /// Kernel allocator metadata.
    pub const ALLOCATOR: Self = Self(80);

    /// Numeric rank used in diagnostics and lock inventories.
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy)]
struct HeldLock {
    rank: LockRank,
    identity: usize,
}

const EMPTY_HELD_LOCK: HeldLock = HeldLock {
    rank: LockRank(0),
    identity: 0,
};

/// A runtime lock-order contract violation. Checks are enabled in every build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockRankError {
    /// A lower-ranked lock was requested while a higher rank was held.
    Inversion,
    /// The CPU attempted to recursively acquire the same non-recursive lock.
    RecursiveAcquire,
    /// More than [`MAX_HELD_LOCKS`] locks were nested on one CPU.
    NestingLimit,
    /// Guards were released out of LIFO order or on a different CPU.
    UnbalancedRelease,
    /// More hardware threads attempted to use ranked locks than supported.
    CpuCapacity,
}

/// Per-CPU record of currently held ranked locks.
///
/// Pure bookkeeping: no interrupt control, no atomics, no architecture
/// assumptions. The owning context (the architecture layer) is responsible for
/// ensuring mutual exclusion and for supplying a stable per-CPU instance.
pub struct RankTracker {
    depth: usize,
    held: [HeldLock; MAX_HELD_LOCKS],
}

impl RankTracker {
    /// Create an empty tracker with no locks held.
    pub const fn new() -> Self {
        Self {
            depth: 0,
            held: [EMPTY_HELD_LOCK; MAX_HELD_LOCKS],
        }
    }

    /// Number of ranked locks currently held by this tracker.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Record acquisition of `rank` by `identity`, validating the lock-order
    /// contract relative to already-held locks.
    pub fn enter(&mut self, rank: LockRank, identity: usize) -> Result<(), LockRankError> {
        if self.depth == MAX_HELD_LOCKS {
            return Err(LockRankError::NestingLimit);
        }
        if self.held[..self.depth]
            .iter()
            .any(|held| held.identity == identity)
        {
            return Err(LockRankError::RecursiveAcquire);
        }
        if self.depth != 0 && rank < self.held[self.depth - 1].rank {
            return Err(LockRankError::Inversion);
        }
        self.held[self.depth] = HeldLock { rank, identity };
        self.depth += 1;
        Ok(())
    }

    /// Record release of the most recently held lock, validating that it
    /// matches `rank` and `identity` (LIFO, same identity).
    pub fn leave(&mut self, rank: LockRank, identity: usize) -> Result<(), LockRankError> {
        let Some(index) = self.depth.checked_sub(1) else {
            return Err(LockRankError::UnbalancedRelease);
        };
        let held = self.held[index];
        if held.rank != rank || held.identity != identity {
            return Err(LockRankError::UnbalancedRelease);
        }
        self.depth = index;
        self.held[index] = EMPTY_HELD_LOCK;
        Ok(())
    }
}

impl Default for RankTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{LockRank, LockRankError, RankTracker};

    #[test]
    fn rank_tracker_accepts_nested_non_decreasing_ranks() {
        let mut tracker = RankTracker::new();
        assert_eq!(tracker.enter(LockRank::REGISTRY, 1), Ok(()));
        assert_eq!(tracker.enter(LockRank::OBJECT, 2), Ok(()));
        assert_eq!(tracker.leave(LockRank::OBJECT, 2), Ok(()));
        assert_eq!(tracker.leave(LockRank::REGISTRY, 1), Ok(()));
        assert_eq!(tracker.depth(), 0);
    }

    #[test]
    fn rank_tracker_rejects_inversion_and_recursion() {
        let mut tracker = RankTracker::new();
        assert_eq!(tracker.enter(LockRank::WAIT, 1), Ok(()));
        assert_eq!(
            tracker.enter(LockRank::OBJECT, 2),
            Err(LockRankError::Inversion)
        );
        assert_eq!(
            tracker.enter(LockRank::WAIT, 1),
            Err(LockRankError::RecursiveAcquire)
        );
    }

    #[test]
    fn rank_tracker_requires_lifo_release() {
        let mut tracker = RankTracker::new();
        assert_eq!(tracker.enter(LockRank::OBJECT, 1), Ok(()));
        assert_eq!(tracker.enter(LockRank::OBJECT, 2), Ok(()));
        assert_eq!(
            tracker.leave(LockRank::OBJECT, 1),
            Err(LockRankError::UnbalancedRelease)
        );
    }

    #[test]
    fn rank_tracker_rejects_over_nesting() {
        let mut tracker = RankTracker::new();
        for i in 0..super::MAX_HELD_LOCKS {
            assert_eq!(
                tracker.enter(LockRank::ARCHITECTURE, i.wrapping_add(1)),
                Ok(())
            );
        }
        assert_eq!(
            tracker.enter(LockRank::ARCHITECTURE, 999),
            Err(LockRankError::NestingLimit)
        );
    }
}
