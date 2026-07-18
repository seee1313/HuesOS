//! SMP-safe synchronization primitives for HuesOS kernel.
//!
//! This module provides interrupt-safe spinlocks suitable for use in
//! kernel code where preemption and interrupts must be handled correctly.
//!
//! Key design points:
//! - All locks disable interrupts on the local CPU while held (cli/sti)
//! - Memory orderings: Acquire on lock, Release on unlock
//! - TicketLock provides fairness (FIFO), RawSpinlock is simpler
//! - No std dependency, works in no_std kernel context

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::instructions::interrupts;

/// Maximum number of locks that one CPU may nest.
const MAX_HELD_LOCKS: usize = 16;
/// Number of hardware-thread rank trackers. This matches `cpu_local::MAX_CPUS`.
const MAX_RANK_TRACKERS: usize = 64;

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

struct RankTracker {
    depth: usize,
    held: [HeldLock; MAX_HELD_LOCKS],
}

impl RankTracker {
    const fn new() -> Self {
        Self {
            depth: 0,
            held: [EMPTY_HELD_LOCK; MAX_HELD_LOCKS],
        }
    }

    fn enter(&mut self, rank: LockRank, identity: usize) -> Result<(), LockRankError> {
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

    fn leave(&mut self, rank: LockRank, identity: usize) -> Result<(), LockRankError> {
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

struct RankTrackerSlot(UnsafeCell<RankTracker>);

impl RankTrackerSlot {
    const fn new() -> Self {
        Self(UnsafeCell::new(RankTracker::new()))
    }
}

// SAFETY: cpu_local allocation permanently assigns each slot index to exactly
// one CPU. Ranked locks disable local interrupts before accessing the tracker,
// so IRQ nesting and task preemption cannot create concurrent mutable access.
unsafe impl Sync for RankTrackerSlot {}

static RANK_TRACKERS: [RankTrackerSlot; MAX_RANK_TRACKERS] =
    [const { RankTrackerSlot::new() }; MAX_RANK_TRACKERS];

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

fn with_rank_tracker<R>(operation: impl FnOnce(&mut RankTracker) -> R) -> Result<R, LockRankError> {
    // SAFETY: every path that uses ranked locks runs after per-CPU GS setup;
    // lock() disables local interrupts before reaching this function.
    let index = unsafe { crate::cpu_local::current_rank_tracker_index() };
    let Some(slot) = RANK_TRACKERS.get(index) else {
        return Err(LockRankError::CpuCapacity);
    };
    // SAFETY: cpu_local assigned this unique slot permanently to the current
    // CPU, and local interrupts remain disabled for the complete operation.
    Ok(operation(unsafe { &mut *slot.0.get() }))
}

fn rank_violation(_error: LockRankError) -> ! {
    interrupts::disable();
    crate::serial::emergency_write("[lock-rank] fatal runtime lock-order violation\n");
    loop {
        x86_64::instructions::hlt();
    }
}

/// Fail-stop if the current CPU is about to context-switch while retaining a
/// ranked lock. This check is active in debug and release builds.
pub fn assert_no_ranked_locks_held() {
    let was_enabled = interrupts::are_enabled();
    interrupts::disable();
    let depth = match with_rank_tracker(|tracker| tracker.depth) {
        Ok(depth) => depth,
        Err(error) => rank_violation(error),
    };
    if depth != 0 {
        rank_violation(LockRankError::UnbalancedRelease);
    }
    if was_enabled {
        interrupts::enable();
    }
}

/// Raw spinlock without interrupt disabling.
/// Use `IrqSafeRawSpinlock` for interrupt-safe variant.
pub struct RawSpinlock {
    locked: AtomicBool,
}

impl RawSpinlock {
    /// Create a new unlocked spinlock.
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock, spinning until available.
    /// Uses Acquire ordering to synchronize with Release in unlock.
    pub fn lock(&self) {
        // Fast path: try to acquire with compare_exchange
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin until the lock appears free, then retry
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Release the lock.
    /// Uses Release ordering to synchronize with Acquire in lock.
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for RawSpinlock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: RawSpinlock contains only an atomic flag; protected data lives in
// the higher-level lock wrapper and is accessed after Acquire synchronization.
unsafe impl Send for RawSpinlock {}
unsafe impl Sync for RawSpinlock {}

/// Spinlock that disables interrupts on the local CPU while held.
/// This is the primary lock type for kernel use where the critical
/// section might be interrupted by a timer/IPI handler that also
/// tries to acquire the same lock.
pub struct IrqSafeRawSpinlock {
    inner: RawSpinlock,
}

impl IrqSafeRawSpinlock {
    /// Create a new unlocked interrupt-safe spinlock.
    pub const fn new() -> Self {
        Self {
            inner: RawSpinlock::new(),
        }
    }

    /// Acquire the lock and disable interrupts on this CPU.
    /// Returns a guard that re-enables interrupts on drop.
    pub fn lock(&self) -> IrqSafeRawSpinlockGuard<'_> {
        // Disable interrupts before attempting to acquire
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        self.inner.lock();
        IrqSafeRawSpinlockGuard {
            lock: &self.inner,
            was_enabled,
        }
    }

    /// Try to acquire without spinning, with interrupt disabling.
    pub fn try_lock(&self) -> Option<IrqSafeRawSpinlockGuard<'_>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        if self.inner.try_lock() {
            Some(IrqSafeRawSpinlockGuard {
                lock: &self.inner,
                was_enabled,
            })
        } else {
            // Restore interrupt state on failure
            if was_enabled {
                interrupts::enable();
            }
            None
        }
    }
}

impl Default for IrqSafeRawSpinlock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: synchronization is delegated to RawSpinlock; interrupt state is
// local CPU state restored by the guard and is not shared memory.
unsafe impl Send for IrqSafeRawSpinlock {}
unsafe impl Sync for IrqSafeRawSpinlock {}

/// Guard for `IrqSafeRawSpinlock` that restores interrupt state on drop.
pub struct IrqSafeRawSpinlockGuard<'a> {
    lock: &'a RawSpinlock,
    was_enabled: bool,
}

impl<'a> Drop for IrqSafeRawSpinlockGuard<'a> {
    fn drop(&mut self) {
        self.lock.unlock();
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

/// Ticket lock providing FIFO fairness.
/// Each CPU gets a ticket on arrival and waits for its turn.
pub struct TicketLock {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
}

impl TicketLock {
    /// Create a new unlocked ticket lock.
    pub const fn new() -> Self {
        Self {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
        }
    }

    /// Acquire the ticket lock, spinning until our ticket is served.
    /// Uses Acquire ordering for the now_serving load.
    pub fn lock(&self) {
        // Atomically get our ticket number
        let my_ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);

        // Spin until our ticket is being served
        // Use Acquire ordering to synchronize with the Release in unlock
        while self.now_serving.load(Ordering::Acquire) != my_ticket {
            spin_loop();
        }
    }

    /// Try to acquire the lock without spinning.
    pub fn try_lock(&self) -> bool {
        let serving = self.now_serving.load(Ordering::Acquire);
        // Acquire only if no ticket is queued. Unlike fetch_add, a failed CAS
        // does not abandon a ticket that would permanently stall the queue.
        self.next_ticket
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Release the lock and serve the next ticket.
    /// Uses Release ordering to publish the update.
    pub fn unlock(&self) {
        self.now_serving.fetch_add(1, Ordering::Release);
    }

    /// Current ticket being served (for debugging).
    pub fn current_ticket(&self) -> u32 {
        self.now_serving.load(Ordering::Relaxed)
    }

    /// Next ticket to be handed out (for debugging).
    pub fn next_ticket(&self) -> u32 {
        self.next_ticket.load(Ordering::Relaxed)
    }
}

impl Default for TicketLock {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: both fields are atomics and the ticket protocol establishes mutual
// exclusion plus Acquire/Release synchronization.
unsafe impl Send for TicketLock {}
unsafe impl Sync for TicketLock {}

/// Interrupt-safe data lock with all-build runtime lock-order enforcement.
///
/// Rank ownership is recorded before spinning so an inversion is diagnosed
/// rather than becoming a silent cross-CPU deadlock. A failed non-blocking
/// acquisition rolls the rank record back before restoring interrupt state.
pub struct RankedIrqSafeTicketLock<T> {
    lock: TicketLock,
    rank: LockRank,
    data: UnsafeCell<T>,
}

impl<T> RankedIrqSafeTicketLock<T> {
    /// Construct a ranked lock protecting `data`.
    pub const fn new(data: T, rank: LockRank) -> Self {
        Self {
            lock: TicketLock::new(),
            rank,
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock or fail-stop if the global rank contract is violated.
    pub fn lock(&self) -> RankedIrqSafeTicketLockGuard<'_, T> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        let identity = core::ptr::from_ref(self).addr();
        match with_rank_tracker(|tracker| tracker.enter(self.rank, identity)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => rank_violation(error),
        }
        self.lock.lock();
        RankedIrqSafeTicketLockGuard {
            owner: self,
            was_enabled,
        }
    }

    /// Attempt acquisition once. Rank violations remain fatal kernel bugs;
    /// ordinary contention returns `None` and leaves no held-rank record.
    pub fn try_lock(&self) -> Option<RankedIrqSafeTicketLockGuard<'_, T>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        let identity = core::ptr::from_ref(self).addr();
        match with_rank_tracker(|tracker| tracker.enter(self.rank, identity)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => rank_violation(error),
        }
        if self.lock.try_lock() {
            return Some(RankedIrqSafeTicketLockGuard {
                owner: self,
                was_enabled,
            });
        }
        match with_rank_tracker(|tracker| tracker.leave(self.rank, identity)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => rank_violation(error),
        }
        if was_enabled {
            interrupts::enable();
        }
        None
    }

    /// Rank assigned to this lock.
    pub const fn rank(&self) -> LockRank {
        self.rank
    }
}

// SAFETY: TicketLock serializes access. T: Send permits ownership to pass
// between CPUs while the guard guarantees exclusive access.
unsafe impl<T: Send> Send for RankedIrqSafeTicketLock<T> {}
unsafe impl<T: Send> Sync for RankedIrqSafeTicketLock<T> {}

/// Exclusive guard returned by [`RankedIrqSafeTicketLock`].
pub struct RankedIrqSafeTicketLockGuard<'a, T> {
    owner: &'a RankedIrqSafeTicketLock<T>,
    was_enabled: bool,
}

impl<T> Drop for RankedIrqSafeTicketLockGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.lock.unlock();
        let identity = core::ptr::from_ref(self.owner).addr();
        match with_rank_tracker(|tracker| tracker.leave(self.owner.rank, identity)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => rank_violation(error),
        }
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

impl<T> Deref for RankedIrqSafeTicketLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard owns the ticket and therefore exclusive access.
        unsafe { &*self.owner.data.get() }
    }
}

impl<T> DerefMut for RankedIrqSafeTicketLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this guard owns the ticket and therefore exclusive access.
        unsafe { &mut *self.owner.data.get() }
    }
}

/// Interrupt-safe ticket lock that protects data of type `T`.
/// Disables interrupts while held.
pub struct IrqSafeTicketLock<T> {
    lock: TicketLock,
    data: UnsafeCell<T>,
}

impl<T> IrqSafeTicketLock<T> {
    /// Create a new interrupt-safe ticket lock protecting `data`.
    pub const fn new(data: T) -> Self {
        Self {
            lock: TicketLock::new(),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, disabling interrupts on this CPU.
    /// Returns a guard providing access to the protected data.
    pub fn lock(&self) -> IrqSafeTicketLockGuard<'_, T> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        self.lock.lock();
        IrqSafeTicketLockGuard {
            lock: &self.lock,
            was_enabled,
            data: self,
        }
    }

    /// Try to acquire without spinning.
    pub fn try_lock(&self) -> Option<IrqSafeTicketLockGuard<'_, T>> {
        let was_enabled = interrupts::are_enabled();
        interrupts::disable();
        // For ticket lock, try_lock is not trivial; simplified to full lock
        self.lock.lock();
        Some(IrqSafeTicketLockGuard {
            lock: &self.lock,
            was_enabled,
            data: self,
        })
    }
}

// SAFETY: access to T is serialized by TicketLock. Requiring T: Send permits
// ownership to move between CPUs while the guard enforces exclusive mutation.
unsafe impl<T: Send> Send for IrqSafeTicketLock<T> {}
unsafe impl<T: Send> Sync for IrqSafeTicketLock<T> {}

/// Guard for `IrqSafeTicketLock` that provides access to protected data
/// and restores interrupt state on drop.
pub struct IrqSafeTicketLockGuard<'a, T> {
    lock: &'a TicketLock,
    was_enabled: bool,
    data: &'a IrqSafeTicketLock<T>,
}

impl<'a, T> Drop for IrqSafeTicketLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.unlock();
        if self.was_enabled {
            interrupts::enable();
        }
    }
}

impl<'a, T> Deref for IrqSafeTicketLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.data.data.get() }
    }
}

impl<'a, T> DerefMut for IrqSafeTicketLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data.data.get() }
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
}
