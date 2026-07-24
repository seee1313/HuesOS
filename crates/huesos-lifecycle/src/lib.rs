//! # HuesOS Lifecycle Policy
//!
//! Host-testable, dependency-free policy primitives for kernel object and task
//! lifecycle accounting. This crate isolates the *decisions* the kernel must
//! make when reclaiming resources from the privileged, hardware-bound code that
//! carries them out, so those decisions can be unit-tested on the host without
//! QEMU, an allocator, or `unsafe`.
//!
//! It targets the remaining work recorded in `docs/OBJECT_LIFECYCLE.md` and
//! `docs/ROADMAP.md` (Immediate #3): finished-task metadata must be reclaimed
//! with a **bounded** policy rather than accumulated forever, and the
//! collection decision ("an object may be dropped only when both its handle
//! references and its kernel references are zero") must satisfy a small,
//! testable set of invariants.
//!
//! ## What lives here
//!
//! - [`BoundedZombieStore`]: a fixed-capacity FIFO store with explicit eviction
//!   and reclamation accounting. Used to hold finished-task metadata so a
//!   supervisor can still observe an exit status while old records are
//!   reclaimed under a hard bound.
//! - [`TaskGraveyard`]: a concrete wrapper over [`BoundedZombieStore`] for
//!   [`FinishedTask`] records that assigns monotonic generations (ABA defense
//!   for stale waiters) and supports waiter-driven reaping.
//! - [`RefAccount`]: a specification model of the registry's two-counter
//!   collection decision (handle references + kernel references), including the
//!   in-flight handle-transfer invariant.
//!
//! ## What does NOT live here
//!
//! No `Arc`s, no page tables, no locks, no syscalls. The kernel integrates
//! these policies behind the registry/scheduler lock; that integration and its
//! on-target behavior (free-frame reclamation under `-smp 2`) are verified in
//! QEMU, not here. See `docs/OBJECT_LIFECYCLE_POLICY.md`.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: it contains no `unsafe`
//! blocks, no `unwrap` or `expect` calls, and no panicking macros anywhere —
//! including its tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// A finished-task record retained so supervisors and waiters can still observe
/// an exit status after the task's stacks and address space have been reaped.
///
/// Records are small, `Copy`, and plain-old-data so the kernel can mirror them
/// into a supervisor ring if desired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinishedTask {
    /// Kernel object id of the exited process/task.
    pub koid: u64,
    /// Monotonic generation assigned when the exit was recorded. Distinguishes
    /// a fresh exit of a reused `koid` from a stale one (ABA defense).
    pub generation: u64,
    /// Exit status as reported through `ProcessWait`.
    pub exit_code: i64,
    /// Monotonic tick at which the task finished.
    pub exit_tick: u64,
}

/// Outcome of an insertion into a [`BoundedZombieStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome<M> {
    /// There was spare capacity; nothing was evicted and `len` grew by one.
    Retained,
    /// The store was full; the oldest record was evicted to admit the new one
    /// and is returned here for the caller to finalize/reclaim.
    Evicted(M),
}

/// A fixed-capacity, order-preserving FIFO store with bounded reclamation.
///
/// The store admits records up to a compile-time capacity `N`. Once full,
/// inserting a new record **evicts the oldest** and returns it, so memory use
/// is bounded regardless of how many tasks finish. Records may also be reaped
/// explicitly via [`BoundedZombieStore::reap_oldest`] or
/// [`BoundedZombieStore::retain`].
///
/// The backing store is an inline array: no allocator, no `unsafe`, fully
/// deterministic. A capacity of `N == 0` is supported (nothing is ever stored;
/// every insert evicts its own argument).
///
/// ### Accounting invariant
///
/// `total_inserted() == total_evicted() + total_reaped() + len()` always holds.
/// [`BoundedZombieStore::live`] returns the left-minus-right residual, which is
/// `len()` when the invariant holds.
pub struct BoundedZombieStore<M, const N: usize> {
    slots: [Option<M>; N],
    /// Physical index of the oldest element.
    head: usize,
    /// Number of occupied slots.
    len: usize,
    next_generation: u64,
    inserted: u64,
    evicted: u64,
    reaped: u64,
}

impl<M, const N: usize> BoundedZombieStore<M, N> {
    /// Compile-time capacity.
    pub const CAPACITY: usize = N;

    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
            next_generation: 1,
            inserted: 0,
            evicted: 0,
            reaped: 0,
        }
    }

    /// Maximum number of records held simultaneously.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Current number of stored records.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no records are stored.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when `len() == capacity()`.
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Total records ever admitted.
    pub fn total_inserted(&self) -> u64 {
        self.inserted
    }

    /// Total records evicted by overflow.
    pub fn total_evicted(&self) -> u64 {
        self.evicted
    }

    /// Total records removed by explicit reaping / `retain`.
    pub fn total_reaped(&self) -> u64 {
        self.reaped
    }

    /// Residual of the accounting invariant: `inserted - evicted - reaped`.
    /// Equals `len()` while the invariant holds.
    pub fn live(&self) -> u64 {
        self.inserted - self.evicted - self.reaped
    }

    /// The generation that the next [`Self::alloc_generation`] will return.
    pub fn next_generation(&self) -> u64 {
        self.next_generation
    }

    /// Hand out a strictly monotonic generation, saturating at `u64::MAX`.
    ///
    /// Generations let a waiter tell a fresh exit from a stale one when a
    /// `koid` is reused. Saturation (not wraparound) keeps the sequence
    /// monotonic for the lifetime of any realistic system.
    pub fn alloc_generation(&mut self) -> u64 {
        let g = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        g
    }

    /// Insert a record, evicting and returning the oldest if at capacity.
    ///
    /// For `N == 0` nothing can be stored: the argument is returned as
    /// [`InsertOutcome::Evicted`] and counted as an eviction.
    pub fn insert(&mut self, meta: M) -> InsertOutcome<M> {
        self.inserted = self.inserted.saturating_add(1);

        if N == 0 {
            self.evicted = self.evicted.saturating_add(1);
            return InsertOutcome::Evicted(meta);
        }

        if self.len == N {
            // Full: overwrite the oldest slot (which is also the tail) and
            // advance `head`. `slots[head]` is `Some` whenever the store is
            // full by construction.
            let old = self.slots[self.head].take();
            self.slots[self.head] = Some(meta);
            self.head = (self.head + 1) % N;
            match old {
                Some(entry) => {
                    self.evicted = self.evicted.saturating_add(1);
                    InsertOutcome::Evicted(entry)
                }
                // Unreachable while the full => all-slots-occupied invariant
                // holds; kept as a safe, non-panicking fallback.
                None => InsertOutcome::Retained,
            }
        } else {
            let tail = (self.head + self.len) % N;
            self.slots[tail] = Some(meta);
            self.len += 1;
            InsertOutcome::Retained
        }
    }

    /// Remove and return the oldest record, if any. Counts as a reap.
    pub fn reap_oldest(&mut self) -> Option<M> {
        if self.len == 0 || N == 0 {
            return None;
        }
        let old = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        if old.is_some() {
            self.reaped = self.reaped.saturating_add(1);
        }
        old
    }

    /// Keep only records for which `keep` returns true, preserving order.
    /// Returns the number of records removed (and counted as reaped).
    ///
    /// Compaction is done in place; the write cursor never overtakes the read
    /// cursor, so no not-yet-read record is overwritten.
    pub fn retain(&mut self, mut keep: impl FnMut(&M) -> bool) -> usize {
        if N == 0 {
            return 0;
        }
        let start_len = self.len;
        let mut write = 0usize;
        for read in 0..start_len {
            let rphys = (self.head + read) % N;
            let keep_it = match &self.slots[rphys] {
                Some(m) => keep(m),
                None => false,
            };
            if keep_it {
                let wphys = (self.head + write) % N;
                if wphys != rphys {
                    let moved = self.slots[rphys].take();
                    self.slots[wphys] = moved;
                }
                write += 1;
            } else {
                self.slots[rphys] = None;
            }
        }
        let removed = start_len - write;
        self.len = write;
        self.reaped = self.reaped.saturating_add(removed as u64);
        removed
    }

    /// Iterate stored records from oldest to newest.
    pub fn iter(&self) -> impl Iterator<Item = &M> {
        let head = self.head;
        let len = self.len;
        (0..len).filter_map(move |i| self.slots[(head + i) % N].as_ref())
    }
}

impl<M, const N: usize> Default for BoundedZombieStore<M, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded graveyard of [`FinishedTask`] records.
///
/// Wraps [`BoundedZombieStore`] to provide the finished-task policy the kernel
/// needs: monotonic generation assignment on exit, lookup by `(koid,
/// generation)`, and waiter-driven reaping.
pub struct TaskGraveyard<const N: usize> {
    store: BoundedZombieStore<FinishedTask, N>,
}

impl<const N: usize> TaskGraveyard<N> {
    /// Create an empty graveyard.
    pub fn new() -> Self {
        Self {
            store: BoundedZombieStore::new(),
        }
    }

    /// Record a task exit, assigning a fresh monotonic generation.
    ///
    /// Returns the stored record and the insertion outcome (which carries the
    /// evicted record if the graveyard was full and had to make room).
    pub fn record_exit(
        &mut self,
        koid: u64,
        exit_code: i64,
        exit_tick: u64,
    ) -> (FinishedTask, InsertOutcome<FinishedTask>) {
        let generation = self.store.alloc_generation();
        self.record_exit_with_generation(koid, generation, exit_code, exit_tick)
    }

    /// Record an exit using the generation allocated by the owning lifecycle.
    ///
    /// A process lifecycle is the authority for the generation in its exit
    /// payload. Kernel integration must use this method so a graveyard record
    /// and a waiter observing that payload identify the same exit, even when a
    /// `Koid` is reused. This method deliberately does not advance the store's
    /// standalone generation allocator; [`Self::record_exit`] remains for
    /// callers that do not already own a lifecycle generation.
    pub fn record_exit_with_generation(
        &mut self,
        koid: u64,
        generation: u64,
        exit_code: i64,
        exit_tick: u64,
    ) -> (FinishedTask, InsertOutcome<FinishedTask>) {
        let record = FinishedTask {
            koid,
            generation,
            exit_code,
            exit_tick,
        };
        let outcome = self.store.insert(record);
        (record, outcome)
    }

    /// Find a finished-task record by `(koid, generation)`.
    pub fn find(&self, koid: u64, generation: u64) -> Option<FinishedTask> {
        self.store
            .iter()
            .copied()
            .find(|task| task.koid == koid && task.generation == generation)
    }

    /// Find the most recent record for a `koid`, ignoring generation.
    pub fn find_latest(&self, koid: u64) -> Option<FinishedTask> {
        let mut latest: Option<FinishedTask> = None;
        for task in self.store.iter().copied() {
            if task.koid == koid {
                latest = Some(task);
            }
        }
        latest
    }

    /// Reap every record for which `waited(koid, generation)` returns true
    /// (i.e. a supervisor has observed it). Returns the number reaped.
    pub fn reap_waited(&mut self, mut waited: impl FnMut(u64, u64) -> bool) -> usize {
        self.store
            .retain(|task| !waited(task.koid, task.generation))
    }

    /// Number of records currently retained.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Capacity bound.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Total exits ever recorded.
    pub fn total_recorded(&self) -> u64 {
        self.store.total_inserted()
    }

    /// Total records evicted by overflow.
    pub fn total_evicted(&self) -> u64 {
        self.store.total_evicted()
    }

    /// Total records reaped by waiters / explicit reaping.
    pub fn total_reaped(&self) -> u64 {
        self.store.total_reaped()
    }

    /// Borrow the underlying store (for diagnostics / iteration).
    pub fn store(&self) -> &BoundedZombieStore<FinishedTask, N> {
        &self.store
    }
}

impl<const N: usize> Default for TaskGraveyard<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A specification model of the registry's two-counter collection decision.
///
/// The real registry (`huesos-object::registry`) owns one strong reference to a
/// discoverable object and removes it only when **both** counters are zero:
///
/// - **handle references**: handles installed in process tables plus handles in
///   flight inside Channel messages;
/// - **kernel references**: non-handle ownership such as a VMAR mapping keeping
///   its backing VMO frames alive.
///
/// This model captures that decision and its key invariants so they can be
/// tested without the kernel. It is a *specification*: the privileged code is
/// expected to behave as if it consulted this model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefAccount {
    handle_refs: u64,
    kernel_refs: u64,
    /// True once the object has been registered (discoverable).
    registered: bool,
    /// True once collection has removed the registry's strong reference.
    collected: bool,
}

impl RefAccount {
    /// A newly registered, discoverable object with no references.
    pub fn registered() -> Self {
        Self {
            handle_refs: 0,
            kernel_refs: 0,
            registered: true,
            collected: false,
        }
    }

    /// An object that was never registered (e.g. a purely internal one).
    pub fn unregistered() -> Self {
        Self {
            handle_refs: 0,
            kernel_refs: 0,
            registered: false,
            collected: false,
        }
    }

    /// Current handle-reference count.
    pub fn handle_refs(&self) -> u64 {
        self.handle_refs
    }

    /// Current kernel-reference count.
    pub fn kernel_refs(&self) -> u64 {
        self.kernel_refs
    }

    /// Whether the object is still discoverable in the registry.
    pub fn is_registered(&self) -> bool {
        self.registered && !self.collected
    }

    /// Whether the registry's strong reference has been collected.
    pub fn is_collected(&self) -> bool {
        self.collected
    }

    /// The collection decision: the object may be dropped iff registered, not
    /// yet collected, and both reference counts are zero.
    pub fn may_collect(&self) -> bool {
        self.registered && !self.collected && self.handle_refs == 0 && self.kernel_refs == 0
    }

    /// Open `n` handle references (installing handles / enqueueing a transfer).
    pub fn open_handles(&mut self, n: u64) -> bool {
        if self.collected {
            return false;
        }
        self.handle_refs = self.handle_refs.saturating_add(n);
        true
    }

    /// Close `n` handle references, saturating at zero (never underflows).
    pub fn close_handles(&mut self, n: u64) {
        self.handle_refs = self.handle_refs.saturating_sub(n);
    }

    /// Open `n` kernel references (e.g. a VMAR mapping).
    pub fn open_kernel_refs(&mut self, n: u64) -> bool {
        if self.collected {
            return false;
        }
        self.kernel_refs = self.kernel_refs.saturating_add(n);
        true
    }

    /// Close `n` kernel references, saturating at zero.
    pub fn close_kernel_refs(&mut self, n: u64) {
        self.kernel_refs = self.kernel_refs.saturating_sub(n);
    }

    /// Attempt collection. Returns true (and marks collected) only if
    /// [`Self::may_collect`] holds; otherwise leaves the account unchanged.
    pub fn try_collect(&mut self) -> bool {
        if self.may_collect() {
            self.collected = true;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! Host tests. Deliberately free of `unwrap`, `expect`, and panicking
    //! macros (an assert expands to a panic at runtime but does not match the
    //! budget's textual panic-macro pattern), keeping this crate
    //! budget-neutral.

    use super::*;
    use std::vec;
    use std::vec::Vec;

    // --- BoundedZombieStore mechanics ---

    #[test]
    fn empty_store_is_empty() {
        let store: BoundedZombieStore<u32, 4> = BoundedZombieStore::new();
        assert!(store.is_empty());
        assert!(!store.is_full());
        assert_eq!(store.len(), 0);
        assert_eq!(store.capacity(), 4);
        assert_eq!(store.iter().count(), 0);
    }

    #[test]
    fn insert_below_capacity_retains() {
        let mut store: BoundedZombieStore<u32, 4> = BoundedZombieStore::new();
        assert_eq!(store.insert(10), InsertOutcome::Retained);
        assert_eq!(store.insert(20), InsertOutcome::Retained);
        assert_eq!(store.len(), 2);
        assert!(!store.is_full());
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![10, 20]);
    }

    #[test]
    fn insert_at_capacity_evicts_oldest_fifo() {
        let mut store: BoundedZombieStore<u32, 3> = BoundedZombieStore::new();
        assert_eq!(store.insert(1), InsertOutcome::Retained);
        assert_eq!(store.insert(2), InsertOutcome::Retained);
        assert_eq!(store.insert(3), InsertOutcome::Retained);
        assert!(store.is_full());
        // Fourth insert evicts the oldest (1).
        assert_eq!(store.insert(4), InsertOutcome::Evicted(1));
        assert_eq!(store.len(), 3);
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![2, 3, 4]);
        // Fifth insert evicts 2.
        assert_eq!(store.insert(5), InsertOutcome::Evicted(2));
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![3, 4, 5]);
    }

    #[test]
    fn wraparound_many_inserts_preserve_order() {
        let mut store: BoundedZombieStore<u32, 4> = BoundedZombieStore::new();
        for value in 0..50u32 {
            let _ = store.insert(value);
        }
        // Only the last 4 survive, oldest to newest.
        assert_eq!(store.len(), 4);
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![46, 47, 48, 49]);
        assert_eq!(store.total_inserted(), 50);
        assert_eq!(store.total_evicted(), 46);
        assert_eq!(store.total_reaped(), 0);
    }

    #[test]
    fn reap_oldest_drains_in_order() {
        let mut store: BoundedZombieStore<u32, 4> = BoundedZombieStore::new();
        let _ = store.insert(7);
        let _ = store.insert(8);
        assert_eq!(store.reap_oldest(), Some(7));
        assert_eq!(store.reap_oldest(), Some(8));
        assert_eq!(store.reap_oldest(), None);
        assert!(store.is_empty());
        assert_eq!(store.total_reaped(), 2);
    }

    #[test]
    fn retain_compacts_and_counts() {
        let mut store: BoundedZombieStore<u32, 8> = BoundedZombieStore::new();
        for value in 1..=6u32 {
            let _ = store.insert(value);
        }
        // Keep only even values.
        let removed = store.retain(|v| v % 2 == 0);
        assert_eq!(removed, 3);
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![2, 4, 6]);
        assert_eq!(store.len(), 3);
        assert_eq!(store.total_reaped(), 3);
    }

    #[test]
    fn retain_across_wraparound() {
        let mut store: BoundedZombieStore<u32, 4> = BoundedZombieStore::new();
        // Force the ring head off zero.
        for value in 0..6u32 {
            let _ = store.insert(value); // ends holding [2,3,4,5], head advanced
        }
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![2, 3, 4, 5]);
        // Keep values >= 4, exercising compaction over a wrapped layout.
        let removed = store.retain(|v| *v >= 4);
        assert_eq!(removed, 2);
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![4, 5]);
        // Still functional after compaction.
        assert_eq!(store.insert(9), InsertOutcome::Retained);
        assert_eq!(store.iter().copied().collect::<Vec<u32>>(), vec![4, 5, 9]);
    }

    #[test]
    fn accounting_invariant_holds() {
        let mut store: BoundedZombieStore<u32, 3> = BoundedZombieStore::new();
        for value in 0..20u32 {
            let _ = store.insert(value);
        }
        let _ = store.reap_oldest();
        let _ = store.retain(|v| *v % 2 == 0);
        assert_eq!(store.live(), store.len() as u64);
        assert_eq!(
            store.total_inserted(),
            store.total_evicted() + store.total_reaped() + store.len() as u64
        );
    }

    #[test]
    fn zero_capacity_store_never_stores() {
        let mut store: BoundedZombieStore<u32, 0> = BoundedZombieStore::new();
        assert_eq!(store.capacity(), 0);
        assert!(store.is_full());
        assert!(store.is_empty());
        // Inserting immediately evicts its own argument.
        assert_eq!(store.insert(42), InsertOutcome::Evicted(42));
        assert_eq!(store.len(), 0);
        assert_eq!(store.total_inserted(), 1);
        assert_eq!(store.total_evicted(), 1);
        assert_eq!(store.reap_oldest(), None);
        assert_eq!(store.retain(|_| true), 0);
    }

    #[test]
    fn generations_are_strictly_monotonic() {
        let mut store: BoundedZombieStore<u32, 2> = BoundedZombieStore::new();
        let first = store.alloc_generation();
        let second = store.alloc_generation();
        assert!(second > first);
        assert_eq!(second, first + 1);
        assert_eq!(store.next_generation(), second + 1);
    }

    #[test]
    fn generation_saturates_instead_of_wrapping() {
        let mut store: BoundedZombieStore<u32, 1> = BoundedZombieStore::new();
        // Force the counter near the top and confirm saturation.
        store.next_generation = u64::MAX;
        let g = store.alloc_generation();
        assert_eq!(g, u64::MAX);
        assert_eq!(store.next_generation(), u64::MAX);
    }

    // --- TaskGraveyard policy ---

    fn exit_code_of(task: Option<FinishedTask>) -> i64 {
        match task {
            Some(t) => t.exit_code,
            None => i64::MIN,
        }
    }

    #[test]
    fn record_exit_assigns_increasing_generations() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let (a, oa) = yard.record_exit(100, -1, 1000);
        let (b, ob) = yard.record_exit(101, 0, 1001);
        assert_eq!(oa, InsertOutcome::Retained);
        assert_eq!(ob, InsertOutcome::Retained);
        assert!(b.generation > a.generation);
        assert_eq!(yard.len(), 2);
    }

    #[test]
    fn externally_owned_generation_is_retained_verbatim() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let (record, outcome) = yard.record_exit_with_generation(7, 99, 3, 500);
        assert_eq!(outcome, InsertOutcome::Retained);
        assert_eq!(record.generation, 99);
        assert_eq!(yard.find(7, 99), Some(record));
        // A lifecycle-provided generation does not consume the standalone
        // allocator used by policy-only callers.
        assert_eq!(yard.store().next_generation(), 1);
    }

    #[test]
    fn find_by_koid_and_generation() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let (rec, _) = yard.record_exit(7, 3, 500);
        assert_eq!(exit_code_of(yard.find(7, rec.generation)), 3);
        // Wrong generation misses (ABA defense).
        assert_eq!(yard.find(7, rec.generation + 99), None);
        assert_eq!(yard.find(8, rec.generation), None);
    }

    #[test]
    fn find_latest_returns_most_recent_for_koid() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let _ = yard.record_exit(5, 1, 10);
        let _ = yard.record_exit(5, 2, 20);
        let latest = yard.find_latest(5);
        assert_eq!(exit_code_of(latest), 2);
        assert_eq!(yard.find_latest(6), None);
    }

    #[test]
    fn koid_reuse_is_distinguished_by_generation() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let (old, _) = yard.record_exit(9, 111, 1);
        let (new, _) = yard.record_exit(9, 222, 2);
        assert_ne!(old.generation, new.generation);
        // A waiter holding the old generation sees the old exit, not the new.
        assert_eq!(exit_code_of(yard.find(9, old.generation)), 111);
        assert_eq!(exit_code_of(yard.find(9, new.generation)), 222);
    }

    #[test]
    fn overflow_evicts_oldest_exit() {
        let mut yard: TaskGraveyard<2> = TaskGraveyard::new();
        let (first, _) = yard.record_exit(1, 0, 0);
        let _ = yard.record_exit(2, 0, 0);
        let (_, outcome) = yard.record_exit(3, 0, 0);
        let mut evicted_koid: Option<u64> = None;
        match outcome {
            InsertOutcome::Evicted(evicted) => evicted_koid = Some(evicted.koid),
            InsertOutcome::Retained => {}
        }
        assert_eq!(evicted_koid, Some(first.koid));
        assert_eq!(yard.len(), 2);
        assert_eq!(yard.total_evicted(), 1);
        // The evicted record is no longer findable.
        assert_eq!(yard.find(first.koid, first.generation), None);
    }

    #[test]
    fn reap_waited_removes_only_observed() {
        let mut yard: TaskGraveyard<8> = TaskGraveyard::new();
        let (a, _) = yard.record_exit(1, 0, 0);
        let (b, _) = yard.record_exit(2, 0, 0);
        let (c, _) = yard.record_exit(3, 0, 0);
        // A supervisor has observed exits a and c, but not b.
        let reaped = yard.reap_waited(|koid, _gen| koid == 1 || koid == 3);
        assert_eq!(reaped, 2);
        assert_eq!(yard.len(), 1);
        assert_eq!(yard.find(a.koid, a.generation), None);
        assert_eq!(yard.find(c.koid, c.generation), None);
        assert_ne!(yard.find(b.koid, b.generation), None);
    }

    // --- RefAccount collection model ---

    #[test]
    fn fresh_registered_object_is_collectable() {
        let mut account = RefAccount::registered();
        assert!(account.is_registered());
        assert!(account.may_collect());
        assert!(account.try_collect());
        assert!(account.is_collected());
        assert!(!account.is_registered());
        // Collection is idempotent: once collected, it cannot collect again.
        assert!(!account.may_collect());
        assert!(!account.try_collect());
    }

    #[test]
    fn handle_refs_block_collection() {
        let mut account = RefAccount::registered();
        account.open_handles(2);
        assert!(!account.may_collect());
        account.close_handles(1);
        assert!(!account.may_collect());
        account.close_handles(1);
        assert!(account.may_collect());
    }

    #[test]
    fn kernel_refs_block_collection_independently() {
        let mut account = RefAccount::registered();
        // No handles, but a VMAR mapping holds a kernel reference.
        account.open_kernel_refs(1);
        assert!(!account.may_collect());
        // Closing every handle still does not free it while mapped.
        account.close_handles(100); // saturates at zero
        assert!(!account.may_collect());
        account.close_kernel_refs(1);
        assert!(account.may_collect());
    }

    #[test]
    fn in_flight_handle_keeps_object_across_transient_zero() {
        // Model: 1 handle in a process table, then it is transferred into a
        // Channel message. remove_keep_alive keeps the global handle count
        // stable across the transfer, so there is never a moment where the
        // object is collectable while a capability is in flight.
        let mut account = RefAccount::registered();
        account.open_handles(1); // installed in the sender's table
        // Transfer: close the table handle and open the in-flight handle
        // atomically; the count stays at 1 throughout.
        account.close_handles(1);
        account.open_handles(1);
        assert_eq!(account.handle_refs(), 1);
        assert!(!account.may_collect());
        // The message is dropped unread, releasing the in-flight count:
        account.close_handles(1);
        assert!(account.may_collect());
    }

    #[test]
    fn counters_saturate_and_never_underflow() {
        let mut account = RefAccount::registered();
        account.close_handles(5); // closing more than open must not underflow
        assert_eq!(account.handle_refs(), 0);
        account.open_handles(u64::MAX);
        account.open_handles(1); // saturating add
        assert_eq!(account.handle_refs(), u64::MAX);
        assert!(!account.may_collect());
    }

    #[test]
    fn unregistered_object_is_not_collectable_via_registry() {
        let mut account = RefAccount::unregistered();
        assert!(!account.is_registered());
        assert!(!account.may_collect());
        assert!(!account.try_collect());
    }
    #[test]
    fn collected_account_cannot_be_resurrected() {
        let mut account = RefAccount::registered();
        assert!(account.try_collect());
        assert!(!account.open_handles(1));
        assert!(!account.open_kernel_refs(1));
        assert_eq!(account.handle_refs(), 0);
        assert_eq!(account.kernel_refs(), 0);
        assert!(!account.try_collect());
    }

}
