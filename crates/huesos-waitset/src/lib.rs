//! # HuesOS Multi-Object Wait Policy
//!
//! Host-testable, dependency-free policy for **multiplexed multi-object waits**
//! with cancellation and timeouts. It advances
//! [ROADMAP.md](../../docs/ROADMAP.md) Immediate #4 (*Blocking syscalls / wait
//! primitives — multiplexed multi-object wait / cancel*).
//!
//! Zircon-style waits observe *signals* on objects (readable, writable,
//! canceled, ...). A multi-object wait blocks until a condition over a set of
//! waited objects holds (any satisfied, or all satisfied), and can be canceled
//! or time out. This crate models that dispatch logic deterministically so it
//! can be unit-tested without the scheduler, QEMU, or `unsafe`.
//!
//! ## What lives here
//!
//! - [`Signals`]: a small signal bitset with the common channel/object signals
//!   and set operations.
//! - [`WaitItem`]: one waited-on object (a user `key`, the `awaited` signals,
//!   and the currently `active` signals), satisfied when `active` intersects
//!   `awaited`.
//! - [`WaitSet`]: a bounded, key-identified collection of wait items with
//!   `add`/`remove`/`signal`/`cancel` and satisfaction queries.
//! - [`WaitMode`] (`Any`/`All`) and [`WaitOutcome`]
//!   (`Pending`/`Signaled`/`Canceled`/`TimedOut`), plus [`WaitSet::poll`] and
//!   [`WaitSet::poll_at`] (deadline-aware).
//!
//! ## What does NOT live here
//!
//! No blocking, no scheduler park/wake, no syscall dispatch, and no locks. The
//! privileged integration (wiring `WaitSet` decisions into the kernel's blocking
//! `ChannelRead`/`PortRead`/multi-wait syscalls and the scheduler hooks) is
//! verified on-target. See `docs/MULTI_OBJECT_WAIT.md`.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: no `unsafe` blocks, no
//! `unwrap` or `expect` calls, and no panicking macros anywhere — including its
//! tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// A set of object signals, as a bitset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signals(u32);

impl Signals {
    /// No signals.
    pub const NONE: Signals = Signals(0);
    /// Object is readable (e.g. a channel has queued messages).
    pub const READABLE: Signals = Signals(1 << 0);
    /// Object is writable (e.g. a channel has buffer space).
    pub const WRITABLE: Signals = Signals(1 << 1);
    /// Object was canceled (e.g. its handle was closed).
    pub const CANCELED: Signals = Signals(1 << 2);
    /// The peer end was closed.
    pub const PEER_CLOSED: Signals = Signals(1 << 3);
    /// Generic user signal (events, process exit, ...).
    pub const SIGNALED: Signals = Signals(1 << 4);

    /// Construct from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Signals(bits)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when no signal is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True when every signal in `other` is set in `self`.
    pub const fn contains(self, other: Signals) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when any signal in `other` is set in `self`.
    pub const fn intersects(self, other: Signals) -> bool {
        self.0 & other.0 != 0
    }

    /// Set union.
    pub const fn union(self, other: Signals) -> Signals {
        Signals(self.0 | other.0)
    }

    /// Set intersection.
    pub const fn intersection(self, other: Signals) -> Signals {
        Signals(self.0 & other.0)
    }

    /// Set difference (`self` minus `other`).
    pub const fn difference(self, other: Signals) -> Signals {
        Signals(self.0 & !other.0)
    }
}

/// One waited-on object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitItem {
    /// User-supplied identifier for this item (returned to the waiter).
    pub key: u64,
    /// Signals the waiter is interested in.
    pub awaited: Signals,
    /// Signals currently observed on the object.
    pub active: Signals,
}

impl WaitItem {
    /// A new item with no active signals.
    pub fn new(key: u64, awaited: Signals) -> Self {
        Self {
            key,
            awaited,
            active: Signals::NONE,
        }
    }

    /// True when any awaited signal is active.
    pub fn is_satisfied(&self) -> bool {
        self.active.intersects(self.awaited)
    }

    /// The subset of awaited signals that are currently active.
    pub fn satisfied_signals(&self) -> Signals {
        self.active.intersection(self.awaited)
    }
}

/// Wait completion condition over a [`WaitSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitMode {
    /// Complete when at least one item is satisfied.
    Any,
    /// Complete when every item is satisfied (vacuously true when empty).
    All,
}

/// The result of polling a [`WaitSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The mode condition is not yet met and no deadline has passed.
    Pending,
    /// The mode condition is met.
    Signaled,
    /// The wait was canceled.
    Canceled,
    /// The deadline passed before the mode condition was met.
    TimedOut,
}

/// A bounded, key-identified set of waited-on objects.
///
/// Items are stored compactly (indices `0..len` are occupied); `remove` keeps
/// the occupied prefix contiguous. Capacity is the const parameter `N`.
pub struct WaitSet<const N: usize> {
    items: [Option<WaitItem>; N],
    len: usize,
    canceled: bool,
}

impl<const N: usize> WaitSet<N> {
    /// An empty, non-canceled wait set.
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
            len: 0,
            canceled: false,
        }
    }

    /// Capacity bound.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Number of items currently waited on.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no items are waited on.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether [`cancel`](Self::cancel) has been called.
    pub fn is_canceled(&self) -> bool {
        self.canceled
    }

    /// Add an item awaiting `awaited` signals under `key`. Returns false if the
    /// set is full or `key` is already present.
    pub fn add(&mut self, key: u64, awaited: Signals) -> bool {
        if self.canceled || self.len == N {
            return false;
        }
        if self.occupied().any(|item| item.key == key) {
            return false;
        }
        self.items[self.len] = Some(WaitItem::new(key, awaited));
        self.len += 1;
        true
    }

    /// Remove the item with `key`, keeping the occupied prefix contiguous.
    /// Returns whether an item was removed.
    pub fn remove(&mut self, key: u64) -> bool {
        match self.position(key) {
            Some(i) => {
                self.items[i..self.len].rotate_left(1);
                self.items[self.len - 1] = None;
                self.len = self.len.saturating_sub(1);
                true
            }
            None => false,
        }
    }

    /// Add `signals` to the active set of the item with `key`. Returns whether
    /// the item exists.
    pub fn signal(&mut self, key: u64, signals: Signals) -> bool {
        match self.find_mut(key) {
            Some(item) => {
                item.active = item.active.union(signals);
                true
            }
            None => false,
        }
    }

    /// Replace the active set of the item with `key`. Returns whether the item
    /// exists.
    pub fn set_active(&mut self, key: u64, signals: Signals) -> bool {
        match self.find_mut(key) {
            Some(item) => {
                item.active = signals;
                true
            }
            None => false,
        }
    }

    /// Clear `signals` from the active set of the item with `key`. Returns
    /// whether the item exists.
    pub fn clear_signal(&mut self, key: u64, signals: Signals) -> bool {
        match self.find_mut(key) {
            Some(item) => {
                item.active = item.active.difference(signals);
                true
            }
            None => false,
        }
    }

    /// Mark the whole wait as canceled. Cancellation takes precedence over
    /// satisfaction in [`poll`](Self::poll).
    pub fn cancel(&mut self) {
        self.canceled = true;
    }

    /// Look up a copy of the item with `key`, if present.
    pub fn get(&self, key: u64) -> Option<WaitItem> {
        self.occupied().find(|item| item.key == key).copied()
    }

    /// Iterate all waited-on items.
    pub fn items(&self) -> impl Iterator<Item = &WaitItem> {
        self.occupied()
    }

    /// Iterate the items that are currently satisfied.
    pub fn satisfied(&self) -> impl Iterator<Item = &WaitItem> {
        self.occupied().filter(|item| item.is_satisfied())
    }

    /// Number of satisfied items.
    pub fn satisfied_count(&self) -> usize {
        self.occupied().filter(|item| item.is_satisfied()).count()
    }

    /// True when at least one item is satisfied.
    pub fn any_satisfied(&self) -> bool {
        self.occupied().any(|item| item.is_satisfied())
    }

    /// True when every item is satisfied (vacuously true when empty).
    pub fn all_satisfied(&self) -> bool {
        self.occupied().all(|item| item.is_satisfied())
    }

    /// Poll the wait set under `mode`, ignoring time. Cancellation wins; then
    /// the mode condition decides `Signaled` vs `Pending`.
    pub fn poll(&self, mode: WaitMode) -> WaitOutcome {
        if self.canceled {
            return WaitOutcome::Canceled;
        }
        let done = match mode {
            WaitMode::Any => self.any_satisfied(),
            WaitMode::All => self.all_satisfied(),
        };
        if done {
            WaitOutcome::Signaled
        } else {
            WaitOutcome::Pending
        }
    }

    /// Poll with a deadline: if the mode condition is not met and
    /// `now >= deadline`, return [`WaitOutcome::TimedOut`]. A `None` deadline
    /// means wait forever (no timeout).
    pub fn poll_at(&self, mode: WaitMode, now: u64, deadline: Option<u64>) -> WaitOutcome {
        let base = self.poll(mode);
        if matches!(base, WaitOutcome::Pending) {
            if let Some(d) = deadline {
                if now >= d {
                    return WaitOutcome::TimedOut;
                }
            }
        }
        base
    }

    // --- internal helpers ---

    fn occupied(&self) -> impl Iterator<Item = &WaitItem> {
        self.items.iter().filter_map(|slot| slot.as_ref())
    }

    fn find_mut(&mut self, key: u64) -> Option<&mut WaitItem> {
        self.items
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|item| item.key == key)
    }

    fn position(&self, key: u64) -> Option<usize> {
        self.items.iter().position(|slot| match slot {
            Some(item) => item.key == key,
            None => false,
        })
    }
}

impl<const N: usize> Default for WaitSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! Host tests. Kept free of `unwrap`, `expect`, and panicking macros
    //! (asserts expand to a panic at runtime but do not match the budget's
    //! textual panic-macro pattern), keeping this crate budget-neutral.

    use super::*;
    use std::vec::Vec;

    // --- Signals ---

    #[test]
    fn signals_set_operations() {
        let rw = Signals::READABLE.union(Signals::WRITABLE);
        assert!(rw.contains(Signals::READABLE));
        assert!(rw.contains(Signals::WRITABLE));
        assert!(!rw.contains(Signals::CANCELED));
        assert!(rw.intersects(Signals::READABLE));
        assert!(!rw.intersects(Signals::CANCELED));
        assert_eq!(rw.difference(Signals::READABLE), Signals::WRITABLE);
        assert_eq!(rw.intersection(Signals::READABLE), Signals::READABLE);
        assert!(Signals::NONE.is_empty());
        assert!(!rw.is_empty());
    }

    #[test]
    fn signals_bits_round_trip() {
        let s = Signals::from_bits(0b1010);
        assert_eq!(s.bits(), 0b1010);
    }

    // --- WaitItem ---

    #[test]
    fn wait_item_satisfaction() {
        let mut item = WaitItem::new(7, Signals::READABLE);
        assert!(!item.is_satisfied());
        item.active = Signals::WRITABLE; // not awaited
        assert!(!item.is_satisfied());
        item.active = item.active.union(Signals::READABLE);
        assert!(item.is_satisfied());
        assert_eq!(item.satisfied_signals(), Signals::READABLE);
    }

    // --- WaitSet membership ---

    #[test]
    fn add_len_capacity_and_rejects() {
        let mut ws: WaitSet<2> = WaitSet::new();
        assert!(ws.is_empty());
        assert_eq!(ws.capacity(), 2);
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.add(2, Signals::WRITABLE));
        assert_eq!(ws.len(), 2);
        // Full.
        assert!(!ws.add(3, Signals::CANCELED));
        // Duplicate key.
        assert!(!ws.add(1, Signals::CANCELED));
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn remove_compacts_and_reports() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.add(2, Signals::READABLE));
        assert!(ws.add(3, Signals::READABLE));
        assert!(ws.remove(2));
        assert_eq!(ws.len(), 2);
        assert_eq!(ws.get(2), None);
        // Remaining keys still present.
        assert_ne!(ws.get(1), None);
        assert_ne!(ws.get(3), None);
        // Removing an absent key is a no-op.
        assert!(!ws.remove(99));
        assert_eq!(ws.len(), 2);
        // Can add again after removal.
        assert!(ws.add(4, Signals::WRITABLE));
        assert_eq!(ws.len(), 3);
    }

    // --- signaling + satisfaction ---

    #[test]
    fn signal_and_clear_affect_satisfaction() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(!ws.any_satisfied());
        assert!(ws.signal(1, Signals::READABLE));
        assert!(ws.any_satisfied());
        assert_eq!(ws.satisfied_count(), 1);
        assert!(ws.clear_signal(1, Signals::READABLE));
        assert!(!ws.any_satisfied());
        // Signaling an absent key reports false.
        assert!(!ws.signal(99, Signals::READABLE));
    }

    #[test]
    fn satisfied_iterates_only_ready_items() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.add(2, Signals::WRITABLE));
        assert!(ws.signal(2, Signals::WRITABLE));
        let keys: Vec<u64> = ws.satisfied().map(|item| item.key).collect();
        assert_eq!(keys, std::vec![2]);
    }

    // --- poll: Any / All ---

    #[test]
    fn poll_any_pending_then_signaled() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.add(2, Signals::WRITABLE));
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Pending);
        assert!(ws.signal(2, Signals::WRITABLE));
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Signaled);
    }

    #[test]
    fn poll_all_requires_every_item() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.add(2, Signals::WRITABLE));
        assert!(ws.signal(1, Signals::READABLE));
        // Only one of two satisfied.
        assert_eq!(ws.poll(WaitMode::All), WaitOutcome::Pending);
        assert!(ws.signal(2, Signals::WRITABLE));
        assert_eq!(ws.poll(WaitMode::All), WaitOutcome::Signaled);
    }

    #[test]
    fn poll_all_on_empty_is_vacuously_signaled() {
        let ws: WaitSet<4> = WaitSet::new();
        assert!(ws.is_empty());
        assert_eq!(ws.poll(WaitMode::All), WaitOutcome::Signaled);
        // Any on empty stays pending.
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Pending);
    }

    // --- cancellation ---

    #[test]
    fn cancel_takes_precedence_over_satisfaction() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.signal(1, Signals::READABLE));
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Signaled);
        ws.cancel();
        assert!(ws.is_canceled());
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Canceled);
        assert_eq!(ws.poll(WaitMode::All), WaitOutcome::Canceled);
    }

    // --- timeout ---

    #[test]
    fn poll_at_times_out_when_pending_past_deadline() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        // Before the deadline: still pending.
        assert_eq!(ws.poll_at(WaitMode::Any, 5, Some(10)), WaitOutcome::Pending);
        // At and after the deadline: timed out.
        assert_eq!(ws.poll_at(WaitMode::Any, 10, Some(10)), WaitOutcome::TimedOut);
        assert_eq!(ws.poll_at(WaitMode::Any, 11, Some(10)), WaitOutcome::TimedOut);
        // No deadline means never times out.
        assert_eq!(ws.poll_at(WaitMode::Any, 1000, None), WaitOutcome::Pending);
    }

    #[test]
    fn poll_at_signaled_ignores_deadline() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        assert!(ws.signal(1, Signals::READABLE));
        // Satisfied, even though the deadline has long passed.
        assert_eq!(ws.poll_at(WaitMode::Any, 999, Some(10)), WaitOutcome::Signaled);
    }

    #[test]
    fn cancel_wins_over_timeout() {
        let mut ws: WaitSet<4> = WaitSet::new();
        assert!(ws.add(1, Signals::READABLE));
        ws.cancel();
        assert_eq!(ws.poll_at(WaitMode::Any, 999, Some(10)), WaitOutcome::Canceled);
    }

    // --- CANCELED as a signal ---

    #[test]
    fn awaiting_canceled_signal_satisfies() {
        let mut ws: WaitSet<4> = WaitSet::new();
        // Wait specifically for the CANCELED signal on an object.
        assert!(ws.add(1, Signals::CANCELED));
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Pending);
        assert!(ws.signal(1, Signals::CANCELED));
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Signaled);
    }
    #[test]
    fn canceled_wait_set_rejects_new_items() {
        let mut ws: WaitSet<2> = WaitSet::new();
        ws.cancel();
        assert!(!ws.add(1, Signals::READABLE));
        assert_eq!(ws.len(), 0);
        assert_eq!(ws.poll(WaitMode::Any), WaitOutcome::Canceled);
    }

}
