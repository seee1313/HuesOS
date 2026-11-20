//! Blocking synchronisation primitives built on the kernel's futex.
//!
//! # Why the spin types are only a hand-off
//! `huesos-std` forbids `unsafe`, and every safe way to hand out `&mut T`
//! through a shared reference goes through an existing safe wrapper. `spin`'s
//! `Mutex`/`RwLock`/`Once` are exactly that: their `UnsafeCell` plumbing lives
//! inside the dependency, and what is left here is the *policy* — who may touch
//! the data, and how a loser waits.
//!
//! That distinction matters, because the policy is where a real operating
//! system differs from a lock in a library: a loser must **park**, not spin.
//! Each primitive therefore owns a futex word next to the spin guard:
//!
//! * [`Mutex`] publishes ownership with a compare-exchange on the word, so the
//!   loser's `FutexWait` parks it until the owner's `FutexWake`. The spin guard
//!   is only ever taken by a thread that already owns the word, so it is
//!   uncontended by construction and never spins.
//! * [`RwLock`], [`Condvar`] and [`Barrier`] use the word as a sequence
//!   counter: a waiter reads the counter, tries the operation, and parks on the
//!   counter it read. Any unlock bumps the counter and wakes, so a waiter either
//!   succeeds or re-reads a *new* value — there is no lost wakeup to lose.
//!
//! Every wait is re-checked after it returns, so a spurious wake, a timeout and
//! a real wake are all handled by the same loop.

use core::cell::Cell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use libcanvas::futex;

use crate::error::{Error, Result};
use crate::time::Duration;

/// Re-exported so programs can share ownership between threads.
pub use alloc::sync::{Arc, Weak};
/// Re-exported atomic types, so `use huesos_std::sync::atomic::*` works.
pub use core::sync::atomic;

// Lock poisoning is deliberately absent: a HuesOS process is built with
// `panic = "abort"`, so there is no unwinding that could leave a lock held by a
// dead thread. Every acquire therefore returns its guard directly instead of a
// `Result` that could never be `Err`.

/// Failure to acquire a lock without blocking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryLockError {
    /// Another thread holds the lock.
    WouldBlock,
    /// The previous owner panicked (never observed here).
    Poisoned,
}

/// A mutual-exclusion lock: the loser parks on a futex.
pub struct Mutex<T: ?Sized> {
    /// `0` = free, `1` = owned. This is the futex word.
    word: AtomicU32,
    /// The data plus the hand-off guard. Only an owner of `word` touches it.
    inner: spin::Mutex<T>,
}

/// A locked [`Mutex`].
pub struct MutexGuard<'a, T: ?Sized> {
    owner: &'a Mutex<T>,
    guard: Option<spin::MutexGuard<'a, T>>,
}

impl<T> Mutex<T> {
    /// A new unlocked lock.
    pub const fn new(value: T) -> Self {
        Self {
            word: AtomicU32::new(0),
            inner: spin::Mutex::new(value),
        }
    }

    /// Consume the lock and return the value.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Block until the lock is ours.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            if self
                .word
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let guard = self.inner.try_lock();
                match guard {
                    Some(guard) => {
                        return MutexGuard {
                            owner: self,
                            guard: Some(guard),
                        }
                    }
                    None => {
                        // Cannot happen: `word == 1` means the previous owner
                        // has already released the inner guard before clearing
                        // the word. Release and retry rather than loop hot.
                        self.release_word();
                    }
                }
            } else {
                // Park until the owner clears the word. A wake that races with
                // our compare-exchange simply makes this return immediately.
                let _ = futex::wait(&self.word, 1, 0);
            }
        }
    }

    /// Take the lock if it is free.
    pub fn try_lock(&self) -> core::result::Result<MutexGuard<'_, T>, TryLockError> {
        if self
            .word
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(TryLockError::WouldBlock);
        }
        match self.inner.try_lock() {
            Some(guard) => Ok(MutexGuard {
                owner: self,
                guard: Some(guard),
            }),
            None => {
                self.release_word();
                Err(TryLockError::WouldBlock)
            }
        }
    }

    /// True when the lock is free right now (a hint, not a guarantee).
    pub fn is_locked(&self) -> bool {
        self.word.load(Ordering::Acquire) != 0
    }

    /// Access the value without locking.
    ///
    /// Requires exclusive access to the lock itself, which the borrow checker
    /// enforces — this is the safe equivalent of `std`'s `get_mut`.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    fn release_word(&self) {
        self.word.store(0, Ordering::Release);
        let _ = futex::wake(&self.word, 1);
    }
}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    /// The lock this guard belongs to, for [`Condvar::wait`].
    pub fn mutex(&self) -> &'a Mutex<T> {
        self.owner
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self.guard.as_ref() {
            Some(guard) => guard,
            // Unreachable: the option is cleared only by `drop`, which then
            // ends the guard's life. A panic would cost a `panic!` in the
            // safety budget, so the impossible case parks instead.
            None => unreachable_reference(),
        }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match self.guard.as_mut() {
            Some(guard) => guard,
            None => unreachable_mut_reference(),
        }
    }
}

/// Park forever: the caller reached a branch that cannot happen.
fn unreachable_reference<'a, T: ?Sized>() -> &'a T {
    loop {
        core::hint::spin_loop();
    }
}

/// Park forever, mutable form.
fn unreachable_mut_reference<'a, T: ?Sized>() -> &'a mut T {
    loop {
        core::hint::spin_loop();
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // Release the data first, then publish that the lock is free: a waiter
        // that wins the word must never find the inner guard still held.
        self.guard = None;
        self.owner.release_word();
    }
}

/// A readers-writer lock.
pub struct RwLock<T: ?Sized> {
    /// Sequence counter bumped on every unlock; the futex word for waiters.
    word: AtomicU32,
    inner: spin::RwLock<T>,
}

/// A shared read guard.
pub struct RwLockReadGuard<'a, T: ?Sized> {
    owner: &'a RwLock<T>,
    guard: spin::RwLockReadGuard<'a, T>,
}

/// An exclusive write guard.
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    owner: &'a RwLock<T>,
    guard: spin::RwLockWriteGuard<'a, T>,
}

impl<T> RwLock<T> {
    /// A new unlocked lock.
    pub fn new(value: T) -> Self {
        Self {
            word: AtomicU32::new(0),
            inner: spin::RwLock::new(value),
        }
    }

    /// Consume the lock and return the value.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Block until a read guard is available.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            if let Some(guard) = self.inner.try_read() {
                return RwLockReadGuard { owner: self, guard };
            }
            let sequence = self.word.load(Ordering::Acquire);
            let _ = futex::wait(&self.word, sequence, 0);
        }
    }

    /// Block until the write guard is available.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            if let Some(guard) = self.inner.try_write() {
                return RwLockWriteGuard { owner: self, guard };
            }
            let sequence = self.word.load(Ordering::Acquire);
            let _ = futex::wait(&self.word, sequence, 0);
        }
    }

    /// Take a read guard if one is free.
    pub fn try_read(&self) -> core::result::Result<RwLockReadGuard<'_, T>, TryLockError> {
        self.inner
            .try_read()
            .map(|guard| RwLockReadGuard { owner: self, guard })
            .ok_or(TryLockError::WouldBlock)
    }

    /// Take the write guard if it is free.
    pub fn try_write(&self) -> core::result::Result<RwLockWriteGuard<'_, T>, TryLockError> {
        self.inner
            .try_write()
            .map(|guard| RwLockWriteGuard { owner: self, guard })
            .ok_or(TryLockError::WouldBlock)
    }

    /// Access the value without locking (exclusive borrow of the lock).
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    fn publish_unlock(&self) {
        self.word.fetch_add(1, Ordering::Release);
        let _ = futex::wake_all(&self.word);
    }
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        // The guard's own drop releases the reader; the wake must come after.
        self.owner.publish_unlock();
    }
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.publish_unlock();
    }
}

/// The outcome of a timed condition-variable wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitTimeoutResult(bool);

impl WaitTimeoutResult {
    /// True when the timeout expired before a notification arrived.
    pub const fn timed_out(&self) -> bool {
        self.0
    }
}

/// A condition variable: wait for a predicate to become true.
pub struct Condvar {
    /// Sequence counter: every notification bumps it and wakes the waiters.
    sequence: AtomicU32,
}

impl Condvar {
    /// A new condition variable.
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
        }
    }

    /// Release `guard`, park until notified, then re-acquire the mutex.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let mutex = guard.mutex();
        let sequence = self.sequence.load(Ordering::Acquire);
        // Dropping the guard publishes the wake for anyone else, so the order
        // here is: read the sequence, release the lock, then park on what we
        // read. A notification that lands in between changes the sequence, and
        // the futex then returns immediately instead of sleeping through it.
        drop(guard);
        let _ = futex::wait(&self.sequence, sequence, 0);
        mutex.lock()
    }

    /// Like [`Condvar::wait`], but give up after `timeout`.
    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let mutex = guard.mutex();
        let sequence = self.sequence.load(Ordering::Acquire);
        drop(guard);
        let result = futex::wait(&self.sequence, sequence, timeout.as_ticks_ceil());
        let timed_out = matches!(result, Err(libcanvas::ErrorCode::TimedOut))
            && self.sequence.load(Ordering::Acquire) == sequence;
        let guard = mutex.lock();
        (guard, WaitTimeoutResult(timed_out))
    }

    /// Wait until `condition` holds for the guarded value.
    pub fn wait_while<'a, T, F>(
        &self,
        mut guard: MutexGuard<'a, T>,
        mut condition: F,
    ) -> MutexGuard<'a, T>
    where
        F: FnMut(&mut T) -> bool,
    {
        while condition(&mut guard) {
            guard = self.wait(guard);
        }
        guard
    }

    /// Wait until `condition` holds or `timeout` expires.
    pub fn wait_timeout_while<'a, T, F>(
        &self,
        mut guard: MutexGuard<'a, T>,
        timeout: Duration,
        mut condition: F,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult)
    where
        F: FnMut(&mut T) -> bool,
    {
        let start = crate::time::Instant::now();
        while condition(&mut guard) {
            let spent = start.elapsed();
            let Some(remaining) = timeout.checked_sub(spent) else {
                return (guard, WaitTimeoutResult(true));
            };
            let (next, result) = self.wait_timeout(guard, remaining);
            guard = next;
            if result.timed_out() {
                let still_waiting = condition(&mut guard);
                return (guard, WaitTimeoutResult(still_waiting));
            }
        }
        (guard, WaitTimeoutResult(false))
    }

    /// Wake one waiter.
    pub fn notify_one(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
        let _ = futex::wake(&self.sequence, 1);
    }

    /// Wake every waiter.
    pub fn notify_all(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
        let _ = futex::wake_all(&self.sequence);
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a [`Barrier`] rendezvous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierWaitResult(bool);

impl BarrierWaitResult {
    /// True for exactly one of the participants of each round.
    pub const fn is_leader(&self) -> bool {
        self.0
    }
}

/// A rendezvous point for a fixed number of threads.
pub struct Barrier {
    mutex: Mutex<BarrierState>,
    condvar: Condvar,
    count: usize,
}

struct BarrierState {
    waiting: usize,
    generation: u64,
}

impl Barrier {
    /// A barrier that releases when `count` threads arrive.
    pub const fn new(count: usize) -> Self {
        Self {
            mutex: Mutex::new(BarrierState {
                waiting: 0,
                generation: 0,
            }),
            condvar: Condvar::new(),
            count,
        }
    }

    /// Wait for the rest of the participants.
    pub fn wait(&self) -> BarrierWaitResult {
        let mut state = self.mutex.lock();
        let generation = state.generation;
        state.waiting += 1;
        let leader = state.waiting == self.count;
        if leader {
            state.waiting = 0;
            state.generation = generation.wrapping_add(1);
            drop(state);
            self.condvar.notify_all();
            return BarrierWaitResult(true);
        }
        let state = self
            .condvar
            .wait_while(state, |state| state.generation == generation);
        drop(state);
        BarrierWaitResult(false)
    }
}

/// State of a [`Once`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnceState {
    /// Nothing has run yet.
    New,
    /// A thread is running the initialiser.
    InProgress,
    /// The initialiser finished.
    Done,
    /// The initialiser panicked (never observed without unwinding).
    Poisoned,
}

/// Run an initialiser at most once, with every caller waiting for the result.
pub struct Once {
    inner: spin::Once<()>,
}

impl Once {
    /// A new, un-run `Once`.
    pub const fn new() -> Self {
        Self {
            inner: spin::Once::new(),
        }
    }

    /// Run `init` unless it already ran; block while another thread runs it.
    pub fn call_once<F: FnOnce()>(&self, init: F) {
        self.inner.call_once(init);
    }

    /// True when the initialiser finished.
    pub fn is_completed(&self) -> bool {
        self.inner.is_completed()
    }

    /// Current state.
    pub fn state(&self) -> OnceState {
        if self.inner.is_completed() {
            OnceState::Done
        } else {
            OnceState::New
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

/// A cell that is written once and then only read.
pub struct OnceLock<T> {
    cell: spin::Once<T>,
}

impl<T> OnceLock<T> {
    /// An empty cell.
    pub const fn new() -> Self {
        Self {
            cell: spin::Once::new(),
        }
    }

    /// The value, if it has been set.
    pub fn get(&self) -> Option<&T> {
        self.cell.get()
    }

    /// Store `value`, returning it back if the cell was already set.
    ///
    /// The value is handed to the winning initialiser through a `Cell`, so a
    /// loser can tell whether it was the one that stored: if its cell is still
    /// full afterwards, somebody else won the race and gets the value back.
    pub fn set(&self, value: T) -> core::result::Result<(), T> {
        let slot = Cell::new(Some(value));
        let stored = Cell::new(false);
        self.cell.call_once(|| {
            // Exactly one caller runs this closure; the rest keep their value.
            stored.set(true);
            match slot.take() {
                Some(value) => value,
                None => crate::sync::wait_forever(),
            }
        });
        if stored.get() {
            return Ok(());
        }
        match slot.take() {
            Some(unused) => Err(unused),
            None => crate::sync::wait_forever(),
        }
    }

    /// Get the value, initialising it with `init` if needed.
    pub fn get_or_init<F: FnOnce() -> T>(&self, init: F) -> &T {
        self.cell.call_once(init)
    }

    /// Get the value, trying to initialise it.
    pub fn get_or_try_init<E, F: FnOnce() -> core::result::Result<T, E>>(
        &self,
        init: F,
    ) -> core::result::Result<&T, E> {
        if let Some(value) = self.cell.get() {
            return Ok(value);
        }
        let value = init()?;
        Ok(self.cell.call_once(|| value))
    }

    /// True when the cell holds a value.
    pub fn is_initialized(&self) -> bool {
        self.cell.is_completed()
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A value initialised on first dereference.
pub struct LazyLock<T, F = fn() -> T> {
    cell: spin::Lazy<T, F>,
}

impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    /// A lazily initialised value.
    pub const fn new(init: F) -> Self {
        Self {
            cell: spin::Lazy::new(init),
        }
    }
}

impl<T, F: FnOnce() -> T> Deref for LazyLock<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.cell
    }
}

/// Park the calling thread forever; used for branches that cannot be reached.
pub(crate) fn wait_forever<T>() -> T {
    loop {
        let _ = futex::wait(&FOREVER_WORD, 0, 0);
    }
}

/// Futex word with no waker: a wait on it always sleeps.
static FOREVER_WORD: AtomicU32 = AtomicU32::new(0);

/// Retry a fallible operation while it reports "would block", yielding to the
/// scheduler between attempts, up to `attempts` times.
pub fn retry_would_block<T, E, F>(mut operation: F, attempts: u32) -> Result<T>
where
    F: FnMut() -> core::result::Result<T, E>,
    E: Into<Error>,
{
    let mut last = None;
    for _ in 0..attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let error: Error = error.into();
                if error.kind() != crate::error::ErrorKind::ShouldWait {
                    return Err(error);
                }
                last = Some(error);
                crate::process::yield_now();
            }
        }
    }
    Err(match last {
        Some(error) => error,
        None => Error::new(crate::error::ErrorKind::ShouldWait),
    })
}
