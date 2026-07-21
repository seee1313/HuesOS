//! # hues-async — a minimal, allocation-free futures executor for fast drivers
//!
//! `hues-async` is a tiny run-to-completion executor for `no_std` ring-3 driver
//! processes. It is built for the lowest practical overhead so device drivers
//! (the first being NVMe, ROADMAP Short-Term #7) can drive queue-based I/O
//! without a heavyweight runtime.
//!
//! ## Design
//!
//! - **Futures-based.** Tasks are [`core::future::Future`]s. An I/O operation is
//!   a future that completes when the device signals completion.
//! - **Allocation-free, fixed capacity.** Futures are stored *inline* in a
//!   static table of `TASKS` slots, each holding up to `F` bytes. Spawning a
//!   future larger than `F` is a (checked) error; nothing is ever heap-allocated.
//! - **Ready bitmask.** A single `u64` tracks which slots are ready to poll
//!   (so `TASKS <= 64`). Waking is one bit-set; the run loop is a tight
//!   trailing-zeros scan.
//! - **No-alloc waker.** The [`Waker`] handed to a future points at the task's
//!   stable slot; waking sets the slot's ready bit. For *external* completions
//!   (e.g. an NVMe completion-queue entry observed by the driver's event loop)
//!   the driver calls [`Executor::wake`] with the [`TaskId`] returned by
//!   [`Executor::spawn`] — this path is generation-guarded against stale ids.
//! - **Hybrid completion.** The executor only polls ready tasks. The *driver*
//!   implements the hybrid wait (a short completion-queue poll window after a
//!   submit, then falling back to an interrupt wait) in its event loop; this
//!   crate stays mechanism-only.
//!
//! ## Contracts (read before use)
//!
//! - **Single-threaded.** One executor runs on one core. The waker and the
//!   run loop are not internally synchronized; the driver process is expected
//!   to drive everything from one thread (the completion handler wakes tasks
//!   from that same thread).
//! - **Stable address.** The executor must not be moved after the first
//!   [`spawn`](Executor::spawn) (wakers hold interior pointers). Create it in
//!   its final location (e.g. the driver's state) before spawning.
//! - **Futures must make progress.** The run loop drains ready tasks until
//!   quiescent; a task that unconditionally re-wakes itself without progressing
//!   will spin.
//! - **Futures are `'static`.** A spawned future must own its data (or borrow
//!   only `'static` state). The executor owns and drops its futures (it drops
//!   any still-live futures when the executor itself is dropped).
//!
//! ## Safety
//!
//! This crate contains a small, deliberate amount of `unsafe` — the minimum
//! needed to store heterogeneous futures inline and to implement a no-alloc
//! [`Waker`]. Every site carries a `SAFETY:` comment, and the surface is
//! documented in `docs/UNSAFE_AUDIT.md` and bounded by `safety-budget.json`.
//! The crate uses no `unwrap`/`expect`/`panic!` outside the compile-time
//! capacity assertion.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

use core::cell::{Cell, UnsafeCell};
use core::future::Future;
use core::mem::{self, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// Errors returned by [`Executor::spawn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    /// The future is larger than the executor's per-task inline capacity `F`.
    TooLarge,
    /// The future's alignment exceeds the executor's inline storage alignment
    /// (16 bytes).
    Misaligned,
    /// All `TASKS` slots are occupied.
    Full,
}

/// A handle to a spawned task. Returned by [`Executor::spawn`] and passed back
/// to [`Executor::wake`] for external (driver-driven) completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId {
    index: u32,
    generation: u32,
}

impl TaskId {
    /// A sentinel that never refers to a live task.
    pub const INVALID: TaskId = TaskId {
        index: u32::MAX,
        generation: u32::MAX,
    };
}

/// Inline storage for one future: up to `F` bytes, 16-byte aligned so futures
/// with alignment up to 16 can be stored soundly.
#[repr(C, align(16))]
struct Storage<const F: usize> {
    bytes: MaybeUninit<[u8; F]>,
}

/// Type-erased poll function: polls the future stored at `ptr`.
type PollFn = unsafe fn(*mut (), &mut Context<'_>) -> Poll<()>;
/// Type-erased drop function: drops the future stored at `ptr` in place.
type DropFn = unsafe fn(*mut ());

/// Stable, F-independent waker payload. Lives inside the task slot so the
/// [`Waker`] can hold a pointer to it for the executor's lifetime.
#[derive(Clone, Copy)]
struct WakeState {
    /// Pointer to the executor's ready bitmask.
    ready: *const Cell<u64>,
    /// This task's bit index.
    index: u32,
}

/// One task slot. `poll_fn` is `None` when the slot is free.
struct Slot<const F: usize> {
    storage: UnsafeCell<Storage<F>>,
    poll_fn: Cell<Option<PollFn>>,
    drop_fn: Cell<Option<DropFn>>,
    /// Bumped whenever the slot is freed, to invalidate stale [`TaskId`]s.
    generation: Cell<u32>,
    wake: Cell<WakeState>,
}

/// A fixed-capacity, allocation-free, single-threaded futures executor.
///
/// `TASKS` is the number of concurrent task slots (at most 64); `F` is the
/// maximum size in bytes of any spawned future.
pub struct Executor<const TASKS: usize, const F: usize> {
    ready: Cell<u64>,
    count: Cell<usize>,
    slots: [Slot<F>; TASKS],
}

impl<const TASKS: usize, const F: usize> Executor<TASKS, F> {
    /// Create an empty executor. Compile-time asserts `TASKS <= 64`.
    pub fn new() -> Self {
        const { assert!(TASKS <= 64, "hues-async: TASKS must be <= 64 (u64 ready mask)") };
        Self {
            ready: Cell::new(0),
            count: Cell::new(0),
            slots: core::array::from_fn(|i| Slot {
                storage: UnsafeCell::new(Storage {
                    bytes: MaybeUninit::uninit(),
                }),
                poll_fn: Cell::new(None),
                drop_fn: Cell::new(None),
                generation: Cell::new(0),
                wake: Cell::new(WakeState {
                    ready: ptr::null(),
                    index: i as u32,
                }),
            }),
        }
    }

    /// Number of currently live tasks.
    pub fn count(&self) -> usize {
        self.count.get()
    }

    /// True when there are no live tasks.
    pub fn is_empty(&self) -> bool {
        self.count.get() == 0
    }

    /// True when at least one task is ready to poll right now.
    pub fn has_ready(&self) -> bool {
        self.ready.get() != 0
    }

    /// Spawn a future. It is scheduled for its first poll immediately.
    ///
    /// Returns a [`TaskId`] the driver can later pass to [`wake`](Self::wake)
    /// when an external completion occurs.
    pub fn spawn<Fut>(&self, fut: Fut) -> Result<TaskId, SpawnError>
    where
        Fut: Future<Output = ()> + 'static,
    {
        if mem::size_of::<Fut>() > F {
            return Err(SpawnError::TooLarge);
        }
        if mem::align_of::<Fut>() > 16 {
            return Err(SpawnError::Misaligned);
        }
        for i in 0..TASKS {
            let slot = &self.slots[i];
            if slot.poll_fn.get().is_some() {
                continue; // occupied
            }
            // SAFETY: the slot is free (no live future). We checked
            // size_of::<Fut>() <= F and align_of::<Fut>() <= 16, and `Storage`
            // is 16-byte aligned, so writing `Fut` into the inline bytes is a
            // valid, aligned placement. The future is pinned here: it is never
            // moved out of the slot while alive (it is dropped in place).
            unsafe {
                let storage = &mut *slot.storage.get();
                (storage.bytes.as_mut_ptr() as *mut Fut).write(fut);
            }
            slot.poll_fn.set(Some(poll_impl::<Fut>));
            slot.drop_fn.set(Some(drop_impl::<Fut>));
            let generation = slot.generation.get().wrapping_add(1);
            slot.generation.set(generation);
            slot.wake.set(WakeState {
                ready: &self.ready as *const Cell<u64>,
                index: i as u32,
            });
            self.count.set(self.count.get() + 1);
            self.ready.set(self.ready.get() | (1u64 << i)); // schedule first poll
            return Ok(TaskId {
                index: i as u32,
                generation,
            });
        }
        Err(SpawnError::Full)
    }

    /// Wake a task by id (driver-driven external completion). Generation-guarded:
    /// a stale id (task already completed and its slot reused) is ignored.
    pub fn wake(&self, task: TaskId) {
        let i = task.index as usize;
        if i >= TASKS {
            return;
        }
        let slot = &self.slots[i];
        if slot.generation.get() == task.generation && slot.poll_fn.get().is_some() {
            self.ready.set(self.ready.get() | (1u64 << task.index));
        }
    }

    /// Poll all ready tasks until none are ready (run-to-completion step).
    /// Returns the number of polls performed. Tasks that wake themselves or
    /// others are re-polled within this call until the set is quiescent.
    pub fn poll(&self) -> usize {
        let mut polled = 0usize;
        loop {
            let bits = self.ready.get();
            if bits == 0 {
                break;
            }
            // Clear the snapshot; wakes during this pass set fresh bits that the
            // next outer iteration picks up.
            self.ready.set(0);
            let mut remaining = bits;
            while remaining != 0 {
                let i = remaining.trailing_zeros() as usize;
                remaining &= !(1u64 << i);
                let slot = &self.slots[i];
                let poll = match slot.poll_fn.get() {
                    Some(p) => p,
                    None => continue, // freed between snapshot and poll
                };
                // The future's address is the start of the slot's inline storage
                // (`Storage` is `repr(C)` with `bytes` as its first field). No
                // reference into the storage is created here; the only `&mut`
                // to the future is the pinned one inside `poll_impl`.
                let ptr = slot.storage.get() as *mut ();
                let waker = unsafe {
                    Waker::from_raw(RawWaker::new(
                        &slot.wake as *const Cell<WakeState> as *const (),
                        &WAKER_VTABLE,
                    ))
                };
                let mut cx = Context::from_waker(&waker);
                // SAFETY: `ptr` points at a live, pinned `Fut` selected by the
                // monomorphized `poll` function pointer stored with the task.
                let done = unsafe { poll(ptr, &mut cx) }.is_ready();
                polled += 1;
                if done {
                    if let Some(drop) = slot.drop_fn.get() {
                        // SAFETY: `ptr` points at the live future; drop it in
                        // place exactly once, then mark the slot free.
                        unsafe { drop(ptr) };
                    }
                    slot.poll_fn.set(None);
                    slot.drop_fn.set(None);
                    slot.generation.set(slot.generation.get().wrapping_add(1));
                    self.count.set(self.count.get().saturating_sub(1));
                }
            }
        }
        polled
    }

    /// Run until there are no live tasks, calling `park` whenever the ready set
    /// is empty (the driver uses `park` to poll its device completion queue
    /// and/or wait for an interrupt). Returns the total number of polls.
    pub fn run(&self, mut park: impl FnMut()) -> usize {
        let mut total = 0usize;
        loop {
            total += self.poll();
            if self.is_empty() {
                break;
            }
            park();
        }
        total
    }
}

impl<const TASKS: usize, const F: usize> Default for Executor<TASKS, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const TASKS: usize, const F: usize> Drop for Executor<TASKS, F> {
    fn drop(&mut self) {
        // Drop any still-live futures so they are not leaked.
        for slot in self.slots.iter_mut() {
            if let Some(drop) = slot.drop_fn.get() {
                let ptr = slot.storage.get() as *mut ();
                // SAFETY: the slot holds a live future; drop it in place during
                // teardown. `&mut self` guarantees exclusive access.
                unsafe { drop(ptr) };
                slot.poll_fn.set(None);
                slot.drop_fn.set(None);
            }
        }
    }
}

/// Monomorphized poll trampoline for a concrete future type.
///
/// # Safety
/// `ptr` must point at a live, pinned `Fut` placed by [`Executor::spawn`].
unsafe fn poll_impl<Fut: Future<Output = ()>>(ptr: *mut (), cx: &mut Context<'_>) -> Poll<()> {
    // SAFETY: the future was placed inline in a stable slot and is never moved
    // while alive, so it is soundly pinned at `ptr`.
    Pin::new_unchecked(&mut *(ptr as *mut Fut)).poll(cx)
}

/// Monomorphized drop trampoline for a concrete future type.
///
/// # Safety
/// `ptr` must point at a live `Fut`; it is dropped exactly once.
unsafe fn drop_impl<Fut>(ptr: *mut ()) {
    ptr::drop_in_place(ptr as *mut Fut);
}

// --- no-alloc waker ---

static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    waker_wake_by_ref(data);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: `data` points at the task slot's stable `WakeState` cell, valid
    // for the executor's lifetime. Read the (Copy) payload and set this task's
    // ready bit. Single-threaded, so the read-modify-write is race-free.
    let cell = &*(data as *const Cell<WakeState>);
    let ws = cell.get();
    (*ws.ready).set((*ws.ready).get() | (1u64 << ws.index));
}

unsafe fn waker_drop(_data: *const ()) {
    // The `WakeState` lives in the slot; the waker owns nothing to free.
}

/// A future that yields once (returns `Pending` and wakes itself, then
/// `Ready` on the next poll). Useful for cooperative interleaving and tests.
pub fn yield_now() -> impl Future<Output = ()> {
    struct Yield {
        yielded: bool,
    }
    impl Future for Yield {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    Yield { yielded: false }
}

// --- block_on: drive a single future to completion ---

static FLAG_VTABLE: RawWakerVTable =
    RawWakerVTable::new(flag_clone, flag_wake, flag_wake_by_ref, flag_drop);

unsafe fn flag_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &FLAG_VTABLE)
}
unsafe fn flag_wake(data: *const ()) {
    // SAFETY: `data` points at the `Cell<bool>` living on `block_on`'s stack for
    // the duration of the drive; single-threaded, so the set is race-free.
    (*(data.cast::<core::cell::Cell<bool>>())).set(true);
}
unsafe fn flag_wake_by_ref(data: *const ()) {
    flag_wake(data);
}
unsafe fn flag_drop(_data: *const ()) {}

/// Drive a single future to completion.
///
/// Polls `fut` until it is ready. When the future is pending and has not woken
/// itself, `park` is called (the driver uses this to process device completions
/// or wait for an interrupt) before re-polling. The future may borrow its
/// environment (it need not be `'static`), since it is polled in place and never
/// moved.
pub fn block_on<O>(fut: impl Future<Output = O>, mut park: impl FnMut()) -> O {
    use core::cell::Cell;
    let woken = Cell::new(true);
    // SAFETY: the waker only touches `woken`, which outlives every poll below.
    let waker = unsafe {
        Waker::from_raw(RawWaker::new(
            &woken as *const Cell<bool> as *const (),
            &FLAG_VTABLE,
        ))
    };
    let mut cx = Context::from_waker(&waker);
    let mut future = fut;
    // SAFETY: `future` is pinned on the stack for the whole drive; never moved.
    let mut pinned = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        woken.set(false);
        if let Poll::Ready(out) = pinned.as_mut().poll(&mut cx) {
            return out;
        }
        if !woken.get() {
            park();
            woken.set(true);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Host tests for the executor. No `unwrap`/`expect`/`panic!` (results are
    //! checked with `assert!` and pattern matching); the crate stays
    //! budget-neutral for the panicking surface.

    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    fn spawn_ok<const T: usize, const F: usize, Fut: Future<Output = ()> + 'static>(
        ex: &Executor<T, F>,
        fut: Fut,
    ) -> TaskId {
        let r = ex.spawn(fut);
        assert!(r.is_ok());
        r.unwrap_or(TaskId::INVALID)
    }

    // --- basic completion ---

    static DONE_A: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn spawns_and_completes_a_ready_future() {
        DONE_A.store(0, Ordering::SeqCst);
        let ex: Executor<4, 64> = Executor::new();
        let _ = spawn_ok(&ex, async {
            DONE_A.store(1, Ordering::SeqCst);
        });
        assert_eq!(ex.count(), 1);
        let polled = ex.poll();
        assert_eq!(polled, 1);
        assert_eq!(DONE_A.load(Ordering::SeqCst), 1);
        assert!(ex.is_empty());
    }

    // --- waker self-reschedule (yield) ---

    static YIELD_POLLS: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn yield_now_reschedules_via_waker() {
        YIELD_POLLS.store(0, Ordering::SeqCst);
        let ex: Executor<4, 64> = Executor::new();
        let _ = spawn_ok(&ex, async {
            yield_now().await;
            YIELD_POLLS.store(1, Ordering::SeqCst);
        });
        // The outer async block polls yield_now (Pending + self-wake) and is
        // re-polled within the same run-to-completion pass.
        ex.poll();
        assert_eq!(YIELD_POLLS.load(Ordering::SeqCst), 1);
        assert!(ex.is_empty());
    }

    // --- multiple tasks ---

    static MULTI: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn runs_multiple_tasks_to_completion() {
        MULTI.store(0, Ordering::SeqCst);
        let ex: Executor<8, 64> = Executor::new();
        for _ in 0..3 {
            let _ = spawn_ok(&ex, async {
                MULTI.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(ex.count(), 3);
        ex.poll();
        assert_eq!(MULTI.load(Ordering::SeqCst), 3);
        assert!(ex.is_empty());
    }

    // --- external wake via TaskId ---

    static EXT_POLLS: AtomicU32 = AtomicU32::new(0);

    /// Parks (Pending, no self-wake) on the first poll, completes on the next.
    struct ParkOnce(bool);
    impl Future for ParkOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            EXT_POLLS.fetch_add(1, Ordering::SeqCst);
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn external_wake_repolls_a_pending_task() {
        EXT_POLLS.store(0, Ordering::SeqCst);
        let ex: Executor<4, 64> = Executor::new();
        let id = spawn_ok(&ex, ParkOnce(false));
        // First poll: runs once, parks (Pending) without self-waking.
        ex.poll();
        assert_eq!(EXT_POLLS.load(Ordering::SeqCst), 1);
        assert_eq!(ex.count(), 1);
        assert!(!ex.has_ready());
        // External completion (e.g. an NVMe CQ entry observed by the driver).
        ex.wake(id);
        assert!(ex.has_ready());
        ex.poll();
        assert_eq!(EXT_POLLS.load(Ordering::SeqCst), 2);
        assert!(ex.is_empty());
    }

    // --- capacity ---

    #[test]
    fn spawn_full_returns_error() {
        let ex: Executor<2, 64> = Executor::new();
        let _ = spawn_ok(&ex, core::future::pending::<()>());
        let _ = spawn_ok(&ex, core::future::pending::<()>());
        let r = ex.spawn(core::future::pending::<()>());
        assert_eq!(r.err(), Some(SpawnError::Full));
    }

    // --- size guard ---

    #[test]
    fn spawn_too_large_returns_error() {
        // Capacity F = 8 bytes. The array is used after the await, so it is
        // live across the suspension point and stored in the future's state,
        // making the future larger than 8 bytes.
        let ex: Executor<2, 8> = Executor::new();
        let big = async {
            let blob = [0u8; 64];
            core::future::pending::<()>().await;
            let _ = blob[0]; // keep `blob` live across the await
        };
        let r = ex.spawn(big);
        assert_eq!(r.err(), Some(SpawnError::TooLarge));
    }

    // --- generation guard on wake ---

    static GEN: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn stale_task_id_wake_is_ignored() {
        GEN.store(0, Ordering::SeqCst);
        let ex: Executor<1, 64> = Executor::new();
        // Task 1 completes immediately, freeing the only slot.
        let id1 = spawn_ok(&ex, async {
            GEN.fetch_add(1, Ordering::SeqCst);
        });
        ex.poll();
        assert!(ex.is_empty());
        // Task 2 reuses the slot and parks (Pending, no self-wake).
        let _id2 = spawn_ok(&ex, ParkOnce2(false));
        ex.poll(); // run task 2 to its parked state
        assert_eq!(ex.count(), 1);
        assert!(!ex.has_ready());
        // Waking with the stale id1 must NOT ready the reused slot.
        ex.wake(id1);
        assert!(!ex.has_ready());
        assert_eq!(ex.count(), 1);
    }

    /// Parks once without self-waking (for the stale-id test).
    struct ParkOnce2(bool);
    impl Future for ParkOnce2 {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }

    // --- run() with a park hook ---

    static RUN_COUNTER: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn run_drives_to_completion_with_park() {
        RUN_COUNTER.store(0, Ordering::SeqCst);
        let ex: Executor<4, 64> = Executor::new();
        let _ = spawn_ok(&ex, async {
            RUN_COUNTER.fetch_add(1, Ordering::SeqCst);
        });
        let _ = spawn_ok(&ex, async {
            yield_now().await;
            RUN_COUNTER.fetch_add(1, Ordering::SeqCst);
        });
        let parks = AtomicU32::new(0);
        ex.run(|| {
            parks.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(RUN_COUNTER.load(Ordering::SeqCst), 2);
        assert!(ex.is_empty());
        // Both tasks completed without ever needing to park.
        assert_eq!(parks.load(Ordering::SeqCst), 0);
    }

    // --- drop cleans up live futures ---

    static DROPPED: AtomicU32 = AtomicU32::new(0);

    struct DropGuard;
    impl Drop for DropGuard {
        fn drop(&mut self) {
            DROPPED.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn dropping_executor_drops_live_futures() {
        DROPPED.store(0, Ordering::SeqCst);
        {
            let ex: Executor<4, 64> = Executor::new();
            let _ = spawn_ok(&ex, async {
                let guard = DropGuard;
                core::future::pending::<()>().await;
                drop(guard); // keep `guard` live across the await
            });
            assert_eq!(DROPPED.load(Ordering::SeqCst), 0);
            // Poll once: the future runs to the suspension point with `guard`
            // alive in its state, then parks.
            ex.poll();
            assert_eq!(DROPPED.load(Ordering::SeqCst), 0);
            // ex drops here with one live (parked) future holding `guard`.
        }
        assert_eq!(DROPPED.load(Ordering::SeqCst), 1);
    }

    // --- block_on ---

    #[test]
    fn block_on_drives_a_yielding_future() {
        static POLLS: AtomicU32 = AtomicU32::new(0);
        POLLS.store(0, Ordering::SeqCst);
        let parks = AtomicU32::new(0);
        // A future that yields once (wakes itself) then completes; block_on
        // re-polls it via the waker without ever needing to park.
        let out = block_on(
            async {
                POLLS.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
                POLLS.fetch_add(1, Ordering::SeqCst);
                42
            },
            || {
                parks.fetch_add(1, Ordering::SeqCst);
            },
        );
        assert_eq!(out, 42);
        assert_eq!(POLLS.load(Ordering::SeqCst), 2);
        assert_eq!(parks.load(Ordering::SeqCst), 0);
    }
}
