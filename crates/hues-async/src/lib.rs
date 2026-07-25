//! # hues-async — a minimal, allocation-free futures executor for ring 0 and ring 3
//!
//! `hues-async` is a tiny run-to-completion executor for `no_std` environments.
//! It works identically in ring-0 kernel drivers and ring-3 userspace driver
//! processes, with **zero allocation** at every level: futures are stored
//! inline, wakers are pointer-based, and the ready set is a single `u64`.
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
//! - **Backend-agnostic.** The executor is generic over a [`Backend`] trait.
//!   [`backend::KernelBackend`] (ring 0) and [`backend::UserBackend`] (ring 3)
//!   plug in the platform-specific park/wake/tick primitives. A
//!   [`NullBackend`] is provided for tests.
//!
//! ## Contracts (read before use)
//!
//! - **Single-threaded per executor.** One executor runs on one core (ring 0)
//!   or one thread (ring 3). The waker and the run loop are not internally
//!   synchronized.
//! - **Stable address.** The executor must not be moved after the first
//!   [`spawn`](Executor::spawn) (wakers hold interior pointers). Create it in
//!   its final location before spawning.
//! - **Futures must make progress.** The run loop drains ready tasks until
//!   quiescent; a task that unconditionally re-wakes itself without progressing
//!   will spin.
//! - **Spawned futures are `'static`.** Use [`scope_on`] for borrowing futures.
//!
//! ## Safety
//!
//! This crate contains a small, deliberate amount of `unsafe` — the minimum
//! needed to store heterogeneous futures inline and to implement a no-alloc
//! [`Waker`]. Every site carries a `SAFETY:` comment.
//! The crate uses no `unwrap`/`expect`/`panic!` outside the compile-time
//! capacity assertion.
//!
//! ## ALLOCATOR PROHIBITION (PRODUCTION CONTRACT)
//!
//! `hues-async` is **allocation-free by design and by enforcement**. No
//! allocator crate (`alloc`, `GlobalAlloc`, `Box`, `Vec`, `String`, etc.)
//! is used, imported, or referenced in any production path of this crate.
//! Futures are stored inline (`Storage<F>`), the ready set is a single `u64`,
//! and wakers own nothing allocable. Any change that introduces heap
//! allocation violates the architectural contract and must be rejected.
//! See `CONTRIBUTING.md` §1 (safety budget) and `docs/UNSAFE_AUDIT.md`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

pub mod backend;

use core::cell::{Cell, UnsafeCell};
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use backend::Backend;

/// A backend that does nothing. Used as the default type parameter so that
/// tests and benchmarks can construct `Executor<N, F>` without specifying a
/// backend. **Not suitable for production use** (park spins, wake is a no-op).
pub struct NullBackend;

impl Backend for NullBackend {
    fn park(&self) {
        core::hint::spin_loop();
    }
    fn wake(&self, _slot: u32) {}
    fn now_ticks(&self) -> u64 {
        0
    }
}

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
/// Generic over:
/// - `TASKS`: number of concurrent task slots (at most 64)
/// - `F`: maximum size in bytes of any spawned future
/// - `B`: the [`Backend`] providing platform-specific park/wake/tick
///
/// The default backend is [`NullBackend`] (tests only). Production code
/// should use [`backend::KernelBackend`] (ring 0) or
/// [`backend::UserBackend`] (ring 3).
pub struct Executor<const TASKS: usize, const F: usize, B: Backend = NullBackend> {
    ready: Cell<u64>,
    count: Cell<usize>,
    slots: [Slot<F>; TASKS],
    backend: B,
    _marker: PhantomData<B>,
}

impl<const TASKS: usize, const F: usize> Executor<TASKS, F, NullBackend> {
    /// Create an empty executor with the [`NullBackend`] (tests only).
    ///
    /// For production use, use [`new_with`](Self::new_with) with a
    /// [`backend::KernelBackend`] or [`backend::UserBackend`].
    pub fn new() -> Self {
        Self::new_with(NullBackend)
    }
}

impl<const TASKS: usize, const F: usize, B: Backend> Executor<TASKS, F, B> {
    /// Create an empty executor with the given backend.
    ///
    /// Compile-time asserts `TASKS <= 64`.
    pub fn new_with(backend: B) -> Self {
        const {
            assert!(
                TASKS <= 64,
                "hues-async: TASKS must be <= 64 (u64 ready mask)"
            )
        };
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
            backend,
            _marker: PhantomData,
        }
    }

    /// Reference to the backend.
    pub fn backend(&self) -> &B {
        &self.backend
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

    /// Run until there are no live tasks. When the ready set is empty and
    /// tasks remain, calls the backend's [`Backend::park`] to sleep until
    /// an external event (IRQ, completion, timer) wakes a slot.
    ///
    /// Returns the total number of polls performed.
    pub fn run(&self) -> usize {
        let mut total = 0usize;
        loop {
            total += self.poll();
            if self.is_empty() {
                break;
            }
            self.backend.park();
        }
        total
    }

    /// Run until there are no live tasks, calling a custom `park` closure
    /// instead of the backend. This preserves backward compatibility with
    /// code that passes a driver-specific park function (e.g. one that
    /// also polls a device completion queue).
    pub fn run_with(&self, mut park: impl FnMut()) -> usize {
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

    /// Current monotonic tick from the backend.
    pub fn now_ticks(&self) -> u64 {
        self.backend.now_ticks()
    }
}

impl<const TASKS: usize, const F: usize, B: Backend> Default for Executor<TASKS, F, B>
where
    B: Default,
{
    fn default() -> Self {
        Self::new_with(B::default())
    }
}

impl<const TASKS: usize, const F: usize, B: Backend> Drop for Executor<TASKS, F, B> {
    fn drop(&mut self) {
        // Drop any still-live futures so they are not leaked.
        for slot in self.slots.iter_mut() {
            if let Some(drop) = slot.drop_fn.get() {
                let ptr = slot.storage.get() as *mut ();
                // SAFETY: `ptr` points at a live future; drop it in place during
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

/// Internal: drive a future to completion with a generic park function.
/// Both [`block_on`] and [`scope_on`] delegate here to avoid duplicating
/// the unsafe waker/pin setup.
fn drive<O>(fut: impl Future<Output = O>, mut park: impl FnMut()) -> O {
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

/// Drive a single future to completion.
///
/// Polls `fut` until it is ready. When the future is pending and has not woken
/// itself, `park` is called before re-polling. The future may borrow its
/// environment (it need not be `'static`), since it is polled in place and never
/// moved.
pub fn block_on<O>(fut: impl Future<Output = O>, park: impl FnMut()) -> O {
    drive(fut, park)
}

/// Drive a single future to completion using a [`Backend`] for parking.
///
/// This is the backend-aware counterpart to [`block_on`]. The future may
/// borrow its environment (it need not be `'static`). When the future is
/// pending and has not woken itself, `backend.park()` is called.
///
/// This function is the foundation for async code in both ring 0 and ring 3:
/// the same `scope_on(&backend, async { ... })` works identically in
/// a kernel IRQ handler and a userspace driver process.
pub fn scope_on<O, B: Backend>(fut: impl Future<Output = O>, backend: &B) -> O {
    drive(fut, || backend.park())
}

#[cfg(test)]
mod tests {
    //! Host tests for the executor. No `unwrap`/`expect`/`panic!` (results are
    //! checked with `assert!` and pattern matching); the crate stays
    //! budget-neutral for the panicking surface.

    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    fn spawn_ok<const T: usize, const F: usize, B: Backend, Fut: Future<Output = ()> + 'static>(
        ex: &Executor<T, F, B>,
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
        ex.poll();
        assert_eq!(EXT_POLLS.load(Ordering::SeqCst), 1);
        assert_eq!(ex.count(), 1);
        assert!(!ex.has_ready());
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
        let ex: Executor<2, 8> = Executor::new();
        let big = async {
            let blob = [0u8; 64];
            core::future::pending::<()>().await;
            let _ = blob[0];
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
        let id1 = spawn_ok(&ex, async {
            GEN.fetch_add(1, Ordering::SeqCst);
        });
        ex.poll();
        assert!(ex.is_empty());
        let _id2 = spawn_ok(&ex, ParkOnce2(false));
        ex.poll();
        assert_eq!(ex.count(), 1);
        assert!(!ex.has_ready());
        ex.wake(id1);
        assert!(!ex.has_ready());
        assert_eq!(ex.count(), 1);
    }

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

    // --- run_with() with a custom park hook ---

    static RUN_COUNTER: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn run_with_drives_to_completion_with_park() {
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
        ex.run_with(|| {
            parks.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(RUN_COUNTER.load(Ordering::SeqCst), 2);
        assert!(ex.is_empty());
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
                drop(guard);
            });
            assert_eq!(DROPPED.load(Ordering::SeqCst), 0);
            ex.poll();
            assert_eq!(DROPPED.load(Ordering::SeqCst), 0);
        }
        assert_eq!(DROPPED.load(Ordering::SeqCst), 1);
    }

    // --- block_on ---

    #[test]
    fn block_on_drives_a_yielding_future() {
        static POLLS: AtomicU32 = AtomicU32::new(0);
        POLLS.store(0, Ordering::SeqCst);
        let parks = AtomicU32::new(0);
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

    // --- scope_on with a backend ---

    #[test]
    fn scope_on_drives_a_future_with_backend() {
        use backend::{Backend, KernelBackend, UserBackend};

        static SCOPE_POLLS: AtomicU32 = AtomicU32::new(0);
        SCOPE_POLLS.store(0, Ordering::SeqCst);

        fn noop_park() {}
        fn noop_wake(_slot: u32) {}
        fn noop_ticks() -> u64 {
            0
        }

        // Works with both KernelBackend and UserBackend.
        let kb = KernelBackend::new(noop_park, noop_wake, noop_ticks);
        let out_k = scope_on(
            async {
                SCOPE_POLLS.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
                SCOPE_POLLS.fetch_add(1, Ordering::SeqCst);
                99
            },
            &kb,
        );
        assert_eq!(out_k, 99);
        assert_eq!(SCOPE_POLLS.load(Ordering::SeqCst), 2);

        SCOPE_POLLS.store(0, Ordering::SeqCst);
        let ub = UserBackend::new(noop_park, noop_wake, noop_ticks);
        let out_u = scope_on(
            async {
                SCOPE_POLLS.fetch_add(1, Ordering::SeqCst);
                77
            },
            &ub,
        );
        assert_eq!(out_u, 77);
        assert_eq!(SCOPE_POLLS.load(Ordering::SeqCst), 1);
    }

    // --- scope_on with borrowing future (non-'static) ---

    #[test]
    fn scope_on_allows_borrowing_futures() {
        use backend::KernelBackend;

        fn noop_park() {}
        fn noop_wake(_slot: u32) {}
        fn noop_ticks() -> u64 {
            0
        }

        let backend = KernelBackend::new(noop_park, noop_wake, noop_ticks);
        let local_data = 42u32;
        // This future borrows `local_data` — it is NOT 'static.
        // block_on would reject this; scope_on accepts it.
        let result = scope_on(
            async {
                let reference = &local_data;
                *reference + 1
            },
            &backend,
        );
        assert_eq!(result, 43);
    }

    // --- executor with a real backend ---

    #[test]
    fn executor_with_backend_polls_tasks() {
        use backend::KernelBackend;

        static BE_POLLS: AtomicU32 = AtomicU32::new(0);
        BE_POLLS.store(0, Ordering::SeqCst);

        fn noop_park() {}
        fn noop_wake(_slot: u32) {}
        fn noop_ticks() -> u64 {
            0
        }

        let backend = KernelBackend::new(noop_park, noop_wake, noop_ticks);
        let ex = Executor::<4, 64, _>::new_with(backend);
        let _ = spawn_ok(&ex, async {
            BE_POLLS.fetch_add(1, Ordering::SeqCst);
        });
        ex.poll();
        assert_eq!(BE_POLLS.load(Ordering::SeqCst), 1);
        assert!(ex.is_empty());
    }
}
