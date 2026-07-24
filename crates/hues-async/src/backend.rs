//! Platform-specific backend abstraction for the executor.
//!
//! The executor itself is backend-agnostic: it polls ready tasks, manages
//! inline future storage, and drives run-to-completion. The *backend*
//! provides the platform-specific primitives: how to park (sleep until
//! woken), how to wake (signal a sleeping executor), and how to read the
//! monotonic clock.
//!
//! Two backends are provided out of the box:
//!
//! - [`KernelBackend`] — ring-0, SMP-aware. Park/yield via the scheduler,
//!   wake via IPI, ticks from the BSP monotonic clock.
//! - [`UserBackend`] — ring-3, single-threaded per process. Park via
//!   `sys_yield`, wake via atomic flag, ticks via `sys_clock`.
//!
//! Both backends use **function-pointer hooks** registered at init time,
//! so `hues-async` never depends on the kernel or syscall crates directly.
//! This keeps the dependency graph acyclic and the crate usable from both
//! rings without conditional compilation.

/// Platform-specific operations required by the executor.
///
/// Implementations must be cheap — `park` and `wake` are called on every
/// executor idle/wake transition. `now_ticks` is called for timer futures.
pub trait Backend {
    /// Park the current execution context until woken.
    ///
    /// - Ring 0: calls the scheduler's `park_current()`.
    /// - Ring 3: calls `sys_yield()` or blocks on a futex-like primitive.
    fn park(&self);

    /// Wake the executor slot identified by `slot`.
    ///
    /// - Ring 0: may send an IPI if the slot lives on a remote CPU.
    /// - Ring 3: sets the ready bit directly (single-threaded, no IPI).
    fn wake(&self, slot: u32);

    /// Current monotonic tick count (scheduler ticks in ring 0, syscall
    /// clock in ring 3). Used by timer futures.
    fn now_ticks(&self) -> u64;
}

/// Ring-0 backend: scheduler-driven, SMP-aware.
///
/// Created once per CPU during kernel init with function pointers to the
/// scheduler's park/wake/tick primitives. The executor carries this
/// backend inline (no heap allocation, no vtable).
///
/// # Example
///
/// ```ignore
/// let backend = KernelBackend::new(
///     huesos_kernel::scheduler::park_current,
///     huesos_kernel::scheduler::wake_slot,
///     huesos_kernel::scheduler::global_ticks,
/// );
/// let executor = Executor::<8, 256, KernelBackend>::new(backend);
/// ```
pub struct KernelBackend {
    park_fn: fn(),
    wake_fn: fn(u32),
    ticks_fn: fn() -> u64,
}

impl KernelBackend {
    /// Create a kernel backend from function pointers.
    ///
    /// The functions must remain valid for the lifetime of any executor
    /// that uses this backend (typically `'static` — they are kernel
    /// functions that live for the entire boot).
    pub const fn new(park: fn(), wake: fn(u32), ticks: fn() -> u64) -> Self {
        Self {
            park_fn: park,
            wake_fn: wake,
            ticks_fn: ticks,
        }
    }
}

impl Backend for KernelBackend {
    fn park(&self) {
        (self.park_fn)();
    }

    fn wake(&self, slot: u32) {
        (self.wake_fn)(slot);
    }

    fn now_ticks(&self) -> u64 {
        (self.ticks_fn)()
    }
}

/// Ring-3 backend: syscall-driven, single-threaded per process.
///
/// Created once per userspace process with function pointers to the
/// syscall wrappers for yield/clock. Wake is a no-op in the simplest
/// model (single-threaded executor: wake = set ready bit directly).
///
/// # Example
///
/// ```ignore
/// let backend = UserBackend::new(
///     libcanvas::sys_yield,
///     | _| { /* no-op: single-threaded wake is a bit-set */ },
///     libcanvas::sys_clock_monotonic,
/// );
/// let executor = Executor::<4, 128, UserBackend>::new(backend);
/// ```
pub struct UserBackend {
    park_fn: fn(),
    wake_fn: fn(u32),
    ticks_fn: fn() -> u64,
}

impl UserBackend {
    /// Create a userspace backend from function pointers.
    pub const fn new(park: fn(), wake: fn(u32), ticks: fn() -> u64) -> Self {
        Self {
            park_fn: park,
            wake_fn: wake,
            ticks_fn: ticks,
        }
    }
}

impl Backend for UserBackend {
    fn park(&self) {
        (self.park_fn)();
    }

    fn wake(&self, slot: u32) {
        (self.wake_fn)(slot);
    }

    fn now_ticks(&self) -> u64 {
        (self.ticks_fn)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static PARK_COUNT: AtomicU32 = AtomicU32::new(0);
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
    static TICK_VAL: AtomicU32 = AtomicU32::new(42);

    fn mock_park() {
        PARK_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    fn mock_wake(_slot: u32) {
        WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    fn mock_ticks() -> u64 {
        TICK_VAL.load(Ordering::SeqCst) as u64
    }

    #[test]
    fn kernel_backend_delegates_to_hooks() {
        PARK_COUNT.store(0, Ordering::SeqCst);
        WAKE_COUNT.store(0, Ordering::SeqCst);

        let b = KernelBackend::new(mock_park, mock_wake, mock_ticks);
        b.park();
        b.park();
        b.wake(3);
        assert_eq!(PARK_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(WAKE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(b.now_ticks(), 42);
    }

    #[test]
    fn user_backend_delegates_to_hooks() {
        PARK_COUNT.store(0, Ordering::SeqCst);
        WAKE_COUNT.store(0, Ordering::SeqCst);

        let b = UserBackend::new(mock_park, mock_wake, mock_ticks);
        b.park();
        b.wake(0);
        b.wake(7);
        assert_eq!(PARK_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(WAKE_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(b.now_ticks(), 42);
    }

    #[test]
    fn backend_trait_is_object_safe_enough_for_generic_use() {
        // Verify both backends implement Backend (compile-time check).
        fn assert_backend<B: Backend>() {}
        assert_backend::<KernelBackend>();
        assert_backend::<UserBackend>();
    }
}
