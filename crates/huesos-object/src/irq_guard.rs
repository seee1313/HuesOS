//! IRQ-safe locking for `huesos-object`.
//!
//! ## The hazard this closes
//!
//! `huesos-object`'s kernel objects (the global registry, `Port`, `Interrupt`,
//! `WaitQueue`, `Channel`, ...) are reachable from two contexts on the same
//! CPU:
//!
//! - ordinary syscall-context code, which runs with interrupts enabled
//!   (`Syscall::PortRead`, `Syscall::InterruptBindPort`,
//!   `Syscall::WaitSetWait`'s poll loop, `ProcessWait`'s blocking timeout
//!   path, `Channel::send`, ...);
//! - the keyboard IRQ1 hardware handler (`idt::keyboard_irq_ack` ->
//!   `irq_callback::emit` -> `kernel::init::handle_irq` ->
//!   `Interrupt::signal` -> `Port::queue` -> `WaitQueue::wake_one` ->
//!   `wake_task`), and the timer IRQ (`wait::notify_tick`).
//!
//! A plain `spin::Mutex` has no notion of interrupt context. If
//! syscall-context code takes one of these locks and a keystroke (or timer
//! tick) fires on the *same* CPU before the guard is dropped, the IRQ
//! handler tries to take the same lock and spins on it forever: the owning
//! context can never resume (it is preempted inside the very IRQ handler
//! that is spinning) to release the lock. This is a single-CPU self-deadlock
//! — it does not require SMP to reproduce — and it silently stops the local
//! CPU's timer tick along with everything else, with no panic message.
//!
//! This is exactly the hazard Zircon's `Guard<SpinLock, IrqSave>` /
//! `Guard<SpinLock, NoIrqSave>` machinery exists to prevent: instead of
//! trusting every call site to remember to disable interrupts before taking
//! a lock that IRQ context also uses, the lock type itself only offers an
//! IRQ-safe acquisition path. [`IrqSafeMutex`] is that same idea, adapted to
//! this codebase: **there is no way to `.lock()` an `IrqSafeMutex` without
//! disabling local interrupts for the critical section**, so a future call
//! site cannot reintroduce this bug by omission the way the original
//! ad-hoc, manually-guarded `spin::Mutex` call sites did (see
//! `docs/UNSAFE_AUDIT.md` § "huesos-object IRQ-guard boundary" for the two
//! real incidents this caused).
//!
//! `tools/check-huesos-object-lock-policy.py` enforces this at the text
//! level: no file under `crates/huesos-object/src/` (this module and
//! `#[cfg(test)]` blocks excepted) may name `spin::Mutex` directly: every
//! shared-state field or static must be an [`IrqSafeMutex`].
//!
//! ## Why not `RankedIrqSafeTicketLock`
//!
//! `huesos_arch::RankedIrqSafeTicketLock` already solves this for privileged
//! kernel/arch/uACPI code, but `huesos-object` is deliberately
//! platform-neutral and host-testable (`cargo test -p huesos-object` runs on
//! the host, with no per-CPU GS-BASE machinery `RankedIrqSafeTicketLock`
//! depends on). Depending on `huesos-arch` here would either break host
//! testing or require `#[cfg]`-gating the entire crate. `huesos-pmm` faced
//! the identical constraint for its allocator lock and solved it with a
//! minimal, crate-local `cli`/`sti` guard (see `docs/UNSAFE_AUDIT.md` "PMM
//! IRQ-guard boundary"); [`IrqSafeMutex`] wraps that same primitive behind a
//! `spin::Mutex`-compatible API so every lock in this crate gets it
//! automatically instead of relying on each call site to opt in correctly.
//!
//! ## Safety budget
//!
//! Two `asm!` sites (`cli` on acquire, conditional `sti` on drop), gated to
//! real kernel builds only (`target_arch = "x86_64", target_os = "none"`); a
//! no-op on host test builds, so `IrqSafeMutex` behaves exactly like
//! `spin::Mutex` under `cargo test`.

use core::ops::{Deref, DerefMut};
use spin::Mutex;

/// RAII guard that disables local interrupts for its lifetime and restores
/// the previous interrupt-enable state on drop.
///
/// This is the primitive [`IrqSafeMutex`] is built on. It is also exposed
/// directly for the rare case for a critical section that touches more than
/// one `IrqSafeMutex` in the same scope (locking two `IrqSafeMutex`es
/// nests two independent `cli`/`sti` pairs correctly, since each restores
/// only the interrupt-enable state it observed on its own entry — but a
/// single shared [`IrqGuard`] covering both avoids the redundant work).
struct IrqGuard {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    were_enabled: bool,
}

impl IrqGuard {
    /// Disable local interrupts and return a guard that restores the prior
    /// state (enabled or disabled) when dropped.
    #[inline]
    fn acquire() -> Self {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            let flags: u64;
            // SAFETY: `pushfq` / `cli` are always safe on x86_64. They only
            // read RFLAGS and mask interrupts on the local CPU; no memory is
            // accessed (`options(nomem)`) and no software-visible register
            // other than the constrained scratch output is touched.
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "pop {flags}",
                    "cli",
                    flags = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            IrqGuard {
                were_enabled: (flags & (1 << 9)) != 0,
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        {
            IrqGuard {}
        }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if self.were_enabled {
            // SAFETY: `sti` is always safe on x86_64; it only unmasks
            // interrupts on the local CPU and has no memory effect
            // (`options(nomem)`).
            unsafe {
                core::arch::asm!("sti", options(nomem, preserves_flags));
            }
        }
    }
}

/// A `spin::Mutex`-compatible lock that always disables local interrupts
/// for the duration of its critical section.
///
/// Use this for every field/static in `huesos-object` that a hardware IRQ
/// handler and ordinary syscall-context code can both reach on the same
/// CPU — which, transitively through the object registry and wait queues,
/// is effectively everything in this crate. See the module docs for why
/// this is a type-enforced replacement for `spin::Mutex` rather than a
/// convention every call site has to remember.
pub struct IrqSafeMutex<T> {
    inner: Mutex<T>,
}

/// RAII guard returned by [`IrqSafeMutex::lock`]. Restores local interrupts
/// to their pre-lock state when dropped, after releasing the inner lock.
pub struct IrqSafeMutexGuard<'a, T> {
    // Field order matters: Rust drops fields in declaration order, so
    // `inner` (the spin::Mutex guard) is released *before* `_irq` restores
    // interrupts. Interrupts must stay masked until after the lock is
    // released, or a keystroke could observe the lock free but interrupts
    // already back on and race a fresh acquisition in from IRQ context
    // before this guard's `Drop` finishes.
    inner: spin::MutexGuard<'a, T>,
    _irq: IrqGuard,
}

impl<T> IrqSafeMutex<T> {
    /// Create a new lock protecting `value`.
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    /// Acquire the lock, disabling local interrupts for the critical
    /// section. Returns a guard that releases the lock and restores
    /// interrupts (if they were enabled) when dropped.
    #[inline]
    pub fn lock(&self) -> IrqSafeMutexGuard<'_, T> {
        // Disable interrupts *before* touching the inner spin::Mutex: if a
        // keystroke fires between taking the inner lock and disabling
        // interrupts, the IRQ handler's own `IrqSafeMutex::lock()` call
        // would spin forever on a lock this CPU already holds, defeating
        // the whole point of the guard.
        let irq = IrqGuard::acquire();
        let inner = self.inner.lock();
        IrqSafeMutexGuard { inner, _irq: irq }
    }
}

impl<T> Deref for IrqSafeMutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for IrqSafeMutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
