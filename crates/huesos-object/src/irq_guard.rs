//! IRQ-safe access helper for `spin::Mutex`-protected state that is reachable
//! from both ordinary syscall-context code (interrupts enabled) and a
//! hardware IRQ handler running on the same CPU (the keyboard IRQ1 bridge,
//! via `Interrupt::signal` -> `Port::queue` -> `WaitQueue::wake_one`, and the
//! object registry that both paths look objects up through).
//!
//! ## The hazard this closes
//!
//! A plain `spin::Mutex` has no notion of interrupt context. If syscall-path
//! code takes the lock, interrupts fire on the same CPU before the guard is
//! dropped, and the IRQ handler tries to take the *same* lock, the CPU spins
//! on its own lock forever: the owning context can never resume (it is
//! preempted inside the IRQ handler) to release the lock the IRQ handler is
//! waiting on. This is a classic single-CPU self-deadlock, not a race
//! between CPUs, so `-smp 1` reproduces it identically to `-smp 2`.
//!
//! Concretely: `huesos_syscalls::waitset::sys_waitset_wait`'s poll loop calls
//! `yield_now()` (which re-enables interrupts before returning) and then
//! immediately calls `update_waitset_signals`, which locks the object
//! registry and a `Port`'s packet queue — the same locks the keyboard IRQ1
//! path (`Interrupt::signal` -> `lookup_object` -> `Port::queue`) needs. A
//! keystroke landing in that window on the same CPU deadlocks it solid,
//! including its timer tick, with no panic message. The bug is latent at
//! boot (the window is short and rarely hit) and becomes reliable within a
//! few seconds of real typing, matching the reported "types fine for a
//! moment, then the whole system or just the terminal freezes" symptom.
//!
//! ## Why not `RankedIrqSafeTicketLock`
//!
//! `huesos_arch::RankedIrqSafeTicketLock` already solves exactly this for
//! privileged kernel/arch/uACPI code, but `huesos-object` is deliberately
//! platform-neutral and host-testable (`cargo test -p huesos-object` runs on
//! the host, with no per-CPU GS-BASE machinery). Depending on `huesos-arch`
//! here would either break host testing or require `#[cfg]`-gating the
//! entire crate. `huesos-pmm` faced the identical constraint for its
//! allocator lock and solved it with a minimal, crate-local `cli`/`sti`
//! guard (see `docs/UNSAFE_AUDIT.md` "PMM IRQ-guard boundary"); this module
//! is that same pattern, reused verbatim for `huesos-object`'s locks that are
//! reachable from IRQ context.
//!
//! ## Safety budget
//!
//! Same two `asm!` sites as the PMM guard, gated to real kernel builds only
//! (`target_arch = "x86_64", target_os = "none"`); a no-op on host test
//! builds (`target_os` is the host OS there, so the guard degrades to a
//! zero-sized, no-op RAII type and every `IrqGuard::acquire()` call site
//! keeps working unchanged under `cargo test`).

/// RAII guard that disables local interrupts for its lifetime and restores
/// the previous interrupt-enable state on drop.
///
/// Construct with [`IrqGuard::acquire`] immediately before taking a
/// `spin::Mutex` that is also reachable from IRQ context, and hold the guard
/// for at least as long as the lock guard.
pub struct IrqGuard {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    were_enabled: bool,
}

impl IrqGuard {
    /// Disable local interrupts and return a guard that restores the prior
    /// state (enabled or disabled) when dropped.
    #[inline]
    pub fn acquire() -> Self {
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
