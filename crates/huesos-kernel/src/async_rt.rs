//! Ring-0 async runtime: reactor + scope_on for kernel tasks.
//!
//! ## Reactor model: drain → wake only
//!
//! The kernel async runtime follows a strict **drain → wake only** model:
//!
//! - **Reactor** (IRQ / timer path): drains hardware events, wakes
//!   scheduler tasks via the existing `wait::notify_tick` path.
//!   Never polls futures. Allocation-free.
//! - **Task context**: uses [`run_sync`] to drive a future to completion.
//!   The future parks via the scheduler when pending (`park_current`).
//!   No persistent executor state in the kernel.
//!
//! This design keeps the kernel minimal: no per-CPU executor, no
//! spawn infrastructure, no ready bitmask. Async is a programming
//! model, not a runtime subsystem. The scheduler IS the reactor.
//!
//! ## Lock rules (ENFORCED)
//!
//! 1. **Never hold a ranked lock across `.await`.** All kernel lock
//!    guards must be dropped before any await point.
//! 2. **`run_sync` requires interrupts enabled.**
//! 3. **Reactor wakes go through `wait::notify_tick`** — the existing
//!    timer path is the reactor. No new IRQ-to-executor bridge needed.
//!
//! ## Completion / payload model
//!
//! - **Inline metadata** (PortPacket, short IPC)
//! - **Shared ring / CQ** (NVMe, block I/O)
//! - **Peek & Claim** (Channel IPC, large messages via peek/consume)

use hues_async::backend::KernelBackend;

/// Kernel backend for hues-async futures. Constructed from the
/// scheduler's park/tick primitives. Zero-size at runtime (fn pointers
/// are part of the type).
pub fn kernel_backend() -> KernelBackend {
    KernelBackend::new(
        crate::scheduler::park_current,
        |_slot| {
            // Backend::wake hook: the scheduler's notify_tick path is
            // the reactor. Timer expiry wakes timed-out waiters;
            // IRQ completion wakes via the same mechanism. No separate
            // executor wake is needed.
        },
        crate::scheduler::global_ticks,
    )
}

/// Drive a single future to completion using the kernel backend.
///
/// The future parks via [`crate::scheduler::park_current`] when pending,
/// and is re-polled when the scheduler schedules the task again (via
/// timer tick, IRQ completion, or explicit wake).
///
/// The future may borrow its environment (non-'static). This is the
/// key difference from `spawn`: the caller's stack frame keeps the
/// borrowed data alive for the duration of the drive.
///
/// # Lock rules
///
/// All locks must be dropped before calling. The park callback yields
/// to the scheduler, which may acquire ranked locks.
///
/// # Example
///
/// ```ignore
/// // Async channel recv using peek/consume
/// let msg = async_rt::run_sync(async {
///     let (size, _handles, cookie) = channel.peek().await?;
///     channel.consume(cookie).await
/// }).ok();
/// ```
pub fn run_sync<O>(fut: impl core::future::Future<Output = O>) -> O {
    hues_async::scope_on(fut, &kernel_backend())
}

/// Initialize the async runtime. Called once from BSP init.
///
/// Currently a no-op: the kernel backend uses fn pointers to
/// scheduler functions that are already initialized. Reserved for
/// future per-CPU executor setup if persistent async tasks are added.
pub fn init() {
    // No-op: kernel backend is constructed on-demand from scheduler
    // hooks. Future: per-CPU executor init will go here.
}
