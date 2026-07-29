//! Global timer tick callback to avoid arch -> kernel dependency.

use crate::IrqSafeTicketLock;

static TIMER_CALLBACK: IrqSafeTicketLock<Option<&'static (dyn Fn() + Send + Sync)>> =
    IrqSafeTicketLock::new(None);
static RESCHEDULE_CALLBACK: IrqSafeTicketLock<Option<&'static (dyn Fn() + Send + Sync)>> =
    IrqSafeTicketLock::new(None);

/// Set the timer tick callback. Should be called by kernel once.
pub fn set_timer_callback(f: &'static (dyn Fn() + Send + Sync)) {
    *TIMER_CALLBACK.lock() = Some(f);
}

/// Set the reschedule-IPI callback. Should be called by kernel once.
pub fn set_reschedule_callback(f: &'static (dyn Fn() + Send + Sync)) {
    *RESCHEDULE_CALLBACK.lock() = Some(f);
}

fn invoke(callback_lock: &IrqSafeTicketLock<Option<&'static (dyn Fn() + Send + Sync)>>) {
    let callback = *callback_lock.lock();
    if let Some(f) = callback {
        f();
    }
}

/// Called by the timer interrupt handler.
///
/// IMPORTANT: the callback (which triggers a context switch) must run with
/// the mutex guard already dropped. A context switch suspends this exact
/// call frame on the *old* task's stack and only resumes it much later
/// (when this task is rescheduled) — if the guard were still held across
/// that suspension, every other task's timer interrupt would deadlock
/// trying to re-acquire the same spinlock.
pub fn tick() {
    invoke(&TIMER_CALLBACK);
}

/// Called by the reschedule IPI handler.
///
/// Separate from [`tick`] so an IPI used only to make a CPU re-run the scheduler
/// never advances wall-clock time and never executes timer-only work.
pub fn reschedule() {
    invoke(&RESCHEDULE_CALLBACK);
}
