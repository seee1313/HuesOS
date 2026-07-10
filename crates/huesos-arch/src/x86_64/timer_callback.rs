//! Global timer tick callback to avoid arch -> kernel dependency.

use crate::IrqSafeTicketLock;

static TIMER_CALLBACK: IrqSafeTicketLock<Option<&'static (dyn Fn() + Send + Sync)>> = IrqSafeTicketLock::new(None);

/// Set the timer tick callback. Should be called by kernel once.
pub fn set_timer_callback(f: &'static (dyn Fn() + Send + Sync)) {
    *TIMER_CALLBACK.lock() = Some(f);
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
    let callback = *TIMER_CALLBACK.lock();
    if let Some(f) = callback {
        f();
    }
}
