//! Generic IRQ event callback used by kernel-side IRQ bridge objects.

use crate::{LockRank, RankedIrqSafeTicketLock};

/// IRQ callback signature: `(typed event key, event_data)`. Event keys are
/// encoded by `huesos_abi::InterruptEventKey` so raw GSIs cannot collide with
/// legacy IRQ or MSI-vector keys.
pub type IrqCallback = fn(u64, u64);

static IRQ_CALLBACK: RankedIrqSafeTicketLock<Option<IrqCallback>> =
    RankedIrqSafeTicketLock::new(None, LockRank::ARCHITECTURE);

/// Set the IRQ callback. Called by the kernel once during init.
pub fn set_irq_callback(callback: IrqCallback) {
    *IRQ_CALLBACK.lock() = Some(callback);
}

/// Emit an IRQ event to the registered callback, if any.
pub fn emit(event_key: u64, data: u64) {
    let callback = *IRQ_CALLBACK.lock();
    if let Some(callback) = callback {
        callback(event_key, data);
    }
}
