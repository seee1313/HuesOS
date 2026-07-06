//! Generic IRQ event callback used by kernel-side IRQ bridge objects.

use spin::Mutex;

/// IRQ callback signature: `(legacy_pic_irq, event_data)`.
pub type IrqCallback = fn(u8, u64);

static IRQ_CALLBACK: Mutex<Option<IrqCallback>> = Mutex::new(None);

/// Set the IRQ callback. Called by the kernel once during init.
pub fn set_irq_callback(callback: IrqCallback) {
    *IRQ_CALLBACK.lock() = Some(callback);
}

/// Emit an IRQ event to the registered callback, if any.
pub fn emit(irq: u8, data: u64) {
    let callback = *IRQ_CALLBACK.lock();
    if let Some(callback) = callback {
        callback(irq, data);
    }
}
