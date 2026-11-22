//! # HuesOS Hardware Abstraction Layer
//!
//! Platform-agnostic interfaces: timers, UART, PIC/APIC.

#![no_std]
#![warn(missing_docs)]

use huesos_arch::serial;

/// Initialize HAL devices.
pub fn init() {
    log::info!("HAL initialized");
}

/// Early panic output.
pub fn early_panic(msg: &str) -> ! {
    serial::write_error_bytes(b"PANIC: ");
    serial::write_error_bytes(msg.as_bytes());
    loop {
        huesos_arch::hlt();
    }
}
