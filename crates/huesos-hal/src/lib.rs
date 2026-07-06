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
    serial::write_byte(b'P');
    serial::write_byte(b'A');
    serial::write_byte(b'N');
    serial::write_byte(b'I');
    serial::write_byte(b'C');
    serial::write_byte(b':');
    serial::write_byte(b' ');
    for b in msg.bytes() {
        serial::write_byte(b);
    }
    loop { huesos_arch::hlt(); }
}
