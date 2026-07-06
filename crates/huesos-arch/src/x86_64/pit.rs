//! Programmable Interval Timer (8253/8254) driver.
//!
//! We keep the legacy PIT (channel 0, wired to IRQ0) instead of the LAPIC
//! timer for this MVP: it's simpler, works identically under QEMU/real
//! hardware without needing MADT parsing, and is precise enough to drive a
//! round-robin scheduler.

use x86_64::instructions::port::Port;

const PIT_FREQUENCY: u32 = 1_193_182;

/// Program the PIT to fire IRQ0 at `hz` times per second.
pub fn init(hz: u32) {
    let divisor = (PIT_FREQUENCY / hz).clamp(1, u16::MAX as u32) as u16;

    let mut cmd: Port<u8> = Port::new(0x43);
    let mut data0: Port<u8> = Port::new(0x40);

    unsafe {
        // Channel 0, lobyte/hibyte access, mode 3 (square wave), binary.
        cmd.write(0b00_11_011_0u8);
        data0.write((divisor & 0xFF) as u8);
        data0.write((divisor >> 8) as u8);
    }
}
