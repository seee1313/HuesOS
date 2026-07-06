//! Interrupt controller setup (8259 PIC).

use pic8259::ChainedPics;
use spin::Mutex;

/// PIC 1 offset (master).
pub const PIC_1_OFFSET: u8 = 32;
/// PIC 2 offset (slave).
pub const PIC_2_OFFSET: u8 = 40;

/// Global chained PICs.
pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// Initialize the PIC and enable interrupts.
pub fn init() {
    unsafe {
        let mut pics = PICS.lock();
        pics.initialize();
        // Explicitly unmask IRQ0 (timer) and IRQ1 (keyboard) regardless of
        // whatever mask the firmware left behind — `initialize()` restores
        // the *previous* mask, which on some UEFI firmware/QEMU
        // combinations leaves the timer masked since firmware doesn't need
        // it once it hands off to the OS.
        pics.write_masks(0b1111_1100, 0b1111_1111);
    }
    enable();
}

/// Enable interrupts.
pub fn enable() {
    x86_64::instructions::interrupts::enable();
}

/// Disable interrupts.
pub fn disable() {
    x86_64::instructions::interrupts::disable();
}
