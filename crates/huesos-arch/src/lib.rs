//! # HuesOS Architecture Layer
//!
//! Architecture-specific primitives: interrupts, paging, segmentation, ports,
//! and SMP-safe synchronization.

#![no_std]
#![feature(abi_x86_interrupt)]
#![warn(missing_docs)]

extern crate alloc;

mod sync;
pub use sync::{IrqSafeTicketLock, IrqSafeRawSpinlock, RawSpinlock, TicketLock};

mod x86_64;
pub use x86_64::*;

// Re-export VirtAddr so `crate::VirtAddr` works in submodules.
pub use ::x86_64::VirtAddr;

/// Halt the CPU until the next interrupt.
pub fn hlt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Read the timestamp counter.
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}
