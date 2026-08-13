//! # HuesOS Architecture Layer
//!
//! Architecture-specific primitives: interrupts, paging, segmentation, ports,
//! and SMP-safe synchronization.

#![no_std]
#![feature(abi_x86_interrupt)]
#![warn(missing_docs)]

extern crate alloc;

mod sync;
pub use sync::{
    assert_no_ranked_locks_held, IrqSafeRawSpinlock, IrqSafeTicketLock, LockRank, LockRankError,
    RankedIrqSafeTicketLock, RawSpinlock, TicketLock,
};

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

/// Whether this CPU advertises the `RDRAND` instruction (CPUID.1:ECX[30]).
pub fn has_rdrand() -> bool {
    let leaf = core::arch::x86_64::__cpuid(1);
    leaf.ecx & (1 << 30) != 0
}

/// Read one 64-bit value from the CPU hardware random generator.
///
/// Returns `None` when the instruction is unsupported or the hardware
/// entropy source is momentarily exhausted (`CF=0`). Per Intel's
/// guidance the instruction is retried a bounded number of times
/// before giving up, so a busy DRNG does not stall the caller.
pub fn rdrand64() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    for _ in 0..10 {
        let value: u64;
        let ok: u8;
        // SAFETY: `rdrand` writes one general-purpose register and the
        // carry flag and touches no memory. It is guarded by the CPUID
        // feature check above.
        unsafe {
            core::arch::asm!(
                "rdrand {value}",
                "setc {ok}",
                value = out(reg) value,
                ok = out(reg_byte) ok,
                options(nomem, nostack)
            );
        }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}
