//! CPU primitives.

/// Get the local APIC ID (simplified: always 0 on UP).
pub fn apic_id() -> u32 {
    0
}

/// Get current CPU id.
pub fn current_id() -> u32 {
    apic_id()
}

/// Invalidate TLB entry for `addr`.
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}
