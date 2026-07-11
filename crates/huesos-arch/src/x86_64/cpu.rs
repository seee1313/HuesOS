//! CPU primitives.

/// Read the initial xAPIC identifier from CPUID leaf 1.
pub fn apic_id() -> u32 {
    let leaf = core::arch::x86_64::__cpuid(1);
    (leaf.ebx >> 24) & 0xff
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
