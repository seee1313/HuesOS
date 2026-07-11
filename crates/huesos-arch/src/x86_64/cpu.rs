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

/// Enable x87/SSE execution for userspace software renderers.
///
/// Kernel Rust code is still built with soft-float and never touches SIMD
/// state. The current scheduler pins userspace tasks, so a single SIMD-using
/// task retains its XMM state across switches; full FXSAVE/FXRSTOR ownership is
/// required before multiple SIMD tasks may share a CPU.
pub fn enable_sse() {
    unsafe {
        core::arch::asm!(
            "mov rax, cr0",
            "and rax, -5",       // clear EM (bit 2)
            "or rax, 2",         // set MP (bit 1)
            "mov cr0, rax",
            "mov rax, cr4",
            "or rax, 0x600",     // OSFXSR | OSXMMEXCPT
            "mov cr4, rax",
            out("rax") _,
            options(nostack)
        );
    }
}

/// Invalidate TLB entry for `addr`.
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}
