//! CPU primitives.

use core::sync::atomic::{AtomicBool, Ordering};

static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Per-CPU architectural supervisor-memory hardening state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryProtectionStatus {
    /// Supervisor execution prevention is active.
    pub smep: bool,
    /// Supervisor access prevention is active.
    pub smap: bool,
}

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

/// Enable architectural supervisor-memory protections supported by this CPU.
///
/// CR0.WP and EFER.NXE are unconditional. SMEP and SMAP are enabled only when
/// advertised by CPUID. Enabling EFER.NXE here (rather than only once on the
/// BSP) covers APs uniformly — they call this from `smp::ap_entry` — so every
/// logical CPU treats the `NO_EXECUTE` page-table bit as valid before the
/// kernel installs any W^X mapping. Once SMAP is active, supervisor access to
/// user pages is possible only while a [`UserAccessGuard`] exists.
pub fn enable_memory_protection() -> MemoryProtectionStatus {
    let features = core::arch::x86_64::__cpuid_count(7, 0).ebx;
    let smep = features & (1 << 7) != 0;
    let smap = features & (1 << 20) != 0;
    // SAFETY: this runs in ring0 once per CPU. EFER.NXE is OR-ed in via the
    // typed x86_64 crate, which preserves SCE/LMA/LME. CR0.WP and CPUID-
    // supported CR4 features are OR-ed via inline asm; existing control-
    // register bits are preserved.
    unsafe {
        use x86_64::registers::control::{Efer, EferFlags};
        Efer::update(|flags| *flags |= EferFlags::NO_EXECUTE_ENABLE);

        core::arch::asm!(
            "mov rax, cr0",
            "or rax, 0x10000",
            "mov cr0, rax",
            out("rax") _,
            options(nostack, preserves_flags),
        );
        if smep || smap {
            let mut add = 0u64;
            if smep {
                add |= 1 << 20;
            }
            if smap {
                add |= 1 << 21;
            }
            core::arch::asm!(
                "mov rax, cr4",
                "or rax, {add}",
                "mov cr4, rax",
                add = in(reg) add,
                out("rax") _,
                options(nostack, preserves_flags),
            );
        }
    }
    SMEP_ENABLED.store(smep, Ordering::Release);
    SMAP_ENABLED.store(smap, Ordering::Release);
    MemoryProtectionStatus { smep, smap }
}

/// Read the status published by [`enable_memory_protection`] on this CPU.
pub fn memory_protection_status() -> MemoryProtectionStatus {
    MemoryProtectionStatus {
        smep: SMEP_ENABLED.load(Ordering::Acquire),
        smap: SMAP_ENABLED.load(Ordering::Acquire),
    }
}

/// Scoped permission for audited supervisor access to validated user pages.
///
/// Interrupts are masked for the guard lifetime so an unrelated IRQ handler
/// cannot inherit EFLAGS.AC. Keep guarded copies bounded and non-blocking.
#[must_use]
pub struct UserAccessGuard {
    smap: bool,
    interrupts_were_enabled: bool,
}

impl UserAccessGuard {
    /// Open a temporary SMAP access window on the current CPU.
    pub fn new() -> Self {
        let interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();
        let smap = SMAP_ENABLED.load(Ordering::Acquire);
        if smap {
            // SAFETY: SMAP support was checked before CR4.SMAP was enabled.
            unsafe { core::arch::asm!("stac", options(nostack, preserves_flags)) };
        }
        Self {
            smap,
            interrupts_were_enabled,
        }
    }
}

/// Clear inherited EFLAGS.AC on interrupt/exception entry.
///
/// User mode may set AC before entering the kernel. Every IDT path calls this
/// before touching supervisor data so SMAP cannot be bypassed asynchronously.
pub(crate) fn clear_user_access() {
    if SMAP_ENABLED.load(Ordering::Acquire) {
        // SAFETY: executed only on CPUs that advertised the SMAP instruction.
        unsafe { core::arch::asm!("clac", options(nostack, preserves_flags)) };
    }
}

impl Default for UserAccessGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UserAccessGuard {
    fn drop(&mut self) {
        if self.smap {
            // SAFETY: paired with this guard's STAC on the same non-preemptible
            // CPU execution path.
            unsafe { core::arch::asm!("clac", options(nostack, preserves_flags)) };
        }
        if self.interrupts_were_enabled {
            x86_64::instructions::interrupts::enable();
        }
    }
}

/// Invalidate TLB entry for `addr`.
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}
