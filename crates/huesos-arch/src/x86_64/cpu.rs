//! CPU primitives.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);
static XSAVE_ENABLED: AtomicBool = AtomicBool::new(false);
static XSAVEOPT_ENABLED: AtomicBool = AtomicBool::new(false);
static SIMD_SAVE_BYTES: AtomicUsize = AtomicUsize::new(512);
static SIMD_XCR0: AtomicU64 = AtomicU64::new(0x3);
static BSP_IA32_PAT: AtomicU64 = AtomicU64::new(0);
static BSP_IA32_PAT_LATCHED: AtomicBool = AtomicBool::new(false);

const IA32_PAT_MSR: u32 = 0x277;

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

/// Active per-task userspace SIMD save-area size in bytes (`512` for `FXSAVE64`,
/// or `576..=4096` when `XSAVE` is active).
pub fn simd_save_bytes() -> usize {
    SIMD_SAVE_BYTES.load(Ordering::Acquire)
}

/// True when `CR4.OSXSAVE` and `XCR0` have been enabled on online CPUs.
pub fn xsave_enabled() -> bool {
    XSAVE_ENABLED.load(Ordering::Acquire)
}

/// True when `XSAVEOPT64` is supported alongside `XSAVE`.
pub fn xsaveopt_enabled() -> bool {
    XSAVEOPT_ENABLED.load(Ordering::Acquire)
}

/// Active `XCR0` feature mask (`0x3` x87+SSE baseline when `FXSAVE64` is used).
pub fn simd_xcr0() -> u64 {
    SIMD_XCR0.load(Ordering::Acquire)
}

/// Parse hardware SMT / core / package geometry from CPUID `0x1F` or `0x0B`,
/// falling back conservatively when neither extended topology leaf is present.
pub fn detect_topology() -> huesos_sched::CpuTopology {
    let max_basic = core::arch::x86_64::__cpuid(0).eax;
    for &leaf_num in &[0x1fu32, 0x0bu32] {
        if max_basic < leaf_num {
            continue;
        }
        let mut leaves = [(0u32, 0u32, 0u32, 0u32); 8];
        let mut count = 0usize;
        for subleaf in 0..8u32 {
            let cpuid = core::arch::x86_64::__cpuid_count(leaf_num, subleaf);
            let level_type = (cpuid.ecx >> 8) & 0xff;
            if level_type == 0 || (cpuid.ebx & 0xffff) == 0 {
                break;
            }
            leaves[count] = (cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx);
            count += 1;
        }
        if count > 0 {
            if let Ok(topo) = huesos_sched::CpuTopology::from_sdm_leaves(&leaves[..count]) {
                return topo;
            }
        }
    }
    huesos_sched::CpuTopology::conservative()
}

/// Enable x87/SSE (and CPUID-advertised `XSAVE`/`AVX`) for userspace tasks.
///
/// Kernel Rust code is built with soft-float (`-sse,-avx`), while userspace
/// tasks get isolated 64-byte-aligned SIMD save areas switched in
/// `context_switch`. When `XSAVE` is absent (for example QEMU `-cpu qemu64`),
/// this cleanly stays on 512-byte `FXSAVE64`/`FXRSTOR64` without touching
/// `CR4.OSXSAVE` or `XCR0`.
pub fn enable_sse() {
    let max_basic = core::arch::x86_64::__cpuid(0).eax;
    let leaf1 = core::arch::x86_64::__cpuid(1);
    let has_xsave_hw = max_basic >= 0xD && (leaf1.ecx & (1 << 26)) != 0;
    let xsave_layout = if has_xsave_hw {
        let d0 = core::arch::x86_64::__cpuid_count(0xD, 0);
        let supported_xcr0 = ((d0.edx as u64) << 32) | (d0.eax as u64);
        if (supported_xcr0 & 0x3) == 0x3 {
            let desired_xcr0 = supported_xcr0 & 0x7;
            let d2 = core::arch::x86_64::__cpuid_count(0xD, 2);
            let subleaves = [(0u32, 0u32, 0u32), (0, 0, 0), (d2.eax, d2.ebx, d2.ecx)];
            huesos_sched::XsaveModel::from_cpuid(&subleaves, desired_xcr0)
                .ok()
                .map(|m| m.layout())
        } else {
            None
        }
    } else {
        None
    };

    unsafe {
        core::arch::asm!(
            "mov rax, cr0",
            "and rax, -13",      // clear EM (bit 2) and TS (bit 3)
            "or rax, 2",         // set MP (bit 1)
            "mov cr0, rax",
            "mov rax, cr4",
            "or rax, 0x600",     // OSFXSR | OSXMMEXCPT
            "mov cr4, rax",
            out("rax") _,
            options(nostack)
        );

        if let Some(layout) = xsave_layout {
            core::arch::asm!(
                "mov rax, cr4",
                "or rax, {osxsave}",
                "mov cr4, rax",
                osxsave = const 1u64 << 18,
                out("rax") _,
                options(nostack)
            );
            let xcr0_lo = layout.xcr0 as u32;
            let xcr0_hi = (layout.xcr0 >> 32) as u32;
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") xcr0_lo,
                in("edx") xcr0_hi,
                options(nomem, nostack)
            );
            let d0_after = core::arch::x86_64::__cpuid_count(0xD, 0);
            let d1 = core::arch::x86_64::__cpuid_count(0xD, 1);
            let active_bytes = (d0_after.ebx as usize).max(layout.size).clamp(576, 4096);
            let aligned_bytes = (active_bytes + 63) & !63;
            SIMD_SAVE_BYTES.store(aligned_bytes, Ordering::Release);
            SIMD_XCR0.store(layout.xcr0, Ordering::Release);
            XSAVEOPT_ENABLED.store((d1.eax & 1) != 0, Ordering::Release);
            XSAVE_ENABLED.store(true, Ordering::Release);
        } else {
            SIMD_SAVE_BYTES.store(512, Ordering::Release);
            SIMD_XCR0.store(0x3, Ordering::Release);
            XSAVEOPT_ENABLED.store(false, Ordering::Release);
            XSAVE_ENABLED.store(false, Ordering::Release);
        }
    }
}

/// Enable architectural supervisor-memory protections supported by this CPU
/// and synchronize `IA32_PAT` from the BSP to every AP so Write-Combining (`WC`)
/// framebuffer mappings work identically across all cores.
pub fn enable_memory_protection() -> MemoryProtectionStatus {
    let features = core::arch::x86_64::__cpuid_count(7, 0).ebx;
    let smep = features & (1 << 7) != 0;
    let smap = features & (1 << 20) != 0;
    let is_first_cpu = !BSP_IA32_PAT_LATCHED.swap(true, Ordering::AcqRel);
    // SAFETY: this runs in ring0 once per CPU. EFER.NXE is OR-ed in via the
    // typed x86_64 crate, which preserves SCE/LMA/LME. CR0.WP and CPUID-
    // supported CR4 features are OR-ed via inline asm; existing control-
    // register bits are preserved. IA32_PAT is captured on the BSP and
    // programmed identically onto every AP before tasks can run on that AP.
    unsafe {
        use x86_64::registers::control::{Cr3, Efer, EferFlags};
        use x86_64::registers::model_specific::Msr;
        Efer::update(|flags| *flags |= EferFlags::NO_EXECUTE_ENABLE);

        let mut pat_msr = Msr::new(IA32_PAT_MSR);
        if is_first_cpu {
            let bsp_pat = pat_msr.read();
            BSP_IA32_PAT.store(bsp_pat, Ordering::Release);
        } else {
            let bsp_pat = BSP_IA32_PAT.load(Ordering::Acquire);
            if bsp_pat != 0 {
                pat_msr.write(bsp_pat);
                let (frame, raw_flags) = Cr3::read_raw();
                Cr3::write_raw(frame, raw_flags);
            }
        }

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
