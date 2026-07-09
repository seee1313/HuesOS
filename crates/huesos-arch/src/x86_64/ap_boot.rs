//! AP (Application Processor) bring-up: trampoline copy, INIT/SIPI, and
//! the Rust entry point called by the trampoline.

use core::arch::global_asm;

// Pull in the real-mode -> long mode trampoline.
global_asm!(include_str!("ap_trampoline.S"));

extern "C" {
    fn ap_trampoline_start();
    fn ap_trampoline_end();
}

/// Physical address of the [`ApBootInfo`] structure shared between BSP and AP.
pub const AP_BOOT_INFO_PHYS: u64 = 0x7000;
/// Physical address where the trampoline is copied before SIPI.
pub const AP_TRAMPOLINE_PHYS: u64 = 0x8000;

/// Data exchanged between BSP and AP during bring-up.
#[repr(C)]
pub struct ApBootInfo {
    /// CR3 value (kernel PML4) for the AP.
    pub cr3: u64,
    /// Initial RSP for the AP.
    pub stack_top: u64,
    /// 64-bit Rust entry point for the AP.
    pub entry_point: u64,
}

/// Copy the AP trampoline from the kernel image to low memory.
///
/// # Safety
/// Must be called on the BSP before any SIPI is sent.
pub unsafe fn copy_trampoline() {
    let src = ap_trampoline_start as *const u8;
    let dst = AP_TRAMPOLINE_PHYS as *mut u8;
    let size = ap_trampoline_end as *const () as usize - ap_trampoline_start as *const () as usize;
    core::ptr::copy_nonoverlapping(src, dst, size);
}

/// Boot AP `apic_id` with the given stack and Rust entry point.
///
/// # Safety
/// Must be called on the BSP with interrupts disabled. The stack must be
/// valid and mapped in the kernel address space.
pub unsafe fn boot_ap(apic_id: u8, stack_top: u64, entry_point: u64) {
    copy_trampoline();

    let info = AP_BOOT_INFO_PHYS as *mut ApBootInfo;
    (*info).cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    (*info).stack_top = stack_top;
    (*info).entry_point = entry_point;

    // INIT IPI
    crate::lapic::send_ipi(apic_id, 0, crate::lapic::IpiDelivery::Init);

    // ~10 ms delay (spin loop; calibrated roughly for QEMU @ 2-3 GHz)
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }

    // STARTUP IPI
    let vector = (AP_TRAMPOLINE_PHYS >> 12) as u8;
    crate::lapic::send_ipi(apic_id, vector, crate::lapic::IpiDelivery::Startup);

    // ~200 µs delay
    for _ in 0..200_000 {
        core::hint::spin_loop();
    }

    // Second STARTUP IPI (required by Intel spec for compatibility)
    crate::lapic::send_ipi(apic_id, vector, crate::lapic::IpiDelivery::Startup);
}
