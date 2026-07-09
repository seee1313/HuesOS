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

/// Ensure low-memory pages used for AP bring-up are reachable.
///
/// Limine base revision 3 dropped the unconditional identity map of the
/// first 4 GiB. We need:
/// - HHDM mappings so the BSP can `memcpy` the trampoline / write ApBootInfo
/// - true identity mappings (`virt == phys`) so the trampoline, *after*
///   enabling paging with the kernel CR3, can still load RSP/entry from
///   absolute addresses 0x7008 / 0x7010.
fn map_ap_low_pages() {
    crate::x86_64::paging::map_hhdm_range(AP_BOOT_INFO_PHYS, 0x1000);
    crate::x86_64::paging::map_hhdm_range(AP_TRAMPOLINE_PHYS, 0x2000);
    crate::x86_64::paging::map_identity_range(AP_BOOT_INFO_PHYS, 0x1000);
    crate::x86_64::paging::map_identity_range(AP_TRAMPOLINE_PHYS, 0x2000);
}

/// Copy the AP trampoline from the kernel image to low memory.
///
/// # Safety
/// Must be called on the BSP before any SIPI is sent. Paging/HHDM mapper
/// must already be initialized.
pub unsafe fn copy_trampoline() {
    map_ap_low_pages();
    let src = ap_trampoline_start as *const u8;
    let dst = crate::x86_64::paging::phys_to_virt(AP_TRAMPOLINE_PHYS).as_mut_ptr::<u8>();
    let size = ap_trampoline_end as *const () as usize - ap_trampoline_start as *const () as usize;
    core::ptr::copy_nonoverlapping(src, dst, size);
}

/// Boot AP `apic_id` with the given stack and Rust entry point.
///
/// # Safety
/// Must be called on the BSP. The stack must be valid and mapped in the
/// kernel address space. Does not wait for the AP to come online.
pub unsafe fn boot_ap(apic_id: u8, stack_top: u64, entry_point: u64) {
    copy_trampoline();

    // Write ApBootInfo through the HHDM — physical 0x7000 is not identity-mapped
    // for ordinary kernel code under base revision 3.
    let info = crate::x86_64::paging::phys_to_virt(AP_BOOT_INFO_PHYS).as_mut_ptr::<ApBootInfo>();
    (*info).cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    (*info).stack_top = stack_top;
    (*info).entry_point = entry_point;

    // INIT IPI (assert).
    crate::lapic::send_ipi(apic_id, 0, crate::lapic::IpiDelivery::Init);

    // Short settle. QEMU TCG is slow enough that a huge spin here
    // makes the whole BSP look hung under a 30s timeout.
    for _ in 0..50_000 {
        core::hint::spin_loop();
    }

    // SIPI: vector = physical page of trampoline (0x8000 >> 12 = 8).
    let vector = (AP_TRAMPOLINE_PHYS >> 12) as u8;
    crate::lapic::send_ipi(apic_id, vector, crate::lapic::IpiDelivery::Startup);

    // Second SIPI for legacy compatibility (Intel SDM).
    for _ in 0..10_000 {
        core::hint::spin_loop();
    }
    crate::lapic::send_ipi(apic_id, vector, crate::lapic::IpiDelivery::Startup);
}
