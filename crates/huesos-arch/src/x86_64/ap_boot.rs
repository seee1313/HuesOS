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
///
/// Layout (must match trampoline loads):
/// - +0x00 cr3
/// - +0x08 stack_top
/// - +0x10 entry_point
/// - +0x18 status (AP writes 1 after entering long mode)
#[repr(C)]
pub struct ApBootInfo {
    /// CR3 value (kernel PML4) for the AP.
    pub cr3: u64,
    /// Initial RSP for the AP.
    pub stack_top: u64,
    /// 64-bit Rust entry point for the AP.
    pub entry_point: u64,
    /// AP progress flag: 0 = not started, 1 = long mode reached.
    pub status: u64,
}

/// Ensure low-memory pages used for AP bring-up are reachable.
///
/// Limine base revision 3 dropped the unconditional identity map of the
/// first 4 GiB. We need:
/// - HHDM mappings so the BSP can `memcpy` the trampoline / write ApBootInfo
/// - true identity mappings (`virt == phys`) so the trampoline, *after*
///   enabling paging with the kernel CR3, can still load RSP/entry from
///   absolute addresses 0x7008 / 0x7010 and execute at 0x8000+.
fn map_ap_low_pages() {
    // First 64 KiB of physical memory: boot info (0x7000), trampoline
    // (0x8000), and any real-mode scaffolding the SIPI path touches.
    // Both HHDM (BSP access) and identity (post-paging trampoline).
    const LOW: u64 = 0x0000;
    const LEN: u64 = 0x1_0000; // 64 KiB
    crate::x86_64::paging::map_hhdm_range(LOW, LEN);
    crate::x86_64::paging::map_identity_range(LOW, LEN);
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
    // Trampoline is tiny; refuse absurd sizes (mis-linked symbols).
    assert!(size > 0 && size < 0x1000, "ap trampoline size out of range");
    core::ptr::copy_nonoverlapping(src, dst, size);
}

/// Read the AP status word written by the trampoline (1 = long mode).
pub fn ap_status() -> u64 {
    let info = crate::x86_64::paging::phys_to_virt(AP_BOOT_INFO_PHYS).as_ptr::<ApBootInfo>();
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*info).status)) }
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
    (*info).status = 0;

    // INIT-SIPI-SIPI (Intel SDM vol 3).
    crate::lapic::send_init_assert(apic_id);
    crate::lapic::delay_us(10_000); // 10 ms (virtualized)

    let vector = (AP_TRAMPOLINE_PHYS >> 12) as u8;
    crate::lapic::send_startup(apic_id, vector);
    crate::lapic::delay_us(200);

    crate::lapic::send_startup(apic_id, vector);
    crate::lapic::delay_us(200);
}
