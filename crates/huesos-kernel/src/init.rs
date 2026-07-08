//! Early initialization routines.

use huesos_pmm::MemoryRegion;

/// Kernel heap size (16 MiB) — mapped fresh via the PMM + paging rather
/// than assumed to already be identity-mapped at a hardcoded address.
const HEAP_SIZE: usize = 16 * 1024 * 1024;
/// Virtual address where we place the kernel heap (high, out of the way of
/// the kernel image itself).
const HEAP_VIRT_START: u64 = 0xffff_ff00_0000_0000;

/// Initialize the physical memory manager from the bootloader-supplied
/// memory map.
///
/// # Safety
/// Must be called once, early in boot, with the HHDM still valid and before
/// any allocation.
pub unsafe fn pmm_init(regions: &[MemoryRegion], hhdm_offset: u64) {
    unsafe {
        huesos_pmm::init(regions, hhdm_offset);
    }
}

/// Map and initialize the kernel heap using real physical frames.
pub fn heap_init() {
    use huesos_arch::paging::{flags, map_new_page};
    use x86_64::structures::paging::{Page, Size4KiB};
    use x86_64::VirtAddr;

    let page_count = HEAP_SIZE.div_ceil(4096);
    for i in 0..page_count {
        let addr = HEAP_VIRT_START + (i as u64) * 4096;
        let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(addr));
        map_new_page(page, flags::KERNEL_RW);
    }

    unsafe {
        let allocator = crate::mem::alloc::KernelAllocator::new(
            HEAP_VIRT_START as usize,
            page_count
        );
        *crate::mem::alloc::GLOBAL_ALLOCATOR.lock() = Some(allocator);
    }
}

/// Initialize root job and initial kernel objects, wiring up the
/// phys-to-virt translator now that paging is ready.
pub fn object_init() {
    huesos_object::init();
    huesos_object::set_phys_to_virt(|phys| huesos_arch::paging::phys_to_virt(phys).as_u64());
}

/// Initialize the framebuffer driver from bootloader-provided geometry, if
/// any was available.
pub fn framebuffer_init(fb: Option<crate::FramebufferInfo>) {
    huesos_fb::init(fb.map(|fb| huesos_fb::FramebufferConfig {
        addr: fb.addr,
        width: fb.width as u32,
        height: fb.height as u32,
        pitch: fb.pitch as u32,
        bpp: fb.bpp,
        red_mask_size: fb.red_mask_size,
        red_mask_shift: fb.red_mask_shift,
        green_mask_size: fb.green_mask_size,
        green_mask_shift: fb.green_mask_shift,
        blue_mask_size: fb.blue_mask_size,
        blue_mask_shift: fb.blue_mask_shift,
    }));
}

/// Wire up the syscall trampoline (STAR/LSTAR/SFMASK) and the
/// architecture-independent dispatcher it calls into.
pub fn syscall_init() {
    let sel = huesos_arch::gdt::selectors();
    huesos_arch::syscall::init(sel.kernel_code, sel.kernel_data, sel.user_code, sel.user_data);
    huesos_arch::syscall::set_handler(handle_syscall);
    huesos_syscalls::set_yield_fn(crate::scheduler::yield_now);
    huesos_syscalls::set_exit_fn(crate::scheduler::exit_current_task);
    huesos_syscalls::set_debug_write_fn(debug_write);
    huesos_syscalls::set_process_create_fn(crate::process::create_suspended_process);
    huesos_syscalls::set_vmar_map_fn(crate::process::map_vmo_into_vmar);
    huesos_syscalls::set_thread_start_fn(crate::process::start_thread);
    huesos_arch::irq_callback::set_irq_callback(handle_irq_event);
}

fn handle_irq_event(irq: u8, data: u64) {
    for interrupt in huesos_object::lookup_interrupts_by_irq(irq) {
        interrupt.signal(huesos_abi::PORT_PACKET_INTERRUPT, data);
    }
}

extern "C" fn handle_syscall(frame: &mut huesos_arch::syscall::SyscallFrame) {
    let result = huesos_syscalls::dispatch(
        frame.num,
        frame.arg1,
        frame.arg2,
        frame.arg3,
        frame.arg4,
        frame.arg5,
    );
    frame.num = match result {
        Ok(v) => v as u64,
        Err(e) => e as i32 as i64 as u64,
    };
}

fn debug_write(bytes: &[u8]) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    for &b in bytes {
        let _ = writer.write_char(b as char);
    }
}
