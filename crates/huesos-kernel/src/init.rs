use huesos_pmm::MemoryRegion;

const HEAP_SIZE: usize = 128 * 1024 * 1024;
const HEAP_VIRT_START: u64 = 0xffff_ff00_0000_0000;

pub unsafe fn pmm_init(regions: &[MemoryRegion], hhdm_offset: u64) {
    unsafe { huesos_pmm::init(regions, hhdm_offset); }
}

pub fn heap_init() {
    use huesos_arch::paging::{flags, map_new_page};
    use x86_64::structures::paging::{Page, Size4KiB};
    use x86_64::VirtAddr;

    let page_count = HEAP_SIZE.div_ceil(4096);

    for i in 0..page_count {
        let v = HEAP_VIRT_START + (i as u64) * 4096;
        let p = Page::<Size4KiB>::containing_address(VirtAddr::new(v));
        map_new_page(p, flags::KERNEL_RW);
    }

    unsafe {
        let a = crate::mem::alloc::KernelAllocator::new(HEAP_VIRT_START as usize, page_count);
        *crate::mem::alloc::GLOBAL_ALLOCATOR.lock() = Some(a);
    }
}

pub fn object_init() {
    huesos_object::init();
    huesos_object::set_phys_to_virt(|p| huesos_arch::paging::phys_to_virt(p).as_u64());
}

pub fn framebuffer_init(fb: Option<crate::FramebufferInfo>) {
    if let Some(f) = fb {
        use huesos_fb::FramebufferConfig;
        huesos_fb::init(Some(FramebufferConfig {
            addr: f.addr, width: f.width as u32, height: f.height as u32,
            pitch: f.pitch as u32, bpp: f.bpp,
            red_mask_size: f.red_mask_size, red_mask_shift: f.red_mask_shift,
            green_mask_size: f.green_mask_size, green_mask_shift: f.green_mask_shift,
            blue_mask_size: f.blue_mask_size, blue_mask_shift: f.blue_mask_shift,
        }));
    }
}

pub fn syscall_init() {
    let s = huesos_arch::gdt::selectors();
    huesos_arch::syscall::init(s.kernel_code, s.kernel_data, s.user_code, s.user_data);
    huesos_arch::syscall::set_handler(handle_syscall);
    huesos_syscalls::set_yield_fn(crate::scheduler::yield_now);
    huesos_syscalls::set_exit_fn(crate::scheduler::exit_current_task);
    huesos_syscalls::set_debug_write_fn(debug_write);
    huesos_syscalls::set_process_create_fn(crate::process::create_suspended_process);
    huesos_syscalls::set_vmar_map_fn(crate::process::map_vmo_into_vmar);
    huesos_syscalls::set_thread_start_fn(crate::process::start_thread);
    huesos_arch::irq_callback::set_irq_callback(handle_irq);
}

fn handle_irq(irq: u8, d: u64) {
    for i in huesos_object::lookup_interrupts_by_irq(irq) {
        i.signal(huesos_abi::PORT_PACKET_INTERRUPT, d);
    }
}

extern "C" fn handle_syscall(f: &mut huesos_arch::syscall::SyscallFrame) {
    let r = huesos_syscalls::dispatch(f.num, f.arg1, f.arg2, f.arg3, f.arg4, f.arg5);
    f.num = match r { Ok(v) => v as u64, Err(e) => e as i32 as i64 as u64 };
}

fn debug_write(b: &[u8]) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    for &c in b { let _ = w.write_char(c as char); }
}
