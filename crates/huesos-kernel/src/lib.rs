//! # HuesOS Kernel Core
//!
//! Core kernel functionality.

#![no_std]
#![warn(missing_docs)]
// Allow missing docs for internal boot/platform modules for now
// (they are not part of the stable public kernel API).
#![allow(missing_docs)]

extern crate alloc;

pub mod init;
pub mod process;
pub mod scheduler;
pub mod task;
pub mod mem;
pub mod boot;

pub use huesos_pmm::MemoryRegion;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static INIT_BINARY: &[u8] = include_bytes!(env!("HUESOS_INIT_PATH"));

#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub addr: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

pub struct BootInfo<'a> {
    pub hhdm_offset: u64,
    pub memory_regions: &'a [MemoryRegion],
    pub framebuffer: Option<FramebufferInfo>,
    pub hbi_image: Option<&'a [u8]>,
    pub rsdp_addr: Option<u64>,
}

pub unsafe fn kmain(boot_info: BootInfo) -> ! {
    huesos_arch::init_early();
    init::pmm_init(boot_info.memory_regions, boot_info.hhdm_offset);

    let phys_offset = huesos_arch::VirtAddr::new(boot_info.hhdm_offset);
    huesos_arch::init_paging(phys_offset);

    init::heap_init();
    init::object_init();

    if let Some(hbi_data) = boot_info.hbi_image {
        if let Ok(hbi) = boot::hbi::HbiImage::parse(hbi_data) {
            dbg("HBI v2.1 parsed. Entries: ");
            dbg_num(hbi.get_num_entries() as u64);
            dbg("\n");
        }
    }

    init::framebuffer_init(boot_info.framebuffer);
    huesos_hal::init();
    init::syscall_init();
    scheduler::init();
    huesos_arch::init_late();

    log_boot_banner(&boot_info);
    spawn_init_process();

    loop { huesos_arch::hlt(); }
}

fn log_boot_banner(boot_info: &BootInfo) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(&mut writer, "HuesOS v{} on CPU {}", VERSION, huesos_arch::cpu::current_id());
    let _ = writeln!(
        &mut writer,
        "PMM: {}/{} frames ({} MiB)",
        huesos_pmm::free_frames(),
        huesos_pmm::total_frames(),
        (huesos_pmm::free_frames() as u64 * 4096) / (1024 * 1024)
    );
    if let Some(fb) = &boot_info.framebuffer {
        let _ = writeln!(&mut writer, "FB: {}x{}@{}", fb.width, fb.height, fb.bpp);
    }
}

fn spawn_init_process() {
    let spawned = process::spawn_from_elf("init", INIT_BINARY);
    let name = *b"init\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let _ = scheduler::spawn_user_thread(
        &name, spawned.process, spawned.entry_point, spawned.user_rsp, spawned.cr3,
    );
}

fn dbg(msg: &str) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = w.write_str(msg);
}

fn dbg_num(v: u64) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = write!(&mut w, "{:#x}", v);
}
