//! # HuesOS Kernel Core
//!
//! Initialization, scheduler, process/thread management, and the main
//! kernel loop.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod init;
pub mod process;
pub mod scheduler;
pub mod task;

use linked_list_allocator::LockedHeap;

/// Kernel heap allocator.
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Kernel version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The userspace `init` binary, embedded directly into the kernel image at
/// build time (see `build.rs`). Avoids needing a bootloader module/initrd
/// mechanism for the MVP: the kernel *is* the "initrd".
pub static INIT_BINARY: &[u8] = include_bytes!(env!("HUESOS_INIT_PATH"));

/// A single bootloader-reported physical memory region.
pub use huesos_pmm::MemoryRegion;

/// Framebuffer info handed off from the bootloader, if one was available.
#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    /// Raw framebuffer pointer (physical/HHDM-mapped, bootloader-provided).
    pub addr: *mut u8,
    /// Width in pixels.
    pub width: u64,
    /// Height in pixels.
    pub height: u64,
    /// Bytes per scanline.
    pub pitch: u64,
    /// Bits per pixel.
    pub bpp: u16,
    /// Red channel bit count.
    pub red_mask_size: u8,
    /// Red channel LSB bit position.
    pub red_mask_shift: u8,
    /// Green channel bit count.
    pub green_mask_size: u8,
    /// Green channel LSB bit position.
    pub green_mask_shift: u8,
    /// Blue channel bit count.
    pub blue_mask_size: u8,
    /// Blue channel LSB bit position.
    pub blue_mask_shift: u8,
}

/// Everything the bootloader hands off to `kmain`, architecture/bootloader
/// agnostic on this side of the boundary.
pub struct BootInfo<'a> {
    /// Higher-half direct map offset.
    pub hhdm_offset: u64,
    /// Physical memory map, as reported by the bootloader.
    pub memory_regions: &'a [MemoryRegion],
    /// Framebuffer info, if the bootloader provided one.
    pub framebuffer: Option<FramebufferInfo>,
}

/// Architecture-independent kernel main.
///
/// # Safety
/// Called exactly once by the bootloader entry point, with a valid stack
/// and the HHDM already mapped.
pub unsafe fn kmain(boot_info: BootInfo) -> ! {
    unsafe {
        huesos_arch::init_early();
    }

    unsafe {
        init::pmm_init(boot_info.memory_regions, boot_info.hhdm_offset);
    }

    let phys_offset = huesos_arch::VirtAddr::new(boot_info.hhdm_offset);
    unsafe {
        huesos_arch::init_paging(phys_offset);
    }

    init::heap_init();
    init::object_init();
    init::framebuffer_init(boot_info.framebuffer);
    huesos_hal::init();

    init::syscall_init();
    scheduler::init();
    huesos_arch::init_late();

    log_boot_banner(&boot_info);

    spawn_init_process();

    loop {
        huesos_arch::hlt();
    }
}

fn log_boot_banner(boot_info: &BootInfo) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        &mut writer,
        "HuesOS v{} up and running on CPU {}",
        VERSION,
        huesos_arch::cpu::current_id()
    );
    let _ = writeln!(
        &mut writer,
        "PMM: {} / {} frames free ({} MiB / {} MiB)",
        huesos_pmm::free_frames(),
        huesos_pmm::total_frames(),
        (huesos_pmm::free_frames() as u64 * 4096) / (1024 * 1024),
        (huesos_pmm::total_frames() as u64 * 4096) / (1024 * 1024),
    );
    if let Some(fb) = &boot_info.framebuffer {
        let _ = writeln!(
            &mut writer,
            "Framebuffer: {}x{} @ {} bpp (pitch {})",
            fb.width, fb.height, fb.bpp, fb.pitch
        );
    }
}

fn spawn_init_process() {
    dbg("spawn_init_process: begin, elf size = ");
    dbg_num(INIT_BINARY.len() as u64);
    dbg("\n");

    let spawned = process::spawn_from_elf("init", INIT_BINARY);
    dbg("spawn_init_process: elf loaded, entry=");
    dbg_num(spawned.entry_point);
    dbg(" rsp=");
    dbg_num(spawned.user_rsp);
    dbg(" cr3=");
    dbg_num(spawned.cr3);
    dbg("\n");

    *process::PENDING_ENTRY.lock() = Some((spawned.entry_point, spawned.user_rsp));

    let name = *b"init\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let id = scheduler::spawn_user_thread(
        &name,
        spawned.process,
        process::user_entry_trampoline,
        spawned.cr3,
    );
    dbg("spawn_init_process: task spawned, id=");
    dbg_num(id);
    dbg("\n");
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
