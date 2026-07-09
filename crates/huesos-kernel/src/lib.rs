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
pub mod smp;
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

    // Protect the HBI image from being overwritten by the PMM!
    if let Some(hbi_data) = boot_info.hbi_image {
        let phys_addr = hbi_data.as_ptr() as u64 - boot_info.hhdm_offset;
        let length = hbi_data.len() as u64;
        huesos_pmm::reserve_range(phys_addr, length);
        
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::SerialWriter;
        let _ = writeln!(
            &mut writer,
            "[PMM] Reserved HBI image: phys_addr={:#x}, length={}",
            phys_addr, length
        );
    }

    let phys_offset = huesos_arch::VirtAddr::new(boot_info.hhdm_offset);
    huesos_arch::init_paging(phys_offset);

    // Limine base revision 3 leaves ACPI/reserved regions out of the HHDM.
    // Map them now so RSDP / XSDT / MADT walks don't #PF.
    init::map_firmware_tables(boot_info.memory_regions, boot_info.rsdp_addr);

    init::heap_init();
    init::object_init();

    if let Some(rsdp) = boot_info.rsdp_addr {
        smp::bringup_aps(rsdp, boot_info.hhdm_offset);
    }

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

    // APs finished local init during bringup_aps and are spinning on the
    // run-gate; release them now that the timer callback + PIC are live.
    smp::release_aps();

    log_boot_banner(&boot_info);
    spawn_init_process();

    // BSP idle: same as APs — timer IRQ drives the scheduler.
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
