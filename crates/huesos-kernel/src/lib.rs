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
pub mod shutdown;
pub mod smp;
pub mod task;
pub mod mem;
pub mod panic;
pub mod boot;

pub use huesos_pmm::MemoryRegion;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static INIT_BINARY: &[u8] = include_bytes!(env!("HUESOS_INIT_PATH"));
static INIT_PROCESS_KOID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub(crate) fn init_process_koid() -> u64 {
    INIT_PROCESS_KOID.load(core::sync::atomic::Ordering::Acquire)
}

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
    let panic_test_requested = boot_info
        .hbi_image
        .is_some_and(cmdline_requests_panic_test);
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
    huesos_arch::fault::set_kernel_fault_handler(crate::panic::from_cpu_fault);
    huesos_arch::fault::set_user_fault_handler(handle_user_fault);
    huesos_hal::init();
    init::syscall_init();
    scheduler::init();
    huesos_arch::init_late();

    // APs finished local init during bringup_aps and are spinning on the
    // run-gate; release them now that the timer callback + PIC are live.
    smp::release_aps();

    if panic_test_requested {
        panic!("intentional panic requested by HBI cmdline panic_test=1");
    }

    log_boot_banner(&boot_info);
    spawn_init_process();

    // BSP idle: timer IRQ drives the scheduler; opportunistically reap.
    loop {
        crate::scheduler::reap_finished_tasks();
        huesos_arch::hlt();
    }
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
    use huesos_object::KernelObject;

    let spawned = process::spawn_from_elf("init", INIT_BINARY);
    INIT_PROCESS_KOID.store(
        spawned.process.koid().0,
        core::sync::atomic::Ordering::Release,
    );
    let name = *b"init\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let _ = scheduler::spawn_user_thread(
        &name, spawned.process, spawned.entry_point, spawned.user_rsp, spawned.cr3,
    );
}

fn cmdline_requests_panic_test(hbi_data: &[u8]) -> bool {
    use crate::boot::hbi::{HbiImage, ModuleType};

    let Ok(image) = HbiImage::parse(hbi_data) else {
        return false;
    };
    let Ok(cmdline) = image.get_module(ModuleType::Cmdline) else {
        return false;
    };
    cmdline
        .split(|byte| byte.is_ascii_whitespace())
        .any(|argument| argument == b"panic_test=1")
}

fn handle_user_fault(info: huesos_arch::fault::FaultInfo) -> ! {
    use core::fmt::Write;
    use huesos_object::KernelObject;

    let mut name_storage = [0u8; 64];
    let (process_koid, name_length) = huesos_object::current_process()
        .map(|process| (process.koid().0, process.copy_name(&mut name_storage)))
        .unwrap_or((0, 0));
    let process_name = if name_length == 0 {
        "<unknown>"
    } else {
        core::str::from_utf8(&name_storage[..name_length]).unwrap_or("<non-utf8>")
    };
    let task_id = scheduler::current_task_id().unwrap_or(u64::MAX);
    let code = match info.kind {
        huesos_arch::fault::FaultKind::PageFault => huesos_abi::fault_exit::PAGE_FAULT,
        huesos_arch::fault::FaultKind::GeneralProtection => {
            huesos_abi::fault_exit::GENERAL_PROTECTION
        }
        huesos_arch::fault::FaultKind::InvalidOpcode => huesos_abi::fault_exit::INVALID_OPCODE,
        huesos_arch::fault::FaultKind::DivideError => huesos_abi::fault_exit::DIVIDE_ERROR,
        huesos_arch::fault::FaultKind::AlignmentCheck => huesos_abi::fault_exit::ALIGNMENT_CHECK,
        huesos_arch::fault::FaultKind::DoubleFault => {
            crate::panic::from_cpu_fault(info)
        }
    };

    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        writer,
        "[user-fault] process={} koid={} task={} cpu={} reason={} rip={:#x} address={:#x} error={:#x} action=terminate-process code={}",
        process_name,
        process_koid,
        task_id,
        huesos_arch::cpu::current_id(),
        info.kind.as_str(),
        info.instruction_pointer,
        info.fault_address,
        info.error_code,
        code,
    );
    scheduler::terminate_current_process(code)
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
