#![no_std]
#![no_main]

use core::panic::PanicInfo;

use limine::request::{FramebufferRequest, HhdmRequest, MemmapRequest};
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};

use huesos_pmm::MemoryRegion;
use huesos_kernel::{BootInfo, FramebufferInfo, kmain};

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(3);

#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmain_entry() -> ! {
    assert!(BASE_REVISION.is_supported(), "unsupported Limine base revision");

    huesos_arch::serial::init();
    log_line("[HuesOS] Bootloader handed over control");

    let hhdm_offset = HHDM_REQUEST.response().map(|r| r.offset).unwrap_or(0);
    assert!(hhdm_offset != 0, "Limine did not provide an HHDM offset");

    let memmap_response = MEMMAP_REQUEST.response().expect("Limine did not provide a memory map");
    let entries = memmap_response.entries();

    const MAX_REGIONS: usize = 128;
    let mut regions = [MemoryRegion { base: 0, length: 0, usable: false }; MAX_REGIONS];
    let mut region_count = 0usize;

    for entry in entries.iter() {
        if region_count >= MAX_REGIONS { break; }
        regions[region_count] = MemoryRegion {
            base: entry.base,
            length: entry.length,
            usable: entry.type_ == limine::memmap::MEMMAP_USABLE,
        };
        region_count += 1;
    }

    let framebuffer = FRAMEBUFFER_REQUEST
        .response()
        .and_then(|r| r.framebuffers().first().copied())
        .map(|fb| FramebufferInfo {
            addr: fb.address() as *mut u8,
            width: fb.width,
            height: fb.height,
            pitch: fb.pitch,
            bpp: fb.bpp,
            red_mask_size: fb.red_mask_size,
            red_mask_shift: fb.red_mask_shift,
            green_mask_size: fb.green_mask_size,
            green_mask_shift: fb.green_mask_shift,
            blue_mask_size: fb.blue_mask_size,
            blue_mask_shift: fb.blue_mask_shift,
        });

    let boot_info = BootInfo {
        hhdm_offset,
        memory_regions: &regions[..region_count],
        framebuffer,
        hbi_image: None,
    };

    kmain(boot_info)
}

fn log_line(msg: &str) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(&mut writer, "{}", msg);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = write!(&mut writer, "[KERNEL PANIC] {}\n", info);
    loop { huesos_arch::hlt(); }
}
