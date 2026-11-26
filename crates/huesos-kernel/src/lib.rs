//! # HuesOS Kernel Core
//!
//! Core kernel functionality.

#![no_std]
#![warn(missing_docs)]
// Allow missing docs for internal boot/platform modules for now
// (they are not part of the stable public kernel API).
#![allow(missing_docs)]

extern crate alloc;

pub mod boot;
pub mod boot_key;
pub mod extable;
pub mod init;
pub mod mem;
pub mod panic;
pub mod process;
pub mod scheduler;
pub mod shutdown;
pub mod smp;
pub mod task;
pub mod tpm;

/// Ring-0 async runtime: per-CPU executor with reactor model.
pub mod async_rt;

/// Event codes for structured observation records (Stage E.2).
///
/// Codes are namespaced by the record's `ObservationClass`, so the same
/// numeric code may mean different things under `Boot` and `Recovery`.
/// They are consumed by `tools/observation-decode.py`, which means they
/// are an interface: append, never renumber.
pub mod observation_code {
    /// `Boot`: kernel subsystems are up and init is about to be
    /// spawned. Detail carries the number of online CPUs.
    pub const KERNEL_READY: u32 = 1;
    /// `Recovery`: the synthetic `.ex_table` probe took a page fault
    /// inside a user-copy and recovered, as designed.
    pub const EXTABLE_PROBE_RECOVERED: u32 = 2;
    /// `Error`: the synthetic `.ex_table` probe did not recover.
    /// Detail carries the returned error code, sign-extended.
    pub const EXTABLE_PROBE_FAILED: u32 = 3;
}

pub use huesos_pmm::MemoryRegion;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[repr(align(16))]
struct AlignedBytes<const N: usize>([u8; N]);

const INIT_BINARY_LEN: usize = include_bytes!(env!("HUESOS_INIT_PATH")).len();
static INIT_BINARY_STORAGE: AlignedBytes<INIT_BINARY_LEN> =
    AlignedBytes(*include_bytes!(env!("HUESOS_INIT_PATH")));

/// Statically embedded, explicitly aligned init ELF image.
///
/// `huesos-elf` decodes ELF fields byte-wise and does not need alignment. The
/// explicit wrapper still keeps the embedded image at a fixed, documented
/// placement, so layout changes elsewhere cannot silently move it.
pub static INIT_BINARY: &[u8] = &INIT_BINARY_STORAGE.0;
static INIT_PROCESS_KOID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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

/// Enter the kernel core from the boot protocol adapter.
///
/// # Safety
/// Call exactly once on the BSP in x86_64 long mode. Every pointer/range in
/// `boot_info` must remain valid through early initialization and describe the
/// active HHDM, firmware tables, framebuffer, modules, and memory map.
pub unsafe fn kmain(boot_info: BootInfo) -> ! {
    huesos_arch::init_early();
    let protection = huesos_arch::cpu::memory_protection_status();
    if protection.smep && protection.smap {
        dbg("[security] BSP SMEP=on SMAP=on\n");
    } else {
        dbg("[security] BSP degraded: SMEP/SMAP unavailable on this CPU\n");
    }
    if let Err(error) = init::pmm_init(boot_info.memory_regions, boot_info.hhdm_offset) {
        // PMM init runs before heap, panic handler, and framebuffer are
        // ready, so surface the diagnostic on early serial and halt the
        // BSP. Matches the pattern used by init::heap_init below.
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::ErrorSerialWriter;
        let _ = writeln!(writer, "[boot] PMM init failed: {error:?}");
        loop {
            huesos_arch::hlt();
        }
    }

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

    let boot_dma_pool = init::reserve_boot_dma_pool();

    // W^X hardening sweep for the kernel image: stamp NO_EXECUTE on
    // every kernel .rodata / .data / .bss / .limine_requests page so
    // a write-what-where in kernel data cannot stage a
    // code-execution gadget in the higher half. `.text` is the only
    // range left executable.
    //
    // EFER.NXE was already set by enable_memory_protection() during
    // init_early on the BSP, so NO_EXECUTE bits are respected by the
    // CPU here; APs pick up the same bits when they load CR3 because
    // NXE is a per-CPU MSR that ap_entry sets before enabling
    // interrupts (see arch::mod::init_early + smp::ap_entry).
    //
    // Failure here does *not* halt the boot: the kernel still runs,
    // it just loses the extra hardening layer. A halt would be an
    // unforced downgrade from "hardened + working" to "not working"
    // and would defeat the purpose of an opportunistic sweep.
    if let Err(error) = huesos_arch::paging::apply_kernel_wx() {
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::SerialWriter;
        let _ = writeln!(writer, "[boot] kernel W^X stamp skipped: {error:?}");
    }

    // Limine base revision 3 leaves ACPI/reserved regions out of the HHDM.
    // Map them now so RSDP / XSDT / MADT walks don't #PF.
    let firmware_tables_mapped =
        init::map_firmware_tables(boot_info.memory_regions, boot_info.rsdp_addr).is_ok();

    if let Err(error) = init::heap_init() {
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::ErrorSerialWriter;
        let _ = writeln!(writer, "[boot] kernel heap mapping failed: {error:?}");
        loop {
            huesos_arch::hlt();
        }
    }

    // Signed HBI is the trust boundary for BOOTFS, command line and platform
    // data. Verify exactly once before any module bytes influence policy.
    let verified_hbi = match boot_info.hbi_image {
        Some(bytes) => match boot::hbi::HbiImage::parse(bytes) {
            Ok(image) => {
                if cmdline_requests_verbose_log(&image) {
                    huesos_arch::serial::set_verbose(true);
                }
                dbg("[HBI] Ed25519 signature verified (v2.2)\n");
                image
            }
            Err(error) => {
                use core::fmt::Write;
                let mut writer = huesos_arch::serial::ErrorSerialWriter;
                let _ = writeln!(writer, "[HBI] signature verification failed: {error:?}");
                loop {
                    huesos_arch::hlt();
                }
            }
        },
        None => {
            err_dbg("[HBI] signed boot image missing; fail-closed halt\n");
            loop {
                huesos_arch::hlt();
            }
        }
    };

    let boot_measurement = match boot::measurement::pcr12_digest(&verified_hbi) {
        Ok(digest) => digest,
        Err(error) => {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::ErrorSerialWriter;
            let _ = writeln!(writer, "[measure] boot measurement failed: {error:?}");
            loop {
                huesos_arch::hlt();
            }
        }
    };
    dbg("[measure] signed kernel/HBI/cmdline digest ready for PCR 12\n");

    let uacpi_tables_ready = boot_info.rsdp_addr.is_some_and(|rsdp| {
        if let Err(error) = huesos_uacpi::initialize_tables(rsdp) {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::SerialWriter;
            let _ = writeln!(writer, "[uACPI] table initialization failed: {error:?}");
            return false;
        }
        match huesos_uacpi::Table::find(b"APIC") {
            Ok(table) if table.bytes().is_ok() => {
                dbg("[uACPI] validated ACPI table graph and MADT\n");
                true
            }
            _ => {
                dbg("[uACPI] MADT unavailable after table initialization\n");
                false
            }
        }
    });
    let acpi_archive = if uacpi_tables_ready {
        match boot_info
            .rsdp_addr
            .ok_or(boot::acpi_archive::ArchiveBuildError::InvalidRsdp)
            .and_then(boot::acpi_archive::build)
        {
            Ok(archive) => {
                dbg("[uACPI] built immutable Ring-3 table archive v2\n");
                Some(archive)
            }
            Err(error) => {
                use core::fmt::Write;
                let mut writer = huesos_arch::serial::SerialWriter;
                let _ = writeln!(writer, "[uACPI] table archive unavailable: {error:?}");
                None
            }
        }
    } else {
        None
    };

    let acpi_snapshot_id = acpi_archive
        .as_deref()
        .and_then(|bytes| bytes.get(..huesos_abi::acpi_archive::HEADER_BYTES))
        .and_then(|hdr| huesos_abi::acpi_archive::decode_v2_header(hdr).ok())
        .map(|header| header.firmware_snapshot_id)
        .unwrap_or(0);

    let (acpi_system_io, acpi_mmio) = if uacpi_tables_ready && acpi_snapshot_id != 0 {
        match boot::acpi_policy::derive_broker_policy(acpi_snapshot_id, boot_info.memory_regions) {
            Ok((io_grants, mmio_grants)) => {
                dbg("[uACPI] derived bounded FADT SystemIO policy\n");
                (io_grants, mmio_grants)
            }
            Err(error) => {
                use core::fmt::Write;
                let mut writer = huesos_arch::serial::SerialWriter;
                let _ = writeln!(
                    writer,
                    "[uACPI] FADT SystemIO policy unavailable: {error:?}; broker denies all"
                );
                (alloc::vec::Vec::new(), alloc::vec::Vec::new())
            }
        }
    } else {
        (alloc::vec::Vec::new(), alloc::vec::Vec::new())
    };

    let allowed_irqs = if uacpi_tables_ready && acpi_snapshot_id != 0 {
        boot::acpi_policy::fadt_sci_irq()
            .into_iter()
            .collect::<alloc::vec::Vec<_>>()
    } else {
        alloc::vec::Vec::new()
    };

    #[cfg(feature = "boot-selftest")]
    let panic_test_requested = cmdline_requests_panic_test(&verified_hbi);
    #[cfg(feature = "boot-selftest")]
    let extable_test_requested = cmdline_requests_extable_test(&verified_hbi);
    #[cfg(feature = "boot-selftest")]
    let irq_test_requested = cmdline_requests_irq_test(&verified_hbi);
    #[cfg(feature = "boot-selftest")]
    let iommu_test_requested = cmdline_requests_iommu_test(&verified_hbi);
    let storage_off_requested = cmdline_requests_storage_off(&verified_hbi);
    let sealed_key_module = verified_hbi
        .get_module(boot::hbi::ModuleType::SealedKey)
        .ok();
    init::object_init(boot_measurement, sealed_key_module);
    install_config_mint_authority(acpi_archive.as_deref(), boot_info.memory_regions);
    initialize_hardware_iommu(acpi_archive.as_deref(), boot_info.memory_regions);

    if firmware_tables_mapped && uacpi_tables_ready {
        match huesos_uacpi::Table::find(b"APIC").and_then(|table| {
            let bytes = table.bytes()?;
            smp::bringup_aps(bytes, boot_info.hhdm_offset);
            Ok(())
        }) {
            Ok(()) => {}
            Err(error) => {
                use core::fmt::Write;
                let mut writer = huesos_arch::serial::SerialWriter;
                let _ = writeln!(
                    writer,
                    "[uACPI] MADT consumer failed: {error:?}; continuing uniprocessor"
                );
            }
        }
    } else if boot_info.rsdp_addr.is_some() {
        dbg("[ACPI] validated table access unavailable; continuing uniprocessor\n");
    }

    let bootfs_image = match verified_hbi.get_module(boot::hbi::ModuleType::Bootfs) {
        Ok(bootfs) => {
            dbg("HBI v2.2 parsed. Entries: ");
            dbg_num(verified_hbi.get_num_entries() as u64);
            dbg("\n");
            Some(bootfs)
        }
        Err(error) => {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::ErrorSerialWriter;
            let _ = writeln!(writer, "[HBI] required BOOTFS missing: {error:?}");
            loop {
                huesos_arch::hlt();
            }
        }
    };
    // The verified HBI command line is delivered to init as a read-only VMO.
    let cmdline_image = verified_hbi.get_module(boot::hbi::ModuleType::Cmdline).ok();
    let storage_boot_info =
        boot::storage::build_storage_boot_info(boot_dma_pool, storage_off_requested);

    init::framebuffer_init(boot_info.framebuffer);
    huesos_arch::fault::set_kernel_fault_handler(crate::panic::from_cpu_fault);
    huesos_arch::fault::set_user_fault_handler(handle_user_fault);
    // Read + sort + publish the linker-emitted .ex_table entries and
    // wire the ring-0 recoverable-copy hook. This is the fault path
    // that turns a race between a validated syscall copy and a
    // concurrent VmarUnmap on another CPU into an ordinary
    // Err(EFAULT) instead of a kernel panic. See crate::extable
    // module docs for the boot ordering rationale and the rollback
    // story.
    let extable_entries = crate::extable::install();
    {
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::SerialWriter;
        let _ = writeln!(
            writer,
            "[extable] installed {extable_entries} recoverable-copy entries"
        );
    }
    #[cfg(feature = "boot-selftest")]
    if extable_test_requested {
        run_extable_synthetic_probe();
    }
    huesos_hal::init();
    init::syscall_init();
    scheduler::init();
    huesos_arch::init_late();

    // APs finished local init during bringup_aps and are spinning on the
    // run-gate; release them now that the timer callback + PIC are live.
    smp::release_aps();

    #[cfg(feature = "boot-selftest")]
    if irq_test_requested {
        boot::irq_probe::run();
    }

    #[cfg(feature = "boot-selftest")]
    if iommu_test_requested {
        boot::iommu_probe::run();
    }

    #[cfg(feature = "boot-selftest")]
    if panic_test_requested {
        panic!("intentional panic requested by HBI cmdline panic_test=1");
    }

    log_boot_banner(&boot_info);
    // First structured record of the boot: everything the kernel needs
    // is up and the first userspace process is about to exist. The
    // detail carries the CPU count so an aggregator can tell an SMP
    // boot from a uniprocessor one without parsing the banner text.
    huesos_object::observation::record(
        huesos_object::observation::ObservationClass::Boot,
        observation_code::KERNEL_READY,
        smp::ap_ready_count() as u64 + 1,
    );
    spawn_init_process(
        bootfs_image,
        acpi_archive.as_deref(),
        acpi_snapshot_id,
        acpi_system_io,
        acpi_mmio,
        allowed_irqs,
        storage_boot_info.as_slice(),
        cmdline_image,
    );

    // BSP idle: timer IRQ drives the scheduler; opportunistically reap & pull.
    loop {
        crate::scheduler::reap_finished_tasks();
        crate::scheduler::idle_try_pull_work();
        huesos_arch::hlt();
    }
}

fn log_boot_banner(boot_info: &BootInfo) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        &mut writer,
        "HuesOS v{} on CPU {}",
        VERSION,
        huesos_arch::cpu::current_id()
    );
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

#[allow(clippy::too_many_arguments)]
fn spawn_init_process(
    bootfs_image: Option<&[u8]>,
    acpi_archive: Option<&[u8]>,
    acpi_snapshot_id: u64,
    acpi_system_io: alloc::vec::Vec<huesos_object::SystemIoGrant>,
    acpi_mmio: alloc::vec::Vec<huesos_object::MmioGrant>,
    allowed_irqs: alloc::vec::Vec<u32>,
    storage_boot_info: &[u8],
    cmdline_image: Option<&[u8]>,
) {
    use huesos_object::KernelObject;

    let spawned = match process::spawn_from_elf("init", INIT_BINARY) {
        Ok(spawned) => spawned,
        Err(error) => {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::SerialWriter;
            let _ = writeln!(
                writer,
                "[init] launch failed: {error:?}; entering kernel idle"
            );
            return;
        }
    };
    INIT_PROCESS_KOID.store(
        spawned.process.koid().0,
        core::sync::atomic::Ordering::Release,
    );

    if let Some(bytes) = bootfs_image {
        if !install_readonly_vmo(&spawned.process, huesos_abi::INIT_BOOTFS_HANDLE, bytes) {
            dbg("[init] failed to install BOOTFS VMO\n");
        }
    } else {
        dbg("[init] HBI BOOTFS module unavailable\n");
    }
    if let Some(bytes) = acpi_archive {
        if install_readonly_mappable_vmo(
            &spawned.process,
            huesos_abi::INIT_ACPI_TABLES_HANDLE,
            bytes,
        ) {
            dbg("[init] installed immutable ACPI table archive VMO\n");
            if install_acpi_broker(
                &spawned.process,
                acpi_snapshot_id,
                acpi_system_io,
                acpi_mmio,
                allowed_irqs,
            ) {
                dbg("[init] installed deny-by-default ACPI broker capability\n");
            } else {
                dbg("[init] failed to install ACPI broker capability\n");
            }
        } else {
            dbg("[init] failed to install ACPI table archive VMO\n");
        }
    }
    // Absent or empty command line is the common case and not an
    // error: init falls back to /etc/init.conf and its built-in
    // defaults when the handle is missing.
    if let Some(bytes) = cmdline_image.filter(|bytes| !bytes.is_empty()) {
        if install_readonly_vmo(&spawned.process, huesos_abi::INIT_CMDLINE_HANDLE, bytes) {
            dbg("[init] installed kernel command line VMO\n");
        } else {
            dbg("[init] failed to install kernel command line VMO\n");
        }
    }
    if storage_boot_info.is_empty() {
        dbg("[init] storage boot-info unavailable\n");
    } else if install_readonly_vmo(
        &spawned.process,
        huesos_abi::INIT_STORAGE_BOOT_INFO_HANDLE,
        storage_boot_info,
    ) {
        dbg("[init] installed storage boot-info VMO\n");
    } else {
        dbg("[init] failed to install storage boot-info VMO\n");
    }

    // FrameDraw capability: the initial process is the root userspace
    // supervisor and the only place a `FrameDraw` [`Resource`] is
    // minted in the MVP. Without this handle installed at slot
    // [`huesos_abi::INIT_FRAME_DRAW_HANDLE`], every
    // [`huesos_abi::Syscall::FramebufferBlit`] the init process
    // issues (e.g. its own early-boot framebuffer logger) would
    // bounce with `AccessDenied` because the kernel-side capability
    // check has nothing to compare the supplied handle against.
    //
    // init mints the resource directly here and transfers it to
    // legitimate graphics consumers (terminal, doom, canvas-hell)
    // over channels at runtime, see `init/src/main.rs`.
    if install_frame_draw_capability(&spawned.process) {
        dbg("[init] installed FrameDraw capability (handle 6)\n");
    } else {
        dbg("[init] failed to install FrameDraw capability\n");
    }
    // Snapshot-bound config-mint authority (AP-8). Minted once, for
    // the root supervisor only; no other process can obtain one.
    if install_pci_config_mint_capability(&spawned.process) {
        dbg("[init] installed PciConfigMint capability (handle 8)\n");
    } else {
        dbg("[init] failed to install PciConfigMint capability\n");
    }
    if install_device_lease_authority_capability(&spawned.process) {
        dbg("[init] installed DeviceLeaseAuthority capability (handle 9)\n");
    } else {
        dbg("[init] failed to install DeviceLeaseAuthority capability\n");
    }

    let name = *b"init\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let _ = scheduler::spawn_user_thread(
        &name,
        spawned.process,
        spawned.entry_point,
        spawned.user_rsp,
        spawned.cr3,
    );
}

/// Extract the MCFG table from the boot archive and hand the
/// snapshot-bound config-mint authority to the syscall layer (AP-8).
///
/// Fail-closed at every step: any inconsistency — no archive, invalid
/// MCFG, ambiguity — leaves the authority uninstalled, and
/// `Syscall::PciConfigMint` then answers `NotSupported`. No config
/// capability can be minted without the kernel's own boot-time view of
/// the firmware's config windows.
fn install_config_mint_authority(archive: Option<&[u8]>, memory_regions: &[MemoryRegion]) {
    use huesos_abi::acpi_archive::{self, ArchiveReader};

    let fail = |reason: &str| {
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::SerialWriter;
        let _ = writeln!(writer, "[acpi] config mint authority disabled: {reason}");
    };

    let Some(bytes) = archive else {
        fail("no ACPI archive");
        return;
    };
    let mut header = [0u8; acpi_archive::HEADER_BYTES];
    if bytes.read_exact_at(0, &mut header).is_err() {
        fail("archive header unreadable");
        return;
    }
    let Ok(header_v2) = acpi_archive::decode_v2_header(&header) else {
        fail("archive header rejected");
        return;
    };

    // Locate the single MCFG table; ambiguity is rejected, never guessed.
    let mut mcfg: Option<(u64, usize)> = None;
    for index in 0..header_v2.table_count {
        let entry_offset = header_v2.table_entries_offset
            + u64::from(index) * acpi_archive::TABLE_ENTRY_BYTES as u64;
        let mut entry_bytes = [0u8; acpi_archive::TABLE_ENTRY_BYTES];
        if bytes.read_exact_at(entry_offset, &mut entry_bytes).is_err() {
            fail("table directory truncated");
            return;
        }
        let Ok(entry) = acpi_archive::decode_v2_table_entry(&entry_bytes) else {
            fail("table directory entry invalid");
            return;
        };
        if entry.signature == *b"MCFG" {
            if mcfg.is_some() {
                fail("multiple MCFG tables in archive");
                return;
            }
            mcfg = Some((entry.offset, entry.length as usize));
        }
    }
    let Some((mcfg_offset, mcfg_length)) = mcfg else {
        fail("no MCFG table in archive");
        return;
    };
    const MCFG_MAX_BYTES: usize = huesos_pci::mcfg::MCFG_HEADER_BYTES
        + huesos_pci::mcfg::MAX_MCFG_ALLOCATIONS * huesos_pci::mcfg::MCFG_ALLOCATION_BYTES;
    if !(huesos_pci::mcfg::MCFG_HEADER_BYTES..=MCFG_MAX_BYTES).contains(&mcfg_length) {
        fail("MCFG table length out of bounds");
        return;
    }
    let mut mcfg_bytes = [0u8; MCFG_MAX_BYTES];
    if bytes
        .read_exact_at(mcfg_offset, &mut mcfg_bytes[..mcfg_length])
        .is_err()
    {
        fail("MCFG table read failed");
        return;
    }
    let Ok((count, regions)) = huesos_pci::mcfg::decode_all(&mcfg_bytes[..mcfg_length]) else {
        fail("MCFG validation failed");
        return;
    };
    if count == 0 {
        fail("MCFG contains no allocations");
        return;
    }
    const MAX_WINDOWS: usize = huesos_pci::mcfg::MAX_MCFG_ALLOCATIONS;
    let mut allocations = [huesos_abi::pci_config::EcamAllocation {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        ecam_base: 0,
        span_bytes: 1 << 20,
    }; MAX_WINDOWS];
    for (index, region) in regions.iter().take(count).enumerate() {
        allocations[index] = huesos_abi::pci_config::EcamAllocation {
            segment: region.segment(),
            start_bus: region.start_bus(),
            end_bus: region.end_bus(),
            ecam_base: region.base(),
            span_bytes: region.end_exclusive() - region.base(),
        };
    }

    // Retain usable-RAM regions for the alias check. Regions beyond the
    // bound are dropped: the stash is a filter, not a memory model.
    let mut usable = [(0u64, 0u64); huesos_syscalls::config_mint::MAX_RAM_REGIONS];
    let mut usable_count = 0usize;
    for region in memory_regions.iter() {
        if usable_count == usable.len() {
            break;
        }
        if region.usable && region.length > 0 {
            usable[usable_count] = (region.base, region.length);
            usable_count += 1;
        }
    }

    let authority = huesos_syscalls::config_mint::ConfigAuthority::new(
        header_v2.firmware_snapshot_id,
        &allocations[..count],
        &usable[..usable_count],
    );
    if huesos_syscalls::config_mint::install_config_authority(authority) {
        use core::fmt::Write;
        let mut writer = huesos_arch::serial::SerialWriter;
        let _ = writeln!(
            writer,
            "[acpi] config mint authority installed: snapshot {} window(s) {}",
            header_v2.firmware_snapshot_id, count
        );
    } else {
        fail("authority already installed");
    }
}

fn kernel_iommu_bind_dma(
    pci_address_packed: u64,
    lease_koid: u64,
    lease_generation: u64,
    base: u64,
    len: u64,
) -> Result<(), huesos_object::DeviceLeaseError> {
    huesos_arch::iommu::bind_lease_dma(
        pci_address_packed,
        lease_koid,
        lease_generation,
        base,
        len,
    )
    .map_err(|_| huesos_object::DeviceLeaseError::IommuBindFailed)
}

/// Discover `DMAR` (Intel VT-d) or `IVRS` (AMD-Vi) from the validated boot ACPI
/// archive, verify that no hardware MMIO base aliases usable RAM, initialize
/// hardware second-stage DMA translation, and wire `DeviceLease` lifecycle hooks
/// (Stage N.2). Platforms without `DMAR`/`IVRS` stay cleanly in `Trusted` mode.
fn initialize_hardware_iommu(archive: Option<&[u8]>, memory_regions: &[MemoryRegion]) {
    use core::fmt::Write;
    use huesos_abi::acpi_archive::{self, ArchiveReader};
    use huesos_pci::iommu::{discover_from_acpi_tables, FirmwareIommuKind, FirmwareIommuStatus};

    huesos_syscalls::set_iommu_status_fn(huesos_arch::iommu::status);
    huesos_object::set_iommu_lease_hooks(Some(huesos_object::IommuLeaseHooks {
        bind_dma: kernel_iommu_bind_dma,
        teardown: huesos_arch::iommu::teardown_lease,
    }));

    let mut writer = huesos_arch::serial::SerialWriter;
    let Some(bytes) = archive else {
        let _ = writeln!(writer, "[iommu] no ACPI archive; DMA mode=Trusted");
        return;
    };
    let mut header = [0u8; acpi_archive::HEADER_BYTES];
    if bytes.read_exact_at(0, &mut header).is_err() {
        let _ = writeln!(
            writer,
            "[iommu] archive header unreadable; DMA mode=Trusted"
        );
        return;
    }
    let Ok(header_v2) = acpi_archive::decode_v2_header(&header) else {
        let _ = writeln!(writer, "[iommu] archive header rejected; DMA mode=Trusted");
        return;
    };

    let mut dmar: Option<(u64, usize)> = None;
    let mut ivrs: Option<(u64, usize)> = None;
    for index in 0..header_v2.table_count {
        let entry_offset = header_v2.table_entries_offset
            + u64::from(index) * acpi_archive::TABLE_ENTRY_BYTES as u64;
        let mut entry_bytes = [0u8; acpi_archive::TABLE_ENTRY_BYTES];
        if bytes.read_exact_at(entry_offset, &mut entry_bytes).is_err() {
            let _ = writeln!(
                writer,
                "[iommu] table directory truncated; DMA mode=Trusted"
            );
            return;
        }
        let Ok(entry) = acpi_archive::decode_v2_table_entry(&entry_bytes) else {
            let _ = writeln!(writer, "[iommu] table entry invalid; DMA mode=Trusted");
            return;
        };
        if entry.signature == *b"DMAR" {
            if dmar.is_some() {
                let _ = writeln!(writer, "[iommu] duplicate DMAR tables; DMA mode=Trusted");
                return;
            }
            dmar = Some((entry.offset, entry.length as usize));
        } else if entry.signature == *b"IVRS" {
            if ivrs.is_some() {
                let _ = writeln!(writer, "[iommu] duplicate IVRS tables; DMA mode=Trusted");
                return;
            }
            ivrs = Some((entry.offset, entry.length as usize));
        }
    }

    if ivrs.is_some() && dmar.is_some() {
        let _ = writeln!(
            writer,
            "[iommu] conflicting DMAR+IVRS tables; DMA mode=Trusted"
        );
        return;
    }

    const IOMMU_TABLE_MAX_BYTES: usize = 4096;
    let mut table_bytes = [0u8; IOMMU_TABLE_MAX_BYTES];
    let report = if let Some((dmar_offset, dmar_length)) = dmar {
        if !(48..=IOMMU_TABLE_MAX_BYTES).contains(&dmar_length) {
            let _ = writeln!(
                writer,
                "[iommu] DMAR length out of bounds; DMA mode=Trusted"
            );
            return;
        }
        if bytes
            .read_exact_at(dmar_offset, &mut table_bytes[..dmar_length])
            .is_err()
        {
            let _ = writeln!(writer, "[iommu] DMAR read failed; DMA mode=Trusted");
            return;
        }
        discover_from_acpi_tables(Some(&table_bytes[..dmar_length]), None)
    } else if let Some((ivrs_offset, ivrs_length)) = ivrs {
        if !(48..=IOMMU_TABLE_MAX_BYTES).contains(&ivrs_length) {
            let _ = writeln!(
                writer,
                "[iommu] IVRS length out of bounds; DMA mode=Trusted"
            );
            return;
        }
        if bytes
            .read_exact_at(ivrs_offset, &mut table_bytes[..ivrs_length])
            .is_err()
        {
            let _ = writeln!(writer, "[iommu] IVRS read failed; DMA mode=Trusted");
            return;
        }
        discover_from_acpi_tables(None, Some(&table_bytes[..ivrs_length]))
    } else {
        let _ = writeln!(writer, "[iommu] no DMAR/IVRS table in archive; DMA mode=Trusted");
        return;
    };

    if report.status != FirmwareIommuStatus::Valid
        || report.unit_count == 0
        || report.unit_count > huesos_arch::vtd::MAX_DRHD_UNITS
    {
        let _ = writeln!(
            writer,
            "[iommu] IOMMU discovery rejected (kind={:?}, status={:?}, units={}); DMA mode=Trusted",
            report.kind, report.status, report.unit_count
        );
        return;
    }

    // Reject any IOMMU register window that aliases usable physical RAM.
    let window_bytes: u64 = match report.kind {
        FirmwareIommuKind::IntelVtd => 65_536,
        FirmwareIommuKind::AmdVi => huesos_iommu::amd_vi::AMD_VI_MMIO_BYTES,
        FirmwareIommuKind::None => return,
    };
    for unit in &report.units[..report.unit_count] {
        let Some(unit_end) = unit.register_base.checked_add(window_bytes) else {
            let _ = writeln!(writer, "[iommu] IOMMU register overflow; DMA mode=Trusted");
            return;
        };
        for ram in memory_regions {
            if !ram.usable || ram.length == 0 {
                continue;
            }
            let ram_end = ram.base.saturating_add(ram.length);
            if unit.register_base < ram_end && ram.base < unit_end {
                let _ = writeln!(
                    writer,
                    "[iommu] IOMMU base {:#x} aliases usable RAM; DMA mode=Trusted",
                    unit.register_base
                );
                return;
            }
        }
    }

    let mut units = [huesos_arch::vtd::VtdUnitInit {
        segment: 0,
        include_pci_all: false,
        scope_bdf_count: 0,
        register_base: 0,
        scope_bdfs: [0; 4],
    }; huesos_arch::vtd::MAX_DRHD_UNITS];
    for (dst, src) in units
        .iter_mut()
        .zip(report.units[..report.unit_count].iter())
    {
        *dst = huesos_arch::vtd::VtdUnitInit {
            segment: src.segment,
            include_pci_all: src.include_pci_all,
            scope_bdf_count: src.scope_bdf_count,
            register_base: src.register_base,
            scope_bdfs: src.scope_bdfs,
        };
    }

    let keep_regions = report
        .region_count
        .min(huesos_arch::vtd::MAX_RESERVED_REGIONS);
    let mut regions = [huesos_arch::vtd::VtdReservedRegion {
        segment: 0,
        requester_bdf: 0,
        base_address: 0,
        limit_address: 0,
    }; huesos_arch::vtd::MAX_RESERVED_REGIONS];
    for (dst, src) in regions
        .iter_mut()
        .zip(report.regions[..keep_regions].iter())
    {
        *dst = huesos_arch::vtd::VtdReservedRegion {
            segment: src.segment,
            requester_bdf: src.requester_bdf,
            base_address: src.base_address,
            limit_address: src.limit_address,
        };
    }

    match report.kind {
        FirmwareIommuKind::IntelVtd => {
            match huesos_arch::vtd::initialize(
                &units[..report.unit_count],
                &regions[..keep_regions],
            ) {
                Ok(caps) => {
                    let _ = writeln!(
                        writer,
                        "[iommu] Intel VT-d active: units={} aw={}-bit caching_mode={} domains_max={} mode=Isolated",
                        report.unit_count,
                        caps.address_width.bits(),
                        caps.caching_mode,
                        caps.max_domains
                    );
                }
                Err(error) => {
                    let _ = writeln!(
                        writer,
                        "[iommu] Intel VT-d hardware init failed ({error:?}); DMA mode=Trusted"
                    );
                }
            }
        }
        FirmwareIommuKind::AmdVi => {
            match huesos_arch::amd_vi::initialize(
                &units[..report.unit_count],
                &regions[..keep_regions],
                report.interrupt_remapping_supported,
            ) {
                Ok(summary) => {
                    let _ = writeln!(
                        writer,
                        "[iommu] AMD-Vi active: units={} aw=48-bit efr={:#x} domains_max=65535 mode=Isolated",
                        summary.unit_count,
                        summary.ext_features
                    );
                }
                Err(error) => {
                    let _ = writeln!(
                        writer,
                        "[iommu] AMD-Vi hardware init failed ({error:?}); DMA mode=Trusted"
                    );
                }
            }
        }
        FirmwareIommuKind::None => {}
    }
}

fn install_readonly_vmo(
    process: &huesos_object::Process,
    slot: huesos_abi::HandleValue,
    bytes: &[u8],
) -> bool {
    install_immutable_vmo(process, slot, bytes, false)
}

fn install_readonly_mappable_vmo(
    process: &huesos_object::Process,
    slot: huesos_abi::HandleValue,
    bytes: &[u8],
) -> bool {
    install_immutable_vmo(process, slot, bytes, true)
}

fn install_immutable_vmo(
    process: &huesos_object::Process,
    slot: huesos_abi::HandleValue,
    bytes: &[u8],
    mappable: bool,
) -> bool {
    use huesos_object::{Handle, KernelObject, Rights};

    let alloc_size = if mappable {
        let Some(size) = bytes.len().div_ceil(4096).max(1).checked_mul(4096) else {
            return false;
        };
        size
    } else {
        bytes.len()
    };
    let Ok(vmo) = huesos_object::Vmo::new_in_job(alloc_size, Some(process.job())) else {
        return false;
    };
    if vmo.write(0, bytes) != bytes.len() {
        return false;
    }
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let mut rights = Rights::READ | Rights::DUPLICATE | Rights::TRANSFER;
    if mappable {
        rights |= Rights::MAP;
    }
    if process
        .handles
        .insert_at(slot, Handle::new(koid, rights))
        .is_err()
    {
        huesos_object::unregister_object(koid);
        return false;
    }
    true
}

fn install_acpi_broker(
    process: &huesos_object::Process,
    snapshot_id: u64,
    system_io: alloc::vec::Vec<huesos_object::SystemIoGrant>,
    mmio: alloc::vec::Vec<huesos_object::MmioGrant>,
    allowed_irqs: alloc::vec::Vec<u32>,
) -> bool {
    use huesos_object::{Handle, KernelObject, Rights};

    // AP-10: the PCI grant list is gone — the broker can never
    // authorize PCI configuration opcodes. Configuration access flows
    // through the dedicated mediated channel to PCI Manager.
    let broker = huesos_object::AcpiBroker::with_full_policy(
        snapshot_id,
        system_io,
        mmio,
        allowed_irqs,
        false,
        false,
    );
    let koid = broker.koid();
    huesos_object::register_object(broker);
    let rights = Rights::READ | Rights::WRITE | Rights::DUPLICATE | Rights::TRANSFER;
    if process
        .handles
        .insert_at(
            huesos_abi::INIT_ACPI_BROKER_HANDLE,
            Handle::new(koid, rights),
        )
        .is_err()
    {
        huesos_object::unregister_object(koid);
        return false;
    }
    true
}

/// Install the [`huesos_abi::INIT_FRAME_DRAW_HANDLE`] capability for
/// the initial process. Mints a binary `FrameDraw` [`Resource`] (the
/// kind with no meaningful `base`/`len`, exactly like `PowerControl`)
/// and inserts the handle at the canonical slot 6. The kernel's
/// [`huesos_syscalls`] capability check accepts this handle as
/// authority to call [`huesos_abi::Syscall::FramebufferBlit`]; no
/// other process can mint the same kind because
/// [`crate::resource::sys_resource_create`] is gated on the root
/// supervisor KOID predicate.
///
/// On failure the resource is unregistered and the process keeps
/// running without a `FrameDraw` handle — its first blit will then
/// return `AccessDenied`, exactly the same observable behaviour the
/// system would have if the user never started the boot.
/// Install the [`huesos_abi::INIT_CONFIG_MINT_HANDLE`] capability for
/// the initial process. Minted once as a binary `PciConfigMint`
/// [`Resource`] exclusively for the root supervisor; it is the sole
/// authority that lets a process call
/// [`huesos_abi::Syscall::PciConfigMint`]. `sys_resource_create` cannot
/// mint this kind, so the uniqueness does not depend on userspace good
/// behaviour. `init` hands the handle to the supervised driver stack
/// over a channel when it launches the ACPI/PCI managers (AP-9);
/// no mapping or PCI authority is granted by this capability alone.
fn install_pci_config_mint_capability(process: &huesos_object::Process) -> bool {
    use huesos_object::{Handle, KernelObject, Resource, ResourceKind, Rights};

    let Ok(resource) = Resource::try_create_exclusive(ResourceKind::PciConfigMint, 0, 1) else {
        return false;
    };
    let koid = resource.koid();
    // `DUPLICATE` is deliberately absent: the authority is unique and a
    // copy would defeat the minted-once accounting. `TRANSFER` lets
    // init hand the single handle to the supervised driver stack.
    let rights = Rights::READ | Rights::TRANSFER;
    if process
        .handles
        .insert_at(
            huesos_abi::INIT_CONFIG_MINT_HANDLE,
            Handle::new(koid, rights),
        )
        .is_err()
    {
        huesos_object::unregister_object(koid);
        return false;
    }
    true
}

fn install_device_lease_authority_capability(process: &huesos_object::Process) -> bool {
    use huesos_object::{Handle, KernelObject, Resource, ResourceKind, Rights};

    let Ok(resource) = Resource::try_create_exclusive(ResourceKind::DeviceLeaseAuthority, 0, 1)
    else {
        return false;
    };
    let koid = resource.koid();
    let rights = Rights::READ | Rights::TRANSFER | Rights::DUPLICATE;
    if process
        .handles
        .insert_at(
            huesos_abi::INIT_DEVICE_LEASE_AUTH_HANDLE,
            Handle::new(koid, rights),
        )
        .is_err()
    {
        huesos_object::unregister_object(koid);
        return false;
    }
    true
}

fn install_frame_draw_capability(process: &huesos_object::Process) -> bool {
    use huesos_object::{Handle, KernelObject, Resource, ResourceKind, Rights};

    let Ok(resource) = Resource::try_create_exclusive(ResourceKind::FrameDraw, 0, 1) else {
        return false;
    };
    let koid = resource.koid();
    // `Resource::try_create_exclusive` already registered the
    // resource in the global registry; do not register_object again.
    //
    // `DUPLICATE` is load-bearing: a second *mint* of `FrameDraw` is
    // impossible (the per-kind overlap check rejects another exclusive
    // or shared resource over `[0, 1)`), yet several legitimate
    // graphics consumers (terminal, doom, ...) each need a live handle
    // in their own table for the per-caller blit check. init therefore
    // duplicates this installed handle and transfers each duplicate
    // over a channel; every consumer ends up holding a handle to the
    // same single resource, and no new authority is ever minted.
    let rights = Rights::READ | Rights::WRITE | Rights::TRANSFER | Rights::DUPLICATE;
    if process
        .handles
        .insert_at(
            huesos_abi::INIT_FRAME_DRAW_HANDLE,
            Handle::new(koid, rights),
        )
        .is_err()
    {
        huesos_object::unregister_object(koid);
        return false;
    }
    true
}

#[cfg(feature = "boot-selftest")]
fn cmdline_requests_panic_test(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, b"panic_test=1")
}

#[cfg(feature = "boot-selftest")]
fn cmdline_requests_irq_test(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, b"irq_test=1")
}

#[cfg(feature = "boot-selftest")]
fn cmdline_requests_iommu_test(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, b"iommu_test=1")
}

#[cfg(feature = "boot-selftest")]
fn cmdline_requests_extable_test(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, b"extable_test=1")
}

fn cmdline_requests_storage_off(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, huesos_abi::storage_boot::STORAGE_OFF_TOKEN)
}

fn cmdline_requests_verbose_log(image: &boot::hbi::HbiImage<'_>) -> bool {
    cmdline_flag_present(image, b"log=verbose") || cmdline_flag_present(image, b"kernel.verbose=1")
}

fn cmdline_flag_present(image: &boot::hbi::HbiImage<'_>, needle: &[u8]) -> bool {
    let Ok(cmdline) = image.get_module(boot::hbi::ModuleType::Cmdline) else {
        return false;
    };
    cmdline
        .split(|byte| byte.is_ascii_whitespace())
        .any(|argument| argument == needle)
}

/// Trigger the synthetic recoverable-copy probe from
/// [`huesos_syscalls::user_access`] and log the outcome on early serial.
/// Only invoked when the HBI command-line requests `extable_test=1`.
///
/// The probe intentionally accesses an unmapped userspace address; the
/// kernel's IDT `#PF` handler is expected to consult the extable and
/// redirect execution to the fixup landing pad, so the caller observes
/// an ordinary `Err(ErrorCode::InvalidArgs)` and the kernel keeps
/// running. If the probe returns any other outcome the fault path is
/// broken and the CI QEMU smoke gate will fail on the missing / wrong
/// marker.
#[cfg(feature = "boot-selftest")]
fn run_extable_synthetic_probe() {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    // SAFETY: this is the only call site of the trusted probe. It runs
    // once during kmain, on the BSP, before any userspace process is
    // spawned. No user-controlled data reaches the fault path — the
    // faulting address is a compile-time constant deep inside the
    // canonical lower half of the address space.
    match unsafe { huesos_syscalls::user_access::synthetic_recoverable_copy_probe() } {
        Ok(()) => {
            let _ = writeln!(
                writer,
                "[extable-test] recovered synthetic user-copy fault OK"
            );
            // A fault that was detected and repaired: this is what the
            // Recovery class is for, and it is the one place in the
            // kernel that provably exercises the recovery path on every
            // boot that asks for it.
            huesos_object::observation::record(
                huesos_object::observation::ObservationClass::Recovery,
                observation_code::EXTABLE_PROBE_RECOVERED,
                0,
            );
        }
        Err(error) => {
            let _ = writeln!(
                writer,
                "[extable-test] FAILED: probe returned {error:?} instead of recovered fault"
            );
            huesos_object::observation::record(
                huesos_object::observation::ObservationClass::Error,
                observation_code::EXTABLE_PROBE_FAILED,
                error as i32 as i64 as u64,
            );
        }
    }
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
        huesos_arch::fault::FaultKind::DoubleFault => crate::panic::from_cpu_fault(info),
    };

    let mut writer = huesos_arch::serial::ErrorSerialWriter;
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

fn err_dbg(msg: &str) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::ErrorSerialWriter;
    let _ = w.write_str(msg);
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
