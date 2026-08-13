use huesos_pmm::MemoryRegion;

// 64 MiB leaves enough physical memory on the default 256 MiB machine for
// large userspace programs (notably the Doom/Freedoom image) while retaining
// ample kernel allocator headroom.
const HEAP_SIZE: usize = 64 * 1024 * 1024;
const HEAP_VIRT_START: u64 = 0xffff_ff00_0000_0000;

/// Limine memmap types that base revision 3 does *not* put into the HHDM,
/// but that firmware tables (RSDP/XSDT/MADT/…) live in. Matches the Limine
/// protocol constants; we hardcode the values so huesos-kernel does not
/// depend on the limine crate.
const MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
const MEMMAP_ACPI_NVS: u64 = 3;
/// Some Limine builds also expose this as type 8 (ACPI tables / mapped reserved).
const MEMMAP_ACPI_TABLES_OR_MAPPED_RESERVED: u64 = 8;
/// Stage-A storage target: a single 64 MiB physically contiguous DMA pool.
const BOOT_DMA_POOL_LEN: u64 = 64 * 1024 * 1024;
/// Prefer a 2 MiB-aligned base so later huge-page/IOMMU mappings can reuse the
/// same aperture without moving the pool.
const BOOT_DMA_POOL_ALIGN: u64 = 2 * 1024 * 1024;
/// Until an IOMMU/IOVA allocator lands, keep the boot pool below 4 GiB so it
/// is usable even for controllers/firmware paths with conservative DMA masks.
const BOOT_DMA_POOL_MAX_PHYS: u64 = 0x1_0000_0000;

/// Reserved boot DMA pool descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootDmaPool {
    /// Device-visible physical base.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

/// Initialize the physical frame allocator from the boot memory map.
///
/// # Safety
/// `regions` must remain readable for the call and every usable physical range
/// must be accessible through the supplied HHDM offset.
pub unsafe fn pmm_init(
    regions: &[MemoryRegion],
    hhdm_offset: u64,
) -> Result<(), huesos_pmm::PmmInitError> {
    unsafe { huesos_pmm::init(regions, hhdm_offset) }
}

/// Reserve and zero the Stage-A boot DMA pool before the kernel heap consumes
/// normal PMM frames.
pub fn reserve_boot_dma_pool() -> Option<BootDmaPool> {
    let base = match huesos_pmm::alloc_contiguous_aligned(
        BOOT_DMA_POOL_LEN,
        BOOT_DMA_POOL_ALIGN,
        BOOT_DMA_POOL_MAX_PHYS,
    ) {
        Ok(base) => base,
        Err(error) => {
            use core::fmt::Write;
            let mut writer = huesos_arch::serial::SerialWriter;
            let _ = writeln!(
                writer,
                "[storage] 64 MiB boot DMA pool unavailable: {error:?}"
            );
            return None;
        }
    };

    let virt = huesos_arch::paging::phys_to_virt(base).as_mut_ptr::<u8>();
    // SAFETY: `alloc_contiguous_aligned` returned a run of ordinary physical
    // RAM that is now exclusively reserved in the PMM. Limine's HHDM covers
    // usable RAM on this boot path, and paging initialization has already
    // published `phys_to_virt`, so zeroing the newly reserved pool through the
    // HHDM cannot alias a live allocation.
    unsafe { core::ptr::write_bytes(virt, 0, BOOT_DMA_POOL_LEN as usize) };

    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        writer,
        "[storage] reserved boot DMA pool: phys={:#x}, len={:#x}",
        base, BOOT_DMA_POOL_LEN
    );
    Some(BootDmaPool {
        base,
        len: BOOT_DMA_POOL_LEN,
    })
}

/// Map firmware / ACPI physical ranges into the HHDM so early ACPI walks
/// (and anything else that does `hhdm + phys`) can touch them.
///
/// Also maps a small window around the RSDP address itself, in case the
/// firmware put it in a region whose type we don't classify above.
pub fn map_firmware_tables(
    regions: &[MemoryRegion],
    rsdp_addr: Option<u64>,
) -> Result<(), huesos_arch::paging::KernelPageError> {
    for r in regions {
        // Do NOT map general RESERVED: that includes MMIO (LAPIC/IOAPIC/PCI)
        // and a WB map of the LAPIC page would make later NO_CACHE remap a
        // no-op (PageAlreadyMapped) and hang on ICR writes under TCG.
        let needs_map = matches!(
            r.kind,
            MEMMAP_ACPI_RECLAIMABLE | MEMMAP_ACPI_NVS | MEMMAP_ACPI_TABLES_OR_MAPPED_RESERVED
        );
        if needs_map && r.length > 0 {
            // ACPI tables are tiny; cap so a mis-typed region cannot explode.
            let len = core::cmp::min(r.length, 4 * 1024 * 1024);
            huesos_arch::paging::map_hhdm_range(r.base, len)?;
        }
    }

    if let Some(rsdp) = rsdp_addr {
        // Always cover the RSDP page (and a couple of neighbours) even if
        // its memmap type was unexpected.
        let page = rsdp & !0xfff;
        huesos_arch::paging::map_hhdm_range(page.saturating_sub(0x1000), 0x3000)?;
    }
    Ok(())
}

pub fn heap_init() -> Result<(), huesos_arch::paging::KernelPageError> {
    use huesos_arch::paging::{flags, map_new_page};
    use x86_64::structures::paging::{Page, Size4KiB};
    use x86_64::VirtAddr;

    let page_count = HEAP_SIZE.div_ceil(4096);

    for i in 0..page_count {
        let v = HEAP_VIRT_START + (i as u64) * 4096;
        let p = Page::<Size4KiB>::containing_address(VirtAddr::new(v));
        map_new_page(p, flags::KERNEL_RW)?;
    }

    unsafe {
        let a = crate::mem::alloc::KernelAllocator::new(HEAP_VIRT_START as usize, page_count);
        *crate::mem::alloc::GLOBAL_ALLOCATOR.lock() = Some(a);
    }
    Ok(())
}

pub fn object_init() {
    huesos_object::init();
    huesos_object::set_phys_to_virt(|p| huesos_arch::paging::phys_to_virt(p).as_u64());
    huesos_object::set_cpu_id_callback(|| unsafe { huesos_arch::cpu_local::current_cpu_index() });
    // Stage D key provider. The TPM comes first: a key sealed to a
    // PCR policy is the real provider, and the build-time blob is
    // the development fallback it replaces. Installing the fallback
    // first and letting the TPM overwrite it would mean a machine
    // whose boot chain was tampered with still mounts, using the key
    // compiled into the image -- the exact outcome sealing exists to
    // prevent.
    let outcome = crate::tpm::init_volume_key();
    match outcome {
        crate::tpm::UnsealOutcome::Installed => {
            tpm_log("[tpm] volume key unsealed (PCR policy satisfied)");
        }
        crate::tpm::UnsealOutcome::PolicyMismatch => {
            // Deliberately fatal for encrypted volumes: no key is
            // installed, so the mount is refused downstream.
            tpm_log("[tpm] unseal refused: PCR policy mismatch (boot chain changed)");
        }
        crate::tpm::UnsealOutcome::Failed => {
            tpm_log("[tpm] unseal failed");
        }
        // Not failures, but not silence either: "no TPM" and "a TPM
        // with nothing sealed to it" are different states, and a
        // silent boot makes them indistinguishable from a TPM that
        // was probed successfully. That ambiguity is what makes a
        // TPM integration impossible to verify from a boot log.
        crate::tpm::UnsealOutcome::NoTpm => {
            tpm_log("[tpm] no TPM 2.0 CRB interface present");
        }
        crate::tpm::UnsealOutcome::NoSealedBlob => {
            tpm_log("[tpm] TPM present, no sealed volume key in this image");
        }
    }
    if outcome != crate::tpm::UnsealOutcome::Installed {
        // Development/plain builds: the build-time blob
        // (HUESOS_VOLUME_KEY_HEX), or nothing at all.
        if let Some(key) = crate::boot_key::BOOT_VOLUME_KEY_BLOB {
            huesos_object::boot_key::set_boot_volume_key(key);
        }
    }
}

pub fn framebuffer_init(fb: Option<crate::FramebufferInfo>) {
    if let Some(f) = fb {
        use huesos_fb::FramebufferConfig;
        huesos_fb::init(Some(FramebufferConfig {
            addr: f.addr,
            width: f.width as u32,
            height: f.height as u32,
            pitch: f.pitch as u32,
            bpp: f.bpp,
            red_mask_size: f.red_mask_size,
            red_mask_shift: f.red_mask_shift,
            green_mask_size: f.green_mask_size,
            green_mask_shift: f.green_mask_shift,
            blue_mask_size: f.blue_mask_size,
            blue_mask_shift: f.blue_mask_shift,
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
    huesos_syscalls::set_clock_fn(crate::scheduler::global_ticks);
    huesos_syscalls::set_cpu_mask_fn(crate::scheduler::online_cpu_mask);
    huesos_syscalls::set_current_cpu_fn(crate::scheduler::current_cpu_index);
    huesos_syscalls::set_shutdown_fn(crate::shutdown::request);
    huesos_syscalls::set_process_create_fn(crate::process::create_suspended_process);
    huesos_syscalls::set_process_create_in_job_fn(crate::process::create_suspended_process_in_job);
    // Gate the Resource / ProcessMarkCritical syscalls on the root
    // userspace supervisor KOID (currently init; a future component_manager
    // will replace it). See docs/ARCHITECTURE_ROADMAP.md §4.
    huesos_syscalls::resource::set_root_supervisor_predicate(|koid| {
        koid == crate::init_process_koid()
    });
    // Kernel-side halt implementation for the capability-gated
    // `Syscall::HardHalt`. Fuchsia-style inversion of control: the
    // syscall only checks the caller's PowerControl capability; the
    // actual arch-specific stop-CPUs-and-hlt sequence lives here.
    huesos_syscalls::resource::set_hard_halt_fn(crate::shutdown::hard_halt);
    huesos_syscalls::set_vmar_map_fn(crate::process::map_vmo_into_vmar);
    huesos_syscalls::set_vmar_unmap_fn(crate::process::unmap_vmar_mapping);
    huesos_syscalls::set_vmar_protect_fn(crate::process::protect_vmar_mapping);
    huesos_syscalls::set_resource_map_fn(crate::process::map_resource_into_current);
    huesos_syscalls::set_heap_extend_fn(crate::process::heap_extend_current);
    huesos_syscalls::set_thread_start_fn(crate::process::start_thread);
    seed_kernel_entropy();
    huesos_arch::irq_callback::set_irq_callback(handle_irq);

    huesos_object::set_scheduler_hooks(
        crate::scheduler::current_task_id,
        crate::scheduler::park_current,
        crate::scheduler::wake_task,
    );
    huesos_object::wait::set_ticks_fn(crate::scheduler::global_ticks);
}

/// Seed the kernel entropy pool used by `SystemGetEntropy`.
///
/// Sources, best first:
///
/// - `RDRAND`, when the CPU advertises it. Eight independent 64-bit
///   draws are mixed in, so the pool inherits the hardware DRNG's
///   entropy directly.
/// - The timestamp counter, sampled between draws. On a machine with
///   no `RDRAND` (older hardware, some hypervisor configurations)
///   this is the only source, and it is weak: boot-time TSC values
///   are correlated across identical machines. That limitation is
///   recorded in `docs/UNSAFE_AUDIT.md` and the allocator treats the
///   cookie as defence-in-depth, not a secret it can rely on alone.
///
/// Called once from [`syscall_init`], before any userspace process
/// can issue a syscall.
fn seed_kernel_entropy() {
    let mut material = [0u8; 96];
    let mut offset = 0usize;
    let push = |value: u64, material: &mut [u8; 96], offset: &mut usize| {
        if *offset + 8 <= material.len() {
            material[*offset..*offset + 8].copy_from_slice(&value.to_le_bytes());
            *offset += 8;
        }
    };

    for _ in 0..8 {
        if let Some(value) = huesos_arch::rdrand64() {
            push(value, &mut material, &mut offset);
        }
        push(huesos_arch::rdtsc(), &mut material, &mut offset);
    }

    huesos_object::entropy::seed(&material[..offset]);
}

fn handle_irq(irq: u8, d: u64) {
    for i in huesos_object::lookup_interrupts_by_irq(irq) {
        i.signal(huesos_abi::PORT_PACKET_INTERRUPT, d);
    }
}

extern "C" fn handle_syscall(f: &mut huesos_arch::syscall::SyscallFrame) {
    let r = huesos_syscalls::dispatch(f.num, f.arg1, f.arg2, f.arg3, f.arg4, f.arg5);
    // Dispatch has returned with syscall/object locks released. Deferred
    // address-space and object destruction is safe here in process context.
    crate::scheduler::reap_if_pending();
    // The bit-pattern translation from `Result<i64, ErrorCode>` to the
    // raw `u64` delivered on `sysret` is the ABI contract with userspace;
    // going through the shared encoder means every syscall handler uses
    // the same audited translation and any drift is caught by
    // `huesos_abi::tests::encode_syscall_result_*`.
    f.num = huesos_abi::encode_syscall_result(r);
}

fn debug_write(b: &[u8]) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    for &c in b {
        let _ = w.write_char(c as char);
    }
}

/// Serial log line for the TPM bring-up path.
///
/// The kernel has no `println!` of its own at this point in init;
/// the storage bring-up uses the same direct serial writer.
fn tpm_log(message: &str) {
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{}", message);
}
