//! SMP bring-up and AP entry point.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Number of CPUs that have successfully entered the Rust AP entry point.
static AP_READY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Stacks allocated for APs (one per CPU beyond BSP).
static mut AP_STACKS: Vec<Vec<u8>> = Vec::new();

/// Parse ACPI MADT, discover CPUs, and bring up all APs.
/// Called once on the BSP after paging and heap are ready.
pub fn bringup_aps(rsdp_addr: u64, hhdm_offset: u64) {
    let madt = unsafe {
        huesos_arch::acpi::parse_madt(rsdp_addr, |p| p + hhdm_offset)
    };

    let Some(madt) = madt else {
        // No ACPI / MADT — stay single-core.
        return;
    };

    log_line("[SMP] MADT parsed");
    log_num(madt.cpu_count as u64);
    log_line(" CPUs found\n");

    if madt.cpu_count <= 1 {
        return;
    }

    // Set LAPIC base so that lapic::id() works on BSP too.
    unsafe {
        huesos_arch::lapic::set_base(madt.local_apic_phys, hhdm_offset);
        huesos_arch::lapic::init();
    }

    // Update BSP cpu_local with real LAPIC ID.
    let bsp_lapic_id = huesos_arch::lapic::id();
    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).lapic_id = bsp_lapic_id;
    }

    // Allocate a stack for each AP.
    let ap_count = madt.cpu_count - 1;
    let mut stacks = alloc::vec::Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        let mut stack = alloc::vec![0u8; 4096 * 16];
        let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) } as u64;
        stacks.push((stack, stack_top));
    }
    unsafe {
        AP_STACKS = stacks.into_iter().map(|(s, _)| s).collect();
    }

    // Copy trampoline once.
    unsafe { huesos_arch::ap_boot::copy_trampoline() };

    let mut ap_index = 0;
    for i in 0..madt.cpu_count {
        let Some(cpu) = madt.cpus[i] else { continue };
        if cpu.apic_id == huesos_arch::lapic::id() as u8 {
            // This is the BSP — skip.
            continue;
        }

        let stack_top = unsafe { AP_STACKS[ap_index].as_ptr().add(AP_STACKS[ap_index].len()) as u64 };
        log_line("[SMP] Booting AP ");
        log_num(cpu.apic_id as u64);
        log_line("\n");

        unsafe {
            huesos_arch::ap_boot::boot_ap(
                cpu.apic_id,
                stack_top,
                ap_entry as *const () as u64,
            );
        }

        ap_index += 1;
    }
}

/// Rust entry point called by the AP trampoline.
///
/// # Safety
/// This is called in 64-bit long mode with a valid stack and CR3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ap_entry() -> ! {
    // Initialize local APIC (base already set by BSP via MMIO).
    huesos_arch::lapic::init();

    // Set up per-CPU locals for this AP.
    let lapic_id = huesos_arch::lapic::id();
    let cpu_local = unsafe { huesos_arch::cpu_local::alloc_cpu_local(lapic_id) };
    unsafe { huesos_arch::cpu_local::init_gs_base(cpu_local) };

    // Load per-CPU GDT.
    let gdt = huesos_arch::gdt::PerCpuGdt::new();
    gdt.load();

    // Initialize per-CPU scheduler.
    crate::scheduler::init();

    // Start LAPIC timer (~100 Hz, divider 16).
    // TODO: calibrate against PIT/TSC for real hardware.
    unsafe {
        huesos_arch::lapic::timer_init(
            huesos_arch::lapic::TimerDivide::Div16,
            huesos_arch::lapic::TimerMode::Periodic,
            0x20000,
            0x20,
        );
    }

    // Enable interrupts.
    huesos_arch::interrupts::enable();

    AP_READY_COUNT.fetch_add(1, Ordering::Relaxed);

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" online\n");

    // Idle loop.
    loop {
        huesos_arch::hlt();
    }
}

fn log_line(msg: &str) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = w.write_str(msg);
}

fn log_num(v: u64) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = write!(&mut w, "{}", v);
}
