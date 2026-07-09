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
        // No ACPI / MADT — fall back to the standard xAPIC MMIO base so the
        // BSP timer path in `init_late` still works.
        unsafe {
            huesos_arch::lapic::set_base(0xfee0_0000, hhdm_offset);
            huesos_arch::lapic::init();
        }
        log_line("[SMP] no MADT, LAPIC at default 0xfee00000\n");
        return;
    };

    log_line("[SMP] MADT parsed ");
    log_num(madt.cpu_count as u64);
    log_line(" CPUs found\n");

    // ALWAYS program LAPIC for the BSP (timer + EOI), even on single-core.
    // Previously this lived after the cpu_count<=1 early-return, so uniprocessor
    // boots left LAPIC_BASE=0 and `init_late` page-faulted at offset 0x3e0.
    unsafe {
        huesos_arch::lapic::set_base(madt.local_apic_phys, hhdm_offset);
        huesos_arch::lapic::init();
    }

    let bsp_lapic_id = huesos_arch::lapic::id();
    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).lapic_id = bsp_lapic_id;
    }

    if madt.cpu_count <= 1 {
        return;
    }

    // TODO: AP bring-up still flaky under TCG; keep BSP fully online first.
    // Re-enable after trampoline identity-map path is verified end-to-end.
    log_line("[SMP] AP bring-up deferred (BSP-only for now)\n");
    return;

    // Allocate a stack for each AP.
    let ap_count = madt.cpu_count - 1;
    let mut stacks = alloc::vec::Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        let stack = alloc::vec![0u8; 4096 * 16];
        stacks.push(stack);
    }
    unsafe {
        AP_STACKS = stacks;
    }

    // Copy trampoline once (also installs identity maps for 0x7000/0x8000).
    unsafe { huesos_arch::ap_boot::copy_trampoline() };

    let mut ap_index = 0;
    for i in 0..madt.cpu_count {
        let Some(cpu) = madt.cpus[i] else { continue };
        if cpu.apic_id == bsp_lapic_id as u8 {
            continue;
        }

        let stack_top = unsafe {
            AP_STACKS[ap_index].as_ptr().add(AP_STACKS[ap_index].len()) as u64
        };
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

    log_line("[SMP] bringup issued, APs ready=");
    log_num(AP_READY_COUNT.load(Ordering::Relaxed) as u64);
    log_line("\n");
}

/// Rust entry point called by the AP trampoline.
///
/// # Safety
/// This is called in 64-bit long mode with a valid stack and CR3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ap_entry() -> ! {
    huesos_arch::lapic::init();

    let lapic_id = huesos_arch::lapic::id();
    let cpu_local = unsafe { huesos_arch::cpu_local::alloc_cpu_local(lapic_id) };
    unsafe { huesos_arch::cpu_local::init_gs_base(cpu_local) };

    let gdt = huesos_arch::gdt::PerCpuGdt::new();
    let gdt_static = alloc::boxed::Box::leak(alloc::boxed::Box::new(gdt));
    gdt_static.load();

    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).gdt = gdt_static as *mut huesos_arch::gdt::PerCpuGdt as *mut ();
    }

    crate::scheduler::init();

    let initial_count = huesos_arch::lapic::calibrate_timer();
    unsafe {
        huesos_arch::lapic::timer_init(
            huesos_arch::lapic::TimerDivide::Div16,
            huesos_arch::lapic::TimerMode::Periodic,
            initial_count,
            0x20,
        );
    }

    huesos_arch::interrupts::enable();
    AP_READY_COUNT.fetch_add(1, Ordering::Relaxed);

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" online\n");

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
