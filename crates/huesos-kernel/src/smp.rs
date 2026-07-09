//! SMP bring-up and AP entry point.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Number of CPUs that have successfully entered the Rust AP entry point.
static AP_READY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Stacks allocated for APs (one per CPU beyond BSP). Kept alive for the
/// lifetime of the kernel so APs never lose their stacks.
static mut AP_STACKS: Vec<Vec<u8>> = Vec::new();

/// How long the BSP waits for each AP to report ready (rough microseconds).
const AP_READY_TIMEOUT_US: u32 = 100_000; // 0.1 s wall-clock-ish under TCG

/// Parse ACPI MADT, discover CPUs, and bring up all APs.
/// Called once on the BSP after paging and heap are ready.
pub fn bringup_aps(rsdp_addr: u64, hhdm_offset: u64) {
    let madt = unsafe { huesos_arch::acpi::parse_madt(rsdp_addr, |p| p + hhdm_offset) };

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

    // Allocate a stack for each AP (64 KiB).
    let ap_count = madt.cpu_count - 1;
    let mut stacks = alloc::vec::Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        stacks.push(alloc::vec![0u8; 4096 * 16]);
    }
    unsafe {
        AP_STACKS = stacks;
    }

    // Copy trampoline once (also installs HHDM + identity maps for 0x7000/0x8000).
    unsafe {
        huesos_arch::ap_boot::copy_trampoline();
    }

    let mut ap_index = 0usize;
    for i in 0..madt.cpu_count {
        let Some(cpu) = madt.cpus[i] else {
            continue;
        };
        if cpu.apic_id == bsp_lapic_id as u8 {
            continue;
        }
        if ap_index >= ap_count {
            break;
        }

        let stack_top = unsafe {
            AP_STACKS[ap_index]
                .as_ptr()
                .add(AP_STACKS[ap_index].len()) as u64
        };

        log_line("[SMP] Booting AP ");
        log_num(cpu.apic_id as u64);
        log_line("\n");

        let ready_before = AP_READY_COUNT.load(Ordering::Relaxed);

        unsafe {
            huesos_arch::ap_boot::boot_ap(
                cpu.apic_id,
                stack_top,
                ap_entry as *const () as u64,
            );
        }

        // Wait until the AP either reports ready or we time out.
        let mut waited = 0u32;
        while AP_READY_COUNT.load(Ordering::Relaxed) == ready_before
            && waited < AP_READY_TIMEOUT_US
        {
            huesos_arch::lapic::delay_us(100);
            waited += 100;
        }

        if AP_READY_COUNT.load(Ordering::Relaxed) > ready_before {
            log_line("[SMP] AP ");
            log_num(cpu.apic_id as u64);
            log_line(" ready\n");
        } else {
            let status = huesos_arch::ap_boot::ap_status();
            log_line("[SMP] AP ");
            log_num(cpu.apic_id as u64);
            log_line(" TIMEOUT (trampoline status=");
            log_num(status);
            log_line(")\n");
        }

        ap_index += 1;
    }

    log_line("[SMP] bringup done, APs ready=");
    log_num(AP_READY_COUNT.load(Ordering::Relaxed) as u64);
    log_line("\n");
}

/// Rust entry point called by the AP trampoline.
///
/// # Safety
/// Called in 64-bit long mode with a valid stack and CR3. Interrupts off.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ap_entry() -> ! {
    // Local APIC MMIO base was already programmed by the BSP (shared phys).
    huesos_arch::lapic::init();

    let lapic_id = huesos_arch::lapic::id();
    let cpu_local = unsafe { huesos_arch::cpu_local::alloc_cpu_local(lapic_id) };
    unsafe {
        huesos_arch::cpu_local::init_gs_base(cpu_local);
    }

    // Per-CPU GDT/TSS (heap is already up on the BSP).
    let gdt = huesos_arch::gdt::PerCpuGdt::new();
    let gdt_static = alloc::boxed::Box::leak(alloc::boxed::Box::new(gdt));
    gdt_static.load();

    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).gdt = gdt_static as *mut huesos_arch::gdt::PerCpuGdt as *mut ();
    }

    // Load the shared IDT (same as BSP).
    // idt::init just reloads IDTR; safe to call again.
    // (No public re-export of a "load only" helper — init is idempotent.)

    // Shared IDT — without this IDTR is still the zeroed real-mode default
    // and the first exception on the AP triple-faults the machine.
    huesos_arch::idt::init();

    crate::scheduler::init();

    // Bring the LAPIC timer up but keep it masked: unmasking + STI before
    // the BSP has finished init_late races the shared timer path. The BSP
    // can enable AP timers later; for bring-up we only need "online".
    const AP_TIMER_INIT: u32 = 10_000_000;
    unsafe {
        huesos_arch::lapic::timer_init(
            huesos_arch::lapic::TimerDivide::Div16,
            huesos_arch::lapic::TimerMode::Periodic,
            AP_TIMER_INIT,
            0x20,
        );
        // Mask LVT timer (bit 16) so we do not take IRQ32 without a stable path.
        // timer_init currently unmasks; re-mask via a zero init count + mask.
        huesos_arch::lapic::timer_stop();
    }

    // Stay with interrupts disabled on the AP for now. HLT with IF=0 is fine;
    // the AP is parked until a future IPI/unmask path wakes it.
    AP_READY_COUNT.fetch_add(1, Ordering::SeqCst);

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" online\n");

    loop {
        // IF=0: HLT still waits for NMI/INIT/reset, not maskable IRQs.
        // Use a pause loop so we do not depend on NMIs.
        core::hint::spin_loop();
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
