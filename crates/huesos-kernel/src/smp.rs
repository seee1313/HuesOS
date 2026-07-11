//! SMP bring-up and AP entry point.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Number of CPUs that have successfully entered the Rust AP entry point
/// and finished local init (scheduler + timer + STI).
static AP_READY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Gate: APs wait here until the BSP has finished `init_late` (PIC + timer
/// callback registered, shared timer count published). Prevents APs from
/// taking IRQ32 before the timer callback is installed.
static APS_MAY_RUN: AtomicBool = AtomicBool::new(false);

/// Stacks allocated for APs (one per CPU beyond BSP). Kept alive for the
/// lifetime of the kernel so APs never lose their stacks.
static AP_STACKS: spin::Once<Vec<Vec<u8>>> = spin::Once::new();

/// How long the BSP waits for each AP to report ready (rough microseconds).
const AP_READY_TIMEOUT_US: u32 = 200_000;

/// Parse ACPI MADT, discover CPUs, and bring up all APs.
/// Called once on the BSP after paging and heap are ready.
pub fn bringup_aps(rsdp_addr: u64, hhdm_offset: u64) {
    let madt = unsafe { huesos_arch::acpi::parse_madt(rsdp_addr, |p| p + hhdm_offset) };

    let Some(madt) = madt else {
        unsafe {
            huesos_arch::lapic::set_base(0xfee0_0000, hhdm_offset);
            huesos_arch::lapic::init();
        }
        // Still calibrate so init_late / APs (none) share a count.
        let c = huesos_arch::lapic::calibrate_timer();
        huesos_arch::lapic::set_timer_initial_count(c);
        log_line("[SMP] no MADT, LAPIC at default 0xfee00000\n");
        return;
    };

    log_line("[SMP] MADT parsed ");
    log_num(madt.cpu_count as u64);
    log_line(" CPUs found\n");

    unsafe {
        huesos_arch::lapic::set_base(madt.local_apic_phys, hhdm_offset);
        huesos_arch::lapic::init();
    }

    // Calibrate once on the BSP *before* APs start. APs reuse this count.
    let count = huesos_arch::lapic::calibrate_timer();
    huesos_arch::lapic::set_timer_initial_count(count);
    log_line("[SMP] LAPIC timer count=");
    log_num(count as u64);
    log_line("\n");

    let bsp_lapic_id = huesos_arch::lapic::id();
    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).lapic_id = bsp_lapic_id;
    }

    if madt.cpu_count <= 1 {
        return;
    }

    let ap_count = madt.cpu_count - 1;
    let mut stacks = alloc::vec::Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        stacks.push(alloc::vec![0u8; 4096 * 16]);
    }
    let ap_stacks = AP_STACKS.call_once(|| stacks);

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

        let stack = &ap_stacks[ap_index];
        let stack_top = stack.as_ptr().wrapping_add(stack.len()) as u64;

        log_line("[SMP] Booting AP ");
        log_num(cpu.apic_id as u64);
        log_line("\n");

        let ready_before = AP_READY_COUNT.load(Ordering::Relaxed);

        unsafe {
            huesos_arch::ap_boot::boot_ap(cpu.apic_id, stack_top, ap_entry as *const () as u64);
        }

        // Wait until the AP finished local init (before the run-gate).
        let mut waited = 0u32;
        while AP_READY_COUNT.load(Ordering::Relaxed) == ready_before && waited < AP_READY_TIMEOUT_US
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

/// Called by the BSP after `scheduler::init` + `init_late` so APs may start
/// their LAPIC timers and enter the idle loop with IF=1.
pub fn release_aps() {
    APS_MAY_RUN.store(true, Ordering::SeqCst);
    log_line("[SMP] APs released to run\n");
}

/// Number of APs that completed local init.
pub fn ap_ready_count() -> usize {
    AP_READY_COUNT.load(Ordering::Relaxed)
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

    // SIMD enable bits are per logical CPU, just like syscall MSRs.
    huesos_arch::cpu::enable_sse();

    // Per-CPU GDT/TSS.
    let gdt = huesos_arch::gdt::PerCpuGdt::new();
    let gdt_static = alloc::boxed::Box::leak(alloc::boxed::Box::new(gdt));
    gdt_static.load();

    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).gdt = gdt_static as *mut huesos_arch::gdt::PerCpuGdt as *mut ();
    }

    // Shared IDT (without this IDTR is still the real-mode zero default).
    huesos_arch::idt::init();

    // Program STAR/LSTAR/SFMASK on this CPU. Syscall MSRs are per-logical-CPU;
    // without this, a userspace task migrated here #UD's on the first `syscall`.
    let s = &gdt_static.selectors;
    huesos_arch::syscall::init(s.kernel_code, s.kernel_data, s.user_code, s.user_data);
    // Handler pointer is global and already set by the BSP in syscall_init().

    // Per-CPU scheduler + idle task + (shared) timer callback registration.
    crate::scheduler::init();

    // Signal "local init done" so the BSP can proceed; then wait for the
    // run-gate before unmasking the timer / STI.
    AP_READY_COUNT.fetch_add(1, Ordering::SeqCst);

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" online (waiting for release)\n");

    while !APS_MAY_RUN.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }

    // Start the local APIC timer with the BSP-calibrated count.
    let initial = huesos_arch::lapic::timer_initial_count().max(1_000_000);
    unsafe {
        huesos_arch::lapic::timer_init(
            huesos_arch::lapic::TimerDivide::Div16,
            huesos_arch::lapic::TimerMode::Periodic,
            initial,
            0x20,
        );
    }

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" scheduling\n");

    huesos_arch::interrupts::enable();

    // Idle loop: HLT waits for the next LAPIC timer IRQ / reschedule IPI.
    // The timer handler runs the per-CPU scheduler tick and may context-switch
    // this idle task onto a real workload that was load-balanced here.
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
