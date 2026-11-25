//! SMP bring-up and AP entry point (`SMP_V2.md` §§3–10, 14).

use crate::task::{KernelStack, KERNEL_STACK_SIZE};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Number of CPUs that have successfully entered the Rust AP entry point
/// and finished local init (scheduler + GDT/IDT/PAT/SIMD/SYSCALL).
static AP_READY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Gate: APs wait here until the BSP has finished `init_late`.
static APS_MAY_RUN: AtomicBool = AtomicBool::new(false);

/// Guard-paged `NX` stacks allocated for APs (one per discovered AP). Retained
/// permanently on the BSP even if an AP times out (`CpuState::Failed`), so a
/// late-waking processor can never touch freed stack memory (`SMP_V2.md` §6).
static AP_STACKS: spin::Once<Vec<KernelStack>> = spin::Once::new();

/// Detected hardware SMT/core/package topology from CPUID `0x1F` / `0x0B`.
static CPU_TOPOLOGY: spin::Once<huesos_sched::CpuTopology> = spin::Once::new();

/// How long the BSP waits for each AP to report ready (rough microseconds).
const AP_READY_TIMEOUT_US: u32 = 200_000;

/// Parse a uACPI-referenced MADT, discover CPUs, and bring up all APs.
pub fn bringup_aps(madt_bytes: &[u8], hhdm_offset: u64) {
    let topology = *CPU_TOPOLOGY.call_once(huesos_arch::cpu::detect_topology);

    let Some(madt) = huesos_arch::acpi::parse_madt_bytes(madt_bytes) else {
        unsafe {
            huesos_arch::lapic::set_base(0xfee0_0000, hhdm_offset);
            huesos_arch::lapic::init();
        }
        let bsp_id = huesos_arch::lapic::id();
        crate::scheduler::note_cpu_discovered(0, bsp_id, topology.locate_apic_id(bsp_id));
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

    match huesos_arch::ioapic::init_keyboard(madt_bytes) {
        Ok(()) => log_line("[IOAPIC] routed keyboard IRQ1\n"),
        Err(error) => {
            log_line("[IOAPIC] keyboard route unavailable; retaining PIC: ");
            log_line(match error {
                huesos_arch::ioapic::IoApicError::NoController => "no controller",
                huesos_arch::ioapic::IoApicError::InvalidMadt => "invalid MADT",
                huesos_arch::ioapic::IoApicError::Mapping => "MMIO mapping failed",
                huesos_arch::ioapic::IoApicError::InvalidVector => "invalid vector",
                huesos_arch::ioapic::IoApicError::NoRoute => "no route",
                huesos_arch::ioapic::IoApicError::UnsupportedDestination => {
                    "unsupported APIC destination"
                }
                huesos_arch::ioapic::IoApicError::Verification => "readback mismatch",
                huesos_arch::ioapic::IoApicError::TooManyControllers => "controller limit exceeded",
                huesos_arch::ioapic::IoApicError::InvalidControllerRange => {
                    "invalid or overlapping GSI ranges"
                }
                huesos_arch::ioapic::IoApicError::InvalidOverrideFlags => {
                    "reserved source-override flags"
                }
                huesos_arch::ioapic::IoApicError::NoVector => "no free interrupt vector",
                huesos_arch::ioapic::IoApicError::AlreadyInitialized => "already initialized",
                huesos_arch::ioapic::IoApicError::NotInitialized => "not initialized",
                huesos_arch::ioapic::IoApicError::RouteConflict => "route conflict",
                huesos_arch::ioapic::IoApicError::RouteNotFound => "route not found",
                huesos_arch::ioapic::IoApicError::Busy => "level route still in service",
                huesos_arch::ioapic::IoApicError::DestinationOffline => "destination CPU offline",
                huesos_arch::ioapic::IoApicError::InvalidSourceOverrideGsi => {
                    "MADT override GSI has no owning controller pin"
                }
            });
            log_line("\n");
        }
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
    crate::scheduler::note_cpu_discovered(0, bsp_lapic_id, topology.locate_apic_id(bsp_lapic_id));

    if madt.cpu_count <= 1 {
        return;
    }

    let ap_count = madt.cpu_count - 1;
    let mut stacks = Vec::with_capacity(ap_count);
    for _ in 0..ap_count {
        stacks.push(KernelStack::allocate(KERNEL_STACK_SIZE));
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
        if cpu.apic_id == bsp_lapic_id {
            continue;
        }
        if ap_index >= ap_count {
            break;
        }
        let discovered_slot = (ap_index + 1).min(huesos_sched::MAX_CPUS - 1);
        crate::scheduler::note_cpu_discovered(
            discovered_slot,
            cpu.apic_id,
            topology.locate_apic_id(cpu.apic_id),
        );

        if !huesos_arch::lapic::can_address_apic_id(cpu.apic_id) {
            crate::scheduler::note_cpu_parked(discovered_slot);
            log_line("[SMP] AP ");
            log_num(u64::from(cpu.apic_id));
            log_line(" parked: APIC ID requires x2APIC hardware\n");
            ap_index += 1;
            continue;
        }

        let stack = &ap_stacks[ap_index];
        let stack_top = stack.top();
        if stack_top == 0 {
            crate::scheduler::note_cpu_parked(discovered_slot);
            ap_index += 1;
            continue;
        }

        crate::scheduler::note_cpu_starting(discovered_slot);
        log_line("[SMP] Booting AP ");
        log_num(cpu.apic_id as u64);
        log_line("\n");

        let ready_before = AP_READY_COUNT.load(Ordering::Acquire);

        unsafe {
            huesos_arch::ap_boot::boot_ap(cpu.apic_id, stack_top, ap_entry as *const () as u64);
        }

        let mut waited = 0u32;
        while AP_READY_COUNT.load(Ordering::Acquire) == ready_before && waited < AP_READY_TIMEOUT_US
        {
            huesos_arch::lapic::delay_us(100);
            waited += 100;
        }

        if AP_READY_COUNT.load(Ordering::Acquire) > ready_before {
            log_line("[SMP] AP ");
            log_num(cpu.apic_id as u64);
            log_line(" ready\n");
        } else {
            crate::scheduler::note_cpu_failed(discovered_slot);
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
    log_num(AP_READY_COUNT.load(Ordering::Acquire) as u64);
    log_line("\n");
}

/// Called by the BSP after `scheduler::init` + `init_late` so APs may start
/// scheduling and enter the idle loop with `IF = 1`.
pub fn release_aps() {
    APS_MAY_RUN.store(true, Ordering::SeqCst);
    log_line("[SMP] APs released to run\n");
}

/// Number of APs that completed local init.
pub fn ap_ready_count() -> usize {
    AP_READY_COUNT.load(Ordering::Acquire)
}

/// Rust entry point called by the AP trampoline.
///
/// # Safety
/// Called in 64-bit long mode with a valid stack and CR3. Interrupts off.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ap_entry() -> ! {
    huesos_arch::lapic::init();

    let lapic_id = huesos_arch::lapic::id();
    unsafe {
        let cpu_local = huesos_arch::cpu_local::alloc_cpu_local(lapic_id);
        huesos_arch::cpu_local::init_gs_base(cpu_local);
    }

    // Per-CPU SIMD (`XSAVE`/`FXSAVE`), `IA32_PAT` (`WC`), SMEP/SMAP, and `NX`.
    huesos_arch::cpu::enable_sse();
    let protection = huesos_arch::cpu::enable_memory_protection();
    log_line("[security] AP ");
    log_num(lapic_id as u64);
    if protection.smep && protection.smap {
        log_line(" SMEP=on SMAP=on\n");
    } else {
        log_line(" degraded: SMEP/SMAP unavailable\n");
    }

    let gdt = huesos_arch::gdt::PerCpuGdt::new();
    let gdt_static = alloc::boxed::Box::leak(alloc::boxed::Box::new(gdt));
    gdt_static.load();

    unsafe {
        let ptr = huesos_arch::cpu_local::cpu_local_ptr();
        (*ptr).gdt = gdt_static as *mut huesos_arch::gdt::PerCpuGdt as *mut ();
    }

    huesos_arch::idt::init();

    let s = &gdt_static.selectors;
    huesos_arch::syscall::init(s.kernel_code, s.kernel_data, s.user_code, s.user_data);

    let cpu_idx = unsafe { huesos_arch::cpu_local::current_cpu_index() };
    if let Some(topo) = CPU_TOPOLOGY.get() {
        crate::scheduler::note_cpu_location(cpu_idx, topo.locate_apic_id(lapic_id));
    }

    crate::scheduler::init();

    AP_READY_COUNT.fetch_add(1, Ordering::SeqCst);

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" online (waiting for release)\n");

    while !APS_MAY_RUN.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }

    crate::scheduler::arm_ap_initial_timer();

    log_line("[SMP] AP ");
    log_num(lapic_id as u64);
    log_line(" scheduling\n");

    huesos_arch::interrupts::enable();

    loop {
        crate::scheduler::reap_if_pending();
        crate::scheduler::idle_try_pull_work();
        huesos_arch::hlt();
    }
}

fn log_line(msg: &str) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = w.write_str(msg);
}

fn log_num(n: u64) {
    use core::fmt::Write;
    let mut w = huesos_arch::serial::SerialWriter;
    let _ = write!(w, "{}", n);
}
