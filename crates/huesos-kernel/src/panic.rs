//! Fatal kernel panic policy and non-returning diagnostics.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};
use huesos_arch::fault::FaultInfo;
use x86_64::registers::control::Cr3;

static PANIC_OWNER: AtomicBool = AtomicBool::new(false);

struct EmergencySerial;

impl Write for EmergencySerial {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        huesos_arch::serial::emergency_write(text);
        Ok(())
    }
}

fn become_panic_owner() -> bool {
    PANIC_OWNER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

fn stop_machine() -> usize {
    huesos_arch::interrupts::disable();
    huesos_arch::lapic::timer_stop();
    huesos_arch::lapic::broadcast_excluding_self(huesos_arch::idt::PANIC_STOP_VECTOR);
    // Give peers a bounded opportunity to acknowledge. Panic must never wait
    // forever for a damaged CPU or interrupt controller.
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    huesos_arch::idt::panic_stopped_cpus()
}

fn halt_forever() -> ! {
    huesos_arch::interrupts::disable();
    loop {
        huesos_arch::hlt();
    }
}

/// Fatal exception callback registered with the architecture layer.
pub fn from_cpu_fault(info: FaultInfo) -> ! {
    if !become_panic_owner() {
        halt_forever();
    }
    let stopped_peers = stop_machine();

    let cpu = huesos_arch::cpu::current_id();
    let cr3 = Cr3::read().0.start_address().as_u64();
    let report = format_args!(
        "CPU: {}\nException: {}\nError code: {:#018x}\nFault address: {:#018x}\nInstruction pointer: {:#018x}\nStack pointer: {:#018x}\nRFLAGS: {:#018x}\nCS: {:#06x}\nCR3: {:#018x}\nStopped peer CPUs: {}\nAction: system halted; no automatic reboot\n",
        cpu,
        info.kind.as_str(),
        info.error_code,
        info.fault_address,
        info.instruction_pointer,
        info.stack_pointer,
        info.rflags,
        info.code_segment,
        cr3,
        stopped_peers,
    );

    let mut serial = EmergencySerial;
    let _ = serial.write_str("\n\n================ HuesOS KERNEL PANIC ================\n");
    let _ = serial.write_fmt(report);
    let _ = serial.write_str("======================================================\n");

    // Recreate Arguments because the first value was consumed by serial.
    huesos_fb::panic_render(format_args!(
        "CPU: {}\nException: {}\nError code: {:#018x}\nFault address: {:#018x}\nInstruction pointer: {:#018x}\nStack pointer: {:#018x}\nRFLAGS: {:#018x}\nCS: {:#06x}\nCR3: {:#018x}\nStopped peer CPUs: {}\n\nSYSTEM HALTED - NO AUTOMATIC REBOOT\n",
        cpu,
        info.kind.as_str(),
        info.error_code,
        info.fault_address,
        info.instruction_pointer,
        info.stack_pointer,
        info.rflags,
        info.code_segment,
        cr3,
        stopped_peers,
    ));
    halt_forever()
}

/// Rust panic entry used by the final boot binary.
pub fn from_rust(info: &core::panic::PanicInfo<'_>) -> ! {
    if !become_panic_owner() {
        halt_forever();
    }
    let stopped_peers = stop_machine();

    let cpu = huesos_arch::cpu::current_id();
    let cr3 = Cr3::read().0.start_address().as_u64();
    let location = info.location();

    let mut serial = EmergencySerial;
    let _ = serial.write_str("\n\n================ HuesOS KERNEL PANIC ================\n");
    let _ = writeln!(serial, "CPU: {}", cpu);
    let _ = writeln!(serial, "Reason: Rust panic");
    let _ = writeln!(serial, "Message: {}", info.message());
    if let Some(location) = location {
        let _ = writeln!(
            serial,
            "Source: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    let _ = writeln!(serial, "CR3: {:#018x}", cr3);
    let _ = writeln!(serial, "Stopped peer CPUs: {}", stopped_peers);
    let _ = serial.write_str("Action: system halted; no automatic reboot\n");
    let _ = serial.write_str("======================================================\n");

    if let Some(location) = location {
        huesos_fb::panic_render(format_args!(
            "CPU: {}\nReason: Rust panic\nMessage: {}\nSource: {}:{}:{}\nCR3: {:#018x}\nStopped peer CPUs: {}\n\nSYSTEM HALTED - NO AUTOMATIC REBOOT\n",
            cpu,
            info.message(),
            location.file(),
            location.line(),
            location.column(),
            cr3,
            stopped_peers,
        ));
    } else {
        huesos_fb::panic_render(format_args!(
            "CPU: {}\nReason: Rust panic\nMessage: {}\nCR3: {:#018x}\nStopped peer CPUs: {}\n\nSYSTEM HALTED - NO AUTOMATIC REBOOT\n",
            cpu,
            info.message(),
            cr3,
            stopped_peers,
        ));
    }
    halt_forever()
}
