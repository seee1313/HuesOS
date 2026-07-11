//! Privileged, non-ACPI orderly software shutdown.

use core::fmt::Write;
use huesos_abi::ErrorCode;
use huesos_object::KernelObject;

/// Validate the root supervisor and halt every CPU.
pub fn request() -> Result<(), ErrorCode> {
    let caller = huesos_object::current_process().ok_or(ErrorCode::AccessDenied)?;
    if caller.koid().0 != crate::init_process_koid() {
        return Err(ErrorCode::AccessDenied);
    }

    let mut serial = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        serial,
        "[shutdown] orderly non-ACPI shutdown requested by init"
    );

    huesos_fb::shutdown_render();
    huesos_arch::interrupts::disable();

    // The 8042 has no power-off command. Disable both PS/2 interfaces so no
    // further device traffic is generated while the software-halted machine
    // waits for physical power removal.
    huesos_arch::keyboard::prepare_shutdown();
    huesos_arch::lapic::timer_stop();
    huesos_arch::lapic::broadcast_excluding_self(huesos_arch::idt::SHUTDOWN_STOP_VECTOR);

    let _ = writeln!(serial, "[shutdown] all CPUs halted; power remains on");
    loop {
        huesos_arch::hlt();
    }
}
