//! Privileged, non-ACPI orderly software shutdown.

use core::fmt::Write;
use huesos_abi::ErrorCode;
use huesos_object::KernelObject;

/// Validate the root supervisor and halt every CPU (legacy KOID-gated
/// path used by [`huesos_abi::Syscall::SystemShutdown`]). Retained as
/// a fallback for `init` when the userspace `shutdown-broker` failed
/// to come up; the happy path is capability-gated
/// [`hard_halt`] via `Syscall::HardHalt` (see
/// `docs/ARCHITECTURE_ROADMAP.md` §3).
///
/// Since PR-E the kernel no longer performs 8042 quiesce on this
/// path — the 8042 driver has moved to userspace along with every
/// other PS/2 concern (see PR #119 / PR #123 for the two migration
/// steps). `interrupts::disable()` already masks all IRQ delivery
/// before the LAPIC halt sequence, so the machine cannot observe a
/// spurious PS/2 IRQ after we return from this function's `hlt`
/// loop even without the historical `out 0x64, 0xAD/0xA7`.
pub fn request() -> Result<(), ErrorCode> {
    let caller = huesos_object::current_process().ok_or(ErrorCode::AccessDenied)?;
    if caller.koid().0 != crate::init_process_koid() {
        return Err(ErrorCode::AccessDenied);
    }

    let mut serial = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        serial,
        "[shutdown] orderly non-ACPI shutdown requested by init (legacy path)"
    );

    huesos_fb::shutdown_render();
    huesos_arch::interrupts::disable();
    huesos_arch::lapic::timer_stop();
    huesos_arch::lapic::broadcast_excluding_self(huesos_arch::idt::SHUTDOWN_STOP_VECTOR);

    let _ = writeln!(serial, "[shutdown] all CPUs halted; power remains on");
    loop {
        huesos_arch::hlt();
    }
}

/// Atomic capability-gated halt used by [`huesos_abi::Syscall::HardHalt`]
/// and by the kernel-side critical-process fallback (see
/// [`note_critical_exit`]). Diverges. Does **not** touch the PS/2
/// controller: any device-specific quiesce is the responsibility of the
/// userspace capability holder (typically `shutdown-broker`) that
/// invoked this path via its `PowerControl` resource handle.
///
/// Fuchsia-inspired inversion of control: this function is what the
/// userspace shutdown flow reduces to once it has done everything it
/// wanted to do; the kernel just stops CPUs and halts. See
/// `docs/ARCHITECTURE_ROADMAP.md` §3.
pub fn hard_halt() -> ! {
    let mut serial = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        serial,
        "[shutdown] hard_halt: capability-gated atomic halt requested"
    );

    huesos_fb::shutdown_render();
    huesos_arch::interrupts::disable();
    huesos_arch::lapic::timer_stop();
    huesos_arch::lapic::broadcast_excluding_self(huesos_arch::idt::SHUTDOWN_STOP_VECTOR);

    let _ = writeln!(serial, "[shutdown] all CPUs halted; power remains on");
    loop {
        huesos_arch::hlt();
    }
}

/// Critical-process fallback: called from the scheduler exit path when
/// a process marked `Process::is_critical()` exits. Enters the same
/// atomic halt as [`hard_halt`] so a dead broker cannot leave the
/// system in a half-shutdown state. See
/// `docs/ARCHITECTURE_ROADMAP.md` §3 for the "critical to root job"
/// analogue borrowed from Fuchsia.
pub fn note_critical_exit(process_name: &str, exit_code: i64) -> ! {
    let mut serial = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        serial,
        "[shutdown] critical process {} exited with code {}; forcing hard_halt",
        process_name, exit_code
    );
    hard_halt();
}
