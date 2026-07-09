//! x86_64-specific implementation.

pub mod acpi;
pub mod ap_boot;
pub mod context_switch;
pub mod cpu;
pub mod gdt;
mod idt;
pub mod interrupts;
pub mod irq_callback;
pub mod keyboard;
pub mod lapic;
pub mod paging;
pub mod pit;
pub mod serial;
pub mod syscall;
pub mod timer_callback;

/// Early architecture initialization (before paging/heap are set up).
///
/// # Safety
/// Must be called exactly once per CPU before entering Rust code.
pub unsafe fn init_early() {
    serial::init();
    // Enable the No-Execute bit in EFER: without this, PageTableFlags::NO_EXECUTE
    // is treated as a reserved bit and using it on any page table entry
    // causes an immediate #GP/#PF instead of the intended W^X protection.
    unsafe {
        use x86_64::registers::control::{Efer, EferFlags};
        Efer::update(|flags| *flags |= EferFlags::NO_EXECUTE_ENABLE);
    }
    gdt::init();
    idt::init();
}

/// Second-stage architecture init: paging must have the PMM ready.
///
/// # Safety
/// `phys_offset` must be a valid HHDM covering physical memory, and the PMM
/// must already be initialized.
pub unsafe fn init_paging(phys_offset: crate::VirtAddr) {
    unsafe {
        paging::init(phys_offset);
    }
}

/// Final stage: enable interrupts, start the LAPIC timer, ready for scheduling.
pub fn init_late() {
    interrupts::init();
    // LAPIC timer: ~100 Hz with divider 16.
    // TODO: calibrate against PIT/TSC for real hardware.
    unsafe {
        lapic::timer_init(
            lapic::TimerDivide::Div16,
            lapic::TimerMode::Periodic,
            0x20000,
            0x20,
        );
    }
}
