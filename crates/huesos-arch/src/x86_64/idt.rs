//! Interrupt Descriptor Table and privilege-aware exception dispatch.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::fault::{FaultInfo, FaultKind};

/// IPI vector used for a scheduler reschedule request. Kept separate from the
/// LAPIC timer vector so remote wake/token paths do not advance time.
pub const RESCHEDULE_VECTOR: u8 = 0xF0;
/// IPI vector used to freeze non-owner CPUs during a kernel panic.
pub const PANIC_STOP_VECTOR: u8 = 0xF1;
/// IPI vector used for an orderly system-wide software halt.
pub const SHUTDOWN_STOP_VECTOR: u8 = 0xF2;
/// IPI vector used for cross-CPU TLB invalidation.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xF3;
/// First vector reserved for NVMe MSI-X/MSI delivery.
pub const NVME_MSI_VECTOR_BASE: u8 = 0xD0;
/// Number of contiguous NVMe MSI vectors installed in the IDT.
pub const NVME_MSI_VECTOR_COUNT: u8 = 16;
static PANIC_STOPPED_CPUS: AtomicUsize = AtomicUsize::new(0);

/// Number of peer CPUs that acknowledged the panic-stop IPI.
pub fn panic_stopped_cpus() -> usize {
    PANIC_STOPPED_CPUS.load(Ordering::Acquire)
}

fn fault_info(
    kind: FaultKind,
    frame: &InterruptStackFrame,
    error_code: u64,
    fault_address: u64,
) -> FaultInfo {
    FaultInfo {
        kind,
        instruction_pointer: frame.instruction_pointer.as_u64(),
        stack_pointer: frame.stack_pointer.as_u64(),
        rflags: frame.cpu_flags.bits(),
        code_segment: frame.code_segment.0 as u64,
        error_code,
        fault_address,
    }
}

fn dispatch(info: FaultInfo) -> ! {
    if info.from_userspace() {
        super::fault::user_fault(info)
    } else {
        super::fault::kernel_fault(info)
    }
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error_handler);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    idt.alignment_check.set_handler_fn(alignment_check_handler);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(super::gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt[32].set_handler_fn(timer_handler);
    idt[33].set_handler_fn(keyboard_handler);
    idt[super::ioapic::KEYBOARD_VECTOR].set_handler_fn(ioapic_keyboard_handler);
    idt[RESCHEDULE_VECTOR].set_handler_fn(reschedule_handler);
    idt[PANIC_STOP_VECTOR].set_handler_fn(panic_stop_handler);
    idt[SHUTDOWN_STOP_VECTOR].set_handler_fn(shutdown_stop_handler);
    idt[TLB_SHOOTDOWN_VECTOR].set_handler_fn(tlb_shootdown_handler);
    idt[NVME_MSI_VECTOR_BASE].set_handler_fn(nvme_msi_handler_0);
    idt[NVME_MSI_VECTOR_BASE + 1].set_handler_fn(nvme_msi_handler_1);
    idt[NVME_MSI_VECTOR_BASE + 2].set_handler_fn(nvme_msi_handler_2);
    idt[NVME_MSI_VECTOR_BASE + 3].set_handler_fn(nvme_msi_handler_3);
    idt[NVME_MSI_VECTOR_BASE + 4].set_handler_fn(nvme_msi_handler_4);
    idt[NVME_MSI_VECTOR_BASE + 5].set_handler_fn(nvme_msi_handler_5);
    idt[NVME_MSI_VECTOR_BASE + 6].set_handler_fn(nvme_msi_handler_6);
    idt[NVME_MSI_VECTOR_BASE + 7].set_handler_fn(nvme_msi_handler_7);
    idt[NVME_MSI_VECTOR_BASE + 8].set_handler_fn(nvme_msi_handler_8);
    idt[NVME_MSI_VECTOR_BASE + 9].set_handler_fn(nvme_msi_handler_9);
    idt[NVME_MSI_VECTOR_BASE + 10].set_handler_fn(nvme_msi_handler_10);
    idt[NVME_MSI_VECTOR_BASE + 11].set_handler_fn(nvme_msi_handler_11);
    idt[NVME_MSI_VECTOR_BASE + 12].set_handler_fn(nvme_msi_handler_12);
    idt[NVME_MSI_VECTOR_BASE + 13].set_handler_fn(nvme_msi_handler_13);
    idt[NVME_MSI_VECTOR_BASE + 14].set_handler_fn(nvme_msi_handler_14);
    idt[NVME_MSI_VECTOR_BASE + 15].set_handler_fn(nvme_msi_handler_15);
    idt
});

/// Load IDT.
pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    dispatch(fault_info(FaultKind::DivideError, &frame, 0, 0));
}

extern "x86-interrupt" fn breakpoint_handler(_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    // INT3 is deliberately non-fatal for now. A debugger hook can replace
    // this behavior later; returning resumes immediately after the trap.
    crate::serial::emergency_write("[idt] BREAKPOINT\n");
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    dispatch(fault_info(FaultKind::InvalidOpcode, &frame, 0, 0));
}

extern "x86-interrupt" fn general_protection_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    super::cpu::clear_user_access();
    dispatch(fault_info(
        FaultKind::GeneralProtection,
        &frame,
        error_code,
        0,
    ));
}

extern "x86-interrupt" fn page_fault_handler(
    mut frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    super::cpu::clear_user_access();
    let address = Cr2::read().map(|a| a.as_u64()).unwrap_or(0);
    let info = fault_info(FaultKind::PageFault, &frame, error_code.bits(), address);

    // Kernel-mode #PF only: consult the recoverable-copy extable *before*
    // committing to the fatal path. This turns validated user-copy sites
    // (e.g. concurrent VMAR unmap racing an in-flight kernel copy) into
    // an ordinary `Err(EFAULT)` return instead of a kernel panic.
    //
    // For user-mode #PF the historical `dispatch` path stands unchanged:
    // ring-3 exceptions always route through the process-termination
    // policy, never through the extable.
    if !info.from_userspace() {
        if let Some(fixup_rip) = super::fault::try_kernel_recover(info) {
            // Redirect resumption to the fixup landing pad. On iretq the
            // CPU will pick up the new RIP and the copy helper returns
            // its `Err` immediately, with no further copy attempted.
            // SAFETY: we only rewrite the saved RIP; every other frame
            // field is preserved, and the fixup address itself came
            // from a static, table-owned kernel symbol registered via
            // set_kernel_recover_hook (never from user-controlled data).
            unsafe {
                frame.as_mut().update(|f| {
                    f.instruction_pointer = x86_64::VirtAddr::new(fixup_rip);
                });
            }
            return;
        }
    }

    dispatch(info);
}

extern "x86-interrupt" fn alignment_check_handler(frame: InterruptStackFrame, error_code: u64) {
    super::cpu::clear_user_access();
    dispatch(fault_info(FaultKind::AlignmentCheck, &frame, error_code, 0));
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
    super::cpu::clear_user_access();
    super::fault::kernel_fault(fault_info(FaultKind::DoubleFault, &frame, error_code, 0));
}

extern "x86-interrupt" fn panic_stop_handler(_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::interrupts::disable();
    PANIC_STOPPED_CPUS.fetch_add(1, Ordering::Release);
    super::lapic::eoi();
    loop {
        crate::hlt();
    }
}

extern "x86-interrupt" fn shutdown_stop_handler(_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::interrupts::disable();
    super::lapic::timer_stop();
    super::lapic::eoi();
    loop {
        crate::hlt();
    }
}

extern "x86-interrupt" fn tlb_shootdown_handler(_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::paging::handle_tlb_shootdown();
    super::lapic::eoi();
}

extern "x86-interrupt" fn reschedule_handler(_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::lapic::eoi();
    crate::x86_64::timer_callback::reschedule();
}

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::lapic::eoi();
    unsafe {
        super::interrupts::PICS.lock().notify_end_of_interrupt(32);
    }
    crate::x86_64::timer_callback::tick();
}

macro_rules! nvme_msi_handler {
    ($name:ident, $offset:expr) => {
        extern "x86-interrupt" fn $name(_stack_frame: InterruptStackFrame) {
            pci_msi_ack(NVME_MSI_VECTOR_BASE + $offset);
        }
    };
}

nvme_msi_handler!(nvme_msi_handler_0, 0);
nvme_msi_handler!(nvme_msi_handler_1, 1);
nvme_msi_handler!(nvme_msi_handler_2, 2);
nvme_msi_handler!(nvme_msi_handler_3, 3);
nvme_msi_handler!(nvme_msi_handler_4, 4);
nvme_msi_handler!(nvme_msi_handler_5, 5);
nvme_msi_handler!(nvme_msi_handler_6, 6);
nvme_msi_handler!(nvme_msi_handler_7, 7);
nvme_msi_handler!(nvme_msi_handler_8, 8);
nvme_msi_handler!(nvme_msi_handler_9, 9);
nvme_msi_handler!(nvme_msi_handler_10, 10);
nvme_msi_handler!(nvme_msi_handler_11, 11);
nvme_msi_handler!(nvme_msi_handler_12, 12);
nvme_msi_handler!(nvme_msi_handler_13, 13);
nvme_msi_handler!(nvme_msi_handler_14, 14);
nvme_msi_handler!(nvme_msi_handler_15, 15);

fn pci_msi_ack(vector: u8) {
    super::cpu::clear_user_access();
    super::lapic::eoi();
    crate::x86_64::irq_callback::emit(vector, 0);
}

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    keyboard_irq_ack(true);
}

extern "x86-interrupt" fn ioapic_keyboard_handler(_stack_frame: InterruptStackFrame) {
    keyboard_irq_ack(false);
}

fn keyboard_irq_ack(pic: bool) {
    // The kernel is a thin IRQ shim on IRQ1: read the scancode from the
    // PS/2 data port, EOI the controller that fired, then hand the raw
    // byte to userspace via the IRQ callback bridge. Scancode decoding,
    // shift/lock state, and ring-buffering live in the userspace
    // `driver-host:input` process.
    super::cpu::clear_user_access();
    use x86_64::instructions::port::Port;
    let mut port: Port<u8> = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    if pic {
        unsafe {
            super::interrupts::PICS.lock().notify_end_of_interrupt(33);
        }
    } else {
        super::lapic::eoi();
    }
    crate::x86_64::irq_callback::emit(1, scancode as u64);
}

#[cfg(test)]
mod tests {
    use super::{
        NVME_MSI_VECTOR_BASE, NVME_MSI_VECTOR_COUNT, PANIC_STOP_VECTOR, RESCHEDULE_VECTOR,
        SHUTDOWN_STOP_VECTOR, TLB_SHOOTDOWN_VECTOR,
    };

    #[test]
    fn reschedule_ipi_has_dedicated_non_timer_vector() {
        assert_ne!(RESCHEDULE_VECTOR, 0x20);
        assert_ne!(RESCHEDULE_VECTOR, PANIC_STOP_VECTOR);
        assert_ne!(RESCHEDULE_VECTOR, SHUTDOWN_STOP_VECTOR);
        assert_ne!(RESCHEDULE_VECTOR, TLB_SHOOTDOWN_VECTOR);
        assert_eq!(RESCHEDULE_VECTOR, 0xF0);
    }

    #[test]
    fn nvme_msi_vectors_do_not_overlap_ipis() {
        let end = NVME_MSI_VECTOR_BASE + NVME_MSI_VECTOR_COUNT - 1;
        assert!(end < RESCHEDULE_VECTOR);
        assert!(NVME_MSI_VECTOR_BASE >= 0xD0);
    }
}
