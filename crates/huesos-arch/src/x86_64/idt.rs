//! Interrupt Descriptor Table and privilege-aware exception dispatch.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Lazy;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::fault::{FaultInfo, FaultKind};

/// IPI vector used to freeze non-owner CPUs during a kernel panic.
pub const PANIC_STOP_VECTOR: u8 = 0xF1;
/// IPI vector used for an orderly system-wide software halt.
pub const SHUTDOWN_STOP_VECTOR: u8 = 0xF2;
/// IPI vector used for cross-CPU TLB invalidation.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xF3;
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
    idt[PANIC_STOP_VECTOR].set_handler_fn(panic_stop_handler);
    idt[SHUTDOWN_STOP_VECTOR].set_handler_fn(shutdown_stop_handler);
    idt[TLB_SHOOTDOWN_VECTOR].set_handler_fn(tlb_shootdown_handler);
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
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    super::cpu::clear_user_access();
    if frame.code_segment.0 & 3 == 0 {
        if let Some(fixup) = super::fault::recover_kernel_fault(
            frame.instruction_pointer.as_u64(),
        ) {
            // SAFETY: the exception frame is the CPU-owned return frame for
            // this handler; the fixup is emitted by the validated extable and
            // points at the same copy function's recovery return.
            unsafe {
                frame.as_mut().instruction_pointer = x86_64::VirtAddr::new(fixup);
            }
            return;
        }
    }
    let address = Cr2::read().map(|a| a.as_u64()).unwrap_or(0);
    dispatch(fault_info(
        FaultKind::PageFault,
        &frame,
        error_code.bits(),
        address,
    ));
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

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    super::cpu::clear_user_access();
    super::lapic::eoi();
    unsafe {
        super::interrupts::PICS.lock().notify_end_of_interrupt(32);
    }
    crate::x86_64::timer_callback::tick();
}

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    keyboard_irq_ack(true);
}

extern "x86-interrupt" fn ioapic_keyboard_handler(_stack_frame: InterruptStackFrame) {
    keyboard_irq_ack(false);
}

fn keyboard_irq_ack(pic: bool) {
    super::cpu::clear_user_access();
    use x86_64::instructions::port::Port;
    let mut port: Port<u8> = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    crate::x86_64::keyboard::on_scancode(scancode);
    if pic {
        unsafe {
            super::interrupts::PICS.lock().notify_end_of_interrupt(33);
        }
    } else {
        super::lapic::eoi();
    }
    crate::x86_64::irq_callback::emit(1, scancode as u64);
}
