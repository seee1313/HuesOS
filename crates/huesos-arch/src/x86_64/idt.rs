//! Interrupt Descriptor Table.

use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use spin::Lazy;

fn dprint(msg: &str) {
    use core::fmt::Write;
    let mut w = crate::serial::SerialWriter;
    let _ = w.write_str(msg);
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(super::gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt[32].set_handler_fn(timer_handler);
    idt[33].set_handler_fn(keyboard_handler);
    idt
});

/// Load IDT.
pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    dprint("[idt] BREAKPOINT\n");
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    dprint("[idt] INVALID OPCODE at ");
    print_hex(stack_frame.instruction_pointer.as_u64());
    dprint("\n");
    loop {
        crate::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    dprint("[idt] GENERAL PROTECTION FAULT code=");
    print_hex(error_code);
    dprint(" rip=");
    print_hex(stack_frame.instruction_pointer.as_u64());
    dprint(" cs=");
    print_hex(stack_frame.code_segment.0 as u64);
    dprint("\n");
    loop {
        crate::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let addr = Cr2::read();
    dprint("[idt] PAGE FAULT addr=");
    print_hex(addr.map(|a| a.as_u64()).unwrap_or(0xdead_dead));
    dprint(" code=");
    print_hex(error_code.bits());
    dprint(" rip=");
    print_hex(stack_frame.instruction_pointer.as_u64());
    dprint("\n");
    loop {
        crate::hlt();
    }
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    dprint("[idt] DOUBLE FAULT rip=");
    print_hex(stack_frame.instruction_pointer.as_u64());
    dprint("\n");
    loop {}
}

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    unsafe {
        super::interrupts::PICS.lock().notify_end_of_interrupt(32);
    }
    crate::x86_64::timer_callback::tick();
}

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    let mut port: Port<u8> = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    crate::x86_64::keyboard::on_scancode(scancode);
    unsafe {
        super::interrupts::PICS.lock().notify_end_of_interrupt(33);
    }
    crate::x86_64::irq_callback::emit(1, scancode as u64);
}

fn print_hex(v: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nibble = (v >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = match nibble {
            0..=9 => b'0' + nibble as u8,
            _ => b'a' + (nibble as u8 - 10),
        };
    }
    if let Ok(s) = core::str::from_utf8(&buf) {
        dprint(s);
    }
}
