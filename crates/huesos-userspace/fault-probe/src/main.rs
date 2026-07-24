//! Deliberately faulting child used to verify process isolation in QEMU.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let bootstrap = libcanvas::channel::bootstrap();
    let mut command = [0u8; 16];
    let Ok(length) = bootstrap.read_into_blocking(&mut command) else {
        libcanvas::process::exit(98)
    };
    let command = &command[..length];
    libcanvas::println!("[fault-probe] triggering {}", as_text(command));

    match command {
        b"page" => trigger_page_fault(),
        b"opcode" => trigger_invalid_opcode(),
        b"gpf" => trigger_general_protection(),
        b"divide" => trigger_divide_error(),
        b"wait" => {
            // Give init a chance to park in ProcessWait. This is deliberately
            // cooperative: the probe exercises the wake path without relying
            // on wall-clock timing or a busy loop.
            for _ in 0..32 {
                libcanvas::process::yield_now();
            }
            libcanvas::process::exit(0)
        }
        b"shutdown" => match libcanvas::system::shutdown() {
            Err(libcanvas::ErrorCode::AccessDenied) => libcanvas::process::exit(0),
            _ => libcanvas::process::exit(95),
        },
        _ => libcanvas::process::exit(97),
    }
}

fn as_text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("unknown fault")
}

fn trigger_page_fault() -> ! {
    let address = huesos_abi::USER_ASPACE_BASE as *const u8;
    // SAFETY: this diagnostic intentionally reads an unmapped ring-3 address.
    let _ = unsafe { core::ptr::read_volatile(address) };
    libcanvas::process::exit(96)
}

fn trigger_invalid_opcode() -> ! {
    // SAFETY: UD2 is architecturally guaranteed to raise #UD.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn trigger_general_protection() -> ! {
    // SAFETY: CLI is privileged and therefore raises #GP when executed at CPL3.
    unsafe { core::arch::asm!("cli", options(noreturn)) }
}

fn trigger_divide_error() -> ! {
    // SAFETY: unsigned division by a zero RCX is guaranteed to raise #DE.
    unsafe {
        core::arch::asm!(
            "xor rdx, rdx",
            "mov rax, 1",
            "xor rcx, rcx",
            "div rcx",
            options(noreturn)
        )
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::process::exit(-1)
}
