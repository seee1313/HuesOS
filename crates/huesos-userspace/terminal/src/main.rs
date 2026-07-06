//! HuesOS framebuffer terminal + built-in mini shell.
//!
//! This terminal is intentionally self-contained for the current migration
//! stage: it consumes keyboard IRQ packets through the userspace
//! Interrupt+Port bridge and runs a small internal command shell. External
//! program execution is deliberately not supported yet.

#![no_std]
#![no_main]

mod ast;
mod commands;
mod keyboard;
mod lexer;
mod parser;
mod screen;
mod shell;

use core::panic::PanicInfo;
use libcanvas::println;
use shell::Shell;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"terminal:ready");

    match Shell::new() {
        Ok(mut shell) => shell.run(),
        Err(e) => {
            println!("[terminal] failed to initialize shell: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[terminal] PANIC\n");
    libcanvas::process::exit(-1);
}
