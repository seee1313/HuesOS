//! HuesOS framebuffer terminal + built-in mini shell.
//!
//! The terminal obtains keyboard input as a service from DriverManager. It no
//! longer binds keyboard IRQs directly; DriverManager opens a keyboard service
//! channel backed by the input DriverHost.

#![no_std]
#![no_main]

mod ast;
mod commands;
mod lexer;
mod parser;
mod screen;
mod shell;

use core::panic::PanicInfo;
use libcanvas::{println, Channel, ErrorCode};
use shell::Shell;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"terminal:ready");

    let keyboard = match wait_for_keyboard_service(&bootstrap) {
        Ok(channel) => channel,
        Err(e) => {
            println!("[terminal] failed to open keyboard service: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    };

    let mut shell = Shell::new(keyboard);
    shell.run();
}

fn wait_for_keyboard_service(bootstrap: &Channel) -> libcanvas::Result<Channel> {
    let mut buf = [0u8; 64];
    let registry = loop {
        match bootstrap.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == b"driver-manager-registry" => break channel,
            Ok((_n, _channel)) => println!("[terminal] ignored unknown bootstrap handle message"),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) => libcanvas::process::yield_now(),
            Err(e) => return Err(e),
        }
    };

    registry.write(b"open:keyboard")?;
    loop {
        match registry.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == b"service:keyboard:channel" => return Ok(channel),
            Ok((_n, _channel)) => println!("[terminal] ignored unknown registry handle message"),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) => libcanvas::process::yield_now(),
            Err(e) => return Err(e),
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[terminal] PANIC\n");
    libcanvas::process::exit(-1);
}
