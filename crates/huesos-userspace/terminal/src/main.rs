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

    let registry = wait_for_registry(&bootstrap);
    let keyboard = match open_service(&registry, b"open:keyboard", b"service:keyboard:channel") {
        Ok(channel) => channel,
        Err(e) => {
            println!("[terminal] failed to open keyboard service: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    };
    let filesystem = open_service(&registry, b"open:filesystem", b"service:filesystem:channel").ok();

    let mut shell = Shell::new(keyboard, filesystem);
    shell.run();
}

fn wait_for_registry(bootstrap: &Channel) -> Channel {
    let mut buf = [0u8; 64];
    loop {
        match bootstrap.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == b"driver-manager-registry" => return channel,
            Ok((_n, _channel)) => println!("[terminal] ignored unknown bootstrap handle message"),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) => libcanvas::process::yield_now(),
            Err(e) => println!("[terminal] registry wait failed: {}", e.as_str()),
        }
    }
}

fn open_service(registry: &Channel, request: &[u8], response: &[u8]) -> libcanvas::Result<Channel> {
    let mut buf = [0u8; 64];
    registry.write(request)?;
    loop {
        match registry.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == response => return Ok(channel),
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
