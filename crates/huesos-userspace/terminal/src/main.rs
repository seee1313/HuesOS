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
mod snake;

use core::panic::PanicInfo;
use libcanvas::{println, Channel, ErrorCode};
use shell::Shell;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    // Announce readiness immediately so init does not time out if we are
    // scheduled late — registry/keyboard setup happens after this.
    let _ = bootstrap.write(b"terminal:ready");
    // Yield once so init can drain the ready message before we block on
    // registry setup (helps under QEMU TCG scheduling).
    libcanvas::process::yield_now();

    let registry = wait_for_registry(&bootstrap);
    let keyboard = match open_service(&registry, b"open:keyboard", b"service:keyboard:channel") {
        Ok(channel) => channel,
        Err(e) => {
            println!("[terminal] failed to open keyboard service: {}", e.as_str());
            // Stay alive so init can still see us; shell needs keyboard.
            loop {
                libcanvas::process::yield_now();
            }
        }
    };
    let filesystem =
        open_service(&registry, b"open:filesystem", b"service:filesystem:channel").ok();

    println!("[terminal] keyboard service online, starting shell");
    let mut shell = Shell::new(keyboard, filesystem);
    shell.run();
}

fn wait_for_registry(bootstrap: &Channel) -> Channel {
    let mut buf = [0u8; 64];
    loop {
        match bootstrap.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == b"driver-manager-registry" => return channel,
            Ok((_n, _channel)) => println!("[terminal] ignored unknown bootstrap handle message"),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
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
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[terminal] PANIC\n");
    libcanvas::process::exit(-1);
}
