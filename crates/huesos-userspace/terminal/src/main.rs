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
use libcanvas::{println, Channel, ErrorCode, HandleValue};
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

    let (registry, frame_draw) = wait_for_bootstrap(&bootstrap);
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
    let mut shell = Shell::new(keyboard, filesystem, bootstrap, frame_draw);
    shell.run();
}

/// Maximum number of bootstrap polls after the registry arrives before we
/// give up waiting for the `framedraw` capability. The registry and the
/// FrameDraw duplicate are written back-to-back by init, so a healthy boot
/// delivers both before the first poll returns. The bound only guards
/// against init failing the transfer: a missing capability degrades the
/// terminal to a serial-only shell instead of wedging the whole boot, which
/// would be a strictly worse failure mode than a blank screen.
const FRAME_DRAW_MAX_POLLS: u32 = 100;

/// Wait for the DriverManager registry channel *and* the `FrameDraw`
/// capability duplicate on the bootstrap channel.
///
/// Returns the registry channel plus the raw `FrameDraw` handle when it
/// arrived. The terminal's `Screen` needs that capability to blit; without
/// it every `Canvas::present` would bounce `AccessDenied` and the screen
/// would freeze on init's last frame, so a missing capability is reported
/// rather than silently drawn around.
fn wait_for_bootstrap(bootstrap: &Channel) -> (Channel, Option<HandleValue>) {
    let mut buf = [0u8; 64];
    let mut registry: Option<Channel> = None;
    let mut frame_draw: Option<HandleValue> = None;
    let mut polls = 0u32;

    loop {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if &buf[..n] == b"driver-manager-registry" => {
                registry = Some(Channel::from_handle(handle));
            }
            Ok((n, Some(handle))) if &buf[..n] == b"framedraw" => {
                frame_draw = Some(handle.raw());
                println!("[terminal] FrameDraw capability received");
            }
            Ok((n, Some(_handle))) => {
                println!(
                    "[terminal] ignored unknown bootstrap handle message: {}",
                    core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>")
                );
            }
            Ok((n, None)) => {
                println!(
                    "[terminal] ignored bootstrap control message: {}",
                    core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>")
                );
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => println!("[terminal] bootstrap wait failed: {}", e.as_str()),
        }

        if registry.is_some() {
            if let Some(frame_draw) = frame_draw {
                if let Some(registry) = registry.take() {
                    return (registry, Some(frame_draw));
                }
                continue;
            }
            polls = polls.saturating_add(1);
            if polls >= FRAME_DRAW_MAX_POLLS {
                println!("[terminal] FrameDraw not received; continuing without a framebuffer");
                if let Some(registry) = registry.take() {
                    return (registry, None);
                }
                continue;
            }
        }
    }
}

/// Maximum number of registry polls before \`open_service\` gives up and
/// returns an error. The bound prevents the terminal from yield-spinning
/// forever when the requested service is unavailable (e.g. hxfs-service
/// exited during a failed mount) and spamming the serial log with
/// repeated \`ignored unknown registry handle message\` markers. At 100
/// polls with a single yield each this is well below the timeout window
/// DriverManager itself uses for service bring-up.
const OPEN_SERVICE_MAX_POLLS: u32 = 100;

fn open_service(registry: &Channel, request: &[u8], response: &[u8]) -> libcanvas::Result<Channel> {
    let mut buf = [0u8; 64];
    registry.write(request)?;
    let mut polls: u32 = 0;
    loop {
        match registry.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == response => return Ok(channel),
            Ok((_n, _channel)) => {
                polls = polls.saturating_add(1);
                if polls >= OPEN_SERVICE_MAX_POLLS {
                    println!(
                        "[terminal] open_service: giving up after {} polls (peer keeps sending unknown handles)",
                        polls
                    );
                    return Err(ErrorCode::TimedOut);
                }
                libcanvas::process::yield_now();
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) | Err(ErrorCode::TimedOut) => {
                polls = polls.saturating_add(1);
                if polls >= OPEN_SERVICE_MAX_POLLS {
                    println!(
                        "[terminal] open_service: giving up after {} polls (registry did not answer)",
                        polls
                    );
                    return Err(ErrorCode::TimedOut);
                }
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
