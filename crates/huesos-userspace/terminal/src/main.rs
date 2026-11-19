//! HuesOS production framebuffer terminal (`hsh`).
//!
//! Receives `driver-manager-registry`, `bootfs-ro`, and `framedraw` from `init`,
//! opens the keyboard service + HxFS/registry query paths, runs Cycle 3 startup
//! smokes (`hsh`, `/bin/fdisk.elf`, `@caps(...)`), and launches the Fish-UX REPL.

#![no_std]
#![no_main]

extern crate alloc;

mod host;
mod screen;
mod shell;
mod snake;

use core::panic::PanicInfo;
use libcanvas::heap::ScudoHeap;
use libcanvas::{println, Channel, ErrorCode, Handle, Vmo};
use shell::Shell;

#[global_allocator]
static ALLOCATOR: ScudoHeap = ScudoHeap;

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym terminal_main,
    );
}

extern "C" fn terminal_main() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"terminal:ready");
    libcanvas::process::yield_now();

    let (registry, bootfs, frame_draw) = wait_for_bootstrap(&bootstrap);
    let keyboard = match open_service(&registry, b"open:keyboard", b"service:keyboard:channel") {
        Ok(channel) => channel,
        Err(e) => {
            println!("[terminal] failed to open keyboard service: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    };
    let filesystem =
        open_service(&registry, b"open:filesystem", b"service:filesystem:channel").ok();

    let mut shell = Shell::new(
        keyboard, filesystem, registry, bootfs, bootstrap, frame_draw,
    );
    shell.run_startup_smokes();
    println!("[terminal] keyboard service online, starting shell");
    shell.run();
}

const FRAME_DRAW_MAX_POLLS: u32 = 100;

fn wait_for_bootstrap(bootstrap: &Channel) -> (Channel, Option<Vmo>, Option<Handle>) {
    let mut buf = [0u8; 64];
    let mut registry: Option<Channel> = None;
    let mut bootfs: Option<Vmo> = None;
    let mut frame_draw: Option<Handle> = None;
    let mut polls = 0u32;

    loop {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if &buf[..n] == b"driver-manager-registry" => {
                registry = Some(Channel::from_handle(handle));
            }
            Ok((n, Some(handle))) if &buf[..n] == b"bootfs-ro" => {
                bootfs = Some(Vmo::from_handle(handle));
            }
            Ok((n, Some(handle))) if &buf[..n] == b"framedraw" => {
                frame_draw = Some(handle);
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
            if let Some(frame_draw) = frame_draw.take() {
                if let Some(registry) = registry.take() {
                    return (registry, bootfs, Some(frame_draw));
                }
                continue;
            }
            polls = polls.saturating_add(1);
            if polls >= FRAME_DRAW_MAX_POLLS {
                println!("[terminal] FrameDraw not received; continuing without a framebuffer");
                if let Some(registry) = registry.take() {
                    return (registry, bootfs, None);
                }
                continue;
            }
        }
    }
}

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
                    return Err(ErrorCode::TimedOut);
                }
                libcanvas::process::yield_now();
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                polls = polls.saturating_add(1);
                if polls >= OPEN_SERVICE_MAX_POLLS {
                    return Err(ErrorCode::TimedOut);
                }
                libcanvas::process::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    println!("[terminal] PANIC");
    libcanvas::process::exit(1);
}
