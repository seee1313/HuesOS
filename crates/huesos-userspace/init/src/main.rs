//! # HuesOS userspace init
//!
//! The first userspace process, launched by the kernel after boot. Init now
//! acts as a tiny userspace service launcher: it validates the syscall/IPC
//! basics, then starts DriverManager and the framebuffer terminal as real
//! child processes through the Zircon-like `ProcessCreate` -> `VmarMap` ->
//! `ThreadCreate` -> `ThreadStart` path.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::{println, Channel, ErrorCode, Process, Vmo};

static DRIVER_MANAGER_ELF: &[u8] = include_bytes!(env!("HUESOS_DRIVER_MANAGER_PATH"));
static TERMINAL_ELF: &[u8] = include_bytes!(env!("HUESOS_TERMINAL_PATH"));

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[init] hello from ring3 userspace, via libcanvas");

    run_vmo_check();
    run_channel_check();

    let driver_manager = launch_service("driver-manager", DRIVER_MANAGER_ELF);
    let terminal = launch_service("terminal", TERMINAL_ELF);

    if let Some((_, channel)) = &driver_manager {
        read_ready_message("driver-manager", channel);
    }
    if let Some((_, channel)) = &terminal {
        read_ready_message("terminal", channel);
    }

    println!("[init] service launch complete; parking as init supervisor");
    loop {
        let _keep_services_alive = (&driver_manager, &terminal);
        libcanvas::process::yield_now();
    }
}

fn launch_service(name: &str, elf: &[u8]) -> Option<(Process, Channel)> {
    match libcanvas::process::spawn_elf(name, elf) {
        Ok((process, bootstrap)) => {
            println!("[init] launched {}", name);
            Some((process, bootstrap))
        }
        Err(e) => {
            println!("[init] failed to launch {}: {}", name, e.as_str());
            None
        }
    }
}

fn read_ready_message(name: &str, channel: &Channel) {
    let mut buf = [0u8; 64];
    for _ in 0..2000 {
        match channel.read_into(&mut buf) {
            Ok(n) => {
                let msg = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                println!("[init] {} says {}", name, msg);
                return;
            }
            Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
            Err(e) => {
                println!("[init] {} bootstrap read failed: {}", name, e.as_str());
                return;
            }
        }
    }
    println!("[init] {} did not send ready message yet", name);
}

fn run_vmo_check() {
    let payload = b"HuesOS VMO round-trip OK\n";
    let ok = (|| -> libcanvas::Result<bool> {
        let vmo = Vmo::create(4096)?;
        vmo.write(0, payload)?;
        let mut readback = [0u8; 32];
        let n = vmo.read(0, &mut readback)?;
        Ok(n >= payload.len() && &readback[..payload.len()] == payload)
    })();

    match ok {
        Ok(true) => println!("[init] VMO read/write round-trip OK"),
        Ok(false) => println!("[init] VMO read/write round-trip FAILED (data mismatch)"),
        Err(e) => println!("[init] VMO read/write round-trip FAILED ({})", e.as_str()),
    }
}

fn run_channel_check() {
    let msg = b"ping over huesos channel\n";
    let ok = (|| -> libcanvas::Result<bool> {
        let (tx, rx) = libcanvas::Channel::pair()?;
        tx.write(msg)?;
        let (buf, n) = rx.read()?;
        Ok(n == msg.len() && &buf[..n] == msg)
    })();

    match ok {
        Ok(true) => println!("[init] channel IPC round-trip OK"),
        Ok(false) => println!("[init] channel IPC round-trip FAILED (data mismatch)"),
        Err(e) => println!("[init] channel IPC round-trip FAILED ({})", e.as_str()),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[init] PANIC in userspace init\n");
    libcanvas::process::exit(-1);
}
