//! Userspace DriverManager.
//!
//! DriverManager owns the driver manifest table, launches DriverHost
//! processes, registers services, and monitors DriverHost heartbeat/status
//! messages. This is the first step toward the chosen architecture where
//! drivers live in DriverHost processes and clients discover services through
//! DriverManager.

#![no_std]
#![no_main]

mod bootfs;
mod fs_service;
mod manifest;
mod protocol;
mod registry;
mod supervisor;

use core::panic::PanicInfo;
use libcanvas::println;
use supervisor::DriverManager;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-manager] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();

    let mut manager = DriverManager::new();
    manager.start_driver_hosts();

    if manager.keyboard_ready() {
        let _ = bootstrap.write(b"driver-manager:ready");
    } else {
        let _ = bootstrap.write(b"driver-manager:degraded");
    }

    manager.run(bootstrap);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-manager] PANIC\n");
    libcanvas::process::exit(-1);
}
