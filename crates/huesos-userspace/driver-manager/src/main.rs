//! Userspace DriverManager skeleton.
//!
//! The DriverManager owns userspace driver lifecycle and service discovery.
//! It is intentionally minimal for this commit: init can spawn it as a real
//! child process and receive a readiness message over the bootstrap channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::println;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-manager] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-manager:ready");

    loop {
        libcanvas::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-manager] PANIC\n");
    libcanvas::process::exit(-1);
}
