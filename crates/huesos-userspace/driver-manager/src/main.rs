//! Userspace DriverManager skeleton.
//!
//! The DriverManager owns userspace driver lifecycle and service discovery.
//! In this stage it also proves the first kernel IRQ bridge: it creates a
//! Port, creates a keyboard Interrupt object, binds the interrupt to that
//! Port, and logs raw IRQ packets from userspace.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::{println, ErrorCode, Interrupt, Port, PORT_PACKET_INTERRUPT};

const KEY_KEYBOARD: u64 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-manager] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-manager:ready");

    match setup_keyboard_irq_bridge() {
        Ok(port) => run_driver_loop(port),
        Err(e) => {
            println!("[driver-manager] keyboard IRQ bridge unavailable: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    }
}

fn setup_keyboard_irq_bridge() -> libcanvas::Result<Port> {
    let port = Port::create()?;
    let keyboard = Interrupt::keyboard()?;
    keyboard.bind_port(&port, KEY_KEYBOARD)?;
    // Keep the Interrupt handle alive for the lifetime of DriverManager by
    // intentionally forgetting this MVP-owned object. A later DriverManager
    // service table will store owned driver objects explicitly.
    core::mem::forget(keyboard);
    println!("[driver-manager] keyboard IRQ bound to userspace Port");
    Ok(port)
}

fn run_driver_loop(port: Port) -> ! {
    loop {
        match port.read() {
            Ok(packet) if packet.packet_type == PORT_PACKET_INTERRUPT && packet.key == KEY_KEYBOARD => {
                let irq = packet.data[0];
                let scancode = packet.data[1];
                let count = packet.data[2];
                println!(
                    "[driver-manager] irq={} scancode={:#x} count={}",
                    irq, scancode, count
                );
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
            Err(e) => {
                println!("[driver-manager] port read failed: {}", e.as_str());
                libcanvas::process::yield_now();
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-manager] PANIC\n");
    libcanvas::process::exit(-1);
}
