//! HuesOS framebuffer terminal skeleton.
//!
//! This is the first userspace terminal process. For now it paints a simple
//! text UI and stays alive; keyboard/DriverManager service wiring lands in
//! the next driver IPC commits.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::println;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"terminal:ready");

    draw_terminal_banner();

    loop {
        libcanvas::process::yield_now();
    }
}

fn draw_terminal_banner() {
    match Canvas::new_fullscreen() {
        Ok(canvas) => {
            let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 5, 8, 16);
            let _ = canvas.draw_text(16, 16, "HuesOS Terminal", 180, 220, 255);
            let _ = canvas.draw_text(16, 40, "userspace process launched by init", 180, 180, 180);
            let _ = canvas.draw_text(16, 64, "> waiting for DriverManager keyboard service", 120, 255, 160);
            let _ = canvas.present();
        }
        Err(e) => println!("[terminal] framebuffer unavailable: {}", e.as_str()),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[terminal] PANIC\n");
    libcanvas::process::exit(-1);
}
