//! # HuesOS userspace init
//!
//! The first userspace process, launched by the kernel after boot. This is
//! a real ring3 program: no_std, talks to the kernel *exclusively* through
//! `libcanvas` (HuesOS's safe syscall library) — there is no
//! `asm!("syscall")` anywhere in this file, on purpose. See
//! `docs/USERSPACE.md` for the guide this program is meant to demonstrate.
//!
//! It proves out the full pipeline (ELF load -> ring3 entry -> real
//! syscall -> IPC -> framebuffer) by:
//!
//!   1. Printing a banner via `libcanvas::println!` (proves syscalls work
//!      from ring3, through the library, not raw asm).
//!   2. Creating a VMO, writing to it, reading it back, and verifying the
//!      round trip (proves VMOs + memory syscalls work).
//!   3. Creating a channel pair and sending itself a message (proves IPC
//!      syscalls work).
//!   4. If a framebuffer is available, drawing a test pattern + text onto
//!      the real screen via `libcanvas::framebuffer::Canvas` (proves the
//!      framebuffer driver and blit syscall work end to end).
//!   5. Exiting cleanly via `libcanvas::process::exit`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::{println, Vmo};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[init] hello from ring3 userspace, via libcanvas!");

    run_vmo_check();
    run_channel_check();
    run_framebuffer_check();

    println!("[init] all checks complete, exiting cleanly");
    libcanvas::process::exit(0);
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

fn run_framebuffer_check() {
    match Canvas::new_fullscreen() {
        Ok(canvas) => {
            let w = canvas.width();
            let h = canvas.height();

            // Background.
            let _ = canvas.fill_rect(0, 0, w, h, 18, 18, 32);

            // A simple color-bar test pattern across the top third of the
            // screen, so a screenshot makes it obvious the real
            // framebuffer driver + blit syscall are both actually working
            // (not just "didn't crash").
            let bar_h = h / 3;
            let bands: [(u8, u8, u8); 6] = [
                (255, 0, 0),
                (255, 165, 0),
                (255, 255, 0),
                (0, 200, 0),
                (0, 120, 255),
                (160, 0, 220),
            ];
            let band_w = w / bands.len() as u32;
            for (i, (r, g, b)) in bands.iter().enumerate() {
                let _ = canvas.fill_rect(i as u32 * band_w, 0, band_w, bar_h, *r, *g, *b);
            }

            let _ = canvas.draw_text(16, bar_h + 24, "HuesOS", 255, 255, 255);
            let _ = canvas.draw_text(16, bar_h + 40, "libcanvas framebuffer test", 200, 200, 200);
            let _ = canvas.draw_text(
                16,
                bar_h + 56,
                "Drawn entirely from ring3 via Canvas + FramebufferBlit",
                150, 220, 150,
            );

            match canvas.present() {
                Ok(()) => println!("[init] framebuffer test pattern presented OK"),
                Err(e) => println!("[init] framebuffer present FAILED ({})", e.as_str()),
            }
        }
        Err(e) => {
            println!("[init] no framebuffer available ({}), skipping graphics test", e.as_str());
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[init] PANIC in userspace init\n");
    libcanvas::process::exit(-1);
}
