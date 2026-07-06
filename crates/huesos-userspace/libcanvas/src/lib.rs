//! # libcanvas — HuesOS's safe userspace system-call library
//!
//! This is HuesOS's equivalent of `ntdll.dll`/`libc`'s syscall layer: the
//! **only** sanctioned way for userspace code to talk to the kernel.
//! Application code should never write `asm!("syscall", ...)` itself —
//! every syscall the kernel exposes has (or should have — see the
//! `TODO`-free but still-growing coverage below) a safe, typed wrapper
//! here that validates arguments, decodes error codes into a real `Result`,
//! and manages resource lifetimes (handles close themselves via `Drop`).
//!
//! ## Why a strict layer, not just "a helper crate"
//!
//! 1. **One place to get the calling convention right.** The `syscall`
//!    instruction's register assignment, its clobbering of `rcx`/`r11`,
//!    and the exact argument-register order are easy to get subtly wrong
//!    (and silently corrupt state instead of crash) if every program
//!    hand-rolls it. `libcanvas::raw` is the one audited implementation.
//! 2. **One place to keep the ABI in sync.** Syscall numbers and error
//!    codes live in `huesos-abi`, shared with the kernel's dispatcher —
//!    `libcanvas` translates that shared, versioned contract into ergonomic
//!    Rust, so an ABI change is a one-crate update, not a
//!    find-and-replace across every userspace program.
//! 3. **Resource safety.** [`handle::Handle`] closes itself on `Drop`.
//!    [`vmo::Vmo`] and [`channel::Channel`] build on that so a program
//!    that panics or takes an early return path can't leak kernel
//!    handles by forgetting a cleanup call.
//! 4. **A real capability boundary for things like the framebuffer.**
//!    [`framebuffer::Canvas`] never hands back a pointer to real video
//!    memory — it's backed by an ordinary VMO the calling process already
//!    owns, and [`framebuffer::Canvas::present`] is the *only* function in
//!    this entire library that can affect the screen, going through a
//!    kernel-side bounds-checked blit.
//!
//! ## Quick example
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! use libcanvas::framebuffer::Canvas;
//!
//! #[unsafe(no_mangle)]
//! pub extern "C" fn _start() -> ! {
//!     libcanvas::println!("hello from a real userspace program!");
//!
//!     if let Ok(canvas) = Canvas::new_fullscreen() {
//!         let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 20, 20, 40);
//!         let _ = canvas.draw_text(16, 16, "Hello, HuesOS!", 255, 255, 255);
//!         let _ = canvas.present();
//!     }
//!
//!     libcanvas::process::exit(0);
//! }
//! # #[panic_handler]
//! # fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
//! ```

#![no_std]
#![warn(missing_docs)]

pub mod channel;
pub mod debug;
pub mod framebuffer;
mod font8x8;
pub mod handle;
pub mod interrupt;
pub mod port;
pub mod process;
mod raw;
pub mod vmo;

pub use handle::Handle;
pub use channel::Channel;
pub use interrupt::Interrupt;
pub use port::Port;
pub use process::{Process, Thread, Vmar};
pub use vmo::Vmo;

/// Re-exported so application code can match on specific failure reasons
/// (`use libcanvas::ErrorCode;`) without depending on `huesos-abi` directly.
pub use huesos_abi::{
    vmar_flags, ErrorCode, PortPacket, BOOTSTRAP_HANDLE, PORT_PACKET_INTERRUPT, USER_STACK_SIZE,
    USER_STACK_TOP,
};

/// Result type used throughout `libcanvas`: every fallible syscall wrapper
/// returns this instead of a raw negative `i64`.
pub type Result<T> = core::result::Result<T, ErrorCode>;
