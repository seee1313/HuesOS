//! The HuesOS user-space standard library.
//!
//! `huesos-std` is the layer between a `/bin` program and the capability
//! syscalls in [`libcanvas`]: `io` gives `Read`/`Write` over stdio plus the
//! `print!` family, `fs` gives files, directories and whole-file helpers over
//! the `Hxfs` service, `path` gives pure lexical path handling, `env` exposes
//! `argv` and the capability mask, and `process` exits and yields.
//!
//! # Why not `std`
//! HuesOS user space is `no_std` with a hand-built dynamic loader, a single
//! `ScudoHeap` allocator per process, and no ambient authority: a program that
//! was not handed a channel simply cannot reach the service. Everything here
//! therefore takes capabilities as data, never discovers them by name, and
//! never unwinds — a failure is a [`Result`], and the entry point turns a
//! non-zero return into a process exit code.
//!
//! # Example
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! use huesos_std::{fs, prelude::*};
//!
//! huesos_std::entry!(run);
//!
//! fn run() -> i32 {
//!     let report = format!("volume {} bytes", fs::volume_bytes().unwrap_or(0));
//!     println!("{report}");
//!     if let Err(error) = fs::write("/tmp/out.txt", report.as_bytes()) {
//!         eprintln!("write failed: {error}");
//!         return 1;
//!     }
//!     0
//! }
//! ```
//!
//! Unit tests would have to run on the host, which cannot link a `/bin`
//! binary; the executable gate is `/bin/std-smoke.elf`, which exercises every
//! module inside the OS and prints `[std] ... OK` markers that
//! `scripts/ci-qemu-smoke.sh` requires.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod audio;
pub mod bootfs;
pub mod buffered;
pub mod collections;
pub mod env;
pub mod error;
pub mod fs;
pub mod io;
pub mod net;
pub mod os;
pub mod path;
pub mod prelude;
pub mod process;
pub mod sync;
pub mod sys;
pub mod thread;
pub mod time;
pub mod tui;
pub mod usb_fat;
pub mod vfs_synth;

pub use error::{Error, ErrorKind, Result};
pub use libcanvas::heap::ScudoHeap;

/// Define the process entry point, the allocator and the panic handler.
///
/// A HuesOS binary starts at `_start` with an unaligned stack (the loader
/// jumps to it), so the stack pointer is aligned before the call into Rust.
/// The allocator must be the per-process `ScudoHeap`: the kernel hands out
/// frames, but user space owns the heap.
#[macro_export]
macro_rules! entry {
    ($main_fn:path) => {
        #[global_allocator]
        static ALLOCATOR: $crate::ScudoHeap = $crate::ScudoHeap;

        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "and rsp, -16",
                "call {entry}",
                "ud2",
                entry = sym _huesos_std_entry_trampoline,
            )
        }

        extern "C" fn _huesos_std_entry_trampoline() -> ! {
            let code = $main_fn();
            $crate::process::exit(code)
        }

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
            $crate::eprintln!("panic: program aborted");
            $crate::process::exit(101)
        }
    };
}
