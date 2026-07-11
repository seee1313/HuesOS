//! Debug/console output — an MVP substitute for a real stdout, backed by
//! the kernel's serial console.

use crate::raw;
use core::fmt;
use huesos_abi::Syscall;

/// Write raw bytes to the kernel debug log. Truncated (not chunked) if
/// longer than the kernel's per-call limit (4096 bytes) — use multiple
/// calls for longer output.
pub fn write_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let chunk = &bytes[..bytes.len().min(4096)];
    let _ = raw::syscall2(
        Syscall::DebugWrite,
        chunk.as_ptr() as u64,
        chunk.len() as u64,
    );
}

/// Write a `&str` to the kernel debug log.
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

/// A [`core::fmt::Write`] adapter so [`crate::print!`]/[`crate::println!`]
/// can use ordinary `write!`/`writeln!` formatting machinery.
pub struct DebugWriter;

impl fmt::Write for DebugWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// `print!`-alike that writes to the kernel debug console via
/// [`Syscall::DebugWrite`] — the only "stdout" HuesOS has right now.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::debug::DebugWriter, $($arg)*);
    }};
}

/// `println!`-alike; see [`print!`].
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::debug::DebugWriter, $($arg)*);
    }};
}
