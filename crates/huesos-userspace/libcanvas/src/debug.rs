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

/// Largest chunk one `DebugWrite` carries. The kernel truncates longer calls,
/// so the line buffer flushes before reaching it.
const LINE_CAP: usize = 512;

/// Formats into a local buffer and issues one `DebugWrite` per newline (or
/// per `LINE_CAP` bytes). A single syscall is serialized against other
/// `DebugWrite`s by the kernel, so a whole line is never split by another
/// process's output. Formatting pieces as separate syscalls was the cause of
/// interleaved boot-log lines.
struct LineBuffer {
    buf: [u8; LINE_CAP],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; LINE_CAP],
            len: 0,
        }
    }

    fn flush(&mut self) {
        if self.len > 0 {
            write_bytes(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl fmt::Write for LineBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            if self.len == LINE_CAP {
                self.flush();
            }
            self.buf[self.len] = byte;
            self.len += 1;
            if byte == b'\n' {
                self.flush();
            }
        }
        Ok(())
    }
}

/// Backend of [`print!`] and [`println!`]. Public only for macro expansion.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut line = LineBuffer::new();
    let _ = fmt::write(&mut line, args);
    line.flush();
}

/// A [`core::fmt::Write`] adapter kept for existing `writeln!(DebugWriter, ..)`
/// call sites. Each call is line-buffered the same way as [`print!`].
pub struct DebugWriter;

impl fmt::Write for DebugWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut line = LineBuffer::new();
        let result = line.write_str(s);
        line.flush();
        result
    }

    /// `writeln!(DebugWriter, ..)` lands here, so the whole formatted line is
    /// one buffered unit rather than one syscall per fragment.
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        _print(args);
        Ok(())
    }
}

/// `print!`-alike that writes to the kernel debug console via
/// [`Syscall::DebugWrite`] — the only "stdout" HuesOS has right now.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::debug::_print(format_args!($($arg)*));
    }};
}

/// `println!`-alike; see [`print!`].
#[macro_export]
macro_rules! println {
    () => { $crate::debug::_print(format_args!("\n")) };
    ($($arg:tt)*) => {{
        $crate::debug::_print(format_args!("{}\n", format_args!($($arg)*)));
    }};
}
