//! Standard I/O: `Read`/`Write` over the three process streams.
//!
//! The kernel does not give a process file descriptors; it gives it three
//! channels (stdin, stdout, stderr) that `libcanvas::stdio` already wraps as
//! whole-slice calls. This module adds the ergonomics a program wants: traits
//! so the same code can write to a file or a stream, and the `print!` family,
//! which formats into a small stack buffer so a `println!` costs no allocation
//! on the heap.

use alloc::vec::Vec;

use libcanvas::stdio;
use libcanvas::ErrorCode;

use crate::error::{Error, Result};

/// A source of bytes; `read` returning `Ok(0)` means end of input.
pub trait Read {
    /// Fill `buf`, returning the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A sink for bytes.
pub trait Write {
    /// Write `buf`, returning the number of bytes accepted.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Push everything buffered so far. Streams are unbuffered, so this is a
    /// no-op for them and a flush for the file writer.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The process' standard input channel.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdin;

/// The process' standard output channel.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdout;

/// The process' standard error channel.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stderr;

impl Stdin {
    /// Read from the console, waiting at most `timeout`.
    ///
    /// `Err(ErrorKind::TimedOut)` means no byte arrived; it is the normal
    /// outcome for a monitor that redraws on a timer, so callers should test
    /// [`crate::error::Error::is_retryable`] rather than treating it as a
    /// failure.
    pub fn read_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: crate::time::Duration,
    ) -> Result<usize> {
        match stdio::stdin_read_timeout(buf, timeout.as_ticks_ceil().max(1)) {
            Ok(n) => Ok(n),
            Err(ErrorCode::PeerClosed) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }
}

impl Read for Stdin {
    /// A closed peer is end of input, not an error: the shell closing the pipe
    /// must not look like a failure to the reader.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match stdio::stdin_read(buf) {
            Ok(n) => Ok(n),
            Err(ErrorCode::PeerClosed) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        stdio::stdout_write(buf).map_err(Error::from)
    }
}

impl Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        stdio::stderr_write(buf).map_err(Error::from)
    }
}

/// Where a seek starts from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    /// Absolute offset from the start of the object.
    Start(u64),
    /// Offset relative to the current position; may be negative.
    Current(i64),
    /// Offset relative to the end; may be negative.
    End(i64),
}

/// A seekable byte stream.
pub trait Seek {
    /// Move the cursor and return the new absolute position.
    fn seek(&mut self, from: SeekFrom) -> Result<u64>;
}

/// The process' stdin.
pub fn stdin() -> Stdin {
    Stdin
}

/// The process' stdout.
pub fn stdout() -> Stdout {
    Stdout
}

/// The process' stderr.
pub fn stderr() -> Stderr {
    Stderr
}

/// Write all of `buf`, looping over short writes.
pub fn write_all<W: Write + ?Sized>(sink: &mut W, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match sink.write(buf)? {
            0 => return Err(Error::new(crate::error::ErrorKind::Io)),
            n => buf = &buf[n..],
        }
    }
    Ok(())
}

/// Read until end of input, growing `out`.
pub fn read_to_end<R: Read + ?Sized>(source: &mut R, out: &mut Vec<u8>) -> Result<usize> {
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        out.extend_from_slice(&buf[..n]);
        total += n;
    }
}

const FMT_BUF: usize = 160;

/// A [`core::fmt::Write`] adapter that formats into a stack buffer and streams
/// it out, so `println!` never allocates.
pub struct Fmt<'a, W: Write + ?Sized> {
    sink: &'a mut W,
    buf: [u8; FMT_BUF],
    len: usize,
    error: Option<Error>,
}

impl<'a, W: Write + ?Sized> Fmt<'a, W> {
    /// Wrap `sink`.
    pub fn new(sink: &'a mut W) -> Self {
        Self {
            sink,
            buf: [0u8; FMT_BUF],
            len: 0,
            error: None,
        }
    }

    /// Flush the buffer, reporting the first error the sink returned.
    pub fn finish(mut self) -> Result<()> {
        self.flush_buffer()?;
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn flush_buffer(&mut self) -> Result<()> {
        let pending = self.len;
        if pending == 0 {
            return Ok(());
        }
        match write_all(&mut *self.sink, &self.buf[..pending]) {
            Ok(()) => {
                self.len = 0;
                Ok(())
            }
            Err(error) => {
                // Keep the bytes: `finish` reports the error, and a caller that
                // retries a flush must not silently lose the start of the line.
                self.error.get_or_insert(error);
                Err(error)
            }
        }
    }
}

impl<W: Write + ?Sized> core::fmt::Write for Fmt<'_, W> {
    /// Formatting failures are stored, not returned: `fmt` has no way to
    /// report them and a program should not abort mid-line because stderr was
    /// closed. [`Fmt::finish`] hands the first error back.
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.as_bytes() {
            if self.len == self.buf.len() && self.flush_buffer().is_err() {
                return Ok(());
            }
            self.buf[self.len] = *byte;
            self.len += 1;
        }
        Ok(())
    }
}

/// Format and write to stdout, without a trailing newline.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut sink = $crate::io::stdout();
        let mut fmt = $crate::io::Fmt::new(&mut sink);
        let _ = core::write!(fmt, $($arg)*);
        let _ = fmt.finish();
    }};
}

/// Format and write to stdout, with a trailing newline.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::print!("{}\n", core::format_args!($($arg)*))
    };
}

/// Format and write to stderr, without a trailing newline.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut sink = $crate::io::stderr();
        let mut fmt = $crate::io::Fmt::new(&mut sink);
        let _ = core::write!(fmt, $($arg)*);
        let _ = fmt.finish();
    }};
}

/// Format and write to stderr, with a trailing newline.
#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::eprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::eprint!("{}\n", core::format_args!($($arg)*))
    };
}

/// Buffered and in-memory I/O, re-exported so `io::BufReader` resolves the way
/// it does in `std`.
pub use crate::buffered::{
    copy, empty, read_exact, read_to_string, repeat, sink, BufRead, BufReader, BufWriter, Cursor,
    Empty, LineWriter, Lines, Repeat, Sink, DEFAULT_BUF_SIZE,
};
