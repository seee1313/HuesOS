//! Buffered and in-memory I/O: `BufRead`, `BufReader`, `BufWriter`,
//! `LineWriter`, `Cursor`, `copy`, `empty`, `repeat`, `sink`.
//!
//! These are re-exported from [`crate::io`] so a program can write
//! `use huesos_std::io::{BufRead, BufReader}` exactly as it would with `std`.
//!
//! # Why buffering matters here
//! Every `stdout_write` is a capability call: it copies into the kernel's
//! channel and may reschedule the writer. A `println!`-heavy program that
//! writes byte by byte would pay one syscall per byte, so the formatting
//! macros already build a whole line in a stack buffer. `BufWriter` is for the
//! other case — a program that writes generated data in small pieces — and
//! `BufReader` is what turns "read one byte at a time" into one syscall per
//! 4 KiB, which is what `hexdump`, `dd` and the shell's line reader need.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Seek, SeekFrom, Write};

/// The default buffer size: one page, matching the service's granularity.
pub const DEFAULT_BUF_SIZE: usize = 4096;

/// A source of bytes with an internal buffer, so callers can inspect data
/// before consuming it.
pub trait BufRead: Read {
    /// The buffered bytes without consuming them.
    fn fill_buf(&mut self) -> Result<&[u8]>;

    /// Mark `amount` buffered bytes as consumed.
    fn consume(&mut self, amount: usize);

    /// Read until `delimiter` (inclusive) or end of input.
    fn read_until(&mut self, delimiter: u8, out: &mut Vec<u8>) -> Result<usize> {
        let mut read = 0;
        loop {
            let (done, used) = {
                let available = self.fill_buf()?;
                match available.iter().position(|byte| *byte == delimiter) {
                    Some(index) => {
                        out.extend_from_slice(&available[..=index]);
                        (true, index + 1)
                    }
                    None => {
                        out.extend_from_slice(available);
                        (false, available.len())
                    }
                }
            };
            self.consume(used);
            read += used;
            if done || used == 0 {
                return Ok(read);
            }
        }
    }

    /// Read one line, keeping its trailing newline.
    fn read_line(&mut self, out: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        let read = self.read_until(b'\n', &mut bytes)?;
        match String::from_utf8(bytes) {
            Ok(text) => {
                out.push_str(&text);
                Ok(read)
            }
            Err(_) => Err(Error::new(ErrorKind::InvalidInput)),
        }
    }

    /// Iterate over lines, without their newlines.
    fn lines(self) -> Lines<Self>
    where
        Self: Sized,
    {
        Lines { reader: self }
    }

    /// True when the buffer holds nothing and the source is at end of input.
    fn is_at_eof(&mut self) -> Result<bool> {
        Ok(self.fill_buf()?.is_empty())
    }
}

/// Iterator returned by [`BufRead::lines`].
pub struct Lines<R> {
    reader: R,
}

impl<R: BufRead> Iterator for Lines<R> {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Result<String>> {
        let mut bytes = Vec::new();
        match self.reader.read_until(b'\n', &mut bytes) {
            Ok(0) => None,
            Ok(_) => {
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                }
                Some(String::from_utf8(bytes).map_err(|_| Error::new(ErrorKind::InvalidInput)))
            }
            Err(error) => Some(Err(error)),
        }
    }
}

/// A reader with an internal buffer.
pub struct BufReader<R> {
    inner: R,
    buffer: Vec<u8>,
    position: usize,
    filled: usize,
}

impl<R: Read> BufReader<R> {
    /// Wrap `inner` with a [`DEFAULT_BUF_SIZE`] buffer.
    pub fn new(inner: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    /// Wrap `inner` with a buffer of `capacity` bytes.
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        let capacity = capacity.max(1);
        let buffer = alloc::vec![0u8; capacity];
        Self {
            inner,
            buffer,
            position: 0,
            filled: 0,
        }
    }

    /// The wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The wrapped reader, mutable. Reading through it bypasses the buffer.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwrap the reader, discarding buffered bytes.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Buffer size in bytes.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Bytes currently buffered and not yet consumed.
    pub fn buffered(&self) -> usize {
        self.filled - self.position
    }

    /// Pull one buffer-full from the underlying reader.
    fn refill(&mut self) -> Result<()> {
        self.position = 0;
        self.filled = self.inner.read(&mut self.buffer)?;
        Ok(())
    }
}

impl<R: Read> Read for BufReader<R> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // Large reads skip the buffer entirely: copying through it would cost
        // more than the syscall saves.
        if self.position == self.filled && out.len() >= self.buffer.len() {
            return self.inner.read(out);
        }
        if self.position == self.filled {
            self.refill()?;
            if self.filled == 0 {
                return Ok(0);
            }
        }
        let available = self.filled - self.position;
        let count = out.len().min(available);
        out[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl<R: Read> BufRead for BufReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if self.position == self.filled {
            self.refill()?;
        }
        Ok(&self.buffer[self.position..self.filled])
    }

    fn consume(&mut self, amount: usize) {
        self.position = (self.position + amount).min(self.filled);
    }
}

impl<R: Seek> Seek for BufReader<R> {
    fn seek(&mut self, from: SeekFrom) -> Result<u64> {
        // A buffered reader knows where the underlying object is (at `filled`),
        // so `Current` is translated rather than dropped.
        let target = match from {
            SeekFrom::Start(offset) => SeekFrom::Start(offset),
            SeekFrom::Current(delta) => {
                let position = self.filled as i64 + delta;
                SeekFrom::Start(position.max(0) as u64)
            }
            SeekFrom::End(delta) => SeekFrom::End(delta),
        };
        self.position = 0;
        self.filled = 0;
        self.inner.seek(target)
    }
}

/// A writer that batches small writes into one syscall each.
pub struct BufWriter<W: Write> {
    inner: Option<W>,
    buffer: Vec<u8>,
}

impl<W: Write> BufWriter<W> {
    /// Wrap `inner` with a [`DEFAULT_BUF_SIZE`] buffer.
    pub fn new(inner: W) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    /// Wrap `inner` with a buffer of `capacity` bytes.
    pub fn with_capacity(capacity: usize, inner: W) -> Self {
        Self {
            inner: Some(inner),
            buffer: Vec::with_capacity(capacity.max(1)),
        }
    }

    /// The wrapped writer.
    pub fn get_ref(&self) -> Option<&W> {
        self.inner.as_ref()
    }

    /// The wrapped writer, mutable. Writing through it bypasses the buffer.
    pub fn get_mut(&mut self) -> Option<&mut W> {
        self.inner.as_mut()
    }

    /// Flush and unwrap the writer.
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        match self.inner.take() {
            Some(inner) => Ok(inner),
            None => Err(Error::new(ErrorKind::Io)),
        }
    }

    /// Bytes waiting to be written.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    fn push(&mut self, data: &[u8]) -> Result<()> {
        let writer = match self.inner.as_mut() {
            Some(writer) => writer,
            None => return Err(Error::new(ErrorKind::Io)),
        };
        crate::io::write_all(writer, data)
    }
}

impl<W: Write> Write for BufWriter<W> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() >= self.buffer.capacity() {
            // Too big to buffer: flush what is pending, then go direct.
            self.flush()?;
            return match self.inner.as_mut() {
                Some(writer) => writer.write(data),
                None => Err(Error::new(ErrorKind::Io)),
            };
        }
        if self.buffer.len() + data.len() > self.buffer.capacity() {
            self.flush()?;
        }
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let pending = core::mem::take(&mut self.buffer);
        let result = self.push(&pending);
        // Keep the allocation so the next write reuses the buffer.
        self.buffer = Vec::with_capacity(pending.capacity().max(DEFAULT_BUF_SIZE));
        result?;
        match self.inner.as_mut() {
            Some(writer) => writer.flush(),
            None => Err(Error::new(ErrorKind::Io)),
        }
    }
}

impl<W: Write> Drop for BufWriter<W> {
    fn drop(&mut self) {
        // A program that forgets to flush still gets its bytes out; a failure
        // here cannot be reported from `drop`, so it is swallowed.
        if !self.buffer.is_empty() {
            let pending = core::mem::take(&mut self.buffer);
            let _ = self.push(&pending);
        }
        if let Some(writer) = self.inner.as_mut() {
            let _ = writer.flush();
        }
    }
}

/// A writer that flushes on every newline: for interactive output.
pub struct LineWriter<W: Write> {
    inner: BufWriter<W>,
}

impl<W: Write> LineWriter<W> {
    /// Wrap `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner: BufWriter::with_capacity(DEFAULT_BUF_SIZE, inner),
        }
    }

    /// The wrapped writer.
    pub fn get_ref(&self) -> Option<&W> {
        self.inner.get_ref()
    }

    /// The wrapped writer, mutable.
    pub fn get_mut(&mut self) -> Option<&mut W> {
        self.inner.get_mut()
    }

    /// Flush and unwrap the writer.
    pub fn into_inner(self) -> Result<W> {
        self.inner.into_inner()
    }
}

impl<W: Write> Write for LineWriter<W> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        match data.iter().rposition(|byte| *byte == b'\n') {
            Some(last_newline) => {
                let (head, tail) = data.split_at(last_newline + 1);
                self.inner.write(head)?;
                self.inner.flush()?;
                if !tail.is_empty() {
                    self.inner.write(tail)?;
                }
                Ok(data.len())
            }
            None => self.inner.write(data),
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// An in-memory reader/writer with a seekable cursor.
pub struct Cursor<T> {
    inner: T,
    position: u64,
}

impl<T> Cursor<T> {
    /// Wrap `inner` at position 0.
    pub fn new(inner: T) -> Self {
        Self { inner, position: 0 }
    }

    /// The current position.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Set the position.
    pub fn set_position(&mut self, position: u64) {
        self.position = position;
    }

    /// The wrapped value.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// The wrapped value, mutable.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Unwrap the value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let source = self.inner.as_ref();
        let position = self.position as usize;
        if position >= source.len() {
            return Ok(0);
        }
        let count = out.len().min(source.len() - position);
        out[..count].copy_from_slice(&source[position..position + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Write for Cursor<Vec<u8>> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let position = self.position as usize;
        // Writing past the end extends the vector with zeros, like `std`.
        if position > self.inner.len() {
            self.inner.resize(position, 0);
        }
        let overlap = self.inner.len().saturating_sub(position).min(data.len());
        self.inner[position..position + overlap].copy_from_slice(&data[..overlap]);
        if overlap < data.len() {
            self.inner.extend_from_slice(&data[overlap..]);
        }
        self.position += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<T: AsRef<[u8]>> Seek for Cursor<T> {
    fn seek(&mut self, from: SeekFrom) -> Result<u64> {
        let length = self.inner.as_ref().len() as i64;
        let position = self.position as i64;
        let target = match from {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(delta) => position + delta,
            SeekFrom::End(delta) => length + delta,
        };
        if target < 0 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

impl Write for Cursor<&mut Vec<u8>> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let position = self.position as usize;
        if position > self.inner.len() {
            self.inner.resize(position, 0);
        }
        let overlap = self.inner.len().saturating_sub(position).min(data.len());
        self.inner[position..position + overlap].copy_from_slice(&data[..overlap]);
        if overlap < data.len() {
            self.inner.extend_from_slice(&data[overlap..]);
        }
        self.position += data.len() as u64;
        Ok(data.len())
    }
}

/// Read from `source` and write to `sink` until end of input.
pub fn copy<R: Read + ?Sized, W: Write + ?Sized>(source: &mut R, sink: &mut W) -> Result<u64> {
    let mut buffer = [0u8; DEFAULT_BUF_SIZE];
    let mut total = 0u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        crate::io::write_all(sink, &buffer[..read])?;
        total += read as u64;
    }
}

/// A reader that yields nothing.
pub fn empty() -> Empty {
    Empty
}

/// The reader returned by [`empty`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Empty;

impl Read for Empty {
    fn read(&mut self, _out: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
}

/// A reader that yields one byte forever.
pub fn repeat(byte: u8) -> Repeat {
    Repeat { byte }
}

/// The reader returned by [`repeat`].
#[derive(Clone, Copy, Debug)]
pub struct Repeat {
    byte: u8,
}

impl Read for Repeat {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        for slot in out.iter_mut() {
            *slot = self.byte;
        }
        Ok(out.len())
    }
}

/// A writer that discards everything.
pub fn sink() -> Sink {
    Sink
}

/// The writer returned by [`sink`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Sink;

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write + ?Sized> Write for &mut W {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        (**self).write(data)
    }

    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}

impl<R: Read + ?Sized> Read for &mut R {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        (**self).read(out)
    }
}

impl Read for &[u8] {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let count = out.len().min(self.len());
        out[..count].copy_from_slice(&self[..count]);
        *self = &self[count..];
        Ok(count)
    }
}

impl BufRead for &[u8] {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        Ok(self)
    }

    fn consume(&mut self, amount: usize) {
        let count = amount.min(self.len());
        *self = &self[count..];
    }
}

impl Write for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Read exactly `buf.len()` bytes, or fail with `Io` on a short read.
pub fn read_exact<R: Read + ?Sized>(source: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = source.read(&mut buf[filled..])?;
        if read == 0 {
            return Err(Error::new(ErrorKind::Io));
        }
        filled += read;
    }
    Ok(())
}

/// Read everything into a `String`, failing if the bytes are not UTF-8.
pub fn read_to_string<R: Read + ?Sized>(source: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    crate::io::read_to_end(source, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| Error::new(ErrorKind::InvalidInput))
}
