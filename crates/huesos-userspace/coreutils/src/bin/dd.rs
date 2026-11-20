//! `/bin/dd.elf` — copy bytes with explicit block sizes.
//!
//! `dd [if=<source>] [of=<sink>] [bs=<bytes>] [count=<blocks>] [skip=<blocks>]
//!    [seek=<blocks>] [status=none|summary]`
//!
//! Sources and sinks are files, standard input/output, or one of the two
//! synthetic devices the pipelines in the smoke tests use:
//!
//! * `/dev/zero` — an endless supply of zero bytes;
//! * `/dev/pattern` — the repeating byte sequence `HuesOS!` (so a test can tell
//!   where a copied block came from).
//!
//! Progress goes to stderr and the summary to stdout, which keeps
//! `dd if=... | something` clean.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::vec;

use huesos_std::io::{Read, Seek, SeekFrom, Write};
use huesos_std::prelude::*;
use huesos_std::{fs, io, time::Instant};

use huesos_coreutils as cu;

cu::coreutil_entry!(run);

/// Bytes per block when `bs=` is not given (`dd`'s historical default).
const DEFAULT_BLOCK: u64 = 512;
/// The repeating pattern `/dev/pattern` produces.
const PATTERN: &[u8] = b"HuesOS!";
/// One progress line per this many blocks.
const PROGRESS_EVERY: u64 = 64;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut input: Option<&str> = None;
    let mut output: Option<&str> = None;
    let mut block_size = DEFAULT_BLOCK;
    let mut count: Option<u64> = None;
    let mut skip = 0u64;
    let mut seek = 0u64;
    let mut quiet = false;

    for arg in args.iter().skip(1) {
        let Some((key, value)) = arg.split_once('=') else {
            cu::errln(&format!("dd: expected key=value, got '{arg}'"));
            return 2;
        };
        match key {
            "if" => input = Some(value),
            "of" => output = Some(value),
            "bs" => match parse_number(value) {
                Some(size) if size > 0 => block_size = size,
                _ => {
                    cu::errln("dd: bs= must be a positive byte count");
                    return 2;
                }
            },
            "count" => match parse_number(value) {
                Some(blocks) => count = Some(blocks),
                None => {
                    cu::errln("dd: count= must be a number of blocks");
                    return 2;
                }
            },
            "skip" => match parse_number(value) {
                Some(blocks) => skip = blocks,
                None => {
                    cu::errln("dd: skip= must be a number of blocks");
                    return 2;
                }
            },
            "seek" => match parse_number(value) {
                Some(blocks) => seek = blocks,
                None => {
                    cu::errln("dd: seek= must be a number of blocks");
                    return 2;
                }
            },
            "status" => quiet = value == "none",
            other => {
                cu::errln(&format!("dd: unknown operand '{other}'"));
                return 2;
            }
        }
    }

    let start = Instant::now();
    let mut buffer = vec![0u8; block_size.min(64 * 1024) as usize];
    let mut source = match open_source(input) {
        Ok(source) => source,
        Err(error) => {
            cu::errln(&format!("dd: {error}"));
            return 1;
        }
    };
    let mut sink = match open_sink(output) {
        Ok(sink) => sink,
        Err(error) => {
            cu::errln(&format!("dd: {error}"));
            return 1;
        }
    };

    // `skip=` seeks when it can and reads otherwise, so it works on a pipe.
    if skip > 0 {
        let bytes = skip.saturating_mul(block_size);
        if let Err(error) = source.skip_bytes(bytes) {
            cu::errln(&format!("dd: skip: {error}"));
            return 1;
        }
    }
    if seek > 0 {
        if let Err(error) = sink.seek_blocks(seek.saturating_mul(block_size)) {
            cu::errln(&format!("dd: seek: {error}"));
            return 1;
        }
    }

    let mut records_in = 0u64;
    let mut records_out = 0u64;
    let mut partial_in = 0u64;
    let mut partial_out = 0u64;
    let mut bytes = 0u64;
    let mut failed = false;

    loop {
        if let Some(count) = count {
            if records_in >= count {
                break;
            }
        }
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) => {
                cu::errln(&format!("dd: read: {error}"));
                failed = true;
                break;
            }
        };
        records_in += 1;
        if read < buffer.len() {
            partial_in += 1;
        }
        let mut written = 0;
        while written < read {
            match sink.write(&buffer[written..read]) {
                Ok(0) => {
                    cu::errln("dd: write returned 0");
                    failed = true;
                    break;
                }
                Ok(n) => written += n,
                Err(error) => {
                    cu::errln(&format!("dd: write: {error}"));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            break;
        }
        records_out += 1;
        if written < buffer.len() {
            partial_out += 1;
        }
        bytes += written as u64;
        if !quiet && records_out.is_multiple_of(PROGRESS_EVERY) {
            cu::errln(&format!(
                "dd: {records_out} records, {bytes} bytes ({})",
                human_size(bytes)
            ));
        }
    }

    if let Err(error) = sink.flush() {
        cu::errln(&format!("dd: flush: {error}"));
        failed = true;
    }
    if let Err(error) = sink.close() {
        cu::errln(&format!("dd: close: {error}"));
        failed = true;
    }

    let elapsed = start.elapsed();
    let ticks = elapsed.as_ticks_ceil().max(1);
    if !quiet {
        cu::outln(&format!(
            "records_in={records_in} records_out={records_out} partial_in={partial_in} partial_out={partial_out}"
        ));
        cu::outln(&format!(
            "bytes={bytes} size={} bs={block_size} seconds={:.2} speed={}/s",
            human_size(bytes),
            ticks as f64 / 100.0,
            human_size(bytes.saturating_mul(100) / ticks)
        ));
    }
    if failed {
        1
    } else {
        0
    }
}

/// Where a copy reads from.
enum Source {
    /// A file on the mounted volume.
    File(fs::File),
    /// Standard input.
    Stdin(io::Stdin),
    /// `/dev/zero`.
    Zero,
    /// `/dev/pattern`.
    Pattern(u64),
}

impl Source {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Source::File(file) => io::Read::read(file, out),
            Source::Stdin(stdin) => stdin.read(out),
            Source::Zero => {
                out.fill(0);
                Ok(out.len())
            }
            Source::Pattern(offset) => {
                for (index, slot) in out.iter_mut().enumerate() {
                    *slot = PATTERN[((*offset as usize) + index) % PATTERN.len()];
                }
                *offset += out.len() as u64;
                Ok(out.len())
            }
        }
    }

    fn skip_bytes(&mut self, bytes: u64) -> Result<()> {
        match self {
            Source::File(file) => {
                file.seek(SeekFrom::Start(bytes))?;
                Ok(())
            }
            Source::Pattern(offset) => {
                *offset += bytes;
                Ok(())
            }
            Source::Zero => Ok(()),
            Source::Stdin(stdin) => {
                let mut scratch = [0u8; 512];
                let mut left = bytes;
                while left > 0 {
                    let want = (left as usize).min(scratch.len());
                    let read = stdin.read(&mut scratch[..want])?;
                    if read == 0 {
                        break;
                    }
                    left -= read as u64;
                }
                Ok(())
            }
        }
    }
}

/// Where a copy writes to.
enum Sink {
    /// A file on the mounted volume.
    File(fs::File),
    /// Standard output.
    Stdout(io::Stdout),
    /// A sink that discards everything (`of=/dev/null`).
    Null,
}

impl Sink {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        match self {
            Sink::File(file) => io::Write::write(file, data),
            Sink::Stdout(stdout) => stdout.write(data),
            Sink::Null => Ok(data.len()),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            Sink::File(file) => file.fsync(),
            Sink::Stdout(stdout) => stdout.flush(),
            Sink::Null => Ok(()),
        }
    }

    fn seek_blocks(&mut self, bytes: u64) -> Result<u64> {
        match self {
            Sink::File(file) => file.seek(SeekFrom::Start(bytes)),
            // Seeking on a stream is meaningless; `dd` treats it as a no-op so a
            // pipeline does not have to special-case it.
            Sink::Stdout(_) | Sink::Null => Ok(bytes),
        }
    }

    fn close(&mut self) -> Result<()> {
        self.flush()
    }
}

fn open_source(name: Option<&str>) -> Result<Source> {
    Ok(match name {
        None | Some("-") => Source::Stdin(io::stdin()),
        Some("/dev/zero") => Source::Zero,
        Some("/dev/pattern") => Source::Pattern(0),
        Some("/dev/urandom") | Some("/dev/random") => {
            cu::errln("dd: /dev/urandom is not available on HuesOS (no entropy device)");
            return Err(huesos_std::Error::new(huesos_std::ErrorKind::Unsupported));
        }
        Some(path) => Source::File(fs::File::open(path)?),
    })
}

fn open_sink(name: Option<&str>) -> Result<Sink> {
    Ok(match name {
        None | Some("-") => Sink::Stdout(io::stdout()),
        Some("/dev/null") => Sink::Null,
        Some(path) => Sink::File(fs::File::create(path)?),
    })
}

/// Parse a byte count with an optional `k`/`M`/`G` suffix.
fn parse_number(text: &str) -> Option<u64> {
    let (digits, scale) = match text.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&text[..text.len() - 1], 1024u64),
        Some(b'm') | Some(b'M') => (&text[..text.len() - 1], 1024 * 1024),
        Some(b'g') | Some(b'G') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u64>().ok()?,
    };
    Some(value.saturating_mul(scale))
}

/// `512`, `4.0k`, `1.5M`: the shape `dd` and `df -h` use.
fn human_size(bytes: u64) -> alloc::string::String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}
