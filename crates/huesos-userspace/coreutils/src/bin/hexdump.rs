//! `/bin/hexdump.elf` — canonical hex dump of a file or a byte range.
//!
//! `hexdump [-C] [-n <length>] [-s <offset>] [<path>]`
//!
//! The format is `hexdump -C`'s: an offset column, sixteen bytes in hex split
//! into two groups of eight, then the same sixteen bytes as text with `.` for
//! anything that is not printable ASCII. Reading a file goes through
//! `huesos_std::fs`, so the same tool dumps a `BOOTFS` blob and a file on the
//! mounted volume, and `-s` seeks instead of reading and discarding.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;

use huesos_std::io::{Seek, SeekFrom};
use huesos_std::prelude::*;
use huesos_std::{fs, io};

use huesos_coreutils as cu;

cu::coreutil_entry!(run);

/// Bytes per output line.
const WIDTH: usize = 16;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut path: Option<&str> = None;
    let mut limit: Option<u64> = None;
    let mut offset: u64 = 0;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            // The canonical layout is the default, so `-C` only has to be
            // accepted, not acted on.
            "-C" | "--canonical" => {}
            "-n" | "--length" => {
                index += 1;
                match args.get(index).and_then(|value| parse_number(value)) {
                    Some(value) => limit = Some(value),
                    None => {
                        cu::errln("hexdump: -n needs a byte count");
                        return 2;
                    }
                }
            }
            "-s" | "--skip" => {
                index += 1;
                match args.get(index).and_then(|value| parse_number(value)) {
                    Some(value) => offset = value,
                    None => {
                        cu::errln("hexdump: -s needs a byte offset");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                cu::outln("usage: hexdump [-C] [-n <bytes>] [-s <offset>] [<path>]");
                cu::outln("  no path reads standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                cu::errln(&format!("hexdump: unknown option '{other}'"));
                return 2;
            }
            other => path = Some(other),
        }
        index += 1;
    }

    let mut failures = 0;
    let mut data = Vec::new();
    match path {
        Some(path) => match fs::File::open(path) {
            Ok(mut file) => {
                if offset > 0 {
                    if let Err(error) = file.seek(SeekFrom::Start(offset)) {
                        cu::errln(&format!("hexdump: seek {path}: {error}"));
                        return 1;
                    }
                }
                if let Err(error) = io::read_to_end(&mut file, &mut data) {
                    cu::errln(&format!("hexdump: read {path}: {error}"));
                    return 1;
                }
            }
            Err(error) => {
                cu::errln(&format!("hexdump: {path}: {error}"));
                return 1;
            }
        },
        None => {
            let mut stdin = io::stdin();
            if let Err(error) = io::read_to_end(&mut stdin, &mut data) {
                cu::errln(&format!("hexdump: stdin: {error}"));
                return 1;
            }
            // A `-s` on a pipe has nothing to seek, so drop the bytes instead.
            if offset as usize >= data.len() {
                data.clear();
            } else {
                data.drain(..offset as usize);
            }
        }
    }

    if let Some(limit) = limit {
        data.truncate(limit as usize);
    }

    let mut line = format!(
        "hexdump: {path_label} bytes={} offset={offset:#x}",
        data.len(),
        path_label = path.unwrap_or("<stdin>")
    );
    cu::outln(&line);
    line.clear();

    let mut emitted = 0u64;
    while (emitted as usize) < data.len() {
        let start = emitted as usize;
        let end = (start + WIDTH).min(data.len());
        let chunk = &data[start..end];
        cu::outln(&format_line(offset + emitted, chunk));
        emitted += chunk.len() as u64;
    }
    if data.is_empty() {
        cu::outln("(no bytes)");
    }
    failures += 0;
    failures
}

/// One canonical line: offset, hex groups, text.
fn format_line(offset: u64, chunk: &[u8]) -> String {
    let mut text = format!("{offset:08x}  ");
    for position in 0..WIDTH {
        match chunk.get(position) {
            Some(byte) => text.push_str(&format!("{byte:02x} ")),
            None => text.push_str("   "),
        }
        if position == 7 {
            text.push(' ');
        }
    }
    text.push_str(" |");
    for byte in chunk {
        let printable = (0x20..=0x7e).contains(byte);
        text.push(if printable { *byte as char } else { '.' });
    }
    text.push('|');
    text
}

/// Parse a decimal or `0x`-prefixed hex byte count, with an optional
/// `k`/`M` suffix (`-n 4k` is four kibibytes).
fn parse_number(text: &str) -> Option<u64> {
    let (digits, scale) = match text.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&text[..text.len() - 1], 1024u64),
        Some(b'm') | Some(b'M') => (&text[..text.len() - 1], 1024 * 1024),
        _ => (text, 1),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u64>().ok()?,
    };
    Some(value.saturating_mul(scale))
}
