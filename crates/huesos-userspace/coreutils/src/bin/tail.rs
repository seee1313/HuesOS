//! `/bin/tail.elf` — the last lines or bytes of a file or stream.
//!
//! `tail [-n <count>] [-c <bytes>] [<path>...]`
//!
//! `-n` counts lines (the default is ten), `-c` counts bytes and wins when both
//! are given. A count of `+N` starts at line `N` instead of counting backwards,
//! which is what `tail -n +2` in a script means. No path (or `-`) reads
//! standard input.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

/// How much to emit.
enum Limit {
    /// The last `count` lines.
    FromEnd(u64),
    /// Everything from line `count` on (1-based, `+N` on the command line).
    FromStart(u64),
    /// The last `count` bytes.
    Bytes(u64),
}

fn run() -> i32 {
    let args = args();
    let mut limit = Limit::FromEnd(10);
    let mut operands: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-n" | "--lines" => {
                index += 1;
                match args.get(index).and_then(|value| parse_lines(value)) {
                    Some(parsed) => limit = parsed,
                    None => {
                        eprintln!("tail: -n needs a line count");
                        return 2;
                    }
                }
            }
            "-c" | "--bytes" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u64>().ok()) {
                    Some(count) => limit = Limit::Bytes(count),
                    None => {
                        eprintln!("tail: -c needs a byte count");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                println!("usage: tail [-n <count>|+<count>] [-c <bytes>] [<path>...]");
                println!("  no path (or `-`) reads standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 && other != "-" => {
                eprintln!("tail: unknown option '{other}'");
                return 2;
            }
            other => operands.push(String::from(other)),
        }
        index += 1;
    }
    if operands.is_empty() {
        operands.push(String::from("-"));
    }

    let mut failures = 0u32;
    for operand in &operands {
        match emit(operand, &limit) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("tail: {operand}: {error}");
                failures += 1;
            }
        }
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

/// `-n 5` counts back from the end, `-n +5` starts at the fifth line.
fn parse_lines(text: &str) -> Option<Limit> {
    match text.strip_prefix('+') {
        Some(rest) => rest
            .parse::<u64>()
            .ok()
            .filter(|count| *count > 0)
            .map(Limit::FromStart),
        None => text.parse::<u64>().ok().map(Limit::FromEnd),
    }
}

fn emit(operand: &str, limit: &Limit) -> Result<()> {
    let data = read_operand(operand)?;
    let mut out = io::stdout();
    match limit {
        Limit::Bytes(count) => {
            let start = data.len().saturating_sub(*count as usize);
            io::write_all(&mut out, &data[start..])?;
        }
        Limit::FromStart(count) => {
            let mut seen = 1u64;
            let mut start = data.len();
            if *count <= 1 {
                start = 0;
            } else {
                for (index, byte) in data.iter().enumerate() {
                    if *byte == b'\n' {
                        seen += 1;
                        if seen == *count {
                            start = index + 1;
                            break;
                        }
                    }
                }
            }
            io::write_all(&mut out, &data[start..])?;
        }
        Limit::FromEnd(count) => {
            let start = start_of_last_lines(&data, *count as usize);
            io::write_all(&mut out, &data[start..])?;
        }
    }
    out.flush()
}

/// Byte offset of the last `count` lines in `data`.
fn start_of_last_lines(data: &[u8], count: usize) -> usize {
    if count == 0 {
        return data.len();
    }
    // Walk backwards over newlines instead of copying the tail around.
    let mut remaining = count;
    let mut index = data.len();
    if data.ends_with(b"\n") {
        index -= 1;
    }
    while index > 0 {
        index -= 1;
        if data[index] == b'\n' {
            remaining -= 1;
            if remaining == 0 {
                return index + 1;
            }
        }
    }
    0
}

fn read_operand(operand: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    if operand == "-" {
        io::read_to_end(&mut io::stdin(), &mut data)?;
    } else {
        let mut file = fs::File::open(&path::normalize(operand))?;
        io::read_to_end(&mut file, &mut data)?;
    }
    Ok(data)
}
