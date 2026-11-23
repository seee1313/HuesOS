//! `/bin/head.elf` — the first lines or bytes of a file or stream.
//!
//! `head [-n <count>] [-c <bytes>] [<path>...]`
//!
//! `-n` counts lines (the default is ten), `-c` counts bytes and wins when both
//! are given. No path (or `-`) reads standard input.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

/// How much to emit.
enum Limit {
    Lines(u64),
    Bytes(u64),
}

fn run() -> i32 {
    let args = args();
    let mut limit = Limit::Lines(10);
    let mut operands: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-n" | "--lines" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u64>().ok()) {
                    Some(count) => limit = Limit::Lines(count),
                    None => {
                        eprintln!("head: -n needs a line count");
                        return 2;
                    }
                }
            }
            "-c" | "--bytes" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u64>().ok()) {
                    Some(count) => limit = Limit::Bytes(count),
                    None => {
                        eprintln!("head: -c needs a byte count");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                println!("usage: head [-n <count>] [-c <bytes>] [<path>...]");
                println!("  no path (or `-`) reads standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 && other != "-" => {
                eprintln!("head: unknown option '{other}'");
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
                eprintln!("head: {operand}: {error}");
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

fn emit(operand: &str, limit: &Limit) -> Result<()> {
    if operand == "-" {
        emit_reader(&mut io::stdin(), limit)
    } else {
        let mut file = fs::File::open(&path::normalize(operand))?;
        emit_reader(&mut file, limit)
    }
}

fn write_out(out: &mut io::Stdout, bytes: &[u8]) -> Result<bool> {
    match io::write_all(out, bytes) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == huesos_std::ErrorKind::PeerClosed => Ok(false),
        Err(err) => Err(err),
    }
}

fn emit_reader<R: io::Read>(reader: &mut R, limit: &Limit) -> Result<()> {
    let mut out = io::stdout();
    let mut buf = [0u8; 4096];
    match limit {
        Limit::Bytes(count) => {
            let mut remaining = *count;
            while remaining > 0 {
                let want = (remaining as usize).min(buf.len());
                let n = reader.read(&mut buf[..want])?;
                if n == 0 {
                    break;
                }
                if !write_out(&mut out, &buf[..n])? {
                    return Ok(());
                }
                remaining = remaining.saturating_sub(n as u64);
            }
            let _ = out.flush();
            Ok(())
        }
        Limit::Lines(count) => {
            if *count == 0 {
                return Ok(());
            }
            let mut seen = 0u64;
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                let mut emit_len = n;
                for (index, &byte) in buf[..n].iter().enumerate() {
                    if byte == b'\n' {
                        seen += 1;
                        if seen == *count {
                            emit_len = index + 1;
                            break;
                        }
                    }
                }
                if !write_out(&mut out, &buf[..emit_len])? {
                    return Ok(());
                }
                if seen == *count {
                    break;
                }
            }
            let _ = out.flush();
            Ok(())
        }
    }
}
