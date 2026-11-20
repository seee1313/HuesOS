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
    let mut out = io::stdout();
    match limit {
        Limit::Bytes(count) => {
            let data = read_operand(operand)?;
            let end = (*count as usize).min(data.len());
            io::write_all(&mut out, &data[..end])?;
            out.flush()
        }
        Limit::Lines(count) => {
            let data = read_operand(operand)?;
            let mut seen = 0u64;
            let mut end = data.len();
            if *count == 0 {
                end = 0;
            } else {
                for (index, byte) in data.iter().enumerate() {
                    if *byte == b'\n' {
                        seen += 1;
                        if seen == *count {
                            end = index + 1;
                            break;
                        }
                    }
                }
            }
            io::write_all(&mut out, &data[..end])?;
            out.flush()
        }
    }
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
