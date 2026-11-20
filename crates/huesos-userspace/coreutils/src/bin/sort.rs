//! `/bin/sort.elf` — sort lines of text.
//!
//! `sort [-r] [-n] [-u] [<path>...]`
//!
//! The default is a byte-wise ascending comparison, which is what a script
//! sorting names, hashes or paths wants. `-n` compares the numeric prefix of
//! each line, `-r` reverses the result, and `-u` drops duplicate lines (after
//! sorting, so duplicates are adjacent). Multiple inputs are concatenated in
//! order; no path (or `-`) reads standard input.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

struct Options {
    reverse: bool,
    numeric: bool,
    unique: bool,
}

fn run() -> i32 {
    let args = args();
    let mut options = Options {
        reverse: false,
        numeric: false,
        unique: false,
    };
    let mut operands: Vec<String> = Vec::new();
    for arg in &args {
        match arg.as_str() {
            "-r" | "--reverse" => options.reverse = true,
            "-n" | "--numeric-sort" => options.numeric = true,
            "-u" | "--unique" => options.unique = true,
            "-h" | "--help" => {
                println!("usage: sort [-r] [-n] [-u] [<path>...]");
                println!("  no path (or `-`) reads standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 && other != "-" => {
                eprintln!("sort: unknown option '{other}'");
                return 2;
            }
            other => operands.push(String::from(other)),
        }
    }
    if operands.is_empty() {
        operands.push(String::from("-"));
    }

    let mut lines: Vec<String> = Vec::new();
    for operand in &operands {
        match read_operand(operand) {
            Ok(data) => {
                let text = String::from_utf8_lossy(&data);
                // `split_terminator` keeps a trailing newline from inventing an
                // empty line at the end of the input.
                for line in text.split_terminator('\n') {
                    lines.push(String::from(line));
                }
            }
            Err(error) => {
                eprintln!("sort: {operand}: {error}");
                return 1;
            }
        }
    }

    // `sort` has no stable-sort requirement here beyond "same input, same
    // output", and `sort_by` with a total order on the key gives that.
    let numeric = options.numeric;
    let reverse = options.reverse;
    lines.sort_by(|left, right| {
        let ordering = if numeric {
            numeric_prefix(left).cmp(&numeric_prefix(right))
        } else {
            left.as_bytes().cmp(right.as_bytes())
        };
        // Ties fall back to the text so the order never depends on input order.
        let ordering = ordering.then_with(|| left.as_bytes().cmp(right.as_bytes()));
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
    if options.unique {
        lines.dedup();
    }

    let mut out = io::stdout();
    for line in &lines {
        let _ = io::write_all(&mut out, line.as_bytes());
        let _ = io::write_all(&mut out, b"\n");
    }
    match out.flush() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("sort: write: {error}");
            1
        }
    }
}

/// The leading decimal number of `text`, ignoring spaces and a sign.
fn numeric_prefix(text: &str) -> i64 {
    let trimmed = text.trim_start();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let mut digits_end = 0;
    for (index, byte) in digits.bytes().enumerate() {
        if byte.is_ascii_digit() || (index == 0 && byte == b'.') {
            digits_end = index + 1;
        } else {
            break;
        }
    }
    let mut value = 0i64;
    let mut scale_seen = false;
    for byte in digits[..digits_end].bytes() {
        if byte == b'.' {
            scale_seen = true;
            continue;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(byte - b'0'));
        if scale_seen {
            // Numeric comparison only needs the integer part; stopping here
            // keeps the parse overflow-free on absurd input.
            break;
        }
    }
    if negative {
        -value
    } else {
        value
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
