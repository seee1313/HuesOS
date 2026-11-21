//! `/bin/wc.elf` — count lines, words and bytes.
//!
//! `wc [-l] [-w] [-c] [<path>...]`
//!
//! With no flag all three counts are printed; with one flag only that count is
//! printed (the way `wc -l` is used in scripts). No path (or `-`) reads
//! standard input. Totals are printed when more than one input was counted, and
//! the input name follows the numbers.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

impl Counts {
    fn add(&mut self, other: Counts) {
        self.lines += other.lines;
        self.words += other.words;
        self.bytes += other.bytes;
    }
}

#[derive(Default)]
struct Options {
    lines: bool,
    words: bool,
    bytes: bool,
}

fn run() -> i32 {
    let args = args();
    let mut options = Options::default();
    let mut any_flag = false;
    let mut operands: Vec<String> = Vec::new();
    for arg in &args {
        match arg.as_str() {
            "-l" | "--lines" => {
                options.lines = true;
                any_flag = true;
            }
            "-w" | "--words" => {
                options.words = true;
                any_flag = true;
            }
            "-c" | "--bytes" => {
                options.bytes = true;
                any_flag = true;
            }
            "-h" | "--help" => {
                println!("usage: wc [-l] [-w] [-c] [<path>...]");
                println!("  no path (or `-`) reads standard input");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 && other != "-" => {
                eprintln!("wc: unknown option '{other}'");
                return 2;
            }
            other => operands.push(String::from(other)),
        }
    }
    if !any_flag {
        options.lines = true;
        options.words = true;
        options.bytes = true;
    }
    if operands.is_empty() {
        operands.push(String::from("-"));
    }

    let mut total = Counts::default();
    let mut failures = 0u32;
    for operand in &operands {
        match count_operand(operand) {
            Ok(counts) => {
                total.add(counts);
                println!("{}", format_counts(&options, counts, operand));
            }
            Err(error) => {
                eprintln!("wc: {operand}: {error}");
                failures += 1;
            }
        }
    }
    if operands.len() > 1 && failures == 0 {
        println!("{}", format_counts(&options, total, "total"));
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

fn count_operand(operand: &str) -> Result<Counts> {
    let mut data = Vec::new();
    if operand == "-" {
        io::read_to_end(&mut io::stdin(), &mut data)?;
    } else {
        let mut file = fs::File::open(&path::normalize(operand))?;
        io::read_to_end(&mut file, &mut data)?;
    }
    Ok(count_bytes(&data))
}

fn count_bytes(data: &[u8]) -> Counts {
    let mut counts = Counts {
        bytes: data.len() as u64,
        ..Counts::default()
    };
    let mut in_word = false;
    for byte in data {
        match byte {
            b'\n' => counts.lines += 1,
            b' ' | b'\t' | b'\r' | 0x0b | 0x0c => {}
            _ => {}
        }
        let separator = matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c);
        if separator {
            in_word = false;
        } else if !in_word {
            in_word = true;
            counts.words += 1;
        }
    }
    counts
}

fn format_counts(options: &Options, counts: Counts, label: &str) -> String {
    let mut text = String::new();
    let mut push = |value: u64| {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(&format!("{value}"));
    };
    if options.lines {
        push(counts.lines);
    }
    if options.words {
        push(counts.words);
    }
    if options.bytes {
        push(counts.bytes);
    }
    text.push(' ');
    text.push_str(label);
    text
}
