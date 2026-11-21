//! `/bin/grep.elf` — search files (or standard input) for a pattern.
//!
//! `grep [-i] [-n] [-v] [-c] [-r] <pattern> [<path>...]`
//!
//! Matching is literal by default: HuesOS utilities stay small and predictable
//! and a byte pattern is what scripts actually need. `-i` folds ASCII case, `-n`
//! prefixes the line number, `-v` inverts, `-c` prints only the count, and `-r`
//! walks directories. No path (or `-`) reads standard input.
//!
//! Exit status follows grep: `0` when something matched, `1` when nothing did,
//! `2` on a usage or I/O error.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

#[derive(Default)]
struct Options {
    ignore_case: bool,
    line_numbers: bool,
    invert: bool,
    count_only: bool,
    recursive: bool,
}

fn run() -> i32 {
    let args = args();
    let mut options = Options::default();
    let mut operands: Vec<String> = Vec::new();
    let mut pattern: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            index += 1;
            while index < args.len() {
                claim_operand(&args[index], &mut pattern, &mut operands);
                index += 1;
            }
            break;
        }
        if pattern.is_some() {
            operands.push(String::from(arg));
            index += 1;
            continue;
        }
        match arg {
            "-i" | "--ignore-case" => options.ignore_case = true,
            "-n" | "--line-number" => options.line_numbers = true,
            "-v" | "--invert-match" => options.invert = true,
            "-c" | "--count" => options.count_only = true,
            "-r" | "-R" | "--recursive" => options.recursive = true,
            "-h" | "--help" => {
                println!("usage: grep [-i] [-n] [-v] [-c] [-r] <pattern> [<path>...]");
                println!("  no path (or `-`) reads standard input; `-r` walks directories");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                // Bundled short flags (`-in`) are the common case.
                let flags = other.trim_start_matches('-');
                let mut recognised = !flags.is_empty();
                for flag in flags.chars() {
                    match flag {
                        'i' => options.ignore_case = true,
                        'n' => options.line_numbers = true,
                        'v' => options.invert = true,
                        'c' => options.count_only = true,
                        'r' | 'R' => options.recursive = true,
                        _ => recognised = false,
                    }
                }
                if !recognised {
                    eprintln!("grep: unknown option '{other}'");
                    return 2;
                }
            }
            other => {
                pattern = Some(String::from(other));
            }
        }
        index += 1;
    }

    let Some(pattern) = pattern else {
        eprintln!("grep: a pattern is required");
        return 2;
    };
    if operands.is_empty() {
        operands.push(String::from("-"));
    }

    let needle = fold(&pattern, options.ignore_case);
    let mut any_match = false;
    let mut failed = false;
    let multiple = operands.len() > 1;
    for operand in &operands {
        if let Err(error) = grep_operand(&needle, operand, &options, multiple, &mut any_match) {
            eprintln!("grep: {operand}: {error}");
            failed = true;
        }
    }
    if failed {
        return 2;
    }
    if any_match {
        0
    } else {
        1
    }
}

/// The first free operand is the pattern; the rest are paths.
fn claim_operand(operand: &str, pattern: &mut Option<String>, operands: &mut Vec<String>) {
    match pattern {
        None => *pattern = Some(String::from(operand)),
        Some(_) => operands.push(String::from(operand)),
    }
}

fn grep_operand(
    needle: &[u8],
    operand: &str,
    options: &Options,
    multiple: bool,
    any_match: &mut bool,
) -> Result<()> {
    if operand == "-" {
        let mut data = Vec::new();
        io::read_to_end(&mut io::stdin(), &mut data)?;
        *any_match |= scan(&data, needle, "<stdin>", options, multiple);
        return Ok(());
    }
    let path_text = path::normalize(operand);
    let metadata = fs::metadata(&path_text)?;
    if metadata.is_dir() {
        if !options.recursive {
            eprintln!("grep: {operand}: is a directory");
            return Err(Error::new(ErrorKind::NotFound));
        }
        for entry in fs::list(&path_text)? {
            let child = path::join(&path_text, &entry.name);
            // Walking is best-effort per entry: an unreadable child is
            // reported and the walk continues.
            if let Err(error) = grep_operand(needle, &child, options, true, any_match) {
                eprintln!("grep: {child}: {error}");
            }
        }
        return Ok(());
    }
    let mut file = fs::File::open(&path_text)?;
    let mut data = Vec::new();
    io::read_to_end(&mut file, &mut data)?;
    *any_match |= scan(&data, needle, operand, options, multiple);
    Ok(())
}

/// Print the matching lines of `data`; returns whether anything matched.
fn scan(data: &[u8], needle: &[u8], label: &str, options: &Options, multiple: bool) -> bool {
    let mut hits = 0u64;
    let mut text = String::new();
    let lines: Vec<&[u8]> = data.split(|byte| *byte == b'\n').collect();
    // A trailing newline leaves one empty slice behind; it is not a line.
    let line_count = if data.ends_with(b"\n") {
        lines.len().saturating_sub(1)
    } else {
        lines.len()
    };
    for (index, line) in lines.iter().take(line_count).enumerate() {
        let haystack = fold_bytes(line, options.ignore_case);
        let matched = contains(&haystack, needle) != options.invert;
        if !matched {
            continue;
        }
        hits += 1;
        if options.count_only {
            continue;
        }
        text.clear();
        if multiple {
            text.push_str(label);
            text.push(':');
        }
        if options.line_numbers {
            text.push_str(&format!("{}:", index + 1));
        }
        text.push_str(&String::from_utf8_lossy(line));
        println!("{text}");
    }
    if options.count_only {
        if multiple {
            println!("{label}:{hits}");
        } else {
            println!("{hits}");
        }
    }
    hits > 0
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn fold(text: &str, ignore_case: bool) -> Vec<u8> {
    fold_bytes(text.as_bytes(), ignore_case)
}

fn fold_bytes(bytes: &[u8], ignore_case: bool) -> Vec<u8> {
    if ignore_case {
        bytes.iter().map(u8::to_ascii_lowercase).collect()
    } else {
        bytes.to_vec()
    }
}
