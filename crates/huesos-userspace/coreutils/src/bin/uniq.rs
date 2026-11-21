//! `/bin/uniq.elf` — report or omit repeated adjacent lines.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let mut show_count = false;
    let mut only_repeated = false;
    let mut only_unique = false;
    let mut ignore_case = false;
    let mut files: Vec<&str> = Vec::new();

    for arg in args.iter() {
        let s = arg.as_str();
        if s.starts_with('-') && s.len() > 1 && s != "--" {
            for ch in s[1..].chars() {
                match ch {
                    'c' => show_count = true,
                    'd' => only_repeated = true,
                    'u' => only_unique = true,
                    'i' => ignore_case = true,
                    _ => {
                        cu::errln(&format!("uniq: unknown option '-{ch}'"));
                        return 1;
                    }
                }
            }
        } else if s != "--" {
            files.push(s);
        }
    }

    let raw = if let Some(path_arg) = files.first() {
        if *path_arg == "-" {
            cu::read_all_stdin()
        } else {
            let path = cu::normalize_path(path_arg);
            let mask = proc_caps_mask();
            if (mask & caps_mask::HXFS_RO) == 0 {
                cu::errln("AccessDenied: HxFS read capability withheld");
                return 1;
            }
            match huesos_std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    cu::errln(&format!("uniq '{path}': {e}"));
                    return 1;
                }
            }
        }
    } else {
        cu::read_all_stdin()
    };

    let text = String::from_utf8_lossy(&raw);
    let mut prev: Option<(&str, usize)> = None;

    let emit = |line: &str, count: usize| {
        if only_repeated && count < 2 {
            return;
        }
        if only_unique && count != 1 {
            return;
        }
        if show_count {
            cu::outln(&format!("{count:>7} {line}"));
        } else {
            cu::outln(line);
        }
    };

    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match prev {
            Some((p, c)) if lines_eq(p, line, ignore_case) => {
                prev = Some((p, c + 1));
            }
            Some((p, c)) => {
                emit(p, c);
                prev = Some((line, 1));
            }
            None => {
                prev = Some((line, 1));
            }
        }
    }
    if let Some((p, c)) = prev {
        emit(p, c);
    }
    0
}

fn lines_eq(a: &str, b: &str, ignore_case: bool) -> bool {
    if !ignore_case {
        a == b
    } else {
        a.eq_ignore_ascii_case(b)
    }
}
