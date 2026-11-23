//! `/bin/seq.elf` — print a sequence of integers.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let mut sep = String::from("\n");
    let mut nums = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-s" {
            i += 1;
            let Some(s) = args.get(i) else {
                cu::errln("seq: -s requires a separator");
                return 1;
            };
            sep = s.clone();
        } else if let Some(s) = a.strip_prefix("-s") {
            sep = String::from(s);
        } else if let Ok(v) = a.parse::<i64>() {
            nums.push(v);
        } else {
            cu::errln(&format!("seq: invalid number '{a}'"));
            return 1;
        }
        i += 1;
    }

    let (first, step, last) = match nums.as_slice() {
        [last] => (1, 1, *last),
        [first, last] => (*first, 1, *last),
        [first, step, last] => (*first, *step, *last),
        _ => {
            cu::errln("usage: seq [-s SEP] [FIRST [INCREMENT]] LAST");
            return 1;
        }
    };
    if step == 0 {
        cu::errln("seq: zero increment");
        return 1;
    }

    let mut cur = first;
    let mut printed = false;
    let mut buf = String::with_capacity(4096);
    while (step > 0 && cur <= last) || (step < 0 && cur >= last) {
        if printed {
            buf.push_str(&sep);
        }
        let _ = core::fmt::Write::write_fmt(&mut buf, format_args!("{cur}"));
        printed = true;
        if buf.len() >= 4096 {
            cu::out(&buf);
            buf.clear();
        }
        match cur.checked_add(step) {
            Some(next) => cur = next,
            None => break,
        }
    }
    if printed {
        buf.push('\n');
    }
    if !buf.is_empty() {
        cu::out(&buf);
    }
    0
}
