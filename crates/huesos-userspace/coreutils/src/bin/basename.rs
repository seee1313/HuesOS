//! `/bin/basename.elf` — strip directory and optional suffix from file name.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(raw) = args.first() else {
        cu::errln("usage: basename <path> [suffix]");
        return 1;
    };
    let trimmed = raw.trim_end_matches('/');
    let base = if trimmed.is_empty() {
        "/"
    } else {
        trimmed.rsplit('/').next().unwrap_or(trimmed)
    };
    let out = if let Some(suffix) = args.get(1) {
        if base.len() > suffix.len() && base.ends_with(suffix.as_str()) {
            String::from(&base[..base.len() - suffix.len()])
        } else {
            String::from(base)
        }
    } else {
        String::from(base)
    };
    cu::outln(&out);
    0
}
