//! `/bin/dirname.elf` — strip last component from file name.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(raw) = args.first() else {
        cu::errln("usage: dirname <path>");
        return 1;
    };
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        cu::outln("/");
        return 0;
    }
    match trimmed.rsplit_once('/') {
        None => cu::outln("."),
        Some(("", _)) => cu::outln("/"),
        Some((parent, _)) => {
            let p = parent.trim_end_matches('/');
            cu::outln(if p.is_empty() { "/" } else { p });
        }
    }
    0
}
