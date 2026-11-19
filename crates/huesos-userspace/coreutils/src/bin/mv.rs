#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let args = cu::collect_args();
    if args.len() < 2 {
        cu::errln("usage: mv <from> <to>");
        return 1;
    }
    let from = cu::normalize_path(&args[0]);
    let to = cu::normalize_path(&args[1]);
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("mv: HxFS service unavailable");
        return 1;
    };
    match svc.rename(&from, &to) {
        Ok(()) => {
            let _ = svc.checkpoint();
            0
        }
        Err(e) => {
            cu::errln(&format!("mv '{from}' -> '{to}': {}", e.as_str()));
            1
        }
    }
}
