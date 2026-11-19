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
    let Some(arg) = args.first() else {
        cu::errln("usage: mkdir <path>");
        return 1;
    };
    let path = cu::normalize_path(arg);
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("mkdir: HxFS service unavailable");
        return 1;
    };
    match svc.mkdir(&path) {
        Ok(d) => {
            let _ = d.fsync();
            0
        }
        Err(e) => {
            cu::errln(&format!("mkdir '{path}': {}", e.as_str()));
            1
        }
    }
}
