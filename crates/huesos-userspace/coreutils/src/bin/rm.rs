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
        cu::errln("usage: rm <path>");
        return 1;
    };
    let path = cu::normalize_path(arg);
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("rm: HxFS service unavailable");
        return 1;
    };
    match svc.unlink(&path) {
        Ok(()) => {
            let _ = svc.checkpoint();
            0
        }
        Err(e) => {
            cu::errln(&format!("rm '{path}': {}", e.as_str()));
            1
        }
    }
}
