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
        cu::errln("usage: touch <path>");
        return 1;
    };
    let path = cu::normalize_path(arg);
    if huesos_std::fs::exists(&path) {
        return 0;
    }
    match huesos_std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&path)
    {
        Ok(f) => {
            let _ = f.fsync();
            0
        }
        Err(e) => {
            cu::errln(&format!("touch '{path}': {e}"));
            1
        }
    }
}
