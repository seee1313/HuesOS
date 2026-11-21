#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let args = cu::collect_args();
    let Some(path_arg) = args.first() else {
        cu::errln("usage: write <path> [text...]");
        return 1;
    };
    let path = cu::normalize_path(path_arg);
    let data: Vec<u8> = if args.len() > 1 && args[1] != "-" {
        let mut s = args[1..].join(" ");
        s.push('\n');
        s.into_bytes()
    } else {
        cu::read_all_stdin()
    };

    match huesos_std::fs::write(&path, &data) {
        Ok(()) => 0,
        Err(e) => {
            cu::errln(&format!("write '{path}': {e}"));
            1
        }
    }
}
