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

    let Some(svc) = cu::take_hxfs() else {
        cu::errln("write: HxFS service unavailable");
        return 1;
    };
    let file = match svc.open_file(&path) {
        Ok(f) => f,
        Err(_) => match svc.create_file(&path) {
            Ok(f) => f,
            Err(e) => {
                cu::errln(&format!("write create '{path}': {}", e.as_str()));
                return 1;
            }
        },
    };
    if let Err(e) = file.truncate(0) {
        cu::errln(&format!("write truncate '{path}': {}", e.as_str()));
        return 1;
    }
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + 2048).min(data.len());
        if let Err(e) = file.write_at(off as u64, &data[off..end]) {
            cu::errln(&format!("write '{path}': {}", e.as_str()));
            return 1;
        }
        off = end;
    }
    if let Err(e) = file.fsync() {
        cu::errln(&format!("write fsync '{path}': {}", e.as_str()));
        return 1;
    }
    0
}
