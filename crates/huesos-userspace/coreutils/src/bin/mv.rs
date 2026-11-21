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
    let mut to = cu::normalize_path(&args[1]);
    if let Ok(meta) = huesos_std::fs::metadata(&to) {
        if meta.is_dir() {
            let leaf = from.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
            if !leaf.is_empty() {
                to = if to == "/" {
                    format!("/{leaf}")
                } else {
                    format!("{to}/{leaf}")
                };
            }
        }
    }
    match huesos_std::fs::rename(&from, &to) {
        Ok(()) => {
            if let Some(svc) = cu::take_hxfs() {
                let _ = svc.checkpoint();
            } else if let Some(dir) = cu::take_hxfs_dir() {
                let _ = dir.fsync();
            }
            0
        }
        Err(e) => {
            cu::errln(&format!("mv '{from}' -> '{to}': {e}"));
            1
        }
    }
}
