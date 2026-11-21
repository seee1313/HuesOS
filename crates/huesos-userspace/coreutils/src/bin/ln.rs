//! `/bin/ln.elf` — create symbolic links on HxFS.

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
    let mut symbolic = false;
    let mut force = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-s" | "--symbolic" => symbolic = true,
            "-f" | "--force" => force = true,
            "-sf" | "-fs" => {
                symbolic = true;
                force = true;
            }
            "--" => {}
            other => operands.push(other),
        }
    }
    if !symbolic {
        cu::errln("ln: hard links are not supported on HxFS; use 'ln -s <target> <link>'");
        return 1;
    }
    if operands.len() < 2 {
        cu::errln("usage: ln -s [-f] <target> <link>");
        return 1;
    }
    let target = operands[0];
    let mut link_path = cu::normalize_path(operands[1]);
    if let Ok(meta) = huesos_std::fs::metadata(&link_path) {
        if meta.is_dir() {
            let leaf = target.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
            if !leaf.is_empty() {
                link_path = if link_path == "/" {
                    format!("/{leaf}")
                } else {
                    format!("{link_path}/{leaf}")
                };
            }
        }
    }
    if force && huesos_std::fs::symlink_metadata(&link_path).is_ok() {
        let _ = huesos_std::fs::remove(&link_path);
    }
    match huesos_std::fs::symlink(target, &link_path) {
        Ok(()) => {
            let _ = huesos_std::fs::sync_all();
            0
        }
        Err(e) => {
            cu::errln(&format!("ln '{link_path}' -> '{target}': {e}"));
            1
        }
    }
}
