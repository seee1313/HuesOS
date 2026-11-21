//! `/bin/readlink.elf` — print symbolic link target or canonicalized path.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    if let Err(code) = cu::check_hxfs_ro() {
        return code;
    }
    let args = cu::collect_args();
    let mut canonicalize = false;
    let mut no_newline = false;
    let mut paths: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-f" | "-e" | "-m" => canonicalize = true,
            "-n" => no_newline = true,
            "-fn" | "-nf" => {
                canonicalize = true;
                no_newline = true;
            }
            "--" => {}
            other => paths.push(other),
        }
    }
    let Some(first) = paths.first() else {
        cu::errln("usage: readlink [-f] [-n] <path>");
        return 1;
    };
    let path = cu::normalize_path(first);
    let resolved = if canonicalize {
        match canonicalize_path(&path, 8) {
            Some(p) => p,
            None => return 1,
        }
    } else {
        match huesos_std::fs::read_link(&path) {
            Ok(target) => target,
            Err(_) => return 1,
        }
    };
    if no_newline {
        cu::out(&resolved);
    } else {
        cu::outln(&resolved);
    }
    0
}

fn canonicalize_path(path: &str, max_hops: usize) -> Option<String> {
    let mut current = cu::normalize_path(path);
    for _ in 0..=max_hops {
        let meta = huesos_std::fs::symlink_metadata(&current).ok()?;
        if !meta.is_symlink() {
            return Some(current);
        }
        let target = huesos_std::fs::read_link(&current).ok()?;
        current = if target.starts_with('/') {
            cu::normalize_path(&target)
        } else {
            let parent = match current.rsplit_once('/') {
                Some(("", _)) | None => "/",
                Some((p, _)) => p,
            };
            cu::normalize_path(&format!("{parent}/{target}"))
        };
    }
    None
}
