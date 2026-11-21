#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let args = cu::collect_args();
    let mut parents = false;
    let mut paths: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            other => paths.push(other),
        }
    }
    if paths.is_empty() {
        cu::errln("usage: mkdir [-p] <path>...");
        return 1;
    }
    let mut exit_code = 0;
    for raw in paths {
        let path = cu::normalize_path(raw);
        if parents {
            if let Err(e) = mkdir_parents(&path) {
                cu::errln(&format!("mkdir '{path}': {e}"));
                exit_code = 1;
            }
        } else {
            match huesos_std::fs::create_dir(&path) {
                Ok(d) => {
                    let _ = d.fsync();
                }
                Err(e) => {
                    cu::errln(&format!("mkdir '{path}': {e}"));
                    exit_code = 1;
                }
            }
        }
    }
    let _ = huesos_std::fs::sync_all();
    exit_code
}

fn mkdir_parents(path: &str) -> huesos_std::error::Result<()> {
    if path == "/" || path.is_empty() {
        return Ok(());
    }
    let mut current = String::new();
    for part in path.split('/').filter(|s| !s.is_empty()) {
        current.push('/');
        current.push_str(part);
        if let Ok(meta) = huesos_std::fs::metadata(&current) {
            if meta.is_dir() {
                continue;
            }
        }
        match huesos_std::fs::create_dir(&current) {
            Ok(d) => {
                let _ = d.fsync();
            }
            Err(e) => {
                if let Ok(meta) = huesos_std::fs::metadata(&current) {
                    if meta.is_dir() {
                        continue;
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(())
}
