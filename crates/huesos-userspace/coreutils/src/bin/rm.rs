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
    let mut recursive = false;
    let mut force = false;
    let mut paths: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-r" | "-R" => recursive = true,
            "-f" => force = true,
            "-rf" | "-fr" => {
                recursive = true;
                force = true;
            }
            "--" => {}
            other => paths.push(other),
        }
    }
    if paths.is_empty() {
        if force {
            return 0;
        }
        cu::errln("usage: rm [-r] [-f] <path>...");
        return 1;
    }
    let mut exit_code = 0;
    for raw in paths {
        let path = cu::normalize_path(raw);
        if let Err(e) = remove_entry(&path, recursive, force) {
            if !force {
                cu::errln(&format!("rm '{path}': {e}"));
                exit_code = 1;
            }
        }
    }
    let _ = huesos_std::fs::sync_all();
    exit_code
}

fn remove_entry(path: &str, recursive: bool, force: bool) -> huesos_std::error::Result<()> {
    let meta = match huesos_std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if force && e.kind() == huesos_std::error::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.is_dir() && recursive {
        if let Ok(entries) = huesos_std::fs::list(path) {
            for entry in entries {
                let child = if path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{path}/{}", entry.name)
                };
                remove_entry(&child, true, force)?;
            }
        }
    }
    huesos_std::fs::remove(path)
}
