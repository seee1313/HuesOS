//! `/bin/tee.elf` — read from stdin and write to stdout and HxFS files.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let mut append = false;
    let mut files: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-a" | "--append" => append = true,
            "--" => {}
            other => files.push(other),
        }
    }

    if !files.is_empty() {
        if let Err(code) = cu::check_hxfs_rw() {
            return code;
        }
    }

    let data = cu::read_all_stdin();
    let _ = huesos_std::io::write_all(&mut huesos_std::io::stdout(), &data);

    let mut exit_code = 0;
    for raw in files {
        let path = cu::normalize_path(raw);
        let opts = huesos_std::fs::OpenOptions::new().write(true).create(true);
        let opts = if append {
            opts.append(true)
        } else {
            opts.truncate(true)
        };
        match opts.open(&path) {
            Ok(mut f) => {
                if let Err(e) = huesos_std::io::write_all(&mut f, &data).and_then(|()| f.fsync()) {
                    cu::errln(&format!("tee '{path}': {e}"));
                    exit_code = 1;
                }
            }
            Err(e) => {
                cu::errln(&format!("tee '{path}': {e}"));
                exit_code = 1;
            }
        }
    }
    if exit_code == 0 {
        let _ = huesos_std::fs::sync_all();
    }
    exit_code
}
