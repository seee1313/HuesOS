#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let path = cu::normalize_path(args.first().map(String::as_str).unwrap_or("/"));

    let mask = proc_caps_mask();
    let allow_hxfs = (mask & caps_mask::HXFS_RO) != 0;
    let allow_bootfs = (mask & caps_mask::BOOTFS_RO) != 0;

    if !allow_hxfs && !allow_bootfs {
        cu::errln("AccessDenied: both HxFS and BOOTFS capabilities withheld");
        return 1;
    }

    let hxfs = if allow_hxfs { cu::take_hxfs() } else { None };
    let hxfs_dir = if allow_hxfs {
        cu::take_hxfs_dir()
    } else {
        None
    };
    let bootfs = if allow_bootfs {
        cu::take_bootfs()
    } else {
        None
    };

    let mut rows: Vec<String> = Vec::new();
    let mut found_any = false;

    if allow_hxfs {
        let dir_opt = if let Some(svc) = hxfs {
            svc.open_dir(&path).ok()
        } else if let Some(scoped) = hxfs_dir {
            if path == "/" {
                None
            } else {
                scoped.open_dir(path.trim_start_matches('/')).ok()
            }
        } else {
            None
        };

        // The scoped handle is the subtree root itself, so `/` lists through
        // the handle as granted instead of asking it to open a path above it.
        if path == "/" && hxfs.is_none() {
            if let Some(scoped) = hxfs_dir {
                found_any = true;
                let mut raw = [0u8; 4096];
                if let Ok(bytes) = scoped.list(&mut raw) {
                    if let Ok(text) = core::str::from_utf8(bytes) {
                        for line in text.lines() {
                            let mut parts = line.split_whitespace();
                            let Some(name) = parts.next() else {
                                continue;
                            };
                            let kind = parts.next().unwrap_or("entry");
                            let size = parts.next().unwrap_or("-");
                            rows.push(format!("{name}\t{kind}\t{size}\thxfs"));
                        }
                    }
                }
            }
        }

        if let Some(dir) = dir_opt {
            found_any = true;
            let mut raw = [0u8; 4096];
            if let Ok(bytes) = dir.list(&mut raw) {
                if let Ok(text) = core::str::from_utf8(bytes) {
                    for line in text.lines() {
                        let mut parts = line.split_whitespace();
                        let Some(name) = parts.next() else {
                            continue;
                        };
                        let kind = parts.next().unwrap_or("entry");
                        let size = parts.next().unwrap_or("-");
                        rows.push(format!("{name}\t{kind}\t{size}\thxfs"));
                    }
                }
            }
        }
    }

    if let Some(vmo) = bootfs.as_ref() {
        let prefix = if path == "/" {
            String::from("/")
        } else {
            format!("{path}/")
        };
        let mut seen_dirs: Vec<String> = Vec::new();
        for (bpath, _off, blen) in cu::iter_bootfs_entries(vmo) {
            if let Some(rest) = bpath.strip_prefix(&prefix) {
                found_any = true;
                if let Some((dir_name, _)) = rest.split_once('/') {
                    let d = String::from(dir_name);
                    if !seen_dirs.contains(&d) {
                        seen_dirs.push(d.clone());
                        rows.push(format!("{d}\tdir\t-\tbootfs"));
                    }
                } else if !rest.is_empty() {
                    rows.push(format!("{rest}\tfile\t{blen}\tbootfs"));
                }
            }
        }
    }

    if !found_any {
        cu::errln(&format!("ls: '{path}' not found"));
        return 1;
    }

    cu::outln("name\ttype\tsize\tsource");
    for row in rows {
        cu::outln(&row);
    }
    0
}
