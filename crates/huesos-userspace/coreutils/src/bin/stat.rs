#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let mut follow = true;
    let mut raw_path: Option<&str> = None;
    for arg in args.iter() {
        match arg.as_str() {
            "-P" | "--no-dereference" => follow = false,
            "-L" | "--dereference" => follow = true,
            other => raw_path = Some(other),
        }
    }
    let Some(arg) = raw_path else {
        cu::errln("usage: stat [-L|-P] <path>");
        return 1;
    };
    let path = cu::normalize_path(arg);
    let mask = proc_caps_mask();
    let allow_hxfs = (mask & caps_mask::HXFS_RO) != 0;
    let allow_bootfs = (mask & caps_mask::BOOTFS_RO) != 0;
    if !allow_hxfs && !allow_bootfs {
        cu::errln("AccessDenied: HxFS and BOOTFS read capabilities withheld");
        return 1;
    }

    if allow_hxfs {
        let meta_res = if follow {
            huesos_std::fs::metadata(&path).or_else(|_| huesos_std::fs::symlink_metadata(&path))
        } else {
            huesos_std::fs::symlink_metadata(&path)
        };
        if let Ok(meta) = meta_res {
            cu::outln("path\tsource\ttype\tsize\tmode");
            let mode_str = format!("0{:03o}", meta.mode() & 0o7777);
            if meta.is_dir() {
                cu::outln(&format!("{path}\thxfs\tdir\t-\t{mode_str}"));
            } else if meta.is_symlink() {
                cu::outln(&format!(
                    "{path}\thxfs\tsymlink\t{}\t{mode_str}",
                    meta.len()
                ));
            } else {
                cu::outln(&format!("{path}\thxfs\tfile\t{}\t{mode_str}", meta.len()));
            }
            return 0;
        }
    }

    if let Some(vmo) = cu::take_bootfs() {
        for (bpath, _off, len) in cu::iter_bootfs_entries(&vmo) {
            if bpath == path {
                cu::outln("path\tsource\ttype\tsize\tmode");
                cu::outln(&format!("{path}\tbootfs\tfile\t{len}\t0644"));
                return 0;
            }
        }
    }

    cu::errln(&format!("stat: '{path}' not found"));
    1
}
