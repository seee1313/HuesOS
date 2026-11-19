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
    let Some(arg) = args.first() else {
        cu::errln("usage: stat <path>");
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
        if let Some(svc) = cu::take_hxfs() {
            if let Ok(file) = svc.open_file(&path) {
                let sz = file.size().unwrap_or(0);
                cu::outln("path\tsource\ttype\tsize");
                cu::outln(&format!("{path}\thxfs\tfile\t{sz}"));
                return 0;
            }
            if svc.open_dir(&path).is_ok() {
                cu::outln("path\tsource\ttype\tsize");
                cu::outln(&format!("{path}\thxfs\tdir\t-"));
                return 0;
            }
        } else if let Some(dir) = cu::take_hxfs_dir() {
            let rel = path.trim_start_matches('/');
            if let Ok(file) = dir.open_file(rel) {
                let sz = file.size().unwrap_or(0);
                cu::outln("path\tsource\ttype\tsize");
                cu::outln(&format!("{path}\thxfs\tfile\t{sz}"));
                return 0;
            }
            if path == "/" || dir.open_dir(rel).is_ok() {
                cu::outln("path\tsource\ttype\tsize");
                cu::outln(&format!("{path}\thxfs\tdir\t-"));
                return 0;
            }
        }
    }

    if let Some(vmo) = cu::take_bootfs() {
        for (bpath, _off, len) in cu::iter_bootfs_entries(&vmo) {
            if bpath == path {
                cu::outln("path\tsource\ttype\tsize");
                cu::outln(&format!("{path}\tbootfs\tfile\t{len}"));
                return 0;
            }
        }
    }

    cu::errln(&format!("stat: '{path}' not found"));
    1
}
