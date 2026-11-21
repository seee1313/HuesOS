#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(arg) = args.first() else {
        let bytes = cu::read_all_stdin();
        let text = String::from_utf8_lossy(&bytes);
        cu::out(text.as_ref());
        return 0;
    };
    if arg == "-" {
        let bytes = cu::read_all_stdin();
        let text = String::from_utf8_lossy(&bytes);
        cu::out(text.as_ref());
        return 0;
    }

    let path = cu::normalize_path(arg);
    let mask = proc_caps_mask();
    let allow_hxfs = (mask & caps_mask::HXFS_RO) != 0;
    let allow_bootfs = (mask & caps_mask::BOOTFS_RO) != 0;
    if !allow_hxfs && !allow_bootfs {
        cu::errln("AccessDenied: HxFS and BOOTFS read capabilities withheld");
        return 1;
    }

    if allow_hxfs {
        if let Ok(mut file) = huesos_std::fs::File::open(&path) {
            if let Ok(buf) = file.read_to_end() {
                let s = String::from_utf8_lossy(&buf);
                cu::out(s.as_ref());
                if !s.is_empty() && !s.ends_with('\n') {
                    cu::out("\n");
                }
                return 0;
            }
        }
    }

    if let Some(vmo) = cu::take_bootfs() {
        for (bpath, off, len) in cu::iter_bootfs_entries(&vmo) {
            if bpath == path {
                let take = len.min(64 * 1024) as usize;
                let mut buf = vec![0u8; take];
                if vmo.read(off, &mut buf) == Ok(take) {
                    let s = String::from_utf8_lossy(&buf);
                    cu::out(s.as_ref());
                    if !s.ends_with('\n') {
                        cu::out("\n");
                    }
                    return 0;
                }
            }
        }
    }

    cu::errln(&format!("cat: '{path}' not found"));
    1
}
