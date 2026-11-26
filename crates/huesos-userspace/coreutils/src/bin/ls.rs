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

    let bootfs = if allow_bootfs {
        cu::take_bootfs()
    } else {
        None
    };

    let mut rows: Vec<String> = Vec::new();
    let mut found_any = false;

    if allow_hxfs {
        let row_source = if path == "/mnt" {
            "vfs"
        } else if huesos_std::usb_fat::split_usb_mount_path(&path).is_some() {
            "vfat"
        } else {
            "hxfs"
        };
        if let Ok(entries) = huesos_std::fs::list(&path) {
            found_any = true;
            for entry in entries {
                let kind = match entry.kind {
                    huesos_std::fs::EntryKind::Dir => "dir",
                    huesos_std::fs::EntryKind::File => "file",
                    huesos_std::fs::EntryKind::Symlink => "symlink",
                    huesos_std::fs::EntryKind::Other => "entry",
                };
                let size = match entry.size {
                    Some(sz) => format!("{sz}"),
                    None => String::from("-"),
                };
                rows.push(format!("{}\t{kind}\t{size}\t{row_source}", entry.name));
            }
            if path == "/"
                && !rows.iter().any(|r| r.starts_with("mnt\t"))
                && huesos_std::usb_fat::is_mounted()
            {
                rows.push(String::from("mnt\tdir\t-\tvfs"));
            }
        } else if let Ok(meta) = huesos_std::fs::symlink_metadata(&path) {
            found_any = true;
            let leaf = path.rsplit('/').next().unwrap_or(&path);
            let kind = match meta.kind {
                huesos_std::fs::EntryKind::Dir => "dir",
                huesos_std::fs::EntryKind::File => "file",
                huesos_std::fs::EntryKind::Symlink => "symlink",
                huesos_std::fs::EntryKind::Other => "entry",
            };
            rows.push(format!("{leaf}\t{kind}\t{}\t{row_source}", meta.len()));
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
            if bpath == path && !found_any {
                found_any = true;
                let leaf = bpath.rsplit('/').next().unwrap_or(&bpath);
                rows.push(format!("{leaf}\tfile\t{blen}\tbootfs"));
                break;
            }
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
