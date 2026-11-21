//! `/bin/cp.elf` — copy files, directories, and symbolic links into HxFS.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;
use libcanvas::Vmo;

cu::coreutil_entry!(run);

fn run() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let args = cu::collect_args();
    let mut recursive = false;
    let mut no_deref = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-r" | "-R" | "--recursive" => {
                recursive = true;
                no_deref = true;
            }
            "-P" | "--no-dereference" => no_deref = true,
            "-L" | "--dereference" => no_deref = false,
            "-a" => {
                recursive = true;
                no_deref = true;
            }
            "--" => {}
            other => operands.push(other),
        }
    }
    if operands.len() < 2 {
        cu::errln("usage: cp [-r] [-P|-L] <src>... <dst>");
        return 1;
    }
    let mask = proc_caps_mask();
    let bootfs = if (mask & caps_mask::BOOTFS_RO) != 0 {
        cu::take_bootfs()
    } else {
        None
    };

    let dst_raw = cu::normalize_path(operands[operands.len() - 1]);
    let srcs = &operands[..operands.len() - 1];
    let dst_is_dir = huesos_std::fs::metadata(&dst_raw)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if srcs.len() > 1 && !dst_is_dir {
        cu::errln(&format!("cp: target '{dst_raw}' is not a directory"));
        return 1;
    }

    let mut exit_code = 0;
    for raw_src in srcs {
        let src = cu::normalize_path(raw_src);
        let dst = if dst_is_dir {
            let leaf = src.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
            if dst_raw == "/" {
                format!("/{leaf}")
            } else {
                format!("{dst_raw}/{leaf}")
            }
        } else {
            dst_raw.clone()
        };
        if let Err(msg) = copy_entry(&src, &dst, recursive, no_deref, bootfs.as_ref()) {
            cu::errln(&format!("cp '{src}' -> '{dst}': {msg}"));
            exit_code = 1;
        }
    }
    let _ = huesos_std::fs::sync_all();
    exit_code
}

fn copy_entry(
    src: &str,
    dst: &str,
    recursive: bool,
    no_deref: bool,
    bootfs: Option<&Vmo>,
) -> Result<(), alloc::string::String> {
    if src == dst {
        return Err(alloc::string::String::from(
            "source and destination are identical",
        ));
    }
    let hxfs_meta = if no_deref {
        huesos_std::fs::symlink_metadata(src)
    } else {
        huesos_std::fs::metadata(src)
    };
    if let Ok(meta) = hxfs_meta {
        if meta.is_symlink() {
            let target = huesos_std::fs::read_link(src).map_err(|e| format!("{e}"))?;
            if huesos_std::fs::symlink_metadata(dst).is_ok() {
                let _ = huesos_std::fs::remove(dst);
            }
            huesos_std::fs::symlink(&target, dst).map_err(|e| format!("{e}"))?;
            return Ok(());
        }
        if meta.is_dir() {
            if !recursive {
                return Err(alloc::string::String::from(
                    "-r not specified; omitting directory",
                ));
            }
            if !huesos_std::fs::metadata(dst)
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                let d = huesos_std::fs::create_dir(dst).map_err(|e| format!("{e}"))?;
                let _ = d.fsync();
            }
            let _ = huesos_std::fs::set_permissions(dst, meta.mode());
            let entries = huesos_std::fs::list(src).map_err(|e| format!("{e}"))?;
            for entry in entries {
                let child_src = if src == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{src}/{}", entry.name)
                };
                let child_dst = if dst == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{dst}/{}", entry.name)
                };
                copy_entry(&child_src, &child_dst, true, no_deref, bootfs)?;
            }
            return Ok(());
        }
        let mut reader = huesos_std::fs::File::open(src).map_err(|e| format!("{e}"))?;
        let mut writer = huesos_std::fs::File::create(dst).map_err(|e| format!("{e}"))?;
        let mut chunk = [0u8; 4096];
        loop {
            let n = reader.read(&mut chunk).map_err(|e| format!("{e}"))?;
            if n == 0 {
                break;
            }
            let mut written = 0usize;
            while written < n {
                let w = writer
                    .write(&chunk[written..n])
                    .map_err(|e| format!("{e}"))?;
                if w == 0 {
                    return Err(alloc::string::String::from("short write"));
                }
                written += w;
            }
        }
        writer.fsync().map_err(|e| format!("{e}"))?;
        let _ = huesos_std::fs::set_permissions(dst, meta.mode());
        return Ok(());
    }

    if let Some(vmo) = bootfs {
        for (bpath, off, len) in cu::iter_bootfs_entries(vmo) {
            if bpath == src {
                let mut writer = huesos_std::fs::File::create(dst).map_err(|e| format!("{e}"))?;
                let mut remaining = len;
                let mut cur_off = off;
                let mut chunk = [0u8; 4096];
                while remaining > 0 {
                    let want = (remaining as usize).min(chunk.len());
                    vmo.read(cur_off, &mut chunk[..want])
                        .map_err(|_| alloc::string::String::from("bootfs read error"))?;
                    let mut written = 0usize;
                    while written < want {
                        let w = writer
                            .write(&chunk[written..want])
                            .map_err(|e| format!("{e}"))?;
                        if w == 0 {
                            return Err(alloc::string::String::from("short write"));
                        }
                        written += w;
                    }
                    cur_off += want as u64;
                    remaining -= want as u64;
                }
                writer.fsync().map_err(|e| format!("{e}"))?;
                return Ok(());
            }
        }
    }

    Err(alloc::string::String::from("not found"))
}
