//! `/bin/chmod.elf` — change POSIX mode bits (`0o7777`) on HxFS objects.

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
    let mut operands: Vec<&str> = Vec::new();
    for arg in args.iter() {
        match arg.as_str() {
            "-R" | "--recursive" => recursive = true,
            "--" => {}
            other => operands.push(other),
        }
    }
    if operands.len() < 2 {
        cu::errln("usage: chmod [-R] <mode> <path>...");
        return 1;
    }
    let mode_spec = operands[0];
    let mut exit_code = 0;
    for raw in &operands[1..] {
        let path = cu::normalize_path(raw);
        if let Err(e) = apply_chmod(&path, mode_spec, recursive) {
            cu::errln(&format!("chmod '{path}': {e}"));
            exit_code = 1;
        }
    }
    let _ = huesos_std::fs::sync_all();
    exit_code
}

fn apply_chmod(path: &str, spec: &str, recursive: bool) -> huesos_std::error::Result<()> {
    let meta = huesos_std::fs::metadata(path)?;
    let new_mode = compute_mode(meta.mode(), spec)
        .ok_or_else(|| huesos_std::error::Error::new(huesos_std::error::ErrorKind::InvalidInput))?;
    huesos_std::fs::set_permissions(path, new_mode)?;
    if recursive && meta.is_dir() {
        if let Ok(entries) = huesos_std::fs::list(path) {
            for entry in entries {
                if entry.kind == huesos_std::fs::EntryKind::Symlink {
                    continue;
                }
                let child = if path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{path}/{}", entry.name)
                };
                apply_chmod(&child, spec, true)?;
            }
        }
    }
    Ok(())
}

fn compute_mode(current: u32, spec: &str) -> Option<u32> {
    if let Ok(octal) = u32::from_str_radix(spec, 8) {
        if octal <= 0o7777 {
            return Some(octal);
        }
    }
    let mut mode = current & 0o7777;
    for clause in spec.split(',') {
        let bytes = clause.as_bytes();
        let mut idx = 0usize;
        let mut who_mask = 0u32;
        while idx < bytes.len() {
            match bytes[idx] {
                b'u' => who_mask |= 0o700,
                b'g' => who_mask |= 0o070,
                b'o' => who_mask |= 0o007,
                b'a' => who_mask |= 0o777,
                _ => break,
            }
            idx += 1;
        }
        if who_mask == 0 {
            who_mask = 0o777;
        }
        if idx >= bytes.len() {
            return None;
        }
        let op = bytes[idx];
        idx += 1;
        let mut perm_bits = 0u32;
        while idx < bytes.len() {
            match bytes[idx] {
                b'r' => perm_bits |= 0o444,
                b'w' => perm_bits |= 0o222,
                b'x' => perm_bits |= 0o111,
                b's' => perm_bits |= 0o6000,
                b't' => perm_bits |= 0o1000,
                _ => return None,
            }
            idx += 1;
        }
        let masked = perm_bits & (who_mask | 0o7000);
        match op {
            b'+' => mode |= masked,
            b'-' => mode &= !masked,
            b'=' => mode = (mode & !who_mask) | masked,
            _ => return None,
        }
    }
    Some(mode & 0o7777)
}
