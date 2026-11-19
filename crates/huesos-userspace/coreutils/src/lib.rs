//! Shared runtime, capability checks, and `BOOTFS`/`HxFS`/registry helpers
//! for HuesOS dynamic `/bin/*.elf` coreutils.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use libcanvas::stdio::{
    arg_str, args_count, caps_mask as proc_caps_mask, exit, stderr_str, stdin_read, stdout_str,
    take_cap_handle, CapKind,
};
use libcanvas::{Channel, ErrorCode, Hxfs, HxfsDirectory, Vmo};

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// Collect `argv[1..]` as owned UTF-8 strings.
pub fn collect_args() -> Vec<String> {
    let count = args_count();
    let mut out = Vec::with_capacity(count.saturating_sub(1));
    let mut buf = [0u8; 256];
    for i in 1..count {
        if let Some(s) = arg_str(i, &mut buf) {
            out.push(String::from(s));
        }
    }
    out
}

/// Write UTF-8 text to `stdout`.
pub fn out(s: &str) {
    let _ = stdout_str(s);
}

/// Write UTF-8 line to `stdout`.
pub fn outln(s: &str) {
    let _ = stdout_str(s);
    let _ = stdout_str("\n");
}

/// Write UTF-8 error line to `stderr`.
pub fn errln(s: &str) {
    let _ = stderr_str(s);
    let _ = stderr_str("\n");
}

/// Read all bytes from `stdin` until `PeerClosed` EOF.
pub fn read_all_stdin() -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stdin_read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    all
}

/// Require read access to `HxFS` (`caps_mask::HXFS_RO`).
pub fn check_hxfs_ro() -> Result<(), i32> {
    if (proc_caps_mask() & caps_mask::HXFS_RO) == 0 {
        errln("AccessDenied: HxFS read capability withheld (@caps hxfs=none)");
        return Err(1);
    }
    Ok(())
}

/// Require write access to `HxFS` (`caps_mask::HXFS_RW`).
pub fn check_hxfs_rw() -> Result<(), i32> {
    let mask = proc_caps_mask();
    if (mask & caps_mask::HXFS_RW) == 0 || (mask & caps_mask::HXFS_RO) == 0 {
        errln("AccessDenied: HxFS write capability withheld (@caps hxfs=ro|none)");
        return Err(1);
    }
    Ok(())
}

/// Require read access to `BOOTFS` (`caps_mask::BOOTFS_RO`).
pub fn check_bootfs_ro() -> Result<(), i32> {
    if (proc_caps_mask() & caps_mask::BOOTFS_RO) == 0 {
        errln("AccessDenied: BOOTFS read capability withheld (@caps bootfs=none)");
        return Err(1);
    }
    Ok(())
}

/// Require read-only `DriverManager` query access (`caps_mask::QUERY_RO`).
pub fn check_query_ro() -> Result<(), i32> {
    if (proc_caps_mask() & caps_mask::QUERY_RO) == 0 {
        errln("AccessDenied: DriverManager query capability withheld");
        return Err(1);
    }
    Ok(())
}

/// Take granted `Hxfs` service handle if present.
pub fn take_hxfs() -> Option<Hxfs> {
    take_cap_handle(CapKind::HxfsService).map(|h| Hxfs::from_channel(Channel::from_handle(h)))
}

/// Take granted `HxfsDirectory` handle if present.
pub fn take_hxfs_dir() -> Option<HxfsDirectory> {
    take_cap_handle(CapKind::HxfsDir).map(|h| HxfsDirectory::from_channel(Channel::from_handle(h)))
}

/// Take granted `BOOTFS` VMO if present and permitted by `caps_mask`.
pub fn take_bootfs() -> Option<Vmo> {
    if (proc_caps_mask() & caps_mask::BOOTFS_RO) == 0 {
        return None;
    }
    take_cap_handle(CapKind::BootfsRo).map(Vmo::from_handle)
}

/// Take granted `DriverManager` query channel if present.
pub fn take_registry() -> Option<Channel> {
    if (proc_caps_mask() & caps_mask::QUERY_RO) == 0 {
        return None;
    }
    take_cap_handle(CapKind::Registry).map(Channel::from_handle)
}

/// Normalize a path relative to `/` (or `cwd` if supplied).
pub fn normalize_path(raw: &str) -> String {
    if raw.is_empty() {
        return String::from("/");
    }
    if raw.starts_with('/') {
        String::from(raw)
    } else {
        format!("/{raw}")
    }
}

/// Parse `HBOOTFS1` entries `(path, offset, len)`.
pub fn iter_bootfs_entries(vmo: &Vmo) -> Vec<(String, u64, u64)> {
    let mut entries = Vec::new();
    let mut hdr = [0u8; BOOTFS_HEADER_SIZE as usize];
    if vmo.read(0, &mut hdr) != Ok(hdr.len()) || &hdr[..8] != BOOTFS_MAGIC {
        return entries;
    }
    let count = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    for idx in 0..count {
        let off = BOOTFS_HEADER_SIZE + u64::from(idx) * BOOTFS_ENTRY_SIZE;
        if vmo.read(off, &mut raw) != Ok(raw.len()) {
            break;
        }
        let plen = raw[..BOOTFS_PATH_SIZE]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BOOTFS_PATH_SIZE);
        if let Ok(p) = core::str::from_utf8(&raw[..plen]) {
            let meta = &raw[BOOTFS_PATH_SIZE..];
            let eoff = u64::from_le_bytes([
                meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
            ]);
            let elen = u64::from_le_bytes([
                meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14], meta[15],
            ]);
            entries.push((String::from(p), eoff, elen));
        }
    }
    entries
}

/// Issue a `query:*` request to `DriverManager` over `CapKind::Registry` and write TSV to `stdout`.
pub fn run_registry_query(cmd_name: &str, req: &[u8]) -> i32 {
    if let Err(code) = check_query_ro() {
        return code;
    }
    let Some(reg) = take_registry() else {
        errln(&format!(
            "{cmd_name}: DriverManager query channel unavailable"
        ));
        return 1;
    };
    if let Err(e) = reg.write(req) {
        errln(&format!("{cmd_name}: query write failed: {}", e.as_str()));
        return 1;
    }
    let mut buf = [0u8; 4096];
    for _ in 0..200 {
        match reg.read_into(&mut buf) {
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                out(text.as_ref());
                if !text.ends_with('\n') {
                    out("\n");
                }
                return 0;
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => {
                errln(&format!("{cmd_name}: query read failed: {}", e.as_str()));
                return 1;
            }
        }
    }
    errln(&format!("{cmd_name}: query timed out"));
    1
}

/// Exit process cleanly, flushing stdio `PeerClosed` EOF.
pub fn finish(code: i32) -> ! {
    exit(code)
}

/// Define SysV `_start`, `ScudoHeap` allocator, and panic handler for one coreutil binary.
#[macro_export]
macro_rules! coreutil_entry {
    ($main_fn:path) => {
        #[global_allocator]
        static ALLOCATOR: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap;

        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "and rsp, -16",
                "call {entry}",
                "ud2",
                entry = sym _coreutil_entry_trampoline,
            );
        }

        extern "C" fn _coreutil_entry_trampoline() -> ! {
            let code = $main_fn();
            $crate::finish(code)
        }

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
            $crate::errln("coreutil panic");
            $crate::finish(1)
        }
    };
}
