//! Standard streams (`stdin`/`stdout`/`stderr`), `argc`/`argv`, and
//! attenuated process capability handles (`@caps(...)`).
//!
//! When built with `dyn-client`, calls forward to `libcanvas.so` so every DSO
//! and executable in the process shares one authoritative stream/argv/caps table.

use crate::handle::Handle;
use crate::{ErrorCode, HandleValue, Result, INVALID_HANDLE};

/// Maximum per-message chunk size for `stdin`/`stdout`/`stderr` Channel writes.
pub const STDIO_CHUNK_BYTES: usize = 4096;

/// Capability handle slots passed via process bootstrap (`AT_HUESOS_*`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapKind {
    /// Standard input channel.
    Stdin = 0,
    /// Standard output channel.
    Stdout = 1,
    /// Standard error channel.
    Stderr = 2,
    /// Attenuated HxFS directory channel (`@caps(dir=...:ro)` / `AT_HUESOS_HXFS_DIR`).
    HxfsDir = 3,
    /// HxFS service channel (`AT_HUESOS_HXFS_SERVICE`).
    HxfsService = 4,
    /// Block device channel (`AT_HUESOS_BLOCK_DEV`).
    BlockDev = 5,
    /// Framebuffer draw resource handle (`AT_HUESOS_FRAME_DRAW`).
    FrameDraw = 6,
    /// Read-only `BOOTFS` VMO (`AT_HUESOS_LIB_VMO` when `caps_mask::BOOTFS_RO` is set).
    BootfsRo = 7,
    /// `DriverManager` query/registry channel (`AT_HUESOS_REGISTRY`).
    Registry = 8,
    /// `net-service` (`Plan 9 /net`) capability channel (`AT_HUESOS_NET_SERVICE`).
    NetService = 9,
    /// `wlan-service` capability channel (`AT_HUESOS_WLAN_SERVICE`).
    WlanService = 10,
    /// Target PE32+ `.exe` VMO passed to `/lib/ld-pe.so` (`AT_HUESOS_PE_VMO`).
    PeVmo = 11,
    /// Self root VMAR passed to `/lib/ld-pe.so` for mapping `.exe`/`.dll` sections.
    PeSelfVmar = 12,
    /// `btl-service` (`Plan 9 /net/btl`) capability channel (`AT_HUESOS_BTL_SERVICE`).
    BtlService = 13,
    /// `audio-service` (`/dev/audio`) capability channel (`AT_HUESOS_AUDIO_SERVICE`).
    AudioService = 14,
}

#[cfg(not(feature = "dyn-client"))]
mod imp {
    use core::ffi::c_char;
    use core::sync::atomic::{
        AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
    };

    use super::{CapKind, STDIO_CHUNK_BYTES};
    use crate::channel::Channel;
    use crate::handle::Handle;
    use crate::rtld_abi::ProcessBootstrapInfo;
    use crate::{debug, process, ErrorCode, HandleValue, Result, INVALID_HANDLE};
    use huesos_abi::auxv::caps_mask;

    static ARGC: AtomicUsize = AtomicUsize::new(0);
    static ARGV: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());
    static CAPS_MASK: AtomicU64 = AtomicU64::new(caps_mask::ALL_DEFAULT);

    static STDIN_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static STDOUT_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static STDERR_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static HXFS_DIR_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static HXFS_SERVICE_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static BLOCK_DEV_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static FRAME_DRAW_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static BOOTFS_VMO_H: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static REGISTRY_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static NET_SERVICE_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static WLAN_SERVICE_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static BTL_SERVICE_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static AUDIO_SERVICE_CH: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static PE_VMO_H: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static PE_SELF_VMAR_H: AtomicU32 = AtomicU32::new(INVALID_HANDLE);
    static PE_OFFSET: AtomicU64 = AtomicU64::new(0);
    static PE_LEN: AtomicU64 = AtomicU64::new(0);

    static STDIN_LOCK: AtomicBool = AtomicBool::new(false);
    static STDIN_POS: AtomicUsize = AtomicUsize::new(0);
    static STDIN_LEN: AtomicUsize = AtomicUsize::new(0);
    static STDIN_EOF: AtomicBool = AtomicBool::new(false);
    static STDIN_BUF: [AtomicU8; STDIO_CHUNK_BYTES] =
        [const { AtomicU8::new(0) }; STDIO_CHUNK_BYTES];

    fn slot_for(kind: CapKind) -> &'static AtomicU32 {
        match kind {
            CapKind::Stdin => &STDIN_CH,
            CapKind::Stdout => &STDOUT_CH,
            CapKind::Stderr => &STDERR_CH,
            CapKind::HxfsDir => &HXFS_DIR_CH,
            CapKind::HxfsService => &HXFS_SERVICE_CH,
            CapKind::BlockDev => &BLOCK_DEV_CH,
            CapKind::FrameDraw => &FRAME_DRAW_CH,
            CapKind::BootfsRo => &BOOTFS_VMO_H,
            CapKind::Registry => &REGISTRY_CH,
            CapKind::NetService => &NET_SERVICE_CH,
            CapKind::WlanService => &WLAN_SERVICE_CH,
            CapKind::BtlService => &BTL_SERVICE_CH,
            CapKind::AudioService => &AUDIO_SERVICE_CH,
            CapKind::PeVmo => &PE_VMO_H,
            CapKind::PeSelfVmar => &PE_SELF_VMAR_H,
        }
    }

    pub fn set_process_ctx(info: &ProcessBootstrapInfo) {
        ARGC.store(info.argc, Ordering::Release);
        ARGV.store(info.argv.cast_mut(), Ordering::Release);
        CAPS_MASK.store(info.caps_mask, Ordering::Release);
        STDIN_CH.store(info.stdin_ch, Ordering::Release);
        STDOUT_CH.store(info.stdout_ch, Ordering::Release);
        STDERR_CH.store(info.stderr_ch, Ordering::Release);
        HXFS_DIR_CH.store(info.hxfs_dir_ch, Ordering::Release);
        HXFS_SERVICE_CH.store(info.hxfs_service_ch, Ordering::Release);
        BLOCK_DEV_CH.store(info.block_dev_ch, Ordering::Release);
        FRAME_DRAW_CH.store(info.frame_draw_ch, Ordering::Release);
        BOOTFS_VMO_H.store(info.bootfs_vmo, Ordering::Release);
        REGISTRY_CH.store(info.registry_ch, Ordering::Release);
        NET_SERVICE_CH.store(info.net_service_ch, Ordering::Release);
        WLAN_SERVICE_CH.store(info.wlan_service_ch, Ordering::Release);
        BTL_SERVICE_CH.store(info.btl_service_ch, Ordering::Release);
        AUDIO_SERVICE_CH.store(info.audio_service_ch, Ordering::Release);
        PE_VMO_H.store(info.pe_vmo, Ordering::Release);
        PE_SELF_VMAR_H.store(info.pe_self_vmar, Ordering::Release);
        PE_OFFSET.store(info.pe_offset, Ordering::Release);
        PE_LEN.store(info.pe_len, Ordering::Release);
    }

    pub fn pe_image_span() -> (u64, u64) {
        (
            PE_OFFSET.load(Ordering::Acquire),
            PE_LEN.load(Ordering::Acquire),
        )
    }

    pub fn args_count() -> usize {
        ARGC.load(Ordering::Acquire)
    }

    pub fn arg_get(index: usize, out: &mut [u8]) -> Option<usize> {
        let count = ARGC.load(Ordering::Acquire);
        if index >= count {
            return None;
        }
        let argv = ARGV.load(Ordering::Acquire);
        if argv.is_null() {
            return None;
        }
        // SAFETY: `argv` was validated from the initial process stack (`0..argc`)
        // and points to NUL-terminated C strings that remain mapped for the process lifetime.
        let arg_ptr = unsafe { *argv.add(index) };
        if arg_ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: `arg_ptr` is NUL-terminated on the initial stack page (4 KiB bounded).
        unsafe {
            while len < 4096 && *arg_ptr.add(len) != 0 {
                let byte = *arg_ptr.add(len) as u8;
                if len < out.len() {
                    out[len] = byte;
                }
                len += 1;
            }
        }
        Some(len)
    }

    fn write_channel_chunked(slot: &AtomicU32, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let raw_h = slot.load(Ordering::Acquire);
        if raw_h == INVALID_HANDLE {
            debug::write_bytes(data);
            return Ok(data.len());
        }
        let ch = Channel::from_handle(Handle::from_syscall_out(raw_h));
        let mut written = 0usize;
        let result = loop {
            if written >= data.len() {
                break Ok(written);
            }
            let end = (written + STDIO_CHUNK_BYTES).min(data.len());
            match ch.write(&data[written..end]) {
                Ok(()) => written = end,
                Err(ErrorCode::ShouldWait) => process::yield_now(),
                Err(err) => break Err(err),
            }
        };
        let _ = ch.into_handle().into_raw();
        result
    }

    pub fn stdout_write(data: &[u8]) -> Result<usize> {
        write_channel_chunked(&STDOUT_CH, data)
    }

    pub fn stderr_write(data: &[u8]) -> Result<usize> {
        write_channel_chunked(&STDERR_CH, data)
    }

    pub fn stdin_read(out: &mut [u8]) -> Result<usize> {
        stdin_read_mode(out, None)
    }

    /// Read from `stdin`, waiting at most `ticks` scheduler ticks.
    ///
    /// `Err(ErrorCode::TimedOut)` means nothing arrived; a monitor uses it to
    /// redraw on its own schedule instead of parking until the next keystroke.
    pub fn stdin_read_timeout(out: &mut [u8], ticks: u64) -> Result<usize> {
        stdin_read_mode(out, Some(ticks.max(1)))
    }

    fn stdin_read_mode(out: &mut [u8], timeout_ticks: Option<u64>) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let raw_h = STDIN_CH.load(Ordering::Acquire);
        if raw_h == INVALID_HANDLE {
            return Ok(0);
        }
        while STDIN_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            process::yield_now();
        }

        let res = (|| -> Result<usize> {
            let pos = STDIN_POS.load(Ordering::Relaxed);
            let len = STDIN_LEN.load(Ordering::Relaxed);
            if pos < len {
                let take = (len - pos).min(out.len());
                for (i, dst) in out[..take].iter_mut().enumerate() {
                    *dst = STDIN_BUF[pos + i].load(Ordering::Relaxed);
                }
                let next_pos = pos + take;
                if next_pos == len {
                    STDIN_POS.store(0, Ordering::Relaxed);
                    STDIN_LEN.store(0, Ordering::Relaxed);
                } else {
                    STDIN_POS.store(next_pos, Ordering::Relaxed);
                }
                return Ok(take);
            }
            if STDIN_EOF.load(Ordering::Relaxed) {
                return Ok(0);
            }
            let mut tmp = [0u8; STDIO_CHUNK_BYTES];
            let ch = Channel::from_handle(Handle::from_syscall_out(raw_h));
            let read_res = loop {
                let attempt = match timeout_ticks {
                    Some(ticks) => ch.read_into_timeout(&mut tmp, ticks),
                    None => ch.read_into_blocking(&mut tmp),
                };
                match attempt {
                    Ok(n) => break Ok(n),
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                        if timeout_ticks.is_some() {
                            break Err(ErrorCode::TimedOut);
                        }
                        process::yield_now();
                    }
                    Err(ErrorCode::PeerClosed) => {
                        STDIN_EOF.store(true, Ordering::Relaxed);
                        break Ok(0);
                    }
                    Err(err) => break Err(err),
                }
            };
            let _ = ch.into_handle().into_raw();
            let n = read_res?;
            if n == 0 {
                return Ok(0);
            }
            let take = n.min(out.len());
            out[..take].copy_from_slice(&tmp[..take]);
            if take < n {
                for (i, &b) in tmp[take..n].iter().enumerate() {
                    STDIN_BUF[i].store(b, Ordering::Relaxed);
                }
                STDIN_POS.store(0, Ordering::Relaxed);
                STDIN_LEN.store(n - take, Ordering::Relaxed);
            }
            Ok(take)
        })();

        STDIN_LOCK.store(false, Ordering::Release);
        res
    }

    pub fn close_stdio() {
        for slot in [&STDIN_CH, &STDOUT_CH, &STDERR_CH] {
            let raw_h = slot.swap(INVALID_HANDLE, Ordering::AcqRel);
            if raw_h != INVALID_HANDLE {
                drop(Handle::from_syscall_out(raw_h));
            }
        }
    }

    pub fn caps_mask() -> u64 {
        CAPS_MASK.load(Ordering::Acquire)
    }

    pub fn cap_handle(kind: CapKind) -> Option<HandleValue> {
        let raw_h = slot_for(kind).load(Ordering::Acquire);
        if raw_h == INVALID_HANDLE {
            None
        } else {
            Some(raw_h)
        }
    }

    pub fn take_cap_handle(kind: CapKind) -> Option<Handle> {
        let raw_h = slot_for(kind).swap(INVALID_HANDLE, Ordering::AcqRel);
        if raw_h == INVALID_HANDLE {
            None
        } else {
            Some(Handle::from_syscall_out(raw_h))
        }
    }
}

#[cfg(feature = "dyn-client")]
mod imp {
    use super::CapKind;
    use crate::handle::Handle;
    use crate::{ErrorCode, HandleValue, Result, INVALID_HANDLE};

    #[link(name = "canvas", kind = "dylib")]
    unsafe extern "C" {
        fn canvas_args_count() -> usize;
        fn canvas_arg_get(
            index: usize,
            out_buf: *mut u8,
            buf_len: usize,
            out_len: *mut usize,
        ) -> i64;
        fn canvas_stdin_read(out_buf: *mut u8, buf_len: usize, out_read: *mut usize) -> i64;
        fn canvas_stdin_read_timeout(
            out_buf: *mut u8,
            buf_len: usize,
            ticks: u64,
            out_read: *mut usize,
        ) -> i64;
        fn canvas_stdout_write(data: *const u8, len: usize, out_written: *mut usize) -> i64;
        fn canvas_stderr_write(data: *const u8, len: usize, out_written: *mut usize) -> i64;
        fn canvas_exit_code(code: i32) -> !;
        fn canvas_caps_mask() -> u64;
        fn canvas_cap_handle(kind: u32) -> u32;
        fn canvas_take_cap_handle(kind: u32) -> u32;
        fn canvas_pe_image_span(out_offset: *mut u64, out_len: *mut u64);
    }

    pub fn args_count() -> usize {
        // SAFETY: exported by `libcanvas.so` (`CANVAS_ABI_1.0`).
        unsafe { canvas_args_count() }
    }

    pub fn arg_get(index: usize, out: &mut [u8]) -> Option<usize> {
        let mut actual = 0usize;
        // SAFETY: `out` and `actual` are valid writable buffers.
        let rc = unsafe { canvas_arg_get(index, out.as_mut_ptr(), out.len(), &mut actual) };
        if rc == 0 {
            Some(actual)
        } else {
            None
        }
    }

    fn stdin_read_dyn(out: &mut [u8], timeout_ticks: Option<u64>) -> Result<usize> {
        let mut actual = 0usize;
        // SAFETY: `out` and `actual` are valid writable buffers.
        let rc = unsafe {
            match timeout_ticks {
                Some(ticks) => {
                    canvas_stdin_read_timeout(out.as_mut_ptr(), out.len(), ticks, &mut actual)
                }
                None => canvas_stdin_read(out.as_mut_ptr(), out.len(), &mut actual),
            }
        };
        if rc == 0 {
            Ok(actual)
        } else {
            Err(ErrorCode::from_raw(rc).unwrap_or(ErrorCode::Internal))
        }
    }

    pub fn stdin_read(out: &mut [u8]) -> Result<usize> {
        stdin_read_dyn(out, None)
    }

    pub fn stdin_read_timeout(out: &mut [u8], ticks: u64) -> Result<usize> {
        stdin_read_dyn(out, Some(ticks))
    }

    pub fn stdout_write(data: &[u8]) -> Result<usize> {
        let mut written = 0usize;
        // SAFETY: `data` is readable for `data.len()` bytes and `written` is writable.
        let rc = unsafe { canvas_stdout_write(data.as_ptr(), data.len(), &mut written) };
        if rc == 0 {
            Ok(written)
        } else {
            Err(ErrorCode::from_raw(rc).unwrap_or(ErrorCode::Internal))
        }
    }

    pub fn stderr_write(data: &[u8]) -> Result<usize> {
        let mut written = 0usize;
        // SAFETY: `data` is readable for `data.len()` bytes and `written` is writable.
        let rc = unsafe { canvas_stderr_write(data.as_ptr(), data.len(), &mut written) };
        if rc == 0 {
            Ok(written)
        } else {
            Err(ErrorCode::from_raw(rc).unwrap_or(ErrorCode::Internal))
        }
    }

    pub fn exit(code: i32) -> ! {
        // SAFETY: `canvas_exit_code` closes stdio and terminates the process.
        unsafe { canvas_exit_code(code) }
    }

    pub fn caps_mask() -> u64 {
        // SAFETY: exported by `libcanvas.so`.
        unsafe { canvas_caps_mask() }
    }

    pub fn cap_handle(kind: CapKind) -> Option<HandleValue> {
        // SAFETY: exported by `libcanvas.so`.
        let raw_h = unsafe { canvas_cap_handle(kind as u32) };
        if raw_h == INVALID_HANDLE {
            None
        } else {
            Some(raw_h)
        }
    }

    pub fn take_cap_handle(kind: CapKind) -> Option<Handle> {
        // SAFETY: exported by `libcanvas.so`; transfers ownership once.
        let raw_h = unsafe { canvas_take_cap_handle(kind as u32) };
        if raw_h == INVALID_HANDLE {
            None
        } else {
            Some(Handle::from_syscall_out(raw_h))
        }
    }

    pub fn pe_image_span() -> (u64, u64) {
        let mut off = 0u64;
        let mut len = 0u64;
        // SAFETY: `off` and `len` are valid stack pointers.
        unsafe { canvas_pe_image_span(&mut off, &mut len) };
        (off, len)
    }
}

/// Initialize the process bootstrap context (internal, invoked by `libcanvas.so` ABI).
#[cfg(not(feature = "dyn-client"))]
pub fn set_process_ctx(info: &crate::rtld_abi::ProcessBootstrapInfo) {
    imp::set_process_ctx(info);
}

/// Number of command-line arguments (`argc`).
pub fn args_count() -> usize {
    imp::args_count()
}

/// Copy argument `index` into `out`, returning its total length in bytes (even if truncated).
pub fn arg_get(index: usize, out: &mut [u8]) -> Option<usize> {
    imp::arg_get(index, out)
}

/// Read argument `index` as UTF-8 into `buf`.
pub fn arg_str(index: usize, buf: &mut [u8]) -> Option<&str> {
    let len = arg_get(index, buf)?;
    if len > buf.len() {
        return None;
    }
    core::str::from_utf8(&buf[..len]).ok()
}

/// Read up to `out.len()` bytes from `stdin` (`Ok(0)` on EOF / `PeerClosed`).
pub fn stdin_read(out: &mut [u8]) -> Result<usize> {
    imp::stdin_read(out)
}

/// Read up to `out.len()` bytes from `stdin`, waiting at most `ticks`
/// scheduler ticks (`Err(ErrorCode::TimedOut)` when nothing arrived).
pub fn stdin_read_timeout(out: &mut [u8], ticks: u64) -> Result<usize> {
    imp::stdin_read_timeout(out, ticks)
}

/// Write all of `data` to `stdout` in `4096`-byte chunks.
pub fn stdout_write(data: &[u8]) -> Result<usize> {
    imp::stdout_write(data)
}

/// Write a UTF-8 string to `stdout`.
pub fn stdout_str(s: &str) -> Result<usize> {
    stdout_write(s.as_bytes())
}

/// Write all of `data` to `stderr` in `4096`-byte chunks.
pub fn stderr_write(data: &[u8]) -> Result<usize> {
    imp::stderr_write(data)
}

/// Write a UTF-8 string to `stderr`.
pub fn stderr_str(s: &str) -> Result<usize> {
    stderr_write(s.as_bytes())
}

/// Close standard stream channels (delivering `PeerClosed` EOF) and exit with `code`.
pub fn exit(code: i32) -> ! {
    #[cfg(not(feature = "dyn-client"))]
    {
        imp::close_stdio();
        crate::process::exit(i64::from(code));
    }
    #[cfg(feature = "dyn-client")]
    imp::exit(code);
}

/// Return the `@caps(...)` capability bitmask (`huesos_abi::auxv::caps_mask`).
pub fn caps_mask() -> u64 {
    imp::caps_mask()
}

/// Return the raw handle value for a capability slot without taking ownership.
pub fn cap_handle(kind: CapKind) -> Option<HandleValue> {
    imp::cap_handle(kind)
}

/// Take ownership of a capability handle slot once (returns `None` if absent or already taken).
pub fn take_cap_handle(kind: CapKind) -> Option<Handle> {
    imp::take_cap_handle(kind)
}

/// Convert a `u32` ABI tag into [`CapKind`].
pub const fn cap_kind_from_u32(kind: u32) -> Option<CapKind> {
    match kind {
        0 => Some(CapKind::Stdin),
        1 => Some(CapKind::Stdout),
        2 => Some(CapKind::Stderr),
        3 => Some(CapKind::HxfsDir),
        4 => Some(CapKind::HxfsService),
        5 => Some(CapKind::BlockDev),
        6 => Some(CapKind::FrameDraw),
        7 => Some(CapKind::BootfsRo),
        8 => Some(CapKind::Registry),
        9 => Some(CapKind::NetService),
        10 => Some(CapKind::WlanService),
        11 => Some(CapKind::PeVmo),
        12 => Some(CapKind::PeSelfVmar),
        _ => None,
    }
}

/// Return `(offset, len)` of the target PE32+ `.exe` inside `PeVmo` (`(0, 0)` for ELF processes).
pub fn pe_image_span() -> (u64, u64) {
    imp::pe_image_span()
}

/// Duplicate or borrow-free check returning `INVALID_HANDLE` on absence.
pub fn cap_raw_or_invalid(kind: CapKind) -> HandleValue {
    cap_handle(kind).unwrap_or(INVALID_HANDLE)
}

/// Check if an error code represents an access/capability denial.
pub const fn is_access_denied(err: ErrorCode) -> bool {
    matches!(err, ErrorCode::AccessDenied)
}
