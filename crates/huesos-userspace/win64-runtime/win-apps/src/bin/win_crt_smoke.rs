//! `/bin/win-crt-smoke.exe` — Full C/C++/Rust Win64 Console Runtime Conformance Binary.
//!
//! Exercises:
//! - ApiSet IAT redirection (`api-ms-win-crt-heap-l1-1-0.dll`, `api-ms-win-crt-stdio-l1-1-0.dll`,
//!   `api-ms-win-core-fibers-l1-1-1.dll`)
//! - `ucrtbase.dll` + `msvcrt.dll` (`malloc`/`free`, `fopen`/`fread`/`fclose`, `__getmainargs`, `atoi`)
//! - `.pdata` / `.xdata` x64 SEH (`RtlLookupFunctionEntry` + `RtlCaptureStackBackTrace`)
//! - `FlsAlloc` / `FlsSetValue` / `FlsGetValue` / `FlsFree` with destructor callback
//! - `MultiByteToWideChar` & `WideCharToMultiByte` UTF-8 <-> UTF-16LE roundtrip
//! - `bcryptprimitives.dll` (`ProcessPrng`), `bcrypt.dll` (`BCryptGenRandom`), `advapi32.dll` (`SystemFunction036`)
//! - `ws2_32.dll` (`WSAStartup`, `inet_pton`, `inet_ntop`, `htons`, `WSACleanup`)

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use win_sdk::*;

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: exits PE64 process.
    unsafe { ExitProcess(101) }
}

#[link(name = "api-ms-win-crt-heap-l1-1-0", kind = "raw-dylib")]
unsafe extern "win64" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr_val: *mut u8);
}

#[link(name = "api-ms-win-crt-stdio-l1-1-0", kind = "raw-dylib")]
unsafe extern "win64" {
    fn fopen(filename: *const u8, mode: *const u8) -> *mut u8;
    fn fread(buf: *mut u8, size: usize, count: usize, stream: *mut u8) -> usize;
    fn fclose(stream: *mut u8) -> i32;
}

#[link(name = "api-ms-win-core-fibers-l1-1-1", kind = "raw-dylib")]
unsafe extern "win64" {
    fn FlsAlloc(cb: Option<extern "win64" fn(usize)>) -> u32;
    fn FlsSetValue(idx: u32, val: usize) -> i32;
    fn FlsGetValue(idx: u32) -> usize;
    fn FlsFree(idx: u32) -> i32;
}

#[link(name = "msvcrt", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __getmainargs(
        argc: *mut i32,
        argv: *mut *mut *mut u8,
        env: *mut *mut *mut u8,
        wildcard: i32,
        start_info: usize,
    ) -> i32;
    fn atoi(s: *const u8) -> i32;
}

#[link(name = "bcryptprimitives", kind = "raw-dylib")]
unsafe extern "win64" {
    fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32;
}

#[link(name = "bcrypt", kind = "raw-dylib")]
unsafe extern "win64" {
    fn BCryptGenRandom(alg: usize, pb: *mut u8, cb: u32, flags: u32) -> i32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "win64" {
    fn SystemFunction036(buf: *mut u8, len: u32) -> u8;
}

#[link(name = "ws2_32", kind = "raw-dylib")]
unsafe extern "win64" {
    fn WSAStartup(ver: u16, data: *mut u8) -> i32;
    fn WSACleanup() -> i32;
    fn htons(v: u16) -> u16;
    fn inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32;
    fn inet_ntop(af: i32, src: *const u8, dst: *mut u8, size: usize) -> *const u8;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "win64" {
    fn RtlLookupFunctionEntry(pc: u64, base_out: *mut u64, hist: usize) -> usize;
    fn RtlCaptureStackBackTrace(skip: u32, capture: u32, trace: *mut usize, hash: *mut u32) -> u16;
    fn MultiByteToWideChar(
        cp: u32,
        flags: u32,
        mb: *const u8,
        mb_len: i32,
        wide: *mut u16,
        wide_cap: i32,
    ) -> i32;
    fn WideCharToMultiByte(
        cp: u32,
        flags: u32,
        wide: *const u16,
        wide_len: i32,
        mb: *mut u8,
        mb_cap: i32,
        def_ch: *const u8,
        used_def: *mut i32,
    ) -> i32;
}

static FLS_DTOR_SEEN: AtomicUsize = AtomicUsize::new(0);

extern "win64" fn on_fls_destroy(val: usize) {
    FLS_DTOR_SEEN.store(val, Ordering::Release);
}

#[inline(never)]
fn nested_seh_probe(frames_out: &mut [usize; 8]) -> u16 {
    // Allocate a non-leaf stack frame so `.pdata`/`.xdata` virtual unwind is exercised!
    let mut local_scratch = [0xA5u8; 64];
    core::hint::black_box(&mut local_scratch);
    let mut hash = 0u32;
    // SAFETY: `frames_out` has room for 8 `usize` entries.
    unsafe { RtlCaptureStackBackTrace(0, 4, frames_out.as_mut_ptr(), &raw mut hash) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn mainCRTStartup() -> u32 {
    // 1. ApiSet `api-ms-win-crt-heap` + `msvcrt` (`malloc`/`free`/`__getmainargs`/`atoi`).
    let mut argc = 0i32;
    let mut argv: *mut *mut u8 = ptr::null_mut();
    let mut envp: *mut *mut u8 = ptr::null_mut();
    // SAFETY: tests `msvcrt` -> `ucrtbase` bridge.
    let rc_args = unsafe { __getmainargs(&raw mut argc, &raw mut argv, &raw mut envp, 0, 0) };
    // SAFETY: parses static C string.
    let parsed = unsafe { atoi(c"421337".as_ptr().cast()) };
    if rc_args != 0 || argc < 1 || parsed != 421_337 {
        win_println!("[win-crt-smoke] FAIL: msvcrt args/atoi ({rc_args}, {argc}, {parsed})");
        return 1;
    }

    // SAFETY: allocates & frees 128 bytes via `api-ms-win-crt-heap-l1-1-0.dll`.
    let mem = unsafe { malloc(128) };
    if mem.is_null() {
        win_println!("[win-crt-smoke] FAIL: api-ms-win-crt-heap malloc NULL");
        return 2;
    }
    // SAFETY: `mem` valid for 128 bytes.
    unsafe {
        ptr::write_bytes(mem, 0xCC, 128);
        free(mem);
    }

    // 2. `api-ms-win-crt-stdio` (`fopen` + `fread` + `fclose` on `C:\welcome.txt`).
    // SAFETY: reads `C:\welcome.txt` via `ucrtbase.dll`.
    unsafe {
        let fp = fopen(c"C:\\welcome.txt".as_ptr().cast(), c"rb".as_ptr().cast());
        if fp.is_null() {
            win_println!("[win-crt-smoke] FAIL: fopen(C:\\welcome.txt) NULL");
            return 3;
        }
        let mut buf = [0u8; 32];
        let n = fread(buf.as_mut_ptr(), 1, buf.len(), fp);
        let _ = fclose(fp);
        if n == 0 {
            win_println!("[win-crt-smoke] FAIL: fread returned 0");
            return 4;
        }
    }

    // 3. `FlsAlloc` / `FlsSetValue` / `FlsGetValue` / `FlsFree` with destructor callback.
    // SAFETY: tests FLS lifecycle via `api-ms-win-core-fibers-l1-1-1.dll`.
    unsafe {
        let idx = FlsAlloc(Some(on_fls_destroy));
        if idx == u32::MAX || FlsSetValue(idx, 0xCAFE_BABE) == 0 {
            win_println!("[win-crt-smoke] FAIL: FlsAlloc/FlsSetValue");
            return 5;
        }
        if FlsGetValue(idx) != 0xCAFE_BABE || FlsFree(idx) == 0 {
            win_println!("[win-crt-smoke] FAIL: FlsGetValue/FlsFree");
            return 6;
        }
    }
    if FLS_DTOR_SEEN.load(Ordering::Acquire) != 0xCAFE_BABE {
        win_println!("[win-crt-smoke] FAIL: FLS destructor not invoked");
        return 7;
    }

    // 4. `.pdata` / `.xdata` SEH `RtlLookupFunctionEntry` & `RtlCaptureStackBackTrace`.
    let fn_pc = nested_seh_probe as *const () as usize as u64;
    let mut mod_base = 0u64;
    // SAFETY: queries `.pdata` entry of `nested_seh_probe`.
    let rt_fn = unsafe { RtlLookupFunctionEntry(fn_pc, &raw mut mod_base, 0) };
    let mut frames = [0usize; 8];
    let depth = nested_seh_probe(&mut frames);
    if rt_fn == 0 || mod_base == 0 || depth == 0 {
        win_println!(
            "[win-crt-smoke] FAIL: SEH unwind (rt_fn={rt_fn:#x} base={mod_base:#x} depth={depth})"
        );
        return 8;
    }

    // 5. UTF-8 <-> UTF-16LE `MultiByteToWideChar` & `WideCharToMultiByte`.
    let src_utf8 = b"HuesOS-Win64\0";
    let mut wide = [0u16; 32];
    let mut back = [0u8; 32];
    // SAFETY: converts NUL-terminated UTF-8 -> UTF-16LE -> UTF-8.
    unsafe {
        let wn = MultiByteToWideChar(65001, 0, src_utf8.as_ptr(), -1, wide.as_mut_ptr(), 32);
        let bn = WideCharToMultiByte(
            65001,
            0,
            wide.as_ptr(),
            -1,
            back.as_mut_ptr(),
            32,
            ptr::null(),
            ptr::null_mut(),
        );
        if wn <= 1 || bn as usize != src_utf8.len() || &back[..src_utf8.len()] != src_utf8 {
            win_println!("[win-crt-smoke] FAIL: UTF-8/UTF-16 roundtrip (wn={wn} bn={bn})");
            return 9;
        }
    }

    // 6. CSPRNG (`ProcessPrng`, `BCryptGenRandom`, `SystemFunction036`).
    let mut rng_a = [0u8; 16];
    let mut rng_b = [0u8; 16];
    let mut rng_c = [0u8; 16];
    // SAFETY: fills buffers from 3 Windows CSPRNG DLLs.
    unsafe {
        if ProcessPrng(rng_a.as_mut_ptr(), rng_a.len()) == 0
            || BCryptGenRandom(0, rng_b.as_mut_ptr(), rng_b.len() as u32, 2) != 0
            || SystemFunction036(rng_c.as_mut_ptr(), rng_c.len() as u32) == 0
            || rng_a == [0u8; 16]
            || rng_a == rng_b
        {
            win_println!("[win-crt-smoke] FAIL: CSPRNG check");
            return 10;
        }
    }

    // 7. Winsock 2.2 (`WSAStartup`, `htons`, `inet_pton`, `inet_ntop`, `WSACleanup`).
    let mut wsa_buf = [0u8; 416];
    let mut ip_raw = [0u8; 4];
    let mut ip_txt = [0u8; 32];
    // SAFETY: exercises `ws2_32.dll` exports.
    unsafe {
        if WSAStartup(0x0202, wsa_buf.as_mut_ptr()) != 0
            || htons(443) != 443u16.to_be()
            || inet_pton(2, c"10.0.2.15".as_ptr().cast(), ip_raw.as_mut_ptr()) != 1
            || ip_raw != [10, 0, 2, 15]
            || inet_ntop(2, ip_raw.as_ptr(), ip_txt.as_mut_ptr(), ip_txt.len()).is_null()
            || WSACleanup() != 0
        {
            win_println!("[win-crt-smoke] FAIL: ws2_32 check");
            return 11;
        }
    }

    win_println!(
        "[win-crt-smoke] PASS: ApiSet + ucrtbase + msvcrt + SEH(depth={depth}) + FLS + CSPRNG + ws2_32 OK"
    );
    0
}
