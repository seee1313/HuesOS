//! HuesOS native PE32+ `/lib/msvcrt.dll` (Classic MSVCRT console runtime).
//!
//! Bridges MinGW-w64 / legacy MSVC imports (`__getmainargs`, `__iob_func`,
//! `_amsg_exit`, `_onexit`, `__set_app_type`) onto `ucrtbase.dll` while
//! forwarding standard C runtime exports (`malloc`/`free`/`fopen`/`atoi`/etc.)
//! via PE `.edata` export forwarder strings (`build.rs`).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use core::ptr;

use huesos_pe::win64_abi::TRUE;

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn NtTerminateProcess(process_handle: usize, exit_status: u32) -> !;
}

#[link(name = "ucrtbase", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __p___argc() -> *mut i32;
    fn __p___argv() -> *mut *mut *mut u8;
    fn __p___environ() -> *mut *mut *mut u8;
    fn __acrt_iob_func(idx: u32) -> *mut u8;
    fn _crt_atexit(func: usize) -> i32;
    #[link_name = "_exit"]
    fn ucrt_under_exit(status: i32) -> !;
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: terminates process on panic.
    unsafe { NtTerminateProcess(usize::MAX, 101) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _DllMainCRTStartup(
    _hinst_dll: usize,
    _fdw_reason: u32,
    _lpv_reserved: usize,
) -> i32 {
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn __set_app_type(_app_type: i32) {}

#[unsafe(no_mangle)]
pub extern "win64" fn __getmainargs(
    argc_out: *mut i32,
    argv_out: *mut *mut *mut u8,
    env_out: *mut *mut *mut u8,
    _do_wildcard: i32,
    _start_info: usize,
) -> i32 {
    // SAFETY: delegates to `ucrtbase` narrow argv/env state.
    unsafe {
        if !argc_out.is_null() {
            ptr::write_unaligned(argc_out, *__p___argc());
        }
        if !argv_out.is_null() {
            ptr::write_unaligned(argv_out, *__p___argv());
        }
        if !env_out.is_null() {
            ptr::write_unaligned(env_out, *__p___environ());
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn __iob_func() -> *mut u8 {
    // SAFETY: returns base of 3-entry stdio array in `ucrtbase`.
    unsafe { __acrt_iob_func(0) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _onexit(func: usize) -> usize {
    // SAFETY: registers callback via `ucrtbase::_crt_atexit`.
    if unsafe { _crt_atexit(func) } == 0 {
        func
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _amsg_exit(errnum: i32) -> ! {
    // SAFETY: delegates to `ucrtbase::_exit`.
    unsafe { ucrt_under_exit(errnum) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn __C_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1
}
