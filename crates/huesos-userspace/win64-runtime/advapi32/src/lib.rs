//! HuesOS native PE32+ `/lib/advapi32.dll` (`SystemFunction036` / `RtlGenRandom` & stub registry).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use core::ptr;

use huesos_pe::win64_abi::{ERROR_INSUFFICIENT_BUFFER, FALSE, PeHostApi, TRUE};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __huesos_ntdll_host() -> *const PeHostApi;
    fn RtlSetLastWin32Error(code: u32);
    fn NtTerminateProcess(process_handle: usize, exit_status: u32) -> !;
}

#[inline]
fn host() -> Option<&'static PeHostApi> {
    // SAFETY: imported via PE32+ IAT from `ntdll.dll`.
    let p = unsafe { __huesos_ntdll_host() };
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` points to `'static` `PE_HOST_API`.
        Some(unsafe { &*p })
    }
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

const ERROR_FILE_NOT_FOUND: i32 = 2;

/// `RtlGenRandom` exported as `SystemFunction036`.
#[unsafe(no_mangle)]
pub extern "win64" fn SystemFunction036(random_buffer: *mut u8, random_buffer_len: u32) -> u8 {
    if random_buffer_len == 0 {
        return 1;
    }
    if random_buffer.is_null() {
        return 0;
    }
    let Some(h) = host() else {
        return 0;
    };
    u8::from((h.gen_random)(random_buffer, random_buffer_len as usize) == 0)
}

#[unsafe(no_mangle)]
pub extern "win64" fn RegOpenKeyExA(
    _hkey: usize,
    _sub_key: *const u8,
    _options: u32,
    _sam_desired: u32,
    _phk_result: *mut usize,
) -> i32 {
    ERROR_FILE_NOT_FOUND
}

#[unsafe(no_mangle)]
pub extern "win64" fn RegOpenKeyExW(
    _hkey: usize,
    _sub_key: *const u16,
    _options: u32,
    _sam_desired: u32,
    _phk_result: *mut usize,
) -> i32 {
    ERROR_FILE_NOT_FOUND
}

#[unsafe(no_mangle)]
pub extern "win64" fn RegQueryValueExA(
    _hkey: usize,
    _value_name: *const u8,
    _reserved: *mut u32,
    _type_out: *mut u32,
    _data: *mut u8,
    _cb_data: *mut u32,
) -> i32 {
    ERROR_FILE_NOT_FOUND
}

#[unsafe(no_mangle)]
pub extern "win64" fn RegQueryValueExW(
    _hkey: usize,
    _value_name: *const u16,
    _reserved: *mut u32,
    _type_out: *mut u32,
    _data: *mut u8,
    _cb_data: *mut u32,
) -> i32 {
    ERROR_FILE_NOT_FOUND
}

#[unsafe(no_mangle)]
pub extern "win64" fn RegCloseKey(_hkey: usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetUserNameA(buffer: *mut u8, pcb_buffer: *mut u32) -> i32 {
    const USER: &[u8] = b"user\0";
    if pcb_buffer.is_null() {
        return FALSE;
    }
    // SAFETY: `pcb_buffer` checked non-null.
    let cap = unsafe { ptr::read_unaligned(pcb_buffer) } as usize;
    // SAFETY: `pcb_buffer` checked non-null.
    unsafe { ptr::write_unaligned(pcb_buffer, USER.len() as u32) };
    if buffer.is_null() || cap < USER.len() {
        // SAFETY: forwards to `ntdll`.
        unsafe { RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER) };
        return FALSE;
    }
    // SAFETY: `buffer` valid for `USER.len()` bytes.
    unsafe { ptr::copy_nonoverlapping(USER.as_ptr(), buffer, USER.len()) };
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetUserNameW(buffer: *mut u16, pcb_buffer: *mut u32) -> i32 {
    const USER: &[u16] = &[b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16, 0];
    if pcb_buffer.is_null() {
        return FALSE;
    }
    // SAFETY: `pcb_buffer` checked non-null.
    let cap = unsafe { ptr::read_unaligned(pcb_buffer) } as usize;
    // SAFETY: `pcb_buffer` checked non-null.
    unsafe { ptr::write_unaligned(pcb_buffer, USER.len() as u32) };
    if buffer.is_null() || cap < USER.len() {
        // SAFETY: forwards to `ntdll`.
        unsafe { RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER) };
        return FALSE;
    }
    for (i, &w) in USER.iter().enumerate() {
        // SAFETY: `i < USER.len() <= cap`.
        unsafe { ptr::write_unaligned(buffer.add(i), w) };
    }
    TRUE
}
