//! HuesOS native PE32+ `/lib/bcrypt.dll` (`BCryptGenRandom` CSPRNG).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use core::ptr;

use huesos_pe::win64_abi::{PeHostApi, TRUE};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __huesos_ntdll_host() -> *const PeHostApi;
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

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = -0x3FFF_FFF3; // 0xC000000D

const BCRYPT_RNG_PSEUDO_HANDLE: usize = 0xB1;

#[unsafe(no_mangle)]
pub extern "win64" fn BCryptOpenAlgorithmProvider(
    ph_algorithm: *mut usize,
    _psz_alg_id: *const u16,
    _psz_implementation: *const u16,
    _dw_flags: u32,
) -> i32 {
    if ph_algorithm.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: `ph_algorithm` checked non-null.
    unsafe { ptr::write_unaligned(ph_algorithm, BCRYPT_RNG_PSEUDO_HANDLE) };
    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "win64" fn BCryptCloseAlgorithmProvider(_h_algorithm: usize, _dw_flags: u32) -> i32 {
    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "win64" fn BCryptGenRandom(
    _h_algorithm: usize,
    pb_buffer: *mut u8,
    cb_buffer: u32,
    _dw_flags: u32,
) -> i32 {
    if cb_buffer == 0 {
        return STATUS_SUCCESS;
    }
    if pb_buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(h) = host() else {
        return STATUS_INVALID_PARAMETER;
    };
    if (h.gen_random)(pb_buffer, cb_buffer as usize) == 0 {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}
