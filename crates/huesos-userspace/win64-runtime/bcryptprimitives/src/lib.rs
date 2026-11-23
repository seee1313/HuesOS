//! HuesOS native PE32+ `/lib/bcryptprimitives.dll` (`ProcessPrng` for Rust `std` & `getrandom`).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;

use huesos_pe::win64_abi::{FALSE, PeHostApi, TRUE};

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

#[unsafe(no_mangle)]
pub extern "win64" fn ProcessPrng(pb_data: *mut u8, cb_data: usize) -> i32 {
    if cb_data == 0 {
        return TRUE;
    }
    if pb_data.is_null() {
        return FALSE;
    }
    let Some(h) = host() else {
        return FALSE;
    };
    if (h.gen_random)(pb_data, cb_data) == 0 {
        TRUE
    } else {
        FALSE
    }
}
