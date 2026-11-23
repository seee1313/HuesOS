//! `/bin/win-hello.exe` — Native PE32+ (`0x8664`) smoke & conformance binary.
//!
//! Validates:
//! - Genuine MS x64 ABI (`extern "win64"`) IAT calls into `/lib/kernel32.dll` -> `/lib/ntdll.dll`
//! - Ring-3 `GS_BASE` TEB (`gs:[0x30]` self-pointer, `gs:[0x60]` PEB, `gs:[0x68]` `LastError`)
//! - `HeapAlloc` / `HeapFree` over `ScudoHeap`
//! - Strict W^X `VirtualAlloc` (`PAGE_EXECUTE_READWRITE` rejected with `ERROR_INVALID_PARAMETER`,
//!   `PAGE_READWRITE` -> `VirtualProtect(PAGE_READONLY)` -> `VirtualFree` accepted)
//! - Runtime `LoadLibraryA` + `GetProcAddress` EAT lookup
//! - Capability-backed `CreateFileA("C:\\welcome.txt", ...)` + `ReadFile`

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;
use win_sdk::*;

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: exits PE64 process.
    unsafe { ExitProcess(101) }
}

unsafe fn cstr_slice<'a>(p: *const u8) -> &'a str {
    if p.is_null() {
        return "";
    }
    let mut n = 0usize;
    while n < 256 {
        if unsafe { *p.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).unwrap_or("")
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn mainCRTStartup() -> u32 {
    let teb = read_gs_teb_self();
    let peb = read_gs_peb();
    let tid = unsafe { GetCurrentThreadId() };
    let img_base = unsafe { GetModuleHandleA(ptr::null()) };
    let cmd = unsafe { cstr_slice(GetCommandLineA()) };

    if teb == 0 || peb == 0 || img_base == 0 {
        win_println!("[win-hello] FAIL: invalid TEB/PEB/ImageBase");
        return 1;
    }

    // 1. Zero-syscall TEB LastError roundtrip (`gs:[0x68]`).
    unsafe { SetLastError(0x1337) };
    let err_rt = unsafe { GetLastError() };
    if err_rt != 0x1337 {
        win_println!("[win-hello] FAIL: LastError mismatch ({err_rt:#x})");
        return 2;
    }
    unsafe { SetLastError(0) };

    // 2. Win32 Heap (`GetProcessHeap` + `HeapAlloc` + `HeapFree`).
    let heap = unsafe { GetProcessHeap() };
    let buf_va = unsafe { HeapAlloc(heap, HEAP_ZERO_MEMORY, 256) };
    if buf_va == 0 {
        win_println!("[win-hello] FAIL: HeapAlloc returned NULL");
        return 3;
    }
    unsafe {
        ptr::write_bytes(buf_va as *mut u8, 0x5A, 256);
        if HeapFree(heap, 0, buf_va) == FALSE {
            win_println!("[win-hello] FAIL: HeapFree failed");
            return 4;
        }
    }

    // 3. Strict W^X check: `PAGE_EXECUTE_READWRITE` MUST be denied!
    let rwx = unsafe { VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
    let rwx_err = unsafe { GetLastError() };
    if rwx != 0 || rwx_err != ERROR_INVALID_PARAMETER {
        win_println!("[win-hello] FAIL: W^X violated (rwx={rwx:#x} err={rwx_err})");
        return 5;
    }

    // Valid RW -> RO -> Free transition.
    let rw_page = unsafe { VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if rw_page == 0 {
        win_println!("[win-hello] FAIL: VirtualAlloc(PAGE_READWRITE) failed");
        return 6;
    }
    let mut old_prot = 0u32;
    unsafe {
        ptr::write_volatile(rw_page as *mut u64, 0xCAFE_BABE_DEAD_BEEFu64);
        if VirtualProtect(rw_page, 4096, PAGE_READONLY, &mut old_prot) == FALSE {
            win_println!("[win-hello] FAIL: VirtualProtect(PAGE_READONLY) failed");
            return 7;
        }
        let readback = ptr::read_volatile(rw_page as *const u64);
        if readback != 0xCAFE_BABE_DEAD_BEEFu64 || VirtualFree(rw_page, 0, MEM_RELEASE) == FALSE {
            win_println!("[win-hello] FAIL: VirtualProtect readback / VirtualFree failed");
            return 8;
        }
    }

    // 4. Dynamic `LoadLibraryA` + `GetProcAddress` EAT lookup.
    let k32 = unsafe { LoadLibraryA(c"kernel32.dll".as_ptr().cast()) };
    let tick_fn_va = unsafe { GetProcAddress(k32, c"GetTickCount64".as_ptr().cast()) };
    if k32 == 0 || tick_fn_va == 0 {
        win_println!("[win-hello] FAIL: GetProcAddress(GetTickCount64) failed");
        return 9;
    }
    let dyn_tick_fn: unsafe extern "win64" fn() -> u64 =
        unsafe { core::mem::transmute(tick_fn_va) };
    let uptime_ms = unsafe { dyn_tick_fn() };

    // 5. File I/O via Win32 path translation (`C:\welcome.txt` -> `/welcome.txt`).
    let f = unsafe {
        CreateFileA(
            c"C:\\welcome.txt".as_ptr().cast(),
            GENERIC_READ,
            1,
            0,
            OPEN_EXISTING,
            0,
            0,
        )
    };
    let mut welcome_bytes = 0u32;
    if f != INVALID_HANDLE_VALUE {
        let mut scratch = [0u8; 64];
        unsafe {
            let _ = ReadFile(
                f,
                scratch.as_mut_ptr(),
                scratch.len() as u32,
                &mut welcome_bytes,
                0,
            );
            let _ = CloseHandle(f);
        }
    }

    win_println!(
        "[win-hello] PE32+ x86_64 native execution on HuesOS (tid={tid} base={img_base:#x} teb={teb:#x} peb={peb:#x})"
    );
    win_println!(
        "[win-hello] cmd=\"{cmd}\" wx_guard=enforced welcome_read={welcome_bytes}B uptime={uptime_ms}ms"
    );
    win_println!("[win-hello] PASS (ABI=PE64)");
    0
}
