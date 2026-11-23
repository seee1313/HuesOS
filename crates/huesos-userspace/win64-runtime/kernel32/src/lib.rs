//! HuesOS native PE32+ `/lib/kernel32.dll` (`x86_64` MS Win64 ABI).
//!
//! Imports core runtime/synchronization/TEB exports from `ntdll.dll` through a
//! genuine PE32+ Import Address Table (`kind = "raw-dylib"`) and exposes the
//! Win32 Base API (`Heap*`, `Virtual*`, `CreateFile*`/`ReadFile`/`WriteFile`,
//! `CreateThread`/`WaitFor*`, `SRWLOCK`/`CRITICAL_SECTION`/`CONDITION_VARIABLE`,
//! `Tls*`, `LoadLibrary*`/`GetProcAddress`, `QueryPerformanceCounter`, `Sleep`,
//! `ExitProcess`, etc.).

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;

use huesos_pe::win64_abi::{
    DEFAULT_PROCESS_HEAP, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_SUCCESS, FALSE,
    INVALID_HANDLE_VALUE, PeHostApi, RtlConditionVariable, RtlCriticalSection, RtlSrwLock,
    SystemInfo64, TLS_MINIMUM_AVAILABLE, TRUE, WAIT_FAILED, Win64ThreadStart, teb_offsets,
};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __huesos_ntdll_host() -> *const PeHostApi;
    fn NtCurrentTeb() -> usize;
    fn RtlGetCurrentPeb() -> usize;
    fn RtlGetLastWin32Error() -> u32;
    fn RtlSetLastWin32Error(code: u32);
    fn RtlGetCurrentThreadId() -> u32;

    fn RtlInitializeCriticalSection(cs: *mut RtlCriticalSection) -> i32;
    fn RtlInitializeCriticalSectionAndSpinCount(cs: *mut RtlCriticalSection, spin: u32) -> i32;
    fn RtlTryEnterCriticalSection(cs: *mut RtlCriticalSection) -> i32;
    fn RtlEnterCriticalSection(cs: *mut RtlCriticalSection) -> i32;
    fn RtlLeaveCriticalSection(cs: *mut RtlCriticalSection) -> i32;
    fn RtlDeleteCriticalSection(cs: *mut RtlCriticalSection) -> i32;

    fn RtlInitializeSRWLock(lock: *mut RtlSrwLock);
    fn RtlTryAcquireSRWLockExclusive(lock: *mut RtlSrwLock) -> u8;
    fn RtlAcquireSRWLockExclusive(lock: *mut RtlSrwLock);
    fn RtlReleaseSRWLockExclusive(lock: *mut RtlSrwLock);
    fn RtlTryAcquireSRWLockShared(lock: *mut RtlSrwLock) -> u8;
    fn RtlAcquireSRWLockShared(lock: *mut RtlSrwLock);
    fn RtlReleaseSRWLockShared(lock: *mut RtlSrwLock);

    fn RtlInitializeConditionVariable(cv: *mut RtlConditionVariable);
    fn RtlWakeConditionVariable(cv: *mut RtlConditionVariable);
    fn RtlWakeAllConditionVariable(cv: *mut RtlConditionVariable);
    fn RtlSleepConditionVariableSRW(
        cv: *mut RtlConditionVariable,
        lock: *mut RtlSrwLock,
        timeout_ms: u32,
        flags: u32,
    ) -> i32;
    fn RtlSleepConditionVariableCS(
        cv: *mut RtlConditionVariable,
        cs: *mut RtlCriticalSection,
        timeout_ms: u32,
    ) -> i32;
    fn RtlWaitOnAddress(addr: *const u8, compare: *const u8, size: usize, timeout_ms: u32) -> i32;
    fn RtlWakeAddressSingle(addr: *const u8);
    fn RtlWakeAddressAll(addr: *const u8);

    fn RtlCreateHeap(
        flags: u32,
        base: usize,
        max_sz: usize,
        init_sz: usize,
        lock: usize,
        params: usize,
    ) -> usize;
    fn RtlDestroyHeap(heap: usize) -> usize;
    fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> usize;
    fn RtlReAllocateHeap(heap: usize, flags: u32, ptr_val: usize, size: usize) -> usize;
    fn RtlFreeHeap(heap: usize, flags: u32, ptr_val: usize) -> u8;
    fn RtlSizeHeap(heap: usize, flags: u32, ptr_val: usize) -> usize;

    fn NtTerminateProcess(process_handle: usize, exit_status: u32) -> !;
}

#[inline]
fn host() -> Option<&'static PeHostApi> {
    // SAFETY: imported via PE32+ IAT from `ntdll.dll`.
    let p = unsafe { __huesos_ntdll_host() };
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` points to `'static` `PE_HOST_API` in `/lib/ld-pe.so`.
        Some(unsafe { &*p })
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: terminates current PE64 process cleanly.
    unsafe { NtTerminateProcess(usize::MAX, 101) }
}

unsafe fn cstr_len(s: *const u8, max: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    while n < max {
        // SAFETY: caller supplies NUL-terminated string.
        if unsafe { *s.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    n
}

unsafe fn wstr_to_utf8(src: *const u16, dst: &mut [u8]) -> Option<usize> {
    if src.is_null() {
        return None;
    }
    let mut i = 0usize;
    let mut out = 0usize;
    loop {
        if i >= 512 {
            return None;
        }
        // SAFETY: `src` is a NUL-terminated UTF-16LE string.
        let unit = unsafe { ptr::read_unaligned(src.add(i)) };
        i += 1;
        if unit == 0 {
            break;
        }
        let ch = char::from_u32(u32::from(unit)).unwrap_or('?');
        let mut enc = [0u8; 4];
        let encoded = ch.encode_utf8(&mut enc).as_bytes();
        if out + encoded.len() > dst.len() {
            return None;
        }
        dst[out..out + encoded.len()].copy_from_slice(encoded);
        out += encoded.len();
    }
    Some(out)
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn _DllMainCRTStartup(
    _hinst_dll: usize,
    _reason: u32,
    _reserved: usize,
) -> i32 {
    TRUE
}

// ============================================================================
// Errors, Thread/Process IDs, and TEB TLS
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn GetLastError() -> u32 {
    // SAFETY: reads `gs:[0x68]` in `ntdll.dll`.
    unsafe { RtlGetLastWin32Error() }
}

#[unsafe(no_mangle)]
pub extern "win64" fn SetLastError(err: u32) {
    // SAFETY: writes `gs:[0x68]` in `ntdll.dll`.
    unsafe { RtlSetLastWin32Error(err) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCurrentThreadId() -> u32 {
    // SAFETY: reads `gs:[0x48]` in `ntdll.dll`.
    unsafe { RtlGetCurrentThreadId() }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCurrentProcessId() -> u32 {
    host().map_or(1, |h| h.process_id)
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCurrentProcess() -> usize {
    usize::MAX
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCurrentThread() -> usize {
    usize::MAX - 1
}

#[unsafe(no_mangle)]
pub extern "win64" fn TlsAlloc() -> u32 {
    match host() {
        Some(h) => (h.tls_alloc)(),
        None => u32::MAX,
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn TlsGetValue(index: u32) -> usize {
    if index as usize >= TLS_MINIMUM_AVAILABLE {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: `NtCurrentTeb()` returns the 8 KiB TEB base (`gs:[0x30]`).
    let teb = unsafe { NtCurrentTeb() };
    if teb == 0 {
        return 0;
    }
    SetLastError(ERROR_SUCCESS);
    // SAFETY: `TLS_SLOTS` (`0x1480..0x1680`) lies inside the 8 KiB TEB.
    unsafe { ptr::read((teb + teb_offsets::TLS_SLOTS + (index as usize) * 8) as *const usize) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn TlsSetValue(index: u32, value: usize) -> i32 {
    if index as usize >= TLS_MINIMUM_AVAILABLE {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `NtCurrentTeb()` returns the 8 KiB TEB base (`gs:[0x30]`).
    let teb = unsafe { NtCurrentTeb() };
    if teb == 0 {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `TLS_SLOTS` (`0x1480..0x1680`) lies inside the 8 KiB TEB.
    unsafe {
        ptr::write(
            (teb + teb_offsets::TLS_SLOTS + (index as usize) * 8) as *mut usize,
            value,
        );
    }
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn TlsFree(index: u32) -> i32 {
    host().map_or(FALSE, |h| (h.tls_free)(index))
}

// ============================================================================
// Virtual Memory & Win32 Heap
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn VirtualAlloc(
    addr: usize,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> usize {
    host().map_or(0, |h| (h.virtual_alloc)(addr, size, alloc_type, protect))
}

#[unsafe(no_mangle)]
pub extern "win64" fn VirtualFree(addr: usize, size: usize, free_type: u32) -> i32 {
    host().map_or(FALSE, |h| (h.virtual_free)(addr, size, free_type))
}

#[unsafe(no_mangle)]
pub extern "win64" fn VirtualProtect(
    addr: usize,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    host().map_or(FALSE, |h| {
        (h.virtual_protect)(addr, size, new_protect, old_protect)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetProcessHeap() -> usize {
    // SAFETY: reads `PEB.ProcessHeap` at `[peb + 0x30]`.
    let peb = unsafe { RtlGetCurrentPeb() };
    if peb == 0 {
        DEFAULT_PROCESS_HEAP
    } else {
        // SAFETY: `peb` points to `Peb64` where offset `0x30` is `process_heap`.
        unsafe { ptr::read((peb + 0x30) as *const usize) }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapCreate(options: u32, init_size: usize, max_size: usize) -> usize {
    // SAFETY: delegates to `ntdll!RtlCreateHeap`.
    unsafe { RtlCreateHeap(options, 0, max_size, init_size, 0, 0) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapDestroy(heap: usize) -> i32 {
    // SAFETY: delegates to `ntdll!RtlDestroyHeap`.
    unsafe { RtlDestroyHeap(heap) as i32 }
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapAlloc(heap: usize, flags: u32, bytes: usize) -> usize {
    // SAFETY: delegates to `ntdll!RtlAllocateHeap`.
    unsafe { RtlAllocateHeap(heap, flags, bytes) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapReAlloc(heap: usize, flags: u32, mem: usize, bytes: usize) -> usize {
    // SAFETY: delegates to `ntdll!RtlReAllocateHeap`.
    unsafe { RtlReAllocateHeap(heap, flags, mem, bytes) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapFree(heap: usize, flags: u32, mem: usize) -> i32 {
    // SAFETY: delegates to `ntdll!RtlFreeHeap`.
    i32::from(unsafe { RtlFreeHeap(heap, flags, mem) } != 0)
}

#[unsafe(no_mangle)]
pub extern "win64" fn HeapSize(heap: usize, flags: u32, mem: usize) -> usize {
    // SAFETY: delegates to `ntdll!RtlSizeHeap`.
    unsafe { RtlSizeHeap(heap, flags, mem) }
}

// ============================================================================
// Console & File I/O
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn GetStdHandle(std_handle: u32) -> usize {
    host().map_or(INVALID_HANDLE_VALUE, |h| (h.get_std_handle)(std_handle))
}

#[unsafe(no_mangle)]
pub extern "win64" fn WriteFile(
    handle: usize,
    buf: *const u8,
    bytes_to_write: u32,
    bytes_written: *mut u32,
    _overlapped: usize,
) -> i32 {
    host().map_or(FALSE, |h| {
        (h.write_file)(handle, buf, bytes_to_write, bytes_written)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn WriteConsoleA(
    handle: usize,
    buf: *const u8,
    chars_to_write: u32,
    chars_written: *mut u32,
    _reserved: usize,
) -> i32 {
    WriteFile(handle, buf, chars_to_write, chars_written, 0)
}

#[unsafe(no_mangle)]
pub extern "win64" fn ReadFile(
    handle: usize,
    buf: *mut u8,
    bytes_to_read: u32,
    bytes_read: *mut u32,
    _overlapped: usize,
) -> i32 {
    host().map_or(FALSE, |h| {
        (h.read_file)(handle, buf, bytes_to_read, bytes_read)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn CreateFileA(
    file_name: *const u8,
    desired_access: u32,
    _share_mode: u32,
    _security_attrs: usize,
    creation_disposition: u32,
    _flags_and_attrs: u32,
    _template_file: usize,
) -> usize {
    let len = unsafe { cstr_len(file_name, 1024) };
    if len == 0 {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    host().map_or(INVALID_HANDLE_VALUE, |h| {
        (h.create_file_utf8)(file_name, len, desired_access, creation_disposition)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn CreateFileW(
    file_name: *const u16,
    desired_access: u32,
    _share_mode: u32,
    _security_attrs: usize,
    creation_disposition: u32,
    _flags_and_attrs: u32,
    _template_file: usize,
) -> usize {
    let mut utf8 = [0u8; 1024];
    let Some(len) = (unsafe { wstr_to_utf8(file_name, &mut utf8) }) else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    host().map_or(INVALID_HANDLE_VALUE, |h| {
        (h.create_file_utf8)(utf8.as_ptr(), len, desired_access, creation_disposition)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn SetFilePointerEx(
    handle: usize,
    distance_to_move: i64,
    new_file_pointer: *mut i64,
    move_method: u32,
) -> i32 {
    host().map_or(FALSE, |h| {
        (h.set_file_pointer)(handle, distance_to_move, new_file_pointer, move_method)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetFileSizeEx(handle: usize, out_size: *mut i64) -> i32 {
    host().map_or(FALSE, |h| (h.get_file_size)(handle, out_size))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DeleteFileA(file_name: *const u8) -> i32 {
    let len = unsafe { cstr_len(file_name, 1024) };
    host().map_or(FALSE, |h| (h.delete_file_utf8)(file_name, len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DeleteFileW(file_name: *const u16) -> i32 {
    let mut utf8 = [0u8; 1024];
    let Some(len) = (unsafe { wstr_to_utf8(file_name, &mut utf8) }) else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    };
    host().map_or(FALSE, |h| (h.delete_file_utf8)(utf8.as_ptr(), len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn CreateDirectoryA(path_name: *const u8, _sec: usize) -> i32 {
    let len = unsafe { cstr_len(path_name, 1024) };
    host().map_or(FALSE, |h| (h.create_dir_utf8)(path_name, len))
}

#[unsafe(no_mangle)]
pub extern "win64" fn CloseHandle(handle: usize) -> i32 {
    host().map_or(FALSE, |h| (h.close_handle)(handle))
}

// ============================================================================
// Threads, Events, and Synchronization Forwarding
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn CreateThread(
    _thread_attrs: usize,
    stack_size: usize,
    start_address: Win64ThreadStart,
    parameter: usize,
    creation_flags: u32,
    thread_id: *mut u32,
) -> usize {
    match host() {
        Some(h) => (h.create_thread)(
            stack_size,
            start_address,
            parameter,
            creation_flags,
            thread_id,
        ),
        None => {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn ExitThread(exit_code: u32) -> ! {
    if let Some(h) = host() {
        (h.exit_thread)(exit_code)
    }
    // SAFETY: fallback process exit.
    unsafe { NtTerminateProcess(usize::MAX, exit_code) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn WaitForSingleObject(handle: usize, milliseconds: u32) -> u32 {
    host().map_or(WAIT_FAILED, |h| {
        (h.wait_for_single_object)(handle, milliseconds)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn WaitForMultipleObjects(
    count: u32,
    handles: *const usize,
    wait_all: i32,
    milliseconds: u32,
) -> u32 {
    host().map_or(WAIT_FAILED, |h| {
        (h.wait_for_multiple_objects)(count, handles, wait_all, milliseconds)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetExitCodeThread(thread: usize, out_exit_code: *mut u32) -> i32 {
    host().map_or(FALSE, |h| (h.get_exit_code_thread)(thread, out_exit_code))
}

#[unsafe(no_mangle)]
pub extern "win64" fn CreateEventA(
    _attrs: usize,
    manual_reset: i32,
    initial_state: i32,
    _name: *const u8,
) -> usize {
    host().map_or(0, |h| (h.create_event)(manual_reset, initial_state))
}

#[unsafe(no_mangle)]
pub extern "win64" fn CreateEventW(
    _attrs: usize,
    manual_reset: i32,
    initial_state: i32,
    _name: *const u16,
) -> usize {
    host().map_or(0, |h| (h.create_event)(manual_reset, initial_state))
}

#[unsafe(no_mangle)]
pub extern "win64" fn SetEvent(event: usize) -> i32 {
    host().map_or(FALSE, |h| (h.set_event)(event))
}

#[unsafe(no_mangle)]
pub extern "win64" fn ResetEvent(event: usize) -> i32 {
    host().map_or(FALSE, |h| (h.reset_event)(event))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn InitializeCriticalSection(cs: *mut RtlCriticalSection) {
    let _ = unsafe { RtlInitializeCriticalSection(cs) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn InitializeCriticalSectionAndSpinCount(
    cs: *mut RtlCriticalSection,
    spin_count: u32,
) -> i32 {
    let _ = unsafe { RtlInitializeCriticalSectionAndSpinCount(cs, spin_count) };
    TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn EnterCriticalSection(cs: *mut RtlCriticalSection) {
    let _ = unsafe { RtlEnterCriticalSection(cs) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn TryEnterCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    unsafe { RtlTryEnterCriticalSection(cs) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn LeaveCriticalSection(cs: *mut RtlCriticalSection) {
    let _ = unsafe { RtlLeaveCriticalSection(cs) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn DeleteCriticalSection(cs: *mut RtlCriticalSection) {
    let _ = unsafe { RtlDeleteCriticalSection(cs) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn InitializeSRWLock(lock: *mut RtlSrwLock) {
    unsafe { RtlInitializeSRWLock(lock) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn AcquireSRWLockExclusive(lock: *mut RtlSrwLock) {
    unsafe { RtlAcquireSRWLockExclusive(lock) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn TryAcquireSRWLockExclusive(lock: *mut RtlSrwLock) -> u8 {
    unsafe { RtlTryAcquireSRWLockExclusive(lock) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn ReleaseSRWLockExclusive(lock: *mut RtlSrwLock) {
    unsafe { RtlReleaseSRWLockExclusive(lock) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn AcquireSRWLockShared(lock: *mut RtlSrwLock) {
    unsafe { RtlAcquireSRWLockShared(lock) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn TryAcquireSRWLockShared(lock: *mut RtlSrwLock) -> u8 {
    unsafe { RtlTryAcquireSRWLockShared(lock) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn ReleaseSRWLockShared(lock: *mut RtlSrwLock) {
    unsafe { RtlReleaseSRWLockShared(lock) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn InitializeConditionVariable(cv: *mut RtlConditionVariable) {
    unsafe { RtlInitializeConditionVariable(cv) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WakeConditionVariable(cv: *mut RtlConditionVariable) {
    unsafe { RtlWakeConditionVariable(cv) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WakeAllConditionVariable(cv: *mut RtlConditionVariable) {
    unsafe { RtlWakeAllConditionVariable(cv) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn SleepConditionVariableSRW(
    cv: *mut RtlConditionVariable,
    lock: *mut RtlSrwLock,
    timeout_ms: u32,
    flags: u32,
) -> i32 {
    unsafe { RtlSleepConditionVariableSRW(cv, lock, timeout_ms, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn SleepConditionVariableCS(
    cv: *mut RtlConditionVariable,
    cs: *mut RtlCriticalSection,
    timeout_ms: u32,
) -> i32 {
    unsafe { RtlSleepConditionVariableCS(cv, cs, timeout_ms) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WaitOnAddress(
    addr: *const u8,
    compare: *const u8,
    size: usize,
    timeout_ms: u32,
) -> i32 {
    unsafe { RtlWaitOnAddress(addr, compare, size, timeout_ms) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WakeByAddressSingle(addr: *const u8) {
    unsafe { RtlWakeAddressSingle(addr) };
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WakeByAddressAll(addr: *const u8) {
    unsafe { RtlWakeAddressAll(addr) };
}

// ============================================================================
// Dynamic Module Loading (`LoadLibrary*` / `GetProcAddress`)
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn LoadLibraryA(lib_file_name: *const u8) -> usize {
    let len = unsafe { cstr_len(lib_file_name, 512) };
    host().map_or(0, |h| (h.load_library_utf8)(lib_file_name, len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn LoadLibraryW(lib_file_name: *const u16) -> usize {
    let mut utf8 = [0u8; 512];
    let Some(len) = (unsafe { wstr_to_utf8(lib_file_name, &mut utf8) }) else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    host().map_or(0, |h| (h.load_library_utf8)(utf8.as_ptr(), len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn GetModuleHandleA(module_name: *const u8) -> usize {
    if module_name.is_null() {
        return host().map_or(0, |h| (h.get_module_handle_utf8)(ptr::null(), 0));
    }
    let len = unsafe { cstr_len(module_name, 512) };
    host().map_or(0, |h| (h.get_module_handle_utf8)(module_name, len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn GetModuleHandleW(module_name: *const u16) -> usize {
    if module_name.is_null() {
        return host().map_or(0, |h| (h.get_module_handle_utf8)(ptr::null(), 0));
    }
    let mut utf8 = [0u8; 512];
    let Some(len) = (unsafe { wstr_to_utf8(module_name, &mut utf8) }) else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    host().map_or(0, |h| (h.get_module_handle_utf8)(utf8.as_ptr(), len))
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn GetProcAddress(module: usize, proc_name: *const u8) -> usize {
    if proc_name.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let raw = proc_name as usize;
    if raw <= 0xffff {
        return host().map_or(0, |h| {
            (h.get_proc_address)(module, ptr::null(), 0, raw as u32)
        });
    }
    let len = unsafe { cstr_len(proc_name, 512) };
    host().map_or(0, |h| (h.get_proc_address)(module, proc_name, len, 0))
}

#[unsafe(no_mangle)]
pub extern "win64" fn FreeLibrary(module: usize) -> i32 {
    host().map_or(FALSE, |h| (h.free_library)(module))
}

// ============================================================================
// Process, CLI, Environment, Time, and System Info
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn ExitProcess(exit_code: u32) -> ! {
    // SAFETY: terminates process via `ntdll!NtTerminateProcess`.
    unsafe { NtTerminateProcess(usize::MAX, exit_code) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCommandLineA() -> *const u8 {
    host().map_or(c"".as_ptr().cast::<u8>(), |h| (h.get_command_line_a)())
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetCommandLineW() -> *const u16 {
    static EMPTY_W: [u16; 1] = [0];
    host().map_or(EMPTY_W.as_ptr(), |h| (h.get_command_line_w)())
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetEnvironmentStringsW() -> *const u16 {
    static EMPTY_ENV: [u16; 2] = [0, 0];
    host().map_or(EMPTY_ENV.as_ptr(), |h| (h.get_env_strings_w)())
}

#[unsafe(no_mangle)]
pub extern "win64" fn FreeEnvironmentStringsW(_env: *const u16) -> i32 {
    TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn QueryPerformanceCounter(out_count: *mut u64) -> i32 {
    if out_count.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let Some(h) = host() else {
        return FALSE;
    };
    // SAFETY: `out_count` checked non-null.
    unsafe { ptr::write(out_count, (h.query_perf_counter)()) };
    TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn QueryPerformanceFrequency(out_freq: *mut u64) -> i32 {
    if out_freq.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let Some(h) = host() else {
        return FALSE;
    };
    // SAFETY: `out_freq` checked non-null.
    unsafe { ptr::write(out_freq, (h.query_perf_freq)()) };
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetTickCount64() -> u64 {
    host().map_or(0, |h| (h.get_tick_count64)())
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn GetSystemTimeAsFileTime(out_ft: *mut u64) {
    if !out_ft.is_null() {
        // 1601->1970 epoch offset + boot ticks in 100ns units.
        let base_100ns: u64 = 116_444_736_000_000_000;
        let ticks_ms = GetTickCount64();
        // SAFETY: `out_ft` checked non-null.
        unsafe { ptr::write_unaligned(out_ft, base_100ns.saturating_add(ticks_ms * 10_000)) };
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn Sleep(milliseconds: u32) {
    if let Some(h) = host() {
        (h.sleep_ms)(milliseconds);
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn SwitchToThread() -> i32 {
    Sleep(0);
    TRUE
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn GetSystemInfo(info: *mut SystemInfo64) {
    if info.is_null() {
        return;
    }
    let cpus = host().map_or(1, |h| (h.get_num_cpus)());
    let mask = if cpus >= 64 {
        usize::MAX
    } else {
        (1usize << cpus) - 1
    };
    // SAFETY: `info` checked non-null.
    unsafe {
        ptr::write(
            info,
            SystemInfo64 {
                processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
                reserved: 0,
                page_size: 4096,
                minimum_application_address: 0x1_0000,
                maximum_application_address: 0x0000_7fff_fffe_ffff,
                active_processor_mask: mask,
                number_of_processors: cpus,
                processor_type: 8664,
                allocation_granularity: 0x1_0000,
                processor_level: 6,
                processor_revision: 0,
            },
        );
    }
}
