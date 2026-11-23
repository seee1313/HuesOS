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
use core::sync::atomic::{AtomicUsize, Ordering};

use huesos_pe::win64_abi::{
    DEFAULT_PROCESS_HEAP, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY, ERROR_SUCCESS, FALSE, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT,
    INVALID_HANDLE_VALUE, PeHostApi, RtlConditionVariable, RtlCriticalSection, RtlSrwLock,
    SystemInfo64, TLS_MINIMUM_AVAILABLE, TLS_OUT_OF_INDEXES, TRUE, WAIT_FAILED, Win64FlsCallback,
    Win64ThreadStart, teb_offsets,
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

    fn RtlEncodePointer(ptr_val: usize) -> usize;
    fn RtlDecodePointer(ptr_val: usize) -> usize;
    fn RtlInitializeSListHead(list_head: *mut [u64; 2]);

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

// ============================================================================
// Fiber-Local Storage (`Fls*`), Wide/UTF-8 Conversion, Console, & SEH Forwarders
// ============================================================================

static FLS_CALLBACKS: [AtomicUsize; TLS_MINIMUM_AVAILABLE] =
    [const { AtomicUsize::new(0) }; TLS_MINIMUM_AVAILABLE];
static UNHANDLED_FILTER: AtomicUsize = AtomicUsize::new(0);
static CONSOLE_IN_MODE: AtomicUsize = AtomicUsize::new(0x0007);
static CONSOLE_OUT_MODE: AtomicUsize = AtomicUsize::new(0x0007); // ENABLE_VIRTUAL_TERMINAL_PROCESSING | PROCESSED_OUTPUT

#[unsafe(no_mangle)]
pub extern "win64" fn FlsAlloc(callback: Option<Win64FlsCallback>) -> u32 {
    let idx = TlsAlloc();
    if idx != TLS_OUT_OF_INDEXES && (idx as usize) < TLS_MINIMUM_AVAILABLE {
        let cb_addr = callback.map_or(0, |f| f as usize);
        FLS_CALLBACKS[idx as usize].store(cb_addr, Ordering::Release);
    }
    idx
}

#[unsafe(no_mangle)]
pub extern "win64" fn FlsGetValue(index: u32) -> usize {
    TlsGetValue(index)
}

#[unsafe(no_mangle)]
pub extern "win64" fn FlsSetValue(index: u32, value: usize) -> i32 {
    TlsSetValue(index, value)
}

#[unsafe(no_mangle)]
pub extern "win64" fn FlsFree(index: u32) -> i32 {
    if (index as usize) < TLS_MINIMUM_AVAILABLE {
        let val = TlsGetValue(index);
        let cb = FLS_CALLBACKS[index as usize].swap(0, Ordering::AcqRel);
        if cb != 0 && val != 0 {
            // SAFETY: `cb` was registered via `FlsAlloc` as `Win64FlsCallback`.
            unsafe {
                let func: Win64FlsCallback = core::mem::transmute(cb);
                func(val);
            }
        }
    }
    TlsFree(index)
}

#[unsafe(no_mangle)]
pub extern "win64" fn MultiByteToWideChar(
    _code_page: u32,
    _flags: u32,
    mb_str: *const u8,
    mb_len: i32,
    wide_buf: *mut u16,
    wide_cap: i32,
) -> i32 {
    if mb_str.is_null() || mb_len == 0 || wide_cap < 0 {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let (in_len, include_nul) = if mb_len < 0 {
        // SAFETY: `mb_str` is NUL-terminated when `mb_len == -1`.
        (unsafe { cstr_len(mb_str, 65_536) }, true)
    } else {
        (mb_len as usize, false)
    };
    // SAFETY: `mb_str` valid for `in_len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(mb_str, in_len) };
    let text = core::str::from_utf8(bytes);

    let mut needed = 0usize;
    match text {
        Ok(s) => {
            for ch in s.chars() {
                let mut u16s = [0u16; 2];
                let enc = ch.encode_utf16(&mut u16s);
                if wide_cap > 0 && !wide_buf.is_null() {
                    if needed + enc.len() > wide_cap as usize {
                        SetLastError(ERROR_INSUFFICIENT_BUFFER);
                        return 0;
                    }
                    for &w in enc.iter() {
                        // SAFETY: `needed < wide_cap`.
                        unsafe { ptr::write_unaligned(wide_buf.add(needed), w) };
                        needed += 1;
                    }
                } else {
                    needed += enc.len();
                }
            }
        }
        Err(_) => {
            for &b in bytes {
                if wide_cap > 0 && !wide_buf.is_null() {
                    if needed >= wide_cap as usize {
                        SetLastError(ERROR_INSUFFICIENT_BUFFER);
                        return 0;
                    }
                    // SAFETY: `needed < wide_cap`.
                    unsafe { ptr::write_unaligned(wide_buf.add(needed), u16::from(b)) };
                }
                needed += 1;
            }
        }
    }
    if include_nul {
        if wide_cap > 0 && !wide_buf.is_null() {
            if needed >= wide_cap as usize {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            // SAFETY: `needed < wide_cap`.
            unsafe { ptr::write_unaligned(wide_buf.add(needed), 0) };
        }
        needed += 1;
    }
    needed as i32
}

#[unsafe(no_mangle)]
pub extern "win64" fn WideCharToMultiByte(
    _code_page: u32,
    _flags: u32,
    wide_str: *const u16,
    wide_len: i32,
    mb_buf: *mut u8,
    mb_cap: i32,
    _default_char: *const u8,
    _used_default: *mut i32,
) -> i32 {
    if wide_str.is_null() || wide_len == 0 || mb_cap < 0 {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let (units, include_nul) = if wide_len < 0 {
        let mut n = 0usize;
        while n < 65_536 {
            // SAFETY: `wide_str` NUL-terminated when `wide_len < 0`.
            if unsafe { ptr::read_unaligned(wide_str.add(n)) } == 0 {
                break;
            }
            n += 1;
        }
        (n, true)
    } else {
        (wide_len as usize, false)
    };

    let mut iter_units = (0..units).map(|i| {
        // SAFETY: `i < units` within `wide_str`.
        unsafe { ptr::read_unaligned(wide_str.add(i)) }
    });
    let mut needed = 0usize;
    for decoded in core::char::decode_utf16(&mut iter_units) {
        let ch = decoded.unwrap_or('\u{FFFD}');
        let mut enc = [0u8; 4];
        let utf8 = ch.encode_utf8(&mut enc).as_bytes();
        if mb_cap > 0 && !mb_buf.is_null() {
            if needed + utf8.len() > mb_cap as usize {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            // SAFETY: `needed + utf8.len() <= mb_cap`.
            unsafe {
                ptr::copy_nonoverlapping(utf8.as_ptr(), mb_buf.add(needed), utf8.len());
            }
        }
        needed += utf8.len();
    }
    if include_nul {
        if mb_cap > 0 && !mb_buf.is_null() {
            if needed >= mb_cap as usize {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            // SAFETY: `needed < mb_cap`.
            unsafe { ptr::write(mb_buf.add(needed), 0) };
        }
        needed += 1;
    }
    needed as i32
}

#[unsafe(no_mangle)]
pub extern "win64" fn WriteConsoleW(
    console_output: usize,
    buffer: *const u16,
    chars_to_write: u32,
    chars_written: *mut u32,
    _reserved: usize,
) -> i32 {
    if buffer.is_null() && chars_to_write > 0 {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let mut utf8_chunk = [0u8; 1024];
    let mut i = 0usize;
    let total = chars_to_write as usize;
    while i < total {
        let mut used = 0usize;
        while i < total && used + 4 <= utf8_chunk.len() {
            // SAFETY: `i < total` inside `buffer`.
            let u = unsafe { ptr::read_unaligned(buffer.add(i)) };
            i += 1;
            let ch = char::from_u32(u32::from(u)).unwrap_or('?');
            let mut enc = [0u8; 4];
            let s = ch.encode_utf8(&mut enc).as_bytes();
            utf8_chunk[used..used + s.len()].copy_from_slice(s);
            used += s.len();
        }
        let mut dummy = 0u32;
        if WriteFile(
            console_output,
            utf8_chunk.as_ptr(),
            used as u32,
            &raw mut dummy,
            0,
        ) == FALSE
        {
            return FALSE;
        }
    }
    if !chars_written.is_null() {
        // SAFETY: `chars_written` checked non-null.
        unsafe { ptr::write_unaligned(chars_written, chars_to_write) };
    }
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetConsoleMode(handle: usize, out_mode: *mut u32) -> i32 {
    if out_mode.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let mode = if handle == HANDLE_STDIN {
        CONSOLE_IN_MODE.load(Ordering::Relaxed) as u32
    } else if handle == HANDLE_STDOUT || handle == HANDLE_STDERR {
        CONSOLE_OUT_MODE.load(Ordering::Relaxed) as u32
    } else {
        SetLastError(6); // ERROR_INVALID_HANDLE
        return FALSE;
    };
    // SAFETY: `out_mode` checked non-null.
    unsafe { ptr::write_unaligned(out_mode, mode) };
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn SetConsoleMode(handle: usize, mode: u32) -> i32 {
    if handle == HANDLE_STDIN {
        CONSOLE_IN_MODE.store(mode as usize, Ordering::Relaxed);
        TRUE
    } else if handle == HANDLE_STDOUT || handle == HANDLE_STDERR {
        CONSOLE_OUT_MODE.store(mode as usize, Ordering::Relaxed);
        TRUE
    } else {
        SetLastError(6);
        FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetFileType(handle: usize) -> u32 {
    if handle == HANDLE_STDIN || handle == HANDLE_STDOUT || handle == HANDLE_STDERR {
        2 // FILE_TYPE_CHAR (console TTY)
    } else if handle == 0 || handle == INVALID_HANDLE_VALUE {
        0 // FILE_TYPE_UNKNOWN
    } else {
        1 // FILE_TYPE_DISK
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn FlushFileBuffers(_handle: usize) -> i32 {
    TRUE
}

#[unsafe(no_mangle)]
pub extern "win64" fn InitializeCriticalSectionEx(
    cs: *mut RtlCriticalSection,
    spin_count: u32,
    _flags: u32,
) -> i32 {
    // SAFETY: delegates to `ntdll` critical section init.
    unsafe {
        if RtlInitializeCriticalSectionAndSpinCount(cs, spin_count) == 0 {
            TRUE
        } else {
            FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn LoadLibraryExA(lib_file_name: *const u8, _file: usize, _flags: u32) -> usize {
    // SAFETY: delegates to `LoadLibraryA`.
    unsafe { LoadLibraryA(lib_file_name) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn LoadLibraryExW(
    lib_file_name: *const u16,
    _file: usize,
    _flags: u32,
) -> usize {
    // SAFETY: delegates to `LoadLibraryW`.
    unsafe { LoadLibraryW(lib_file_name) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetModuleHandleExA(
    _flags: u32,
    module_name: *const u8,
    out_module: *mut usize,
) -> i32 {
    if out_module.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: delegates to `GetModuleHandleA` and writes non-null `out_module`.
    let h = unsafe { GetModuleHandleA(module_name) };
    // SAFETY: `out_module` checked non-null.
    unsafe { ptr::write_unaligned(out_module, h) };
    if h != 0 { TRUE } else { FALSE }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetModuleHandleExW(
    _flags: u32,
    module_name: *const u16,
    out_module: *mut usize,
) -> i32 {
    if out_module.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: delegates to `GetModuleHandleW`.
    let h = unsafe { GetModuleHandleW(module_name) };
    // SAFETY: `out_module` checked non-null.
    unsafe { ptr::write_unaligned(out_module, h) };
    if h != 0 { TRUE } else { FALSE }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetModuleFileNameA(_module: usize, filename: *mut u8, size: u32) -> u32 {
    const DEFAULT_NAME: &[u8] = b"C:\\bin\\app.exe";
    if filename.is_null() || size == 0 {
        return 0;
    }
    let copy_len = DEFAULT_NAME.len().min((size as usize).saturating_sub(1));
    // SAFETY: `filename` valid for `size` bytes.
    unsafe {
        ptr::copy_nonoverlapping(DEFAULT_NAME.as_ptr(), filename, copy_len);
        ptr::write(filename.add(copy_len), 0);
    }
    copy_len as u32
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetModuleFileNameW(_module: usize, filename: *mut u16, size: u32) -> u32 {
    const DEFAULT_NAME: &[u8] = b"C:\\bin\\app.exe";
    if filename.is_null() || size == 0 {
        return 0;
    }
    let copy_len = DEFAULT_NAME.len().min((size as usize).saturating_sub(1));
    for i in 0..copy_len {
        // SAFETY: `i < size` within `filename`.
        unsafe { ptr::write_unaligned(filename.add(i), u16::from(DEFAULT_NAME[i])) };
    }
    // SAFETY: `copy_len < size` within `filename`.
    unsafe { ptr::write_unaligned(filename.add(copy_len), 0) };
    copy_len as u32
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetSystemTimePreciseAsFileTime(out_ft: *mut u64) {
    // SAFETY: delegates to `GetSystemTimeAsFileTime`.
    unsafe { GetSystemTimeAsFileTime(out_ft) };
}

#[unsafe(no_mangle)]
pub extern "win64" fn IsDebuggerPresent() -> i32 {
    FALSE
}

#[unsafe(no_mangle)]
pub extern "win64" fn IsProcessorFeaturePresent(feature: u32) -> i32 {
    // PF_FASTFAIL_AVAILABLE (23), PF_COMPARE_EXCHANGE_DOUBLE (2), PF_RDTSC_INSTRUCTION_AVAILABLE (8)
    if matches!(feature, 2 | 8 | 23) {
        TRUE
    } else {
        FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn SetUnhandledExceptionFilter(filter: usize) -> usize {
    UNHANDLED_FILTER.swap(filter, Ordering::AcqRel)
}

#[unsafe(no_mangle)]
pub extern "win64" fn UnhandledExceptionFilter(_exception_info: usize) -> i32 {
    1 // EXCEPTION_EXECUTE_HANDLER
}

#[unsafe(no_mangle)]
pub extern "win64" fn RaiseException(code: u32, _flags: u32, _num_args: u32, _args: usize) -> ! {
    ExitProcess(code)
}

#[unsafe(no_mangle)]
pub extern "win64" fn EncodePointer(ptr_val: usize) -> usize {
    // SAFETY: forwards to `ntdll::RtlEncodePointer`.
    unsafe { RtlEncodePointer(ptr_val) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DecodePointer(ptr_val: usize) -> usize {
    // SAFETY: forwards to `ntdll::RtlDecodePointer`.
    unsafe { RtlDecodePointer(ptr_val) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn InitializeSListHead(list_head: *mut [u64; 2]) {
    // SAFETY: forwards to `ntdll::RtlInitializeSListHead`.
    unsafe { RtlInitializeSListHead(list_head) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetACP() -> u32 {
    65001 // CP_UTF8
}

#[unsafe(no_mangle)]
pub extern "win64" fn GetOEMCP() -> u32 {
    65001
}

#[unsafe(no_mangle)]
pub extern "win64" fn IsValidCodePage(cp: u32) -> i32 {
    if matches!(cp, 0 | 437 | 1252 | 65000 | 65001) {
        TRUE
    } else {
        FALSE
    }
}
