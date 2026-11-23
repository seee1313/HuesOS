//! Minimal `#![no_std]` Win64 SDK bindings (`kernel32.dll` + `ntdll.dll` IAT imports)
//! shared by `/bin/win-hello.exe`, `/bin/win-threads.exe`, and `/bin/win-bench.exe`.

#![no_std]
#![allow(clippy::missing_safety_doc)]

use core::fmt::{self, Write};
pub use huesos_pe::win64_abi::*;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "win64" {
    pub fn GetStdHandle(std_handle: u32) -> usize;
    pub fn WriteFile(
        handle: usize,
        buf: *const u8,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: usize,
    ) -> i32;
    pub fn ReadFile(
        handle: usize,
        buf: *mut u8,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: usize,
    ) -> i32;
    pub fn CreateFileA(
        file_name: *const u8,
        desired_access: u32,
        share_mode: u32,
        security_attrs: usize,
        creation_disposition: u32,
        flags_and_attrs: u32,
        template_file: usize,
    ) -> usize;
    pub fn CloseHandle(handle: usize) -> i32;

    pub fn GetLastError() -> u32;
    pub fn SetLastError(err: u32);
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetCurrentProcessId() -> u32;

    pub fn GetProcessHeap() -> usize;
    pub fn HeapAlloc(heap: usize, flags: u32, bytes: usize) -> usize;
    pub fn HeapFree(heap: usize, flags: u32, mem: usize) -> i32;

    pub fn VirtualAlloc(addr: usize, size: usize, alloc_type: u32, protect: u32) -> usize;
    pub fn VirtualProtect(addr: usize, size: usize, new_protect: u32, old_protect: *mut u32)
    -> i32;
    pub fn VirtualFree(addr: usize, size: usize, free_type: u32) -> i32;

    pub fn CreateThread(
        thread_attrs: usize,
        stack_size: usize,
        start_address: Win64ThreadStart,
        parameter: usize,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> usize;
    pub fn WaitForSingleObject(handle: usize, milliseconds: u32) -> u32;
    pub fn WaitForMultipleObjects(
        count: u32,
        handles: *const usize,
        wait_all: i32,
        milliseconds: u32,
    ) -> u32;
    pub fn GetExitCodeThread(thread: usize, out_exit_code: *mut u32) -> i32;

    pub fn CreateEventA(
        attrs: usize,
        manual_reset: i32,
        initial_state: i32,
        name: *const u8,
    ) -> usize;
    pub fn SetEvent(event: usize) -> i32;

    pub fn InitializeCriticalSection(cs: *mut RtlCriticalSection);
    pub fn EnterCriticalSection(cs: *mut RtlCriticalSection);
    pub fn LeaveCriticalSection(cs: *mut RtlCriticalSection);
    pub fn DeleteCriticalSection(cs: *mut RtlCriticalSection);

    pub fn InitializeSRWLock(lock: *mut RtlSrwLock);
    pub fn AcquireSRWLockExclusive(lock: *mut RtlSrwLock);
    pub fn ReleaseSRWLockExclusive(lock: *mut RtlSrwLock);

    pub fn InitializeConditionVariable(cv: *mut RtlConditionVariable);
    pub fn WakeAllConditionVariable(cv: *mut RtlConditionVariable);
    pub fn SleepConditionVariableSRW(
        cv: *mut RtlConditionVariable,
        lock: *mut RtlSrwLock,
        timeout_ms: u32,
        flags: u32,
    ) -> i32;

    pub fn TlsAlloc() -> u32;
    pub fn TlsGetValue(index: u32) -> usize;
    pub fn TlsSetValue(index: u32, value: usize) -> i32;
    pub fn TlsFree(index: u32) -> i32;

    pub fn LoadLibraryA(lib_file_name: *const u8) -> usize;
    pub fn GetModuleHandleA(module_name: *const u8) -> usize;
    pub fn GetProcAddress(module: usize, proc_name: *const u8) -> usize;

    pub fn GetCommandLineA() -> *const u8;
    pub fn QueryPerformanceCounter(out_count: *mut u64) -> i32;
    pub fn QueryPerformanceFrequency(out_freq: *mut u64) -> i32;
    pub fn GetTickCount64() -> u64;
    pub fn GetSystemInfo(info: *mut SystemInfo64);
    pub fn Sleep(milliseconds: u32);
    pub fn ExitProcess(exit_code: u32) -> !;
}

/// Read current TEB self-pointer directly from `gs:[0x30]` in Ring 3.
#[inline]
pub fn read_gs_teb_self() -> usize {
    let val: usize;
    // SAFETY: `GS_BASE` points to the 8 KiB Win64 TEB in every PE64 thread.
    unsafe {
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) val, options(nostack, preserves_flags, readonly));
    }
    val
}

/// Read process PEB pointer directly from `gs:[0x60]` in Ring 3.
#[inline]
pub fn read_gs_peb() -> usize {
    let val: usize;
    // SAFETY: `gs:[0x60]` holds the PEB pointer in every Win64 TEB.
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) val, options(nostack, preserves_flags, readonly));
    }
    val
}

/// Buffered stack console writer over `WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), ...)`.
pub struct ConsoleOut {
    handle: usize,
    buf: [u8; 512],
    len: usize,
}

impl ConsoleOut {
    pub fn stdout() -> Self {
        // SAFETY: Win32 `GetStdHandle` import.
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        Self {
            handle,
            buf: [0u8; 512],
            len: 0,
        }
    }

    pub fn flush(&mut self) {
        if self.len > 0 && self.handle != INVALID_HANDLE_VALUE {
            let mut written = 0u32;
            // SAFETY: `self.buf[..self.len]` is valid stack storage.
            unsafe {
                let _ = WriteFile(
                    self.handle,
                    self.buf.as_ptr(),
                    self.len as u32,
                    &mut written,
                    0,
                );
            }
            self.len = 0;
        }
    }
}

impl Write for ConsoleOut {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

impl Drop for ConsoleOut {
    fn drop(&mut self) {
        self.flush();
    }
}

#[macro_export]
macro_rules! win_println {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut out = $crate::ConsoleOut::stdout();
        let _ = writeln!(out, $($arg)*);
        out.flush();
    }};
}
