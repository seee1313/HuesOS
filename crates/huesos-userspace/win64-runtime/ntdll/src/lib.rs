//! HuesOS native PE32+ `/lib/ntdll.dll` (`x86_64` MS Win64 ABI).
//!
//! Executes directly in Ring 3 as a relocated PE32+ DLL, reading and mutating the
//! per-thread Win64 `TEB` via `gs:[...]` (`NtCurrentTeb`, `RtlGetCurrentPeb`,
//! `RtlGetLastWin32Error`, `RtlSetLastWin32Error`, `RtlGetCurrentThreadId`),
//! implementing fast userspace synchronization (`CRITICAL_SECTION`, `SRWLOCK`,
//! `CONDITION_VARIABLE`, `RtlWaitOnAddress`) over hardware atomics + futex, and
//! bridging kernel-backed operations through [`PeHostApi`].

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use huesos_pe::win64_abi::{
    ERROR_INVALID_PARAMETER, ERROR_SUCCESS, ERROR_TIMEOUT, FALSE, INFINITE, PE_HOST_API_VERSION,
    PeHostApi, RtlConditionVariable, RtlCriticalSection, RtlSrwLock, TRUE, Win64Context,
};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

static HOST_API: AtomicPtr<PeHostApi> = AtomicPtr::new(ptr::null_mut());

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let api = HOST_API.load(Ordering::Acquire);
    if !api.is_null() {
        // SAFETY: `api` points to static `PE_HOST_API` in `/lib/ld-pe.so`.
        unsafe { ((*api).exit_process)(101) }
    }
    loop {
        core::hint::spin_loop();
    }
}

#[inline]
fn host() -> Option<&'static PeHostApi> {
    let ptr = HOST_API.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `ptr` was installed by `ld-pe` from static `'static` storage.
        Some(unsafe { &*ptr })
    }
}

/// DLL entry point invoked by `/lib/ld-pe.so` on process/thread attach & detach.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn _DllMainCRTStartup(
    _hinst_dll: usize,
    _reason: u32,
    _reserved: usize,
) -> i32 {
    TRUE
}

/// Loader bootstrap hook invoked by `/lib/ld-pe.so` immediately after mapping `ntdll.dll`.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn __huesos_ntdll_bind_host(api: *const PeHostApi) {
    if !api.is_null() {
        // SAFETY: `api` is valid static `PeHostApi` provided by `/lib/ld-pe.so`.
        let ver = unsafe { (*api).version };
        if ver == PE_HOST_API_VERSION {
            HOST_API.store(api.cast_mut(), Ordering::Release);
        }
    }
}

/// Internal accessor imported by `kernel32.dll` for host-backed Win32 operations.
#[unsafe(no_mangle)]
pub extern "win64" fn __huesos_ntdll_host() -> *const PeHostApi {
    HOST_API.load(Ordering::Acquire).cast_const()
}

/// Return linear address of current thread's `TEB` (`gs:[0x30]`).
#[unsafe(no_mangle)]
pub extern "win64" fn NtCurrentTeb() -> usize {
    let teb: usize;
    // SAFETY: `GS_BASE` points to the 8 KiB Win64 TEB initialized by `ld-pe`.
    unsafe {
        asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags, readonly));
    }
    teb
}

/// Return linear address of process `PEB` (`gs:[0x60]`).
#[unsafe(no_mangle)]
pub extern "win64" fn RtlGetCurrentPeb() -> usize {
    let peb: usize;
    // SAFETY: `gs:[0x60]` holds the process PEB pointer in every Win64 TEB.
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
    }
    peb
}

/// Read Win32 `LastErrorValue` directly from `gs:[0x68]`.
#[unsafe(no_mangle)]
pub extern "win64" fn RtlGetLastWin32Error() -> u32 {
    let code: u32;
    // SAFETY: `gs:[0x68]` is the Win64 TEB `LastErrorValue` slot.
    unsafe {
        asm!("mov {:e}, dword ptr gs:[0x68]", out(reg) code, options(nostack, preserves_flags, readonly));
    }
    code
}

/// Write Win32 `LastErrorValue` directly to `gs:[0x68]`.
#[unsafe(no_mangle)]
pub extern "win64" fn RtlSetLastWin32Error(code: u32) {
    // SAFETY: `gs:[0x68]` is writable thread-local TEB memory.
    unsafe {
        asm!("mov dword ptr gs:[0x68], {:e}", in(reg) code, options(nostack, preserves_flags));
    }
}

/// Read current Win64 thread ID directly from `gs:[0x48]`.
#[unsafe(no_mangle)]
pub extern "win64" fn RtlGetCurrentThreadId() -> u32 {
    let tid: u64;
    // SAFETY: `gs:[0x48]` is `ClientId.UniqueThread` in the Win64 TEB.
    unsafe {
        asm!("mov {}, gs:[0x48]", out(reg) tid, options(nostack, preserves_flags, readonly));
    }
    tid as u32
}

// ============================================================================
// Critical Section (`RTL_CRITICAL_SECTION`)
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlInitializeCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    unsafe { RtlInitializeCriticalSectionAndSpinCount(cs, 256) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlInitializeCriticalSectionAndSpinCount(
    cs: *mut RtlCriticalSection,
    spin_count: u32,
) -> i32 {
    if cs.is_null() {
        return -1;
    }
    // SAFETY: caller supplied valid `RtlCriticalSection` pointer.
    unsafe {
        ptr::write(
            cs,
            RtlCriticalSection {
                debug_info: 0,
                lock_count: 0,
                recursion_count: 0,
                owning_thread: 0,
                lock_semaphore: 0,
                spin_count: spin_count as usize,
            },
        );
    }
    0 // STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlTryEnterCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    if cs.is_null() {
        return FALSE;
    }
    let me = RtlGetCurrentThreadId() as usize;
    // SAFETY: `cs` is valid and aligned.
    let cs_ref = unsafe { &mut *cs };
    let state =
        // SAFETY: `lock_count` is a 4-byte aligned `u32`.
        unsafe { &*(&raw const cs_ref.lock_count as *const AtomicU32) };

    if cs_ref.owning_thread == me && state.load(Ordering::Acquire) != 0 {
        cs_ref.recursion_count = cs_ref.recursion_count.saturating_add(1);
        return TRUE;
    }
    if state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        cs_ref.owning_thread = me;
        cs_ref.recursion_count = 1;
        return TRUE;
    }
    FALSE
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlEnterCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    if cs.is_null() {
        return -1;
    }
    let me = RtlGetCurrentThreadId() as usize;
    // SAFETY: `cs` is valid and aligned.
    let cs_ref = unsafe { &mut *cs };
    // SAFETY: `lock_count` is 4-byte aligned.
    let state = unsafe { &*(&raw const cs_ref.lock_count as *const AtomicU32) };

    if cs_ref.owning_thread == me && state.load(Ordering::Acquire) != 0 {
        cs_ref.recursion_count = cs_ref.recursion_count.saturating_add(1);
        return 0;
    }

    for _ in 0..cs_ref.spin_count.min(512) {
        if state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            cs_ref.owning_thread = me;
            cs_ref.recursion_count = 1;
            return 0;
        }
        core::hint::spin_loop();
    }

    if state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while state.swap(2, Ordering::Acquire) != 0 {
            if let Some(h) = host() {
                let _ = (h.futex_wait)(state as *const AtomicU32 as *const u32, 2, INFINITE);
            } else {
                core::hint::spin_loop();
            }
        }
    }
    cs_ref.owning_thread = me;
    cs_ref.recursion_count = 1;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlLeaveCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    if cs.is_null() {
        return -1;
    }
    // SAFETY: `cs` is valid and owned by calling thread.
    let cs_ref = unsafe { &mut *cs };
    if cs_ref.recursion_count > 1 {
        cs_ref.recursion_count -= 1;
        return 0;
    }
    cs_ref.recursion_count = 0;
    cs_ref.owning_thread = 0;
    // SAFETY: `lock_count` is 4-byte aligned.
    let state = unsafe { &*(&raw const cs_ref.lock_count as *const AtomicU32) };
    if state.swap(0, Ordering::Release) == 2
        && let Some(h) = host()
    {
        let _ = (h.futex_wake)(state as *const AtomicU32 as *const u32, 1);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlDeleteCriticalSection(cs: *mut RtlCriticalSection) -> i32 {
    if !cs.is_null() {
        // SAFETY: `cs` is valid.
        unsafe {
            (*cs).owning_thread = 0;
            (*cs).recursion_count = 0;
            (*cs).lock_count = 0;
        }
    }
    0
}

// ============================================================================
// Slim Reader/Writer Lock (`RTL_SRWLOCK`) & Condition Variable
// ============================================================================

const SRW_EXCLUSIVE_LOCKED: u32 = 0xffff_ffff;

#[inline]
unsafe fn srw_word(lock: *mut RtlSrwLock) -> &'static AtomicU32 {
    // SAFETY: `RtlSrwLock` is 8-byte aligned (`usize`), so its low 32 bits are 4-byte aligned.
    unsafe { &*(lock as *const AtomicU32) }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlInitializeSRWLock(lock: *mut RtlSrwLock) {
    if !lock.is_null() {
        // SAFETY: `lock` is valid.
        unsafe { (*lock).ptr = 0 };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlTryAcquireSRWLockExclusive(lock: *mut RtlSrwLock) -> u8 {
    if lock.is_null() {
        return 0;
    }
    let w = unsafe { srw_word(lock) };
    u8::from(
        w.compare_exchange(
            0,
            SRW_EXCLUSIVE_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok(),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlAcquireSRWLockExclusive(lock: *mut RtlSrwLock) {
    if lock.is_null() {
        return;
    }
    let w = unsafe { srw_word(lock) };
    loop {
        let cur = w.load(Ordering::Relaxed);
        if cur == 0
            && w.compare_exchange_weak(
                0,
                SRW_EXCLUSIVE_LOCKED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return;
        }
        if let Some(h) = host() {
            let _ = (h.futex_wait)(w as *const AtomicU32 as *const u32, cur, INFINITE);
        } else {
            core::hint::spin_loop();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlReleaseSRWLockExclusive(lock: *mut RtlSrwLock) {
    if lock.is_null() {
        return;
    }
    let w = unsafe { srw_word(lock) };
    w.store(0, Ordering::Release);
    if let Some(h) = host() {
        let _ = (h.futex_wake)(w as *const AtomicU32 as *const u32, u32::MAX);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlTryAcquireSRWLockShared(lock: *mut RtlSrwLock) -> u8 {
    if lock.is_null() {
        return 0;
    }
    let w = unsafe { srw_word(lock) };
    let mut cur = w.load(Ordering::Relaxed);
    while cur < SRW_EXCLUSIVE_LOCKED - 1 {
        match w.compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return 1,
            Err(actual) => cur = actual,
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlAcquireSRWLockShared(lock: *mut RtlSrwLock) {
    if lock.is_null() {
        return;
    }
    let w = unsafe { srw_word(lock) };
    loop {
        let cur = w.load(Ordering::Relaxed);
        if cur < SRW_EXCLUSIVE_LOCKED - 1
            && w.compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
        if let Some(h) = host() {
            let _ = (h.futex_wait)(w as *const AtomicU32 as *const u32, cur, INFINITE);
        } else {
            core::hint::spin_loop();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlReleaseSRWLockShared(lock: *mut RtlSrwLock) {
    if lock.is_null() {
        return;
    }
    let w = unsafe { srw_word(lock) };
    if w.fetch_sub(1, Ordering::Release) == 1
        && let Some(h) = host()
    {
        let _ = (h.futex_wake)(w as *const AtomicU32 as *const u32, u32::MAX);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlInitializeConditionVariable(cv: *mut RtlConditionVariable) {
    if !cv.is_null() {
        // SAFETY: `cv` is valid.
        unsafe { (*cv).ptr = 0 };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlWakeConditionVariable(cv: *mut RtlConditionVariable) {
    if cv.is_null() {
        return;
    }
    // SAFETY: `cv` is 8-byte aligned.
    let seq = unsafe { &*(cv as *const AtomicU32) };
    seq.fetch_add(1, Ordering::Release);
    if let Some(h) = host() {
        let _ = (h.futex_wake)(seq as *const AtomicU32 as *const u32, 1);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlWakeAllConditionVariable(cv: *mut RtlConditionVariable) {
    if cv.is_null() {
        return;
    }
    // SAFETY: `cv` is 8-byte aligned.
    let seq = unsafe { &*(cv as *const AtomicU32) };
    seq.fetch_add(1, Ordering::Release);
    if let Some(h) = host() {
        let _ = (h.futex_wake)(seq as *const AtomicU32 as *const u32, u32::MAX);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlSleepConditionVariableSRW(
    cv: *mut RtlConditionVariable,
    lock: *mut RtlSrwLock,
    timeout_ms: u32,
    flags: u32,
) -> i32 {
    if cv.is_null() || lock.is_null() {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `cv` is valid.
    let seq = unsafe { &*(cv as *const AtomicU32) };
    let observed = seq.load(Ordering::Acquire);
    let shared = (flags & 1) != 0;
    unsafe {
        if shared {
            RtlReleaseSRWLockShared(lock);
        } else {
            RtlReleaseSRWLockExclusive(lock);
        }
    }
    let rc = match host() {
        Some(h) => (h.futex_wait)(seq as *const AtomicU32 as *const u32, observed, timeout_ms),
        None => ERROR_INVALID_PARAMETER,
    };
    unsafe {
        if shared {
            RtlAcquireSRWLockShared(lock);
        } else {
            RtlAcquireSRWLockExclusive(lock);
        }
    }
    if rc == ERROR_SUCCESS {
        TRUE
    } else {
        RtlSetLastWin32Error(rc);
        FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlSleepConditionVariableCS(
    cv: *mut RtlConditionVariable,
    cs: *mut RtlCriticalSection,
    timeout_ms: u32,
) -> i32 {
    if cv.is_null() || cs.is_null() {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `cv` is valid.
    let seq = unsafe { &*(cv as *const AtomicU32) };
    let observed = seq.load(Ordering::Acquire);
    unsafe {
        let _ = RtlLeaveCriticalSection(cs);
    }
    let rc = match host() {
        Some(h) => (h.futex_wait)(seq as *const AtomicU32 as *const u32, observed, timeout_ms),
        None => ERROR_INVALID_PARAMETER,
    };
    unsafe {
        let _ = RtlEnterCriticalSection(cs);
    }
    if rc == ERROR_SUCCESS {
        TRUE
    } else {
        RtlSetLastWin32Error(rc);
        FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlWaitOnAddress(
    addr: *const u8,
    compare: *const u8,
    size: usize,
    timeout_ms: u32,
) -> i32 {
    if addr.is_null() || compare.is_null() || !matches!(size, 4 | 8) || (addr as usize & 3) != 0 {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let equal = if size == 4 {
        // SAFETY: `addr` and `compare` are valid for 4 bytes.
        unsafe {
            (*(addr as *const AtomicU32)).load(Ordering::SeqCst)
                == ptr::read_unaligned(compare as *const u32)
        }
    } else {
        // SAFETY: `addr` and `compare` are valid for 8 bytes.
        unsafe {
            (*(addr as *const AtomicUsize)).load(Ordering::SeqCst)
                == ptr::read_unaligned(compare as *const usize)
        }
    };
    if !equal {
        return TRUE;
    }
    // SAFETY: `compare` has at least 4 bytes.
    let expected_low = unsafe { ptr::read_unaligned(compare as *const u32) };
    let rc = match host() {
        Some(h) => (h.futex_wait)(addr as *const u32, expected_low, timeout_ms),
        None => ERROR_TIMEOUT,
    };
    if rc == ERROR_SUCCESS {
        TRUE
    } else {
        RtlSetLastWin32Error(rc);
        FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlWakeAddressSingle(addr: *const u8) {
    if let Some(h) = host() {
        let _ = (h.futex_wake)(addr as *const u32, 1);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn RtlWakeAddressAll(addr: *const u8) {
    if let Some(h) = host() {
        let _ = (h.futex_wake)(addr as *const u32, u32::MAX);
    }
}

// ============================================================================
// Rtl Heap, Nt Process/Time, and Ldr Exports
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn RtlCreateHeap(
    flags: u32,
    _base: usize,
    max_sz: usize,
    init_sz: usize,
    _lock: usize,
    _params: usize,
) -> usize {
    host().map_or(0, |h| (h.heap_create)(flags, init_sz, max_sz))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlDestroyHeap(heap: usize) -> usize {
    host().map_or(0, |h| (h.heap_destroy)(heap) as usize)
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> usize {
    host().map_or(0, |h| (h.heap_alloc)(heap, flags, size))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlReAllocateHeap(
    heap: usize,
    flags: u32,
    ptr_val: usize,
    size: usize,
) -> usize {
    host().map_or(0, |h| (h.heap_realloc)(heap, flags, ptr_val, size))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlFreeHeap(heap: usize, flags: u32, ptr_val: usize) -> u8 {
    host().map_or(0, |h| u8::from((h.heap_free)(heap, flags, ptr_val) != 0))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlSizeHeap(heap: usize, flags: u32, ptr_val: usize) -> usize {
    host().map_or(usize::MAX, |h| (h.heap_size)(heap, flags, ptr_val))
}

#[unsafe(no_mangle)]
pub extern "win64" fn NtTerminateProcess(_process_handle: usize, exit_status: u32) -> ! {
    if let Some(h) = host() {
        (h.exit_process)(exit_status)
    }
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn NtDelayExecution(_alertable: u8, interval_100ns: *const i64) -> i32 {
    if interval_100ns.is_null() {
        return -1;
    }
    // SAFETY: `interval_100ns` is non-null. Negative intervals are relative in 100ns units.
    let raw = unsafe { ptr::read(interval_100ns) };
    let ms = if raw < 0 {
        ((-raw) as u64).div_ceil(10_000) as u32
    } else {
        0
    };
    if let Some(h) = host() {
        (h.sleep_ms)(ms);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn NtQueryPerformanceCounter(
    out_counter: *mut u64,
    out_freq: *mut u64,
) -> i32 {
    if out_counter.is_null() {
        return -1;
    }
    let Some(h) = host() else {
        return -1;
    };
    // SAFETY: `out_counter` checked non-null.
    unsafe {
        ptr::write(out_counter, (h.query_perf_counter)());
        if !out_freq.is_null() {
            ptr::write(out_freq, (h.query_perf_freq)());
        }
    }
    0
}

// ============================================================================
// Win64 `.pdata` / `.xdata` SEH & Stack Unwinding (`Rtl*`)
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn RtlLookupFunctionEntry(
    control_pc: u64,
    image_base_out: *mut u64,
    _history_table: usize,
) -> usize {
    host().map_or(0, |h| (h.lookup_function_entry)(control_pc, image_base_out))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlVirtualUnwind(
    handler_type: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: usize,
    ctx: *mut Win64Context,
    handler_data: *mut usize,
    establisher_frame: *mut u64,
    _context_pointers: usize,
) -> usize {
    host().map_or(0, |h| {
        (h.virtual_unwind_step)(
            handler_type,
            image_base,
            control_pc,
            function_entry,
            ctx,
            handler_data,
            establisher_frame,
        )
    })
}

#[inline(always)]
fn capture_context_inline() -> Win64Context {
    let mut ctx = Win64Context::zeroed();
    let rbx_v: u64;
    let rsp_v: u64;
    let rbp_v: u64;
    let rsi_v: u64;
    let rdi_v: u64;
    let r12_v: u64;
    let r13_v: u64;
    let r14_v: u64;
    let r15_v: u64;
    let rip_v: u64;
    // SAFETY: reads current non-volatile registers inline within caller's stack frame.
    unsafe {
        asm!(
            "mov {rbx_o}, rbx",
            "mov {rsp_o}, rsp",
            "mov {rbp_o}, rbp",
            "mov {rsi_o}, rsi",
            "mov {rdi_o}, rdi",
            "mov {r12_o}, r12",
            "mov {r13_o}, r13",
            "mov {r14_o}, r14",
            "mov {r15_o}, r15",
            "lea {rip_o}, [rip + 0]",
            rbx_o = out(reg) rbx_v,
            rsp_o = out(reg) rsp_v,
            rbp_o = out(reg) rbp_v,
            rsi_o = out(reg) rsi_v,
            rdi_o = out(reg) rdi_v,
            r12_o = out(reg) r12_v,
            r13_o = out(reg) r13_v,
            r14_o = out(reg) r14_v,
            r15_o = out(reg) r15_v,
            rip_o = out(reg) rip_v,
            options(nostack, preserves_flags),
        );
    }
    ctx.gpr[3] = rbx_v;
    ctx.gpr[4] = rsp_v;
    ctx.gpr[5] = rbp_v;
    ctx.gpr[6] = rsi_v;
    ctx.gpr[7] = rdi_v;
    ctx.gpr[12] = r12_v;
    ctx.gpr[13] = r13_v;
    ctx.gpr[14] = r14_v;
    ctx.gpr[15] = r15_v;
    ctx.rip = rip_v;
    ctx
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlCaptureContext(ctx_ptr: *mut Win64Context) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = capture_context_inline();
    // SAFETY: `ctx_ptr` checked non-null above.
    unsafe {
        ptr::write_unaligned(ctx_ptr, ctx);
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlAddFunctionTable(
    function_table: usize,
    entry_count: u32,
    base_address: u64,
) -> u8 {
    host().map_or(0, |h| {
        (h.add_function_table)(function_table, entry_count, base_address)
    })
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlDeleteFunctionTable(function_table: usize) -> u8 {
    host().map_or(0, |h| (h.delete_function_table)(function_table))
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlPcToFileHeader(pc_value: u64, base_of_image_out: *mut u64) -> u64 {
    let mut base = 0u64;
    let _ = RtlLookupFunctionEntry(pc_value, &raw mut base, 0);
    if !base_of_image_out.is_null() {
        // SAFETY: `base_of_image_out` checked non-null.
        unsafe { ptr::write_unaligned(base_of_image_out, base) };
    }
    base
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlCaptureStackBackTrace(
    frames_to_skip: u32,
    frames_to_capture: u32,
    back_trace: *mut usize,
    back_trace_hash: *mut u32,
) -> u16 {
    if back_trace.is_null() || frames_to_capture == 0 {
        return 0;
    }
    let mut ctx = capture_context_inline();

    let max_total = frames_to_skip.saturating_add(frames_to_capture).min(64);
    let mut captured = 0u16;
    let mut hash = 0u32;

    for step_idx in 0..max_total {
        if ctx.rip < 0x1000 {
            break;
        }
        let mut img_base = 0u64;
        let fn_entry = RtlLookupFunctionEntry(ctx.rip, &raw mut img_base, 0);
        if fn_entry == 0 {
            if step_idx > 0 {
                // Reached non-PE host loader boundary (`ld-pe.so` ELF frame).
                break;
            }
            // Innermost leaf function: pop return address directly from `[rsp]`.
            let sp = ctx.gpr[4];
            if sp < 0x1000 || (sp & 7) != 0 {
                break;
            }
            // SAFETY: 8-byte aligned stack pointer inside current thread stack.
            ctx.rip = unsafe { ptr::read(sp as *const u64) };
            ctx.gpr[4] = sp.wrapping_add(8);
        } else {
            let mut hdata = 0usize;
            let mut est = 0u64;
            let _ = RtlVirtualUnwind(
                0,
                img_base,
                ctx.rip,
                fn_entry,
                &raw mut ctx,
                &raw mut hdata,
                &raw mut est,
                0,
            );
        }
        if ctx.rip == 0 {
            break;
        }
        if step_idx >= frames_to_skip {
            // SAFETY: `captured < frames_to_capture` within caller's `back_trace` array.
            unsafe {
                ptr::write(back_trace.add(usize::from(captured)), ctx.rip as usize);
            }
            hash = hash.rotate_left(5).wrapping_add(ctx.rip as u32);
            captured += 1;
        }
    }

    if !back_trace_hash.is_null() {
        // SAFETY: `back_trace_hash` checked non-null.
        unsafe { ptr::write_unaligned(back_trace_hash, hash) };
    }
    captured
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlUnwindEx(
    _target_frame: usize,
    _target_ip: usize,
    _exception_record: usize,
    _return_value: usize,
    _context_record: *mut Win64Context,
    _history_table: usize,
) {
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlRaiseException(_exception_record: usize) -> ! {
    NtTerminateProcess(usize::MAX, 0xC000_0025)
}

#[unsafe(no_mangle)]
pub extern "win64" fn __C_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1 // ExceptionContinueSearch
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlEncodePointer(ptr_val: usize) -> usize {
    ptr_val ^ 0x5A5A_5A5A_A5A5_A5A5usize
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlDecodePointer(ptr_val: usize) -> usize {
    ptr_val ^ 0x5A5A_5A5A_A5A5_A5A5usize
}

#[unsafe(no_mangle)]
pub extern "win64" fn RtlInitializeSListHead(list_head: *mut [u64; 2]) {
    if !list_head.is_null() {
        // SAFETY: `list_head` checked non-null.
        unsafe { ptr::write_unaligned(list_head, [0, 0]) };
    }
}
