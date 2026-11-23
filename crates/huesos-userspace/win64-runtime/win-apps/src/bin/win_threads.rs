//! `/bin/win-threads.exe` — Multi-threaded Win64 PE32+ concurrency & TLS test.
//!
//! Spawns 4 native Win64 worker threads (`CreateThread`), exercises per-thread
//! TEB TLS (`TlsAlloc` / `TlsSetValue` / `TlsGetValue` at `gs:[0x1480 + idx*8]`),
//! `SRWLOCK`, `CRITICAL_SECTION`, `CreateEventA`, and `WaitForMultipleObjects`.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use win_sdk::*;

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { ExitProcess(101) }
}

const NUM_THREADS: usize = 4;
const ITERS_PER_THREAD: u32 = 2500;

struct SharedState {
    srw: UnsafeCell<RtlSrwLock>,
    cs: UnsafeCell<RtlCriticalSection>,
    srw_counter: UnsafeCell<u32>,
    cs_counter: UnsafeCell<u32>,
    tls_slot: AtomicU32,
    start_gate: AtomicU32,
    tls_ok: AtomicBool,
}

// SAFETY: synchronized via Win32 `SRWLOCK`, `CRITICAL_SECTION`, and atomics.
unsafe impl Sync for SharedState {}

static SHARED: SharedState = SharedState {
    srw: UnsafeCell::new(RtlSrwLock { ptr: 0 }),
    cs: UnsafeCell::new(RtlCriticalSection {
        debug_info: 0,
        lock_count: 0,
        recursion_count: 0,
        owning_thread: 0,
        lock_semaphore: 0,
        spin_count: 0,
    }),
    srw_counter: UnsafeCell::new(0),
    cs_counter: UnsafeCell::new(0),
    tls_slot: AtomicU32::new(TLS_OUT_OF_INDEXES),
    start_gate: AtomicU32::new(0),
    tls_ok: AtomicBool::new(true),
};

extern "win64" fn worker_proc(worker_idx: usize) -> u32 {
    let slot = SHARED.tls_slot.load(Ordering::Acquire);
    let tid = unsafe { GetCurrentThreadId() };
    let magic = ((worker_idx + 1) << 20) ^ (tid as usize);

    if unsafe { TlsSetValue(slot, magic) } == FALSE {
        SHARED.tls_ok.store(false, Ordering::Release);
        return 1;
    }

    // Wait for main thread's manual-reset start event (`start_gate`).
    let gate = SHARED.start_gate.load(Ordering::Acquire) as usize;
    if unsafe { WaitForSingleObject(gate, INFINITE) } != WAIT_OBJECT_0 {
        SHARED.tls_ok.store(false, Ordering::Release);
        return 2;
    }

    for i in 0..ITERS_PER_THREAD {
        unsafe {
            AcquireSRWLockExclusive(SHARED.srw.get());
            let p = SHARED.srw_counter.get();
            *p = (*p).wrapping_add(1);
            ReleaseSRWLockExclusive(SHARED.srw.get());

            EnterCriticalSection(SHARED.cs.get());
            let c = SHARED.cs_counter.get();
            *c = (*c).wrapping_add(1);
            LeaveCriticalSection(SHARED.cs.get());
        }
        if (i & 0xff) == 0 && unsafe { TlsGetValue(slot) } != magic {
            SHARED.tls_ok.store(false, Ordering::Release);
            return 3;
        }
    }

    if unsafe { TlsGetValue(slot) } != magic || read_gs_teb_self() == 0 {
        SHARED.tls_ok.store(false, Ordering::Release);
        return 4;
    }
    100 + worker_idx as u32
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn mainCRTStartup() -> u32 {
    unsafe {
        InitializeSRWLock(SHARED.srw.get());
        InitializeCriticalSection(SHARED.cs.get());
    }

    let slot = unsafe { TlsAlloc() };
    if slot == TLS_OUT_OF_INDEXES {
        win_println!("[win-threads] FAIL: TlsAlloc exhausted");
        return 1;
    }
    SHARED.tls_slot.store(slot, Ordering::Release);

    let gate = unsafe { CreateEventA(0, TRUE, FALSE, core::ptr::null()) };
    if gate == 0 {
        win_println!("[win-threads] FAIL: CreateEventA failed");
        return 2;
    }
    SHARED.start_gate.store(gate as u32, Ordering::Release);

    let mut handles = [0usize; NUM_THREADS];
    let mut tids = [0u32; NUM_THREADS];
    for i in 0..NUM_THREADS {
        let h = unsafe { CreateThread(0, 128 * 1024, worker_proc, i, 0, &mut tids[i]) };
        if h == 0 {
            win_println!("[win-threads] FAIL: CreateThread({i}) failed");
            return 3;
        }
        handles[i] = h;
    }

    // Release all 4 worker threads simultaneously!
    let _ = unsafe { SetEvent(gate) };

    let wait_rc =
        unsafe { WaitForMultipleObjects(NUM_THREADS as u32, handles.as_ptr(), TRUE, 15_000) };
    if wait_rc != WAIT_OBJECT_0 {
        win_println!("[win-threads] FAIL: WaitForMultipleObjects returned {wait_rc:#x}");
        return 4;
    }

    for (i, &h) in handles.iter().enumerate() {
        let mut code = 0u32;
        let _ = unsafe { GetExitCodeThread(h, &mut code) };
        let _ = unsafe { CloseHandle(h) };
        if code != 100 + i as u32 {
            win_println!("[win-threads] FAIL: worker {i} exited with {code}");
            return 5;
        }
    }
    let _ = unsafe { CloseHandle(gate) };
    let _ = unsafe { TlsFree(slot) };
    unsafe { DeleteCriticalSection(SHARED.cs.get()) };

    let srw_total = unsafe { *SHARED.srw_counter.get() };
    let cs_total = unsafe { *SHARED.cs_counter.get() };
    let expected = (NUM_THREADS as u32) * ITERS_PER_THREAD;
    let tls_ok = SHARED.tls_ok.load(Ordering::Acquire);

    if srw_total != expected || cs_total != expected || !tls_ok {
        win_println!(
            "[win-threads] FAIL: srw={srw_total} cs={cs_total} expected={expected} tls_ok={tls_ok}"
        );
        return 6;
    }

    win_println!(
        "[win-threads] PASS (threads={NUM_THREADS} counter={srw_total} cs={cs_total} tls=ok)"
    );
    0
}
