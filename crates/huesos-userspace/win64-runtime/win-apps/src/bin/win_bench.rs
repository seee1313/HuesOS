//! `/bin/win-bench.exe` — Native Win64 PE32+ microbenchmark suite.
//!
//! Measures Ring-3 TEB `GS_BASE` access latency, `HeapAlloc`/`HeapFree` (`Scudo`),
//! `SRWLOCK` uncontended acquire/release, and W^X `VirtualAlloc`/`VirtualProtect`/`VirtualFree`.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::hint::black_box;
use core::panic::PanicInfo;
use win_sdk::*;

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { ExitProcess(101) }
}

fn qpc() -> u64 {
    let mut c = 0u64;
    let _ = unsafe { QueryPerformanceCounter(&mut c) };
    c
}

fn qpf() -> u64 {
    let mut f = 0u64;
    let _ = unsafe { QueryPerformanceFrequency(&mut f) };
    f.max(1)
}

fn cycles_to_ns_per_op(delta_ticks: u64, freq_hz: u64, iters: u64) -> u64 {
    let total_ns = delta_ticks.saturating_mul(1_000_000_000) / freq_hz.max(1);
    total_ns / iters.max(1)
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn mainCRTStartup() -> u32 {
    let mut sys_info = SystemInfo64 {
        processor_architecture: 0,
        reserved: 0,
        page_size: 0,
        minimum_application_address: 0,
        maximum_application_address: 0,
        active_processor_mask: 0,
        number_of_processors: 0,
        processor_type: 0,
        allocation_granularity: 0,
        processor_level: 0,
        processor_revision: 0,
    };
    unsafe { GetSystemInfo(&mut sys_info) };
    let freq = qpf();

    // 1. TEB LastError roundtrip (`gs:[0x68]`).
    const TEB_ITERS: u64 = 100_000;
    let t0 = qpc();
    for i in 0..TEB_ITERS {
        unsafe {
            SetLastError(i as u32);
            black_box(GetLastError());
        }
    }
    let teb_ns = cycles_to_ns_per_op(qpc().saturating_sub(t0), freq, TEB_ITERS);

    // 2. SRWLOCK uncontended acquire + release.
    const SRW_ITERS: u64 = 100_000;
    let mut lock = RtlSrwLock { ptr: 0 };
    unsafe { InitializeSRWLock(&mut lock) };
    let t1 = qpc();
    for _ in 0..SRW_ITERS {
        unsafe {
            AcquireSRWLockExclusive(&mut lock);
            black_box(&lock);
            ReleaseSRWLockExclusive(&mut lock);
        }
    }
    let srw_ns = cycles_to_ns_per_op(qpc().saturating_sub(t1), freq, SRW_ITERS);

    // 3. Win32 HeapAlloc + HeapFree (`ScudoHeap`).
    const HEAP_ITERS: u64 = 10_000;
    let heap = unsafe { GetProcessHeap() };
    let t2 = qpc();
    for _ in 0..HEAP_ITERS {
        let p = unsafe { HeapAlloc(heap, 0, 128) };
        if p == 0 {
            win_println!("[win-bench] FAIL: HeapAlloc OOM");
            return 1;
        }
        black_box(p);
        let _ = unsafe { HeapFree(heap, 0, p) };
    }
    let heap_ns = cycles_to_ns_per_op(qpc().saturating_sub(t2), freq, HEAP_ITERS);

    // 4. VirtualAlloc + VirtualProtect(RO) + VirtualFree W^X cycle.
    const VMEM_ITERS: u64 = 128;
    let t3 = qpc();
    for _ in 0..VMEM_ITERS {
        let va = unsafe { VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if va == 0 {
            win_println!("[win-bench] FAIL: VirtualAlloc failed");
            return 2;
        }
        let mut old = 0u32;
        let _ = unsafe { VirtualProtect(va, 4096, PAGE_READONLY, &mut old) };
        let _ = unsafe { VirtualFree(va, 0, MEM_RELEASE) };
    }
    let vmem_ns = cycles_to_ns_per_op(qpc().saturating_sub(t3), freq, VMEM_ITERS);

    win_println!(
        "[win-bench] HuesOS PE64 Benchmark (cpus={} qpf={} Hz)",
        sys_info.number_of_processors,
        freq
    );
    win_println!("  TEB Set/GetLastError (gs:[0x68]) : ~{teb_ns} ns/op ({TEB_ITERS} ops)");
    win_println!("  SRWLOCK Exclusive Lock/Unlock    : ~{srw_ns} ns/op ({SRW_ITERS} ops)");
    win_println!("  HeapAlloc(128B) + HeapFree       : ~{heap_ns} ns/op ({HEAP_ITERS} ops)");
    win_println!("  VirtualAlloc+Protect(RO)+Free    : ~{vmem_ns} ns/op ({VMEM_ITERS} ops)");
    win_println!("[win-bench] PASS");
    0
}
