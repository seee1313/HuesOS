//! Userspace dynamic-linking smoke test in Rust (`dyn-client`).
//!
//! Exercises multi-threaded Variant-II TLS, General-Dynamic TLS in a
//! `dlopen`-loaded C shared object (`libsmoke_plugin.so`), `open_soname` +
//! `open_vmo` deduplication/refcounting, `dladdr`, `dlerror`, `dlclose`,
//! `atexit`, and concurrent `ScudoHeap` allocations across spawned threads.

#![no_std]
#![no_main]
#![feature(thread_local)]

extern crate alloc;

mod futex_smoke;

use alloc::vec::Vec;
use core::cell::Cell;
use core::ffi::c_void;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use libcanvas::dl::{self, DynamicModule, RTLD_LOCAL};
use libcanvas::heap::ScudoHeap;
use libcanvas::{process, thread, Vmo};

#[global_allocator]
static ALLOCATOR: ScudoHeap = ScudoHeap;

#[thread_local]
static WORKER_TLS: Cell<u64> = Cell::new(0x1000);

static ATEXIT_RAN: AtomicBool = AtomicBool::new(false);

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym rust_smoke_main,
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::println!("[dyn-rust-smoke] PANIC");
    process::exit(99)
}

extern "C" fn on_rust_atexit() {
    ATEXIT_RAN.store(true, Ordering::SeqCst);
    libcanvas::println!("[dyn-rust-smoke] atexit OK");
}

unsafe extern "C" fn worker_entry(arg: *mut c_void) -> i64 {
    let id = arg as usize as u64;
    if WORKER_TLS.get() != 0x1000 {
        return 10 + id as i64;
    }
    WORKER_TLS.set(WORKER_TLS.get() + id * 17);
    if WORKER_TLS.get() != 0x1000 + id * 17 {
        return 20 + id as i64;
    }

    // Exercise concurrent `ScudoHeap` allocation + deallocation across threads.
    let mut items = Vec::with_capacity(64);
    for i in 0u64..64 {
        items.push(i.wrapping_mul(id));
    }
    if items[63] != 63 * id {
        return 30 + id as i64;
    }
    drop(items);

    // Exercise General-Dynamic TLS (`__tls_get_addr`) inside `libsmoke_plugin.so`
    // on a secondary thread spawned after `dlopen`.
    let Some(plugin) = DynamicModule::open_soname("libsmoke_plugin.so", RTLD_LOCAL) else {
        return 40 + id as i64;
    };
    let Some(bump_ptr) = plugin.symbol("smoke_plugin_tls_bump") else {
        return 50 + id as i64;
    };
    // SAFETY: `smoke_plugin_tls_bump` in `libsmoke_plugin.so` is `extern "C" fn(u64) -> u64`.
    let bump: unsafe extern "C" fn(u64) -> u64 = unsafe { core::mem::transmute(bump_ptr) };
    // SAFETY: valid function pointer inside pinned/refcounted plugin module.
    let v1 = unsafe { bump(id * 10) };
    if v1 != 0x1122_3344_5566_7788 + id * 10 {
        return 60 + id as i64;
    }
    drop(plugin);

    if id == 2 {
        thread::exit(0x200 + id as i64);
    }
    0x200 + id as i64
}

extern "C" fn rust_smoke_main() -> ! {
    if !dl::atexit(on_rust_atexit) {
        libcanvas::println!("[dyn-rust-smoke] FAIL: atexit");
        process::exit(1);
    }

    let bootstrap = libcanvas::channel::bootstrap();
    let mut msg = [0u8; 32];
    let plugin_vmo = match bootstrap.read_optional_handle(&mut msg) {
        Ok((_n, Some(h))) => Some(Vmo::from_handle(h)),
        _ => None,
    };

    if DynamicModule::open_soname("../escape.so", RTLD_LOCAL).is_some() {
        libcanvas::println!("[dyn-rust-smoke] FAIL: traversal accepted");
        process::exit(2);
    }
    if dl::last_error().is_none() {
        libcanvas::println!("[dyn-rust-smoke] FAIL: missing dlerror");
        process::exit(3);
    }

    let Some(plugin) = DynamicModule::open_soname("libsmoke_plugin.so", RTLD_LOCAL) else {
        libcanvas::println!("[dyn-rust-smoke] FAIL: open_soname");
        process::exit(4);
    };

    if let Some(ref vmo) = plugin_vmo {
        let Some(vmo_mod) = DynamicModule::open_vmo(vmo, RTLD_LOCAL) else {
            libcanvas::println!("[dyn-rust-smoke] FAIL: open_vmo");
            process::exit(5);
        };
        drop(vmo_mod);
    }

    let Some(add_ptr) = plugin.symbol("smoke_plugin_add") else {
        libcanvas::println!("[dyn-rust-smoke] FAIL: dlsym");
        process::exit(6);
    };
    // SAFETY: `smoke_plugin_add` is `extern "C" fn(i32, i32) -> i32`.
    let add: unsafe extern "C" fn(i32, i32) -> i32 = unsafe { core::mem::transmute(add_ptr) };
    // SAFETY: valid symbol pointer inside `plugin`.
    if unsafe { add(100, 23) } != 123 {
        libcanvas::println!("[dyn-rust-smoke] FAIL: add");
        process::exit(7);
    }
    if dl::addr_info(add_ptr as usize).is_none() {
        libcanvas::println!("[dyn-rust-smoke] FAIL: dladdr");
        process::exit(8);
    }

    // Spawn 2 concurrent worker threads and verify independent TLS + heap + plugin GD TLS.
    // SAFETY: `worker_entry` casts `arg` as an integer id and does not dereference it.
    let Ok(w1) = (unsafe {
        thread::spawn(
            "worker-1",
            worker_entry,
            core::ptr::without_provenance_mut(1),
            64 * 1024,
        )
    }) else {
        libcanvas::println!("[dyn-rust-smoke] FAIL: spawn w1");
        process::exit(9);
    };
    // SAFETY: `worker_entry` casts `arg` as an integer id and does not dereference it.
    let Ok(w2) = (unsafe {
        thread::spawn(
            "worker-2",
            worker_entry,
            core::ptr::without_provenance_mut(2),
            64 * 1024,
        )
    }) else {
        libcanvas::println!("[dyn-rust-smoke] FAIL: spawn w2");
        process::exit(10);
    };

    match (w1.join(), w2.join()) {
        (Ok(0x201), Ok(0x202)) => {}
        (r1, r2) => {
            libcanvas::println!("[dyn-rust-smoke] FAIL: join {:?} {:?}", r1, r2);
            process::exit(11);
        }
    }

    // Main thread's Variant-II TLS must remain untouched by worker mutations.
    if WORKER_TLS.get() != 0x1000 {
        libcanvas::println!("[dyn-rust-smoke] FAIL: main TLS clobbered");
        process::exit(12);
    }

    // Futex primitives: compare, park with a deadline, and a cross-thread
    // wake. Runs before `drop(plugin)` so the process is still fully loaded.
    if let Some(code) = futex_smoke::run() {
        libcanvas::println!("[dyn-rust-smoke] FAIL: futex smoke (code {})", code);
        process::exit(20 + i64::from(code));
    }

    drop(plugin);
    libcanvas::println!("[dyn-rust-smoke] PASS");
    process::exit(0)
}
