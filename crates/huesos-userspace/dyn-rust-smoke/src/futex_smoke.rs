//! Futex smoke test, appended to `dyn-rust-smoke` so the primitive is proven
//! from ring 3 by a real program (not just host unit tests).
//!
//! What it proves, in order:
//!
//! 1. **Compare before park.** A word that does not hold `expected` returns
//!    immediately, without ever touching a wait queue.
//! 2. **A real park with a deadline.** A wait on an unchanged word with a
//!    short timeout returns [`ErrorCode::TimedOut`] — which can only happen
//!    if the thread actually parked and the kernel's timer woke it, because
//!    userspace has no other way to produce that error.
//! 3. **Cross-thread wake.** A worker thread parks on a word; the main
//!    thread stores a new value and wakes it. The worker must observe the
//!    new value, and the wake must report the waiter it found.
//!
//! The shared word is a `static AtomicU32` in `.bss`, which is exactly the
//! "ordinary userspace word" a real `Mutex` would use.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use huesos_abi::ErrorCode;
use libcanvas::{futex, process, system, thread};

/// The word both threads park on and store to.
static FUTEX_WORD: AtomicU32 = AtomicU32::new(0);
/// Set by the worker immediately before it parks, so the main thread knows
/// the worker is on its way into the kernel.
static FUTEX_READY: AtomicU32 = AtomicU32::new(0);
/// Exit code the futex worker reports: the value it read after waking.
static FUTEX_OBSERVED: AtomicU64 = AtomicU64::new(0);

/// Busy-yield for `ticks` scheduler ticks (100 Hz), the same way `/bin/sleep`
/// does it: the caller stays preemptible, so the thread it is waiting for can
/// still be scheduled.
fn sleep_ticks(ticks: u64) {
    let Ok(start) = system::monotonic_ticks() else {
        return;
    };
    while let Ok(now) = system::monotonic_ticks() {
        if now.wrapping_sub(start) >= ticks {
            return;
        }
        process::yield_now();
    }
}

unsafe extern "C" fn futex_worker(_arg: *mut core::ffi::c_void) -> i64 {
    FUTEX_READY.store(1, Ordering::SeqCst);
    // No deadline: this returns only because the main thread wakes us.
    if futex::wait(&FUTEX_WORD, 0, 0).is_err() {
        return 1;
    }
    let observed = FUTEX_WORD.load(Ordering::SeqCst);
    FUTEX_OBSERVED.store(observed as u64, Ordering::SeqCst);
    observed as i64
}

/// Run the futex smoke. Returns `None` on success, or `Some(exit_code)` with
/// the failure to report.
pub fn run() -> Option<i32> {
    // 1. A word that differs from `expected` must not park. We pass a
    //    timeout large enough that parking would visibly delay the smoke.
    match futex::wait(&FUTEX_WORD, 0xF00D, 20) {
        Ok(()) => {}
        Err(_) => return Some(21),
    }
    if FUTEX_WORD.load(Ordering::SeqCst) != 0 {
        return Some(22);
    }

    // 2. A real park with a deadline must time out. Three ticks at 100 Hz is
    //    long enough to be a genuine park, short enough for a boot smoke.
    match futex::wait(&FUTEX_WORD, 0, 3) {
        Err(ErrorCode::TimedOut) => {}
        Ok(()) => return Some(23),
        Err(_) => return Some(24),
    }
    // Timing out must not have changed the word or woken anybody.
    if FUTEX_WORD.load(Ordering::SeqCst) != 0 {
        return Some(25);
    }
    if futex::wake(&FUTEX_WORD, u32::MAX).unwrap_or(usize::MAX) != 0 {
        return Some(26);
    }

    // 3. Cross-thread wake. The worker marks itself ready and parks; we only
    //    store and wake after it has been parked for several ticks.
    FUTEX_READY.store(0, Ordering::SeqCst);
    FUTEX_OBSERVED.store(0, Ordering::SeqCst);
    // SAFETY: `futex_worker` takes no arguments and dereferences none.
    let spawned = unsafe {
        thread::spawn(
            "futex-worker",
            futex_worker,
            core::ptr::null_mut(),
            64 * 1024,
        )
    };
    let Ok(worker) = spawned else {
        return Some(27);
    };
    while FUTEX_READY.load(Ordering::SeqCst) == 0 {
        process::yield_now();
    }
    sleep_ticks(5);
    FUTEX_WORD.store(0x5EED, Ordering::SeqCst);
    let woken = match futex::wake(&FUTEX_WORD, 1) {
        Ok(woken) => woken,
        Err(_) => return Some(28),
    };
    let exit_code = match worker.join() {
        Ok(code) => code,
        Err(_) => return Some(29),
    };
    if exit_code != 0x5EED {
        return Some(30);
    }
    if FUTEX_OBSERVED.load(Ordering::SeqCst) != 0x5EED {
        return Some(31);
    }
    // The wake must have found the parked worker. A `0` here means the
    // worker had not reached the kernel yet: the smoke still passes
    // functionally, but the parking proof would be lost, so say so loudly.
    if woken != 1 {
        libcanvas::println!(
            "[dyn-rust-smoke] futex wake found no waiter (woken={}), parking proof lost",
            woken
        );
        return Some(32);
    }

    libcanvas::println!("[dyn-rust-smoke] futex OK (compare, park+timeout, cross-thread wake)");
    None
}
