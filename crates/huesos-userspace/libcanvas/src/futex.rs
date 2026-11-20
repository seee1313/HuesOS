//! Futex primitives: park and wake on an ordinary userspace word.
//!
//! A futex is the smallest possible kernel-supported wait primitive: a
//! `u32` in the calling process's memory, plus a wait queue in the kernel
//! keyed by its address. Everything else — mutexes, condition variables,
//! once cells, channels — is a userspace protocol layered on top, which is
//! what lets `huesos-std` provide blocking synchronisation without the
//! kernel knowing what a mutex is.
//!
//! # The protocol callers must follow
//!
//! ```text
//! if word.load() == expected {
//!     futex::wait(&word, expected, timeout);   // may return spuriously
//! }
//! // always re-check after waking
//! ```
//!
//! [`wait`] returns as soon as the timeout expires *or* somebody wakes the
//! word, and it does not tell the two apart in the common `Ok(())` case;
//! a timeout is reported as [`crate::ErrorCode::TimedOut`] for callers that care.
//! Both are "wake up and look again" events, never "the condition is now
//! true". No state is stored in the kernel, so a wake that finds nobody
//! waiting is not an error — it is the expected outcome of a race that the
//! caller's re-check handles.

use core::sync::atomic::AtomicU32;
use huesos_abi::Syscall;

use crate::raw;

/// Park the calling thread while `word` still holds `expected`.
///
/// `timeout_ticks` is in scheduler ticks (`0` waits forever, no timeout).
/// Returns:
/// - `Ok(())` — woken, or `word` already differed from `expected` (nothing
///   was slept for); the caller must re-read the word,
/// - `Err(`[`crate::ErrorCode::TimedOut`]`)` — the timeout expired,
/// - `Err(InvalidArgs)` — `word` is not a valid futex word, or the
///   scheduler is not running yet.
///
/// Passing an `&AtomicU32` (rather than a bare pointer) is what keeps this
/// safe: the kernel only ever reads the word, and the caller is the one
/// that has to make the surrounding protocol atomic, which is exactly the
/// job of an atomic.
pub fn wait(word: &AtomicU32, expected: u32, timeout_ticks: u64) -> crate::Result<()> {
    let ret = raw::syscall3(
        Syscall::FutexWait,
        word as *const AtomicU32 as u64,
        expected as u64,
        timeout_ticks,
    );
    // `TimedOut` is a normal outcome, but it is still reported so callers
    // like `Condvar::wait_timeout` can distinguish it from a wake.
    raw::decode(ret)?;
    Ok(())
}

/// Wake up to `max_wake` threads parked on `word`, returning how many were
/// actually woken.
///
/// `max_wake == 0` wakes nobody and returns `Ok(0)`; `u32::MAX` is the
/// "wake everybody" idiom. A wake with no waiters is `Ok(0)`, not an error.
pub fn wake(word: &AtomicU32, max_wake: u32) -> crate::Result<usize> {
    let ret = raw::syscall2(Syscall::FutexWake, word as *const AtomicU32 as u64, max_wake as u64);
    Ok(raw::decode(ret)? as usize)
}

/// Wake every thread parked on `word`, returning how many were woken.
pub fn wake_all(word: &AtomicU32) -> crate::Result<usize> {
    wake(word, u32::MAX)
}
