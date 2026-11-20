//! Futex syscalls: raw wait/wake on a 32-bit word owned by userspace.
//!
//! The kernel does not store futex state in the word — it only keeps a wait
//! queue per `(process, address)` (see [`huesos_object::futex`]). Correctness
//! therefore rests entirely on the userspace protocol:
//!
//! ```text
//! read word; if word != expected  -> return, nothing to do
//! enqueue (prepare)                -> waker can now see us
//! read word again; if != expected  -> dequeue and return
//! park (with optional timeout)
//! ```
//!
//! The second read is what closes the lost-wakeup race: a thread that
//! changes the word and calls `FutexWake` between our first read and our
//! `prepare` finds an empty queue, wakes nobody, and would strand us — the
//! re-read after `prepare` makes us observe that change instead of sleeping
//! through it.
//!
//! Futex waiters are the only syscall threads that park on memory *they*
//! handed us, so the word is always touched through the audited
//! recoverable user-copy path ([`user_memory::read_value`]): an unmapped or
//! protected page fails the syscall with `InvalidArgs` rather than faulting
//! ring 0.

use huesos_abi::ErrorCode;
use huesos_object::wait::{ParkResult, WaitQueue};

use crate::{user_memory, util::current_proc, SyscallResult};

/// Futex words are naturally-aligned `u32`s. Misaligned words could straddle
/// a page boundary, which would make the "compare as one atomic access"
/// contract impossible to honour.
const FUTEX_ALIGN: u64 = 4;
/// Width of one futex word, used for the readable-range check.
const FUTEX_WORD_BYTES: usize = 4;

/// Check that `uaddr` can name a futex word, returning the validated pointer.
///
/// Alignment and ABI bounds are checked here; page-table permissions are
/// checked again by the actual copy, so a race that unmaps the page between
/// this check and the read is still handled recoverably.
fn validate_word(uaddr: u64) -> Result<*const u32, ErrorCode> {
    if uaddr % FUTEX_ALIGN != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_range(uaddr, FUTEX_WORD_BYTES, false)?;
    Ok(uaddr as *const u32)
}

/// Read one futex word through the recoverable user-copy path.
fn read_word(uaddr: u64) -> Result<u32, ErrorCode> {
    let word = validate_word(uaddr)?;
    user_memory::read_value(word)
}

/// `FutexWait(uaddr, expected, timeout_ticks)`.
///
/// See [`huesos_abi::Syscall::FutexWait`] for the return contract. The three
/// outcomes are all normal: "woken", "the word already differed" (both
/// `Ok(0)`, because the caller must re-read the word either way) and "the
/// timeout expired" ([`ErrorCode::TimedOut`]).
pub(crate) fn sys_futex_wait(uaddr: u64, expected: u32, timeout_ticks: u64) -> SyscallResult {
    // Compare before consulting the queue: a word that already moved on is
    // the common case for a contended lock.
    if read_word(uaddr)? != expected {
        return Ok(0);
    }
    let proc = current_proc()?;
    let node = proc.futex_acquire(uaddr);
    // Enqueue before the second compare so a concurrent `FutexWake` cannot
    // land on an empty queue and be lost.
    let prepared = match WaitQueue::prepare(node.queue()) {
        Some(prepared) => prepared,
        None => {
            // No scheduler yet: parking here would never be woken, so refuse
            // instead of hanging the boot.
            proc.futex_release(uaddr, &node);
            return Err(ErrorCode::InvalidArgs);
        }
    };
    match read_word(uaddr) {
        // The word changed under us (or the page went away) after we
        // enqueued: leave the queue and report the read result.
        Ok(value) if value != expected => {
            prepared.cancel();
            proc.futex_release(uaddr, &node);
            Ok(0)
        }
        Ok(_) => {
            let result = prepared.park_timeout(timeout_ticks);
            proc.futex_release(uaddr, &node);
            match result {
                ParkResult::Woken => Ok(0),
                ParkResult::TimedOut => Err(ErrorCode::TimedOut),
            }
        }
        Err(error) => {
            prepared.cancel();
            proc.futex_release(uaddr, &node);
            Err(error)
        }
    }
}

/// `FutexWake(uaddr, max_wake)` — wake up to `max_wake` parked threads and
/// return how many were actually woken.
///
/// Waking validates only alignment: the address is a *key*, never
/// dereferenced here, so waking must not fail because the page was unmapped
/// after the waiters parked.
pub(crate) fn sys_futex_wake(uaddr: u64, max_wake: u32) -> SyscallResult {
    if uaddr % FUTEX_ALIGN != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    Ok(proc.futex_wake(uaddr, max_wake) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_misaligned_futex_words() {
        for bad in [1u64, 2, 3, 0x1001, 0x1002, 0x1003] {
            assert_eq!(validate_word(bad).err(), Some(ErrorCode::InvalidArgs));
        }
    }

    #[test]
    fn rejects_addresses_outside_the_user_half() {
        // Kernel-half addresses are rejected by the ABI bounds check before
        // any page-table walk, so this needs no live process.
        assert_eq!(validate_word(0).err(), Some(ErrorCode::InvalidArgs));
        assert_eq!(
            validate_word(huesos_abi::USER_ASPACE_END).err(),
            Some(ErrorCode::InvalidArgs)
        );
    }
}
