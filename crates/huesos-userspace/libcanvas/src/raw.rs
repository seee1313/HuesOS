//! The raw `syscall` trampoline — the *only* place in this entire library
//! (and, if you follow the rules, in this entire operating system's
//! userspace) where inline assembly touches the `syscall` instruction.
//!
//! Nothing outside this module is `unsafe` because of the syscall ABI
//! itself; every public function in `libcanvas` validates its arguments
//! and returns a safe [`crate::Result`] instead. Application code should
//! never need to see this module at all — it exists so that *if* HuesOS
//! ever needs a syscall `libcanvas` doesn't wrap yet, there is exactly one
//! sanctioned, reviewed, documented place to add it, instead of every
//! program growing its own copy of inline assembly with its own subtly
//! different bugs (wrong clobber list, wrong argument register, etc).

use huesos_abi::Syscall;

/// Issue a syscall with up to 5 arguments and return its raw `i64` result
/// (negative = error code from `huesos_abi::ErrorCode`, non-negative =
/// success value, meaning depends on the syscall).
///
/// # Safety
/// The caller is responsible for every argument meaning what the target
/// syscall expects (pointer validity, length correctness, etc) — this
/// function itself just performs the CPU-level calling convention and
/// nothing else. This is why it's private to the crate: every public
/// `libcanvas` function upholds those preconditions internally before
/// ever reaching here, so callers of *those* functions never have to
/// think about this contract themselves.
#[inline(always)]
pub(crate) unsafe fn syscall5(syscall: Syscall, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let num = syscall as u64;
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") num => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            out("rcx") _,
            out("r11") _,
            clobber_abi("sysv64"),
        );
    }
    ret
}

/// Convenience wrapper for syscalls that take fewer than 5 arguments.
#[inline(always)]
pub(crate) unsafe fn syscall0(syscall: Syscall) -> i64 {
    unsafe { syscall5(syscall, 0, 0, 0, 0, 0) }
}

/// Convenience wrapper for a 1-argument syscall.
#[inline(always)]
pub(crate) unsafe fn syscall1(syscall: Syscall, a1: u64) -> i64 {
    unsafe { syscall5(syscall, a1, 0, 0, 0, 0) }
}

/// Convenience wrapper for a 2-argument syscall.
#[inline(always)]
pub(crate) unsafe fn syscall2(syscall: Syscall, a1: u64, a2: u64) -> i64 {
    unsafe { syscall5(syscall, a1, a2, 0, 0, 0) }
}

/// Convenience wrapper for a 3-argument syscall.
#[inline(always)]
pub(crate) unsafe fn syscall3(syscall: Syscall, a1: u64, a2: u64, a3: u64) -> i64 {
    unsafe { syscall5(syscall, a1, a2, a3, 0, 0) }
}

/// Convenience wrapper for a 4-argument syscall.
#[inline(always)]
pub(crate) unsafe fn syscall4(syscall: Syscall, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    unsafe { syscall5(syscall, a1, a2, a3, a4, 0) }
}

/// Turn a raw syscall return value into a [`crate::Result<i64>`]: negative
/// values are decoded as [`huesos_abi::ErrorCode`], everything else is
/// `Ok`.
pub(crate) fn decode(raw: i64) -> crate::Result<i64> {
    if raw < 0 {
        Err(huesos_abi::ErrorCode::from_raw(raw).unwrap_or(huesos_abi::ErrorCode::InvalidArgs))
    } else {
        Ok(raw)
    }
}
