//! Audited x86_64 syscall trampoline.
//!
//! This is the only userspace module that executes the `syscall` instruction.
//! The trampoline accepts integer register values, all of which are valid at
//! the CPU ABI level. Pointer/range semantics are validated by the kernel's
//! user-copy boundary, so issuing a syscall with a bad address returns an error
//! rather than causing Rust undefined behavior. Consequently these private
//! helpers are safe functions; only the inline assembly implementation needs
//! an unsafe block.

use huesos_abi::Syscall;

/// Issue a syscall with up to five register arguments.
///
/// A negative result is an ABI error code. Public typed wrappers remain
/// responsible for ownership and semantic validation, but callers cannot
/// violate Rust memory safety merely by placing an integer in a syscall
/// register.
#[inline(always)]
pub(crate) fn syscall5(syscall: Syscall, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let number = syscall as u64;
    let result: i64;
    // SAFETY: the register assignment and clobber list match the HuesOS syscall
    // entry contract. `syscall` preserves no Rust references across the
    // boundary, and the kernel validates every userspace memory operand.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") number => result,
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
    result
}

/// Issue a zero-argument syscall.
#[inline(always)]
pub(crate) fn syscall0(syscall: Syscall) -> i64 {
    syscall5(syscall, 0, 0, 0, 0, 0)
}

/// Issue a one-argument syscall.
#[inline(always)]
pub(crate) fn syscall1(syscall: Syscall, a1: u64) -> i64 {
    syscall5(syscall, a1, 0, 0, 0, 0)
}

/// Issue a two-argument syscall.
#[inline(always)]
pub(crate) fn syscall2(syscall: Syscall, a1: u64, a2: u64) -> i64 {
    syscall5(syscall, a1, a2, 0, 0, 0)
}

/// Issue a three-argument syscall.
#[inline(always)]
pub(crate) fn syscall3(syscall: Syscall, a1: u64, a2: u64, a3: u64) -> i64 {
    syscall5(syscall, a1, a2, a3, 0, 0)
}

/// Issue a four-argument syscall.
#[inline(always)]
pub(crate) fn syscall4(syscall: Syscall, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    syscall5(syscall, a1, a2, a3, a4, 0)
}

/// Decode a raw syscall return into the shared error type.
pub(crate) fn decode(raw: i64) -> crate::Result<i64> {
    if raw < 0 {
        Err(huesos_abi::ErrorCode::from_raw(raw).unwrap_or(huesos_abi::ErrorCode::InvalidArgs))
    } else {
        Ok(raw)
    }
}
