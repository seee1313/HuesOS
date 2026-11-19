//! Audited x86_64 syscall trampoline.
//!
//! This is the only userspace module that executes the `syscall` instruction
//! (when compiled statically or into `libcanvas.so`), or delegates to
//! `canvas_syscall` in `libcanvas.so` (when compiled with `dyn-client`).
//! Application code should never execute `syscall` directly.

use huesos_abi::Syscall;

#[cfg(all(feature = "c-abi", feature = "dyn-client"))]
compile_error!("libcanvas features `c-abi` and `dyn-client` are mutually exclusive");

#[cfg(feature = "dyn-client")]
#[link(name = "canvas", kind = "dylib")]
unsafe extern "C" {
    fn canvas_syscall(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64;
}

/// Issue a syscall with up to five register arguments.
///
/// A negative result is an ABI error code. Public typed wrappers remain
/// responsible for ownership and semantic validation, but callers cannot
/// violate Rust memory safety merely by placing an integer in a syscall
/// register.
#[cfg(not(feature = "dyn-client"))]
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

/// Issue a syscall through `libcanvas.so` (`canvas_syscall`).
#[cfg(feature = "dyn-client")]
#[inline]
pub(crate) fn syscall5(syscall: Syscall, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    // SAFETY: `canvas_syscall` is exported by `libcanvas.so` with the stable
    // SysV AMD64 ABI and executes the audited kernel syscall trampoline inside
    // `libcanvas.so`.
    unsafe { canvas_syscall(syscall as u64, a1, a2, a3, a4, a5) }
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
