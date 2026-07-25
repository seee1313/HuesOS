//! Recoverable user-memory access primitives.
//!
//! ## What this module solves
//!
//! [`user_memory`] already validates every syscall pointer against ABI bounds
//! and against the active user page-table permissions **at validation time**.
//! But between "validation returns Ok" and "the raw copy executes", another
//! thread on another CPU can unmap the user range through `VmarUnmap` /
//! `VmarProtect`. Without a recovery path the raw copy takes a ring-0 `#PF`
//! and the kernel panics — which is exactly the DoS primitive we want to
//! close.
//!
//! ## How the primitive works
//!
//! The [`user_access_ok!`] macro wraps a body that performs a raw user
//! memory read/write in an `asm!` block whose start / end / fixup labels
//! are emitted into a dedicated `.ex_table` section:
//!
//! ```text
//! .ex_table  →  [start_rip: u64][end_rip: u64][fixup_rip: u64]  ×  N sites
//! ```
//!
//! [`huesos_arch::fault::try_kernel_recover`] (installed by
//! [`huesos_kernel::extable`]) consults this table on every ring-0 `#PF`.
//! When the faulting RIP lies in `[start, end)` for some entry, the CPU
//! resumes at `fixup_rip` instead of taking the fatal panic path. The
//! fixup returns `Err(ErrorCode::InvalidArgs)` from the enclosing syscall,
//! so userspace sees an ordinary error instead of the whole system going
//! down.
//!
//! ## Why an `asm!` block instead of `ptr::copy_nonoverlapping`
//!
//! - LLVM treats an `asm!` block as **opaque**: it cannot inline, split,
//!   reorder, or elide instructions inside it. That guarantees the fault
//!   really lands in `[start, end)` even in `--release --lto=fat`, which
//!   is exactly where the earlier extable attempt (`651cc1c revert`)
//!   failed.
//! - Every operand goes through explicit `in` / `inout` register
//!   constraints; there is no ambient Rust code that could observe an
//!   in-flight raw pointer after a fault.
//! - `options(nostack, preserves_flags)` matches the calling contract of
//!   a syscall handler.
//!
//! ## Not a byte-loop
//!
//! Unlike the reverted [`uaccess.S`][rev] which reimplemented a 1-byte-at-
//! a-time copy in assembly, this primitive delegates the copy itself to
//! `rep movsb` — the CPU's own fast byte-string move. Modern x86 CPUs
//! recognise `rep movsb` and pick an optimal microcode path (ERMS on
//! Intel, FSRM on newer parts). A fault on any byte inside the sequence
//! parks RIP at the specific `rep movsb` instruction, which is inside
//! `[start, end)`, and the fixup takes over.
//!
//! [rev]: https://github.com/seee1313/HuesOS/commit/651cc1c
//! [`user_memory`]: crate::user_memory

/// Copy `len` bytes from `src` to `dst`. On success returns `Ok(())`. On
/// a ring-0 `#PF` inside the copy — for example because another CPU
/// concurrently unmapped `src` — returns `Err(ErrorCode::InvalidArgs)`
/// without panicking the kernel.
///
/// # Safety
/// - `src` must be a validated userspace pointer (see
///   [`crate::user_memory::validate_range`]) at call time.
/// - `dst` must be a live, writable kernel-owned buffer at least `len`
///   bytes long.
/// - Caller must hold the process `user_memory_lock` per the standard
///   user-copy contract.
///
/// The fault-recovery layer does **not** relax these preconditions; it
/// only ensures that a race with a concurrent unmap fails cleanly
/// instead of taking down the kernel.
#[inline(never)]
pub(crate) unsafe fn recoverable_copy_from_user(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> Result<(), huesos_abi::ErrorCode> {
    if len == 0 {
        return Ok(());
    }
    // Return value: 0 = success, 1 = fault-recovered.
    let outcome: u64;

    // SAFETY: dst / src / len are contract-checked by the caller and the
    // block delegates the byte moves to `rep movsb`. On a ring-0 #PF the
    // extable entry emitted below redirects RIP to the fixup label, which
    // sets `outcome = 1` and joins the success path — no ambient Rust
    // reference to src/dst ever exists mid-copy, so this is sound even
    // under a partial completion.
    unsafe {
        core::arch::asm!(
            // ---- Protected instruction (start ≤ RIP < end) ----
            "22:",
            "rep movsb",
            "23:",
            // ---- Success join ----
            "xor {out:e}, {out:e}",
            "jmp 24f",
            // ---- Fixup landing pad ----
            "44:",
            "mov {out:e}, 1",
            // ---- Merge point ----
            "24:",
            // ---- Emit the extable entry after the code so the labels
            // are all defined by the assembler at emission time. ----
            ".pushsection .ex_table, \"a\", @progbits",
            ".balign 8",
            ".quad 22b, 23b, 44b",
            ".popsection",
            in("rsi") src,
            in("rdi") dst,
            in("rcx") len,
            out = out(reg) outcome,
            options(nostack, preserves_flags),
        );
    }

    if outcome == 0 {
        Ok(())
    } else {
        Err(huesos_abi::ErrorCode::InvalidArgs)
    }
}

/// Copy `len` bytes from a kernel-owned `src` to a validated userspace
/// `dst`. Mirror of [`recoverable_copy_from_user`] with the operand
/// direction reversed.
///
/// # Safety
/// See [`recoverable_copy_from_user`].
#[inline(never)]
pub(crate) unsafe fn recoverable_copy_to_user(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> Result<(), huesos_abi::ErrorCode> {
    if len == 0 {
        return Ok(());
    }
    let outcome: u64;

    // SAFETY: same invariants as recoverable_copy_from_user; direction is
    // just src -> dst with `rep movsb` reading kernel memory and writing
    // user memory. A fault on the store side lands on the `rep movsb`
    // RIP and is caught by the same extable entry.
    unsafe {
        core::arch::asm!(
            "22:",
            "rep movsb",
            "23:",
            "xor {out:e}, {out:e}",
            "jmp 24f",
            "44:",
            "mov {out:e}, 1",
            "24:",
            ".pushsection .ex_table, \"a\", @progbits",
            ".balign 8",
            ".quad 22b, 23b, 44b",
            ".popsection",
            in("rsi") src,
            in("rdi") dst,
            in("rcx") len,
            out = out(reg) outcome,
            options(nostack, preserves_flags),
        );
    }

    if outcome == 0 {
        Ok(())
    } else {
        Err(huesos_abi::ErrorCode::InvalidArgs)
    }
}
