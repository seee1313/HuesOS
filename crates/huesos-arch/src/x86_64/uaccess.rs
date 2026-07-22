//! Recoverable bounded user-copy assembly entry points.
//!
//! The faulting load/store ranges are paired with fixups in the linker-emitted
//! `.ex_table` section. The architecture page-fault handler redirects a
//! covered kernel fault to the fixup, which returns `-1` instead of panicking.

unsafe extern "C" {
    fn huesos_copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> i64;
    fn huesos_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> i64;
}

/// Copy bytes from a validated user source with exception-table recovery.
///
/// # Safety
/// `dst` must be writable for `len` bytes and both ranges must remain valid for
/// the duration of the call. The caller must hold the Process user-copy lock
/// and an active [`crate::cpu::UserAccessGuard`].
pub unsafe fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> i64 {
    // SAFETY: the caller establishes the destination, lock, and SMAP-window
    // invariants documented above; the assembly has extable entries for both
    // user-memory dereferences.
    unsafe { huesos_copy_from_user(dst, src, len) }
}

/// Copy bytes to a validated user destination with exception-table recovery.
///
/// # Safety
/// `src` must be readable for `len` bytes and both ranges must remain valid for
/// the duration of the call. The caller must hold the Process user-copy lock
/// and an active [`crate::cpu::UserAccessGuard`].
pub unsafe fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> i64 {
    // SAFETY: the caller establishes the source, lock, and SMAP-window
    // invariants documented above; the assembly has extable entries for both
    // user-memory dereferences.
    unsafe { huesos_copy_to_user(dst, src, len) }
}
