//! Boot-time negative probes for the kernel syscall boundary.
//!
//! This module is feature-gated and enabled only for `huesos-init`. It keeps
//! deliberately invalid raw syscall arguments inside libcanvas, preserving the
//! rule that applications do not issue hand-written syscalls.

use crate::raw;
use huesos_abi::{ErrorCode, Syscall};

fn is_invalid_args(result: i64) -> bool {
    result == ErrorCode::InvalidArgs as i32 as i64
}

/// Verify that three distinct invalid pointer classes are rejected normally.
///
/// The probes cover a kernel-half input pointer, an unmapped low userspace
/// output, and a mapped-but-read-only text page used as an output. Returning
/// `true` means every syscall returned `InvalidArgs` and execution continued.
pub fn user_pointer_guard_smoke_test() -> bool {
    const KERNEL_HALF: u64 = 0xffff_ff80_0000_0000;
    const UNMAPPED_LOW_USER: u64 = huesos_abi::USER_ASPACE_BASE;

    // SAFETY: the purpose of this feature-gated diagnostic is to pass invalid
    // values through the audited raw syscall ABI. The kernel must reject them
    // before dereferencing. No Rust reference is created from either address.
    let kernel_read = raw::syscall2(Syscall::DebugWrite, KERNEL_HALF, 1);
    let unmapped_write = raw::syscall2(Syscall::VmoCreate, 4096, UNMAPPED_LOW_USER);

    // Function text is mapped user-readable/executable but not writable. It is
    // a stable way to exercise effective PTE write-permission validation.
    let text_address = user_pointer_guard_smoke_test as *const () as u64;
    let readonly_write = raw::syscall1(Syscall::FramebufferInfo, text_address);

    is_invalid_args(kernel_read)
        && is_invalid_args(unmapped_write)
        && is_invalid_args(readonly_write)
}
