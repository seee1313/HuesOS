//! `SystemGetEntropy` — kernel CSPRNG bytes for userspace.
//!
//! The hardened userspace allocator (`huesos-scudo`) derives its
//! chunk-header cookie from these bytes. That cookie is what makes
//! the header checksum unforgeable: with a constant cookie an
//! attacker who can overwrite a header can also recompute a valid
//! checksum, and every integrity check downstream becomes
//! decorative.
//!
//! The pool lives in `huesos_object::entropy` (ChaCha20 DRBG,
//! seeded during kernel init). If it was never seeded this syscall
//! fails with `Internal` instead of serving predictable bytes: a
//! caller that receives an error can refuse to start, whereas a
//! caller handed deterministic "randomness" cannot tell.

use crate::user_memory;
use crate::SyscallResult;
use huesos_abi::{ErrorCode, MAX_ENTROPY_BYTES};

pub(crate) fn sys_system_get_entropy(out: *mut u8, len: usize) -> SyscallResult {
    if len == 0 || len > MAX_ENTROPY_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }

    // Generate into a kernel buffer first, then hand it to the
    // validated copy layer. The pool lock is released before the
    // user copy so a faulting user page cannot hold the global
    // entropy lock while the copy layer walks page tables.
    let mut buffer = [0u8; MAX_ENTROPY_BYTES];
    let slice = &mut buffer[..len];
    if !huesos_object::entropy::fill(slice) {
        return Err(ErrorCode::Internal);
    }

    user_memory::copy_to_user(out, slice)?;
    Ok(len as i64)
}

/// `VmarHeapExtend` — grow/shrink the caller's own heap window.
///
/// All authority checks live in the kernel callback
/// (`huesos_kernel::process::heap_extend_current`), which clamps the
/// request to the calling process's reserved heap window. This layer
/// only validates the argument struct read from userspace.
pub(crate) fn sys_vmar_heap_extend(args_ptr: *const huesos_abi::HeapExtendArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let heap_extend = (*crate::callbacks::HEAP_EXTEND_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let base = heap_extend(args)?;
    if base > i64::MAX as u64 {
        return Err(ErrorCode::Internal);
    }
    Ok(base as i64)
}
