//! Heap-window and entropy syscall wrappers.
//!
//! These are the two kernel primitives the hardened userspace
//! allocator (`huesos-scudo`) is built on:
//!
//! - [`get_entropy`] supplies the unpredictable bytes behind the
//!   allocator's chunk-header cookie. Without it the header checksum
//!   would be computed from a constant and an attacker able to
//!   overwrite a header could forge a valid one.
//! - [`heap_commit`] / [`heap_decommit`] grow and shrink the
//!   process's own heap window on demand. A ring-3 process holds no
//!   handle to its own VMAR, so this is its only way to obtain
//!   memory — the platform's `mmap` equivalent, narrowed to a region
//!   the process already owns.

use crate::{raw, Result};
use huesos_abi::{heap_op, HeapExtendArgs, Syscall, MAX_ENTROPY_BYTES, USER_HEAP_BASE};

/// Page size of the heap window; every offset and length passed to
/// [`heap_commit`] / [`heap_decommit`] must be a multiple of this.
pub const PAGE_SIZE: usize = 4096;

/// Base address of this process's heap window.
pub const HEAP_BASE: usize = USER_HEAP_BASE as usize;

/// Total size of the reserved heap window (address space, not
/// committed memory).
pub const HEAP_SIZE: usize = huesos_abi::USER_HEAP_SIZE as usize;

/// Fill `out` with kernel CSPRNG bytes.
///
/// `out` may be at most [`MAX_ENTROPY_BYTES`] long; longer requests
/// return `InvalidArgs`. Fails with `Internal` if the kernel pool was
/// never seeded rather than returning predictable bytes.
pub fn get_entropy(out: &mut [u8]) -> Result<usize> {
    if out.is_empty() || out.len() > MAX_ENTROPY_BYTES {
        return Err(huesos_abi::ErrorCode::InvalidArgs);
    }
    let written = raw::decode(raw::syscall2(
        Syscall::SystemGetEntropy,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    ))?;
    Ok(written as usize)
}

/// A convenience wrapper returning a single random `u64`.
pub fn random_u64() -> Result<u64> {
    let mut bytes = [0u8; 8];
    get_entropy(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn heap_extend(offset: usize, len: usize, op: u32) -> Result<usize> {
    let args = HeapExtendArgs {
        offset: offset as u64,
        len: len as u64,
        op,
        reserved: 0,
    };
    let base = raw::decode(raw::syscall1(
        Syscall::VmarHeapExtend,
        &args as *const _ as u64,
    ))?;
    Ok(base as usize)
}

/// Commit (map) `len` bytes at `offset` inside the heap window.
///
/// Returns the absolute address of the committed range. Committing a
/// range that is already committed succeeds without changing it, so a
/// caller may re-commit without tracking kernel state precisely.
pub fn heap_commit(offset: usize, len: usize) -> Result<usize> {
    heap_extend(offset, len, heap_op::COMMIT)
}

/// Decommit (unmap and free) `len` bytes at `offset` inside the heap
/// window. Ranges that are not committed are skipped silently.
pub fn heap_decommit(offset: usize, len: usize) -> Result<usize> {
    heap_extend(offset, len, heap_op::DECOMMIT)
}
