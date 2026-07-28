//! Validated copies across the userspace/kernel address-space boundary.
//!
//! Raw syscall arguments are controlled by ring 3. They must never be
//! dereferenced merely because they are non-null: while servicing a syscall
//! the CPU runs at CPL0 and could otherwise read or overwrite kernel memory on
//! the caller's behalf. This module is the only place in `huesos-syscalls`
//! that turns a userspace address into a Rust pointer.

use alloc::vec::Vec;
use core::{
    mem::{self, MaybeUninit},
    slice,
};
use huesos_abi::{ErrorCode, USER_ASPACE_BASE, USER_ASPACE_END};
use huesos_arch::VirtAddr;

use crate::user_access;

const PAGE_SIZE: u64 = 4096;

/// Maximum byte count copied by one VMO read/write syscall.
pub(crate) const MAX_VMO_TRANSFER: usize = 1024 * 1024;
/// Maximum payload carried by one Channel message.
pub(crate) const MAX_CHANNEL_BYTES: usize = 64 * 1024;
/// Maximum handles carried by one Channel message.
pub(crate) const MAX_CHANNEL_HANDLES: usize = 64;

fn with_user_memory_lock<R>(
    operation: impl FnOnce() -> Result<R, ErrorCode>,
) -> Result<R, ErrorCode> {
    let process = crate::util::current_proc()?;
    let _guard = process.user_memory_lock.lock();
    operation()
}

/// Validate an entire userspace range against ABI bounds and active page-table
/// permissions. `write` means that the kernel will write into the range.
pub(crate) fn validate_range(addr: u64, len: usize, write: bool) -> Result<(), ErrorCode> {
    if len == 0 {
        return Ok(());
    }
    if !(USER_ASPACE_BASE..USER_ASPACE_END).contains(&addr) {
        return Err(ErrorCode::InvalidArgs);
    }
    let end = addr.checked_add(len as u64).ok_or(ErrorCode::InvalidArgs)?;
    if end > USER_ASPACE_END || end <= addr {
        return Err(ErrorCode::InvalidArgs);
    }

    let mut page = addr & !(PAGE_SIZE - 1);
    let last_page = (end - 1) & !(PAGE_SIZE - 1);
    loop {
        if !huesos_arch::paging::active_user_page_accessible(VirtAddr::new(page), write) {
            return Err(ErrorCode::InvalidArgs);
        }
        if page == last_page {
            break;
        }
        page = page.checked_add(PAGE_SIZE).ok_or(ErrorCode::InvalidArgs)?;
    }
    Ok(())
}

/// Validate an output object before a syscall performs side effects or blocks.
pub(crate) fn validate_write<T>(out: *mut T) -> Result<(), ErrorCode> {
    validate_range(out as u64, mem::size_of::<T>(), true)
}

/// Validate an output array before a syscall consumes a queued object.
pub(crate) fn validate_write_array<T>(out: *mut T, count: usize) -> Result<(), ErrorCode> {
    let len = checked_array_byte_len::<T>(count)?;
    validate_range(out as u64, len, true)
}

fn checked_value_byte_len<T>() -> Result<usize, ErrorCode> {
    let len = mem::size_of::<T>();
    if len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    Ok(len)
}

fn checked_array_byte_len<T>(count: usize) -> Result<usize, ErrorCode> {
    let elem = mem::size_of::<T>();
    if count != 0 && elem == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    elem.checked_mul(count).ok_or(ErrorCode::InvalidArgs)
}

fn recoverable_read_at<T: Copy>(src: *const T) -> Result<T, ErrorCode> {
    let byte_len = checked_value_byte_len::<T>()?;
    validate_range(src as u64, byte_len, false)?;
    let mut value = MaybeUninit::<T>::uninit();
    let _access = huesos_arch::cpu::UserAccessGuard::new();
    // SAFETY: byte_len bytes at src were verified readable in the active
    // user page tables. value owns an uninitialized kernel destination of the
    // same size, and the process user_memory_lock is held by the caller. The
    // recoverable copy converts a post-validation unmap/protect race into
    // InvalidArgs instead of a ring-0 panic. assume_init is sound after a
    // successful full-byte copy; T is restricted by this module's ABI contract
    // to Copy records with all bit patterns valid.
    unsafe {
        user_access::recoverable_copy_from_user(
            value.as_mut_ptr().cast::<u8>(),
            src.cast::<u8>(),
            byte_len,
        )?;
        Ok(value.assume_init())
    }
}

fn recoverable_read_array_at<T: Copy>(src: *const T, count: usize) -> Result<Vec<T>, ErrorCode> {
    let byte_len = checked_array_byte_len::<T>(count)?;
    validate_range(src as u64, byte_len, false)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ErrorCode::NoMemory)?;
    if count == 0 {
        return Ok(values);
    }
    let _access = huesos_arch::cpu::UserAccessGuard::new();
    // SAFETY: the complete userspace source range was validated above.
    // values has enough spare capacity for count initialized T records, and
    // that spare memory is a live kernel destination. set_len is performed
    // only after the recoverable copy reports success, so no uninitialized
    // values become observable on fault.
    unsafe {
        user_access::recoverable_copy_from_user(
            values.spare_capacity_mut().as_mut_ptr().cast::<u8>(),
            src.cast::<u8>(),
            byte_len,
        )?;
        values.set_len(count);
    }
    Ok(values)
}

/// Copy one plain ABI value from userspace.
///
/// Callers use this only with `#[repr(C)]`, `Copy` ABI records whose bit
/// patterns are valid for every field (integers and raw pointers).
pub(crate) fn read_value<T: Copy>(src: *const T) -> Result<T, ErrorCode> {
    with_user_memory_lock(|| recoverable_read_at(src))
}

/// Copy an array of plain values from userspace into kernel-owned memory.
pub(crate) fn read_array<T: Copy>(src: *const T, count: usize) -> Result<Vec<T>, ErrorCode> {
    with_user_memory_lock(|| recoverable_read_array_at(src, count))
}

/// Allocate an initialized kernel byte buffer without invoking the infallible
/// `vec![..]` growth path on attacker-controlled sizes.
pub(crate) fn zeroed_buffer(len: usize) -> Result<Vec<u8>, ErrorCode> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| ErrorCode::NoMemory)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Copy bytes from userspace into a caller-provided kernel buffer.
pub(crate) fn copy_from_user_into(src: *const u8, out: &mut [u8]) -> Result<(), ErrorCode> {
    with_user_memory_lock(|| {
        validate_range(src as u64, out.len(), false)?;
        if !out.is_empty() {
            let _access = huesos_arch::cpu::UserAccessGuard::new();
            unsafe { user_access::recoverable_copy_from_user(out.as_mut_ptr(), src, out.len())? };
        }
        Ok(())
    })
}

/// Copy bytes from userspace into a kernel-owned vector.
///
/// This is the main bulk-copy path for VMO reads and Channel messages
/// (up to 1 MiB and 64 KiB respectively). It goes through the
/// recoverable [`user_access::recoverable_copy_from_user`] primitive
/// so a race between `validate_range` above and a concurrent VmarUnmap
/// on another CPU returns `Err(ErrorCode::InvalidArgs)` instead of
/// panicking the kernel.
pub(crate) fn copy_from_user(src: *const u8, len: usize) -> Result<Vec<u8>, ErrorCode> {
    with_user_memory_lock(|| {
        validate_range(src as u64, len, false)?;
        let mut bytes = zeroed_buffer(len)?;
        if len != 0 {
            let _access = huesos_arch::cpu::UserAccessGuard::new();
            // SAFETY: caller-side contract for user_access is (a) src's
            // full range was verified readable by validate_range above,
            // (b) bytes owns a distinct initialized destination of
            // exactly len bytes, (c) we hold the process
            // user_memory_lock via with_user_memory_lock. The
            // recoverable copy adds fault recovery on top of the same
            // rep movsb the previous ptr::copy_nonoverlapping compiled
            // to; the wire format and byte order are identical, only
            // the failure mode changes from panic to Err.
            unsafe { user_access::recoverable_copy_from_user(bytes.as_mut_ptr(), src, len)? };
        }
        Ok(bytes)
    })
}

fn recoverable_write_at<T: Copy>(dst: *mut T, value: &T) -> Result<(), ErrorCode> {
    let byte_len = checked_value_byte_len::<T>()?;
    validate_range(dst as u64, byte_len, true)?;
    let _access = huesos_arch::cpu::UserAccessGuard::new();
    // SAFETY: dst's complete byte range was validated writable, value is a
    // live kernel-owned ABI record of the same size, and the caller holds the
    // process user_memory_lock. The recoverable copy preserves the previous
    // unaligned ABI byte layout while turning a concurrent destination unmap
    // into InvalidArgs.
    unsafe {
        user_access::recoverable_copy_to_user(
            dst.cast::<u8>(),
            (value as *const T).cast::<u8>(),
            byte_len,
        )
    }
}

/// Copy one plain ABI value to userspace.
pub(crate) fn write_value<T: Copy>(dst: *mut T, value: &T) -> Result<(), ErrorCode> {
    with_user_memory_lock(|| recoverable_write_at(dst, value))
}

/// Copy a kernel byte slice to userspace.
///
/// Mirror of [`copy_from_user`] for outbound bulk transfers. Goes
/// through [`user_access::recoverable_copy_to_user`] so a concurrent
/// unmap of the destination returns `Err(ErrorCode::InvalidArgs)`
/// instead of panicking.
pub(crate) fn copy_to_user(dst: *mut u8, bytes: &[u8]) -> Result<(), ErrorCode> {
    with_user_memory_lock(|| {
        validate_range(dst as u64, bytes.len(), true)?;
        if !bytes.is_empty() {
            let _access = huesos_arch::cpu::UserAccessGuard::new();
            // SAFETY: caller-side contract for user_access is (a) dst's
            // full range was verified writable by validate_range above,
            // (b) bytes is a distinct live kernel-owned slice (kernel
            // addresses are excluded by validate_range so src/dst
            // cannot alias), (c) we hold the process user_memory_lock.
            unsafe { user_access::recoverable_copy_to_user(dst, bytes.as_ptr(), bytes.len())? };
        }
        Ok(())
    })
}

fn recoverable_write_array_at<T: Copy>(dst: *mut T, values: &[T]) -> Result<(), ErrorCode> {
    let byte_len = checked_array_byte_len::<T>(values.len())?;
    validate_range(dst as u64, byte_len, true)?;
    if values.is_empty() {
        return Ok(());
    }
    let _access = huesos_arch::cpu::UserAccessGuard::new();
    // SAFETY: dst's complete byte range was validated writable. values is a
    // live kernel-owned contiguous slice of Copy ABI records; viewing it as
    // bytes preserves the existing unaligned syscall ABI, and the recoverable
    // copy handles post-validation destination faults.
    unsafe {
        let bytes = slice::from_raw_parts(values.as_ptr().cast::<u8>(), byte_len);
        user_access::recoverable_copy_to_user(dst.cast::<u8>(), bytes.as_ptr(), bytes.len())
    }
}

/// Copy an array of plain values to userspace.
pub(crate) fn write_array<T: Copy>(dst: *mut T, values: &[T]) -> Result<(), ErrorCode> {
    with_user_memory_lock(|| recoverable_write_array_at(dst, values))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds_only(addr: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = addr.checked_add(len as u64) else {
            return false;
        };
        addr >= USER_ASPACE_BASE && addr < USER_ASPACE_END && end > addr && end <= USER_ASPACE_END
    }

    #[test]
    fn rejects_null_guard_and_kernel_half() {
        assert!(!bounds_only(0, 1));
        assert!(!bounds_only(USER_ASPACE_BASE - 1, 1));
        assert!(!bounds_only(0xffff_8000_0000_0000, 8));
    }

    #[test]
    fn rejects_overflow_and_crossing_upper_bound() {
        assert!(!bounds_only(u64::MAX - 3, 8));
        assert!(!bounds_only(USER_ASPACE_END - 4, 8));
        assert!(bounds_only(USER_ASPACE_END - 4, 4));
    }

    #[test]
    fn accepts_page_crossing_range_inside_userspace() {
        assert!(bounds_only(USER_ASPACE_BASE + PAGE_SIZE - 2, 4));
    }

    #[test]
    fn typed_copy_sizes_reject_zero_sized_records() {
        assert!(matches!(
            checked_value_byte_len::<()>(),
            Err(ErrorCode::InvalidArgs)
        ));
        assert!(matches!(checked_array_byte_len::<()>(0), Ok(0)));
        assert!(matches!(
            checked_array_byte_len::<()>(1),
            Err(ErrorCode::InvalidArgs)
        ));
    }

    #[test]
    fn typed_copy_sizes_reject_overflow() {
        assert!(matches!(
            checked_array_byte_len::<u64>(usize::MAX),
            Err(ErrorCode::InvalidArgs)
        ));
    }
}
