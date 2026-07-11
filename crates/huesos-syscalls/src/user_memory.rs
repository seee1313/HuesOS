//! Validated copies across the userspace/kernel address-space boundary.
//!
//! Raw syscall arguments are controlled by ring 3. They must never be
//! dereferenced merely because they are non-null: while servicing a syscall
//! the CPU runs at CPL0 and could otherwise read or overwrite kernel memory on
//! the caller's behalf. This module is the only place in `huesos-syscalls`
//! that turns a userspace address into a Rust pointer.

use alloc::vec::Vec;
use core::{mem, ptr};
use huesos_abi::{ErrorCode, USER_ASPACE_BASE, USER_ASPACE_END};
use huesos_arch::VirtAddr;

const PAGE_SIZE: u64 = 4096;

/// Maximum byte count copied by one VMO read/write syscall.
pub(crate) const MAX_VMO_TRANSFER: usize = 1024 * 1024;
/// Maximum payload carried by one Channel message.
pub(crate) const MAX_CHANNEL_BYTES: usize = 64 * 1024;
/// Maximum handles carried by one Channel message.
pub(crate) const MAX_CHANNEL_HANDLES: usize = 64;

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
    let len = mem::size_of::<T>()
        .checked_mul(count)
        .ok_or(ErrorCode::InvalidArgs)?;
    validate_range(out as u64, len, true)
}

/// Copy one plain ABI value from userspace.
///
/// Callers use this only with `#[repr(C)]`, `Copy` ABI records whose bit
/// patterns are valid for every field (integers and raw pointers).
pub(crate) fn read_value<T: Copy>(src: *const T) -> Result<T, ErrorCode> {
    validate_range(src as u64, mem::size_of::<T>(), false)?;
    // SAFETY: every byte of T was verified readable in the active user page
    // tables. Unaligned access is intentional because the ABI does not require
    // callers to align argument records.
    Ok(unsafe { ptr::read_unaligned(src) })
}

/// Copy an array of plain values from userspace into kernel-owned memory.
pub(crate) fn read_array<T: Copy>(src: *const T, count: usize) -> Result<Vec<T>, ErrorCode> {
    let byte_len = mem::size_of::<T>()
        .checked_mul(count)
        .ok_or(ErrorCode::InvalidArgs)?;
    validate_range(src as u64, byte_len, false)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ErrorCode::NoMemory)?;
    for i in 0..count {
        // SAFETY: the complete array range was validated above. read_unaligned
        // avoids imposing an alignment requirement on the syscall ABI.
        values.push(unsafe { ptr::read_unaligned(src.add(i)) });
    }
    Ok(values)
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

/// Copy bytes from userspace into a kernel-owned vector.
pub(crate) fn copy_from_user(src: *const u8, len: usize) -> Result<Vec<u8>, ErrorCode> {
    validate_range(src as u64, len, false)?;
    let mut bytes = zeroed_buffer(len)?;
    if len != 0 {
        // SAFETY: the full source range is readable, and `bytes` owns a
        // distinct initialized destination of exactly `len` bytes.
        unsafe { ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), len) };
    }
    Ok(bytes)
}

/// Copy one plain ABI value to userspace.
pub(crate) fn write_value<T: Copy>(dst: *mut T, value: &T) -> Result<(), ErrorCode> {
    validate_write(dst)?;
    // SAFETY: the complete destination is user-accessible and writable.
    // write_unaligned keeps the raw syscall ABI independent of Rust alignment.
    unsafe { ptr::write_unaligned(dst, *value) };
    Ok(())
}

/// Copy a kernel byte slice to userspace.
pub(crate) fn copy_to_user(dst: *mut u8, bytes: &[u8]) -> Result<(), ErrorCode> {
    validate_range(dst as u64, bytes.len(), true)?;
    if !bytes.is_empty() {
        // SAFETY: the complete destination range is writable and cannot
        // overlap the kernel-owned source slice because kernel addresses are
        // excluded by validate_range.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    }
    Ok(())
}

/// Copy an array of plain values to userspace.
pub(crate) fn write_array<T: Copy>(dst: *mut T, values: &[T]) -> Result<(), ErrorCode> {
    validate_write_array(dst, values.len())?;
    for (i, value) in values.iter().enumerate() {
        // SAFETY: the complete destination array was validated above.
        unsafe { ptr::write_unaligned(dst.add(i), *value) };
    }
    Ok(())
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
}
