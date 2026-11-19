//! Alignment constants used by the userspace ELF process launcher.

pub(super) const PAGE_SIZE: u64 = 4096;

pub(super) fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub(super) fn align_up(value: u64, align: u64) -> Option<u64> {
    Some(value.checked_add(align - 1)? & !(align - 1))
}
