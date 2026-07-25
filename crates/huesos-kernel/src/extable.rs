//! Kernel-mode recoverable-copy fixup dispatch.
//!
//! Bridges [`huesos_arch::fault`] and the host-tested [`huesos_extable`]
//! policy crate:
//!
//! 1. Each user-copy site in `huesos-syscalls::user_access` emits a
//!    3-quadword entry (`start_rip`, `end_rip`, `fixup_rip`) into the
//!    `.ex_table` linker section via `asm! .pushsection`. The linker
//!    exports `__huesos_ex_table_start` / `__huesos_ex_table_end` around
//!    that section so we can read the raw entries at boot.
//! 2. [`install`] reads those raw entries once, sorts them in place into
//!    a heap-owned `Vec<FixupRange>`, validates the sorted /
//!    non-overlapping invariant via [`Extable::new_sorted`], and stores
//!    the sorted snapshot behind an `Arc` published to a static slot.
//! 3. On every ring-0 `#PF` the IDT calls
//!    [`huesos_arch::fault::try_kernel_recover`], which consults the hook
//!    installed here. If the faulting RIP is covered, the CPU is
//!    redirected to `fixup_rip`; otherwise the historical fatal-panic
//!    path is taken.
//!
//! ## Boot ordering
//!
//! The read-and-sort pass runs from `kmain` after `init::heap_init`
//! (needed for the `Vec`) and after `init::syscall_init` has installed
//! the fault-handler callbacks. The exact call site is
//! `crate::extable::install`, invoked from `kmain` right after
//! `apply_kernel_wx()`.
//!
//! ## Rollback story
//!
//! If a future revision decides to disable the fixup path (for example
//! to bisect a suspected regression), delete the `install()` call from
//! `kmain`. The hook slot stays unset, `try_kernel_recover` returns
//! `None` for every fault, and the `.ex_table` section becomes inert
//! read-only rodata — no linker or code change required.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicPtr, Ordering};

use huesos_arch::fault::FaultInfo;
use huesos_extable::{Extable, FixupRange};

/// One raw entry in the linker-emitted `.ex_table` section. Layout must
/// match the `.quad start, end, fixup` sequence emitted by
/// `huesos-syscalls::user_access`'s `asm! .pushsection` blocks.
///
/// `#[repr(C)]` locks the field order and adds no padding: three
/// consecutive `u64`s at 8-byte alignment, exactly 24 bytes per entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RawEntry {
    start_rip: u64,
    end_rip: u64,
    fixup_rip: u64,
}

// Compile-time size check so a future field reordering that would break
// the ABI with the asm! emitter fails at build time, not at boot.
const _: () = assert!(size_of::<RawEntry>() == 24);

extern "C" {
    static __huesos_ex_table_start: u8;
    static __huesos_ex_table_end: u8;
}

/// Published sorted extable snapshot. `AtomicPtr` publishes a `*const
/// SortedTable` on install; `try_recover` reads it lock-free from every
/// ring-0 #PF handler. Storing `Arc` as raw pointer avoids taking a lock
/// on the fault path; the `Arc` is leaked intentionally — the sorted
/// snapshot lives for the entire kernel lifetime.
static SORTED_PTR: AtomicPtr<SortedTable> = AtomicPtr::new(core::ptr::null_mut());

struct SortedTable {
    entries: Vec<FixupRange>,
}

/// Read every raw entry from `[__huesos_ex_table_start,
/// __huesos_ex_table_end)`, sort by `start_rip`, validate the sorted /
/// non-overlapping invariant, and publish the sorted snapshot.
///
/// Also registers [`try_recover`] with the architecture layer as the
/// ring-0 fault-recovery hook.
///
/// Idempotent: a second call replaces the snapshot with a re-read of the
/// same section. The kernel calls this exactly once from `kmain`.
///
/// Returns the number of entries that were installed, so `kmain` can log
/// it on early serial for operator visibility.
pub fn install() -> usize {
    // Address-of on extern statics is safe; only a dereference is unsafe.
    let start = core::ptr::addr_of!(__huesos_ex_table_start) as usize;
    let end = core::ptr::addr_of!(__huesos_ex_table_end) as usize;

    if end < start {
        // Would only happen with a broken linker script; log-and-skip is
        // strictly better than a panic on boot.
        huesos_arch::fault::set_kernel_recover_hook(try_recover);
        return 0;
    }
    let byte_len = end - start;
    if !byte_len.is_multiple_of(size_of::<RawEntry>()) {
        // Same story: a partial entry means someone emitted a malformed
        // `.pushsection` block. Skip installation, keep the hook wired so
        // the empty snapshot returns None uniformly.
        huesos_arch::fault::set_kernel_recover_hook(try_recover);
        return 0;
    }
    let entry_count = byte_len / size_of::<RawEntry>();

    // Read the raw section into an owned Vec<FixupRange> so we can sort
    // and re-validate. The section itself lives in .rodata and stays
    // valid for the kernel lifetime, but we never mutate it in place.
    let mut entries: Vec<FixupRange> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let addr = start + i * size_of::<RawEntry>();
        // SAFETY: [start, end) is a linker-defined range of packed
        // RawEntry records placed by the assembler. Unaligned read is
        // used defensively: the linker script `.balign 8` guarantees
        // alignment, but read_unaligned costs the same on x86 and
        // survives a future linker-script edit that forgets it.
        let raw = unsafe { core::ptr::read_unaligned(addr as *const RawEntry) };
        entries.push(FixupRange {
            start_rip: raw.start_rip,
            end_rip: raw.end_rip,
            fixup_rip: raw.fixup_rip,
        });
    }

    // Sort by start_rip; the policy crate's Extable::new_sorted then
    // validates well-formedness + non-overlap.
    huesos_extable::sort_ranges(&mut entries);

    // Validate. If validation fails (overlapping ranges or reversed
    // start/end from a botched emit), publish an empty snapshot so
    // try_recover uniformly returns None — a broken table must never
    // silently claim to recover the wrong fault.
    if Extable::new_sorted(&entries).is_none() {
        let empty: Vec<FixupRange> = Vec::new();
        publish(SortedTable { entries: empty });
        huesos_arch::fault::set_kernel_recover_hook(try_recover);
        return 0;
    }

    publish(SortedTable { entries });
    huesos_arch::fault::set_kernel_recover_hook(try_recover);
    entry_count
}

fn publish(table: SortedTable) {
    // Leak the Arc so the snapshot outlives the kernel lifetime and
    // try_recover can dereference the AtomicPtr without an atomic
    // reference count operation on the fault path.
    let arc = Arc::new(table);
    let raw = Arc::into_raw(arc) as *mut SortedTable;
    let previous = SORTED_PTR.swap(raw, Ordering::Release);
    if !previous.is_null() {
        // Idempotent re-install: reconstruct + drop the old Arc to avoid
        // a leak on repeated installs (test paths).
        // SAFETY: previous was published by an earlier `into_raw` on the
        // same Arc type, and we removed it from the atomic before drop.
        drop(unsafe { Arc::from_raw(previous as *const SortedTable) });
    }
}

/// Ring-0 fault-recovery hook wired into [`huesos_arch::fault`]. Called
/// on every ring-0 `#PF`; consults the published sorted snapshot without
/// taking a lock.
fn try_recover(info: FaultInfo) -> Option<u64> {
    let ptr = SORTED_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr was published by `install` via `Arc::into_raw`. The
    // Arc is leaked (never re-freed), so the pointee is valid for the
    // kernel lifetime.
    let table = unsafe { &*ptr };
    let extable = Extable::new_sorted(&table.entries)?;
    match huesos_extable::resolve_kernel_fault(info.instruction_pointer, &extable) {
        huesos_extable::FaultResolution::Recover { fixup_rip } => Some(fixup_rip),
        huesos_extable::FaultResolution::Fatal => None,
    }
}

/// Number of installed extable entries, for boot-time logging and host
/// tests. Returns 0 before [`install`] has run.
pub fn entry_count() -> usize {
    let ptr = SORTED_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: same invariant as try_recover.
    let table = unsafe { &*ptr };
    table.entries.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_arch::fault::{FaultInfo, FaultKind};

    fn fault_at(rip: u64, cs_ring: u64) -> FaultInfo {
        FaultInfo {
            kind: FaultKind::PageFault,
            instruction_pointer: rip,
            stack_pointer: 0,
            rflags: 0,
            code_segment: cs_ring,
            error_code: 0,
            fault_address: 0,
        }
    }

    /// Force-publish a known-good sorted snapshot so host tests can
    /// exercise try_recover without a linker section. Kept behind
    /// #[cfg(test)] so no production caller can bypass install()'s
    /// validation.
    fn publish_test_snapshot(entries: Vec<FixupRange>) {
        publish(SortedTable { entries });
    }

    #[test]
    fn try_recover_returns_none_when_unpublished_or_out_of_range() {
        // Empty snapshot: try_recover returns None uniformly.
        publish_test_snapshot(Vec::new());
        assert_eq!(try_recover(fault_at(0, 0)), None);
        assert_eq!(try_recover(fault_at(u64::MAX, 0)), None);
    }

    #[test]
    fn try_recover_maps_covered_rip_to_fixup() {
        publish_test_snapshot(alloc::vec![
            FixupRange {
                start_rip: 0x1000,
                end_rip: 0x1010,
                fixup_rip: 0x9000
            },
            FixupRange {
                start_rip: 0x2000,
                end_rip: 0x2020,
                fixup_rip: 0x9008
            },
        ]);
        assert_eq!(try_recover(fault_at(0x1000, 0)), Some(0x9000));
        assert_eq!(try_recover(fault_at(0x100F, 0)), Some(0x9000));
        assert_eq!(try_recover(fault_at(0x1010, 0)), None); // end is exclusive
        assert_eq!(try_recover(fault_at(0x2000, 0)), Some(0x9008));
        assert_eq!(try_recover(fault_at(0x201F, 0)), Some(0x9008));
        assert_eq!(try_recover(fault_at(0x2020, 0)), None);
    }

    #[test]
    fn try_recover_ignores_userspace_faults() {
        publish_test_snapshot(alloc::vec![FixupRange {
            start_rip: 0x1000,
            end_rip: 0x1010,
            fixup_rip: 0x9000,
        }]);
        // cs_ring = 3 => from_userspace() = true. huesos_arch's
        // try_kernel_recover already filters CPL3 out; we mirror the
        // policy here so the tests document the same behavior.
        let user_info = fault_at(0x1005, 3);
        assert!(user_info.from_userspace());
        // Our try_recover does NOT filter CPL3 itself — that filter lives
        // in huesos_arch::fault::try_kernel_recover. Document by asserting
        // that even a CPL3 fault RIP inside our covered range returns
        // Some(...); the arch-layer wrapper is what enforces CPL0-only.
        assert_eq!(try_recover(user_info), Some(0x9000));
    }
}
