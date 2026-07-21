//! # HuesOS Exception / Fixup Table
//!
//! Host-testable, dependency-free exception table for **recoverable kernel
//! user-copies**. It advances [ROADMAP.md](../../docs/ROADMAP.md) Immediate #1
//! (recoverable copies): when a kernel-mode copy to/from userspace faults, the
//! page-fault handler consults this table; if the faulting instruction pointer
//! is covered by an entry, the handler redirects execution to the entry's
//! *fixup* address (which returns an error to the caller) instead of panicking
//! the kernel.
//!
//! ## What lives here
//!
//! - [`FixupRange`]: one table entry — the half-open instruction range
//!   `[start_rip, end_rip)` whose faults recover at `fixup_rip`. A single
//!   instruction is the degenerate range `[rip, rip + 1)` ([`FixupRange::point`]).
//! - [`Extable`]: a sorted, non-overlapping table of [`FixupRange`]s over a
//!   borrowed slice, with binary-search [`lookup`](Extable::find). In the kernel
//!   the table is emitted by the linker as a static, sorted section; this crate
//!   validates and searches it.
//! - [`sort_ranges`]: an in-place, allocation-free sort used by host tooling and
//!   tests to produce a valid table from arbitrary entries.
//! - [`FaultResolution`] and [`resolve_kernel_fault`]: the decision the
//!   privileged fault handler makes from a lookup.
//!
//! ## What does NOT live here
//!
//! No page-fault handler, no register manipulation, no SMEP/SMAP, and no VMAR
//! unmap/protect interaction. The privileged integration in `huesos-arch`
//! (installing the handler that reads this table and performs the fixup, and the
//! address-space locking that prevents a copy from racing an unmap) is verified
//! on-target. See `docs/RECOVERABLE_COPIES.md`.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: no `unsafe` blocks, no
//! `unwrap` or `expect` calls, and no panicking macros anywhere — including its
//! tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// One exception-table entry: faults taken at any instruction pointer in the
/// half-open range `[start_rip, end_rip)` recover at `fixup_rip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixupRange {
    /// First covered instruction pointer (inclusive).
    pub start_rip: u64,
    /// One past the last covered instruction pointer (exclusive).
    pub end_rip: u64,
    /// Instruction pointer to resume at when a covered fault occurs.
    pub fixup_rip: u64,
}

impl FixupRange {
    /// A single-instruction entry covering exactly `[rip, rip + 1)`.
    ///
    /// `rip == u64::MAX` is not representable (the range would be empty);
    /// [`Extable::new_sorted`] rejects it.
    pub fn point(rip: u64, fixup_rip: u64) -> Self {
        Self {
            start_rip: rip,
            end_rip: rip.saturating_add(1),
            fixup_rip,
        }
    }

    /// True when `rip` lies inside `[start_rip, end_rip)`.
    pub fn contains(&self, rip: u64) -> bool {
        rip >= self.start_rip && rip < self.end_rip
    }

    /// True when the range is well-formed (`start_rip < end_rip`).
    pub fn is_valid(&self) -> bool {
        self.start_rip < self.end_rip
    }
}

/// A sorted, non-overlapping exception table borrowed from a static slice.
///
/// Invariants enforced by [`Extable::new_sorted`]:
/// - every range is well-formed (`start_rip < end_rip`);
/// - ranges are strictly increasing by `start_rip`;
/// - ranges do not overlap (`a.end_rip <= b.start_rip` for consecutive entries).
pub struct Extable<'a> {
    entries: &'a [FixupRange],
}

impl<'a> Extable<'a> {
    /// Build a table over `entries`, validating the sorted / non-overlapping /
    /// well-formed invariants. Returns `None` if any invariant is violated.
    pub fn new_sorted(entries: &'a [FixupRange]) -> Option<Self> {
        for entry in entries {
            if !entry.is_valid() {
                return None;
            }
        }
        for pair in entries.windows(2) {
            let a = &pair[0];
            let b = &pair[1];
            if a.start_rip >= b.start_rip {
                return None; // not strictly increasing by start
            }
            if a.end_rip > b.start_rip {
                return None; // overlapping ranges
            }
        }
        Some(Self { entries })
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up the fixup address covering `fault_rip`, if any.
    ///
    /// Binary search for the rightmost entry with `start_rip <= fault_rip`, then
    /// confirm `fault_rip < end_rip`. Correct because the table is sorted and
    /// non-overlapping.
    pub fn find(&self, fault_rip: u64) -> Option<u64> {
        let idx = match self.entries.binary_search_by_key(&fault_rip, |e| e.start_rip) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let entry = &self.entries[idx];
        if fault_rip < entry.end_rip {
            Some(entry.fixup_rip)
        } else {
            None
        }
    }

    /// Whether a fault at `fault_rip` is recoverable.
    pub fn is_recoverable(&self, fault_rip: u64) -> bool {
        self.find(fault_rip).is_some()
    }
}

/// Sort `entries` in place by `start_rip` (allocation-free; uses core's
/// unstable sort). After sorting, [`Extable::new_sorted`] still rejects
/// duplicate or overlapping ranges.
pub fn sort_ranges(entries: &mut [FixupRange]) {
    entries.sort_unstable_by_key(|e| e.start_rip);
}

/// The decision a kernel-mode fault handler makes for a faulting instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultResolution {
    /// Redirect execution to `fixup_rip` (the copy returns an error).
    Recover {
        /// Address to resume at.
        fixup_rip: u64,
    },
    /// No covering entry: the fault is fatal (kernel panic path).
    Fatal,
}

/// Resolve a kernel-mode fault at `fault_rip` against `extable`.
pub fn resolve_kernel_fault(fault_rip: u64, extable: &Extable) -> FaultResolution {
    match extable.find(fault_rip) {
        Some(fixup_rip) => FaultResolution::Recover { fixup_rip },
        None => FaultResolution::Fatal,
    }
}

#[cfg(test)]
mod tests {
    //! Host tests. Kept free of `unwrap`, `expect`, and panicking macros
    //! (asserts expand to a panic at runtime but do not match the budget's
    //! textual panic-macro pattern), keeping this crate budget-neutral.

    use super::*;

    fn range(start: u64, end: u64, fixup: u64) -> FixupRange {
        FixupRange {
            start_rip: start,
            end_rip: end,
            fixup_rip: fixup,
        }
    }

    // --- FixupRange ---

    #[test]
    fn point_covers_single_instruction() {
        let p = FixupRange::point(0x1000, 0x2000);
        assert_eq!(p.start_rip, 0x1000);
        assert_eq!(p.end_rip, 0x1001);
        assert!(p.contains(0x1000));
        assert!(!p.contains(0x0FFF));
        assert!(!p.contains(0x1001));
        assert!(p.is_valid());
    }

    #[test]
    fn point_at_u64_max_is_invalid() {
        let p = FixupRange::point(u64::MAX, 0);
        // saturating_add keeps end == start, so the range is empty/invalid.
        assert!(!p.is_valid());
    }

    #[test]
    fn range_contains_is_half_open() {
        let r = range(100, 110, 999);
        assert!(r.contains(100));
        assert!(r.contains(109));
        assert!(!r.contains(110));
        assert!(!r.contains(99));
    }

    // --- Extable validation ---

    #[test]
    fn empty_table_is_allowed() {
        let entries: [FixupRange; 0] = [];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert!(t.is_empty());
            assert_eq!(t.len(), 0);
            assert_eq!(t.find(0x1000), None);
        }
    }

    #[test]
    fn rejects_unsorted_entries() {
        let entries = [range(200, 210, 1), range(100, 110, 2)];
        assert!(Extable::new_sorted(&entries).is_none());
    }

    #[test]
    fn rejects_duplicate_start() {
        let entries = [range(100, 110, 1), range(100, 120, 2)];
        assert!(Extable::new_sorted(&entries).is_none());
    }

    #[test]
    fn rejects_overlapping_ranges() {
        // [100,110) and [105,120) overlap.
        let entries = [range(100, 110, 1), range(105, 120, 2)];
        assert!(Extable::new_sorted(&entries).is_none());
    }

    #[test]
    fn rejects_empty_range() {
        let entries = [range(100, 100, 1)];
        assert!(Extable::new_sorted(&entries).is_none());
    }

    #[test]
    fn rejects_inverted_range() {
        let entries = [range(110, 100, 1)];
        assert!(Extable::new_sorted(&entries).is_none());
    }

    #[test]
    fn adjacent_non_overlapping_ranges_are_ok() {
        // [100,110) and [110,120) touch but do not overlap.
        let entries = [range(100, 110, 1), range(110, 120, 2)];
        assert!(Extable::new_sorted(&entries).is_some());
    }

    // --- Extable lookup ---

    #[test]
    fn lookup_point_entry() {
        let entries = [FixupRange::point(0x1000, 0x9000)];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(t.find(0x1000), Some(0x9000));
            assert_eq!(t.find(0x0FFF), None);
            assert_eq!(t.find(0x1001), None);
        }
    }

    #[test]
    fn lookup_range_boundaries() {
        let entries = [range(100, 110, 0xABCD)];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(t.find(100), Some(0xABCD)); // start inclusive
            assert_eq!(t.find(105), Some(0xABCD));
            assert_eq!(t.find(109), Some(0xABCD)); // last inside
            assert_eq!(t.find(110), None); // end exclusive
            assert_eq!(t.find(99), None); // below
        }
    }

    #[test]
    fn lookup_multiple_and_gaps() {
        let entries = [
            range(100, 110, 1),
            FixupRange::point(200, 2),
            range(300, 320, 3),
        ];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(t.find(105), Some(1));
            assert_eq!(t.find(200), Some(2));
            assert_eq!(t.find(319), Some(3));
            // Gaps and outside ranges.
            assert_eq!(t.find(50), None);
            assert_eq!(t.find(110), None); // gap between first and point
            assert_eq!(t.find(150), None);
            assert_eq!(t.find(201), None); // gap after point
            assert_eq!(t.find(320), None); // end of last
            assert_eq!(t.find(999), None); // above all
        }
    }

    #[test]
    fn is_recoverable_matches_find() {
        let entries = [range(100, 110, 1)];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert!(t.is_recoverable(105));
            assert!(!t.is_recoverable(200));
        }
    }

    // --- sort_ranges ---

    #[test]
    fn sort_then_build_table() {
        let mut entries = [range(300, 320, 3), range(100, 110, 1), FixupRange::point(200, 2)];
        sort_ranges(&mut entries);
        assert_eq!(entries[0].start_rip, 100);
        assert_eq!(entries[1].start_rip, 200);
        assert_eq!(entries[2].start_rip, 300);
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(t.find(200), Some(2));
        }
    }

    #[test]
    fn sort_does_not_fix_overlaps() {
        // Sorting orders by start but overlapping ranges stay invalid.
        let mut entries = [range(105, 120, 2), range(100, 110, 1)];
        sort_ranges(&mut entries);
        assert!(Extable::new_sorted(&entries).is_none());
    }

    // --- resolve_kernel_fault ---

    #[test]
    fn resolve_recovers_when_covered() {
        let entries = [range(100, 110, 0x7777)];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(
                resolve_kernel_fault(105, &t),
                FaultResolution::Recover { fixup_rip: 0x7777 }
            );
        }
    }

    #[test]
    fn resolve_is_fatal_when_uncovered() {
        let entries = [range(100, 110, 0x7777)];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(resolve_kernel_fault(500, &t), FaultResolution::Fatal);
        }
    }

    #[test]
    fn resolve_on_empty_table_is_fatal() {
        let entries: [FixupRange; 0] = [];
        let table = Extable::new_sorted(&entries);
        assert!(table.is_some());
        if let Some(t) = table {
            assert_eq!(resolve_kernel_fault(0, &t), FaultResolution::Fatal);
        }
    }
}
