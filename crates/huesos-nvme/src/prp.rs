//! PRP (Physical Region Page) layout computation for NVMe Read/Write.
//!
//! NVMe data transfers name physical memory through PRP entries:
//! - PRP1 is the first byte address; it may carry an offset within its page
//!   (only the first PRP may be unaligned).
//! - If the transfer fits in one page, PRP2 is unused.
//! - If it spans exactly two pages, PRP2 is the second page's (aligned) address.
//! - If it spans more than two pages, PRP2 points to a PRP list: a page holding
//!   aligned per-page PRP entries (the last slot of a PRP-list page may chain to
//!   another PRP-list page for very large transfers; the driver handles that
//!   chaining, this module computes the entry values).
//!
//! Page size is always a power of two for NVMe (2^(12+MPS)).

/// PRP1: the first byte address of the transfer (`base + offset`).
pub const fn prp1(base: u64, offset: u32) -> u64 {
    base + offset as u64
}

/// Number of distinct memory pages touched by `length` bytes starting `offset`
/// bytes into the first page. Returns 0 for a zero-length transfer.
pub fn pages_touched(offset: u32, length: u32, page_size: u32) -> usize {
    if length == 0 {
        return 0;
    }
    let ps = page_size as u64;
    let start = offset as u64;
    let end = start + length as u64;
    let first = start / ps;
    let last = (end - 1) / ps;
    (last - first + 1) as usize
}

/// True when the transfer spans more than two pages and therefore needs a PRP
/// list (PRP2 points at a list page) rather than a single direct PRP2 page.
pub fn needs_prp_list(offset: u32, length: u32, page_size: u32) -> bool {
    pages_touched(offset, length, page_size) > 2
}

/// Number of PRP entries after PRP1 (the "rest"): `pages_touched - 1`.
pub fn rest_count(offset: u32, length: u32, page_size: u32) -> usize {
    pages_touched(offset, length, page_size).saturating_sub(1)
}

/// The aligned base address of the overall page index `n` (0 = PRP1's page).
/// `page_size` must be a power of two.
pub fn page_base(base: u64, offset: u32, page_size: u32, n: usize) -> u64 {
    let ps = page_size as u64;
    let first_page_base = (base + offset as u64) & !(ps - 1);
    first_page_base + (n as u64) * ps
}

/// The i-th "rest" page address (0-indexed): the page after PRP1's page is
/// rest index 0. These are the values that go into PRP2 (if one) or the PRP
/// list (if several).
pub fn rest_page(base: u64, offset: u32, page_size: u32, i: usize) -> u64 {
    page_base(base, offset, page_size, i + 1)
}

/// Fill `out` with the rest page addresses for the transfer. Returns the number
/// written (min of `rest_count` and `out.len()`).
pub fn fill_rest(base: u64, offset: u32, length: u32, page_size: u32, out: &mut [u64]) -> usize {
    let n = rest_count(offset, length, page_size).min(out.len());
    let mut i = 0;
    while i < n {
        out[i] = rest_page(base, offset, page_size, i);
        i += 1;
    }
    n
}

/// How many PRP entries fit in one PRP-list page of `page_size` bytes
/// (each entry is 8 bytes). When a transfer needs more entries than this, the
/// driver chains PRP-list pages (the last slot points to the next list page).
pub const fn entries_per_list_page(page_size: u32) -> usize {
    (page_size as usize) / 8
}

/// How many PRP-list pages a transfer needs.
///
/// A list page holds `page_size / 8` slots. When more entries are
/// needed than fit, the **last slot of each list page is a pointer to
/// the next list page** rather than a data page, so each page except
/// the final one contributes `entries_per_list_page - 1` data
/// entries.
///
/// Returns 0 when no list is needed (0, 1 or 2 pages touched: those
/// use PRP1 and a direct PRP2).
pub fn list_pages_needed(offset: u32, length: u32, page_size: u32) -> usize {
    let entries = rest_count(offset, length, page_size);
    let per_page = entries_per_list_page(page_size);
    if entries <= 1 || per_page < 2 {
        // 0 or 1 rest entries go in PRP2 directly; a page too small to
        // hold both a data entry and a chain pointer cannot chain.
        return 0;
    }
    if entries <= per_page {
        return 1;
    }
    // Every page gives up its last slot to the chain pointer, except
    // the last page in the chain.
    let usable = per_page - 1;
    // ceil division, avoiding overflow on the +usable-1 term.
    let mut pages = entries / usable;
    if !entries.is_multiple_of(usable) {
        pages += 1;
    }
    // The final page does not need a chain pointer, so the last page
    // may hold one extra entry. Recheck whether that saves a page.
    if (pages - 1) * usable + per_page >= entries {
        pages
    } else {
        pages + 1
    }
}

/// One slot to write into a PRP list page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListSlot {
    /// Index of the list page this slot belongs to (0-based).
    pub list_page: usize,
    /// Slot index within that list page.
    pub slot: usize,
    /// The 64-bit value to store.
    pub value: u64,
    /// True when `value` points at the next list page rather than at
    /// a data page. Useful for assertions and diagnostics.
    pub is_chain: bool,
}

/// Compute the full PRP list layout, including chain pointers.
///
/// `list_pages` are the physical addresses of the driver's list pages;
/// there must be at least [`list_pages_needed`] of them. Slots are
/// emitted into `out` in write order. Returns the number of slots
/// written, or `None` if `out` or `list_pages` is too small — the
/// caller must then reject the transfer rather than program a
/// truncated list, which would make the device DMA into whatever the
/// stale slots happen to contain.
pub fn plan_list(
    base: u64,
    offset: u32,
    length: u32,
    page_size: u32,
    list_pages: &[u64],
    out: &mut [ListSlot],
) -> Option<usize> {
    let entries = rest_count(offset, length, page_size);
    let per_page = entries_per_list_page(page_size);
    let needed = list_pages_needed(offset, length, page_size);
    if needed == 0 || list_pages.len() < needed {
        return None;
    }

    let mut written = 0usize;
    let mut entry = 0usize;
    let mut page = 0usize;
    while entry < entries {
        // Reserve the last slot for a chain pointer unless this is the
        // final list page.
        let is_last_page = page + 1 == needed;
        let capacity = if is_last_page { per_page } else { per_page - 1 };
        let mut slot = 0usize;
        while slot < capacity && entry < entries {
            if written >= out.len() {
                return None;
            }
            out[written] = ListSlot {
                list_page: page,
                slot,
                value: rest_page(base, offset, page_size, entry),
                is_chain: false,
            };
            written += 1;
            slot += 1;
            entry += 1;
        }
        if !is_last_page {
            if written >= out.len() {
                return None;
            }
            out[written] = ListSlot {
                list_page: page,
                slot: per_page - 1,
                value: list_pages[page + 1],
                is_chain: true,
            };
            written += 1;
        }
        page += 1;
    }
    Some(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u32 = 4096;

    // 4096 / 8 = 512 slots per list page.
    const SLOTS: usize = 512;

    #[test]
    fn no_list_for_small_transfers() {
        // 0, 1, 2 pages: PRP1 (+ direct PRP2), never a list.
        assert_eq!(list_pages_needed(0, 0, PAGE), 0);
        assert_eq!(list_pages_needed(0, PAGE, PAGE), 0);
        assert_eq!(list_pages_needed(0, 2 * PAGE, PAGE), 0);
    }

    #[test]
    fn one_list_page_when_entries_fit() {
        // 3 pages touched -> 2 rest entries -> one list page.
        assert_eq!(list_pages_needed(0, 3 * PAGE, PAGE), 1);
        // Exactly 512 rest entries still fits one page: the final page
        // needs no chain pointer, so all 512 slots carry data.
        let length = (SLOTS as u32 + 1) * PAGE;
        assert_eq!(rest_count(0, length, PAGE), SLOTS);
        assert_eq!(list_pages_needed(0, length, PAGE), 1);
    }

    #[test]
    fn chains_when_entries_exceed_one_page() {
        // 513 rest entries cannot fit 512 slots: the first page gives
        // up its last slot to the chain pointer, leaving 511 + 513-511.
        let length = (SLOTS as u32 + 2) * PAGE;
        assert_eq!(rest_count(0, length, PAGE), SLOTS + 1);
        assert_eq!(list_pages_needed(0, length, PAGE), 2);
    }

    #[test]
    fn plan_places_chain_pointer_in_last_slot() {
        let length = (SLOTS as u32 + 2) * PAGE; // 513 rest entries
        let pages = [0x10_0000u64, 0x20_0000u64];
        let mut out = [ListSlot {
            list_page: 0,
            slot: 0,
            value: 0,
            is_chain: false,
        }; SLOTS + 8];
        let Some(written) = plan_list(0, 0, length, PAGE, &pages, &mut out) else {
            assert!(false, "planning a two-page chain must succeed");
            return;
        };
        // 511 data + 1 chain on page 0, then 2 data on page 1.
        assert_eq!(written, SLOTS + 2);

        let chain = out[SLOTS - 1];
        assert!(chain.is_chain, "last slot of a non-final page chains");
        assert_eq!(chain.list_page, 0);
        assert_eq!(chain.slot, SLOTS - 1);
        assert_eq!(chain.value, pages[1], "chain points at the next list page");

        // Data entries are consecutive pages, and the chain slot must
        // not have consumed one of them.
        assert_eq!(out[0].value, PAGE as u64);
        assert!(!out[0].is_chain);
        assert_eq!(out[SLOTS - 2].value, (SLOTS as u64 - 1) * PAGE as u64);
        // First entry on the second list page continues the sequence.
        assert_eq!(out[SLOTS].list_page, 1);
        assert_eq!(out[SLOTS].slot, 0);
        assert_eq!(out[SLOTS].value, SLOTS as u64 * PAGE as u64);
    }

    #[test]
    fn plan_covers_every_page_exactly_once() {
        // Walk a range of sizes and assert the planned data entries are
        // exactly the pages after PRP1, in order, with no gaps or
        // duplicates — the property a truncated list would break.
        let pages = [0x10_0000u64, 0x20_0000u64, 0x30_0000u64];
        for extra in [3u32, 100, 511, 512, 513, 900] {
            let length = (extra + 1) * PAGE;
            let entries = rest_count(0, length, PAGE);
            let mut out = [ListSlot {
                list_page: 0,
                slot: 0,
                value: 0,
                is_chain: false,
            }; 1200];
            let Some(written) = plan_list(0, 0, length, PAGE, &pages, &mut out) else {
                assert!(false, "planning must succeed for {extra} pages");
                return;
            };
            let data: alloc::vec::Vec<u64> = out[..written]
                .iter()
                .filter(|slot| !slot.is_chain)
                .map(|slot| slot.value)
                .collect();
            assert_eq!(data.len(), entries, "entry count for {extra}");
            for (i, value) in data.iter().enumerate() {
                assert_eq!(*value, (i as u64 + 1) * PAGE as u64, "page {i} of {extra}");
            }
        }
    }

    #[test]
    fn plan_rejects_insufficient_list_pages() {
        // 513 entries need two list pages; offering one must fail
        // rather than silently truncate.
        let length = (SLOTS as u32 + 2) * PAGE;
        let pages = [0x10_0000u64];
        let mut out = [ListSlot {
            list_page: 0,
            slot: 0,
            value: 0,
            is_chain: false,
        }; SLOTS + 8];
        assert_eq!(plan_list(0, 0, length, PAGE, &pages, &mut out), None);
    }

    #[test]
    fn plan_honours_unaligned_offset() {
        // Offset pushes the transfer one page further; entries must be
        // page bases, never `buf + n * page_size`.
        let offset = 512u32;
        let length = 3 * PAGE;
        let base = 0x40_0000u64;
        let pages = [0x10_0000u64, 0x20_0000u64];
        let mut out = [ListSlot {
            list_page: 0,
            slot: 0,
            value: 0,
            is_chain: false,
        }; 16];
        let Some(written) = plan_list(base, offset, length, PAGE, &pages, &mut out) else {
            assert!(false, "unaligned planning must succeed");
            return;
        };
        assert_eq!(written, rest_count(offset, length, PAGE));
        for (i, slot) in out[..written].iter().enumerate() {
            assert_eq!(
                slot.value % PAGE as u64,
                0,
                "entry {i} must be page aligned"
            );
            assert_eq!(slot.value, base + (i as u64 + 1) * PAGE as u64);
        }
    }

    #[test]
    fn single_page_transfer() {
        // 4 KiB aligned: exactly one page, no PRP2.
        assert_eq!(pages_touched(0, 4096, PAGE), 1);
        assert_eq!(rest_count(0, 4096, PAGE), 0);
        assert!(!needs_prp_list(0, 4096, PAGE));
        assert_eq!(prp1(0x10_0000, 0), 0x10_0000);
    }

    #[test]
    fn partial_first_page_still_one_page() {
        // 100 bytes starting 100 bytes into a page: one page.
        assert_eq!(pages_touched(100, 100, PAGE), 1);
        assert_eq!(rest_count(100, 100, PAGE), 0);
    }

    #[test]
    fn crosses_into_second_page() {
        // 200 bytes starting 4000 bytes in: crosses the page boundary -> 2 pages.
        assert_eq!(pages_touched(4000, 200, PAGE), 2);
        assert_eq!(rest_count(4000, 200, PAGE), 1);
        assert!(!needs_prp_list(4000, 200, PAGE)); // exactly 2 -> direct PRP2
    }

    #[test]
    fn three_pages_needs_prp_list() {
        // Aligned 3-page transfer.
        assert_eq!(pages_touched(0, 3 * 4096, PAGE), 3);
        assert_eq!(rest_count(0, 3 * 4096, PAGE), 2);
        assert!(needs_prp_list(0, 3 * 4096, PAGE));
    }

    #[test]
    fn prp1_carries_offset() {
        assert_eq!(prp1(0x20_0000, 512), 0x20_0000 + 512);
    }

    #[test]
    fn rest_pages_are_aligned_and_sequential() {
        let base = 0x40_0000u64;
        // Offset 100, length spanning 3 pages.
        let p0 = rest_page(base, 100, PAGE, 0); // page after PRP1's page
        let p1 = rest_page(base, 100, PAGE, 1);
        assert_eq!(p0 % PAGE as u64, 0); // aligned
        assert_eq!(p1 % PAGE as u64, 0);
        assert_eq!(p1 - p0, PAGE as u64);
        // PRP1's page base is base (offset 100 is within base's page).
        assert_eq!(page_base(base, 100, PAGE, 0), base);
        assert_eq!(p0, base + PAGE as u64);
    }

    #[test]
    fn fill_rest_writes_expected() {
        let base = 0x80_0000u64;
        let mut out = [0u64; 4];
        let n = fill_rest(base, 0, 3 * 4096, PAGE, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0], base + PAGE as u64);
        assert_eq!(out[1], base + 2 * PAGE as u64);
    }

    #[test]
    fn fill_rest_respects_buffer_size() {
        let mut out = [0u64; 1];
        let n = fill_rest(0x1000, 0, 5 * 4096, PAGE, &mut out);
        assert_eq!(n, 1); // buffer only holds one
    }

    #[test]
    fn zero_length_touches_no_pages() {
        assert_eq!(pages_touched(0, 0, PAGE), 0);
        assert_eq!(rest_count(0, 0, PAGE), 0);
    }

    #[test]
    fn entries_per_list_page_is_page_over_8() {
        assert_eq!(entries_per_list_page(4096), 512);
    }
}
