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

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u32 = 4096;

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
