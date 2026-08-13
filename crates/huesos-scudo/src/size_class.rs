//! Size-class map (Scudo `SizeClassMap`).
//!
//! Scudo segregates small allocations into a fixed set of size
//! classes. Segregation is what makes the primary allocator's free
//! lists O(1) and — more importantly here — it is a hardening
//! property: a chunk can only ever be recycled into an allocation of
//! the same class, so an attacker cannot free a small object and have
//! the space handed back as a differently-shaped larger one.
//!
//! The table below mirrors upstream's default `AndroidSizeClassMap`
//! shape: dense 16-byte steps for the smallest sizes (where most
//! allocations land), then progressively coarser geometric steps.
//! Anything larger than the last class is served by the secondary
//! allocator instead.

/// Allocation granularity and minimum alignment of every chunk.
///
/// 16 bytes matches the platform's maximum fundamental alignment, so
/// a chunk that is 16-byte aligned satisfies any `Layout` alignment
/// up to that without extra padding.
pub const MIN_ALIGNMENT: usize = 16;

/// Number of size classes served by the primary allocator.
pub const NUM_CLASSES: usize = 32;

/// The largest allocation the primary allocator serves. Requests
/// above this go to the secondary.
pub const MAX_PRIMARY_SIZE: usize = 65536;

/// Size of each class, in bytes.
///
/// Every entry is a multiple of [`MIN_ALIGNMENT`] and the table is
/// strictly increasing — both invariants are asserted by the tests,
/// because a violation would silently break the class lookup.
pub const CLASS_SIZES: [usize; NUM_CLASSES] = [
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 4096, 6144, 8192, 16384, 32768, 65536,
];

/// How many chunks the primary tries to carve at once for a class
/// (Scudo's `TransferBatch`). Small classes are refilled in larger
/// counts because they are requested far more often; large classes
/// use small batches so a single refill cannot strand a lot of
/// memory in one class's free list.
pub fn batch_count(class: usize) -> usize {
    match CLASS_SIZES.get(class) {
        Some(size) if *size <= 128 => 32,
        Some(size) if *size <= 1024 => 16,
        Some(size) if *size <= 8192 => 8,
        Some(_) => 4,
        None => 0,
    }
}

/// Map a requested size to its class index, or `None` when the
/// request belongs to the secondary allocator.
pub fn class_for_size(size: usize) -> Option<usize> {
    if size > MAX_PRIMARY_SIZE {
        return None;
    }
    // Linear scan over 32 entries; the table is tiny, monotonic, and
    // hot in cache. A branchless computed index would be faster but
    // much harder to review, and the allocator's cost is dominated by
    // the header/checksum work rather than this lookup.
    CLASS_SIZES.iter().position(|class| *class >= size.max(1))
}

/// Size in bytes of the chunks in `class`.
pub fn size_for_class(class: usize) -> Option<usize> {
    CLASS_SIZES.get(class).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_strictly_increasing_and_aligned() {
        let mut previous = 0usize;
        for size in CLASS_SIZES {
            assert!(size > previous, "class table must be strictly increasing");
            assert_eq!(
                size % MIN_ALIGNMENT,
                0,
                "every class must be a multiple of MIN_ALIGNMENT"
            );
            previous = size;
        }
        assert_eq!(previous, MAX_PRIMARY_SIZE);
    }

    #[test]
    fn class_lookup_is_smallest_fitting_class() {
        // Exact boundaries pick their own class, not the next one.
        for (index, size) in CLASS_SIZES.iter().enumerate() {
            assert_eq!(class_for_size(*size), Some(index));
        }
        // One byte over a boundary moves to the next class.
        for (index, size) in CLASS_SIZES.iter().enumerate().take(NUM_CLASSES - 1) {
            assert_eq!(class_for_size(size + 1), Some(index + 1));
        }
    }

    #[test]
    fn zero_size_maps_to_smallest_class() {
        // A zero-size request still needs a distinct address, so it
        // is served as the smallest chunk rather than rejected.
        assert_eq!(class_for_size(0), Some(0));
    }

    #[test]
    fn oversized_requests_go_to_secondary() {
        assert_eq!(class_for_size(MAX_PRIMARY_SIZE + 1), None);
        assert_eq!(class_for_size(usize::MAX), None);
    }

    #[test]
    fn every_class_has_a_batch_count() {
        for class in 0..NUM_CLASSES {
            assert!(batch_count(class) > 0);
        }
        assert_eq!(batch_count(NUM_CLASSES), 0);
    }

    #[test]
    fn size_for_class_round_trips() {
        for class in 0..NUM_CLASSES {
            let size = match size_for_class(class) {
                Some(size) => size,
                None => {
                    assert!(false, "class {class} must have a size");
                    return;
                }
            };
            assert_eq!(class_for_size(size), Some(class));
        }
        assert_eq!(size_for_class(NUM_CLASSES), None);
    }
}
