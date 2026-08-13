//! Delayed reuse quarantine (Scudo `Quarantine`).
//!
//! A freed chunk is not returned to its free list immediately.
//! It is marked `Quarantined` and parked here first; only when the
//! quarantine exceeds its budget is the oldest entry evicted and
//! actually recycled.
//!
//! Two properties come out of that delay:
//!
//! - **Use-after-free is much more likely to be caught.** A dangling
//!   pointer written through while the chunk sits in quarantine hits
//!   a chunk whose header still says `Quarantined`; the next real
//!   free or allocation of that chunk detects it.
//! - **Double free is caught deterministically.** The second free
//!   reads a `Quarantined` header instead of an `Allocated` one and
//!   is rejected before any list is touched.
//!
//! The quarantine is a fixed-capacity FIFO — no allocation, bounded
//! memory, and eviction order that is independent of the sizes
//! involved.

/// One quarantined chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedChunk {
    /// Window offset of the chunk's header start.
    pub offset: usize,
    /// Size class, or `None` for a secondary block.
    pub class: Option<u8>,
    /// The original request size (needed to release a secondary block).
    pub request_size: usize,
}

/// How many chunks can be held at once.
pub const CAPACITY: usize = 64;

/// Total bytes the quarantine will hold before evicting.
pub const MAX_BYTES: usize = 256 * 1024;

/// A bounded FIFO of freed-but-not-yet-recycled chunks.
pub struct Quarantine {
    entries: [Option<QuarantinedChunk>; CAPACITY],
    head: usize,
    len: usize,
    bytes: usize,
}

impl Quarantine {
    /// An empty quarantine.
    pub const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            head: 0,
            len: 0,
            bytes: 0,
        }
    }

    /// Number of chunks currently held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the quarantine holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total bytes currently held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether `offset` is currently quarantined.
    ///
    /// Used by the integrity checks to distinguish a double free
    /// from an unrelated bad pointer.
    pub fn contains(&self, offset: usize) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.offset == offset)
    }

    /// Park `chunk`, evicting and returning the oldest entry when
    /// either budget is exceeded.
    ///
    /// Returns `Some(chunk)` when the caller must now actually
    /// recycle that chunk.
    pub fn push(&mut self, chunk: QuarantinedChunk) -> Option<QuarantinedChunk> {
        let evicted = if self.len == CAPACITY || self.bytes + chunk.request_size > MAX_BYTES {
            self.pop_oldest()
        } else {
            None
        };

        let slot = (self.head + self.len) % CAPACITY;
        self.entries[slot] = Some(chunk);
        self.len += 1;
        self.bytes += chunk.request_size;
        evicted
    }

    /// Remove and return the oldest entry.
    pub fn pop_oldest(&mut self) -> Option<QuarantinedChunk> {
        if self.len == 0 {
            return None;
        }
        let entry = self.entries[self.head].take();
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        if let Some(chunk) = entry {
            self.bytes = self.bytes.saturating_sub(chunk.request_size);
        }
        entry
    }

    /// Drain every entry, for a shutdown or a forced flush.
    pub fn drain_next(&mut self) -> Option<QuarantinedChunk> {
        self.pop_oldest()
    }
}

impl Default for Quarantine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(offset: usize, size: usize) -> QuarantinedChunk {
        QuarantinedChunk {
            offset,
            class: Some(0),
            request_size: size,
        }
    }

    #[test]
    fn new_quarantine_is_empty() {
        let quarantine = Quarantine::new();
        assert!(quarantine.is_empty());
        assert_eq!(quarantine.len(), 0);
        assert_eq!(quarantine.bytes(), 0);
    }

    #[test]
    fn small_pushes_are_held_not_recycled() {
        let mut quarantine = Quarantine::new();
        for index in 0..10 {
            assert_eq!(
                quarantine.push(chunk(index * 64, 16)),
                None,
                "a small push must not evict"
            );
        }
        assert_eq!(quarantine.len(), 10);
    }

    #[test]
    fn eviction_is_fifo() {
        let mut quarantine = Quarantine::new();
        for index in 0..CAPACITY {
            assert_eq!(quarantine.push(chunk(index * 64, 16)), None);
        }
        // The next push must evict the very first chunk.
        let evicted = quarantine.push(chunk(9999, 16));
        assert_eq!(evicted, Some(chunk(0, 16)));
        // ...and then the second.
        let evicted = quarantine.push(chunk(10_000, 16));
        assert_eq!(evicted, Some(chunk(64, 16)));
    }

    #[test]
    fn byte_budget_forces_eviction() {
        let mut quarantine = Quarantine::new();
        let big = MAX_BYTES / 4;
        assert_eq!(quarantine.push(chunk(0, big)), None);
        assert_eq!(quarantine.push(chunk(1000, big)), None);
        assert_eq!(quarantine.push(chunk(2000, big)), None);
        assert_eq!(quarantine.push(chunk(3000, big)), None);
        // Fifth quarter exceeds the budget and evicts the oldest.
        assert_eq!(quarantine.push(chunk(4000, big)), Some(chunk(0, big)));
    }

    #[test]
    fn contains_finds_quarantined_offsets() {
        let mut quarantine = Quarantine::new();
        assert!(!quarantine.contains(128));
        quarantine.push(chunk(128, 32));
        assert!(quarantine.contains(128));
        assert!(!quarantine.contains(256));
    }

    #[test]
    fn bytes_accounting_returns_to_zero() {
        let mut quarantine = Quarantine::new();
        for index in 0..10 {
            quarantine.push(chunk(index * 64, 100));
        }
        assert_eq!(quarantine.bytes(), 1000);
        while quarantine.drain_next().is_some() {}
        assert_eq!(quarantine.bytes(), 0);
        assert!(quarantine.is_empty());
    }

    #[test]
    fn wraparound_preserves_order() {
        let mut quarantine = Quarantine::new();
        // Fill, then churn well past capacity so head wraps.
        for index in 0..CAPACITY {
            quarantine.push(chunk(index, 16));
        }
        for index in CAPACITY..(CAPACITY * 3) {
            let evicted = quarantine.push(chunk(index, 16));
            assert_eq!(
                evicted,
                Some(chunk(index - CAPACITY, 16)),
                "eviction must stay FIFO across wraparound"
            );
        }
    }
}
