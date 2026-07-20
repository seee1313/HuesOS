//! Deny-by-default policy primitives for the Ring-3 ACPI broker.
//!
//! These are pure, `no_std`, host-testable building blocks the broker uses
//! to (a) keep an append-only audit trail of every decision it renders and
//! (b) bound the rate at which a single capability may be exercised. They
//! carry no I/O, no allocation, and no `unsafe`, so they are exercised
//! directly by `cargo test` without firmware or a live kernel present.

/// Outcome recorded for an audited broker decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuditOutcome {
    /// The request was authorized by policy.
    Allowed = 0,
    /// The request was denied by policy (deny-by-default).
    Denied = 1,
    /// The request could not be evaluated (malformed / internal error).
    Error = 2,
}

/// A single audited broker decision.
///
/// `#[repr(C)]` and plain-old-data so the kernel can copy it verbatim into an
/// in-memory ring the userspace supervisor later drains for forensics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AuditEntry {
    /// Monotonically increasing sequence assigned at record time.
    pub sequence: u64,
    /// Raw opcode of the request that was decided (`acpi_broker::Opcode`).
    pub opcode: u8,
    /// Whether the request was allowed, denied, or errored.
    pub outcome: AuditOutcome,
    /// Opaque argument captured for the record (e.g. base address or value).
    pub argument: u64,
}

impl AuditEntry {
    /// Construct an audit entry with an explicit sequence number.
    pub const fn new(sequence: u64, opcode: u8, outcome: AuditOutcome, argument: u64) -> Self {
        Self {
            sequence,
            opcode,
            outcome,
            argument,
        }
    }
}

/// A fixed-capacity, append-only audit ring.
///
/// Once full, the oldest entry is overwritten, giving bounded memory with no
/// allocation and no `unsafe`. `len()` never exceeds the capacity `N`.
#[derive(Clone, Copy, Debug)]
pub struct AuditLog<const N: usize> {
    slots: [Option<AuditEntry>; N],
    /// Index of the next write slot (the head of the ring).
    head: usize,
    /// Number of valid entries currently held (`<= N`).
    len: usize,
    /// Monotonic sequence counter for newly recorded entries.
    sequence: u64,
}

impl<const N: usize> AuditLog<N> {
    /// Create an empty audit log. Requires `N > 0`; a zero-capacity log is
    /// useless and rejected at the type level by the caller's choice of `N`.
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            head: 0,
            len: 0,
            sequence: 0,
        }
    }

    /// Maximum number of entries the log can retain.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of valid entries currently retained (`<= capacity()`).
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the log currently holds no entries.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Record a decision and return the stored entry by value.
    ///
    /// Assigns the next monotonic sequence number, overwriting the oldest
    /// slot once the ring is full.
    pub fn record(&mut self, opcode: u8, outcome: AuditOutcome, argument: u64) -> AuditEntry {
        let entry = AuditEntry::new(self.sequence, opcode, outcome, argument);
        self.sequence = self.sequence.wrapping_add(1);
        self.slots[self.head] = Some(entry);
        self.head = (self.head + 1) % N;
        if self.len < N {
            self.len += 1;
        }
        entry
    }

    /// Iterate the retained entries in chronological (insertion) order.
    pub fn iter(&self) -> AuditIter<'_, N> {
        AuditIter {
            log: self,
            pos: 0,
        }
    }
}

impl<const N: usize> Default for AuditLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Chronological iterator over the entries of an [`AuditLog`].
pub struct AuditIter<'a, const N: usize> {
    log: &'a AuditLog<N>,
    pos: usize,
}

impl<'a, const N: usize> Iterator for AuditIter<'a, N> {
    type Item = &'a AuditEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.log.len {
            return None;
        }
        // Map the chronological position to a ring slot. While the log has
        // not yet wrapped, entries sit in slots [0, len); afterwards they
        // start at `head` and wrap around.
        let slot = if self.log.len < N {
            self.pos
        } else {
            (self.log.head + self.pos) % N
        };
        self.pos += 1;
        self.log.slots[slot].as_ref()
    }
}

/// Fixed-window rate limiter for a single broker capability.
///
/// Permits up to `max_events` acquisitions within any window of
/// `window_ticks` monotonic clock ticks. Callers feed the current tick via
/// `try_acquire(now)`; the limiter rolls to a fresh window automatically.
#[derive(Clone, Copy, Debug)]
pub struct RateLimiter {
    window_ticks: u64,
    max_events: u32,
    window_start: u64,
    count: u32,
}

impl RateLimiter {
    /// Create a limiter allowing `max_events` per `window_ticks`-long window.
    pub const fn new(window_ticks: u64, max_events: u32) -> Self {
        Self {
            window_ticks,
            max_events,
            window_start: 0,
            count: 0,
        }
    }

    /// Attempt to consume one event slot at tick `now`.
    ///
    /// Returns `true` if the event is permitted (and the slot is consumed),
    /// or `false` if the current window is already exhausted. Rolls to a new
    /// window automatically when `now` advances past the window boundary.
    pub fn try_acquire(&mut self, now: u64) -> bool {
        let window_end = self.window_start.saturating_add(self.window_ticks);
        if now >= window_end {
            self.window_start = now;
            self.count = 0;
        }
        if self.count < self.max_events {
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Remaining events permitted in the current window.
    pub const fn available(&self) -> u32 {
        self.max_events.saturating_sub(self.count)
    }

    /// Reset the limiter to a fresh, empty window.
    pub fn reset(&mut self) {
        self.window_start = 0;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_records_in_chronological_order() {
        let mut log = AuditLog::<4>::new();
        assert!(log.is_empty());
        assert_eq!(log.capacity(), 4);

        let e0 = log.record(1, AuditOutcome::Allowed, 0x10);
        assert_eq!(e0.sequence, 0);
        assert_eq!(e0.opcode, 1);
        assert_eq!(log.len(), 1);

        log.record(2, AuditOutcome::Denied, 0x20);
        log.record(3, AuditOutcome::Allowed, 0x30);
        log.record(4, AuditOutcome::Error, 0x40);
        assert_eq!(log.len(), 4);

        // Wrapping the ring keeps len at capacity and drops the oldest entry.
        let e4 = log.record(5, AuditOutcome::Denied, 0x50);
        assert_eq!(e4.sequence, 4);
        assert_eq!(log.len(), 4);
        assert_eq!(log.capacity(), 4);

        // Chronological order is sequence 1,2,3,4 (seq 0 was evicted).
        let mut seqs = [0u64; 4];
        let mut opcodes = [0u8; 4];
        let mut i = 0;
        for entry in log.iter() {
            seqs[i] = entry.sequence;
            opcodes[i] = entry.opcode;
            i += 1;
        }
        assert_eq!(seqs, [1, 2, 3, 4]);
        assert_eq!(opcodes, [2, 3, 4, 5]);
    }

    #[test]
    fn audit_log_sequence_is_monotonic() {
        let mut log = AuditLog::<2>::new();
        let a = log.record(7, AuditOutcome::Allowed, 1);
        let b = log.record(7, AuditOutcome::Allowed, 2);
        let c = log.record(7, AuditOutcome::Allowed, 3);
        assert_eq!(a.sequence, 0);
        assert_eq!(b.sequence, 1);
        assert_eq!(c.sequence, 2);
    }

    #[test]
    fn rate_limiter_allows_up_to_max_then_denies() {
        let mut limiter = RateLimiter::new(100, 3);
        assert!(limiter.try_acquire(0));
        assert!(limiter.try_acquire(10));
        assert!(limiter.try_acquire(20));
        // Window of 100 ticks has not elapsed; the 4th event is denied.
        assert!(!limiter.try_acquire(30));
        assert_eq!(limiter.available(), 0);
    }

    #[test]
    fn rate_limiter_rolls_to_new_window() {
        let mut limiter = RateLimiter::new(100, 2);
        assert!(limiter.try_acquire(0));
        assert!(limiter.try_acquire(50));
        assert!(!limiter.try_acquire(99));
        // Past the window boundary: a fresh window opens.
        assert!(limiter.try_acquire(100));
        assert!(limiter.try_acquire(150));
        assert!(!limiter.try_acquire(199));
        assert_eq!(limiter.available(), 0);
    }

    #[test]
    fn rate_limiter_reset_clears_window() {
        let mut limiter = RateLimiter::new(100, 1);
        assert!(limiter.try_acquire(0));
        assert!(!limiter.try_acquire(10));
        limiter.reset();
        assert!(limiter.try_acquire(10));
        assert_eq!(limiter.available(), 0);
    }
}
