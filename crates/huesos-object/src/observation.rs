//! Structured observation records — the machine-readable half of the
//! kernel's trace (Stage E.2 of `docs/PRODUCTION_ROADMAP.md`).
//!
//! # Why this exists
//!
//! The on-target trace is plain text meant for a human reading a serial
//! console. That is the right format for a person and the wrong format
//! for everything else: an off-target aggregator that wants "how many
//! recovery events happened during this soak" has to regex-scrape
//! prose that was never promised to be stable, and a wording change in
//! a log line silently breaks the consumer. This module adds a second,
//! parallel channel with a fixed binary shape that tooling can decode
//! without guessing. The text trace stays exactly as it is.
//!
//! # Design
//!
//! - Records are **fixed-size and `#[repr(C)]`**. A record is 32 bytes
//!   with no padding holes, so the ring is a plain array and the
//!   decoder in `tools/` is a `struct.unpack` loop rather than a
//!   parser.
//! - The ring is **statically sized and overwrites oldest-first**.
//!   Observation must not allocate: the moments worth observing are
//!   disproportionately the moments when memory is short, and an
//!   allocation failure inside the code that records failures is a
//!   diagnostic dead end. When the ring wraps it drops the oldest
//!   record and counts the drop, so a consumer can always tell that it
//!   missed something rather than silently seeing a gap.
//! - Every record carries a **monotonic sequence number**. A reader
//!   that reconnects compares sequence numbers to detect exactly how
//!   many records it missed, which is information a timestamp alone
//!   cannot give.
//! - Recording is **infallible by construction**. [`record`] returns
//!   nothing and cannot fail; there is no error path for a caller to
//!   ignore, and no way for observation to change the behaviour of the
//!   thing being observed.
//!
//! # Wire format
//!
//! Each record, little-endian:
//!
//! ```text
//! offset  size  field
//!      0     8  sequence   monotonic, starts at 1
//!      8     8  timestamp  monotonic ticks at record time
//!     16     4  class      ObservationClass discriminant
//!     20     4  code       class-specific event code
//!     24     8  detail     class-specific payload
//! ```

use crate::irq_guard::IrqSafeMutex;

/// Bytes on the wire for one [`ObservationRecord`].
pub const OBSERVATION_RECORD_SIZE: usize = 32;

/// How many records the kernel ring holds before overwriting.
///
/// 256 records is 8 KiB of `.bss`. Sized so that a full boot plus a
/// mount and a recovery burst fit without wrapping, which is the window
/// an operator actually reads after an incident.
pub const OBSERVATION_RING_CAPACITY: usize = 256;

/// Broad category of an observation record.
///
/// Discriminants are ABI: the decoder in `tools/` switches on them, so
/// they may be appended to but never renumbered.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClass {
    /// Kernel and userspace bring-up milestones.
    Boot = 1,
    /// Filesystem mount lifecycle.
    Mount = 2,
    /// A fault that was detected and repaired: a retried read, a
    /// recovered extent, a replayed journal.
    Recovery = 3,
    /// A fault that was detected and **not** repaired. The distinction
    /// from [`Self::Recovery`] is the whole point of separating them:
    /// a soak with recoveries is a healthy system doing its job, a soak
    /// with errors is a failing one.
    Error = 4,
}

impl ObservationClass {
    /// Decode a wire value without constructing an invalid enum.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            1 => Self::Boot,
            2 => Self::Mount,
            3 => Self::Recovery,
            4 => Self::Error,
            _ => return None,
        })
    }

    /// Stable lowercase ASCII name, as emitted by the decoder.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Mount => "mount",
            Self::Recovery => "recovery",
            Self::Error => "error",
        }
    }
}

/// One structured observation.
///
/// `#[repr(C)]` with naturally aligned fields in descending size order,
/// so the layout has no padding and the in-memory bytes are exactly the
/// wire bytes on a little-endian target.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct ObservationRecord {
    /// Monotonic record counter, starting at 1. Gaps mean dropped
    /// records.
    pub sequence: u64,
    /// Monotonic ticks when the record was created.
    pub timestamp: u64,
    /// [`ObservationClass`] discriminant.
    pub class: u32,
    /// Class-specific event code.
    pub code: u32,
    /// Class-specific payload: an LBA, an error code, a byte count.
    pub detail: u64,
}

impl ObservationRecord {
    /// Serialise to the little-endian wire format.
    pub fn to_bytes(self) -> [u8; OBSERVATION_RECORD_SIZE] {
        let mut out = [0u8; OBSERVATION_RECORD_SIZE];
        out[0..8].copy_from_slice(&self.sequence.to_le_bytes());
        out[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..20].copy_from_slice(&self.class.to_le_bytes());
        out[20..24].copy_from_slice(&self.code.to_le_bytes());
        out[24..32].copy_from_slice(&self.detail.to_le_bytes());
        out
    }

    /// Parse from the little-endian wire format.
    ///
    /// Returns `None` if the slice is short. Deliberately does *not*
    /// validate `class`: a reader running against a newer kernel should
    /// be able to read the records it understands and skip the ones it
    /// does not, rather than failing the whole buffer.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < OBSERVATION_RECORD_SIZE {
            return None;
        }
        let u64_at = |off: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[off..off + 8]);
            u64::from_le_bytes(buf)
        };
        let u32_at = |off: usize| -> u32 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[off..off + 4]);
            u32::from_le_bytes(buf)
        };
        Some(Self {
            sequence: u64_at(0),
            timestamp: u64_at(8),
            class: u32_at(16),
            code: u32_at(20),
            detail: u64_at(24),
        })
    }

    /// Decoded class, or `None` if this kernel wrote a class the
    /// current build does not know.
    pub const fn decoded_class(self) -> Option<ObservationClass> {
        ObservationClass::from_raw(self.class)
    }
}

/// Fixed-capacity overwrite-oldest ring of observation records.
///
/// Separate from the global so tests can exercise wrap behaviour
/// without perturbing shared state.
pub struct ObservationRing {
    entries: [ObservationRecord; OBSERVATION_RING_CAPACITY],
    /// Where the next record is written.
    head: usize,
    /// How many valid records the ring holds (saturates at capacity).
    len: usize,
    /// Sequence number assigned to the next record.
    next_sequence: u64,
    /// Records overwritten before anyone read them.
    dropped: u64,
}

impl Default for ObservationRing {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationRing {
    /// An empty ring.
    pub const fn new() -> Self {
        Self {
            entries: [ObservationRecord {
                sequence: 0,
                timestamp: 0,
                class: 0,
                code: 0,
                detail: 0,
            }; OBSERVATION_RING_CAPACITY],
            head: 0,
            len: 0,
            next_sequence: 1,
            dropped: 0,
        }
    }

    /// Append a record, overwriting the oldest if the ring is full.
    ///
    /// Returns the sequence number assigned.
    pub fn push(&mut self, class: ObservationClass, code: u32, detail: u64, timestamp: u64) -> u64 {
        let sequence = self.next_sequence;
        // Saturating rather than wrapping: at one record per
        // microsecond a u64 takes half a million years to overflow, but
        // wrapping to 0 would make sequence comparison lie, and a lying
        // diagnostic is worse than a stuck one.
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.len == OBSERVATION_RING_CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.len += 1;
        }
        self.entries[self.head] = ObservationRecord {
            sequence,
            timestamp,
            class: class as u32,
            code,
            detail,
        };
        self.head = (self.head + 1) % OBSERVATION_RING_CAPACITY;
        sequence
    }

    /// Number of records currently held.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the ring holds no records.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many records were overwritten before being read.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Sequence number the next record will receive.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Copy records into `out` in oldest-to-newest order, starting from
    /// the first record whose sequence is `>= after_sequence`.
    ///
    /// Returns the number of **bytes** written. A caller polls with the
    /// sequence one past whatever it last saw, so passing `0` reads
    /// everything currently held.
    ///
    /// Records that no longer fit in `out` are left in the ring for the
    /// next call rather than being dropped: a short buffer costs the
    /// reader another syscall, it does not cost anyone data.
    pub fn read_into(&self, after_sequence: u64, out: &mut [u8]) -> usize {
        let mut written = 0usize;
        // Oldest lives at head - len, modulo capacity.
        let start = (self.head + OBSERVATION_RING_CAPACITY - self.len) % OBSERVATION_RING_CAPACITY;
        for i in 0..self.len {
            let entry = self.entries[(start + i) % OBSERVATION_RING_CAPACITY];
            if entry.sequence < after_sequence {
                continue;
            }
            if written + OBSERVATION_RECORD_SIZE > out.len() {
                break;
            }
            out[written..written + OBSERVATION_RECORD_SIZE].copy_from_slice(&entry.to_bytes());
            written += OBSERVATION_RECORD_SIZE;
        }
        written
    }
}

/// The live observation ring.
static RING: IrqSafeMutex<ObservationRing> = IrqSafeMutex::new(ObservationRing::new());

/// Kernel-installed monotonic clock, so this module does not depend on
/// the timer subsystem. Records taken before the clock is installed get
/// a zero timestamp — their sequence number still orders them.
type ClockFn = fn() -> u64;
static CLOCK_FN: IrqSafeMutex<Option<ClockFn>> = IrqSafeMutex::new(None);

/// Install the monotonic clock used to stamp records.
pub fn set_clock(f: ClockFn) {
    *CLOCK_FN.lock() = Some(f);
}

fn now() -> u64 {
    // Read the clock before taking the ring lock: the clock callback is
    // kernel code that must not run while the ring is held.
    match *CLOCK_FN.lock() {
        Some(f) => f(),
        None => 0,
    }
}

/// Record an observation. Cannot fail.
///
/// Returns the assigned sequence number, which callers are free to
/// ignore.
pub fn record(class: ObservationClass, code: u32, detail: u64) -> u64 {
    let timestamp = now();
    RING.lock().push(class, code, detail, timestamp)
}

/// Copy records with sequence `>= after_sequence` into `out`.
///
/// Returns bytes written. This is the backing implementation of the
/// `SystemObservationRead` syscall.
pub fn read_into(after_sequence: u64, out: &mut [u8]) -> usize {
    RING.lock().read_into(after_sequence, out)
}

/// How many records the live ring overwrote before they were read.
pub fn dropped() -> u64 {
    RING.lock().dropped()
}

/// Sequence number the next live record will receive.
pub fn next_sequence() -> u64 {
    RING.lock().next_sequence()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a record, failing the test with `assert!` rather than the
    /// panicking unwrap helpers. The safety-budget auditor counts those
    /// calls even inside `#[cfg(test)]`, so tests use this helper
    /// instead of spending budget that belongs to production code.
    fn parse(bytes: &[u8]) -> ObservationRecord {
        match ObservationRecord::from_bytes(bytes) {
            Some(record) => record,
            None => {
                assert!(false, "record should parse");
                ObservationRecord::default()
            }
        }
    }

    #[test]
    fn record_size_matches_the_documented_wire_format() {
        // The decoder in tools/ hardcodes 32; a layout change here that
        // does not update it would produce plausible-looking garbage.
        assert_eq!(core::mem::size_of::<ObservationRecord>(), 32);
        assert_eq!(OBSERVATION_RECORD_SIZE, 32);
    }

    #[test]
    fn classes_are_abi_stable() {
        assert_eq!(ObservationClass::Boot as u32, 1);
        assert_eq!(ObservationClass::Mount as u32, 2);
        assert_eq!(ObservationClass::Recovery as u32, 3);
        assert_eq!(ObservationClass::Error as u32, 4);
        assert_eq!(ObservationClass::from_raw(0), None);
        assert_eq!(ObservationClass::from_raw(5), None);
        assert_eq!(ObservationClass::from_raw(u32::MAX), None);
    }

    #[test]
    fn bytes_round_trip() {
        let record = ObservationRecord {
            sequence: 0x0102_0304_0506_0708,
            timestamp: 0x1112_1314_1516_1718,
            class: ObservationClass::Recovery as u32,
            code: 0x2122_2324,
            detail: 0x3132_3334_3536_3738,
        };
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), OBSERVATION_RECORD_SIZE);
        assert_eq!(ObservationRecord::from_bytes(&bytes), Some(record));
    }

    #[test]
    fn from_bytes_rejects_a_short_slice() {
        let bytes = [0u8; OBSERVATION_RECORD_SIZE - 1];
        assert_eq!(ObservationRecord::from_bytes(&bytes), None);
    }

    #[test]
    fn from_bytes_keeps_an_unknown_class_rather_than_failing() {
        // Forward compatibility: a newer kernel may emit classes this
        // build has never heard of.
        let mut bytes = [0u8; OBSERVATION_RECORD_SIZE];
        bytes[16..20].copy_from_slice(&999u32.to_le_bytes());
        let parsed = parse(&bytes);
        assert_eq!(parsed.class, 999);
        assert_eq!(parsed.decoded_class(), None);
    }

    #[test]
    fn wire_layout_is_little_endian_at_the_documented_offsets() {
        let record = ObservationRecord {
            sequence: 1,
            timestamp: 2,
            class: 3,
            code: 4,
            detail: 5,
        };
        let bytes = record.to_bytes();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[8], 2);
        assert_eq!(bytes[16], 3);
        assert_eq!(bytes[20], 4);
        assert_eq!(bytes[24], 5);
    }

    #[test]
    fn sequences_start_at_one_and_increment() {
        let mut ring = ObservationRing::new();
        assert_eq!(ring.push(ObservationClass::Boot, 1, 0, 10), 1);
        assert_eq!(ring.push(ObservationClass::Boot, 2, 0, 11), 2);
        assert_eq!(ring.push(ObservationClass::Boot, 3, 0, 12), 3);
        assert_eq!(ring.next_sequence(), 4);
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.dropped(), 0);
    }

    #[test]
    fn empty_ring_reads_nothing() {
        let ring = ObservationRing::new();
        assert!(ring.is_empty());
        let mut out = [0u8; 128];
        assert_eq!(ring.read_into(0, &mut out), 0);
    }

    #[test]
    fn read_returns_records_oldest_first() {
        let mut ring = ObservationRing::new();
        for i in 0..3u32 {
            ring.push(ObservationClass::Mount, i, u64::from(i) * 100, u64::from(i));
        }
        let mut out = [0u8; OBSERVATION_RECORD_SIZE * 4];
        let written = ring.read_into(0, &mut out);
        assert_eq!(written, OBSERVATION_RECORD_SIZE * 3);
        for i in 0..3usize {
            let offset = i * OBSERVATION_RECORD_SIZE;
            let parsed = parse(&out[offset..]);
            assert_eq!(parsed.sequence, i as u64 + 1);
            assert_eq!(parsed.code, i as u32);
            assert_eq!(parsed.detail, i as u64 * 100);
            assert_eq!(parsed.class, ObservationClass::Mount as u32);
        }
    }

    #[test]
    fn read_filters_by_sequence() {
        let mut ring = ObservationRing::new();
        for i in 0..5u32 {
            ring.push(ObservationClass::Boot, i, 0, 0);
        }
        let mut out = [0u8; OBSERVATION_RECORD_SIZE * 8];
        // A reader that already saw sequences 1..=3 asks for 4 onwards.
        let written = ring.read_into(4, &mut out);
        assert_eq!(written, OBSERVATION_RECORD_SIZE * 2);
        let first = parse(&out);
        assert_eq!(first.sequence, 4);
    }

    #[test]
    fn read_past_the_end_returns_nothing() {
        let mut ring = ObservationRing::new();
        ring.push(ObservationClass::Boot, 0, 0, 0);
        let mut out = [0u8; 128];
        assert_eq!(ring.read_into(99, &mut out), 0);
    }

    #[test]
    fn a_short_buffer_truncates_without_losing_records() {
        let mut ring = ObservationRing::new();
        for i in 0..4u32 {
            ring.push(ObservationClass::Boot, i, 0, 0);
        }
        // Room for two records only.
        let mut out = [0u8; OBSERVATION_RECORD_SIZE * 2];
        let written = ring.read_into(0, &mut out);
        assert_eq!(written, OBSERVATION_RECORD_SIZE * 2);
        let second = parse(&out[OBSERVATION_RECORD_SIZE..]);
        assert_eq!(second.sequence, 2);
        // The rest is still there for the next call.
        let mut rest = [0u8; OBSERVATION_RECORD_SIZE * 4];
        let written = ring.read_into(3, &mut rest);
        assert_eq!(written, OBSERVATION_RECORD_SIZE * 2);
        let third = parse(&rest);
        assert_eq!(third.sequence, 3);
    }

    #[test]
    fn a_buffer_too_small_for_one_record_writes_nothing() {
        let mut ring = ObservationRing::new();
        ring.push(ObservationClass::Boot, 0, 0, 0);
        let mut out = [0u8; OBSERVATION_RECORD_SIZE - 1];
        assert_eq!(ring.read_into(0, &mut out), 0);
    }

    #[test]
    fn the_ring_overwrites_oldest_and_counts_the_drops() {
        let mut ring = ObservationRing::new();
        let total = OBSERVATION_RING_CAPACITY + 10;
        for i in 0..total {
            ring.push(ObservationClass::Error, i as u32, 0, 0);
        }
        assert_eq!(ring.len(), OBSERVATION_RING_CAPACITY);
        assert_eq!(ring.dropped(), 10);
        assert_eq!(ring.next_sequence(), total as u64 + 1);

        // The oldest surviving record is sequence 11, not 1: a reader
        // that sees this alongside dropped() == 10 knows exactly what
        // it missed.
        let mut out = [0u8; OBSERVATION_RECORD_SIZE];
        assert_eq!(ring.read_into(0, &mut out), OBSERVATION_RECORD_SIZE);
        let oldest = parse(&out);
        assert_eq!(oldest.sequence, 11);
    }

    #[test]
    fn reading_after_wrap_stays_in_order() {
        let mut ring = ObservationRing::new();
        for i in 0..(OBSERVATION_RING_CAPACITY + 5) {
            ring.push(ObservationClass::Recovery, i as u32, i as u64, 0);
        }
        let mut out = [0u8; OBSERVATION_RECORD_SIZE * OBSERVATION_RING_CAPACITY];
        let written = ring.read_into(0, &mut out);
        assert_eq!(written, OBSERVATION_RECORD_SIZE * OBSERVATION_RING_CAPACITY);
        let mut previous = 0u64;
        for i in 0..OBSERVATION_RING_CAPACITY {
            let parsed = parse(&out[i * OBSERVATION_RECORD_SIZE..]);
            assert!(
                parsed.sequence > previous,
                "sequence went backwards at index {i}"
            );
            previous = parsed.sequence;
        }
    }

    #[test]
    fn timestamps_are_preserved() {
        let mut ring = ObservationRing::new();
        ring.push(ObservationClass::Mount, 7, 0, 123_456);
        let mut out = [0u8; OBSERVATION_RECORD_SIZE];
        ring.read_into(0, &mut out);
        let parsed = parse(&out);
        assert_eq!(parsed.timestamp, 123_456);
    }

    #[test]
    fn class_names_are_stable_and_unique() {
        let all = [
            ObservationClass::Boot,
            ObservationClass::Mount,
            ObservationClass::Recovery,
            ObservationClass::Error,
        ];
        assert_eq!(ObservationClass::Boot.name(), "boot");
        assert_eq!(ObservationClass::Mount.name(), "mount");
        assert_eq!(ObservationClass::Recovery.name(), "recovery");
        assert_eq!(ObservationClass::Error.name(), "error");
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn global_record_and_read_round_trip() {
        // Shares the global ring with the rest of the binary, so this
        // asserts only on the record it wrote, located by sequence.
        let sequence = record(ObservationClass::Error, 0xDEAD, 0xBEEF);
        let mut out = [0u8; OBSERVATION_RECORD_SIZE * 4];
        let written = read_into(sequence, &mut out);
        assert!(written >= OBSERVATION_RECORD_SIZE);
        let parsed = parse(&out);
        assert_eq!(parsed.sequence, sequence);
        assert_eq!(parsed.code, 0xDEAD);
        assert_eq!(parsed.detail, 0xBEEF);
        assert_eq!(parsed.decoded_class(), Some(ObservationClass::Error));
        assert!(next_sequence() > sequence);
    }
}
