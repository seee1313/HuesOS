//! Runtime knobs — the `sysctl`-style tunables an operator can change
//! on a live system (Stage E.1 of `docs/PRODUCTION_ROADMAP.md`).
//!
//! # Why this exists
//!
//! Before this module every operational parameter in the storage stack
//! was a `const`. Changing the scrub interval or turning up recovery
//! logging to diagnose a failing drive meant editing source, rebuilding
//! the kernel, and rebooting the machine you were trying to observe —
//! which is exactly when a reboot destroys the evidence. An operator
//! needs to turn a knob on the running system and watch the trace
//! change.
//!
//! # Design
//!
//! - The knob set is **fixed and closed**. Knobs are named by a
//!   [`KnobId`] enum, not by string, so there is no registry to walk,
//!   no allocation, and no way for a caller to invent a knob name.
//!   Adding a knob is a deliberate ABI change with a value-stability
//!   test, the same discipline the syscall table gets.
//! - Every knob is a `u64` and every knob **clamps rather than
//!   rejects**. A knob is an operational lever, often turned under
//!   pressure through a shell one-liner; failing the write because the
//!   value was one over the maximum would be a worse outcome than
//!   applying the maximum and reporting what was applied. The write
//!   returns the value that actually took effect, so a caller that
//!   cares can compare.
//! - The state is read-mostly: reads take the lock, copy one `u64`, and
//!   release it. Reads happen on hot paths (the recovery retry loop
//!   consults its knob per attempt), writes happen when a human types a
//!   command.
//! - The lock is [`IrqSafeMutex`], per the crate-wide policy enforced by
//!   `tools/check-huesos-object-lock-policy.py`: knob reads are
//!   reachable from IRQ-adjacent code, so a bare `spin::Mutex` here
//!   would be a self-deadlock waiting for a scheduling accident.
//!
//! # What is deliberately *not* here
//!
//! There is no authority check in this module. Capability enforcement
//! belongs at the syscall boundary (`huesos-syscalls`), which is the
//! only layer that knows who the caller is. A kernel subsystem calling
//! [`get`] directly is already inside the trust boundary.

use crate::irq_guard::IrqSafeMutex;

/// Number of distinct runtime knobs. Used to size the backing array
/// and to bound the wire-format decode.
pub const KNOB_COUNT: usize = 4;

/// Identifies one runtime knob.
///
/// Discriminants are ABI: they cross the syscall boundary as raw `u32`
/// values, so they may be appended to but never renumbered. See the
/// `knob_ids_are_abi_stable` test.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnobId {
    /// How often the background scrubber walks the filesystem, in
    /// seconds. `0` disables scrubbing entirely — a legitimate setting
    /// while diagnosing a drive whose media errors are being logged,
    /// where a scrub pass would add noise and I/O load.
    ScrubIntervalSecs = 0,
    /// How many times a recoverable read is retried before the extent
    /// is marked bad. Clamped to at least 1: a zero here would mean
    /// "never even try", which silently converts every transient error
    /// into permanent data loss.
    RecoveryRetryCount = 1,
    /// Log verbosity, 0 (quiet) to 4 (trace). Higher values are only
    /// useful while actively diagnosing: at 4 the trace includes
    /// per-extent decisions, which is far too much output to leave on.
    LogVerbosity = 2,
    /// Upper bound on NVMe queue depth actually used, regardless of
    /// what the controller advertises. Clamped to at least 1. Exists
    /// because a controller that misbehaves at high depth is a real
    /// failure mode, and the operator response is to cap the depth
    /// without rebuilding.
    NvmeMaxQueueDepth = 3,
}

impl KnobId {
    /// Decode a wire value without constructing an invalid enum.
    ///
    /// Returns `None` for any unrecognised id, including ids from a
    /// future ABI version this kernel predates. A caller that receives
    /// `None` learns "this kernel does not have that knob", which is a
    /// recoverable answer.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            0 => Self::ScrubIntervalSecs,
            1 => Self::RecoveryRetryCount,
            2 => Self::LogVerbosity,
            3 => Self::NvmeMaxQueueDepth,
            _ => return None,
        })
    }

    /// Index into the backing array.
    const fn index(self) -> usize {
        self as u32 as usize
    }

    /// Value this knob holds on a freshly booted system.
    ///
    /// These match the constants the code used before knobs existed, so
    /// enabling this module changes no behaviour until someone turns a
    /// knob.
    pub const fn default_value(self) -> u64 {
        match self {
            // Once an hour: frequent enough to find bit rot long before
            // a second fault makes it unrecoverable, rare enough not to
            // compete with the workload.
            Self::ScrubIntervalSecs => 3600,
            Self::RecoveryRetryCount => 3,
            // 1 = errors and lifecycle events, the level a healthy
            // production system should run at.
            Self::LogVerbosity => 1,
            Self::NvmeMaxQueueDepth => 256,
        }
    }

    /// Inclusive range this knob accepts. Writes are clamped into it.
    pub const fn bounds(self) -> (u64, u64) {
        match self {
            // 0 is meaningful (scrubbing off); a week is the longest
            // interval that still counts as scrubbing at all.
            Self::ScrubIntervalSecs => (0, 604_800),
            // At least one attempt, and a ceiling low enough that a
            // pathological retry storm cannot stall the I/O path for
            // minutes.
            Self::RecoveryRetryCount => (1, 16),
            Self::LogVerbosity => (0, 4),
            // The NVMe spec caps a submission queue at 65536 entries.
            Self::NvmeMaxQueueDepth => (1, 65_536),
        }
    }

    /// Stable ASCII name, for the trace and for operator tooling.
    ///
    /// Names are part of the operator-visible surface: `tools/` parses
    /// them out of the trace, so they change only alongside a tooling
    /// change.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ScrubIntervalSecs => "scrub.interval_secs",
            Self::RecoveryRetryCount => "recovery.retry_count",
            Self::LogVerbosity => "log.verbosity",
            Self::NvmeMaxQueueDepth => "nvme.max_queue_depth",
        }
    }

    /// Every knob, in id order. Lets callers enumerate the set without
    /// hardcoding the count.
    pub const fn all() -> [Self; KNOB_COUNT] {
        [
            Self::ScrubIntervalSecs,
            Self::RecoveryRetryCount,
            Self::LogVerbosity,
            Self::NvmeMaxQueueDepth,
        ]
    }
}

/// The knob values themselves.
///
/// Split out from the global so it is constructible in a test without
/// touching global state — a test that mutated the global would make
/// every other test in the binary order-dependent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeKnobs {
    values: [u64; KNOB_COUNT],
}

impl Default for RuntimeKnobs {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeKnobs {
    /// A knob set holding every default.
    pub const fn new() -> Self {
        let mut values = [0u64; KNOB_COUNT];
        // Written out rather than looped because `for` is not allowed
        // in a `const fn` on this toolchain.
        values[KnobId::ScrubIntervalSecs.index()] = KnobId::ScrubIntervalSecs.default_value();
        values[KnobId::RecoveryRetryCount.index()] = KnobId::RecoveryRetryCount.default_value();
        values[KnobId::LogVerbosity.index()] = KnobId::LogVerbosity.default_value();
        values[KnobId::NvmeMaxQueueDepth.index()] = KnobId::NvmeMaxQueueDepth.default_value();
        Self { values }
    }

    /// Read one knob.
    pub const fn get(&self, id: KnobId) -> u64 {
        self.values[id.index()]
    }

    /// Write one knob, clamping into [`KnobId::bounds`].
    ///
    /// Returns the value that actually took effect, which differs from
    /// the requested value exactly when clamping occurred.
    pub fn set(&mut self, id: KnobId, value: u64) -> u64 {
        let (min, max) = id.bounds();
        let clamped = if value < min {
            min
        } else if value > max {
            max
        } else {
            value
        };
        self.values[id.index()] = clamped;
        clamped
    }

    /// Restore every knob to its default. Used by tests, and by the
    /// operator escape hatch for "I have turned too many things".
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// The live knob set. Read on hot paths, written by operator action.
static KNOBS: IrqSafeMutex<RuntimeKnobs> = IrqSafeMutex::new(RuntimeKnobs::new());

/// Read a knob from the live set.
pub fn get(id: KnobId) -> u64 {
    KNOBS.lock().get(id)
}

/// Write a knob in the live set, returning the clamped value applied.
///
/// The caller is responsible for having checked authority; see the
/// module docs.
pub fn set(id: KnobId, value: u64) -> u64 {
    KNOBS.lock().set(id, value)
}

/// Snapshot every knob at once.
///
/// Takes the lock once rather than once per knob, so the result is a
/// coherent view rather than a smear across concurrent writes.
pub fn snapshot() -> RuntimeKnobs {
    *KNOBS.lock()
}

/// Restore every knob to its default value.
pub fn reset() {
    KNOBS.lock().reset();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_within_their_own_bounds() {
        // A default outside its bounds would mean the first write of
        // any value silently moved the knob, which would be baffling
        // to debug.
        for id in KnobId::all() {
            let (min, max) = id.bounds();
            let default = id.default_value();
            assert!(
                default >= min && default <= max,
                "{} default {} outside bounds {}..={}",
                id.name(),
                default,
                min,
                max
            );
        }
    }

    #[test]
    fn knob_ids_are_abi_stable() {
        // These numbers cross the syscall boundary. Renumbering them
        // silently repoints an operator's command at a different knob.
        assert_eq!(KnobId::ScrubIntervalSecs as u32, 0);
        assert_eq!(KnobId::RecoveryRetryCount as u32, 1);
        assert_eq!(KnobId::LogVerbosity as u32, 2);
        assert_eq!(KnobId::NvmeMaxQueueDepth as u32, 3);
        assert_eq!(KNOB_COUNT, KnobId::all().len());
    }

    #[test]
    fn from_raw_rejects_unknown_ids() {
        for (raw, expected) in [
            (0u32, Some(KnobId::ScrubIntervalSecs)),
            (1, Some(KnobId::RecoveryRetryCount)),
            (2, Some(KnobId::LogVerbosity)),
            (3, Some(KnobId::NvmeMaxQueueDepth)),
            (4, None),
            (u32::MAX, None),
        ] {
            assert_eq!(KnobId::from_raw(raw), expected, "raw {raw}");
        }
    }

    #[test]
    fn every_id_round_trips_through_its_index() {
        for id in KnobId::all() {
            assert_eq!(KnobId::from_raw(id as u32), Some(id));
            assert!(id.index() < KNOB_COUNT);
        }
    }

    #[test]
    fn names_are_unique() {
        // Tooling greps the trace by name; two knobs sharing a name
        // would make one of them unaddressable.
        let all = KnobId::all();
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn new_holds_every_default() {
        let knobs = RuntimeKnobs::new();
        for id in KnobId::all() {
            assert_eq!(knobs.get(id), id.default_value(), "{}", id.name());
        }
    }

    #[test]
    fn set_clamps_below_minimum() {
        let mut knobs = RuntimeKnobs::new();
        // Zero retries would turn every transient error into data loss.
        let applied = knobs.set(KnobId::RecoveryRetryCount, 0);
        assert_eq!(applied, 1);
        assert_eq!(knobs.get(KnobId::RecoveryRetryCount), 1);
    }

    #[test]
    fn set_clamps_above_maximum() {
        let mut knobs = RuntimeKnobs::new();
        let applied = knobs.set(KnobId::LogVerbosity, u64::MAX);
        assert_eq!(applied, 4);
        assert_eq!(knobs.get(KnobId::LogVerbosity), 4);
    }

    #[test]
    fn set_accepts_exact_bounds() {
        let mut knobs = RuntimeKnobs::new();
        for id in KnobId::all() {
            let (min, max) = id.bounds();
            assert_eq!(knobs.set(id, min), min, "{} min", id.name());
            assert_eq!(knobs.get(id), min);
            assert_eq!(knobs.set(id, max), max, "{} max", id.name());
            assert_eq!(knobs.get(id), max);
        }
    }

    #[test]
    fn zero_is_accepted_where_it_is_meaningful() {
        // Scrubbing off is a real operator choice, not an error.
        let mut knobs = RuntimeKnobs::new();
        assert_eq!(knobs.set(KnobId::ScrubIntervalSecs, 0), 0);
        assert_eq!(knobs.get(KnobId::ScrubIntervalSecs), 0);
    }

    #[test]
    fn writing_one_knob_leaves_the_others_alone() {
        let mut knobs = RuntimeKnobs::new();
        knobs.set(KnobId::LogVerbosity, 4);
        assert_eq!(knobs.get(KnobId::LogVerbosity), 4);
        assert_eq!(
            knobs.get(KnobId::ScrubIntervalSecs),
            KnobId::ScrubIntervalSecs.default_value()
        );
        assert_eq!(
            knobs.get(KnobId::RecoveryRetryCount),
            KnobId::RecoveryRetryCount.default_value()
        );
        assert_eq!(
            knobs.get(KnobId::NvmeMaxQueueDepth),
            KnobId::NvmeMaxQueueDepth.default_value()
        );
    }

    #[test]
    fn reset_restores_every_default() {
        let mut knobs = RuntimeKnobs::new();
        for id in KnobId::all() {
            knobs.set(id, id.bounds().1);
        }
        knobs.reset();
        assert_eq!(knobs, RuntimeKnobs::new());
    }

    #[test]
    fn global_accessors_round_trip() {
        // The global is shared with every other test in this binary,
        // so this test restores it before returning.
        let before = snapshot();
        let applied = set(KnobId::LogVerbosity, 3);
        assert_eq!(applied, 3);
        assert_eq!(get(KnobId::LogVerbosity), 3);
        reset();
        assert_eq!(
            get(KnobId::LogVerbosity),
            KnobId::LogVerbosity.default_value()
        );
        // Put back whatever the rest of the binary expected to find.
        for id in KnobId::all() {
            set(id, before.get(id));
        }
    }
}
