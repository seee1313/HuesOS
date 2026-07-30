//! Storage observability, counters, and fault-injection policy core.
//!
//! Stage Y keeps instrumentation decisions deterministic and no-heap. Runtime
//! services can copy these counters into serial/debug output without allocating.

/// Storage subsystem marker id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StorageMarker {
    /// NVMe DriverHost accepted boot resources.
    NvmeResources = 1,
    /// BlockDevice service became ready.
    BlockReady = 2,
    /// Hxfs service started mount.
    HxfsMountStart = 3,
    /// Hxfs journal replay started.
    HxfsReplayStart = 4,
    /// Hxfs journal replay completed.
    HxfsReplayDone = 5,
    /// Hxfs checkpoint was published.
    HxfsCheckpoint = 6,
    /// Hxblob index lookup/read was performed.
    HxblobRead = 7,
}

/// Hxfs service counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HxfsCounters {
    /// File/data reads.
    pub reads: u64,
    /// File/data writes.
    pub writes: u64,
    /// Checkpoint publications.
    pub checkpoints: u64,
    /// Journal replay attempts.
    pub journal_replays: u64,
    /// Cache hits.
    pub cache_hits: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Allocation failures.
    pub enospc: u64,
    /// Quota denials.
    pub quota_denied: u64,
    /// Hxblob lookups.
    pub hxblob_lookups: u64,
    /// Faults injected by test policy.
    pub injected_faults: u64,
}

impl HxfsCounters {
    /// Record a read.
    pub fn record_read(&mut self) {
        self.reads = self.reads.saturating_add(1);
    }

    /// Record a write.
    pub fn record_write(&mut self) {
        self.writes = self.writes.saturating_add(1);
    }

    /// Record a checkpoint.
    pub fn record_checkpoint(&mut self) {
        self.checkpoints = self.checkpoints.saturating_add(1);
    }

    /// Record a journal replay attempt.
    pub fn record_replay(&mut self) {
        self.journal_replays = self.journal_replays.saturating_add(1);
    }

    /// Record cache hit/miss.
    pub fn record_cache(&mut self, hit: bool) {
        if hit {
            self.cache_hits = self.cache_hits.saturating_add(1);
        } else {
            self.cache_misses = self.cache_misses.saturating_add(1);
        }
    }

    /// Record an allocation failure.
    pub fn record_enospc(&mut self) {
        self.enospc = self.enospc.saturating_add(1);
    }

    /// Record quota denial.
    pub fn record_quota_denied(&mut self) {
        self.quota_denied = self.quota_denied.saturating_add(1);
    }

    /// Record an Hxblob lookup.
    pub fn record_hxblob_lookup(&mut self) {
        self.hxblob_lookups = self.hxblob_lookups.saturating_add(1);
    }

    /// Record an injected fault.
    pub fn record_injected_fault(&mut self) {
        self.injected_faults = self.injected_faults.saturating_add(1);
    }
}

/// Fault-injection point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FaultPoint {
    /// Drop the next data write.
    DropDataWrite = 1,
    /// Drop the next metadata write.
    DropMetadataWrite = 2,
    /// Fail the next flush.
    FailFlush = 3,
    /// Corrupt metadata checksum after write.
    CorruptMetadata = 4,
    /// Hide primary root-store ring.
    LosePrimaryRoot = 5,
    /// Hide backup root-store ring.
    LoseBackupRoot = 6,
}

/// Fault action decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    /// No fault should be injected.
    Pass,
    /// Inject the configured fault now.
    Inject(FaultPoint),
}

/// Deterministic no-heap fault injector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultInjector {
    point: Option<FaultPoint>,
    fire_on_count: u64,
    seen: u64,
    fired: bool,
}

impl FaultInjector {
    /// Disabled fault injector.
    pub const fn disabled() -> Self {
        Self {
            point: None,
            fire_on_count: 0,
            seen: 0,
            fired: false,
        }
    }

    /// Configure a one-shot fault at a deterministic hit count.
    pub const fn one_shot(point: FaultPoint, fire_on_count: u64) -> Self {
        Self {
            point: Some(point),
            fire_on_count,
            seen: 0,
            fired: false,
        }
    }

    /// Observe one possible injection point.
    pub fn observe(&mut self, point: FaultPoint) -> FaultAction {
        let Some(configured) = self.point else {
            return FaultAction::Pass;
        };
        if configured != point || self.fired {
            return FaultAction::Pass;
        }
        self.seen = self.seen.saturating_add(1);
        if self.seen >= self.fire_on_count {
            self.fired = true;
            FaultAction::Inject(point)
        } else {
            FaultAction::Pass
        }
    }

    /// Whether the configured fault has fired.
    pub const fn fired(&self) -> bool {
        self.fired
    }
}

/// Latency histogram with fixed buckets in microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyHistogram<const N: usize> {
    bounds_us: [u64; N],
    counts: [u64; N],
    overflow: u64,
}

impl<const N: usize> LatencyHistogram<N> {
    /// Create a histogram from sorted upper bounds.
    pub const fn new(bounds_us: [u64; N]) -> Self {
        Self {
            bounds_us,
            counts: [0; N],
            overflow: 0,
        }
    }

    /// Record one latency sample.
    pub fn record(&mut self, latency_us: u64) {
        let mut index = 0usize;
        while index < self.bounds_us.len() {
            if latency_us <= self.bounds_us[index] {
                self.counts[index] = self.counts[index].saturating_add(1);
                return;
            }
            index += 1;
        }
        self.overflow = self.overflow.saturating_add(1);
    }

    /// Bucket counts.
    pub const fn counts(&self) -> &[u64; N] {
        &self.counts
    }

    /// Overflow count.
    pub const fn overflow(&self) -> u64 {
        self.overflow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_saturate_and_record() {
        let mut counters = HxfsCounters::default();
        counters.record_read();
        counters.record_write();
        counters.record_checkpoint();
        counters.record_cache(true);
        counters.record_cache(false);
        counters.record_quota_denied();
        assert_eq!(counters.reads, 1);
        assert_eq!(counters.cache_hits, 1);
        assert_eq!(counters.cache_misses, 1);
        assert_eq!(counters.quota_denied, 1);
    }

    #[test]
    fn fault_injector_is_one_shot() {
        let mut injector = FaultInjector::one_shot(FaultPoint::FailFlush, 2);
        assert_eq!(
            injector.observe(FaultPoint::DropDataWrite),
            FaultAction::Pass
        );
        assert_eq!(injector.observe(FaultPoint::FailFlush), FaultAction::Pass);
        assert_eq!(
            injector.observe(FaultPoint::FailFlush),
            FaultAction::Inject(FaultPoint::FailFlush)
        );
        assert_eq!(injector.observe(FaultPoint::FailFlush), FaultAction::Pass);
        assert!(injector.fired());
    }

    #[test]
    fn latency_histogram_records_fixed_buckets() {
        let mut hist = LatencyHistogram::new([10, 100, 1000]);
        hist.record(7);
        hist.record(99);
        hist.record(5000);
        assert_eq!(hist.counts(), &[1, 1, 0]);
        assert_eq!(hist.overflow(), 1);
    }
}
