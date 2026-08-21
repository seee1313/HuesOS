//! Job/ResourceDomain hierarchy models.
//!
//! Scheduler v2 places every Task under a Job. Jobs compete on each CPU's
//! root EEVDF tree; Tasks of one Job compete inside that Job's per-CPU EEVDF
//! tree. This prevents thread-count amplification: a Job with 100 threads
//! competes as one root entity, not 100.
//!
//! System-wide fairness is deliberately approximate (per-CPU local EEVDF +
//! service-deficit balancing + strict aggregate hard caps); exact global
//! virtual time is rejected because it would put shared cache-line state in
//! every context switch. All models here are host-testable and allocation
//! free on the hot path.

/// Fixed Job identity (capability-backed in the kernel; here a plain id).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct JobId(u32);

impl JobId {
    /// Zero is reserved for the root/system Job.
    pub const ROOT: Self = Self(0);

    pub const fn new(raw: u32) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Per-CPU demand/load accounting for one Job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobCpuLoad {
    /// Runnable (ready) thread count for this Job on this CPU.
    pub runnable: u32,
    /// Weighted fair demand (sum of thread weights) on this CPU.
    pub demand_weight: u64,
    /// Service received this accounting window on this CPU, in ns.
    pub service_ns: u64,
}

impl JobCpuLoad {
    pub const fn new() -> Self {
        Self {
            runnable: 0,
            demand_weight: 0,
            service_ns: 0,
        }
    }
}

impl Default for JobCpuLoad {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate Job state used by the balancing/accounting oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobState<const CPUS: usize> {
    pub id: JobId,
    pub weight: u64,
    /// Per-CPU load snapshots.
    pub per_cpu: [JobCpuLoad; CPUS],
    /// Global service received this window (sum across CPUs).
    pub service_total_ns: u64,
    /// Runnable parallelism across all CPUs (threads ready anywhere).
    pub runnable_total: u32,
    /// Hard cap (aggregate ns per period); 0 = unlimited.
    pub cap_ns_per_period: u64,
    /// Monotonic period counter for cap accounting.
    pub cap_period_start_ns: u64,
}

/// Job update failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobError {
    CpuOutOfRange,
    Overflow,
    ZeroWeight,
    NotAllocated,
}

impl<const CPUS: usize> JobState<CPUS> {
    /// Create a Job with the given weight and cap.
    pub fn new(id: JobId, weight: u64, cap_ns_per_period: u64) -> Result<Self, JobError> {
        if weight == 0 {
            return Err(JobError::ZeroWeight);
        }
        Ok(Self {
            id,
            weight,
            per_cpu: [JobCpuLoad::new(); CPUS],
            service_total_ns: 0,
            runnable_total: 0,
            cap_ns_per_period,
            cap_period_start_ns: 0,
        })
    }

    /// Record one thread becoming runnable on `cpu`.
    pub fn thread_ready(&mut self, cpu: usize, weight: u64) -> Result<(), JobError> {
        let load = self.per_cpu.get_mut(cpu).ok_or(JobError::CpuOutOfRange)?;
        load.runnable = load.runnable.checked_add(1).ok_or(JobError::Overflow)?;
        load.demand_weight = load
            .demand_weight
            .checked_add(weight)
            .ok_or(JobError::Overflow)?;
        self.runnable_total = self
            .runnable_total
            .checked_add(1)
            .ok_or(JobError::Overflow)?;
        Ok(())
    }

    /// Record one thread leaving the runnable state on `cpu`.
    pub fn thread_blocked(&mut self, cpu: usize, weight: u64) -> Result<(), JobError> {
        let load = self.per_cpu.get_mut(cpu).ok_or(JobError::CpuOutOfRange)?;
        load.runnable = load.runnable.saturating_sub(1);
        load.demand_weight = load.demand_weight.saturating_sub(weight);
        self.runnable_total = self.runnable_total.saturating_sub(1);
        Ok(())
    }

    /// Charge service for this Job on one CPU.
    pub fn charge(&mut self, cpu: usize, ns: u64) -> Result<(), JobError> {
        let load = self.per_cpu.get_mut(cpu).ok_or(JobError::CpuOutOfRange)?;
        load.service_ns = load.service_ns.checked_add(ns).ok_or(JobError::Overflow)?;
        self.service_total_ns = self
            .service_total_ns
            .checked_add(ns)
            .ok_or(JobError::Overflow)?;
        Ok(())
    }

    /// Total runnable demand across all CPUs (weighted).
    pub fn demand_total(&self) -> u64 {
        self.per_cpu
            .iter()
            .fold(0u64, |acc, l| acc.saturating_add(l.demand_weight))
    }

    /// Whether this Job is currently over its hard cap for `now_ns`.
    pub fn capped(&self, now_ns: u64) -> bool {
        if self.cap_ns_per_period == 0 {
            return false;
        }
        let elapsed = now_ns.saturating_sub(self.cap_period_start_ns);
        self.service_total_ns >= self.cap_ns_per_period && elapsed < self.cap_ns_per_period
    }

    /// Reset the accounting window if `now_ns` advanced past one period.
    pub fn maybe_replenish(&mut self, now_ns: u64) -> bool {
        if self.cap_ns_per_period == 0 {
            return false;
        }
        let elapsed = now_ns.saturating_sub(self.cap_period_start_ns);
        if elapsed < self.cap_ns_per_period {
            return false;
        }
        self.cap_period_start_ns = self
            .cap_period_start_ns
            .saturating_add(self.cap_ns_per_period);
        self.service_total_ns = 0;
        for load in &mut self.per_cpu {
            load.service_ns = 0;
        }
        true
    }
}

/// Maximum number of Jobs represented by the fixed Job table.
pub const MAX_JOBS: usize = 64;

/// Fixed-capacity Job table. Allocates JobIds densely; slot 0 is reserved
/// for the root Job and cannot be reused.
pub struct JobTable {
    /// Bitmap of allocated slots (bit 0 permanently set for root).
    used: [u64; 1],
    generations: [u32; MAX_JOBS],
}

/// A published Job identity with its generation (stable across table reuse).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobSlotId {
    pub index: usize,
    pub generation: u32,
}

impl JobTable {
    pub const fn new() -> Self {
        // Root Job slot 0 is permanently allocated.
        Self {
            used: [1],
            generations: [0; MAX_JOBS],
        }
    }

    /// Allocate a new Job slot (never slot 0).
    pub fn allocate(&mut self) -> Option<JobSlotId> {
        let mut bits = self.used[0];
        loop {
            let free = !bits;
            if free == 0 {
                return None;
            }
            let bit = free.trailing_zeros() as usize;
            let index = bit;
            if index >= MAX_JOBS {
                return None;
            }
            let mask = 1u64 << bit;
            if bits & mask == 0 {
                self.used[0] |= mask;
                let generation = self.generations[index].wrapping_add(1);
                self.generations[index] = generation;
                return Some(JobSlotId { index, generation });
            }
            bits |= mask;
        }
    }

    /// Release a Job slot (slot 0 is permanent and refused).
    pub fn free(&mut self, id: JobSlotId) -> Result<(), JobError> {
        if id.index == 0 || id.index >= MAX_JOBS {
            return Err(JobError::NotAllocated);
        }
        let word = id.index / 64;
        let mask = 1u64 << (id.index % 64);
        if self.used[word] & mask == 0 {
            return Err(JobError::NotAllocated);
        }
        if self.generations[id.index] != id.generation {
            return Err(JobError::NotAllocated);
        }
        self.used[word] &= !mask;
        Ok(())
    }

    /// Whether a Job slot is currently allocated.
    pub fn is_allocated(&self, index: usize) -> bool {
        index < MAX_JOBS && self.used[index / 64] & (1u64 << (index % 64)) != 0
    }
}

impl Default for JobTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: u32) -> JobId {
        JobId::new(id).unwrap_or_else(|| unreachable!())
    }

    #[test]
    fn job_state_tracks_per_cpu_demand_and_service() {
        let mut state = JobState::<4>::new(job(7), 1024, 1_000_000).unwrap();
        state.thread_ready(0, 1024).unwrap();
        state.thread_ready(0, 512).unwrap();
        state.thread_ready(2, 1024).unwrap();
        assert_eq!(state.runnable_total, 3);
        assert_eq!(state.per_cpu[0].runnable, 2);
        assert_eq!(state.demand_total(), 2560);
        state.charge(0, 100).unwrap();
        assert_eq!(state.per_cpu[0].service_ns, 100);
        assert_eq!(state.service_total_ns, 100);
        assert!(!state.capped(50));
        state.thread_blocked(2, 1024).unwrap();
        assert_eq!(state.runnable_total, 2);
    }

    #[test]
    fn job_hard_cap_replenishes_after_period() {
        let mut state = JobState::<1>::new(job(3), 1024, 1000).unwrap();
        state.charge(0, 1000).unwrap();
        assert!(state.capped(500));
        // Window still active at 999 ns.
        assert!(!state.maybe_replenish(999));
        // At one period, service resets and the cap releases.
        assert!(state.maybe_replenish(1000));
        assert_eq!(state.service_total_ns, 0);
        assert!(!state.capped(1500));
    }

    #[test]
    fn job_table_reserves_root_and_reuses_slots_with_generations() {
        let mut table = JobTable::new();
        assert!(table.is_allocated(0));
        let first = table.allocate().unwrap();
        assert_ne!(first.index, 0);
        assert_eq!(first.generation, 1);
        table.free(first).unwrap();
        assert!(!table.is_allocated(first.index));
        let second = table.allocate().unwrap();
        assert_eq!(second.index, first.index);
        assert_eq!(second.generation, 2);
        assert_eq!(
            table.free(JobSlotId {
                index: 0,
                generation: 1
            }),
            Err(JobError::NotAllocated)
        );
    }

    #[test]
    fn zero_weight_job_is_refused() {
        assert_eq!(JobState::<1>::new(job(1), 0, 0), Err(JobError::ZeroWeight));
    }
}
