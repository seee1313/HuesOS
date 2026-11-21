//! Typed scheduler and system views.
//!
//! `libcanvas::system` hands back the raw record bytes the kernel wrote; this
//! module turns them into owned records a program can index, sort and print.
//! Decoding happens in one place so `schedctl` and `btop` cannot disagree about
//! what a field means.

use alloc::vec::Vec;

use huesos_abi::{SchedCpuRecord, SchedSummary, TaskRecord};

use crate::error::{Error, Result};
use libcanvas;

/// One scheduler sample.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Counters since boot.
    pub summary: SchedSummary,
    /// One record per online CPU, in dense CPU order.
    pub cpus: Vec<SchedCpuRecord>,
}

impl Snapshot {
    /// Tasks ready to run across every CPU.
    pub fn runnable(&self) -> u32 {
        self.cpus.iter().map(|cpu| cpu.runnable).sum()
    }

    /// Tasks owned by every CPU.
    pub fn tasks(&self) -> u32 {
        self.cpus.iter().map(|cpu| cpu.tasks).sum()
    }

    /// Admitted CBS utilization, summed over CPUs, parts per million.
    pub fn admitted_ppm(&self) -> u32 {
        self.cpus.iter().map(|cpu| cpu.admitted_ppm).sum()
    }

    /// The busiest CPU's share of total ticks, as a percentage (0..=100).
    ///
    /// The scheduler does not count idle time separately, so this is a *share*
    /// of the sampled window rather than a utilization to be trusted to the
    /// percent: two consecutive samples of the same CPU produce the number a
    /// monitor actually needs (ticks consumed between samples).
    pub fn ticks(&self) -> u64 {
        self.cpus.iter().map(|cpu| cpu.ticks).sum()
    }
}

/// Read the scheduler counters.
pub fn snapshot() -> Result<Snapshot> {
    let cpu_cap = libcanvas::system::cpu_count().unwrap_or(64).clamp(1, 64);
    let bytes =
        core::mem::size_of::<SchedSummary>() + cpu_cap * core::mem::size_of::<SchedCpuRecord>();
    let mut buffer = alloc::vec![0u8; bytes];
    let mut cpus = Vec::with_capacity(cpu_cap);
    let summary = libcanvas::system::sched_snapshot_into(&mut buffer, |record| cpus.push(*record))
        .map_err(map_error)?;
    Ok(Snapshot { summary, cpus })
}

/// Read the whole task table.
pub fn tasks() -> Result<Vec<TaskRecord>> {
    let mut records = Vec::new();
    libcanvas::system::for_each_task(|record| records.push(*record)).map_err(map_error)?;
    Ok(records)
}

fn map_error(code: huesos_abi::ErrorCode) -> Error {
    Error::from_code(code)
}
