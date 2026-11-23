//! Monotonic clock and privileged system-control syscalls.

use huesos_abi::ErrorCode;

use huesos_abi::{SchedCpuRecord, SchedSummary, TaskRecord};

use crate::callbacks::{
    CLOCK_FN, CPU_COUNT_FN, CPU_MASK_FN, CURRENT_CPU_FN, SCHED_CPU_FN, SCHED_SUMMARY_FN,
    SHUTDOWN_FN, TASK_RECORD_FN,
};
use crate::user_memory;
use crate::SyscallResult;

pub(crate) fn sys_clock_get_monotonic() -> SyscallResult {
    let clock = CLOCK_FN.get().ok_or(ErrorCode::NotSupported)?;
    let ticks = clock();
    if ticks > i64::MAX as u64 {
        return Err(ErrorCode::Busy);
    }
    Ok(ticks as i64)
}

pub(crate) fn sys_system_cpu_count() -> SyscallResult {
    let count_fn = *CPU_COUNT_FN.lock();
    if let Some(count) = count_fn {
        return i64::try_from(count()).map_err(|_| ErrorCode::Busy);
    }
    let mask_fn = (*CPU_MASK_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    Ok(mask_fn().count_ones() as i64)
}

pub(crate) fn sys_system_current_cpu() -> SyscallResult {
    let current = CURRENT_CPU_FN.get().ok_or(ErrorCode::NotSupported)?;
    Ok(current() as i64)
}

/// Write the scheduler snapshot: summary record, then one record per CPU.
pub(crate) fn sys_system_sched_stats(out: *mut u8, len: usize) -> SyscallResult {
    let summary_fn = (*SCHED_SUMMARY_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let cpu_fn = (*SCHED_CPU_FN.lock()).ok_or(ErrorCode::NotSupported)?;

    let summary_bytes = core::mem::size_of::<SchedSummary>();
    // A short buffer is not an error the caller can act on by retrying: it
    // cannot read the summary that would tell it the size, so report the
    // shortfall and let it size the buffer from `SystemCpuCount`.
    if len < summary_bytes {
        return Err(ErrorCode::InvalidArgs);
    }
    let mut summary = SchedSummary::default();
    summary_fn(&mut summary);
    user_memory::write_value(out.cast::<SchedSummary>(), &summary)?;
    let mut written = summary_bytes;

    let record_size = core::mem::size_of::<SchedCpuRecord>();
    let mut online_records = 0usize;
    for cpu in 0..huesos_abi::MAX_LOGICAL_CPUS {
        let mut record = SchedCpuRecord::default();
        cpu_fn(cpu, &mut record);
        if record.online == 0 {
            continue;
        }
        if written + record_size > len {
            break;
        }
        // `out` is the caller's buffer and `written` never passes `len`, which
        // the kernel validated; offsetting a raw pointer is safe, and
        // `write_value` re-validates the range it is handed.
        user_memory::write_value(out.wrapping_add(written).cast::<SchedCpuRecord>(), &record)?;
        written += record_size;
        online_records += 1;
        if online_records == summary.cpu_count as usize {
            break;
        }
    }
    Ok(written as i64)
}

/// Write up to `len / size_of::<TaskRecord>()` task records starting at `start`.
pub(crate) fn sys_system_task_query(start: usize, out: *mut u8, len: usize) -> SyscallResult {
    let record_fn = (*TASK_RECORD_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let record_size = core::mem::size_of::<TaskRecord>();
    if record_size == 0 || len < record_size {
        return Err(ErrorCode::InvalidArgs);
    }
    const BATCH_MAX: usize = 32;
    let capacity = (len / record_size).min(BATCH_MAX);
    let mut batch = [TaskRecord::default(); BATCH_MAX];
    let (written, total) = record_fn(start, &mut batch[..capacity]);
    for (slot, record) in batch.iter().enumerate().take(written) {
        user_memory::write_value(
            out.wrapping_add(slot * record_size).cast::<TaskRecord>(),
            record,
        )?;
    }
    // (records << 32) | total, so a caller can page without guessing the size.
    Ok(((written as i64) << 32) | (total as u32 as i64))
}

pub(crate) fn sys_system_shutdown() -> SyscallResult {
    let shutdown = (*SHUTDOWN_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    shutdown()?;
    // A successful shutdown never returns. Keep the ABI result defined for a
    // test implementation that elects to return instead.
    Ok(0)
}
