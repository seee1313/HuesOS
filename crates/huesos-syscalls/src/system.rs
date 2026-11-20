//! Monotonic clock and privileged system-control syscalls.

use huesos_abi::ErrorCode;

use huesos_abi::{SchedCpuRecord, SchedSummary, TaskRecord};

use crate::callbacks::{
    CLOCK_FN, CPU_MASK_FN, CURRENT_CPU_FN, SCHED_CPU_FN, SCHED_SUMMARY_FN, SHUTDOWN_FN,
    TASK_RECORD_FN,
};
use crate::user_memory;
use crate::SyscallResult;

pub(crate) fn sys_clock_get_monotonic() -> SyscallResult {
    let clock = (*CLOCK_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let ticks = clock();
    if ticks > i64::MAX as u64 {
        return Err(ErrorCode::Busy);
    }
    Ok(ticks as i64)
}

pub(crate) fn sys_system_cpu_count() -> SyscallResult {
    let mask_fn = (*CPU_MASK_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    Ok(mask_fn().count_ones() as i64)
}

pub(crate) fn sys_system_current_cpu() -> SyscallResult {
    let current = (*CURRENT_CPU_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    Ok(current() as i64)
}

/// Write the scheduler snapshot: summary record, then one record per CPU.
pub(crate) fn sys_system_sched_stats(out: *mut u8, len: usize) -> SyscallResult {
    let summary_fn = (*SCHED_SUMMARY_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let cpu_fn = (*SCHED_CPU_FN.lock()).ok_or(ErrorCode::NotSupported)?;

    let mut summary = SchedSummary::default();
    summary_fn(&mut summary);
    let summary_bytes = core::mem::size_of::<SchedSummary>();
    if len < summary_bytes {
        // A short buffer is not an error: the caller learns the record size
        // from the summary it cannot yet read, so report the shortfall.
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::copy_to_user(out, as_bytes(&summary))?;
    let mut written = summary_bytes;

    let record_size = core::mem::size_of::<SchedCpuRecord>();
    for cpu in 0..summary.cpu_count as usize {
        if written + record_size > len {
            break;
        }
        let mut record = SchedCpuRecord::default();
        cpu_fn(cpu, &mut record);
        // Safety of the cast: `copy_to_user` validates the caller's range and
        // `written` is bounded by `len`, so the destination stays inside the
        // buffer the caller declared.
        let target = unsafe { out.add(written) };
        user_memory::copy_to_user(target, as_bytes(&record))?;
        written += record_size;
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
    let capacity = len / record_size;
    let mut written = 0usize;
    let mut index = start;
    while written < capacity {
        let mut record = TaskRecord::default();
        if !record_fn(index, &mut record) {
            break;
        }
        let target = unsafe { out.add(written * record_size) };
        user_memory::copy_to_user(target, as_bytes(&record))?;
        written += 1;
        index += 1;
    }
    // (records << 32) | total, so a caller can page without guessing the size.
    let total = crate::callbacks::task_total() as u32 as i64;
    Ok(((written as i64) << 32) | total)
}

/// View a plain-old-data record as bytes for `copy_to_user`.
fn as_bytes<T: Copy>(record: &T) -> &[u8] {
    // Safety: `T` is a `repr(C)` record of plain integers with no padding
    // invariants, and the borrow lives only for the copy.
    unsafe {
        core::slice::from_raw_parts((record as *const T) as *const u8, core::mem::size_of::<T>())
    }
}

pub(crate) fn sys_system_shutdown() -> SyscallResult {
    let shutdown = (*SHUTDOWN_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    shutdown()?;
    // A successful shutdown never returns. Keep the ABI result defined for a
    // test implementation that elects to return instead.
    Ok(0)
}
