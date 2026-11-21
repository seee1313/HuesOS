//! Monotonic time and supervisor system-control wrappers.

use crate::raw;
use huesos_abi::Syscall;

/// Read the kernel monotonic clock in 100 Hz scheduler ticks.
pub fn monotonic_ticks() -> crate::Result<u64> {
    let value = raw::syscall0(Syscall::ClockGetMonotonic);
    raw::decode(value).map(|ticks| ticks as u64)
}

/// Number of online CPUs using HuesOS dense CPU indexes.
pub fn cpu_count() -> crate::Result<usize> {
    let value = raw::syscall0(Syscall::SystemCpuCount);
    raw::decode(value).map(|count| count as usize)
}

/// Dense CPU index of the caller.
pub fn current_cpu() -> crate::Result<usize> {
    let value = raw::syscall0(Syscall::SystemCurrentCpu);
    raw::decode(value).map(|cpu| cpu as usize)
}

/// In-memory boot volume key owned by KeyBroker.
///
/// This type deliberately has no `Debug`, `Clone`, or `Copy` implementation.
/// Its bytes are cleared on drop before the backing stack/heap memory can be
/// reused.
pub struct VolumeKey([u8; 32]);

impl VolumeKey {
    /// Construct from a validated KeyBroker reply.
    ///
    /// This does not grant authority by itself: the bytes can only arrive over
    /// the generation-bound channel endpoint DriverManager transferred to the
    /// supervised HxFS process.
    pub fn from_broker_reply(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the key for subkey derivation or a single-use broker reply.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
            let _ = core::hint::black_box(*byte);
        }
    }
}

/// Atomically move the boot volume key out of the kernel.
///
/// `authority` must name the unique `ResourceKind::VolumeKey` capability
/// minted by init for KeyBroker. The syscall is one-shot: after a successful
/// call the kernel no longer retains the key. `Ok(None)` means this boot has no
/// sealed/build-time key and only plain volumes may mount.
pub fn take_volume_key(authority: &crate::Handle) -> crate::Result<Option<VolumeKey>> {
    let mut key = [0u8; 32];
    let ret = raw::syscall2(
        Syscall::VolumeKeyTake,
        authority.raw() as u64,
        &mut key as *mut [u8; 32] as u64,
    );
    match raw::decode(ret) {
        Ok(_) => Ok(Some(VolumeKey(key))),
        Err(crate::ErrorCode::NotFound) => Ok(None),
        Err(error) => {
            for byte in key.iter_mut() {
                *byte = 0;
                let _ = core::hint::black_box(*byte);
            }
            Err(error)
        }
    }
}

/// Request an orderly non-ACPI software shutdown.
///
/// Kernel policy accepts this only from the root init supervisor. On success
/// every CPU halts and this function does not return.
pub fn shutdown() -> crate::Result<()> {
    let value = raw::syscall0(Syscall::SystemShutdown);
    raw::decode(value).map(|_| ())
}

/// Bytes in one observation record on the wire. Re-exported so callers
/// can size a buffer without depending on `huesos-abi` directly.
pub use huesos_abi::OBSERVATION_RECORD_SIZE;

/// Largest buffer one [`observation_read`] call will fill.
pub use huesos_abi::MAX_OBSERVATION_BYTES;

/// Runtime knob selector. Re-exported from the ABI so callers do not
/// have to depend on `huesos-abi` directly.
pub use huesos_abi::KnobIdAbi as KnobId;

/// Read one runtime knob (Stage E.1).
///
/// Unrestricted: no capability is needed to learn a value the caller is
/// already subject to.
pub fn knob_get(id: KnobId) -> crate::Result<u64> {
    let mut value: u64 = 0;
    let ret = raw::syscall2(
        Syscall::SystemKnobGet,
        id as u32 as u64,
        &mut value as *mut u64 as u64,
    );
    raw::decode(ret)?;
    Ok(value)
}

/// Write one runtime knob, returning the value actually applied.
///
/// `cap` must name a live `SystemControl` resource handle; without it
/// the call fails with `AccessDenied`. The kernel clamps the request
/// into the knob's bounds rather than rejecting it, so the returned
/// value may differ from `value` — compare them if you care.
pub fn knob_set(id: KnobId, value: u64, cap: huesos_abi::HandleValue) -> crate::Result<u64> {
    let mut applied: u64 = 0;
    let ret = raw::syscall4(
        Syscall::SystemKnobSet,
        id as u32 as u64,
        value,
        &mut applied as *mut u64 as u64,
        cap as u64,
    );
    raw::decode(ret)?;
    Ok(applied)
}

/// Drain structured observation records into `out` (Stage E.2).
///
/// Reads records whose sequence number is `>= after_sequence`; pass `0`
/// for everything the kernel still holds. Returns the number of bytes
/// written, always a whole multiple of
/// [`huesos_abi::OBSERVATION_RECORD_SIZE`]. A zero return means
/// "nothing new", which is an ordinary poll result rather than an
/// error.
///
/// To follow the stream, remember the highest sequence number seen and
/// pass it plus one on the next call. A gap in sequence numbers means
/// the ring wrapped and records were lost.
pub fn observation_read(after_sequence: u64, out: &mut [u8]) -> crate::Result<usize> {
    let ret = raw::syscall3(
        Syscall::SystemObservationRead,
        after_sequence,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    );
    raw::decode(ret).map(|written| written as usize)
}

/// Largest snapshot the kernel can produce: the summary plus one record per
/// possible CPU. Sized from the ABI so a bigger machine needs no edit here.
const MAX_SNAPSHOT_BYTES: usize = core::mem::size_of::<huesos_abi::SchedSummary>()
    + 64 * core::mem::size_of::<huesos_abi::SchedCpuRecord>();

/// Read the aggregate scheduler counters.
pub fn sched_summary() -> crate::Result<huesos_abi::SchedSummary> {
    let mut buffer = [0u8; MAX_SNAPSHOT_BYTES];
    let written = sched_stats_into(&mut buffer)?;
    let summary_size = core::mem::size_of::<huesos_abi::SchedSummary>();
    if written < summary_size {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    huesos_abi::SchedSummary::from_bytes(&buffer[..summary_size])
        .ok_or(crate::ErrorCode::InvalidArgs)
}

/// Visit the per-CPU scheduler records.
///
/// `visit` sees the CPUs the kernel reported in this sample, in dense CPU
/// order; the count is returned so a caller can detect a CPU that came online
/// between the summary and the records.
pub fn sched_cpus(mut visit: impl FnMut(&huesos_abi::SchedCpuRecord)) -> crate::Result<usize> {
    let mut buffer = [0u8; MAX_SNAPSHOT_BYTES];
    let written = sched_stats_into(&mut buffer)?;
    let summary_size = core::mem::size_of::<huesos_abi::SchedSummary>();
    let record_size = core::mem::size_of::<huesos_abi::SchedCpuRecord>();
    if written < summary_size || record_size == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let mut seen = 0;
    let mut offset = summary_size;
    while offset + record_size <= written {
        let record = huesos_abi::SchedCpuRecord::from_bytes(&buffer[offset..offset + record_size])
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        visit(&record);
        seen += 1;
        offset += record_size;
    }
    Ok(seen)
}

/// Read the whole task table into `visit`, in the kernel's enumeration order.
///
/// Pages through the table in chunks of `PAGE` records; the table can grow
/// while it is read, and the count that comes back is the size the kernel
/// reported on the last page.
pub fn for_each_task(mut visit: impl FnMut(&huesos_abi::TaskRecord)) -> crate::Result<usize> {
    const PAGE: usize = 16;
    let record_size = core::mem::size_of::<huesos_abi::TaskRecord>();
    let mut buffer = [0u8; PAGE * core::mem::size_of::<huesos_abi::TaskRecord>()];
    let mut index = 0usize;
    let mut total;
    loop {
        let packed = raw::syscall3(
            Syscall::SystemTaskQuery,
            index as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
        );
        let packed = raw::decode(packed)? as u64;
        let written = (packed >> 32) as usize;
        total = (packed & 0xFFFF_FFFF) as usize;
        if written == 0 {
            break;
        }
        for slot in 0..written {
            let start = slot * record_size;
            let record = huesos_abi::TaskRecord::from_bytes(&buffer[start..start + record_size])
                .ok_or(crate::ErrorCode::InvalidArgs)?;
            visit(&record);
        }
        index += written;
        if index >= total {
            break;
        }
    }
    Ok(total)
}

fn sched_stats_into(buffer: &mut [u8]) -> crate::Result<usize> {
    let written = raw::syscall2(
        Syscall::SystemSchedStats,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    );
    raw::decode(written).map(|bytes| bytes as usize)
}
