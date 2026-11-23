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

/// Stack-allocated sanitized x86_64 processor brand / vendor string.
#[derive(Clone, Copy)]
pub struct CpuBrand {
    bytes: [u8; 48],
    len: usize,
}

impl CpuBrand {
    /// Trimmed printable ASCII processor brand string.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("x86_64")
    }
}

/// Query the hardware x86_64 processor brand string via unprivileged `CPUID`
/// leaves `0x8000_0002..=0x8000_0004`, falling back to the leaf-0 vendor string.
pub fn cpu_brand_string() -> CpuBrand {
    let mut raw_brand = [0u8; 48];
    let mut raw_len = 0usize;
    let max_ext = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if max_ext >= 0x8000_0004 {
        for (chunk_idx, leaf_num) in (0x8000_0002..=0x8000_0004).enumerate() {
            let leaf = core::arch::x86_64::__cpuid(leaf_num);
            let base = chunk_idx * 16;
            raw_brand[base..base + 4].copy_from_slice(&leaf.eax.to_le_bytes());
            raw_brand[base + 4..base + 8].copy_from_slice(&leaf.ebx.to_le_bytes());
            raw_brand[base + 8..base + 12].copy_from_slice(&leaf.ecx.to_le_bytes());
            raw_brand[base + 12..base + 16].copy_from_slice(&leaf.edx.to_le_bytes());
        }
        raw_len = raw_brand
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_brand.len());
    }
    if raw_len == 0 {
        let leaf0 = core::arch::x86_64::__cpuid(0);
        raw_brand[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        raw_brand[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        raw_brand[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());
        raw_len = raw_brand[..12].iter().position(|&b| b == 0).unwrap_or(12);
    }

    let mut out = [0u8; 48];
    let mut out_len = 0usize;
    let mut prev_space = true;
    for &b in &raw_brand[..raw_len] {
        let ch = if (0x21..=0x7e).contains(&b) {
            prev_space = false;
            b
        } else if b == b' ' && !prev_space {
            prev_space = true;
            b' '
        } else {
            continue;
        };
        if out_len < out.len() {
            out[out_len] = ch;
            out_len += 1;
        }
    }
    while out_len > 0 && out[out_len - 1] == b' ' {
        out_len -= 1;
    }
    if out_len == 0 {
        let fallback = b"x86_64";
        out[..fallback.len()].copy_from_slice(fallback);
        out_len = fallback.len();
    }
    CpuBrand {
        bytes: out,
        len: out_len,
    }
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
/// possible dense CPU index.
const MAX_SNAPSHOT_BYTES: usize = core::mem::size_of::<huesos_abi::SchedSummary>()
    + huesos_abi::MAX_LOGICAL_CPUS * core::mem::size_of::<huesos_abi::SchedCpuRecord>();

/// Read the aggregate scheduler counters.
pub fn sched_summary() -> crate::Result<huesos_abi::SchedSummary> {
    let summary_size = core::mem::size_of::<huesos_abi::SchedSummary>();
    let mut buffer = [0u8; core::mem::size_of::<huesos_abi::SchedSummary>()];
    let written = sched_stats_into(&mut buffer)?;
    if written < summary_size {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    huesos_abi::SchedSummary::from_bytes(&buffer[..summary_size])
        .ok_or(crate::ErrorCode::InvalidArgs)
}

/// Read the aggregate scheduler summary and per-CPU records into caller storage.
pub fn sched_snapshot_into(
    buffer: &mut [u8],
    mut visit: impl FnMut(&huesos_abi::SchedCpuRecord),
) -> crate::Result<huesos_abi::SchedSummary> {
    let written = sched_stats_into(buffer)?;
    let summary_size = core::mem::size_of::<huesos_abi::SchedSummary>();
    let record_size = core::mem::size_of::<huesos_abi::SchedCpuRecord>();
    if written < summary_size || record_size == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let summary = huesos_abi::SchedSummary::from_bytes(&buffer[..summary_size])
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let mut offset = summary_size;
    while offset + record_size <= written {
        let record = huesos_abi::SchedCpuRecord::from_bytes(&buffer[offset..offset + record_size])
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        visit(&record);
        offset += record_size;
    }
    Ok(summary)
}

/// Read the aggregate scheduler summary and per-CPU records in a single syscall.
pub fn sched_snapshot(
    visit: impl FnMut(&huesos_abi::SchedCpuRecord),
) -> crate::Result<huesos_abi::SchedSummary> {
    let mut buffer = [0u8; MAX_SNAPSHOT_BYTES];
    sched_snapshot_into(&mut buffer, visit)
}

/// Visit the per-CPU scheduler records.
///
/// `visit` sees the CPUs the kernel reported in this sample, in dense CPU
/// order; the count is returned so a caller can detect a CPU that came online
/// between the summary and the records.
pub fn sched_cpus(mut visit: impl FnMut(&huesos_abi::SchedCpuRecord)) -> crate::Result<usize> {
    let mut seen = 0;
    let _ = sched_snapshot(|record| {
        visit(record);
        seen += 1;
    })?;
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
