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
