//! Operations surface: runtime knobs and structured observation
//! (Stage E.1 and E.2 of `docs/PRODUCTION_ROADMAP.md`).
//!
//! The state lives in `huesos_object::{knobs, observation}`; this layer
//! is the syscall boundary, which means it owns exactly two concerns:
//! validating what userspace handed us, and deciding who is allowed to
//! do it.
//!
//! # Authority
//!
//! Reads — [`sys_system_knob_get`] and [`sys_system_observation_read`]
//! — are unrestricted. A process is already subject to the knob values
//! and is already the subject of the records; refusing to let it read
//! them protects nothing and guarantees that the diagnostic tooling
//! which most needs to run during an incident is the tooling that
//! cannot.
//!
//! Writes — [`sys_system_knob_set`] — require a live
//! `ResourceKind::SystemControl` handle. A knob write is global: a
//! process that sets `log.verbosity` to zero blinds every subsystem at
//! once, which is an effective way to hide an intrusion. That is an
//! authority, and it is deliberately not `PowerControl`, so a service
//! trusted to tune the system is not thereby trusted to halt it.

use huesos_abi::{ErrorCode, HandleValue, KnobIdAbi, MAX_OBSERVATION_BYTES};
use huesos_object::knobs::{self, KnobId};
use huesos_object::observation;
use huesos_object::ResourceKind;

use crate::resource::require_resource_of_kind;
use crate::user_memory;
use crate::SyscallResult;

/// Translate the wire knob tag into the kernel enum.
fn decode_knob(raw: u32) -> Result<KnobId, ErrorCode> {
    let abi = KnobIdAbi::from_raw(raw).ok_or(ErrorCode::InvalidArgs)?;
    Ok(match abi {
        KnobIdAbi::ScrubIntervalSecs => KnobId::ScrubIntervalSecs,
        KnobIdAbi::RecoveryRetryCount => KnobId::RecoveryRetryCount,
        KnobIdAbi::LogVerbosity => KnobId::LogVerbosity,
        KnobIdAbi::NvmeMaxQueueDepth => KnobId::NvmeMaxQueueDepth,
    })
}

/// `SystemKnobGet` — read one runtime knob.
pub(crate) fn sys_system_knob_get(knob: u32, out: *mut u64) -> SyscallResult {
    let id = decode_knob(knob)?;
    user_memory::validate_write(out)?;
    let value = knobs::get(id);
    user_memory::write_value(out, &value)?;
    Ok(0)
}

/// `SystemKnobSet` — write one runtime knob, capability-gated.
///
/// The value is clamped into the knob's bounds rather than rejected;
/// `out` receives what was actually applied. See
/// `huesos_object::knobs` for why clamping beats failing here.
pub(crate) fn sys_system_knob_set(
    knob: u32,
    value: u64,
    out: *mut u64,
    cap_handle: HandleValue,
) -> SyscallResult {
    // Authority first: a caller without the capability learns nothing
    // about whether its arguments were valid.
    let _cap = require_resource_of_kind(cap_handle, ResourceKind::SystemControl)?;
    let id = decode_knob(knob)?;
    // Validate the output pointer before mutating global state, so a
    // caller that passed a bad pointer does not leave the knob changed
    // and the report undelivered.
    if !out.is_null() {
        user_memory::validate_write(out)?;
    }
    let applied = knobs::set(id, value);
    if !out.is_null() {
        user_memory::write_value(out, &applied)?;
    }
    Ok(0)
}

/// `SystemObservationRead` — drain structured observation records.
///
/// Returns the number of bytes written, always a whole multiple of the
/// record size. A zero return means "nothing new since that sequence",
/// which is a normal poll result and not an error.
pub(crate) fn sys_system_observation_read(
    after_sequence: u64,
    out: *mut u8,
    len: usize,
) -> SyscallResult {
    if len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let capped = len.min(MAX_OBSERVATION_BYTES);
    // Copy into a kernel buffer first and release the ring lock before
    // touching user memory: a faulting user page must never be able to
    // hold the observation lock, or the next thing to record a fault
    // deadlocks against the fault being reported.
    let mut buffer = [0u8; MAX_OBSERVATION_BYTES];
    let written = observation::read_into(after_sequence, &mut buffer[..capped]);
    if written == 0 {
        return Ok(0);
    }
    user_memory::copy_to_user(out, &buffer[..written])?;
    Ok(written as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_abi::OBSERVATION_RECORD_SIZE;

    #[test]
    fn observation_record_size_matches_object_crate() {
        // Two crates state this number: the ABI (for userspace) and the
        // object crate (for the ring). If they ever disagree, userspace
        // decodes a shifted stream and every field looks plausible.
        assert_eq!(
            OBSERVATION_RECORD_SIZE,
            observation::OBSERVATION_RECORD_SIZE
        );
    }

    #[test]
    fn knob_abi_ids_match_the_kernel_enum() {
        // The handler translates by matching on the ABI enum, so a
        // renumbering on either side has to be caught here.
        for (abi, kernel) in [
            (KnobIdAbi::ScrubIntervalSecs, KnobId::ScrubIntervalSecs),
            (KnobIdAbi::RecoveryRetryCount, KnobId::RecoveryRetryCount),
            (KnobIdAbi::LogVerbosity, KnobId::LogVerbosity),
            (KnobIdAbi::NvmeMaxQueueDepth, KnobId::NvmeMaxQueueDepth),
        ] {
            assert_eq!(abi as u32, kernel as u32);
            assert_eq!(decode_knob(abi as u32), Ok(kernel));
        }
    }

    #[test]
    fn decode_rejects_an_unknown_knob() {
        assert_eq!(decode_knob(4), Err(ErrorCode::InvalidArgs));
        assert_eq!(decode_knob(u32::MAX), Err(ErrorCode::InvalidArgs));
    }

    #[test]
    fn a_zero_length_observation_read_is_rejected() {
        // Distinct from "no records": a zero-length buffer is a caller
        // bug, and reporting it as success would hide it forever.
        let result = sys_system_observation_read(0, core::ptr::null_mut(), 0);
        assert_eq!(result, Err(ErrorCode::InvalidArgs));
    }
}
