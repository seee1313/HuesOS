//! Kernel-mode recoverable-copy fixup dispatch.
//!
//! Bridges [`huesos_arch::fault`] and the host-tested [`huesos_extable`]
//! policy crate:
//!
//! 1. The kernel owns a **statically-declared, sorted extable** of validated
//!    user-copy sites. Each entry maps an instruction-pointer range
//!    `[start_rip, end_rip)` covering the single unsafe block that
//!    performs a raw user-memory access to a `fixup_rip` at which execution
//!    resumes with the copy helper returning `Err(EFAULT)`.
//! 2. On every ring-0 `#PF`, the IDT calls
//!    [`huesos_arch::fault::try_kernel_recover`], which consults the hook
//!    installed here. If the faulting RIP is covered, the CPU is redirected
//!    to `fixup_rip`; otherwise the historical fatal-panic path is taken.
//!
//! ## Why the table is empty in this PR
//!
//! Populating the table requires a stable way to *name* the start/end/fixup
//! RIPs of an unsafe copy block, which in turn requires either (a) a
//! Linux-style `.ex_table` linker section fed by an `asm!(".pushsection …")`
//! macro at every covered copy site, or (b) an assembly-only user-copy
//! primitive that the kernel calls into. Both are follow-up work: this PR
//! only lands the *plumbing* so the follow-up populates a single, well-
//! defined array and does not have to modify the fault path again.
//!
//! An empty extable means [`try_recover`] always returns `None`, which means
//! [`huesos_arch::fault::try_kernel_recover`] always returns `None`, which
//! means the fault path is byte-for-byte identical to the pre-hook kernel.
//! Deleting the [`install`] call — or leaving `EXTABLE_ENTRIES` empty, which
//! is the current state — is therefore always a safe rollback.
//!
//! See the reverted `f7b74b2..651cc1c` series in git history for the
//! previous attempt that shipped populated entries and the fault-path
//! change in one PR; this PR intentionally splits that into two steps.

use huesos_arch::fault::FaultInfo;
use huesos_extable::{Extable, FixupRange};

/// Kernel exception table. Kept empty in this PR so the fault path stays
/// byte-for-byte identical to the historical kernel (see the module docs).
/// The follow-up PR populates this from a `.ex_table` linker section fed
/// by a `user_access_ok!` macro at each covered copy site.
///
/// `#[rustfmt::skip]` reserves the tabular one-entry-per-line layout the
/// follow-up will use even though the array is empty today.
#[rustfmt::skip]
static EXTABLE_ENTRIES: [FixupRange; 0] = [];

/// Ring-0 fault-recovery hook wired into [`huesos_arch::fault`].
///
/// Called by the `#PF` handler only for CPL0 faults, only after the frame
/// is captured, and only if the arch-layer static hook slot has been
/// registered by [`install`]. Must be effectively pure: no allocation,
/// no blocking lock, no I/O.
fn try_recover(info: FaultInfo) -> Option<u64> {
    // Build the borrow every call: EXTABLE_ENTRIES is a `'static` slice and
    // `Extable::new_sorted` is a cheap validated wrapper. When the array is
    // empty this reduces to a single bounds-check + `None` return.
    let extable = Extable::new_sorted(&EXTABLE_ENTRIES)?;
    match huesos_extable::resolve_kernel_fault(info.instruction_pointer, &extable) {
        huesos_extable::FaultResolution::Recover { fixup_rip } => Some(fixup_rip),
        huesos_extable::FaultResolution::Fatal => None,
    }
}

/// Register the recoverable-copy hook with the architecture layer. Idempotent
/// and safe to call once during kernel init; a second call would simply
/// overwrite the hook pointer with the same value.
pub fn install() {
    huesos_arch::fault::set_kernel_recover_hook(try_recover);
}

/// Extable entry count, exposed for diagnostics and host tests. Kept
/// separate from `EXTABLE_ENTRIES.len()` so an on-boot log line can print
/// the count without importing the slice type publicly.
pub fn entry_count() -> usize {
    EXTABLE_ENTRIES.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_arch::fault::{FaultInfo, FaultKind};

    fn fault_at(rip: u64, cs_ring: u64) -> FaultInfo {
        FaultInfo {
            kind: FaultKind::PageFault,
            instruction_pointer: rip,
            stack_pointer: 0,
            rflags: 0,
            code_segment: cs_ring,
            error_code: 0,
            fault_address: 0,
        }
    }

    #[test]
    fn empty_extable_returns_none_for_every_rip() {
        // The empty table means "no site is recoverable", so try_recover
        // must return None for every conceivable fault site including the
        // boundary values. This locks in the "safe rollback = leave the
        // array empty" invariant against future accidental non-emptiness.
        assert_eq!(try_recover(fault_at(0, 0)), None);
        assert_eq!(try_recover(fault_at(0xffff_ffff_8000_0000, 0)), None);
        assert_eq!(try_recover(fault_at(u64::MAX, 0)), None);
    }

    #[test]
    fn entry_count_matches_static_length() {
        assert_eq!(entry_count(), EXTABLE_ENTRIES.len());
    }
}
