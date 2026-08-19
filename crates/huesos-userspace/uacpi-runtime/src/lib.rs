//! Isolated full-uACPI Ring-3 build scaffold.
//!
//! This crate deliberately compiles the complete pinned uACPI source set
//! separately from the kernel's permanent `UACPI_BAREBONES_MODE` crate. AP-4
//! activates only process-local allocation, time, synchronization, and ACPI
//! dispatch suppression. It grants no table map, SystemIO, SystemMemory, PCI,
//! interrupt, reset, or power authority. Later AP stages replace callback
//! families only after their capability protocols and negative tests exist.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod primitives;

pub use primitives::dispatch_suppressed;

/// Pinned vendored uACPI revision compiled by this runtime scaffold.
pub const UPSTREAM_REVISION: &str = "9c9b26d6291a1cdd9014cc5bb6b03e596697cbfd";

/// Whether any privileged host callback is active in this build stage.
///
/// This remains `false` for AP-3. It is a review aid, not an authorization
/// predicate; actual authority is always enforced by kernel handles/brokers.
pub const fn privileged_callbacks_enabled() -> bool {
    false
}

/// Build-stage identity used in diagnostics and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStage {
    /// Full interpreter linked with process-local primitives; every hardware
    /// callback remains denied or unavailable.
    ProcessPrimitivesReady,
}

/// Return the current immutable runtime build stage.
pub const fn runtime_stage() -> RuntimeStage {
    RuntimeStage::ProcessPrimitivesReady
}
