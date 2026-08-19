//! Isolated full-uACPI Ring-3 build scaffold.
//!
//! This crate deliberately compiles the complete pinned uACPI source set
//! separately from the kernel's permanent `UACPI_BAREBONES_MODE` crate. AP-4
//! activates process-local primitives; AP-5 adds only read-only translation
//! from an installed archive-v2 VMO. It grants no raw physical map, SystemIO,
//! SystemMemory, PCI, interrupt, reset, or power authority. Later AP stages
//! replace callback families only after their capability protocols and negative
//! tests exist.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod archive;
mod primitives;

pub use archive::{install_archive, ArchiveInstallError, ArchiveMappingInfo};
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
    /// Process-local primitives and archive-only table translation are ready;
    /// every hardware callback remains denied or unavailable.
    ArchiveMapReady,
}

/// Return the current immutable runtime build stage.
pub const fn runtime_stage() -> RuntimeStage {
    RuntimeStage::ArchiveMapReady
}
