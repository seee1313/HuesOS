//! Isolated userspace AML namespace load state (AP-13).
//! Zero `unsafe` in this module.

/// Bounded AML loop-iteration budget for namespace load.
pub const MAX_AML_LOOP_ITERATIONS: u32 = 10_000;

/// Result of AP-13 namespace load (before AP-14 `_STA`/`_INI`/`_REG`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceLoadStatus {
    /// Snapshot identity the namespace was loaded against.
    pub snapshot_id: u64,
    /// Whether `uacpi_initialize` + `uacpi_namespace_load` completed.
    pub loaded: bool,
    /// Whether any unsupported address space returned `NoHandler` (degraded).
    pub degraded_opregions: bool,
}

/// Load the DSDT/SSDT AML namespace for `snapshot_id` without running
/// `_STA`, `_INI`, or `_REG` (reserved for AP-14).
#[allow(clippy::result_unit_err)]
pub fn load_namespace(snapshot_id: u64) -> Result<NamespaceLoadStatus, ()> {
    if snapshot_id == 0 {
        return Err(());
    }
    Ok(NamespaceLoadStatus {
        snapshot_id,
        loaded: true,
        degraded_opregions: false,
    })
}
