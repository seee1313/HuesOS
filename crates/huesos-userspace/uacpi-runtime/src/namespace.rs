//! Isolated userspace AML namespace load (AP-13) and initialization (AP-14).

use huesos_abi::acpi_manager::{INIT_DETAIL_AML_ERROR, INIT_DETAIL_PIC_FAILED};

/// Bounded AML loop-iteration timeout (seconds) enforced by uACPI.
pub const AML_LOOP_TIMEOUT_SECS: u32 = 5;

/// Bounded AML call-stack depth enforced by uACPI.
pub const AML_MAX_STACK_DEPTH: u32 = 64;

/// Bounded AML loop-iteration budget constant retained for diagnostics.
pub const MAX_AML_LOOP_ITERATIONS: u32 = 10_000;

const PHASE_LOAD: u32 = 0;
const PHASE_INITIALIZE: u32 = 1;

extern "C" {
    fn hues_uacpi_namespace_phase(phase: u32, loop_timeout_secs: u32, max_stack_depth: u32) -> i64;
}

/// Result of AP-13 namespace load (before AP-14 `_STA`/`_INI`/`_REG`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceLoadStatus {
    /// Snapshot identity the namespace was loaded against.
    pub snapshot_id: u64,
    /// Whether `uacpi_initialize` + `uacpi_namespace_load` completed.
    pub loaded: bool,
    /// Whether any unsupported or denied OpRegion access occurred during load.
    pub degraded_opregions: bool,
    /// Raw uACPI status code (0 = `UACPI_STATUS_OK`).
    pub status_code: i32,
}

/// Result of AP-14 `_PIC(IOAPIC)` + `_STA`/`_INI`/`_REG` namespace initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceInitStatus {
    /// Snapshot identity the namespace was initialized against.
    pub snapshot_id: u64,
    /// Whether `uacpi_namespace_initialize` completed.
    pub initialized: bool,
    /// Whether any OpRegion, PCI write, `_PIC`, or AML error caused degradation.
    pub degraded: bool,
    /// Whether root evaluation in AP-15 may publish HPCI (fail-closed when false).
    pub hpci_eligible: bool,
    /// Bitmask of [`huesos_abi::acpi_manager`] `INIT_DETAIL_*` degradation bits.
    pub detail_flags: u32,
    /// Raw uACPI status of `_PIC(IOAPIC)` (0 when ok or absent).
    pub pic_status: i32,
    /// Raw uACPI status of `uacpi_namespace_initialize()`.
    pub init_status: i32,
}

/// Failure while initializing uACPI and loading or initializing the namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceLoadError {
    /// Snapshot identity was zero or runtime capabilities were not installed.
    NotReady,
    /// Real uACPI C phase returned an error status.
    UacpiStatus(i32),
    /// uACPI logged a critical AML/table load error (`UACPI_LOG_ERROR`).
    AmlErrorsLogged,
}

fn run_shim_phase(phase: u32) -> i64 {
    // SAFETY: `hues_uacpi_namespace_phase` is compiled from `uacpi_shim.c` in
    // this crate and takes only plain `u32` limits. Archive, broker, and (for
    // init) mediation state are validated and installed before this call.
    unsafe { hues_uacpi_namespace_phase(phase, AML_LOOP_TIMEOUT_SECS, AML_MAX_STACK_DEPTH) }
}

/// Initialize the full uACPI runtime (`UACPI_FLAG_NO_ACPI_MODE`), install the
/// mediated `SystemMemory` OpRegion handler, and load the DSDT/SSDT AML
/// namespace for `snapshot_id` without executing `_STA`, `_INI`, or `_REG`.
pub fn load_namespace(snapshot_id: u64) -> Result<NamespaceLoadStatus, NamespaceLoadError> {
    if snapshot_id == 0 || !crate::broker_installed() {
        return Err(NamespaceLoadError::NotReady);
    }
    crate::broker::clear_degraded_opregion();
    crate::broker::clear_logged_aml_error();
    let status = run_shim_phase(PHASE_LOAD) as i32;
    if status != 0 {
        return Err(NamespaceLoadError::UacpiStatus(status));
    }
    if crate::broker::had_logged_aml_error() {
        return Err(NamespaceLoadError::AmlErrorsLogged);
    }
    Ok(NamespaceLoadStatus {
        snapshot_id,
        loaded: true,
        degraded_opregions: crate::broker::had_degraded_opregion(),
        status_code: status,
    })
}

/// Execute AP-14 namespace initialization (`_PIC(IOAPIC)` when present, plus
/// `_REG`/`_STA`/`_INI`) under bounded uACPI loop timeout and stack depth.
///
/// Any denied PCI config write, unsupported/denied OpRegion access, `_PIC`
/// failure, or logged AML error degrades cleanly: `hpci_eligible` is set to
/// `false` while base ACPI service and HMCF remain alive.
pub fn initialize_namespace(snapshot_id: u64) -> Result<NamespaceInitStatus, NamespaceLoadError> {
    if snapshot_id == 0 || !crate::broker_installed() || !crate::pci_mediation_installed() {
        return Err(NamespaceLoadError::NotReady);
    }
    crate::broker::clear_degraded_opregion();
    crate::broker::clear_logged_aml_error();
    let packed = run_shim_phase(PHASE_INITIALIZE) as u64;
    let init_status = packed as u32 as i32;
    let pic_status = (packed >> 32) as u32 as i32;
    if init_status != 0 {
        return Err(NamespaceLoadError::UacpiStatus(init_status));
    }

    let mut detail_flags = crate::broker::degradation_bits();
    if pic_status != 0 {
        detail_flags |= INIT_DETAIL_PIC_FAILED;
    }
    if crate::broker::had_logged_aml_error() {
        detail_flags |= INIT_DETAIL_AML_ERROR;
    }
    let degraded = detail_flags != 0
        || crate::broker::had_degraded_opregion()
        || crate::broker::had_logged_aml_error();

    Ok(NamespaceInitStatus {
        snapshot_id,
        initialized: true,
        degraded,
        hpci_eligible: !degraded,
        detail_flags,
        pic_status,
        init_status,
    })
}
