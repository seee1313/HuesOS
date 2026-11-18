//! AP-15 PCI root-bridge (`PNP0A03`/`PNP0A08`) discovery and `HPCI` table
//! construction over the isolated Ring-3 uACPI namespace.

use huesos_abi::hmcf;
use huesos_abi::pci::{
    self, Aperture, ApertureKind, ConfigBackend, ConsistencyError, RootBridge, RootBridgeTable,
    MAX_APERTURES, MAX_ENCODED_BYTES, MAX_ROOTS,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPciRootDesc {
    segment: u16,
    start_bus: u8,
    end_bus: u8,
    has_bus_range: u8,
    has_bbn: u8,
    aperture_start: u16,
    aperture_count: u16,
    _pad: u16,
    flags: u32,
}

impl RawPciRootDesc {
    const fn zero() -> Self {
        Self {
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            has_bus_range: 0,
            has_bbn: 0,
            aperture_start: 0,
            aperture_count: 0,
            _pad: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPciApertureDesc {
    root_index: u16,
    kind: u8,
    _pad: u8,
    flags: u32,
    pci_base: u64,
    cpu_base: u64,
    len: u64,
}

impl RawPciApertureDesc {
    const fn zero() -> Self {
        Self {
            root_index: 0,
            kind: 0,
            _pad: 0,
            flags: 0,
            pci_base: 0,
            cpu_base: 0,
            len: 0,
        }
    }
}

#[repr(C)]
struct RawPciRootsOut {
    root_count: u16,
    aperture_count: u16,
    _pad: u32,
    roots: [RawPciRootDesc; MAX_ROOTS],
    apertures: [RawPciApertureDesc; MAX_APERTURES],
}

impl RawPciRootsOut {
    const fn zero() -> Self {
        Self {
            root_count: 0,
            aperture_count: 0,
            _pad: 0,
            roots: [RawPciRootDesc::zero(); MAX_ROOTS],
            apertures: [RawPciApertureDesc::zero(); MAX_APERTURES],
        }
    }
}

extern "C" {
    fn hues_uacpi_collect_pci_roots(out: *mut RawPciRootsOut) -> i32;
}

/// Failure while collecting or validating `HPCI` root descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCollectError {
    /// Runtime capabilities or HMCF view were invalid.
    NotReady,
    /// uACPI C evaluation returned an error status.
    UacpiStatus(i32),
    /// An AML error or denied/unsupported OpRegion occurred during root eval.
    DegradedEvaluation,
    /// Root table was empty, invalid, or inconsistent with HMCF.
    Consistency(ConsistencyError),
    /// Encoding the `HPCI` binary blob failed.
    Encode(pci::Error),
}

/// Deterministic root identity bound to `(snapshot_id, segment, start_bus, end_bus)`.
fn canonical_root_id(snapshot_id: u64, segment: u16, start_bus: u8, end_bus: u8) -> u64 {
    let mut x = snapshot_id.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (u64::from(segment) << 16)
        ^ (u64::from(start_bus) << 8)
        ^ u64::from(end_bus);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x.max(1)
}

fn aperture_kind_from_raw(raw: u8) -> Option<ApertureKind> {
    match raw {
        1 => Some(ApertureKind::Io),
        2 => Some(ApertureKind::Mmio32),
        3 => Some(ApertureKind::Mmio64),
        4 => Some(ApertureKind::PrefetchableMemory),
        _ => None,
    }
}

/// Discover `PNP0A03`/`PNP0A08` PCI roots from the initialized uACPI
/// namespace, evaluate bounded `_SEG`, `_BBN`, and `_CRS` resources, validate
/// consistency against `hmcf_bytes`, and encode the canonical `HPCI` blob.
pub fn collect_and_encode_hpci(
    snapshot_id: u64,
    hmcf_bytes: &[u8],
    out_buf: &mut [u8; MAX_ENCODED_BYTES],
) -> Result<(usize, RootBridgeTable), RootCollectError> {
    if snapshot_id == 0 || !crate::broker_installed() {
        return Err(RootCollectError::NotReady);
    }
    let hmcf_view = hmcf::decode(hmcf_bytes).map_err(|_| RootCollectError::NotReady)?;

    crate::broker::clear_degraded_opregion();
    crate::broker::clear_logged_aml_error();

    let mut raw = RawPciRootsOut::zero();
    // SAFETY: `hues_uacpi_collect_pci_roots` takes a valid mutable pointer to
    // stack-allocated `RawPciRootsOut` and writes only bounded fixed arrays.
    let status = unsafe { hues_uacpi_collect_pci_roots(&mut raw as *mut RawPciRootsOut) };
    if status != 0 {
        return Err(RootCollectError::UacpiStatus(status));
    }
    if crate::broker::had_logged_aml_error() || crate::broker::had_degraded_opregion() {
        return Err(RootCollectError::DegradedEvaluation);
    }

    let root_count = usize::from(raw.root_count);
    let aperture_count = usize::from(raw.aperture_count);
    if root_count == 0 || root_count > MAX_ROOTS || aperture_count > MAX_APERTURES {
        return Err(RootCollectError::Consistency(ConsistencyError::EmptyRoots));
    }

    let mut table = RootBridgeTable::empty();
    for raw_root in &raw.roots[..root_count] {
        let mut matched_ecam = None;
        for record in hmcf_view.records() {
            if record.segment == raw_root.segment
                && raw_root.start_bus >= record.start_bus
                && raw_root.end_bus <= record.end_bus
            {
                let bus_off = u64::from(raw_root.start_bus - record.start_bus);
                if let Some(base) = record.ecam_base.checked_add(bus_off << 20) {
                    matched_ecam = Some(base);
                }
                break;
            }
        }
        let Some(ecam_base) = matched_ecam else {
            return Err(RootCollectError::Consistency(
                ConsistencyError::MissingHmcfCoverage,
            ));
        };
        let root = RootBridge {
            root_id: canonical_root_id(
                snapshot_id,
                raw_root.segment,
                raw_root.start_bus,
                raw_root.end_bus,
            ),
            segment: raw_root.segment,
            start_bus: raw_root.start_bus,
            end_bus: raw_root.end_bus,
            backend: ConfigBackend::Ecam,
            flags: raw_root.flags,
            ecam_base,
            aperture_start: raw_root.aperture_start,
            aperture_count: raw_root.aperture_count,
        };
        if !table.push_root(root) {
            return Err(RootCollectError::Encode(pci::Error::BadLength));
        }
    }

    for raw_ap in &raw.apertures[..aperture_count] {
        let Some(kind) = aperture_kind_from_raw(raw_ap.kind) else {
            return Err(RootCollectError::Encode(pci::Error::UnknownKind));
        };
        let ap = Aperture {
            root_index: raw_ap.root_index,
            kind,
            flags: raw_ap.flags,
            pci_base: raw_ap.pci_base,
            cpu_base: raw_ap.cpu_base,
            len: raw_ap.len,
        };
        if !table.push_aperture(ap) {
            return Err(RootCollectError::Encode(pci::Error::BadLength));
        }
    }

    pci::validate_roots_and_hmcf(&table, &hmcf_view).map_err(RootCollectError::Consistency)?;
    let encoded_len = pci::encode(&table, out_buf).map_err(RootCollectError::Encode)?;
    Ok((encoded_len, table))
}
