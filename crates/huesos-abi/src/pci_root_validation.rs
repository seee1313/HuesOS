//! Preliminary HPCI/HMCF consistency checks for read-only discovery.
//!
//! This module does not publish or accept a snapshot: HPCI v1 does not carry
//! snapshot or producer-generation identity, so callers must independently
//! bind a future envelope to the current supervisor generation and firmware
//! snapshot before trusting it. No resource allocation is authorized here.

use crate::{hmcf, pci};

/// Root validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid HPCI format or record geometry.
    InvalidTable,
    /// HMCF does not belong to the expected snapshot and producer generation.
    Binding,
    /// Root identities or segment/bus ranges overlap.
    RootOverlap,
    /// Two root apertures overlap in CPU or PCI address space.
    ApertureOverlap,
    /// No single HMCF window covers the root with matching ECAM geometry.
    WindowMismatch,
    /// This read-only phase does not claim routing or native control.
    UnsupportedFlags,
}

/// Check structural and cross-snapshot geometry for candidate roots.
///
/// For legacy, HMCF bounds the segment-0 bus subset but ECAM is not used.
/// For ECAM the root base must point at its first bus within the matching
/// window. Reject the entire candidate table on ambiguity. This is a pure
/// preliminary validator and does not implement per-root degradation.
pub fn validate(
    table: &pci::RootBridgeTable,
    windows: &hmcf::HmcfView<'_>,
    expected_generation: u64,
    expected_snapshot: u64,
) -> Result<(), Error> {
    pci::validate(table).map_err(|_| Error::InvalidTable)?;
    if table.root_count == 0 {
        return Err(Error::InvalidTable);
    }
    if expected_generation == 0
        || expected_snapshot == 0
        || windows
            .check_binding(expected_generation, expected_snapshot)
            .is_err()
    {
        return Err(Error::Binding);
    }
    // Wire decoding does not by itself reject overlap across HMCF records.
    // Treat either overlapping bus domains or physical windows as ambiguous.
    for (i, a) in windows.records().enumerate() {
        for b in windows.records().take(i) {
            let a_end = a
                .ecam_base
                .checked_add(a.span_bytes)
                .ok_or(Error::WindowMismatch)?;
            let b_end = b
                .ecam_base
                .checked_add(b.span_bytes)
                .ok_or(Error::WindowMismatch)?;
            if (a.segment == b.segment && a.start_bus <= b.end_bus && b.start_bus <= a.end_bus)
                || (a.ecam_base < b_end && b.ecam_base < a_end)
            {
                return Err(Error::WindowMismatch);
            }
        }
    }
    for i in 0..table.root_count {
        let root = table.roots[i];
        if root.flags != 0 {
            return Err(Error::UnsupportedFlags);
        }
        for other in &table.roots[..i] {
            if root.root_id == other.root_id
                || (root.segment == other.segment
                    && root.start_bus <= other.end_bus
                    && other.start_bus <= root.end_bus)
            {
                return Err(Error::RootOverlap);
            }
        }
        let matched = windows.records().any(|window| {
            if window.segment != root.segment
                || root.start_bus < window.start_bus
                || root.end_bus > window.end_bus
            {
                return false;
            }
            match root.backend {
                pci::ConfigBackend::LegacyIo => root.segment == 0 && root.ecam_base == 0,
                pci::ConfigBackend::Ecam => {
                    u64::from(root.start_bus - window.start_bus)
                        .checked_mul(hmcf::BUS_BYTES)
                        .and_then(|offset| window.ecam_base.checked_add(offset))
                        == Some(root.ecam_base)
                }
            }
        });
        if !matched {
            return Err(Error::WindowMismatch);
        }
    }
    for i in 0..table.aperture_count {
        let a = table.apertures[i];
        if a.flags & pci::APERTURE_FLAG_HOTPLUG_RESERVE != 0 {
            return Err(Error::UnsupportedFlags);
        }
        for b in &table.apertures[..i] {
            // I/O and memory are distinct spaces; all memory aperture kinds
            // share the same address space regardless of prefetchability.
            if (a.kind == pci::ApertureKind::Io) != (b.kind == pci::ApertureKind::Io) {
                continue;
            }
            let a_cpu_end = a.cpu_base.checked_add(a.len).ok_or(Error::InvalidTable)?;
            let b_cpu_end = b.cpu_base.checked_add(b.len).ok_or(Error::InvalidTable)?;
            let a_pci_end = a.pci_base.checked_add(a.len).ok_or(Error::InvalidTable)?;
            let b_pci_end = b.pci_base.checked_add(b.len).ok_or(Error::InvalidTable)?;
            let same_segment = table.roots[a.root_index as usize].segment
                == table.roots[b.root_index as usize].segment;
            if (a.cpu_base < b_cpu_end && b.cpu_base < a_cpu_end)
                || (same_segment && a.pci_base < b_pci_end && b.pci_base < a_pci_end)
            {
                return Err(Error::ApertureOverlap);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root(start: u8, end: u8, id: u64) -> pci::RootBridge {
        pci::RootBridge {
            root_id: id,
            segment: 0,
            start_bus: start,
            end_bus: end,
            backend: pci::ConfigBackend::Ecam,
            flags: 0,
            ecam_base: 0x8000_0000 + u64::from(start) * hmcf::BUS_BYTES,
            aperture_start: 0,
            aperture_count: 0,
        }
    }
    fn with_windows(f: impl FnOnce(hmcf::HmcfView<'_>)) {
        let Ok(rec) = hmcf::HmcfRecord::new(0, 0, 127, 0x8000_0000) else {
            assert!(false);
            return;
        };
        let mut bytes = [0; hmcf::MAX_BYTES];
        let Ok(len) = hmcf::encode(7, 3, &[rec], &mut bytes) else {
            assert!(false);
            return;
        };
        let Ok(view) = hmcf::decode(&bytes[..len]) else {
            assert!(false);
            return;
        };
        f(view);
    }
    #[test]
    fn validates_subwindows_and_binding() {
        with_windows(|view| {
            let mut t = pci::RootBridgeTable::empty();
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::InvalidTable));
            assert!(t.push_root(root(4, 7, 1)));
            assert_eq!(validate(&t, &view, 3, 7), Ok(()));
            assert_eq!(validate(&t, &view, 2, 7), Err(Error::Binding));
            t.roots[0].ecam_base += hmcf::BUS_BYTES;
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::WindowMismatch));
            t.roots[0] = root(126, 128, 1);
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::WindowMismatch));
        });
    }
    #[test]
    fn rejects_duplicate_or_overlapping_roots_and_flags() {
        with_windows(|view| {
            let mut t = pci::RootBridgeTable::empty();
            assert!(t.push_root(root(0, 9, 1)));
            assert!(t.push_root(root(9, 20, 2)));
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::RootOverlap));
            t.roots[1] = root(10, 20, 1);
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::RootOverlap));
            t.roots[1] = root(10, 20, 2);
            assert_eq!(validate(&t, &view, 3, 7), Ok(()));
            t.roots[1].flags = pci::ROOT_FLAG_NATIVE_HOTPLUG;
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::UnsupportedFlags));
        });
    }
    #[test]
    fn rejects_overlapping_translated_apertures() {
        with_windows(|view| {
            let mut t = pci::RootBridgeTable::empty();
            let mut r = root(0, 9, 1);
            r.aperture_count = 2;
            assert!(t.push_root(r));
            let a = pci::Aperture {
                root_index: 0,
                kind: pci::ApertureKind::Mmio64,
                flags: 0,
                pci_base: 0x1000,
                cpu_base: 0x4000,
                len: 0x100,
            };
            assert!(t.push_aperture(a));
            assert!(t.push_aperture(pci::Aperture {
                pci_base: 0x2000,
                cpu_base: 0x4080,
                ..a
            }));
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::ApertureOverlap));
            t.apertures[1].cpu_base = 0x5000;
            assert_eq!(validate(&t, &view, 3, 7), Ok(()));
            t.apertures[1].pci_base = 0x1080;
            assert_eq!(validate(&t, &view, 3, 7), Err(Error::ApertureOverlap));
        });
    }
}
