//! Snapshot-bound PCI configuration mint authority ABI (AP-8).
//!
//! HuesOS never lets ring 3 name a raw physical range for PCI
//! configuration access. Instead, the firmware publishes its ECAM windows
//! in the `MCFG` table; the boot kernel snapshots the validated archive,
//! the isolated ACPI manager re-decodes `MCFG` and publishes a bounded
//! `HMCF` image, and DriverManager retains it for the current supervised
//! generation. This module defines the **request** a caller presents to
//! turn that retained evidence into capabilities, and the pure cross-check
//! the kernel applies before minting anything.
//!
//! The request never carries a physical address. It carries the firmware
//! snapshot identity and the supervised producer generation bound by the
//! `HMCF` image itself, so a stale archive or a replayed generation cannot
//! be used to mint authority for another boot's firmware layout.
//!
//! ## What the kernel checks (in order)
//!
//! 1. the caller presented the unique `PciConfigMint` resource handle;
//! 2. the `HMCF` bytes decode and validate (format, sizes, canonical order,
//!    checksum — see [`crate::hmcf`]);
//! 3. the image's `firmware_snapshot_id` equals both the request's and the
//!    identity the boot kernel stashed from its own archive-v2 build, and
//!    the image's `producer_generation` equals the request's;
//! 4. every `HMCF` record matches **exactly** one window the boot kernel
//!    independently decoded from the bound archive's `MCFG` (same segment,
//!    same bus range, same base, same span) — a subset is fine, every
//!    record is mandatory; anything else is rejected, including widened
//!    or otherwise reshaped requests;
//! 5. no minted window overlaps general-purpose usable RAM;
//! 6. the range is not already held (an exact duplicate request fails as
//!    [`crate::ErrorCode::Busy`]).
//!
//! Checksums in `HMCF` and `MCFG` are consistency checks, not
//! authentication; authenticity comes from the immutable VMOs and the
//! kernel's independent decoding of the boot archive. Generation
//! freshness relative to the *live* supervisor is enforced by
//! DriverManager, which owns the supervision timeline; the kernel
//! enforces the archive/snapshot binding and the window equality.

use crate::hmcf::{HmcfRecord, HmcfView};
use crate::HandleValue;

/// Wire version of [`PciConfigMintRequest`].
pub const MINT_REQUEST_VERSION: u16 = 1;
/// Mint one read-only `Mmio` capability per window carried by the
/// bound `HMCF` image.
pub const MINT_KIND_ECAM_WINDOWS: u16 = 1;
/// Mint the fixed legacy configuration I/O-port authority
/// (`0xCF8..0x100`, mechanism #1) for PCI segment 0.
pub const MINT_KIND_LEGACY_CF8_CFC: u16 = 2;
/// Base of the fixed legacy configuration I/O-port window.
pub const LEGACY_CF8_CFC_BASE: u64 = 0x0CF8;
/// Width of the fixed legacy configuration I/O-port window: `0xCF8`
/// (address) through `0xCFF` (data) inclusive.
pub const LEGACY_CF8_CFC_LEN: u64 = 8;
/// Encoded size of [`PciConfigMintRequest`].
pub const MINT_REQUEST_BYTES: usize = 32;

/// Bounded mint request. Passed by pointer to
/// [`crate::Syscall::PciConfigMint`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciConfigMintRequest {
    /// Must equal [`MINT_REQUEST_VERSION`].
    pub version: u16,
    /// One of [`MINT_KIND_ECAM_WINDOWS`] or [`MINT_KIND_LEGACY_CF8_CFC`];
    /// anything else is rejected.
    pub kind: u16,
    /// Reserved; must be zero.
    pub reserved: u32,
    /// Firmware snapshot identity the caller expects to be bound to the
    /// `HMCF` image. Must equal both the image's and the kernel-stashed
    /// archive-v2 identity.
    pub firmware_snapshot_id: u64,
    /// Supervised producer generation the caller expects to be bound to
    /// the `HMCF` image. Must equal the image's.
    pub producer_generation: u64,
    /// Caller-owned, read-only handle to the `HMCF` image.
    pub hmcf_vmo: HandleValue,
}

impl Default for PciConfigMintRequest {
    fn default() -> Self {
        Self {
            version: MINT_REQUEST_VERSION,
            kind: MINT_KIND_ECAM_WINDOWS,
            reserved: 0,
            firmware_snapshot_id: 0,
            producer_generation: 0,
            hmcf_vmo: 0,
        }
    }
}

/// Structural rejection reasons for [`PciConfigMintRequest::validate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MintRequestError {
    /// Unsupported `version`.
    Version,
    /// `kind` is not one of the defined mint kinds.
    Kind,
    /// Reserved field non-zero.
    Reserved,
    /// `firmware_snapshot_id` or `producer_generation` is zero.
    Identity,
    /// `hmcf_vmo` is not a legal (non-zero) handle value.
    Handle,
}

impl PciConfigMintRequest {
    /// Validate the fixed parts of the request. Does not look at the
    /// `HMCF` image itself; the kernel performs that against the VMO.
    pub const fn validate(&self) -> Result<(), MintRequestError> {
        if self.version != MINT_REQUEST_VERSION {
            return Err(MintRequestError::Version);
        }
        if !matches!(self.kind, MINT_KIND_ECAM_WINDOWS | MINT_KIND_LEGACY_CF8_CFC) {
            return Err(MintRequestError::Kind);
        }
        if self.reserved != 0 {
            return Err(MintRequestError::Reserved);
        }
        if self.firmware_snapshot_id == 0 || self.producer_generation == 0 {
            return Err(MintRequestError::Identity);
        }
        if self.hmcf_vmo == 0 {
            return Err(MintRequestError::Handle);
        }
        Ok(())
    }
}

/// One validated config-window allocation from the bound archive's
/// `MCFG` table, as decoded by the boot kernel. This is the kernel's
/// independent view the `HMCF` image must agree with exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamAllocation {
    /// PCI segment group.
    pub segment: u16,
    /// First bus number covered by the window.
    pub start_bus: u8,
    /// Last bus number covered by the window.
    pub end_bus: u8,
    /// Physical base of the ECAM window (page/MiB aligned).
    pub ecam_base: u64,
    /// Window width in bytes; always `(end_bus - start_bus + 1) * 1 MiB`.
    pub span_bytes: u64,
}

impl EcamAllocation {
    /// Whether `record` names exactly this allocation — same segment,
    /// same bus range, same base, same span.
    pub const fn matches_record(&self, record: &HmcfRecord) -> bool {
        record.segment == self.segment
            && record.start_bus == self.start_bus
            && record.end_bus == self.end_bus
            && record.ecam_base == self.ecam_base
            && record.span_bytes == self.span_bytes
    }
}

/// Failure of the `HMCF` ↔ bound-`MCFG` cross-check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossCheckError {
    /// No window in the bound `MCFG` matches an `HMCF` record exactly.
    /// This covers widening, shifting, reshaping, and replaying a
    /// record that does not belong to this firmware snapshot.
    UnknownWindow {
        /// Index of the offending record in canonical wire order.
        record_index: usize,
    },
    /// A minted window overlaps general-purpose usable RAM.
    RamAlias {
        /// Index of the offending record in canonical wire order.
        record_index: usize,
    },
}

/// Verify that every record of `view` is exactly backed by one window in
/// `windows` and that no record overlaps general-purpose usable RAM.
///
/// `windows` must come from the boot kernel's own decode of the bound
/// archive's `MCFG` (at most [`crate::hmcf::MAX_RECORDS`] entries);
/// `usable_ram` is the boot memory map filtered to usable RAM as
/// `(base, length)` pairs. Returns the number of records validated
/// (equal to `view.record_count()`).
///
/// Subset semantics: the image may claim fewer windows than the `MCFG`
/// publishes (a producer may legitimately withhold a window it has no
/// use for); it may never claim one the `MCFG` does not publish, nor
/// reshape one it does.
pub fn verify_hmcf_against_mcfg(
    view: &HmcfView<'_>,
    windows: &[EcamAllocation],
    usable_ram: &[(u64, u64)],
) -> Result<usize, CrossCheckError> {
    for (record_index, record) in view.records().enumerate() {
        let matched = windows.iter().any(|window| window.matches_record(&record));
        if !matched {
            return Err(CrossCheckError::UnknownWindow { record_index });
        }
        let base = record.ecam_base;
        let length = record.span_bytes;
        if ram_alias(base, length, usable_ram) {
            return Err(CrossCheckError::RamAlias { record_index });
        }
    }
    Ok(view.record_count())
}

/// Whether `[base, base+length)` intersects any usable RAM region.
fn ram_alias(base: u64, length: u64, usable_ram: &[(u64, u64)]) -> bool {
    let Some(end) = base.checked_add(length) else {
        // An overflowing range is not representable; treat it as an
        // alias rather than minting something unverifiable.
        return true;
    };
    usable_ram
        .iter()
        .any(|&(ram_base, ram_len)| match ram_base.checked_add(ram_len) {
            Some(ram_end) => base < ram_end && ram_base < end,
            None => true,
        })
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::hmcf::{decode, encode, HmcfRecord, MAX_BYTES, MAX_RECORDS};

    const SNAPSHOT: u64 = 0x1122_3344_5566_7788;
    const GENERATION: u64 = 42;

    const FALLBACK_RECORD: HmcfRecord = HmcfRecord {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        ecam_base: 0,
        span_bytes: 1 << 20,
        flags: 0,
    };

    macro_rules! decode_or_return {
        ($image:expr) => {
            match decode(&$image) {
                Ok(view) => view,
                Err(_) => {
                    assert!(false, "decode must succeed");
                    return;
                }
            }
        };
    }

    fn record(segment: u16, start_bus: u8, end_bus: u8, ecam_base: u64) -> HmcfRecord {
        match HmcfRecord::new(segment, start_bus, end_bus, ecam_base) {
            Ok(record) => record,
            Err(_) => {
                assert!(false, "record must validate");
                FALLBACK_RECORD
            }
        }
    }

    fn allocation_for(record: &HmcfRecord) -> EcamAllocation {
        EcamAllocation {
            segment: record.segment,
            start_bus: record.start_bus,
            end_bus: record.end_bus,
            ecam_base: record.ecam_base,
            span_bytes: record.span_bytes,
        }
    }

    fn windows_from(records: &[HmcfRecord]) -> [EcamAllocation; MAX_RECORDS as usize] {
        let mut out = [EcamAllocation {
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            ecam_base: 0,
            span_bytes: 1 << 20,
        }; MAX_RECORDS as usize];
        for (index, record) in records.iter().enumerate() {
            out[index] = allocation_for(record);
        }
        out
    }

    fn image(records: &[HmcfRecord]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0u8; MAX_BYTES];
        match encode(SNAPSHOT, GENERATION, records, &mut out) {
            Ok(len) => {
                out.truncate(len);
                out
            }
            Err(_) => {
                assert!(false, "encode must succeed");
                alloc::vec::Vec::new()
            }
        }
    }

    #[test]
    fn identical_windows_pass() {
        let records = [
            record(0, 0, 255, 0xE000_0000),
            record(1, 0, 63, 0xF000_0000),
        ];
        let image = image(&records);
        let view = decode_or_return!(&image);
        let windows = windows_from(&records);
        assert_eq!(verify_hmcf_against_mcfg(&view, &windows[..2], &[]), Ok(2));
    }

    #[test]
    fn subset_of_bound_windows_passes() {
        let records = [record(0, 0, 255, 0xE000_0000)];
        let image = image(&records);
        let view = decode_or_return!(&image);
        let bound = [record(0, 0, 255, 0xE000_0000), record(7, 0, 0, 0x4000_0000)];
        let windows = windows_from(&bound);
        assert_eq!(verify_hmcf_against_mcfg(&view, &windows[..2], &[]), Ok(1));
    }

    #[test]
    fn widened_record_is_rejected() {
        let image = image(&[record(0, 0, 255, 0xE000_0000)]);
        let view = decode_or_return!(&image);
        let narrow = [EcamAllocation {
            segment: 0,
            start_bus: 0,
            end_bus: 127,
            ecam_base: 0xE000_0000,
            span_bytes: 128 * (1 << 20),
        }];
        assert_eq!(
            verify_hmcf_against_mcfg(&view, &narrow, &[]),
            Err(CrossCheckError::UnknownWindow { record_index: 0 })
        );
    }

    #[test]
    fn span_mismatch_is_rejected() {
        let image = image(&[record(0, 0, 255, 0xE000_0000)]);
        let view = decode_or_return!(&image);
        let reshaped = [EcamAllocation {
            segment: 0,
            start_bus: 0,
            end_bus: 255,
            ecam_base: 0xE000_0000,
            span_bytes: 128 * (1 << 20),
        }];
        assert_eq!(
            verify_hmcf_against_mcfg(&view, &reshaped, &[]),
            Err(CrossCheckError::UnknownWindow { record_index: 0 })
        );
    }

    #[test]
    fn foreign_replayed_window_is_rejected() {
        let image = image(&[record(9, 128, 255, 0x0200_0000)]);
        let view = decode_or_return!(&image);
        assert_eq!(
            verify_hmcf_against_mcfg(&view, &[], &[]),
            Err(CrossCheckError::UnknownWindow { record_index: 0 })
        );
        let windows = [EcamAllocation {
            segment: 9,
            start_bus: 128,
            end_bus: 255,
            ecam_base: 0x0200_0000,
            span_bytes: 128 * (1 << 20),
        }];
        assert_eq!(verify_hmcf_against_mcfg(&view, &windows, &[]), Ok(1));
    }

    #[test]
    fn usable_ram_alias_is_rejected() {
        let record = record(0, 0, 31, 0x1000_0000);
        let image = image(&[record]);
        let view = decode_or_return!(&image);
        let windows = [allocation_for(&record)];
        let ram = [(0x0800_0000u64, 0x2000_0000u64)];
        assert_eq!(
            verify_hmcf_against_mcfg(&view, &windows, &ram),
            Err(CrossCheckError::RamAlias { record_index: 0 })
        );
    }

    #[test]
    fn adjacent_ram_is_not_an_alias() {
        let record = record(0, 0, 31, 0x1000_0000);
        let image = image(&[record]);
        let view = decode_or_return!(&image);
        let windows = [allocation_for(&record)];
        let ram = [(0x0C00_0000u64, 0x0400_0000u64)];
        assert_eq!(verify_hmcf_against_mcfg(&view, &windows, &ram), Ok(1));
    }

    #[test]
    fn empty_usable_ram_map_accepts() {
        let record = record(0, 0, 255, 0xE000_0000);
        let image = image(&[record]);
        let view = decode_or_return!(&image);
        let windows = [allocation_for(&record)];
        assert_eq!(verify_hmcf_against_mcfg(&view, &windows, &[]), Ok(1));
    }

    #[test]
    fn request_validation() {
        let mut req = PciConfigMintRequest {
            version: MINT_REQUEST_VERSION,
            kind: MINT_KIND_ECAM_WINDOWS,
            reserved: 0,
            firmware_snapshot_id: 42,
            producer_generation: 3,
            hmcf_vmo: 9,
        };
        assert_eq!(req.validate(), Ok(()));
        req.version = 2;
        assert_eq!(req.validate(), Err(MintRequestError::Version));
        req.version = MINT_REQUEST_VERSION;
        req.kind = 77;
        assert_eq!(req.validate(), Err(MintRequestError::Kind));
        req.kind = MINT_KIND_LEGACY_CF8_CFC;
        req.reserved = 1;
        assert_eq!(req.validate(), Err(MintRequestError::Reserved));
        req.reserved = 0;
        req.firmware_snapshot_id = 0;
        assert_eq!(req.validate(), Err(MintRequestError::Identity));
        req.producer_generation = 0;
        req.firmware_snapshot_id = 42;
        assert_eq!(req.validate(), Err(MintRequestError::Identity));
        req.producer_generation = 3;
        req.hmcf_vmo = 0;
        assert_eq!(req.validate(), Err(MintRequestError::Handle));
        assert_eq!(
            PciConfigMintRequest::default().validate(),
            Err(MintRequestError::Identity)
        );
    }

    #[test]
    fn request_layout_is_locked() {
        assert_eq!(
            core::mem::size_of::<PciConfigMintRequest>(),
            MINT_REQUEST_BYTES
        );
        assert_eq!(MINT_KIND_ECAM_WINDOWS, 1);
        assert_eq!(MINT_KIND_LEGACY_CF8_CFC, 2);
        assert_eq!(LEGACY_CF8_CFC_BASE, 0x0CF8);
        assert_eq!(LEGACY_CF8_CFC_LEN, 8);
    }
}
