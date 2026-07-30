//! Hxfs scrub/fsck validation primitives.
//!
//! Stage I provides report structures and metadata validation helpers for online
//! scrub. Repair is intentionally out of scope.

use crate::crc32c::metadata_crc32c;
use crate::format::{BlockHeader, BLOCK_SIZE};
use crate::{validate_metadata_block, HxfsError};

/// Scrub finding kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubFindingKind {
    /// Metadata checksum failed.
    BadChecksum,
    /// Metadata block type/owner/lba was unexpected.
    BadMetadata,
    /// Tree ordering or shape is invalid.
    BadTree,
}

/// One scrub finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubFinding {
    /// LBA where the issue was found.
    pub lba: u64,
    /// Finding kind.
    pub kind: ScrubFindingKind,
}

/// Fixed-capacity scrub report.
pub struct ScrubReport<const N: usize> {
    findings: [Option<ScrubFinding>; N],
    total_findings: u64,
}

impl<const N: usize> Default for ScrubReport<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ScrubReport<N> {
    /// Empty report.
    pub const fn new() -> Self {
        Self {
            findings: [const { None }; N],
            total_findings: 0,
        }
    }

    /// Record a finding. Once the inline table is full, only the total counter
    /// continues to grow.
    pub fn record(&mut self, finding: ScrubFinding) {
        self.total_findings = self.total_findings.saturating_add(1);
        if let Some(slot) = self.findings.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(finding);
        }
    }

    /// Total findings, including those beyond inline capacity.
    pub const fn total_findings(&self) -> u64 {
        self.total_findings
    }

    /// Inline retained findings.
    pub fn findings(&self) -> &[Option<ScrubFinding>; N] {
        &self.findings
    }

    /// Whether no findings were recorded.
    pub const fn is_clean(&self) -> bool {
        self.total_findings == 0
    }
}

/// Validate one metadata block and record a scrub finding on failure.
pub fn scrub_metadata_block<const N: usize>(
    report: &mut ScrubReport<N>,
    block: &[u8; BLOCK_SIZE],
    expected_lba: u64,
    expected_type: u32,
    expected_owner: u64,
) -> Result<BlockHeader, HxfsError> {
    match validate_metadata_block(block, expected_lba, expected_type, expected_owner) {
        Ok(header) => Ok(header),
        Err(HxfsError::BadChecksum) => {
            report.record(ScrubFinding {
                lba: expected_lba,
                kind: ScrubFindingKind::BadChecksum,
            });
            Err(HxfsError::BadChecksum)
        }
        Err(error) => {
            report.record(ScrubFinding {
                lba: expected_lba,
                kind: ScrubFindingKind::BadMetadata,
            });
            Err(error)
        }
    }
}

/// Quick checksum-only validation useful for background scans.
pub fn checksum_matches(block: &[u8; BLOCK_SIZE], stored_crc32c: u32) -> bool {
    metadata_crc32c(block) == stored_crc32c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_tracks_overflow_count() {
        let mut report = ScrubReport::<1>::new();
        report.record(ScrubFinding {
            lba: 1,
            kind: ScrubFindingKind::BadTree,
        });
        report.record(ScrubFinding {
            lba: 2,
            kind: ScrubFindingKind::BadTree,
        });
        assert_eq!(report.total_findings(), 2);
        assert!(report.findings()[0].is_some());
    }
}
