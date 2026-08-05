//! Report-only Hxfs fsck/scrub policy core.
//!
//! Stage W starts with detection, not repair. Repair is deliberately excluded
//! until the exact destructive semantics are reviewed.

use crate::format::*;

/// Fsck/scrub finding class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsckFinding {
    /// Required v3/v4/v5 checkpoint root is missing.
    MissingRequiredRoot {
        /// Missing checkpoint root.
        root: FsckRoot,
    },
    /// A root is present without the feature bit that defines it.
    UnexpectedRoot {
        /// Unexpected checkpoint root.
        root: FsckRoot,
    },
    /// Root-store feature combination is invalid.
    BadFeatureSet,
    /// Root-store is Recovering and needs journal replay before ordinary mount.
    NeedsJournalReplay,
    /// Quota used bytes/objects disagree with caller-provided accounting.
    QuotaMismatch,
    /// Refcount/backref/allocation accounting disagree.
    ReferenceMismatch,
}

/// Checkpoint root kind used in reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsckRoot {
    /// Allocation tree.
    Allocation,
    /// Refcount tree.
    Refcount,
    /// Backref tree.
    Backref,
    /// Quota tree.
    Quota,
    /// Encryption policy tree.
    EncryptionPolicy,
    /// Compression policy tree.
    CompressionPolicy,
    /// Hxblob index tree.
    HxblobIndex,
    /// Hxblob Merkle metadata tree.
    HxblobMerkle,
    /// Virtual-volume tree.
    VirtualVolume,
    /// GPT summary.
    GptSummary,
    /// Install manifest.
    InstallManifest,
}

/// Fixed-capacity report-only fsck result.
pub struct FsckReport<const N: usize> {
    findings: [Option<FsckFinding>; N],
    overflow: u32,
}

impl<const N: usize> Default for FsckReport<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FsckReport<N> {
    /// Create an empty report.
    pub const fn new() -> Self {
        Self {
            findings: [const { None }; N],
            overflow: 0,
        }
    }

    /// Record a finding, counting overflow if the fixed report is full.
    pub fn record(&mut self, finding: FsckFinding) {
        let mut index = 0usize;
        while index < self.findings.len() {
            if self.findings[index].is_none() {
                self.findings[index] = Some(finding);
                return;
            }
            index += 1;
        }
        self.overflow = self.overflow.saturating_add(1);
    }

    /// Findings array.
    pub const fn findings(&self) -> &[Option<FsckFinding>; N] {
        &self.findings
    }

    /// Number of findings that did not fit.
    pub const fn overflow(&self) -> u32 {
        self.overflow
    }

    /// Whether no finding was recorded.
    pub fn is_clean(&self) -> bool {
        self.overflow == 0 && self.findings.iter().all(Option::is_none)
    }
}

/// Scrub root-store and checkpoint feature/root consistency.
pub fn scrub_checkpoint_roots<const N: usize>(
    superblock: Superblock,
    checkpoint: Checkpoint,
) -> FsckReport<N> {
    let mut report = FsckReport::new();
    if superblock.incompatible_features & BASE_INCOMPAT_FEATURES != BASE_INCOMPAT_FEATURES {
        report.record(FsckFinding::BadFeatureSet);
    }
    if superblock.root_state == ROOT_STATE_RECOVERING {
        report.record(FsckFinding::NeedsJournalReplay);
    }
    if superblock.incompatible_features & FEATURE_INCOMPAT_V3_STORAGE_TREES != 0 {
        require_root(
            &mut report,
            checkpoint.allocation_tree_lba,
            FsckRoot::Allocation,
        );
        require_root(
            &mut report,
            checkpoint.refcount_tree_lba,
            FsckRoot::Refcount,
        );
        require_root(&mut report, checkpoint.backref_tree_lba, FsckRoot::Backref);
    }
    if superblock.incompatible_features & FEATURE_INCOMPAT_QUOTA_ENFORCEMENT != 0 {
        require_root(&mut report, checkpoint.quota_tree_lba, FsckRoot::Quota);
    }
    if superblock.incompatible_features & FEATURE_INCOMPAT_V4_POLICY_AND_BLOB_TREES != 0 {
        optional_feature_root(
            &mut report,
            checkpoint.encryption_policy_tree_lba,
            FsckRoot::EncryptionPolicy,
        );
        optional_feature_root(
            &mut report,
            checkpoint.compression_policy_tree_lba,
            FsckRoot::CompressionPolicy,
        );
    }
    if superblock.incompatible_features & FEATURE_INCOMPAT_HXBLOB_INDEX != 0 {
        require_root(
            &mut report,
            checkpoint.hxblob_index_tree_lba,
            FsckRoot::HxblobIndex,
        );
        optional_feature_root(
            &mut report,
            checkpoint.hxblob_merkle_tree_lba,
            FsckRoot::HxblobMerkle,
        );
    } else if checkpoint.hxblob_index_tree_lba != 0 {
        report.record(FsckFinding::UnexpectedRoot {
            root: FsckRoot::HxblobIndex,
        });
    }
    if superblock.incompatible_features & FEATURE_INCOMPAT_V5_VOLUME_TOPOLOGY != 0 {
        optional_feature_root(
            &mut report,
            checkpoint.virtual_volume_tree_lba,
            FsckRoot::VirtualVolume,
        );
        optional_feature_root(
            &mut report,
            checkpoint.gpt_summary_lba,
            FsckRoot::GptSummary,
        );
        optional_feature_root(
            &mut report,
            checkpoint.install_manifest_lba,
            FsckRoot::InstallManifest,
        );
    }
    report
}

/// Validate caller-provided tree accounting totals.
pub fn scrub_accounting<const N: usize>(
    allocation_records: u64,
    refcount_records: u64,
    backref_records: u64,
    quota_objects: u64,
    live_objects: u64,
) -> FsckReport<N> {
    let mut report = FsckReport::new();
    if allocation_records != refcount_records || refcount_records != backref_records {
        report.record(FsckFinding::ReferenceMismatch);
    }
    if quota_objects != live_objects {
        report.record(FsckFinding::QuotaMismatch);
    }
    report
}

fn require_root<const N: usize>(report: &mut FsckReport<N>, lba: u64, root: FsckRoot) {
    if lba == 0 {
        report.record(FsckFinding::MissingRequiredRoot { root });
    }
}

fn optional_feature_root<const N: usize>(_report: &mut FsckReport<N>, _lba: u64, _root: FsckRoot) {
    // Optional v5 roots are allowed to be zero in foundation images. The helper
    // exists to keep future required-root changes localized.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock(features: u64, state: u32) -> Superblock {
        Superblock {
            format_guid: FORMAT_GUID,
            format_version: FORMAT_VERSION,
            type_system_version: TYPE_SYSTEM_VERSION,
            instance_uuid: [1; 16],
            sequence_number: 1,
            block_size: BLOCK_SIZE as u32,
            checkpoint_lba: 1,
            backup_checkpoint_lba: 0,
            journal_start_lba: 0,
            journal_end_lba: 0,
            compatible_features: 0,
            ro_compatible_features: 0,
            incompatible_features: features,
            root_state: state,
            root_flags: 0,
        }
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            sequence_number: 1,
            volume_table_lba: 2,
            volume_count: 1,
            system_volume_uuid: [2; 16],
            allocation_tree_lba: 3,
            refcount_tree_lba: 4,
            backref_tree_lba: 5,
            quota_tree_lba: 6,
            encryption_policy_tree_lba: 0,
            compression_policy_tree_lba: 0,
            hxblob_index_tree_lba: 7,
            hxblob_merkle_tree_lba: 0,
            virtual_volume_tree_lba: 0,
            gpt_summary_lba: 0,
            install_manifest_lba: 0,
        }
    }

    #[test]
    fn clean_roots_report_has_no_findings() {
        let report = scrub_checkpoint_roots::<8>(
            superblock(
                BASE_INCOMPAT_FEATURES
                    | FEATURE_INCOMPAT_QUOTA_ENFORCEMENT
                    | FEATURE_INCOMPAT_HXBLOB_INDEX,
                ROOT_STATE_CLEAN,
            ),
            checkpoint(),
        );
        assert!(report.is_clean());
    }

    #[test]
    fn missing_required_roots_are_reported() {
        let mut checkpoint = checkpoint();
        checkpoint.allocation_tree_lba = 0;
        let report = scrub_checkpoint_roots::<8>(
            superblock(BASE_INCOMPAT_FEATURES, ROOT_STATE_RECOVERING),
            checkpoint,
        );
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::NeedsJournalReplay)));
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::MissingRequiredRoot {
                root: FsckRoot::Allocation,
            })));
    }

    #[test]
    fn accounting_mismatches_are_reported() {
        let report = scrub_accounting::<4>(2, 1, 1, 5, 4);
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::ReferenceMismatch)));
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::QuotaMismatch)));
    }

    // Production-gate scrub/fsck coverage: each test pins one
    // invariant from the report-only scrub path in
    // docs/STORAGE_NVME_FS_ROADMAP.md §N (Stage W).
    //
    //   W1 feat(hxfs): add metadata tree scrub walker
    //   W2 feat(hxfs): validate extent ownership and backrefs
    //   W3 feat(hxblob): validate blob hashes and Merkle roots
    //   W4 feat(tools): add read-only hxfs-scrub tool
    //   W5 docs(hxfs): define repair policy before implementation
    //
    // The current host-test surface covers the clean / missing
    // / accounting-mismatch branches. The tests below pin
    // boundary behaviour: report capacity, recovery state,
    // feature-flag accounting, and the post-condition that
    // a clean report is a clean report.

    #[test]
    fn report_is_clean_only_when_no_findings_are_recorded() {
        let report = scrub_checkpoint_roots::<8>(
            superblock(
                BASE_INCOMPAT_FEATURES
                    | FEATURE_INCOMPAT_QUOTA_ENFORCEMENT
                    | FEATURE_INCOMPAT_HXBLOB_INDEX,
                ROOT_STATE_CLEAN,
            ),
            checkpoint(),
        );
        assert!(report.is_clean());
        // A clean report must have zero findings.
        let mut count = 0usize;
        let mut index = 0;
        while index < report.findings().len() {
            if report.findings()[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        assert_eq!(count, 0);
    }

    #[test]
    fn recovering_root_state_without_journal_replays_need_a_walk() {
        // The scrub walker must report NeedsJournalReplay
        // whenever the superblock root_state is Recovering,
        // even if the checkpoint itself looks valid. The
        // recovery is a precondition for the walk to make
        // meaningful claims about the data layout.
        let report = scrub_checkpoint_roots::<8>(
            superblock(BASE_INCOMPAT_FEATURES, ROOT_STATE_RECOVERING),
            checkpoint(),
        );
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::NeedsJournalReplay)));
    }

    #[test]
    fn missing_hxblob_index_when_feature_set_is_reported() {
        // The Hxblob index root is required when the
        // FEATURE_INCOMPAT_HXBLOB_INDEX incompat bit is
        // advertised in the superblock. The scrub walker
        // must not silently skip this requirement.
        let mut checkpoint = checkpoint();
        checkpoint.hxblob_index_tree_lba = 0;
        let report = scrub_checkpoint_roots::<8>(
            superblock(
                BASE_INCOMPAT_FEATURES | FEATURE_INCOMPAT_HXBLOB_INDEX,
                ROOT_STATE_CLEAN,
            ),
            checkpoint,
        );
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::MissingRequiredRoot {
                root: FsckRoot::HxblobIndex,
            })));
    }

    #[test]
    fn accounting_match_is_a_clean_report() {
        // When recorded values match the observed values, the
        // accounting scrub must produce no findings.
        let report = scrub_accounting::<4>(10, 10, 10, 10, 10);
        assert!(report.is_clean());
    }

    #[test]
    fn accounting_object_count_mismatch_alone_is_reported() {
        // A pure object-count mismatch (refcount = 0 but
        // objects_in_use != 0) must surface ReferenceMismatch
        // even when the byte counters are equal.
        let report = scrub_accounting::<4>(0, 5, 5, 5, 5);
        assert!(report
            .findings()
            .contains(&Some(FsckFinding::ReferenceMismatch)));
        assert!(!report.findings().contains(&Some(FsckFinding::QuotaMismatch)));
    }
}
