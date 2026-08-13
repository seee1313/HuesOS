//! Hxfs fsck/scrub policy core, plus the repair planner built on it.
//!
//! Detection came first and repair stayed out until the destructive
//! semantics were reviewed; that review is `docs/design/HXFS_REPAIR_POLICY.md`
//! and this module implements it. The planner is deliberately separate from
//! the executor: a plan can be inspected, printed, and refused without
//! anything on the volume having changed yet.

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
        assert!(!report
            .findings()
            .contains(&Some(FsckFinding::QuotaMismatch)));
    }
}

/// What a repair is permitted to do to a finding.
///
/// The class, not the finding, decides the permission. See
/// `docs/design/HXFS_REPAIR_POLICY.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairClass {
    /// The correct value is recomputable from data the volume still
    /// holds. Rewriting it discards nothing.
    Derivable,
    /// Consistency can only be restored by discarding something that
    /// might be live. Requires explicit destructive consent.
    Destructive,
    /// No independent source of truth exists. Repair would be a guess
    /// with a checksum on it, so the pass refuses instead.
    Refuse,
}

/// Classify a finding under the repair policy.
pub const fn classify(finding: FsckFinding) -> RepairClass {
    match finding {
        // Totals are a cache of the live objects; the objects win.
        FsckFinding::QuotaMismatch => RepairClass::Derivable,
        // Rebuilding reference state can drop references it cannot
        // attribute to a live owner.
        FsckFinding::ReferenceMismatch => RepairClass::Destructive,
        // The tree cannot be interpreted without its feature bit, so
        // it can only be detached, never validated.
        FsckFinding::UnexpectedRoot { .. } => RepairClass::Destructive,
        // Synthesising a missing root hides every object it indexed
        // behind a clean-looking volume.
        FsckFinding::MissingRequiredRoot { .. } => RepairClass::Refuse,
        // Clearing unknown feature bits mounts an on-disk format this
        // build does not implement.
        FsckFinding::BadFeatureSet => RepairClass::Refuse,
        // Not corruption: the journal holds the correct values and is
        // about to write them.
        FsckFinding::NeedsJournalReplay => RepairClass::Refuse,
    }
}

/// Why a repair pass declined to act.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairRefusal {
    /// The volume is mid-recovery; replay owns these values.
    JournalReplayPending,
    /// A finding with no trustworthy source of truth was present, so
    /// the whole pass refused rather than repairing around it.
    Unrepairable {
        /// The finding that forced the refusal.
        finding: FsckFinding,
    },
    /// The plan contains destructive actions and the caller did not
    /// grant destructive consent.
    ConsentRequired,
    /// More actions than the plan can hold.
    PlanOverflow,
}

/// A single intended repair action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairAction {
    /// The finding this action answers.
    pub finding: FsckFinding,
    /// The permission class the action runs under.
    pub class: RepairClass,
}

/// An ordered, inspectable set of intended repairs.
///
/// Building a plan changes nothing. A caller that wants a dry run
/// builds the plan and prints it.
pub struct RepairPlan<const N: usize> {
    actions: [Option<RepairAction>; N],
    destructive: u32,
}

impl<const N: usize> Default for RepairPlan<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RepairPlan<N> {
    /// Create an empty plan.
    pub const fn new() -> Self {
        Self {
            actions: [const { None }; N],
            destructive: 0,
        }
    }

    /// Planned actions, in the order they would be applied.
    pub const fn actions(&self) -> &[Option<RepairAction>; N] {
        &self.actions
    }

    /// Number of planned actions.
    pub fn action_count(&self) -> usize {
        self.actions.iter().filter(|slot| slot.is_some()).count()
    }

    /// How many planned actions may discard live data.
    pub const fn destructive_count(&self) -> u32 {
        self.destructive
    }

    /// Whether the plan would change anything.
    pub fn is_empty(&self) -> bool {
        self.action_count() == 0
    }

    fn push(&mut self, action: RepairAction) -> Result<(), RepairRefusal> {
        for slot in self.actions.iter_mut() {
            if slot.is_none() {
                if action.class == RepairClass::Destructive {
                    self.destructive = self.destructive.saturating_add(1);
                }
                *slot = Some(action);
                return Ok(());
            }
        }
        Err(RepairRefusal::PlanOverflow)
    }
}

/// Caller authorisation for actions that may discard live data.
///
/// A distinct type rather than a bool field: a caller that has not
/// considered destructive repair cannot grant it by copying an
/// example and leaving a flag set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestructiveConsent {
    /// Only derivable repairs may be applied.
    Withheld,
    /// Destructive repairs are authorised for this pass.
    Granted,
}

/// Build a repair plan from a scrub report.
///
/// Enforces the ordering rules from the policy: replay before repair,
/// refuse before repair, report before applying.
pub fn plan_repairs<const N: usize, const M: usize>(
    report: &FsckReport<M>,
    consent: DestructiveConsent,
) -> Result<RepairPlan<N>, RepairRefusal> {
    // Rule 1: a volume mid-recovery has a journal that is about to
    // overwrite whatever we would repair, and findings taken from the
    // un-replayed state may be artefacts of it.
    for finding in report.findings().iter().flatten() {
        if *finding == FsckFinding::NeedsJournalReplay {
            return Err(RepairRefusal::JournalReplayPending);
        }
    }

    // Rule 2: refuse as a whole rather than repairing around an
    // unexplained structural fault. Partial repair yields a volume
    // that looks healthier than it is.
    for finding in report.findings().iter().flatten() {
        if classify(*finding) == RepairClass::Refuse {
            return Err(RepairRefusal::Unrepairable { finding: *finding });
        }
    }

    let mut plan = RepairPlan::new();
    // Derivable actions first: they discard nothing, so if a later
    // destructive action is refused the safe work is still described.
    for finding in report.findings().iter().flatten() {
        if classify(*finding) == RepairClass::Derivable {
            plan.push(RepairAction {
                finding: *finding,
                class: RepairClass::Derivable,
            })?;
        }
    }
    for finding in report.findings().iter().flatten() {
        if classify(*finding) == RepairClass::Destructive {
            plan.push(RepairAction {
                finding: *finding,
                class: RepairClass::Destructive,
            })?;
        }
    }

    if plan.destructive_count() > 0 && consent == DestructiveConsent::Withheld {
        return Err(RepairRefusal::ConsentRequired);
    }
    Ok(plan)
}

#[cfg(test)]
mod repair_tests {
    use super::*;

    fn report_with(findings: &[FsckFinding]) -> FsckReport<8> {
        let mut report = FsckReport::new();
        for finding in findings {
            report.record(*finding);
        }
        report
    }

    /// A quota total is a cache of the live objects, so it can be
    /// rewritten without discarding anything and needs no consent.
    #[test]
    fn derivable_findings_are_planned_without_consent() {
        let report = report_with(&[FsckFinding::QuotaMismatch]);
        let Ok(plan) = plan_repairs::<8, 8>(&report, DestructiveConsent::Withheld) else {
            assert!(false, "a derivable repair must not require consent");
            return;
        };
        assert_eq!(plan.action_count(), 1);
        assert_eq!(plan.destructive_count(), 0);
    }

    /// Rebuilding reference state can drop references it cannot
    /// attribute to a live owner, so it must not happen silently.
    #[test]
    fn destructive_findings_require_explicit_consent() {
        let report = report_with(&[FsckFinding::ReferenceMismatch]);
        assert_eq!(
            plan_repairs::<8, 8>(&report, DestructiveConsent::Withheld).err(),
            Some(RepairRefusal::ConsentRequired)
        );
        let Ok(plan) = plan_repairs::<8, 8>(&report, DestructiveConsent::Granted) else {
            assert!(false, "granted consent must allow the plan");
            return;
        };
        assert_eq!(plan.destructive_count(), 1);
    }

    /// Synthesising a missing root would present a clean volume whose
    /// indexed objects are all unreachable. Consent cannot buy this.
    #[test]
    fn unrepairable_findings_are_refused_even_with_consent() {
        let report = report_with(&[FsckFinding::MissingRequiredRoot {
            root: FsckRoot::Refcount,
        }]);
        assert_eq!(
            plan_repairs::<8, 8>(&report, DestructiveConsent::Granted).err(),
            Some(RepairRefusal::Unrepairable {
                finding: FsckFinding::MissingRequiredRoot {
                    root: FsckRoot::Refcount,
                }
            })
        );
    }

    /// Rule 2: a repairable finding sitting next to an unexplained
    /// structural fault must not be repaired on its own. Doing so
    /// leaves a volume that looks healthier than it is and strips
    /// evidence from the next scrub.
    #[test]
    fn one_unrepairable_finding_refuses_the_whole_pass() {
        let report = report_with(&[FsckFinding::QuotaMismatch, FsckFinding::BadFeatureSet]);
        assert_eq!(
            plan_repairs::<8, 8>(&report, DestructiveConsent::Granted).err(),
            Some(RepairRefusal::Unrepairable {
                finding: FsckFinding::BadFeatureSet
            })
        );
    }

    /// Rule 1: the journal is about to write the correct values, and
    /// findings read from the un-replayed state may be artefacts of
    /// it. Replay outranks every other repair, including derivable
    /// ones that would otherwise be safe.
    #[test]
    fn pending_journal_replay_outranks_every_other_repair() {
        let report = report_with(&[FsckFinding::QuotaMismatch, FsckFinding::NeedsJournalReplay]);
        assert_eq!(
            plan_repairs::<8, 8>(&report, DestructiveConsent::Granted).err(),
            Some(RepairRefusal::JournalReplayPending)
        );
    }

    /// Derivable actions are ordered ahead of destructive ones, so a
    /// pass that stops early has still described the work that
    /// discards nothing.
    #[test]
    fn derivable_actions_are_ordered_before_destructive_ones() {
        let report = report_with(&[FsckFinding::ReferenceMismatch, FsckFinding::QuotaMismatch]);
        let Ok(plan) = plan_repairs::<8, 8>(&report, DestructiveConsent::Granted) else {
            assert!(false, "the plan must build with consent");
            return;
        };
        let Some(Some(first)) = plan.actions().first() else {
            assert!(false, "the plan must have a first action");
            return;
        };
        assert_eq!(first.class, RepairClass::Derivable);
    }

    /// A clean volume must produce a plan that would change nothing.
    #[test]
    fn a_clean_report_plans_no_work() {
        let report = report_with(&[]);
        let Ok(plan) = plan_repairs::<8, 8>(&report, DestructiveConsent::Withheld) else {
            assert!(false, "a clean report must plan cleanly");
            return;
        };
        assert!(plan.is_empty());
    }

    /// A plan that cannot hold every action must refuse rather than
    /// silently apply a truncated repair.
    #[test]
    fn a_plan_too_small_for_its_actions_refuses() {
        let report = report_with(&[FsckFinding::QuotaMismatch, FsckFinding::QuotaMismatch]);
        assert_eq!(
            plan_repairs::<1, 8>(&report, DestructiveConsent::Granted).err(),
            Some(RepairRefusal::PlanOverflow)
        );
    }
}
