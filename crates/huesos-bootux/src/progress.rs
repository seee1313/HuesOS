//! Boot progress tracking.
//!
//! The stage table is data (see [`crate::config`]), so this module
//! deliberately knows nothing about which services exist. It maps
//! service-reported events onto a weighted 0..=1000 completion value
//! and records per-stage outcomes for the renderer.
//!
//! Permille rather than percent: with a dozen weighted stages, integer
//! percent quantises badly enough that a short stage can complete
//! without moving the bar at all, which reads as a hang.

use crate::config::{InitConfig, InlineStr, MAX_ID, MAX_LABEL, MAX_STAGES};

/// Full scale for [`BootProgress::permille`].
pub const SCALE: u32 = 1000;

/// Lifecycle of a single stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageState {
    /// Not started yet.
    Pending,
    /// Started; `progress` is the service-reported 0..=100 within band.
    Running,
    /// Reported ready.
    Done,
    /// Timed out or failed to launch.
    Failed,
    /// Started and answered, but with reduced function (e.g.
    /// DriverManager comes up without a keyboard). Distinct from both
    /// `Done` and `Failed`: the boot is not broken and must continue
    /// without a red banner, but reporting it as plain success would
    /// hide a real degradation the operator should see.
    Degraded,
    /// Deliberately not run (e.g. no storage on this boot). Skipped
    /// stages keep their weight credited so the bar still reaches full
    /// on a machine with fewer devices.
    Skipped,
}

/// Per-stage runtime record.
#[derive(Clone, Copy)]
pub struct Stage {
    pub id: InlineStr<MAX_ID>,
    pub label: InlineStr<MAX_LABEL>,
    pub weight: u32,
    pub timeout_secs: u32,
    pub state: StageState,
    /// Service-reported progress within this stage, 0..=100.
    pub progress: u8,
    /// Tick at which this stage started, for the deadline.
    pub started_tick: Option<u64>,
}

impl Stage {
    /// Fraction of this stage's weight that has been earned, 0..=100.
    fn earned_percent(&self) -> u32 {
        match self.state {
            StageState::Pending => 0,
            StageState::Running => self.progress as u32,
            // A failed stage still yields its band: the boot moved on,
            // and a bar that can never reach full is a worse signal
            // than the explicit red marker the renderer draws.
            StageState::Done | StageState::Skipped | StageState::Failed | StageState::Degraded => {
                100
            }
        }
    }
}

/// What a parsed service message asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceReport<'a> {
    /// `name:ready`
    Ready { name: &'a [u8] },
    /// `name:degraded`
    Degraded { name: &'a [u8] },
    /// `name:progress:NN`
    Progress { name: &'a [u8], percent: u8 },
    /// Anything else; carried through so the caller can log it.
    Other,
}

/// Parse a bootstrap message from a service.
///
/// The wire form is the existing `name:ready` string protocol, extended
/// with `name:progress:NN`. Reusing the channel init already reads
/// avoids a new syscall, and keeps every service able to influence only
/// its own band rather than global boot state.
pub fn parse_report(message: &[u8]) -> ServiceReport<'_> {
    let Some(colon) = message.iter().position(|byte| *byte == b':') else {
        return ServiceReport::Other;
    };
    let name = &message[..colon];
    let rest = &message[colon + 1..];
    if rest == b"ready" {
        return ServiceReport::Ready { name };
    }
    if rest == b"degraded" {
        return ServiceReport::Degraded { name };
    }
    let Some(percent_text) = strip_prefix(rest, b"progress:") else {
        return ServiceReport::Other;
    };
    match parse_percent(percent_text) {
        Some(percent) => ServiceReport::Progress { name, percent },
        None => ServiceReport::Other,
    }
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() > prefix.len() && &bytes[..prefix.len()] == prefix {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn parse_percent(text: &[u8]) -> Option<u8> {
    if text.is_empty() || text.len() > 3 {
        return None;
    }
    let mut value: u32 = 0;
    for byte in text {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value * 10 + digit as u32;
    }
    if value > 100 {
        return None;
    }
    Some(value as u8)
}

/// Weighted boot progress over a fixed stage table.
pub struct BootProgress {
    stages: [Stage; MAX_STAGES],
    count: usize,
    total_weight: u32,
    /// Highest permille ever reported, enforcing monotonicity.
    high_water: u32,
    active: Option<usize>,
}

impl BootProgress {
    /// Build the tracker from parsed configuration.
    pub fn from_config(config: &InitConfig) -> Self {
        let blank = Stage {
            id: InlineStr::empty(),
            label: InlineStr::empty(),
            weight: 1,
            timeout_secs: config.default_timeout_secs,
            state: StageState::Pending,
            progress: 0,
            started_tick: None,
        };
        let mut stages = [blank; MAX_STAGES];
        let mut count = 0;
        for source in config.stages() {
            stages[count] = Stage {
                id: source.id,
                label: source.label,
                weight: source.weight,
                timeout_secs: source.timeout_secs,
                state: StageState::Pending,
                progress: 0,
                started_tick: None,
            };
            count += 1;
        }
        Self {
            stages,
            count,
            total_weight: config.total_weight(),
            high_water: 0,
            active: None,
        }
    }

    pub fn stages(&self) -> &[Stage] {
        &self.stages[..self.count]
    }

    pub fn index_of(&self, id: &[u8]) -> Option<usize> {
        self.stages[..self.count]
            .iter()
            .position(|stage| stage.id.eq_bytes(id))
    }

    pub fn active(&self) -> Option<usize> {
        self.active
    }

    /// Label of the running stage, or a terminal summary.
    ///
    /// The settled summary must agree with the failure banner drawn
    /// beneath it: reporting "Ready" above "stage 'terminal' did not
    /// report ready" is the kind of contradiction that makes a user
    /// distrust everything else on the screen.
    pub fn current_label(&self) -> &str {
        match self.active {
            Some(index) => self.stages[index].label.as_str(),
            None if !self.all_settled() => "Starting",
            None if self.any_failed() => "Started with errors",
            None if self.any_degraded() => "Started with reduced function",
            None => "Ready",
        }
    }

    /// Mark a stage started at `tick`, arming its deadline.
    pub fn start(&mut self, index: usize, tick: Option<u64>) {
        if index >= self.count {
            return;
        }
        self.stages[index].state = StageState::Running;
        self.stages[index].started_tick = tick;
        self.active = Some(index);
    }

    /// Record intra-stage progress. Values that would move the stage
    /// backwards are ignored.
    pub fn report_progress(&mut self, index: usize, percent: u8) {
        if index >= self.count {
            return;
        }
        let stage = &mut self.stages[index];
        if stage.state != StageState::Running {
            return;
        }
        let clamped = percent.min(100);
        if clamped > stage.progress {
            stage.progress = clamped;
        }
    }

    pub fn finish(&mut self, index: usize, state: StageState) {
        if index >= self.count {
            return;
        }
        self.stages[index].state = state;
        self.stages[index].progress = 100;
        if self.active == Some(index) {
            self.active = None;
        }
    }

    /// Has the stage exceeded its deadline as of `now`?
    ///
    /// A stage started without a tick (clock read failed) never expires:
    /// refusing to boot because the clock syscall misbehaved would be
    /// worse than the hang the deadline protects against.
    pub fn expired(&self, index: usize, now: u64, ticks_per_sec: u64) -> bool {
        if index >= self.count {
            return false;
        }
        let stage = &self.stages[index];
        if stage.state != StageState::Running {
            return false;
        }
        let Some(started) = stage.started_tick else {
            return false;
        };
        let budget = (stage.timeout_secs as u64).saturating_mul(ticks_per_sec);
        now.saturating_sub(started) > budget
    }

    /// Weighted completion, 0..=[`SCALE`], monotonically non-decreasing.
    pub fn permille(&mut self) -> u32 {
        let mut earned: u64 = 0;
        for stage in &self.stages[..self.count] {
            earned += stage.weight as u64 * stage.earned_percent() as u64;
        }
        let denominator = self.total_weight as u64 * 100;
        let value = (earned * SCALE as u64)
            .checked_div(denominator)
            .unwrap_or(0) as u32;
        let value = value.min(SCALE);
        if value > self.high_water {
            self.high_water = value;
        }
        self.high_water
    }

    /// Did any stage come up with reduced function?
    pub fn any_degraded(&self) -> bool {
        self.stages[..self.count]
            .iter()
            .any(|stage| stage.state == StageState::Degraded)
    }

    pub fn all_settled(&self) -> bool {
        self.stages[..self.count]
            .iter()
            .all(|stage| !matches!(stage.state, StageState::Pending | StageState::Running))
    }

    pub fn any_failed(&self) -> bool {
        self.stages[..self.count]
            .iter()
            .any(|stage| stage.state == StageState::Failed)
    }

    /// First failed stage, for the diagnostic banner.
    pub fn first_failure(&self) -> Option<&Stage> {
        self.stages[..self.count]
            .iter()
            .find(|stage| stage.state == StageState::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve a stage index in a test, naming the id when absent.
    fn idx(progress: &BootProgress, id: &[u8]) -> usize {
        let found = progress.index_of(id);
        assert!(
            found.is_some(),
            "stage not found: {}",
            core::str::from_utf8(id).unwrap_or("?")
        );
        found.unwrap_or(0)
    }

    fn config() -> InitConfig {
        let mut config = InitConfig::new().with_default_stages();
        config.finish();
        config
    }

    #[test]
    fn parses_ready_and_progress() {
        assert_eq!(
            parse_report(b"terminal:ready"),
            ServiceReport::Ready { name: b"terminal" }
        );
        assert_eq!(
            parse_report(b"storage:progress:40"),
            ServiceReport::Progress {
                name: b"storage",
                percent: 40
            }
        );
        assert_eq!(
            parse_report(b"storage:progress:100"),
            ServiceReport::Progress {
                name: b"storage",
                percent: 100
            }
        );
    }

    #[test]
    fn parses_degraded_as_its_own_outcome() {
        // Regression: DriverManager answers `degraded` when it comes up
        // without a keyboard. Treating that as an unrecognised message
        // hung the boot until the stage deadline; treating it as plain
        // `ready` would hide the degradation.
        assert_eq!(
            parse_report(b"driver-manager:degraded"),
            ServiceReport::Degraded {
                name: b"driver-manager"
            }
        );
    }

    #[test]
    fn degraded_settles_the_stage_without_failing_the_boot() {
        let mut progress = BootProgress::from_config(&config());
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Degraded);
        }
        assert_eq!(progress.permille(), SCALE);
        assert!(progress.all_settled());
        assert!(progress.any_degraded());
        assert!(!progress.any_failed(), "degraded is not a failure");
    }

    #[test]
    fn rejects_malformed_progress() {
        // Out of range, non-numeric, empty, and overlong all fall back
        // to Other rather than panicking or wrapping.
        assert_eq!(parse_report(b"storage:progress:101"), ServiceReport::Other);
        assert_eq!(parse_report(b"storage:progress:abc"), ServiceReport::Other);
        assert_eq!(parse_report(b"storage:progress:"), ServiceReport::Other);
        assert_eq!(parse_report(b"storage:progress:1234"), ServiceReport::Other);
        assert_eq!(parse_report(b"no-colon"), ServiceReport::Other);
    }

    #[test]
    fn starts_at_zero_and_reaches_full() {
        let mut progress = BootProgress::from_config(&config());
        assert_eq!(progress.permille(), 0);
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Done);
        }
        assert_eq!(progress.permille(), SCALE);
    }

    #[test]
    fn weighting_reflects_configured_weights() {
        // storage has weight 30 of 65 total in the default table, so
        // completing it alone must move the bar further than the three
        // light stages combined.
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.finish(storage, StageState::Done);
        let with_storage = progress.permille();

        let mut other = BootProgress::from_config(&config());
        for id in [
            b"selftest".as_slice(),
            b"driver-manager",
            b"shutdown-broker",
        ] {
            let index = idx(&other, id);
            other.finish(index, StageState::Done);
        }
        assert!(
            with_storage > other.permille(),
            "the heaviest stage must dominate: {} vs {}",
            with_storage,
            other.permille()
        );
    }

    #[test]
    fn intra_stage_progress_moves_the_bar() {
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.start(storage, Some(0));
        let idle = progress.permille();
        progress.report_progress(storage, 50);
        let halfway = progress.permille();
        assert!(
            halfway > idle,
            "a long stage must move while it works: {idle} -> {halfway}"
        );
        progress.finish(storage, StageState::Done);
        assert!(progress.permille() > halfway);
    }

    #[test]
    fn progress_never_goes_backwards() {
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.start(storage, Some(0));
        progress.report_progress(storage, 60);
        let high = progress.permille();
        // A service that reports a lower number afterwards must not
        // rewind the bar; a bar that moves backwards reads as a fault.
        progress.report_progress(storage, 10);
        assert_eq!(progress.permille(), high);
    }

    #[test]
    fn progress_before_start_is_ignored() {
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.report_progress(storage, 90);
        assert_eq!(progress.permille(), 0);
    }

    #[test]
    fn failed_stage_still_credits_its_band() {
        // Otherwise the bar could never reach full after a non-critical
        // service failed, which is a worse signal than the red marker.
        let mut progress = BootProgress::from_config(&config());
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Failed);
        }
        assert_eq!(progress.permille(), SCALE);
        assert!(progress.any_failed());
        assert!(progress.first_failure().is_some());
    }

    #[test]
    fn skipped_stage_credits_its_band() {
        let mut progress = BootProgress::from_config(&config());
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Skipped);
        }
        assert_eq!(progress.permille(), SCALE);
        assert!(!progress.any_failed());
    }

    #[test]
    fn deadline_expires_only_after_the_budget() {
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.start(storage, Some(1_000));
        let ticks = 100;
        let budget = 30 * ticks;
        assert!(!progress.expired(storage, 1_000 + budget, ticks));
        assert!(progress.expired(storage, 1_000 + budget + 1, ticks));
    }

    #[test]
    fn unarmed_deadline_never_expires() {
        // Clock read failed at start: keep waiting rather than fail a
        // healthy service because the clock syscall misbehaved.
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.start(storage, None);
        assert!(!progress.expired(storage, u64::MAX, 100));
    }

    #[test]
    fn settled_stage_does_not_expire() {
        let mut progress = BootProgress::from_config(&config());
        let storage = idx(&progress, b"storage");
        progress.start(storage, Some(0));
        progress.finish(storage, StageState::Done);
        assert!(!progress.expired(storage, u64::MAX, 100));
    }

    #[test]
    fn config_declared_stage_participates_without_code_changes() {
        // The forward-compatibility property: a future service is added
        // by config alone and immediately gets a band and a deadline.
        let mut config = InitConfig::new().with_default_stages();
        config.parse_file(b"stage.network=20\nstage.network.label=Network\ntimeout.network=45\n");
        config.finish();
        let mut progress = BootProgress::from_config(&config);
        let network = idx(&progress, b"network");
        assert_eq!(progress.stages()[network].timeout_secs, 45);
        progress.start(network, Some(0));
        progress.report_progress(network, 100);
        assert!(progress.permille() > 0);
        assert_eq!(progress.current_label(), "Network");
    }

    #[test]
    fn empty_table_does_not_divide_by_zero() {
        let mut config = InitConfig::new();
        config.finish();
        let mut progress = BootProgress::from_config(&config);
        assert_eq!(progress.permille(), 0);
        assert!(progress.all_settled());
    }

    #[test]
    fn settled_label_agrees_with_the_failure_banner() {
        // Regression: the splash showed "Ready" directly above a red
        // "stage ... did not report ready" banner.
        let mut progress = BootProgress::from_config(&config());
        let terminal = idx(&progress, b"terminal");
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Done);
        }
        progress.finish(terminal, StageState::Failed);
        assert_eq!(progress.current_label(), "Started with errors");

        let mut degraded = BootProgress::from_config(&config());
        for index in 0..degraded.stages().len() {
            degraded.finish(index, StageState::Done);
        }
        let dm = idx(&degraded, b"driver-manager");
        degraded.finish(dm, StageState::Degraded);
        assert_eq!(degraded.current_label(), "Started with reduced function");
    }

    #[test]
    fn current_label_tracks_the_active_stage() {
        let mut progress = BootProgress::from_config(&config());
        assert_eq!(progress.current_label(), "Starting");
        let storage = idx(&progress, b"storage");
        progress.start(storage, Some(0));
        assert_eq!(progress.current_label(), "Probing storage controller");
        for index in 0..progress.stages().len() {
            progress.finish(index, StageState::Done);
        }
        assert_eq!(progress.current_label(), "Ready");
    }
}
