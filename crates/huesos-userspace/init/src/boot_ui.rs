//! Boot presentation: owns the splash, the stage table, and the
//! service-message plumbing that drives them.
//!
//! Keeping this beside `main` rather than inside it means the boot
//! sequence reads as a list of stages instead of a list of framebuffer
//! calls, and the splash can be absent (serial-only boot) without every
//! call site testing for it.

use crate::log::InitLogger;
use crate::splash::{state_marker, Splash};
use huesos_bootux::config::InitConfig;
use huesos_bootux::progress::{parse_report, BootProgress, ServiceReport, StageState};
use libcanvas::{Channel, ErrorCode};

/// Timer frequency of `monotonic_ticks`, in ticks per second.
const TICKS_PER_SEC: u64 = 100;

/// Cooperative poll budget per ready-wait, retained as a backstop for
/// the case where the clock is unavailable and the wall-clock deadline
/// cannot be armed. Without it a dead peer plus a broken clock would
/// park the boot forever.
const POLL_BUDGET: u32 = 200_000;

/// Boot-time UI state.
pub struct BootUi {
    progress: BootProgress,
    splash: Option<Splash>,
    /// Mirror technical log lines to the framebuffer console.
    pub log_screen: bool,
}

impl BootUi {
    pub fn new(config: &InitConfig, logger: &mut InitLogger) -> Self {
        let progress = BootProgress::from_config(config);
        let splash = if config.splash {
            Splash::new(config)
        } else {
            None
        };
        match (&splash, config.splash) {
            (Some(splash), _) => {
                crate::init_logln!(
                    logger,
                    "[init] splash: {}x{}, {} stages",
                    splash.width(),
                    splash.height(),
                    progress.stages().len()
                );
            }
            (None, true) => {
                // Requested but unavailable: say so, and make sure the
                // operator is not left with a blank screen.
                crate::init_logln!(logger, "[init] splash unavailable; falling back to log");
            }
            (None, false) => {
                crate::init_logln!(logger, "[init] splash disabled by configuration");
            }
        }
        let log_screen = config.log_screen || splash.is_none();
        Self {
            progress,
            splash,
            log_screen,
        }
    }

    fn now(&self) -> Option<u64> {
        libcanvas::system::monotonic_ticks().ok()
    }

    /// Begin a stage by id. Unknown ids are ignored so a build with a
    /// trimmed stage table still boots.
    pub fn begin(&mut self, id: &[u8], logger: &mut InitLogger) {
        let Some(index) = self.progress.index_of(id) else {
            return;
        };
        let tick = self.now();
        self.progress.start(index, tick);
        let label = self.progress.stages()[index].label;
        crate::init_logln!(
            logger,
            "[init] stage {} start: {}",
            ascii(id),
            label.as_str()
        );
        self.render();
    }

    /// Mark a stage finished with an explicit outcome.
    pub fn end(&mut self, id: &[u8], state: StageState, logger: &mut InitLogger) {
        let Some(index) = self.progress.index_of(id) else {
            return;
        };
        self.progress.finish(index, state);
        crate::init_logln!(
            logger,
            "[init] stage {} {}",
            ascii(id),
            match state {
                StageState::Done => "ok",
                StageState::Failed => "FAILED",
                StageState::Degraded => "degraded",
                StageState::Skipped => "skipped",
                _ => "?",
            }
        );
        self.render();
        if state == StageState::Failed {
            if let Some(splash) = self.splash.as_mut() {
                splash.render_failure(&self.progress);
            }
        }
    }

    /// Report intra-stage progress for the stage init is running
    /// itself.
    ///
    /// Stages driven by another process advance when that process
    /// sends `name:progress:NN`. The self-test stage has no such peer —
    /// init *is* the peer — so it reports its own steps. Without this
    /// the longest single stage of the boot showed a motionless bar and
    /// then jumped, which is precisely the behaviour the weighting was
    /// introduced to avoid.
    pub fn step(&mut self, id: &[u8], percent: u8) {
        self.report(id, percent);
    }

    /// Record progress for `id`, starting the stage if a report
    /// arrives before init formally began it.
    ///
    /// Auto-start matters for stages another process drives: the first
    /// thing init hears about the Hxfs mount may be `storage:progress`,
    /// and a report for a stage still marked pending would otherwise be
    /// dropped by `report_progress`.
    fn report(&mut self, id: &[u8], percent: u8) {
        let Some(index) = self.progress.index_of(id) else {
            return;
        };
        if self.progress.stages()[index].state == StageState::Pending {
            let tick = self.now();
            self.progress.start(index, tick);
        }
        self.progress.report_progress(index, percent);
        self.render();
    }

    pub fn render(&mut self) {
        if let Some(splash) = self.splash.as_mut() {
            splash.render(&mut self.progress);
        }
    }

    /// Wait for `name:ready` on `channel`, advancing the bar on any
    /// `name:progress:NN` that arrives first.
    ///
    /// Returns the stage outcome. A stage that exceeds its configured
    /// deadline is reported `Failed` and the boot continues: a missing
    /// optional service is not a reason to refuse to boot, but it must
    /// not be silent either.
    pub fn wait_ready(
        &mut self,
        id: &[u8],
        channel: &Channel,
        logger: &mut InitLogger,
    ) -> StageState {
        let Some(index) = self.progress.index_of(id) else {
            return StageState::Skipped;
        };
        let ticks_per_sec = TICKS_PER_SEC;
        let mut buf = [0u8; 64];
        let mut spins: u32 = 0;
        loop {
            match channel.read_into(&mut buf) {
                Ok(n) => match parse_report(&buf[..n]) {
                    // Reports are routed by the name the service sends,
                    // not by the stage init happens to be waiting on. A
                    // single bootstrap channel carries traffic for
                    // several stages: DriverManager owns the NVMe and
                    // Hxfs bring-up, so `storage:progress:NN` arrives on
                    // the same channel init is using to wait for
                    // `driver-manager:ready`. Matching on the waited-for
                    // stage would drop exactly the reports that describe
                    // the longest part of the boot.
                    ServiceReport::Ready { name } if name == id => {
                        self.end(id, StageState::Done, logger);
                        return StageState::Done;
                    }
                    ServiceReport::Degraded { name } if name == id => {
                        // A real answer, not a failure: the service is
                        // up with reduced function. Settle the stage so
                        // the boot proceeds, but record it honestly.
                        self.end(id, StageState::Degraded, logger);
                        return StageState::Degraded;
                    }
                    ServiceReport::Ready { name } => {
                        self.end(name, StageState::Done, logger);
                    }
                    ServiceReport::Degraded { name } => {
                        self.end(name, StageState::Degraded, logger);
                    }
                    ServiceReport::Progress { name, percent } => {
                        self.report(name, percent);
                    }
                    ServiceReport::Other => {
                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                        crate::init_logln!(logger, "[init] {} says {}", ascii(id), text);
                    }
                },
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                    self.render();
                }
                Err(error) => {
                    crate::init_logln!(
                        logger,
                        "[init] {} bootstrap read failed: {}",
                        ascii(id),
                        error.as_str()
                    );
                    self.end(id, StageState::Failed, logger);
                    return StageState::Failed;
                }
            }

            spins = spins.saturating_add(1);
            if let Some(now) = self.now() {
                if self.progress.expired(index, now, ticks_per_sec) {
                    crate::init_logln!(
                        logger,
                        "[init] {} did not report ready within {}s",
                        ascii(id),
                        self.progress.stages()[index].timeout_secs
                    );
                    self.end(id, StageState::Failed, logger);
                    return StageState::Failed;
                }
            } else if spins >= POLL_BUDGET {
                // Clock unavailable: fall back to the spin budget rather
                // than waiting forever.
                crate::init_logln!(
                    logger,
                    "[init] {} ready-wait exhausted (no clock)",
                    ascii(id)
                );
                self.end(id, StageState::Failed, logger);
                return StageState::Failed;
            }
        }
    }

    /// Pump `channel` until every stage has settled or their deadlines
    /// expire.
    ///
    /// Stages another process drives finish after init has run out of
    /// its own work. Without this the boot would reach the framebuffer
    /// handoff with the storage stage still open, and the last thing on
    /// screen would be a bar frozen mid-way — the failure mode this
    /// whole design exists to avoid.
    pub fn drain(&mut self, channel: &Channel, logger: &mut InitLogger) {
        let mut buf = [0u8; 64];
        let mut spins: u32 = 0;
        while !self.progress.all_settled() {
            match channel.read_into(&mut buf) {
                Ok(n) => match parse_report(&buf[..n]) {
                    ServiceReport::Ready { name } => self.end(name, StageState::Done, logger),
                    ServiceReport::Degraded { name } => {
                        self.end(name, StageState::Degraded, logger)
                    }
                    ServiceReport::Progress { name, percent } => self.report(name, percent),
                    ServiceReport::Other => {
                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                        crate::init_logln!(logger, "[init] says {}", text);
                    }
                },
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                    self.render();
                }
                Err(error) => {
                    crate::init_logln!(logger, "[init] drain read failed: {}", error.as_str());
                    return;
                }
            }

            spins = spins.saturating_add(1);
            match self.now() {
                Some(now) => {
                    // Expire whatever is still outstanding, each against
                    // its own configured deadline.
                    for index in 0..self.progress.stages().len() {
                        if self.progress.expired(index, now, TICKS_PER_SEC) {
                            let id = self.progress.stages()[index].id;
                            crate::init_logln!(
                                logger,
                                "[init] {} did not report ready within {}s",
                                id.as_str(),
                                self.progress.stages()[index].timeout_secs
                            );
                            self.end(id.as_bytes(), StageState::Failed, logger);
                        }
                    }
                }
                None if spins >= POLL_BUDGET => {
                    crate::init_logln!(logger, "[init] drain exhausted (no clock)");
                    return;
                }
                None => {}
            }
        }
    }

    /// Final frame plus a one-line summary on UART.
    pub fn finish(&mut self, logger: &mut InitLogger) {
        // Anything still pending never ran; credit it as skipped so the
        // bar completes rather than freezing just short of full.
        for index in 0..self.progress.stages().len() {
            if matches!(
                self.progress.stages()[index].state,
                StageState::Pending | StageState::Running
            ) {
                self.progress.finish(index, StageState::Skipped);
            }
        }
        if let Some(splash) = self.splash.as_mut() {
            splash.finish(&mut self.progress);
        }
        for stage in self.progress.stages() {
            crate::init_logln!(
                logger,
                "[init] stage summary {} {}",
                state_marker(stage.state),
                stage.id.as_str()
            );
        }
        // Report degradation distinctly. Saying "all ok" when a service
        // came up without its keyboard would be the kind of summary
        // that trains people to ignore summaries.
        let verdict = if self.progress.any_failed() {
            "with failures"
        } else if self.progress.any_degraded() {
            "degraded"
        } else {
            "all ok"
        };
        crate::init_logln!(logger, "[init] boot stages complete: {}", verdict);
    }

    pub fn any_failed(&self) -> bool {
        self.progress.any_failed()
    }
}

fn ascii(id: &[u8]) -> &str {
    core::str::from_utf8(id).unwrap_or("<non-utf8>")
}
