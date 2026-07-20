//! Userspace process supervision policy.
//!
//! A pure, `no_std`, host-testable state machine the kernel's process
//! supervisor uses to decide what to do after a userspace process crashes.
//! It implements crash-loop detection: once too many crashes happen inside a
//! sliding time window the supervisor stops restarting and escalates, forcing
//! an explicit operator/root decision instead of spinning forever.

/// Decision the supervisor should take after observing a crash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SupervisionDecision {
    /// Restart the process immediately (first crash, or the window elapsed).
    Restart = 0,
    /// Do not restart yet; wait `backoff_ticks` before the next attempt.
    Backoff = 1,
    /// Stop restarting and escalate to the root supervisor / operator.
    GiveUp = 2,
}

/// The action the supervisor should take after a crash.
///
/// Pairs the [`SupervisionDecision`] with the backoff delay, which is zero
/// unless the decision is [`SupervisionDecision::Backoff`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionAction {
    /// What to do next.
    pub decision: SupervisionDecision,
    /// How many monotonic ticks to wait before retrying (0 unless `Backoff`).
    pub backoff_ticks: u64,
}

/// Crash-loop throttle for one supervised process.
///
/// Retains the timestamps of the most recent crashes in a fixed ring and
/// counts how many fall inside a sliding `window_ticks` window. The ring
/// capacity `CAP` must be at least `max_crashes + 1` for give-up detection to
/// be exact; smaller capacities simply bound memory and degrade the give-up
/// threshold gracefully.
#[derive(Clone, Copy, Debug)]
pub struct CrashThrottle<const CAP: usize> {
    window_ticks: u64,
    max_crashes: u32,
    base_backoff_ticks: u64,
    crashes: [u64; CAP],
    count: u32,
    head: usize,
}

impl<const CAP: usize> CrashThrottle<CAP> {
    /// Create a throttle allowing `max_crashes` crashes per `window_ticks`
    /// window, backing off by `base_backoff_ticks` after the first repeat.
    pub const fn new(window_ticks: u64, max_crashes: u32, base_backoff_ticks: u64) -> Self {
        assert!(CAP > 0, "CrashThrottle capacity must be non-zero");
        Self {
            window_ticks,
            max_crashes,
            base_backoff_ticks,
            crashes: [0u64; CAP],
            count: 0,
            head: 0,
        }
    }

    /// Record a crash at tick `now` and return the resulting action.
    ///
    /// The first crash in a window restarts immediately; subsequent crashes
    /// back off exponentially (base, 2*base, 4*base, ...); once more than
    /// `max_crashes` crashes land in the window the supervisor gives up.
    pub fn on_crash(&mut self, now: u64) -> SupervisionAction {
        self.record(now);
        let recent = self.recent_count(now);
        if recent > self.max_crashes {
            SupervisionAction {
                decision: SupervisionDecision::GiveUp,
                backoff_ticks: 0,
            }
        } else if recent == 1 {
            SupervisionAction {
                decision: SupervisionDecision::Restart,
                backoff_ticks: 0,
            }
        } else {
            // Exponential backoff: 2nd crash waits base, 3rd waits 2*base, ...
            let shift = (recent - 2).min(31);
            let backoff = self.base_backoff_ticks.saturating_mul(1u64 << shift);
            SupervisionAction {
                decision: SupervisionDecision::Backoff,
                backoff_ticks: backoff,
            }
        }
    }

    /// Number of crashes recorded inside the current window ending at `now`.
    pub fn recent_count(&self, now: u64) -> u32 {
        let mut c = 0u32;
        let mut i = 0usize;
        while i < self.count as usize {
            let idx = if self.count < CAP as u32 {
                i
            } else {
                (self.head + i) % CAP
            };
            let t = self.crashes[idx];
            // Monotonic clock: a crash is inside the window when the elapsed
            // time does not exceed the window length.
            if now.wrapping_sub(t) <= self.window_ticks {
                c += 1;
            }
            i += 1;
        }
        c
    }

    fn record(&mut self, now: u64) {
        self.crashes[self.head] = now;
        self.head = (self.head + 1) % CAP;
        if self.count < CAP as u32 {
            self.count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_crash_restarts_without_backoff() {
        let mut throttle = CrashThrottle::<4>::new(100, 2, 10);
        let action = throttle.on_crash(0);
        assert_eq!(
            action,
            SupervisionAction {
                decision: SupervisionDecision::Restart,
                backoff_ticks: 0,
            }
        );
    }

    #[test]
    fn repeats_back_off_exponentially_until_give_up() {
        let mut throttle = CrashThrottle::<4>::new(100, 2, 10);
        assert_eq!(throttle.on_crash(0).decision, SupervisionDecision::Restart);
        // 2nd crash: Backoff with base backoff.
        let second = throttle.on_crash(10);
        assert_eq!(second.decision, SupervisionDecision::Backoff);
        assert_eq!(second.backoff_ticks, 10);
        // 3rd crash in window: exceeds max_crashes (2) -> give up.
        let third = throttle.on_crash(20);
        assert_eq!(third.decision, SupervisionDecision::GiveUp);
        assert_eq!(third.backoff_ticks, 0);
    }

    #[test]
    fn window_elapse_resets_the_crash_count() {
        let mut throttle = CrashThrottle::<4>::new(100, 2, 10);
        assert_eq!(throttle.on_crash(0).decision, SupervisionDecision::Restart);
        // Far outside the window: only the newest crash counts.
        assert_eq!(
            throttle.on_crash(200).decision,
            SupervisionDecision::Restart
        );
        assert_eq!(throttle.recent_count(200), 1);
    }

    #[test]
    fn backoff_doubles_each_repeat() {
        let mut throttle = CrashThrottle::<8>::new(1000, 5, 5);
        assert_eq!(throttle.on_crash(0).decision, SupervisionDecision::Restart);
        assert_eq!(throttle.on_crash(10).backoff_ticks, 5);
        assert_eq!(throttle.on_crash(20).backoff_ticks, 10);
        assert_eq!(throttle.on_crash(30).backoff_ticks, 20);
        assert_eq!(throttle.on_crash(40).backoff_ticks, 40);
    }
}
