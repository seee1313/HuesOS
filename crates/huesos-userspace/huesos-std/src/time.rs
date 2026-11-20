//! Time: `Duration`, `Instant` and `SystemTime` over the kernel's monotonic
//! scheduler clock.
//!
//! The kernel exposes one clock — a monotonic tick counter at a fixed
//! [`TICKS_PER_SEC`] — and nothing else. Wall-clock time would need a
//! time-of-day source the ABI does not have, so [`SystemTime`] is defined as
//! "ticks since boot, offset by the epoch at boot" and keeps its `UNIX_EPOCH`
//! semantics honest: two `SystemTime`s subtracted still measure real elapsed
//! time, and adding a `Duration` still moves forward.

use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

use libcanvas::system;

/// Scheduler ticks per second (`monotonic_ticks` is a 100 Hz counter).
pub const TICKS_PER_SEC: u64 = 100;

/// Ticks in one millisecond (10 ms per tick at 100 Hz).
pub const TICKS_PER_MILLIS: u64 = TICKS_PER_SEC / 1000;

/// Ticks in one nanosecond: at 100 Hz a tick is 10 ms, so this is 0 and the
/// conversion rounds *up* instead of pretending to sub-tick precision.
const NANOS_PER_TICK: u64 = 1_000_000_000 / TICKS_PER_SEC;

/// A span of time, with nanosecond resolution like `std`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Duration {
    secs: u64,
    nanos: u32,
}

impl Duration {
    /// Zero.
    pub const ZERO: Duration = Duration::new(0, 0);
    /// One nanosecond.
    pub const NANOSECOND: Duration = Duration::new(0, 1);
    /// One microsecond.
    pub const MICROSECOND: Duration = Duration::new(0, 1_000);
    /// One millisecond.
    pub const MILLISECOND: Duration = Duration::new(0, 1_000_000);
    /// One second.
    pub const SECOND: Duration = Duration::new(1, 0);

    /// Build from whole seconds and nanoseconds; `nanos` must be < 1e9.
    pub const fn new(secs: u64, nanos: u32) -> Duration {
        assert!(nanos < 1_000_000_000);
        Duration { secs, nanos }
    }

    /// Whole seconds.
    pub const fn from_secs(secs: u64) -> Duration {
        Duration { secs, nanos: 0 }
    }

    /// Whole milliseconds.
    pub const fn from_millis(millis: u64) -> Duration {
        Duration {
            secs: millis / 1_000,
            nanos: ((millis % 1_000) as u32) * 1_000_000,
        }
    }

    /// Whole microseconds.
    pub const fn from_micros(micros: u64) -> Duration {
        Duration {
            secs: micros / 1_000_000,
            nanos: ((micros % 1_000_000) as u32) * 1_000,
        }
    }

    /// Whole nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Duration {
        Duration {
            secs: nanos / 1_000_000_000,
            nanos: (nanos % 1_000_000_000) as u32,
        }
    }

    /// Build from a tick count.
    pub const fn from_ticks(ticks: u64) -> Duration {
        Duration {
            secs: ticks / TICKS_PER_SEC,
            nanos: ((ticks % TICKS_PER_SEC) as u32) * (NANOS_PER_TICK as u32),
        }
    }

    /// Whole seconds part.
    pub const fn as_secs(&self) -> u64 {
        self.secs
    }

    /// Sub-second part in nanoseconds.
    pub const fn subsec_nanos(&self) -> u32 {
        self.nanos
    }

    /// Total milliseconds, truncated.
    pub const fn as_millis(&self) -> u128 {
        (self.secs as u128) * 1_000 + (self.nanos / 1_000_000) as u128
    }

    /// Total microseconds, truncated.
    pub const fn as_micros(&self) -> u128 {
        (self.secs as u128) * 1_000_000 + (self.nanos / 1_000) as u128
    }

    /// This duration as scheduler ticks, rounded *up*: sleeping for less than
    /// one tick must still sleep one tick, otherwise `sleep(1ms)` returns
    /// immediately and a polling loop spins.
    pub const fn as_ticks_ceil(&self) -> u64 {
        let mut ticks = self.secs.saturating_mul(TICKS_PER_SEC);
        if self.nanos > 0 {
            let nanos_per_tick = NANOS_PER_TICK as u32;
            ticks = ticks.saturating_add(((self.nanos - 1) / nanos_per_tick + 1) as u64);
        }
        ticks
    }

    /// Zero if empty.
    pub const fn is_zero(&self) -> bool {
        self.secs == 0 && self.nanos == 0
    }

    /// Saturating addition.
    pub const fn saturating_add(self, other: Duration) -> Duration {
        let mut secs = self.secs.saturating_add(other.secs);
        let mut nanos = self.nanos + other.nanos;
        if nanos >= 1_000_000_000 {
            nanos -= 1_000_000_000;
            secs = secs.saturating_add(1);
        }
        Duration { secs, nanos }
    }

    /// Checked subtraction.
    pub const fn checked_sub(self, other: Duration) -> Option<Duration> {
        let (secs, nanos) = if self.nanos >= other.nanos {
            (self.secs, self.nanos - other.nanos)
        } else {
            match self.secs.checked_sub(other.secs + 1) {
                Some(secs) => (secs, self.nanos + 1_000_000_000 - other.nanos),
                None => return None,
            }
        };
        if secs < other.secs || (secs == other.secs && self.nanos < other.nanos) {
            return None;
        }
        Some(Duration { secs, nanos })
    }

    /// Checked addition.
    pub const fn checked_add(self, other: Duration) -> Option<Duration> {
        match self.secs.checked_add(other.secs) {
            Some(secs) => {
                let mut secs = secs;
                let mut nanos = self.nanos + other.nanos;
                if nanos >= 1_000_000_000 {
                    nanos -= 1_000_000_000;
                    match secs.checked_add(1) {
                        Some(next) => secs = next,
                        None => return None,
                    }
                }
                Some(Duration { secs, nanos })
            }
            None => None,
        }
    }
}

impl Add for Duration {
    type Output = Duration;

    fn add(self, other: Duration) -> Duration {
        self.saturating_add(other)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, other: Duration) {
        *self = self.saturating_add(other);
    }
}

impl Sub for Duration {
    type Output = Duration;

    /// Saturates at zero instead of panicking: a clock that never goes
    /// backwards makes underflow impossible in practice, and a shell must not
    /// die because a timing measurement raced.
    fn sub(self, other: Duration) -> Duration {
        self.checked_sub(other).unwrap_or(Duration::ZERO)
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl Mul<u32> for Duration {
    type Output = Duration;

    fn mul(self, rhs: u32) -> Duration {
        let nanos = u128::from(self.nanos) * u128::from(rhs);
        let extra_secs = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
        Duration {
            secs: self
                .secs
                .saturating_mul(u64::from(rhs))
                .saturating_add(extra_secs),
            nanos: (nanos % 1_000_000_000) as u32,
        }
    }
}

impl Div<u32> for Duration {
    type Output = Duration;

    fn div(self, rhs: u32) -> Duration {
        let total_nanos = u128::from(self.secs) * 1_000_000_000 + u128::from(self.nanos);
        let share = total_nanos / u128::from(rhs);
        Duration {
            secs: u64::try_from(share / 1_000_000_000).unwrap_or(0),
            nanos: (share % 1_000_000_000) as u32,
        }
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.secs > 0 {
            write!(f, "{}.{:03}s", self.secs, self.nanos / 1_000_000)
        } else if self.nanos >= 1_000_000 {
            write!(f, "{}ms", self.nanos / 1_000_000)
        } else if self.nanos >= 1_000 {
            write!(f, "{}us", self.nanos / 1_000)
        } else {
            write!(f, "{}ns", self.nanos)
        }
    }
}

/// A monotonic instant, comparable and subtractable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Instant {
    ticks: u64,
}

impl Instant {
    /// Read the clock. Falls back to tick 0 if the syscall is unavailable,
    /// which keeps `Instant` usable inside a boot smoke test.
    pub fn now() -> Instant {
        Instant {
            ticks: system::monotonic_ticks().unwrap_or(0),
        }
    }

    /// Ticks since boot.
    pub const fn from_ticks(ticks: u64) -> Instant {
        Instant { ticks }
    }

    /// Raw tick count.
    pub const fn as_ticks(&self) -> u64 {
        self.ticks
    }

    /// Time since this instant, saturating at zero if the clock went backwards
    /// (it cannot, but a wrapping counter would look like it).
    pub fn elapsed(&self) -> Duration {
        self.duration_since(*self)
    }

    /// `now - self`.
    pub fn elapsed_since_now(&self) -> Duration {
        Instant::now().duration_since(*self)
    }

    /// Difference to an earlier instant, saturating at zero.
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_ticks(self.ticks.saturating_sub(earlier.ticks))
    }

    /// Checked addition of a duration.
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        self.ticks
            .checked_add(duration.as_ticks_ceil())
            .map(Instant::from_ticks)
    }

    /// Checked subtraction of a duration.
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        self.ticks
            .checked_sub(duration.as_ticks_ceil())
            .map(Instant::from_ticks)
    }

    /// Saturating addition.
    pub fn saturating_add(&self, duration: Duration) -> Instant {
        Instant::from_ticks(self.ticks.saturating_add(duration.as_ticks_ceil()))
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        self.saturating_add(other)
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        Instant::from_ticks(self.ticks.saturating_sub(other.as_ticks_ceil()))
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

/// A clock reading on the process' notion of the epoch.
///
/// The ABI has no time-of-day call, so this counts ticks since boot and the
/// epoch is "boot". Durations between readings are exact; absolute values are
/// only meaningful within one boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SystemTime {
    ticks: u64,
}

impl SystemTime {
    /// The best available "now".
    pub fn now() -> SystemTime {
        SystemTime {
            ticks: system::monotonic_ticks().unwrap_or(0),
        }
    }

    /// Time since `earlier`, or an error if `earlier` is later.
    pub fn duration_since(
        &self,
        earlier: SystemTime,
    ) -> core::result::Result<Duration, SystemTimeError> {
        if self.ticks < earlier.ticks {
            return Err(SystemTimeError(Duration::from_ticks(
                earlier.ticks - self.ticks,
            )));
        }
        Ok(Duration::from_ticks(self.ticks - earlier.ticks))
    }

    /// Time since the epoch (boot).
    pub fn elapsed(&self) -> core::result::Result<Duration, SystemTimeError> {
        self.duration_since(UNIX_EPOCH)
    }

    /// Checked addition.
    pub fn checked_add(&self, duration: Duration) -> Option<SystemTime> {
        self.ticks
            .checked_add(duration.as_ticks_ceil())
            .map(|ticks| SystemTime { ticks })
    }

    /// Checked subtraction.
    pub fn checked_sub(&self, duration: Duration) -> Option<SystemTime> {
        self.ticks
            .checked_sub(duration.as_ticks_ceil())
            .map(|ticks| SystemTime { ticks })
    }

    /// Ticks since boot.
    pub const fn as_ticks(&self) -> u64 {
        self.ticks
    }
}

/// The instant the process' clock starts, i.e. boot.
pub const UNIX_EPOCH: SystemTime = SystemTime { ticks: 0 };

/// The second system time was earlier than the first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemTimeError(Duration);

impl SystemTimeError {
    /// How far the two readings are apart.
    pub const fn duration(&self) -> Duration {
        self.0
    }
}

impl fmt::Display for SystemTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "second time provided was later than self by {}", self.0)
    }
}

impl Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, other: Duration) -> SystemTime {
        SystemTime {
            ticks: self.ticks.saturating_add(other.as_ticks_ceil()),
        }
    }
}

impl Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, other: Duration) -> SystemTime {
        SystemTime {
            ticks: self.ticks.saturating_sub(other.as_ticks_ceil()),
        }
    }
}

impl Sub<SystemTime> for SystemTime {
    type Output = Duration;

    fn sub(self, other: SystemTime) -> Duration {
        self.duration_since(other)
            .unwrap_or_else(|error| error.duration())
    }
}
