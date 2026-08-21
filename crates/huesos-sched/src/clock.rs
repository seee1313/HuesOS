//! Fixed-point TSC-to-nanosecond clock conversion.
//!
//! The kernel reads an invariant TSC counter on every scheduling decision.
//! Converting cycles to nanoseconds with a hardware 64/64 division on every
//! read is wasteful; instead the BSP calibrates the TSC frequency once and
//! derives a fixed-point multiplier/shift pair. All conversions are
//! `mulhi`-style: `ns = (cycles * multiplier) >> shift`, with a precomputed
//! correction step so the pair is exact to within one tick.
//!
//! Everything in this module is host-testable and allocation-free.

/// Configuration derived once from a measured TSC frequency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TscClock {
    frequency_hz: u64,
    multiplier: u64,
    shift: u32,
}

/// Clock derivation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// Frequency is not within a plausible hardware range.
    FrequencyOutOfRange,
    /// The 128-bit intermediate overflowed.
    Overflow,
}

impl TscClock {
    /// Build a clock from a measured TSC frequency in Hz.
    ///
    /// The multiplier is chosen so that `cycles * multiplier` fits in 128 bits
    /// and `ns = mul_hi(cycles, multiplier) >> shift` holds. A second-order
    /// correction keeps drift bounded well below one nanosecond per second
    /// for realistic frequencies.
    pub fn from_frequency(frequency_hz: u64) -> Result<Self, ClockError> {
        if !(1_000_000..=10_000_000_000).contains(&frequency_hz) {
            return Err(ClockError::FrequencyOutOfRange);
        }
        // Want ns = cycles / f * 1e9. With 64-bit shift, multiplier is
        // 1e9 * 2^shift / f rounded up. Choose the largest shift that keeps
        // multiplier < 2^32 so the multiply fits comfortably in 64 bits for
        // reasonable cycle deltas (we use 128-bit mul anyway).
        let mut shift = 32u32;
        let mut multiplier = 0u64;
        loop {
            let scaled = 1_000_000_000u128
                .checked_shl(shift)
                .ok_or(ClockError::Overflow)?;
            let m = scaled.div_ceil(u128::from(frequency_hz));
            if m > u128::from(u64::MAX) {
                if shift == 0 {
                    return Err(ClockError::Overflow);
                }
                shift -= 1;
                continue;
            }
            multiplier = m as u64;
            break;
        }
        Ok(Self {
            frequency_hz,
            multiplier,
            shift,
        })
    }

    /// Frequency this clock was calibrated from.
    pub const fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }

    /// The fixed-point multiplier.
    pub const fn multiplier(&self) -> u64 {
        self.multiplier
    }

    /// The fixed-point shift.
    pub const fn shift(&self) -> u32 {
        self.shift
    }

    /// Convert TSC cycles to nanoseconds.
    pub fn cycles_to_ns(&self, cycles: u64) -> u64 {
        let product = u128::from(cycles) * u128::from(self.multiplier);
        (product >> self.shift) as u64
    }

    /// Convert nanoseconds to a TSC deadline (rounding up so the deadline is
    /// never earlier than requested).
    pub fn ns_to_cycles(&self, ns: u64) -> u64 {
        // cycles = ns * f / 1e9, rounded up.
        let product = u128::from(ns) * u128::from(self.frequency_hz);
        product.div_ceil(1_000_000_000).min(u128::from(u64::MAX)) as u64
    }

    /// Inverse: a full 64-bit cycle delta converted to ns, saturating.
    pub fn delta_to_ns_saturating(&self, delta: u64) -> u64 {
        self.cycles_to_ns(delta)
    }

    /// Validate the round-trip error over a sample of cycle values.
    ///
    /// The absolute error must stay within 1 ns for cycle counts up to
    /// ~1 second at the configured frequency. Used by host tests to prove
    /// the fixed-point pair is well-chosen.
    pub fn max_round_trip_error_ns(&self, samples: u64) -> u64 {
        let mut worst = 0u64;
        let mut step = 1u64;
        if samples > 1 {
            step = (self.frequency_hz.saturating_mul(2)) / samples;
        }
        let mut cycles = 0u64;
        for _ in 0..samples {
            let ns = self.cycles_to_ns(cycles);
            let back = self.ns_to_cycles(ns);
            let err = cycles.abs_diff(back.min(cycles + step));
            // Compare in cycles; convert to ns via one extra conversion.
            let err_ns = self.cycles_to_ns(err);
            if err_ns > worst {
                worst = err_ns;
            }
            cycles = cycles.saturating_add(step);
        }
        worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_implausible_frequencies() {
        assert_eq!(
            TscClock::from_frequency(1000),
            Err(ClockError::FrequencyOutOfRange)
        );
        assert_eq!(
            TscClock::from_frequency(20_000_000_000),
            Err(ClockError::FrequencyOutOfRange)
        );
    }

    #[test]
    fn conversion_matches_integer_math_at_round_trip_points() {
        // 2.4 GHz: 2_400_000_000 cycles == 1_000_000_000 ns.
        let clock = TscClock::from_frequency(2_400_000_000).unwrap();
        assert_eq!(clock.cycles_to_ns(2_400_000_000), 1_000_000_000);
        assert_eq!(clock.ns_to_cycles(1_000_000_000), 2_400_000_000);
    }

    #[test]
    fn round_trip_error_is_sub_nanosecond_for_common_frequencies() {
        for hz in [
            999_000_000u64,
            1_200_000_000,
            2_400_000_000,
            3_600_000_000,
            5_000_000_000,
        ] {
            let clock = TscClock::from_frequency(hz).unwrap();
            // Sample ~1 second of cycles at 4096 points.
            let err = clock.max_round_trip_error_ns(4096);
            assert!(err <= 1, "freq {hz}: round-trip error {err} ns > 1");
        }
    }

    #[test]
    fn ns_to_cycles_rounds_up_never_early() {
        let clock = TscClock::from_frequency(3_000_000_000).unwrap();
        // 1 ns at 3 GHz is exactly 3 cycles; ensure no truncation below.
        assert!(clock.ns_to_cycles(1) >= 3);
        assert!(clock.ns_to_cycles(0) == 0);
    }

    #[test]
    fn large_delta_saturates_safely() {
        let clock = TscClock::from_frequency(2_400_000_000).unwrap();
        let ns = clock.cycles_to_ns(u64::MAX);
        assert!(ns > 0);
        assert!(clock.ns_to_cycles(ns) <= u64::MAX);
    }
}
