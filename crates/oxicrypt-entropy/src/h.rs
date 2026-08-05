//! Fixed-point min-entropy type — the `H` that flows through the pipeline.
//!
//! Min-entropy values are exact fixed-point numbers in steps of 1/256 bit
//! (design decision, 2026-06-12). This keeps every comparison and every
//! health-test cutoff derivation in pure integer arithmetic — no `f32`/`f64`
//! exists anywhere on the claimed-H or cutoff path.
//!
//! Two roles, one type:
//!
//! - the **claimed H** a caller injects at pipeline construction (an
//!   assessment outcome, never a source attribute), and
//! - the **design ceiling** a noise source declares via
//!   [`NoiseSource::max_claimable_h`](crate::source::NoiseSource::max_claimable_h).
//!
//! Conversions that cannot be represented exactly round **down** —
//! a min-entropy claim is never silently overstated.

/// Number of fixed-point steps per bit of min-entropy.
pub const H_STEPS_PER_BIT: u32 = 256;

/// Min-entropy in exact 1/256-bit steps.
///
/// Ordering is the natural numeric ordering, so ceiling checks are plain
/// comparisons. The type is deliberately tiny and `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinEntropy(u32);

impl MinEntropy {
    /// Zero bits of min-entropy.
    pub const ZERO: Self = Self(0);

    /// Constructs from a whole number of bits per sample (exact).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        // Cannot saturate: 255 * 256 < u32::MAX. Saturating form keeps the
        // no-overflow argument compiler-checked.
        Self((bits as u32).saturating_mul(H_STEPS_PER_BIT))
    }

    /// Constructs from raw 1/256-bit steps (exact).
    #[must_use]
    pub const fn from_steps(steps: u32) -> Self {
        Self(steps)
    }

    /// Constructs from a rational `num/den` bits, rounding **down** to the
    /// 1/256-bit grid (the conservative direction — the claim is never
    /// overstated). Returns `None` if `den` is zero or the value overflows.
    #[must_use]
    pub fn from_fraction_floor(num: u64, den: u64) -> Option<Self> {
        let steps = num
            .saturating_mul(u64::from(H_STEPS_PER_BIT))
            .checked_div(den)?;
        u32::try_from(steps).ok().map(Self)
    }

    /// Raw value in 1/256-bit steps.
    #[must_use]
    pub const fn steps(self) -> u32 {
        self.0
    }

    /// Whole bits, rounded down.
    #[must_use]
    // Floor division by a non-zero constant is the documented conservative
    // rounding direction; it cannot panic.
    #[allow(clippy::integer_division, clippy::arithmetic_side_effects)]
    pub const fn bits_floor(self) -> u32 {
        self.0 / H_STEPS_PER_BIT
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn from_bits_is_exact() {
        assert_eq!(MinEntropy::from_bits(8).steps(), 8 * 256);
        assert_eq!(MinEntropy::from_bits(8).bits_floor(), 8);
        assert_eq!(MinEntropy::ZERO.steps(), 0);
    }

    #[test]
    fn fraction_rounds_down_never_up() {
        // 0.2 bits = 51.2 steps → must floor to 51, never 52.
        let h = MinEntropy::from_fraction_floor(1, 5).unwrap();
        assert_eq!(h.steps(), 51);
        // Exactly representable values stay exact: 0.5 bits = 128 steps.
        assert_eq!(MinEntropy::from_fraction_floor(1, 2).unwrap().steps(), 128);
        // Zero denominator is rejected, not panicking.
        assert!(MinEntropy::from_fraction_floor(1, 0).is_none());
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(MinEntropy::from_bits(2) < MinEntropy::from_bits(3));
        assert_eq!(MinEntropy::from_steps(512), MinEntropy::from_bits(2));
    }
}
