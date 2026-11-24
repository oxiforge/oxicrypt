//! Fixed-point min-entropy type — the `H` that flows through the pipeline.
//!
//! Min-entropy values are exact fixed-point numbers in steps of 1/256 bit,
//! so every comparison and every health-test cutoff derivation on them is
//! integer arithmetic.
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
/// comparisons.
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
    /// overstated).
    ///
    /// Returns `None` in two cases: `den` is zero, or the result does not
    /// fit in `u32` steps. Every other `num/den` converts, including a
    /// full-width `num`.
    #[must_use]
    pub fn from_fraction_floor(num: u64, den: u64) -> Option<Self> {
        if den == 0 {
            return None;
        }
        #[allow(
            clippy::integer_division,
            clippy::arithmetic_side_effects,
            reason = "a u64 times 256 fits in u128, `den` is non-zero, and floor division is the documented rounding"
        )]
        let steps = (u128::from(num) * u128::from(H_STEPS_PER_BIT)) / u128::from(den);
        u32::try_from(steps).ok().map(Self)
    }

    /// `const` form of [`from_fraction_floor`](Self::from_fraction_floor),
    /// for `const` tables and `const` assertions, where an `Option` cannot
    /// be unwrapped.
    ///
    /// Rounds `num/den` bits down to the 1/256-bit grid exactly as
    /// `from_fraction_floor` does, and returns the same value wherever that
    /// function returns `Some`.
    ///
    /// # Panics
    ///
    /// Panics if `den` is zero or if the result does not fit in `u32` steps:
    /// the two cases in which `from_fraction_floor` returns `None`.
    /// In a `const` context the panic is a compile-time error, so an
    /// unrepresentable fraction in a table cannot reach a running module.
    ///
    /// ```compile_fail
    /// use oxicrypt_entropy::h::MinEntropy;
    /// const _: MinEntropy = MinEntropy::from_fraction_floor_const(1, 0);
    /// ```
    ///
    /// ```compile_fail
    /// use oxicrypt_entropy::h::MinEntropy;
    /// const _: MinEntropy = MinEntropy::from_fraction_floor_const(u64::MAX, 1);
    /// ```
    ///
    /// One step above `u32::MAX`, `2^32 / 256` bits, is refused:
    ///
    /// ```compile_fail
    /// use oxicrypt_entropy::h::MinEntropy;
    /// const _: MinEntropy = MinEntropy::from_fraction_floor_const(1 << 32, 256);
    /// ```
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the value is checked against u32::MAX on the line before"
    )]
    pub const fn from_fraction_floor_const(num: u64, den: u64) -> MinEntropy {
        assert!(
            den != 0,
            "MinEntropy::from_fraction_floor_const: zero denominator"
        );
        #[allow(
            clippy::integer_division,
            clippy::arithmetic_side_effects,
            reason = "a u64 times 256 fits in u128, `den` is non-zero, and floor division is the documented rounding"
        )]
        let steps = (num as u128 * H_STEPS_PER_BIT as u128) / den as u128;
        assert!(
            steps <= u32::MAX as u128,
            "MinEntropy::from_fraction_floor_const: value exceeds u32 steps"
        );
        Self(steps as u32)
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
    fn fraction_handles_a_full_width_numerator() {
        const FULL: MinEntropy = MinEntropy::from_fraction_floor_const(u64::MAX, u64::MAX);
        // u64::MAX / u64::MAX is exactly one bit, though u64::MAX * 256
        // does not fit in u64.
        assert_eq!(
            MinEntropy::from_fraction_floor(u64::MAX, u64::MAX).map(MinEntropy::steps),
            Some(256)
        );
        // u64::MAX bits exceeds u32 steps.
        assert!(MinEntropy::from_fraction_floor(u64::MAX, 1).is_none());
        // The const form agrees.
        assert_eq!(FULL.steps(), 256);
    }

    #[test]
    fn fraction_accepts_exactly_u32_max_steps() {
        let top = u64::from(u32::MAX);
        assert_eq!(
            MinEntropy::from_fraction_floor(top, 256).map(MinEntropy::steps),
            Some(u32::MAX)
        );
        assert!(MinEntropy::from_fraction_floor(top + 1, 256).is_none());
        // The const form agrees, called at run time so a refusal fails this
        // test rather than the build.
        assert_eq!(
            MinEntropy::from_fraction_floor_const(top, 256).steps(),
            u32::MAX
        );
    }

    #[test]
    fn from_fraction_floor_const_matches_from_fraction_floor() {
        const HALF: MinEntropy = MinEntropy::from_fraction_floor_const(1, 2);
        assert_eq!(HALF.steps(), 128);
        for (num, den, steps) in [(1, 2, 128), (1, 5, 51), (3, 1, 768)] {
            let h = MinEntropy::from_fraction_floor_const(num, den);
            assert_eq!(h.steps(), steps);
            assert_eq!(h, MinEntropy::from_fraction_floor(num, den).unwrap());
        }
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(MinEntropy::from_bits(2) < MinEntropy::from_bits(3));
        assert_eq!(MinEntropy::from_steps(512), MinEntropy::from_bits(2));
    }
}
