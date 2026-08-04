//! Approved continuous health tests (SP 800-90B §4.4) with §4.3 semantics.
//!
//! Stage two of the pipeline: every raw sample passes through the
//! [`HealthMonitor`] (Repetition Count Test + Adaptive Proportion Test)
//! before it can reach any downstream consumer. Health tests sit outside
//! the noise-source trait, so every source — present and future —
//! inherits the same battery.
//!
//! # Failure semantics (all failures permanent)
//!
//! Every health-test failure is **permanent**: the monitor enters a
//! terminal poisoned state, the failing sample (and any sample after it)
//! is never released, and only re-instantiation clears the condition.
//! There is no degraded-output mode and no intermittent/persistent split —
//! the strictest precedented posture, which is also the simplest to argue
//! (SP 800-90B §4.3 item 2 requires that a persistent failure produce no
//! outputs; collapsing all failures onto that path removes a code path
//! with no assurance benefit).
//!
//! # Exactness
//!
//! No floating-point type appears anywhere in this module. The RCT cutoff
//! is closed-form integer arithmetic; APT cutoffs come from a precomputed
//! table whose seed rows are the transcribed SP 800-90B Table 2 reference
//! values (see [`crate::sp800_90b`]). Binomial cutoff generation for the
//! full (H, W, α) grid is an out-of-boundary tool concern; the in-boundary
//! artifact is the table plus verification tests — an α/H point without
//! table coverage is a typed [`HealthError::UnsupportedAlpha`] refusal,
//! never a runtime computation.

use crate::h::{H_STEPS_PER_BIT, MinEntropy};
use crate::source::RawSample;
use crate::sp800_90b::{
    APT_ALPHA30_ALPHA_EXP, APT_ALPHA30_BINARY, APT_ALPHA30_NON_BINARY, APT_TABLE2_ALPHA_EXP,
    APT_TABLE2_BINARY, APT_TABLE2_NON_BINARY, APT_WINDOW_BINARY, APT_WINDOW_NON_BINARY,
    AptTable2Row, CONTINUOUS_ALPHA_EXP_RECOMMENDED_MAX, CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN,
};

/// The cutoff-generating parameter for the continuous health tests, restricted
/// to the power-of-two set α = 2⁻ᵃ with `a` in the SP 800-90B §4.3 item 3
/// recommended range 20..=40.
///
/// **α is the probability that a healthy source producing exactly its claimed
/// min-entropy H trips the test — it is not the observed false-positive rate.**
/// The distinction is load-bearing and is the one the Security Policy draws:
/// because the claimed H is deliberately conservative relative to the assessed
/// min-entropy, the operational false-positive rate is far below α. Describing
/// α here as simply a false-positive probability would assert the reading the
/// policy explicitly rules out, which is why `doc-guard` asserts both surfaces
/// carry this distinction.
///
/// The default is 2⁻³⁰, following the dominant certified jitter-entropy
/// lineage (jent v3.7.0 §6.1.37/§6.1.44, design digest of 2026-06-12)
/// rather than the spec's illustrative 2⁻²⁰.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alpha {
    exp: u32,
}

impl Alpha {
    /// Default cutoff-generating parameter: α = 2⁻³⁰ (cert-lineage precedent).
    pub const DEFAULT: Self = Self { exp: 30 };

    /// α = 2⁻ᵃ for `exp = a`. Returns `None` outside the §4.3 item 3
    /// recommended range 20..=40.
    #[must_use]
    pub const fn from_exp(exp: u32) -> Option<Self> {
        if exp >= CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN
            && exp <= CONTINUOUS_ALPHA_EXP_RECOMMENDED_MAX
        {
            Some(Self { exp })
        } else {
            None
        }
    }

    /// The exponent `a` in α = 2⁻ᵃ.
    #[must_use]
    pub const fn exp(self) -> u32 {
        self.exp
    }
}

/// Which approved continuous health test failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthTest {
    /// Repetition Count Test (§4.4.1).
    Rct,
    /// Adaptive Proportion Test (§4.4.2).
    Apt,
}

/// Typed health-layer errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthError {
    /// A continuous health test failed. The monitor is permanently
    /// poisoned; only re-instantiation clears the condition.
    Failed(HealthTest),
    /// The monitor is already poisoned by an earlier failure; no sample
    /// is ever released after a failure.
    Poisoned,
    /// The requested (α, alphabet, H) point has no precomputed APT cutoff
    /// row. Cutoffs are table-borne by design (no runtime binomial); the
    /// table grows via the out-of-boundary generator, and an uncovered
    /// point is refused rather than approximated.
    UnsupportedAlpha {
        /// The exponent `a` in the requested α = 2⁻ᵃ.
        alpha_exp: u32,
    },
}

/// Repetition Count Test (§4.4.1).
///
/// Cutoff `C = 1 + ⌈−log₂(α)/H⌉`; with α = 2⁻ᵃ and H carried as 1/256-bit
/// fixed-point steps this is `1 + ceil((256·a)/steps)` — pure integer
/// arithmetic (the §4.4.1 worked example α = 2⁻²⁰, H = 2.0 → C = 11 and
/// the jent reference point α = 2⁻³⁰, H = 1 → C = 31 are pinned by test).
#[derive(Debug)]
pub struct RepetitionCountTest {
    cutoff: u32,
    last: Option<RawSample>,
    run_len: u32,
}

impl RepetitionCountTest {
    /// Creates the test for an injected claim `h` at false-positive
    /// probability `alpha`. Returns `None` for a zero claim (the cutoff
    /// formula requires H > 0).
    #[must_use]
    pub fn new(h: MinEntropy, alpha: Alpha) -> Option<Self> {
        let steps = h.steps();
        if steps == 0 {
            return None;
        }
        // ceil((256 * a) / steps); cannot overflow: a ≤ 40, 256*40 = 10240.
        let cutoff =
            1u32.saturating_add(alpha.exp().saturating_mul(H_STEPS_PER_BIT).div_ceil(steps));
        Some(Self {
            cutoff,
            last: None,
            run_len: 0,
        })
    }

    /// The cutoff value C.
    #[must_use]
    pub const fn cutoff(&self) -> u32 {
        self.cutoff
    }

    /// Feeds one sample. `Err(Failed(Rct))` when a value repeats C times.
    fn feed(&mut self, sample: RawSample) -> Result<(), HealthError> {
        if self.last == Some(sample) {
            self.run_len = self.run_len.saturating_add(1);
        } else {
            self.last = Some(sample);
            self.run_len = 1;
        }
        if self.run_len >= self.cutoff {
            return Err(HealthError::Failed(HealthTest::Rct));
        }
        Ok(())
    }
}

/// Adaptive Proportion Test (§4.4.2).
///
/// Window W = 1024 (binary) / 512 (non-binary); cutoff from the
/// precomputed table (claimed H rounded **down** to the table grid — the
/// claim is never overstated, and test stringency follows the weaker
/// claim).
#[derive(Debug)]
pub struct AdaptiveProportionTest {
    window: u32,
    cutoff: u32,
    reference: Option<RawSample>,
    count: u32,
    pos: u32,
}

impl AdaptiveProportionTest {
    /// Creates the test for claim `h`, alphabet shape `is_binary`, at
    /// cutoff-generating parameter `alpha`.
    ///
    /// # Errors
    ///
    /// [`HealthError::UnsupportedAlpha`] when the (α, alphabet, H) point
    /// has no table coverage yet.
    pub fn new(h: MinEntropy, is_binary: bool, alpha: Alpha) -> Result<Self, HealthError> {
        let cutoff = apt_cutoff(h, is_binary, alpha)?;
        let window = if is_binary {
            APT_WINDOW_BINARY
        } else {
            APT_WINDOW_NON_BINARY
        };
        Ok(Self {
            window,
            cutoff,
            reference: None,
            count: 0,
            pos: 0,
        })
    }

    /// The cutoff value C in use.
    #[must_use]
    pub const fn cutoff(&self) -> u32 {
        self.cutoff
    }

    /// Feeds one sample per the §4.4.2 procedure: the first sample of a
    /// window is the reference A; the count B of A-occurrences across the
    /// window (reference included) reaching C is a failure.
    fn feed(&mut self, sample: RawSample) -> Result<(), HealthError> {
        match self.reference {
            None => {
                self.reference = Some(sample);
                self.count = 1;
                self.pos = 1;
            }
            Some(reference) => {
                self.pos = self.pos.saturating_add(1);
                if sample == reference {
                    self.count = self.count.saturating_add(1);
                }
            }
        }
        if self.count >= self.cutoff {
            return Err(HealthError::Failed(HealthTest::Apt));
        }
        if self.pos >= self.window {
            // Window complete without tripping — restart per step 4.
            self.reference = None;
            self.count = 0;
            self.pos = 0;
        }
        Ok(())
    }
}

/// Looks up the APT cutoff for (h, alphabet, α), rounding `h` DOWN to the
/// nearest covered table row (conservative direction).
///
/// Two α grids are table-covered: the transcribed SP 800-90B Table 2
/// reference rows (α = 2⁻²⁰) and the generated α = 2⁻³⁰ grid (the ratified
/// default — see [`crate::sp800_90b::APT_ALPHA30_BINARY`]). Both share the
/// same H grid; only the cutoffs differ. Any other α exponent is a typed
/// [`HealthError::UnsupportedAlpha`] refusal — cutoffs are table-borne, never
/// computed in-boundary; a new α grows the table via the out-of-boundary
/// generator.
fn apt_cutoff(h: MinEntropy, is_binary: bool, alpha: Alpha) -> Result<u32, HealthError> {
    let table: &[AptTable2Row] = match (alpha.exp(), is_binary) {
        (APT_TABLE2_ALPHA_EXP, true) => &APT_TABLE2_BINARY,
        (APT_TABLE2_ALPHA_EXP, false) => &APT_TABLE2_NON_BINARY,
        (APT_ALPHA30_ALPHA_EXP, true) => &APT_ALPHA30_BINARY,
        (APT_ALPHA30_ALPHA_EXP, false) => &APT_ALPHA30_NON_BINARY,
        _ => {
            return Err(HealthError::UnsupportedAlpha {
                alpha_exp: alpha.exp(),
            });
        }
    };
    // Largest table H that does not exceed the claim (round DOWN).
    let mut chosen: Option<u32> = None;
    for row in table {
        // row.h ≤ h  ⇔  num·256 ≤ steps·den   (exact integer comparison)
        let lhs = u64::from(row.h.num).saturating_mul(u64::from(H_STEPS_PER_BIT));
        let rhs = u64::from(h.steps()).saturating_mul(u64::from(row.h.den));
        if lhs <= rhs {
            chosen = Some(row.cutoff);
        }
    }
    chosen.ok_or(HealthError::UnsupportedAlpha {
        alpha_exp: alpha.exp(),
    })
}

/// The per-pipeline health monitor: RCT + APT over every sample, with
/// permanent poisoning on any failure.
#[derive(Debug)]
pub struct HealthMonitor {
    rct: RepetitionCountTest,
    apt: AdaptiveProportionTest,
    poisoned: bool,
}

impl HealthMonitor {
    /// Creates a monitor for claim `h` over an alphabet shape, at `alpha`.
    ///
    /// # Errors
    ///
    /// [`HealthError::UnsupportedAlpha`] (no APT table coverage) — a zero
    /// claim is also reported this way since no cutoff is derivable.
    pub fn new(h: MinEntropy, is_binary: bool, alpha: Alpha) -> Result<Self, HealthError> {
        let rct = RepetitionCountTest::new(h, alpha).ok_or(HealthError::UnsupportedAlpha {
            alpha_exp: alpha.exp(),
        })?;
        let apt = AdaptiveProportionTest::new(h, is_binary, alpha)?;
        Ok(Self {
            rct,
            apt,
            poisoned: false,
        })
    }

    /// Feeds one sample through both tests.
    ///
    /// On the first failure the monitor poisons permanently: the failing
    /// sample is not released and every subsequent call returns
    /// [`HealthError::Poisoned`].
    pub fn feed(&mut self, sample: RawSample) -> Result<(), HealthError> {
        if self.poisoned {
            return Err(HealthError::Poisoned);
        }
        let rct = self.rct.feed(sample);
        let apt = self.apt.feed(sample);
        if let Err(e) = rct {
            self.poisoned = true;
            return Err(e);
        }
        if let Err(e) = apt {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// Whether an earlier failure has permanently poisoned this monitor.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// RCT cutoff in use (for documentation and verification surfaces).
    #[must_use]
    pub const fn rct_cutoff(&self) -> u32 {
        self.rct.cutoff()
    }

    /// APT cutoff in use.
    #[must_use]
    pub const fn apt_cutoff(&self) -> u32 {
        self.apt.cutoff()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn alpha20() -> Alpha {
        Alpha::from_exp(20).unwrap()
    }

    // ── Alpha ────────────────────────────────────────────────────────

    #[test]
    fn alpha_range_enforced() {
        assert!(Alpha::from_exp(19).is_none());
        assert!(Alpha::from_exp(41).is_none());
        assert_eq!(Alpha::from_exp(20).unwrap().exp(), 20);
        assert_eq!(Alpha::from_exp(40).unwrap().exp(), 40);
        assert_eq!(Alpha::DEFAULT.exp(), 30);
    }

    // ── RCT cutoffs (§4.4.1 worked example + jent reference point) ──

    #[test]
    fn rct_cutoff_spec_worked_example() {
        // §4.4.1: α = 2⁻²⁰, H = 2.0 → C = 1 + 20/2 = 11.
        let t = RepetitionCountTest::new(MinEntropy::from_bits(2), alpha20()).unwrap();
        assert_eq!(t.cutoff(), 11);
    }

    #[test]
    fn rct_cutoff_jent_reference_point() {
        // jent v3.7.0 cert-lineage reference: α = 2⁻³⁰, H = 1 → C = 31.
        let t = RepetitionCountTest::new(MinEntropy::from_bits(1), Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 31);
    }

    #[test]
    fn rct_cutoff_varies_with_alpha_and_fractional_h() {
        // α sweep at H = 1: C = 1 + a.
        for a in [20u32, 25, 30, 40] {
            let t = RepetitionCountTest::new(MinEntropy::from_bits(1), Alpha::from_exp(a).unwrap())
                .unwrap();
            assert_eq!(t.cutoff(), 1 + a);
        }
        // Fractional H: α = 2⁻²⁰, H = 0.5 → C = 1 + ⌈20/0.5⌉ = 41.
        let t = RepetitionCountTest::new(MinEntropy::from_fraction_floor(1, 2).unwrap(), alpha20())
            .unwrap();
        assert_eq!(t.cutoff(), 41);
    }

    #[test]
    fn rct_boundary_c_minus_one_passes_c_trips() {
        // H = 2.0, α = 2⁻²⁰ → C = 11: ten repeats pass, the 11th trips.
        let mut m = HealthMonitor::new(MinEntropy::from_bits(2), false, alpha20()).unwrap();
        for _ in 0..10 {
            m.feed(7).unwrap();
        }
        assert_eq!(m.feed(7).unwrap_err(), HealthError::Failed(HealthTest::Rct));
        assert!(m.is_poisoned());
    }

    // ── APT cutoffs (Table 2 reference rows) ─────────────────────────

    #[test]
    fn apt_cutoff_table2_rows() {
        // Binary H = 1 → 589; non-binary H = 8 → 13 (§4.4.2 Table 2).
        let t = AdaptiveProportionTest::new(MinEntropy::from_bits(1), true, alpha20()).unwrap();
        assert_eq!(t.cutoff(), 589);
        let t = AdaptiveProportionTest::new(MinEntropy::from_bits(8), false, alpha20()).unwrap();
        assert_eq!(t.cutoff(), 13);
    }

    #[test]
    fn apt_h_rounds_down_to_grid() {
        // Claimed H = 0.9 bits (binary) sits between grid rows 0.8 and 1.0
        // → uses the 0.8 row (cutoff 664): claim never overstated.
        let h = MinEntropy::from_fraction_floor(9, 10).unwrap();
        let t = AdaptiveProportionTest::new(h, true, alpha20()).unwrap();
        assert_eq!(t.cutoff(), 664);
    }

    #[test]
    fn apt_below_grid_refused() {
        // Binary grid floor is H = 0.2; a claim below it has no row.
        let h = MinEntropy::from_fraction_floor(1, 10).unwrap();
        assert_eq!(
            AdaptiveProportionTest::new(h, true, alpha20()).unwrap_err(),
            HealthError::UnsupportedAlpha { alpha_exp: 20 }
        );
    }

    #[test]
    fn apt_default_alpha_now_table_covered() {
        // The α = 2⁻³⁰ default is now table-covered (generated grid landed).
        // Binary H = 1 → 609; non-binary H = 1 → 325 (the jent cross-check).
        let t =
            AdaptiveProportionTest::new(MinEntropy::from_bits(1), true, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 609);
        let t =
            AdaptiveProportionTest::new(MinEntropy::from_bits(1), false, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 325);
    }

    #[test]
    fn apt_alpha30_grid_rows() {
        // Spot-check both ends of each α = 2⁻³⁰ grid.
        //
        // The binary grid floor is the H = 0.2 row. Note 0.2 bits = 51.2
        // fixed-point steps, which floors to 51 — *below* the 0.2 row's
        // 51.2-step boundary — so a claim of exactly 1/5 rounds under the
        // grid (same fixed-point edge the α = 2⁻²⁰ path has). To exercise the
        // 0.2 row we claim 0.3 bits, which rounds DOWN to the 0.2 row → 952.
        let h_03 = MinEntropy::from_fraction_floor(3, 10).unwrap();
        let t = AdaptiveProportionTest::new(h_03, true, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 952);
        // Binary top of grid: H = 1 → 609.
        let t =
            AdaptiveProportionTest::new(MinEntropy::from_bits(1), true, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 609);
        // Non-binary: H = 8 → 16, and H = 0.5 (exactly 128 steps) → 422.
        let t =
            AdaptiveProportionTest::new(MinEntropy::from_bits(8), false, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 16);
        let t = AdaptiveProportionTest::new(
            MinEntropy::from_fraction_floor(1, 2).unwrap(),
            false,
            Alpha::DEFAULT,
        )
        .unwrap();
        assert_eq!(t.cutoff(), 422);
    }

    #[test]
    fn apt_alpha30_rounds_down_to_grid() {
        // Claimed H = 0.9 (binary) rounds DOWN to the 0.8 row at α = 2⁻³⁰
        // (cutoff 683) — same round-down discipline as the α = 2⁻²⁰ path.
        let h = MinEntropy::from_fraction_floor(9, 10).unwrap();
        let t = AdaptiveProportionTest::new(h, true, Alpha::DEFAULT).unwrap();
        assert_eq!(t.cutoff(), 683);
    }

    #[test]
    fn apt_alpha30_below_grid_refused() {
        // Below the binary grid floor (H = 0.2) there is still no row.
        let h = MinEntropy::from_fraction_floor(1, 10).unwrap();
        assert_eq!(
            AdaptiveProportionTest::new(h, true, Alpha::DEFAULT).unwrap_err(),
            HealthError::UnsupportedAlpha { alpha_exp: 30 }
        );
    }

    #[test]
    fn apt_unsupported_alpha_still_refused() {
        // An α with no table (e.g. 2⁻²⁵) is refused — cutoffs are table-borne.
        let a25 = Alpha::from_exp(25).unwrap();
        assert_eq!(
            AdaptiveProportionTest::new(MinEntropy::from_bits(1), true, a25).unwrap_err(),
            HealthError::UnsupportedAlpha { alpha_exp: 25 }
        );
    }

    #[test]
    fn apt_boundary_within_window() {
        // Non-binary, H = 8 → C = 13, W = 512: twelve A-occurrences pass,
        // the 13th trips inside the same window.
        let mut t =
            AdaptiveProportionTest::new(MinEntropy::from_bits(8), false, alpha20()).unwrap();
        t.feed(0xAB).unwrap(); // reference, count = 1
        let mut fed = 1u32;
        for i in 0..11u32 {
            // Interleave non-reference samples; stay inside the window.
            t.feed(u8::try_from(i % 7).unwrap().wrapping_add(1))
                .unwrap();
            t.feed(0xAB).unwrap();
            fed += 2;
        }
        assert!(fed < 512);
        // count is now 12; the next reference occurrence reaches C = 13.
        assert_eq!(
            t.feed(0xAB).unwrap_err(),
            HealthError::Failed(HealthTest::Apt)
        );
    }

    #[test]
    fn apt_window_rollover_resets_count() {
        // Binary, H = 1 → C = 589, W = 1024: alternating 0/1 never trips —
        // each window counts ~512 reference occurrences, under the cutoff,
        // and the count resets at every window boundary.
        let mut t = AdaptiveProportionTest::new(MinEntropy::from_bits(1), true, alpha20()).unwrap();
        let mut bit = 0u8;
        for _ in 0..(1024 * 3) {
            t.feed(bit).unwrap();
            bit ^= 1;
        }
    }

    // ── Permanent failure semantics ──────────────────────────────────

    #[test]
    fn poisoned_monitor_never_recovers() {
        let mut m = HealthMonitor::new(MinEntropy::from_bits(2), false, alpha20()).unwrap();
        for _ in 0..10 {
            m.feed(7).unwrap();
        }
        assert!(m.feed(7).is_err());
        // Even perfectly varied samples are refused after poisoning.
        for s in 0..50u8 {
            assert_eq!(m.feed(s).unwrap_err(), HealthError::Poisoned);
        }
        assert!(m.is_poisoned());
    }
}
