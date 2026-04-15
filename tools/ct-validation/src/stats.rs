//! Welch's two-sample t-test with percentile cropping, following
//! Reparaz et al., "dude, is my code constant time?" (EuroS&P 2017).
//!
//! All math here is floating-point; there are no secrets in this
//! module, so it is deliberately non-constant-time.

/// Classification of a t-test result against the dudect thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `|t| < 3.0`. No leak observable at the current sample budget.
    /// Collecting more samples might still uncover one; this is an
    /// *absence-of-evidence* result, not proof of constant-time.
    Clean,
    /// `3.0 ≤ |t| < 5.0`. Suspicious. Could be a slow-converging
    /// leak, could be measurement noise. Re-run with more samples.
    Warn,
    /// `|t| ≥ 5.0`. Clear leak — the fixed and random classes
    /// produce statistically-separated timing distributions.
    Leak,
}

impl Verdict {
    /// Classify a raw t-statistic against the dudect thresholds.
    #[must_use]
    pub fn from_t(t: f64) -> Verdict {
        let abs = t.abs();
        if abs >= 5.0 {
            Verdict::Leak
        } else if abs >= 3.0 {
            Verdict::Warn
        } else {
            Verdict::Clean
        }
    }

    /// "Worse" verdict wins — used when merging multiple
    /// percentile-cropped results.
    #[must_use]
    pub fn worst(self, other: Verdict) -> Verdict {
        match (self, other) {
            (Verdict::Leak, _) | (_, Verdict::Leak) => Verdict::Leak,
            (Verdict::Warn, _) | (_, Verdict::Warn) => Verdict::Warn,
            _ => Verdict::Clean,
        }
    }
}

/// Full result record for one target's measurement run.
#[derive(Debug, Clone)]
pub struct VerdictReport {
    /// Short human-readable target identifier, e.g. `rsa_mont2048_pow_secret`.
    pub target: &'static str,
    /// Number of measurements per class actually fed into the t-test
    /// (pre-cropping). `samples_total / 2` because half goes to each
    /// class.
    pub n_per_class: usize,
    /// The worst-case t-statistic across all percentile crops.
    pub worst_abs_t: f64,
    /// The percentile at which `worst_abs_t` was observed. `1.0`
    /// means "no cropping applied".
    pub worst_crop: f64,
    /// Overall verdict — worst-case across all crops.
    pub verdict: Verdict,
}

/// Compute Welch's two-sample t-statistic for two samples of equal
/// length. Returns `0.0` if either variance is zero or sample count
/// is below 2 — those are degenerate cases the caller should never
/// feed us in practice, but returning zero keeps the math stable.
#[must_use]
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let na = a.len();
    let nb = b.len();
    if na < 2 || nb < 2 {
        return 0.0;
    }
    let (ma, va) = mean_var(a);
    let (mb, vb) = mean_var(b);
    let denom = (va / (na as f64) + vb / (nb as f64)).sqrt();
    if denom == 0.0 || !denom.is_finite() {
        return 0.0;
    }
    (ma - mb) / denom
}

/// Sample mean and **sample** (Bessel-corrected) variance.
fn mean_var(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var)
}

/// Run Welch's test at a battery of percentile crops and return the
/// worst (highest `|t|`) result. `samples_fixed` and `samples_random`
/// are consumed by value — we sort their copies internally — so the
/// caller doesn't have to pre-sort.
#[must_use]
pub fn cropped_report(
    target: &'static str,
    mut samples_fixed: Vec<f64>,
    mut samples_random: Vec<f64>,
) -> VerdictReport {
    // Sort ascending so we can crop tails. NaN is not expected here
    // (we feed f64 counts derived from integer clock ticks) but we
    // treat any NaN as "larger than everything" so it gets cropped
    // first.
    samples_fixed.sort_by(|x, y| x.partial_cmp(y).unwrap_or(core::cmp::Ordering::Greater));
    samples_random.sort_by(|x, y| x.partial_cmp(y).unwrap_or(core::cmp::Ordering::Greater));

    // Drop the lowest 1% of each class first — those are usually
    // impossibly-fast measurements where the CPU pipelined the
    // entire target into a previous instruction's shadow.
    let drop_low = (samples_fixed.len() / 100).max(1);
    let fixed_base = &samples_fixed[drop_low..];
    let random_base = &samples_random[drop_low..];

    // Percentile crops — from the dudect paper, inclusive of the
    // "no crop" case.
    let crops: &[f64] = &[1.0, 0.999, 0.995, 0.99, 0.975, 0.95, 0.9];

    let mut worst_abs_t = 0.0_f64;
    let mut worst_crop = 1.0_f64;
    for &p in crops {
        let keep_f = ((fixed_base.len() as f64) * p) as usize;
        let keep_r = ((random_base.len() as f64) * p) as usize;
        if keep_f < 2 || keep_r < 2 {
            continue;
        }
        let cropped_f = &fixed_base[..keep_f];
        let cropped_r = &random_base[..keep_r];
        let t = welch_t(cropped_f, cropped_r);
        if t.abs() > worst_abs_t {
            worst_abs_t = t.abs();
            worst_crop = p;
        }
    }

    VerdictReport {
        target,
        n_per_class: samples_fixed.len(),
        worst_abs_t,
        worst_crop,
        verdict: Verdict::from_t(worst_abs_t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When fixed and random samples are drawn from the same
    /// deterministic sequence, Welch's t should be exactly zero.
    #[test]
    fn welch_t_zero_for_identical_inputs() {
        let xs: Vec<f64> = (0..1000).map(|i| i as f64).collect();
        let t = welch_t(&xs, &xs);
        assert!(
            t.abs() < 1e-12,
            "t should be 0 for identical inputs, got {t}"
        );
    }

    /// Classic textbook fixture: two small hand-computed samples.
    /// Sample A: [30, 31, 29, 32, 30], mean=30.4, sample var=1.3
    /// Sample B: [28, 27, 29, 26, 28], mean=27.6, sample var=1.3
    /// se = sqrt(1.3/5 + 1.3/5) = sqrt(0.52) ≈ 0.7211
    /// t  = (30.4 − 27.6) / 0.7211 ≈ 3.8828
    #[test]
    fn welch_t_matches_hand_computed_fixture() {
        let a = [30.0_f64, 31.0, 29.0, 32.0, 30.0];
        let b = [28.0_f64, 27.0, 29.0, 26.0, 28.0];
        let t = welch_t(&a, &b);
        // Hand-computed expected value, allow a small FP tolerance.
        assert!((t - 3.8828).abs() < 1e-3, "unexpected t = {t}");
    }

    /// Strongly-separated samples should land in Leak.
    #[test]
    fn verdict_classifies_large_t_as_leak() {
        // 200 samples drawn from two well-separated means. Using an
        // LCG so the test stays deterministic.
        let mut rng: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (rng >> 33) as u32
        };
        let fixed: Vec<f64> = (0..200).map(|_| 100.0 + f64::from(next() % 10)).collect();
        let random: Vec<f64> = (0..200).map(|_| 200.0 + f64::from(next() % 10)).collect();
        let report = cropped_report("fixture_leak", fixed, random);
        assert_eq!(report.verdict, Verdict::Leak);
        assert!(report.worst_abs_t > 50.0);
    }

    /// Samples from the same distribution should land in Clean.
    #[test]
    fn verdict_classifies_small_t_as_clean() {
        let mut rng: u64 = 0xdead_beef_cafe_babe;
        let mut next = || {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (rng >> 33) as u32
        };
        let fixed: Vec<f64> = (0..1000).map(|_| f64::from(next() % 1000)).collect();
        let random: Vec<f64> = (0..1000).map(|_| f64::from(next() % 1000)).collect();
        let report = cropped_report("fixture_clean", fixed, random);
        assert_eq!(
            report.verdict,
            Verdict::Clean,
            "uniform-same-distribution gave t = {}",
            report.worst_abs_t,
        );
    }

    #[test]
    fn verdict_worst_is_monotone() {
        assert_eq!(Verdict::Clean.worst(Verdict::Warn), Verdict::Warn);
        assert_eq!(Verdict::Warn.worst(Verdict::Clean), Verdict::Warn);
        assert_eq!(Verdict::Leak.worst(Verdict::Clean), Verdict::Leak);
        assert_eq!(Verdict::Clean.worst(Verdict::Leak), Verdict::Leak);
        assert_eq!(Verdict::Leak.worst(Verdict::Warn), Verdict::Leak);
    }
}
