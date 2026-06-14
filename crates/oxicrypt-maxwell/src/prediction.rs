//! SP 800-90B §6.3.7–§6.3.10 **shared prediction-estimate** machinery.
//!
//! The four prediction estimators — MultiMCW (§6.3.7), Lag (§6.3.8), MultiMMC
//! (§6.3.9), and LZ78Y (§6.3.10) — each run their own predictor over the data
//! and then feed three integers into one common min-entropy formula: the number
//! of correct predictions `C`, the number of predictions `N`, and the length of
//! the longest run of correct predictions `max_run_len`. This module is the
//! Rust transcription of that shared formula, the NIST `SP800-90B_EntropyAssessment`
//! reference tool ("EA tool") v1.1.8 `predictionEstimate` (and its helpers
//! `calc_p_local`, `prediction_estimate_function`, `relEpsilonEqual`) in
//! `cpp/shared/utils.h`. Like the rest of `oxicrypt-maxwell` it is **outside the
//! cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The formula (SP 800-90B §6.3, "predictionEstimate")
//!
//! Given `C` correct predictions out of `N`, alphabet size `k`, and the longest
//! correct-prediction run `max_run_len`:
//!
//! 1. `p_global = C / N`. Its upper 99% confidence bound is
//!    `p_global' = min(1, p_global + Z·sqrt(p_global(1−p_global)/(N−1)))` when
//!    `p_global > 0`, and `1 − 0.01^(1/N)` when `p_global == 0` (the EA tool's
//!    zero-count branch). `Z = Φ⁻¹(0.995) = 2.5758293035489008`
//!    ([`crate::Z_995`]).
//! 2. `p_local` is the solution `p` of the recurrence-derived equation
//!    `prediction_estimate_function(p, max_run_len + 1, N) = log(0.99)`, found by
//!    a bisection over `p ∈ [curMax, 1]` (the EA tool's `calc_p_local`). It is
//!    only computed when it can actually raise the estimate (`curMax < 1` and the
//!    function at `curMax` already exceeds `log(0.99)`).
//! 3. `entEst = −log2(max(1/k, p_global', p_local))`.
//!
//! # The `prediction_estimate_function` recurrence (the error-prone part)
//!
//! `prediction_estimate_function(p, r, N)` evaluates, for `q = 1 − p`, the fixed
//! point of `x ← 1 + q·p^r·x^(r+1)` (iterated until `x` stops changing, ≤ 66
//! steps), then returns
//! `log(1 − p·x) − log((r + 1 − r·x)·q) − (N + 1)·log(x)`. The EA tool runs this
//! in `long double`; this module uses `f64` (the 1.0e-6 parity bound absorbs the
//! difference — see `docs/estimator-parity-tolerances.md`). The convergence test
//! `(x − xlast) > LDBL_EPSILON·x` becomes `(x − xlast) > f64::EPSILON·x`.
//!
//! # Bisection convergence (`relEpsilonEqual`)
//!
//! `calc_p_local` stops when the function value is "close enough" to `log(0.99)`
//! per the EA tool's `relEpsilonEqual(pVal, log_alpha, ABSEPSILON, RELEPSILON, 4)`
//! — a combined absolute / relative / ULP closeness test (`ABSEPSILON = DBL_MIN`,
//! `RELEPSILON = DBL_EPSILON`, `maxULP = 4`). It is transcribed faithfully in
//! [`rel_epsilon_equal`] because the exact stopping point determines the returned
//! `p` to the last few ULPs, and that flows straight into the min-entropy.

// This module is a 1:1 transcription of the EA reference's predictionEstimate /
// calc_p_local / prediction_estimate_function / relEpsilonEqual. Those routines
// are floating-point- and arithmetic-heavy and use the reference's conventional
// names (C, N, k, p, q, x, r, pVal, lbound/hbound, …); faithfulness to the C++
// is the priority and the parity oracle (<= 1e-6 vs EA on all bundled datasets)
// is the real correctness gate. This module-level allow covers the
// algorithm-inherent lints uniformly so the transcription reads like the
// reference rather than being restructured to satisfy style/restriction lints.
#![allow(
    clippy::cast_precision_loss,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use crate::Z_995;

/// The EA tool's bisection iteration cap (`utils.h`: `#define ITERMAX 1076`).
const ITERMAX: usize = 1076;

/// One shared prediction min-entropy result, mirroring the values the EA tool's
/// `predictionEstimate` prints at verbose level 3.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PredictionEstimate {
    /// Number of correct predictions (`C`).
    pub c: u64,
    /// Number of predictions made (`N`).
    pub n: u64,
    /// Longest run of correct predictions (`max_run_len`); the EA tool reports
    /// `r = max_run_len + 1`.
    pub max_run_len: u64,
    /// `p_global = C / N`.
    pub p_global: f64,
    /// `p_global'` — the upper 99% confidence bound on `p_global`.
    pub p_global_prime: f64,
    /// `p_local`, or `-1.0` when it could not raise the estimate (the EA tool's
    /// "P_local can't change the result" sentinel).
    pub p_local: f64,
    /// `entEst = −log2(max(1/k, p_global', p_local))` — the per-symbol prediction
    /// min-entropy in bits (per-bit on the bitstring track).
    pub min_entropy: f64,
}

/// Combined absolute / relative / ULP floating-point closeness test, transcribed
/// from `utils.h::relEpsilonEqual(A, B, maxAbsFactor, maxRelFactor, maxULP)`.
///
/// Returns true when `a` and `b` are close per: equality (incl. infinities),
/// absolute closeness when relative comparison would be nonsense (subnormals /
/// overflow), relative closeness (`|b−a| ≤ |b|·maxRelFactor`), or being within
/// `max_ulp` ULPs of one another (same sign only).
#[allow(
    // The bit-pattern ULP comparison mirrors the EA tool's memcpy(&Aint,&absA);
    // f64::to_bits is the safe Rust spelling of that reinterpret. The float
    // equality checks are deliberate (they are the reference's exact branches).
    clippy::float_cmp
)]
#[must_use]
pub fn rel_epsilon_equal(
    a: f64,
    b: f64,
    max_abs_factor: f64,
    max_rel_factor: f64,
    max_ulp: u64,
) -> bool {
    // NaN is by definition not equal to anything (including itself).
    if a.is_nan() || b.is_nan() {
        return false;
    }

    // Equal values (handles equal infinities and exact copies).
    if a == b {
        return true;
    }

    // If either is infinity but they are not equal, they aren't close.
    if a.is_infinite() || b.is_infinite() {
        return false;
    }

    let mut a = a;
    let mut b = b;
    let mut abs_a = a.abs();
    let mut abs_b = b.abs();
    // Make A the closest to 0 (swap so abs_a <= abs_b).
    if abs_a > abs_b {
        std::mem::swap(&mut a, &mut b);
        std::mem::swap(&mut abs_a, &mut abs_b);
    }

    // Difference of the larger magnitude from the smaller magnitude.
    let diff = (b - a).abs();

    // Is relative closeness going to be nonsense? (subnormal / overflow guards,
    // matching the EA tool's DBL_MIN / isinf checks).
    if abs_a < f64::MIN_POSITIVE
        || diff < f64::MIN_POSITIVE
        || diff.is_infinite()
        || abs_b * max_rel_factor < f64::MIN_POSITIVE
    {
        // Relative closeness is nonsense; fall back to absolute.
        return diff <= max_abs_factor;
    }
    // Relative closeness is meaningful.
    if diff <= abs_b * max_rel_factor {
        return true;
    }

    // Neither is subnormal and they aren't conventionally close, but check ULPs.
    // Different signs can't be a few ULPs apart.
    if a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }

    // Reinterpret the magnitudes as integers (the EA tool's memcpy trick).
    let a_int = abs_a.to_bits();
    let b_int = abs_b.to_bits();
    // By IEEE-754 construction abs_b > abs_a here, so b_int > a_int.
    b_int.saturating_sub(a_int) <= max_ulp
}

/// `prediction_estimate_function(p, r, N)` from `utils.h`: evaluate the
/// fixed-point recurrence `x ← 1 + q·p^r·x^(r+1)` (`q = 1 − p`) to convergence,
/// then return `log(1 − p·x) − log((r + 1 − r·x)·q) − (N + 1)·log(x)`.
///
/// `p` must be in `(0, 1)` (the EA tool asserts `p >= 1/k` and `p < 1`); callers
/// only ever pass values in that range.
#[must_use]
pub fn prediction_estimate_function(p: f64, r: f64, n: f64) -> f64 {
    let q = 1.0 - p;
    let mut x = 1.0_f64;
    let mut xlast = 0.0_f64;

    // x is monotonic up in [1, 1/p]; iterate until it stops changing (<= 66
    // steps, matching the EA tool's `i <= 65` loop bound).
    let mut i = 0usize;
    while i <= 65 && (x - xlast) > (f64::EPSILON * x) {
        xlast = x;
        x = 1.0 + q * p.powf(r) * x.powf(r + 1.0);
        i = i.saturating_add(1);
    }

    (1.0 - p * x).ln() - ((r + 1.0 - r * x) * q).ln() - (n + 1.0) * x.ln()
}

/// `calc_p_local(max_run_len, N, ldomain)` from `utils.h`: bisection for the
/// `p_local` solving `prediction_estimate_function(p, max_run_len+1, N) = log(0.99)`
/// over `p ∈ [ldomain, 1]`.
///
/// Transcribes the EA tool's bisection loop byte-for-byte, including its
/// invariant guards and cycle detection, so the returned `p` matches to the last
/// few ULPs.
#[allow(
    // The bisection deliberately compares floats for the cycle check (lastP == p)
    // and uses the reference's open/closed-interval guards; those exact branches
    // are load-bearing for reproducing the EA result.
    clippy::float_cmp
)]
#[must_use]
pub fn calc_p_local(max_run_len: u64, n: u64, ldomain: f64) -> f64 {
    // The EA tool's RELEPSILON = DBL_EPSILON, ABSEPSILON = DBL_MIN, maxULP = 4.
    let rel_epsilon = f64::EPSILON;
    let abs_epsilon = f64::MIN_POSITIVE;
    let max_ulp = 4u64;

    let log_alpha = 0.99_f64.ln();
    let hdomain = 1.0_f64;

    let mut lbound = ldomain;
    let mut hbound = hdomain;

    let mut lvalue = f64::INFINITY;
    let mut hvalue = f64::NEG_INFINITY;

    let r = (max_run_len as f64) + 1.0;
    let n_f = n as f64;

    // Bounds are in [0,1] so overflow isn't an issue (underflow is handled).
    let mut p = f64::midpoint(lbound, hbound);
    let mut p_val = prediction_estimate_function(p, r, n_f);

    for _ in 0..ITERMAX {
        // Reached "equality"?
        if rel_epsilon_equal(p_val, log_alpha, abs_epsilon, rel_epsilon, max_ulp) {
            break;
        }

        // Update based on the found pVal.
        if log_alpha < p_val {
            lbound = p;
            lvalue = p_val;
        } else {
            hbound = p;
            hvalue = p_val;
        }

        // Verify ldomain <= lbound < p < hbound <= hdomain.
        if lbound >= hbound {
            p = lbound.max(hbound).min(hdomain);
            break;
        }

        // Invariant: lbound, hbound must lie within [ldomain, hdomain].
        if !in_closed_interval(lbound, ldomain, hdomain)
            || !in_closed_interval(hbound, ldomain, hdomain)
        {
            p = hdomain;
            break;
        }

        // Invariant: the target must lie within [lvalue, hvalue].
        if !in_closed_interval(log_alpha, lvalue, hvalue) {
            p = hdomain;
            break;
        }

        // Update p.
        let last_p = p;
        p = f64::midpoint(lbound, hbound);

        // Invariant: p must lie strictly within (lbound, hbound).
        if !in_open_interval(p, lbound, hbound) {
            p = hbound;
            break;
        }

        // Cycle detection.
        if last_p == p {
            p = hbound;
            break;
        }

        p_val = prediction_estimate_function(p, r, n_f);

        // Invariant: pVal must lie within [lvalue, hvalue] (loose monotonicity).
        if !in_closed_interval(p_val, lvalue, hvalue) {
            p = hbound;
            break;
        }
    }

    p
}

/// `INCLOSEDINTERVAL(x, a, b)` from `utils.h` — true when `x` is in the closed
/// interval bounded by `a` and `b` (in either order).
fn in_closed_interval(x: f64, a: f64, b: f64) -> bool {
    if a > b {
        (x >= b) && (x <= a)
    } else {
        (x >= a) && (x <= b)
    }
}

/// `INOPENINTERVAL(x, a, b)` from `utils.h` — true when `x` is in the open
/// interval bounded by `a` and `b` (in either order).
fn in_open_interval(x: f64, a: f64, b: f64) -> bool {
    if a > b {
        (x > b) && (x < a)
    } else {
        (x > a) && (x < b)
    }
}

/// `predictionEstimate(C, N, max_run_len, k, …)` from `utils.h`: the shared
/// min-entropy formula for all four §6.3.7–§6.3.10 prediction estimators.
///
/// `c` correct predictions out of `n`, longest correct-prediction run
/// `max_run_len`, alphabet size `k`. Deterministic; does not panic.
///
/// Returns the full [`PredictionEstimate`]; `min_entropy` is the per-symbol
/// (per-bit on the bitstring track) result the EA tool prints as "min entropy".
#[must_use]
pub fn prediction_estimate(c: u64, n: u64, max_run_len: u64, k: u64) -> PredictionEstimate {
    // curMax starts at 1/k.
    let mut cur_max = 1.0 / (k as f64);

    let p_global = if n == 0 { 0.0 } else { (c as f64) / (n as f64) };

    let n_f = n as f64;
    let p_global_prime = if p_global > 0.0 {
        (p_global + Z_995 * ((p_global * (1.0 - p_global)) / (n_f - 1.0)).sqrt()).min(1.0)
    } else {
        // Zero-count branch: 1 - 0.01^(1/N).
        1.0 - 0.01_f64.powf(1.0 / n_f)
    };

    cur_max = cur_max.max(p_global_prime);

    let mut p_local = -1.0_f64;
    let r = (max_run_len as f64) + 1.0;
    if cur_max < 1.0 && prediction_estimate_function(cur_max, r, n_f) > 0.99_f64.ln() {
        p_local = calc_p_local(max_run_len, n, cur_max);
        cur_max = cur_max.max(p_local);
    }

    let min_entropy = -cur_max.log2();

    PredictionEstimate {
        c,
        n,
        max_run_len,
        p_global,
        p_global_prime,
        p_local,
        min_entropy,
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss
)]
mod tests {
    use super::*;

    /// rand8_short bitstring MultiMCW anchor, from the EA tool verbose-3 output
    /// (`selftest/rand8_short.res`): C = 39756, r = 15 (max_run_len = 14),
    /// N = 79937, P_global = 0.49734165655453672,
    /// P_global' = 0.50189688057077464, P_local can't change the result,
    /// min entropy = 0.99453711551450596. The shared formula must reproduce
    /// these from (C, N, max_run_len, k=2).
    #[test]
    fn rand8_short_multi_mcw_shared_formula() {
        const EPS: f64 = 1.0e-9;
        let est = prediction_estimate(39756, 79937, 14, 2);
        assert!(
            (est.p_global - 0.497_341_656_554_536_7).abs() < EPS,
            "p_global={}",
            est.p_global
        );
        assert!(
            (est.p_global_prime - 0.501_896_880_570_774_6).abs() < EPS,
            "p_global_prime={}",
            est.p_global_prime
        );
        // P_local can't change the result for this vector.
        assert!(
            est.p_local < 0.0,
            "p_local should be the -1 sentinel: {}",
            est.p_local
        );
        assert!(
            (est.min_entropy - 0.994_537_115_514_506).abs() < EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// biased-random-bits MultiMCW anchor (1-bit; Literal == bitstring):
    /// C = 979_925, r = 534 (max_run_len = 533), N = 999_937,
    /// P_global = 0.97998673916456736, P_global' = 0.9803474839023909,
    /// min entropy = 0.028634892142081356.
    #[test]
    fn biased_random_bits_multi_mcw_shared_formula() {
        const EPS: f64 = 1.0e-9;
        let est = prediction_estimate(979_925, 999_937, 533, 2);
        assert!(
            (est.p_global - 0.979_986_739_164_567_4).abs() < EPS,
            "p_global={}",
            est.p_global
        );
        assert!(
            (est.p_global_prime - 0.980_347_483_902_390_9).abs() < EPS,
            "p_global_prime={}",
            est.p_global_prime
        );
        assert!(
            (est.min_entropy - 0.028_634_892_142_081_356).abs() < EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// The p_global == 0 branch uses `1 - 0.01^(1/N)`, not the confidence bound.
    #[test]
    fn zero_count_branch() {
        let est = prediction_estimate(0, 1000, 0, 2);
        let expected = 1.0 - 0.01_f64.powf(1.0 / 1000.0);
        assert!(
            (est.p_global_prime - expected).abs() < 1.0e-12,
            "p_global_prime={}",
            est.p_global_prime
        );
        assert!(est.min_entropy.is_finite());
    }

    /// Determinism: the shared formula is bit-identical across runs.
    #[test]
    fn determinism_bit_exact() {
        let a = prediction_estimate(39756, 79937, 14, 2);
        let b = prediction_estimate(39756, 79937, 14, 2);
        assert_eq!(a, b);
    }

    /// rel_epsilon_equal sanity: a value equals itself; well-separated values do
    /// not; values within a few ULPs do.
    #[test]
    fn rel_epsilon_equal_basics() {
        assert!(rel_epsilon_equal(
            1.0,
            1.0,
            f64::MIN_POSITIVE,
            f64::EPSILON,
            4
        ));
        assert!(!rel_epsilon_equal(
            1.0,
            2.0,
            f64::MIN_POSITIVE,
            f64::EPSILON,
            4
        ));
        let x = 1.0_f64;
        let y = f64::from_bits(x.to_bits() + 2); // 2 ULPs away
        assert!(rel_epsilon_equal(x, y, f64::MIN_POSITIVE, f64::EPSILON, 4));
    }
}
