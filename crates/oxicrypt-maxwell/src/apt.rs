//! SP 800-90B §4.4.2 Adaptive Proportion Test (APT) cutoff generator.
//!
//! This module computes the APT cutoff `C` for an arbitrary `(window, H, α)`
//! point and emits the standard `(H, C)` grids that seed the in-boundary
//! `oxicrypt-entropy` APT tables. It is **out of the cryptographic boundary**:
//! pure offline analysis tooling, like the rest of `oxicrypt-maxwell`. The
//! in-boundary crate never computes a binomial cutoff at runtime — it carries a
//! precomputed integer table generated here and verified against the same
//! reference points.
//!
//! # The APT cutoff (SP 800-90B §4.4.2)
//!
//! For window size `W` and per-sample max probability `p = 2⁻ᴴ`, the cutoff is
//!
//! ```text
//! C = 1 + qbinom(1 − α, W, p)
//! ```
//!
//! where `qbinom(q, n, p)` is the smallest integer `k` such that the binomial
//! CDF `P(X ≤ k; n, p) ≥ q` and `α = 2⁻ᵃ` is the cutoff-generating parameter
//! (the probability that a source at exactly its claimed H trips the test —
//! not the observed false-positive rate; see the Security Policy on ISC-125).
//! `W` is **1024 for binary data** and **512 for non-binary data** (§4.4.2).
//!
//! ## CDF via the regularized incomplete beta function
//!
//! The binomial CDF is evaluated through the regularized incomplete beta
//! function (the same family R's `qbinom` uses), *not* a PMF sum — a naive
//! Excel-`CRITBINOM`-style summation is known to be imprecise at `α = 2⁻³⁰`
//! (documented in the jent reference). The identity is
//!
//! ```text
//! P(X ≤ k; n, p) = I_{1−p}(n − k, k + 1)
//! ```
//!
//! and `I_x(a, b)` is computed in `f64` with the Numerical Recipes
//! `betai`/`betacf` method: a `lgamma`-based prefactor times the Lentz
//! continued-fraction evaluation of the incomplete beta, with the standard
//! `x < (a+1)/(a+b+2)` symmetry switch for continued-fraction convergence.
//!
//! # Precision (f64 sufficed — no escalation)
//!
//! The task spec mandates a self-correcting precision rule: implement in `f64`
//! first, and only escalate (exact big-integer tails for integer `H`,
//! extended precision for fractional `H`) if any reference point is off. **The
//! `f64` incomplete-beta method reproduces all 11 reference points exactly**
//! (see [`tests`]), so no precision escalation was needed for any row class.
//! The continued fraction is iterated to a 3e-16 relative tolerance, and the
//! `qbinom` search hardens against the last-ULP wobble by stepping back/forward
//! one index around the bisection result until the exact smallest `k` with
//! `CDF ≥ q` is pinned. The cutoff itself is an integer, so the only precision
//! requirement is that the CDF land on the correct side of `q` at the boundary
//! index — which it does on every reference point with margin.
//!
//! # Validation (the 11-point reproduction)
//!
//! From **SP 800-90B Table 2** (September 2025 final), `α = 2⁻²⁰`:
//!
//! | Track | W | H | C |
//! |-------|------|-----|-----|
//! | binary | 1024 | 0.2 | 941 |
//! | binary | 1024 | 0.4 | 840 |
//! | binary | 1024 | 0.6 | 748 |
//! | binary | 1024 | 0.8 | 664 |
//! | binary | 1024 | 1.0 | 589 |
//! | non-binary | 512 | 0.5 | 410 |
//! | non-binary | 512 | 1.0 | 311 |
//! | non-binary | 512 | 2.0 | 177 |
//! | non-binary | 512 | 4.0 | 62 |
//! | non-binary | 512 | 8.0 | 13 |
//!
//! plus the jent cross-check `W = 512, H = 1, α = 2⁻³⁰ → C = 325` (jent v3.7.0
//! cert lineage). All 11 are asserted exactly by the unit tests in this module.
//!
//! # References
//!
//! - NIST SP 800-90B, §4.4.2 (Adaptive Proportion Test) and Table 2, September
//!   2025 final.
//! - jent (jitterentropy-library) v3.7.0: `W = 512, H = 1, α = 2⁻³⁰ → 325`.
//! - Press et al., *Numerical Recipes*, 3rd ed., §6.4 (`betai`/`betacf`).

/// Smallest positive `f64` used to guard against division by zero in the
/// continued fraction (Numerical Recipes `FPMIN`).
const FPMIN: f64 = 1.0e-300;

/// Relative convergence tolerance for the continued fraction (Numerical
/// Recipes `EPS`, near `f64` machine epsilon).
const EPS: f64 = 3.0e-16;

/// Maximum continued-fraction iterations before bailing out. The incomplete
/// beta converges in far fewer for the binomial parameters used here; the cap
/// only bounds pathological inputs.
const MAXIT: u32 = 2000;

/// Lentz continued-fraction evaluation of the incomplete beta `I_x(a, b)`
/// (Numerical Recipes `betacf`). Valid for `0 < x < 1`.
// The single-letter names (a, b, c, d, h, m, x) are the canonical Numerical
// Recipes variable names; renaming them would obscure the transcription. All
// float arithmetic here is pure analysis (out of boundary), not crypto.
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suspicious_operation_groupings
)]
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;

    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;

    let mut m: u32 = 1;
    while m <= MAXIT {
        let mf = f64::from(m);
        let m2 = 2.0 * mf;

        // One even step, then one odd step (the two halves of the recurrence).
        let aa = mf * (b - mf) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;

        let aa = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;

        if (del - 1.0).abs() < EPS {
            break;
        }
        m = m.saturating_add(1);
    }
    h
}

/// Regularized incomplete beta function `I_x(a, b)` in `f64` (Numerical
/// Recipes `betai`). Returns a value in `[0, 1]`.
#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    // Prefactor: x^a (1-x)^b / (a B(a,b)), computed via lgamma for stability.
    let ln_bt = lgamma(a + b) - lgamma(a) - lgamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let bt = ln_bt.exp();
    // Continued fraction converges fast for x below the symmetry point; use the
    // I_x(a,b) = 1 - I_{1-x}(b,a) reflection otherwise.
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// Natural log of the gamma function. `f64::ln_gamma` is unstable, so this
/// uses the Lanczos approximation (g = 7, n = 9), accurate to ~15 digits for
/// the positive real arguments the binomial CDF produces.
fn lgamma(x: f64) -> f64 {
    // Lanczos coefficients (g = 7). Trimmed to f64-representable precision.
    const G: f64 = 7.0;
    const COEF: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    // Reflection for x < 0.5 keeps accuracy; binomial CDF args are >= 1, but
    // this makes lgamma correct in general.
    if x < 0.5 {
        // ln Γ(x) = ln(π / sin(πx)) − ln Γ(1 − x)
        let pi = core::f64::consts::PI;
        (pi / (pi * x).sin()).ln() - lgamma(1.0 - x)
    } else {
        let xm1 = x - 1.0;
        let mut a = COEF[0];
        let t = xm1 + G + 0.5;
        // Accumulate COEF[i] / (xm1 + i) for i = 1..=8, advancing an f64 index
        // alongside the slice iterator (no usize→f64 cast).
        let mut denom = xm1 + 1.0;
        for c in COEF.iter().skip(1) {
            a += c / denom;
            denom += 1.0;
        }
        let sqrt_2pi = (2.0 * core::f64::consts::PI).sqrt();
        // ln Γ(x) = ln(√(2π)) + ln(a) + (x − 0.5)·ln(t) − t  (Lanczos form).
        sqrt_2pi.ln() + a.ln() + (xm1 + 0.5) * t.ln() - t
    }
}

/// Binomial CDF `P(X ≤ k; n, p)` via the incomplete-beta identity
/// `P(X ≤ k) = I_{1−p}(n − k, k + 1)`.
///
/// `k` is clamped into `[0, n]` semantics: `k < 0` is not representable (`u32`),
/// `k >= n` returns `1.0`.
#[allow(clippy::many_single_char_names)]
fn binom_cdf(k: u32, n: u32, p: f64) -> f64 {
    if k >= n {
        return 1.0;
    }
    // k < n, so n - k >= 1: saturating_sub never underflows here.
    let a = f64::from(n.saturating_sub(k));
    let b = f64::from(k) + 1.0;
    betai(a, b, 1.0 - p)
}

/// `qbinom(q, n, p)`: the smallest integer `k` with `P(X ≤ k; n, p) ≥ q`.
///
/// Bisection to bracket the quantile, then a one-step correction in each
/// direction to absorb last-ULP wobble in the CDF — guaranteeing the exact
/// smallest `k`, not merely one near it.
fn qbinom(q: f64, n: u32, p: f64) -> u32 {
    let mut lo: u32 = 0;
    let mut hi: u32 = n;
    while lo < hi {
        // Midpoint without overflow: lo + (hi - lo) >> 1. The right shift is
        // an exact halving of a non-negative span; no integer-division lint.
        let mid = lo.saturating_add(hi.saturating_sub(lo) >> 1);
        if binom_cdf(mid, n, p) >= q {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    // Correct downward: while the predecessor still satisfies CDF >= q.
    while lo > 0 && binom_cdf(lo.saturating_sub(1), n, p) >= q {
        lo = lo.saturating_sub(1);
    }
    // Correct upward: while the current index falls short of q.
    while lo < n && binom_cdf(lo, n, p) < q {
        lo = lo.saturating_add(1);
    }
    lo
}

/// Computes the SP 800-90B §4.4.2 APT cutoff `C` for window `window`,
/// min-entropy `H = h_num / h_den` bits, and false-positive exponent
/// `alpha_exp` (`α = 2⁻ᵃˡᵖʰᵃ⁻ᵉˣᵖ`).
///
/// `H` is taken as an exact rational `h_num / h_den` so the caller never has to
/// pass a lossy `f64` min-entropy. The per-sample probability is
/// `p = 2⁻ᴴ = 2^(−h_num / h_den)`, computed once in `f64`. The cutoff is
/// `C = 1 + qbinom(1 − α, window, p)`.
///
/// # Panics
///
/// Does not panic. `h_den == 0` is treated as `H = 0` (`p = 1`), giving the
/// degenerate cutoff for a zero-entropy claim; callers pass non-zero `h_den`.
#[must_use]
pub fn apt_cutoff(window: u32, h_num: u32, h_den: u32, alpha_exp: u32) -> u32 {
    // p = 2^(-H) where H = h_num/h_den (bits). H = 0 (or h_den == 0) -> p = 1.
    let h = if h_den == 0 {
        0.0
    } else {
        f64::from(h_num) / f64::from(h_den)
    };
    let p = (2.0_f64).powf(-h);
    // α = 2^(-alpha_exp); q = 1 - α.
    let alpha = (2.0_f64).powf(-f64::from(alpha_exp));
    let q = 1.0 - alpha;
    1u32.saturating_add(qbinom(q, window, p))
}

/// One `(H, C)` row of a generated APT grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AptRow {
    /// Min-entropy numerator (bits = `h_num / h_den`).
    pub h_num: u32,
    /// Min-entropy denominator.
    pub h_den: u32,
    /// Generated cutoff `C`.
    pub cutoff: u32,
}

/// The standard binary (W = 1024) H grid: `{1/5, 2/5, 3/5, 4/5, 1/1}`.
pub const BINARY_H_GRID: [(u32, u32); 5] = [(1, 5), (2, 5), (3, 5), (4, 5), (1, 1)];

/// The standard non-binary (W = 512) H grid: `{1/2, 1/1, 2/1, 4/1, 8/1}`.
pub const NON_BINARY_H_GRID: [(u32, u32); 5] = [(1, 2), (1, 1), (2, 1), (4, 1), (8, 1)];

/// Window size for binary data (§4.4.2).
pub const WINDOW_BINARY: u32 = 1024;

/// Window size for non-binary data (§4.4.2).
pub const WINDOW_NON_BINARY: u32 = 512;

/// Generates the binary (W = 1024) APT grid at `alpha_exp`.
#[must_use]
pub fn binary_grid(alpha_exp: u32) -> [AptRow; 5] {
    grid(WINDOW_BINARY, &BINARY_H_GRID, alpha_exp)
}

/// Generates the non-binary (W = 512) APT grid at `alpha_exp`.
#[must_use]
pub fn non_binary_grid(alpha_exp: u32) -> [AptRow; 5] {
    grid(WINDOW_NON_BINARY, &NON_BINARY_H_GRID, alpha_exp)
}

/// Generates a 5-row grid for a fixed window over an H grid.
fn grid(window: u32, h_grid: &[(u32, u32); 5], alpha_exp: u32) -> [AptRow; 5] {
    let mut out = [AptRow {
        h_num: 0,
        h_den: 1,
        cutoff: 0,
    }; 5];
    let mut i = 0usize;
    while i < h_grid.len() {
        if let (Some(&(num, den)), Some(slot)) = (h_grid.get(i), out.get_mut(i)) {
            *slot = AptRow {
                h_num: num,
                h_den: den,
                cutoff: apt_cutoff(window, num, den, alpha_exp),
            };
        }
        i = i.saturating_add(1);
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// SP 800-90B Table 2 (α = 2⁻²⁰), binary W = 1024 — all five rows exact.
    #[test]
    fn table2_binary_alpha20_exact() {
        let expected = [
            (1, 5, 941),
            (2, 5, 840),
            (3, 5, 748),
            (4, 5, 664),
            (1, 1, 589),
        ];
        for (num, den, c) in expected {
            assert_eq!(
                apt_cutoff(WINDOW_BINARY, num, den, 20),
                c,
                "binary H={num}/{den}"
            );
        }
    }

    /// SP 800-90B Table 2 (α = 2⁻²⁰), non-binary W = 512 — all five rows exact.
    #[test]
    fn table2_non_binary_alpha20_exact() {
        let expected = [
            (1, 2, 410),
            (1, 1, 311),
            (2, 1, 177),
            (4, 1, 62),
            (8, 1, 13),
        ];
        for (num, den, c) in expected {
            assert_eq!(
                apt_cutoff(WINDOW_NON_BINARY, num, den, 20),
                c,
                "non-binary H={num}/{den}"
            );
        }
    }

    /// jent cross-check: W = 512, H = 1, α = 2⁻³⁰ → 325 (jent v3.7.0 lineage).
    #[test]
    fn jent_cross_check_alpha30_exact() {
        assert_eq!(apt_cutoff(WINDOW_NON_BINARY, 1, 1, 30), 325);
    }

    /// The full 11-point reproduction in one assertion block — the documented
    /// validation contract for the generator.
    #[test]
    fn eleven_point_validation() {
        // (window, h_num, h_den, alpha_exp, expected)
        let points = [
            (WINDOW_BINARY, 1, 5, 20, 941),
            (WINDOW_BINARY, 2, 5, 20, 840),
            (WINDOW_BINARY, 3, 5, 20, 748),
            (WINDOW_BINARY, 4, 5, 20, 664),
            (WINDOW_BINARY, 1, 1, 20, 589),
            (WINDOW_NON_BINARY, 1, 2, 20, 410),
            (WINDOW_NON_BINARY, 1, 1, 20, 311),
            (WINDOW_NON_BINARY, 2, 1, 20, 177),
            (WINDOW_NON_BINARY, 4, 1, 20, 62),
            (WINDOW_NON_BINARY, 8, 1, 20, 13),
            (WINDOW_NON_BINARY, 1, 1, 30, 325),
        ];
        let mut passed = 0;
        for (w, num, den, a, exp) in points {
            assert_eq!(apt_cutoff(w, num, den, a), exp, "W={w} H={num}/{den} a={a}");
            passed += 1;
        }
        assert_eq!(passed, 11, "all 11 reference points must be checked");
    }

    /// The generated α = 2⁻³⁰ grids match the values transcribed into the
    /// in-boundary `oxicrypt-entropy` APT_ALPHA30 tables. This is the
    /// generator side of the cross-crate contract (the entropy crate asserts
    /// the same hardcoded values without depending on maxwell).
    #[test]
    fn alpha30_grids_match_in_boundary_table() {
        let bin = binary_grid(30);
        let expected_bin = [
            (1, 5, 952),
            (2, 5, 856),
            (3, 5, 766),
            (4, 5, 683),
            (1, 1, 609),
        ];
        for (row, (num, den, c)) in bin.iter().zip(expected_bin) {
            assert_eq!((row.h_num, row.h_den, row.cutoff), (num, den, c));
        }

        let nonbin = non_binary_grid(30);
        let expected_nonbin = [
            (1, 2, 422),
            (1, 1, 325),
            (2, 1, 190),
            (4, 1, 71),
            (8, 1, 16),
        ];
        for (row, (num, den, c)) in nonbin.iter().zip(expected_nonbin) {
            assert_eq!((row.h_num, row.h_den, row.cutoff), (num, den, c));
        }
    }

    /// lgamma sanity: ln Γ(n) = ln((n−1)!) for small integers.
    #[test]
    fn lgamma_matches_factorial() {
        // Γ(5) = 4! = 24.
        assert!((lgamma(5.0) - 24.0_f64.ln()).abs() < 1.0e-10);
        // Γ(1) = 1 → ln = 0.
        assert!(lgamma(1.0).abs() < 1.0e-10);
        // Γ(0.5) = sqrt(π).
        assert!((lgamma(0.5) - core::f64::consts::PI.sqrt().ln()).abs() < 1.0e-10);
    }

    /// Cutoffs increase with α exponent (smaller α → larger tolerance → higher
    /// cutoff) and decrease with H, on a representative point.
    #[test]
    fn monotonicity_sanity() {
        // Larger alpha_exp (rarer false positive) → larger cutoff.
        assert!(apt_cutoff(WINDOW_NON_BINARY, 1, 1, 30) > apt_cutoff(WINDOW_NON_BINARY, 1, 1, 20));
        // Higher H → lower cutoff.
        assert!(apt_cutoff(WINDOW_NON_BINARY, 1, 1, 30) > apt_cutoff(WINDOW_NON_BINARY, 2, 1, 30));
    }
}
