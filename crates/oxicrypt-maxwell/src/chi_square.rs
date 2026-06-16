//! SP 800-90B §5.2 chi-square IID tests (independence + goodness-of-fit).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 §5.2 chi-square tests (`cpp/iid/chi_square_tests.h`, with
//! the `relEpsilonEqual` / `calc_proportions` / `divide` helpers from
//! `cpp/shared/utils.h`) bit-for-bit, to within the pre-registered 1.0e-6
//! bits/estimator parity bound (`docs/estimator-parity-tolerances.md` — here the
//! tolerance applies to the chi-square statistic `T` and the p-value, with the
//! degrees of freedom matched exactly). Like the rest of `oxicrypt-maxwell` it is
//! **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The §5.2 chi-square tests
//!
//! SP 800-90B §5.2 runs two Pearson chi-square tests on a candidate IID
//! sequence:
//!
//! - **Chi-square independence** — bins all ordered symbol pairs `(x_j, x_{j+1})`
//!   by their expected frequency under the independence null and compares the
//!   observed pair counts to the binned expectations.
//! - **Chi-square goodness-of-fit** — splits the sequence into ten contiguous
//!   sub-blocks and compares the per-block symbol frequencies to the overall
//!   symbol distribution.
//!
//! Each test yields a statistic `T` and degrees of freedom `df`; the p-value is
//! the upper-tail regularized incomplete gamma `Q(df/2, T/2) = igamc(df/2, T/2)`
//! (the Cephes implementation in [`chi_square_pvalue`]). The data **fails** the
//! §5.2 test when either p-value is `< 0.001`. Both p-values being `>= 0.001`
//! means **pass** ([`ChiSquareResult::passed`]).
//!
//! There are separate binary (`alphabet_size == 2`) and non-binary code paths,
//! exactly as in `chi_square_tests.h`.
//!
//! # Cephes incomplete-gamma p-value (Part A)
//!
//! [`cephes_polevl`], [`cephes_p1evl`], [`cephes_lgam`], [`cephes_igam`],
//! [`cephes_igamc`], and [`chi_square_pvalue`] are faithful pure-Rust
//! transcriptions of the Cephes Math Library routines embedded in
//! `chi_square_tests.h` (lines 53–370). The constants (`MACHEP`, `MAXLOG`,
//! `MAXNUM`, `PI`, `big`, `biginv`, the `A`/`B`/`C` polynomial coefficient
//! arrays, `MAXLGM`) are transcribed verbatim from lines 53–92. The C `static int
//! sgngam` is threaded as a return value out of [`cephes_lgam`] rather than a
//! global (it is consumed only by the `x < -34.0` recursion inside `cephes_lgam`
//! itself, which the chi-square path never reaches, but it is preserved for
//! fidelity). The convergence loops iterate to `MACHEP` relative tolerance
//! exactly as written.
//!
//! ## Sentinel / overflow branches
//!
//! The EA tool's overflow / underflow branches (`lgam: OVERFLOW`, `igam:
//! UNDERFLOW`, `igamc: UNDERFLOW`) print to `stderr` and return a sentinel. This
//! module **returns the same sentinel without printing** (these branches are
//! unreachable for the chi-square arguments `igamc(df/2, T/2)` produced by any
//! real dataset — `df` and `T` are bounded and positive). The sentinel values
//! match the EA tool: `cephes_lgam` overflow returns `sgngam * MAXNUM`,
//! `cephes_igam` underflow returns `0.0`, `cephes_igamc` underflow returns `0.0`.
//!
//! # `relEpsilonEqual` (Part A helper)
//!
//! [`rel_epsilon_equal`] transcribes `utils.h:80-163` faithfully: NaN is never
//! equal; equal (including infinite) values are equal; mismatched-sign or
//! mixed-infinite values are not close; the absolute / relative / ULP ladder
//! follows Knuth AoCP vol II §4.2.2. The ULP step uses `f64::to_bits` in place of
//! the C `memcpy` type-pun. The Cephes routines call it as
//! `relEpsilonEqual(a, b, DBL_EPSILON, DBL_EPSILON, 4)` with `DBL_EPSILON =
//! f64::EPSILON = 2.220446049250313e-16`.
//!
//! # Symbol mapping (Part B)
//!
//! The EA tool pre-maps each dataset's present symbol values down to a contiguous
//! `0..alphabet_size` range (`data.symbols`), because the non-binary tests use
//! the symbol value as an array index (`data[j]*alphabet_size + data[j+1]`). This
//! module builds the same monotonic map — sorted distinct byte values →
//! `0,1,2,…` — and remaps the data through it before BOTH the binary and
//! non-binary tests. For the EA datasets the bytes are already contiguous from
//! `0`, so the map is the identity, but it is required for correctness on
//! arbitrary input: the binary path (`alphabet_size == 2`) treats the two symbol
//! values as bit values `0`/`1` in its m-bit tuple histogram, so two distinct
//! values that are NOT `{0,1}` (e.g. `{1,9}`) must be remapped first or the
//! histogram indexes out of bounds (a fuzz-found panic, ISC-54).
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention). The
//! alphabet size is the number of **distinct** byte values present. `T` and the
//! p-value are computed deterministically; the chi-square tests are `O(n)` (no
//! shuffles), so they run over full datasets cheaply.

// This module is a faithful 1:1 transcription of the EA tool's Cephes routines
// and §5.2 sub-tests. Three lint families are inherent to that transcription and
// are allowed module-wide rather than scattered per line:
//
// * `excessive_precision` — the Cephes constants (`MACHEP`, `MAXLOG`, the A/B/C
//   coefficient arrays, …) are transcribed verbatim from `chi_square_tests.h`
//   lines 53–92. The C literals carry more digits than an f64 can represent; the
//   Rust literal rounds to exactly the same f64 the C compiler produces, so
//   keeping the verbatim digits is the faithful (and self-documenting) choice.
// * `approx_constant` — `PI` is the Cephes-defined `3.14159265358979323846`
//   literal (`chi_square_tests.h:56`), deliberately the EA tool's own constant
//   rather than `std::f64::consts::PI` (they are bit-identical at f64, but the
//   transcription names the EA source).
// * `unreadable_literal` / `inconsistent_digit_grouping` — the grouped digit
//   forms mirror the source magnitudes; consistency across the whole table
//   matters more than per-literal grouping rules.
// Two further families are inherent to the index-arithmetic transcription and
// the parity oracle (`ea_iid`) is the real correctness check, so they are
// allowed module-wide rather than wrapped expression by expression:
//
// * `indexing_slicing` / `arithmetic_side_effects` / `integer_division` — the
//   sub-tests index the tuple/bin/observed tables and walk the data with the EA
//   tool's exact `i*alph+j`, `j+=2`, `sample_size/10`, `sample_size/m` index
//   arithmetic. The indices are bounded by construction (`e` has `alph*alph`
//   entries, `bin` ranges over `0..nbins`, the pair walk stops at
//   `sample_size-1`), and the integer divisions are EA's own; the `1.0e-6`
//   parity bound on `T`/p-value plus exact `df` matching catch any error a lint
//   could not.
// * `cast_*` (precision/sign/wrap/truncation) — the f64 casts are the EA tool's
//   own `(double)` casts; the `i32`/`usize`/`u32` casts are bounded by the
//   dataset length and the small alphabet size.
//
// Style lints that fight the 1:1 form: `needless_bool` (the `if
// !relEpsilonEqual(...)` guard is transcribed verbatim from igamc),
// `manual_slice_fill` / `sort_by_key` (the explicit per-element zero loop and the
// `sort_by(expectation_order)` comparator mirror the C `for`/`sort` exactly).
#![allow(
    clippy::excessive_precision,
    clippy::approx_constant,
    clippy::unreadable_literal,
    clippy::inconsistent_digit_grouping,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::if_not_else,
    clippy::manual_slice_fill,
    clippy::manual_repeat_n,
    clippy::unnecessary_sort_by
)]

/// Cephes machine epsilon, `2**-53` (`chi_square_tests.h:53`).
const MACHEP: f64 = 1.110_223_024_625_156_540_42E-16;
/// Cephes `log(MAXNUM)` (`chi_square_tests.h:54`).
const MAXLOG: f64 = 7.097_827_128_933_839_967_322_24E2;
/// Cephes `MAXNUM`, `2**1024*(1-MACHEP)` (`chi_square_tests.h:55`).
const MAXNUM: f64 = 1.797_693_134_862_315_8E308;
/// Cephes `PI` (`chi_square_tests.h:56`).
const PI: f64 = 3.141_592_653_589_793_238_46;
/// Cephes continued-fraction rescale threshold (`chi_square_tests.h:58`).
const BIG: f64 = 4.503_599_627_370_496e15;
/// Reciprocal of [`BIG`] (`chi_square_tests.h:59`).
const BIGINV: f64 = 2.220_446_049_250_313_080_85e-16;
/// `lgam` overflow threshold (`chi_square_tests.h:92`, `#define MAXLGM`).
const MAXLGM: f64 = 2.556_348e305;

/// `DBL_EPSILON` as used by the EA tool's `relEpsilonEqual` calls.
const DBL_EPSILON: f64 = f64::EPSILON;

/// Stirling's-formula log-gamma coefficients (`chi_square_tests.h:67-73`).
const A: [f64; 5] = [
    8.116_141_674_705_084_503E-4,
    -5.950_619_042_843_014_383_24E-4,
    7.936_503_404_577_169_439_45E-4,
    -2.777_777_777_300_996_872_05E-3,
    8.333_333_333_333_319_277_22E-2,
];
/// log-gamma numerator coefficients, `x` in `[2,3]` (`chi_square_tests.h:74-81`).
const B: [f64; 6] = [
    -1.378_251_525_691_208_591E3,
    -3.880_163_151_346_378_409_24E4,
    -3.316_129_927_388_711_847_44E5,
    -1.162_370_974_927_623_073_83E6,
    -1.721_737_008_208_396_621_46E6,
    -8.535_556_642_457_654_656_27E5,
];
/// log-gamma denominator coefficients, `x` in `[2,3]` (`chi_square_tests.h:82-90`).
/// (The implicit leading `1.0` coefficient is supplied by [`cephes_p1evl`].)
const C: [f64; 6] = [
    -3.518_157_014_365_234_705_49E2,
    -1.706_421_066_518_811_592_23E4,
    -2.205_285_905_538_544_548_39E5,
    -1.139_334_443_679_825_072_07E6,
    -2.532_523_071_775_829_512_85E6,
    -2.018_891_414_335_327_732_31E6,
];

// =========================================================================
//  Part A — Cephes incomplete-gamma p-value
// =========================================================================

/// `relEpsilonEqual` — `utils.h:80-163`, transcribed faithfully.
///
/// Returns `true` when `a` and `b` are within the absolute / relative / ULP
/// tolerance ladder. NaN is never equal to anything (including itself); equal
/// values (including equal infinities) are equal; mismatched-sign or
/// mixed-infinite-but-unequal values are not close.
#[allow(
    // The bindings (a/b swap, absA/absB, diff) mirror the C variable names and
    // control flow exactly; the float comparisons are the EA tool's own.
    clippy::float_cmp,
    clippy::similar_names
)]
fn rel_epsilon_equal(
    a: f64,
    b: f64,
    max_abs_factor: f64,
    max_rel_factor: f64,
    max_ulp: u32,
) -> bool {
    // NaN is by definition not equal to anything (including itself).
    if a.is_nan() || b.is_nan() {
        return false;
    }

    // Equal infinities, and the corner case where they are actually copies.
    if a == b {
        return true;
    }

    // If either is infinity, but they are not equal, they aren't close.
    if a.is_infinite() || b.is_infinite() {
        return false;
    }

    let mut a = a;
    let mut b = b;
    let mut abs_a = a.abs();
    let mut abs_b = b.abs();
    // Make sure that `a` is the closest to 0.
    if abs_a > abs_b {
        std::mem::swap(&mut a, &mut b);
        std::mem::swap(&mut abs_a, &mut abs_b);
    }

    // Capture the difference of the largest magnitude from the smallest.
    let diff = (b - a).abs();

    // Is absA, diff, or absB*maxRelFactor subnormal? Did diff overflow? If so the
    // relative comparison is nonsense; fall back to the absolute factor.
    if (abs_a < f64::MIN_POSITIVE)
        || (diff < f64::MIN_POSITIVE)
        || diff.is_infinite()
        || (abs_b * max_rel_factor < f64::MIN_POSITIVE)
    {
        return diff <= max_abs_factor;
    }
    // Relative closeness (Knuth AoCP vol II §4.2.2).
    if diff <= abs_b * max_rel_factor {
        return true;
    }

    // Not relatively close in the conventional sense; check ULP distance.
    // If different sign, they can't be only a few ULPs apart.
    if a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }

    // C uses memcpy to reinterpret the bits; f64::to_bits is the safe equivalent.
    // Both magnitudes are >= DBL_MIN here, so neither is zero. By IEEE-754
    // construction Bint > Aint (absA <= absB, same sign).
    let a_int = abs_a.to_bits();
    let b_int = abs_b.to_bits();
    b_int.saturating_sub(a_int) <= u64::from(max_ulp)
}

/// `cephes_polevl` — evaluate a polynomial (`chi_square_tests.h:96-111`).
///
/// `coef[0]` is the leading coefficient; the polynomial has degree `n` (so
/// `coef` has `n + 1` entries).
#[allow(clippy::needless_range_loop)]
fn cephes_polevl(x: f64, coef: &[f64], n: usize) -> f64 {
    let mut ans = coef[0];
    // i = N; do { ans = ans*x + *p++; } while(--i);  — N iterations.
    for i in 1..=n {
        ans = ans * x + coef[i];
    }
    ans
}

/// `cephes_p1evl` — evaluate a polynomial whose leading coefficient is an
/// implicit `1.0` (`chi_square_tests.h:113-128`).
#[allow(clippy::needless_range_loop)]
fn cephes_p1evl(x: f64, coef: &[f64], n: usize) -> f64 {
    let mut ans = x + coef[0];
    // i = N-1; do { ans = ans*x + *p++; } while(--i);  — N-1 iterations.
    for i in 1..n {
        ans = ans * x + coef[i];
    }
    ans
}

/// `cephes_lgam` — logarithm of the gamma function (`chi_square_tests.h:130-236`).
///
/// Returns `(lgam(x), sgngam)`. The C version mutates the `static int sgngam`
/// flag; here it is threaded through the return value and through the recursive
/// `x < -34.0` call, faithfully reproducing the C control flow. For the
/// chi-square path the argument is always `>= 0.5` (it is `df/2`), so neither the
/// negative-recursion nor the overflow branch is reached, but both are
/// transcribed.
#[allow(
    // The bindings mirror the C names (p/q/u/w/z) and the float comparisons are
    // the EA tool's own; the goto-based control flow is rendered with a helper
    // closure for the `loverf` sentinel.
    clippy::float_cmp,
    clippy::many_single_char_names
)]
fn cephes_lgam(x: f64) -> (f64, i32) {
    let mut sgngam: i32 = 1;

    // `loverf:` label — the OVERFLOW sentinel. The EA tool prints to stderr; we
    // return the sentinel `sgngam * MAXNUM` without printing.
    let loverf = |sgngam: i32| sgngam as f64 * MAXNUM;

    if x < -34.0 {
        let q = -x;
        // Recursion modifies sgngam in C; we take the recursive sgngam below.
        let (w, _w_sgngam) = cephes_lgam(q);
        let p = q.floor();

        if rel_epsilon_equal(p, q, DBL_EPSILON, DBL_EPSILON, 4) {
            return (loverf(sgngam), sgngam);
        }

        #[allow(clippy::cast_possible_truncation)]
        let i = p as i64; // p is floor(q).
        sgngam = if (i & 1) == 0 { -1 } else { 1 };

        let mut z = q - p;
        let mut p_local = p;
        if z > 0.5 {
            p_local += 1.0;
            z = p_local - q;
        }

        z = q * (PI * z).sin();

        if rel_epsilon_equal(z, 0.0, DBL_EPSILON, DBL_EPSILON, 4) {
            return (loverf(sgngam), sgngam);
        }

        let z = PI.ln() - z.ln() - w;
        return (z, sgngam);
    }

    if x < 13.0 {
        let mut z = 1.0_f64;
        let mut p = 0.0_f64;
        let mut u = x;

        while u >= 3.0 {
            p -= 1.0;
            u = x + p;
            z *= u;
        }

        while u < 2.0 {
            if rel_epsilon_equal(u, 0.0, DBL_EPSILON, DBL_EPSILON, 4) {
                return (loverf(sgngam), sgngam);
            }
            z /= u;
            p += 1.0;
            u = x + p;
        }

        if z < 0.0 {
            sgngam = -1;
            z = -z;
        } else {
            sgngam = 1;
        }

        if rel_epsilon_equal(u, 2.0, DBL_EPSILON, DBL_EPSILON, 4) {
            return (z.ln(), sgngam);
        }

        p -= 2.0;
        let x2 = x + p;
        let p = x2 * cephes_polevl(x2, &B, 5) / cephes_p1evl(x2, &C, 6);

        return (z.ln() + p, sgngam);
    }

    if x > MAXLGM {
        return (loverf(sgngam), sgngam);
    }

    let mut q = (x - 0.5) * x.ln() - x + (2.0 * PI).sqrt().ln();

    if x > 1.0e8 {
        return (q, sgngam);
    }

    let p = 1.0 / (x * x);

    if x >= 1000.0 {
        q += ((7.936_507_936_507_936_507_936_5e-4 * p - 2.777_777_777_777_777_777_777_8e-3) * p
            + 0.083_333_333_333_333_333_333_3)
            / x;
    } else {
        q += cephes_polevl(p, &A, 4) / x;
    }

    (q, sgngam)
}

/// `cephes_igam` — lower regularized incomplete gamma `P(a, x)` via power series
/// (`chi_square_tests.h:238-272`).
#[allow(clippy::float_cmp, clippy::many_single_char_names)]
fn cephes_igam(a: f64, x: f64) -> f64 {
    // Backstop iteration cap (ISC-54): the series converges for any finite
    // a>0, x>0 in far fewer than ITER_CAP steps; the cap only ever fires on
    // pathological finite input the non-finite guard below doesn't catch, and is
    // invisible to every real chi-square statistic. EA's C loop is uncapped.
    const ITER_CAP: u32 = 10_000;

    // ISC-54 hardening: a non-finite (NaN/inf) argument can never satisfy the
    // power-series convergence test below (`c / ans <= MACHEP` is false for
    // NaN), so the loop would spin forever. The EA C tool is never fed such an
    // argument (its datasets are non-empty), but this out-of-boundary tool must
    // handle arbitrary input without hanging. `P(a, x)` is undefined for a
    // non-finite statistic; return the conservative 0.0 sentinel (the same
    // value the existing non-positive / underflow guards return).
    if !a.is_finite() || !x.is_finite() {
        return 0.0;
    }
    if (x <= 0.0) || (a <= 0.0) {
        return 0.0;
    }

    if (x > 1.0) && (x > a) {
        return 1.0 - cephes_igamc(a, x);
    }

    // Compute x**a * exp(-x) / gamma(a).
    let (lgam_a, _sgngam) = cephes_lgam(a);
    let mut ax = a * x.ln() - x - lgam_a;

    if ax < -MAXLOG {
        // igam: UNDERFLOW — sentinel 0.0 (no print).
        return 0.0;
    }

    ax = ax.exp();

    // power series
    let mut r = a;
    let mut c = 1.0_f64;
    let mut ans = 1.0_f64;

    let mut iters: u32 = 0;
    loop {
        r += 1.0;
        c *= x / r;
        ans += c;
        iters = iters.saturating_add(1);
        if (c / ans <= MACHEP) || (iters >= ITER_CAP) {
            break;
        }
    }

    ans * ax / a
}

/// `cephes_igamc` — upper regularized incomplete gamma `Q(a, x)` via continued
/// fraction (`chi_square_tests.h:274-336`).
#[allow(
    // Bindings mirror the C names (pk/pkm1/pkm2/qk/qkm1/qkm2, yc/y/z/t/r);
    // the float comparisons are the EA tool's own.
    clippy::float_cmp,
    clippy::many_single_char_names,
    clippy::similar_names
)]
fn cephes_igamc(a: f64, x: f64) -> f64 {
    // Backstop iteration cap (ISC-54): the continued fraction converges for any
    // finite a>0, x>0 well within ITER_CAP steps; the cap only guards against
    // pathological finite input the non-finite guard below doesn't catch, and is
    // invisible to every real chi-square statistic. EA's C loop is uncapped.
    const ITER_CAP: u32 = 10_000;

    // ISC-54 hardening: a non-finite (NaN/inf) argument can never satisfy the
    // continued-fraction convergence test below (`t <= MACHEP` is false when `t`
    // is NaN), so the loop would spin forever. Empty input to `chi_square_tests`
    // produces a NaN chi-square statistic (0/0 proportions) that lands here; the
    // EA C tool never sees this (its datasets are non-empty) but this
    // out-of-boundary tool must not hang on arbitrary input. `Q(a, x)` is
    // undefined for a non-finite statistic; return the conservative 1.0 sentinel
    // (the same value the existing non-positive guard returns — a p-value of 1.0
    // is the most permissive, "no evidence" answer).
    if !a.is_finite() || !x.is_finite() {
        return 1.0;
    }
    if (x <= 0.0) || (a <= 0.0) {
        return 1.0;
    }

    if (x < 1.0) || (x < a) {
        return 1.0 - cephes_igam(a, x);
    }

    let (lgam_a, _sgngam) = cephes_lgam(a);
    let mut ax = a * x.ln() - x - lgam_a;

    if ax < -MAXLOG {
        // igamc: UNDERFLOW — sentinel 0.0 (no print).
        return 0.0;
    }

    ax = ax.exp();

    // continued fraction
    let mut y = 1.0 - a;
    let mut z = x + y + 1.0;
    let mut c = 0.0_f64;
    let mut pkm2 = 1.0_f64;
    let mut qkm2 = x;
    let mut pkm1 = x + 1.0;
    let mut qkm1 = z * x;
    let mut ans = pkm1 / qkm1;
    let mut t;

    let mut iters: u32 = 0;
    loop {
        c += 1.0;
        y += 1.0;
        z += 2.0;
        let yc = y * c;
        let pk = pkm1 * z - pkm2 * yc;
        let qk = qkm1 * z - qkm2 * yc;

        if !rel_epsilon_equal(qk, 0.0, DBL_EPSILON, DBL_EPSILON, 4) {
            let r = pk / qk;
            t = ((ans - r) / r).abs();
            ans = r;
        } else {
            t = 1.0;
        }

        pkm2 = pkm1;
        pkm1 = pk;
        qkm2 = qkm1;
        qkm1 = qk;

        if pk.abs() > BIG {
            pkm2 *= BIGINV;
            pkm1 *= BIGINV;
            qkm2 *= BIGINV;
            qkm1 *= BIGINV;
        }

        iters = iters.saturating_add(1);
        if (t <= MACHEP) || (iters >= ITER_CAP) {
            break;
        }
    }

    ans * ax
}

/// `chi_square_pvalue(x, k)` — the §5.2 p-value `Q(k/2, x/2) = igamc(k/2, x/2)`
/// (`chi_square_tests.h:368-370`).
///
/// `x` is the chi-square statistic `T`; `k` is the degrees of freedom.
#[must_use]
pub fn chi_square_pvalue(x: f64, k: f64) -> f64 {
    cephes_igamc(k / 2.0, x / 2.0)
}

// =========================================================================
//  Part B — the four sub-tests
// =========================================================================

/// One `tupleTranslateEntry` (`chi_square_tests.h:377-381`): a tuple value, its
/// expected count, and the bin it is assigned to.
#[derive(Debug, Clone, Copy)]
struct TupleTranslateEntry {
    tuple: u32,
    expectation: f64,
    bin: i32,
}

/// Number of **distinct** byte values present — the EA tool's `alph_size`.
fn alphabet_size(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&s| s).count()
}

/// Build the monotonic symbol map (sorted distinct byte values → `0,1,2,…`) and
/// remap `data` through it, matching the EA tool's `data.symbols` pre-mapping.
///
/// Returns the remapped data over `0..alphabet_size`. For datasets whose bytes
/// are already contiguous from `0` the map is the identity.
fn map_symbols(data: &[u8]) -> Vec<u8> {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    // map[value] = its contiguous index. Sorted-distinct order is just the
    // ascending byte value order, so a single pass assigns the indices.
    let mut map = [0u8; 256];
    let mut next: u16 = 0;
    for (v, &s) in seen.iter().enumerate() {
        if s {
            map[v] = next as u8;
            next += 1;
        }
    }
    data.iter().map(|&b| map[b as usize]).collect()
}

/// `calc_proportions` (`utils.h:751-762`): `p[v] = count(v) / sample_size`.
/// `p` has length `alphabet_size`; `data` symbols are pre-mapped to `0..len(p)`.
#[allow(clippy::cast_precision_loss)]
fn calc_proportions(data: &[u8], alph: usize, sample_size: usize) -> Vec<f64> {
    let mut p = vec![0.0_f64; alph];
    for &d in data.iter().take(sample_size) {
        // d is a mapped symbol in 0..alph.
        if let Some(slot) = p.get_mut(d as usize) {
            *slot += 1.0;
        }
    }
    for v in &mut p {
        *v /= sample_size as f64;
    }
    p
}

/// `expectationOrder` (`chi_square_tests.h:522-525`): sort by expectation
/// ascending, secondary by tuple ascending.
fn expectation_order(a: &TupleTranslateEntry, b: &TupleTranslateEntry) -> std::cmp::Ordering {
    match a.expectation.partial_cmp(&b.expectation) {
        Some(std::cmp::Ordering::Equal) | None => a.tuple.cmp(&b.tuple),
        Some(ord) => ord,
    }
}

/// `independence_calc_expectations` (`chi_square_tests.h:383-394`): fill the
/// `alphabet_size^2` tuple table with `e[i*alph + j].expectation =
/// p[i]*p[j]*floor(sample_size*0.5)`.
#[allow(clippy::cast_possible_truncation)]
fn independence_calc_expectations(p: &[f64], sample_size: usize) -> Vec<TupleTranslateEntry> {
    let alph = p.len();
    let mut e = Vec::with_capacity(alph * alph);
    #[allow(clippy::cast_precision_loss)]
    let half = (sample_size as f64 * 0.5).floor();
    for i in 0..alph {
        for j in 0..alph {
            let index = (i * alph + j) as u32;
            e.push(TupleTranslateEntry {
                tuple: index,
                expectation: p[i] * p[j] * half,
                bin: -1,
            });
        }
    }
    e
}

/// `allocate_bins` (`chi_square_tests.h:396-421`): walk the expectation-sorted
/// entries, starting a new bin whenever the accumulated expectation reaches
/// `5.0`, then merge a too-small trailing bin into its predecessor. Returns the
/// per-bin expectation vector; `e[i].bin` is assigned in place.
fn allocate_bins(e: &mut [TupleTranslateEntry]) -> Vec<f64> {
    let mut bin_exp: Vec<f64> = Vec::new();
    let mut current_bin: i32 = 0;
    let mut current_expectation = 0.0_f64;

    for entry in e.iter_mut() {
        if current_expectation >= 5.0 {
            bin_exp.push(current_expectation);
            current_bin += 1;
            current_expectation = 0.0;
        }
        entry.bin = current_bin;
        current_expectation += entry.expectation;
    }

    // If current_bin is 0 we can't combine anything.
    if (current_bin != 0) && (current_expectation < 5.0) {
        // Combine the last two bins: walk back over the trailing bin.
        let mut i = e.len();
        while i > 0 {
            i -= 1;
            if e[i].bin == current_bin {
                e[i].bin = current_bin - 1;
            } else {
                break;
            }
        }
        // bin_exp[current_bin-1] += current_expectation.
        if let Some(slot) = bin_exp.get_mut((current_bin - 1) as usize) {
            *slot += current_expectation;
        }
    } else {
        bin_exp.push(current_expectation);
    }

    bin_exp
}

/// `calc_T` (`chi_square_tests.h:430-443`): `Σ (o[i] - binExp[i])^2 / binExp[i]`.
#[allow(clippy::cast_precision_loss)]
fn calc_t(bin_expectations: &[f64], o: &[i64]) -> f64 {
    let mut t = 0.0_f64;
    for (i, &exp) in bin_expectations.iter().enumerate() {
        let oc = o.get(i).copied().unwrap_or(0) as f64;
        t += (oc - exp).powi(2) / exp;
    }
    t
}

/// `independence_calc_observed` (`chi_square_tests.h:423-428`): for
/// `j = 0,2,4,… < sample_size-1`, bump the bin of pair `(data[j], data[j+1])`.
/// `e` must be sorted by tuple (used as a lookup table). `data` is pre-mapped.
fn independence_calc_observed(
    data: &[u8],
    e: &[TupleTranslateEntry],
    o: &mut [i64],
    sample_size: usize,
    alph: usize,
) {
    let mut j = 0;
    // for(j=0; j<sample_size-1; j+=2)
    while j + 1 < sample_size {
        let index = (data[j] as usize) * alph + (data[j + 1] as usize);
        let bin = e[index].bin;
        if let Some(slot) = o.get_mut(bin as usize) {
            *slot += 1;
        }
        j += 2;
    }
}

/// `goodness_of_fit_calc_observed` (`chi_square_tests.h:445-449`): over a block
/// of `sample_size` symbols, bump the bin of each symbol. `e` sorted by tuple.
fn goodness_of_fit_calc_observed(
    block: &[u8],
    e: &[TupleTranslateEntry],
    o: &mut [i64],
    block_len: usize,
) {
    for &d in block.iter().take(block_len) {
        let bin = e[d as usize].bin;
        if let Some(slot) = o.get_mut(bin as usize) {
            *slot += 1;
        }
    }
}

/// `binary_chi_square_independence` (`chi_square_tests.h:457-520`). `data` is the
/// raw bit values (`0`/`1`). Returns `(score, df)`.
#[allow(
    // Counts/exponents are bounded by the dataset length; the f64 casts are the
    // EA tool's own (double) casts and the 1.0e-6 parity bound absorbs rounding.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn binary_chi_square_independence(data: &[u8], sample_size: usize) -> (f64, i32) {
    // Proportion of 0s and 1s.
    let mut p1 = 0.0_f64;
    for &d in data.iter().take(sample_size) {
        p1 += f64::from(d);
    }
    p1 /= sample_size as f64;
    let p0 = 1.0 - p1;

    // Compute m: largest 1<m<=11 with min_p^m * (sample_size/m) >= 5.
    let min_p = p0.min(p1);
    let mut m: i32 = 11;
    let threshold = 5.0_f64;
    while m > 1 {
        // pow(min_p, m) * (sample_size / m) — note integer division sample_size/m.
        let term = min_p.powi(m) * ((sample_size / m as usize) as f64);
        if term >= threshold {
            break;
        }
        m -= 1;
    }

    if m < 2 {
        return (0.0, 0);
    }

    let tuple_count: usize = 1usize << m;
    let mut occ = vec![0_i64; tuple_count];
    let block_count = sample_size / m as usize;

    for i in 0..block_count {
        let mut symbol: usize = 0;
        for j in 0..(m as usize) {
            symbol = (symbol << 1) | data[i * m as usize + j] as usize;
        }
        occ[symbol] += 1;
    }

    let mut t = 0.0_f64;
    for (i, &count) in occ.iter().enumerate() {
        let w = (i as u32).count_ones(); // __builtin_popcount(i).
        let e = p1.powi(w as i32) * p0.powi(m - w as i32) * (block_count as f64);
        t += (count as f64 - e).powi(2) / e;
    }

    let df = (1i64 << m) - 2; // pow(2, m) - 2.
    #[allow(clippy::cast_possible_truncation)]
    (t, df as i32)
}

/// `chi_square_independence` (`chi_square_tests.h:531-558`, non-binary). `data`
/// is pre-mapped to `0..alph`. Returns `(score, df)`.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn chi_square_independence(data: &[u8], sample_size: usize, alph: usize) -> (f64, i32) {
    let p = calc_proportions(data, alph, sample_size);

    // Expected count per ordered pair.
    let mut e = independence_calc_expectations(&p, sample_size);
    // Sort by expectation asc, tuple asc.
    e.sort_by(expectation_order);

    // Allocate sorted entries into bins.
    let bin_expectations = allocate_bins(&mut e);

    // Sort back by tuple so e is a lookup table.
    e.sort_by(|a, b| a.tuple.cmp(&b.tuple));

    // Observed pair frequencies.
    let mut o = vec![0_i64; bin_expectations.len()];
    independence_calc_observed(data, &e, &mut o, sample_size, alph);

    let score = calc_t(&bin_expectations, &o);
    let df = bin_expectations.len() as i64 - alph as i64;
    (score, df as i32)
}

/// `binary_goodness_of_fit` (`chi_square_tests.h:560-594`). `data` is raw bit
/// values. Returns `(score, df=9)`.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn binary_goodness_of_fit(data: &[u8], sample_size: usize) -> (f64, i32) {
    let sublength = sample_size / 10;
    let mut ones: i64 = 0;
    for &d in data.iter().take(sample_size) {
        ones += i64::from(d);
    }

    // p = divide(ones, sample_size) = (double)ones/(double)sample_size.
    let p = (ones as f64) / (sample_size as f64);
    let mut t = 0.0_f64;

    let e0 = (1.0 - p) * sublength as f64;
    let e1 = p * sublength as f64;

    for i in 0..10 {
        let mut o1: i64 = 0;
        for j in 0..sublength {
            o1 += i64::from(data[i * sublength + j]);
        }
        let o0 = sublength as i64 - o1;
        t += (o0 as f64 - e0).powi(2) / e0 + (o1 as f64 - e1).powi(2) / e1;
    }

    (t, 9)
}

/// `goodness_of_fit` (`chi_square_tests.h:596-633`, non-binary). `data`
/// pre-mapped to `0..alph`. Returns `(score, df = 9*(nbins-1))`.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn goodness_of_fit(data: &[u8], sample_size: usize, alph: usize) -> (f64, i32) {
    let p = calc_proportions(data, alph, sample_size);

    // e[j] = { tuple: j, expectation: p[j]*floor(sample_size/10.0) }.
    #[allow(clippy::cast_precision_loss)]
    let tenth = (sample_size as f64 / 10.0).floor();
    let mut e: Vec<TupleTranslateEntry> = (0..alph)
        .map(|j| TupleTranslateEntry {
            tuple: j as u32,
            expectation: p[j] * tenth,
            bin: -1,
        })
        .collect();

    e.sort_by(expectation_order);
    let bin_expectations = allocate_bins(&mut e);
    e.sort_by(|a, b| a.tuple.cmp(&b.tuple));

    let block_size = sample_size / 10;
    let mut t = 0.0_f64;
    let mut o = vec![0_i64; bin_expectations.len()];

    for j in 0..10 {
        for slot in &mut o {
            *slot = 0;
        }
        let block = &data[j * block_size..];
        goodness_of_fit_calc_observed(block, &e, &mut o, block_size);
        t += calc_t(&bin_expectations, &o);
    }

    let df = 9 * (bin_expectations.len() as i64 - 1);
    (t, df as i32)
}

// =========================================================================
//  Part C — top-level
// =========================================================================

/// The full §5.2 chi-square result: both tests' statistics, degrees of freedom,
/// p-values, and the overall pass/fail.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChiSquareResult {
    /// Chi-square independence test statistic `T`.
    pub independence_score: f64,
    /// Chi-square independence degrees of freedom.
    pub independence_df: i32,
    /// Chi-square independence p-value `Q(df/2, T/2)`.
    pub independence_pvalue: f64,
    /// Chi-square goodness-of-fit test statistic `T`.
    pub gof_score: f64,
    /// Chi-square goodness-of-fit degrees of freedom.
    pub gof_df: i32,
    /// Chi-square goodness-of-fit p-value `Q(df/2, T/2)`.
    pub gof_pvalue: f64,
    /// Overall §5.2 verdict: both p-values `>= 0.001`.
    pub passed: bool,
}

/// Run the SP 800-90B §5.2 chi-square tests over `data` (raw bytes, one symbol
/// per byte).
///
/// Dispatches the binary (`alphabet_size == 2`) and non-binary code paths exactly
/// as the EA tool's `chi_square_tests`. The non-binary path pre-maps symbols to a
/// contiguous `0..alphabet_size` range; the binary path decomposes nothing — it
/// uses the raw byte bit values (`0`/`1`) directly.
///
/// This function is **deterministic**: the same `data` always yields a
/// bit-identical [`ChiSquareResult`].
///
/// # Panics
///
/// Does not panic on the EA datasets. Empty input yields `alphabet_size == 0`
/// (treated as non-binary), zero-length proportions, and a degenerate but
/// non-panicking result.
#[must_use]
pub fn chi_square_tests(data: &[u8]) -> ChiSquareResult {
    let sample_size = data.len();

    // ISC-54: empty input has no proportions to compute — `calc_proportions`
    // would divide counts by `sample_size == 0`, producing NaN that propagates
    // into the chi-square statistic and (before the cephes hardening) hung the
    // p-value continued fraction. Return the documented degenerate result
    // directly: zero statistics, zero df, and p-value 1.0 (the most permissive
    // "no evidence against IID" answer), which passes the >= 0.001 verdict. The
    // EA C tool is never run on an empty dataset; this guard makes the
    // out-of-boundary tool well-defined on arbitrary input.
    if sample_size == 0 {
        return ChiSquareResult {
            independence_score: 0.0,
            independence_df: 0,
            independence_pvalue: 1.0,
            gof_score: 0.0,
            gof_df: 0,
            gof_pvalue: 1.0,
            passed: true,
        };
    }

    let alph = alphabet_size(data);

    // Map the present symbol values down to a contiguous `0..alph` range. EA
    // operates on `data.symbols`, which are already mapped; maxwell takes raw
    // bytes. The map is monotonic and IDENTITY for already-0-based data (every
    // real EA/collected dataset), so it never changes the EA-parity values — but
    // it is REQUIRED for the binary path too: arbitrary input can have exactly
    // two DISTINCT values that are not {0,1} (e.g. {1,9}), which the binary
    // tuple/bin indexing assumes are bit values, indexing out of bounds without
    // this remap (ISC-54).
    let mapped = map_symbols(data);

    // Independence test.
    let (indep_score, indep_df) = if alph == 2 {
        binary_chi_square_independence(&mapped, sample_size)
    } else {
        chi_square_independence(&mapped, sample_size, alph)
    };
    let indep_pvalue = chi_square_pvalue(indep_score, f64::from(indep_df));

    // Goodness-of-fit test.
    let (gof_score, gof_df) = if alph == 2 {
        binary_goodness_of_fit(&mapped, sample_size)
    } else {
        goodness_of_fit(&mapped, sample_size, alph)
    };
    let gof_pvalue = chi_square_pvalue(gof_score, f64::from(gof_df));

    // EA: pvalue < 0.001 → fail. Pass iff both p-values >= 0.001.
    let passed = (indep_pvalue >= 0.001) && (gof_pvalue >= 0.001);

    ChiSquareResult {
        independence_score: indep_score,
        independence_df: indep_df,
        independence_pvalue: indep_pvalue,
        gof_score,
        gof_df,
        gof_pvalue,
        passed,
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact reference values, use unwrap/expect/panic for fatal
    // setup invariants, index fixed-size fixtures, and print skip notices — all
    // fine in test code.
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    // check_anchor takes the full EA reference row (6 values + verdict) so each
    // call reads as a labelled table line.
    clippy::too_many_arguments
)]
mod tests {
    use super::*;
    use crate::parity::resolve_datasets_dir;

    /// Parity tolerance on `T` and the p-value (the pre-registered 1.0e-6 bound).
    const PARITY_EPS: f64 = 1.0e-6;

    /// Tolerance for textbook chi-square critical-value lookups.
    const TABLE_EPS: f64 = 1.0e-4;

    /// ISC-54 regression: a non-finite chi-square statistic must NOT hang the
    /// Cephes continued fraction / power series. Before the fix,
    /// `chi_square_pvalue(NaN, k)` looped forever because the convergence test
    /// `t <= MACHEP` is never true for NaN. The test would time out (not just
    /// fail) on a regression; the assertion documents the intended sentinel.
    #[test]
    fn pvalue_non_finite_does_not_hang() {
        // igamc path (x large/NaN): returns the permissive 1.0 sentinel.
        assert_eq!(chi_square_pvalue(f64::NAN, 1.0), 1.0);
        assert_eq!(chi_square_pvalue(f64::INFINITY, 1.0), 1.0);
        // Non-finite df.
        assert_eq!(chi_square_pvalue(1.0, f64::NAN), 1.0);
        // Both finite-degenerate (df=0): returns 1.0 (existing guard).
        assert_eq!(chi_square_pvalue(0.0, 0.0), 1.0);
    }

    /// ISC-54 regression: empty input must return the documented degenerate
    /// result without computing NaN proportions or hanging. Before the fix this
    /// fed a NaN statistic into the p-value and hung.
    #[test]
    fn empty_input_is_degenerate_and_passes() {
        let r = chi_square_tests(&[]);
        assert_eq!(r.independence_score, 0.0);
        assert_eq!(r.independence_df, 0);
        assert_eq!(r.independence_pvalue, 1.0);
        assert_eq!(r.gof_score, 0.0);
        assert_eq!(r.gof_df, 0);
        assert_eq!(r.gof_pvalue, 1.0);
        assert!(r.passed, "empty input has no evidence against IID");
    }

    /// ISC-54 regression: a two-symbol alphabet whose values are NOT {0,1}
    /// (arbitrary input — e.g. {1,9}) must take the binary path WITHOUT indexing
    /// out of bounds, and must give the same result as the {0,1}-mapped data
    /// (the monotonic remap is what makes the binary tuple/bin indexing valid).
    /// Fuzz-found: input `[1, 9]` panicked at the m-bit tuple histogram.
    #[test]
    fn binary_non_01_alphabet_matches_mapped() {
        // Repeat a fixed non-{0,1} two-symbol pattern; alph_size == 2.
        let raw: Vec<u8> = (0..4000)
            .map(|i| if i % 3 == 0 { 9u8 } else { 1u8 })
            .collect();
        let mapped: Vec<u8> = raw.iter().map(|&b| u8::from(b == 9)).collect();
        let r_raw = chi_square_tests(&raw); // must not panic
        let r_mapped = chi_square_tests(&mapped);
        assert_eq!(r_raw.independence_score, r_mapped.independence_score);
        assert_eq!(r_raw.gof_score, r_mapped.gof_score);
        assert_eq!(r_raw.passed, r_mapped.passed);
        // The minimal fuzz crash input itself: just must not panic.
        let _ = chi_square_tests(&[1u8, 9u8]);
    }

    /// The Cephes p-value path against textbook chi-square critical values.
    /// (Critical value `x` for tail probability `p` at `df` degrees of freedom.)
    #[test]
    fn chi_square_pvalue_textbook_values() {
        // df=1, x=3.841459 → upper-tail p = 0.05.
        assert!(
            (chi_square_pvalue(3.841_459, 1.0) - 0.05).abs() < TABLE_EPS,
            "df=1 p={}",
            chi_square_pvalue(3.841_459, 1.0)
        );
        // df=2, x=5.991465 → 0.05.
        assert!(
            (chi_square_pvalue(5.991_465, 2.0) - 0.05).abs() < TABLE_EPS,
            "df=2 p={}",
            chi_square_pvalue(5.991_465, 2.0)
        );
        // df=10, x=2.558 → 0.99.
        assert!(
            (chi_square_pvalue(2.558, 10.0) - 0.99).abs() < TABLE_EPS,
            "df=10 p={}",
            chi_square_pvalue(2.558, 10.0)
        );
        // df=1, x=6.634897 → 0.01.
        assert!(
            (chi_square_pvalue(6.634_897, 1.0) - 0.01).abs() < TABLE_EPS,
            "df=1@0.01 p={}",
            chi_square_pvalue(6.634_897, 1.0)
        );
        // df=5, x=11.0705 → 0.05.
        assert!(
            (chi_square_pvalue(11.070_5, 5.0) - 0.05).abs() < TABLE_EPS,
            "df=5 p={}",
            chi_square_pvalue(11.070_5, 5.0)
        );
        // df=20, x=31.4104 → 0.05.
        assert!(
            (chi_square_pvalue(31.410_4, 20.0) - 0.05).abs() < TABLE_EPS,
            "df=20 p={}",
            chi_square_pvalue(31.410_4, 20.0)
        );
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..10_000u32).map(|i| (i % 13) as u8).collect();
        let a = chi_square_tests(&buf);
        let b = chi_square_tests(&buf);
        assert_eq!(a, b, "ChiSquareResult must be bit-identical across runs");
    }

    /// EA ground-truth anchors (from `ea_iid -i -v -v -v` on the canonical short
    /// datasets). Independence + GOF `T`, `df`, and p-value must match within
    /// 1.0e-6 on `T`/p-value and exactly on `df`. Skips if a dataset is absent.
    fn check_anchor(
        name: &str,
        indep_t: f64,
        indep_df: i32,
        indep_p: f64,
        gof_t: f64,
        gof_df: i32,
        gof_p: f64,
        expect_pass: bool,
    ) {
        let dir = resolve_datasets_dir(None);
        let path = dir.join(format!("{name}.bin"));
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} absent — skipping anchor", path.display());
            return;
        };
        let r = chi_square_tests(&data);
        assert_eq!(r.independence_df, indep_df, "{name} indep df");
        assert_eq!(r.gof_df, gof_df, "{name} gof df");
        assert!(
            (r.independence_score - indep_t).abs() < PARITY_EPS,
            "{name} indep T: got {} want {}",
            r.independence_score,
            indep_t
        );
        assert!(
            (r.gof_score - gof_t).abs() < PARITY_EPS,
            "{name} gof T: got {} want {}",
            r.gof_score,
            gof_t
        );
        assert!(
            (r.independence_pvalue - indep_p).abs() < PARITY_EPS,
            "{name} indep P: got {} want {}",
            r.independence_pvalue,
            indep_p
        );
        assert!(
            (r.gof_pvalue - gof_p).abs() < PARITY_EPS,
            "{name} gof P: got {} want {}",
            r.gof_pvalue,
            gof_p
        );
        assert_eq!(r.passed, expect_pass, "{name} verdict");
    }

    /// rand1_short (binary path).
    #[test]
    fn rand1_short_anchor() {
        check_anchor(
            "rand1_short",
            106.896_127_145_024_64,
            126,
            0.890_220_890_079_810_87,
            10.918_427_951_175_554,
            9,
            0.281_341_776_599_411_23,
            true,
        );
    }

    /// rand4_short (non-binary path, alphabet 16).
    #[test]
    fn rand4_short_anchor() {
        check_anchor(
            "rand4_short",
            234.346_199_983_151_62,
            240,
            0.590_806_068_805_577_62,
            150.755_147_091_801_58,
            135,
            0.167_501_957_612_742_78,
            true,
        );
    }

    /// rand8_short (non-binary path, alphabet 256) — FAILS (indep p < 0.001).
    #[test]
    fn rand8_short_anchor_fails() {
        check_anchor(
            "rand8_short",
            1026.242_376_130_105_6,
            735,
            5.514_377_257_621_011_9e-12,
            1288.236_790_739_753_6,
            1206,
            0.049_333_049_713_476_802,
            false,
        );
    }

    /// IID oracle direction: the bundled IID oracle passes the §5.2 tests.
    #[test]
    fn oracle_iid_passes() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/oracle_iid.bin");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} absent — skipping", path.display());
            return;
        };
        let r = chi_square_tests(&data);
        assert!(
            r.passed,
            "oracle_iid should pass §5.2: indep_p={} gof_p={}",
            r.independence_pvalue, r.gof_pvalue
        );
    }

    /// Non-IID oracle direction: the bundled non-IID oracle fails the §5.2 tests.
    #[test]
    fn oracle_noniid_fails() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/oracle_noniid.bin");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} absent — skipping", path.display());
            return;
        };
        let r = chi_square_tests(&data);
        assert!(
            !r.passed,
            "oracle_noniid should fail §5.2: indep_p={} gof_p={}",
            r.independence_pvalue, r.gof_pvalue
        );
    }

    /// Hand-constructable binary goodness-of-fit: a perfectly balanced binary
    /// sequence (alternating 0/1) has each sub-block exactly half ones, so the
    /// observed counts equal the expected counts in every block → T = 0, p = 1.
    #[test]
    fn binary_gof_balanced_is_zero() {
        // 10000 alternating bits: every sub-block of 1000 has exactly 500 ones.
        let buf: Vec<u8> = (0..10_000u32).map(|i| (i % 2) as u8).collect();
        let (t, df) = binary_goodness_of_fit(&buf, buf.len());
        assert_eq!(df, 9);
        assert!(t.abs() < 1.0e-9, "balanced GOF T should be 0, got {t}");
        // p-value of T=0 is 1.0.
        assert!(
            (chi_square_pvalue(t, f64::from(df)) - 1.0).abs() < 1.0e-12,
            "p(T=0) should be 1.0"
        );
    }

    /// A skewed binary input where the global proportion differs sharply from
    /// some sub-blocks drives the GOF statistic well above zero (positive T).
    #[test]
    fn binary_gof_skewed_is_positive() {
        // First half all ones, second half all zeros: global p=0.5, but each
        // block is all-1 or all-0, maximally far from the expected 50/50.
        let mut buf = vec![1u8; 5000];
        buf.extend(std::iter::repeat(0u8).take(5000));
        let (t, df) = binary_goodness_of_fit(&buf, buf.len());
        assert_eq!(df, 9);
        assert!(t > 1.0, "skewed GOF T should be large, got {t}");
    }

    /// The symbol map is the identity for already-contiguous data and remaps
    /// sparse byte values down to 0..alph.
    #[test]
    fn map_symbols_is_monotonic() {
        // Contiguous from 0: identity.
        let contig = [0u8, 1, 2, 3, 2, 1, 0];
        assert_eq!(map_symbols(&contig), contig.to_vec());
        // Sparse {10, 20, 30}: → {0, 1, 2}, order-preserving.
        let sparse = [30u8, 10, 20, 10, 30];
        assert_eq!(map_symbols(&sparse), vec![2, 0, 1, 0, 2]);
        assert_eq!(alphabet_size(&sparse), 3);
    }
}
