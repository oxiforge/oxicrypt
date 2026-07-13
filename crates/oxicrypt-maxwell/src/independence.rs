//! **Independence analysis (2D/3D min-entropy)** — reviewer-facing evidence that
//! higher-order (joint-alphabet) structure does not threaten the ratified
//! per-OE min-entropy claim (out of the cryptographic boundary).
//!
//! This is the min-entropy half of ISC-121, the pairs/triplets counterpart to
//! the FFT half already shipped as [`crate::periodicity`]. The precedent is the
//! jent v3.7.0 design doc §4.1: the entropy analysis "calculates the min-entropy
//! of **pairs and triplets of adjacent time deltas** … if the different
//! min-entropy values are in relative close proximity to each other, the adjacent
//! time deltas are considered to have very little mutual dependencies." The
//! precedent warns that "for a representative value … **at the very least
//! 10,000,000** should be collected."
//!
//! # What this is — and is not
//!
//! It is evidence established with the same estimator class that set the claim.
//! It **never claims the source is independent** — the pilot source is assessed
//! non-IID (the §5 tests fail; the predictors bind), so joint-alphabet values are
//! *expected* to reflect dependence. Three layers, in strength order:
//!
//! 1. **The pair-suite leg (the probative core).** The full literal §6.3 non-IID
//!    estimator battery (MCV + t-Tuple, LRS, MultiMCW, Lag, MultiMMC, LZ78Y — the
//!    `h_original` set, every one EA-parity-proven) run on the disjoint-pair
//!    stream at **both phase offsets**; `pair_suite_min / 2` (min over estimators
//!    and phases) is the per-delta value. The same suite is also run on the
//!    original 1-D symbol stream, so the *structure evidence*
//!    `pair_suite_min/2 − suite_min_1d` is methodology-matched (same code, same
//!    tool). Available only when the source symbols are ≤ 4 bits (the pair
//!    alphabet `2^(2·bits)` must fit the 8-bit estimator wire); for wider sources
//!    the suite leg reports "unavailable — symbol width" and the MCV legs stand
//!    alone.
//! 2. **The tuple-MCV leg (the precedent artifact).** §6.3.1 confidence-bound MCV
//!    on pairs (2 phases) **and** triplets (3 phases, MCV-only — the predictor
//!    battery's power collapses on a 4096-symbol alphabet at ~3.3M draws and
//!    12-bit symbols exceed the estimator wire), plus the plain
//!    `−log₂(max p̂)` precedent form. The per-delta value takes the minimum over
//!    phases — a phase-locked artifact cannot hide in the sampling alignment.
//! 3. **The shuffled-baseline control.** Every measured value is paired with the
//!    same statistic computed on **deterministically shuffled** copies of the
//!    input (the ISC-134 discipline — one documented master seed,
//!    bit-reproducible; the MCV legs use a K = 10 ensemble, the pair-suite leg a
//!    single documented one-draw null). Shuffling preserves the marginal
//!    distribution and destroys serial dependence, and — being same-n,
//!    same-alphabet — carries identical finite-sample bias. The reviewer-facing
//!    proximity evidence is the **measured-vs-null deficit**. A deficit can be
//!    driven by benign nonstationary drift, not only exploitable dependence — the
//!    FFT half and the reviewer decide which.
//!
//! # Gate (claim-anchored FLAG — engineering, not spec)
//!
//! With a `--claim H` supplied, the analysis FLAGs when
//! `min(pair_suite_min/2, H₃_mcv/3) < H` (when the suite leg is unavailable the
//! pair term falls back to the pair-MCV per-delta `H₂/2`). A flag is a verdict +
//! exit FAILURE, mirroring the [`crate::periodicity`] acceptance contract.
//! Without a claim the analysis is report-only (exit SUCCESS), the
//! [`crate::iid_gate`] reporting-tool contract. **Below the 10,000,000-sample
//! precedent minimum the flag is advisory-only:** the verdict is computed and
//! printed but the exit stays SUCCESS and the sidecar carries
//! `"advisory_only": true` — a smoke run on 1M pilot data can never fake an
//! acceptance failure.
//!
//! # Stated limitations (load-bearing)
//!
//! The tuple view covers `k ≤ 3`; longer-range and periodic structure is
//! delegated to the FFT half ([`crate::periodicity`]) and the 1-D §6.3 predictors
//! (lag ≤ 128). This delegation is deliberate. The claim-anchored flag is a floor
//! detector; between "consistent with the 1-D assessment" and "claim-threatening"
//! the evidence is the deficit numbers, not the flag. The proximity ratios and
//! the shuffled-baseline deficits are computed on the **plain** form (matching the
//! precedent's `−log₂(max p̂)` formula); the confidence-bound (MCV) values are the
//! conservative claim-gate values.
//!
//! # Determinism and panic-freedom
//!
//! Pure and deterministic: the same input bytes (and, for the sidecar, the same
//! `run_utc`) always yield an identical report and identical sidecar bytes. The
//! shuffle is seeded from a fixed nothing-up-my-sleeve master
//! ([`INDEPENDENCE_MASTER_SEED`]) and never reads any entropy source. The analysis
//! never panics — degenerate inputs (too short to form a tuple) return a
//! well-defined non-flagging degenerate report, and non-finite intermediates are
//! serialized as JSON `null`. The sidecar `"degenerate"` field is authoritative
//! from the report alone; a benign non-finite diagnostic value never sets it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{McvEstimate, lag, lrs, lz78y, mcv, mcv_from_mode, multi_mcw, multi_mmc};

/// The precedent's minimum sample count for a representative pairs/triplets
/// value (jent v3.7.0 §4.1, quoted in the module doc). Below this the
/// claim-anchored flag is advisory-only.
pub const PRECEDENT_MIN_SAMPLES: usize = 10_000_000;

/// Master seed for the shuffled-baseline control (ISC-134 discipline).
///
/// These are the SHA-512 initial hash words for √11, √13, √17, √19 (the `h4..h7`
/// IV words) — a standard nothing-up-my-sleeve choice, and a deliberate sibling
/// of [`crate::permutation::SHUFFLE_SEED`] (which uses the `h0..h3` words) so the
/// independence shuffles are their own documented, reproducible stream. Every
/// word is non-zero (xoshiro256** requires a non-zero state). The exact value is
/// irrelevant to correctness — any fixed constant makes the control reproducible;
/// documenting a principled origin avoids any suspicion of a value chosen to
/// flatter results. Per-replica states for the K-shuffle ensemble are drawn from
/// this master by advancing the same vetted xoshiro256** generator.
pub const INDEPENDENCE_MASTER_SEED: [u64; 4] = [
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Number of shuffles in the MCV-leg null ensemble (one draw is a single draw
/// from the null, not the null; the 4096-bin triplet leg is where a one-draw null
/// is noisiest).
pub const K_MCV_SHUFFLES: usize = 10;

/// The pair-suite leg is documented as a single-draw null (suite runtime bounds
/// it; the suite leg's gate is its absolute claim comparison, not its deficit).
pub const K_SUITE_SHUFFLES: usize = 1;

/// Estimator labels for the literal §6.3 suite, in `h_original` composition order.
pub const SUITE_LABELS: [&str; 7] = [
    "MCV", "tTuple", "LRS", "MultiMCW", "Lag", "MultiMMC", "LZ78Y",
];

// ---------------------------------------------------------------------------
// Tuple encoding (byte-exact, big-endian symbol packing)
// ---------------------------------------------------------------------------

/// Encode the **disjoint** adjacent `k`-tuples of `symbols` at a given `phase`
/// offset into big-endian packed codes.
///
/// Pairs (`k = 2`) at phase 0 are `(s₀s₁)(s₂s₃)…`; at phase 1 `(s₁s₂)(s₃s₄)…`.
/// Triplets (`k = 3`) run phases 0, 1, 2. The tail partial tuple is dropped. The
/// code is big-endian: `code = Σⱼ sⱼ << ((k−1−j)·bits)` — pair code
/// `(s₀ << bits) | s₁`, triplet code `(s₀ << 2·bits) | (s₁ << bits) | s₂`. The
/// alphabet is `2^(k·bits)`; the largest shift is `(k−1)·bits ≤ 2·8 = 16 < 64`,
/// so every shift is in range for `u64` and no code exceeds `2^24`.
///
/// Deterministic; never panics (checked shifts, `.get()` access, saturating
/// index arithmetic).
#[must_use]
#[allow(
    // `hi as u32` is a tuple-position index `(k-1-j) <= 2` — always tiny and in
    // range for u32; the checked_shl below is the real overflow guard.
    clippy::cast_possible_truncation
)]
pub(crate) fn tuple_codes(symbols: &[u8], bits: u8, k: usize, phase: usize) -> Vec<u64> {
    let bits = u32::from(bits);
    let n = symbols.len();
    let mut out: Vec<u64> = Vec::new();
    if k == 0 {
        return out;
    }
    let mut i = phase;
    while i.saturating_add(k) <= n {
        let mut code: u64 = 0;
        for j in 0..k {
            let Some(&s) = symbols.get(i.saturating_add(j)) else {
                break;
            };
            // shift = (k-1-j) * bits, with (k-1-j) <= 2 and bits <= 8 → <= 16.
            let hi = (k.saturating_sub(1)).saturating_sub(j);
            let shift = (hi as u32).saturating_mul(bits);
            code |= u64::from(s).checked_shl(shift).unwrap_or(0);
        }
        out.push(code);
        i = i.saturating_add(k);
    }
    out
}

/// The pair-encoded byte stream at a given phase, for the pair-suite leg.
///
/// Requires `2·bits ≤ 8` (checked by the caller, which only builds this when the
/// suite leg is available); each pair code then fits `u8`. The truncating cast is
/// therefore lossless — `code < 2^(2·bits) ≤ 256`.
#[must_use]
#[allow(
    // 2*bits <= 8 is a caller precondition, so every code is < 256 and the cast
    // is lossless by construction, not a truncation.
    clippy::cast_possible_truncation
)]
fn pair_bytes(symbols: &[u8], bits: u8, phase: usize) -> Vec<u8> {
    tuple_codes(symbols, bits, 2, phase)
        .into_iter()
        .map(|c| c as u8)
        .collect()
}

// ---------------------------------------------------------------------------
// Tuple MCV (bounded confidence-bound + plain −log₂(max p̂))
// ---------------------------------------------------------------------------

/// The plain-form min-entropy `−log₂(max p̂)` from a mode count and total.
///
/// Empty input (`total == 0`) returns `+∞` (a degenerate sentinel, mirroring
/// [`crate::mcv_from_mode`]); otherwise `−log₂(mode / total)`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn plain_min_entropy(mode_count: u64, total: u64) -> f64 {
    if total == 0 {
        return f64::INFINITY;
    }
    let p = (mode_count as f64) / (total as f64);
    -p.log2()
}

/// Histogram a tuple-code slice over its `alphabet` and return both the
/// confidence-bound MCV estimate (shared [`crate::mcv_from_mode`] core) and the
/// plain-form value.
#[allow(
    // codes.len() fits u64 on supported targets; the count → f64 casts are the
    // same the parity-proven MCV core performs.
    clippy::cast_precision_loss,
    // `c as usize`: c < alphabet = 2^(k·bits) <= 2^24 by construction, which fits
    // usize even on 32-bit targets; the .get_mut() is a further total guard.
    clippy::cast_possible_truncation
)]
fn mcv_from_codes(codes: &[u64], alphabet: usize) -> (McvEstimate, f64) {
    let mut hist = vec![0u64; alphabet];
    for &c in codes {
        // c < alphabet by construction (code < 2^(k·bits) = alphabet).
        if let Some(slot) = hist.get_mut(c as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let mode = hist.iter().copied().max().unwrap_or(0);
    let total = codes.len() as u64;
    (mcv_from_mode(mode, total), plain_min_entropy(mode, total))
}

/// The tuple alphabet size `2^(k·bits)`, saturating (never panics).
#[allow(
    // `k as u32`: k is the tuple order (1..=3); the cast is exact and the
    // checked_shl guards any overflow.
    clippy::cast_possible_truncation
)]
fn tuple_alphabet(bits: u8, k: usize) -> usize {
    let shift = (k as u32).saturating_mul(u32::from(bits));
    1usize.checked_shl(shift).unwrap_or(usize::MAX)
}

/// Per-phase bounded (confidence-bound MCV min-entropy) and plain values for the
/// `k`-tuples of `symbols`. Returns `(bounded_per_phase, plain_per_phase)`, each
/// of length `k` (one entry per phase offset `0..k`).
fn tuple_mcv_per_phase(symbols: &[u8], bits: u8, k: usize) -> (Vec<f64>, Vec<f64>) {
    let alphabet = tuple_alphabet(bits, k);
    let mut bounded = Vec::with_capacity(k);
    let mut plain = Vec::with_capacity(k);
    for phase in 0..k {
        let codes = tuple_codes(symbols, bits, k, phase);
        let (b, p) = mcv_from_codes(&codes, alphabet);
        bounded.push(b.min_entropy);
        plain.push(p);
    }
    (bounded, plain)
}

/// Minimum over a slice, ignoring nothing (an empty slice yields `+∞`).
fn min_over(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

// ---------------------------------------------------------------------------
// The MCV leg (tuple-MCV + plain + shuffled-baseline control)
// ---------------------------------------------------------------------------

/// The tuple-MCV leg result: bounded (confidence-bound) whole-tuple min-entropy
/// for `k = 1, 2, 3` (min over phases), the per-phase values, the plain-form
/// counterparts, the shuffled-baseline null (plain per-delta mean ± spread), the
/// measured-vs-null per-delta deficits, and the plain proximity ratios.
#[derive(Debug, Clone, PartialEq)]
pub struct McvLeg {
    /// Confidence-bound (bounded) whole-tuple min-entropy, `k = 1` (per-delta).
    pub h1: f64,
    /// Confidence-bound whole-**pair** min-entropy, min over the 2 phases.
    pub h2: f64,
    /// Confidence-bound whole-**triplet** min-entropy, min over the 3 phases.
    pub h3: f64,
    /// Bounded whole-pair min-entropy per phase (length 2).
    pub pair_bounded_per_phase: Vec<f64>,
    /// Bounded whole-triplet min-entropy per phase (length 3).
    pub triplet_bounded_per_phase: Vec<f64>,
    /// Plain-form `−log₂(max p̂)`, `k = 1`.
    pub plain1: f64,
    /// Plain-form whole-pair value, min over phases.
    pub plain2: f64,
    /// Plain-form whole-triplet value, min over phases.
    pub plain3: f64,
    /// Plain whole-pair value per phase (length 2).
    pub pair_plain_per_phase: Vec<f64>,
    /// Plain whole-triplet value per phase (length 3).
    pub triplet_plain_per_phase: Vec<f64>,
    /// Shuffled-baseline **plain per-delta** null mean `[pd₁, pd₂, pd₃]` over the
    /// `K_MCV_SHUFFLES` ensemble.
    pub null_mean: [f64; 3],
    /// Shuffled-baseline plain per-delta null sample spread (std-dev) `[σ₁, σ₂, σ₃]`.
    pub null_spread: [f64; 3],
    /// `null_mean[1] − measured_pd₂` (plain per-delta) — positive signals
    /// dependence the shuffle destroyed.
    pub deficit2: f64,
    /// `null_mean[2] − measured_pd₃` (plain per-delta).
    pub deficit3: f64,
    /// Plain proximity ratio `(plain₂/2) / plain₁`.
    pub r2_plain: f64,
    /// Plain proximity ratio `(plain₃/3) / plain₁`.
    pub r3_plain: f64,
}

impl McvLeg {
    /// Per-delta bounded pair value `H₂/2`.
    #[must_use]
    pub fn h2_per_delta(&self) -> f64 {
        self.h2 / 2.0
    }

    /// Per-delta bounded triplet value `H₃/3` (the gate's triplet term).
    #[must_use]
    pub fn h3_per_delta(&self) -> f64 {
        self.h3 / 3.0
    }
}

/// Draw a fresh per-replica xoshiro256** state by advancing the master generator
/// four words (guarded non-zero).
fn draw_replica(rng_state: &mut [u64; 4]) -> [u64; 4] {
    let mut s = [
        crate::permutation::xoshiro_next(rng_state),
        crate::permutation::xoshiro_next(rng_state),
        crate::permutation::xoshiro_next(rng_state),
        crate::permutation::xoshiro_next(rng_state),
    ];
    if s == [0u64; 4] {
        s[0] = 1;
    }
    s
}

/// Plain per-delta triple `[pd₁, pd₂, pd₃]` (min over phases) for `symbols`.
fn plain_per_delta(symbols: &[u8], bits: u8) -> [f64; 3] {
    let (_, p1) = tuple_mcv_per_phase(symbols, bits, 1);
    let (_, p2) = tuple_mcv_per_phase(symbols, bits, 2);
    let (_, p3) = tuple_mcv_per_phase(symbols, bits, 3);
    [min_over(&p1), min_over(&p2) / 2.0, min_over(&p3) / 3.0]
}

/// Compute the full tuple-MCV leg for `symbols` with a `k_shuffles`-draw
/// shuffled-baseline null.
///
/// Deterministic (fixed [`INDEPENDENCE_MASTER_SEED`]). `k_shuffles == 0` yields a
/// zeroed null (used by the oracle bit-identity paths that do not need the
/// control).
#[must_use]
pub fn mcv_leg(symbols: &[u8], bits: u8, k_shuffles: usize) -> McvLeg {
    let (b1, p1) = tuple_mcv_per_phase(symbols, bits, 1);
    let (b2, p2) = tuple_mcv_per_phase(symbols, bits, 2);
    let (b3, p3) = tuple_mcv_per_phase(symbols, bits, 3);

    let h1 = min_over(&b1);
    let h2 = min_over(&b2);
    let h3 = min_over(&b3);
    let plain1 = min_over(&p1);
    let plain2 = min_over(&p2);
    let plain3 = min_over(&p3);

    // Measured plain per-delta.
    let pd = [plain1, plain2 / 2.0, plain3 / 3.0];

    // Shuffled-baseline null on the plain per-delta values.
    let (null_mean, null_spread) = shuffled_null_mcv(symbols, bits, k_shuffles);

    let deficit2 = null_mean[1] - pd[1];
    let deficit3 = null_mean[2] - pd[2];

    let (r2_plain, r3_plain) = if plain1.is_finite() && plain1 > 0.0 {
        (pd[1] / plain1, pd[2] / plain1)
    } else {
        (f64::NAN, f64::NAN)
    };

    McvLeg {
        h1,
        h2,
        h3,
        pair_bounded_per_phase: b2,
        triplet_bounded_per_phase: b3,
        plain1,
        plain2,
        plain3,
        pair_plain_per_phase: p2,
        triplet_plain_per_phase: p3,
        null_mean,
        null_spread,
        deficit2,
        deficit3,
        r2_plain,
        r3_plain,
    }
}

/// The shuffled-baseline null for the MCV leg: `k` deterministic Fisher–Yates
/// shuffles (reusing the vetted [`crate::permutation::fy_shuffle`]), recomputing
/// the plain per-delta triple each time. Returns `(mean, sample_spread)` over the
/// ensemble; `k == 0` returns zeros.
#[allow(clippy::cast_precision_loss)]
fn shuffled_null_mcv(symbols: &[u8], bits: u8, k: usize) -> ([f64; 3], [f64; 3]) {
    if k == 0 {
        return ([0.0; 3], [0.0; 3]);
    }
    let mut rng_state = INDEPENDENCE_MASTER_SEED;
    let mut sums = [0.0f64; 3];
    let mut samples: Vec<[f64; 3]> = Vec::with_capacity(k);
    for _ in 0..k {
        let mut st = draw_replica(&mut rng_state);
        let mut work = symbols.to_vec();
        crate::permutation::fy_shuffle(&mut work, &mut st);
        let pd = plain_per_delta(&work, bits);
        for (acc, &v) in sums.iter_mut().zip(pd.iter()) {
            *acc += v;
        }
        samples.push(pd);
    }
    let kf = k as f64;
    let mean = [sums[0] / kf, sums[1] / kf, sums[2] / kf];
    let mut spread = [0.0f64; 3];
    if k > 1 {
        let denom = (k.saturating_sub(1)) as f64;
        for (idx, sp) in spread.iter_mut().enumerate() {
            let m = mean.get(idx).copied().unwrap_or(0.0);
            let mut var = 0.0f64;
            for s in &samples {
                let d = s.get(idx).copied().unwrap_or(0.0) - m;
                var += d * d;
            }
            *sp = (var / denom).sqrt();
        }
    }
    (mean, spread)
}

// ---------------------------------------------------------------------------
// The pair-suite leg (literal §6.3 battery on the pair-encoded stream)
// ---------------------------------------------------------------------------

/// The literal §6.3 suite result on one byte stream: the per-estimator
/// min-entropies (in [`SUITE_LABELS`] order) and their minimum (the `h_original`
/// composition — `−1.0` "did not run" sentinels excluded from the minimum).
#[derive(Debug, Clone, PartialEq)]
pub struct SuiteResult {
    /// Per-estimator min-entropy, `[MCV, tTuple, LRS, MultiMCW, Lag, MultiMMC, LZ78Y]`.
    pub per_estimator: [f64; 7],
    /// Minimum over the estimators that ran (`h ≥ 0`).
    pub min: f64,
}

/// The pair-suite leg: per-estimator values at both phase offsets, their overall
/// minimum, the per-delta value, and the two deficits (vs the methodology-matched
/// 1-D suite, and vs the single-draw shuffled null).
#[derive(Debug, Clone, PartialEq)]
pub struct PairSuiteLeg {
    /// `[suite(phase 0), suite(phase 1)]` per-estimator values.
    pub per_estimator_per_phase: [[f64; 7]; 2],
    /// Minimum over estimators **and** phases (whole-pair).
    pub min: f64,
    /// `min / 2` — the per-delta value.
    pub min_per_delta: f64,
    /// `min_per_delta − suite_min_1d` — the structure evidence (both suite-derived).
    pub structure_deficit_vs_1d: f64,
    /// Whole-pair suite minimum on the single shuffled-baseline draw.
    pub null_min: f64,
    /// `null_min/2 − min_per_delta` — positive signals pair-level structure.
    pub deficit_vs_null: f64,
}

/// Run the literal §6.3 suite on `buf` (interpreted at `width` bits/symbol),
/// reusing the exact per-estimator functions the `h_original` composition uses.
///
/// The minimum matches [`crate::h_original`] (the `−1.0` sentinel is filtered
/// before the minimum) — the pair-suite leg is bit-identical to those functions
/// run directly on the encoded buffer.
#[must_use]
fn run_suite(buf: &[u8], width: u8) -> SuiteResult {
    let sa = lrs::lrs_literal(buf);
    let per_estimator = [
        mcv(buf, width).literal.min_entropy,
        sa.t_tuple_min_entropy,
        sa.lrs_min_entropy,
        multi_mcw::multi_mcw_literal(buf).min_entropy(),
        lag::lag_literal(buf).min_entropy(),
        multi_mmc::multimmc_literal(buf).min_entropy(),
        lz78y::lz78y_literal(buf).min_entropy(),
    ];
    let min = per_estimator
        .iter()
        .copied()
        .filter(|&h| h >= 0.0)
        .fold(f64::INFINITY, f64::min);
    SuiteResult { per_estimator, min }
}

/// The width of the pair-encoded alphabet in bits (`2·bits`); the suite leg is
/// available only when this fits the 8-bit estimator wire.
fn pair_width(bits: u8) -> u8 {
    bits.saturating_mul(2)
}

/// `true` when the pair-suite leg is available (source symbols ≤ 4 bits, so the
/// pair alphabet `2^(2·bits)` fits the 8-bit estimator wire).
#[must_use]
pub fn suite_available(bits: u8) -> bool {
    pair_width(bits) <= 8
}

/// Compute the pair-suite leg (both phases + the methodology-matched 1-D suite +
/// the single-draw shuffled null). The caller guarantees [`suite_available`].
#[must_use]
fn pair_suite_leg(symbols: &[u8], bits: u8, suite_min_1d: f64) -> PairSuiteLeg {
    let width = pair_width(bits);
    let s0 = run_suite(&pair_bytes(symbols, bits, 0), width);
    let s1 = run_suite(&pair_bytes(symbols, bits, 1), width);
    let min = s0.min.min(s1.min);
    let min_per_delta = min / 2.0;

    // Single-draw shuffled-baseline null (K_SUITE_SHUFFLES == 1): shuffle the
    // symbol stream, re-encode pairs (phase 0), run the suite.
    let mut rng_state = INDEPENDENCE_MASTER_SEED;
    let mut st = draw_replica(&mut rng_state);
    let mut work = symbols.to_vec();
    crate::permutation::fy_shuffle(&mut work, &mut st);
    let null_min = run_suite(&pair_bytes(&work, bits, 0), width).min;

    PairSuiteLeg {
        per_estimator_per_phase: [s0.per_estimator, s1.per_estimator],
        min,
        min_per_delta,
        structure_deficit_vs_1d: min_per_delta - suite_min_1d,
        null_min,
        deficit_vs_null: null_min / 2.0 - min_per_delta,
    }
}

// ---------------------------------------------------------------------------
// The full analysis
// ---------------------------------------------------------------------------

/// Which term drove a claim FLAG (for the legible `flag_cause` sidecar field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagCause {
    /// The pair per-delta value (suite leg, or MCV pair when the suite is
    /// unavailable) fell below the claim.
    Pair,
    /// The triplet-MCV per-delta value fell below the claim.
    TripletMcv,
}

impl FlagCause {
    /// A stable machine-readable token for the sidecar.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Pair => "pair_below_claim",
            Self::TripletMcv => "triplet_mcv_below_claim",
        }
    }
}

/// The full independence-analysis report.
#[derive(Debug, Clone, PartialEq)]
#[allow(
    // The four booleans (suite_available, flagged, advisory_only, degenerate) are
    // independent orthogonal report facts surfaced verbatim in the sidecar, not a
    // hidden state machine; folding them into enums would obscure the schema.
    clippy::struct_excessive_bools
)]
pub struct IndependenceReport {
    /// Number of symbols analyzed.
    pub n: usize,
    /// Source bits per symbol (`1..=8`).
    pub bits_per_symbol: u8,
    /// Pair alphabet `2^(2·bits)`.
    pub pair_alphabet: usize,
    /// Triplet alphabet `2^(3·bits)`.
    pub triplet_alphabet: usize,
    /// Disjoint pair counts per phase `[phase 0, phase 1]`.
    pub pair_count_per_phase: [usize; 2],
    /// Disjoint triplet counts per phase `[phase 0, phase 1, phase 2]`.
    pub triplet_count_per_phase: [usize; 3],
    /// Distinct pair codes present (phase 0) — occupancy.
    pub pair_occupancy: usize,
    /// Distinct triplet codes present (phase 0) — occupancy.
    pub triplet_occupancy: usize,
    /// `true` when the pair-suite leg ran (source ≤ 4 bits).
    pub suite_available: bool,
    /// The literal §6.3 suite on the original 1-D symbol stream (when available).
    pub suite_1d: Option<SuiteResult>,
    /// The pair-suite leg (when available).
    pub pair_suite: Option<PairSuiteLeg>,
    /// The tuple-MCV leg (always present).
    pub mcv: McvLeg,
    /// The claim, if `--claim` was supplied.
    pub claim: Option<f64>,
    /// `true` when `min(pair_term, H₃_mcv/3) < claim` (the comparison; see
    /// `advisory_only` for the exit).
    pub flagged: bool,
    /// Which term drove the flag (legible cause).
    pub flag_cause: Option<FlagCause>,
    /// `true` when `n < PRECEDENT_MIN_SAMPLES` — the flag is advisory, exit stays
    /// SUCCESS.
    pub advisory_only: bool,
    /// `true` when the input was too short to form tuples or a headline value was
    /// non-finite.
    pub degenerate: bool,
}

impl IndependenceReport {
    /// The pair per-delta gate term: the suite leg's `min_per_delta` when
    /// available, else the MCV pair per-delta `H₂/2`.
    #[must_use]
    pub fn pair_term(&self) -> f64 {
        self.pair_suite
            .as_ref()
            .map_or_else(|| self.mcv.h2_per_delta(), |p| p.min_per_delta)
    }

    /// The gate value `min(pair_term, H₃_mcv/3)`.
    #[must_use]
    pub fn gate_value(&self) -> f64 {
        self.pair_term().min(self.mcv.h3_per_delta())
    }

    /// The process exit intent: FAILURE only for a non-advisory claim flag.
    #[must_use]
    pub fn exit_failure(&self) -> bool {
        self.flagged && !self.advisory_only
    }
}

/// Count distinct codes present in a code slice (occupancy).
fn occupancy(codes: &[u64]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for &c in codes {
        seen.insert(c);
    }
    seen.len()
}

/// Validate a `--claim` min-entropy value: a claim must be a finite, positive
/// real number (bits/symbol). Rejects `NaN`/`inf` — which would silently
/// subvert the acceptance gate (`gate < NaN` is always false, `gate < inf`
/// always true) — and non-positive values.
#[must_use]
pub fn validate_claim(h: f64) -> bool {
    h.is_finite() && h > 0.0
}

/// Run the full independence analysis over `symbols` at `bits` bits/symbol,
/// optionally gated against `claim`.
///
/// Deterministic and panic-free. Inputs too short to form a triplet
/// (`n < 3`) return a degenerate, non-flagging report.
#[must_use]
pub fn analyze(symbols: &[u8], bits: u8, claim: Option<f64>) -> IndependenceReport {
    let n = symbols.len();
    let bits = bits.clamp(1, 8);
    let pair_alphabet = tuple_alphabet(bits, 2);
    let triplet_alphabet = tuple_alphabet(bits, 3);

    let pair_count_per_phase = [
        tuple_codes(symbols, bits, 2, 0).len(),
        tuple_codes(symbols, bits, 2, 1).len(),
    ];
    let triplet_count_per_phase = [
        tuple_codes(symbols, bits, 3, 0).len(),
        tuple_codes(symbols, bits, 3, 1).len(),
        tuple_codes(symbols, bits, 3, 2).len(),
    ];
    let pair_occupancy = occupancy(&tuple_codes(symbols, bits, 2, 0));
    let triplet_occupancy = occupancy(&tuple_codes(symbols, bits, 3, 0));

    let mcv = mcv_leg(symbols, bits, K_MCV_SHUFFLES);

    let available = suite_available(bits);
    let (suite_1d, pair_suite) = if available {
        let s1d = run_suite(symbols, bits);
        let leg = pair_suite_leg(symbols, bits, s1d.min);
        (Some(s1d), Some(leg))
    } else {
        (None, None)
    };

    let degenerate = n < 3 || !mcv.h1.is_finite() || !mcv.h2.is_finite() || !mcv.h3.is_finite();
    let advisory_only = n < PRECEDENT_MIN_SAMPLES;

    let mut report = IndependenceReport {
        n,
        bits_per_symbol: bits,
        pair_alphabet,
        triplet_alphabet,
        pair_count_per_phase,
        triplet_count_per_phase,
        pair_occupancy,
        triplet_occupancy,
        suite_available: available,
        suite_1d,
        pair_suite,
        mcv,
        claim,
        flagged: false,
        flag_cause: None,
        advisory_only,
        degenerate,
    };

    // Gate. The FLAG decision uses `report.gate_value()` — the same source the
    // displayed gate value uses — so the two can never drift. A degenerate
    // input never flags (its bounded values are 0-entropy sentinels, not
    // evidence); a non-finite claim (defense-in-depth against a bad CLI value
    // that slipped past `validate_claim`) never flags.
    if let Some(h) = claim
        && h.is_finite()
        && !report.degenerate
        && report.gate_value() < h
    {
        let pair_term = report.pair_term();
        let triplet_term = report.mcv.h3_per_delta();
        report.flag_cause = Some(if pair_term <= triplet_term {
            FlagCause::Pair
        } else {
            FlagCause::TripletMcv
        });
        report.flagged = true;
    }

    report
}

// ---------------------------------------------------------------------------
// Provenance (--metadata copy-through) and the sidecar writer
// ---------------------------------------------------------------------------

/// Provenance fields copied through from the collection metadata sidecar when
/// `--metadata` is given (all optional).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    /// Operating-environment identifier.
    pub oe_id: Option<String>,
    /// Boundary label.
    pub boundary: Option<String>,
    /// Timer source label.
    pub timer_source: Option<String>,
}

/// Extract an optional JSON string field `"key": "value"` from `text`. Missing =
/// `None` (provenance is best-effort copy-through, never an error).
#[must_use]
fn json_opt_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = text.find(&needle)?;
    let after = text.get(at.saturating_add(needle.len())..)?;
    let colon = after.find(':')?;
    let rest = after.get(colon.saturating_add(1)..)?.trim_start();
    let body = rest.strip_prefix('"')?;
    // Scan to the closing UNescaped quote, unescaping JSON string escapes so a
    // value containing `\"` is not truncated at the backslash-quote.
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'b' => out.push('\u{08}'),
                'f' => out.push('\u{0C}'),
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        code = code
                            .checked_mul(16)?
                            .checked_add(chars.next()?.to_digit(16)?)?;
                    }
                    out.push(char::from_u32(code)?);
                }
                other => out.push(other),
            },
            other => out.push(other),
        }
    }
    None
}

/// Parse the provenance fields from a collection metadata sidecar (`--metadata`).
#[must_use]
pub fn parse_metadata(text: &str) -> Provenance {
    Provenance {
        oe_id: json_opt_string(text, "oe_id"),
        boundary: json_opt_string(text, "boundary"),
        timer_source: json_opt_string(text, "timer_source"),
    }
}

/// Serialize an `f64` for the sidecar: finite → Rust shortest-roundtrip
/// `Display`; non-finite → JSON `null`. A non-finite diagnostic value (e.g. a
/// proximity ratio over a zero-entropy stream) is benign and does NOT mark the
/// report degenerate — the sidecar `degenerate` field is authoritative from
/// `IndependenceReport::degenerate` alone.
fn json_f64(x: f64) -> String {
    if x.is_finite() {
        format!("{x}")
    } else {
        "null".to_owned()
    }
}

/// Serialize a `[f64]` slice as a JSON array (element-wise via [`json_f64`]).
fn json_f64_array(xs: &[f64]) -> String {
    let parts: Vec<String> = xs.iter().map(|&x| json_f64(x)).collect();
    format!("[{}]", parts.join(", "))
}

/// A JSON string value, or `null` for `None`.
fn json_opt(s: Option<&str>) -> String {
    match s {
        Some(v) => format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")),
        None => "null".to_owned(),
    }
}

/// The default sidecar filename.
pub const SIDECAR_FILE: &str = "independence-results.json";

/// Write the `independence-results.json` sidecar to `dir`.
///
/// `run_utc` and `input_sha256` are supplied by the caller (production supplies
/// the real values; the determinism oracle supplies fixed ones so the sidecar
/// bytes are comparable). The serialization rules are frozen: floats via Rust
/// shortest-roundtrip `Display`, non-finite `f64` → JSON `null` (the
/// `"degenerate"` field is authoritative from the report). The sidecar
/// directory is created if absent. Returns the written path.
#[allow(
    // The hand-written JSON assembles many fields; splitting it would obscure the
    // 1:1 correspondence with the frozen schema.
    clippy::too_many_lines
)]
pub fn write_sidecar(
    report: &IndependenceReport,
    run_utc: &str,
    input_sha256: Option<&str>,
    prov: &Provenance,
    dir: &Path,
) -> std::io::Result<PathBuf> {
    let json = render_sidecar(report, run_utc, input_sha256, prov);
    std::fs::create_dir_all(dir)?;
    let path = dir.join(SIDECAR_FILE);
    let mut f = std::fs::File::create(&path)?;
    f.write_all(json.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(path)
}

/// Render the sidecar JSON as a `String` (the deterministic core of
/// [`write_sidecar`], factored out so the determinism oracle can compare bytes
/// without touching the filesystem).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_sidecar(
    report: &IndependenceReport,
    run_utc: &str,
    input_sha256: Option<&str>,
    prov: &Provenance,
) -> String {
    let m = &report.mcv;

    // suite_1d block.
    let suite_1d_json = match &report.suite_1d {
        Some(s) => format!(
            "{{\"per_estimator\": {}, \"min\": {}}}",
            json_f64_array(&s.per_estimator),
            json_f64(s.min)
        ),
        None => "null".to_owned(),
    };

    // pair_suite block.
    let pair_suite_json = match &report.pair_suite {
        Some(p) => format!(
            "{{\"per_estimator_per_phase\": [{}, {}], \"min\": {}, \"min_per_delta\": {}, \
             \"structure_deficit_vs_1d\": {}, \"null_min\": {}, \"deficit_vs_null\": {}}}",
            json_f64_array(&p.per_estimator_per_phase[0]),
            json_f64_array(&p.per_estimator_per_phase[1]),
            json_f64(p.min),
            json_f64(p.min_per_delta),
            json_f64(p.structure_deficit_vs_1d),
            json_f64(p.null_min),
            json_f64(p.deficit_vs_null),
        ),
        None => "null".to_owned(),
    };

    // mcv block.
    let per_delta_per_phase = format!(
        "{{\"pairs\": {}, \"triplets\": {}}}",
        json_f64_array(&m.pair_bounded_per_phase),
        json_f64_array(&m.triplet_bounded_per_phase),
    );
    let plain_block = format!(
        "{{\"h1\": {}, \"h2\": {}, \"h3\": {}}}",
        json_f64(m.plain1),
        json_f64(m.plain2),
        json_f64(m.plain3),
    );
    let deficits_block = format!(
        "{{\"d2\": {}, \"d3\": {}}}",
        json_f64(m.deficit2),
        json_f64(m.deficit3),
    );
    let mcv_json = format!(
        "{{\"h1\": {}, \"h2\": {}, \"h3\": {}, \"per_delta_per_phase\": {}, \"plain\": {}, \
         \"null_mean\": {}, \"null_spread\": {}, \"deficits\": {}, \"r2_plain\": {}, \
         \"r3_plain\": {}}}",
        json_f64(m.h1),
        json_f64(m.h2),
        json_f64(m.h3),
        per_delta_per_phase,
        plain_block,
        json_f64_array(&m.null_mean),
        json_f64_array(&m.null_spread),
        deficits_block,
        json_f64(m.r2_plain),
        json_f64(m.r3_plain),
    );

    let claim_json = report.claim.map_or_else(|| "null".to_owned(), json_f64);
    let flagged_json = report.flagged.to_string();
    let flag_cause_json = report
        .flag_cause
        .map_or_else(|| "null".to_owned(), |c| format!("\"{}\"", c.token()));

    // `degenerate` is authoritative from the report alone; a benign non-finite
    // diagnostic value renders as JSON `null` without marking the report
    // degenerate (so a real FLAG is never poisoned into a "degenerate" sidecar).
    format!(
        "{{\n  \
         \"maxwell_version\": \"{ver}\",\n  \
         \"run_utc\": \"{run_utc}\",\n  \
         \"input_sha256\": {sha},\n  \
         \"oe_id\": {oe},\n  \
         \"boundary\": {boundary},\n  \
         \"timer_source\": {timer},\n  \
         \"n\": {n},\n  \
         \"bits_per_symbol\": {bits},\n  \
         \"tuple_mode\": \"disjoint\",\n  \
         \"phases\": {{\"pairs\": 2, \"triplets\": 3}},\n  \
         \"estimator_labels\": {labels},\n  \
         \"pair_alphabet\": {pair_alph},\n  \
         \"triplet_alphabet\": {trip_alph},\n  \
         \"pair_count_per_phase\": [{pcp0}, {pcp1}],\n  \
         \"triplet_count_per_phase\": [{tcp0}, {tcp1}, {tcp2}],\n  \
         \"pair_occupancy\": {pocc},\n  \
         \"triplet_occupancy\": {tocc},\n  \
         \"suite_available\": {suite_avail},\n  \
         \"shuffle\": {{\"master_seed\": \"{seed:016x}{seed1:016x}{seed2:016x}{seed3:016x}\", \
         \"k_mcv\": {k_mcv}, \"k_suite\": {k_suite}}},\n  \
         \"suite_1d\": {suite1d},\n  \
         \"pair_suite\": {pair_suite},\n  \
         \"mcv\": {mcv},\n  \
         \"claim\": {claim},\n  \
         \"flagged\": {flagged},\n  \
         \"flag_cause\": {flag_cause},\n  \
         \"advisory_only\": {advisory},\n  \
         \"degenerate\": {degenerate}\n\
         }}",
        ver = env!("CARGO_PKG_VERSION"),
        sha = json_opt(input_sha256),
        oe = json_opt(prov.oe_id.as_deref()),
        boundary = json_opt(prov.boundary.as_deref()),
        timer = json_opt(prov.timer_source.as_deref()),
        n = report.n,
        bits = report.bits_per_symbol,
        labels = format_labels(),
        pair_alph = report.pair_alphabet,
        trip_alph = report.triplet_alphabet,
        pcp0 = report.pair_count_per_phase[0],
        pcp1 = report.pair_count_per_phase[1],
        tcp0 = report.triplet_count_per_phase[0],
        tcp1 = report.triplet_count_per_phase[1],
        tcp2 = report.triplet_count_per_phase[2],
        pocc = report.pair_occupancy,
        tocc = report.triplet_occupancy,
        suite_avail = report.suite_available,
        seed = INDEPENDENCE_MASTER_SEED[0],
        seed1 = INDEPENDENCE_MASTER_SEED[1],
        seed2 = INDEPENDENCE_MASTER_SEED[2],
        seed3 = INDEPENDENCE_MASTER_SEED[3],
        k_mcv = K_MCV_SHUFFLES,
        k_suite = K_SUITE_SHUFFLES,
        suite1d = suite_1d_json,
        pair_suite = pair_suite_json,
        mcv = mcv_json,
        claim = claim_json,
        flagged = flagged_json,
        flag_cause = flag_cause_json,
        advisory = report.advisory_only,
        degenerate = report.degenerate,
    )
}

/// The estimator-label JSON array.
fn format_labels() -> String {
    let parts: Vec<String> = SUITE_LABELS.iter().map(|l| format!("\"{l}\"")).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
#[allow(
    // Tests assert exact hand-computed values, use unwrap/expect/panic for fatal
    // setup invariants, index fixed-size fixtures, and print skip notices — all
    // fine in test code (mirrors the rest of the crate's test posture).
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]
mod tests {
    use super::*;

    /// SplitMix64 — a deterministic, well-distributed byte generator for the
    /// synthetic oracle fixtures (no `rand` dependency; the same generator the
    /// periodicity tests use).
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// N uniform 4-bit symbols (low nibble of a fresh SplitMix64 draw).
    fn uniform_nibbles(n: usize, seed: u64) -> Vec<u8> {
        let mut rng = SplitMix64::new(seed);
        (0..n).map(|_| (rng.next_u64() & 0x0F) as u8).collect()
    }

    /// N independent 4-bit symbols with P(symbol 0) = 0.5 (heavy mode), the rest
    /// uniform over 1..16.
    fn concentrated_symbols(n: usize, seed: u64) -> Vec<u8> {
        let mut rng = SplitMix64::new(seed);
        (0..n)
            .map(|_| {
                let r = rng.next_u64();
                if r & 1 == 0 {
                    0u8
                } else {
                    1 + ((r >> 1) % 15) as u8
                }
            })
            .collect()
    }

    /// N binary symbols from a first-order Markov chain with a given switch
    /// probability (stationary π = [0.5, 0.5]).
    fn markov_binary(n: usize, switch_prob: f64, seed: u64) -> Vec<u8> {
        let mut rng = SplitMix64::new(seed);
        let threshold = (switch_prob * (u64::MAX as f64)) as u64;
        let mut state = 0u8;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(state);
            if rng.next_u64() < threshold {
                state ^= 1;
            }
        }
        out
    }

    // ----- O1: analytic recovery -----

    /// O1(a): concentrated distribution (heavy mode P(0)=0.5). The bounded-MCV
    /// per-delta pair and triplet values recover the analytic per-delta 1.0
    /// (= H₁ = −log₂(0.5)) within ≤ 0.01 bit, and never exceed it (one-sided
    /// conservatism — both finite-sample bias and the confidence bound push down).
    #[test]
    fn o1_a_concentrated_recovery() {
        let data = concentrated_symbols(1_000_000, 0xC0CE_A711_0F1D_2E3C);
        let leg = mcv_leg(&data, 4, 0);
        let analytic = 1.0f64; // -log2(0.5)
        let pd2 = leg.h2_per_delta();
        let pd3 = leg.h3_per_delta();
        assert!(
            (pd2 - analytic).abs() <= 0.01,
            "O1(a) pair per-delta {pd2} vs analytic {analytic}"
        );
        assert!(
            (pd3 - analytic).abs() <= 0.01,
            "O1(a) triplet per-delta {pd3} vs analytic {analytic}"
        );
        assert!(
            pd2 <= analytic + 1e-9,
            "bounded pair must not exceed analytic"
        );
        assert!(
            pd3 <= analytic + 1e-9,
            "bounded triplet must not exceed analytic"
        );
    }

    /// O1(b): uniform 4-bit data. Bounded-MCV per-delta lands in the pre-registered
    /// two-sided window `[analytic − Δ, analytic]` with Δ(pairs,256 bins)=0.15 and
    /// Δ(triplets,4096 bins)=0.30, and never exceeds analytic (one-sided
    /// conservatism).
    #[test]
    fn o1_b_uniform_windows() {
        const D_PAIRS: f64 = 0.15;
        const D_TRIPLETS: f64 = 0.30;
        let data = uniform_nibbles(1_000_000, 0xA1B2_C3D4_E5F6_0718);
        let leg = mcv_leg(&data, 4, 0);
        let analytic = 4.0f64; // uniform 4-bit per-delta
        let pd2 = leg.h2_per_delta();
        let pd3 = leg.h3_per_delta();
        assert!(
            pd2 <= analytic + 1e-9 && pd2 >= analytic - D_PAIRS,
            "O1(b) pairs: {pd2} not in [{}, {analytic}] (Δ={D_PAIRS})",
            analytic - D_PAIRS
        );
        assert!(
            pd3 <= analytic + 1e-9 && pd3 >= analytic - D_TRIPLETS,
            "O1(b) triplets: {pd3} not in [{}, {analytic}] (Δ={D_TRIPLETS})",
            analytic - D_TRIPLETS
        );
    }

    /// O1(c): plain-form 1-D uniform recovery within 0.05 bit at n=1M (mode bias
    /// only — the 16-symbol alphabet's max-bin bias is small).
    #[test]
    fn o1_c_plain_uniform_recovery() {
        let data = uniform_nibbles(1_000_000, 0x0F1E_2D3C_4B5A_6978);
        let leg = mcv_leg(&data, 4, 0);
        let analytic = 4.0f64;
        assert!(
            (leg.plain1 - analytic).abs() <= 0.05,
            "O1(c) plain H1 {} vs analytic {analytic}",
            leg.plain1
        );
    }

    // ----- O2: analytic dependence detection -----

    /// O2: first-order Markov binary chain (P(switch)=0.1). The plain-form pair
    /// per-delta recovers the analytic dependent value within the pair window, and
    /// the shuffled-baseline deficit is positive and ≥ half the analytic dependence
    /// gap — the detection direction is proven (kills "reports independence for
    /// everything").
    #[test]
    fn o2_dependence_detection() {
        let switch = 0.1f64;
        let data = markov_binary(1_000_000, switch, 0xDEAD_BEEF_1234_5678);
        let leg = mcv_leg(&data, 1, K_MCV_SHUFFLES);

        // Analytic (stationary π=[0.5,0.5]): max pair prob = π·P(stay)=0.5·0.9.
        let stay = 1.0 - switch;
        let max_pair = 0.5 * stay;
        let h2_dep_per_delta = -max_pair.log2() / 2.0;
        // Independent pair max = (max π)^2 = 0.25 → per-delta 1.0.
        let max_pair_indep = 0.25f64;
        let h2_indep_per_delta = -max_pair_indep.log2() / 2.0;
        let analytic_gap = h2_indep_per_delta - h2_dep_per_delta;

        // Measured plain pair per-delta recovers the dependent value (pair window).
        let measured_pd2 = leg.plain2 / 2.0;
        assert!(
            (measured_pd2 - h2_dep_per_delta).abs() <= 0.15,
            "O2 measured plain pair per-delta {measured_pd2} vs analytic dependent {h2_dep_per_delta}"
        );

        // Shuffled-baseline deficit positive and ≥ half the analytic gap.
        assert!(
            leg.deficit2 > 0.0,
            "O2 deficit2 must be positive, got {}",
            leg.deficit2
        );
        assert!(
            leg.deficit2 >= 0.5 * analytic_gap,
            "O2 deficit2 {} must be ≥ half analytic gap {}",
            leg.deficit2,
            0.5 * analytic_gap
        );
        // Triplet deficit direction too.
        assert!(leg.deficit3 > 0.0, "O2 deficit3 must be positive");
    }

    // ----- O3: internal bit-identity -----

    /// O3: the pair-MCV path equals `mcv(pair_encoded_buf, 2·bits).literal`
    /// bit-exactly (same shared core), and the pair-suite leg equals the
    /// per-estimator functions run directly on the encoded buffer, bit-exactly.
    #[test]
    fn o3_internal_bit_identity() {
        let data = concentrated_symbols(50_000, 0x1357_9BDF_2468_ACE0);
        let bits = 4u8;

        // Pair-MCV bit-identity (phase 0), bounded track.
        let codes = tuple_codes(&data, bits, 2, 0);
        let (bounded, _) = mcv_from_codes(&codes, tuple_alphabet(bits, 2));
        let encoded = pair_bytes(&data, bits, 0);
        let via_mcv = mcv(&encoded, 8).literal;
        assert_eq!(
            bounded, via_mcv,
            "pair-MCV must equal mcv(pair_encoded, 2·bits).literal bit-exactly"
        );

        // Pair-suite bit-identity (phase 0): our run_suite over pair bytes equals
        // the per-estimator functions called directly on the same buffer.
        let leg_suite = run_suite(&encoded, 8);
        let sa = lrs::lrs_literal(&encoded);
        let direct = [
            mcv(&encoded, 8).literal.min_entropy,
            sa.t_tuple_min_entropy,
            sa.lrs_min_entropy,
            multi_mcw::multi_mcw_literal(&encoded).min_entropy(),
            lag::lag_literal(&encoded).min_entropy(),
            multi_mmc::multimmc_literal(&encoded).min_entropy(),
            lz78y::lz78y_literal(&encoded).min_entropy(),
        ];
        assert_eq!(
            leg_suite.per_estimator, direct,
            "pair-suite per-estimator must match direct estimator calls bit-exactly"
        );
    }

    // ----- O4: determinism + encoder KATs -----

    /// O4 encoder KATs: byte-exact tuple-code sequences asserting stride, phase,
    /// and tail semantics on **both** paths — an odd-length (9-symbol) pair vector
    /// and a non-multiple-of-3 (8-symbol) triplet vector, so tail truncation is
    /// exercised.
    #[test]
    fn o4_encoder_kats() {
        // 9 symbols, 4-bit: pairs phase 0 = (0,1)(2,3)(4,5)(6,7); symbol 8 dropped.
        let v9 = [0u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let bits = 4u8;
        // code = (s0<<4)|s1.
        assert_eq!(
            tuple_codes(&v9, bits, 2, 0),
            vec![0x01, 0x23, 0x45, 0x67],
            "pair phase-0 stride/tail"
        );
        // phase 1 = (1,2)(3,4)(5,6)(7,8): codes 0x12,0x34,0x56,0x78; symbol 0 skipped.
        assert_eq!(
            tuple_codes(&v9, bits, 2, 1),
            vec![0x12, 0x34, 0x56, 0x78],
            "pair phase-1 stride/tail"
        );

        // 8 symbols, 4-bit: triplets phase 0 = (0,1,2)(3,4,5); symbols 6,7 dropped.
        let v8 = [0u8, 1, 2, 3, 4, 5, 6, 7];
        // code = (s0<<8)|(s1<<4)|s2.
        assert_eq!(
            tuple_codes(&v8, bits, 3, 0),
            vec![0x012, 0x345],
            "triplet phase-0 stride/tail"
        );
        // phase 1 = (1,2,3)(4,5,6); symbols 0 and 7 dropped.
        assert_eq!(
            tuple_codes(&v8, bits, 3, 1),
            vec![0x123, 0x456],
            "triplet phase-1 stride/tail"
        );
        // phase 2 = (2,3,4)(5,6,7); symbols 0,1 dropped, none trailing.
        assert_eq!(
            tuple_codes(&v8, bits, 3, 2),
            vec![0x234, 0x567],
            "triplet phase-2 stride/tail"
        );
    }

    /// O4 determinism: the report AND the rendered sidecar bytes are bit-identical
    /// across two runs (fixed run_utc so the timestamp does not confound).
    #[test]
    fn o4_determinism_bit_exact() {
        let data = concentrated_symbols(20_000, 0x2020_2020_2020_2020);
        let bits = 4u8;
        let a = analyze(&data, bits, Some(0.5));
        let b = analyze(&data, bits, Some(0.5));
        assert_eq!(a, b, "report must be bit-identical across runs");

        let prov = Provenance {
            oe_id: Some("oe-test".to_owned()),
            boundary: Some("primary".to_owned()),
            timer_source: Some("tsc".to_owned()),
        };
        let sa = render_sidecar(&a, "1700000000", Some("deadbeef"), &prov);
        let sb = render_sidecar(&b, "1700000000", Some("deadbeef"), &prov);
        assert_eq!(sa, sb, "sidecar bytes must be bit-identical across runs");
        // Sanity: the sidecar carries the frozen top-level keys.
        for key in [
            "\"tuple_mode\": \"disjoint\"",
            "\"pair_suite\":",
            "\"mcv\":",
            "\"advisory_only\":",
            "\"degenerate\":",
        ] {
            assert!(sa.contains(key), "sidecar missing {key}");
        }
    }

    // ----- degenerate + metadata parsing -----

    /// Degenerate (too short to form a triplet) is non-flagging and marked.
    #[test]
    fn degenerate_short_input() {
        for s in [vec![], vec![1u8], vec![1u8, 2]] {
            let r = analyze(&s, 4, Some(0.5));
            assert!(r.degenerate, "n={} must be degenerate", s.len());
            assert!(!r.flagged, "degenerate must not flag");
            assert!(!r.exit_failure(), "degenerate must not exit-fail");
        }
    }

    /// Metadata provenance copy-through parses the three optional fields and
    /// tolerates absence.
    #[test]
    fn metadata_parse() {
        let text = r#"{ "oe_id": "OE-7", "boundary": "primary", "timer_source": "tsc", "x": 1 }"#;
        let p = parse_metadata(text);
        assert_eq!(p.oe_id.as_deref(), Some("OE-7"));
        assert_eq!(p.boundary.as_deref(), Some("primary"));
        assert_eq!(p.timer_source.as_deref(), Some("tsc"));
        let empty = parse_metadata("{}");
        assert_eq!(empty, Provenance::default());
    }

    /// Advisory-only below 10M: a claim flag is computed but never exit-fails.
    #[test]
    fn advisory_below_precedent_minimum() {
        // Concentrated data: gate value ≈ 0.99, so a claim of 2.0 flags.
        let data = concentrated_symbols(20_000, 0x5555_5555_5555_5555);
        let r = analyze(&data, 4, Some(2.0));
        assert!(r.advisory_only, "n<10M must be advisory");
        assert!(r.flagged, "gate value < 2.0 should flag");
        assert!(!r.exit_failure(), "advisory flag must not exit-fail");
    }

    // ----- review-hardening oracles (evidence-integrity edges) -----

    /// `--claim` validation rejects the values that would subvert the gate:
    /// `NaN` (gate `< NaN` always false → any data passes) and `inf` (gate
    /// `< inf` always true → spurious flag), plus non-positive claims.
    #[test]
    fn validate_claim_rejects_non_finite_and_non_positive() {
        assert!(!validate_claim(f64::NAN));
        assert!(!validate_claim(f64::INFINITY));
        assert!(!validate_claim(f64::NEG_INFINITY));
        assert!(!validate_claim(0.0));
        assert!(!validate_claim(-1.0));
        assert!(validate_claim(0.5));
        assert!(validate_claim(4.0));
    }

    /// Defense-in-depth: even if a non-finite claim reaches `analyze`, it never
    /// flags (neither the always-false `NaN` nor the always-true `inf` path).
    #[test]
    fn non_finite_claim_never_flags() {
        let data = concentrated_symbols(20_000, 0x1234_5678_9abc_def0);
        for c in [f64::NAN, f64::INFINITY] {
            let r = analyze(&data, 4, Some(c));
            assert!(!r.flagged, "non-finite claim {c} must not flag");
            assert!(!r.exit_failure());
        }
    }

    /// Provenance parsing keeps a value containing escaped quotes/backslashes
    /// intact (previously truncated at the first `\"`).
    #[test]
    fn metadata_parse_handles_escaped_quotes() {
        let text = r#"{ "boundary": "rack \"A\" primary", "oe_id": "line\\1" }"#;
        let p = parse_metadata(text);
        assert_eq!(p.boundary.as_deref(), Some(r#"rack "A" primary"#));
        assert_eq!(p.oe_id.as_deref(), Some(r"line\1"));
    }

    /// A real acceptance FLAG (constant stream → 0 entropy) renders the sidecar
    /// with `degenerate:false`: the benign NaN proximity ratios must not poison
    /// the authoritative report degenerate flag.
    #[test]
    fn sidecar_degenerate_is_authoritative_not_poisoned_by_nan() {
        let data = vec![7u8; 20_000];
        let r = analyze(&data, 4, Some(0.5));
        assert!(r.flagged, "constant stream vs claim 0.5 must flag");
        assert!(!r.degenerate, "constant (n>=3, finite h) is not degenerate");
        assert!(
            !r.mcv.r2_plain.is_finite(),
            "constant stream yields a NaN r2_plain (the poison source)"
        );
        let json = render_sidecar(&r, "0", None, &Provenance::default());
        assert!(json.contains("\"flagged\": true"), "{json}");
        assert!(json.contains("\"degenerate\": false"), "{json}");
        assert!(json.contains("\"r2_plain\": null"), "{json}");
    }

    /// `write_sidecar` creates a missing sidecar directory and writes the file,
    /// so a run never silently produces no evidence artifact.
    #[test]
    fn sidecar_written_to_missing_dir() {
        let data = vec![7u8; 100];
        let r = analyze(&data, 4, None);
        let base = std::env::temp_dir().join(format!("oxicrypt-maxwell-sc-{}", std::process::id()));
        let dir = base.join("nested/independence");
        let _ = std::fs::remove_dir_all(&base);
        let path = write_sidecar(&r, "0", None, &Provenance::default(), &dir)
            .expect("write_sidecar must create the dir and write");
        assert!(path.exists(), "sidecar file must exist");
        assert!(path.ends_with(SIDECAR_FILE));
        let _ = std::fs::remove_dir_all(&base);
    }
}
