//! SP 800-90B §6.3.4 Compression (Maurer-style) min-entropy estimator
//! (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 compression estimator
//! (`cpp/non_iid/compression_test.h`) to within the pre-registered
//! 1.0e-6 bits/estimator parity bound (`docs/estimator-parity-tolerances.md`).
//! Like the rest of `oxicrypt-maxwell` it is **outside the cryptographic
//! boundary** — pure offline analysis tooling, `#![forbid(unsafe_code)]`, and
//! it produces no security parameters.
//!
//! # The compression estimator (SP 800-90B §6.3.4)
//!
//! The estimator runs on the **bitstring track** only: each symbol is
//! decomposed MSB-first into its `bits_per_symbol` bits (the same decomposition
//! as the MCV bitstring track, the collision estimator, and the EA tool's
//! `bsymbols`, `bsymbols[i*w+j] = (symbols[i] >> (w-1-j)) & 1`). The EA tool
//! calls `compression_test(data.bsymbols, data.blen, …)` for multi-bit data and
//! `compression_test(data.symbols, …)` for binary data — but for 1-bit data
//! `bsymbols == symbols`, so every dataset (including 1-bit data) carries one
//! compression reference value on the same binary computation.
//!
//! ## The computation (matched from `compression_test.h`)
//!
//! Over the binary sequence `b[0..len]`, with block width `b = 6`
//! ([`BLOCK_BITS`]), alphabet `1 << b = 64` ([`ALPH_SIZE`]), and training prefix
//! `d = 1000` ([`TRAINING_BLOCKS`]):
//!
//! 1. `num_blocks = len / b`. If `num_blocks <= d` the EA tool warns and returns
//!    `-1.0` (not enough data); this module returns
//!    [`CompressionEstimate::insufficient_data`] with `min_entropy = -1.0`, and
//!    the harness/CLI treats a negative result the way the EA tool does
//!    (skipped, not a failure). The EA datasets all have far more than `d`
//!    blocks.
//! 2. Build a dictionary of the last-seen block index over the first `d` blocks
//!    (1-based: `dict[block] = i + 1`).
//! 3. For each test block `i in d..num_blocks` (there are `v = num_blocks - d`
//!    of them): the per-block distance is `log2(i + 1 - dict[block])`; accumulate
//!    its sum into `X` and the sum of its square into `sigma`, then update
//!    `dict[block] = i + 1`.
//! 4. `X̄ = X / v`; `σ̂ = 0.5907 · sqrt( sigma/(v-1) − X̄² )`
//!    (`0.5907` is the EA tool's literal §6.3.4 constant [`SIGMA_SCALE`]).
//! 5. `X̄' = X̄ − Z · σ̂ / sqrt(v)` where `Z = Φ⁻¹(0.995) =
//!    2.5758293035489008` (the EA tool's `ZALPHA`, the same constant the MCV,
//!    APT, and collision estimators use — [`crate::Z_995`]).
//! 6. Solve `com_exp(p) = X̄'` for the most-likely-symbol probability
//!    `p ∈ [1/64, 1]` by the EA tool's bisection (`G`/`com_exp`,
//!    `relEpsilonEqual` convergence, the documented invariant breaks, at most
//!    [`ITERMAX`] iterations). The search runs only when
//!    `com_exp(1/64) > X̄'`; otherwise `p = -1.0`.
//! 7. If `p > 1/64`, `entEst = -log2(p) / b` ("Found p"); else `p = 1/64`,
//!    `entEst = 1.0` ("Could Not Find p").
//!
//! ## The `G` function and floating point
//!
//! `compression_test.h` evaluates `G` in `long double` (80-bit extended on
//! x86_64) with Kahan compensated summation. Rust has no `long double`, so this
//! module evaluates `G` in `f64`. The bisection's convergence test
//! (`relEpsilonEqual` with `RELEPSILON = f64::EPSILON`) is an `f64`-relative
//! comparison either way, so it bounds `pVal` to `X̄'` at `f64` precision
//! regardless of the accumulator width. Empirically the `f64` `G` differs from
//! the `long double` + Kahan `G` by < 1e-14 at the converged `p` on the short
//! datasets and the resulting `entEst` reproduces every EA v1.1.8 reference
//! value to < 1.3e-10 bits — far inside the 1.0e-6 parity bound. See the
//! `docs/estimator-parity-tolerances.md` rationale.
//!
//! # The 11-point reproduction
//!
//! All 11 EA-distribution datasets reproduce their EA tool v1.1.8 compression
//! min-entropy (the verbose "min entropy" line of the `selftest/*.res` files —
//! the controlling track per dataset: "Bitstring" for multi-bit data, "Literal"
//! for 1-bit data, which are the same binary computation) to within 1.0e-6 bits.
//! The reference values are recorded in [`crate::parity::REFERENCE_TABLE`] and
//! verified by `maxwell parity`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention; sub-8-bit
//! symbols are already masked into the low bits of each byte). `bits_per_symbol`
//! must be in `1..=8`; out-of-range widths are clamped (`0 -> 1`, `>8 -> 8`) so
//! callers cannot trigger out-of-range shifts.

use crate::Z_995;

/// Block width in bits (`b` in `compression_test.h`). The §6.3.4 compression
/// estimate parses the bitstring into 6-bit blocks.
pub const BLOCK_BITS: usize = 6;

/// Block alphabet size, `1 << BLOCK_BITS` (`alph_size` in `compression_test.h`).
pub const ALPH_SIZE: u32 = 1 << BLOCK_BITS;

/// Training-prefix length in blocks (`d` in `compression_test.h`). The first `d`
/// blocks seed the dictionary; the remaining `num_blocks - d` blocks are tested.
pub const TRAINING_BLOCKS: usize = 1000;

/// The §6.3.4 standard-deviation scale constant `c = 0.5907`
/// (`compression_test.h`: `sigma = 0.5907 * sqrt(...)`).
pub const SIGMA_SCALE: f64 = 0.5907;

/// Maximum bisection iterations (`ITERMAX` in `shared/utils.h`).
pub const ITERMAX: usize = 1076;

/// `f64`-relative convergence factor for the bisection's `relEpsilonEqual`
/// (`RELEPSILON = DBL_EPSILON` in `shared/utils.h`).
const RELEPSILON: f64 = f64::EPSILON;

/// Absolute-closeness floor for the bisection's `relEpsilonEqual`
/// (`ABSEPSILON = DBL_MIN` in `shared/utils.h` — the smallest positive normal
/// `f64`).
const ABSEPSILON: f64 = f64::MIN_POSITIVE;

/// Max-ULP slack for the bisection's `relEpsilonEqual` (the EA tool passes `4`).
const MAX_ULP: u64 = 4;

/// One compression min-entropy estimate over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompressionEstimate {
    /// Number of test blocks, `num_blocks - d` (the EA tool's `v`). `0` for the
    /// insufficient-data sentinel.
    pub v: u64,
    /// Sample mean of the per-block `log2` distances, `X / v` (the EA tool's
    /// `X̄`). `0.0` for the insufficient-data sentinel.
    pub x_bar: f64,
    /// Scaled sample standard deviation, `0.5907·sqrt(sigma/(v-1) − X̄²)` (the EA
    /// tool's `σ̂`). `0.0` for the insufficient-data sentinel.
    pub sigma_hat: f64,
    /// Lower 99% confidence bound on the mean, `X̄ − Z·σ̂/sqrt(v)` (the EA tool's
    /// `X̄'`). `0.0` for the insufficient-data sentinel.
    pub x_bar_prime: f64,
    /// Most-likely-symbol probability solved from `com_exp(p) = X̄'`, or `1/64`
    /// in the "Could Not Find p" edge case. `1/64` for the insufficient-data
    /// sentinel.
    pub p: f64,
    /// `−log2(p)/b` — the per-bit compression min-entropy estimate (the EA
    /// tool's returned `entEst`). `1.0` in the "Could Not Find p" edge case;
    /// `-1.0` for the insufficient-data sentinel (matching the EA tool's `-1.0`
    /// return).
    pub min_entropy: f64,
    /// `true` when a root `p > 1/64` was found; `false` in the "Could Not Find
    /// p" edge case and for the insufficient-data sentinel.
    pub found_p: bool,
}

impl CompressionEstimate {
    /// The EA tool's "not enough samples" return (`compression_test.h` prints a
    /// warning and returns `-1.0` when `num_blocks <= d`). Surfaced as a
    /// distinct sentinel so the harness/CLI can treat it the way the EA tool
    /// does — `min_entropy < 0` means "skipped", not "zero entropy".
    #[must_use]
    pub const fn insufficient_data() -> Self {
        Self {
            v: 0,
            x_bar: 0.0,
            sigma_hat: 0.0,
            x_bar_prime: 0.0,
            p: 1.0 / ALPH_SIZE as f64,
            min_entropy: -1.0,
            found_p: false,
        }
    }
}

/// Decompose `symbols` MSB-first into a binary sequence, matching the EA tool's
/// `bsymbols` construction (`(symbol >> (w-1-j)) & 1`). For `bits_per_symbol == 1`
/// the bytes are already the bit values (`0`/`1`), returned as-is.
///
/// Identical in behavior to the collision and Markov modules' decomposition;
/// kept local so each estimator module is self-contained.
fn to_bitstring(symbols: &[u8], bits_per_symbol: u8) -> Vec<u8> {
    if bits_per_symbol == 1 {
        return symbols.to_vec();
    }
    let mut bits: Vec<u8> =
        Vec::with_capacity(symbols.len().saturating_mul(bits_per_symbol as usize));
    for &s in symbols {
        // j = 0 .. bits_per_symbol-1, shifting by (bits-1) down to 0: MSB-first.
        let mut shift = bits_per_symbol;
        while shift > 0 {
            shift = shift.saturating_sub(1);
            bits.push((s >> shift) & 1);
        }
    }
    bits
}

/// `INCLOSEDINTERVAL(x, a, b)` from `shared/utils.h`: `true` iff `x` lies in the
/// closed interval bounded by `a` and `b`, regardless of which bound is larger.
fn in_closed_interval(x: f64, a: f64, b: f64) -> bool {
    if a > b {
        x >= b && x <= a
    } else {
        x >= a && x <= b
    }
}

/// `INOPENINTERVAL(x, a, b)` from `shared/utils.h`: `true` iff `x` lies strictly
/// inside the open interval bounded by `a` and `b`, regardless of order.
fn in_open_interval(x: f64, a: f64, b: f64) -> bool {
    if a > b {
        x > b && x < a
    } else {
        x > a && x < b
    }
}

/// `relEpsilonEqual(A, B, ABSEPSILON, RELEPSILON, 4)` from `shared/utils.h`:
/// a relative-closeness test that falls back to an absolute or ULP comparison
/// where the relative test would be nonsense. Transcribed exactly so the
/// bisection converges on the same iteration the EA tool does.
#[allow(
    // The bit-pattern ULP comparison reads each f64's IEEE-754 encoding via
    // to_bits (the safe analogue of the EA tool's memcpy); the values compared
    // are magnitudes (non-negative), so the unsigned subtraction below cannot
    // wrap on the path that reaches it (a >= b is established first).
    clippy::similar_names,
    // The `a == b` fast-path is a deliberate exact-equality short-circuit
    // (it also catches equal infinities) inside this closeness predicate.
    clippy::float_cmp
)]
fn rel_epsilon_equal(a_in: f64, b_in: f64) -> bool {
    let (mut a, mut b) = (a_in, b_in);
    // NaN is not equal to anything (including itself).
    if a.is_nan() || b.is_nan() {
        return false;
    }
    // Exact equality (also catches equal infinities).
    if a == b {
        return true;
    }
    // One is infinite but they are not equal -> not close.
    if a.is_infinite() || b.is_infinite() {
        return false;
    }

    let mut abs_a = a.abs();
    let mut abs_b = b.abs();
    // Ensure A is the value closest to 0 (smaller magnitude).
    if abs_a > abs_b {
        core::mem::swap(&mut a, &mut b);
        core::mem::swap(&mut abs_a, &mut abs_b);
    }

    let diff = (b - a).abs();

    // Is the relative test going to be nonsense (subnormal / overflow)?
    if abs_a < f64::MIN_POSITIVE
        || diff < f64::MIN_POSITIVE
        || diff.is_infinite()
        || abs_b * RELEPSILON < f64::MIN_POSITIVE
    {
        // Yes — use the absolute comparison.
        return diff <= ABSEPSILON;
    }
    // No — relative closeness is meaningful.
    if diff <= abs_b * RELEPSILON {
        return true;
    }

    // Not relatively close in the conventional sense; check the ULP distance.
    // Different signs can't be a few ULPs apart.
    if a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    // abs_a >= abs_b was normalized away above, so abs_b >= abs_a here, and
    // both are >= f64::MIN_POSITIVE (neither is zero). For IEEE-754 the bit
    // patterns of non-negative magnitudes are monotonic, so b_bits >= a_bits.
    let a_bits = abs_a.to_bits();
    let b_bits = abs_b.to_bits();
    b_bits.saturating_sub(a_bits) <= MAX_ULP
}

/// The §6.3.4 `G(z, d, num_blocks)` function from `compression_test.h`,
/// evaluated in `f64`.
///
/// The EA tool uses `long double` + Kahan summation here; this `f64` evaluation
/// reproduces every reference `entEst` to < 1.3e-10 bits (see the module-level
/// floating-point note). `underflowTruncate` matches the EA tool's early break
/// when a tail term underflows to `<= 0`.
#[allow(
    // The casts to f64 mirror the EA tool's own (double) casts; index variables
    // are bounded by num_blocks (a slice-derived length) and the 1.0e-6 parity
    // bound absorbs the rounding. The loop counters advance by 1 and the
    // saturating ops keep the arithmetic total.
    clippy::cast_precision_loss,
    clippy::similar_names
)]
fn g(z: f64, d: usize, num_blocks: usize) -> f64 {
    debug_assert!(d > 0);
    debug_assert!(num_blocks > d);

    let v = num_blocks.saturating_sub(d);

    // i = 2 .. d: accumulate A_{d+1} = sum_{i=2}^{d} log2(i) * B_i, with
    // B_term = (1 - z) and B_2 = B_term (B_1 is unused since a_1 = 0).
    let b_term = 1.0 - z;
    let mut bi = b_term; // B_2
    let mut ai = 0.0_f64; // running A
    let mut i = 2_usize;
    while i <= d {
        ai += (i as f64).log2() * bi;
        bi *= b_term;
        i = i.saturating_add(1);
    }
    let ad1 = ai; // A_{d+1}

    // i = d+1 .. num_blocks-1: extend A and accumulate the tail of firstSum.
    let mut first_sum = 0.0_f64;
    let mut underflow_truncate = false;
    let mut i = d.saturating_add(1);
    let upper = num_blocks.saturating_sub(1);
    while i <= upper {
        let a_i = (i as f64).log2() * bi;
        ai += a_i;

        // tail term (num_blocks - i) * a_i; break if it underflows to <= 0.
        let ai_scaled = (num_blocks.saturating_sub(i) as f64) * a_i;
        if ai_scaled > 0.0 {
            first_sum += ai_scaled;
        } else {
            underflow_truncate = true;
            break;
        }

        bi *= b_term;
        i = i.saturating_add(1);
    }

    // Finalize firstSum with the (num_blocks - d) * A_{d+1} term.
    first_sum += (num_blocks.saturating_sub(d) as f64) * ad1;

    // A_{num_blocks+1} (only when the tail loop ran to completion).
    if !underflow_truncate {
        ai += (num_blocks as f64).log2() * bi;
    }

    // 1/v * z * (z*firstSum + (A_num_blocks - A_{d+1}))
    (1.0 / v as f64) * z * (z * first_sum + (ai - ad1))
}

/// `com_exp(p, alph_size, d, num_blocks)` from `compression_test.h`:
/// `G(p) + (alph_size - 1) * G(q)` with `q = (1-p)/(alph_size-1)`.
#[allow(clippy::cast_precision_loss)]
fn com_exp(p: f64, alph_size: u32, d: usize, num_blocks: usize) -> f64 {
    let alph = f64::from(alph_size);
    let q = (1.0 - p) / (alph - 1.0);
    g(p, d, num_blocks) + (alph - 1.0) * g(q, d, num_blocks)
}

/// Compute the SP 800-90B §6.3.4 compression min-entropy estimate for the
/// bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The function is **deterministic**: the same
/// `(symbols, bits_per_symbol)` always yields a bit-identical
/// [`CompressionEstimate`].
///
/// # Behavior on degenerate input
///
/// The EA tool returns `-1.0` (a warning, not an estimate) when there are not
/// more than `d = 1000` blocks. This function returns
/// [`CompressionEstimate::insufficient_data`] (`min_entropy = -1.0`) in that
/// case. The EA datasets all have far more than `d` blocks.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn compression(symbols: &[u8], bits_per_symbol: u8) -> CompressionEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    compression_bits(&bits)
}

/// Run the §6.3.4 compression estimate over an already-decomposed binary
/// sequence (`0`/`1` values). Split out so tests can drive the estimate
/// directly.
#[allow(
    // Counts are bounded by the slice length (fits usize); the casts to f64 are
    // the EA tool's own (double) casts and the 1.0e-6 parity bound absorbs the
    // rounding. Block indexing uses .get() so the access is total; the shift is
    // by < BLOCK_BITS so it cannot overflow a u32.
    clippy::cast_precision_loss,
    clippy::similar_names,
    // `len / BLOCK_BITS` is the intended whole-block count (SP 800-90B parses
    // the data into fixed b-bit blocks, discarding any partial trailing block).
    clippy::integer_division,
    // Faithful single-function transcription of compression_test.h; splitting
    // it would obscure the 1:1 correspondence with the EA reference.
    clippy::too_many_lines,
    // `last_p == p` is the EA tool's exact-equality bisection cycle-detection
    // (`if(lastP == p)`); an exact compare is the intended behavior.
    clippy::float_cmp
)]
fn compression_bits(bits: &[u8]) -> CompressionEstimate {
    let len = bits.len();
    let d = TRAINING_BLOCKS;
    let num_blocks = len / BLOCK_BITS;

    // Not enough data: the EA tool warns and returns -1.0.
    if num_blocks <= d {
        return CompressionEstimate::insufficient_data();
    }

    let v = num_blocks.saturating_sub(d);

    // Pack the j-th block MSB-first into a 6-bit value, exactly as
    // compression_test.h does: block |= (data[i*b + j] & 1) << (b - j - 1).
    let block_at = |block_index: usize| -> usize {
        let base = block_index.saturating_mul(BLOCK_BITS);
        let mut block = 0_usize;
        let mut j = 0_usize;
        while j < BLOCK_BITS {
            let bit = bits.get(base.saturating_add(j)).copied().unwrap_or(0) & 1;
            // shift = BLOCK_BITS - j - 1, in 0..BLOCK_BITS.
            let shift = BLOCK_BITS.saturating_sub(j).saturating_sub(1);
            block |= (bit as usize) << shift;
            j = j.saturating_add(1);
        }
        block
    };

    // Dictionary of last-seen 1-based block index, sized to the block alphabet.
    let mut dict = vec![0_usize; ALPH_SIZE as usize];

    // Training: first d blocks seed the dictionary (dict[block] = i + 1).
    let mut i = 0_usize;
    while i < d {
        let block = block_at(i);
        if let Some(slot) = dict.get_mut(block) {
            *slot = i.saturating_add(1);
        }
        i = i.saturating_add(1);
    }

    // Test: accumulate the per-block log2 distance and its square.
    let mut x_sum = 0.0_f64;
    let mut sigma_sum = 0.0_f64;
    let mut i = d;
    while i < num_blocks {
        let block = block_at(i);
        let last = dict.get(block).copied().unwrap_or(0);
        // distance = i + 1 - dict[block]; dict entries are <= i so this is >= 1.
        let distance = i.saturating_add(1).saturating_sub(last);
        let dist_log2 = (distance as f64).log2();
        x_sum += dist_log2;
        sigma_sum += dist_log2 * dist_log2;
        if let Some(slot) = dict.get_mut(block) {
            *slot = i.saturating_add(1);
        }
        i = i.saturating_add(1);
    }

    let v_f = v as f64;

    // X̄ = X / v   (compression_test.h: `X /= v`).
    let x_bar = x_sum / v_f;

    // σ̂ = 0.5907 * sqrt( sigma/(v-1) − X̄² )
    //   (compression_test.h: `sigma = 0.5907 * sqrt(sigma/(v-1.0) - X*X)`).
    let sigma_hat = SIGMA_SCALE * (sigma_sum / (v_f - 1.0) - x_bar * x_bar).sqrt();

    // X̄' = X̄ − Z·σ̂/sqrt(v)
    //   (compression_test.h: `X -= ZALPHA * sigma/sqrt(v)`).
    let x_bar_prime = x_bar - Z_995 * sigma_hat / v_f.sqrt();

    // Bisection for p, matching compression_test.h step-by-step.
    let ldomain = 1.0 / f64::from(ALPH_SIZE);
    let hdomain = 1.0;
    let mut p: f64;

    if com_exp(ldomain, ALPH_SIZE, d, num_blocks) > x_bar_prime {
        let mut lbound = ldomain;
        let mut hbound = hdomain;
        let mut lvalue = f64::INFINITY;
        let mut hvalue = f64::NEG_INFINITY;

        // The bounds are in [0,1]; underflows (not overflows) are the concern.
        p = lbound.midpoint(hbound);
        let mut p_val = com_exp(p, ALPH_SIZE, d, num_blocks);

        let mut iter = 0_usize;
        while iter < ITERMAX {
            // Reached "equality"?
            if rel_epsilon_equal(p_val, x_bar_prime) {
                break;
            }

            // Update bounds based on the found pVal.
            if x_bar_prime < p_val {
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

            // Invariant: bounds must stay inside the domain, else search failure
            // -> "full entropy" (p = ldomain, step #8).
            if !(in_closed_interval(lbound, ldomain, hdomain)
                && in_closed_interval(hbound, ldomain, hdomain))
            {
                p = ldomain;
                break;
            }

            // Invariant: the target must lie in [lvalue, hvalue], else search
            // failure -> "full entropy" (p = ldomain).
            if !in_closed_interval(x_bar_prime, lvalue, hvalue) {
                p = ldomain;
                break;
            }

            // Update p.
            let last_p = p;
            p = lbound.midpoint(hbound);

            // Invariant: p must lie strictly inside (lbound, hbound).
            if !in_open_interval(p, lbound, hbound) {
                p = hbound;
                break;
            }

            // Cycle detection (the EA tool's `if(lastP == p)`).
            if last_p == p {
                p = hbound;
                break;
            }

            p_val = com_exp(p, ALPH_SIZE, d, num_blocks);

            // Invariant: pVal must stay in [lvalue, hvalue] (loose monotonicity).
            if !in_closed_interval(p_val, lvalue, hvalue) {
                p = hbound;
                break;
            }

            iter = iter.saturating_add(1);
        }
    } else {
        p = -1.0;
    }

    // entEst = -log2(p)/b if p > 1/alph_size, else p = 1/alph_size, entEst = 1.0.
    if p > ldomain {
        CompressionEstimate {
            v: v as u64,
            x_bar,
            sigma_hat,
            x_bar_prime,
            p,
            min_entropy: -p.log2() / BLOCK_BITS as f64,
            found_p: true,
        }
    } else {
        CompressionEstimate {
            v: v as u64,
            x_bar,
            sigma_hat,
            x_bar_prime,
            p: ldomain,
            min_entropy: 1.0,
            found_p: false,
        }
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact reference intermediates, use unwrap/panic for fatal
    // setup invariants, and print skip notices for absent datasets — all fine in
    // test code.
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::parity::{REFERENCE_TABLE, resolve_datasets_dir};

    /// Cross-tool parity bound — the f64 `G` reproduces the long-double EA `G`
    /// only to floating-point closeness, so the anchor intermediates are checked
    /// at the same 1e-6 parity tolerance rather than the tighter exact-anchor
    /// epsilon the integer-counting estimators use.
    const PARITY_EPS: f64 = 1.0e-6;

    /// Build the MSB-first bitstring of a dataset and run the estimate, so the
    /// anchors are checked against the *real* dataset bits when present.
    fn compression_of_file(name: &str) -> Option<CompressionEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(compression(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor (from the EA `selftest/rand8_short.res`, verbose 3,
    /// "Bitstring Compression Estimate"):
    /// X-bar = 5.212412765159554, sigma-hat = 1.0221918650488746,
    /// X-bar' = 5.1887036615688391, Found p, p = 0.047508507395589983,
    /// min entropy = 0.73261171806065617.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = compression_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert!(
            (est.x_bar - 5.212_412_765_159_554).abs() < PARITY_EPS,
            "x_bar={}",
            est.x_bar
        );
        assert!(
            (est.sigma_hat - 1.022_191_865_048_874_6).abs() < PARITY_EPS,
            "sigma_hat={}",
            est.sigma_hat
        );
        assert!(
            (est.x_bar_prime - 5.188_703_661_568_839).abs() < PARITY_EPS,
            "x_bar_prime={}",
            est.x_bar_prime
        );
        assert!(est.found_p, "rand8_short must find p");
        assert!(
            (est.p - 0.047_508_507_395_589_98).abs() < PARITY_EPS,
            "p={}",
            est.p
        );
        assert!(
            (est.min_entropy - 0.732_611_718_060_656_2).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// biased-random-bits anchor (1-bit data; EA labels it "Literal" because
    /// `bsymbols == symbols` for binary): min entropy = 0.017766579116465193.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = compression_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert!(est.found_p, "biased-random-bits must find p");
        assert!(
            (est.min_entropy - 0.017_766_579_116_465_193).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        // Needs more than d=1000 blocks => more than 6000 bits. Use a pseudo
        // pattern long enough to exercise the dictionary and the bisection.
        let buf: Vec<u8> = (0..20_000u32).map(|i| (i % 19) as u8).collect();
        let a = compression(&buf, 8);
        let b = compression(&buf, 8);
        assert_eq!(
            a, b,
            "CompressionEstimate must be bit-identical across runs"
        );
    }

    /// Too-short input: not more than d=1000 blocks -> insufficient-data
    /// sentinel (min_entropy = -1.0), no panic, no NaN.
    #[test]
    fn too_short_input_is_insufficient_data() {
        // 6000 bits = exactly 1000 blocks = d, which is NOT > d, so insufficient.
        for n_bits in [0usize, 6, 6000] {
            let buf = vec![0u8; n_bits];
            let est = compression(&buf, 1);
            assert_eq!(est.v, 0, "v should be 0 for insufficient data");
            assert_eq!(
                est.min_entropy, -1.0,
                "insufficient data must return -1.0 (EA warning sentinel)"
            );
            assert!(!est.found_p);
            assert!(est.min_entropy.is_finite());
        }
    }

    /// All-zero bits: every test block hashes to the same dictionary slot, so
    /// each distance is 1 (the previous block index), `log2(1) = 0`, giving
    /// X̄ = 0, σ̂ = 0, X̄' = 0. The bisection guard `com_exp(1/64) > 0` holds,
    /// the search drives p toward the high end (low entropy). The estimate must
    /// be finite, non-negative, and well below 1 bit (a constant stream has
    /// ~0 entropy). This exercises the full Found-p path on a degenerate input
    /// without panicking.
    #[test]
    fn all_zeros_low_entropy_no_panic() {
        // 2000 blocks * 6 bits = 12000 bits > d.
        let buf = vec![0u8; 12_000];
        let est = compression(&buf, 1);
        assert!(est.min_entropy.is_finite(), "min_entropy must be finite");
        assert!(
            est.x_bar.abs() < 1.0e-12,
            "X-bar should be 0, got {}",
            est.x_bar
        );
        assert!(
            est.min_entropy >= 0.0 && est.min_entropy < 1.0,
            "all-zero compression min-entropy should be in [0,1), got {}",
            est.min_entropy
        );
    }
}
