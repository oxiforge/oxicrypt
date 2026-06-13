//! SP 800-90B §6.3.2 Collision min-entropy estimator (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 collision estimator
//! (`cpp/non_iid/collision_test.h`) bit-for-bit, to within the pre-registered
//! 1.0e-6 bits/estimator parity bound (`docs/estimator-parity-tolerances.md`).
//! Like the rest of `oxicrypt-maxwell` it is **outside the cryptographic
//! boundary** — pure offline analysis tooling, `#![forbid(unsafe_code)]`, and
//! it produces no security parameters.
//!
//! # The collision estimator (SP 800-90B §6.3.2)
//!
//! The estimator runs on the **bitstring track** only: each symbol is
//! decomposed MSB-first into its `bits_per_symbol` bits (the same decomposition
//! as the MCV bitstring track and the EA tool's `bsymbols`,
//! `bsymbols[i*w+j] = (symbols[i] >> (w-1-j)) & 1`), and the binary sequence of
//! length `L * bits_per_symbol` is walked counting *collision times*:
//!
//! 1. From the current index `i`, the next collision time is
//!    - `t = 2` if the next two bits are equal (`b[i] == b[i+1]`: `00` or `11`),
//!    - else `t = 3` (the next bit differs, so a value must repeat within three
//!      steps for a binary alphabet) — but only if a third bit exists
//!      (`i < len-2`); otherwise the trailing partial window is discarded and
//!      the walk stops.
//!
//!    Each complete event increments `v` (the event count), accumulates `t²`
//!    into the sum-of-squares, and advances `i` by `t`. After the loop, `i`
//!    equals `Sum t_i` (the total bits consumed by complete events).
//! 2. `X̄ = Sum t_i / v`.
//! 3. `σ̂ = sqrt( (Σ t_i² − Sum t_i · X̄) / (v − 1) )` — the sample standard
//!    deviation, in the EA tool's algebraically-rearranged form.
//! 4. `X̄' = X̄ − Z · σ̂ / sqrt(v)`, then clamped to a floor of `2.0` (the
//!    smallest meaningful collision time), where `Z = Φ⁻¹(0.995) =
//!    2.5758293035489008` (the EA tool's `ZALPHA`, the same constant the MCV and
//!    APT estimators use).
//! 5. Solve the §6.3.2 expected-collision-time equation `E[t](p) = X̄'` for the
//!    most-likely-symbol probability `p ∈ [0.5, 1]`.
//!
//! ## The solver — Uyen Dinh's quadratic (matched from `collision_test.h`)
//!
//! The EA tool does **not** root-find the full §6.3.2 expression. Per the
//! comment in `collision_test.h`, Uyen Dinh observed that with the simpler `F`
//! function the entire §6.3.2 step-7 expression reduces to the quadratic
//!
//! ```text
//! X̄' = −2p² + 2p + 2
//! ```
//!
//! whose only root in `[0.5, 1]` is the `+` branch of the quadratic formula:
//!
//! ```text
//! p = 0.5 + sqrt(1.25 − 0.5 · X̄')
//! ```
//!
//! This module matches that closed form exactly (no numerical root-find), which
//! is why every reference value reproduces to floating-point noise.
//!
//! ## The edge case — `Could Not Find p`
//!
//! The discriminant `1.25 − 0.5·X̄'` is non-negative iff `X̄' ≤ 2.5`. The EA
//! tool branches on `X̄' < 2.5`:
//!
//! - `X̄' < 2.5` → "Found p": `p = 0.5 + sqrt(1.25 − 0.5·X̄')`,
//!   `min_entropy = −log2(p)`.
//! - `X̄' ≥ 2.5` → the roots become complex (data looks at-or-above uniform);
//!   the EA tool prints *"Could Not Find p. Proceeding with the lower bound for
//!   p."*, sets `p = 0.5` and `min_entropy = 1.0`.
//!
//! This edge case is reproduced exactly. The `normal` reference dataset is the
//! canonical example: its `X̄' = 2.5224700384317478 ≥ 2.5`, so collision
//! min-entropy is `1.0`.
//!
//! # The 11-point reproduction
//!
//! All 11 EA-distribution datasets reproduce their EA tool v1.1.8 *bitstring*
//! collision min-entropy to within 1.0e-6 bits (observed delta 0.0 on every
//! dataset, including the `normal` edge case). The reference values are recorded
//! in [`crate::parity::REFERENCE_TABLE`] and verified by `maxwell parity`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention; sub-8-bit
//! symbols are already masked into the low bits of each byte). `bits_per_symbol`
//! must be in `1..=8`; out-of-range widths are clamped (`0 -> 1`, `>8 -> 8`) so
//! callers cannot trigger out-of-range shifts.

use crate::Z_995;

/// One collision min-entropy estimate over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CollisionEstimate {
    /// Number of complete collision events (the EA tool's `v`).
    pub v: u64,
    /// Total bits consumed by complete events (the EA tool's `Sum t_i`, i.e. the
    /// final walk index `i`).
    pub sum_t: u64,
    /// Sample mean of the collision times, `Sum t_i / v` (the EA tool's `X̄`).
    pub x_bar: f64,
    /// Sample standard deviation of the collision times (the EA tool's `σ̂`).
    pub sigma_hat: f64,
    /// Lower 99% confidence bound on the mean, clamped to a floor of `2.0`
    /// (the EA tool's `X̄'`).
    pub x_bar_prime: f64,
    /// Most-likely-symbol probability solved from `E[t](p) = X̄'` (the `+`
    /// branch of the reduced quadratic), or `0.5` in the edge case.
    pub p: f64,
    /// `−log2(p)` — the collision min-entropy estimate in bits. `1.0` in the
    /// edge case.
    pub min_entropy: f64,
    /// `true` when a root `p ∈ (0.5, 1]` was found (`X̄' < 2.5`); `false` in the
    /// "Could Not Find p" edge case (`X̄' ≥ 2.5`).
    pub found_p: bool,
}

/// `X̄' < 2.5` is the EA tool's "Found p" / "Could Not Find p" boundary: the
/// reduced quadratic's discriminant `1.25 − 0.5·X̄'` is non-negative iff
/// `X̄' ≤ 2.5`, and `collision_test.h` branches strictly on `X̄' < 2.5`.
const X_BAR_PRIME_ROOT_BOUND: f64 = 2.5;

/// The EA tool floors `X̄'` at `2.0` — the smallest meaningful collision time
/// for a binary sequence (a collision takes at least two bits).
const X_BAR_PRIME_FLOOR: f64 = 2.0;

/// Decompose `symbols` MSB-first into a binary sequence, matching the EA tool's
/// `bsymbols` construction (`(symbol >> (w-1-j)) & 1`). For `bits_per_symbol == 1`
/// the bytes are already the bit values (`0`/`1`), returned as-is.
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

/// Compute the SP 800-90B §6.3.2 collision min-entropy estimate for the
/// bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The function is **deterministic**: the same
/// `(symbols, bits_per_symbol)` always yields a bit-identical
/// [`CollisionEstimate`].
///
/// # Behavior on degenerate input
///
/// The EA tool's collision walk assumes enough data to form at least one
/// complete event and two events for the sample variance (`v - 1` in the
/// denominator). Inputs too short to do so are not part of the parity contract
/// and never arise for the EA datasets (each has ≥ 1e6 bits). For robustness
/// this implementation returns a conservative sentinel rather than dividing by
/// zero or `NaN`-ing:
///
/// - **`v == 0`** (fewer than two bits, no complete event): returns
///   `min_entropy = 1.0` with `found_p = false` and `p = 0.5` — the same
///   conservative "no usable estimate" lower bound the EA tool falls back to in
///   its edge case. `x_bar`/`sigma_hat`/`x_bar_prime` are `0.0`.
/// - **`v == 1`** (exactly one event): the sample variance divides by `v-1 == 0`.
///   `σ̂` is taken as `0.0`, so `X̄' = X̄` (floored at 2.0) and the normal
///   solver path runs.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn collision(symbols: &[u8], bits_per_symbol: u8) -> CollisionEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    collision_bits(&bits)
}

/// Run the collision walk + estimate over an already-decomposed binary sequence
/// (`0`/`1` values). Split out so tests can drive the walk directly.
#[allow(
    // The arithmetic here is bounded: `len` is a slice length (fits usize, and
    // u64 on supported targets); `i` only ever advances by 2 or 3 and never
    // exceeds `len`; `t*t` is at most 9. The walk cannot overflow on any input
    // a real dataset produces, and the saturating ops below make it total.
    clippy::cast_precision_loss
)]
fn collision_bits(bits: &[u8]) -> CollisionEstimate {
    let len = bits.len();

    let mut i: usize = 0;
    let mut v: u64 = 0;
    // Sum of t_i² accumulated in f64, exactly as the EA tool accumulates `s`.
    let mut sum_sq: f64 = 0.0;

    // Walk: match collision_test.h's loop exactly, including how it discards the
    // final partial window (the `else if (i < len-2)` guard, then `break`).
    // `len - 1` and `len - 2` are computed without underflow via saturating ops.
    while len > 1 && i < len.saturating_sub(1) {
        // i < len-1 guarantees i and i+1 are in bounds; .get() makes that total
        // without panicking. The pair always resolves to Some on a valid walk.
        let (Some(&b0), Some(&b1)) = (bits.get(i), bits.get(i.saturating_add(1))) else {
            break; // unreachable on a valid walk; fail closed rather than panic.
        };
        let t: usize = if b0 == b1 {
            2 // "00" or "11" — collision at the next bit.
        } else if i < len.saturating_sub(2) {
            3 // next bit differs; a binary value must repeat within three steps.
        } else {
            break; // trailing partial window: discard, end the walk.
        };
        v = v.saturating_add(1);
        // t is 2 or 3, so t*t is 4 or 9 — exact in f64.
        sum_sq += (t.saturating_mul(t)) as f64;
        i = i.saturating_add(t);
    }

    let sum_t = i as u64;

    // v == 0: no complete event. Mirror the EA tool's "no usable estimate"
    // fallback (p = 0.5, H = 1.0) rather than dividing by zero.
    if v == 0 {
        return CollisionEstimate {
            v: 0,
            sum_t,
            x_bar: 0.0,
            sigma_hat: 0.0,
            x_bar_prime: 0.0,
            p: 0.5,
            min_entropy: 1.0,
            found_p: false,
        };
    }

    let v_f = v as f64;
    let sum_t_f = sum_t as f64;

    // X̄ = Sum t_i / v   (collision_test.h: `X = i / (double)v`).
    let x_bar = sum_t_f / v_f;

    // σ̂ = sqrt( (Σ t_i² − Sum_t · X̄) / (v − 1) )
    //   (collision_test.h: `s = sqrt((s - (i*X)) / (v-1))`).
    // For v == 1 the denominator is 0; take σ̂ = 0 (no spread from one sample).
    let sigma_hat = if v <= 1 {
        0.0
    } else {
        let denom = v.saturating_sub(1) as f64;
        ((sum_sq - sum_t_f * x_bar) / denom).sqrt()
    };

    // X̄' = X̄ − Z·σ̂/sqrt(v), then floored at 2.0
    //   (collision_test.h: `X -= ZALPHA * s/sqrt(v); if(X < 2.0) X = 2.0;`).
    let x_bar_prime = (x_bar - Z_995 * sigma_hat / v_f.sqrt()).max(X_BAR_PRIME_FLOOR);

    // Solve E[t](p) = X̄' via the reduced quadratic, matching collision_test.h:
    //   X̄' < 2.5 → p = 0.5 + sqrt(1.25 − 0.5·X̄'), H = −log2(p)  ("Found p")
    //   X̄' ≥ 2.5 → p = 0.5, H = 1.0                              ("Could Not Find p")
    if x_bar_prime < X_BAR_PRIME_ROOT_BOUND {
        let p = 0.5 + (1.25 - 0.5 * x_bar_prime).sqrt();
        CollisionEstimate {
            v,
            sum_t,
            x_bar,
            sigma_hat,
            x_bar_prime,
            p,
            min_entropy: -p.log2(),
            found_p: true,
        }
    } else {
        CollisionEstimate {
            v,
            sum_t,
            x_bar,
            sigma_hat,
            x_bar_prime,
            p: 0.5,
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

    /// Tolerance for the hand-verified intermediates / min-entropy (tighter than
    /// the 1e-6 parity bound — this is exact reproduction of the EA `.res`
    /// anchors, not cross-tool parity).
    const ANCHOR_EPS: f64 = 1.0e-9;

    /// Build the MSB-first bitstring of an 8-bit dataset and run the walk, so the
    /// rand8 anchor is checked against the *real* dataset bits when present.
    fn collision_of_file(name: &str) -> Option<CollisionEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(collision(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor (from the EA `.res` file): v=32005, Sum t_i=79999,
    /// X̄=2.4995781909076706, σ̂=0.50000763353681899, X̄'=2.4923789816296962,
    /// p=0.56172932192363623, minH=0.83205298221524804.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = collision_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.v, 32005, "v");
        assert_eq!(est.sum_t, 79999, "sum_t");
        assert!(
            (est.x_bar - 2.499_578_190_907_670_6).abs() < ANCHOR_EPS,
            "x_bar={}",
            est.x_bar
        );
        assert!(
            (est.sigma_hat - 0.500_007_633_536_819).abs() < ANCHOR_EPS,
            "sigma_hat={}",
            est.sigma_hat
        );
        assert!(
            (est.x_bar_prime - 2.492_378_981_629_696).abs() < ANCHOR_EPS,
            "x_bar_prime={}",
            est.x_bar_prime
        );
        assert!(
            (est.p - 0.561_729_321_923_636_2).abs() < ANCHOR_EPS,
            "p={}",
            est.p
        );
        assert!(est.found_p, "rand8_short must find p");
        assert!(
            (est.min_entropy - 0.832_052_982_215_248).abs() < ANCHOR_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// `normal` edge case (from the EA `.res` file): v=3170586, Sum t_i=7999999,
    /// X̄'=2.5224700384317478 ≥ 2.5 → "Could Not Find p" → p=0.5, minH=1.0.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn normal_edge_case_could_not_find_p() {
        let Some(est) = collision_of_file("normal") else {
            eprintln!("normal.bin absent — skipping edge-case test");
            return;
        };
        assert_eq!(est.v, 3_170_586, "v");
        assert_eq!(est.sum_t, 7_999_999, "sum_t");
        assert!(
            (est.x_bar_prime - 2.522_470_038_431_747_8).abs() < ANCHOR_EPS,
            "x_bar_prime={}",
            est.x_bar_prime
        );
        assert!(!est.found_p, "normal must NOT find p (edge case)");
        assert_eq!(est.p, 0.5, "edge-case p must be exactly 0.5");
        assert_eq!(
            est.min_entropy, 1.0,
            "edge-case min_entropy must be exactly 1.0"
        );
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..2000u32).map(|i| (i % 19) as u8).collect();
        let a = collision(&buf, 8);
        let b = collision(&buf, 8);
        assert_eq!(a, b, "CollisionEstimate must be bit-identical across runs");
    }

    /// A perfectly alternating bit sequence (`0101…`) never produces a `t == 2`
    /// event: every adjacent pair differs, so every event is `t == 3`. This
    /// exercises the `else if (i < len-2)` branch and the trailing-window
    /// discard.
    #[test]
    fn alternating_bits_use_t3_branch() {
        // 1-bit symbols: bytes are already 0/1. 0,1,0,1,... length 12.
        let buf: Vec<u8> = (0..12u32).map(|i| (i % 2) as u8).collect();
        let est = collision(&buf, 1);
        // Walk from i=0: pairs always differ -> t=3 each. i: 0->3->6->9.
        // At i=9: i<len-1 (9<11) true, bits[9]!=bits[10] -> need i<len-2 (9<10) true -> t=3, i=12.
        // At i=12: 12 < 11 false -> stop. So events at i=0,3,6,9 => v=4, sum_t=12.
        assert_eq!(est.v, 4, "v");
        assert_eq!(est.sum_t, 12, "sum_t");
    }

    /// Empty / too-short input: no complete event -> conservative fallback
    /// (p=0.5, H=1.0, found_p=false), no panic, no NaN.
    #[test]
    fn too_short_input_is_sane() {
        for buf in [&[][..], &[0u8][..], &[1u8][..]] {
            let est = collision(buf, 1);
            assert_eq!(est.v, 0, "v");
            assert!(!est.found_p);
            assert_eq!(est.p, 0.5);
            assert_eq!(est.min_entropy, 1.0);
            assert!(est.min_entropy.is_finite());
        }
    }
}
