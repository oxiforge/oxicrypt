//! SP 800-90B §6.3.3 Markov min-entropy estimator (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 Markov estimator (`cpp/non_iid/markov_test.h`)
//! bit-for-bit, to within the pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). Like the rest of `oxicrypt-maxwell`
//! it is **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The Markov estimator (SP 800-90B §6.3.3)
//!
//! The EA tool's `markov_test` is **binary only**: it assumes a bit string and
//! models it as a first-order Markov chain over the alphabet `{0, 1}`, then
//! bounds the min-entropy of the most-likely length-128 path. It runs on the
//! **bitstring track** — `markov_test(data.bsymbols, data.blen, …)` in
//! `non_iid_main.cpp` — exactly like the §6.3.2 collision estimator. For 1-bit
//! datasets `data.bsymbols == data.symbols`, so the value the EA tool labels
//! "Literal" for binary data and "Bitstring" for multi-bit data is in both cases
//! the same binary Markov computation. Therefore every dataset (including 1-bit
//! data) carries exactly one Markov reference value, on the MSB-first bit
//! decomposition — the same decomposition the MCV bitstring track and the
//! collision estimator use (`bsymbols[i*w+j] = (symbols[i] >> (w-1-j)) & 1`).
//!
//! ## The computation (matched from `markov_test.h`)
//!
//! Over the binary sequence `b[0..len]` (`len = L * bits_per_symbol`):
//!
//! 1. Count, across the `len-1` adjacent pairs `b[i], b[i+1]`:
//!    - `C_0` — number of `0` bits in `b[0..len-1]`,
//!    - `C_00` — number of `00` transitions, `C_10` — number of `10`
//!      transitions.
//!    - `C_1 = (len-1) - C_0` is the number of `1` bits in `b[0..len-1]`.
//! 2. Transition probabilities (the EA tool uses the identity
//!    `P_X1 = 1 - P_X0`; a zero denominator yields both `0.0`):
//!    `P_00 = C_00/C_0`, `P_01 = 1 - P_00`, `P_10 = C_10/C_1`,
//!    `P_11 = 1 - P_10`.
//! 3. The last bit is then folded into `C_0` so it counts `0` bits over the
//!    full `b[0..len]`, and the unconditional probabilities are
//!    `P_0 = C_0/len`, `P_1 = 1 - P_0`.
//! 4. Six candidate min-entropies are formed for the six structurally-distinct
//!    most-likely length-128 paths, each guarded by `> 0.0` on the
//!    probabilities it uses (matching the EA tool's guards exactly — a guarded
//!    term that is skipped does not lower `H_min`):
//!
//!    | Path        | Expression                                   |
//!    |-------------|----------------------------------------------|
//!    | `00…0`      | `−log2(P_0) − 127·log2(P_00)`                 |
//!    | `0101…01`   | `−log2(P_0) − 64·log2(P_01) − 63·log2(P_10)`  |
//!    | `011…1`     | `−log2(P_0) − log2(P_01) − 126·log2(P_11)`    |
//!    | `100…0`     | `−log2(P_1) − log2(P_10) − 126·log2(P_00)`    |
//!    | `1010…10`   | `−log2(P_1) − 64·log2(P_10) − 63·log2(P_01)`  |
//!    | `11…1`      | `−log2(P_1) − 127·log2(P_11)`                 |
//!
//!    `H_min` starts at `128.0` and is reduced to the minimum candidate.
//! 5. The estimate is `entEst = min(H_min / 128.0, 1.0)` — per-bit min-entropy,
//!    capped at `1.0`.
//!
//! ## Computation-order note
//!
//! `markov_test.h` initializes `H_min = 128.0` and walks the six candidates in
//! the table order above, keeping the running minimum (`if(tmp < H_min) …`).
//! This module evaluates the same six candidates and takes the same minimum;
//! the 1.0e-6 tolerance absorbs any ordering-of-`fmin` difference (none was
//! observed — every reference value reproduces to floating-point noise).
//!
//! # The 11-point reproduction
//!
//! All 11 EA-distribution datasets reproduce their EA tool v1.1.8 Markov
//! min-entropy (the verbose "min entropy" line of the `selftest/*.res` files) to
//! within 1.0e-6 bits. The reference values are recorded in
//! [`crate::parity::REFERENCE_TABLE`] and verified by `maxwell parity`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention; sub-8-bit
//! symbols are already masked into the low bits of each byte). `bits_per_symbol`
//! must be in `1..=8`; out-of-range widths are clamped (`0 -> 1`, `>8 -> 8`) so
//! callers cannot trigger out-of-range shifts.

/// One Markov min-entropy estimate over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarkovEstimate {
    /// Unconditional probability of a `0` bit, `C_0 / len` (the EA tool's `P_0`).
    pub p_0: f64,
    /// Unconditional probability of a `1` bit, `1 - P_0` (the EA tool's `P_1`).
    pub p_1: f64,
    /// Transition probability `P(0 -> 0)` (`C_00 / C_0`, or `0.0` if `C_0 == 0`).
    pub p_00: f64,
    /// Transition probability `P(0 -> 1)`, `1 - P_00` (or `0.0` if `C_0 == 0`).
    pub p_01: f64,
    /// Transition probability `P(1 -> 0)` (`C_10 / C_1`, or `0.0` if `C_1 == 0`).
    pub p_10: f64,
    /// Transition probability `P(1 -> 1)`, `1 - P_10` (or `0.0` if `C_1 == 0`).
    pub p_11: f64,
    /// Minimum candidate path entropy over the six length-128 paths (the EA
    /// tool's `H_min`); `128.0` if no candidate was eligible.
    pub h_min: f64,
    /// `min(H_min / 128.0, 1.0)` — the per-bit Markov min-entropy estimate in
    /// bits (the EA tool's returned `entEst`).
    pub min_entropy: f64,
}

/// Path length the §6.3.3 estimate bounds: the EA tool models the most-likely
/// 128-bit sequence, so `H_min` is normalized by `128.0`.
const MARKOV_PATH_LEN: f64 = 128.0;

/// Decompose `symbols` MSB-first into a binary sequence, matching the EA tool's
/// `bsymbols` construction (`(symbol >> (w-1-j)) & 1`). For `bits_per_symbol == 1`
/// the bytes are already the bit values (`0`/`1`), returned as-is.
///
/// Identical in behavior to the collision module's decomposition; kept local so
/// each estimator module is self-contained.
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

/// Compute the SP 800-90B §6.3.3 Markov min-entropy estimate for the bitstring
/// track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The function is **deterministic**: the same
/// `(symbols, bits_per_symbol)` always yields a bit-identical [`MarkovEstimate`].
///
/// # Behavior on degenerate input
///
/// The EA tool asserts `len > 1` (a Markov model needs at least two symbols).
/// Inputs too short to form a single transition are not part of the parity
/// contract and never arise for the EA datasets (each has ≥ 1e6 bits). For
/// robustness this implementation does not panic: with fewer than two bits no
/// transition counts accrue, every candidate path is guarded off, `H_min`
/// remains `128.0`, and the estimate clamps to `1.0` — the same conservative
/// "no usable estimate" upper bound the per-bit cap already enforces.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn markov(symbols: &[u8], bits_per_symbol: u8) -> MarkovEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    markov_bits(&bits)
}

/// Run the §6.3.3 Markov estimate over an already-decomposed binary sequence
/// (`0`/`1` values). Split out so tests can drive the estimate directly.
#[allow(
    // Counts are bounded by the slice length (fits usize, and u64 on supported
    // targets); the casts to f64 are the EA tool's own `(double)` casts and the
    // 1.0e-6 parity bound absorbs the rounding. The walk advances by 1 and never
    // exceeds `len`; the saturating ops below make the index arithmetic total.
    clippy::cast_precision_loss,
    // The bindings use SP 800-90B Markov notation (c_0/c_00/c_10, p_00/p_01/
    // p_10/p_11/p_0/p_1) transcribed from markov_test.h; the similarity is
    // inherent to the spec's naming.
    clippy::similar_names
)]
fn markov_bits(bits: &[u8]) -> MarkovEstimate {
    let len = bits.len();

    // Pass over the len-1 adjacent pairs, matching markov_test.h's loop:
    //   for i in 0..len-1 { if b[i]==0 { C_0++; if b[i+1]==0 C_00++ }
    //                       else if b[i+1]==0 C_10++ }
    // C_0 counts 0-bits in b[0..len-1]; C_00 / C_10 count 00 / 10 transitions.
    let mut c_0: u64 = 0;
    let mut c_00: u64 = 0;
    let mut c_10: u64 = 0;
    if len > 1 {
        let pairs = len.saturating_sub(1);
        let mut i: usize = 0;
        while i < pairs {
            // i < len-1 keeps i and i+1 in bounds; .get() makes that total.
            let (Some(&b0), Some(&b1)) = (bits.get(i), bits.get(i.saturating_add(1))) else {
                break; // unreachable on a valid walk; fail closed rather than panic.
            };
            if b0 == 0 {
                c_0 = c_0.saturating_add(1);
                if b1 == 0 {
                    c_00 = c_00.saturating_add(1);
                }
            } else if b1 == 0 {
                c_10 = c_10.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
    }

    // C_1 = (len-1) - C_0: number of 1-bits in b[0..len-1].
    let pairs = len.saturating_sub(1) as u64;
    let c_1 = pairs.saturating_sub(c_0);

    // Transition probabilities. markov_test.h uses P_X1 = 1 - P_X0, and sets
    // both to 0.0 when the conditioning count is 0 (so the > 0.0 guards below
    // skip the paths that would use them).
    let (p_00, p_01) = if c_0 > 0 {
        let p00 = (c_00 as f64) / (c_0 as f64);
        (p00, 1.0 - p00)
    } else {
        (0.0, 0.0)
    };
    let (p_10, p_11) = if c_1 > 0 {
        let p10 = (c_10 as f64) / (c_1 as f64);
        (p10, 1.0 - p10)
    } else {
        (0.0, 0.0)
    };

    // Fold the last bit into C_0 so it counts 0-bits over all of b[0..len], then
    // form the unconditional probabilities (markov_test.h: the post-loop
    // `if(data[len-1]==0) C_0++; P_0 = C_0/(double)len`).
    let mut c_0_full = c_0;
    if len > 0
        && let Some(&last) = bits.get(len.saturating_sub(1))
        && last == 0
    {
        c_0_full = c_0_full.saturating_add(1);
    }
    let (p_0, p_1) = if len > 0 {
        let p0 = (c_0_full as f64) / (len as f64);
        (p0, 1.0 - p0)
    } else {
        (0.0, 0.0)
    };

    // Six candidate length-128 path entropies. H_min starts at 128.0; each
    // candidate is guarded by > 0.0 on the probabilities it uses, exactly as in
    // markov_test.h, and lowers H_min when smaller.
    let mut h_min = MARKOV_PATH_LEN;
    let mut consider = |value: f64| {
        if value < h_min {
            h_min = value;
        }
    };

    // 00...0
    if p_00 > 0.0 {
        consider(-p_0.log2() - 127.0 * p_00.log2());
    }
    // 0101...01
    if p_01 > 0.0 && p_10 > 0.0 {
        consider(-p_0.log2() - 64.0 * p_01.log2() - 63.0 * p_10.log2());
    }
    // 011...1
    if p_01 > 0.0 && p_11 > 0.0 {
        consider(-p_0.log2() - p_01.log2() - 126.0 * p_11.log2());
    }
    // 100...0
    if p_10 > 0.0 && p_00 > 0.0 {
        consider(-p_1.log2() - p_10.log2() - 126.0 * p_00.log2());
    }
    // 1010...10
    if p_10 > 0.0 && p_01 > 0.0 {
        consider(-p_1.log2() - 64.0 * p_10.log2() - 63.0 * p_01.log2());
    }
    // 11...1
    if p_11 > 0.0 {
        consider(-p_1.log2() - 127.0 * p_11.log2());
    }

    // entEst = min(H_min/128.0, 1.0).
    let min_entropy = (h_min / MARKOV_PATH_LEN).min(1.0);

    MarkovEstimate {
        p_0,
        p_1,
        p_00,
        p_01,
        p_10,
        p_11,
        h_min,
        min_entropy,
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

    /// Build the MSB-first bitstring of a dataset and run the estimate, so the
    /// anchors are checked against the *real* dataset bits when present.
    fn markov_of_file(name: &str) -> Option<MarkovEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(markov(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor (from the EA `selftest/rand8_short.res`, verbose 3):
    /// P_0 = 0.5012375, P_1 = 0.4987625,
    /// P_00 = 0.50078555574951988, P_01 = 0.49921444425048012,
    /// P_10 = 0.5016791979949875, P_11 = 0.4983208020050125,
    /// min entropy = 0.99772497672796534.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = markov_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert!(
            (est.p_0 - 0.501_237_5).abs() < ANCHOR_EPS,
            "p_0={}",
            est.p_0
        );
        assert!(
            (est.p_1 - 0.498_762_5).abs() < ANCHOR_EPS,
            "p_1={}",
            est.p_1
        );
        assert!(
            (est.p_00 - 0.500_785_555_749_519_9).abs() < ANCHOR_EPS,
            "p_00={}",
            est.p_00
        );
        assert!(
            (est.p_01 - 0.499_214_444_250_480_1).abs() < ANCHOR_EPS,
            "p_01={}",
            est.p_01
        );
        assert!(
            (est.p_10 - 0.501_679_197_994_987_5).abs() < ANCHOR_EPS,
            "p_10={}",
            est.p_10
        );
        assert!(
            (est.p_11 - 0.498_320_802_005_012_5).abs() < ANCHOR_EPS,
            "p_11={}",
            est.p_11
        );
        assert!(
            (est.min_entropy - 0.997_724_976_727_965_3).abs() < ANCHOR_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// biased-random-bits anchor (1-bit data; EA labels it "Literal" because
    /// `bsymbols == symbols` for binary): min entropy = 0.029123023940057061.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = markov_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert!(
            (est.min_entropy - 0.029_123_023_940_057_06).abs() < ANCHOR_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..2000u32).map(|i| (i % 19) as u8).collect();
        let a = markov(&buf, 8);
        let b = markov(&buf, 8);
        assert_eq!(a, b, "MarkovEstimate must be bit-identical across runs");
    }

    /// A perfectly alternating bit sequence (`0101…`) is maximally *predictable*
    /// under the Markov model: P_00 = P_11 = 0, P_01 = P_10 = 1, so once the
    /// first bit is fixed the entire chain is determined. The most-likely
    /// 128-step path has probability P_0 = P_1 = ½ (only the start bit carries
    /// any uncertainty; every transition is certain), giving total path entropy
    /// `−log2(½) = 1` bit, which §6.3.3 divides over the 128-step block:
    /// `min_entropy = 1 / 128 = 0.0078125` bits/bit — the per-bit floor, NOT
    /// full entropy.
    #[test]
    fn alternating_bits_is_near_zero_entropy() {
        // 1-bit symbols: bytes are already 0/1. 0,1,0,1,... length 1000.
        let buf: Vec<u8> = (0..1000u32).map(|i| (i % 2) as u8).collect();
        let est = markov(&buf, 1);
        // P_01 = P_10 = 1 (every 0 is followed by 1 and vice versa);
        // P_00 = P_11 = 0.
        assert!((est.p_01 - 1.0).abs() < ANCHOR_EPS, "p_01={}", est.p_01);
        assert!((est.p_10 - 1.0).abs() < ANCHOR_EPS, "p_10={}", est.p_10);
        assert!(est.p_00.abs() < ANCHOR_EPS, "p_00={}", est.p_00);
        assert!(est.p_11.abs() < ANCHOR_EPS, "p_11={}", est.p_11);
        // Total path entropy 1 bit / 128 steps = 1/128 per bit (the deterministic
        // transitions contribute 0; only the start bit's ½ probability remains).
        assert!(
            (est.min_entropy - 1.0 / 128.0).abs() < ANCHOR_EPS,
            "min_entropy={}",
            est.min_entropy
        );
    }

    /// All-zero bits: P_0 = 1, P_00 = 1, so the `00…0` path gives
    /// `−log2(1) − 127·log2(1) = 0` → H_min = 0 → estimate 0.0 (no entropy).
    #[test]
    fn all_zeros_is_zero_entropy() {
        let buf = vec![0u8; 1000];
        let est = markov(&buf, 1);
        assert!((est.p_0 - 1.0).abs() < ANCHOR_EPS, "p_0={}", est.p_0);
        assert!((est.p_00 - 1.0).abs() < ANCHOR_EPS, "p_00={}", est.p_00);
        assert!(
            est.min_entropy.abs() < ANCHOR_EPS,
            "all-zero min_entropy should be 0, got {}",
            est.min_entropy
        );
        assert!(est.min_entropy.is_finite());
    }

    /// Empty / too-short input: no transition counts, every candidate guarded
    /// off, H_min stays 128, estimate clamps to 1.0 (conservative upper bound),
    /// no panic, no NaN.
    #[test]
    fn too_short_input_is_sane() {
        for buf in [&[][..], &[0u8][..], &[1u8][..]] {
            let est = markov(buf, 1);
            assert_eq!(est.h_min, MARKOV_PATH_LEN, "h_min should stay 128");
            assert_eq!(est.min_entropy, 1.0, "too-short estimate clamps to 1.0");
            assert!(est.min_entropy.is_finite());
        }
    }
}
