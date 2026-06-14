//! `oxicrypt-maxwell` — SP 800-90B min-entropy estimator suite (out of boundary).
//!
//! This crate implements the SP 800-90B §6.3.1 **Most Common Value (MCV)**
//! min-entropy estimator (see [`mcv`]), the SP 800-90B §6.3.2 **Collision**
//! min-entropy estimator (see [`collision`]), the SP 800-90B §6.3.3 **Markov**
//! min-entropy estimator (see [`markov`]), the SP 800-90B §6.3.4 **Compression**
//! min-entropy estimator (see [`compression`]), the SP 800-90B §6.3.5 **t-Tuple**
//! and §6.3.6 **LRS** min-entropy estimators (see [`lrs`]), the SP 800-90B
//! §6.3.7 **MultiMCW prediction** min-entropy estimator (see [`multi_mcw`]), the
//! SP 800-90B §6.3.8 **Lag prediction** min-entropy estimator (see [`lag`]), the
//! SP 800-90B §6.3.9 **MultiMMC prediction** min-entropy estimator (see
//! [`multi_mmc`]), and the SP 800-90B §6.3.10 **LZ78Y prediction** min-entropy
//! estimator (see [`lz78y`]) — which together complete the SP 800-90B §6.3
//! non-IID estimator suite — all built on the shared [`prediction`] estimate
//! machinery, and a parity
//! harness that checks all of these implementations against the NIST
//! `SP800-90B_EntropyAssessment` reference tool ("EA tool"), version **1.1.8**.
//! It is **outside the
//! cryptographic
//! boundary** — it is pure offline analysis tooling (like `acvp-harness`, `oxi`,
//! and `benches`) and is `#![forbid(unsafe_code)]`. It does not change the
//! in-boundary unsafe accounting and produces no security parameters.
//!
//! # The MCV estimator (SP 800-90B §6.3.1)
//!
//! Given a sequence of `L` symbols, let `mode_count` be the number of
//! occurrences of the most frequent symbol value and `p_hat = mode_count / L`.
//! The estimator forms the upper bound of a two-sided 99% normal confidence
//! interval:
//!
//! ```text
//! p_u = min(1, p_hat + Z * sqrt( p_hat * (1 - p_hat) / (L - 1) ))
//! H   = -log2(p_u)
//! ```
//!
//! ## The `Z` constant — deviation from the task spec, documented
//!
//! The task spec proposed `Z = 2.576`. The EA tool v1.1.8 in fact uses the
//! full-precision inverse standard-normal CDF value **Φ⁻¹(0.995) =
//! `2.5758293035489008`** (the 0.995 quantile, i.e. the upper bound of a
//! two-sided 99% CI). Reproducing the EA reference values to the
//! pre-registered **1.0e-6 bits** parity bound (see
//! `docs/estimator-parity-tolerances.md`) requires the full-precision
//! constant: the rounded `2.576` diverges by ~2.4e-5 bits on `rand8_short`,
//! which is ~24× over the bound. The full-precision constant reproduces all 11
//! reference values to within floating-point noise (observed delta 0.0 on
//! every dataset). The hand-verified `rand8_short` vector
//! (`L=10000, mode_count=58, p_hat=0.0058, p_u=0.0077560937775866,
//! H=7.0104540377360411`) confirms `Z`: the `Z` implied by that `p_u` is
//! `2.5758293035488586`, matching `Φ⁻¹(0.995)` to 13 significant digits.
//!
//! # Two tracks
//!
//! - **Literal**: MCV over the symbol alphabet `0 .. 2^bits_per_symbol`.
//! - **Bitstring**: each symbol is decomposed MSB-first into its
//!   `bits_per_symbol` bits, concatenated into one binary sequence of length
//!   `L * bits_per_symbol`, and MCV is run over the alphabet `{0, 1}`. The
//!   reported value is per-bit (it is *not* scaled by `bits_per_symbol`),
//!   matching the EA tool's "Bitstring MCV min entropy" line.
//! - When `bits_per_symbol == 1` the two tracks are identical, so only the
//!   literal track is reported and [`McvResult::bitstring`] is `None` (the EA
//!   tool emits no separate bitstring line for 1-bit data).
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte**. For `bits_per_symbol < 8`
//! the EA datasets already store each symbol masked into the low bits of its
//! byte; the implementation does not re-mask (and so a value exceeding the
//! declared alphabet would simply be counted as its own symbol). `L` is the
//! byte count.
//!
//! # Provenance
//!
//! The 11 reference datasets are NIST-distributed with the EA tool and are
//! referenced **by path, not vendored**. Their SHA-256 digests, declared
//! widths, and EA reference min-entropy values are recorded in the parity
//! table ([`parity::REFERENCE_TABLE`]) for provenance. The acceptance bound is
//! the pre-registered 1.0e-6 bits/estimator from
//! `docs/estimator-parity-tolerances.md`.

#![forbid(unsafe_code)]

pub mod apt;
pub mod collision;
pub mod compression;
pub mod gate;
pub mod lag;
pub mod lrs;
pub mod lz78y;
pub mod markov;
pub mod multi_mcw;
pub mod multi_mmc;
pub mod parity;
pub mod periodicity;
pub mod prediction;

/// Full-precision `Z` value used by the EA tool v1.1.8: Φ⁻¹(0.995), the upper
/// bound of a two-sided 99% normal confidence interval.
///
/// See the crate-level docs for why this is *not* the rounded `2.576` from the
/// task spec — the rounded value misses the 1.0e-6 parity bound.
pub const Z_995: f64 = 2.575_829_303_548_901;

/// One MCV min-entropy estimate (one track: literal or bitstring).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct McvEstimate {
    /// Count of occurrences of the most frequent symbol value.
    pub mode_count: u64,
    /// `mode_count / L`.
    pub p_hat: f64,
    /// Upper 99% confidence bound on the mode probability, clamped to 1.0.
    pub p_u: f64,
    /// `-log2(p_u)` — the min-entropy estimate in bits.
    pub min_entropy: f64,
}

/// The full MCV result for a dataset: both tracks.
///
/// `bitstring` is `None` when `bits_per_symbol == 1` (the literal and bitstring
/// tracks coincide and the EA tool reports only one line).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct McvResult {
    /// MCV over the symbol alphabet.
    pub literal: McvEstimate,
    /// MCV over the MSB-first bit decomposition; `None` for 1-bit data.
    pub bitstring: Option<McvEstimate>,
}

/// Compute the MCV min-entropy estimate over an arbitrary symbol slice.
///
/// `counts` indexes by symbol value; `alphabet_len` is the number of distinct
/// symbol values the histogram spans (its slot count). Returns sane,
/// non-panicking values for empty input.
///
/// # Behavior on degenerate input
///
/// - **Empty input** (`L == 0`): returns `mode_count = 0`, `p_hat = 0.0`,
///   `p_u = 0.0`, `min_entropy = f64::INFINITY` (`-log2(0)` is `+inf`).
///   There is no entropy claim to make from zero samples; the infinity is a
///   sentinel, not a usable estimate.
/// - **Single symbol** (`L == 1`): `L - 1 == 0` would divide by zero in the
///   confidence term, so the standard error is taken as `0.0`, giving
///   `p_u = p_hat = 1.0` and `min_entropy = 0.0` (zero entropy, the correct
///   conservative answer for one observation).
fn mcv_from_mode(mode_count: u64, total: u64) -> McvEstimate {
    if total == 0 {
        return McvEstimate {
            mode_count: 0,
            p_hat: 0.0,
            p_u: 0.0,
            // -log2(0) = +inf. Sentinel for "no estimate from zero samples".
            min_entropy: f64::INFINITY,
        };
    }

    #[allow(clippy::cast_precision_loss)]
    let l = total as f64;
    #[allow(clippy::cast_precision_loss)]
    let p_hat = (mode_count as f64) / l;

    // Standard-error term: sqrt( p_hat * (1 - p_hat) / (L - 1) ).
    // For L == 1 the denominator is 0; the conservative SP 800-90B answer is to
    // take the bound as p_hat itself (no width), yielding H = 0.
    let se = if total <= 1 {
        0.0
    } else {
        // total >= 2, so total - 1 >= 1: no underflow.
        #[allow(clippy::cast_precision_loss)]
        let denom = total.saturating_sub(1) as f64;
        (p_hat * (1.0 - p_hat) / denom).sqrt()
    };

    let p_u = (p_hat + Z_995 * se).min(1.0);
    let min_entropy = -p_u.log2();

    McvEstimate {
        mode_count,
        p_hat,
        p_u,
        min_entropy,
    }
}

/// Histogram the literal symbols and return the MCV estimate.
fn mcv_literal(symbols: &[u8]) -> McvEstimate {
    // 256 slots cover every possible byte value; sub-8-bit symbols occupy a
    // prefix of the table. u64 counters: a slice cannot exceed usize::MAX
    // elements, well within u64 on supported targets.
    let mut counts = [0u64; 256];
    for &s in symbols {
        if let Some(slot) = counts.get_mut(s as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let mode_count = counts.iter().copied().max().unwrap_or(0);
    let total = symbols.len() as u64;
    mcv_from_mode(mode_count, total)
}

/// Histogram the MSB-first bit decomposition and return the MCV estimate.
fn mcv_bitstring(symbols: &[u8], bits_per_symbol: u8) -> McvEstimate {
    // Count zeros and ones directly; the binary alphabet needs no allocation.
    let mut ones: u64 = 0;
    let mut total: u64 = 0;
    // bits_per_symbol is 1..=8; shifting by (bits-1)..0 stays in range for u8.
    for &s in symbols {
        let mut bit = bits_per_symbol;
        while bit > 0 {
            bit = bit.saturating_sub(1);
            let b = (s >> bit) & 1;
            if b == 1 {
                ones = ones.saturating_add(1);
            }
            total = total.saturating_add(1);
        }
    }
    let zeros = total.saturating_sub(ones);
    let mode_count = ones.max(zeros);
    mcv_from_mode(mode_count, total)
}

/// Compute the SP 800-90B §6.3.1 MCV min-entropy estimate for both tracks.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` must be in
/// `1..=8`. The bitstring track is omitted (`None`) when `bits_per_symbol == 1`.
///
/// This function is **deterministic**: the same `(symbols, bits_per_symbol)`
/// always yields a bit-identical [`McvResult`].
///
/// # Panics
///
/// Does not panic. `bits_per_symbol` outside `1..=8` is clamped into range
/// (`0 -> 1`, `>8 -> 8`) so callers cannot trigger out-of-range shifts; the
/// CLI and tests always pass valid widths.
#[must_use]
pub fn mcv(symbols: &[u8], bits_per_symbol: u8) -> McvResult {
    let bps = bits_per_symbol.clamp(1, 8);
    let literal = mcv_literal(symbols);
    let bitstring = if bps == 1 {
        None
    } else {
        Some(mcv_bitstring(symbols, bps))
    };
    McvResult { literal, bitstring }
}

#[cfg(test)]
#[allow(
    // Tests assert exact sentinel values, use unwrap/expect/panic for fatal
    // setup invariants, and index fixed-size fixtures — all fine in test code.
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    /// Tolerance for the hand-verified unit vector (tighter than the 1e-6
    /// parity bound — this is exact reproduction, not cross-tool parity).
    const UNIT_EPS: f64 = 1.0e-9;

    /// Hand-verified `rand8_short` literal vector from the task spec:
    /// L=10000, mode_count=58, p_hat=0.0058, p_u=0.0077560937775866,
    /// H=7.0104540377360411.
    #[test]
    fn rand8_short_hand_verified_vector() {
        // Construct a 10000-symbol buffer whose most frequent byte occurs 58
        // times. We do not need the real file: MCV depends only on L and the
        // mode count. Lay down 58 copies of symbol 0, then fill the rest so no
        // other symbol reaches 58 (cycle through 1..=255, max 9942/255 ≈ 39).
        let mut buf: Vec<u8> = Vec::with_capacity(10_000);
        buf.resize(58, 0u8);
        let mut next: u16 = 1;
        while buf.len() < 10_000 {
            buf.push((next % 256) as u8);
            next += 1;
            if next > 255 {
                next = 1;
            }
        }
        assert_eq!(buf.len(), 10_000);

        let est = mcv_literal(&buf);
        assert_eq!(est.mode_count, 58);
        assert!((est.p_hat - 0.0058).abs() < UNIT_EPS, "p_hat={}", est.p_hat);
        assert!(
            (est.p_u - 0.007_756_093_777_586_6).abs() < UNIT_EPS,
            "p_u={}",
            est.p_u
        );
        assert!(
            (est.min_entropy - 7.010_454_037_736_041).abs() < UNIT_EPS,
            "H={}",
            est.min_entropy
        );
    }

    /// Determinism: two runs on the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        // Documented epsilon for the determinism contract: 1e-12. The actual
        // requirement is *bit-exact* (delta 0.0); the epsilon is the slack we
        // assert within, far tighter than any meaningful difference.
        const DET_EPS: f64 = 1.0e-12;

        let buf: Vec<u8> = (0..1000u32).map(|i| (i % 17) as u8).collect();
        let a = mcv(&buf, 8);
        let b = mcv(&buf, 8);
        assert_eq!(a, b, "McvResult must be bit-identical across runs");
        // Explicit delta check (redundant with PartialEq, documents the bound).
        assert!((a.literal.min_entropy - b.literal.min_entropy).abs() <= DET_EPS);
        let (Some(ab), Some(bb)) = (a.bitstring, b.bitstring) else {
            panic!("8-bit data must produce a bitstring track");
        };
        assert!((ab.min_entropy - bb.min_entropy).abs() <= DET_EPS);
    }

    /// Empty input: no panic, sentinel infinity, mode_count 0.
    #[test]
    fn empty_input_is_sane() {
        let r = mcv(&[], 8);
        assert_eq!(r.literal.mode_count, 0);
        assert_eq!(r.literal.p_hat, 0.0);
        assert_eq!(r.literal.p_u, 0.0);
        assert!(
            r.literal.min_entropy.is_infinite() && r.literal.min_entropy > 0.0,
            "empty input min_entropy should be +inf, got {}",
            r.literal.min_entropy
        );
        // bitstring track also processes zero bits -> same sentinel.
        let bs = r.bitstring.expect("8-bit declares a bitstring track");
        assert_eq!(bs.mode_count, 0);
        assert!(bs.min_entropy.is_infinite());
    }

    /// Single symbol: no division by zero, H = 0 (one observation -> no entropy).
    #[test]
    fn single_symbol_is_sane() {
        let r = mcv(&[0x42], 8);
        assert_eq!(r.literal.mode_count, 1);
        assert!((r.literal.p_hat - 1.0).abs() < UNIT_EPS);
        assert!((r.literal.p_u - 1.0).abs() < UNIT_EPS);
        assert!(
            r.literal.min_entropy.abs() < UNIT_EPS,
            "single-symbol H should be 0, got {}",
            r.literal.min_entropy
        );
        assert!(r.literal.min_entropy.is_finite());
    }

    /// 1-bit data reports only the literal track.
    #[test]
    fn one_bit_has_no_bitstring_track() {
        let buf = [0u8, 1, 0, 1, 1, 0, 1, 0];
        let r = mcv(&buf, 1);
        assert!(r.bitstring.is_none());
        // mode is whichever of {0,1} is more frequent; here 1 appears 4, 0 appears 4.
        assert_eq!(r.literal.mode_count, 4);
    }

    /// Bitstring track on a known 4-bit pattern: all-ones nibbles -> every bit
    /// is 1 -> p_hat = 1, H = 0.
    #[test]
    fn bitstring_all_ones() {
        let buf = [0x0Fu8; 100]; // low nibble all ones, 4-bit symbols
        let r = mcv(&buf, 4);
        let bs = r.bitstring.expect("4-bit declares a bitstring track");
        assert_eq!(bs.mode_count, 400); // 100 symbols * 4 bits, all ones
        assert!((bs.min_entropy).abs() < UNIT_EPS);
    }
}
