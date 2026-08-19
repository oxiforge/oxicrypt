//! SP 800-90B §6.3.8 **Lag prediction** min-entropy estimator (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 Lag predictor (`cpp/non_iid/lag_test.h`) bit-for-bit, to
//! within the pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). It is the second of the four §6.3.7–
//! §6.3.10 **prediction** estimators; the shared min-entropy formula they all
//! feed lives in [`crate::prediction`]. Like the rest of `oxicrypt-maxwell` it is
//! **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The Lag predictor (SP 800-90B §6.3.8)
//!
//! `D = 128` sub-predictors, one per lag `1 ..= D`. Lag `d`'s prediction for
//! `data[i]` is `data[i − d]` (the value `d` positions back). A scoreboard
//! records, per lag, how often that lag has predicted correctly; the current
//! "winner" is the lag with the best running score, and its prediction is the one
//! tested for the next sample. The estimator counts `C` correct predictions out
//! of `N = len − 1` predictions (the first sample has no prediction) and the
//! longest run `max_run_len` of consecutive correct predictions, then feeds
//! `(C, N, max_run_len, k)` into the shared
//! [`crate::prediction::prediction_estimate`].
//!
//! ## Lag offsets (matched from `lag_test.h`)
//!
//! The EA tool tracks the winner as a zero-based offset `winner ∈ 0..D`, where
//! offset `w` is lag `w + 1`. Its prediction test is
//! `data[i] == data[i − winner − 1]`. This module uses the same zero-based offset
//! convention (`lag = offset + 1`), so the scoreboard is `[i64; D]` indexed by
//! offset.
//!
//! ## Ordering (matched from `lag_test.h`)
//!
//! For each index `i` from `1` to `len−1`, in this exact order:
//! 1. **Predict**: compare `data[i − winner − 1]` (the state *before* this step's
//!    scoreboard updates) to `data[i]`; on a hit, `C++` and extend the
//!    correct-run counter, else reset the run to 0.
//! 2. **Score / pick winner**: for each offset `w` (lag `w + 1`) with
//!    `i − w − 1 ≥ 0` whose prediction `data[i − w − 1]` matched `data[i]`,
//!    increment `scoreboard[w]`; set `winner = w` whenever
//!    `++scoreboard[w] >= highScore` (`highScore` then tracks that value). The EA
//!    tool walks the current symbol's occurrence ring buffer most-recent-first,
//!    which is exactly ascending offset order (smaller lag = more recent), so
//!    iterating `w = 0 .. D` and scoring the offsets whose lagged sample equals
//!    `data[i]` reproduces the EA tie behavior (later/larger offset wins a tie
//!    only via the `>=`; equal scores keep the most-recently-promoted offset
//!    seen latest in this ascending walk). The EA window cutoff (`i − D`) and the
//!    `D`-entry ring cap together restrict offsets to `0 ..= D−1`, which is
//!    already enforced here by the `w < D` loop bound and the `i − w − 1 ≥ 0`
//!    guard.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte**. The estimator runs on the
//! **bitstring track**: each symbol is decomposed MSB-first into its
//! `bits_per_symbol` bits (`(symbol >> (w−1−j)) & 1`), exactly as the MCV
//! bitstring track, collision, Markov, compression, t-Tuple, LRS, and MultiMCW
//! estimators do, and the predictor runs over the binary alphabet (`k = 2`). This
//! is the EA tool's controlling per-bit assessment
//! (`lag_test(data.bsymbols, data.blen, 2, …)`); for 1-bit data
//! `bsymbols == symbols`, so the EA tool's "Literal" line for binary data is the
//! same computation. `bits_per_symbol` is clamped into `1..=8`.
//!
//! # The `len < 2` guard
//!
//! The EA tool asserts `L > 2` and makes `N = L − 1` predictions; with fewer than
//! two samples there is no prediction to make. This is reproduced as
//! [`LagEstimate::unavailable`]; it never arises for the EA datasets (each has
//! ≥ 1e6 bits).

// This module is a 1:1 transcription of the EA reference's lag_test (in the
// straightforward per-lag form the reference documents as equivalent to its ring
// buffer optimization). The scoreboard/winner bookkeeping uses the reference's
// conventional names (D, N, C, scoreboard, winner, highScore, curRunOfCorrects,
// maxRunOfCorrects); faithfulness to the C++ is the priority and the parity
// oracle (<= 1e-6 vs EA on all bundled datasets) is the real correctness gate.
// This module-level allow covers the algorithm-inherent lints uniformly so the
// transcription reads like the reference rather than being restructured to
// satisfy style/restriction lints.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_wrap
)]

use crate::prediction::{PredictionEstimate, prediction_estimate};

/// The number of Lag sub-predictors (`D_LAG` in `lag_test.h`): lags `1 ..= 128`.
const D_LAG: usize = 128;

/// Minimum sample count to run the test: the EA tool asserts `L > 2`, i.e. at
/// least 2 samples are needed to make any prediction (`N = L − 1`).
pub const MIN_SAMPLES: usize = 2;

/// One Lag (§6.3.8) prediction min-entropy result over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LagEstimate {
    /// The shared prediction-estimate intermediates and result (`C`, `N`,
    /// `max_run_len`, `p_global`, `p_global'`, `p_local`, `min_entropy`). `-1.0`
    /// `min_entropy` is the "could not run" sentinel; see [`Self::unavailable`].
    pub estimate: PredictionEstimate,
}

impl LagEstimate {
    /// The "estimate did not run" sentinel, returned for inputs shorter than
    /// [`MIN_SAMPLES`] bits. Never arises for the EA datasets (each has ≥ 1e6
    /// bits).
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            estimate: PredictionEstimate {
                c: 0,
                n: 0,
                max_run_len: 0,
                p_global: -1.0,
                p_global_prime: -1.0,
                p_local: -1.0,
                min_entropy: -1.0,
            },
        }
    }

    /// The per-bit Lag min-entropy in bits (the EA tool's "min entropy"), or
    /// `-1.0` when the estimate could not run.
    #[must_use]
    pub const fn min_entropy(&self) -> f64 {
        self.estimate.min_entropy
    }
}

/// Decompose `symbols` MSB-first into a binary sequence, matching the EA tool's
/// `bsymbols` construction (`(symbol >> (w-1-j)) & 1`). For `bits_per_symbol == 1`
/// the bytes are already the bit values (`0`/`1`), returned as-is.
///
/// Identical in behavior to the other estimator modules' decomposition; kept
/// local so each estimator module is self-contained.
fn to_bitstring(symbols: &[u8], bits_per_symbol: u8) -> Vec<u8> {
    if bits_per_symbol == 1 {
        return symbols.to_vec();
    }
    let mut bits: Vec<u8> =
        Vec::with_capacity(symbols.len().saturating_mul(bits_per_symbol as usize));
    for &s in symbols {
        let mut shift = bits_per_symbol;
        while shift > 0 {
            shift = shift.saturating_sub(1);
            bits.push((s >> shift) & 1);
        }
    }
    bits
}

/// Run the §6.3.8 Lag predictor over a symbol slice `data` with alphabet size
/// `alph_size`, transcribing `lag_test.h`.
///
/// `data` holds symbol values in `0..alph_size` (one per element). For the
/// bitstring track these are `0`/`1` bytes with `alph_size == 2`. Returns the
/// shared prediction estimate, or [`LagEstimate::unavailable`] when there are
/// fewer than [`MIN_SAMPLES`] samples.
///
/// The function is deterministic and does not panic.
fn lag_core(data: &[u8], alph_size: u64) -> LagEstimate {
    let len = data.len();
    if len < MIN_SAMPLES {
        return LagEstimate::unavailable();
    }

    // N = L - 1 predictions (the first sample has no prediction).
    let n = (len - 1) as u64;

    // Scoreboard, one running score per lag offset (offset w == lag w+1).
    let mut scoreboard: [i64; D_LAG] = [0; D_LAG];
    let mut winner: usize = 0;
    let mut high_score: i64 = 0;

    let mut c: u64 = 0;
    let mut run_len: u64 = 0;
    let mut max_run_len: u64 = 0;

    // The rest of the values yield a prediction (index 0 only seeds history).
    for i in 1..len {
        let cur = data[i];

        // 1. Check the current winner's prediction: data[i] vs data[i-winner-1].
        // winner is in 0..D and is only ever set to an offset w with
        // i-w-1 >= 0, so winner+1 <= i here and the index is in range.
        if cur == data[i - winner - 1] {
            c += 1;
            run_len += 1;
            if run_len > max_run_len {
                max_run_len = run_len;
            }
        } else {
            run_len = 0;
        }

        // 2. Update the scoreboard and select the new winner. Walk offsets in
        // ascending order (lag w+1), which matches the EA ring buffer's
        // most-recent-first walk; only offsets whose lagged sample equals data[i]
        // (and that are in-range) are scored, each at most once per step.
        for w in 0..D_LAG {
            // Offset w needs a sample w+1 back; stop once it would underflow.
            if w + 1 > i {
                break;
            }
            if data[i - w - 1] == cur {
                scoreboard[w] += 1;
                if scoreboard[w] >= high_score {
                    winner = w;
                    high_score = scoreboard[w];
                }
            }
        }
    }

    LagEstimate {
        estimate: prediction_estimate(c, n, max_run_len, alph_size),
    }
}

/// Compute the SP 800-90B §6.3.8 Lag prediction min-entropy estimate for the
/// bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The estimator decomposes to the MSB-first bitstring and runs the
/// predictor over the binary alphabet (`k = 2`). The function is
/// **deterministic**: the same `(symbols, bits_per_symbol)` always yields a
/// bit-identical [`LagEstimate`].
///
/// # Behavior on degenerate input
///
/// Fewer than [`MIN_SAMPLES`] bits returns [`LagEstimate::unavailable`]
/// (min-entropy `-1.0`, the EA tool's could-not-run sentinel). Never arises for
/// the EA datasets (each has ≥ 1e6 bits).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn lag(symbols: &[u8], bits_per_symbol: u8) -> LagEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    // Bitstring track: binary alphabet.
    lag_core(&bits, 2)
}

/// Compute the §6.3.8 Lag prediction estimate for the **literal track**: the raw
/// symbols over their own (translated) alphabet, mirroring the EA tool's
/// `lag_test(data.symbols, data.len, data.alph_size, …, "Literal")`.
///
/// The symbols are translated to a dense `0..alph_size` alphabet (see
/// `crate::dense_alphabet`) and run through the same alphabet-generic
/// `lag_core` as the bitstring track. Literal-track input to `H_original`.
/// Deterministic; does not panic.
#[must_use]
pub fn lag_literal(symbols: &[u8]) -> LagEstimate {
    let (dense, alph_size) = crate::dense_alphabet(symbols);
    lag_core(&dense, alph_size as u64)
}

#[cfg(test)]
#[allow(
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

    /// Cross-tool parity bound — the predictor counts (C, N, max_run_len) are
    /// exact integers, but the shared p_local bisection + final log2 run in f64
    /// here vs long double in the EA tool, so anchors are checked at 1e-6.
    const PARITY_EPS: f64 = 1.0e-6;

    fn lag_of_file(name: &str) -> Option<LagEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(lag(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor, Bitstring track (from `selftest/rand8_short.res`):
    /// C = 39922, r = 14 (max_run_len = 13), N = 79999,
    /// min entropy = 0.98969349388795491.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = lag_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 39922, "C");
        assert_eq!(est.estimate.n, 79999, "N");
        assert_eq!(est.estimate.max_run_len, 13, "max_run_len (r = 14)");
        assert!(
            (est.min_entropy() - 0.989_693_493_887_954_9).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// biased-random-bits anchor, Literal track (1-bit; bsymbols == symbols):
    /// C = 959838, r = 527 (max_run_len = 526), N = 999999,
    /// min entropy = 0.040599763274887825.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = lag_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 959_838, "C");
        assert_eq!(est.estimate.n, 999_999, "N");
        assert_eq!(est.estimate.max_run_len, 526, "max_run_len (r = 527)");
        assert!(
            (est.min_entropy() - 0.040_599_763_274_887_825).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// Literal-track parity: `lag_literal` matches EA v1.1.8 "Literal Lag
    /// Prediction Estimate: min entropy" to within 1e-6 on every multi-bit
    /// reference dataset (harvested 2026-06-16 via `ea_non_iid -i -a -v -v`).
    /// Skips datasets absent on host.
    #[test]
    fn literal_parity_multibit() {
        const EA_LITERAL_LAG: &[(&str, f64)] = &[
            ("biased-random-bytes", 0.466_258_265_027_8),
            ("normal", 6.106_223_223_599_8),
            ("rand4_short", 3.783_650_612_553_7),
            ("rand8_short", 6.636_441_287_083_9),
            ("truerand_4bit", 3.976_270_969_447_0),
            ("truerand_8bit", 7.939_764_556_109_4),
        ];
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(name, ea) in EA_LITERAL_LAG {
            let Some(row) = REFERENCE_TABLE.iter().find(|r| r.name == name) else {
                continue;
            };
            let Ok(data) = std::fs::read(dir.join(row.file)) else {
                eprintln!("{name}.bin absent — skipping literal parity");
                continue;
            };
            let got = lag_literal(&data).min_entropy();
            assert!(
                (got - ea).abs() <= PARITY_EPS,
                "{name}: literal Lag {got} vs EA {ea} (delta {})",
                (got - ea).abs()
            );
            checked += 1;
        }
        if checked == 0 {
            eprintln!("no multi-bit datasets present — literal parity skipped");
        }
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..2000u32).map(|i| (i % 19) as u8).collect();
        let a = lag(&buf, 8);
        let b = lag(&buf, 8);
        assert_eq!(a, b, "LagEstimate must be bit-identical across runs");
    }

    /// All-zero bits: lag 1 always predicts correctly (every sample equals the
    /// previous one), so C = N and the run never breaks. The shared formula then
    /// yields a very low (near-zero) min-entropy. Sanity: estimate runs, is
    /// finite and small.
    #[test]
    fn all_zeros_is_low_entropy() {
        let buf = vec![0u8; 8192];
        let est = lag(&buf, 1);
        assert_eq!(
            est.estimate.c, est.estimate.n,
            "all-zeros: C should equal N"
        );
        assert!(est.min_entropy() >= 0.0 && est.min_entropy().is_finite());
        assert!(
            est.min_entropy() < 0.01,
            "all-zeros min_entropy should be near 0, got {}",
            est.min_entropy()
        );
    }

    /// Too-short input: fewer than MIN_SAMPLES bits returns the unavailable
    /// sentinel (min-entropy -1.0), no panic.
    #[test]
    fn too_short_input_is_unavailable() {
        let buf = vec![0u8; 1]; // 1 bit at 1 bit/symbol < MIN_SAMPLES
        let est = lag(&buf, 1);
        assert_eq!(est.min_entropy(), -1.0, "too-short returns -1.0 sentinel");
    }
}
