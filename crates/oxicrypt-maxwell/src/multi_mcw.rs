//! SP 800-90B §6.3.7 **MultiMCW (Multi Most-Common-in-Window) prediction**
//! min-entropy estimator (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 MultiMCW predictor (`cpp/non_iid/multi_mcw_test.h`)
//! bit-for-bit, to within the pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). It is the first of the four §6.3.7–
//! §6.3.10 **prediction** estimators; the shared min-entropy formula they all
//! feed lives in [`crate::prediction`]. Like the rest of `oxicrypt-maxwell` it is
//! **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The MultiMCW predictor (SP 800-90B §6.3.7)
//!
//! Four sliding windows of sizes `W = {63, 255, 1023, 4095}` each track the most
//! common value seen in their last `W[j]` samples ("the frequent"). A scoreboard
//! records how often each window's prediction has been correct; the current
//! "winner" is the window with the best recent score, and its frequent is the
//! prediction for the next sample. The estimator counts `C` correct predictions
//! out of `N = len − W[0]` predictions and the longest run `max_run_len` of
//! consecutive correct predictions, then feeds `(C, N, max_run_len, k)` into the
//! shared [`crate::prediction::prediction_estimate`].
//!
//! ## Ordering (matched from `multi_mcw_test.h`)
//!
//! For each index `i` from `W[0]` to `len−1`, in this exact order:
//! 1. **Predict**: compare `frequent[winner]` (the state *before* this step's
//!    updates) to `data[i]`; on a hit, `C++` and extend the correct-run counter,
//!    else reset the run to 0.
//! 2. **Score / pick winner**: for each window `j` with `i ≥ W[j]` whose frequent
//!    matched `data[i]`, increment `scoreboard[j]`; set `winner = j` whenever
//!    `++scoreboard[j] >= scoreboard[winner]` (ties move the winner to `j`).
//! 3. **Slide windows**: for each window `j` with `i ≥ W[j]`, drop `data[i−W[j]]`
//!    and add `data[i]`; then re-select that window's frequent — either the new
//!    sample becomes the frequent (when the dropped sample was not the frequent
//!    and the new count ties/beats `max_cnts[j]`), or, when the dropped sample
//!    *was* the frequent, `max_cnts[j]` is decremented and a full rescan picks the
//!    new frequent (preferring the most-recently-seen value on ties via
//!    `win_poses`).
//!
//! The pre-loop initialization fills the windows from the first `W[3]` samples,
//! using the same `<=` tie rule (later samples win ties) and recording each
//! value's last position in `win_poses`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte**. The estimator runs on the
//! **bitstring track**: each symbol is decomposed MSB-first into its
//! `bits_per_symbol` bits (`(symbol >> (w−1−j)) & 1`), exactly as the MCV
//! bitstring track, collision, Markov, compression, t-Tuple, and LRS estimators
//! do, and the predictor runs over the binary alphabet (`k = 2`). This is the EA
//! tool's controlling per-bit assessment (`multi_mcw_test(data.bsymbols,
//! data.blen, 2, …)`); for 1-bit data `bsymbols == symbols`, so the EA tool's
//! "Literal" line for binary data is the same computation. `bits_per_symbol` is
//! clamped into `1..=8`.
//!
//! # The `len < W[3]+1` guard
//!
//! The EA tool returns `-1.0` (estimate could not run) when there are fewer than
//! `W[3] + 1 = 4096` samples. This is reproduced as
//! [`MultiMcwEstimate::unavailable`]; it never arises for the EA datasets (each
//! has ≥ 1e6 bits).

// This module is a 1:1 transcription of the EA reference's multi_mcw_test. The
// sliding-window bookkeeping is index- and arithmetic-heavy and uses the
// reference's conventional names (W, N, C, run_len, win_cnts, win_poses,
// frequent, scoreboard, winner, max_cnts, max_pos); faithfulness to the C++ is
// the priority and the parity oracle (<= 1e-6 vs EA on all bundled datasets) is
// the real correctness gate. This module-level allow covers the
// algorithm-inherent lints uniformly so the transcription reads like the
// reference rather than being restructured to satisfy style/restriction lints.
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

/// The four MultiMCW window sizes (SP 800-90B §6.3.7 / `multi_mcw_test.h`).
const WINDOWS: [usize; 4] = [63, 255, 1023, 4095];

/// Number of windows (`NUM_WINS`).
const NUM_WINS: usize = 4;

/// Minimum sample count to run the test: `W[NUM_WINS-1] + 1 = 4096`.
pub const MIN_SAMPLES: usize = WINDOWS[NUM_WINS - 1] + 1;

/// One MultiMCW (§6.3.7) prediction min-entropy result over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MultiMcwEstimate {
    /// The shared prediction-estimate intermediates and result (`C`, `N`,
    /// `max_run_len`, `p_global`, `p_global'`, `p_local`, `min_entropy`). `-1.0`
    /// `min_entropy` is the "could not run" sentinel; see [`Self::unavailable`].
    pub estimate: PredictionEstimate,
}

impl MultiMcwEstimate {
    /// The EA tool's "estimate did not run" sentinel (`return -1.0`), returned
    /// for inputs shorter than [`MIN_SAMPLES`] bits. Never arises for the EA
    /// datasets (each has ≥ 1e6 bits).
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

    /// The per-bit MultiMCW min-entropy in bits (the EA tool's "min entropy"),
    /// or `-1.0` when the estimate could not run.
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

/// Run the §6.3.7 MultiMCW predictor over a symbol slice `data` with alphabet
/// size `alph_size`, transcribing `multi_mcw_test.h`.
///
/// `data` holds symbol values in `0..alph_size` (one per element). For the
/// bitstring track these are `0`/`1` bytes with `alph_size == 2`. Returns the
/// shared prediction estimate, or [`MultiMcwEstimate::unavailable`] when there
/// are fewer than [`MIN_SAMPLES`] samples.
///
/// The function is deterministic and does not panic.
fn multi_mcw_core(data: &[u8], alph_size: usize) -> MultiMcwEstimate {
    let len = data.len();
    if len < MIN_SAMPLES {
        return MultiMcwEstimate::unavailable();
    }

    // N = len - W[0].
    let n = len - WINDOWS[0];

    let mut winner: usize = 0;
    let mut c: u64 = 0;
    let mut run_len: u64 = 0;
    let mut max_run_len: u64 = 0;

    // Per-window per-symbol counts and last-seen positions.
    let mut win_cnts: [Vec<i64>; NUM_WINS] = [
        vec![0i64; alph_size],
        vec![0i64; alph_size],
        vec![0i64; alph_size],
        vec![0i64; alph_size],
    ];
    // Positions can be -1-equivalent only via i; the EA tool uses `long` and
    // initializes to 0, then assigns real indices i (>= 0). We mirror that with
    // i64 positions initialized to 0.
    let mut win_poses: [Vec<i64>; NUM_WINS] = [
        vec![0i64; alph_size],
        vec![0i64; alph_size],
        vec![0i64; alph_size],
        vec![0i64; alph_size],
    ];
    let mut max_cnts: [i64; NUM_WINS] = [0; NUM_WINS];
    let mut scoreboard: [i64; NUM_WINS] = [0; NUM_WINS];
    let mut frequent: [usize; NUM_WINS] = [0; NUM_WINS];

    // --- Compute initial window counts (from the first W[NUM_WINS-1] samples). ---
    for i in 0..WINDOWS[NUM_WINS - 1] {
        let di = data[i] as usize;
        for j in 0..NUM_WINS {
            if i < WINDOWS[j] {
                win_cnts[j][di] += 1;
                // `<=` so later samples win ties (EA tool's exact rule).
                if max_cnts[j] <= win_cnts[j][di] {
                    max_cnts[j] = win_cnts[j][di];
                    frequent[j] = di;
                }
                win_poses[j][di] = i as i64;
            }
        }
    }

    // --- Perform predictions. ---
    for i in WINDOWS[0]..len {
        let di = data[i] as usize;

        // 1. Test prediction of the current winner.
        if frequent[winner] == di {
            c += 1;
            run_len += 1;
            if run_len > max_run_len {
                max_run_len = run_len;
            }
        } else {
            run_len = 0;
        }

        // 2. Update scoreboard and select the new winner.
        for j in 0..NUM_WINS {
            if (i >= WINDOWS[j]) && (frequent[j] == di) {
                scoreboard[j] += 1;
                if scoreboard[j] >= scoreboard[winner] {
                    winner = j;
                }
            }
        }

        // 3. Update window counts and select new frequents.
        for j in 0..NUM_WINS {
            if i >= WINDOWS[j] {
                let dropped = data[i - WINDOWS[j]] as usize;
                win_cnts[j][dropped] -= 1;
                win_cnts[j][di] += 1;
                win_poses[j][di] = i as i64;

                if (dropped != frequent[j]) && (max_cnts[j] <= win_cnts[j][di]) {
                    max_cnts[j] = win_cnts[j][di];
                    frequent[j] = di;
                } else if dropped == frequent[j] {
                    max_cnts[j] -= 1;
                    // Search for a possible new frequent (most-recent wins ties).
                    let mut max_pos: i64 = (i - WINDOWS[j]) as i64;
                    for k in 0..alph_size {
                        if (max_cnts[j] < win_cnts[j][k])
                            || ((max_cnts[j] == win_cnts[j][k]) && (max_pos <= win_poses[j][k]))
                        {
                            max_cnts[j] = win_cnts[j][k];
                            frequent[j] = k;
                            max_pos = win_poses[j][k];
                        }
                    }
                }
            }
        }
    }

    MultiMcwEstimate {
        estimate: prediction_estimate(c, n as u64, max_run_len, alph_size as u64),
    }
}

/// Compute the SP 800-90B §6.3.7 MultiMCW prediction min-entropy estimate for
/// the bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The estimator decomposes to the MSB-first bitstring and runs
/// the predictor over the binary alphabet (`k = 2`). The function is
/// **deterministic**: the same `(symbols, bits_per_symbol)` always yields a
/// bit-identical [`MultiMcwEstimate`].
///
/// # Behavior on degenerate input
///
/// Fewer than [`MIN_SAMPLES`] bits returns [`MultiMcwEstimate::unavailable`]
/// (min-entropy `-1.0`, the EA tool's could-not-run sentinel). Never arises for
/// the EA datasets (each has ≥ 1e6 bits).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn multi_mcw(symbols: &[u8], bits_per_symbol: u8) -> MultiMcwEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    // Bitstring track: binary alphabet.
    multi_mcw_core(&bits, 2)
}

/// Compute the §6.3.7 MultiMCW prediction estimate for the **literal track**:
/// the raw symbols over their own (translated) alphabet, mirroring the EA tool's
/// `multi_mcw_test(data.symbols, data.len, data.alph_size, …, "Literal")`.
///
/// The symbols are translated to a dense `0..alph_size` alphabet (see
/// [`crate::dense_alphabet`]) so the per-symbol tables index correctly, then run
/// through the same alphabet-generic [`multi_mcw_core`] as the bitstring track.
/// This is the literal-track input to `H_original`. The function is
/// **deterministic** and does not panic.
#[must_use]
pub fn multi_mcw_literal(symbols: &[u8]) -> MultiMcwEstimate {
    let (dense, alph_size) = crate::dense_alphabet(symbols);
    multi_mcw_core(&dense, alph_size)
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

    fn multi_mcw_of_file(name: &str) -> Option<MultiMcwEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(multi_mcw(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor, Bitstring track (from `selftest/rand8_short.res`):
    /// C = 39756, r = 15 (max_run_len = 14), N = 79937,
    /// min entropy = 0.99453711551450596.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = multi_mcw_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        // Exact integer intermediates.
        assert_eq!(est.estimate.c, 39756, "C");
        assert_eq!(est.estimate.n, 79937, "N");
        assert_eq!(est.estimate.max_run_len, 14, "max_run_len (r = 15)");
        assert!(
            (est.min_entropy() - 0.994_537_115_514_506).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// biased-random-bits anchor, Literal track (1-bit; bsymbols == symbols):
    /// C = 979_925, r = 534 (max_run_len = 533), N = 999_937,
    /// min entropy = 0.028634892142081356.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = multi_mcw_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 979_925, "C");
        assert_eq!(est.estimate.n, 999_937, "N");
        assert_eq!(est.estimate.max_run_len, 533, "max_run_len (r = 534)");
        assert!(
            (est.min_entropy() - 0.028_634_892_142_081_356).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// Literal-track parity: `multi_mcw_literal` matches EA v1.1.8 "Literal
    /// MultiMCW Prediction Estimate: min entropy" to within 1e-6 on every
    /// multi-bit reference dataset (harvested 2026-06-16 via
    /// `ea_non_iid -i -a -v -v <file> <width>`). Skips datasets absent on host.
    #[test]
    fn literal_parity_multibit() {
        // (dataset name, EA "Literal MultiMCW" min entropy).
        const EA_LITERAL_MULTIMCW: &[(&str, f64)] = &[
            ("biased-random-bytes", 0.319_646_253_765_9),
            ("normal", 5.668_174_320_274_3),
            ("rand4_short", 3.866_954_682_482_6),
            ("rand8_short", 7.375_192_249_729_9),
            ("truerand_4bit", 3.992_285_280_721_5),
            ("truerand_8bit", 7.988_579_819_367_0),
        ];
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(name, ea) in EA_LITERAL_MULTIMCW {
            let Some(row) = REFERENCE_TABLE.iter().find(|r| r.name == name) else {
                continue;
            };
            let Ok(data) = std::fs::read(dir.join(row.file)) else {
                eprintln!("{name}.bin absent — skipping literal parity");
                continue;
            };
            let got = multi_mcw_literal(&data).min_entropy();
            assert!(
                (got - ea).abs() <= PARITY_EPS,
                "{name}: literal MultiMCW {got} vs EA {ea} (delta {})",
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
        // Needs >= MIN_SAMPLES bits; 8-bit symbols give 8x the byte count.
        let buf: Vec<u8> = (0..2000u32).map(|i| (i % 19) as u8).collect();
        let a = multi_mcw(&buf, 8);
        let b = multi_mcw(&buf, 8);
        assert_eq!(a, b, "MultiMcwEstimate must be bit-identical across runs");
    }

    /// All-zero bits: every prediction is correct (the frequent is always 0),
    /// so C = N and the run never breaks. The shared formula then yields a very
    /// low (near-zero) min-entropy. Sanity: estimate runs and is finite and small.
    #[test]
    fn all_zeros_is_low_entropy() {
        let buf = vec![0u8; 8192]; // >= MIN_SAMPLES bits at 1 bit/symbol
        let est = multi_mcw(&buf, 1);
        // Every prediction hits: C == N, longest run == N.
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
        let buf = vec![0u8; 100]; // 100 bits at 1 bit/symbol < 4096
        let est = multi_mcw(&buf, 1);
        assert_eq!(est.min_entropy(), -1.0, "too-short returns -1.0 sentinel");
    }
}
