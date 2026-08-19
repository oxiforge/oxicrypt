//! SP 800-90B §6.3.9 **MultiMMC (Multi Markov Model with Counting) prediction**
//! min-entropy estimator (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 MultiMMC predictor (`cpp/non_iid/multi_mmc_test.h`,
//! specifically its `binaryMultiMMCPredictionEstimate` fast path, which is the
//! function the EA tool dispatches to for `alph_size == 2`) bit-for-bit, to
//! within the pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). It is the third of the four §6.3.7–
//! §6.3.10 **prediction** estimators; the shared min-entropy formula they all
//! feed lives in [`crate::prediction`]. Like the rest of `oxicrypt-maxwell` it is
//! **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The MultiMMC predictor (SP 800-90B §6.3.9)
//!
//! `D = 16` sub-predictors. Sub-predictor `d` (`d = 0 ..= 15`) uses a prefix of
//! length `d + 1`: it maps each length-`(d+1)` context (the `d+1` symbols
//! immediately before the symbol being predicted) to a count table over the next
//! symbol, and predicts the most-frequent next symbol for the current context. A
//! scoreboard records how often each sub-predictor has been correct; the current
//! "winner" `d` makes the prediction tested for the run/correct counters. The
//! estimator counts `C` correct predictions out of `N = len − 2` predictions and
//! the longest run `max_run_len` of consecutive correct predictions, then feeds
//! `(C, N, max_run_len, k = 2)` into the shared
//! [`crate::prediction::prediction_estimate`].
//!
//! ## The binary dictionary (matched from `multi_mmc_test.h` /
//! `utils.h::BINARYDICTLOC`)
//!
//! For the binary alphabet, each sub-predictor `d` stores its count tables in one
//! flat array of `1 << (d + 2)` counters: each length-`(d+1)` context `b`
//! addresses a length-2 sub-array at base `(b & ((1 << (d+1)) − 1)) << 1`, whose
//! two slots hold the observed counts of next-symbol `0` and next-symbol `1`. The
//! context is encoded MSB-first into the low `d+1` bits of `b`: when predicting
//! `data[i]`, the EA tool builds `b` so that bit `d` of `b` is `S[i-d-1]` and bit
//! `0` is `S[i-1]` (it ORs `S[i-d-1] << d` into `b` as `d` grows). This module
//! uses `BinaryDict` to reproduce that exact addressing.
//!
//! ## The memory cap (matched from `multi_mmc_test.h`: `MAX_ENTRIES`)
//!
//! Each sub-predictor caps the number of distinct `(context, next-symbol)`
//! entries it will create at `MAX_ENTRIES = 100_000` (`dictElems[d]`). Once a
//! sub-predictor is full, it **stops inserting new entries but keeps incrementing
//! the counts of entries that already exist** — exactly the EA tool's
//! `dictElems[d] < MAX_ENTRIES` guard around every entry creation. The bound is
//! on `(context, next)` pairs, not bare contexts. With the binary datasets here
//! the cap is never reached (`2 * 2^16` distinct pairs at the deepest predictor is
//! far under 100k once you account for which contexts actually occur), but it is
//! transcribed faithfully so the implementation is the predictor, not a
//! data-specific shortcut.
//!
//! ## The tie rule (matched from `binaryMultiMMCPredictionEstimate`)
//!
//! The binary fast path predicts `0` only when its count strictly exceeds the
//! count for `1` (`binaryDictEntry[0] > binaryDictEntry[1]`), so a **tie predicts
//! `1`**. This is consistent with the EA tool's generic `PostfixDictionary`
//! (`in > curPrediction` on a tie → the larger symbol, i.e. `1`, wins).
//!
//! ## The "prefix not seen ⇒ stop deeper predictors" rule
//!
//! When sub-predictor `d`'s context has never been seen as a prefix, it makes no
//! prediction (does not touch the scoreboard) and — because a length-`(d+1)`
//! context that has not occurred implies no longer context has either — all
//! deeper predictors `> d` are skipped for this `i` as well (`found_x` gates the
//! loop). On the first inner iteration `d == 0` always evaluates a prediction.
//!
//! ## Ordering (matched from `binaryMultiMMCPredictionEstimate`)
//!
//! For each index `i` from `2` to `len−1`, capture `cur_winner = winner` then, for
//! `d = 0` while `d < D` and `d <= i − 2`, in this exact order:
//! 1. **Resolve the context** `b` for length `d+1` and look it up.
//! 2. **Predict** (only when `d == 0` or the shorter context was found): the
//!    larger-count next symbol; a zero total means the context was not present
//!    (`found_x = false`).
//! 3. **Score** (only when found): on a correct prediction, `scoreboard[d]++` and
//!    `winner = d` whenever `scoreboard[d] >= scoreboard[winner]`; and **only when
//!    `d == cur_winner`** update `C` / the run counters (a correct hit extends the
//!    run, a miss zeroes it).
//! 4. **Update the dictionary**: increment the `(context, data[i])` count if it
//!    exists; else, if the prefix was found and the cap allows, create it; else, if
//!    the prefix was *not* found and the cap allows, create the `(context,
//!    data[i])` entry (seeding the context).
//!
//! The pre-loop initialization seeds each predictor `d` with the single entry
//! implied by the first `d + 2` samples (`context = S[0..=d]`, `next = S[d+1]`),
//! exactly as the EA tool's init loop does — this is the "different order for the
//! first few symbols" the reference comments call out; once initialized the rest
//! runs in the correct order.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte**. The estimator runs on the
//! **bitstring track**: each symbol is decomposed MSB-first into its
//! `bits_per_symbol` bits (`(symbol >> (w−1−j)) & 1`), exactly as the MCV
//! bitstring track, collision, Markov, compression, t-Tuple, LRS, MultiMCW, and
//! Lag estimators do, and the predictor runs over the binary alphabet (`k = 2`).
//! This is the EA tool's controlling per-bit assessment
//! (`multi_mmc_test(data.bsymbols, data.blen, 2, …)` → the binary fast path); for
//! 1-bit data `bsymbols == symbols`, so the EA tool's "Literal" line for binary
//! data is the same computation. `bits_per_symbol` is clamped into `1..=8`.
//!
//! # The `len <= 3` guard
//!
//! The EA tool asserts `L > 3` for the binary fast path (and the predictor makes
//! `N = L − 2` predictions). This is reproduced as
//! [`MultiMmcEstimate::unavailable`]; it never arises for the EA datasets (each
//! has ≥ 1e6 bits). The init loop additionally reads up to `S[D_MMC]` (index 16),
//! so this module only seeds the predictors it has enough samples for and clamps
//! every dictionary access — no out-of-bounds, no panic, on any input length.

// This module is a 1:1 transcription of the EA reference's
// binaryMultiMMCPredictionEstimate (the alph_size==2 fast path that the bitstring
// track always takes). The dictionary/scoreboard bookkeeping is index- and
// arithmetic-heavy and uses the reference's conventional names (D_MMC,
// MAX_ENTRIES, N, C, scoreboard, winner, curPattern, dictElems, curRunOfCorrects,
// maxRunOfCorrects); faithfulness to the C++ is the priority and the parity oracle
// (<= 1e-6 vs EA on all bundled datasets) is the real correctness gate. This
// module-level allow covers the algorithm-inherent lints uniformly so the
// transcription reads like the reference rather than being restructured to satisfy
// style/restriction lints.
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

/// The number of MultiMMC sub-predictors (`D_MMC` in `multi_mmc_test.h`): prefix
/// lengths `1 ..= 16`.
const D_MMC: usize = 16;

/// Per-sub-predictor cap on the number of distinct `(context, next-symbol)`
/// entries (`MAX_ENTRIES` in `multi_mmc_test.h`). Once a sub-predictor holds this
/// many entries it stops creating new ones but keeps counting existing ones.
const MAX_ENTRIES: i64 = 100_000;

/// Minimum sample count to run the test: the EA tool's binary fast path asserts
/// `L > 3`, i.e. at least 4 samples (`N = L − 2`).
pub const MIN_SAMPLES: usize = 4;

/// One MultiMMC (§6.3.9) prediction min-entropy result over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MultiMmcEstimate {
    /// The shared prediction-estimate intermediates and result (`C`, `N`,
    /// `max_run_len`, `p_global`, `p_global'`, `p_local`, `min_entropy`). `-1.0`
    /// `min_entropy` is the "could not run" sentinel; see [`Self::unavailable`].
    pub estimate: PredictionEstimate,
}

impl MultiMmcEstimate {
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

    /// The per-bit MultiMMC min-entropy in bits (the EA tool's "min entropy"),
    /// or `-1.0` when the estimate could not run.
    #[must_use]
    pub const fn min_entropy(&self) -> f64 {
        self.estimate.min_entropy
    }
}

/// One sub-predictor's binary count dictionary, reproducing the EA tool's
/// `binaryDict[d]` flat array plus its `BINARYDICTLOC` addressing.
///
/// Sub-predictor `d` (`prefix_len = d + 1`) stores `1 << (d + 2)` counters. A
/// length-`(d+1)` context `b` addresses the length-2 sub-array whose base index is
/// `(b & ((1 << (d+1)) − 1)) << 1`; slot `+0` counts next-symbol `0`, slot `+1`
/// counts next-symbol `1`. Counts are `i64` to mirror the EA tool's `long`.
struct BinaryDict {
    /// Flat counter array; length `1 << (prefix_len + 1) == 1 << (d + 2)`.
    counts: Vec<i64>,
    /// Mask `(1 << prefix_len) − 1` applied to a context before addressing.
    mask: u32,
}

impl BinaryDict {
    /// Allocate the dictionary for prefix length `prefix_len` (`= d + 1`), all
    /// counts zero.
    fn new(prefix_len: u32) -> Self {
        // 1 << (prefix_len + 1) total counters (2 per context). prefix_len is in
        // 1..=16, so this is at most 1 << 17 = 131072 — well within usize.
        let size = 1usize << (prefix_len + 1);
        Self {
            counts: vec![0i64; size],
            mask: (1u32 << prefix_len) - 1,
        }
    }

    /// Base index of the length-2 sub-array for context `b` (the `BINARYDICTLOC`
    /// computation `((b & mask) << 1)`).
    fn base(&self, b: u32) -> usize {
        ((b & self.mask) << 1) as usize
    }

    /// Count recorded for `next` (`0` or `1`) after context `b`.
    fn get(&self, b: u32, next: u8) -> i64 {
        self.counts[self.base(b) + (next & 1) as usize]
    }

    /// Increment the `(b, next)` count by one.
    fn incr(&mut self, b: u32, next: u8) {
        let idx = self.base(b) + (next & 1) as usize;
        self.counts[idx] += 1;
    }

    /// Set the `(b, next)` count to one (used when creating a fresh entry).
    fn set_one(&mut self, b: u32, next: u8) {
        let idx = self.base(b) + (next & 1) as usize;
        self.counts[idx] = 1;
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

/// Run the §6.3.9 MultiMMC binary predictor over a bit slice `data`, transcribing
/// `binaryMultiMMCPredictionEstimate`.
///
/// `data` holds bit values (`0`/`1`, one per element). Returns the shared
/// prediction estimate, or [`MultiMmcEstimate::unavailable`] when there are fewer
/// than [`MIN_SAMPLES`] samples.
///
/// The function is deterministic and does not panic (all dictionary indices are
/// bounded by construction and the init loop only seeds predictors it has samples
/// for).
fn multi_mmc_core(data: &[u8]) -> MultiMmcEstimate {
    let len = data.len();
    if len < MIN_SAMPLES {
        return MultiMmcEstimate::unavailable();
    }

    // N = L - 2 predictions (the first two samples seed history / make no
    // counted prediction).
    let n = (len - 2) as u64;

    // One count dictionary per sub-predictor d (prefix length d+1).
    let mut dict: Vec<BinaryDict> = (0..D_MMC)
        .map(|d| BinaryDict::new((d + 1) as u32))
        .collect();
    let mut dict_elems: [i64; D_MMC] = [0; D_MMC];
    let mut scoreboard: [i64; D_MMC] = [0; D_MMC];
    let mut winner: usize = 0;

    let mut correct_count: u64 = 0;
    let mut cur_run: u64 = 0;
    let mut max_run: u64 = 0;

    // --- Initialize the predictors (EA tool's init loop). ---
    // For predictor d, the context is S[0..=d] (encoded MSB-first into the low
    // d+1 bits) and the seeded next-symbol is S[d+1]. The EA tool builds
    // curPattern cumulatively as (curPattern << 1) | (S[d] & 1) over d = 0..D_MMC,
    // so after step d the low d+1 bits hold S[0..=d] with S[0] in the MSB. It
    // accesses S[d+1], so predictor d can only be seeded when d + 1 < len.
    {
        let mut cur_pattern: u32 = 0;
        for d in 0..D_MMC {
            // The shift consumes data[d]; the seed consumes data[d+1]. Stop once
            // either is out of range (the EA tool relies on L being huge and never
            // hits this; we clamp so short inputs cannot panic). Seeding predictor
            // d needs both data[d] (for this context bit) and data[d+1] (the
            // next-symbol), i.e. d + 1 < len.
            if d + 1 >= len {
                break;
            }
            cur_pattern = (cur_pattern << 1) | u32::from(data[d] & 1);
            dict[d].set_one(cur_pattern, data[d + 1]);
            dict_elems[d] = 1;
        }
    }

    // --- Perform predictions. i is the index of the new symbol to predict. ---
    for i in 2..len {
        let mut found_x = false;
        let cur_winner = winner;
        let mut cur_pattern: u32 = 0;
        let cur = data[i];

        // d+1 is the number of symbols used by the predictor; bounded by both
        // D_MMC and how much history exists (d <= i - 2).
        let d_max = D_MMC.min(i - 1); // d in 0..d_max  <=>  d <= i-2
        for d in 0..d_max {
            // Prepend S[i-d-1] at bit position d: after this, the low d+1 bits of
            // cur_pattern hold the context (S[i-d-1] ... S[i-1]) with S[i-d-1] in
            // the MSB, matching the EA tool's `curPattern |= (S[i-d-1]&1) << d`.
            cur_pattern |= u32::from(data[i - d - 1] & 1) << d;

            let mut cur_prediction: u8 = 2; // sentinel "no prediction"

            // Only predict on the first round (d==0) or when the shorter prefix
            // was found; otherwise this and all deeper predictors are skipped.
            if d == 0 || found_x {
                let c0 = dict[d].get(cur_pattern, 0);
                let c1 = dict[d].get(cur_pattern, 1);
                // Tie predicts 1 (the `else` branch): predict 0 only when c0 > c1.
                let cur_count = if c0 > c1 {
                    cur_prediction = 0;
                    c0
                } else {
                    cur_prediction = 1;
                    c1
                };
                found_x = cur_count != 0;
            }

            if found_x {
                // The context is present. Check whether the prediction is correct.
                if cur_prediction == cur {
                    scoreboard[d] += 1;
                    if scoreboard[d] >= scoreboard[winner] {
                        winner = d;
                    }
                    if d == cur_winner {
                        correct_count += 1;
                        cur_run += 1;
                        if cur_run > max_run {
                            max_run = cur_run;
                        }
                    }
                } else if d == cur_winner {
                    // Wrong prediction by the previous best predictor — reset run.
                    cur_run = 0;
                }

                // Count (context, cur) or, if new and the cap allows, add it.
                if dict[d].get(cur_pattern, cur) != 0 {
                    dict[d].incr(cur_pattern, cur);
                } else if dict_elems[d] < MAX_ENTRIES {
                    dict[d].set_one(cur_pattern, cur);
                    dict_elems[d] += 1;
                }
            } else if dict_elems[d] < MAX_ENTRIES {
                // The context prefix was not found, so (context, cur) can't have
                // occurred; create it if the cap allows.
                dict[d].set_one(cur_pattern, cur);
                dict_elems[d] += 1;
            }
        }
    }

    MultiMmcEstimate {
        estimate: prediction_estimate(correct_count, n, max_run, 2),
    }
}

/// One sub-predictor's general-alphabet postfix dictionary for a single context,
/// reproducing the EA tool's `PostfixDictionary` (`utils.h`).
///
/// Maps each observed next-symbol to its count and caches the current argmax
/// (`best_count`) and the predicted symbol (`prediction`). The tie rule matches
/// the EA tool exactly: on `(count == best_count)`, the **larger symbol value**
/// wins (`in > curPrediction`). A `BTreeMap<u8, i64>` mirrors `map<uint8_t, long>`
/// (the count update / membership semantics are independent of iteration order,
/// but a `BTreeMap` keeps behavior deterministic and matches the C++ container's
/// element type).
struct PostfixDict {
    /// Per-next-symbol counts (`map<uint8_t, long> postfixes`).
    postfixes: std::collections::BTreeMap<u8, i64>,
    /// Cached argmax count (`curBest`); `0` until the first increment.
    best_count: i64,
    /// Cached predicted next-symbol (`curPrediction`); `0` until the first
    /// increment (matching the EA tool's `curPrediction = 0` constructor).
    prediction: u8,
}

impl PostfixDict {
    /// A fresh dictionary, matching `PostfixDictionary() { curBest = 0;
    /// curPrediction = 0; }`.
    fn new() -> Self {
        Self {
            postfixes: std::collections::BTreeMap::new(),
            best_count: 0,
            prediction: 0,
        }
    }

    /// The argmax-count next-symbol, matching `predict(&count)`. The EA tool
    /// asserts `curBest > 0` here; this is only ever called after a `found_x`
    /// lookup that implies at least one increment, so `best_count > 0` holds.
    fn predict(&self) -> u8 {
        self.prediction
    }

    /// Increment the count for next-symbol `in_sym`, creating the entry when it is
    /// absent only if `make_new`. Returns `true` iff a new entry was created.
    /// Updates the cached argmax on every increment, with the EA tool's tie rule
    /// (`(curCount == curBest) && (in > curPrediction)` → the larger symbol wins).
    /// Mirrors `incrementPostfix(in, makeNew)`.
    fn increment_postfix(&mut self, in_sym: u8, make_new: bool) -> bool {
        let cur_count;
        let mut new_entry = false;
        if let Some(slot) = self.postfixes.get_mut(&in_sym) {
            // Entry present: always increment.
            *slot += 1;
            cur_count = *slot;
        } else if make_new {
            // Entry absent but creation allowed.
            new_entry = true;
            self.postfixes.insert(in_sym, 1);
            cur_count = 1;
        } else {
            // Entry absent and creation disallowed: no change.
            return false;
        }

        if (cur_count > self.best_count)
            || ((cur_count == self.best_count) && (in_sym > self.prediction))
        {
            self.prediction = in_sym;
            self.best_count = cur_count;
        }

        new_entry
    }
}

/// Run the §6.3.9 MultiMMC predictor over a general-alphabet symbol slice `data`,
/// transcribing the `alph_size != 2` general path of `multi_mmc_test`.
///
/// `data` holds dense symbol values in `0..alph_size` (one per element).
/// Sub-predictor `d` (prefix length `d + 1`) keys a `BTreeMap` on the `d + 1`
/// context symbols (`data[i-d-1..=i-1]` as a `Vec<u8>`) to a [`PostfixDict`] over
/// the next symbol. Returns the shared prediction estimate, or
/// [`MultiMmcEstimate::unavailable`] when there are fewer than [`MIN_SAMPLES`]
/// samples. The final estimate is `prediction_estimate(C, N = len − 2,
/// max_run_len, alph_size)`, exactly like the binary core.
///
/// The function is deterministic and does not panic.
fn multi_mmc_core_general(data: &[u8], alph_size: usize) -> MultiMmcEstimate {
    use std::collections::BTreeMap;

    let len = data.len();
    if len < MIN_SAMPLES {
        return MultiMmcEstimate::unavailable();
    }

    // N = len - 2.
    let n = (len - 2) as u64;

    // M[d] maps a length-(d+1) context (Vec<u8>) to its PostfixDict.
    let mut m: Vec<BTreeMap<Vec<u8>, PostfixDict>> = (0..D_MMC).map(|_| BTreeMap::new()).collect();
    let mut entries: [i64; D_MMC] = [0; D_MMC];
    let mut scoreboard: [i64; D_MMC] = [0; D_MMC];
    let mut winner: usize = 0;

    let mut correct_count: u64 = 0;
    let mut run_len: u64 = 0;
    let mut max_run_len: u64 = 0;

    // --- Initialize MMC counts (step 4.a/4.b for the () case). ---
    // For predictor d (when d < N), context = data[0..=d] and seeded next =
    // data[d+1]. The EA tool guards with `if(d < N)` (N = len-2), which is exactly
    // when data[d+1] is in range (d+1 <= len-2 < len).
    for d in 0..D_MMC {
        if (d as u64) < n {
            let key: Vec<u8> = data[0..=d].to_vec();
            m[d].entry(key)
                .or_insert_with(PostfixDict::new)
                .increment_postfix(data[d + 1], true);
            entries[d] = 1;
        }
    }

    // --- Perform predictions. i is the index of the new symbol to predict. ---
    for i in 2..len {
        let mut found_x = false;
        let cur_winner = winner;
        let cur = data[i];

        // d in 0..D_MMC while (i - 2 >= d), i.e. d <= i - 2.
        let d_max = D_MMC.min(i - 1);
        for d in 0..d_max {
            // The length-(d+1) context (data[i-d-1] ... data[i-1]).
            // Only resolve / predict on the first round (d==0) or when the shorter
            // context was found; otherwise this and all deeper predictors skip.
            let mut prediction: u8 = 0;
            if d == 0 || found_x {
                let key: Vec<u8> = data[i - d - 1..i].to_vec();
                if let Some(pd) = m[d].get(&key) {
                    found_x = true;
                    prediction = pd.predict();
                } else {
                    found_x = false;
                }
            }

            if found_x {
                // The context occurred. Check the prediction; update scoreboard /
                // winner and (when d == cur_winner) the run counters.
                if prediction == cur {
                    scoreboard[d] += 1;
                    if scoreboard[d] >= scoreboard[winner] {
                        winner = d;
                    }
                    if d == cur_winner {
                        correct_count += 1;
                        run_len += 1;
                        if run_len > max_run_len {
                            max_run_len = run_len;
                        }
                    }
                } else if d == cur_winner {
                    run_len = 0;
                }

                // Increment (context, cur); create only if the cap allows.
                let key: Vec<u8> = data[i - d - 1..i].to_vec();
                if let Some(pd) = m[d].get_mut(&key)
                    && pd.increment_postfix(cur, entries[d] < MAX_ENTRIES)
                {
                    entries[d] += 1;
                }
            } else if entries[d] < MAX_ENTRIES {
                // The context prefix was not found; create the (context, cur)
                // entry (seeding the context) if the cap allows.
                let key: Vec<u8> = data[i - d - 1..i].to_vec();
                m[d].entry(key)
                    .or_insert_with(PostfixDict::new)
                    .increment_postfix(cur, true);
                entries[d] += 1;
            }
        }
    }

    MultiMmcEstimate {
        estimate: prediction_estimate(correct_count, n, max_run_len, alph_size as u64),
    }
}

/// Compute the §6.3.9 MultiMMC prediction estimate for the **literal track**: the
/// raw symbols over their own (translated) alphabet, mirroring the EA tool's
/// `multi_mmc_test(data.symbols, data.len, data.alph_size, …, "Literal")`.
///
/// The symbols are translated to a dense `0..alph_size` alphabet via the shared
/// `crate::value_sorted_alphabet` — MultiMMC's value-sensitive tie rule requires
/// the EA tool's ascending-value mapping rather than the first-seen
/// `crate::dense_alphabet` (LZ78Y shares this requirement and the same helper). A
/// binary alphabet (`alph_size <= 2`) routes through the binary fast path
/// `multi_mmc_core` (the EA tool's `alph_size == 2` branch); larger alphabets use
/// `multi_mmc_core_general`. This is the literal-track input to `H_original`. The
/// function is **deterministic** and does not panic.
#[must_use]
pub fn multimmc_literal(symbols: &[u8]) -> MultiMmcEstimate {
    let (dense, alph) = crate::value_sorted_alphabet(symbols);
    if alph <= 2 {
        multi_mmc_core(&dense)
    } else {
        multi_mmc_core_general(&dense, alph)
    }
}

/// Compute the SP 800-90B §6.3.9 MultiMMC prediction min-entropy estimate for the
/// bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The estimator decomposes to the MSB-first bitstring and runs the
/// predictor over the binary alphabet (`k = 2`). The function is
/// **deterministic**: the same `(symbols, bits_per_symbol)` always yields a
/// bit-identical [`MultiMmcEstimate`].
///
/// # Behavior on degenerate input
///
/// Fewer than [`MIN_SAMPLES`] bits returns [`MultiMmcEstimate::unavailable`]
/// (min-entropy `-1.0`, the EA tool's could-not-run sentinel). Never arises for
/// the EA datasets (each has ≥ 1e6 bits).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn multi_mmc(symbols: &[u8], bits_per_symbol: u8) -> MultiMmcEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    // Bitstring track: binary alphabet.
    multi_mmc_core(&bits)
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

    fn multi_mmc_of_file(name: &str) -> Option<MultiMmcEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(multi_mmc(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor, Bitstring track (EA `-v -v`): C = 39974, r = 15
    /// (max_run_len = 14), N = 79998, min entropy = 0.98781454404229407.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = multi_mmc_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 39974, "C");
        assert_eq!(est.estimate.n, 79998, "N");
        assert_eq!(est.estimate.max_run_len, 14, "max_run_len (r = 15)");
        assert!(
            (est.min_entropy() - 0.987_814_544_042_294_1).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// biased-random-bits anchor, Literal track (1-bit; bsymbols == symbols):
    /// C = 979985, r = 534 (max_run_len = 533), N = 999998,
    /// min entropy = 0.02863458625634421.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = multi_mmc_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 979_985, "C");
        assert_eq!(est.estimate.n, 999_998, "N");
        assert_eq!(est.estimate.max_run_len, 533, "max_run_len (r = 534)");
        assert!(
            (est.min_entropy() - 0.028_634_586_256_344_21).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// Literal-track parity: `multimmc_literal` matches EA v1.1.8 "Literal
    /// MultiMMC Prediction Estimate: min entropy" to within 1e-6 on every
    /// multi-bit reference dataset. Skips datasets absent on host.
    #[test]
    fn literal_parity_multibit() {
        // (dataset name, EA "Literal MultiMMC" min entropy).
        const EA_LITERAL_MULTIMMC: &[(&str, f64)] = &[
            ("biased-random-bytes", 0.320_276_876_685_1),
            ("normal", 5.675_758_441_025_9),
            ("rand4_short", 3.884_655_279_493_4),
            ("rand8_short", 7.327_627_679_188_1),
            ("truerand_4bit", 3.985_262_644_080_8),
            ("truerand_8bit", 7.926_808_819_751_7),
        ];
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(name, ea) in EA_LITERAL_MULTIMMC {
            let Some(row) = REFERENCE_TABLE.iter().find(|r| r.name == name) else {
                continue;
            };
            let Ok(data) = std::fs::read(dir.join(row.file)) else {
                eprintln!("{name}.bin absent — skipping literal parity");
                continue;
            };
            let got = multimmc_literal(&data).min_entropy();
            assert!(
                (got - ea).abs() <= PARITY_EPS,
                "{name}: literal MultiMMC {got} vs EA {ea} (delta {})",
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
        let a = multi_mmc(&buf, 8);
        let b = multi_mmc(&buf, 8);
        assert_eq!(a, b, "MultiMmcEstimate must be bit-identical across runs");
    }

    /// All-zero bits: every context is all-zeros and the next symbol is always 0,
    /// so once seeded each predictor always predicts correctly. C should equal N
    /// and the run never breaks, giving a very low (near-zero) min-entropy.
    #[test]
    fn all_zeros_is_low_entropy() {
        let buf = vec![0u8; 8192];
        let est = multi_mmc(&buf, 1);
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
        let buf = vec![0u8; 3]; // 3 bits at 1 bit/symbol < MIN_SAMPLES
        let est = multi_mmc(&buf, 1);
        assert_eq!(est.min_entropy(), -1.0, "too-short returns -1.0 sentinel");
    }

    /// Minimum-length input (exactly MIN_SAMPLES bits) runs without panic: this
    /// exercises the init loop's short-input clamping (it would otherwise read
    /// past the end seeding deeper predictors).
    #[test]
    fn min_length_input_no_panic() {
        let buf = vec![0u8, 1, 0, 1]; // exactly 4 bits at 1 bit/symbol
        let est = multi_mmc(&buf, 1);
        // N = len - 2 = 2 predictions; estimate runs (min_entropy >= 0).
        assert_eq!(est.estimate.n, 2, "N = len - 2");
        assert!(est.min_entropy() >= 0.0 && est.min_entropy().is_finite());
    }
}
