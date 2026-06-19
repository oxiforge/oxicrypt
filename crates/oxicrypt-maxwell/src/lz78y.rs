//! SP 800-90B §6.3.10 **LZ78Y prediction** min-entropy estimator (bitstring
//! track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 LZ78Y predictor (`cpp/non_iid/lz78y_test.h`, specifically
//! its `binaryLZ78YPredictionEstimate` fast path, which is the function the EA
//! tool dispatches to for `alph_size == 2`) bit-for-bit, to within the
//! pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). It is the last of the four §6.3.7–
//! §6.3.10 **prediction** estimators and completes the SP 800-90B §6.3 non-IID
//! estimator suite; the shared min-entropy formula they all feed lives in
//! [`crate::prediction`]. Like the rest of `oxicrypt-maxwell` it is **outside the
//! cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The LZ78Y predictor (SP 800-90B §6.3.10)
//!
//! `B = 16` ([`B_LEN`], the EA tool's `B_len`) is the longest context the
//! predictor ever uses. For each symbol `S[i]` (`i = B + 1 ..< L`), the predictor
//! holds, for every prefix length `m = 1 ..= B`, a dictionary keyed by the
//! length-`m` context `(S[i-m] … S[i-1])` immediately preceding `S[i]`; each
//! dictionary entry counts how often each next-symbol followed that context. The
//! prediction for step `i` is the next-symbol with the **single highest count
//! across all prefix lengths** (ties resolved by the EA tool's iteration order,
//! see below). After the prediction is chosen, every context that is present has
//! its `(context, S[i])` count incremented (and absent contexts may be created,
//! subject to the cap). Over the `N = L − B − 1` predictions the estimator counts
//! `C` correct predictions and the longest run `max_run_len` of consecutive
//! correct predictions, then feeds `(C, N, max_run_len, k = 2)` into the shared
//! [`crate::prediction::prediction_estimate`].
//!
//! Unlike MultiMMC (§6.3.9) the LZ78Y predictor has **no scoreboard / winner**:
//! it does not track which prefix length has historically been best. Its single
//! prediction per step is simply the highest-count `(context, next)` pair seen
//! over all `B` prefix lengths at this step, and correctness is scored once per
//! step (not per prefix length).
//!
//! ## The binary dictionary (matched from `lz78y_test.h` /
//! `utils.h::BINARYDICTLOC`)
//!
//! For the binary alphabet, the dictionary for prefix length `m` (`m = 1 ..= B`)
//! is one flat array of `1 << (m + 1)` counters: each length-`m` context `b`
//! addresses a length-2 sub-array at base `(b & ((1 << m) − 1)) << 1`, whose two
//! slots hold the observed counts of next-symbol `0` and next-symbol `1`. The EA
//! tool stores these as `binaryDict[m-1]` (a 0-indexed array of `B` pointers) and
//! addresses them with `BINARYDICTLOC(m, b)`; this module uses one
//! [`BinaryDict`] per prefix length to reproduce that addressing exactly.
//!
//! The per-step context is encoded by the EA tool's `compressedBitSymbols`: it
//! packs the `B` bits `S[i-B] … S[i-1]` MSB-first into `curPattern` (so `S[i-B]`
//! is the most-significant bit, `S[i-1]` the least). For prefix length `m`, the
//! EA tool then masks `curPattern` to its low `m` bits (`curPattern & ((1<<m)−1)`),
//! which is exactly the length-`m` tuple `(S[i-m] … S[i-1])`. This module computes
//! the same packed pattern once per step and masks per prefix length identically.
//!
//! ## The memory cap (matched from `lz78y_test.h`: `MAX_DICTIONARY_SIZE`)
//!
//! A **single shared** counter `dict_elems` (the EA tool's `dictElems`) bounds the
//! total number of distinct `(prefix-length, context)` entries created across
//! **all** prefix lengths at `MAX_DICTIONARY_SIZE = 65536` ([`MAX_DICTIONARY_SIZE`],
//! the EA tool's `MAX_DICTIONARY_SIZE`). Once the dictionary is full it **stops
//! creating new entries but keeps incrementing the counts of entries that already
//! exist** — exactly the EA tool's `dictElems < MAX_DICTIONARY_SIZE` guard around
//! every entry creation. This is one global cap, **not** a per-prefix-length cap
//! (the distinction from MultiMMC's per-sub-predictor `MAX_ENTRIES`). The init
//! loop seeds `B` entries, so `dict_elems` starts at `B = 16`. Because an entry is
//! created (`= 1`) whenever a context is first encountered as a prefix, the cap
//! genuinely bites on the EA datasets — once `dict_elems` reaches 65536 only the
//! already-known contexts keep counting, which is part of the predictor's
//! behavior, not a data-specific shortcut.
//!
//! ## The prediction rule and tie-breaking (matched from
//! `binaryLZ78YPredictionEstimate`)
//!
//! For each prefix length `m` (the EA tool iterates `j = B` **down to** `1`), the
//! per-prefix candidate is the larger-count next symbol for that context: the EA
//! tool's `binaryDictEntry[0] > binaryDictEntry[1]` predicts `0`, else `1`, so a
//! **per-prefix tie predicts `1`**. The step's prediction is the candidate with
//! the **strictly greatest** count across prefix lengths (`curCount > maxCount`).
//! Because the iteration runs from the longest prefix (`m = B`) down to the
//! shortest (`m = 1`), and the update is strict (`>`, not `>=`), when two prefix
//! lengths tie on count the **longer** one wins (it is visited first and a later
//! equal count does not displace it). A prefix length whose context has never been
//! seen (`curCount == 0`, i.e. both slots zero) contributes no candidate and is
//! skipped, but — unlike MultiMMC — this does **not** stop shorter prefixes: every
//! prefix length `m = B ..= 1` is examined every step.
//!
//! ## Ordering (matched from `binaryLZ78YPredictionEstimate`)
//!
//! For each index `i` from `B + 1` to `L − 1`:
//! 1. **Pack the context** `curPattern = compressedBitSymbols(S[i-B .. i])`.
//! 2. For `m = B` down to `1`, in this exact order:
//!    a. Mask `curPattern` to its low `m` bits and look up `(count0, count1)`.
//!    b. The per-prefix candidate is `0` when `count0 > count1`, else `1`; its
//!       count is the corresponding slot. `found_x` is true iff that count is
//!       nonzero.
//!    c. If `found_x` and the count strictly exceeds the running `max_count`,
//!       adopt this candidate as the step prediction.
//!    d. **Update**: if `found_x`, increment the `(context, S[i])` count; else, if
//!       the shared cap allows, create the `(context, S[i])` entry (`= 1`) and bump
//!       `dict_elems`.
//! 3. After the prefix loop, score **once**: if a prediction was made and equals
//!    `S[i]`, increment `C` and extend the current run (updating `max_run_len`);
//!    otherwise zero the current run.
//!
//! The pre-loop initialization seeds, for each prefix length `m = 1 ..= B`, the
//! single entry `(context = S[B-m .. B], next = S[B])` implied by the first
//! `B + 1` samples, exactly as the EA tool's init loop does, and sets
//! `dict_elems = B`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte**. The estimator runs on the
//! **bitstring track**: each symbol is decomposed MSB-first into its
//! `bits_per_symbol` bits (`(symbol >> (w−1−j)) & 1`), exactly as the MCV
//! bitstring track and every other §6.3 estimator does, and the predictor runs
//! over the binary alphabet (`k = 2`). This is the EA tool's controlling per-bit
//! assessment (`LZ78Y_test(data.bsymbols, data.blen, 2, …)` → the binary fast
//! path); for 1-bit data `bsymbols == symbols`, so the EA tool's "Literal" line
//! for binary data is the same computation. `bits_per_symbol` is clamped into
//! `1..=8`.
//!
//! # The `len <= B + 2` guard
//!
//! The EA tool asserts `L > B_len` and `L − B_len > 2` for the binary fast path
//! (the predictor makes `N = L − B − 1` predictions). This is reproduced as
//! [`Lz78yEstimate::unavailable`]; it never arises for the EA datasets (each has
//! ≥ 1e6 bits). The init loop reads up to `S[B]` (index 16), so this module only
//! seeds the predictors it has enough samples for and clamps every dictionary
//! access — no out-of-bounds, no panic, on any input length.

// This module is a 1:1 transcription of the EA reference's
// binaryLZ78YPredictionEstimate (the alph_size==2 fast path that the bitstring
// track always takes). The dictionary bookkeeping is index- and arithmetic-heavy
// and uses the reference's conventional names (B_len, MAX_DICTIONARY_SIZE, N, C,
// curPattern, dictElems, curRunOfCorrects, maxRunOfCorrects, maxCount); fidelity
// to the C++ is the priority and the parity oracle (<= 1e-6 vs EA on all bundled
// datasets) is the real correctness gate. This module-level allow covers the
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
    clippy::cast_possible_wrap,
    // The module doc transcribes the EA reference's nested lettered sub-steps
    // (a/b/c/d under step 2); the wrapped-line indentation that reads cleanly
    // here trips the doc-list-indent style lint.
    clippy::doc_overindented_list_items
)]

use crate::prediction::{PredictionEstimate, prediction_estimate};

/// The longest context length the LZ78Y predictor uses (`B_len` in
/// `lz78y_test.h`): prefix lengths `1 ..= 16`.
const B_LEN: usize = 16;

/// Shared cap on the total number of distinct `(prefix-length, context)` entries
/// across **all** prefix lengths (`MAX_DICTIONARY_SIZE` in `lz78y_test.h`). Once
/// the dictionary holds this many entries it stops creating new ones but keeps
/// counting existing ones. Unlike MultiMMC's per-sub-predictor cap, this is one
/// global counter.
const MAX_DICTIONARY_SIZE: i64 = 65536;

/// Minimum sample count to run the test: the EA tool's binary fast path asserts
/// `L > B_len` and `L − B_len > 2`, i.e. at least `B_len + 3` samples
/// (`N = L − B_len − 1`).
pub const MIN_SAMPLES: usize = B_LEN + 3;

/// One LZ78Y (§6.3.10) prediction min-entropy result over the bitstring track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Lz78yEstimate {
    /// The shared prediction-estimate intermediates and result (`C`, `N`,
    /// `max_run_len`, `p_global`, `p_global'`, `p_local`, `min_entropy`). `-1.0`
    /// `min_entropy` is the "could not run" sentinel; see [`Self::unavailable`].
    pub estimate: PredictionEstimate,
}

impl Lz78yEstimate {
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

    /// The per-bit LZ78Y min-entropy in bits (the EA tool's "min entropy"), or
    /// `-1.0` when the estimate could not run.
    #[must_use]
    pub const fn min_entropy(&self) -> f64 {
        self.estimate.min_entropy
    }
}

/// One prefix length's binary count dictionary, reproducing the EA tool's
/// `binaryDict[m-1]` flat array plus its `BINARYDICTLOC` addressing.
///
/// Prefix length `m` stores `1 << (m + 1)` counters. A length-`m` context `b`
/// addresses the length-2 sub-array whose base index is `(b & ((1 << m) − 1)) << 1`;
/// slot `+0` counts next-symbol `0`, slot `+1` counts next-symbol `1`. Counts are
/// `i64` to mirror the EA tool's `long`.
struct BinaryDict {
    /// Flat counter array; length `1 << (prefix_len + 1)`.
    counts: Vec<i64>,
    /// Mask `(1 << prefix_len) − 1` applied to a context before addressing.
    mask: u32,
}

impl BinaryDict {
    /// Allocate the dictionary for prefix length `prefix_len` (`= m`, in
    /// `1..=16`), all counts zero.
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

    /// True when context `b` has been seen at all (either next-symbol count is
    /// nonzero) — the EA tool's "is this an existing entry?" predicate, which it
    /// derives in-line from `curCount != 0` after picking the larger slot. The
    /// core loop inlines that predicate (matching the reference); this helper
    /// names it for the test that documents the dictionary's addressing.
    #[cfg(test)]
    fn context_seen(&self, b: u32) -> bool {
        let base = self.base(b);
        self.counts[base] != 0 || self.counts[base + 1] != 0
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

/// Pack `B_LEN` bits `data[start .. start + B_LEN]` MSB-first into a `u32`,
/// reproducing the EA tool's `compressedBitSymbols(S, B_len)`: `data[start]` is
/// the most-significant bit, `data[start + B_LEN - 1]` the least.
///
/// The caller guarantees `start + B_LEN <= data.len()`.
fn compressed_bit_symbols(data: &[u8], start: usize) -> u32 {
    let mut pattern: u32 = 0;
    for j in 0..B_LEN {
        pattern = (pattern << 1) | u32::from(data[start + j] & 1);
    }
    pattern
}

/// Run the §6.3.10 LZ78Y binary predictor over a bit slice `data`, transcribing
/// `binaryLZ78YPredictionEstimate`.
///
/// `data` holds bit values (`0`/`1`, one per element). Returns the shared
/// prediction estimate, or [`Lz78yEstimate::unavailable`] when there are fewer
/// than [`MIN_SAMPLES`] samples.
///
/// The function is deterministic and does not panic (all dictionary indices are
/// bounded by construction and the init loop only seeds prefixes it has samples
/// for).
fn lz78y_core(data: &[u8]) -> Lz78yEstimate {
    let len = data.len();
    if len < MIN_SAMPLES {
        return Lz78yEstimate::unavailable();
    }

    // N = L - B_len - 1 predictions (the first B_len+1 samples seed history).
    let n = (len - B_LEN - 1) as u64;

    // One count dictionary per prefix length m (m = 1..=B_LEN), stored at
    // index m-1 to mirror binaryDict[m-1].
    let mut dict: Vec<BinaryDict> = (1..=B_LEN).map(|m| BinaryDict::new(m as u32)).collect();
    // Single shared entry counter across ALL prefix lengths (EA: dictElems).
    let mut dict_elems: i64 = 0;

    let mut correct_count: u64 = 0;
    let mut cur_run: u64 = 0;
    let mut max_run: u64 = 0;

    // --- Initialize the dictionary (EA tool's init loop). ---
    // For prefix length m = j+1 (j = 0..B_LEN-1), the EA tool builds curPattern
    // as `curPattern |= (S[B_len-j-1]&1) << j`, then seeds
    // BINARYDICTLOC(j+1, curPattern)[S[B_len]&1] = 1, dictElems++. After step j
    // the low j+1 bits hold the context (S[B_len-j-1] ... S[B_len-1]) with
    // S[B_len-j-1] in the MSB. The seed next-symbol is S[B_len].
    {
        let mut cur_pattern: u32 = 0;
        let next = data[B_LEN]; // S[B_len]; len >= B_LEN + 3 guarantees this index.
        for j in 0..B_LEN {
            // Prepend S[B_len-j-1] at bit position j.
            cur_pattern |= u32::from(data[B_LEN - j - 1] & 1) << j;
            // Prefix length m = j + 1 -> dict index j.
            dict[j].set_one(cur_pattern, next);
            dict_elems += 1;
        }
    }

    // --- Perform predictions. i is the index of the new symbol to predict. ---
    for i in (B_LEN + 1)..len {
        let cur = data[i];
        let mut have_prediction = false;
        let mut prediction: u8 = 2; // sentinel "no prediction"
        let mut max_count: i64 = 0;

        // Pack the B_len-bit context S[i-B_len .. i] once, MSB-first.
        let packed = compressed_bit_symbols(data, i - B_LEN);

        // j is the prefix length, iterated from B_len down to 1 (so the LONGEST
        // prefix is visited first and wins ties under the strict `>` update).
        for j in (1..=B_LEN).rev() {
            let m = j; // prefix length
            // Mask the packed pattern to its low m bits: the m-tuple
            // (S[i-m] ... S[i-1]). The BinaryDict's own mask is identical, but we
            // mask here too so `context_seen` / addressing use the same value the
            // EA tool's `curPattern &= (1<<j)-1` produces.
            let ctx = packed & ((1u32 << m) - 1);
            let d = &mut dict[m - 1];

            // Per-prefix candidate: larger-count next symbol; a per-prefix tie
            // predicts 1 (predict 0 only when count0 > count1).
            let c0 = d.get(ctx, 0);
            let c1 = d.get(ctx, 1);
            let (round_prediction, cur_count) = if c0 > c1 { (0u8, c0) } else { (1u8, c1) };
            let found_x = cur_count != 0;

            if found_x {
                // The context is present. Strictly-greater count adopts it as the
                // step prediction (so longer prefixes win count ties).
                if cur_count > max_count {
                    max_count = cur_count;
                    have_prediction = true;
                    prediction = round_prediction;
                }
                // x exists as a prefix, so always increment (context, cur).
                d.incr(ctx, cur);
            } else if dict_elems < MAX_DICTIONARY_SIZE {
                // The prefix was not found, so (context, cur) can't have occurred;
                // create it if the SHARED cap allows.
                d.set_one(ctx, cur);
                dict_elems += 1;
            }
        }

        // Score ONCE per step (not per prefix length).
        if have_prediction && prediction == cur {
            correct_count += 1;
            cur_run += 1;
            if cur_run > max_run {
                max_run = cur_run;
            }
        } else {
            cur_run = 0;
        }
    }

    Lz78yEstimate {
        estimate: prediction_estimate(correct_count, n, max_run, 2),
    }
}

/// A general-alphabet postfix dictionary, transcribing the EA tool's
/// `PostfixDictionary` (`utils.h`). For one prefix context it counts how often
/// each next symbol followed, caches the current argmax (`cur_best` count /
/// `cur_prediction` symbol), and reproduces the EA tie-break: on equal count the
/// **larger** symbol value wins.
struct PostfixDictionary {
    /// Next-symbol -> count map (EA's `map<uint8_t, long> postfixes`). `BTreeMap`
    /// for deterministic iteration, though the cached best is what `predict` uses.
    postfixes: std::collections::BTreeMap<u8, i64>,
    /// Cached best (largest) count seen (EA's `curBest`); `0` means "no postfix
    /// recorded yet" (the EA tool asserts `curBest > 0` before `predict`).
    cur_best: i64,
    /// Cached argmax next symbol (EA's `curPrediction`).
    cur_prediction: u8,
}

impl PostfixDictionary {
    /// Fresh dictionary with no postfixes (EA ctor: `curBest = 0; curPrediction = 0`).
    fn new() -> Self {
        Self {
            postfixes: std::collections::BTreeMap::new(),
            cur_best: 0,
            cur_prediction: 0,
        }
    }

    /// Return the argmax next symbol and its count (EA's `predict(&count)`). Only
    /// called after at least one `increment_postfix`, so `cur_best > 0`.
    fn predict(&self) -> (u8, i64) {
        (self.cur_prediction, self.cur_best)
    }

    /// Increment the count for next symbol `in_sym`, creating the entry if absent
    /// and `make_new`. Returns `true` iff a new entry was made. Updates the cached
    /// best/prediction on every increment, with the EA tie-break (`>` on count, or
    /// equal count and strictly larger symbol). Transcribes
    /// `PostfixDictionary::incrementPostfix`.
    fn increment_postfix(&mut self, in_sym: u8, make_new: bool) -> bool {
        let cur_count;
        let mut new_entry = false;
        match self.postfixes.get_mut(&in_sym) {
            Some(slot) => {
                *slot += 1;
                cur_count = *slot;
            }
            None => {
                if make_new {
                    new_entry = true;
                    self.postfixes.insert(in_sym, 1);
                    cur_count = 1;
                } else {
                    return false;
                }
            }
        }

        if cur_count > self.cur_best || (cur_count == self.cur_best && in_sym > self.cur_prediction)
        {
            self.cur_prediction = in_sym;
            self.cur_best = cur_count;
        }

        new_entry
    }
}

/// Run the §6.3.10 LZ78Y predictor over a general (`alph_size > 2`) symbol slice
/// `data`, transcribing `LZ78Y_test`'s general path (`alph_size != 2`).
///
/// `data` holds dense symbols (`0 .. alph_size`). One [`PostfixDictionary`] per
/// `(prefix-length, context)` pair, keyed by the length-`m` context
/// `(S[i-m] … S[i-1])` (a `Vec<u8>` of length `m`). Returns the shared prediction
/// estimate, or [`Lz78yEstimate::unavailable`] when there are fewer than
/// [`MIN_SAMPLES`] samples. Deterministic; does not panic.
fn lz78y_core_general(data: &[u8], alph_size: usize) -> Lz78yEstimate {
    let len = data.len();
    if len < MIN_SAMPLES {
        return Lz78yEstimate::unavailable();
    }

    // N = len - B_len - 1 predictions.
    let n = (len - B_LEN - 1) as u64;

    // D[j-1] maps a length-j context (Vec<u8>) to its PostfixDictionary
    // (EA: array<map<array<uint8_t,B_len>, PostfixDictionary>, B_len> D).
    let mut dict: Vec<std::collections::BTreeMap<Vec<u8>, PostfixDictionary>> = (0..B_LEN)
        .map(|_| std::collections::BTreeMap::new())
        .collect();
    // Single shared entry counter across all prefix lengths (EA: dict_size).
    let mut dict_size: i64 = 0;

    let mut correct_count: u64 = 0;
    let mut cur_run: u64 = 0;
    let mut max_run: u64 = 0;

    // --- Initialize dictionary (EA init loop: j = 1..=B_len). ---
    // D[j-1][ data[B_len-j .. B_len] ].incrementPostfix(data[B_len], true).
    {
        let next = data[B_LEN]; // S[B_len]; len >= B_LEN + 3 guarantees this.
        for j in 1..=B_LEN {
            let key: Vec<u8> = data[B_LEN - j..B_LEN].to_vec();
            dict[j - 1]
                .entry(key)
                .or_insert_with(PostfixDictionary::new)
                .increment_postfix(next, true);
            dict_size += 1;
        }
    }

    // --- Perform predictions. i = B_len+1 .. len. ---
    for i in (B_LEN + 1)..len {
        let cur = data[i];
        let mut have_prediction = false;
        let mut prediction: u8 = 0;
        let mut max_count: i64 = 0;

        // j is the prefix length, iterated from B_len down to 1.
        for j in (1..=B_LEN).rev() {
            // Context = the j-tuple (S[i-j] ... S[i-1]).
            let key: Vec<u8> = data[i - j..i].to_vec();

            // Found if this context already has a PostfixDictionary (EA: D[j-1].find(x)).
            if let Some(entry) = dict[j - 1].get_mut(&key) {
                // x has occurred: find max (x,y) pair, then increment (x, cur).
                let (y, count) = entry.predict();
                if count > max_count {
                    max_count = count;
                    prediction = y;
                    have_prediction = true;
                }
                entry.increment_postfix(cur, true);
            } else if dict_size < MAX_DICTIONARY_SIZE {
                // x not found, so (x, cur) can't have occurred; create if cap allows.
                dict[j - 1]
                    .entry(key)
                    .or_insert_with(PostfixDictionary::new)
                    .increment_postfix(cur, true);
                dict_size += 1;
            }
        }

        // Score ONCE per step.
        if have_prediction && prediction == cur {
            correct_count += 1;
            cur_run += 1;
            if cur_run > max_run {
                max_run = cur_run;
            }
        } else {
            cur_run = 0;
        }
    }

    Lz78yEstimate {
        estimate: prediction_estimate(correct_count, n, max_run, alph_size as u64),
    }
}

/// Compute the SP 800-90B §6.3.10 LZ78Y prediction min-entropy estimate for the
/// bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The estimator decomposes to the MSB-first bitstring and runs the
/// predictor over the binary alphabet (`k = 2`). The function is
/// **deterministic**: the same `(symbols, bits_per_symbol)` always yields a
/// bit-identical [`Lz78yEstimate`].
///
/// # Behavior on degenerate input
///
/// Fewer than [`MIN_SAMPLES`] bits returns [`Lz78yEstimate::unavailable`]
/// (min-entropy `-1.0`, the EA tool's could-not-run sentinel). Never arises for
/// the EA datasets (each has ≥ 1e6 bits).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn lz78y(symbols: &[u8], bits_per_symbol: u8) -> Lz78yEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    // Bitstring track: binary alphabet.
    lz78y_core(&bits)
}

/// Compute the §6.3.10 LZ78Y prediction estimate for the **literal track**: the
/// raw symbols over their own (translated) alphabet, mirroring the EA tool's
/// `LZ78Y_test(data.symbols, data.len, data.alph_size, …, "Literal")`.
///
/// The symbols are translated to a dense `0 .. alph_size` alphabet via the shared
/// [`crate::value_sorted_alphabet`] (ascending raw-value order). LZ78Y's
/// `PostfixDictionary` tie-break is on the **raw symbol value**
/// (`in > curPrediction`), so the remap must be order-preserving — value-sorted
/// gives "larger raw value wins" ⟺ "larger dense index wins", reproducing the EA
/// tie-break exactly; a first-seen remap ([`crate::dense_alphabet`]) would NOT
/// preserve it. (MultiMMC §6.3.9 shares this requirement and the same helper.) A
/// binary alphabet (`alph_size <= 2`) takes the dedicated binary fast path
/// ([`lz78y_core`], same computation the EA tool dispatches for `alph_size == 2`);
/// a larger alphabet takes the general path ([`lz78y_core_general`]). Literal-track
/// input to `H_original`. Deterministic; does not panic.
#[must_use]
pub fn lz78y_literal(symbols: &[u8]) -> Lz78yEstimate {
    let (dense, alph) = crate::value_sorted_alphabet(symbols);
    if alph <= 2 {
        lz78y_core(&dense)
    } else {
        lz78y_core_general(&dense, alph)
    }
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

    fn lz78y_of_file(name: &str) -> Option<Lz78yEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(lz78y(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor, Bitstring track (EA `-v -v`): C = 39959, r = 15
    /// (max_run_len = 14), N = 79983, min entropy = 0.98808180379990307.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = lz78y_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 39959, "C");
        assert_eq!(est.estimate.n, 79983, "N");
        assert_eq!(est.estimate.max_run_len, 14, "max_run_len (r = 15)");
        assert!(
            (est.min_entropy() - 0.988_081_803_799_903_1).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// biased-random-bits anchor, Literal track (1-bit; bsymbols == symbols):
    /// C = 979970, r = 534 (max_run_len = 533), N = 999983,
    /// min entropy = 0.028635020154766915.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = lz78y_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.estimate.c, 979_970, "C");
        assert_eq!(est.estimate.n, 999_983, "N");
        assert_eq!(est.estimate.max_run_len, 533, "max_run_len (r = 534)");
        assert!(
            (est.min_entropy() - 0.028_635_020_154_766_915).abs() < PARITY_EPS,
            "min_entropy={}",
            est.min_entropy()
        );
    }

    /// Literal-track parity: `lz78y_literal` matches EA v1.1.8 "Literal LZ78Y
    /// Prediction Estimate: min entropy" to within 1e-6 on every multi-bit
    /// reference dataset. Skips datasets absent on host.
    #[test]
    fn literal_parity_multibit() {
        const EA_LITERAL_LZ78Y: &[(&str, f64)] = &[
            ("biased-random-bytes", 0.321_372_180_809_8),
            ("normal", 5.679_163_897_126_1),
            ("rand4_short", 3.882_495_664_055_9),
            ("rand8_short", 7.353_355_393_835_4),
            ("truerand_4bit", 3.984_277_226_741_6),
            ("truerand_8bit", 7.926_787_180_805_8),
        ];
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(name, ea) in EA_LITERAL_LZ78Y {
            let Some(row) = REFERENCE_TABLE.iter().find(|r| r.name == name) else {
                continue;
            };
            let Ok(data) = std::fs::read(dir.join(row.file)) else {
                eprintln!("{name}.bin absent — skipping literal parity");
                continue;
            };
            let got = lz78y_literal(&data).min_entropy();
            assert!(
                (got - ea).abs() <= PARITY_EPS,
                "{name}: literal LZ78Y {got} vs EA {ea} (delta {})",
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
        let a = lz78y(&buf, 8);
        let b = lz78y(&buf, 8);
        assert_eq!(a, b, "Lz78yEstimate must be bit-identical across runs");
    }

    /// All-zero bits: every context is all-zeros and the next symbol is always 0,
    /// so once seeded the predictor always predicts correctly. C should equal N
    /// and the run never breaks, giving a very low (near-zero) min-entropy.
    #[test]
    fn all_zeros_is_low_entropy() {
        let buf = vec![0u8; 8192];
        let est = lz78y(&buf, 1);
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
        // B_LEN + 2 = 18 bits at 1 bit/symbol < MIN_SAMPLES (= B_LEN + 3 = 19).
        let buf = vec![0u8; B_LEN + 2];
        let est = lz78y(&buf, 1);
        assert_eq!(est.min_entropy(), -1.0, "too-short returns -1.0 sentinel");
    }

    /// Minimum-length input (exactly MIN_SAMPLES bits) runs without panic: this
    /// exercises the init loop reading up to S[B_LEN] and the single prediction
    /// (N = L - B_LEN - 1 = 2).
    #[test]
    fn min_length_input_no_panic() {
        let mut buf = vec![0u8; MIN_SAMPLES]; // exactly B_LEN + 3 bits
        // Vary a couple of bits so the predictor isn't trivially all-zeros.
        buf[B_LEN] = 1;
        buf[B_LEN + 1] = 1;
        let est = lz78y(&buf, 1);
        assert_eq!(est.estimate.n, 2, "N = L - B_LEN - 1");
        assert!(est.min_entropy() >= 0.0 && est.min_entropy().is_finite());
    }

    /// `context_seen` predicate sanity: a fresh dictionary reports unseen; after
    /// a set it reports seen. Documents the EA tool's `curCount != 0` predicate.
    #[test]
    fn context_seen_predicate() {
        let mut d = BinaryDict::new(3);
        assert!(!d.context_seen(0b101));
        d.set_one(0b101, 1);
        assert!(d.context_seen(0b101));
        assert!(!d.context_seen(0b010));
    }
}
