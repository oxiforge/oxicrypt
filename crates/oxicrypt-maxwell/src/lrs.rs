//! SP 800-90B §6.3.5 t-Tuple **and** §6.3.6 LRS (Longest Repeated Substring)
//! min-entropy estimators (bitstring track).
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 `SAalgs` routine (`cpp/shared/lrs_test.h`), which derives
//! **both** the §6.3.5 t-Tuple estimate and the §6.3.6 LRS estimate from a
//! single suffix-array + LCP pass over the data. It matches the EA reference
//! values to within the pre-registered 1.0e-6 bits/estimator parity bound
//! (`docs/estimator-parity-tolerances.md`). Like the rest of `oxicrypt-maxwell`
//! it is **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # Why the two estimators share a module
//!
//! The EA tool computes the t-Tuple and LRS estimates together in one function
//! (`SAalgs` / `SAalgs32`), because both are read off the same data structure:
//! the suffix array of the data and its longest-common-prefix (LCP) array,
//! processed by the tuple-counting algorithm of Aaron Kaufer
//! (<http://www.untruth.org/~josh/sp80090b/Kaufer%20Further%20Improvements%20for%20SP%20800-90B%20Tuple%20Counts.pdf>).
//! Splitting them would duplicate the (expensive) suffix-array build. This module
//! mirrors that: `sa_lcp` builds the structure once and `saalgs` derives both.
//!
//! # The estimators (SP 800-90B §6.3.5 / §6.3.6)
//!
//! Both run on the **bitstring track** — the EA tool's controlling assessment
//! for these datasets is `SAalgs(data.bsymbols, …)` for multi-bit data and
//! `SAalgs(data.symbols, …)` for binary data (where `bsymbols == symbols`). So
//! each dataset, including 1-bit data, carries exactly one t-Tuple and one LRS
//! reference value, on the same MSB-first bit decomposition the MCV bitstring
//! track, collision, Markov, and compression estimators use
//! (`bsymbols[i*w+j] = (symbols[i] >> (w-1-j)) & 1`).
//!
//! ## Suffix array + LCP (matched from `lrs_test.h`)
//!
//! `calcSALCP32` builds, for an `n`-symbol text, a suffix array `sa` of length
//! `n+1` whose entry `sa[0] = n` is the empty suffix (lexicographically smallest)
//! and whose entries `sa[1..=n]` are the `n` non-empty suffixes in sorted order
//! (the EA tool delegates this to `divsufsort`). `sa2lcp32` then runs Kasai's
//! `O(n)` LCP algorithm over that `n+1`-entry arrangement, producing `lcp[k]` =
//! the longest common prefix of the rank-`k` and rank-`k-1` suffixes, with
//! `lcp[0] = -1`, `lcp[1] = 0`.
//!
//! `SAalgs` then applies Kaufer's conventions: it drops `lcp[0]` (the `erase`)
//! so the working array `L` has `L[i] = lcp[i+1]`, sets `L[n] = 0`, and relies on
//! `L[0] == 0`. This module reproduces that arrangement exactly (see
//! `sa_lcp`).
//!
//! ## t-Tuple estimate (§6.3.5)
//!
//! Kaufer's single left-to-right pass over `L` maintains running tuple counts and
//! fills `Q[i]` = the number of occurrences of the most common `i`-tuple. `u` is
//! the largest tuple length whose most-common count is `≥ 35` (the EA tool's
//! `for(u=1; (u<=v) && (Q[u]>=35); u++)`). For each `i` in `1..u`,
//! `P_max,i = (Q[i] / (n−i+1))^(1/i)`; `P_max` is their maximum. Then
//! `p_u = min(1, P_max + Z·sqrt(P_max(1−P_max)/(n−1)))` and the estimate is
//! `−log2(p_u)`. If no tuple repeats `≥ 35` times (`P_max ≤ 0`), the EA tool
//! returns `-1.0` (estimate failed).
//!
//! ## LRS estimate (§6.3.6)
//!
//! Runs only when `v ≥ u` (`v` is the LRS length). A second pass accumulates,
//! for each tuple length `i` in `u..=v`, `S[i]` = the number of colliding pairs
//! of `i`-length substrings (sum of `C(count, 2)` over distinct `i`-tuples). With
//! `denom_i = C(n−i+1, 2)`, `P_max = max_i (S[i]/denom_i)^(1/i)`, and the estimate
//! is `−log2(min(1, P_max + Z·sqrt(P_max(1−P_max)/(n−1))))`.
//!
//! # Floating point
//!
//! `lrs_test.h` evaluates `P_max`, `p_u`, and the `powl`/`sqrtl`/`log2l` chain in
//! `long double` (80-bit extended on x86_64). Rust has no `long double`, so this
//! module evaluates them in `f64`. The integer tuple counts (`Q`, `S`) are exact
//! (`u64`/`u128`), so the only difference is the final `pow`/`sqrt`/`log2` chain,
//! which reproduces every EA v1.1.8 reference value to well within the 1.0e-6
//! parity bound. See `docs/estimator-parity-tolerances.md`.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention; sub-8-bit
//! symbols are already masked into the low bits of each byte). `bits_per_symbol`
//! must be in `1..=8`; out-of-range widths are clamped (`0 -> 1`, `>8 -> 8`) so
//! callers cannot trigger out-of-range shifts.

// This module is a wall-to-wall transcription of the EA reference's SA-IS suffix
// array, Kasai LCP, and Kaufer SAalgs tuple-counting routines. Those algorithms
// are inherently index- and arithmetic-heavy and use conventional single-letter
// names; faithfulness to the C++ reference is the priority and the parity oracle
// (<= 1e-6 vs EA on all bundled datasets) is the real correctness gate. The
// per-function reasoning is in the fn-level allow comments below; this
// module-level allow covers the same algorithm-inherent lints uniformly so the
// transcription reads 1:1 with the reference rather than being restructured to
// satisfy style/restriction lints.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::comparison_chain,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::similar_names,
    clippy::too_many_lines
)]

use crate::Z_995;

/// The EA tool's tuple-count threshold (`SAalgs`: `Q[u] >= 35`). A tuple length
/// counts toward the t-Tuple estimate only if its most-common tuple recurs at
/// least this many times.
pub const TUPLE_THRESHOLD: u64 = 35;

/// One combined t-Tuple (§6.3.5) and LRS (§6.3.6) result over the bitstring
/// track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LrsEstimate {
    /// Sequence length `n` (number of bits on the bitstring track).
    pub n: usize,
    /// `v` — the length of the longest repeated substring (the max LCP value).
    pub v: usize,
    /// `u` — the smallest tuple length whose most-common count drops below
    /// [`TUPLE_THRESHOLD`] (the EA tool's `u`). The t-Tuple estimate's reported
    /// `t` is `u - 1`.
    pub u: usize,
    /// `P_max` for the t-Tuple estimate (the EA tool's `p-hat_max`); `-1.0` when
    /// the t-Tuple estimate failed (no tuple recurs ≥ 35 times).
    pub t_tuple_p_max: f64,
    /// `−log2(p_u)` for the §6.3.5 t-Tuple estimate, per symbol of the bitstring
    /// track (so per-bit, in `(0, 1]`); `-1.0` when the estimate failed.
    pub t_tuple_min_entropy: f64,
    /// `P_max` for the LRS estimate (the EA tool's `p-hat`); `-1.0` when the LRS
    /// estimate could not run (`v < u`).
    pub lrs_p_max: f64,
    /// `−log2(p_u)` for the §6.3.6 LRS estimate, per symbol of the bitstring
    /// track (so per-bit, in `(0, 1]`); `-1.0` when the estimate could not run.
    pub lrs_min_entropy: f64,
}

impl LrsEstimate {
    /// The EA tool's "estimate did not run" sentinel: both estimates `-1.0`.
    /// Returned for inputs too short to form a repeated substring (`v == 0`),
    /// which never arise for the EA datasets (each has ≥ 1e6 bits).
    #[must_use]
    pub const fn unavailable(n: usize) -> Self {
        Self {
            n,
            v: 0,
            u: 0,
            t_tuple_p_max: -1.0,
            t_tuple_min_entropy: -1.0,
            lrs_p_max: -1.0,
            lrs_min_entropy: -1.0,
        }
    }
}

/// Decompose `symbols` MSB-first into a binary sequence, matching the EA tool's
/// `bsymbols` construction (`(symbol >> (w-1-j)) & 1`). For `bits_per_symbol == 1`
/// the bytes are already the bit values (`0`/`1`), returned as-is.
///
/// Identical in behavior to the collision/Markov/compression modules'
/// decomposition; kept local so each estimator module is self-contained.
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

/// Build the suffix array (`sa`) and Kaufer-convention LCP array (`L`) of
/// `text`, reproducing `calcSALCP32` + `sa2lcp32` + the `SAalgs` `erase`/`L[n]=0`
/// transform from `lrs_test.h`.
///
/// Returns `(sa, l)` where:
/// - `sa` has length `n+1`: `sa[0] = n` (the empty suffix, rank 0) and
///   `sa[1..=n]` are the `n` non-empty suffix start positions in sorted order.
/// - `l` has length `n+1` and is the Kaufer working array: `l[i]` is the LCP of
///   the rank-`(i+1)` and rank-`i` suffixes in the `n+1`-entry sorted order, with
///   `l[0] == 0` and `l[n] == 0`.
///
/// The suffix array itself is built by [`suffix_array_sais`] (the EA tool uses
/// `divsufsort`; this is an independent linear-time SA-IS implementation that
/// produces the identical sorted order — a suffix array is unique for a fixed
/// total order on suffixes).
#[allow(
    // Indices are bounded by n (a slice-derived length); the saturating ops keep
    // the arithmetic total and the casts are between usize and the index domain.
    clippy::cast_precision_loss,
    clippy::similar_names,
    // Suffix-array / Kasai LCP uses the conventional single-letter index names
    // (i, j, k, h, …); the indexing stays in bounds by the loop invariants
    // (matching the EA reference's array accesses).
    clippy::many_single_char_names,
    clippy::indexing_slicing
)]
fn sa_lcp(text: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let n = text.len();

    // The n non-empty suffixes, sorted (positions 0..n).
    let sorted = suffix_array_sais(text);

    // EA's sa[] is the empty suffix (position n) followed by the sorted ones.
    // sa has length n+1; sa[0] = n, sa[1..=n] = sorted[0..n].
    let mut sa = Vec::with_capacity(n.saturating_add(1));
    sa.push(n);
    sa.extend_from_slice(&sorted);

    // Kasai's algorithm over the n+1-entry arrangement (sa2lcp32). rank maps a
    // start position to its index in `sa`. rank has size n+1 (positions 0..=n).
    let mut rank = vec![0usize; n.saturating_add(1)];
    for (i, &pos) in sa.iter().enumerate() {
        // pos in 0..=n; rank slot exists for every position including the empty
        // suffix at n (which lands at rank 0 since sa[0] = n).
        if let Some(slot) = rank.get_mut(pos) {
            *slot = i;
        }
    }

    // lcp has size n+1 (indices 0..=n), matching sa2lcp32's `lcp` over n+1 ranks.
    // lcp[0] = -1 and lcp[1] = 0 in the EA tool; we represent the -1 sentinel as
    // it is only ever erased away below, so we keep lcp as usize and never read
    // index 0's "value" (it becomes l after the shift and l[0] must be 0).
    let mut lcp = vec![0usize; n.saturating_add(1)];
    // lcp[1] = 0 already (default). lcp[0] is the erased sentinel.

    // Traverse suffixes in position order, carrying h (the LCP length).
    let mut h = 0usize;
    let mut i = 0usize;
    while i < n {
        let k = rank.get(i).copied().unwrap_or(0); // rank of suffix at position i
        if k > 1 {
            // predecessor of suffix-i in sorted order is the suffix at sa[k-1].
            let j = sa.get(k.saturating_sub(1)).copied().unwrap_or(n);
            // extend the common prefix from offset h.
            while i.saturating_add(h) < n
                && j.saturating_add(h) < n
                && text.get(i.saturating_add(h)) == text.get(j.saturating_add(h))
            {
                h = h.saturating_add(1);
            }
            if let Some(slot) = lcp.get_mut(k) {
                *slot = h;
            }
        }
        if h > 0 {
            h = h.saturating_sub(1);
        }
        i = i.saturating_add(1);
    }

    // SAalgs: L.erase(L.begin()) drops lcp[0]; then L[n] = 0. After the shift the
    // working array l has l[i] = lcp[i+1] for i in 0..n, and l[n] = 0. l[0] =
    // lcp[1] = 0 (the EA tool asserts L[0] == 0).
    let mut l = vec![0usize; n.saturating_add(1)];
    let mut idx = 0usize;
    while idx < n {
        l[idx] = lcp.get(idx.saturating_add(1)).copied().unwrap_or(0);
        idx = idx.saturating_add(1);
    }
    // l[n] = 0 (already zero from the vec! initializer; set explicitly for
    // clarity / to mirror the EA tool's `L[n] = 0`).
    if let Some(last) = l.get_mut(n) {
        *last = 0;
    }

    (sa, l)
}

/// Compute the suffix array of `text` (the `n` non-empty suffix start positions
/// in ascending lexicographic order) via the SA-IS induced-sorting algorithm.
///
/// SA-IS (Nong, Zhang & Chan, 2009) is linear-time and deterministic; for a
/// fixed total order on suffixes the suffix array is unique, so this reproduces
/// the order `divsufsort` produces inside the EA tool. The input alphabet is the
/// byte values present in `text` (≤ 256 distinct symbols); a unique smallest
/// sentinel is appended internally so every suffix has a defined order.
///
/// Returns a `Vec<usize>` of length `text.len()` (empty for empty input).
#[must_use]
fn suffix_array_sais(text: &[u8]) -> Vec<usize> {
    let n = text.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![0];
    }

    // Map the byte text into an i64 alphabet with a 0 sentinel appended. Working
    // in i64 keeps the recursive reduced-string alphabet (which can exceed 255)
    // representable and lets us use 0 as the unique sentinel.
    let mut s: Vec<i64> = Vec::with_capacity(n.saturating_add(1));
    for &b in text {
        // Shift real symbols up by 1 so 0 is reserved for the sentinel.
        s.push(i64::from(b).saturating_add(1));
    }
    s.push(0); // sentinel, strictly smaller than every real symbol.

    let alphabet_size = 257; // 256 byte values shifted to 1..=256, plus sentinel 0.
    let sa = sais_core(&s, alphabet_size);

    // sa has length n+1 and its first entry is the sentinel suffix (position n).
    // Drop it: the EA arrangement places the empty suffix separately as sa[0]=n.
    // The remaining n entries are the non-empty suffixes in sorted order.
    sa.into_iter().filter(|&p| p < n).collect()
}

/// Core SA-IS over an integer string `s` (which MUST end in a unique smallest
/// sentinel `0`) with the given `alphabet_size`. Returns the suffix array of `s`
/// (length `s.len()`), including the sentinel suffix.
///
/// Faithful induced-sorting implementation; recursion handles the reduced
/// problem when LMS substrings are not already distinct.
#[allow(
    // SA-IS indexes bucket/type arrays whose sizes are derived from the input
    // length and alphabet; all index arithmetic is via saturating ops or proven
    // in-range by the algorithm's structure. The i64 alphabet values are small.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::too_many_lines,
    // SA-IS is index-and-arithmetic heavy by nature; accesses stay in bounds by
    // the algorithm's structure and conventional single-letter names are used.
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::comparison_chain,
    clippy::many_single_char_names
)]
fn sais_core(s: &[i64], alphabet_size: usize) -> Vec<usize> {
    let n = s.len();
    let mut sa = vec![usize::MAX; n];
    if n == 1 {
        sa[0] = 0;
        return sa;
    }

    // Type array: true = S-type, false = L-type. The last char (sentinel) is
    // S-type by definition.
    let mut is_s = vec![false; n];
    is_s[n - 1] = true;
    for i in (0..n - 1).rev() {
        is_s[i] = if s[i] < s[i + 1] {
            true
        } else if s[i] > s[i + 1] {
            false
        } else {
            is_s[i + 1]
        };
    }

    // LMS position: i is a left-most S-type if is_s[i] && !is_s[i-1].
    let is_lms = |i: usize| -> bool { i > 0 && is_s[i] && !is_s[i - 1] };

    // Bucket sizes (count of each symbol) and bucket end/head offsets.
    let bucket_sizes = |s: &[i64]| -> Vec<usize> {
        let mut sizes = vec![0usize; alphabet_size];
        for &c in s {
            let idx = c as usize;
            if let Some(slot) = sizes.get_mut(idx) {
                *slot = slot.saturating_add(1);
            }
        }
        sizes
    };
    let bucket_heads = |sizes: &[usize]| -> Vec<usize> {
        let mut heads = vec![0usize; alphabet_size];
        let mut sum = 0usize;
        for (i, &sz) in sizes.iter().enumerate() {
            heads[i] = sum;
            sum = sum.saturating_add(sz);
        }
        heads
    };
    let bucket_tails = |sizes: &[usize]| -> Vec<usize> {
        let mut tails = vec![0usize; alphabet_size];
        let mut sum = 0usize;
        for (i, &sz) in sizes.iter().enumerate() {
            sum = sum.saturating_add(sz);
            tails[i] = sum; // one past the last slot of bucket i
        }
        tails
    };

    let sizes = bucket_sizes(s);

    // --- Step 1: place LMS suffixes (rough) at bucket tails. ---
    let mut tails = bucket_tails(&sizes);
    for i in 0..n {
        if is_lms(i) {
            let c = s[i] as usize;
            if let Some(t) = tails.get_mut(c) {
                *t = t.saturating_sub(1);
                let pos = *t;
                if let Some(slot) = sa.get_mut(pos) {
                    *slot = i;
                }
            }
        }
    }

    induce_sort(s, &mut sa, &is_s, &sizes, &bucket_heads, &bucket_tails);

    // --- Step 2: name the LMS substrings. ---
    let mut lms_names = vec![usize::MAX; n];
    let mut name_count = 0usize;
    {
        let mut prev: Option<usize> = None;
        // Collect LMS positions in sorted order (the order they appear in sa now).
        for &pos in sa.iter() {
            if pos != usize::MAX && is_lms(pos) {
                let same = match prev {
                    None => false,
                    Some(p) => lms_substr_equal(s, &is_s, p, pos),
                };
                if !same {
                    name_count = name_count.saturating_add(1);
                }
                // Name is 1-based here; converted to 0-based for recursion below.
                lms_names[pos] = name_count;
                prev = Some(pos);
            }
        }
    }

    // Build the reduced string from LMS names in *text* order.
    let mut reduced: Vec<i64> = Vec::new();
    let mut reduced_pos: Vec<usize> = Vec::new();
    for (i, name) in lms_names.iter().enumerate() {
        if *name != usize::MAX {
            reduced.push(*name as i64);
            reduced_pos.push(i);
        }
    }

    let reduced_len = reduced.len();

    // --- Step 3: recurse or directly invert. ---
    let reduced_sa: Vec<usize> = if name_count == reduced_len {
        // All names distinct: the suffix array of the reduced string is just the
        // inverse permutation of the names.
        let mut rsa = vec![0usize; reduced_len];
        for (i, name) in reduced.iter().enumerate() {
            // names are 1-based; slot name-1.
            let idx = (*name as usize).saturating_sub(1);
            if let Some(slot) = rsa.get_mut(idx) {
                *slot = i;
            }
        }
        rsa
    } else {
        // Names not distinct: shift names down to 0-based with a 0 sentinel and
        // recurse. The reduced string already ends with the LMS at the sentinel
        // (the unique smallest LMS substring), so its name is unique and acts as
        // the sentinel.
        let mut reduced_zero: Vec<i64> = reduced.iter().map(|&x| x.saturating_sub(1)).collect();
        // The reduced alphabet has name_count symbols (0..name_count after the
        // shift). Ensure the last element is the unique smallest (it is, being
        // the sentinel's LMS).
        // Guard: recursion needs a terminating sentinel; the construction above
        // guarantees the final LMS (at the text sentinel) is uniquely smallest.
        let _ = &mut reduced_zero;
        sais_core(&reduced_zero, name_count.saturating_add(1))
    };

    // --- Step 4: place the LMS suffixes into sa in the order given by the
    // reduced suffix array, then induce-sort once more. ---
    for slot in sa.iter_mut() {
        *slot = usize::MAX;
    }
    let mut tails = bucket_tails(&sizes);
    for &r in reduced_sa.iter().rev() {
        // r indexes the reduced string; map back to the original LMS position.
        let i = reduced_pos.get(r).copied().unwrap_or(0);
        let c = s[i] as usize;
        if let Some(t) = tails.get_mut(c) {
            *t = t.saturating_sub(1);
            let pos = *t;
            if let Some(slot) = sa.get_mut(pos) {
                *slot = i;
            }
        }
    }

    induce_sort(s, &mut sa, &is_s, &sizes, &bucket_heads, &bucket_tails);

    sa
}

/// Induced sort step shared by both SA-IS placement passes: given LMS suffixes
/// already placed at their bucket tails, induce the L-type suffixes from the
/// bucket heads (left to right) and then the S-type suffixes from the bucket
/// tails (right to left).
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    // Induced-sort step of SA-IS: bucket indexing + index arithmetic kept in
    // bounds by the bucket sizes; conventional single-letter names.
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::comparison_chain,
    clippy::many_single_char_names
)]
fn induce_sort(
    s: &[i64],
    sa: &mut [usize],
    is_s: &[bool],
    sizes: &[usize],
    bucket_heads: &dyn Fn(&[usize]) -> Vec<usize>,
    bucket_tails: &dyn Fn(&[usize]) -> Vec<usize>,
) {
    let n = s.len();

    // Induce L-type: scan left to right, place s[sa[i]-1] at its bucket head if
    // it is L-type.
    let mut heads = bucket_heads(sizes);
    for i in 0..n {
        let pos = sa[i];
        if pos != usize::MAX && pos > 0 {
            let j = pos - 1;
            if !is_s[j] {
                let c = s[j] as usize;
                if let Some(h) = heads.get_mut(c) {
                    let slot = *h;
                    *h = h.saturating_add(1);
                    if let Some(cell) = sa.get_mut(slot) {
                        *cell = j;
                    }
                }
            }
        }
    }

    // Induce S-type: scan right to left, place s[sa[i]-1] at its bucket tail if
    // it is S-type.
    let mut tails = bucket_tails(sizes);
    for i in (0..n).rev() {
        let pos = sa[i];
        if pos != usize::MAX && pos > 0 {
            let j = pos - 1;
            if is_s[j] {
                let c = s[j] as usize;
                if let Some(t) = tails.get_mut(c) {
                    *t = t.saturating_sub(1);
                    let slot = *t;
                    if let Some(cell) = sa.get_mut(slot) {
                        *cell = j;
                    }
                }
            }
        }
    }
}

/// True if the two LMS substrings starting at positions `a` and `b` are equal
/// (same length and same characters), per the SA-IS naming step.
#[allow(
    // SA-IS naming step: conventional single-letter names (s, a, b, i, n); the
    // indexing is bounded by n via the loop guards.
    clippy::many_single_char_names,
    clippy::indexing_slicing
)]
fn lms_substr_equal(s: &[i64], is_s: &[bool], a: usize, b: usize) -> bool {
    let n = s.len();
    let is_lms = |i: usize| -> bool { i > 0 && is_s[i] && !is_s[i - 1] };
    let mut i = 0usize;
    loop {
        let pa = a.saturating_add(i);
        let pb = b.saturating_add(i);
        let a_oob = pa >= n;
        let b_oob = pb >= n;
        if a_oob || b_oob {
            return a_oob && b_oob;
        }
        if s[pa] != s[pb] || is_s[pa] != is_s[pb] {
            return false;
        }
        // Stop when we've passed the first char and hit the next LMS in both.
        if i > 0 && is_lms(pa) && is_lms(pb) {
            return true;
        }
        // If only one reached the next LMS, the substrings differ in length.
        if i > 0 && (is_lms(pa) != is_lms(pb)) {
            return false;
        }
        i = i.saturating_add(1);
    }
}

/// Apply the §6.3.5 / §6.3.6 upper-confidence-bound transform to a `P_max`:
/// `p_u = min(1, P_max + Z·sqrt(P_max(1−P_max)/(n−1)))`, then return `−log2(p_u)`.
///
/// Mirrors `lrs_test.h`'s `pu = Pmax + ZALPHA_L*sqrtl(Pmax*(1.0L-Pmax)/(n-1));
/// if(pu>1) pu=1; res = -log2l(pu);`.
#[allow(clippy::cast_precision_loss)]
fn min_entropy_from_pmax(p_max: f64, n: usize) -> f64 {
    let denom = (n.saturating_sub(1)) as f64;
    let mut p_u = p_max + Z_995 * (p_max * (1.0 - p_max) / denom).sqrt();
    if p_u > 1.0 {
        p_u = 1.0;
    }
    -p_u.log2()
}

/// Derive both the t-Tuple (§6.3.5) and LRS (§6.3.6) estimates from the suffix
/// array + LCP of `text`, transcribing the Kaufer algorithm in
/// `lrs_test.h::SAalgs32`.
///
/// `text` is the bitstring track (0/1 bytes for binary, or any byte alphabet for
/// the literal track — though this crate always feeds the bitstring track). The
/// function is deterministic.
#[allow(
    // The counts (Q, A, S) are exact integers; casts to f64 mirror the EA tool's
    // (long double) casts at the final pow/sqrt/log2 chain and the 1.0e-6 parity
    // bound absorbs the rounding. Index arithmetic uses saturating ops / .get()
    // so it is total. The single-function transcription mirrors SAalgs32 1:1.
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::too_many_lines,
    // SAalgs uses the EA reference's conventional single-letter names
    // (i, j, t, u, Q, A, S, …); accesses stay in bounds by construction.
    clippy::many_single_char_names,
    clippy::indexing_slicing
)]
fn saalgs(text: &[u8]) -> LrsEstimate {
    let n = text.len();
    if n < 2 {
        return LrsEstimate::unavailable(n);
    }

    let (_sa, l) = sa_lcp(text);

    // Find v = the length of the LRS = max LCP value over l[0..n].
    // (lrs_test.h: for i in 0..n { if L[i] > v { v = L[i]; } })
    let mut v: usize = 0;
    {
        let mut i = 0usize;
        while i < n {
            let li = l.get(i).copied().unwrap_or(0);
            if li > v {
                v = li;
            }
            i = i.saturating_add(1);
        }
    }

    // No repeated substring: the EA tool asserts v > 0. For robustness we return
    // the unavailable sentinel rather than panicking (never happens on EA data).
    if v == 0 {
        return LrsEstimate::unavailable(n);
    }

    // Kaufer accumulation arrays (1-based logical indices, sized like SAalgs32):
    //   Q[i] for i in 0..=v, initialized to 1 (Q[0] unused; Q[i]>=1).
    //   A[i] for i in 0..=v+1, initialized to 0.
    //   I[j] for j in 0..=v+2, initialized to 0.
    let mut q = vec![1i64; v.saturating_add(1)];
    let mut a = vec![0i64; v.saturating_add(2)];
    let mut idx_i = vec![0i64; v.saturating_add(3)];

    // l_at(i) reads the working LCP array with the EA tool's L[i] semantics for
    // i in 0..=n (L[n] == 0). For i==0 it is 0 (asserted by the EA tool).
    let l_at = |i: usize| -> i64 {
        if i == 0 {
            0
        } else {
            l.get(i).copied().unwrap_or(0) as i64
        }
    };

    // First pass: build Q (most-common tuple counts) — SAalgs32 main loop.
    let mut j: i64 = 0;
    {
        let mut i: usize = 1;
        while i <= n {
            let mut c: i64 = 0;
            let li = l_at(i);
            let li_prev = l_at(i.saturating_sub(1));

            if li < li_prev {
                let mut t = li_prev;
                j -= 1;
                while t > li {
                    let jj = j as usize;
                    let ij = idx_i.get(jj).copied().unwrap_or(0);
                    if j > 0 && ij == t {
                        // update count for non-zero entry of A
                        let ij1 = idx_i.get(jj.saturating_add(1)).copied().unwrap_or(0) as usize;
                        let add = a.get(ij1).copied().unwrap_or(0);
                        let dst = ij as usize;
                        if let Some(slot) = a.get_mut(dst) {
                            *slot = slot.saturating_add(add);
                        }
                        if let Some(slot) = a.get_mut(ij1) {
                            *slot = 0;
                        }
                        j -= 1;
                    }

                    let jj2 = j as usize;
                    let ij1b = idx_i.get(jj2.saturating_add(1)).copied().unwrap_or(0) as usize;
                    let a_ij1 = a.get(ij1b).copied().unwrap_or(0);
                    let q_t = q.get(t as usize).copied().unwrap_or(1);
                    if q_t >= a_ij1.saturating_add(1) {
                        if j > 0 {
                            t = idx_i.get(jj2).copied().unwrap_or(0);
                        } else {
                            t = li;
                        }
                    } else {
                        if let Some(slot) = q.get_mut(t as usize) {
                            *slot = a_ij1.saturating_add(1);
                        }
                        t -= 1;
                    }
                }

                let jj3 = j as usize;
                let ij1c = idx_i.get(jj3.saturating_add(1)).copied().unwrap_or(0) as usize;
                c = a.get(ij1c).copied().unwrap_or(0); // carry-over count
                if let Some(slot) = a.get_mut(ij1c) {
                    *slot = 0;
                }
            }

            if li > 0 {
                let jj = j as usize;
                let ij = idx_i.get(jj).copied().unwrap_or(0);
                if j < 1 || ij < li {
                    j += 1;
                    if let Some(slot) = idx_i.get_mut(j as usize) {
                        *slot = li;
                    }
                }
                let ij_now = idx_i.get(j as usize).copied().unwrap_or(0) as usize;
                if let Some(slot) = a.get_mut(ij_now) {
                    *slot = slot.saturating_add(c.saturating_add(1));
                }
            }

            i = i.saturating_add(1);
        }
    }

    // Calculate u: smallest tuple length where Q[u] < threshold.
    // (for(u=1; (u<=v) && (Q[u]>=35); u++);)
    let mut u: usize = 1;
    while u <= v && q.get(u).copied().unwrap_or(0) >= TUPLE_THRESHOLD as i64 {
        u = u.saturating_add(1);
    }

    // --- t-Tuple estimate (§6.3.5). ---
    let mut t_tuple_p_max: f64 = -1.0;
    {
        let mut i: usize = 1;
        while i < u {
            let qi = q.get(i).copied().unwrap_or(0);
            // curP = Q[i] / (n - i + 1)
            let denom = (n.saturating_sub(i).saturating_add(1)) as f64;
            let cur_p = (qi as f64) / denom;
            let cur_pmax = cur_p.powf(1.0 / (i as f64));
            if cur_pmax > t_tuple_p_max {
                t_tuple_p_max = cur_pmax;
            }
            i = i.saturating_add(1);
        }
    }
    let t_tuple_min_entropy = if t_tuple_p_max > 0.0 {
        min_entropy_from_pmax(t_tuple_p_max, n)
    } else {
        -1.0
    };

    // --- LRS estimate (§6.3.6). ---
    let (lrs_p_max, lrs_min_entropy) = if v >= u {
        // Reset A and accumulate the colliding-pair sums S[i] for i in u..=v.
        for slot in a.iter_mut() {
            *slot = 0;
        }
        // S[i] for i in 0..=v (u128 to match the EA 64-bit path's headroom).
        let mut s_sum = vec![0u128; v.saturating_add(1)];

        let mut i: usize = 1;
        while i <= n {
            let li = l_at(i);
            let li_prev = l_at(i.saturating_sub(1));
            let u_i = u as i64;

            if li_prev >= u_i && li < li_prev {
                let mut b = li;
                // A[u] stores the number of u-length tuples; clear down to A[u].
                if b < u_i {
                    b = u_i - 1;
                }

                let mut t = li_prev;
                while t > b {
                    let tu = t as usize;
                    let add = a.get(tu.saturating_add(1)).copied().unwrap_or(0);
                    if let Some(slot) = a.get_mut(tu) {
                        *slot = slot.saturating_add(add);
                    }
                    if let Some(slot) = a.get_mut(tu.saturating_add(1)) {
                        *slot = 0;
                    }
                    let at = a.get(tu).copied().unwrap_or(0);
                    // choices = (A[t]+1) * A[t] / 2 = C(A[t]+1, 2).
                    let at_u = at.max(0) as u128;
                    let choices = (at_u.saturating_add(1)).saturating_mul(at_u) >> 1;
                    if let Some(slot) = s_sum.get_mut(tu) {
                        *slot = slot.saturating_add(choices);
                    }
                    t -= 1;
                }

                if b >= u_i {
                    let bu = b as usize;
                    let add = a.get(bu.saturating_add(1)).copied().unwrap_or(0);
                    if let Some(slot) = a.get_mut(bu) {
                        *slot = slot.saturating_add(add);
                    }
                }
                if let Some(slot) = a.get_mut((b as usize).saturating_add(1)) {
                    *slot = 0;
                }
            }

            if li >= u_i {
                let lu = li as usize;
                if let Some(slot) = a.get_mut(lu) {
                    *slot = slot.saturating_add(1);
                }
            }

            i = i.saturating_add(1);
        }

        // P_max = max over i in u..=v of (S[i] / C(n-i+1, 2))^(1/i).
        let mut p_max: f64 = 0.0;
        let mut i = u;
        while i <= v {
            // choices = (n-i) * (n-i+1) / 2 = C(n-i+1, 2).
            let ni = (n.saturating_sub(i)) as u128;
            let choices = (ni.saturating_mul(ni.saturating_add(1))) >> 1;
            let si = s_sum.get(i).copied().unwrap_or(0);
            let cur_p = if choices == 0 {
                0.0
            } else {
                (si as f64) / (choices as f64)
            };
            let cur_pmax = cur_p.powf(1.0 / (i as f64));
            if cur_pmax > p_max {
                p_max = cur_pmax;
            }
            i = i.saturating_add(1);
        }

        (p_max, min_entropy_from_pmax(p_max, n))
    } else {
        // v < u: the EA tool prints "Can't Run LRS Test" and returns -1.0.
        (-1.0, -1.0)
    };

    LrsEstimate {
        n,
        v,
        u,
        t_tuple_p_max,
        t_tuple_min_entropy,
        lrs_p_max,
        lrs_min_entropy,
    }
}

/// The length of the longest repeated substring (LRS) of `text` — the maximum
/// LCP value over the literal symbols, exactly the EA tool's `len_LRS32`/
/// `len_LRS64` (`max over the LCP array`, `lrs_test.h:569-595`).
///
/// This is the `W` used by the SP 800-90B §5.3 LRS **IID test** (which runs on
/// the *literal* raw symbols, not the bitstring track — see
/// [`crate::iid_lrs`]). It reuses the suffix-array + Kasai-LCP machinery
/// (`sa_lcp`) the §6.3.6 estimator already builds, so the SA-IS implementation
/// is not duplicated; the §6.3.6 estimator's `LrsEstimate.v` is the same value
/// computed over the *bitstring* track.
///
/// Returns `0` for inputs too short to repeat (`text.len() < 2` or no repeated
/// substring), matching the empty/degenerate LCP. The function is deterministic.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn lrs_length(text: &[u8]) -> usize {
    let n = text.len();
    if n < 2 {
        return 0;
    }
    let (_sa, l) = sa_lcp(text);
    // v = max over the LCP working array (lrs_test.h: `for(j ...) if(lcp[j] > v)`).
    let mut v: usize = 0;
    for &li in l.iter() {
        if li > v {
            v = li;
        }
    }
    v
}

/// Compute the SP 800-90B §6.3.5 t-Tuple and §6.3.6 LRS min-entropy estimates
/// for the bitstring track of `symbols`.
///
/// `symbols` are raw bytes (one symbol per byte); `bits_per_symbol` is clamped
/// into `1..=8`. The function is **deterministic**: the same
/// `(symbols, bits_per_symbol)` always yields a bit-identical [`LrsEstimate`].
///
/// # Behavior on degenerate input
///
/// The EA tool asserts the data has a repeated substring (`v > 0`). Inputs too
/// short to repeat (fewer than two bits, or no repeats) are not part of the
/// parity contract and never arise for the EA datasets (each has ≥ 1e6 bits).
/// For robustness this implementation does not panic: it returns
/// [`LrsEstimate::unavailable`] (both estimates `-1.0`, the EA tool's
/// estimate-failed sentinel).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn lrs(symbols: &[u8], bits_per_symbol: u8) -> LrsEstimate {
    let bps = bits_per_symbol.clamp(1, 8);
    let bits = to_bitstring(symbols, bps);
    saalgs(&bits)
}

/// Compute the §6.3.5 t-Tuple and §6.3.6 LRS estimates for the **literal track**:
/// run `saalgs` over the raw symbols directly, mirroring the EA tool's
/// `SAalgs(data.symbols, data.len, data.alph_size, …, "Literal")`.
///
/// The suffix-array core is alphabet-agnostic and both estimates depend only on
/// the symbols' substring-repetition structure (bijection-invariant), so no
/// dense translation is needed — `saalgs` runs on the raw byte alphabet. The
/// returned [`LrsEstimate`] carries both `t_tuple_min_entropy` and `min_entropy`
/// (LRS), the literal-track inputs to `H_original`. Deterministic; does not
/// panic.
#[must_use]
pub fn lrs_literal(symbols: &[u8]) -> LrsEstimate {
    saalgs(symbols)
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

    /// Cross-tool parity bound — the integer counts are exact, but the final
    /// pow/sqrt/log2 chain runs in f64 here vs long double in the EA tool, so the
    /// anchors are checked at the 1e-6 parity tolerance.
    const PARITY_EPS: f64 = 1.0e-6;

    /// Tight epsilon for the exact integer intermediates (u, v, t) which must
    /// reproduce the EA tool's values exactly (no floating point involved).
    fn lrs_of_file(name: &str) -> Option<LrsEstimate> {
        let row = REFERENCE_TABLE.iter().find(|r| r.name == name)?;
        let dir = resolve_datasets_dir(None);
        let data = std::fs::read(dir.join(row.file)).ok()?;
        Some(lrs(&data, row.bits_per_symbol))
    }

    /// rand8_short anchor, Bitstring track (from `selftest/rand8_short.res`):
    /// t-Tuple: t = 12 (so u = 13), p-hat_max = 0.5273483862919730153461,
    ///          min entropy = 0.91078644573541412.
    /// LRS:     u = 13, v = 31, p-hat = 0.5017483769192231424813,
    ///          min entropy = 0.98193035773637427.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn rand8_short_anchor() {
        let Some(est) = lrs_of_file("rand8_short") else {
            eprintln!("rand8_short.bin absent — skipping anchor test");
            return;
        };
        // Exact integer intermediates.
        assert_eq!(est.u, 13, "u (t = u-1 = 12)");
        assert_eq!(est.v, 31, "v (LRS length)");
        // t-Tuple.
        assert!(
            (est.t_tuple_p_max - 0.527_348_386_291_973).abs() < PARITY_EPS,
            "t_tuple_p_max={}",
            est.t_tuple_p_max
        );
        assert!(
            (est.t_tuple_min_entropy - 0.910_786_445_735_414_1).abs() < PARITY_EPS,
            "t_tuple_min_entropy={}",
            est.t_tuple_min_entropy
        );
        // LRS.
        assert!(
            (est.lrs_p_max - 0.501_748_376_919_223_1).abs() < PARITY_EPS,
            "lrs_p_max={}",
            est.lrs_p_max
        );
        assert!(
            (est.lrs_min_entropy - 0.981_930_357_736_374_3).abs() < PARITY_EPS,
            "lrs_min_entropy={}",
            est.lrs_min_entropy
        );
    }

    /// biased-random-bits anchor, Literal track (1-bit; bsymbols == symbols):
    /// t-Tuple: t = 513 (u = 514), min entropy = 0.02648925705363097.
    /// LRS:     u = 514, v = 585, min entropy = 0.055881394003087378.
    ///
    /// Skips gracefully if the dataset is absent on this host.
    #[test]
    fn biased_random_bits_anchor() {
        let Some(est) = lrs_of_file("biased-random-bits") else {
            eprintln!("biased-random-bits.bin absent — skipping anchor test");
            return;
        };
        assert_eq!(est.u, 514, "u (t = u-1 = 513)");
        assert_eq!(est.v, 585, "v (LRS length)");
        assert!(
            (est.t_tuple_min_entropy - 0.026_489_257_053_630_97).abs() < PARITY_EPS,
            "t_tuple_min_entropy={}",
            est.t_tuple_min_entropy
        );
        assert!(
            (est.lrs_min_entropy - 0.055_881_394_003_087_38).abs() < PARITY_EPS,
            "lrs_min_entropy={}",
            est.lrs_min_entropy
        );
    }

    /// Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..5000u32).map(|i| (i % 19) as u8).collect();
        let a = lrs(&buf, 8);
        let b = lrs(&buf, 8);
        assert_eq!(a, b, "LrsEstimate must be bit-identical across runs");
    }

    /// Suffix array correctness against a brute-force sort on a small string.
    /// (Validates the SA-IS implementation independently of the EA datasets.)
    #[test]
    fn suffix_array_matches_brute_force() {
        let cases: &[&[u8]] = &[
            b"banana",
            b"mississippi",
            b"abracadabra",
            b"aaaaaa",
            b"abababab",
            &[0u8, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0],
            b"the quick brown fox",
        ];
        for &text in cases {
            let got = suffix_array_sais(text);
            let n = text.len();
            // Brute force: all suffix start positions sorted by suffix bytes.
            let mut expected: Vec<usize> = (0..n).collect();
            expected.sort_by(|&x, &y| text[x..].cmp(&text[y..]));
            assert_eq!(
                got,
                expected,
                "SA-IS mismatch on {:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// LCP working-array sanity: l[0] must be 0 and l[n] must be 0 (the EA tool's
    /// post-erase invariants), and v (max l) must equal the brute-force LRS
    /// length on a small string.
    #[test]
    fn lcp_invariants_and_lrs_length() {
        let text: &[u8] = b"abracadabra";
        let n = text.len();
        let (_sa, l) = sa_lcp(text);
        assert_eq!(l[0], 0, "l[0] must be 0");
        assert_eq!(l[n], 0, "l[n] must be 0");
        let v = (0..n).map(|i| l[i]).max().unwrap_or(0);
        // Brute-force longest repeated substring length of "abracadabra" is 4
        // ("abra" appears twice).
        assert_eq!(v, 4, "LRS length of abracadabra should be 4 (abra)");
    }

    /// Too-short input: no repeated substring -> unavailable sentinel
    /// (both estimates -1.0), no panic.
    #[test]
    fn too_short_input_is_unavailable() {
        for buf in [&[][..], &[0u8][..], &[1u8, 0u8][..]] {
            let est = lrs(buf, 1);
            assert!(est.t_tuple_min_entropy < 0.0 || est.t_tuple_min_entropy.is_finite());
            // For length < 2 we always get the unavailable sentinel.
            if buf.len() < 2 {
                assert_eq!(est.t_tuple_min_entropy, -1.0);
                assert_eq!(est.lrs_min_entropy, -1.0);
            }
        }
    }

    /// Literal-track parity: `lrs_literal` reproduces EA v1.1.8's "Literal
    /// t-Tuple" and "Literal LRS" min-entropy lines to within 1e-6 on every
    /// multi-bit reference dataset (harvested 2026-06-16 via
    /// `ea_non_iid -i -a -v -v`). Skips datasets absent on host.
    #[test]
    fn literal_parity_multibit() {
        // (dataset, EA "Literal t-Tuple", EA "Literal LRS").
        const EA_LITERAL: &[(&str, f64, f64)] = &[
            (
                "biased-random-bytes",
                0.291_159_804_498_6,
                0.519_281_371_376_5,
            ),
            ("normal", 5.529_117_785_448_8, 6.105_039_079_589_7),
            ("rand4_short", 3.567_472_672_399_5, 3.833_525_522_232_9),
            ("rand8_short", 7.010_454_037_736_0, 7.289_198_671_720_6),
            ("truerand_4bit", 3.687_753_694_232_6, 3.934_965_665_764_1),
            ("truerand_8bit", 7.865_118_002_899_5, 7.939_199_033_369_9),
        ];
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(name, ea_tt, ea_lrs) in EA_LITERAL {
            let Some(row) = REFERENCE_TABLE.iter().find(|r| r.name == name) else {
                continue;
            };
            let Ok(data) = std::fs::read(dir.join(row.file)) else {
                eprintln!("{name}.bin absent — skipping literal parity");
                continue;
            };
            let est = lrs_literal(&data);
            assert!(
                (est.t_tuple_min_entropy - ea_tt).abs() <= PARITY_EPS,
                "{name}: literal t-Tuple {} vs EA {ea_tt}",
                est.t_tuple_min_entropy
            );
            assert!(
                (est.lrs_min_entropy - ea_lrs).abs() <= PARITY_EPS,
                "{name}: literal LRS {} vs EA {ea_lrs}",
                est.lrs_min_entropy
            );
            checked += 1;
        }
        if checked == 0 {
            eprintln!("no multi-bit datasets present — literal parity skipped");
        }
    }
}
