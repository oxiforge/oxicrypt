//! SP 800-90B §5.1 permutation testing battery — the 19-statistic IID test.
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 §5.1 permutation tests
//! (`cpp/iid/permutation_tests.h`, with the RNG/shuffle/stats helpers from
//! `cpp/shared/utils.h`). Like the rest of `oxicrypt-maxwell` it is **outside
//! the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The §5.1 permutation test (the shuffle test)
//!
//! Given a dataset, the test computes 19 order- and value-sensitive statistics
//! on the original sequence (the *unpermuted* values `t[i]`), then repeatedly
//! shuffles the sequence and recomputes the same 19 statistics on each shuffle.
//! For each statistic it counts how many shuffles produced a value greater than
//! (`C[i][0]`), equal to (`C[i][1]`), or less than (`C[i][2]`) the original. A
//! statistic is *IID-consistent* when the original value sits comfortably inside
//! the shuffle distribution: `(C0 + C1 > 5) && (C1 + C2 > 5)`. The data passes
//! the IID assumption iff **all** statistics are IID-consistent.
//!
//! The intuition: if the data is IID, the order of the samples carries no
//! information, so the original sequence's statistics look like a random draw
//! from the permutation distribution. If some statistic of the original is
//! extreme (only ever exceeded, or only ever matched), order matters → not IID.
//!
//! # Data model (matched from `utils.h` `calc_stats` and the EA driver)
//!
//! Datasets are raw bytes, **one symbol per byte** (the same `&[u8]` convention
//! the §6.3 estimators use). The EA tool internally "maps down" the present
//! symbol values to a contiguous `0..alph_size` range before running the
//! order/equality-based statistics, but that map is **monotonic
//! (order-preserving)**, so every statistic here (max, runs, collisions,
//! equality counts, lagged products) is invariant under it. We therefore compute
//! the 19 statistics **directly on the raw bytes**, matching the EA values
//! exactly. The only branch that matters is binary vs non-binary:
//!
//! - [`alph_size`](AlphabetStats::alph_size) — number of distinct byte values
//!   present.
//! - `binary` ≡ (`alph_size == 2`).
//! - `rawmean` = (sum of raw bytes) / len  (used by `excursion`).
//! - `median` = `0.5` if binary; else the median of the sorted raw bytes (odd
//!   len → middle element; even len → mean of the two middle elements).
//!
//! For binary data, two block conversions of the raw bit-sequence appear
//! (`permutation_tests.h` lines 27–50):
//!
//! - [`conversion1`]: each output byte = **count of 1-bits** in its 8-bit block
//!   (0..=8). Used by the directional, periodicity, and covariance families.
//! - [`conversion2`]: each output byte = the 8-bit block read as a **binary
//!   number** (0..=255). Used by the collision family.
//!
//! # The 19 statistics (EA `test_names`, index order)
//!
//! | # | Name | On non-binary | On binary |
//! |---|------|---------------|-----------|
//! | 0 | excursion | raw bytes + rawmean | raw bits + rawmean |
//! | 1 | numDirectionalRuns | alt_seq1(raw) | alt_seq1(conversion1) |
//! | 2 | lenDirectionalRuns | alt_seq1(raw) | alt_seq1(conversion1) |
//! | 3 | numIncreasesDecreases | alt_seq1(raw) | alt_seq1(conversion1) |
//! | 4 | numRunsMedian | alt_seq2(raw, median) | alt_seq2(raw bits, 0.5) |
//! | 5 | lenRunsMedian | alt_seq2(raw, median) | alt_seq2(raw bits, 0.5) |
//! | 6 | avgCollision | find_collisions(raw, alph) | find_collisions(conversion2, 256) |
//! | 7 | maxCollision | find_collisions(raw, alph) | find_collisions(conversion2, 256) |
//! | 8–12 | periodicity(1,2,8,16,32) | raw bytes | conversion1 |
//! | 13–17 | covariance(1,2,8,16,32) | raw bytes | conversion1 |
//! | 18 | compression | bzip2 of decimal text | bzip2 of decimal text |
//!
//! Note the runsMedian family (4, 5): for binary the EA tool uses the **raw bit
//! values** with `median = 0.5` (`consecutive_runs_tests` calls
//! `alt_sequence2(data, 0.5, …)` on `dp->symbols`, *not* conversion1), unlike
//! the directional family which uses conversion1.
//!
//! # The compression slot
//!
//! Statistic 18 (`compression`) is the bzip2-compressed length of the
//! space-separated decimal text of the raw bytes (EA `compression()`,
//! `blockSize100k = 5`). It is computed **bit-exactly** against the EA tool via
//! the pure-Rust `bzip2` crate (libbz2-rs-sys backend — no C, no `bzip2-sys`):
//! the compressed length matches EA's `ea_iid -v -v -v` "Unpermuted result
//! compression" value byte-for-byte on the oracle datasets (rand1_short = 1611,
//! rand4_short = 5520, rand8_short = 10987). As `oxicrypt-maxwell` is
//! out-of-boundary tooling, this third-party dependency never touches the
//! validated module or its zero-dependency claim (see
//! `docs/security-policy/security-policy.md`).
//!
//! - [`compression`] returns the real compressed byte length as an `f64`.
//! - The compression slot (index 18) is **included** in the verdict
//!   ([`PermutationVerdict::compression_included`] is `true`) — it participates
//!   like every other statistic.
//!
//! # Determinism (ISC-134)
//!
//! The EA tool seeds its xoshiro256** RNG from `/dev/urandom`, which makes its
//! shuffle non-deterministic. This module instead uses a **fixed,
//! nothing-up-my-sleeve seed** ([`SHUFFLE_SEED`]) so that
//! [`permutation_stats`] and [`permutation_test`] are fully deterministic: the
//! same input always yields a bit-identical result. The shuffle never reads any
//! entropy source. The xoshiro256** generator, the Lemire bounded
//! `randomRange64`, and the Fisher–Yates shuffle are transcribed verbatim from
//! `utils.h`; only the seed source differs.

/// Number of permutation statistics (EA `num_tests`).
pub const NUM_TESTS: usize = 19;

/// Number of shuffles per run (EA `PERMS`, `utils.h`).
pub const PERMS: usize = 10_000;

/// The five lag parameters `p` shared by the periodicity (§5.1.9) and
/// covariance (§5.1.10) families (EA hard-codes `1, 2, 8, 16, 32`).
const LAGS: [usize; 5] = [1, 2, 8, 16, 32];

/// Index of the compression statistic in the 19-element arrays.
const COMPRESSION_IDX: usize = 18;

/// The statistic names, in the exact index order EA uses (`test_names`).
pub const TEST_NAMES: [&str; NUM_TESTS] = [
    "excursion",
    "numDirectionalRuns",
    "lenDirectionalRuns",
    "numIncreasesDecreases",
    "numRunsMedian",
    "lenRunsMedian",
    "avgCollision",
    "maxCollision",
    "periodicity(1)",
    "periodicity(2)",
    "periodicity(8)",
    "periodicity(16)",
    "periodicity(32)",
    "covariance(1)",
    "covariance(2)",
    "covariance(8)",
    "covariance(16)",
    "covariance(32)",
    "compression",
];

/// Fixed nothing-up-my-sleeve seed for the deterministic shuffle (ISC-134).
///
/// These are the first 256 bits of the fractional part of √2 expressed in hex
/// (`0x6a09e667f3bcc908…`, the SHA-512 IV words for √2/√3/√5/√7), a standard
/// "nothing-up-my-sleeve" choice. The exact value is irrelevant to correctness
/// — any fixed constant makes the shuffle reproducible — but documenting a
/// principled origin avoids any suspicion of a value chosen to flatter results.
/// xoshiro256** requires a non-zero state; all four words are non-zero.
pub const SHUFFLE_SEED: [u64; 4] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
];

/// Baseline statistics over a dataset (EA `calc_stats` + alphabet size).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlphabetStats {
    /// Number of distinct byte values present in the data.
    pub alph_size: usize,
    /// `true` when exactly two distinct values are present (`alph_size == 2`).
    pub binary: bool,
    /// Mean of the raw bytes (`sum / len`); `0.0` for empty input.
    pub rawmean: f64,
    /// Median: `0.5` if binary, else the median of the sorted raw bytes.
    pub median: f64,
}

/// The 19 unpermuted statistic values for a dataset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PermutationStats {
    /// `values[i]` is the original (unpermuted) value of statistic `i`.
    /// `values[18]` (compression) is the real bzip2-compressed byte length,
    /// computed bit-exactly vs the EA tool — see the module compression-slot note.
    pub values: [f64; NUM_TESTS],
    /// The statistic names, parallel to `values`.
    pub names: [&'static str; NUM_TESTS],
}

/// The full permutation-test verdict for a dataset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PermutationVerdict {
    /// `c_counts[i] = (C[i][0], C[i][1], C[i][2])` — the (greater, equal, less)
    /// tallies across the completed shuffles for statistic `i`.
    pub c_counts: [(u64, u64, u64); NUM_TESTS],
    /// `per_test_pass[i]` — whether statistic `i` is IID-consistent
    /// (`(C0 + C1 > 5) && (C1 + C2 > 5)`). All 19 statistics — including the
    /// compression slot (index 18) — count toward the verdict.
    pub per_test_pass: [bool; NUM_TESTS],
    /// `true` iff every statistic passed (all 19, including compression, are
    /// active).
    pub is_iid: bool,
    /// Whether the compression slot (index 18) was computed and counted toward
    /// the verdict. Always `true`: compression is computed bit-exactly vs the EA
    /// tool and participates in the verdict like every other statistic.
    pub compression_included: bool,
}

// ---------------------------------------------------------------------------
// Baseline statistics
// ---------------------------------------------------------------------------

/// Compute the baseline statistics (alphabet size, binary flag, rawmean,
/// median) for a dataset, matching EA `calc_stats` plus the alphabet-size scan.
///
/// Empty input yields `alph_size = 0`, `binary = false`, `rawmean = 0.0`,
/// `median = 0.0` (no panic; the statistics over empty data are all trivially
/// `0`).
#[must_use]
#[allow(
    // `len` is a slice length (fits usize and u64 on supported targets); the
    // sum of bytes fits u64; the casts to f64 are the EA tool's own `(double)`
    // casts and the parity bound absorbs the rounding.
    clippy::cast_precision_loss,
    // `len / 2` is the median index — integer division is exactly EA's
    // `dp->len / 2` and the `len & 1` parity branch handles the odd case.
    clippy::integer_division,
    // `(hi + lo) / 2.0` is the even-length median as EA writes it
    // (`(v[half] + v[half-1]) / 2.0`); these are small f64s (bytes), so the
    // overflow `u8::midpoint` guards against cannot occur, and the float form
    // matches EA exactly. Using `f64::midpoint` would change rounding.
    clippy::manual_midpoint
)]
pub fn alphabet_stats(data: &[u8]) -> AlphabetStats {
    if data.is_empty() {
        return AlphabetStats {
            alph_size: 0,
            binary: false,
            rawmean: 0.0,
            median: 0.0,
        };
    }

    // Distinct-value count and sum in one pass.
    let mut present = [false; 256];
    let mut sum: u64 = 0;
    for &b in data {
        if let Some(slot) = present.get_mut(b as usize) {
            *slot = true;
        }
        sum = sum.saturating_add(u64::from(b));
    }
    let alph_size = present.iter().filter(|&&p| p).count();
    let binary = alph_size == 2;

    let len = data.len();
    let rawmean = (sum as f64) / (len as f64);

    let median = if binary {
        // EA forces median = 0.5 for binary data (used only by §5.1.5/5.1.6).
        0.5
    } else {
        // Median of the sorted raw bytes. Monotonic mapping makes this identical
        // to EA's median over its mapped symbols.
        let mut v = data.to_vec();
        v.sort_unstable();
        let half = len / 2;
        if len % 2 == 1 {
            // Odd length: the middle element. half = len/2 is in bounds.
            f64::from(v.get(half).copied().unwrap_or(0))
        } else {
            // Even length: mean of the two middle elements. half >= 1 here
            // because len >= 2 (alph_size >= 2 implies len >= 2).
            let hi = f64::from(v.get(half).copied().unwrap_or(0));
            let lo = f64::from(v.get(half.saturating_sub(1)).copied().unwrap_or(0));
            (hi + lo) / 2.0
        }
    };

    AlphabetStats {
        alph_size,
        binary,
        rawmean,
        median,
    }
}

// ---------------------------------------------------------------------------
// Binary conversions (EA §5.1 Conversion I / II)
// ---------------------------------------------------------------------------

/// EA §5.1 Conversion I: partition the binary sequence into 8-bit blocks; each
/// output byte is the **count of 1-bits** in its block (0..=8). Output length is
/// `ceil(len / 8)`. (`permutation_tests.h` lines 27–35.)
#[must_use]
#[allow(
    // `i / 8` is the 8-bit block index (EA `ret[i/8]`); integer division is the
    // intended block math.
    clippy::integer_division
)]
fn conversion1(data: &[u8]) -> Vec<u8> {
    let out_len = data.len().div_ceil(8);
    let mut out = vec![0u8; out_len];
    for (i, &b) in data.iter().enumerate() {
        if let Some(slot) = out.get_mut(i / 8) {
            // Each input bit is 0 or 1; eight of them sum to at most 8.
            *slot = slot.saturating_add(b);
        }
    }
    out
}

/// EA §5.1 Conversion II: partition the binary sequence into 8-bit blocks; each
/// output byte is the block read as a **binary number**
/// (`out[i/8] += data[i] << (7 - i%8)`), MSB-first. Output length is
/// `ceil(len / 8)`. (`permutation_tests.h` lines 42–50.)
#[must_use]
#[allow(
    // `i / 8` is the block index and `7 - i%8` is the in-block MSB-first shift
    // (EA `ret[i/8] += data[i] << (7 - i%8)`); integer division and the bounded
    // shift subtraction (`i%8` is 0..=7) are the intended block math.
    clippy::integer_division,
    clippy::arithmetic_side_effects
)]
fn conversion2(data: &[u8]) -> Vec<u8> {
    let out_len = data.len().div_ceil(8);
    let mut out = vec![0u8; out_len];
    for (i, &b) in data.iter().enumerate() {
        if let Some(slot) = out.get_mut(i / 8) {
            // shift in 0..=7; b is 0 or 1; the byte never overflows.
            *slot = slot.saturating_add(b << (7 - (i % 8)));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The 11 statistic primitives (EA §5.1.1 – §5.1.11)
// ---------------------------------------------------------------------------

/// §5.1.1 Excursion: max over `i` of `|running_sum(0..=i) - (i+1)·mean|`.
/// (`permutation_tests.h` lines 57–72.) Operates on `&[u8]` values (raw bytes
/// for non-binary, raw bits for binary).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn excursion(data: &[u8], rawmean: f64) -> f64 {
    let mut running_sum = 0.0_f64;
    let mut max = 0.0_f64;
    for (i, &b) in data.iter().enumerate() {
        running_sum += f64::from(b);
        // (i+1) as f64: i < len <= usize::MAX; the index count is exact in f64
        // for any realistic dataset (< 2^53 samples).
        let d_i = (running_sum - ((i as f64) + 1.0) * rawmean).abs();
        if d_i > max {
            max = d_i;
        }
    }
    max
}

/// EA `alt_sequence1`: `ret[i] = (data[i] > data[i+1]) ? -1 : 1` for
/// `i in 0..len-1`. (`permutation_tests.h` lines 80–88.)
#[must_use]
fn alt_sequence1(data: &[u8]) -> Vec<i8> {
    if data.len() < 2 {
        return Vec::new();
    }
    let pairs = data.len().saturating_sub(1);
    let mut ret = Vec::with_capacity(pairs);
    for i in 0..pairs {
        // i and i+1 both < len; .get() makes the access total.
        let (Some(&a), Some(&b)) = (data.get(i), data.get(i.saturating_add(1))) else {
            break;
        };
        ret.push(if a > b { -1 } else { 1 });
    }
    ret
}

/// EA `alt_sequence2`: `ret[i] = (data[i] < median) ? -1 : 1` for
/// `i in 0..len`. (`permutation_tests.h` lines 94–102.)
#[must_use]
fn alt_sequence2(data: &[u8], median: f64) -> Vec<i8> {
    let mut ret = Vec::with_capacity(data.len());
    for &b in data {
        ret.push(if f64::from(b) < median { -1 } else { 1 });
    }
    ret
}

/// EA `num_directional_runs`: number of maximal constant runs in `alt_seq`
/// (one for the first element, plus one per adjacent change).
/// (`permutation_tests.h` lines 119–133.)
#[must_use]
fn num_directional_runs(alt_seq: &[i8]) -> u64 {
    if alt_seq.is_empty() {
        return 0;
    }
    let mut num_runs: u64 = 1; // the first run always exists for non-empty input
    for i in 1..alt_seq.len() {
        if alt_seq.get(i) != alt_seq.get(i.saturating_sub(1)) {
            num_runs = num_runs.saturating_add(1);
        }
    }
    num_runs
}

/// EA `len_directional_runs`: length of the longest constant run in `alt_seq`.
/// (`permutation_tests.h` lines 146–169.) Returns 0 for empty input (EA
/// initializes `max_run = 0` and never enters the loop or the final fixup with
/// a meaningful `run`; for non-empty input the minimum is 1).
#[must_use]
fn len_directional_runs(alt_seq: &[i8]) -> u64 {
    if alt_seq.is_empty() {
        return 0;
    }
    let mut max_run: u64 = 0;
    let mut run: u64 = 1;
    for i in 1..alt_seq.len() {
        if alt_seq.get(i) == alt_seq.get(i.saturating_sub(1)) {
            run = run.saturating_add(1);
        } else {
            if run > max_run {
                max_run = run;
            }
            run = 1;
        }
    }
    if run > max_run {
        max_run = run;
    }
    max_run
}

/// EA `num_increases_decreases`: `max(#(+1), #(-1))` in `alt_seq`.
/// (`permutation_tests.h` lines 176–187.)
#[must_use]
fn num_increases_decreases(alt_seq: &[i8]) -> u64 {
    let pos = alt_seq.iter().filter(|&&v| v == 1).count() as u64;
    let total = alt_seq.len() as u64;
    let neg = total.saturating_sub(pos);
    pos.max(neg)
}

/// EA `find_collisions`: walk forward tracking seen values in a reset-per-step
/// boolean table; on a repeat, push the window length `(j+1)` and advance the
/// outer index past it. (`permutation_tests.h` lines 190–224.)
///
/// **Deviation (documented):** EA sizes the `dups` table to `k` (= `alph_size`
/// for non-binary, `256` for binary), indexing it by the **mapped** symbol
/// (`0..k`). We run on **raw bytes** (0..=255) without mapping, so we size the
/// table to a fixed `256` regardless of `k`. This is in-bounds for any byte and
/// produces *identical* collision gaps: only values actually present in the data
/// are ever marked or tested, and equality of byte values is exactly equality of
/// mapped values (the map is a bijection on present values). The `k` parameter
/// is thus unused here beyond documenting the EA call; we keep the signature for
/// fidelity but always allocate 256 slots.
#[must_use]
fn find_collisions(data: &[u8]) -> Vec<u64> {
    let n = data.len();
    let mut ret: Vec<u64> = Vec::new();
    let mut dups = [false; 256];

    let mut i: usize = 0;
    let mut j: usize = 0;

    while i.saturating_add(j) < n {
        // Reset the seen-table for this outer step.
        dups.fill(false);

        while i.saturating_add(j) < n {
            let Some(&val) = data.get(i.saturating_add(j)) else {
                break;
            };
            // dups is 256-wide; val as usize is 0..=255, always in bounds.
            let seen = dups.get(val as usize).copied().unwrap_or(false);
            if seen {
                // Record the window length (j+1), advance the outer loop past
                // the collision, reset, and break the inner loop — exactly as EA.
                ret.push((j as u64).saturating_add(1));
                i = i.saturating_add(j);
                j = 0;
                break;
            }
            if let Some(slot) = dups.get_mut(val as usize) {
                *slot = true;
            }
            j = j.saturating_add(1);
        }

        i = i.saturating_add(1);
    }

    ret
}

/// §5.1.7 avgCollision: mean of the collision-gap sequence (EA `avg_collision`
/// = `divide(sum, size)`; `divide` returns 0 for an empty/zero divisor).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn avg_collision(col_seq: &[u64]) -> f64 {
    if col_seq.is_empty() {
        return 0.0;
    }
    let sum: u64 = col_seq.iter().fold(0u64, |a, &x| a.saturating_add(x));
    (sum as f64) / (col_seq.len() as f64)
}

/// §5.1.8 maxCollision: max of the collision-gap sequence (0 for empty).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn max_collision(col_seq: &[u64]) -> f64 {
    col_seq.iter().copied().max().unwrap_or(0) as f64
}

/// §5.1.9 periodicity(p): count of `i in 0..n-p` with `data[i] == data[i+p]`.
/// (`permutation_tests.h` lines 253–265.) Returns 0 if `n < p` (EA asserts
/// `n >= p`; we fail closed to 0 rather than panic).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn periodicity(data: &[u8], p: usize) -> f64 {
    let n = data.len();
    if n < p {
        return 0.0;
    }
    let limit = n.saturating_sub(p);
    let mut t: u64 = 0;
    for i in 0..limit {
        if data.get(i) == data.get(i.saturating_add(p)) {
            t = t.saturating_add(1);
        }
    }
    t as f64
}

/// §5.1.10 covariance(p): `sum over i in 0..n-p of data[i]·data[i+p]`.
/// (`permutation_tests.h` lines 272–280.) Accumulates in u64 (max product
/// 255·255 ≈ 6.5e4, times up to ~1e6 terms ≈ 6.5e10, well within u64). Returns
/// 0 if `n < p`.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    // n, p, i, a, b, t are the spec's loop/lag/value names transcribed from EA.
    clippy::many_single_char_names
)]
fn covariance(data: &[u8], p: usize) -> f64 {
    let n = data.len();
    if n < p {
        return 0.0;
    }
    let limit = n.saturating_sub(p);
    let mut t: u64 = 0;
    for i in 0..limit {
        let (Some(&a), Some(&b)) = (data.get(i), data.get(i.saturating_add(p))) else {
            break;
        };
        t = t.saturating_add(u64::from(a).saturating_mul(u64::from(b)));
    }
    t as f64
}

/// §5.1.11 compression — bzip2-compressed length of the space-separated decimal
/// text of the raw bytes, at bzip2 level 5.
///
/// Transcribes the EA tool's `compression()` (`cpp/iid/permutation_tests.h`):
/// each sample is formatted as `"%u"` decimal, values are joined by single
/// spaces with **no trailing space and no newline**, and the buffer is passed to
/// `BZ2_bzBuffToBuffCompress(dest, &dest_len, msg, curlen, 5, 0, 0)` —
/// `blockSize100k = 5`, `verbosity = 0`, `workFactor = 0` (libbz2's default
/// work factor of 30). The statistic is the compressed byte length.
///
/// Backed by the pure-Rust `bzip2` crate (libbz2-rs-sys backend — no C, no
/// `bzip2-sys`). `oxicrypt-maxwell` is **out-of-boundary** tooling, so this — the
/// workspace's first third-party dependency — never touches the validated module
/// or its zero-dependency claim; see `docs/security-policy/security-policy.md`.
/// The crate's `#![forbid(unsafe_code)]` is unaffected: the unavoidable bzip2
/// `unsafe` lives inside the dependency, not here.
///
/// Deterministic. In-memory bzip2 compression of a finite buffer cannot fail; on
/// the impossible error path the function returns [`f64::NAN`] rather than panic.
#[must_use]
fn compression(data: &[u8]) -> f64 {
    use std::fmt::Write as _;
    use std::io::Write as _;

    // EA decimal text: each byte as ASCII decimal, single-space separated, no
    // trailing space, no newline. `write!` into a String performs the `%u`
    // formatting without manual digit arithmetic and never fails for a String.
    let mut text = String::with_capacity(data.len().saturating_mul(4));
    for (i, &b) in data.iter().enumerate() {
        if i > 0 {
            text.push(' ');
        }
        if write!(text, "{b}").is_err() {
            return f64::NAN;
        }
    }

    // bzip2 level 5 (EA blockSize100k = 5), default work factor.
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(5));
    let compressed = encoder
        .write_all(text.as_bytes())
        .and_then(|()| encoder.finish());
    match compressed {
        // Lengths here are small (≤ a few KB); the usize→f64 cast is exact.
        #[allow(clippy::cast_precision_loss)]
        Ok(out) => out.len() as f64,
        Err(_) => f64::NAN,
    }
}

// ---------------------------------------------------------------------------
// The 19-statistic vector over one (possibly shuffled) sequence
// ---------------------------------------------------------------------------

/// Compute all 19 statistics over `data` given the baseline stats. The values
/// match EA `run_tests` (which dispatches to the per-family helpers, branching
/// on `alph_size == 2`). `active` selects which statistics to compute; an
/// inactive slot keeps the value it already holds in `out` (EA's early-exit:
/// once a statistic is decided, it stops being recomputed).
#[allow(
    // The family dispatch mirrors EA's run_tests verbatim; splitting it further
    // would obscure the 1:1 correspondence with the C source.
    clippy::too_many_lines,
    // dir_data/per_data/cov_data/col_data name the four per-family input slices;
    // the shared `_data` suffix is intentional and clearer than abbreviating.
    clippy::similar_names
)]
fn compute_all(
    data: &[u8],
    stats: &AlphabetStats,
    active: &[bool; NUM_TESTS],
    out: &mut [f64; NUM_TESTS],
) {
    // For the directional / periodicity / covariance / collision families the
    // binary branch first converts the raw bit-sequence; non-binary uses raw
    // bytes directly. We compute the converted vectors once and reuse them.
    let cs1: Vec<u8>;
    let cs2: Vec<u8>;
    let dir_data: &[u8];
    let per_data: &[u8];
    let cov_data: &[u8];
    let col_data: &[u8];

    if stats.binary {
        cs1 = conversion1(data);
        cs2 = conversion2(data);
        dir_data = &cs1;
        per_data = &cs1;
        cov_data = &cs1;
        col_data = &cs2;
    } else {
        dir_data = data;
        per_data = data;
        cov_data = data;
        col_data = data;
    }

    // Index-free slot access (the workspace denies `indexing_slicing`).
    let is_active = |i: usize| active.get(i).copied().unwrap_or(false);
    let set = |out: &mut [f64; NUM_TESTS], i: usize, v: f64| {
        if let Some(slot) = out.get_mut(i) {
            *slot = v;
        }
    };

    // 0: excursion — always on the raw bit/byte sequence with rawmean.
    if is_active(0) {
        set(out, 0, excursion(data, stats.rawmean));
    }

    // 1–3: directional family on alt_sequence1(dir_data).
    if is_active(1) || is_active(2) || is_active(3) {
        let alt1 = alt_sequence1(dir_data);
        #[allow(clippy::cast_precision_loss)]
        {
            if is_active(1) {
                set(out, 1, num_directional_runs(&alt1) as f64);
            }
            if is_active(2) {
                set(out, 2, len_directional_runs(&alt1) as f64);
            }
            if is_active(3) {
                set(out, 3, num_increases_decreases(&alt1) as f64);
            }
        }
    }

    // 4–5: runs-vs-median family on alt_sequence2.
    //   binary: raw bit values + median 0.5 (NOT conversion1);
    //   non-binary: raw bytes + median.
    if is_active(4) || is_active(5) {
        let alt2 = alt_sequence2(data, stats.median);
        #[allow(clippy::cast_precision_loss)]
        {
            if is_active(4) {
                set(out, 4, num_directional_runs(&alt2) as f64);
            }
            if is_active(5) {
                set(out, 5, len_directional_runs(&alt2) as f64);
            }
        }
    }

    // 6–7: collision family on find_collisions(col_data).
    if is_active(6) || is_active(7) {
        let col_seq = find_collisions(col_data);
        if is_active(6) {
            set(out, 6, avg_collision(&col_seq));
        }
        if is_active(7) {
            set(out, 7, max_collision(&col_seq));
        }
    }

    // 8–12: periodicity(p) on per_data.
    for (k, &p) in LAGS.iter().enumerate() {
        let idx = 8usize.saturating_add(k);
        if is_active(idx) {
            set(out, idx, periodicity(per_data, p));
        }
    }

    // 13–17: covariance(p) on cov_data.
    for (k, &p) in LAGS.iter().enumerate() {
        let idx = 13usize.saturating_add(k);
        if is_active(idx) {
            set(out, idx, covariance(cov_data, p));
        }
    }

    // 18: compression (bit-exact bzip2 length).
    if is_active(COMPRESSION_IDX) {
        set(out, COMPRESSION_IDX, compression(data));
    }
}

// ---------------------------------------------------------------------------
// xoshiro256** RNG + Lemire bounded range + Fisher–Yates (from utils.h)
// ---------------------------------------------------------------------------

/// `rotl(x, k)` — rotate-left, as in `utils.h` (`(x << k) | (x >> (64 - k))`).
/// Implemented via the intrinsic `rotate_left`, which is bit-identical to the C
/// expression for `0 < k < 64` (the only values used here: 7 and 45).
#[inline]
const fn rotl(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

/// xoshiro256** 1.0 next-output, transcribed verbatim from `utils.h`
/// (`xoshiro256starstar`). Advances `state` in place and returns the output.
#[inline]
#[allow(
    // s0..s3 are the canonical xoshiro state-word names; the short, similar
    // names mirror the reference C and keep the transcription readable.
    clippy::many_single_char_names,
    clippy::similar_names
)]
fn xoshiro256starstar(state: &mut [u64; 4]) -> u64 {
    // Destructure into named words to avoid `indexing_slicing` (denied
    // workspace-wide) while transcribing the C update verbatim.
    let [mut s0, mut s1, mut s2, mut s3] = *state;

    let result = rotl(s1.wrapping_mul(5), 7).wrapping_mul(9);
    let t = s1 << 17;

    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;

    s2 ^= t;

    s3 = rotl(s3, 45);

    *state = [s0, s1, s2, s3];
    result
}

/// Public next-output of the verbatim xoshiro256** generator ([`utils.h`
/// `xoshiro256starstar`]). Advances `state` in place and returns the raw u64.
///
/// Exposed so other modules in this crate (e.g. the §3.1.4 restart cutoff
/// Monte-Carlo, `restart.rs`) can reuse the exact same vetted generator rather
/// than re-transcribing it. Callers seed `state` with a fixed
/// nothing-up-my-sleeve constant ([`SHUFFLE_SEED`]) for determinism — EA itself
/// seeds from `/dev/urandom`, so its cutoff varies run-to-run; the maxwell
/// port uses a fixed seed so `X_cutoff` is reproducible (ISC-134).
#[inline]
#[must_use]
pub fn xoshiro_next(state: &mut [u64; 4]) -> u64 {
    xoshiro256starstar(state)
}

/// Uniform `f64` in `[0, 1)` from the xoshiro256** generator, matching EA
/// `randomUnit` ([`utils.h`] line 650): `(next() >> 11) * 2^-53`. Advances
/// `state` in place.
///
/// The top 53 bits of the 64-bit output are scaled into the unit interval; this
/// is the standard "53 significant bits" double-precision uniform and is
/// bit-identical to EA's expression.
#[inline]
#[must_use]
#[allow(
    // `>> 11` leaves 53 bits, which is exactly representable in f64's 53-bit
    // mantissa: the cast is lossless by construction, not a truncation.
    clippy::cast_precision_loss
)]
pub fn random_unit(state: &mut [u64; 4]) -> f64 {
    (xoshiro256starstar(state) >> 11) as f64 * 2.0_f64.powi(-53)
}

/// Lemire bounded integer in `[0, s]` (inclusive), transcribed from `utils.h`
/// (`randomRange64`), including the rejection loop. Uses u128 for the multiply.
#[inline]
#[allow(
    // `m as u64` deliberately takes m mod 2^64 (the low word, EA's `l`), and
    // `m >> 64` is the high word (the result) — both intended truncations from
    // the u128 multiply, exactly as the reference C does.
    clippy::cast_possible_truncation,
    // `s + 1` and `(-s) % s` are the Lemire derivation; wrapping is intended on
    // the `-s` (C unsigned negation) and `s` never overflows for the inputs used
    // (`s <= len - 1`), but we use wrapping ops explicitly to be total.
    clippy::arithmetic_side_effects,
    // s, x, m, l, t are Lemire's variable names transcribed from utils.h.
    clippy::many_single_char_names
)]
fn random_range64(s: u64, state: &mut [u64; 4]) -> u64 {
    let mut x = xoshiro256starstar(state);

    if s == u64::MAX {
        return x;
    }

    // We want [0, s], not [0, s): EA increments s.
    let s = s.wrapping_add(1);
    let mut m = u128::from(x).wrapping_mul(u128::from(s));
    let mut l = m as u64; // m mod 2^64

    if l < s {
        // t = (2^64 - s) mod s, written as ((u64)(-s)) % s in C unsigned arith.
        let t = s.wrapping_neg() % s;
        while l < t {
            x = xoshiro256starstar(state);
            m = u128::from(x).wrapping_mul(u128::from(s));
            l = m as u64;
        }
    }

    (m >> 64) as u64
}

/// Fisher–Yates in-place shuffle, transcribed from `utils.h` (`FYshuffle`):
/// for `i` from `len-1` down to `1`, draw `r in [0, i]` and swap `data[r]`,
/// `data[i]`. EA shuffles `symbols` and `rawsymbols` in lockstep; we shuffle the
/// single raw-byte array and recompute conversions per round, which is
/// equivalent because every statistic is derived from the raw bytes.
///
/// Exposed `pub(crate)` so the [`crate::independence`] shuffled-baseline control
/// reuses this exact vetted Fisher–Yates + Lemire `randomRange64` + xoshiro256**
/// machinery (ISC-134) rather than re-transcribing an RNG; the caller supplies a
/// per-replica `state` derived from a documented master seed.
#[allow(
    // `i as u64` (index → range bound) and `r as usize` (draw → index) are safe:
    // dataset lengths fit usize and u64 on supported targets, and `r <= i < len`.
    clippy::cast_possible_truncation
)]
pub(crate) fn fy_shuffle(data: &mut [u8], state: &mut [u64; 4]) {
    let len = data.len();
    if len < 2 {
        return;
    }
    let mut i = len.saturating_sub(1);
    while i > 0 {
        // r in [0, i].
        let r = random_range64(i as u64, state) as usize;
        // r <= i < len and i < len: both in bounds. `slice::swap` is the
        // indexing-lint-clean way to swap two elements.
        if r != i && r < len {
            data.swap(r, i);
        }
        i = i.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A statistic is *decided* (IID-consistent) once its original value sits
/// comfortably inside the shuffle distribution: `(C0 + C1 > 5) && (C1 + C2 > 5)`
/// (EA `permutation_tests.h` lines 669 and 733).
const fn is_decided(entry: (u64, u64, u64)) -> bool {
    let (c0, c1, c2) = entry;
    c0.saturating_add(c1) > 5 && c1.saturating_add(c2) > 5
}

/// Compute the 19 unpermuted §5.1 statistics for `data` (L1).
///
/// Deterministic: the same input always yields a bit-identical
/// [`PermutationStats`]. The compression slot (`values[18]`) is the real
/// bzip2-compressed byte length, computed bit-exactly vs the EA tool.
#[must_use]
pub fn permutation_stats(data: &[u8]) -> PermutationStats {
    let stats = alphabet_stats(data);
    let active = [true; NUM_TESTS];
    let mut values = [0.0_f64; NUM_TESTS];
    compute_all(data, &stats, &active, &mut values);
    // Statistic 18 (compression) is computed bit-exactly vs the EA tool, like
    // every other statistic.
    PermutationStats {
        values,
        names: TEST_NAMES,
    }
}

/// Run the full §5.1 permutation test for `data` (L2): compute the 19 original
/// statistics, then PERMS deterministic Fisher–Yates shuffles, tallying
/// (greater, equal, less) per statistic and applying the early-exit decision.
///
/// Deterministic (fixed [`SHUFFLE_SEED`], ISC-134): the same input always yields
/// a bit-identical [`PermutationVerdict`]. The compression slot (index 18) is
/// included in the verdict — all 19 statistics participate.
///
/// # Early-exit (matches EA)
///
/// A statistic is *decided* once `(C0 + C1 > 5) && (C1 + C2 > 5)`; thereafter it
/// is no longer recomputed or tallied. The loop stops once all active statistics
/// are decided or PERMS shuffles have run — making clearly-non-IID data fail
/// fast.
#[must_use]
pub fn permutation_test(data: &[u8]) -> PermutationVerdict {
    run_permutation(data, PERMS)
}

/// Core verdict loop, parameterized by the shuffle count. The public
/// [`permutation_test`] always passes the spec [`PERMS`] (10_000); callers that
/// need a different shuffle budget (e.g. the §3.1.4 restart §5 path, which runs
/// the permutation test on rows and columns and uses a smaller budget) and
/// tests pass a smaller count for speed — clearly-IID / clearly-non-IID data
/// reach a stable verdict in far fewer shuffles, and the unoptimized test build
/// makes the full 10_000-shuffle run on multi-kilobyte data minutes-long.
#[allow(
    // The verdict drives a counter-update loop whose structure mirrors EA's
    // permutation_tests; the length is inherent to handling 19 statistics.
    clippy::too_many_lines,
    // `t` (original stats) and `tp` (permuted stats) are EA's own names.
    clippy::similar_names
)]
pub fn run_permutation(data: &[u8], perms: usize) -> PermutationVerdict {
    let stats = alphabet_stats(data);

    // Original (unpermuted) statistics.
    let active_all = [true; NUM_TESTS];
    let mut t = [0.0_f64; NUM_TESTS];
    compute_all(data, &stats, &active_all, &mut t);

    // All 19 statistics participate, including compression (statistic 18), now
    // computed bit-exactly vs the EA tool — no longer a STOP-AND-LEAVE exclusion.
    let compression_included = true;
    let mut active = [true; NUM_TESTS];

    let mut c: [(u64, u64, u64); NUM_TESTS] = [(0, 0, 0); NUM_TESTS];

    // The shuffle works on a mutable copy of the raw bytes.
    let mut work = data.to_vec();
    let mut state = SHUFFLE_SEED;

    // Scratch for per-shuffle statistics; inactive slots retain prior values.
    let mut tp = t;

    // We stop once every statistic is decided. All NUM_TESTS slots start active
    // now (no STOP-AND-LEAVE exclusion), so the target is the full slot count.
    let total_slots = NUM_TESTS;
    let mut decided: usize = 0;

    for _ in 0..perms {
        if decided >= total_slots {
            break;
        }

        fy_shuffle(&mut work, &mut state);
        compute_all(&work, &stats, &active, &mut tp);

        // Tally each active statistic. Iterate the four parallel arrays in
        // lockstep (avoids the denied `indexing_slicing`).
        for (((entry, &act), &orig), &perm) in
            c.iter_mut().zip(active.iter()).zip(t.iter()).zip(tp.iter())
        {
            if !act {
                continue;
            }
            if perm > orig {
                entry.0 = entry.0.saturating_add(1);
            } else if (perm - orig).abs() == 0.0 {
                // Exact equality (the statistics are integers or exact ratios;
                // EA compares long doubles with ==). `perm == orig` directly
                // would trip the float_cmp lint; the zero-difference test is
                // equivalent for finite values and reads as intentional.
                entry.1 = entry.1.saturating_add(1);
            } else {
                entry.2 = entry.2.saturating_add(1);
            }
        }

        // Retire newly-decided statistics (a separate pass so the tally loop
        // above can borrow `active` immutably).
        decided = 0;
        for (act, &entry) in active.iter_mut().zip(c.iter()) {
            if !*act {
                // Already decided.
                decided = decided.saturating_add(1);
            } else if is_decided(entry) {
                *act = false;
                decided = decided.saturating_add(1);
            }
        }
    }

    // Per-statistic pass + overall verdict. A statistic passes iff its final
    // counts satisfy the decision inequality; all 19 (including compression)
    // count toward `is_iid`.
    let mut per_test_pass = [false; NUM_TESTS];
    let mut is_iid = true;
    for (pass_slot, &entry) in per_test_pass.iter_mut().zip(c.iter()) {
        let pass = is_decided(entry);
        *pass_slot = pass;
        if !pass {
            is_iid = false;
        }
    }

    PermutationVerdict {
        c_counts: c,
        per_test_pass,
        is_iid,
        compression_included,
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact hand-computed values, use unwrap/panic for fatal setup
    // invariants, index fixed-size fixtures, and print skip notices for absent
    // datasets — all fine in test code.
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

    const EPS: f64 = 1.0e-9;

    /// Excursion on `[0, 2, 0, 2]`: mean = 1.0.
    /// running sums: 0,2,2,4; d_i = |0-1|, |2-2|, |2-3|, |4-4| = 1,0,1,0 → max 1.
    #[test]
    fn excursion_hand_vector() {
        let data = [0u8, 2, 0, 2];
        let stats = alphabet_stats(&data);
        assert_eq!(stats.alph_size, 2, "two distinct values");
        assert!(stats.binary);
        assert!(
            (stats.rawmean - 1.0).abs() < EPS,
            "rawmean={}",
            stats.rawmean
        );
        // excursion runs on the raw bytes, not the conversion.
        let e = excursion(&data, stats.rawmean);
        assert!((e - 1.0).abs() < EPS, "excursion={e}");
    }

    /// Directional runs on `[3, 1, 2]`: alt_seq1 = [ (3>1)->-1, (1>2? no)->+1 ]
    /// = [-1, +1]. num_directional_runs = 2 (first + one change);
    /// len_directional_runs = 1 (no two adjacent equal);
    /// num_increases_decreases = max(1,1) = 1.
    #[test]
    fn directional_hand_vector() {
        let data = [3u8, 1, 2];
        let alt1 = alt_sequence1(&data);
        assert_eq!(alt1, vec![-1, 1]);
        assert_eq!(num_directional_runs(&alt1), 2);
        assert_eq!(len_directional_runs(&alt1), 1);
        assert_eq!(num_increases_decreases(&alt1), 1);
    }

    /// Directional runs with a real run: `[1, 2, 3]` → alt_seq1 = [+1, +1]
    /// (1<=2, 2<=3). num runs = 1, len run = 2, inc/dec = max(2,0) = 2.
    #[test]
    fn directional_increasing_run() {
        let data = [1u8, 2, 3];
        let alt1 = alt_sequence1(&data);
        assert_eq!(alt1, vec![1, 1]);
        assert_eq!(num_directional_runs(&alt1), 1);
        assert_eq!(len_directional_runs(&alt1), 2);
        assert_eq!(num_increases_decreases(&alt1), 2);
    }

    /// Runs-vs-median on `[1, 2, 3]`: median = 2.0 (odd len, middle element).
    /// alt_seq2 = [ 1<2 ? -1 : +1 = -1, 2<2 ? no = +1, 3<2 ? no = +1 ]
    /// = [-1, +1, +1]. num runs = 2; len run = 2.
    #[test]
    fn runs_median_hand_vector() {
        let data = [1u8, 2, 3];
        let stats = alphabet_stats(&data);
        assert!((stats.median - 2.0).abs() < EPS, "median={}", stats.median);
        let alt2 = alt_sequence2(&data, stats.median);
        assert_eq!(alt2, vec![-1, 1, 1]);
        assert_eq!(num_directional_runs(&alt2), 2);
        assert_eq!(len_directional_runs(&alt2), 2);
    }

    /// Median on an even-length, non-binary sample `[1, 2, 3, 10]`:
    /// sorted = [1,2,3,10], half = 2 → (v[2]+v[1])/2 = (3+2)/2 = 2.5.
    #[test]
    fn median_even_length() {
        let data = [1u8, 2, 3, 10];
        let stats = alphabet_stats(&data);
        assert_eq!(stats.alph_size, 4);
        assert!(!stats.binary);
        assert!((stats.median - 2.5).abs() < EPS, "median={}", stats.median);
    }

    /// Periodicity on a known pattern `[1, 0, 1, 0, 1]` (3 distinct? no, 2 →
    /// binary). To exercise the non-binary periodicity primitive directly use a
    /// 3-symbol pattern `[1, 2, 1, 2, 1]`: p=1 → compare (1,2)(2,1)(1,2)(2,1):
    /// no equals → 0. p=2 → compare (1,1)(2,2)(1,1): 3 equals → 3.
    #[test]
    fn periodicity_hand_vector() {
        let data = [1u8, 2, 1, 2, 1];
        assert!((periodicity(&data, 1) - 0.0).abs() < EPS);
        assert!((periodicity(&data, 2) - 3.0).abs() < EPS);
    }

    /// Covariance on `[1, 2, 3]`: p=1 → 1*2 + 2*3 = 8.
    #[test]
    fn covariance_hand_vector() {
        let data = [1u8, 2, 3];
        assert!(
            (covariance(&data, 1) - 8.0).abs() < EPS,
            "cov={}",
            covariance(&data, 1)
        );
    }

    /// Conversion I/II on a known binary input. 16 bits:
    /// 1111_1111 0000_0001 → conversion1 = [8, 1] (counts of 1s);
    /// conversion2 = [255, 1] (block as binary number, MSB-first).
    #[test]
    fn conversions_hand_vector() {
        let bits = [1u8, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(conversion1(&bits), vec![8, 1]);
        assert_eq!(conversion2(&bits), vec![255, 1]);
    }

    /// find_collisions on `[0, 1, 0, 2, 2]`:
    /// outer i=0: see 0(j0),1(j1),0 repeat at j2 → push j+1 = 3; i += 2 → i=2;
    /// outer i=3 (after ++i twice? trace): EA semantics — we just assert the
    /// gap sequence a careful hand-trace gives. Trace with the EA algorithm:
    ///   i=0,j=0: dups reset. inner: val=0 new(j=1); val=1 new(j=2);
    ///            val=0 DUP → push 3, i=0+2=2, j=0, break. ++i → i=3.
    ///   i=3,j=0: dups reset. inner: val(3+0=3)=2 new(j=1); val(4)=2 DUP →
    ///            push 2, i=3+1=4? wait i+=j=1 → i=4, j=0, break. ++i → i=5.
    ///   i=5,j=0: i+j=5 == n → outer ends.
    /// So gaps = [3, 2]; avg = 2.5; max = 3.
    #[test]
    fn find_collisions_hand_vector() {
        let data = [0u8, 1, 0, 2, 2];
        let gaps = find_collisions(&data);
        assert_eq!(gaps, vec![3, 2], "gaps={gaps:?}");
        assert!((avg_collision(&gaps) - 2.5).abs() < EPS);
        assert!((max_collision(&gaps) - 3.0).abs() < EPS);
    }

    /// Binary excursion uses the raw bit-sequence. `[1,1,0,0]`: mean 0.5;
    /// running sums 1,2,2,2; d_i = |1-0.5|,|2-1|,|2-1.5|,|2-2| = .5,1,.5,0 → 1.
    #[test]
    fn binary_excursion_uses_raw_bits() {
        let data = [1u8, 1, 0, 0];
        let stats = alphabet_stats(&data);
        assert!(stats.binary);
        assert!((stats.rawmean - 0.5).abs() < EPS);
        assert!((excursion(&data, stats.rawmean) - 1.0).abs() < EPS);
    }

    /// Compression slot matches the EA tool bit-for-bit (`ea_iid -v -v -v`
    /// "Unpermuted result compression") on the three short oracle datasets:
    /// rand1_short = 1611, rand4_short = 5520, rand8_short = 10987.
    #[test]
    fn compression_matches_ea_on_short_datasets() {
        let dir = crate::parity::resolve_datasets_dir(None);
        for (file, expected) in [
            ("rand1_short.bin", 1611.0_f64),
            ("rand4_short.bin", 5520.0_f64),
            ("rand8_short.bin", 10987.0_f64),
        ] {
            let Ok(data) = std::fs::read(dir.join(file)) else {
                eprintln!("skipping {file}: dataset not present");
                continue;
            };
            let got = permutation_stats(&data).values[COMPRESSION_IDX];
            assert!(
                (got - expected).abs() < f64::EPSILON,
                "{file}: compression {got} != EA {expected}"
            );
        }
    }

    /// Determinism: permutation_stats is bit-identical across two calls.
    #[test]
    fn determinism_stats_bit_exact() {
        let buf: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
        let a = permutation_stats(&buf);
        let b = permutation_stats(&buf);
        for i in 0..NUM_TESTS {
            if i == COMPRESSION_IDX {
                // Compression is a real finite bzip2 length: deterministic means
                // it is equal across the two calls and finite (no longer NaN).
                assert!(
                    a.values[i] == b.values[i] && a.values[i].is_finite(),
                    "compression slot must be equal and finite across calls"
                );
            } else {
                assert_eq!(a.values[i], b.values[i], "stat {i} differs");
            }
        }
    }

    /// Determinism: permutation_test is bit-identical across two calls (fixed
    /// seed, ISC-134). Use a short, clearly-non-IID prefix so the run is fast.
    #[test]
    fn determinism_test_bit_exact() {
        // A strongly periodic sequence — fails fast. Small length keeps the full
        // spec-PERMS public path quick even in the unoptimized test build.
        let buf: Vec<u8> = (0..600u32).map(|i| (i % 4) as u8).collect();
        let a = permutation_test(&buf);
        let b = permutation_test(&buf);
        assert_eq!(a.c_counts, b.c_counts, "c_counts must be identical");
        assert_eq!(a.per_test_pass, b.per_test_pass);
        assert_eq!(a.is_iid, b.is_iid);
        // Compression is now computed bit-exactly and counts toward the verdict.
        assert!(a.compression_included);
    }

    /// Locate `tests/data/<name>` relative to the crate manifest.
    fn data_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
    }

    /// Shuffle count for the oracle verdict tests. Far below the spec
    /// [`PERMS`] (10_000), but clearly-IID / clearly-non-IID data reach a stable
    /// verdict in a few hundred shuffles, and this keeps the unoptimized test
    /// build fast. The public [`permutation_test`] always uses the full `PERMS`.
    const TEST_PERMS: usize = 500;

    /// Oracle (IID direction): EA's canonical `rand8_short` dataset — 10k
    /// samples, verified IID by the EA reference tool across all three §5
    /// components — passes maxwell's permutation verdict. Resolved through the EA
    /// data dir (skip if absent, same convention as the parity tests). A
    /// synthetic SplitMix64 stream is *not* used here: its low byte trips the §5
    /// chi-square goodness-of-fit at this size, so it is not a clean all-IID
    /// fixture; the canonical EA dataset is.
    #[test]
    fn oracle_iid_passes() {
        let path = crate::parity::resolve_datasets_dir(None).join("rand8_short.bin");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("rand8_short.bin absent — skipping IID oracle test");
            return;
        };
        let v = run_permutation(&data, TEST_PERMS);
        assert!(
            v.is_iid,
            "rand8_short should be IID-consistent (matches the EA verdict)"
        );
    }

    /// Oracle (non-IID direction): the synthetic serially-correlated random walk
    /// (`tests/data/oracle_noniid.bin`, EA-verified non-IID) fails the
    /// permutation verdict. A 10k prefix is enough — the lag-correlated structure
    /// makes a covariance/excursion statistic extreme regardless of length.
    #[test]
    fn oracle_noniid_fails() {
        let Ok(data) = std::fs::read(data_path("oracle_noniid.bin")) else {
            eprintln!("oracle_noniid.bin absent — skipping");
            return;
        };
        let n = data.len().min(10_000);
        let prefix = data.get(..n).expect("prefix within bounds");
        let v = run_permutation(prefix, TEST_PERMS);
        assert!(!v.is_iid, "oracle_noniid should NOT be IID-consistent");
    }
}
