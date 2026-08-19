//! SP 800-90B §3.1.4 restart-data analysis (sanity check + §5 IID battery + gate).
//!
//! This is the Rust port of EA's `cpp/restart_main.cpp`, scoped to the **IID
//! restart path**: the §3.1.4.3 sanity check (Monte-Carlo cutoff vs the maximum
//! row/column symbol count), the §5 IID tests run on rows **and** columns, the
//! §6.1 MCV per-bit min-entropy on rows and columns, and the §3.1.4.2 validation
//! gate `min(H_r, H_c) >= H_I / 2`.
//!
//! # Scope (Block B)
//!
//! The full EA restart tool, on the non-IID branch, also mins the §6.3 estimator
//! suite over rows and columns to form `H_r` / `H_c`. **That non-IID restart
//! path is OUT OF SCOPE here.** Block B's restart scope is exactly the §5 IID
//! path: sanity check, the three §5 verdicts (permutation, chi-square, LRS) on
//! row && col, MCV-derived `H_r`/`H_c`, and the validation gate. The non-IID
//! restart suite is a future item.
//!
//! # Data layout
//!
//! EA fixes the restart matrix at `r = c = 1000` (1,000,000 samples), in "row
//! dataset" order (SP 800-90B §3.1.4.1): `rdata[i*r + j]` is restart `i`,
//! sample `j`. The columns are the transpose: `cdata[j*c + i] = rdata[i*r + j]`.
//! (EA `restart_main.cpp` lines 463-474.) This module keeps `rows`/`cols`
//! parameterized so the tests can use small square fixtures, but the CLI uses
//! the spec `1000 x 1000`.
//!
//! # Determinism
//!
//! EA seeds its xoshiro256** RNG from `/dev/urandom`, so its `X_cutoff` varies
//! run-to-run. This port seeds from a fixed nothing-up-my-sleeve constant
//! (`permutation::SHUFFLE_SEED`) so `X_cutoff` — and therefore the whole
//! [`RestartResult`] — is reproducible (ISC-134). With a large
//! `simulation_rounds` the cutoff is statistically stable regardless of seed;
//! the fixed seed only removes the run-to-run jitter in the low-order count.

use crate::mcv;
use crate::permutation::{PermutationVerdict, SHUFFLE_SEED, random_unit, run_permutation};

use crate::chi_square::chi_square_tests;
use crate::iid_lrs::len_lrs_iid_test;

/// Result of an SP 800-90B §3.1.4 restart analysis (IID path).
#[derive(Debug, Clone, Copy, PartialEq)]
// The five bool fields are the distinct §3.1.4 verdicts (sanity, the three §5
// tests, combined IID, validation); each is a meaningful, separately-reported
// result, mirroring the EA tool's per-test pass flags — not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct RestartResult {
    /// Per-restart significance level `α = 1 - exp(ln(0.99) / (rows + cols))`
    /// (EA `restart_main.cpp` line 444).
    pub alpha: f64,
    /// Maximum symbol count across any single row (EA `X_r`, lines 448-459).
    pub x_r: u32,
    /// Maximum symbol count across any single column (EA `X_c`, lines 461-474).
    pub x_c: u32,
    /// `max(X_r, X_c)` (EA `X_max`, line 477).
    pub x_max: u32,
    /// Monte-Carlo sanity-check cutoff (EA `X_cutoff`, `simulateBound`).
    pub x_cutoff: u32,
    /// §3.1.4.3 sanity check: `true` iff `X_max <= X_cutoff` (EA lines 477-499).
    pub sanity_passed: bool,
    /// §5.1 permutation verdict, row && col (EA IID branch, lines 790-804).
    pub perm_passed: bool,
    /// §5.2 chi-square verdict, row && col (EA IID branch, lines 743-745).
    pub chi_square_passed: bool,
    /// §5.3 LRS verdict, row && col (EA IID branch, lines 767-769).
    pub lrs_passed: bool,
    /// Combined §5 IID verdict: `perm && chi_square && lrs`.
    pub is_iid: bool,
    /// §6.1 MCV controlling per-bit min-entropy over the rows (EA `H_r`).
    pub h_r: f64,
    /// §6.1 MCV controlling per-bit min-entropy over the columns (EA `H_c`).
    pub h_c: f64,
    /// The supplied initial entropy estimate `H_I`.
    pub h_i: f64,
    /// §3.1.4.2 validation: sanity passed **and** `min(H_r, H_c) >= H_I / 2`
    /// (EA lines 477-499 + 834).
    pub validation_passed: bool,
    /// `min(H_r, H_c, H_I)` — the validated entropy assessment (EA line 882).
    pub min_entropy: f64,
}

/// EA `simulateCount` (`restart_main.cpp` lines 86-106): draw 1000 indices from
/// the "inverted near-uniform" worst-case distribution and return the maximum
/// count over the first `k_effective` symbols.
///
/// `idx = floor(random_unit() / p)` maps `[0,1)` onto `0..=floor(1/p)`. The
/// histogram has 256 slots (a draw can land at most at `floor(1/p) <= 255` for
/// the entropy levels of interest); the max is taken over `counts[0..k_eff]`.
#[allow(
    // `idx` is `floor(u/p)` with `u in [0,1)`, `p = 2^-H_I > 0`, so
    // `idx in 0..=floor(1/p)`; for the asserted `k_eff <= 256` this is an
    // in-range index. The cast is the EA `(int)floor(...)` truncation, made
    // total by clamping below.
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn simulate_count(k_effective: usize, p: f64, state: &mut [u64; 4]) -> u16 {
    let mut counts = [0u16; 256];
    for _ in 0..1000 {
        let raw = (random_unit(state) / p).floor();
        // raw is in [0, floor(1/p)]; clamp into the 256-slot table to stay total
        // (EA relies on k_eff <= 256 so the index is in range by construction).
        let idx = (raw as usize).min(255);
        if let Some(slot) = counts.get_mut(idx) {
            *slot = slot.saturating_add(1);
        }
    }
    let mut max_count = 0u16;
    // Max over the first k_effective slots (EA bounds the scan at k_eff, not 256).
    for slot in counts.iter().take(k_effective.min(256)) {
        if *slot > max_count {
            max_count = *slot;
        }
    }
    max_count
}

/// EA `simulateBound` (`restart_main.cpp` lines 107-163): run `rounds`
/// independent [`simulate_count`] draws, sort, and return the order statistic at
/// index `floor((1 - alpha) * rounds) - 1`.
///
/// `p = 2^-H_I`, `k_effective = ceil(1/p)`. Deterministic: seeded from the fixed
/// [`SHUFFLE_SEED`] (EA seeds from `/dev/urandom`; see the module note).
///
/// # Panics
///
/// Does not panic in release. In debug, mirrors EA's asserts (`k > 1`,
/// `k_effective <= k`, the order-statistic bounds) as `debug_assert!`.
#[allow(
    // The cutoff/index arithmetic mirrors EA's `(int)`/`floor`/`ceil` casts on
    // values bounded by the sample counts (<= 1000) and `rounds` (a usize);
    // none overflow for the inputs the restart path uses.
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn simulate_bound(alpha: f64, k: usize, h_i: f64, rounds: usize) -> u32 {
    debug_assert!(k > 1 && k <= 256, "alphabet size out of range for cutoff");

    // Probability of the most-likely symbol (computed once).
    let p = 2.0_f64.powf(-h_i);
    let k_effective = (1.0 / p).ceil() as usize;
    debug_assert!(
        k_effective <= k,
        "k_effective ({k_effective}) must be <= alphabet size ({k})"
    );

    let mut state = SHUFFLE_SEED;
    let mut results: Vec<u16> = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        results.push(simulate_count(k_effective, p, &mut state));
    }
    results.sort_unstable();

    // returnIndex = floor((1 - alpha) * rounds) - 1.
    let return_index = (((1.0 - alpha) * rounds as f64).floor() as usize).saturating_sub(1);

    debug_assert!(
        return_index < results.len(),
        "order-statistic index in range"
    );
    u32::from(results.get(return_index).copied().unwrap_or(0))
}

/// Maximum per-row symbol count over a row-major matrix (`rows` rows of `cols`
/// symbols). EA `X_r`/`X_c` loops (`restart_main.cpp` lines 448-474): for each
/// row, histogram its `cols` symbols and track the row's max count; the result
/// is the max over all rows.
fn max_row_count(matrix: &[u8], rows: usize, cols: usize) -> u32 {
    let mut x = 0u32;
    for i in 0..rows {
        let mut counts = [0u32; 256];
        let mut row_max = 0u32;
        let base = i.saturating_mul(cols);
        for j in 0..cols {
            if let Some(&sym) = matrix.get(base.saturating_add(j))
                && let Some(slot) = counts.get_mut(sym as usize)
            {
                *slot = slot.saturating_add(1);
                if *slot > row_max {
                    row_max = *slot;
                }
            }
        }
        if row_max > x {
            x = row_max;
        }
    }
    x
}

/// Transpose a row-major `rows x cols` matrix into column-major order:
/// `cdata[j*rows + i] = rdata[i*cols + j]`.
///
/// EA constructs `cdata[j*c + i] = rdata[i*r + j]` with `r == c == 1000` (a
/// square transpose). Generalized here so `cdata` is the `cols x rows`
/// transpose, laid out row-major with row length `rows`. (`restart_main.cpp`
/// lines 463-474.)
fn transpose(matrix: &[u8], rows: usize, cols: usize) -> Vec<u8> {
    let mut out = vec![0u8; rows.saturating_mul(cols)];
    for i in 0..rows {
        for j in 0..cols {
            let src = i.saturating_mul(cols).saturating_add(j);
            let dst = j.saturating_mul(rows).saturating_add(i);
            if let (Some(&v), Some(slot)) = (matrix.get(src), out.get_mut(dst)) {
                *slot = v;
            }
        }
    }
    out
}

/// Distinct symbol count of the matrix (EA `data.alph_size`).
///
/// Public so the CLI can enforce [`restart_analysis`]'s degenerate-input
/// precondition before calling, which its `# Panics` section states the CLI does.
/// One definition, one home: a second distinct-count in `main.rs` could drift
/// from the one the analysis actually uses.
#[must_use]
pub fn alphabet_size(matrix: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for &b in matrix {
        if let Some(slot) = seen.get_mut(b as usize)
            && !*slot
        {
            *slot = true;
            n = n.saturating_add(1);
        }
    }
    n
}

/// Restart-data MCV min-entropy: the **literal** (per-symbol) most-common-value
/// estimate. EA `restart_main` computes `most_common(..., "Literal")` on the row
/// and column data (lines 531, 538) — a per-SYMBOL value in `0..=word_size`, the
/// same units as `H_I` and as the `min(H_r, H_c, H_I)` / `min(H_r,H_c) < H_I/2`
/// gate. (The §5/§6.3 bitstring per-bit tracks are NOT used for the restart H_r/H_c.)
fn mcv_literal(symbols: &[u8], bits_per_symbol: u8) -> f64 {
    mcv(symbols, bits_per_symbol).literal.min_entropy
}

/// The §3.1.4.2 validation gate, factored out for direct unit testing.
///
/// Returns `(validation_passed, min_entropy)` where
/// `validation_passed = sanity_passed && min(h_r, h_c) >= h_i / 2` (EA lines
/// 477-499 + 834) and `min_entropy = min(h_r, h_c, h_i)` (EA line 882).
#[must_use]
pub fn restart_validation(h_r: f64, h_c: f64, h_i: f64, sanity_passed: bool) -> (bool, f64) {
    let min_rc = h_r.min(h_c);
    let validation_passed = sanity_passed && (min_rc >= h_i / 2.0);
    let min_entropy = min_rc.min(h_i);
    (validation_passed, min_entropy)
}

/// Run the SP 800-90B §3.1.4 restart analysis (IID path) over `matrix`.
///
/// `matrix` is the row-major restart matrix (`rows * cols` bytes, one symbol per
/// byte); `rows * cols` must equal `matrix.len()`. EA fixes `rows = cols = 1000`
/// (1,000,000 samples). `bits_per_symbol` is the symbol width (1..=8). `h_i` is
/// the initial entropy estimate. `simulation_rounds` is the cutoff Monte-Carlo
/// round count (EA default 5,000,000); `perms` is the §5.1 permutation shuffle
/// budget (EA `PERMS` = 10,000).
///
/// Returns a fully-populated [`RestartResult`]. This function is
/// **deterministic** (fixed RNG seed): the same inputs always yield a
/// bit-identical result.
///
/// # Panics
///
/// In debug builds, `simulate_bound`'s `debug_assert!`s fire on degenerate
/// inputs (alphabet size <= 1, or `k_effective > alphabet_size`); callers (the
/// CLI) reject single-symbol matrices before calling. In release these are no-ops
/// and the function returns a result computed on the clamped values.
#[must_use]
pub fn restart_analysis(
    matrix: &[u8],
    bits_per_symbol: u8,
    h_i: f64,
    rows: usize,
    cols: usize,
    simulation_rounds: usize,
    perms: usize,
) -> RestartResult {
    // 1. Row data (as given) and column data (transpose).
    let rdata = matrix;
    let cdata = transpose(matrix, rows, cols);

    // 2. X_r over rows of rdata; X_c over rows of cdata (= columns of rdata).
    //    cdata is laid out cols x rows (row length = rows).
    let x_r = max_row_count(rdata, rows, cols);
    let x_c = max_row_count(&cdata, cols, rows);
    let x_max = x_r.max(x_c);

    // 3. alpha = 1 - exp(ln(0.99) / (rows + cols)).  (EA line 444.)
    #[allow(clippy::cast_precision_loss)]
    let alpha = 1.0 - (0.99_f64.ln() / rows.saturating_add(cols) as f64).exp();

    // 4. X_cutoff from the §3.1.4.3 Monte-Carlo over the matrix alphabet size.
    let k = alphabet_size(matrix);
    let x_cutoff = simulate_bound(alpha, k, h_i, simulation_rounds);

    // 5. Sanity check: X_max <= X_cutoff.  (EA lines 477-499.)
    let sanity_passed = x_max <= x_cutoff;

    // 6. §5 IID tests on rows && columns.  (EA IID branch, lines 743-804.)
    let perm_passed = run_permutation_iid(rdata, perms) && run_permutation_iid(&cdata, perms);
    let chi_square_passed = chi_square_tests(rdata).passed && chi_square_tests(&cdata).passed;
    let lrs_passed = len_lrs_iid_test(rdata).passed && len_lrs_iid_test(&cdata).passed;
    let is_iid = perm_passed && chi_square_passed && lrs_passed;

    // 7. H_r / H_c via §6.1 MCV (the IID restart path).  (EA lines 521-541.)
    let h_r = mcv_literal(rdata, bits_per_symbol);
    let h_c = mcv_literal(&cdata, bits_per_symbol);

    // 8. Final validation gate + min-entropy.  (EA lines 834, 882.)
    let (validation_passed, min_entropy) = restart_validation(h_r, h_c, h_i, sanity_passed);

    RestartResult {
        alpha,
        x_r,
        x_c,
        x_max,
        x_cutoff,
        sanity_passed,
        perm_passed,
        chi_square_passed,
        lrs_passed,
        is_iid,
        h_r,
        h_c,
        h_i,
        validation_passed,
        min_entropy,
    }
}

/// `run_permutation(data, perms).is_iid`, kept tiny so the row/col call sites
/// read cleanly.
fn run_permutation_iid(data: &[u8], perms: usize) -> bool {
    let v: PermutationVerdict = run_permutation(data, perms);
    v.is_iid
}

#[cfg(test)]
#[allow(
    // Tests assert exact literals, use unwrap/index on fixed-size fixtures, and
    // build small synthetic matrices — all fine in test code.
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    /// A small, fast cutoff round count for the synthetic fixtures.
    const TEST_ROUNDS: usize = 2000;
    /// A small permutation budget — most synthetic fixtures reach a stable
    /// verdict in far fewer than the spec PERMS.
    ///
    /// **These are not the spec verdicts.** §5.1 verdicts genuinely flip between
    /// this budget and [`permutation::PERMS`] on identical data: the symmetric
    /// fixture below reports `perm=false` at 200 and `perm=true` at 500 and above.
    /// Never generalise a claim about §5.1's sensitivity from a run at this
    /// budget — doing so is what produced a false "uncatchable" residual here.
    const TEST_PERMS: usize = 200;

    /// Build a near-uniform `n x n` matrix over `k` symbols using a simple
    /// counter pattern (no RNG): symbol = position mod k.
    fn near_uniform(n: usize, k: u8) -> Vec<u8> {
        near_uniform_dims(n, n, k)
    }

    /// Build a near-uniform `rows x cols` matrix over `k` symbols (position mod
    /// k). Every symbol appears so `alphabet_size == k` for `rows*cols >= k`.
    fn near_uniform_dims(rows: usize, cols: usize, k: u8) -> Vec<u8> {
        (0..rows * cols).map(|p| (p % k as usize) as u8).collect()
    }

    /// ISC-83 / test 1: alpha is exact for the spec `rows + cols == 2000`.
    ///
    /// `alpha` depends only on `rows + cols` (EA line 444), not the data or the
    /// matrix size — so this uses a tiny `2 x 1998` fixture (rows + cols = 2000,
    /// 3996 samples) to stay fast while exercising the real `restart_analysis`
    /// path. The result is bit-identical to the spec `1000 x 1000` alpha.
    #[test]
    fn alpha_exact_1000() {
        let rows = 2;
        let cols = 1998; // rows + cols == 2000, same as the spec 1000 + 1000
        let matrix = near_uniform_dims(rows, cols, 2); // 2-symbol -> k == 2
        let r = restart_analysis(&matrix, 1, 0.9, rows, cols, TEST_ROUNDS, TEST_PERMS);
        let expected = 1.0 - (0.99_f64.ln() / 2000.0).exp();
        assert!(
            (r.alpha - expected).abs() < 1e-15,
            "alpha {} != expected {}",
            r.alpha,
            expected
        );
    }

    /// ISC-83.2 / test 2a: a near-uniform matrix passes the sanity check.
    #[test]
    fn sanity_passes_near_uniform() {
        // 20x20 over 4 symbols: each row has ~5 of each symbol, X_max small;
        // h_i = 1.9 (just under log2(4)=2) gives a generous cutoff.
        let matrix = near_uniform(20, 4);
        let r = restart_analysis(&matrix, 2, 1.9, 20, 20, TEST_ROUNDS, TEST_PERMS);
        assert!(
            r.sanity_passed,
            "near-uniform should pass sanity: X_max={} X_cutoff={}",
            r.x_max, r.x_cutoff
        );
    }

    /// ISC-83.2 / test 2b: a heavily-skewed 2-symbol matrix fails the sanity
    /// check (X_max ~ cols >> cutoff). Uses `cols = 1000` because EA's
    /// `simulateCount` always draws **1000** samples per restart, so `X_cutoff`
    /// lives on the `0..=1000` scale regardless of fixture size; a fixture must
    /// have 1000-wide rows for a near-fully-dominant row to exceed the cutoff.
    /// k=2 (so `simulate_bound`'s `k > 1` assert holds) and h_i = 0.9 give
    /// k_effective = ceil(2^0.9 / 1) ... = ceil(1/0.536) = 2 = k, cutoff ~585.
    /// rows=2 keeps the §5 battery (run on 2000 samples) fast.
    #[test]
    fn sanity_fails_skewed() {
        let rows = 2;
        let cols = 1000;
        // All '0' except a single '1' so alphabet_size == 2 and each row is a
        // near-fully-dominant run of '0' -> X_max ~ cols (1000) > cutoff (~585).
        let mut matrix = vec![0u8; rows * cols];
        matrix[rows * cols - 1] = 1;
        // h_i = 0.9 -> p = 2^-0.9 ~ 0.536 -> ceil(1/p) = 2 = k.
        let r = restart_analysis(&matrix, 1, 0.9, rows, cols, TEST_ROUNDS, TEST_PERMS);
        // X_max should be ~ cols (a row of all-zeros has count cols).
        assert!(r.x_max >= (cols as u32) - 1, "X_max too small: {}", r.x_max);
        assert!(
            r.x_max > r.x_cutoff,
            "fixture must exceed cutoff for a meaningful FAIL: X_max={} X_cutoff={}",
            r.x_max,
            r.x_cutoff
        );
        assert!(
            !r.sanity_passed,
            "skewed matrix should FAIL sanity: X_max={} X_cutoff={}",
            r.x_max, r.x_cutoff
        );
    }

    /// ISC-83.3 / test 3: the validation gate logic, tested directly.
    #[test]
    fn validation_gate_logic() {
        // Passes: min(h_r,h_c)=0.8 >= h_i/2 = 0.45, sanity ok.
        let (pass, min_e) = restart_validation(0.8, 0.9, 0.9, true);
        assert!(pass, "should pass when min >= h_i/2 and sanity ok");
        assert_eq!(min_e, 0.8, "min_entropy = min(h_r,h_c,h_i)");

        // Fails: min(h_r,h_c)=0.4 < h_i/2 = 0.45.
        let (fail, min_e2) = restart_validation(0.4, 0.9, 0.9, true);
        assert!(!fail, "should fail when min < h_i/2");
        assert_eq!(min_e2, 0.4);

        // Fails on sanity even if entropy is fine.
        let (fail_sanity, _) = restart_validation(0.8, 0.9, 0.9, false);
        assert!(!fail_sanity, "sanity failure forces validation failure");

        // min_entropy picks h_i when it is the smallest.
        let (_, min_hi) = restart_validation(0.9, 0.9, 0.5, true);
        assert_eq!(min_hi, 0.5);
    }

    /// Test 4: transpose correctness on a tiny 3x3 matrix.
    #[test]
    fn transpose_3x3() {
        // matrix (row-major):
        //   1 2 3
        //   4 5 6
        //   7 8 9
        let m = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let t = transpose(&m, 3, 3);
        // transpose:
        //   1 4 7
        //   2 5 8
        //   3 6 9
        assert_eq!(t, vec![1, 4, 7, 2, 5, 8, 3, 6, 9]);
    }

    /// Test 4b: non-square transpose (2 rows x 3 cols -> 3 rows x 2 cols).
    #[test]
    fn transpose_2x3() {
        // 2x3 row-major:  1 2 3 / 4 5 6
        let m = vec![1, 2, 3, 4, 5, 6];
        let t = transpose(&m, 2, 3);
        // -> 3x2: 1 4 / 2 5 / 3 6
        assert_eq!(t, vec![1, 4, 2, 5, 3, 6]);
    }

    /// Test 5: determinism — two calls give identical RestartResult.
    #[test]
    fn deterministic() {
        let matrix = near_uniform(20, 4);
        let a = restart_analysis(&matrix, 2, 1.9, 20, 20, TEST_ROUNDS, TEST_PERMS);
        let b = restart_analysis(&matrix, 2, 1.9, 20, 20, TEST_ROUNDS, TEST_PERMS);
        assert_eq!(a, b, "RestartResult must be bit-identical across runs");
    }

    /// X_r / X_c sanity on the 3x3 fixture: each symbol appears once per row and
    /// once per column, so X_r == X_c == 1.
    #[test]
    fn row_col_counts_3x3() {
        let m = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        // alphabet_size 9 > 1 so simulate_bound asserts hold; h_i small.
        let r = restart_analysis(&m, 4, 1.0, 3, 3, TEST_ROUNDS, TEST_PERMS);
        assert_eq!(r.x_r, 1, "each distinct symbol once per row");
        assert_eq!(r.x_c, 1, "each distinct symbol once per column");
        assert_eq!(r.x_max, 1);
    }
    // ----- ISC-83 / ISC-83.1: the §5 battery verdicts on rows AND columns -----
    //
    // `perm_passed` / `chi_square_passed` / `lrs_passed` are computed as
    // `row && col`, stored in the result, and — before this — asserted nowhere.
    // Restart data is a CMVP submission artifact and its IID verdict is the number
    // a reviewer reads.

    /// Deterministic pseudo-random matrix, no RNG dependency.
    fn pseudo_random_matrix(n: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..n * n)
            .map(|_| {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                u8::try_from((z ^ (z >> 31)) & 0xFF).unwrap_or(0)
            })
            .collect()
    }

    /// Positive control for the three verdicts: without this, a mutation forcing
    /// any of them to `false` would be invisible — every other verdict fixture
    /// here expects `false`.
    #[test]
    fn restart_iid_verdicts_are_true_on_iid_data() {
        let n = 32;
        let m = pseudo_random_matrix(n, 0x1234_5678_9abc_def0);
        let r = restart_analysis(&m, 8, 1.0, n, n, TEST_ROUNDS, TEST_PERMS);
        assert!(r.perm_passed, "§5.1 permutation must pass on IID data");
        assert!(r.chi_square_passed, "§5.2 chi-square must pass on IID data");
        assert!(r.lrs_passed, "§5.3 LRS must pass on IID data");
        assert!(
            r.is_iid,
            "is_iid must be the conjunction of the three verdicts"
        );
    }

    /// ISC-83.1 — the COLUMN half specifically.
    ///
    /// The fixture was **measured, not assumed**. A constant column at `n = 32`
    /// was the obvious choice and is wrong: a contiguous run in the column stream
    /// is necessarily a period-`n` pattern in the row stream, and at `n = 32` the
    /// §5.1 permutation test catches it on the rows too, which would prove nothing
    /// about columns. Sweeping `n` and the column pattern found that `n = 100`
    /// with a two-valued column separates them cleanly: the row stream passes all
    /// three §5 tests and the column stream fails all three.
    ///
    /// The row stream is asserted to pass each test individually, so the combined
    /// verdict being false can only come from the transposed data. Deleting any
    /// `&& cdata` half flips this test and nothing else.
    #[test]
    fn restart_iid_verdicts_evaluate_the_transposed_column_data() {
        let n = 100;
        let mut m = pseudo_random_matrix(n, 0x0f1e_2d3c_4b5a_6978);
        for i in 0..n {
            if let Some(slot) = m.get_mut(i.saturating_mul(n)) {
                *slot = if i % 2 == 0 { 0x41 } else { 0x42 };
            }
        }

        // Positive control: the row stream alone is IID by all three §5 tests, so
        // any failure below is attributable to the columns.
        assert!(
            run_permutation_iid(&m, TEST_PERMS),
            "row stream must pass §5.1 alone, or this proves nothing about columns"
        );
        assert!(
            chi_square_tests(&m).passed,
            "row stream must pass §5.2 alone"
        );
        assert!(
            len_lrs_iid_test(&m).passed,
            "row stream must pass §5.3 alone"
        );

        // Yet the combined verdict is not IID — the column half did the work.
        let r = restart_analysis(&m, 8, 1.0, n, n, TEST_ROUNDS, TEST_PERMS);
        assert!(
            !r.perm_passed,
            "§5.1 must fail: the column stream is not IID"
        );
        assert!(
            !r.chi_square_passed,
            "§5.2 must fail: the column stream is not IID"
        );
        assert!(
            !r.lrs_passed,
            "§5.3 must fail: the column stream is not IID"
        );
        assert!(!r.is_iid, "the conjunction must be false");
    }

    /// ISC-83 — the ROW half specifically, the mirror of the column test.
    ///
    /// Deleting the column halves is caught by the test above; deleting the ROW
    /// halves was not caught by anything, and it is the more consequential side: a
    /// defect confined to one restart's own sequence is a row-wise defect, which
    /// is exactly what §5-on-rows exists to catch.
    ///
    /// The fixture is the column fixture **transposed**. Because `cdata` is the
    /// transpose of `rdata`, transposing the input swaps the two roles exactly: the
    /// stream that passed all three §5 tests is now the column data, and the one
    /// that failed them is now the row data. No new tuning was needed.
    #[test]
    fn restart_iid_verdicts_evaluate_the_row_data() {
        let n = 100;
        let mut m = pseudo_random_matrix(n, 0x0f1e_2d3c_4b5a_6978);
        for i in 0..n {
            if let Some(slot) = m.get_mut(i.saturating_mul(n)) {
                *slot = if i % 2 == 0 { 0x41 } else { 0x42 };
            }
        }
        let t = transpose(&m, n, n);

        // Positive control, mirrored: the COLUMN stream of `t` (which is `m`)
        // passes all three §5 tests, so any failure is attributable to the rows.
        let back = transpose(&t, n, n);
        assert!(
            run_permutation_iid(&back, TEST_PERMS),
            "column stream must pass §5.1 alone, or this proves nothing about rows"
        );
        assert!(
            chi_square_tests(&back).passed,
            "column stream passes §5.2 alone"
        );
        assert!(
            len_lrs_iid_test(&back).passed,
            "column stream passes §5.3 alone"
        );

        let r = restart_analysis(&t, 8, 1.0, n, n, TEST_ROUNDS, TEST_PERMS);
        assert!(!r.perm_passed, "§5.1 must fail: the row stream is not IID");
        assert!(
            !r.chi_square_passed,
            "§5.2 must fail: the row stream is not IID"
        );
        assert!(!r.lrs_passed, "§5.3 must fail: the row stream is not IID");
        assert!(!r.is_iid, "the conjunction must be false");
    }

    /// `is_iid` must be the conjunction of the three §5 verdicts, asserted on a
    /// fixture where they are **not** all equal.
    ///
    /// Run at the spec [`permutation::PERMS`] budget rather than [`TEST_PERMS`],
    /// and that is the whole point. At 200 shuffles this fixture reports
    /// `perm=false`, which makes `is_iid` and `perm_passed` agree and leaves a
    /// `perm_passed`-for-conjunction substitution undetectable — a residual this
    /// test previously documented as *uncatchable*. That claim was wrong: at 500
    /// shuffles and above the same fixture reports `perm=true, chi=false,
    /// lrs=true`, so `is_iid` must be false while `perm_passed` is true, and the
    /// substitution fails here. The under-powered budget, not the battery, was the
    /// obstacle. Measured 500/1000/2000/5000/10000 — identical verdicts, and
    /// ~2.4s at every budget, because the permutation test exits early once the
    /// counters settle.
    #[test]
    fn restart_is_iid_is_the_conjunction_of_the_three_verdicts() {
        let n = 100;
        let mut m = pseudo_random_matrix(n, 0x0f1e_2d3c_4b5a_6978);
        // Symmetrize: cdata == rdata, so the verdicts are the row stream's own.
        for i in 0..n {
            for j in (i + 1)..n {
                if let Some(&v) = m.get(i.saturating_mul(n).saturating_add(j))
                    && let Some(slot) = m.get_mut(j.saturating_mul(n).saturating_add(i))
                {
                    *slot = v;
                }
            }
        }
        let r = restart_analysis(&m, 8, 1.0, n, n, TEST_ROUNDS, crate::permutation::PERMS);
        // Fixture guard: this only tests the conjunction if the verdicts differ,
        // AND only closes the perm substitution if perm is the one that is true.
        assert!(
            r.perm_passed && !r.chi_square_passed && r.lrs_passed,
            "fixture must be mixed with perm TRUE, got perm={} chi={} lrs={}",
            r.perm_passed,
            r.chi_square_passed,
            r.lrs_passed
        );
        assert_eq!(
            r.is_iid,
            r.perm_passed && r.chi_square_passed && r.lrs_passed,
            "is_iid must be the conjunction, not any single verdict"
        );
        assert!(
            !r.is_iid,
            "a mixed verdict is not IID — and perm_passed alone would say it is"
        );
    }

    /// `H_r` and `H_c` are **provably equal** on this IID path, and the test says
    /// so rather than leaving a reader to infer that `min(H_r, H_c)` is doing
    /// work. §6.1 MCV depends only on the symbol frequency multiset, and the
    /// transpose is a permutation of the matrix, so the multiset — and therefore
    /// the mode, and therefore the estimate — is identical. Measured across five
    /// unrelated fixtures before being asserted.
    #[test]
    fn restart_row_and_column_mcv_are_equal_by_construction() {
        let n = 32;
        for seed in [0x1111_2222_3333_4444u64, 0xdead_beef_cafe_babe] {
            let m = pseudo_random_matrix(n, seed);
            let r = restart_analysis(&m, 8, 1.0, n, n, TEST_ROUNDS, TEST_PERMS);
            assert!(
                (r.h_r - r.h_c).abs() < f64::EPSILON,
                "MCV over a permutation of the same symbols must be identical: \
                 h_r={} h_c={}",
                r.h_r,
                r.h_c
            );
        }
        // Positive control: the equality must hold on a MEANINGFUL value, not on
        // a degenerate one. Two NaNs would fail the comparison above (NaN is not
        // less than EPSILON) but two zeros would satisfy it while proving nothing.
        let m = pseudo_random_matrix(n, 0x5555_6666_7777_8888);
        let r = restart_analysis(&m, 8, 1.0, n, n, TEST_ROUNDS, TEST_PERMS);
        assert!(
            r.h_r > 1.0 && r.h_r.is_finite(),
            "the equality must be asserted on a real estimate, got h_r={}",
            r.h_r
        );
        // Asserting min(H_r, H_c) == H_r separately would be entailed by the
        // equality and add nothing; the consequence for the §3.1.4.2 gate is
        // recorded in the security policy instead.
    }
}
