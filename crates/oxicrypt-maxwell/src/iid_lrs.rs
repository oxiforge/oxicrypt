//! SP 800-90B §5.3 LRS (longest-repeated-substring) **IID test**.
//!
//! This module reproduces the NIST `SP800-90B_EntropyAssessment` reference tool
//! ("EA tool") v1.1.8 §5.3 LRS test (`cpp/shared/lrs_test.h::len_LRS_test`, with
//! `n_choose_2` from `cpp/shared/utils.h`). Like the rest of `oxicrypt-maxwell`
//! it is **outside the cryptographic boundary** — pure offline analysis tooling,
//! `#![forbid(unsafe_code)]`, and it produces no security parameters.
//!
//! # The §5.3 LRS IID test (NOT the §6.3.6 LRS estimator)
//!
//! Despite the shared name, this is a different test from the §6.3.6 LRS
//! *min-entropy estimator* in [`crate::lrs`]:
//!
//! - The **§6.3.6 estimator** runs on the **bitstring track** and produces a
//!   per-bit min-entropy value.
//! - The **§5.3 IID test** (this module) runs on the **literal raw symbols**
//!   (`len_LRS_test(data.symbols, …, "Literal")`, `iid_main.cpp:334`) and
//!   produces a *pass/fail verdict* for the IID assumption.
//!
//! The intuition: under an IID assumption the per-symbol collision probability
//! is `p_col = Σ_v p_v²` (the probability two independent draws collide). The
//! probability that two independent length-`W` strings collide is `p_col^W`. For
//! `L` symbols there are `N = C(L − W + 1, 2)` pairs of overlapping length-`W`
//! substrings; the probability of seeing **at least one** length-`W` collision
//! across those `N` pairs (binomial, treating the pairs as independent) is
//! `Pr(X ≥ 1) = 1 − (1 − p_col^W)^N`. If the data is IID, observing a repeated
//! substring of the *longest* length `W` should not be wildly improbable, so the
//! test **passes** iff `Pr(X ≥ 1) ≥ 1/1000`.
//!
//! Equivalently (and as the EA tool actually computes the verdict, avoiding the
//! underflow-prone `(1 − p_col^W)^N` expansion, `lrs_test.h:707-715`):
//!
//! ```text
//! PASS  ⇔  log(0.999) ≥ N · log1p(−p_col^W)
//! ```
//!
//! # `W` — the longest repeated substring length
//!
//! `W` is the max LCP value over the **literal** symbols, exactly the EA tool's
//! `len_LRS32`/`len_LRS64`. It is computed by [`crate::lrs::lrs_length`], which
//! reuses the suffix-array + Kasai-LCP machinery the §6.3.6 estimator already
//! builds rather than re-implementing SA-IS.
//!
//! # Floating point (L2 verdict-parity-on-stable-datasets convention)
//!
//! The EA tool evaluates `p_col`, `p_col^W`, `log1p`, and the verdict comparison
//! in 80-bit `long double`; this module uses `f64` (Rust has no `long double`),
//! matching the permutation (§5.1) and chi-square (§5.2) modules' convention:
//!
//! - `W` is an **exact integer** (the max LCP).
//! - `p_col` is an **exact f64 sum** of squared rational proportions.
//! - `N = C(L − W + 1, 2)` is computed in **`i128`** (`L` up to ~1e6 ⇒ `N` up to
//!   ~5e11; `i128` cannot overflow) and only then cast to `f64`.
//!
//! The only floating-point difference from the EA tool is the final
//! `powf`/`ln_1p`/compare chain. Because the verdict is a threshold comparison
//! that sits far from the boundary on stable datasets, the f64 evaluation
//! reproduces the EA tool's pass/fail verdict (this is the L2
//! verdict-parity-on-stable-datasets contract, identical to permutation and
//! chi-square). The reported `P_col` and `Pr(X ≥ 1)` are diagnostics; the
//! load-bearing output is the boolean verdict.
//!
//! # Input convention
//!
//! Datasets are raw bytes, **one symbol per byte** (the EA convention; the §5.3
//! test runs on the literal symbol alphabet). `L` is the byte count.

// This module is a 1:1 transcription of the EA reference's `len_LRS_test` +
// `n_choose_2`. The lints below are inherent to that transcription and the
// verdict oracle (`ea_iid` / the bundled IID/non-IID oracles) is the real
// correctness gate, so they are allowed module-wide rather than per expression:
//
// * `integer_division` — `(n² − n) / 2` is EA's exact `n_choose_2` (the numerator
//   is always even, so the division is exact).
// * `arithmetic_side_effects` — the `L − W + 1` index arithmetic is the EA tool's
//   own; `W ≤ L` always, so it cannot underflow, and it runs in i128 with ample
//   headroom.
// * `cast_lossless` — `w as i128` / `l as i128` mirror the EA tool's `(long
//   double)`/`(long int)` casts; the explicit-cast form keeps the transcription
//   reading 1:1 with the C source.
// * `explicit_iter_loop` — the explicit `counts.iter()` mirrors EA's indexed
//   `for(i = 0; i < p.size(); i++)` collision-proportion sum.
#![allow(
    clippy::integer_division,
    clippy::arithmetic_side_effects,
    clippy::cast_lossless,
    clippy::explicit_iter_loop
)]

/// `n_choose_2(n) = (n² − n) / 2` (`utils.h:783`), evaluated in `i128` so the
/// `O(L²)` value cannot overflow for any realistic `L`.
///
/// The EA tool computes this in `long int`; `i128` strictly dominates it and
/// avoids any overflow concern for `L` up to ~1e6 (`N` up to ~5e11).
#[must_use]
const fn n_choose_2(n: i128) -> i128 {
    // (n*n - n) / 2 — integer division is exact since n*n - n is always even.
    (n.saturating_mul(n).saturating_sub(n)) / 2
}

/// The SP 800-90B §5.3 LRS IID-test result for a dataset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LrsIidResult {
    /// `p_col = Σ_v p_v²` — the per-symbol collision probability under the IID
    /// assumption (`Σ` over the 256 possible byte values; absent symbols
    /// contribute 0). Bounded in `[1/k, 1]`.
    pub p_col: f64,
    /// `W` — the length of the longest repeated substring over the literal
    /// symbols (the max LCP value; `0` for inputs too short to repeat).
    pub w: u64,
    /// `Pr(X ≥ 1) = 1 − exp(N · log1p(−p_col^W))` — the probability of seeing at
    /// least one length-`W` collision across the `N = C(L − W + 1, 2)`
    /// overlapping-substring pairs. Reported for diagnostics; the verdict is
    /// computed from the underflow-safe log form, not this value.
    pub pr_x_ge_1: f64,
    /// `true` iff the data passes the §5.3 LRS IID test: `Pr(X ≥ 1) ≥ 1/1000`,
    /// i.e. `log(0.999) ≥ N · log1p(−p_col^W)` (`lrs_test.h:715`).
    pub passed: bool,
}

/// Run the SP 800-90B §5.3 LRS IID test over `data` (raw bytes, one symbol per
/// byte), transcribing `lrs_test.h::len_LRS_test`.
///
/// This function is **deterministic**: the same `data` always yields a
/// bit-identical [`LrsIidResult`].
///
/// # Degenerate input
///
/// If `p_col` is effectively `1.0` (all one symbol — every collision has
/// probability 1), the EA tool short-circuits to a guaranteed **pass** with
/// `Pr(X ≥ 1) = 1.0` and `W = 0` (`lrs_test.h:629-639`). Empty / too-short input
/// yields `W = 0`; with `p_col < 1` and `W = 0` the test passes trivially
/// (`p_col^0 = 1`, `log1p(-1) = −∞`, and `log(0.999) ≥ −∞`).
///
/// # Panics
///
/// Does not panic.
#[must_use]
#[allow(
    // `data.len()` and the histogram counts fit u64 on supported targets; the
    // f64 casts mirror the EA tool's own (long double) casts. `W as f64`/`W as
    // i32` losslessly represent the small max-LCP value, and `N as f64` from
    // i128 is the EA tool's `(long double)N` cast. The L2 verdict-parity bound
    // (threshold comparison far from the boundary) absorbs the f64-vs-long-double
    // rounding.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub fn len_lrs_iid_test(data: &[u8]) -> LrsIidResult {
    let l = data.len();

    // 1. Proportions p[v] = count(v) / L over a 256-slot histogram (k = 256 is a
    //    safe upper bound for SP 800-90B; Σ over absent symbols is 0).
    //    p_col = Σ p[v]² (EA `calc_collision_proportion`).
    let mut counts = [0u64; 256];
    for &b in data {
        if let Some(slot) = counts.get_mut(b as usize) {
            *slot = slot.saturating_add(1);
        }
    }
    let p_col = if l == 0 {
        // No data: no collisions possible; treat as 0 so the test passes trivially.
        0.0
    } else {
        let denom = l as f64;
        let mut acc = 0.0_f64;
        for &c in counts.iter() {
            let p = (c as f64) / denom;
            acc += p * p;
        }
        acc
    };

    // 2. Degenerate all-one-symbol case (EA: `if(p_col > 1.0 - LDBL_EPSILON)`):
    //    a collision of any length has probability 1, so the test passes.
    if p_col > 1.0 - f64::EPSILON {
        return LrsIidResult {
            p_col,
            w: 0,
            pr_x_ge_1: 1.0,
            passed: true,
        };
    }

    // 3. W = the length of the longest repeated substring over the LITERAL bytes
    //    (the max LCP value; EA `len_LRS32`/`len_LRS64`).
    let w = crate::lrs::lrs_length(data) as u64;

    // 4. p_col^W and log(1 - p_col^W) via the underflow-safe log1p form.
    //    W can exceed i32, so use powf(W as f64) (the spec's recommended form).
    let p_col_power = p_col.powf(w as f64);
    let log_prob_no_cols_per_pair = (-p_col_power).ln_1p(); // = log1p(-p_col^W)

    // 5. N = C(L - W + 1, 2), in i128 to avoid any overflow (L up to ~1e6 ⇒ N up
    //    to ~5e11). (L - W + 1) is non-negative: W <= L always.
    let n_terms = (l as i128) - (w as i128) + 1;
    let n = n_choose_2(n_terms);
    let n_f = n as f64;

    // 6. Pr(X >= 1) = 1 - exp(N * log1p(-p_col^W)) (reporting only).
    let pr_x_ge_1 = 1.0 - (n_f * log_prob_no_cols_per_pair).exp();

    // 7. Verdict (lrs_test.h:715): PASS iff Pr(X >= 1) >= 1/1000, i.e.
    //    log(0.999) >= N * log1p(-p_col^W).
    let passed = (0.999_f64).ln() >= n_f * log_prob_no_cols_per_pair;

    LrsIidResult {
        p_col,
        w,
        pr_x_ge_1,
        passed,
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact / hand-computed values, use unwrap/expect/panic for
    // fatal setup invariants, and print skip notices for absent datasets — all
    // fine in test code.
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

    /// Locate `tests/data/<name>` relative to the crate manifest.
    fn data_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
    }

    /// 1. Determinism: two runs over the same buffer are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..5000u32).map(|i| (i % 23) as u8).collect();
        let a = len_lrs_iid_test(&buf);
        let b = len_lrs_iid_test(&buf);
        assert_eq!(a, b, "LrsIidResult must be bit-identical across runs");
    }

    /// 2. Degenerate all-one-symbol input → passes, p_col == 1.0.
    #[test]
    fn degenerate_all_one_symbol_passes() {
        let buf = vec![0x42u8; 4096];
        let r = len_lrs_iid_test(&buf);
        assert_eq!(r.p_col, 1.0, "all-one-symbol p_col must be exactly 1.0");
        assert_eq!(r.w, 0, "degenerate short-circuit reports W = 0");
        assert_eq!(r.pr_x_ge_1, 1.0);
        assert!(r.passed, "all-one-symbol input passes the §5.3 LRS test");
    }

    /// 3a. Oracle (IID direction): the bundled IID oracle passes the §5.3 test
    /// (EA-verified). LRS is O(n) via SA-IS, so the full file is fine.
    #[test]
    fn oracle_iid_passes() {
        let Ok(data) = std::fs::read(data_path("oracle_iid.bin")) else {
            eprintln!("oracle_iid.bin absent — skipping IID oracle test");
            return;
        };
        let r = len_lrs_iid_test(&data);
        assert!(
            r.passed,
            "oracle_iid should pass §5.3 LRS: p_col={} W={} Pr={}",
            r.p_col, r.w, r.pr_x_ge_1
        );
    }

    /// 3b. Oracle (non-IID direction): the bundled non-IID oracle fails the §5.3
    /// test (EA-verified).
    #[test]
    fn oracle_noniid_fails() {
        let Ok(data) = std::fs::read(data_path("oracle_noniid.bin")) else {
            eprintln!("oracle_noniid.bin absent — skipping non-IID oracle test");
            return;
        };
        let r = len_lrs_iid_test(&data);
        assert!(
            !r.passed,
            "oracle_noniid should fail §5.3 LRS: p_col={} W={} Pr={}",
            r.p_col, r.w, r.pr_x_ge_1
        );
    }

    /// 4. EA anchor on `rand4_short`, resolved through the EA data dir (skip if
    ///    absent). EA passes it, so the verdict must be PASS.
    #[test]
    fn rand4_short_anchor_passes() {
        let path = crate::parity::resolve_datasets_dir(None).join("rand4_short.bin");
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("rand4_short.bin absent — skipping EA anchor");
            return;
        };
        let r = len_lrs_iid_test(&data);
        assert!(
            r.passed,
            "rand4_short should pass §5.3 LRS (EA verdict): p_col={} W={} Pr={}",
            r.p_col, r.w, r.pr_x_ge_1
        );
    }

    /// 5. `lrs_length` sanity: a hand-constructable string with a known LRS —
    ///    "abcabc" → longest repeated substring "abc" has length 3 (max LCP).
    #[test]
    fn lrs_length_known_value() {
        assert_eq!(
            crate::lrs::lrs_length(b"abcabc"),
            3,
            "LRS of abcabc is abc (3)"
        );
        // "abracadabra" → "abra" repeats, length 4.
        assert_eq!(
            crate::lrs::lrs_length(b"abracadabra"),
            4,
            "LRS of abracadabra is abra (4)"
        );
        // No repeat: all-distinct bytes → 0.
        assert_eq!(crate::lrs::lrs_length(b"abcdef"), 0, "no repeat → 0");
        // Too short to repeat.
        assert_eq!(crate::lrs::lrs_length(b"a"), 0);
        assert_eq!(crate::lrs::lrs_length(b""), 0);
    }
}
