//! SP 800-90B §5 IID gate: combine the three §5 verdicts and route the reported
//! per-bit min-entropy down the IID or non-IID branch (mirrors the EA tool's
//! `iid_main` vs `non_iid_main` dispatch).
//!
//! This module ties together the three SP 800-90B §5 IID tests already built in
//! `oxicrypt-maxwell` — the §5.1 permutation battery ([`crate::permutation`]),
//! the §5.2 chi-square tests ([`crate::chi_square`]), and the §5.3 LRS IID test
//! ([`crate::iid_lrs`]) — into a single IID/non-IID verdict, and then selects the
//! reported per-bit min-entropy from the appropriate estimator family:
//!
//! - **IID branch** (all three §5 tests pass): the SP 800-90B §6.1 MCV estimator
//!   only. The EA tool's `iid_main` reports the MCV min-entropy for IID sources.
//! - **non-IID branch** (any §5 test fails): the minimum over the full SP 800-90B
//!   §6.3 non-IID estimator suite, exactly the values the parity harness checks
//!   ([`crate::parity`]). The EA tool's `non_iid_main` reports the minimum over
//!   the §6.3 estimates.
//!
//! Like the rest of `oxicrypt-maxwell` it is **outside the cryptographic
//! boundary** — pure offline analysis tooling, `#![forbid(unsafe_code)]`, and it
//! produces no security parameters.
//!
//! # Two reported numbers: per-bit controlling + per-symbol assessed
//!
//! The gate reports two min-entropy numbers, mirroring the EA tool's two outputs:
//!
//! - [`IidGateResult::min_entropy`] — the **per-bit** (controlling /
//!   bitstring-track) value, the same number each estimator contributes to the
//!   parity table ([`crate::parity`]) and the value used for the IID/non-IID
//!   routing decision.
//! - [`IidGateResult::assessed`] — the **per-symbol** [`AssessedMinEntropy`], the EA
//!   tool's final `Assessed min entropy` headline `min(H_original, H_bitstring ×
//!   word_size)`. `H_original` is the literal-track assessment — MCV-literal on the
//!   IID branch (EA `iid_main`), the §6.3 literal-suite minimum
//!   ([`crate::h_original`]) on the non-IID branch (EA `non_iid_main`);
//!   `H_bitstring` is the per-bit controlling value above; `word_size` is
//!   `bits_per_symbol`. For 1-bit data the literal and bitstring tracks coincide,
//!   so the assessed number equals the per-bit value (`word_size == 1`, no
//!   `H_bitstring` scaling — matching EA's "no `H_bitstring` assessment for binary
//!   data").
//!
//! # Controlling-track values (matching the parity table)
//!
//! Each non-IID estimator contributes the same per-bit value the parity harness
//! records (`parity.rs` `check_*` helpers):
//!
//! - **MCV** (IID branch and non-IID suite): the **bitstring** track for
//!   multi-bit data; the **literal** track for 1-bit data (`bits_per_symbol == 1`
//!   or [`crate::McvResult::bitstring`] is `None`), where the two tracks coincide.
//! - **Collision, Markov, Compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC,
//!   LZ78Y**: their single per-bit (bitstring-track) `min_entropy`, the value the
//!   corresponding `parity::check_*` helper compares.
//!
//! # Determinism
//!
//! [`iid_gate`] is **deterministic**: each underlying §5 test and §6 estimator is
//! deterministic (the permutation battery uses a fixed seed), so the same
//! `(data, bits_per_symbol)` always yields a bit-identical [`IidGateResult`].

#![forbid(unsafe_code)]

use crate::chi_square::chi_square_tests;
use crate::collision::collision;
use crate::compression::compression;
use crate::iid_lrs::len_lrs_iid_test;
use crate::lag::lag;
use crate::lrs::lrs;
use crate::lz78y::lz78y;
use crate::markov::markov;
use crate::multi_mcw::multi_mcw;
use crate::multi_mmc::multi_mmc;
use crate::permutation::permutation_test;
use crate::{McvResult, mcv};

/// Which estimator family supplies the reported min-entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// All three §5 tests passed: report the §6.1 MCV estimate.
    Iid,
    /// At least one §5 test failed: report the minimum over the §6.3 suite.
    NonIid,
}

/// The EA tool's final per-**symbol** "Assessed min entropy" headline and its
/// inputs: `per_symbol = min(h_original, h_bitstring × word_size)`.
///
/// Exposing the components (not just `per_symbol`) lets a consumer recompute and
/// audit the headline without re-running the gate — this is the reported-number
/// surface for the entropy assessment. `h_bitstring` always equals
/// [`IidGateResult::min_entropy`] (the per-bit controlling value).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AssessedMinEntropy {
    /// The EA "Assessed min entropy" headline, per symbol:
    /// `min(h_original, h_bitstring × word_size)`.
    pub per_symbol: f64,
    /// `H_original` — the literal-track assessment (per symbol). MCV-literal on the
    /// IID branch; the §6.3 literal-suite minimum ([`crate::h_original`]) on the
    /// non-IID branch.
    pub h_original: f64,
    /// `H_bitstring` — the per-bit controlling value (== [`IidGateResult::min_entropy`]).
    pub h_bitstring: f64,
    /// `word_size` — bits per symbol; the per-bit→per-symbol scaling factor.
    pub word_size: u8,
}

/// The SP 800-90B §5 IID gate result: the three §5 verdicts, the combined IID
/// decision, the selected branch, and the routed per-bit min-entropy.
#[derive(Debug, Clone, Copy, PartialEq)]
// The three §5 sub-verdicts plus the combined IID flag are the required public
// shape of this result (one bool per SP 800-90B §5 test, plus the AND of them);
// they are independent report fields, not a state machine to refactor.
#[allow(clippy::struct_excessive_bools)]
pub struct IidGateResult {
    /// §5.1 permutation battery verdict ([`crate::permutation::PermutationVerdict::is_iid`]).
    pub permutation_passed: bool,
    /// §5.2 chi-square tests verdict ([`crate::chi_square::ChiSquareResult::passed`]).
    pub chi_square_passed: bool,
    /// §5.3 LRS IID test verdict ([`crate::iid_lrs::LrsIidResult::passed`]).
    pub lrs_passed: bool,
    /// `true` iff all three §5 tests passed.
    pub is_iid: bool,
    /// [`Branch::Iid`] when [`Self::is_iid`], else [`Branch::NonIid`].
    pub branch: Branch,
    /// The routed **per-bit** (controlling-track) min-entropy: the §6.1 MCV
    /// estimate on the IID branch, or the minimum over the §6.3 suite on the
    /// non-IID branch. See the module docs for the per-bit/per-symbol boundary.
    pub min_entropy: f64,
    /// The EA tool's final per-symbol "Assessed min entropy" headline and its
    /// inputs (see [`AssessedMinEntropy`]). `assessed.h_bitstring == min_entropy`.
    pub assessed: AssessedMinEntropy,
}

/// The §6.1 MCV controlling per-bit min-entropy.
///
/// For 1-bit data (`bits_per_symbol == 1`, where [`McvResult::bitstring`] is
/// `None`) the literal and bitstring tracks coincide, so the literal track is the
/// per-bit value. For multi-bit data the **bitstring** track is the per-bit value
/// the parity table records for MCV.
fn mcv_controlling(result: &McvResult) -> f64 {
    result
        .bitstring
        .map_or(result.literal.min_entropy, |bs| bs.min_entropy)
}

/// Run the SP 800-90B §5 IID gate over `data` (raw bytes, one symbol per byte).
///
/// Runs the three §5 tests, combines them into the IID verdict, selects the
/// branch, and routes the per-bit min-entropy: the §6.1 MCV estimate on the IID
/// branch, or the minimum over the §6.3 non-IID suite on the non-IID branch
/// (mirroring the EA tool's `iid_main` vs `non_iid_main`). [`IidGateResult::min_entropy`]
/// is the per-bit controlling-track value; [`IidGateResult::assessed`] additionally
/// carries the EA per-symbol `Assessed min entropy` headline and its inputs (see
/// the module docs).
///
/// This function is **deterministic**: the same `(data, bits_per_symbol)` always
/// yields a bit-identical [`IidGateResult`].
///
/// # Panics
///
/// Does not panic. `bits_per_symbol` outside `1..=8` is handled by the underlying
/// estimators (MCV clamps it into range).
#[must_use]
pub fn iid_gate(data: &[u8], bits_per_symbol: u8) -> IidGateResult {
    // 1. The three §5 IID tests.
    let permutation_passed = permutation_test(data).is_iid;
    let chi_square_passed = chi_square_tests(data).passed;
    let lrs_passed = len_lrs_iid_test(data).passed;
    let is_iid = permutation_passed && chi_square_passed && lrs_passed;

    let branch = if is_iid { Branch::Iid } else { Branch::NonIid };

    // 2. Route the reported per-bit min-entropy.
    let mcv_result = mcv(data, bits_per_symbol);
    let mcv_h = mcv_controlling(&mcv_result);

    let min_entropy = if is_iid {
        // IID branch (§6.1): MCV only.
        mcv_h
    } else {
        // non-IID branch (§6.3): the minimum over the full suite — the same
        // controlling-track per-bit values the parity harness checks.
        let lrs_est = lrs(data, bits_per_symbol);
        let candidates = [
            mcv_h,
            collision(data, bits_per_symbol).min_entropy,
            markov(data, bits_per_symbol).min_entropy,
            compression(data, bits_per_symbol).min_entropy,
            lrs_est.t_tuple_min_entropy,
            lrs_est.lrs_min_entropy,
            multi_mcw(data, bits_per_symbol).min_entropy(),
            lag(data, bits_per_symbol).min_entropy(),
            multi_mmc(data, bits_per_symbol).min_entropy(),
            lz78y(data, bits_per_symbol).min_entropy(),
        ];
        candidates.iter().copied().fold(f64::INFINITY, f64::min)
    };

    // 3. The per-symbol assessed headline: min(H_original, H_bitstring × word_size).
    //    H_bitstring is the per-bit controlling value just routed (`min_entropy`);
    //    H_original is the literal-track assessment — MCV-literal on the IID branch
    //    (EA `iid_main`), the §6.3 literal-suite minimum on the non-IID branch (EA
    //    `non_iid_main`). For 1-bit data the literal and bitstring tracks coincide,
    //    so `bitstring` is `None`, `word_size` is 1, and the literal value is the
    //    assessed number unscaled.
    let h_original = if is_iid {
        mcv_result.literal.min_entropy
    } else {
        crate::h_original(data)
    };
    let assessed = AssessedMinEntropy {
        per_symbol: assessed_per_symbol_min_entropy(
            h_original,
            mcv_result.bitstring.map(|_| min_entropy),
            bits_per_symbol,
        ),
        h_original,
        h_bitstring: min_entropy,
        word_size: bits_per_symbol,
    };

    IidGateResult {
        permutation_passed,
        chi_square_passed,
        lrs_passed,
        is_iid,
        branch,
        min_entropy,
        assessed,
    }
}

/// Scale a per-bit IID/non-IID assessment to the per-**symbol** "Assessed min
/// entropy" the EA tool reports as its final number.
///
/// EA's final line is `min(H_original, H_bitstring × word_size)` (EA
/// `iid_main` / `non_iid_main`): `h_original_per_symbol` is the literal-track
/// assessment (already per symbol), `h_bitstring_per_bit` is the bitstring-track
/// assessment (per bit) scaled up by `word_size` bits/symbol. Verified against
/// `ea_iid -v -v -v` on the multi-bit reference datasets (rand4_short → 3.7900…,
/// rand8_short → 7.0105…). For 1-bit data the literal and bitstring tracks coincide:
/// pass `None` and the literal value is returned unscaled (`word_size == 1`).
///
/// **Policy STOP-AND-LEAVE (ISC-9):** this is the scaling *arithmetic* only. Which
/// number is canonical at maxwell's tool boundary — the per-bit controlling value
/// ([`IidGateResult::min_entropy`], unchanged) or this per-symbol assessed number —
/// is an attended decision and is deliberately NOT wired into the gate output here.
#[must_use]
pub fn assessed_per_symbol_min_entropy(
    h_original_per_symbol: f64,
    h_bitstring_per_bit: Option<f64>,
    word_size: u8,
) -> f64 {
    match h_bitstring_per_bit {
        // 1-bit data: the literal and bitstring tracks coincide, so the literal
        // value already IS the per-symbol assessed number (word_size == 1).
        None => h_original_per_symbol,
        Some(bs) => h_original_per_symbol.min(bs * f64::from(word_size)),
    }
}

#[cfg(test)]
#[allow(
    // Tests panic on invariant violations, use unwrap/expect for fatal setup,
    // index fixed-size fixtures, and print skip notices for absent datasets.
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    /// The per-symbol `word_size` scaling matches the EA tool's final "Assessed min
    /// entropy" on the multi-bit reference datasets — `min(H_original, H_bitstring ×
    /// word_size)`. Values are `ea_iid -v -v -v` ground truth (v1.1.8); they are the
    /// same `literal_min_entropy` / `bitstring_min_entropy` the parity table records.
    #[test]
    fn assessed_per_symbol_matches_ea_on_multi_bit_datasets() {
        // rand4_short (4-bit): H_original 3.7900… < H_bitstring×4 3.9168… → H_original.
        let rand4 = assessed_per_symbol_min_entropy(
            3.790_037_390_213_974,
            Some(0.979_189_482_962_402_2),
            4,
        );
        assert!(
            (rand4 - 3.790_037_390_213_974).abs() < 1e-12,
            "rand4_short assessed: got {rand4}, EA = 3.7900373902139739"
        );
        // rand8_short (8-bit): H_original 7.0105… < H_bitstring×8 7.8671… → H_original.
        let rand8 = assessed_per_symbol_min_entropy(
            7.010_454_037_736_041,
            Some(0.983_386_784_659_150_3),
            8,
        );
        assert!(
            (rand8 - 7.010_454_037_736_041).abs() < 1e-12,
            "rand8_short assessed: got {rand8}, EA = 7.0104540377360411"
        );
    }

    /// The scaling takes the minimum of the two tracks, and 1-bit data (no separate
    /// bitstring track) returns the literal value unscaled.
    #[test]
    fn assessed_per_symbol_takes_the_min_of_the_two_tracks() {
        // literal below the scaled bitstring → literal wins.
        assert!((assessed_per_symbol_min_entropy(3.0, Some(0.9), 4) - 3.0).abs() < 1e-12);
        // scaled bitstring below literal → scaled bitstring wins (0.9 × 4 = 3.6).
        assert!((assessed_per_symbol_min_entropy(3.9, Some(0.9), 4) - 3.6).abs() < 1e-12);
        // 1-bit data: the bitstring track coincides; the literal value is unscaled.
        assert!((assessed_per_symbol_min_entropy(0.961, None, 1) - 0.961).abs() < 1e-12);
    }

    /// The assembled per-symbol `assessed.per_symbol` reproduces the EA tool's
    /// final "Assessed min entropy" line to within 1e-6 on every multi-bit
    /// reference dataset — and crucially in the EA mode matching the gate's own
    /// branch verdict: the IID-classified datasets match `ea_iid -i -a -v -v`, the
    /// non-IID ones match `ea_non_iid -i -a -v -v` (v1.1.8, harvested 2026-06-17).
    /// This gates the full assembly: branch-selected H_original (MCV-literal on
    /// IID, §6.3 literal-suite min on non-IID), H_bitstring × word_size, and the
    /// outer min. Skips datasets absent on host.
    #[test]
    fn assessed_assembly_matches_ea_on_multi_bit_datasets() {
        use crate::parity::resolve_datasets_dir;
        // (file, bits_per_symbol, EA "Assessed min entropy" in the gate's branch mode).
        const EA_ASSESSED: &[(&str, u8, f64)] = &[
            ("biased-random-bytes.bin", 8, 0.319_650_651_838_2), // IID
            ("normal.bin", 8, 5.622_155_277_204_8),              // IID
            ("rand4_short.bin", 4, 3.215_488_267_876_7),         // non-IID
            ("rand8_short.bin", 8, 5.860_893_744_485_2),         // non-IID
            ("truerand_4bit.bin", 4, 3.971_194_336_729_6),       // IID
            ("truerand_8bit.bin", 8, 7.865_118_002_899_6),       // IID
        ];
        const PARITY_EPS: f64 = 1.0e-6;
        let dir = resolve_datasets_dir(None);
        let mut checked = 0usize;
        for &(file, bits, ea) in EA_ASSESSED {
            let Ok(data) = std::fs::read(dir.join(file)) else {
                eprintln!("{file} absent — skipping assessed-assembly parity");
                continue;
            };
            let r = iid_gate(&data, bits);
            // H_bitstring is always the routed per-bit controlling value.
            assert!(
                (r.assessed.h_bitstring - r.min_entropy).abs() < 1e-15,
                "{file}: assessed.h_bitstring {} != min_entropy {}",
                r.assessed.h_bitstring,
                r.min_entropy
            );
            assert_eq!(r.assessed.word_size, bits, "{file}: word_size");
            assert!(
                (r.assessed.per_symbol - ea).abs() <= PARITY_EPS,
                "{file}: assessed.per_symbol {} vs EA {ea} (delta {})",
                r.assessed.per_symbol,
                (r.assessed.per_symbol - ea).abs()
            );
            checked += 1;
        }
        if checked == 0 {
            eprintln!("no multi-bit datasets present — assessed-assembly parity skipped");
        }
    }

    /// Locate `tests/data/<name>` relative to the crate manifest.
    fn data_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
    }

    /// 1a. Branch correctness — IID direction. The EA-verified IID oracle
    /// (`oracle_iid.bin`, 8-bit, 100k samples, passes all three §5 tests) must
    /// route to [`Branch::Iid`]. This exercises the full gate including the
    /// 10,000-shuffle permutation battery, which the oracle was sized to keep
    /// tractable (see `tests/data/README.md`). Skips if the dataset is absent.
    #[test]
    fn oracle_iid_routes_to_iid_branch() {
        let Ok(data) = std::fs::read(data_path("oracle_iid.bin")) else {
            eprintln!("oracle_iid.bin absent — skipping IID-branch test");
            return;
        };
        let r = iid_gate(&data, 8);
        assert!(
            r.is_iid,
            "oracle_iid must be IID: perm={} chi={} lrs={}",
            r.permutation_passed, r.chi_square_passed, r.lrs_passed
        );
        assert!(
            matches!(r.branch, Branch::Iid),
            "oracle_iid must take the IID branch"
        );
        // The IID-branch min-entropy is the §6.1 MCV controlling value, finite.
        assert!(r.min_entropy.is_finite() && r.min_entropy >= 0.0);
    }

    /// 1b. Branch correctness — non-IID direction (full EA oracle). The
    /// EA-verified non-IID oracle (`oracle_noniid.bin`, fails all three §5 tests)
    /// must route to [`Branch::NonIid`]. Skips if the dataset is absent.
    ///
    /// `#[ignore]` by default: the §5.1 permutation battery does NOT early-exit on
    /// this dataset (a non-IID source can still have slow-to-decide statistics, so
    /// it runs nearly the full 10,000 shuffles on 100k samples — ~460 s in the
    /// unoptimized test build). The fast, always-on
    /// [`periodic_synthetic_routes_to_noniid`] covers the required clearly-non-IID
    /// routing assertion. Run this full-oracle check on demand with
    /// `cargo nextest run -p oxicrypt-maxwell --run-ignored all iid_gate`.
    #[test]
    #[ignore = "slow: full 10k-shuffle permutation on the 100k non-IID oracle (~460s); \
                periodic_synthetic_routes_to_noniid is the fast equivalent"]
    fn oracle_noniid_routes_to_noniid_branch() {
        let Ok(data) = std::fs::read(data_path("oracle_noniid.bin")) else {
            eprintln!("oracle_noniid.bin absent — skipping non-IID-branch test");
            return;
        };
        let r = iid_gate(&data, 8);
        assert!(
            !r.is_iid,
            "oracle_noniid must be non-IID: perm={} chi={} lrs={}",
            r.permutation_passed, r.chi_square_passed, r.lrs_passed
        );
        assert!(
            matches!(r.branch, Branch::NonIid),
            "oracle_noniid must take the non-IID branch"
        );
    }

    /// 1c. Fast synthetic branch probe (always runs, no dataset needed). A tiny,
    /// strongly periodic buffer is clearly non-IID — the chi-square / LRS tests
    /// reject the structure — so the gate must route to [`Branch::NonIid`]. This
    /// is the REQUIRED clearly-non-IID assertion without the oracle dependency or
    /// the 100k permutation cost.
    #[test]
    fn periodic_synthetic_routes_to_noniid() {
        // A short, highly structured period-4 ramp repeated: serially dependent,
        // and the value distribution is concentrated on four symbols.
        let buf: Vec<u8> = (0..8000u32).map(|i| (i % 4) as u8).collect();
        let r = iid_gate(&buf, 8);
        assert!(
            !r.is_iid,
            "periodic input must be non-IID: perm={} chi={} lrs={}",
            r.permutation_passed, r.chi_square_passed, r.lrs_passed
        );
        assert!(matches!(r.branch, Branch::NonIid));
    }

    /// 2. Determinism: two calls on the same small input are bit-identical.
    #[test]
    fn determinism_bit_exact() {
        let buf: Vec<u8> = (0..4000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let a = iid_gate(&buf, 8);
        let b = iid_gate(&buf, 8);
        assert_eq!(a, b, "IidGateResult must be bit-identical across runs");
    }

    /// 3. Routed-value sanity on a non-IID result. The routed min-entropy is the
    ///    minimum over the §6.3 suite, so it is finite, non-negative, and not
    ///    greater than every individual §6.3 estimate. Checked on the synthetic
    ///    periodic buffer (always non-IID, no dataset dependency).
    #[test]
    fn noniid_routed_value_is_suite_minimum() {
        let buf: Vec<u8> = (0..8000u32).map(|i| (i % 4) as u8).collect();
        let r = iid_gate(&buf, 8);
        assert!(
            matches!(r.branch, Branch::NonIid),
            "fixture must be non-IID"
        );

        let bits = 8u8;
        let mcv_result = mcv(&buf, bits);
        let mcv_h = mcv_controlling(&mcv_result);
        let lrs_est = lrs(&buf, bits);
        let individual = [
            mcv_h,
            collision(&buf, bits).min_entropy,
            markov(&buf, bits).min_entropy,
            compression(&buf, bits).min_entropy,
            lrs_est.t_tuple_min_entropy,
            lrs_est.lrs_min_entropy,
            multi_mcw(&buf, bits).min_entropy(),
            lag(&buf, bits).min_entropy(),
            multi_mmc(&buf, bits).min_entropy(),
            lz78y(&buf, bits).min_entropy(),
        ];

        assert!(
            r.min_entropy.is_finite(),
            "routed min-entropy must be finite, got {}",
            r.min_entropy
        );
        assert!(
            r.min_entropy >= 0.0,
            "routed min-entropy must be >= 0, got {}",
            r.min_entropy
        );
        for (i, &h) in individual.iter().enumerate() {
            assert!(
                r.min_entropy <= h + 1.0e-12,
                "routed min-entropy {} must be <= §6.3 estimate[{i}] = {h}",
                r.min_entropy
            );
        }
    }
}
