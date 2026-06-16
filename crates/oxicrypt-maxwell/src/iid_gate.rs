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
//! # Per-bit, not per-symbol — scope boundary
//!
//! The routed [`IidGateResult::min_entropy`] is the **per-bit** (controlling /
//! bitstring-track) min-entropy — the same value each estimator contributes to
//! the parity table ([`crate::parity`]), and the value used for the IID/non-IID
//! routing decision.
//!
//! The EA tool's final `Assessed min entropy` line additionally scales the
//! bitstring value by `word_size` (bits per symbol) and, for multi-bit data, may
//! take the literal estimate as controlling. That **per-symbol final-number
//! scaling is deliberately out of scope here** — it is the tool-level
//! final-number concern of a later parity step. This gate's job is the §5
//! verdict, the branch selection, and the per-bit routed estimate. Callers that
//! need the per-symbol final number apply the `word_size` scaling on top of this
//! value.
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
/// (mirroring the EA tool's `iid_main` vs `non_iid_main`). The min-entropy is the
/// per-bit controlling-track value (see the module docs); the per-symbol
/// `word_size` scaling is out of scope.
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

    IidGateResult {
        permutation_passed,
        chi_square_passed,
        lrs_passed,
        is_iid,
        branch,
        min_entropy,
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
