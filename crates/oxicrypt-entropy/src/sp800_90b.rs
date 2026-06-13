//! Cited SP 800-90B specification constants — the single transcription site.
//!
//! # Provenance (transcribed, never recalled)
//!
//! Every constant in this module was transcribed from:
//!
//! - **NIST SP 800-90B**, *Recommendation for the Entropy Sources Used for
//!   Random Bit Generation*, January 2018,
//!   <https://doi.org/10.6028/NIST.SP.800-90B> — fetched 2026-06-12.
//! - **NIST SP 800-90B Errata** (last updated 2025-05-29, csrc.nist.gov
//!   publication page) — fetched 2026-06-12. The errata sheet corrects only
//!   §5.2.4 (chi-squared critical value) and a §6.3.1 worked example; **no
//!   correction touches any section transcribed here** (§3.1.4, §3.1.5,
//!   §4.3–4.5).
//! - **NIST SP 800-90C**, *Recommendation for Random Bit Generator (RBG)
//!   Constructions*, September 2025 (final),
//!   <https://doi.org/10.6028/NIST.SP.800-90C> — fetched 2026-06-12.
//!   Transcribed here: the full-entropy input margin (§3.2.2.2, anchored on
//!   §2.6 item 11).
//!
//! Per the workspace spec-constants doctrine, no other module may restate a
//! 90B numeric: spec revision is a one-module change.
//!
//! # Exactness
//!
//! All values are integers or exact rationals ([`SpecRatio`]). No
//! floating-point type appears in this module or anywhere in the health-test
//! cutoff path (design constraint; see the crate-level documentation).
//!
//! # Transcribed formulas (normative text, not code)
//!
//! **RCT cutoff (§4.4.1):** `C = 1 + ⌈ −log₂(α) / H ⌉`. With `α = 2⁻ᵃ` this
//! is pure integer arithmetic: `C = 1 + ⌈ a / H ⌉`. The spec's worked
//! example — `α = 2⁻²⁰`, `H = 2.0` → `C = 11` — is asserted by unit test
//! against this module's constants.
//!
//! **APT cutoff (§4.4.2, footnote 10):** the smallest `C` with
//! `Pr(B ≥ C) ≤ α` for `B ~ Binomial(W, 2⁻ᴴ)`, i.e.
//! `C = 1 + CRITBINOM(W, 2⁻ᴴ, 1 − α)`. In-boundary cutoffs are precomputed
//! tables verified against [`APT_TABLE2_BINARY`] / [`APT_TABLE2_NON_BINARY`]
//! reference rows below (generation lives out of boundary).
//!
//! **Vetted-conditioning output entropy (§3.1.5.1.2):**
//! `h_out = Output_Entropy(n_in, n_out, nw, h_in)` where
//!
//! 1. `P_high = 2^(−h_in)`; `P_low = (1 − P_high) / (2^n_in − 1)`
//! 2. `n = min(n_out, nw)`
//! 3. `ψ = 2^(n_in − n) · P_low + P_high`
//! 4. `U = 2^(n_in − n) + sqrt(2n · 2^(n_in − n) · ln 2)`
//! 5. `ω = U · P_low`
//! 6. return `−log₂(max(ψ, ω))`
//!
//! Vetted conditioning components are permitted to claim full-entropy
//! outputs (§3.1.5.1.2). Truncating a vetted component's output reduces the
//! entropy estimate proportionally (§3.1.5.1.2). The non-vetted path
//! (§3.1.5.2, `0.999·n_out` factor) is intentionally not transcribed as
//! constants: this workspace uses a vetted conditioner only.
//!
//! **Developer-defined alternatives (§4.5)** are not used — the two approved
//! continuous tests (§4.4) are implemented as specified, so the §4.5
//! substitution criteria impose no constants here.

/// An exact rational value transcribed from SP 800-90B.
///
/// Spec values that are not integers (probabilities, entropy levels) are
/// carried as `num/den` pairs so that no floating-point representation enters
/// the transcription. Both fields are public, immutable spec data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecRatio {
    /// Numerator.
    pub num: u32,
    /// Denominator (non-zero by construction of each constant).
    pub den: u32,
}

// ─── §3.1.4.1 Constructing Restart Data ─────────────────────────────────────

/// §3.1.4.1: "the entropy source shall be restarted r = 1000 times".
pub const RESTART_ROUNDS: u32 = 1000;

/// §3.1.4.1: "for each restart, c = 1000 consecutive samples shall be
/// collected directly from the noise source".
pub const RESTART_SAMPLES_PER_ROUND: u32 = 1000;

// ─── §3.1.4.2 Validation Testing ────────────────────────────────────────────

/// §3.1.4.2: "If the minimum of Hr and Hc is less than half of HI, the
/// validation fails" — the divisor in that comparison.
pub const RESTART_ESTIMATE_MIN_FRACTION_OF_HI: SpecRatio = SpecRatio { num: 1, den: 2 };

// ─── §3.1.4.3 Sanity Check — Most Common Value ──────────────────────────────

/// §3.1.4.3: per-experiment type-I error — "Let α be 0.000 005"
/// (= 1/200 000, exact).
pub const RESTART_SANITY_ALPHA: SpecRatio = SpecRatio {
    num: 1,
    den: 200_000,
};

/// §3.1.4.3: type-I error "set at 0.01 over the entire sanity check".
pub const RESTART_SANITY_ALPHA_TOTAL: SpecRatio = SpecRatio { num: 1, den: 100 };

/// §3.1.4.3: "each of the 2000 binomial experiments" (1000 rows + 1000
/// columns).
pub const RESTART_SANITY_EXPERIMENTS: u32 = 2000;

// ─── §4.3 Requirements for Health Tests ─────────────────────────────────────

/// §4.3 item 3: recommended false-positive probability lower bound exponent —
/// "recommended to be between 2⁻²⁰ and 2⁻⁴⁰" (α = 2⁻ᵃ; this is the smallest
/// recommended `a`). Lower probabilities (larger `a`) are acceptable.
pub const CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN: u32 = 20;

/// §4.3 item 3: recommended false-positive probability upper bound exponent
/// (see [`CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN`]).
pub const CONTINUOUS_ALPHA_EXP_RECOMMENDED_MAX: u32 = 40;

/// §4.3 item 4: "startup tests shall run the continuous health tests over at
/// least 1024 consecutive samples". The same section permits the tested
/// samples to be discarded — this workspace discards them (a policy choice
/// recorded in the design contract, not a spec constant).
pub const STARTUP_MIN_SAMPLES: u32 = 1024;

// ─── §4.4.2 Adaptive Proportion Test ────────────────────────────────────────

/// §4.4.2: window size W "shall be assigned to 1024 if the noise source is
/// binary".
pub const APT_WINDOW_BINARY: u32 = 1024;

/// §4.4.2: window size W shall be "512 if the noise source is not binary".
pub const APT_WINDOW_NON_BINARY: u32 = 512;

/// One reference row of SP 800-90B Table 2 (§4.4.2): an example APT cutoff
/// `C` for a min-entropy level `h` at `α = 2⁻²⁰`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AptTable2Row {
    /// Min-entropy per sample for this row (exact rational, bits).
    pub h: SpecRatio,
    /// Example cutoff value C.
    pub cutoff: u32,
}

/// §4.4.2 Table 2, α-exponent of the example cutoffs: "with α = 2⁻²⁰".
pub const APT_TABLE2_ALPHA_EXP: u32 = 20;

/// §4.4.2 Table 2, binary data (W = 1024), α = 2⁻²⁰.
pub const APT_TABLE2_BINARY: [AptTable2Row; 5] = [
    AptTable2Row {
        h: SpecRatio { num: 1, den: 5 },
        cutoff: 941,
    }, // H = 0.2
    AptTable2Row {
        h: SpecRatio { num: 2, den: 5 },
        cutoff: 840,
    }, // H = 0.4
    AptTable2Row {
        h: SpecRatio { num: 3, den: 5 },
        cutoff: 748,
    }, // H = 0.6
    AptTable2Row {
        h: SpecRatio { num: 4, den: 5 },
        cutoff: 664,
    }, // H = 0.8
    AptTable2Row {
        h: SpecRatio { num: 1, den: 1 },
        cutoff: 589,
    }, // H = 1
];

/// §4.4.2 Table 2, non-binary data (W = 512), α = 2⁻²⁰.
pub const APT_TABLE2_NON_BINARY: [AptTable2Row; 5] = [
    AptTable2Row {
        h: SpecRatio { num: 1, den: 2 },
        cutoff: 410,
    }, // H = 0.5
    AptTable2Row {
        h: SpecRatio { num: 1, den: 1 },
        cutoff: 311,
    }, // H = 1
    AptTable2Row {
        h: SpecRatio { num: 2, den: 1 },
        cutoff: 177,
    }, // H = 2
    AptTable2Row {
        h: SpecRatio { num: 4, den: 1 },
        cutoff: 62,
    }, // H = 4
    AptTable2Row {
        h: SpecRatio { num: 8, den: 1 },
        cutoff: 13,
    }, // H = 8
];

// ─── §4.4.2 APT cutoffs at α = 2⁻³⁰ (the ratified default) ───────────────────

/// α-exponent of the [`APT_ALPHA30_BINARY`] / [`APT_ALPHA30_NON_BINARY`]
/// tables: α = 2⁻³⁰, the workspace's ratified default false-positive
/// probability (jent v3.7.0 cert-lineage precedent; see
/// [`crate::health::Alpha::DEFAULT`]).
///
/// # Provenance — generated, not from a published table
///
/// Unlike the [`APT_TABLE2_BINARY`] / [`APT_TABLE2_NON_BINARY`] rows (which
/// are transcribed from SP 800-90B Table 2), the α = 2⁻³⁰ cutoffs below have
/// no published reference table. They were **generated** by the
/// out-of-boundary `oxicrypt-maxwell` APT generator
/// (`oxicrypt_maxwell::apt::apt_cutoff`), which computes
/// `C = 1 + qbinom(1 − α, W, 2⁻ᴴ)` with the binomial CDF evaluated via the
/// regularized incomplete beta function (the same method R's `qbinom` uses).
///
/// That generator is validated to reproduce **all 11** SP 800-90B Table 2
/// reference points exactly (α = 2⁻²⁰) plus the jent cross-check
/// `W = 512, H = 1, α = 2⁻³⁰ → 325`. The single α = 2⁻³⁰ point with an
/// external reference — non-binary `H = 1 → 325` — appears in
/// [`APT_ALPHA30_NON_BINARY`] below and matches the jent value, anchoring the
/// whole generated grid. The in-boundary crate does **not** depend on the
/// generator: these are precomputed integer constants, and a unit test in
/// this module re-asserts every value against the generator's known output.
pub const APT_ALPHA30_ALPHA_EXP: u32 = 30;

/// §4.4.2 cutoffs for binary data (W = 1024) at α = 2⁻³⁰. Generated; see
/// [`APT_ALPHA30_ALPHA_EXP`] for provenance.
pub const APT_ALPHA30_BINARY: [AptTable2Row; 5] = [
    AptTable2Row {
        h: SpecRatio { num: 1, den: 5 },
        cutoff: 952,
    }, // H = 0.2
    AptTable2Row {
        h: SpecRatio { num: 2, den: 5 },
        cutoff: 856,
    }, // H = 0.4
    AptTable2Row {
        h: SpecRatio { num: 3, den: 5 },
        cutoff: 766,
    }, // H = 0.6
    AptTable2Row {
        h: SpecRatio { num: 4, den: 5 },
        cutoff: 683,
    }, // H = 0.8
    AptTable2Row {
        h: SpecRatio { num: 1, den: 1 },
        cutoff: 609,
    }, // H = 1
];

/// §4.4.2 cutoffs for non-binary data (W = 512) at α = 2⁻³⁰. Generated; the
/// `H = 1 → 325` row is the jent cross-check anchor. See
/// [`APT_ALPHA30_ALPHA_EXP`] for provenance.
pub const APT_ALPHA30_NON_BINARY: [AptTable2Row; 5] = [
    AptTable2Row {
        h: SpecRatio { num: 1, den: 2 },
        cutoff: 422,
    }, // H = 0.5
    AptTable2Row {
        h: SpecRatio { num: 1, den: 1 },
        cutoff: 325,
    }, // H = 1  (jent cross-check anchor)
    AptTable2Row {
        h: SpecRatio { num: 2, den: 1 },
        cutoff: 190,
    }, // H = 2
    AptTable2Row {
        h: SpecRatio { num: 4, den: 1 },
        cutoff: 71,
    }, // H = 4
    AptTable2Row {
        h: SpecRatio { num: 8, den: 1 },
        cutoff: 16,
    }, // H = 8
];

// ─── §3.1.5.1.1 Table 1 — Vetted Conditioning Components ────────────────────

/// §3.1.5.1.1 Table 1: for a vetted hash-function conditioning component,
/// the narrowest internal width nw equals the hash-function output size.
/// For SHA-256 (this workspace's ratified conditioner): 256 bits.
pub const VETTED_SHA256_NW_BITS: u32 = 256;

/// §3.1.5.1.1 Table 1: for a vetted hash-function conditioning component,
/// the output length n_out equals the hash-function output size.
/// For SHA-256: 256 bits.
pub const VETTED_SHA256_NOUT_BITS: u32 = 256;

// ─── SP 800-90C §3.2.2.2 — Full-Entropy Input Margin ────────────────────────

/// SP 800-90C §3.2.2.2 (September 2025, final): "The amount of entropy
/// required for each use of the conditioning function is output_len + 64
/// bits (see item 11 in Sec. 2.6)" — where output_len is the length of the
/// conditioning function's output block.
///
/// §2.6 item 11 anchors the margin: full-entropy bits can be extracted
/// "when the amount of fresh entropy inserted into the algorithm exceeds
/// the number of bits that are extracted by at least 64 bits"
/// (see NIST IR 8427 for the underlying analysis).
///
/// This is the `+ 64` in the conditioner's per-block input-entropy
/// requirement `h_in ≥ n_out + 64`.
pub const FULL_ENTROPY_INPUT_MARGIN_BITS: u32 = 64;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// §3.1.4.3 internal consistency: 0.01 spread over 2000 experiments is
    /// exactly the stated per-experiment α of 0.000 005.
    #[test]
    fn restart_sanity_alpha_consistent() {
        // (1/100) / 2000 == 1/200_000
        assert_eq!(
            u64::from(RESTART_SANITY_ALPHA_TOTAL.den) * u64::from(RESTART_SANITY_EXPERIMENTS),
            u64::from(RESTART_SANITY_ALPHA.den) * u64::from(RESTART_SANITY_ALPHA_TOTAL.num),
        );
        assert_eq!(RESTART_SANITY_ALPHA.num, 1);
        assert_eq!(
            RESTART_SANITY_EXPERIMENTS,
            2 * RESTART_ROUNDS.min(RESTART_SAMPLES_PER_ROUND)
        );
    }

    /// §4.4.1 worked example: α = 2⁻²⁰, H = 2.0 → C = 1 + ⌈20/2⌉ = 11.
    /// Integer-exact check that the transcribed RCT formula and the
    /// recommended-α constant reproduce the spec's own example.
    #[test]
    fn rct_worked_example_holds() {
        let alpha_exp = CONTINUOUS_ALPHA_EXP_RECOMMENDED_MIN; // 20
        let h_num = 2u32; // H = 2.0 exactly
        let cutoff = 1 + alpha_exp.div_ceil(h_num);
        assert_eq!(cutoff, 11);
    }

    /// Table 2 sanity: cutoffs strictly decrease as min-entropy increases
    /// (more entropy claimed → repeats less probable → tighter cutoff).
    #[test]
    fn apt_table2_monotonic() {
        for table in [&APT_TABLE2_BINARY, &APT_TABLE2_NON_BINARY] {
            for pair in table.windows(2) {
                // h strictly increases: num0*den1 < num1*den0
                assert!(
                    u64::from(pair[0].h.num) * u64::from(pair[1].h.den)
                        < u64::from(pair[1].h.num) * u64::from(pair[0].h.den)
                );
                assert!(pair[0].cutoff > pair[1].cutoff);
            }
        }
    }

    /// §4.4.2: every Table 2 cutoff is below its window (a count within the
    /// window can actually reach it) and windows match the binary/non-binary
    /// assignment.
    #[test]
    fn apt_table2_within_windows() {
        assert_eq!(APT_WINDOW_BINARY, 1024);
        assert_eq!(APT_WINDOW_NON_BINARY, 512);
        for row in &APT_TABLE2_BINARY {
            assert!(row.cutoff <= APT_WINDOW_BINARY);
        }
        for row in &APT_TABLE2_NON_BINARY {
            assert!(row.cutoff <= APT_WINDOW_NON_BINARY);
        }
    }

    /// The α = 2⁻³⁰ tables equal the values the out-of-boundary
    /// `oxicrypt-maxwell` APT generator produces. The reference values are
    /// hardcoded here so the in-boundary crate does NOT depend on maxwell;
    /// `oxicrypt_maxwell::apt::tests::alpha30_grids_match_in_boundary_table`
    /// asserts the generator side of this same contract.
    #[test]
    fn apt_alpha30_matches_generator() {
        assert_eq!(APT_ALPHA30_ALPHA_EXP, 30);

        // Binary W = 1024, α = 2⁻³⁰ (generator output, jent-anchored grid).
        let bin = [
            (SpecRatio { num: 1, den: 5 }, 952u32),
            (SpecRatio { num: 2, den: 5 }, 856),
            (SpecRatio { num: 3, den: 5 }, 766),
            (SpecRatio { num: 4, den: 5 }, 683),
            (SpecRatio { num: 1, den: 1 }, 609),
        ];
        for (row, (h, c)) in APT_ALPHA30_BINARY.iter().zip(bin) {
            assert_eq!(row.h, h);
            assert_eq!(row.cutoff, c);
        }

        // Non-binary W = 512, α = 2⁻³⁰; H = 1 → 325 is the jent cross-check.
        let nonbin = [
            (SpecRatio { num: 1, den: 2 }, 422u32),
            (SpecRatio { num: 1, den: 1 }, 325),
            (SpecRatio { num: 2, den: 1 }, 190),
            (SpecRatio { num: 4, den: 1 }, 71),
            (SpecRatio { num: 8, den: 1 }, 16),
        ];
        for (row, (h, c)) in APT_ALPHA30_NON_BINARY.iter().zip(nonbin) {
            assert_eq!(row.h, h);
            assert_eq!(row.cutoff, c);
        }
    }

    /// The α = 2⁻³⁰ tables share the structural invariants of Table 2:
    /// monotonic in H, within their windows, and aligned to the same H grid.
    #[test]
    fn apt_alpha30_structural_invariants() {
        for (table, window) in [
            (&APT_ALPHA30_BINARY, APT_WINDOW_BINARY),
            (&APT_ALPHA30_NON_BINARY, APT_WINDOW_NON_BINARY),
        ] {
            for pair in table.windows(2) {
                // h strictly increases.
                assert!(
                    u64::from(pair[0].h.num) * u64::from(pair[1].h.den)
                        < u64::from(pair[1].h.num) * u64::from(pair[0].h.den)
                );
                // cutoff strictly decreases.
                assert!(pair[0].cutoff > pair[1].cutoff);
            }
            for row in table {
                assert!(row.cutoff <= window);
            }
        }
        // Same H grid as Table 2 (rarer α only shifts cutoffs, not the grid).
        for (a30, a20) in APT_ALPHA30_BINARY.iter().zip(APT_TABLE2_BINARY.iter()) {
            assert_eq!(a30.h, a20.h);
            // Rarer false positive (2⁻³⁰ < 2⁻²⁰) → larger cutoff.
            assert!(a30.cutoff > a20.cutoff);
        }
        for (a30, a20) in APT_ALPHA30_NON_BINARY
            .iter()
            .zip(APT_TABLE2_NON_BINARY.iter())
        {
            assert_eq!(a30.h, a20.h);
            assert!(a30.cutoff > a20.cutoff);
        }
    }
}
