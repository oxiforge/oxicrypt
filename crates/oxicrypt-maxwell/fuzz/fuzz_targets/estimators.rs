#![no_main]
//! Fuzz target proving the `oxicrypt-maxwell` SP 800-90B estimator suite never
//! panics on malformed or arbitrary input (ISC-54).
//!
//! `oxicrypt-maxwell` is OUT OF the cryptographic boundary — pure offline
//! analysis tooling — but it parses/consumes arbitrary byte streams (the EA
//! datasets and, in production, real noise-source captures). Every public entry
//! point documents "does not panic" and clamps/guards degenerate input; this
//! target is the executable proof of that contract under libFuzzer mutation.
//!
//! The single target takes `data: &[u8]`, derives a `bits_per_symbol` in
//! `1..=8` from the first byte, and drives every public estimator/test in turn.
//! A panic (overflow, slice OOB, unwrap, divide-by-zero, unreachable, shift
//! overflow) anywhere in the suite aborts the process and is reported by
//! libFuzzer as a crash — i.e. a real bug in maxwell that must be fixed.
//!
//! Run: `cargo +nightly fuzz run estimators -- -max_total_time=45 -rss_limit_mb=4096`

use libfuzzer_sys::fuzz_target;

use oxicrypt_maxwell::{
    chi_square::chi_square_tests,
    collision::collision,
    compression::compression,
    iid_gate::iid_gate,
    iid_lrs::len_lrs_iid_test,
    independence::analyze as independence_analyze,
    lag::lag,
    lrs::{lrs, lrs_length},
    lz78y::lz78y,
    markov::markov,
    mcv,
    multi_mcw::multi_mcw,
    multi_mmc::multi_mmc,
    permutation::{permutation_stats, run_permutation},
};

fuzz_target!(|data: &[u8]| {
    // Derive a width in 1..=8 from the first byte (the public functions clamp
    // out-of-range widths themselves, but feeding only valid widths exercises
    // every shift/decompose path the EA datasets actually use).
    let bits: u8 = (data.first().copied().unwrap_or(8) % 8) + 1;

    // --- §5.1 permutation statistics + verdict ----------------------------
    // permutation_stats computes the 19 original statistics over the alphabet.
    let _ = permutation_stats(data);
    // run_permutation with a SMALL shuffle budget (50) so the fuzzer iterates
    // fast: the full PERMS=10_000 path is exercised structurally by these same
    // shuffles; 50 is enough to drive the Fisher-Yates / counter-update loops on
    // arbitrary input. (permutation_test() with full PERMS is reachable via
    // iid_gate below, gated to small inputs.)
    let _ = run_permutation(data, 50);

    // --- §5.2 chi-square tests --------------------------------------------
    let _ = chi_square_tests(data);

    // --- §5.3 LRS IID test + §6.3.5/6 t-Tuple/LRS -------------------------
    let _ = len_lrs_iid_test(data);
    let _ = lrs(data, bits);
    // Direct suffix-array longest-repeated-substring over the raw bytes.
    let _ = lrs_length(data);

    // --- §6.3 non-IID estimator suite -------------------------------------
    let _ = mcv(data, bits);
    let _ = collision(data, bits);
    let _ = markov(data, bits);
    let _ = compression(data, bits);
    let _ = multi_mcw(data, bits);
    let _ = lag(data, bits);
    let _ = multi_mmc(data, bits);
    let _ = lz78y(data, bits);

    // --- §5 IID gate (full integration) -----------------------------------
    // iid_gate internally runs permutation_test() with the full PERMS=10_000
    // budget. The early-exit terminates clearly-non-IID / degenerate data in
    // far fewer shuffles, but to keep the fuzzer's iteration rate high we only
    // drive the full gate on SMALL inputs. Larger inputs already have every
    // component above exercised individually, so no coverage is lost — only the
    // top-level wiring is skipped for big buffers (documented in fuzz/README.md).
    if data.len() <= 512 {
        let _ = iid_gate(data, bits);
        // --- independence analysis (2D/3D min-entropy) --------------------
        // Drives the tuple encoder (all phases, tail truncation), the tuple-MCV
        // histograms, the pair-suite leg (bits<=4), the shuffled-baseline
        // control, and the claim gate — all on arbitrary small input. Gated to
        // small inputs alongside iid_gate: the pair-suite leg runs the full §6.3
        // predictor battery, already exercised individually above.
        // Raw first: with arbitrary bytes and a small `bits` this now usually
        // takes the width refusal, which is itself a path worth fuzzing.
        let _ = independence_analyze(data, bits, Some(0.5));
        // Then masked into the declared width, so the analysis body keeps being
        // fuzzed. Without this the refusal added in #152 would quietly become the
        // only path this target reaches, and the encoder/histogram/suite coverage
        // described above would be lost while the target still looked green.
        let mask = u8::try_from((1u16.wrapping_shl(u32::from(bits))).saturating_sub(1))
            .unwrap_or(u8::MAX);
        let masked: Vec<u8> = data.iter().map(|&s| s & mask).collect();
        // Asserted, not discarded: this is now the ONLY call that reaches the
        // analysis body, so if the mask or the `bits` derivation ever drifts, both
        // calls take the refusal and the coverage described above silently vanishes
        // while libFuzzer still reports green.
        assert!(
            independence_analyze(&masked, bits, Some(0.5)).is_ok(),
            "masked input must fit the declared width"
        );
    }
});
