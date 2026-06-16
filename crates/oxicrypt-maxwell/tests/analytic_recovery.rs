//! Analytic min-entropy recovery (ISC-10).
//!
//! Unlike the EA-parity tests, this needs no reference tool: for an i.i.d.
//! Bernoulli(p) bit source the per-bit min-entropy is known in closed form,
//! `H = -log2(max(p, 1-p))`. We generate such sources deterministically and
//! confirm the §6.3.1 MCV estimate recovers `H` (from below — the estimator's
//! 99% upper-confidence bound on the mode probability makes its estimate a
//! slight, bounded under-estimate of the analytic value, never an over-estimate).

// Test code: the `>> 11` keeps the value within f64's 53-bit mantissa (lossless),
// and `expect` on a known-present track is a deliberate fatal-on-setup assertion.
#![allow(clippy::cast_precision_loss, clippy::expect_used)]

use oxicrypt_maxwell::mcv;

/// SplitMix64 — deterministic, high-quality; low bit drives the Bernoulli draw.
fn sm64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// `n` i.i.d. Bernoulli(p) samples as 0/1 bytes, threshold on a uniform draw.
fn bernoulli(n: usize, p: f64, seed: u64) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // uniform in [0,1) from the top 53 bits.
        let u = (sm64(&mut s) >> 11) as f64 * 2.0_f64.powi(-53);
        out.push(u8::from(u < p));
    }
    out
}

fn analytic_min_entropy(p: f64) -> f64 {
    -(p.max(1.0 - p)).log2()
}

#[test]
fn mcv_recovers_bernoulli_min_entropy() {
    let n = 1_000_000;
    // (p, tolerance). Larger bias => tighter sampling, so a small absolute
    // tolerance suffices; near-uniform needs a touch more slack for the CI term.
    let cases = [
        (0.5, 0.01),  // near-uniform: H = 1.0
        (0.75, 0.01), // H = -log2(0.75) ≈ 0.415
        (0.90, 0.01), // H = -log2(0.90) ≈ 0.152
        (0.99, 0.02), // strongly biased: H = -log2(0.99) ≈ 0.0145
    ];
    for (i, &(p, tol)) in cases.iter().enumerate() {
        let data = bernoulli(n, p, 0xA5A5_0000 ^ (i as u64));
        let analytic = analytic_min_entropy(p);
        // 1-bit data: the literal track IS the per-bit MCV estimate.
        let est = mcv(&data, 1).literal.min_entropy;
        let delta = (est - analytic).abs();
        assert!(
            delta <= tol,
            "p={p}: MCV estimate {est:.6} vs analytic {analytic:.6} (Δ={delta:.6} > tol {tol})"
        );
        // The estimator must never materially over-state entropy.
        assert!(
            est <= analytic + 1.0e-6,
            "p={p}: MCV {est:.6} over-states analytic {analytic:.6}"
        );
    }
}

#[test]
fn mcv_near_uniform_is_close_to_one_bit() {
    // A near-uniform byte source: full 8-bit alphabet, ~1 bit/bit on the
    // bitstring track and ~8 bits/symbol on the literal track.
    let mut s = 0x1234_5678_9ABC_DEF0u64;
    let n = 1_000_000;
    let data: Vec<u8> = (0..n).map(|_| (sm64(&mut s) & 0xFF) as u8).collect();
    let r = mcv(&data, 8);
    let bits = r.bitstring.expect("8-bit data has a bitstring track");
    assert!(
        (bits.min_entropy - 1.0).abs() <= 0.01,
        "near-uniform bitstring MCV {:.6} should be ≈ 1.0/bit",
        bits.min_entropy
    );
    // Literal per-symbol estimate should be close to the full 8 bits.
    assert!(
        r.literal.min_entropy >= 7.8,
        "near-uniform literal MCV {:.6} should be ≈ 8 bits/symbol",
        r.literal.min_entropy
    );
}
