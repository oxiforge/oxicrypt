#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! ML-DSA (FIPS 204) benchmarks — all three parameter sets
//! (ML-DSA-44, -65, -87), measuring keygen, sign, and verify.
//!
//! `keygen` takes a 32-byte seed (`xi` — FIPS 204 §6.1); the external
//! `sign`/`verify` take a context string `ctx` (empty here) alongside
//! the message. Signing is deterministic, so a fixed seed + message
//! gives a reproducible suite. The sign bench reuses one secret key
//! across iterations (ML-DSA is stateless); the verify bench signs once
//! outside the timing loop and measures a single verification.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

/// Deterministic keygen seed (`xi`) shared by every parameter set.
const XI: [u8; 32] = [0x42u8; 32];
const MSG: &[u8] = b"benchmark message for ML-DSA (FIPS 204)";
/// Empty context string (FIPS 204 §5.2 external API).
const CTX: &[u8] = b"";

/// Keygen bench for one ML-DSA parameter set.
macro_rules! ml_dsa_keygen_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let mut group = c.benchmark_group("ML-DSA keygen");
            group.bench_function($label, |b| {
                b.iter(|| $variant::keygen(black_box(&XI)).expect("keygen"));
            });
            group.finish();
        }
    };
}

/// Sign bench: the secret key is generated once outside the timing
/// loop (ML-DSA is stateless, so one key serves every iteration).
macro_rules! ml_dsa_sign_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (_pk, sk) = $variant::keygen(&XI).expect("keygen");

            let mut group = c.benchmark_group("ML-DSA sign");
            group.bench_function($label, |b| {
                b.iter(|| $variant::sign(black_box(&sk), black_box(MSG), CTX).expect("sign"));
            });
            group.finish();
        }
    };
}

/// Verify bench: the signature is produced once outside the timing
/// loop; the measured cost is a single verification.
macro_rules! ml_dsa_verify_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (pk, sk) = $variant::keygen(&XI).expect("keygen");
            let sig = $variant::sign(&sk, MSG, CTX).expect("sign");

            let mut group = c.benchmark_group("ML-DSA verify");
            group.bench_function($label, |b| {
                b.iter(|| {
                    $variant::verify(black_box(&pk), black_box(MSG), CTX, black_box(&sig))
                        .expect("verify")
                });
            });
            group.finish();
        }
    };
}

ml_dsa_keygen_bench!(bench_ml_dsa_keygen_44, ml_dsa_44, "ML-DSA-44");
ml_dsa_keygen_bench!(bench_ml_dsa_keygen_65, ml_dsa_65, "ML-DSA-65");
ml_dsa_keygen_bench!(bench_ml_dsa_keygen_87, ml_dsa_87, "ML-DSA-87");

ml_dsa_sign_bench!(bench_ml_dsa_sign_44, ml_dsa_44, "ML-DSA-44");
ml_dsa_sign_bench!(bench_ml_dsa_sign_65, ml_dsa_65, "ML-DSA-65");
ml_dsa_sign_bench!(bench_ml_dsa_sign_87, ml_dsa_87, "ML-DSA-87");

ml_dsa_verify_bench!(bench_ml_dsa_verify_44, ml_dsa_44, "ML-DSA-44");
ml_dsa_verify_bench!(bench_ml_dsa_verify_65, ml_dsa_65, "ML-DSA-65");
ml_dsa_verify_bench!(bench_ml_dsa_verify_87, ml_dsa_87, "ML-DSA-87");

criterion_group!(
    benches,
    bench_ml_dsa_keygen_44,
    bench_ml_dsa_keygen_65,
    bench_ml_dsa_keygen_87,
    bench_ml_dsa_sign_44,
    bench_ml_dsa_sign_65,
    bench_ml_dsa_sign_87,
    bench_ml_dsa_verify_44,
    bench_ml_dsa_verify_65,
    bench_ml_dsa_verify_87,
);
criterion_main!(benches);
