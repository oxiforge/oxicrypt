#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! ML-KEM (FIPS 203) benchmarks — all three parameter sets
//! (ML-KEM-512, -768, -1024), measuring keygen, encapsulate, and
//! decapsulate.
//!
//! `keygen` takes two 32-byte seeds (`d`, `z` — FIPS 203 §6.1);
//! `encapsulate` takes the encapsulation key plus a 32-byte message
//! randomness `m`. All seeds are deterministic (`0x42`) so the suite is
//! reproducible. The encaps/decaps benches build a key pair (and, for
//! decaps, a ciphertext) once outside the timing loop, then measure the
//! single operation.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};

/// Deterministic keygen seeds (`d`, `z`) shared by every parameter set.
const D: [u8; 32] = [0x42u8; 32];
const Z: [u8; 32] = [0x24u8; 32];
/// Deterministic encapsulation randomness `m`.
const M: [u8; 32] = [0x13u8; 32];

/// Keygen bench for one ML-KEM parameter set.
macro_rules! ml_kem_keygen_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let mut group = c.benchmark_group("ML-KEM keygen");
            group.bench_function($label, |b| {
                b.iter(|| $variant::keygen(black_box(&D), black_box(&Z)).expect("keygen"));
            });
            group.finish();
        }
    };
}

/// Encapsulate bench: the encapsulation key is generated once outside
/// the timing loop; the measured cost is a single `encapsulate`.
macro_rules! ml_kem_encaps_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (ek, _dk) = $variant::keygen(&D, &Z).expect("keygen");

            let mut group = c.benchmark_group("ML-KEM encapsulate");
            group.bench_function($label, |b| {
                b.iter(|| $variant::encapsulate(black_box(&ek), black_box(&M)).expect("encaps"));
            });
            group.finish();
        }
    };
}

/// Decapsulate bench: the decapsulation key and a ciphertext are built
/// once outside the timing loop; the measured cost is a single
/// `decapsulate`.
macro_rules! ml_kem_decaps_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (ek, dk) = $variant::keygen(&D, &Z).expect("keygen");
            let (_ss, ct) = $variant::encapsulate(&ek, &M).expect("encaps");

            let mut group = c.benchmark_group("ML-KEM decapsulate");
            group.bench_function($label, |b| {
                b.iter(|| $variant::decapsulate(black_box(&dk), black_box(&ct)).expect("decaps"));
            });
            group.finish();
        }
    };
}

ml_kem_keygen_bench!(bench_ml_kem_keygen_512, ml_kem_512, "ML-KEM-512");
ml_kem_keygen_bench!(bench_ml_kem_keygen_768, ml_kem_768, "ML-KEM-768");
ml_kem_keygen_bench!(bench_ml_kem_keygen_1024, ml_kem_1024, "ML-KEM-1024");

ml_kem_encaps_bench!(bench_ml_kem_encaps_512, ml_kem_512, "ML-KEM-512");
ml_kem_encaps_bench!(bench_ml_kem_encaps_768, ml_kem_768, "ML-KEM-768");
ml_kem_encaps_bench!(bench_ml_kem_encaps_1024, ml_kem_1024, "ML-KEM-1024");

ml_kem_decaps_bench!(bench_ml_kem_decaps_512, ml_kem_512, "ML-KEM-512");
ml_kem_decaps_bench!(bench_ml_kem_decaps_768, ml_kem_768, "ML-KEM-768");
ml_kem_decaps_bench!(bench_ml_kem_decaps_1024, ml_kem_1024, "ML-KEM-1024");

criterion_group!(
    benches,
    bench_ml_kem_keygen_512,
    bench_ml_kem_keygen_768,
    bench_ml_kem_keygen_1024,
    bench_ml_kem_encaps_512,
    bench_ml_kem_encaps_768,
    bench_ml_kem_encaps_1024,
    bench_ml_kem_decaps_512,
    bench_ml_kem_decaps_768,
    bench_ml_kem_decaps_1024,
);
criterion_main!(benches);
