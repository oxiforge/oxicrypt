#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! ML-KEM (FIPS 203) benchmarks — all three parameter sets
//! (ML-KEM-512, -768, -1024), measuring key generation, encapsulate, and
//! decapsulate.
//!
//! Key generation is measured through `expand_key`, which expands fixed
//! 32-byte seeds `d` and `z` and runs the pairwise consistency test;
//! `encapsulate` draws its 32-byte `m` from a module-seeded DRBG. The
//! encaps/decaps benches build a key pair (and, for decaps, a ciphertext)
//! once outside the timing loop, then measure the single operation.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_ml_kem::{ml_kem_512, ml_kem_768, ml_kem_1024};

const D: [u8; 32] = [0x42u8; 32];
const Z: [u8; 32] = [0x24u8; 32];

fn make_drbg() -> HmacDrbgSha256 {
    HmacDrbgSha256::instantiate_from_module(b"ml-kem-bench").expect("instantiate")
}

macro_rules! ml_kem_keygen_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let mut group = c.benchmark_group("ML-KEM expand_key");
            group.bench_function($label, |b| {
                b.iter(|| $variant::expand_key(black_box(&D), black_box(&Z)).expect("expand_key"));
            });
            group.finish();
        }
    };
}

macro_rules! ml_kem_encaps_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (ek, _dk) = $variant::expand_key(&D, &Z).expect("expand_key");
            let mut drbg = make_drbg();

            let mut group = c.benchmark_group("ML-KEM encapsulate");
            group.bench_function($label, |b| {
                b.iter(|| $variant::encapsulate(black_box(&ek), &mut drbg).expect("encaps"));
            });
            group.finish();
        }
    };
}

macro_rules! ml_kem_decaps_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (ek, dk) = $variant::expand_key(&D, &Z).expect("expand_key");
            let (_ss, ct) = $variant::encapsulate(&ek, &mut make_drbg()).expect("encaps");

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
