#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! SLH-DSA (FIPS 205) benchmarks — the SHA2 family ONLY
//! (SHA2-128f/128s/192f/192s/256f/256s), measuring keygen, sign, and
//! verify. The SHAKE family is deliberately OUT of scope to bound suite
//! runtime — add it later if a SHAKE measurement is actually needed.
//!
//! `keygen` takes a `3*N`-byte seed (`SK.seed || SK.prf || PK.seed`,
//! FIPS 205 §9.2); `N` is the per-variant hash-output length (16/24/32),
//! so the seed array length is computed from each module's `N` const.
//! The external `sign`/`verify` take a context string `ctx` (empty
//! here). All seeds are deterministic (`0x42`) for reproducibility.
//!
//! Runtime guard for the `s` ("small/slow") variants: SLH-DSA `s`-variant
//! SIGNING is enormously expensive (seconds per signature), so those
//! sign benches live in their own group `SLH-DSA sign (slow)` with
//! `sample_size(10)` (criterion's minimum) and a 100 ms warm-up. They
//! are intended to be compiled (`cargo bench --no-run`) and single-shot
//! smoke-tested (`cargo bench -- --test`), never full-sampled. The
//! `s`-variant keygen and verify are fast and are benched normally.

use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_slh_dsa::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f,
    slh_dsa_sha2_256s,
};

const SEED_BYTE: u8 = 0x42;
const MSG: &[u8] = b"benchmark message for SLH-DSA (FIPS 205)";
/// Empty context string (FIPS 205 §9.2 external API).
const CTX: &[u8] = b"";

/// Keygen bench for one SLH-DSA-SHA2 parameter set. The `3*N`-byte seed
/// is built from the module's own `N` const.
macro_rules! slh_keygen_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let seed = [SEED_BYTE; 3 * $variant::N];

            let mut group = c.benchmark_group("SLH-DSA keygen");
            group.bench_function($label, |b| {
                b.iter(|| $variant::keygen(black_box(&seed)).expect("keygen"));
            });
            group.finish();
        }
    };
}

/// Sign bench for the FAST (`f`) variants: secret key generated once
/// outside the timing loop (SLH-DSA is stateless).
macro_rules! slh_sign_bench_fast {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let seed = [SEED_BYTE; 3 * $variant::N];
            let (_pk, sk) = $variant::keygen(&seed).expect("keygen");

            let mut group = c.benchmark_group("SLH-DSA sign");
            group.bench_function($label, |b| {
                b.iter(|| $variant::sign(black_box(&sk), black_box(MSG), CTX).expect("sign"));
            });
            group.finish();
        }
    };
}

/// Sign bench for the SLOW (`s`) variants: same shape as the fast one
/// but in a separate `slow` group with the minimum sample size and a
/// short warm-up, so it is only ever compile- and smoke-tested.
macro_rules! slh_sign_bench_slow {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let seed = [SEED_BYTE; 3 * $variant::N];
            let (_pk, sk) = $variant::keygen(&seed).expect("keygen");

            let mut group = c.benchmark_group("SLH-DSA sign (slow)");
            group.sample_size(10);
            group.warm_up_time(Duration::from_millis(100));
            group.bench_function($label, |b| {
                b.iter(|| $variant::sign(black_box(&sk), black_box(MSG), CTX).expect("sign"));
            });
            group.finish();
        }
    };
}

/// Verify bench: signature produced once outside the timing loop. Fast
/// for every variant (including `s`).
macro_rules! slh_verify_bench {
    ($fn_name:ident, $variant:ident, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let seed = [SEED_BYTE; 3 * $variant::N];
            let (pk, sk) = $variant::keygen(&seed).expect("keygen");
            let sig = $variant::sign(&sk, MSG, CTX).expect("sign");

            let mut group = c.benchmark_group("SLH-DSA verify");
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

slh_keygen_bench!(bench_slh_keygen_128f, slh_dsa_sha2_128f, "SHA2-128f");
slh_keygen_bench!(bench_slh_keygen_128s, slh_dsa_sha2_128s, "SHA2-128s");
slh_keygen_bench!(bench_slh_keygen_192f, slh_dsa_sha2_192f, "SHA2-192f");
slh_keygen_bench!(bench_slh_keygen_192s, slh_dsa_sha2_192s, "SHA2-192s");
slh_keygen_bench!(bench_slh_keygen_256f, slh_dsa_sha2_256f, "SHA2-256f");
slh_keygen_bench!(bench_slh_keygen_256s, slh_dsa_sha2_256s, "SHA2-256s");

slh_sign_bench_fast!(bench_slh_sign_128f, slh_dsa_sha2_128f, "SHA2-128f");
slh_sign_bench_fast!(bench_slh_sign_192f, slh_dsa_sha2_192f, "SHA2-192f");
slh_sign_bench_fast!(bench_slh_sign_256f, slh_dsa_sha2_256f, "SHA2-256f");

slh_sign_bench_slow!(bench_slh_sign_128s, slh_dsa_sha2_128s, "SHA2-128s");
slh_sign_bench_slow!(bench_slh_sign_192s, slh_dsa_sha2_192s, "SHA2-192s");
slh_sign_bench_slow!(bench_slh_sign_256s, slh_dsa_sha2_256s, "SHA2-256s");

slh_verify_bench!(bench_slh_verify_128f, slh_dsa_sha2_128f, "SHA2-128f");
slh_verify_bench!(bench_slh_verify_128s, slh_dsa_sha2_128s, "SHA2-128s");
slh_verify_bench!(bench_slh_verify_192f, slh_dsa_sha2_192f, "SHA2-192f");
slh_verify_bench!(bench_slh_verify_192s, slh_dsa_sha2_192s, "SHA2-192s");
slh_verify_bench!(bench_slh_verify_256f, slh_dsa_sha2_256f, "SHA2-256f");
slh_verify_bench!(bench_slh_verify_256s, slh_dsa_sha2_256s, "SHA2-256s");

criterion_group!(
    benches,
    bench_slh_keygen_128f,
    bench_slh_keygen_128s,
    bench_slh_keygen_192f,
    bench_slh_keygen_192s,
    bench_slh_keygen_256f,
    bench_slh_keygen_256s,
    bench_slh_sign_128f,
    bench_slh_sign_192f,
    bench_slh_sign_256f,
    bench_slh_sign_128s,
    bench_slh_sign_192s,
    bench_slh_sign_256s,
    bench_slh_verify_128f,
    bench_slh_verify_128s,
    bench_slh_verify_192f,
    bench_slh_verify_192s,
    bench_slh_verify_256f,
    bench_slh_verify_256s,
);
criterion_main!(benches);
