#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! LMS (SP 800-208) benchmarks — SHA-256/M=32 family only, bounded to
//! H ∈ {5, 10, 15} × W ∈ {4, 8} (the larger Winternitz values). H=20/25
//! are deliberately out of scope: keygen cost grows as 2^H.
//!
//! LMS is stateful: each signature consumes one Merkle leaf and `sign`
//! refuses once the tree is exhausted (2^H one-time keys). The H=5
//! pairs have only 32 leaves, so their sign benches generate a fresh
//! key per iteration via `iter_batched_ref` (setup excluded from
//! timing). The taller trees reuse one key, on the expectation that
//! criterion schedules fewer iterations than 2^H for these slow
//! operations, with a rekey fallback for when the tree does exhaust.
//!
//! A third group, `sign-cached`, measures `LmsSigningKey` — the
//! tree-cache wrapper whose constructor precomputes the Merkle node
//! table (built outside the timing loop), making per-signature cost
//! O(H) table reads + one OTS sign instead of an O(2^H) tree walk.

use std::time::Duration;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_lms::{
    lms_sha256_m32_h5_w4 as h5_w4, lms_sha256_m32_h5_w8 as h5_w8, lms_sha256_m32_h10_w4 as h10_w4,
    lms_sha256_m32_h10_w8 as h10_w8, lms_sha256_m32_h15_w4 as h15_w4,
    lms_sha256_m32_h15_w8 as h15_w8,
};

/// Deterministic keygen seed (`xi`) shared by every pair.
const XI: [u8; 32] = [0x42u8; 32];
const MSG: &[u8] = b"benchmark message for LMS (SP 800-208)";

/// Keygen bench for one (LMS, LM-OTS) pair. Keygen cost is dominated
/// by computing all 2^H OTS leaf public keys, so taller trees pass a
/// reduced `$samples` to keep the suite bounded.
macro_rules! lms_keygen_bench {
    ($fn_name:ident, $pair:ident, $label:literal, $samples:expr) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let mut group = c.benchmark_group("LMS-SHA256/M32 keygen");
            group.sample_size($samples);
            group.warm_up_time(Duration::from_secs(1));
            group.bench_function($label, |b| {
                b.iter(|| $pair::keygen(black_box(&XI)).expect("keygen"));
            });
            group.finish();
        }
    };
}

/// Sign bench with a fresh key per iteration (H=5 only: 32 leaves
/// would exhaust under criterion's iteration counts). Keygen runs in
/// `iter_batched_ref` setup, outside the timing loop.
macro_rules! lms_sign_bench_fresh_key {
    ($fn_name:ident, $pair:ident, $label:literal, $samples:expr) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let mut group = c.benchmark_group("LMS-SHA256/M32 sign");
            group.sample_size($samples);
            group.warm_up_time(Duration::from_secs(1));
            group.bench_function($label, |b| {
                b.iter_batched_ref(
                    || $pair::keygen(&XI).expect("keygen").0,
                    |sk| $pair::sign(sk, black_box(MSG)).expect("sign"),
                    BatchSize::PerIteration,
                );
            });
            group.finish();
        }
    };
}

/// Sign bench reusing one key across iterations (tall trees: plenty of
/// leaves, and per-iteration keygen would dominate wall-clock). If the
/// tree ever exhausts, rekey and keep going.
macro_rules! lms_sign_bench_shared_key {
    ($fn_name:ident, $pair:ident, $label:literal, $samples:expr) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let (mut sk, _pk) = $pair::keygen(&XI).expect("keygen");

            let mut group = c.benchmark_group("LMS-SHA256/M32 sign");
            group.sample_size($samples);
            group.warm_up_time(Duration::from_secs(1));
            group.bench_function($label, |b| {
                b.iter(|| match $pair::sign(&mut sk, black_box(MSG)) {
                    Ok(sig) => sig,
                    Err(_) => {
                        // Tree exhausted — rekey and sign with leaf 0.
                        sk = $pair::keygen(&XI).expect("keygen").0;
                        $pair::sign(&mut sk, black_box(MSG)).expect("sign")
                    }
                });
            });
            group.finish();
        }
    };
}

/// Cached-sign bench: `LmsSigningKey` precomputes the Merkle node
/// table once (outside the timing loop), so the measured cost is
/// OTS-sign + table reads — O(H) instead of the uncached O(2^H). One
/// shared cached key per pair with a rekey-on-exhaustion fallback,
/// mirroring `lms_sign_bench_shared_key`. Note for H=5 (32 leaves) the
/// rekey fires every 32 iterations, so its numbers amortize 1/32 of a
/// tree rebuild. Taller trees are not expected to exhaust; the rekey
/// branch covers it if they do.
macro_rules! lms_sign_cached_bench {
    ($fn_name:ident, $pair:ident, $label:literal, $samples:expr) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            // Tree built once here — excluded from the timing loop.
            let (mut csk, _pk) = $pair::LmsSigningKey::new(&XI).expect("cached keygen");

            let mut group = c.benchmark_group("LMS-SHA256/M32 sign-cached");
            group.sample_size($samples);
            group.warm_up_time(Duration::from_secs(1));
            group.bench_function($label, |b| {
                b.iter(|| match csk.sign(black_box(MSG)) {
                    Ok(sig) => sig,
                    Err(_) => {
                        // Tree exhausted — rekey and sign with leaf 0.
                        csk = $pair::LmsSigningKey::new(&XI).expect("cached keygen").0;
                        csk.sign(black_box(MSG)).expect("sign")
                    }
                });
            });
            group.finish();
        }
    };
}

lms_keygen_bench!(bench_lms_keygen_h5_w4, h5_w4, "H5/W4", 20);
lms_keygen_bench!(bench_lms_keygen_h5_w8, h5_w8, "H5/W8", 20);
lms_keygen_bench!(bench_lms_keygen_h10_w4, h10_w4, "H10/W4", 10);
lms_keygen_bench!(bench_lms_keygen_h10_w8, h10_w8, "H10/W8", 10);
lms_keygen_bench!(bench_lms_keygen_h15_w4, h15_w4, "H15/W4", 10);
lms_keygen_bench!(bench_lms_keygen_h15_w8, h15_w8, "H15/W8", 10);

lms_sign_bench_fresh_key!(bench_lms_sign_h5_w4, h5_w4, "H5/W4", 20);
lms_sign_bench_fresh_key!(bench_lms_sign_h5_w8, h5_w8, "H5/W8", 20);
lms_sign_bench_shared_key!(bench_lms_sign_h10_w4, h10_w4, "H10/W4", 10);
lms_sign_bench_shared_key!(bench_lms_sign_h10_w8, h10_w8, "H10/W8", 10);
lms_sign_bench_shared_key!(bench_lms_sign_h15_w4, h15_w4, "H15/W4", 10);
lms_sign_bench_shared_key!(bench_lms_sign_h15_w8, h15_w8, "H15/W8", 10);

lms_sign_cached_bench!(bench_lms_sign_cached_h5_w4, h5_w4, "H5/W4", 10);
lms_sign_cached_bench!(bench_lms_sign_cached_h5_w8, h5_w8, "H5/W8", 10);
lms_sign_cached_bench!(bench_lms_sign_cached_h10_w4, h10_w4, "H10/W4", 10);
lms_sign_cached_bench!(bench_lms_sign_cached_h10_w8, h10_w8, "H10/W8", 10);
lms_sign_cached_bench!(bench_lms_sign_cached_h15_w4, h15_w4, "H15/W4", 10);
lms_sign_cached_bench!(bench_lms_sign_cached_h15_w8, h15_w8, "H15/W8", 10);

criterion_group!(
    benches,
    bench_lms_keygen_h5_w4,
    bench_lms_keygen_h5_w8,
    bench_lms_keygen_h10_w4,
    bench_lms_keygen_h10_w8,
    bench_lms_keygen_h15_w4,
    bench_lms_keygen_h15_w8,
    bench_lms_sign_h5_w4,
    bench_lms_sign_h5_w8,
    bench_lms_sign_h10_w4,
    bench_lms_sign_h10_w8,
    bench_lms_sign_h15_w4,
    bench_lms_sign_h15_w8,
    bench_lms_sign_cached_h5_w4,
    bench_lms_sign_cached_h5_w8,
    bench_lms_sign_cached_h10_w4,
    bench_lms_sign_cached_h10_w8,
    bench_lms_sign_cached_h15_w4,
    bench_lms_sign_cached_h15_w8,
);
criterion_main!(benches);
