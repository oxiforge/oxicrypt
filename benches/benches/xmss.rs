#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // The shared-key sign bench's `match sign { Ok => .., Err => rekey }`
    // is a deliberate rekey-on-exhaustion fallback (mirrors lms.rs, where
    // the identical pattern lives inside a macro so the lint never fires).
    // Here it is written directly, so silence the rewrite-to-if-let lint.
    clippy::single_match_else,
    missing_docs
)]

//! XMSS (SP 800-208 / RFC 8391) benchmarks — the single instantiated
//! parameter set (SHA2-256, tree height H=10 → 1024 one-time keys),
//! measuring keygen, sign, and verify.
//!
//! `keygen` takes a 32-byte seed (`xi`) and returns `(XmssPrivateKey,
//! public_key)`; it builds the full Merkle tree (all `2^H` leaf public
//! keys), so it is the dominant cost.
//!
//! XMSS is STATEFUL like LMS: each `sign` consumes one Merkle leaf,
//! advances `leaf_index`, and refuses once the tree is exhausted
//! (`MAX_SIGNATURES = NUM_LEAVES = 2^H`). The sign bench therefore
//! reuses one key across iterations (per-iteration keygen would
//! dominate wall-clock for an H=10 tree, and criterion schedules far
//! fewer iterations than 1024 for this slow operation) with a
//! rekey-on-exhaustion fallback — mirroring `lms.rs`'s shared-key sign
//! bench. The verify bench signs once outside the timing loop and
//! measures a single verification.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_xmss::{keygen, sign, verify};

/// Deterministic keygen seed (`xi`).
const XI: [u8; 32] = [0x42u8; 32];
const MSG: &[u8] = b"benchmark message for XMSS (SP 800-208)";

/// Keygen bench: builds the full Merkle tree each call. A reduced
/// sample size keeps the suite bounded.
fn bench_xmss_keygen(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("XMSS-SHA256 keygen");
    group.sample_size(10);
    group.bench_function("H10", |b| {
        b.iter(|| keygen(black_box(&XI)).expect("keygen"));
    });
    group.finish();
}

/// Sign bench reusing one key across iterations (H=10: 1024 leaves, and
/// per-iteration keygen would dominate). If the tree exhausts, rekey
/// and keep going.
fn bench_xmss_sign(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let (mut sk, _pk) = keygen(&XI).expect("keygen");

    let mut group = c.benchmark_group("XMSS-SHA256 sign");
    group.sample_size(10);
    group.bench_function("H10", |b| {
        b.iter(|| match sign(&mut sk, black_box(MSG)) {
            Ok(sig) => sig,
            Err(_) => {
                // Tree exhausted — rekey and sign with leaf 0.
                sk = keygen(&XI).expect("keygen").0;
                sign(&mut sk, black_box(MSG)).expect("sign")
            }
        });
    });
    group.finish();
}

/// Verify bench: signature produced once outside the timing loop.
fn bench_xmss_verify(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let (mut sk, pk) = keygen(&XI).expect("keygen");
    let sig = sign(&mut sk, MSG).expect("sign");

    let mut group = c.benchmark_group("XMSS-SHA256 verify");
    group.bench_function("H10", |b| {
        b.iter(|| verify(black_box(&pk), black_box(MSG), black_box(&sig)).expect("verify"));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_xmss_keygen,
    bench_xmss_sign,
    bench_xmss_verify
);
criterion_main!(benches);
