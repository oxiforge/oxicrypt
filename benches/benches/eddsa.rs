#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_eddsa::Ed25519PrivateKey;

fn make_drbg() -> HmacDrbgSha256 {
    let mut drbg = HmacDrbgSha256::new();
    drbg.instantiate(
        &[0x42u8; 32],
        &[0x01u8; 16],
        b"eddsa-bench",
    )
    .expect("instantiate");
    drbg
}

fn bench_ed25519_sign(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();
    let sk = Ed25519PrivateKey::generate(&mut drbg).expect("keygen");
    let msg = b"benchmark message for Ed25519 signing";

    c.bench_function("Ed25519 sign", |b| {
        b.iter(|| {
            sk.sign(black_box(msg)).expect("sign");
        });
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();
    let sk = Ed25519PrivateKey::generate(&mut drbg).expect("keygen");
    let pk = sk.public_key();
    let msg = b"benchmark message for Ed25519 signing";
    let sig = sk.sign(msg).expect("sign");

    c.bench_function("Ed25519 verify", |b| {
        b.iter(|| {
            oxicrypt_eddsa::verify(black_box(&pk), black_box(msg), black_box(&sig))
                .expect("operational");
        });
    });
}

criterion_group!(benches, bench_ed25519_sign, bench_ed25519_verify);
criterion_main!(benches);
