#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_ecdsa::{verify, EcdsaP256PrivateKey};

fn make_drbg() -> HmacDrbgSha256 {
    let mut drbg = HmacDrbgSha256::new();
    drbg.instantiate(
        &[0x42u8; 32],
        &[0x01u8; 16],
        b"ecdsa-bench",
    )
    .expect("instantiate");
    drbg
}

fn bench_ecdsa_p256_sign(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();
    let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("keygen");
    let msg = b"benchmark message for ECDSA P-256";

    c.bench_function("ECDSA-P256 sign", |b| {
        b.iter(|| {
            sk.sign_sha256(&mut drbg, black_box(msg))
                .expect("sign");
        });
    });
}

fn bench_ecdsa_p256_verify(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();
    let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("keygen");
    let pk = sk.public_key();
    let msg = b"benchmark message for ECDSA P-256";
    let sig = sk.sign_sha256(&mut drbg, msg).expect("sign");

    c.bench_function("ECDSA-P256 verify", |b| {
        b.iter(|| {
            verify(black_box(&pk), black_box(msg), black_box(&sig))
                .expect("operational");
        });
    });
}

fn bench_ecdsa_p256_keygen(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();

    c.bench_function("ECDSA-P256 keygen", |b| {
        b.iter(|| {
            EcdsaP256PrivateKey::generate(black_box(&mut drbg))
                .expect("keygen");
        });
    });
}

criterion_group!(
    benches,
    bench_ecdsa_p256_sign,
    bench_ecdsa_p256_verify,
    bench_ecdsa_p256_keygen,
);
criterion_main!(benches);
