#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_ecdh::compute_shared_secret_p256;
use oxicrypt_ecdsa::EcdsaP256PrivateKey;

fn make_drbg() -> HmacDrbgSha256 {
    let mut drbg = HmacDrbgSha256::new();
    drbg.instantiate(&[0x42u8; 32], &[0x01u8; 16], b"ecdh-bench")
        .expect("instantiate");
    drbg
}

fn bench_ecdh_p256(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut drbg = make_drbg();
    // Use ECDSA keygen for a valid P-256 key pair.
    let alice = EcdsaP256PrivateKey::generate(&mut drbg).expect("keygen");
    let bob = EcdsaP256PrivateKey::generate(&mut drbg).expect("keygen");
    let bob_pk = bob.public_key();

    c.bench_function("ECDH P-256 shared secret", |b| {
        b.iter(|| {
            compute_shared_secret_p256(black_box(alice.private_scalar()), black_box(&bob_pk))
                .expect("ecdh");
        });
    });
}

criterion_group!(benches, bench_ecdh_p256);
criterion_main!(benches);
