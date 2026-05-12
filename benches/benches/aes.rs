#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use oxicrypt_aes::{Aes256Key, gcm_encrypt};

fn bench_aes256_gcm_encrypt(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let raw_key = [0x42u8; 32];
    let key = Aes256Key::new(&raw_key).expect("valid key");
    let iv = [0u8; 12];
    let aad = b"";

    let mut group = c.benchmark_group("AES-256-GCM encrypt");
    for size in [64, 256, 1024, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        let mut ciphertext = vec![0u8; size];
        let mut tag = [0u8; 16];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                gcm_encrypt(
                    black_box(&key),
                    black_box(&iv),
                    black_box(aad),
                    black_box(pt),
                    &mut ciphertext,
                    &mut tag,
                )
                .expect("gcm_encrypt");
            });
        });
    }
    group.finish();
}

fn bench_aes256_ecb_block(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let raw_key = [0x42u8; 32];
    let key = Aes256Key::new(&raw_key).expect("valid key");
    let plaintext = [0xABu8; 16];
    let mut ciphertext = [0u8; 16];

    c.bench_function("AES-256-ECB single block", |b| {
        b.iter(|| {
            oxicrypt_aes::ecb_encrypt(black_box(&key), black_box(&plaintext), &mut ciphertext)
                .expect("ecb_encrypt");
        });
    });
}

criterion_group!(benches, bench_aes256_gcm_encrypt, bench_aes256_ecb_block);
criterion_main!(benches);
