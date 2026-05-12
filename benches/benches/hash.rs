#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench_sha256_oneshot(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("SHA-256 one-shot");
    for size in [64, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| oxicrypt_sha::sha256(black_box(d)).expect("operational"));
        });
    }
    group.finish();
}

fn bench_sha512_oneshot(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("SHA-512 one-shot");
    for size in [64, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| oxicrypt_sha::sha512(black_box(d)).expect("operational"));
        });
    }
    group.finish();
}

fn bench_sha256_streaming(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("SHA-256 streaming");
    let chunk = vec![0xCDu8; 4096];
    let chunks: usize = 256; // 256 × 4096 = 1 MiB
    group.throughput(Throughput::Bytes((chunks * 4096) as u64));
    group.bench_function("1MiB/4KiB-chunks", |b| {
        b.iter(|| {
            let mut h = oxicrypt_sha::Sha256::new().expect("operational");
            for _ in 0..chunks {
                h.update(black_box(&chunk));
            }
            h.finalize()
        });
    });
    group.finish();
}

fn bench_sha3_256_oneshot(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("SHA3-256 one-shot");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| oxicrypt_sha::sha3_256(black_box(d)).expect("operational"));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_oneshot,
    bench_sha512_oneshot,
    bench_sha256_streaming,
    bench_sha3_256_oneshot,
);
criterion_main!(benches);
