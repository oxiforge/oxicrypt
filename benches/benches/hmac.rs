#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxicrypt_hmac::HmacSha256;

fn bench_hmac_sha256(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let key = [0x42u8; 32];
    let mut group = c.benchmark_group("HMAC-SHA-256");
    for size in [64, 256, 1024, 4096] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                let mut mac = HmacSha256::new(black_box(&key)).expect("operational");
                mac.update(black_box(d));
                mac.finalize()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hmac_sha256);
criterion_main!(benches);
