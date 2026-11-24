#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use oxicrypt_drbg::HmacDrbgSha256;

fn bench_hmac_drbg_generate(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("HMAC_DRBG-SHA-256 generate");
    for size in [32, 64, 256, 1024] {
        let mut out = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            let mut drbg = HmacDrbgSha256::instantiate_from_module(b"bench").expect("instantiate");
            b.iter(|| {
                drbg.generate(black_box(None), black_box(&mut out))
                    .expect("generate");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hmac_drbg_generate);
criterion_main!(benches);
