//! Conditioned-output throughput for the SP 800-90B entropy pipeline
//! (entropy-crate ISC-88).
//!
//! Measures [`EntropyPipeline::conditioned_block`] — the sole vetted output
//! path — end to end: noise-source sampling, the continuous health battery,
//! and SHA-256 conditioning of a 256-bit block.
//!
//! The number is dominated by the noise source, not the conditioner. At the
//! pilot operational environment's claim of H = 0.5 bits/sample the pipeline
//! draws `⌈(256 + 64)/H⌉ = 640` health-tested samples per block, each a timed
//! jitter measurement. So this benchmark is a **platform** measurement: it
//! characterises the reference machine's jitter-sampling rate as much as the
//! module's code, which is exactly why ISC-88 asks for it per reference
//! platform rather than as a portable constant.
//!
//! The source is the real `raw-counter` jitter source. It cannot be swapped
//! for a synthetic one: `NoiseSource` is a sealed trait and the mock sources
//! live behind `#[cfg(test)]` in the entropy crate, deliberately, so no
//! third-party source can enter the pipeline. A synthetic source would also
//! measure the wrong thing.
//!
//! Expect high variance relative to the algorithm benches in this crate.
//! Jitter timing is load-sensitive by construction — that is the property the
//! source harvests — so run it on an otherwise-idle machine and treat the
//! spread as signal about the platform, not noise in the harness.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use oxicrypt_entropy::conditioner::CONDITIONED_BLOCK_LEN;
use oxicrypt_entropy::h::MinEntropy;
use oxicrypt_entropy::health::Alpha;
use oxicrypt_entropy::jitter::{JitterConfig, JitterSource};
use oxicrypt_entropy::pipeline::EntropyPipeline;
use oxicrypt_entropy::timer::RawCounterTimer;

/// The pilot operational environment's ratified claim: H = 0.5 bits per
/// sample, expressed in the fixed-point type's 1/256-bit steps.
const PILOT_CLAIM_STEPS: u32 = 128;

fn bench_conditioned_block(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let claim = MinEntropy::from_steps(PILOT_CLAIM_STEPS);
    let source = JitterSource::new(RawCounterTimer::new(), JitterConfig::default())
        .expect("raw-counter jitter source must construct on the reference platform");
    let mut pipeline = EntropyPipeline::new(source, claim, Alpha::DEFAULT)
        .expect("pipeline construction at the pilot claim");
    pipeline
        .run_startup()
        .expect("SP 800-90B startup health battery");

    let mut group = c.benchmark_group("entropy conditioned output");
    // One 256-bit block per iteration; the throughput figure is therefore
    // bytes of *conditioned* output, not bytes of raw sample consumed.
    group.throughput(Throughput::Bytes(CONDITIONED_BLOCK_LEN as u64));
    // 640 health-tested jitter samples per block makes each iteration orders
    // of magnitude slower than an algorithm bench. Criterion's default 100
    // samples would run for a very long time for no extra resolution.
    group.sample_size(10);
    group.bench_function("conditioned_block (H=0.5, 640 samples/block)", |b| {
        b.iter(|| {
            black_box(
                pipeline
                    .conditioned_block()
                    .expect("conditioned block on a healthy pipeline"),
            )
        });
    });
    group.finish();
}

criterion_group!(benches, bench_conditioned_block);
criterion_main!(benches);
