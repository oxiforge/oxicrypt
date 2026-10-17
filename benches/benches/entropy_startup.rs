//! Start-up health-test time for the SP 800-90B entropy pipeline.
//!
//! Two measurements, each on a freshly constructed source and pipeline per
//! iteration, because start-up runs once per pipeline and a second call is
//! refused:
//!
//! - `run_startup` — [`EntropyPipeline::run_startup`] alone: the
//!   conditioning known-answer test, then the continuous health tests over
//!   `STARTUP_MIN_SAMPLES` (1024) consecutive samples, which are discarded.
//!   Construction is outside the timed region.
//! - `construct + run_startup` — the same, preceded by
//!   [`JitterSource::new`] and [`EntropyPipeline::new`]. Source construction
//!   measures the timer's adequacy before it admits the source, so this is
//!   the time from nothing to an operational pipeline.
//!
//! The source is the real `raw-counter` jitter source, for the reason the
//! `conditioned_output` benchmark gives: `NoiseSource` is sealed and the
//! mock sources are test-only, so it is the only source a benchmark can
//! construct. Each start-up sample is a timed jitter measurement, so the
//! figure characterises the platform it runs on, not the module alone.

#![allow(clippy::expect_used, missing_docs)]

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_entropy::h::MinEntropy;
use oxicrypt_entropy::health::Alpha;
use oxicrypt_entropy::jitter::{JitterConfig, JitterSource};
use oxicrypt_entropy::pipeline::EntropyPipeline;
use oxicrypt_entropy::timer::RawCounterTimer;

/// The pilot operational environment's ratified claim: H = 0.5 bits per
/// sample, expressed in the fixed-point type's 1/256-bit steps.
const PILOT_CLAIM_STEPS: u32 = 128;

type Pipeline = EntropyPipeline<JitterSource<'static, RawCounterTimer>>;

fn fresh_pipeline() -> Pipeline {
    let source = JitterSource::new(RawCounterTimer::new(), JitterConfig::default())
        .expect("raw-counter jitter source must construct on the reference platform");
    EntropyPipeline::new(
        source,
        MinEntropy::from_steps(PILOT_CLAIM_STEPS),
        Alpha::DEFAULT,
    )
    .expect("pipeline construction at the pilot claim")
}

fn bench_startup(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let mut group = c.benchmark_group("entropy startup");
    group.sample_size(10);
    group.bench_function("run_startup (H=0.5, 1024 samples)", |b| {
        b.iter_batched(
            fresh_pipeline,
            |mut pipeline| {
                pipeline
                    .run_startup()
                    .expect("SP 800-90B startup health battery");
                black_box(pipeline)
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function("construct + run_startup (H=0.5)", |b| {
        b.iter(|| {
            let mut pipeline = fresh_pipeline();
            pipeline
                .run_startup()
                .expect("SP 800-90B startup health battery");
            black_box(pipeline)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_startup);
criterion_main!(benches);
