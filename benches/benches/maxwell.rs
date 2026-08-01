//! `maxwell` 1 M-sample processing time (entropy-crate ISC-89).
//!
//! Measures the SP 800-90B assessment the off-boundary `maxwell` tool runs
//! over a collected dataset: [`oxicrypt_maxwell::iid_gate::iid_gate`], which
//! routes IID vs non-IID and, on the non-IID branch, runs the full §6.3
//! estimator suite. One megabyte of samples is the ESV data-file size
//! (1 000 000 one-byte-per-sample symbols), so this is the per-boundary cost
//! of assessing one real capture.
//!
//! Both branches are measured, because they cost very different amounts and a
//! single figure would misrepresent whichever dataset the operator has. The
//! IID branch pays the §5 permutation battery; the non-IID branch pays the ten
//! §6.3 estimators. Which one a capture takes is decided by the data, not the
//! caller.
//!
//! Inputs are synthesised deterministically rather than read from disk: the
//! EA reference datasets are not present in every environment (see
//! `parity::tests::ea_dataset_suite_is_provisioned`), and a benchmark that
//! silently measured nothing when they were absent would be the same defect
//! this crate has been closing elsewhere. The synthetic inputs are shaped to
//! land on the intended branch, and the bench asserts that they did — a
//! routing change that quietly moved both cases onto one branch would
//! otherwise leave two identical numbers looking like a result.
//!
//! # Sizes, and why they differ per branch
//!
//! The two branches are ~270× apart in cost. Measured on the reference
//! platform at 8-bit symbols: the IID branch takes ~9 s per megabyte, the
//! non-IID branch 2417.75 s ≈ 40.3 min. Criterion's floor is 10 samples, so a
//! 1 M-sample non-IID group would run for roughly **6.5 hours** — it was tried,
//! and criterion's own estimate was 23 339 s.
//!
//! Two caveats travel with those numbers, both recorded in
//! `docs/entropy-performance.md`: the IID figure is a **best case**, because
//! `permutation_test` exits early once all 19 statistics are decided and clean
//! PRNG input decides them within tens of shuffles; and 8-bit symbols are
//! **wider than this module emits** — the jitter source produces the low 4 bits
//! of each delta — so these are not yet per-boundary costs.
//!
//! So the default run measures the IID branch at the full 1 M ESV size and the
//! non-IID branch at 100 k, which is a useful regression signal at a sane
//! runtime. Set `OXICRYPT_BENCH_MAXWELL_FULL=1` to raise the non-IID case to
//! 1 M and accept the hours. The documented 1 M non-IID figure in
//! `docs/entropy-performance.md` comes from a single timed run of the
//! `maxwell iid-gate` CLI on a 1 M-sample capture — the measurement an
//! operator actually performs — and is labelled there as wall-clock, not as a
//! criterion statistic.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // The `as u8` casts on generated samples are the intended narrowing: these
    // are 8-bit symbols, and taking the low byte of a 64-bit PRNG word is how
    // they are drawn. Truncation is the operation, not a hazard.
    clippy::cast_possible_truncation,
    missing_docs
)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use oxicrypt_maxwell::iid_gate::{Branch, iid_gate};

/// The ESV data-file sample count — one byte per sample.
const SAMPLES: usize = 1_000_000;

/// Non-IID default. The §6.3 suite at 1 M would need ~6.5 h for criterion's
/// 10-sample floor; see the module docs.
const NONIID_DEFAULT_SAMPLES: usize = 100_000;

/// Sample count for the non-IID group — 1 M under `OXICRYPT_BENCH_MAXWELL_FULL=1`.
fn noniid_samples() -> usize {
    if std::env::var("OXICRYPT_BENCH_MAXWELL_FULL").is_ok_and(|v| v == "1") {
        SAMPLES
    } else {
        NONIID_DEFAULT_SAMPLES
    }
}

/// SplitMix64, so the inputs are reproducible without a dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Near-uniform 8-bit samples — routes IID.
fn uniform_samples() -> Vec<u8> {
    let mut rng = SplitMix64(0x0090_0B00_0090_0B00);
    (0..SAMPLES).map(|_| (rng.next() >> 33) as u8).collect()
}

/// A first-order Markov chain with a strong stay-probability — routes non-IID.
fn dependent_samples(n: usize) -> Vec<u8> {
    let mut rng = SplitMix64(0x00D3_9E7D_00D3_9E7D);
    let mut cur = 0u8;
    (0..n)
        .map(|_| {
            if rng.next() % 100 < 5 {
                cur = (rng.next() >> 33) as u8;
            }
            cur
        })
        .collect()
}

fn bench_maxwell_1m(c: &mut Criterion) {
    oxicrypt_bench::init_module();

    let n_noniid = noniid_samples();
    let uniform = uniform_samples();
    let dependent = dependent_samples(n_noniid);

    // Branch assertions BEFORE measuring. Two numbers from the same branch
    // would look like a result and mean nothing. Note these are themselves two
    // full assessments — at the default sizes that is ~9 s plus ~4 min before
    // criterion begins.
    assert_eq!(
        iid_gate(&uniform, 8).branch,
        Branch::Iid,
        "uniform input must route IID for this benchmark to measure the IID branch"
    );
    assert_eq!(
        iid_gate(&dependent, 8).branch,
        Branch::NonIid,
        "dependent input ({n_noniid} samples) must route non-IID for this benchmark to \
         measure the §6.3 suite"
    );

    // Criterion's floor is 10 samples; a 1 M-sample assessment runs for seconds
    // (IID) to tens of minutes (non-IID), so the default 100 would be absurd.
    let mut group = c.benchmark_group("maxwell assessment");
    group.sample_size(10);

    group.throughput(Throughput::Bytes(SAMPLES as u64));
    group.bench_function("iid_gate 8-bit 1M, IID branch (§5 battery)", |b| {
        b.iter(|| black_box(iid_gate(black_box(&uniform), 8)));
    });

    group.throughput(Throughput::Bytes(n_noniid as u64));
    group.bench_function(
        format!("iid_gate 8-bit {n_noniid}, non-IID branch (§6.3 suite)"),
        |b| {
            b.iter(|| black_box(iid_gate(black_box(&dependent), 8)));
        },
    );

    group.finish();
}

criterion_group!(benches, bench_maxwell_1m);
criterion_main!(benches);
