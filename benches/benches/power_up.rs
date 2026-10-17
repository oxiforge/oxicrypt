#![allow(clippy::expect_used, missing_docs)]

//! Power-up self-test benchmarks.
//!
//! Every binary that links oxicrypt runs the known-answer tests of each
//! approved algorithm crate it links before it becomes operational. This
//! times that work.
//!
//! Two groups:
//!
//! - `power-up per crate` — each algorithm crate's whole `KATS` slice, run
//!   in order as the module runs it, so a slow self-test is visible by
//!   crate.
//! - `power-up total` — the algorithm KATs each entry point runs at start-up:
//!   `oxi_init` in the C library, the ACVP harness and the `oxi`
//!   command-line tool.
//!
//! Each entry point's set is read from the file that entry point builds it
//! from, compiled here as a module, so the benchmark times the set the entry
//! point runs. The per-crate group walks the ACVP harness's set, which links
//! every approved algorithm crate.
//!
//! The pre-operational integrity test is not included: it verifies a signed
//! artifact, and a benchmark binary is not one. The module's state machine
//! is not included either; it latches after the first initialisation, and
//! its cost is a few atomic operations next to the KATs.

use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_module::KatEntry;

#[path = "../../crates/oxicrypt-ffi/src/power_up.rs"]
mod ffi;
#[path = "../../acvp-harness/src/power_up.rs"]
mod harness;
#[path = "../../oxi/src/power_up.rs"]
mod oxi;

fn run_all(kats: &[KatEntry]) {
    for kat in kats {
        black_box((kat.run)()).expect("KAT passes");
    }
}

fn bench_per_crate(c: &mut Criterion) {
    // The KATs call `*_internal` functions, which refuse until the
    // module's self-tests have started.
    oxicrypt_bench::init_module();
    let mut group = c.benchmark_group("power-up per crate");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    for (krate, kats) in harness::ALGORITHM_SELF_TESTS {
        // The benchmark ID is the crate's short name (`sha`, `tls-kdf`), so
        // saved criterion baselines keep matching.
        let name = krate.trim_start_matches("oxicrypt_").replace('_', "-");
        run_all(kats);
        group.bench_function(name.as_str(), |b| b.iter(|| run_all(kats)));
    }
    group.finish();
}

fn bench_total(c: &mut Criterion) {
    // The KATs call `*_internal` functions, which refuse until the
    // module's self-tests have started.
    oxicrypt_bench::init_module();
    let mut group = c.benchmark_group("power-up total");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    let entry_points: [(&str, Vec<KatEntry>); 3] = [
        ("oxi_init (C library)", ffi::algorithm_self_tests()),
        ("acvp-harness", harness::POWER_UP_KATS.to_vec()),
        ("oxi CLI", oxi::power_up_tests()),
    ];
    for (entry, kats) in &entry_points {
        run_all(kats);
        group.bench_function(*entry, |b| b.iter(|| run_all(kats)));
    }
    group.finish();
}

criterion_group!(benches, bench_per_crate, bench_total);
criterion_main!(benches);
