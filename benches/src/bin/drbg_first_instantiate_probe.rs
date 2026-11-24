//! Measures the first `HmacDrbgSha256::instantiate_from_module` in a fresh
//! process, and the duration of the seed path's lock spin bound on the same
//! machine.
//!
//! The first instantiate in a process decides the seed path and, on the
//! assessed path, constructs and starts the entropy source, so only a fresh
//! process measures it. The `drbg_first_instantiate` bench runs this binary
//! once per sample. Output is one line on stdout:
//! `instantiate_ms=<f64> spin_ms=<f64> path=<assessed|operating-system> label=<label>`.
//! With `--spin-only` the module is not initialised and only `spin_ms=<f64>`
//! is printed. The exit status is 1, with the error on stderr, when the
//! instantiate or the path report fails.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::hint::black_box;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use oxicrypt_drbg::HmacDrbgSha256;

/// The seed path's lock spin bound: 2^24 iterations of `spin_loop`.
const SPIN_ITERATIONS: u32 = 1 << 24;

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn spin_bound_duration() -> Duration {
    let start = Instant::now();
    let mut counter: u32 = 0;
    while black_box(counter) < SPIN_ITERATIONS {
        core::hint::spin_loop();
        counter = black_box(counter.wrapping_add(1));
    }
    start.elapsed()
}

fn main() -> ExitCode {
    if std::env::args().skip(1).any(|a| a == "--spin-only") {
        println!("spin_ms={}", millis(spin_bound_duration()));
        return ExitCode::SUCCESS;
    }

    oxicrypt_bench::init_module();

    let start = Instant::now();
    let drbg = HmacDrbgSha256::instantiate_from_module(b"probe");
    let instantiate = start.elapsed();
    if let Err(e) = drbg {
        eprintln!("instantiate_from_module failed: {e:?}");
        return ExitCode::FAILURE;
    }

    let spin = spin_bound_duration();

    let report = match oxicrypt_drbg::entropy_on_demand_test() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("entropy_on_demand_test failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "instantiate_ms={} spin_ms={} path={} label={}",
        millis(instantiate),
        millis(spin),
        report.path,
        report.label
    );
    ExitCode::SUCCESS
}
