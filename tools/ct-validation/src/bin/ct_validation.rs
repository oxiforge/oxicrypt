//! Binary entry point for the ct-validation harness.
//!
//! Usage:
//!
//! ```text
//! cargo run -p ct-validation --release --
//! cargo run -p ct-validation --release -- rsa_mont2048_pow_secret
//! cargo run -p ct-validation --release -- --samples 200000 rsa_oaep_decode
//! ```
//!
//! With no target argument, runs every target in order with the
//! default sample budget. Output is plain text suitable for pasting
//! into §12.1 of the Security Policy, which is withheld from this
//! tree (see `docs/security-policy/README.md`).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

use ct_validation::measure::RunConfig;
use ct_validation::stats::{Verdict, VerdictReport};
use ct_validation::targets::{all_target_names, run_by_name};
use oxicrypt_module::KatEntry;
use std::env;

/// Stands in for the pre-operational integrity test. This harness is a
/// development binary that is never signed, so the real integrity test
/// cannot pass inside it; the stub is declared here, visibly, rather
/// than the module offering any way to skip the requirement.
const UNSIGNED_HARNESS_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned development binary",
    run: || Ok(()),
}];

fn parse_args() -> (RunConfig, Vec<String>) {
    let mut cfg = RunConfig::default();
    let mut targets: Vec<String> = Vec::new();
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--samples" => {
                if let Some(v) = it.next() {
                    cfg.samples = v.parse().unwrap_or_else(|_| {
                        eprintln!("bad --samples value: {v}");
                        std::process::exit(2);
                    });
                }
            }
            "--warmup" => {
                if let Some(v) = it.next() {
                    cfg.warmup = v.parse().unwrap_or(cfg.warmup);
                }
            }
            "--seed" => {
                if let Some(v) = it.next() {
                    cfg.seed = v.parse().unwrap_or(cfg.seed);
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => targets.push(other.to_string()),
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(2);
            }
        }
    }
    if targets.is_empty() {
        targets = all_target_names()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    (cfg, targets)
}

fn print_help() {
    println!(
        "ct-validation — dudect-style constant-time harness for oxicrypt\n\
         \n\
         USAGE:\n\
         \x20   ct-validation [OPTIONS] [TARGET ...]\n\
         \n\
         OPTIONS:\n\
         \x20   --samples N    Measurements per target (default 100000)\n\
         \x20   --warmup N     Untimed warm-up iterations (default 1000)\n\
         \x20   --seed N       PRNG seed for class selection\n\
         \n\
         TARGETS:"
    );
    for t in all_target_names() {
        println!("    {t}");
    }
    println!("\nWith no TARGET argument, all targets are run in order.");
}

fn format_report(r: &VerdictReport) -> String {
    let tag = match r.verdict {
        Verdict::Clean => "CLEAN",
        Verdict::Warn => "WARN ",
        Verdict::Leak => "LEAK ",
    };
    format!(
        "[{tag}] {target:<28} n={n:>7}  worst |t|={t:7.3}  crop={crop:>5.3}",
        tag = tag,
        target = r.target,
        n = r.n_per_class,
        t = r.worst_abs_t,
        crop = r.worst_crop,
    )
}

fn main() {
    let (cfg, targets) = parse_args();

    // Several targets measure `*_internal` functions, which refuse until
    // the module's self-tests have started. Measuring a refusal would
    // time the guard rather than the primitive, so the run stops unless
    // the module is in `SelfTest` or `Operational`.
    let _ = oxicrypt_module::initialize_with_tests(UNSIGNED_HARNESS_BINARY, &[]);
    if let Err(e) = oxicrypt_module::require_self_test_started() {
        eprintln!("ct-validation: module not started: {e}");
        std::process::exit(2);
    }
    println!(
        "ct-validation: samples={s}  warmup={w}  seed={seed:#x}",
        s = cfg.samples,
        w = cfg.warmup,
        seed = cfg.seed,
    );
    println!(
        "platform: {arch} / {os}",
        arch = std::env::consts::ARCH,
        os = std::env::consts::OS,
    );
    println!();

    let mut worst = Verdict::Clean;
    for name in &targets {
        match run_by_name(name, &cfg) {
            Some(r) => {
                println!("{}", format_report(&r));
                worst = worst.worst(r.verdict);
            }
            None => {
                eprintln!("unknown target: {name}");
                std::process::exit(2);
            }
        }
    }
    println!();
    match worst {
        Verdict::Clean => {
            println!("overall: CLEAN at the current sample budget");
            std::process::exit(0);
        }
        Verdict::Warn => {
            println!("overall: WARN — re-run with --samples >= 500000 before accepting");
            std::process::exit(0);
        }
        Verdict::Leak => {
            println!("overall: LEAK — at least one target is not constant-time");
            std::process::exit(1);
        }
    }
}
