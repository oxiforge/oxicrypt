//! Binary entry point for the ct-validation harness.
//!
//! Usage:
//!
//! ```text
//! cargo run -p ct-validation --release --
//! cargo run -p ct-validation --release -- rsa_mont2048_pow_secret
//! cargo run -p ct-validation --release -- --samples 200000 rsa_oaep_decode
//! cargo run -p ct-validation --release -- --strict ghash
//! ```
//!
//! With no target argument, runs every target in order with the
//! default sample budget. The exit code is 0 when every target is
//! `CLEAN`, 1 when any is `LEAK`, and 2 on a usage error or a module
//! that did not start. A `WARN` exits 0, or under `--strict` is measured
//! once more, at 500 000 samples or `--samples` if larger and with a seed
//! derived from `--seed`, and a second `WARN` exits 1. Output is plain
//! text suitable for pasting into §12.1 of the Security Policy, which is withheld from this
//! tree (see `docs/security-policy/README.md`).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

use ct_validation::measure::{RunConfig, run_with_policy, strict_rerun_config};
use ct_validation::stats::{Verdict, VerdictReport};
use ct_validation::targets::{all_target_names, is_known_target, run_by_name};
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

/// Parses the arguments after the program name into the run
/// configuration, whether `--strict` was given, and the targets, every
/// target when none is named. `--help` prints the usage and exits 0.
///
/// # Errors
///
/// The message to print for a usage error: an unknown flag, a `--samples`,
/// `--warmup` or `--seed` value that does not parse as an unsigned
/// integer, or one of those flags given last with no value.
fn parse_args(
    args: impl IntoIterator<Item = String>,
) -> Result<(RunConfig, bool, Vec<String>), String> {
    fn value<T: std::str::FromStr>(
        flag: &str,
        it: &mut impl Iterator<Item = String>,
    ) -> Result<T, String> {
        let v = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        v.parse().map_err(|_| format!("bad {flag} value: {v}"))
    }

    let mut cfg = RunConfig::default();
    let mut strict = false;
    let mut targets: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--samples" => cfg.samples = value("--samples", &mut it)?,
            "--warmup" => cfg.warmup = value("--warmup", &mut it)?,
            "--seed" => cfg.seed = value("--seed", &mut it)?,
            "--strict" => strict = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => targets.push(other.to_string()),
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    if targets.is_empty() {
        targets = all_target_names()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    Ok((cfg, strict, targets))
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
         \x20   --strict       Fail on WARN: a target whose verdict is WARN is\n\
         \x20                  measured once more, at max(500000, --samples)\n\
         \x20                  samples and with the seed --seed + 0x9e3779b97f4a7c15\n\
         \x20                  so the re-run is an independent sample, and a\n\
         \x20                  second WARN exits 1 as LEAK does\n\
         \n\
         A value of --samples, --warmup or --seed that does not parse as an\n\
         unsigned integer, or one of those flags given last with no value,\n\
         is reported and exits 2.\n\
         \n\
         TARGETS:"
    );
    for t in all_target_names() {
        println!("    {t}");
    }
    #[cfg(feature = "fixture")]
    {
        println!("    cmac_verify_leaky  (control, must exit 1; not run by default)");
        println!("    aa                 (A/A control, identical classes; not run by default)");
    }
    println!(
        "\nWith no TARGET argument, all targets are run in order.\n\
         \n\
         EXIT CODES:\n\
         \x20   0    every target CLEAN, or WARN without --strict\n\
         \x20   1    a target LEAK, or WARN twice under --strict\n\
         \x20   2    usage error, unknown target, or module not started"
    );
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
    let (cfg, strict, targets) = parse_args(env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(2);
    });

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
        "ct-validation: samples={s}  warmup={w}  seed={seed:#x}  strict={strict}",
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
        if !is_known_target(name) {
            eprintln!("unknown target: {name}");
            std::process::exit(2);
        }
        let reports = run_with_policy(&cfg, strict, |c| {
            run_by_name(name, c).expect("target name checked above")
        });
        for (i, r) in reports.iter().enumerate() {
            if i > 0 {
                let rerun = strict_rerun_config(&cfg);
                println!(
                    "  re-run after WARN at --samples {s} --seed {seed:#x}:",
                    s = rerun.samples,
                    seed = rerun.seed,
                );
            }
            println!("{}", format_report(r));
        }
        let last = reports.last().expect("one report per target");
        worst = worst.worst(last.verdict);
    }
    println!();
    match worst {
        Verdict::Clean => println!("overall: CLEAN at the current sample budget"),
        Verdict::Warn if strict => {
            println!("overall: WARN twice under --strict — at least one target fails");
        }
        Verdict::Warn => {
            println!("overall: WARN — re-run with --samples >= 500000 before accepting");
        }
        Verdict::Leak => println!("overall: LEAK — at least one target is not constant-time"),
    }
    std::process::exit(worst.exit_code(strict));
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    fn parse(args: &[&str]) -> Result<(u64, u64, u64, bool, Vec<String>), String> {
        parse_args(args.iter().map(|a| (*a).to_string())).map(|(cfg, strict, targets)| {
            (
                cfg.samples as u64,
                cfg.warmup as u64,
                cfg.seed,
                strict,
                targets,
            )
        })
    }

    #[test]
    fn bad_warmup_is_refused() {
        assert_eq!(
            parse(&["--warmup", "ten"]),
            Err("bad --warmup value: ten".to_string())
        );
    }

    #[test]
    fn bad_seed_is_refused() {
        assert_eq!(
            parse(&["--seed", "-1"]),
            Err("bad --seed value: -1".to_string())
        );
    }

    #[test]
    fn trailing_samples_without_a_value_is_refused() {
        assert_eq!(
            parse(&["ghash", "--samples"]),
            Err("--samples needs a value".to_string())
        );
    }

    #[test]
    fn good_arguments_are_parsed() {
        assert_eq!(
            parse(&[
                "--samples",
                "2000",
                "--warmup",
                "10",
                "--seed",
                "7",
                "--strict",
                "ghash"
            ]),
            Ok((2000, 10, 7, true, vec!["ghash".to_string()]))
        );
    }
}
