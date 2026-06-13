//! `maxwell` — command-line driver for the SP 800-90B MCV min-entropy
//! estimator and its NIST EA-tool parity harness.
//!
//! This binary is **out of the cryptographic boundary** — pure offline
//! analysis tooling. See the `oxicrypt-maxwell` crate docs for the algorithm,
//! the `Z` constant, and the parity contract.
//!
//! # Subcommands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `maxwell mcv <FILE> <BITS_PER_SYMBOL>` | MCV estimates (both tracks) for one file |
//! | `maxwell collision <FILE> <BITS_PER_SYMBOL>` | §6.3.2 Collision estimate (bitstring) for one file |
//! | `maxwell parity [--datasets <DIR>]` | Run the full EA-tool parity table (MCV + Collision) |
//! | `maxwell apt-table <ALPHA_EXP>` | SP 800-90B §4.4.2 APT cutoff grids at α = 2⁻ᵃ |
//!
//! `parity` resolves its dataset directory from `--datasets`, else the
//! `OXICRYPT_EA_DATA` environment variable, else
//! `~/repos/SP800-90B_EntropyAssessment/bin`. It exits non-zero if any present
//! dataset fails (absent datasets are skipped, not failures).
#![forbid(unsafe_code)]
#![allow(
    // A CLI binary must write to stdout/stderr; the workspace denies these
    // globally for in-boundary crypto code, but this is out-of-boundary tooling.
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxicrypt_maxwell::apt::{AptRow, binary_grid, non_binary_grid};
use oxicrypt_maxwell::collision::collision;
use oxicrypt_maxwell::parity::{Verdict, resolve_datasets_dir, run_parity};
use oxicrypt_maxwell::{McvEstimate, mcv};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mcv") => cmd_mcv(args.get(2..).unwrap_or(&[])),
        Some("collision") => cmd_collision(args.get(2..).unwrap_or(&[])),
        Some("parity") => cmd_parity(args.get(2..).unwrap_or(&[])),
        Some("apt-table") => cmd_apt_table(args.get(2..).unwrap_or(&[])),
        Some("--help" | "-h") | None => {
            usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("maxwell: unknown command '{other}'");
            usage();
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "maxwell — SP 800-90B MCV min-entropy estimator (out of boundary)\n\
         \n\
         USAGE:\n\
         \x20 maxwell mcv <FILE> <BITS_PER_SYMBOL>        compute MCV estimates (1..=8 bits)\n\
         \x20 maxwell collision <FILE> <BITS_PER_SYMBOL>  §6.3.2 Collision estimate (bitstring)\n\
         \x20 maxwell parity [--datasets <DIR>]           run the EA-tool parity table (MCV + Collision)\n\
         \x20 maxwell apt-table <ALPHA_EXP>               SP 800-90B §4.4.2 APT cutoff grids\n\
         \n\
         parity dataset dir precedence: --datasets, then $OXICRYPT_EA_DATA,\n\
         then ~/repos/SP800-90B_EntropyAssessment/bin"
    );
}

fn print_apt_grid(label: &str, window: u32, rows: &[AptRow]) {
    println!("{label} (W = {window}):");
    for r in rows {
        // Render H exactly as num/den, plus a decimal hint for readability.
        #[allow(clippy::cast_precision_loss)]
        let h_dec = f64::from(r.h_num) / f64::from(r.h_den);
        println!(
            "  H = {}/{} ({h_dec:.4} bits)  C = {}",
            r.h_num, r.h_den, r.cutoff
        );
    }
}

fn cmd_apt_table(args: &[String]) -> ExitCode {
    let Some(alpha_str) = args.first() else {
        eprintln!("usage: maxwell apt-table <ALPHA_EXP>   (e.g. 20 or 30 for α = 2⁻ᵃ)");
        return ExitCode::FAILURE;
    };
    let Ok(alpha_exp) = alpha_str.parse::<u32>() else {
        eprintln!("maxwell: ALPHA_EXP must be a non-negative integer (α = 2⁻ALPHA_EXP)");
        return ExitCode::FAILURE;
    };

    println!("SP 800-90B §4.4.2 Adaptive Proportion Test cutoffs — α = 2^-{alpha_exp}");
    println!("method: C = 1 + qbinom(1 - α, W, 2^-H), CDF via incomplete beta (f64)");
    print_apt_grid(
        "binary",
        oxicrypt_maxwell::apt::WINDOW_BINARY,
        &binary_grid(alpha_exp),
    );
    print_apt_grid(
        "non-binary",
        oxicrypt_maxwell::apt::WINDOW_NON_BINARY,
        &non_binary_grid(alpha_exp),
    );
    ExitCode::SUCCESS
}

fn print_estimate(label: &str, e: &McvEstimate) {
    println!(
        "  {label:9}  mode_count={:<10} p_hat={:.17} p_u={:.17} min_entropy={:.17}",
        e.mode_count, e.p_hat, e.p_u, e.min_entropy
    );
}

fn cmd_mcv(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell mcv <FILE> <BITS_PER_SYMBOL>");
        return ExitCode::FAILURE;
    };

    let Ok(bits @ 1..=8) = bits_str.parse::<u8>() else {
        eprintln!("maxwell: BITS_PER_SYMBOL must be an integer in 1..=8");
        return ExitCode::FAILURE;
    };

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = mcv(&data, bits);
    println!("{file}  (L={} symbols, {bits} bits/symbol)", data.len());
    print_estimate("literal", &result.literal);
    match result.bitstring {
        Some(bs) => print_estimate("bitstring", &bs),
        None => println!("  bitstring  (none — 1-bit data; literal == bitstring)"),
    }
    ExitCode::SUCCESS
}

fn cmd_collision(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell collision <FILE> <BITS_PER_SYMBOL>");
        return ExitCode::FAILURE;
    };

    let Ok(bits @ 1..=8) = bits_str.parse::<u8>() else {
        eprintln!("maxwell: BITS_PER_SYMBOL must be an integer in 1..=8");
        return ExitCode::FAILURE;
    };

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let est = collision(&data, bits);
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    println!("  v           = {}", est.v);
    println!("  Sum t_i     = {}", est.sum_t);
    println!("  X-bar       = {:.17}", est.x_bar);
    println!("  sigma-hat   = {:.17}", est.sigma_hat);
    println!("  X-bar'      = {:.17}", est.x_bar_prime);
    if est.found_p {
        println!("  p           = {:.17}  (Found p)", est.p);
    } else {
        println!(
            "  p           = {:.17}  (Could Not Find p — lower bound)",
            est.p
        );
    }
    println!("  min_entropy = {:.17}", est.min_entropy);
    ExitCode::SUCCESS
}

fn cmd_parity(args: &[String]) -> ExitCode {
    // Parse optional --datasets <DIR>.
    let mut dir_override: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args.get(i).map(String::as_str) {
            Some("--datasets") => {
                if let Some(d) = args.get(i.saturating_add(1)) {
                    dir_override = Some(PathBuf::from(d));
                    i = i.saturating_add(2);
                } else {
                    eprintln!("maxwell: --datasets requires a directory argument");
                    return ExitCode::FAILURE;
                }
            }
            Some(other) => {
                eprintln!("maxwell: unexpected argument '{other}'");
                return ExitCode::FAILURE;
            }
            None => break,
        }
    }

    let dir: PathBuf = resolve_datasets_dir(dir_override.as_deref().map(Path::new));
    println!(
        "EA-tool parity (MCV + Collision) — datasets: {}",
        dir.display()
    );
    println!(
        "tolerance: {:.0e} bits absolute, all estimators",
        1.0e-6_f64
    );

    let results = run_parity(&dir);
    for r in &results {
        println!("{}", r.line());
    }

    let v = Verdict::tally(&results);
    println!(
        "verdict: {} passed, {} skipped, {} failed",
        v.passed, v.skipped, v.failed
    );

    if v.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
