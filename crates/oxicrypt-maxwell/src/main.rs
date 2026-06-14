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
//! | `maxwell markov <FILE> <BITS_PER_SYMBOL>` | §6.3.3 Markov estimate (bitstring) for one file |
//! | `maxwell compression <FILE> <BITS_PER_SYMBOL>` | §6.3.4 Compression estimate (bitstring) for one file |
//! | `maxwell multi-mcw <FILE> <BITS_PER_SYMBOL>` | §6.3.7 MultiMCW prediction estimate (bitstring) for one file |
//! | `maxwell lag <FILE> <BITS_PER_SYMBOL>` | §6.3.8 Lag prediction estimate (bitstring) for one file |
//! | `maxwell multi-mmc <FILE> <BITS_PER_SYMBOL>` | §6.3.9 MultiMMC prediction estimate (bitstring) for one file |
//! | `maxwell lz78y <FILE> <BITS_PER_SYMBOL>` | §6.3.10 LZ78Y prediction estimate (bitstring) for one file |
//! | `maxwell parity [--datasets <DIR>]` | Run the full EA-tool parity table (all estimators) |
//! | `maxwell apt-table <ALPHA_EXP>` | SP 800-90B §4.4.2 APT cutoff grids at α = 2⁻ᵃ |
//! | `maxwell gate --oe <DIR>` | SP 800-90B §6.3 per-OE reuse/acceptance gate |
//! | `maxwell periodicity <FILE>` | FFT + autocorrelation periodicity screen (pilot acceptance) |
//!
//! `parity` resolves its dataset directory from `--datasets`, else the
//! `OXICRYPT_EA_DATA` environment variable, else
//! `~/repos/SP800-90B_EntropyAssessment/bin`. It exits non-zero if any present
//! dataset fails (absent datasets are skipped, not failures).
//!
//! `gate` reads a `gate-results.json` sidecar from the OE directory (the four
//! §6.3 min-entropy/sanity values, recorded from the entropy assessment) and
//! exits zero only when all four §6.3 conditions hold.
//!
//! `periodicity` runs a lightweight FFT + autocorrelation periodicity screen on
//! a raw dataset (one byte per sample) and exits non-zero if a dominant periodic
//! component is detected (pilot acceptance fails). This is a screen with
//! engineering-chosen thresholds, not a NIST-specified statistic.
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
use oxicrypt_maxwell::compression::compression;
use oxicrypt_maxwell::gate::{evaluate, load_inputs};
use oxicrypt_maxwell::lag::lag;
use oxicrypt_maxwell::lz78y::lz78y;
use oxicrypt_maxwell::markov::markov;
use oxicrypt_maxwell::multi_mcw::multi_mcw;
use oxicrypt_maxwell::multi_mmc::multi_mmc;
use oxicrypt_maxwell::parity::{Verdict, resolve_datasets_dir, run_parity};
use oxicrypt_maxwell::periodicity::screen;
use oxicrypt_maxwell::{McvEstimate, mcv};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mcv") => cmd_mcv(args.get(2..).unwrap_or(&[])),
        Some("collision") => cmd_collision(args.get(2..).unwrap_or(&[])),
        Some("markov") => cmd_markov(args.get(2..).unwrap_or(&[])),
        Some("compression") => cmd_compression(args.get(2..).unwrap_or(&[])),
        Some("multi-mcw") => cmd_multi_mcw(args.get(2..).unwrap_or(&[])),
        Some("lag") => cmd_lag(args.get(2..).unwrap_or(&[])),
        Some("multi-mmc") => cmd_multi_mmc(args.get(2..).unwrap_or(&[])),
        Some("lz78y") => cmd_lz78y(args.get(2..).unwrap_or(&[])),
        Some("parity") => cmd_parity(args.get(2..).unwrap_or(&[])),
        Some("apt-table") => cmd_apt_table(args.get(2..).unwrap_or(&[])),
        Some("gate") => cmd_gate(args.get(2..).unwrap_or(&[])),
        Some("periodicity") => cmd_periodicity(args.get(2..).unwrap_or(&[])),
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
         \x20 maxwell markov <FILE> <BITS_PER_SYMBOL>     §6.3.3 Markov estimate (bitstring)\n\
         \x20 maxwell compression <FILE> <BITS_PER_SYMBOL> §6.3.4 Compression estimate (bitstring)\n\
         \x20 maxwell multi-mcw <FILE> <BITS_PER_SYMBOL>  §6.3.7 MultiMCW prediction estimate (bitstring)\n\
         \x20 maxwell lag <FILE> <BITS_PER_SYMBOL>        §6.3.8 Lag prediction estimate (bitstring)\n\
         \x20 maxwell multi-mmc <FILE> <BITS_PER_SYMBOL>  §6.3.9 MultiMMC prediction estimate (bitstring)\n\
         \x20 maxwell lz78y <FILE> <BITS_PER_SYMBOL>      §6.3.10 LZ78Y prediction estimate (bitstring)\n\
         \x20 maxwell parity [--datasets <DIR>]           run the EA-tool parity table (all estimators)\n\
         \x20 maxwell apt-table <ALPHA_EXP>               SP 800-90B §4.4.2 APT cutoff grids\n\
         \x20 maxwell gate --oe <DIR>                     SP 800-90B §6.3 per-OE acceptance gate\n\
         \x20 maxwell periodicity <FILE>                  FFT + autocorrelation periodicity screen\n\
         \n\
         parity dataset dir precedence: --datasets, then $OXICRYPT_EA_DATA,\n\
         then ~/repos/SP800-90B_EntropyAssessment/bin\n\
         \n\
         gate reads <DIR>/gate-results.json (raw/restart-row/restart-col\n\
         min-entropy + restart sanity); exits 0 only if all four §6.3\n\
         conditions hold.\n\
         \n\
         periodicity screens one raw dataset (one byte/sample); exits non-zero\n\
         if a dominant periodic component is detected (pilot acceptance fails).\n\
         Thresholds are engineering choices for a screen, not spec constants."
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

fn cmd_markov(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell markov <FILE> <BITS_PER_SYMBOL>");
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

    let est = markov(&data, bits);
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    println!("  P_0         = {:.17}", est.p_0);
    println!("  P_1         = {:.17}", est.p_1);
    println!("  P_0,0       = {:.17}", est.p_00);
    println!("  P_0,1       = {:.17}", est.p_01);
    println!("  P_1,0       = {:.17}", est.p_10);
    println!("  P_1,1       = {:.17}", est.p_11);
    println!("  H_min       = {:.17}", est.h_min);
    println!("  min_entropy = {:.17}", est.min_entropy);
    ExitCode::SUCCESS
}

fn cmd_compression(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell compression <FILE> <BITS_PER_SYMBOL>");
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

    let est = compression(&data, bits);
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    if est.min_entropy < 0.0 {
        println!("  *** insufficient data — need more than 1000 6-bit blocks ***");
        return ExitCode::FAILURE;
    }
    println!("  v           = {}", est.v);
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

fn cmd_multi_mcw(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell multi-mcw <FILE> <BITS_PER_SYMBOL>");
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

    let est = multi_mcw(&data, bits).estimate;
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    if est.min_entropy < 0.0 {
        println!("  *** insufficient data for the MultiMCW predictor ***");
        return ExitCode::FAILURE;
    }
    println!("  C (correct) = {}", est.c);
    println!("  N (preds)   = {}", est.n);
    println!("  max_run_len = {}", est.max_run_len);
    println!("  p_global    = {:.17}", est.p_global);
    println!("  p_global'   = {:.17}", est.p_global_prime);
    println!("  p_local     = {:.17}", est.p_local);
    println!("  min_entropy = {:.17}", est.min_entropy);
    ExitCode::SUCCESS
}

fn cmd_lag(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell lag <FILE> <BITS_PER_SYMBOL>");
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

    let est = lag(&data, bits).estimate;
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    if est.min_entropy < 0.0 {
        println!("  *** insufficient data for the Lag predictor ***");
        return ExitCode::FAILURE;
    }
    println!("  C (correct) = {}", est.c);
    println!("  N (preds)   = {}", est.n);
    println!("  max_run_len = {}", est.max_run_len);
    println!("  p_global    = {:.17}", est.p_global);
    println!("  p_global'   = {:.17}", est.p_global_prime);
    println!("  p_local     = {:.17}", est.p_local);
    println!("  min_entropy = {:.17}", est.min_entropy);
    ExitCode::SUCCESS
}

fn cmd_multi_mmc(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell multi-mmc <FILE> <BITS_PER_SYMBOL>");
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

    let est = multi_mmc(&data, bits).estimate;
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    if est.min_entropy < 0.0 {
        println!("  *** insufficient data for the MultiMMC predictor ***");
        return ExitCode::FAILURE;
    }
    println!("  C (correct) = {}", est.c);
    println!("  N (preds)   = {}", est.n);
    println!("  max_run_len = {}", est.max_run_len);
    println!("  p_global    = {:.17}", est.p_global);
    println!("  p_global'   = {:.17}", est.p_global_prime);
    println!("  p_local     = {:.17}", est.p_local);
    println!("  min_entropy = {:.17}", est.min_entropy);
    ExitCode::SUCCESS
}

fn cmd_lz78y(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell lz78y <FILE> <BITS_PER_SYMBOL>");
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

    let est = lz78y(&data, bits).estimate;
    println!(
        "{file}  (L={} symbols, {bits} bits/symbol, bitstring track)",
        data.len()
    );
    if est.min_entropy < 0.0 {
        println!("  *** insufficient data for the LZ78Y predictor ***");
        return ExitCode::FAILURE;
    }
    println!("  C (correct) = {}", est.c);
    println!("  N (preds)   = {}", est.n);
    println!("  max_run_len = {}", est.max_run_len);
    println!("  p_global    = {:.17}", est.p_global);
    println!("  p_global'   = {:.17}", est.p_global_prime);
    println!("  p_local     = {:.17}", est.p_local);
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
        "EA-tool parity (MCV + Collision + Markov + Compression + t-Tuple + LRS + MultiMCW + Lag \
         + MultiMMC + LZ78Y) — datasets: {}",
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

fn cmd_gate(args: &[String]) -> ExitCode {
    // Parse the required --oe <DIR>.
    let mut oe_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args.get(i).map(String::as_str) {
            Some("--oe") => {
                if let Some(d) = args.get(i.saturating_add(1)) {
                    oe_dir = Some(PathBuf::from(d));
                    i = i.saturating_add(2);
                } else {
                    eprintln!("maxwell: --oe requires a directory argument");
                    return ExitCode::FAILURE;
                }
            }
            Some(other) => {
                eprintln!("maxwell: unexpected argument '{other}'");
                eprintln!("usage: maxwell gate --oe <DIR>");
                return ExitCode::FAILURE;
            }
            None => break,
        }
    }

    let Some(dir) = oe_dir else {
        eprintln!("usage: maxwell gate --oe <DIR>");
        eprintln!(
            "  reads <DIR>/gate-results.json and applies the SP 800-90B §6.3 acceptance gate"
        );
        return ExitCode::FAILURE;
    };

    let inputs = match load_inputs(&dir) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("maxwell: {e}");
            return ExitCode::FAILURE;
        }
    };

    let decision = evaluate(&inputs);
    println!(
        "SP 800-90B §6.3 per-OE acceptance gate — OE: {}",
        dir.display()
    );
    println!(
        "  raw min-entropy           = {:.6} bit/delta",
        inputs.raw_min_entropy
    );
    println!(
        "  restart row min-entropy   = {:.6} bit/delta",
        inputs.restart_row_min_entropy
    );
    println!(
        "  restart col min-entropy   = {:.6} bit/delta",
        inputs.restart_col_min_entropy
    );
    println!(
        "  restart min(row,col)      = {:.6} bit/delta",
        inputs.restart_min()
    );
    println!(
        "  restart sanity (§3.1.4.3) = {}",
        inputs.restart_sanity_pass
    );
    println!("  conditions:");
    println!(
        "    [{}] {}",
        check_mark(decision.conditions.raw_rate),
        oxicrypt_maxwell::gate::Condition::RawRate.label()
    );
    println!(
        "    [{}] {}",
        check_mark(decision.conditions.restart_sanity),
        oxicrypt_maxwell::gate::Condition::RestartSanity.label()
    );
    println!(
        "    [{}] {}",
        check_mark(decision.conditions.restart_half_raw),
        oxicrypt_maxwell::gate::Condition::RestartHalfRaw.label()
    );
    println!(
        "    [{}] {}",
        check_mark(decision.conditions.restart_rate),
        oxicrypt_maxwell::gate::Condition::RestartRate.label()
    );

    if decision.accept {
        println!("verdict: ACCEPT — all four §6.3 conditions hold; OE reuse permitted");
        ExitCode::SUCCESS
    } else {
        println!("verdict: REJECT — the following §6.3 condition(s) failed:");
        for c in decision.failed() {
            println!("  - {}", c.label());
        }
        ExitCode::FAILURE
    }
}

/// Render a pass/fail tick for the per-condition lines.
fn check_mark(pass: bool) -> char {
    if pass { 'x' } else { ' ' }
}

fn cmd_periodicity(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("usage: maxwell periodicity <FILE>");
        eprintln!(
            "  FFT + autocorrelation periodicity screen over a raw dataset (one byte/sample)"
        );
        return ExitCode::FAILURE;
    };

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let r = screen(&data);
    println!("{file}  (n={} samples, FFT size {})", r.n, r.fft_size);
    println!("note: periodicity screen — thresholds are engineering choices, not spec constants");
    println!(
        "  spectral  peak bin {:<8} peak/mean = {:.3} (threshold {:.1})  [{}]",
        r.peak_bin,
        r.peak_to_mean_ratio,
        oxicrypt_maxwell::periodicity::SPECTRAL_PEAK_RATIO,
        check_mark(r.spectral_flag)
    );
    println!(
        "  autocorr  peak lag {:<8} |r|       = {:.6} (threshold {:.3})  [{}]",
        r.peak_lag,
        r.peak_autocorr,
        oxicrypt_maxwell::periodicity::AUTOCORR_PEAK_THRESHOLD,
        check_mark(r.autocorr_flag)
    );

    if r.flagged() {
        println!("verdict: FLAGGED — dominant periodic component detected; pilot acceptance fails");
        ExitCode::FAILURE
    } else {
        println!("verdict: PASS — no dominant periodic component detected");
        ExitCode::SUCCESS
    }
}
