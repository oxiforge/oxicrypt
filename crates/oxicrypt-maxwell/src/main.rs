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
//! | `maxwell t-tuple <FILE> <BITS_PER_SYMBOL>` | §6.3.5 t-Tuple estimate (bitstring) for one file |
//! | `maxwell lrs <FILE> <BITS_PER_SYMBOL>` | §6.3.6 LRS estimate (bitstring) for one file |
//! | `maxwell parity [--datasets <DIR>]` | Run the full EA-tool parity table (all estimators) |
//! | `maxwell apt-table <ALPHA_EXP>` | SP 800-90B §4.4.2 APT cutoff grids at α = 2⁻ᵃ |
//! | `maxwell gate --oe <DIR>` | SP 800-90B §6.3 per-OE reuse/acceptance gate |
//! | `maxwell periodicity <FILE>` | FFT + autocorrelation periodicity screen (pilot acceptance) |
//! | `maxwell iid-permutation <FILE>` | SP 800-90B §5.1 permutation testing battery (19-statistic IID test) |
//! | `maxwell chi-square <FILE>` | SP 800-90B §5.2 chi-square IID tests (independence + goodness-of-fit) |
//! | `maxwell lrs-iid <FILE>` | SP 800-90B §5.3 LRS (longest-repeated-substring) IID test |
//! | `maxwell iid-gate <FILE> <BITS_PER_SYMBOL>` | SP 800-90B §5 IID gate: §5 verdict + branch + per-bit routed + per-symbol assessed min-entropy |
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

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxicrypt_maxwell::apt::{AptRow, binary_grid, non_binary_grid};
use oxicrypt_maxwell::chi_square::chi_square_tests;
use oxicrypt_maxwell::collision::collision;
use oxicrypt_maxwell::compression::compression;
use oxicrypt_maxwell::gate::{evaluate, load_inputs};
use oxicrypt_maxwell::iid_gate::{Branch, iid_gate};
use oxicrypt_maxwell::iid_lrs::len_lrs_iid_test;
use oxicrypt_maxwell::independence::{
    self, FlagCause, IndependenceReport, Provenance, analyze, parse_metadata, write_sidecar,
};
use oxicrypt_maxwell::lag::lag;
use oxicrypt_maxwell::lrs::lrs;
use oxicrypt_maxwell::lz78y::lz78y;
use oxicrypt_maxwell::markov::markov;
use oxicrypt_maxwell::multi_mcw::multi_mcw;
use oxicrypt_maxwell::multi_mmc::multi_mmc;
use oxicrypt_maxwell::parity::{
    Outcome, Verdict, datasets_optional, resolve_datasets_dir, run_parity,
};
use oxicrypt_maxwell::periodicity::screen;
use oxicrypt_maxwell::permutation::{PERMS, permutation_stats, permutation_test};
use oxicrypt_maxwell::restart::{RestartResult, alphabet_size, restart_analysis};
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
        Some("t-tuple") => cmd_t_tuple(args.get(2..).unwrap_or(&[])),
        Some("lrs") => cmd_lrs(args.get(2..).unwrap_or(&[])),
        Some("parity") => cmd_parity(args.get(2..).unwrap_or(&[])),
        Some("apt-table") => cmd_apt_table(args.get(2..).unwrap_or(&[])),
        Some("gate") => cmd_gate(args.get(2..).unwrap_or(&[])),
        Some("periodicity") => cmd_periodicity(args.get(2..).unwrap_or(&[])),
        Some("independence") => cmd_independence(args.get(2..).unwrap_or(&[])),
        Some("iid-permutation") => cmd_iid_permutation(args.get(2..).unwrap_or(&[])),
        Some("chi-square") => cmd_chi_square(args.get(2..).unwrap_or(&[])),
        Some("lrs-iid") => cmd_lrs_iid(args.get(2..).unwrap_or(&[])),
        Some("iid-gate") => cmd_iid_gate(args.get(2..).unwrap_or(&[])),
        Some("restart") => cmd_restart(args.get(2..).unwrap_or(&[])),
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
         \x20 maxwell t-tuple <FILE> <BITS_PER_SYMBOL>    §6.3.5 t-Tuple estimate (bitstring)\n\
         \x20 maxwell lrs <FILE> <BITS_PER_SYMBOL>        §6.3.6 LRS estimate (bitstring)\n\
         \x20 maxwell parity [--datasets <DIR>]           run the EA-tool parity table (all estimators)\n\
         \x20 maxwell apt-table <ALPHA_EXP>               SP 800-90B §4.4.2 APT cutoff grids\n\
         \x20 maxwell gate --oe <DIR>                     SP 800-90B §6.3 per-OE acceptance gate\n\
         \x20 maxwell periodicity <FILE>                  FFT + autocorrelation periodicity screen\n\
         \x20 maxwell independence <FILE> <BITS_PER_SYMBOL> [--claim H] [--metadata F] [--sidecar DIR]\n\
         \x20                                              2D/3D min-entropy independence evidence\n\
         \x20 maxwell iid-permutation <FILE>              SP 800-90B §5.1 permutation battery (19-stat IID test)\n\
         \x20 maxwell chi-square <FILE>                   SP 800-90B §5.2 chi-square IID tests (indep + GOF)\n\
         \x20 maxwell lrs-iid <FILE>                      SP 800-90B §5.3 LRS (longest repeated substring) IID test\n\
         \x20 maxwell iid-gate <FILE> <BITS_PER_SYMBOL>   SP 800-90B §5 IID gate (verdict + branch + per-bit + per-symbol assessed H)\n\
         \x20 maxwell restart <FILE> <BITS_PER_SYMBOL> <H_I> SP 800-90B §3.1.4 restart analysis (sanity + §5 + gate)\n\
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

/// Read `<FILE> <BITS_PER_SYMBOL>` and return the parsed bytes + width, or print
/// a usage error and return `None`.
fn read_file_and_bits(cmd: &str, args: &[String]) -> Option<(Vec<u8>, u8)> {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell {cmd} <FILE> <BITS_PER_SYMBOL>");
        return None;
    };
    let Ok(bits @ 1..=8) = bits_str.parse::<u8>() else {
        eprintln!("maxwell: BITS_PER_SYMBOL must be an integer in 1..=8");
        return None;
    };
    match std::fs::read(file) {
        Ok(d) => Some((d, bits)),
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            None
        }
    }
}

/// §6.3.5 t-Tuple estimate (bitstring track). Shares the single suffix-array pass
/// with `lrs`; parity is already covered by the harness — this is CLI convenience.
fn cmd_t_tuple(args: &[String]) -> ExitCode {
    let Some((data, bits)) = read_file_and_bits("t-tuple", args) else {
        return ExitCode::FAILURE;
    };
    let est = lrs(&data, bits);
    println!(
        "L={} symbols, {bits} bits/symbol, bitstring track (n={} bits)",
        data.len(),
        est.n
    );
    if est.t_tuple_min_entropy < 0.0 {
        println!("  *** §6.3.5 t-Tuple estimate did not run (no tuple recurs enough) ***");
        return ExitCode::FAILURE;
    }
    println!("  t (= u-1)   = {}", est.u.saturating_sub(1));
    println!("  P_max       = {:.17}", est.t_tuple_p_max);
    println!("  min_entropy = {:.17}", est.t_tuple_min_entropy);
    ExitCode::SUCCESS
}

/// §6.3.6 LRS (longest-repeated-substring) estimate (bitstring track). Shares the
/// suffix-array pass with `t-tuple`; parity is harness-covered — CLI convenience.
fn cmd_lrs(args: &[String]) -> ExitCode {
    let Some((data, bits)) = read_file_and_bits("lrs", args) else {
        return ExitCode::FAILURE;
    };
    let est = lrs(&data, bits);
    println!(
        "L={} symbols, {bits} bits/symbol, bitstring track (n={} bits)",
        data.len(),
        est.n
    );
    if est.lrs_min_entropy < 0.0 {
        println!("  *** §6.3.6 LRS estimate could not run (v < u) ***");
        return ExitCode::FAILURE;
    }
    println!("  v (max LRS) = {}", est.v);
    println!("  P_max       = {:.17}", est.lrs_p_max);
    println!("  min_entropy = {:.17}", est.lrs_min_entropy);
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
    // ISC-62 version stamp: maxwell crate version vs the EA reference-tool
    // version the table was generated against.
    println!(
        "parity: oxicrypt-maxwell v{} vs EA tool v{}",
        env!("CARGO_PKG_VERSION"),
        oxicrypt_maxwell::parity::EA_TOOL_VERSION
    );
    println!(
        "EA-tool parity (§6.3: MCV + Collision + Markov + Compression + t-Tuple + LRS + MultiMCW \
         + Lag + MultiMMC + LZ78Y; §5 IID battery on the 3 short datasets) — datasets: {}",
        dir.display()
    );
    println!(
        "tolerance: {:.0e} bits absolute (§6.3 estimators); §5.1 L1 stats relative-or-absolute \
         {:.0e}; §5 verdicts exact",
        oxicrypt_maxwell::parity::PARITY_TOLERANCE_BITS,
        oxicrypt_maxwell::parity::PARITY_TOLERANCE_BITS
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

    let absent: Vec<&str> = results
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Skip { .. }))
        .map(|r| r.name)
        .collect();

    let (accepted, evidence, line) =
        parity_verdict(&v, results.len(), &absent, datasets_optional());
    println!("{line}");
    if !evidence {
        // Also on stderr: the opt-out is process environment, not a per-invocation
        // act, so a caller that reads only the exit code can be silently running
        // against a disarmed gate. The stream a script is most likely to surface
        // must carry the words too.
        eprintln!("{line}");
    }
    if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Decide the closing verdict for a parity run: `(accepted, is_evidence, line)`.
///
/// `accepted` drives the exit code; `is_evidence` is the stronger property the
/// Security Policy's parity claim rests on. **They are not the same**: an opted-out
/// partial run is accepted (exit zero) and is explicitly *not* evidence. Nothing
/// anywhere may infer coverage from the exit code alone — that is why this returns
/// both and why the line always says which it is.
///
/// Pure and separated from [`cmd_parity`] so every quadrant is reachable by a test.
/// Driving them through the binary would need a provisioned EA v1.1.8 bundle for
/// the PASS case, which CI does not have (#153) — the branch carrying the CMVP
/// claim would then be the one branch never probed.
#[must_use]
fn parity_verdict(
    v: &Verdict,
    total: usize,
    absent: &[&str],
    optional: bool,
) -> (bool, bool, String) {
    if !v.ok() {
        // Deliberately does NOT say the datasets "disagreed beyond the tolerance":
        // `Outcome::Fail` also covers a provenance/digest mismatch, an unreadable
        // file, and a module power-up failure — cases where no numeric comparison
        // ran at all. The per-dataset FAIL lines above carry the actual reason.
        return (
            false,
            false,
            format!(
                "verdict: FAIL — {} of {total} datasets did not match the EA v{} reference \
                 (see the FAIL lines above for each reason); {} absent; NOT parity evidence",
                v.failed,
                oxicrypt_maxwell::parity::EA_TOOL_VERSION,
                v.skipped
            ),
        );
    }
    if v.full_strength() {
        return (
            true,
            true,
            format!(
                "verdict: PASS — all {total} datasets compared within {:.0e} bits, full-strength; \
                 this run is parity evidence",
                oxicrypt_maxwell::parity::PARITY_TOLERANCE_BITS
            ),
        );
    }
    if optional {
        (
            true,
            false,
            format!(
                "verdict: PARTIAL — {} of {total} datasets compared; NOT parity evidence. \
                 Accepted because OXICRYPT_EA_DATA_OPTIONAL=1 is set in this process environment. \
                 Absent: {}",
                v.passed,
                absent.join(", ")
            ),
        )
    } else {
        (
            false,
            false,
            format!(
                "verdict: INCOMPLETE — {} of {total} datasets compared, {} absent; \
                 NOT parity evidence. Point --datasets or $OXICRYPT_EA_DATA at the EA v{} bundle, \
                 or set OXICRYPT_EA_DATA_OPTIONAL=1 to accept a partial run. Absent: {}",
                v.passed,
                v.skipped,
                oxicrypt_maxwell::parity::EA_TOOL_VERSION,
                absent.join(", ")
            ),
        )
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

/// Compute the SHA-256 of the input as lowercase hex, powering the module
/// up with the real KAT set first (the parity-harness provenance path).
/// Returns `None` on a service error — the sidecar then carries `null`.
fn input_sha256_hex(data: &[u8]) -> Option<String> {
    oxicrypt_maxwell::parity::sha256_hex(data)
}

/// Render one line of the pair-suite per-estimator table.
fn print_suite_row(label: &str, per_estimator: &[f64; 7]) {
    let cells: Vec<String> = per_estimator.iter().map(|h| format!("{h:.6}")).collect();
    println!("    {label:<8} {}", cells.join("  "));
}

#[allow(clippy::too_many_lines)]
fn print_independence(file: &str, r: &IndependenceReport) {
    println!(
        "{file}  (n={} symbols, {} bits/symbol)",
        r.n, r.bits_per_symbol
    );
    println!(
        "note: independence evidence screen — engineering choices, not spec constants; \
         the pair/triplet view covers k<=3 (FFT half + 1-D predictors own longer-range structure)"
    );
    println!(
        "  alphabets: pairs {} bins (occupancy {}), triplets {} bins (occupancy {})",
        r.pair_alphabet, r.pair_occupancy, r.triplet_alphabet, r.triplet_occupancy
    );
    println!(
        "  tuples: pairs {:?}/phase, triplets {:?}/phase (disjoint, tail dropped)",
        r.pair_count_per_phase, r.triplet_count_per_phase
    );

    // Pair-suite leg.
    println!(
        "  pair-suite leg [{}]:",
        independence::SUITE_LABELS.join("  ")
    );
    match (&r.suite_1d, &r.pair_suite) {
        (Some(s1d), Some(ps)) => {
            print_suite_row("1D", &s1d.per_estimator);
            print_suite_row("pairP0", &ps.per_estimator_per_phase[0]);
            print_suite_row("pairP1", &ps.per_estimator_per_phase[1]);
            println!(
                "    suite_min_1d = {:.6}   pair_suite_min = {:.6}   pair_suite_min/2 = {:.6}",
                s1d.min, ps.min, ps.min_per_delta
            );
            println!(
                "    structure deficit vs 1D = {:.6}   deficit vs shuffled null = {:.6}",
                ps.structure_deficit_vs_1d, ps.deficit_vs_null
            );
        }
        _ => println!(
            "    unavailable — symbol width ({} bits > 4; pair alphabet exceeds the 8-bit wire)",
            r.bits_per_symbol
        ),
    }

    // Tuple-MCV leg.
    let m = &r.mcv;
    println!("  tuple-MCV leg (confidence-bound):");
    println!(
        "    H1 = {:.6}   H2 = {:.6} (per-delta {:.6})   H3 = {:.6} (per-delta {:.6})",
        m.h1,
        m.h2,
        m.h2_per_delta(),
        m.h3,
        m.h3_per_delta()
    );
    println!(
        "    pair bounded/phase = {:?}   triplet bounded/phase = {:?}",
        m.pair_bounded_per_phase, m.triplet_bounded_per_phase
    );
    println!(
        "    plain: H1 = {:.6}  H2 = {:.6}  H3 = {:.6}   r2 = {:.6}  r3 = {:.6}",
        m.plain1, m.plain2, m.plain3, m.r2_plain, m.r3_plain
    );
    println!(
        "    shuffled-baseline (K={}) null per-delta mean = [{:.6}, {:.6}, {:.6}] +/- [{:.6}, {:.6}, {:.6}]",
        independence::K_MCV_SHUFFLES,
        m.null_mean[0],
        m.null_mean[1],
        m.null_mean[2],
        m.null_spread[0],
        m.null_spread[1],
        m.null_spread[2]
    );
    println!(
        "    plain per-delta deficits vs null: d2 = {:.6}   d3 = {:.6}",
        m.deficit2, m.deficit3
    );

    // Gate / verdict.
    match r.claim {
        Some(h) => {
            println!(
                "  claim = {h:.6}   gate value min(pair_term {:.6}, H3/3 {:.6}) = {:.6}",
                r.pair_term(),
                m.h3_per_delta(),
                r.gate_value()
            );
            if r.flagged {
                let cause = match r.flag_cause {
                    Some(FlagCause::Pair) => "pair term below claim",
                    Some(FlagCause::TripletMcv) => "triplet-MCV term below claim",
                    None => "below claim",
                };
                if r.advisory_only {
                    println!(
                        "verdict: FLAGGED (advisory — n < 10,000,000 precedent minimum; exit SUCCESS): {cause}"
                    );
                } else {
                    println!("verdict: FLAGGED — {cause}; acceptance evidence fails");
                }
            } else {
                println!("verdict: consistent — gate value >= claim");
            }
        }
        None => println!("  report-only (no --claim); exit SUCCESS"),
    }
    if r.advisory_only {
        println!(
            "  warning: n = {} < 10,000,000 — below the precedent minimum for a representative value",
            r.n
        );
    }
    if r.degenerate {
        println!("  note: degenerate input (too short to form tuples or non-finite values)");
    }
}

#[allow(
    // One CLI handler: arg parsing, provenance load, analyze, sidecar write, and
    // exit-code decision. Splitting scatters the command contract across helpers.
    clippy::too_many_lines
)]
fn cmd_independence(args: &[String]) -> ExitCode {
    // Positional <FILE> <BITS_PER_SYMBOL>, then optional flags.
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!(
            "usage: maxwell independence <FILE> <BITS_PER_SYMBOL> [--claim <H>] [--metadata <FILE>] [--sidecar <DIR>]"
        );
        eprintln!(
            "  2D/3D (pairs/triplets) min-entropy independence evidence over a raw dataset\n\
             \x20 (one byte/sample). With --claim, FLAGs (exit FAILURE) when\n\
             \x20 min(pair_suite_min/2, H3_mcv/3) < H; below 10,000,000 samples the flag is advisory."
        );
        return ExitCode::FAILURE;
    };
    let Ok(bits @ 1..=8) = bits_str.parse::<u8>() else {
        eprintln!("maxwell: BITS_PER_SYMBOL must be an integer in 1..=8");
        return ExitCode::FAILURE;
    };

    let mut claim: Option<f64> = None;
    let mut metadata: Option<PathBuf> = None;
    let mut sidecar_dir: Option<PathBuf> = None;
    let mut i = 2usize;
    while i < args.len() {
        match args.get(i).map(String::as_str) {
            Some("--claim") => {
                let Some(v) = args.get(i.saturating_add(1)) else {
                    eprintln!("maxwell: --claim requires a value");
                    return ExitCode::FAILURE;
                };
                let Ok(h) = v.parse::<f64>() else {
                    eprintln!("maxwell: --claim value must be a real number");
                    return ExitCode::FAILURE;
                };
                if !independence::validate_claim(h) {
                    eprintln!("maxwell: --claim value must be a finite, positive real number");
                    return ExitCode::FAILURE;
                }
                claim = Some(h);
                i = i.saturating_add(2);
            }
            Some("--metadata") => {
                let Some(v) = args.get(i.saturating_add(1)) else {
                    eprintln!("maxwell: --metadata requires a file path");
                    return ExitCode::FAILURE;
                };
                metadata = Some(PathBuf::from(v));
                i = i.saturating_add(2);
            }
            Some("--sidecar") => {
                let Some(v) = args.get(i.saturating_add(1)) else {
                    eprintln!("maxwell: --sidecar requires a directory path");
                    return ExitCode::FAILURE;
                };
                sidecar_dir = Some(PathBuf::from(v));
                i = i.saturating_add(2);
            }
            Some(other) => {
                eprintln!("maxwell: unexpected argument '{other}'");
                return ExitCode::FAILURE;
            }
            None => break,
        }
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            return ExitCode::FAILURE;
        }
    };

    // Provenance copy-through from the collection metadata sidecar.
    let prov = match &metadata {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(text) => parse_metadata(&text),
            Err(e) => {
                eprintln!("maxwell: cannot read metadata '{}': {e}", p.display());
                return ExitCode::FAILURE;
            }
        },
        None => Provenance::default(),
    };

    // ISC-145: match EA v1.1.8 on input validation. A sample wider than the
    // declared width is a hard error with no assessment — the estimators would
    // drop it from the histogram while still counting it in the denominator, so
    // the reported min-entropy would be computed over a fraction of the data.
    // Refusing is fail-closed and, unlike masking, does not silently reinterpret
    // the operator's dataset.
    let report = match analyze(&data, bits, claim) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("maxwell: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A *narrower* observed width is not an error: EA warns and continues, and a
    // legitimately narrow source (a 1-bit noise source declared at 8) is common.
    // It is still worth saying, because a declaration wider than the data inflates
    // the tuple alphabet and thins every histogram.
    if report.observed_bits_per_symbol < bits {
        eprintln!(
            "maxwell: warning — declared {bits} bits/symbol but no sample needs more than {}; \
             the assessment proceeds over the declared {bits}-bit alphabet, which is wider than \
             the data occupies.",
            report.observed_bits_per_symbol
        );
    }
    print_independence(file, &report);

    // Sidecar (default beside the input file).
    let dir: PathBuf = sidecar_dir.unwrap_or_else(|| {
        Path::new(file)
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    });
    let run_utc = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    );
    let sha = input_sha256_hex(&data);
    let sidecar_ok = match write_sidecar(&report, &run_utc, sha.as_deref(), &prov, &dir) {
        Ok(path) => {
            println!("  sidecar: {}", path.display());
            true
        }
        Err(e) => {
            eprintln!(
                "maxwell: could not write sidecar in '{}': {e}",
                dir.display()
            );
            false
        }
    };

    // A run whose machine-readable evidence artifact was never written must not
    // report success, even when the claim gate itself did not flag.
    if report.exit_failure() || !sidecar_ok {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_iid_permutation(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("usage: maxwell iid-permutation <FILE>");
        eprintln!(
            "  SP 800-90B §5.1 permutation testing battery (19-statistic IID test) over a raw\n\
             \x20 dataset (one byte/sample). The compression statistic (index 18) is computed\n\
             \x20 bit-exactly vs the EA tool (pure-Rust bzip2 length) and is included in the\n\
             \x20 verdict like every other statistic."
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

    let stats = permutation_stats(&data);
    println!("{file}  (L={} symbols, one byte/sample)", data.len());
    println!(
        "note: SP 800-90B §5.1 permutation battery — compression (18) is the bit-exact bzip2 length"
    );
    println!();
    println!("unpermuted statistics t[i]:");
    for (name, &v) in stats.names.iter().zip(stats.values.iter()) {
        println!("  {name:<24} = {v:.17}");
    }

    println!();
    println!("permutation test ({PERMS} shuffles, fixed seed):");
    let verdict = permutation_test(&data);
    println!("            statistic        C0(>)    C1(=)    C2(<)  pass");
    println!("  ----------------------------------------------------------");
    for ((name, &(c0, c1, c2)), &pass) in stats
        .names
        .iter()
        .zip(verdict.c_counts.iter())
        .zip(verdict.per_test_pass.iter())
    {
        let mark = if pass { "yes" } else { "NO" };
        println!("  {name:<24} {c0:>8} {c1:>8} {c2:>8}  {mark}");
    }
    println!();
    println!(
        "  compression included in verdict: {}",
        verdict.compression_included
    );
    if verdict.is_iid {
        println!("verdict: IID — all active statistics are IID-consistent");
        ExitCode::SUCCESS
    } else {
        println!("verdict: NOT IID — at least one statistic is extreme under permutation");
        ExitCode::FAILURE
    }
}

fn cmd_chi_square(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("usage: maxwell chi-square <FILE>");
        eprintln!(
            "  SP 800-90B §5.2 chi-square IID tests (independence + goodness-of-fit) over a raw\n\
             \x20 dataset (one byte/sample). Fails if either p-value < 0.001."
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

    let r = chi_square_tests(&data);
    println!("{file}  (L={} symbols, one byte/sample)", data.len());
    println!();
    println!("Chi square independence: T = {:.17}", r.independence_score);
    println!("Chi square independence: df = {}", r.independence_df);
    println!(
        "Chi square independence: P-value = {:.17}",
        r.independence_pvalue
    );
    println!();
    println!("Chi square goodness of fit: T = {:.17}", r.gof_score);
    println!("Chi square goodness of fit: df = {}", r.gof_df);
    println!("Chi square goodness of fit: P-value = {:.17}", r.gof_pvalue);
    println!();

    if r.passed {
        println!("verdict: PASS");
        ExitCode::SUCCESS
    } else {
        println!("verdict: FAIL");
        ExitCode::FAILURE
    }
}

fn cmd_lrs_iid(args: &[String]) -> ExitCode {
    let Some(file) = args.first() else {
        eprintln!("usage: maxwell lrs-iid <FILE>");
        eprintln!(
            "  SP 800-90B §5.3 LRS (longest repeated substring) IID test over a raw dataset\n\
             \x20 (one byte/sample), on the literal symbol alphabet. Fails if Pr(X >= 1) < 1/1000."
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

    let r = len_lrs_iid_test(&data);
    println!(
        "{file}  (L={} symbols, one byte/sample, literal track)",
        data.len()
    );
    println!();
    // Strings mirror the EA tool's `ea_iid -v -v -v` "Literal Longest Repeated
    // Substring results:" verbose lines for a clean diff.
    println!(
        "Literal Longest Repeated Substring results: P_col = {:.17}",
        r.p_col
    );
    println!("Literal Longest Repeated Substring results: W = {}", r.w);
    println!(
        "Literal Longest Repeated Substring results: Pr(X >= 1) = {:.17}",
        r.pr_x_ge_1
    );
    println!();

    if r.passed {
        println!("verdict: PASS");
        ExitCode::SUCCESS
    } else {
        println!("verdict: FAIL");
        ExitCode::FAILURE
    }
}

fn cmd_iid_gate(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str)) = (args.first(), args.get(1)) else {
        eprintln!("usage: maxwell iid-gate <FILE> <BITS_PER_SYMBOL>");
        eprintln!(
            "  SP 800-90B §5 IID gate: runs the three §5 tests (permutation, chi-square, LRS),\n\
             \x20 reports the IID verdict and selected branch, routes the per-bit min-entropy\n\
             \x20 (IID -> §6.1 MCV; non-IID -> minimum over the §6.3 suite), and reports the\n\
             \x20 per-symbol assessed min-entropy headline min(H_original, H_bitstring x word_size)."
        );
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

    let r = iid_gate(&data, bits);
    println!("{file}  (L={} symbols, {bits} bits/symbol)", data.len());
    println!();
    println!(
        "  §5.1 permutation       [{}]",
        verdict_mark(r.permutation_passed)
    );
    println!(
        "  §5.2 chi-square        [{}]",
        verdict_mark(r.chi_square_passed)
    );
    println!("  §5.3 LRS               [{}]", verdict_mark(r.lrs_passed));
    println!();
    println!("  IID: {}", if r.is_iid { "yes" } else { "no" });
    let branch_label = match r.branch {
        Branch::Iid => "IID (MCV)",
        Branch::NonIid => "non-IID (§6.3 min)",
    };
    println!("  branch: {branch_label}");
    println!("  routed min-entropy (per bit):      {:.17}", r.min_entropy);
    println!(
        "  assessed min-entropy (per symbol): {:.17}",
        r.assessed.per_symbol
    );
    if r.assessed.word_size == 1 {
        println!(
            "    = H_original {:.17}  (1-bit data: literal == bitstring, no H_bitstring scaling)",
            r.assessed.h_original
        );
    } else {
        println!(
            "    = min(H_original {:.17}, H_bitstring {:.17} x {})",
            r.assessed.h_original, r.assessed.h_bitstring, r.assessed.word_size
        );
    }

    // The gate is a reporting tool; exit success once it has computed the
    // verdict. (The verdict itself is in the output, not the exit code.)
    ExitCode::SUCCESS
}

/// EA `DEFAULT_SIMULATION_ROUNDS` (`restart_main.cpp` line 27): the cutoff
/// Monte-Carlo round count when `-s` is not given.
const DEFAULT_SIMULATION_ROUNDS: usize = 5_000_000;

/// EA fixes the restart matrix at `r = c = 1000` (1,000,000 samples).
const RESTART_DIM: usize = 1000;

fn cmd_restart(args: &[String]) -> ExitCode {
    let (Some(file), Some(bits_str), Some(h_i_str)) = (args.first(), args.get(1), args.get(2))
    else {
        eprintln!("usage: maxwell restart <FILE> <BITS_PER_SYMBOL> <H_I>");
        eprintln!(
            "  SP 800-90B §3.1.4 restart analysis (IID path): the §3.1.4.3 sanity check,\n\
             \x20 the three §5 IID tests on rows && columns, the §6.1 MCV per-bit H on rows\n\
             \x20 and columns, and the §3.1.4.2 validation gate min(H_r, H_c) >= H_I/2.\n\
             \x20 FILE must be exactly 1,000,000 bytes (1000x1000 restart matrix, row order)."
        );
        return ExitCode::FAILURE;
    };

    let Ok(bits @ 1..=8) = bits_str.parse::<u8>() else {
        eprintln!("maxwell: BITS_PER_SYMBOL must be an integer in 1..=8");
        return ExitCode::FAILURE;
    };

    let Ok(h_i) = h_i_str.parse::<f64>() else {
        eprintln!("maxwell: H_I must be a real number");
        return ExitCode::FAILURE;
    };
    // `nan` and `inf` parse successfully as f64 and pass a `< 0.0` test, so the
    // nonnegativity check alone let a non-finite H_I reach the analysis, where
    // every comparison against it is false and the validation gate rejects the
    // data without being able to say why.
    if !h_i.is_finite() {
        eprintln!("maxwell: H_I ({h_i}) must be finite");
        return ExitCode::FAILURE;
    }
    if h_i < 0.0 {
        eprintln!("maxwell: H_I ({h_i}) must be nonnegative");
        return ExitCode::FAILURE;
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("maxwell: cannot read '{file}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let expected = RESTART_DIM * RESTART_DIM;
    if data.len() != expected {
        eprintln!(
            "maxwell: restart data must be exactly {expected} samples ({RESTART_DIM}x{RESTART_DIM}); got {}",
            data.len()
        );
        return ExitCode::FAILURE;
    }

    // `restart_analysis`'s `# Panics` section says the CLI rejects degenerate
    // matrices before calling. It did not: a constant 1,000,000-byte matrix — what
    // a stuck noise source produces — reached `simulate_bound` and tripped its
    // debug assert (exit 101, no verdict), while release builds silently computed
    // a cutoff from `k_effective > k`. These two checks make that sentence true.
    if let Some(reason) = restart_input_rejection(alphabet_size(&data), h_i) {
        eprintln!("maxwell: {reason}");
        return ExitCode::FAILURE;
    }

    let r = restart_analysis(
        &data,
        bits,
        h_i,
        RESTART_DIM,
        RESTART_DIM,
        DEFAULT_SIMULATION_ROUNDS,
        PERMS,
    );

    println!("{file}  ({RESTART_DIM}x{RESTART_DIM} matrix, {bits} bits/symbol)");
    println!("H_I: {h_i}");
    println!("ALPHA: {:.17}, X_cutoff: {}", r.alpha, r.x_cutoff);
    println!("X_r: {}", r.x_r);
    println!("X_c: {}", r.x_c);
    println!("X_max: {}", r.x_max);
    println!(
        "Restart Sanity Check: {}",
        if r.sanity_passed { "Passed" } else { "FAILED" }
    );
    println!();
    println!("  §5.1 permutation       [{}]", verdict_mark(r.perm_passed));
    println!(
        "  §5.2 chi-square        [{}]",
        verdict_mark(r.chi_square_passed)
    );
    println!("  §5.3 LRS               [{}]", verdict_mark(r.lrs_passed));
    println!("  IID: {}", if r.is_iid { "yes" } else { "no" });
    println!();
    println!("H_r: {:.17}", r.h_r);
    println!("H_c: {:.17}", r.h_c);
    println!("H_I: {:.17}", r.h_i);
    println!();
    println!(
        "Validation Test: {}",
        if r.validation_passed {
            "Passed"
        } else {
            "FAILED"
        }
    );
    println!("min(H_r, H_c, H_I): {:.17}", r.min_entropy);

    let (accepted, lines) = restart_verdict(&r);
    for line in &lines {
        println!("{line}");
    }
    if accepted {
        ExitCode::SUCCESS
    } else {
        for line in &lines {
            eprintln!("{line}");
        }
        ExitCode::FAILURE
    }
}

/// Print the closing verdict for a restart analysis and report whether the data
/// is accepted as §3.1.4.2 validation evidence.
///
/// Split out from [`cmd_restart`] so the exit decision is reachable by a test:
/// driving it through the binary would mean a 1,000,000-sample analysis, which
/// runs for minutes and cannot sit in the suite.
///
/// The convention is `cmd_gate`'s and ISC-146's — a printed FAILED is a non-zero
/// exit. Restart analysis is a CMVP submission artifact, so a caller scripting
/// the evidence run must not have to parse stdout to learn it was rejected.
///
/// `validation_passed` already subsumes `sanity_passed` (§3.1.4.2 requires the
/// sanity check to have held), so it alone is the decision; the bullets below
/// exist to name *which* check rejected the data, and each is predicated on its
/// own condition rather than on the combined verdict.
/// Why a restart matrix must be refused before analysis, or `None` to proceed.
///
/// [`restart_analysis`]'s `# Panics` section states that the CLI rejects
/// degenerate matrices before calling. It did not: a constant 1,000,000-byte
/// matrix — what a stuck noise source produces — reached `simulate_bound` and
/// tripped its debug assert (exit 101, no verdict at all), while a release build
/// silently computed a cutoff from `k_effective > k`. These two checks make that
/// sentence true, and live here rather than inline so both are testable without a
/// 1,000,000-sample analysis.
#[must_use]
fn restart_input_rejection(alphabet: usize, h_i: f64) -> Option<String> {
    if alphabet <= 1 {
        return Some(format!(
            "restart matrix has {alphabet} distinct symbol(s); the §3.1.4.3 cutoff is undefined \
             for an alphabet of one. A constant matrix is itself the finding — the noise source \
             produced no variation."
        ));
    }
    // `k_effective = ceil(2^H_I)` must fit inside the observed alphabet, or the
    // Monte-Carlo cutoff is drawn over symbols the data never contained.
    let k_effective = 2.0_f64.powf(h_i).ceil();
    // `alphabet_size` counts distinct u8 values, so it is at most 256 and the
    // widening through u16 is lossless — no precision cast on the comparison.
    let alphabet_f = f64::from(u16::try_from(alphabet).unwrap_or(u16::MAX));
    if k_effective > alphabet_f {
        return Some(format!(
            "H_I {h_i} implies at least {k_effective:.0} equiprobable symbols, but the matrix \
             contains only {alphabet}; the §3.1.4.3 cutoff would be drawn over symbols the data \
             never contained. Lower H_I, or supply data over a wider alphabet."
        ));
    }
    None
}

#[must_use]
fn restart_verdict(r: &RestartResult) -> (bool, Vec<String>) {
    if r.validation_passed {
        return (
            true,
            vec![
                "verdict: PASS — §3.1.4.3 sanity and the §3.1.4.2 validation gate both hold"
                    .to_owned(),
            ],
        );
    }

    let mut lines =
        vec!["verdict: FAIL — the following restart check(s) rejected the data:".to_owned()];
    if !r.sanity_passed {
        lines.push(format!(
            "  - §3.1.4.3 restart sanity check: X_max {} exceeds the cutoff {}",
            r.x_max, r.x_cutoff
        ));
    }
    let h_min = r.h_r.min(r.h_c);
    // The literal complement of the gate (`min_rc >= h_i / 2.0`), spelled through
    // `partial_cmp` so the incomparable case is explicit rather than hidden in a
    // negation. `h_min < h_i / 2.0` would NOT be the complement: under a NaN both
    // it and the gate are false, printing a FAIL header with no cause beneath it —
    // a verdict that names nothing. `cmd_restart` now rejects a non-finite H_I at
    // parse, so this is belt and braces; it stays because the header must never be
    // causeless.
    if !matches!(
        h_min.partial_cmp(&(r.h_i / 2.0)),
        Some(Ordering::Greater | Ordering::Equal)
    ) {
        lines.push(format!(
            "  - §3.1.4.2 validation gate: min(H_r, H_c) = {h_min:.17} is below H_I/2 = {:.17}",
            r.h_i / 2.0
        ));
    }
    (false, lines)
}

/// Render a PASS/FAIL tick for the §5 sub-test verdict lines.
fn verdict_mark(pass: bool) -> &'static str {
    if pass { "PASS" } else { "FAIL" }
}

/// Index of the compression statistic (mirrors `permutation::COMPRESSION_IDX`,
/// which is private). Retained as documentation of the slot index; compression
/// is now computed and displayed like every other statistic, so it no longer
/// drives any special-case display branch.
#[allow(dead_code)]
const COMPRESSION_INDEX: usize = 18;

#[cfg(test)]
#[allow(
    // Tests assert exact verdict decisions on constructed results.
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    // ---- maxwell parity: all four quadrants of the verdict ----

    fn verdict(passed: usize, skipped: usize, failed: usize) -> Verdict {
        Verdict {
            passed,
            skipped,
            failed,
        }
    }

    /// The branch that carries the Security Policy's parity claim. It is
    /// unreachable in CI (no EA bundle, #153), so without this it would be the
    /// one branch never probed.
    #[test]
    fn parity_verdict_full_run_is_accepted_and_is_evidence() {
        let (accepted, evidence, line) = parity_verdict(&verdict(11, 0, 0), 11, &[], false);
        assert!(accepted, "a full-strength run must exit zero: {line}");
        assert!(
            evidence,
            "a full-strength run is the parity evidence: {line}"
        );
        assert!(line.contains("PASS") && line.contains("this run is parity evidence"));
    }

    /// The defect #154 closes: nothing compared, yet reported as success.
    #[test]
    fn parity_verdict_all_skip_is_rejected() {
        let (accepted, evidence, line) = parity_verdict(&verdict(0, 11, 0), 11, &["a", "b"], false);
        assert!(!accepted, "an all-skip run must exit non-zero: {line}");
        assert!(!evidence);
        assert!(line.contains("INCOMPLETE") && line.contains("NOT parity evidence"));
        assert!(
            line.contains("a, b"),
            "must name the absent datasets: {line}"
        );
    }

    /// Accepted and NOT evidence are different properties; the opt-out separates
    /// them. Nothing may infer coverage from the exit code alone.
    #[test]
    fn parity_verdict_opt_out_is_accepted_but_is_not_evidence() {
        let (accepted, evidence, line) = parity_verdict(&verdict(3, 8, 0), 11, &["a"], true);
        assert!(accepted, "the opt-out accepts a partial run: {line}");
        assert!(
            !evidence,
            "an opted-out partial run must never be evidence: {line}"
        );
        assert!(line.contains("PARTIAL") && line.contains("NOT parity evidence"));
    }

    /// A failure outranks the opt-out: opting into a partial suite must not
    /// launder a dataset that actually disagreed.
    #[test]
    fn parity_verdict_failure_outranks_the_opt_out() {
        let (accepted, evidence, line) = parity_verdict(&verdict(9, 1, 1), 11, &["a"], true);
        assert!(!accepted, "a failed dataset must exit non-zero: {line}");
        assert!(!evidence);
        assert!(line.contains("FAIL"));
    }

    /// `Outcome::Fail` also covers provenance mismatch, an unreadable file, and
    /// module power-up failure — the line must not assert a numeric disagreement
    /// that may never have been computed.
    #[test]
    fn parity_verdict_failure_line_does_not_assert_a_cause_it_cannot_know() {
        let (_, _, line) = parity_verdict(&verdict(0, 10, 1), 11, &[], false);
        assert!(
            !line.contains("disagreed"),
            "FAIL line must not name a cause it cannot know: {line}"
        );
        assert!(
            line.contains("see the FAIL lines above"),
            "FAIL line must defer to the per-dataset reasons: {line}"
        );
        assert!(
            line.contains("10 absent"),
            "FAIL line must not silently drop the skips: {line}"
        );
    }

    /// An empty result set has nothing skipped, which `skipped == 0` alone would
    /// call full-strength — ISC-146's defect re-armed behind a future filter flag.
    #[test]
    fn parity_verdict_empty_run_is_not_full_strength() {
        let v = verdict(0, 0, 0);
        assert!(!v.complete(), "an empty run compared nothing");
        assert!(!v.full_strength());
        let (accepted, evidence, line) = parity_verdict(&v, 0, &[], false);
        assert!(!accepted, "a run over zero datasets must not pass: {line}");
        assert!(!evidence);
    }

    // ---- maxwell restart ----

    /// The panic this closes: a constant matrix reached `simulate_bound` and
    /// tripped `debug_assert!(k > 1)`, exiting 101 with no verdict.
    #[test]
    fn restart_rejects_a_degenerate_alphabet() {
        let reason = restart_input_rejection(1, 0.9).expect("alphabet of one must be refused");
        assert!(reason.contains("distinct symbol"), "{reason}");
        assert!(
            restart_input_rejection(0, 0.9).is_some(),
            "an empty alphabet must be refused too"
        );
    }

    /// The other half: `k_effective = ceil(2^H_I)` must fit inside the alphabet.
    #[test]
    fn restart_rejects_an_initial_entropy_the_alphabet_cannot_support() {
        let reason = restart_input_rejection(2, 7.0).expect("H_I 7.0 needs 128 symbols, not 2");
        assert!(
            reason.contains("128") && reason.contains("only 2"),
            "{reason}"
        );
        // The boundary must be inclusive: ceil(2^0.9) == 2 fits an alphabet of 2.
        assert!(
            restart_input_rejection(2, 0.9).is_none(),
            "k_effective == alphabet must be accepted, not refused"
        );
        assert!(
            restart_input_rejection(256, 8.0).is_none(),
            "a full byte alphabet must support H_I = 8"
        );
    }

    /// A restart result that passes everything, as the baseline to mutate.
    fn accepted_result() -> RestartResult {
        RestartResult {
            alpha: 0.000_009_9,
            x_r: 10,
            x_c: 10,
            x_max: 10,
            x_cutoff: 20,
            sanity_passed: true,
            perm_passed: true,
            chi_square_passed: true,
            lrs_passed: true,
            is_iid: true,
            h_r: 7.5,
            h_c: 7.5,
            h_i: 7.0,
            validation_passed: true,
            min_entropy: 7.0,
        }
    }

    #[test]
    fn restart_verdict_accepts_a_passing_analysis() {
        let (accepted, lines) = restart_verdict(&accepted_result());
        assert!(accepted);
        assert!(lines.iter().any(|l| l.contains("PASS")), "{lines:?}");
    }

    /// The defect this closes: `cmd_restart` printed FAILED and returned SUCCESS.
    #[test]
    fn restart_verdict_rejects_a_failed_validation_gate() {
        let mut r = accepted_result();
        r.validation_passed = false;
        r.h_r = 1.0;
        r.h_c = 1.0;
        let (accepted, lines) = restart_verdict(&r);
        assert!(!accepted);
        assert!(
            lines.iter().any(|l| l.contains("§3.1.4.2 validation gate")),
            "must name the entropy cause: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("§3.1.4.3 restart sanity")),
            "sanity held; that bullet must stay silent: {lines:?}"
        );
    }

    /// A sanity failure forces `validation_passed` false upstream. The verdict
    /// must reject it and must NOT also claim the entropy comparison failed.
    #[test]
    fn restart_verdict_names_only_the_cause_that_fired() {
        let mut r = accepted_result();
        r.sanity_passed = false;
        r.validation_passed = false;
        r.x_max = 99;
        // H_r/H_c stay healthy: min = 7.5 >= H_I/2 = 3.5.
        let (accepted, lines) = restart_verdict(&r);
        assert!(!accepted);
        assert!(
            lines.iter().any(|l| l.contains("§3.1.4.3 restart sanity")),
            "must name the sanity cause: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("§3.1.4.2 validation gate")),
            "entropy comparison held; asserting it failed would be false: {lines:?}"
        );
    }

    /// A FAIL header with no cause under it names nothing. Both predicates are
    /// false under a NaN H_I, which is why the entropy bullet is written as the
    /// literal complement of the gate.
    #[test]
    fn restart_verdict_fail_header_always_has_a_cause() {
        let mut r = accepted_result();
        r.validation_passed = false;
        r.h_i = f64::NAN;
        let (accepted, lines) = restart_verdict(&r);
        assert!(!accepted);
        assert!(
            lines.len() > 1,
            "FAIL header must never stand alone: {lines:?}"
        );
    }
}
