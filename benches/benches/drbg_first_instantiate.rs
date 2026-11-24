//! Measures the first `HmacDrbgSha256::instantiate_from_module` in a fresh
//! process, 20 samples, and checks it against the startup budget.
//!
//! The first instantiate in a process decides the seed path and, on the
//! assessed path, starts the entropy source, so every later instantiate in
//! the same process is cheaper and measures something else. Each sample is
//! therefore a fresh run of the helper binary `drbg-first-instantiate-probe`.
//! The bench prints the median and maximum instantiate time, the seed path
//! and label (which must agree across all samples), the median time of the
//! seed path's 2^24-iteration lock spin bound, and the ratio of that spin
//! time to the longest instantiate. It exits 1 when the median exceeds
//! 2000 ms, the maximum exceeds 4000 ms, or the spin time is under sixteen
//! times the longest instantiate.
//!
//! Test hook: `DRBG_FIRST_INSTANTIATE_BUDGET_MS` overrides the 2000 ms
//! median budget, so a small value shows the failing exit.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    missing_docs
)]

use std::process::{Command, ExitCode};

const PROBE: &str = env!("CARGO_BIN_EXE_drbg-first-instantiate-probe");
const SAMPLES: usize = 20;
const MEDIAN_BUDGET_MS: f64 = 2000.0;
const MAX_BUDGET_MS: f64 = 4000.0;
const SPIN_MARGIN: f64 = 16.0;

struct Sample {
    instantiate_ms: f64,
    spin_ms: f64,
    path: String,
    label: String,
}

fn parse(line: &str) -> Result<Sample, String> {
    let (head, label) = line
        .split_once(" label=")
        .ok_or_else(|| format!("no label in {line:?}"))?;
    let mut instantiate_ms = None;
    let mut spin_ms = None;
    let mut path = None;
    for field in head.split_whitespace() {
        match field.split_once('=') {
            Some(("instantiate_ms", v)) => instantiate_ms = v.parse::<f64>().ok(),
            Some(("spin_ms", v)) => spin_ms = v.parse::<f64>().ok(),
            Some(("path", v)) => path = Some(v.to_owned()),
            _ => return Err(format!("unexpected field {field:?} in {line:?}")),
        }
    }
    Ok(Sample {
        instantiate_ms: instantiate_ms.ok_or_else(|| format!("no instantiate_ms in {line:?}"))?,
        spin_ms: spin_ms.ok_or_else(|| format!("no spin_ms in {line:?}"))?,
        path: path.ok_or_else(|| format!("no path in {line:?}"))?,
        label: label.to_owned(),
    })
}

fn run_probe() -> Result<Sample, String> {
    let out = Command::new(PROBE)
        .output()
        .map_err(|e| format!("cannot run {PROBE}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "probe exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(out.stdout).map_err(|e| format!("probe output: {e}"))?;
    parse(stdout.trim())
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    let half = n >> 1;
    if n % 2 == 1 {
        values[half]
    } else {
        f64::midpoint(values[half - 1], values[half])
    }
}

fn median_budget_ms() -> Result<f64, String> {
    match std::env::var("DRBG_FIRST_INSTANTIATE_BUDGET_MS") {
        Ok(v) => v
            .parse::<f64>()
            .map_err(|e| format!("DRBG_FIRST_INSTANTIATE_BUDGET_MS={v:?}: {e}")),
        Err(_) => Ok(MEDIAN_BUDGET_MS),
    }
}

fn run() -> Result<bool, String> {
    let median_budget = median_budget_ms()?;
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        samples.push(run_probe()?);
    }

    let first = &samples[0];
    if let Some(s) = samples
        .iter()
        .find(|s| s.path != first.path || s.label != first.label)
    {
        return Err(format!(
            "seed path differs between samples: {} ({}) and {} ({})",
            first.path, first.label, s.path, s.label
        ));
    }

    let mut inst: Vec<f64> = samples.iter().map(|s| s.instantiate_ms).collect();
    let mut spin: Vec<f64> = samples.iter().map(|s| s.spin_ms).collect();
    let inst_median = median(&mut inst);
    let inst_max = inst.iter().copied().fold(f64::MIN, f64::max);
    let spin_median = median(&mut spin);
    let ratio = spin_median / inst_max;

    println!("drbg_first_instantiate ({SAMPLES} fresh processes)");
    println!("  path                  {}", first.path);
    println!("  label                 {}", first.label);
    println!("  instantiate median    {inst_median:.3} ms (budget {median_budget} ms)");
    println!("  instantiate max       {inst_max:.3} ms (budget {MAX_BUDGET_MS} ms)");
    println!("  spin 2^24 median      {spin_median:.3} ms");
    println!("  spin / max instantiate {ratio:.2} (required >= {SPIN_MARGIN})");

    let mut ok = true;
    if inst_median > median_budget {
        println!("FAIL: median {inst_median:.3} ms exceeds {median_budget} ms");
        ok = false;
    }
    if inst_max > MAX_BUDGET_MS {
        println!("FAIL: maximum {inst_max:.3} ms exceeds {MAX_BUDGET_MS} ms");
        ok = false;
    }
    if spin_median < SPIN_MARGIN * inst_max {
        println!(
            "FAIL: spin bound {spin_median:.3} ms is under {SPIN_MARGIN} x the longest instantiate ({inst_max:.3} ms); raise the bound"
        );
        ok = false;
    }
    Ok(ok)
}

fn main() -> ExitCode {
    // `cargo bench` passes `--bench` and filter arguments; none apply here.
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("drbg_first_instantiate: {e}");
            ExitCode::FAILURE
        }
    }
}
