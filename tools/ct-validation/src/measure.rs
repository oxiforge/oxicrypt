//! Paired fixed-vs-random measurement driver.
//!
//! The harness is generic over a [`TargetFn`] closure that, given a
//! secret input byte slice, runs the primitive once and returns. Each
//! iteration draws a class bit from a xorshift PRNG, prepares the input
//! of that class, and reads a counter immediately before and after one
//! call of the target.
//!
//! On `x86_64` the counter is the time-stamp counter, read with `RDTSC`
//! between two `LFENCE`s. The fence before the read holds the read until
//! every earlier instruction has completed, so neither the input
//! preparation (before `t0`) nor the target (before `t1`) is still
//! executing when the counter is read. The fence after the read holds
//! every later instruction until the read has completed, so the target
//! does not start before `t0`. `LFENCE` does not drain the store buffer
//! and does not reset branch history. Elsewhere the counter is
//! `std::time::Instant` in nanoseconds.
//!
//! Sampling is class-independent: every iteration draws random bytes,
//! selects the input from the fixed or the random bytes with a byte mask
//! rather than a branch, and records the class beside the count, which
//! is split into the two classes only after the loop. The fences leave
//! the store buffer and branch history as the preparation left them, so
//! a class-dependent branch or store before `t0` would be measured as a
//! difference between the classes. With a class-dependent preparation,
//! a target that gives both classes the same instructions on the same
//! data reported a leak in 7 of 10 runs.
//!
//! The counter is not cycle-accurate under frequency scaling. The two
//! classes are interleaved in one loop, so a drift in frequency affects
//! both.

use crate::stats::{Verdict, VerdictReport, cropped_report};

/// Least sample budget of the single re-run `--strict` gives a target
/// whose first verdict is [`Verdict::Warn`].
pub const STRICT_RERUN_SAMPLES: usize = 500_000;

/// Added to the seed of a `--strict` re-run, so that the re-run draws a
/// class schedule and random inputs independent of the first run's.
pub const STRICT_RERUN_SEED_OFFSET: u64 = 0x9e37_79b9_7f4a_7c15;

/// The configuration of the `--strict` re-run after a first run under
/// `cfg`: [`STRICT_RERUN_SAMPLES`] or `cfg.samples`, whichever is larger,
/// and the seed offset by [`STRICT_RERUN_SEED_OFFSET`].
#[must_use]
pub fn strict_rerun_config(cfg: &RunConfig) -> RunConfig {
    RunConfig {
        samples: cfg.samples.max(STRICT_RERUN_SAMPLES),
        seed: cfg.seed.wrapping_add(STRICT_RERUN_SEED_OFFSET),
        ..cfg.clone()
    }
}

/// Target primitive wrapper. The harness calls this once per
/// measurement, passing whichever secret the class dictates.
/// The closure must perform *exactly* the work being measured —
/// no allocation, no Box, no dyn call per invocation — because
/// any extra work on the measurement hot path contributes to
/// variance.
///
/// The `&[u8]` argument is whatever "secret input" means for this
/// target. For `mont2048::pow_secret` it's a 256-byte secret
/// exponent. For `p256_point::mul` it's a 32-byte secret scalar.
/// For OAEP decode it's a 96-byte seed-and-plaintext pair, from which
/// the target builds the encoded message.
pub type TargetFn<'a> = Box<dyn FnMut(&[u8]) + 'a>;

/// Parameters for one [`run_target`] invocation.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Total measurements to collect (split evenly between the two
    /// classes). Must be ≥ 16.
    pub samples: usize,
    /// Number of untimed warm-up iterations per class before
    /// measurement begins. Helps the CPU's branch predictor and
    /// i-cache settle so the first 100 samples aren't systematically
    /// faster or slower than the rest.
    pub warmup: usize,
    /// Deterministic RNG seed for class selection and for the
    /// random-class secret bytes. Same seed → same measurement
    /// schedule, which is important for reproducing a suspicious
    /// run.
    pub seed: u64,
}

impl Default for RunConfig {
    fn default() -> RunConfig {
        RunConfig {
            samples: 100_000,
            warmup: 1_000,
            seed: 0x00C0_FFEE_DEAD_BEEF,
        }
    }
}

/// A single paired measurement: class tag and timing counter.
#[derive(Debug, Clone, Copy)]
pub struct Measurement {
    /// `0` = fixed class, `1` = random class.
    pub class: u8,
    /// Cycle / tick count for the single measured call.
    pub ticks: u64,
}

/// xorshift64\*: small, fast, deterministic. We use this as a class-
/// selection PRNG and also to fill the random-class secret bytes.
/// `seed` must be non-zero.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> XorShift64 {
        let s = if seed == 0 {
            0xdead_beef_cafe_babe
        } else {
            seed
        };
        XorShift64 { state: s }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let w = self.next_u64().to_le_bytes();
            let take = core::cmp::min(8, buf.len() - i);
            buf[i..i + take].copy_from_slice(&w[..take]);
            i += take;
        }
    }

    /// Return 0 or 1 with equal probability.
    fn next_class(&mut self) -> u8 {
        (self.next_u64() & 1) as u8
    }
}

/// Read the cycle counter. Kept as a small inlineable helper so
/// its wrapper call doesn't show up in every measurement budget.
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: LFENCE and RDTSC are available on every x86_64 CPU
        // oxicrypt targets. The fences order the read against the
        // surrounding instructions, as the module header describes.
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback to nanoseconds-since-epoch-of-this-process.
        use std::sync::OnceLock;
        use std::time::Instant;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let t0 = EPOCH.get_or_init(Instant::now);
        Instant::now().duration_since(*t0).as_nanos() as u64
    }
}

/// Builds a random-class input from PRNG bytes: the first argument is
/// that many fresh PRNG bytes, the second the input to fill, both the
/// length of the fixed-class secret.
pub type DrawFn<'a> = Box<dyn FnMut(&[u8], &mut [u8]) + 'a>;

/// Drive a measurement pass over `target` and return the cropped
/// report.
///
/// `fixed_secret` is the fixed-class secret; it's passed to `target`
/// unchanged every time the class bit is 0. When the class bit is 1
/// the target receives fresh PRNG bytes of the same length. The target
/// is responsible for whatever "interpret these bytes as a secret"
/// means for it (Scalar::from_bytes, U2048::from_be_bytes, whatever).
pub fn run_target(
    name: &'static str,
    fixed_secret: &[u8],
    target: TargetFn<'_>,
    cfg: &RunConfig,
) -> VerdictReport {
    let copy: DrawFn<'_> = Box::new(|raw, input| input.copy_from_slice(raw));
    run_target_drawn(name, fixed_secret, copy, target, cfg)
}

/// [`run_target`] with the random-class input built by `draw` from the
/// PRNG bytes, for a target whose random class is a distribution other
/// than uniform bytes. `draw` runs on every iteration, of either class,
/// before the counter is read.
pub fn run_target_drawn(
    name: &'static str,
    fixed_secret: &[u8],
    mut draw: DrawFn<'_>,
    mut target: TargetFn<'_>,
    cfg: &RunConfig,
) -> VerdictReport {
    assert!(cfg.samples >= 16, "sample count too low");
    let mut rng = XorShift64::new(cfg.seed);

    // Crucial dudect hygiene: both classes must feed the target
    // through the **same memory buffer**. If we passed the fixed
    // class a `.rodata` slice and the random class a stack slice,
    // the differing cache-line residency alone would inflate
    // |t| to ~100 sigma on primitives that are otherwise perfectly
    // constant-time. We instead keep one `working_buf` that is
    // rewritten on every iteration — with `fixed_secret`'s bytes
    // on fixed-class iterations, with PRNG bytes on random-class
    // iterations — and pass `&working_buf` to the target both
    // times. The address is identical, so cache / TLB behaviour is
    // symmetric between the two classes.
    let mut working_buf = vec![0u8; fixed_secret.len()];
    // The random-class input is built here on every iteration and reaches
    // `working_buf` through the same byte select as the fixed class.
    // Drawn straight into `working_buf`, PRNG bytes arrive as 8-byte
    // stores, and a target's first 16-byte load of them cannot be
    // forwarded from the store buffer; that stall fell in the random class
    // only and was measured as a leak at two of four seeds on a
    // shift-and-XOR target.
    let mut raw_buf = vec![0u8; fixed_secret.len()];
    let mut random_buf = vec![0u8; fixed_secret.len()];

    // Warm-up: untimed random-class calls to settle the branch
    // predictor and warm the i-cache.
    for _ in 0..cfg.warmup {
        rng.fill_bytes(&mut raw_buf);
        draw(&raw_buf, &mut random_buf);
        working_buf.copy_from_slice(&random_buf);
        target(&working_buf);
    }

    // Class-independent sampling; the module header gives the reason.
    let mut measurements: Vec<Measurement> = Vec::with_capacity(cfg.samples);
    for _ in 0..cfg.samples {
        let class = rng.next_class();
        rng.fill_bytes(&mut raw_buf);
        draw(&raw_buf, &mut random_buf);
        let mask = std::hint::black_box(0u8.wrapping_sub(class));
        for ((w, f), r) in working_buf.iter_mut().zip(fixed_secret).zip(&random_buf) {
            *w = (f & !mask) | (r & mask);
        }

        // `black_box` keeps the compiler from moving the target across
        // the counter reads; `read_tsc` fences them in the processor.
        let secret_ref: &[u8] = std::hint::black_box(&working_buf);
        let t0 = read_tsc();
        target(secret_ref);
        let t1 = read_tsc();
        std::hint::black_box(&t1);

        measurements.push(Measurement {
            class,
            ticks: t1.wrapping_sub(t0),
        });
    }

    let mut fixed_samples: Vec<f64> = Vec::with_capacity(cfg.samples / 2 + 16);
    let mut random_samples: Vec<f64> = Vec::with_capacity(cfg.samples / 2 + 16);
    for m in &measurements {
        if m.class == 0 {
            fixed_samples.push(m.ticks as f64);
        } else {
            random_samples.push(m.ticks as f64);
        }
    }

    cropped_report(name, fixed_samples, random_samples)
}

/// Run one target through `run` and return its reports in order; the
/// last one is the target's verdict.
///
/// Under `strict`, a first verdict of [`Verdict::Warn`] is measured once
/// more under [`strict_rerun_config`] and the second report decides, so a
/// second `Warn` fails the run as a `Leak` does. Without `strict`, or on
/// a first `Clean` or `Leak`, the single report stands.
pub fn run_with_policy(
    cfg: &RunConfig,
    strict: bool,
    mut run: impl FnMut(&RunConfig) -> VerdictReport,
) -> Vec<VerdictReport> {
    let first = run(cfg);
    let rerun = strict && first.verdict == Verdict::Warn;
    let mut reports = vec![first];
    if rerun {
        reports.push(run(&strict_rerun_config(cfg)));
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(verdict: Verdict) -> VerdictReport {
        VerdictReport {
            target: "fixture",
            n_per_class: 8,
            worst_abs_t: 0.0,
            worst_crop: 1.0,
            verdict,
        }
    }

    /// Feeds `verdicts` to [`run_with_policy`] under `cfg`, one per call,
    /// and returns the final verdict and the sample budget and seed of
    /// every call made.
    fn drive_with(
        cfg: &RunConfig,
        strict: bool,
        verdicts: &[Verdict],
    ) -> (Verdict, Vec<(usize, u64)>) {
        let mut calls = Vec::new();
        let mut next = verdicts.iter();
        let reports = run_with_policy(cfg, strict, |c| {
            calls.push((c.samples, c.seed));
            report(*next.next().unwrap())
        });
        (reports.last().unwrap().verdict, calls)
    }

    fn drive(strict: bool, verdicts: &[Verdict]) -> (Verdict, Vec<(usize, u64)>) {
        drive_with(&RunConfig::default(), strict, verdicts)
    }

    #[test]
    fn strict_reruns_a_warn_once_at_the_wider_budget_and_a_new_seed() {
        let first = RunConfig::default();
        let rerun = (
            STRICT_RERUN_SAMPLES,
            first.seed.wrapping_add(STRICT_RERUN_SEED_OFFSET),
        );
        let calls = vec![(first.samples, first.seed), rerun];
        assert_ne!(rerun.1, first.seed);
        assert_eq!(
            drive(true, &[Verdict::Warn, Verdict::Clean]),
            (Verdict::Clean, calls.clone())
        );
        assert_eq!(
            drive(true, &[Verdict::Warn, Verdict::Warn, Verdict::Clean]),
            (Verdict::Warn, calls.clone())
        );
        assert_eq!(
            drive(true, &[Verdict::Warn, Verdict::Leak]),
            (Verdict::Leak, calls)
        );
    }

    #[test]
    fn strict_rerun_keeps_a_budget_above_the_floor() {
        let cfg = RunConfig {
            samples: 2 * STRICT_RERUN_SAMPLES,
            ..RunConfig::default()
        };
        let (_, calls) = drive_with(&cfg, true, &[Verdict::Warn, Verdict::Clean]);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, 2 * STRICT_RERUN_SAMPLES);
    }

    #[test]
    fn clean_leak_and_non_strict_runs_are_not_repeated() {
        let default = RunConfig::default();
        for (strict, v) in [
            (true, Verdict::Clean),
            (true, Verdict::Leak),
            (false, Verdict::Warn),
            (false, Verdict::Clean),
        ] {
            assert_eq!(
                drive(strict, &[v, Verdict::Clean]),
                (v, vec![(default.samples, default.seed)])
            );
        }
    }

    /// Every input the target receives is the fixed secret or a drawn
    /// one, and both classes occur.
    #[test]
    fn target_sees_the_fixed_secret_and_drawn_inputs() {
        let seen = std::cell::RefCell::new(Vec::new());
        let draw: DrawFn<'_> = Box::new(|raw, input| {
            input.copy_from_slice(raw);
            input[0] |= 1;
        });
        let target: TargetFn<'_> = Box::new(|s| seen.borrow_mut().push(s.to_vec()));
        let cfg = RunConfig {
            samples: 64,
            warmup: 0,
            seed: 7,
        };
        let _ = run_target_drawn("fixture", &[0u8, 0], draw, target, &cfg);
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 64);
        let fixed = seen.iter().filter(|s| s.as_slice() == [0, 0]).count();
        let drawn = seen.iter().filter(|s| s[0] & 1 == 1).count();
        assert!(fixed > 0 && drawn > 0);
        assert_eq!(fixed + drawn, 64);
    }
}
