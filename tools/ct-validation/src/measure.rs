//! Paired fixed-vs-random measurement driver.
//!
//! The harness is generic over a [`TargetFn`] closure that, given a
//! secret input byte slice, runs the primitive once and returns. The
//! driver wraps each call with a timing counter, reads a
//! deterministic-class bit from a xorshift PRNG to decide whether
//! the call should use the fixed or random secret, and pushes the
//! measurement into the matching bucket.
//!
//! Two timing sources are supported:
//!
//! - On `x86_64`, we use `core::arch::x86_64::_rdtsc()` via a safe
//!   wrapper. This reads the time-stamp counter directly; it's much
//!   finer-grained than `Instant::now()` on Linux and what the
//!   original dudect paper used.
//! - On everything else (aarch64 on Apple Silicon, for example) we
//!   fall back to `std::time::Instant::now()` in nanoseconds.
//!
//! We do **not** claim cycle-accurate measurements on systems with
//! dynamic frequency scaling or TSO — but the t-test only cares
//! about relative differences between two classes measured in the
//! same interleaved loop, so frequency drift affects both classes
//! symmetrically and washes out.

use crate::stats::{cropped_report, VerdictReport};

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
/// For OAEP decode it's a 256-byte encoded message.
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
        let s = if seed == 0 { 0xdead_beef_cafe_babe } else { seed };
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
        // SAFETY: _rdtsc is available on all x86_64 CPUs pqclib is
        // targeted at. We don't need CPUID serialisation — dudect
        // explicitly tolerates the small jitter it introduces
        // because the t-test averages over millions of samples.
        core::arch::x86_64::_rdtsc()
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

/// Drive a measurement pass over `target` and return the cropped
/// report.
///
/// `fixed_secret` is the fixed-class secret; it's passed to `target`
/// unchanged every time the class bit is 0. When the class bit is 1
/// the harness fills a freshly-allocated buffer of the same length
/// from its PRNG and passes that to `target`. The target is
/// responsible for whatever "interpret these bytes as a secret"
/// means for it (Scalar::from_bytes, U2048::from_be_bytes, whatever).
pub fn run_target(
    name: &'static str,
    fixed_secret: &[u8],
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

    // Warm-up: untimed random-class calls to settle the branch
    // predictor and warm the i-cache.
    for _ in 0..cfg.warmup {
        rng.fill_bytes(&mut working_buf);
        target(&working_buf);
    }

    let mut fixed_samples: Vec<f64> = Vec::with_capacity(cfg.samples / 2 + 16);
    let mut random_samples: Vec<f64> = Vec::with_capacity(cfg.samples / 2 + 16);

    for _ in 0..cfg.samples {
        let class = rng.next_class();
        if class == 0 {
            // Rewrite the buffer with the fixed secret every call.
            // Even though the content is identical on every
            // fixed-class iteration, we go through the same write
            // as the random class so the store-buffer / write-
            // combining pattern matches.
            working_buf.copy_from_slice(fixed_secret);
        } else {
            rng.fill_bytes(&mut working_buf);
        }

        // Fence around the timed region. This is a measurement
        // barrier in the "logical" sense — we want the compiler to
        // not reorder reads of `start`/`end` across `target(...)`.
        // We don't use an actual mfence because dudect tolerates
        // out-of-order execution.
        let secret_ref: &[u8] = std::hint::black_box(&working_buf);
        let t0 = read_tsc();
        target(secret_ref);
        let t1 = read_tsc();
        std::hint::black_box(&t1);

        let ticks = t1.wrapping_sub(t0);
        if class == 0 {
            fixed_samples.push(ticks as f64);
        } else {
            random_samples.push(ticks as f64);
        }
    }

    cropped_report(name, fixed_samples, random_samples)
}
