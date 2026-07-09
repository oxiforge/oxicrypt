//! Lightweight **FFT + autocorrelation periodicity screen** for raw entropy
//! datasets (SP 800-90B pilot acceptance, ISC-133).
//!
//! This module is a *screen*, not a NIST-specified statistic. Its job is the
//! minimal-pilot question: does the raw 1M-sample dataset we intend to certify
//! show a **dominant deterministic periodicity**? A clearly periodic noise
//! stream (a stuck oscillator, an aliased clock, a sawtooth artifact) would
//! contaminate any min-entropy claim, so a dominant period **fails pilot
//! acceptance**. The full ≥10M-delta pairs/triplets independence analysis
//! (ISC-120/ISC-121's 2D/3D min-entropy half) is a separate, deferred work item;
//! this screen deliberately rides the cheap 1M pilot data.
//!
//! It is **out of the cryptographic boundary** — pure offline analysis tooling,
//! like the rest of `oxicrypt-maxwell`, and `#![forbid(unsafe_code)]` at the
//! crate level. It produces no security parameters.
//!
//! # Two independent detectors
//!
//! The samples are loaded one symbol per byte and treated as a real-valued
//! signal `x[0..n]` after **mean removal** (subtracting the sample mean kills
//! the DC component so a non-zero baseline is not mistaken for structure). Both
//! detectors share a single radix-2 Cooley–Tukey FFT of the zero-padded signal,
//! so the whole screen is `O(n log n)` — a direct `O(n²)` DFT over 1M samples
//! would be far too slow.
//!
//! 1. **Spectral-peak detector.** From the FFT we form the one-sided power
//!    spectrum (`|X[k]|²`) over the bins `k = SPECTRAL_MIN_BIN ..= n/2` — bin 0
//!    is DC and the lowest few bins are excluded as slow low-frequency drift
//!    rather than a periodic line (see [`SPECTRAL_MIN_BIN`], #102). We flag when
//!    the single largest searched bin dominates the rest of that band — its power
//!    exceeds [`SPECTRAL_PEAK_RATIO`] times the **mean** power over the same band.
//!    A flat (white-noise-like) spectrum has a peak-to-mean ratio near a small
//!    constant; a strong periodic line produces a peak many times the mean.
//!
//! 2. **Autocorrelation detector.** By the Wiener–Khinchin theorem the
//!    autocorrelation is the inverse FFT of the power spectrum. We normalize it
//!    by the zero-lag value (so lag-0 is exactly `1.0`) and flag when the largest
//!    **non-zero-lag** autocorrelation magnitude, over lags `1 ..= maxlag`,
//!    exceeds [`AUTOCORR_PEAK_THRESHOLD`]. A periodic signal exhibits a large
//!    autocorrelation peak at its period (and multiples); aperiodic noise decays
//!    to small values immediately after lag 0.
//!
//! A dataset is **flagged** (fails the screen) when **either** detector trips.
//! Either alone is sufficient evidence of dominant periodicity; requiring both
//! would let a sharp single spectral line that happens to smear in
//! autocorrelation slip through.
//!
//! # Thresholds are engineering choices, not spec constants
//!
//! The two thresholds below are **deliberate engineering choices for a screen**,
//! not values transcribed from SP 800-90B / 90C / an IG (the spec defines no
//! such screen). They are set conservatively to catch *dominant* periodicity
//! while not flagging ordinary noise, and they are expected to be **tuned
//! against real pilot data** once the orinoco collection runs. See each
//! constant's docs for the reasoning, and the crate REVIEW-NEEDED note.
//!
//! # Determinism and panic-freedom
//!
//! The analysis is pure and deterministic: the same input bytes always yield the
//! same [`PeriodicityReport`]. There is no RNG in the production path. The
//! analysis functions never panic — degenerate inputs (empty, single-sample,
//! constant) return a well-defined non-flagging report.

/// Spectral-peak detector threshold: the largest non-DC power-spectrum bin must
/// exceed this multiple of the **mean** non-DC bin power to be called dominant.
///
/// **Engineering choice for a screen, not a spec constant.** Rationale: for an
/// ideal white sequence the expected power is flat across bins, so the
/// peak-to-mean ratio of the periodogram is `O(log n)` (the maximum of many
/// roughly-exponential bins). At `n ≈ 2²⁰` that statistical maximum lands
/// comfortably below ~30, while a genuine periodic line concentrates a large
/// fraction of total power into one bin and drives the ratio into the hundreds
/// or thousands. A factor of **50×** sits well above the white-noise ceiling and
/// well below a true periodic line — a wide, defensible margin for a *dominant*
/// component. Tune against real pilot data (see REVIEW-NEEDED).
pub const SPECTRAL_PEAK_RATIO: f64 = 50.0;

/// Lowest spectrum bin the spectral-peak detector searches — bins below this are
/// excluded from **both** the peak search and the mean-power denominator.
///
/// **Engineering choice for a screen, not a spec constant (#102).** The screen
/// hunts a *dominant periodic line* (a stuck oscillator, an aliased clock). The
/// lowest few bins instead capture **slow low-frequency drift** — a wandering
/// block mean over the record — which is not a repeating period and is already
/// covered by the autocorrelation detector when it is genuinely periodic. On
/// real pilot data that drift concentrated in bins 1–4 and tripped the spectral
/// ratio (peak-to-mean 145–174) despite a clean autocorrelation (~0.07), a false
/// positive. Restricting the spectral search to bins `>= 8` measures peak-vs-mean
/// *within the band the screen is actually about*, so drift no longer masquerades
/// as a line. Excluding these bins from the mean as well as the peak keeps the
/// ratio honest — leaving drift energy in the mean would deflate the ratio and
/// mask a real high-band line.
///
/// **Why 8 and not 5.** The observed drift sat in bins 1–4; 8 is one octave above
/// bin 4, a deliberate margin so drift leaking a bin or two still falls inside the
/// excluded band. The cost of that margin — a genuine periodic *line* whose
/// fundamental lands in bins 1–7 is now invisible to **this** detector — is
/// covered by the autocorrelation detector, which is left in place precisely as
/// the low-order backstop: a dominant slow line is highly self-correlated at short
/// lags (a bin-k line peaks the normalized autocorrelation near its period
/// `n/k <= n/2`, and often at its half-period, both within the `n/4` lag cap for
/// `k >= 2`), so it trips [`AUTOCORR_PEAK_THRESHOLD`] even though the spectral
/// search skips it. What the spectral floor lets through is exactly the drift case
/// — weak, distributed low-frequency energy that is *not* a dominant line — which
/// is the whole point. See the `low_order_periodic_line_is_caught_by_autocorr_backstop`
/// oracle. Tune against pilot data (see REVIEW-NEEDED).
pub const SPECTRAL_MIN_BIN: usize = 8;

/// Autocorrelation detector threshold: the largest **non-zero-lag** normalized
/// autocorrelation magnitude that is still considered "no dominant period".
///
/// **Engineering choice for a screen, not a spec constant.** Normalized
/// autocorrelation is `1.0` at lag 0 by construction; for aperiodic noise the
/// non-zero-lag values scatter around `0` with magnitude `~1/√n` (here
/// `~1e-3`). A strongly periodic signal shows a non-zero-lag peak approaching
/// `1.0` at its period. **0.5** is half the maximum possible correlation — a
/// signal whose values are half-explained by a fixed-lag copy of themselves is
/// unambiguously dominated by that period, while leaving an enormous margin
/// above the `~1e-3` noise floor. Tune against real pilot data (see
/// REVIEW-NEEDED).
pub const AUTOCORR_PEAK_THRESHOLD: f64 = 0.5;

/// Default cap on the autocorrelation lag range searched, as a fraction of the
/// sample count.
///
/// **Engineering choice.** We search lags `1 ..= n/4`: a "period" longer than a
/// quarter of the record appears fewer than four times and is statistically
/// indistinguishable from a slow trend rather than a *dominant repeating*
/// component, and bounding the lag keeps the post-FFT scan cheap and the verdict
/// stable. Lag 0 is always excluded (it is `1.0` by definition).
pub const MAX_LAG_FRACTION_DENOM: usize = 4;

/// The result of running the periodicity screen on a dataset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeriodicityReport {
    /// Number of samples analyzed (the original, pre-zero-pad length).
    pub n: usize,
    /// FFT size actually used (the next power of two `>= n`, or `0`/`1` for
    /// degenerate inputs that are not analyzed).
    pub fft_size: usize,
    /// Index of the dominant spectrum bin **within the searched band**
    /// (`>= SPECTRAL_MIN_BIN`; `0` when the band is empty or not meaningful).
    pub peak_bin: usize,
    /// Power of the dominant searched bin divided by the mean bin power over the
    /// same `SPECTRAL_MIN_BIN..=n/2` band. `0.0` for a flat/degenerate spectrum.
    pub peak_to_mean_ratio: f64,
    /// Lag (in samples) of the largest non-zero-lag autocorrelation magnitude.
    pub peak_lag: usize,
    /// The largest non-zero-lag **normalized** autocorrelation magnitude in
    /// `[0, 1]` (`0.0` for degenerate inputs).
    pub peak_autocorr: f64,
    /// `true` if the spectral-peak detector tripped
    /// (`peak_to_mean_ratio > SPECTRAL_PEAK_RATIO`).
    pub spectral_flag: bool,
    /// `true` if the autocorrelation detector tripped
    /// (`peak_autocorr > AUTOCORR_PEAK_THRESHOLD`).
    pub autocorr_flag: bool,
}

impl PeriodicityReport {
    /// The dataset is **flagged** (fails the screen) if **either** detector
    /// tripped. A flagged dataset shows a dominant periodic component and fails
    /// pilot acceptance.
    #[must_use]
    pub const fn flagged(&self) -> bool {
        self.spectral_flag || self.autocorr_flag
    }

    /// A non-flagging report for an input too small/degenerate to screen
    /// (`n < 2`). Such inputs carry no period to detect.
    const fn degenerate(n: usize) -> Self {
        Self {
            n,
            fft_size: n,
            peak_bin: 0,
            peak_to_mean_ratio: 0.0,
            peak_lag: 0,
            peak_autocorr: 0.0,
            spectral_flag: false,
            autocorr_flag: false,
        }
    }
}

/// A minimal complex number (`re + i·im`) for the in-place FFT.
///
/// Hand-rolled rather than pulling in a complex-number crate, matching the
/// crate's zero-third-party-dependency posture.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    const ZERO: Self = Self { re: 0.0, im: 0.0 };

    const fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    fn add(self, o: Self) -> Self {
        Self::new(self.re + o.re, self.im + o.im)
    }

    fn sub(self, o: Self) -> Self {
        Self::new(self.re - o.re, self.im - o.im)
    }

    fn mul(self, o: Self) -> Self {
        Self::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }

    /// Squared magnitude `|z|² = re² + im²` — the power-spectrum value.
    fn norm_sq(self) -> f64 {
        self.re * self.re + self.im * self.im
    }
}

/// The smallest power of two `>= n`, saturating (never panics, never wraps).
///
/// Returns `1` for `n <= 1`. For values whose next power of two would overflow
/// `usize` the result saturates at the largest representable power of two; the
/// 1M-sample production path is nowhere near that bound.
fn next_pow2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut p: usize = 1;
    // Stop before shifting out the top bit; saturate at the largest power of two.
    let cap = (usize::MAX >> 1).saturating_add(1);
    while p < n {
        if p >= cap {
            return cap;
        }
        p = p.wrapping_shl(1);
    }
    p
}

/// In-place iterative radix-2 Cooley–Tukey FFT.
///
/// `buf.len()` **must** be a power of two (the only caller, [`screen`], passes a
/// zero-padded power-of-two buffer). `inverse == true` computes the inverse
/// transform (with `+i` twiddles); the caller applies the `1/N` scaling, so this
/// routine itself is unscaled in both directions.
///
/// Pure `f64` arithmetic, no allocation beyond the bit-reversal swap, and no
/// panic: indexing uses checked `get`/`get_mut` with explicit fallbacks so a
/// malformed length can never trigger an out-of-bounds panic.
#[allow(
    // Conventional FFT loop variables (n, i, j, k, w, len) — the short names
    // mirror the Danielson–Lanczos / Cooley–Tukey textbook formulation.
    clippy::many_single_char_names,
    // `len` is a power-of-two slice length; the twiddle-angle cast to f64 is
    // exact for the magnitudes a real FFT size ever reaches.
    clippy::cast_precision_loss
)]
fn fft_in_place(buf: &mut [Complex], inverse: bool) {
    let n = buf.len();
    if n <= 1 {
        return;
    }

    // ── bit-reversal permutation ──
    let mut j = 0usize;
    let mut i = 1usize;
    while i < n {
        let mut bit = n >> 1;
        while (j & bit) != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            buf.swap(i, j);
        }
        i = i.saturating_add(1);
    }

    // ── Danielson–Lanczos butterflies ──
    let sign = if inverse { 1.0 } else { -1.0 };
    let mut len = 2usize;
    while len <= n {
        let half = len >> 1;
        // Principal twiddle angle for this stage: ±2π/len.
        let ang = sign * std::f64::consts::TAU / (len as f64);
        let wlen = Complex::new(ang.cos(), ang.sin());
        let mut start = 0usize;
        while start < n {
            let mut w = Complex::new(1.0, 0.0);
            let mut k = 0usize;
            while k < half {
                let i_even = start.saturating_add(k);
                let i_odd = i_even.saturating_add(half);
                let even = buf.get(i_even).copied().unwrap_or(Complex::ZERO);
                let odd_raw = buf.get(i_odd).copied().unwrap_or(Complex::ZERO);
                let odd = w.mul(odd_raw);
                if let Some(slot) = buf.get_mut(i_even) {
                    *slot = even.add(odd);
                }
                if let Some(slot) = buf.get_mut(i_odd) {
                    *slot = even.sub(odd);
                }
                w = w.mul(wlen);
                k = k.saturating_add(1);
            }
            start = start.saturating_add(len);
        }
        len <<= 1;
    }
}

/// Run the FFT + autocorrelation periodicity screen over `samples`.
///
/// `samples` are raw bytes, one symbol per byte (the Q2 `raw.bin` format). The
/// signal is mean-removed, zero-padded to the next power of two, and transformed
/// once; both detectors read off that single transform.
///
/// Returns a [`PeriodicityReport`]; [`PeriodicityReport::flagged`] is the
/// accept/reject bit. **Deterministic** — identical input bytes always produce
/// an identical report. **Never panics**, including on empty, single-sample, or
/// constant input (those return a non-flagging degenerate report).
///
/// # Cost
///
/// `O(n log n)` for the FFT plus `O(n)` for the spectrum/autocorrelation scans.
#[must_use]
#[allow(
    // `m / 2` (one-sided spectrum) and `n / MAX_LAG_FRACTION_DENOM` (lag cap)
    // are intentional truncating integer divisions — fractional bins/lags are
    // meaningless. The workspace denies integer_division globally for the
    // in-boundary crypto path; this is out-of-boundary analysis tooling.
    clippy::integer_division
)]
pub fn screen(samples: &[u8]) -> PeriodicityReport {
    let n = samples.len();
    if n < 2 {
        return PeriodicityReport::degenerate(n);
    }

    // ── mean removal (drop DC so a non-zero baseline is not "structure") ──
    let mut sum = 0.0f64;
    for &s in samples {
        sum += f64::from(s);
    }
    #[allow(clippy::cast_precision_loss)]
    let mean = sum / (n as f64);

    // ── zero-pad to a power of two and load as complex ──
    let m = next_pow2(n);
    let mut buf = vec![Complex::ZERO; m];
    for (slot, &s) in buf.iter_mut().zip(samples.iter()) {
        slot.re = f64::from(s) - mean;
        slot.im = 0.0;
    }

    // ── forward transform (shared by both detectors) ──
    fft_in_place(&mut buf, false);

    // ── power spectrum ──
    // |X[k]|² for every bin. Bin 0 is DC (≈0 after mean removal); bins below
    // SPECTRAL_MIN_BIN are excluded as low-frequency drift (#102). By Hermitian
    // symmetry of a real signal the spectrum is mirrored about m/2, so the
    // one-sided search SPECTRAL_MIN_BIN..=m/2 covers all distinct frequencies of
    // interest.
    let power: Vec<f64> = buf.iter().map(|c| c.norm_sq()).collect();

    let half = m / 2;
    let mut peak_bin = 0usize;
    let mut peak_power = 0.0f64;
    let mut sum_power = 0.0f64;
    let mut count = 0usize;
    // Start at SPECTRAL_MIN_BIN (not bin 1): the lowest bins carry slow
    // low-frequency drift, not a dominant periodic line (#102). Bins below it
    // are excluded from both the peak search and the mean below. When half <
    // SPECTRAL_MIN_BIN (a tiny FFT) the loop is empty → count 0 → ratio 0 → no
    // spectral flag, matching the degenerate contract.
    let mut k = SPECTRAL_MIN_BIN;
    while k <= half {
        let p = power.get(k).copied().unwrap_or(0.0);
        sum_power += p;
        count = count.saturating_add(1);
        if p > peak_power {
            peak_power = p;
            peak_bin = k;
        }
        k = k.saturating_add(1);
    }

    let mean_power = if count > 0 {
        #[allow(clippy::cast_precision_loss)]
        let c = count as f64;
        sum_power / c
    } else {
        0.0
    };
    let peak_to_mean_ratio = if mean_power > 0.0 {
        peak_power / mean_power
    } else {
        0.0
    };
    let spectral_flag = peak_to_mean_ratio > SPECTRAL_PEAK_RATIO;

    // ── autocorrelation via Wiener–Khinchin: IFFT of the power spectrum ──
    // Reuse `buf` as the IFFT input: replace each bin with its power (real),
    // inverse-transform, and the real part is the (unnormalized) autocorrelation.
    for (slot, &p) in buf.iter_mut().zip(power.iter()) {
        slot.re = p;
        slot.im = 0.0;
    }
    fft_in_place(&mut buf, true);
    // Inverse FFT here is unscaled; normalization by the zero-lag value below
    // cancels the common 1/m factor, so we read the real parts directly.

    let zero_lag = buf.first().map_or(0.0, |c| c.re);
    let max_lag = (n / MAX_LAG_FRACTION_DENOM).max(1);
    let mut peak_lag = 0usize;
    let mut peak_autocorr = 0.0f64;
    if zero_lag > 0.0 {
        let mut lag = 1usize;
        while lag <= max_lag {
            let r = buf.get(lag).map_or(0.0, |c| c.re);
            // Normalize by zero-lag; magnitude (a strong anti-correlation at a
            // fixed lag is just as much a "period" as a positive one).
            let norm = (r / zero_lag).abs();
            if norm > peak_autocorr {
                peak_autocorr = norm;
                peak_lag = lag;
            }
            lag = lag.saturating_add(1);
        }
    }
    let autocorr_flag = peak_autocorr > AUTOCORR_PEAK_THRESHOLD;

    PeriodicityReport {
        n,
        fft_size: m,
        peak_bin,
        peak_to_mean_ratio,
        peak_lag,
        peak_autocorr,
        spectral_flag,
        autocorr_flag,
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact sentinel values, use unwrap/expect/panic for fatal
    // setup invariants, and index fixed-size fixtures — all fine in test code
    // (mirrors the lib.rs / gate.rs test posture).
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    // Synthetic test signals divide by integer periods and use short loop/index
    // names; `% K == 0` reads more clearly here than `.is_multiple_of(K)`.
    clippy::integer_division,
    clippy::many_single_char_names,
    clippy::manual_is_multiple_of
)]
mod tests {
    use super::*;

    /// A deterministic, reproducible pseudo-random byte generator for the
    /// "clean source passes" tests — a 64-bit SplitMix64, no `rand` dependency.
    /// SplitMix64 is a well-distributed counter-based mixer; its output is
    /// aperiodic over any practical test length.
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next_u64() & 0xFF) as u8).collect()
        }
    }

    /// `next_pow2` is correct on the boundary cases the FFT relies on.
    #[test]
    fn next_pow2_is_correct() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(1024), 1024);
        assert_eq!(next_pow2(1025), 2048);
    }

    /// **FFT correctness sanity test** (proves the transform itself, à la the Q2
    /// sha256-stub lesson — a wrong FFT would silently break the whole screen).
    ///
    /// A pure cosine at an exact FFT bin frequency must concentrate all its power
    /// in that one bin (and its Hermitian mirror). We build
    /// `x[t] = cos(2π·f·t / N)` with `N = 64`, `f = 5`, transform it, and assert
    /// the power spectrum's maximum non-DC bin is exactly `5`.
    #[test]
    fn fft_single_frequency_peaks_in_expected_bin() {
        const N: usize = 64;
        const F: usize = 5;
        let mut buf = vec![Complex::ZERO; N];
        for (t, slot) in buf.iter_mut().enumerate() {
            let ang = std::f64::consts::TAU * (F as f64) * (t as f64) / (N as f64);
            slot.re = ang.cos();
            slot.im = 0.0;
        }
        fft_in_place(&mut buf, false);
        let power: Vec<f64> = buf.iter().map(|c| c.norm_sq()).collect();

        // Find the dominant non-DC bin in the lower half.
        let mut best = 0usize;
        let mut best_p = 0.0f64;
        for (k, &p) in power.iter().enumerate().take(N / 2 + 1).skip(1) {
            if p > best_p {
                best_p = p;
                best = k;
            }
        }
        assert_eq!(
            best, F,
            "cosine of freq {F} must peak in bin {F}, got {best}"
        );

        // The peak should hold essentially all the energy: bin F carries N²/4
        // (= 1024 here), every other non-DC bin is ~0.
        let total: f64 = power.iter().take(N / 2 + 1).skip(1).sum();
        assert!(
            best_p / total > 0.99,
            "freq bin should hold >99% of non-DC power, got {}",
            best_p / total
        );
    }

    /// **FFT round-trip**: forward then inverse (with 1/N scaling) recovers the
    /// input — corroborates the inverse path the autocorrelation relies on.
    #[test]
    fn fft_inverse_round_trips() {
        const N: usize = 32;
        let mut original = vec![Complex::ZERO; N];
        for (t, slot) in original.iter_mut().enumerate() {
            slot.re = (t as f64) * 0.5 - 7.0;
            slot.im = 0.0;
        }
        let mut buf = original.clone();
        fft_in_place(&mut buf, false);
        fft_in_place(&mut buf, true);
        for (a, b) in buf.iter().zip(original.iter()) {
            // inverse FFT here is unscaled, so divide by N to recover.
            assert!((a.re / (N as f64) - b.re).abs() < 1e-9, "re mismatch");
            assert!((a.im / (N as f64)).abs() < 1e-9, "im should stay ~0");
        }
    }

    /// **Oracle (ISC-133), periodic flags #1**: a pure period-`k` sawtooth must
    /// be flagged. `x[t] = t mod k` is strongly periodic, so both detectors
    /// should fire; at minimum [`PeriodicityReport::flagged`] is true.
    #[test]
    fn pure_periodic_sawtooth_is_flagged() {
        const K: usize = 16;
        let samples: Vec<u8> = (0..4096usize).map(|t| (t % K) as u8).collect();
        let r = screen(&samples);
        assert!(
            r.flagged(),
            "pure period-{K} sawtooth must be flagged: {r:?}"
        );
        // The autocorrelation peak should land at a multiple of the period.
        assert!(
            r.peak_lag % K == 0 && r.peak_lag > 0,
            "autocorr peak lag {} should be a multiple of period {K}",
            r.peak_lag
        );
    }

    /// **Oracle (ISC-133), periodic flags #2**: a sine quantized to bytes, at an
    /// exact bin frequency, must be flagged (spectral detector's home turf).
    #[test]
    fn quantized_sine_is_flagged() {
        const N: usize = 4096;
        const PERIOD: usize = 64; // N / PERIOD = 64 cycles, an exact bin
        let samples: Vec<u8> = (0..N)
            .map(|t| {
                let ang = std::f64::consts::TAU * (t as f64) / (PERIOD as f64);
                // Map sine [-1,1] -> byte [0,255].
                ((ang.sin() * 0.5 + 0.5) * 255.0).round() as u8
            })
            .collect();
        let r = screen(&samples);
        assert!(r.spectral_flag, "quantized sine must trip spectral: {r:?}");
        assert!(r.flagged(), "quantized sine must be flagged: {r:?}");
    }

    /// **Oracle (ISC-133), buried period**: a strong periodic component buried
    /// in pseudo-random noise must still be flagged. We add a period-32 square
    /// component to SplitMix64 noise.
    #[test]
    fn periodic_buried_in_noise_is_flagged() {
        const N: usize = 8192;
        const PERIOD: usize = 32;
        let mut rng = SplitMix64::new(0xDEAD_BEEF);
        let noise = rng.bytes(N);
        let samples: Vec<u8> = noise
            .iter()
            .enumerate()
            .map(|(t, &b)| {
                // Light dither + a strong deterministic square wave.
                let square: i32 = if (t / (PERIOD / 2)) % 2 == 0 { 96 } else { -96 };
                let v = i32::from(b) / 4 + square + 96; // keep within byte range
                v.clamp(0, 255) as u8
            })
            .collect();
        let r = screen(&samples);
        assert!(
            r.flagged(),
            "strong periodic component buried in noise must be flagged: {r:?}"
        );
    }

    /// **Oracle (#102), low-frequency drift passes**: dominant white noise with a
    /// slow mean modulation across the record (energy in the lowest bins, but no
    /// repeating period) must NOT be flagged. This is the pilot's block-mean
    /// drift: a large low-bin spectral peak yet a clean autocorrelation. Before
    /// the bin-8 floor the drift bin dominated and tripped the 50x ratio; with
    /// [`SPECTRAL_MIN_BIN`] only the flat >=8 band is searched, so it passes —
    /// reverting the floor makes this test fail, which is the point.
    #[test]
    fn low_frequency_drift_below_bin8_passes() {
        const N: usize = 4096;
        let mut rng = SplitMix64::new(0xD1F7_0FF5);
        let noise = rng.bytes(N);
        let samples: Vec<u8> = noise
            .iter()
            .enumerate()
            .map(|(t, &b)| {
                // Half-cycle mean modulation over the whole record -> energy in
                // the lowest bins, riding on dominant white noise so the
                // autocorrelation stays clean (like the pilot's block-mean wander).
                let ang = std::f64::consts::PI * (t as f64) / (N as f64);
                let drift = ang.cos() * 40.0;
                let v = 128.0 + drift + (f64::from(b) - 128.0);
                v.clamp(0.0, 255.0) as u8
            })
            .collect();
        let r = screen(&samples);
        assert!(
            !r.spectral_flag,
            "low-frequency drift (bin < {SPECTRAL_MIN_BIN}) must not trip spectral after #102: {r:?}"
        );
        assert!(
            !r.flagged(),
            "low-frequency drift must pass the screen: {r:?}"
        );
        // The reported peak now lands in the searched band, never a drift bin.
        assert!(
            r.peak_bin >= SPECTRAL_MIN_BIN,
            "peak bin {} must be within the searched band (>= {SPECTRAL_MIN_BIN})",
            r.peak_bin
        );
    }

    /// **Oracle (#102 backstop), low-order line still caught**: a genuine periodic
    /// line whose fundamental is below [`SPECTRAL_MIN_BIN`] (the bins 1–7 the
    /// spectral floor now skips) must still be flagged — the autocorrelation
    /// detector is the low-order backstop. This proves the bin-8 floor did not
    /// open a hole: slow *drift* passes, but a real low-order *period* does not. A
    /// dominant bin-6 line is exact-bin (no spectral leakage into `>= 8`), so the
    /// spectral detector legitimately ignores it, yet its short-lag
    /// self-correlation trips the autocorrelation detector.
    #[test]
    fn low_order_periodic_line_is_caught_by_autocorr_backstop() {
        const N: usize = 4096;
        const BIN: usize = 6; // exact FFT bin, below SPECTRAL_MIN_BIN (8)
        let samples: Vec<u8> = (0..N)
            .map(|t| {
                let ang = std::f64::consts::TAU * (BIN as f64) * (t as f64) / (N as f64);
                ((ang.cos() * 0.5 + 0.5) * 255.0).round() as u8
            })
            .collect();
        let r = screen(&samples);
        assert!(
            r.autocorr_flag,
            "a low-order (bin {BIN}) periodic line must trip the autocorr backstop: {r:?}"
        );
        assert!(
            r.flagged(),
            "the low-order line must still be flagged: {r:?}"
        );
    }

    /// **Oracle (ISC-133), clean source passes**: aperiodic pseudo-random bytes
    /// from a deterministic generator must NOT be flagged.
    #[test]
    fn clean_pseudorandom_passes() {
        let mut rng = SplitMix64::new(0x0123_4567_89AB_CDEF);
        let samples = rng.bytes(8192);
        let r = screen(&samples);
        assert!(
            !r.flagged(),
            "clean pseudo-random source must pass (not flagged): {r:?}"
        );
        // Sanity on the measured statistics: peak-to-mean well under the
        // spectral threshold and autocorrelation well under its threshold.
        assert!(
            r.peak_to_mean_ratio < SPECTRAL_PEAK_RATIO,
            "clean peak/mean {} should be < {SPECTRAL_PEAK_RATIO}",
            r.peak_to_mean_ratio
        );
        assert!(
            r.peak_autocorr < AUTOCORR_PEAK_THRESHOLD,
            "clean autocorr {} should be < {AUTOCORR_PEAK_THRESHOLD}",
            r.peak_autocorr
        );
    }

    /// **Clean source passes (second seed)** — guards against a single lucky
    /// seed: a different deterministic stream also passes.
    #[test]
    fn clean_pseudorandom_passes_second_seed() {
        let mut rng = SplitMix64::new(0xFACE_FEED_CAFE_BABE);
        let samples = rng.bytes(8192);
        let r = screen(&samples);
        assert!(!r.flagged(), "second clean stream must pass: {r:?}");
    }

    /// Determinism: two screens of the same input are bit-identical.
    #[test]
    fn screen_is_deterministic() {
        let mut rng = SplitMix64::new(42);
        let samples = rng.bytes(2048);
        let a = screen(&samples);
        let b = screen(&samples);
        assert_eq!(a, b, "screen must be bit-identical across runs");
    }

    /// Degenerate inputs never panic and never flag.
    #[test]
    fn degenerate_inputs_are_sane() {
        for s in [vec![], vec![7u8]] {
            let r = screen(&s);
            assert!(!r.flagged(), "tiny input must not flag: {r:?}");
            assert_eq!(r.n, s.len());
        }
        // Constant source: no varying signal, so after mean removal it is all
        // zeros -> flat (zero) spectrum -> no spectral peak, no autocorrelation
        // structure. Must not panic and must not flag.
        let constant = vec![200u8; 4096];
        let r = screen(&constant);
        assert!(!r.flagged(), "constant source must not flag: {r:?}");
    }

    /// Non-power-of-two lengths are handled (zero-padded) without panic.
    #[test]
    fn non_power_of_two_length_is_handled() {
        // 1000 is not a power of two; FFT size should round up to 1024.
        let mut rng = SplitMix64::new(7);
        let samples = rng.bytes(1000);
        let r = screen(&samples);
        assert_eq!(r.fft_size, 1024);
        assert_eq!(r.n, 1000);
        assert!(!r.flagged(), "clean 1000-sample stream should pass: {r:?}");
    }
}
