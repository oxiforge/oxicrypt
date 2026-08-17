# Entropy pipeline and assessment performance

Measured figures for the two entropy-side throughput questions: how fast the
pipeline produces vetted conditioned output, and how long a full SP 800-90B
assessment of one capture takes.

Read the qualifiers, not just the numbers. Both measurements have conditions
that change them by more than the difference anyone would care about, and each
is stated beside its figure rather than in a footnote.

```sh
cargo bench -p oxicrypt-bench --features entropy-bench --bench conditioned_output
cargo bench -p oxicrypt-bench --features entropy-bench --bench maxwell
```

The `entropy-bench` feature is opt-in for a reason beyond tidiness: cargo
unifies features across an invocation, so a plain dependency here would enable
`oxicrypt-entropy/raw-counter` for every `--workspace` command in the repo.

## Reference platform

| | |
|---|---|
| CPU | AMD Ryzen 7 4800H (Zen 2, 8C/16T; 12 vCPU exposed to the guest), reporting 2894 MHz |
| Virtualization | **KVM guest**, clocksource `kvm-clock`; `tsc_known_freq` and `tsc_scale` present |
| Frequency control | **Not recorded.** Governor and boost state are not exposed inside the guest, and host-side frequency and load are not visible from here at all. The 4800H's 2.9→4.2 GHz range is a ~45% swing that these figures cannot account for. |
| Machine state | Otherwise idle apart from the measurement; not otherwise controlled |
| OS | Ubuntu 26.04 LTS, kernel 7.0.0-28-generic |
| Toolchain | rustc 1.95.0 (2026-04-14), criterion 0.5.1, release via the bench profile |
| Build | `--features entropy-bench` (which enables `oxicrypt-entropy/raw-counter`); no `parallel`, no `accel-*` |

> **The virtualization and frequency rows are load-bearing for the
> conditioned-output figure and must not be dropped when this table is copied.**
> The jitter source harvests execution-time variation, a KVM guest's timing
> profile is not its host's, and `RawCounterTimer` is simultaneously the thing
> being measured and the instrument measuring it. The number below characterises
> this VM. It is **not** the pilot operational environment's figure — that is
> the bare-metal host, and it needs its own run before it can be cited as the
> per-OE number the Security Policy's operational claims sit alongside.
>
> The `maxwell` assessment figures are ordinary compute and less sensitive to
> virtualization — tens of percent rather than orders of magnitude — though the
> unrecorded frequency behaviour applies to them too.

## Conditioned-output throughput

The pipeline's sole vetted output path, `EntropyPipeline::conditioned_block` —
noise-source sampling, the continuous health battery, and SHA-256 conditioning
of one 256-bit block, end to end.

| Claim | Samples per block | Time per block | Conditioned throughput |
|---|---|---|---|
| H = 0.5 bits/sample (pilot OE claim) | 640 | **1.5578 ms** (95% CI 1.5488–1.5671) | **20.06 KiB/s** (19.94–20.18) |

Samples per block is `⌈(n_out + 64) / H⌉` = `⌈320 / 0.5⌉` = 640, the SP 800-90C
§3.2.2.2 full-entropy input requirement; it is computed by
`Conditioner::for_claim`, not hard-coded. Raising the claimed H lowers the count
proportionally and the throughput follows, which is why the claim is a column
rather than a footnote.

The denominator is **conditioned output bytes** — the vetted product a consumer
counts. In raw sample terms the same figure is 640 B / 1.5578 ms ≈ 401 KiB/s
consumed, ≈ 2.4 µs per sample. Every other benchmark in `oxicrypt-bench` reports
input bytes, so do not compare this row against them directly.

**Read it as a noise-source measurement, not a conditioner one.** One SHA-256
compression over 640 bytes is a fraction of a microsecond; essentially all of the
1.56 ms is 640 timed jitter samples plus their per-sample health tests.

**This is a steady-state, hot-loop figure — the fastest regime, not the
operational one.** Iterations are deliberately not independent: `JitterSource`
carries a `steer` value that makes each round's workload a function of the
previous round's delta, its 8 KiB walk buffer and internal state stay cache-hot
across a back-to-back loop, and the health monitor's RCT/APT state persists
across blocks rather than resetting per block. So the number is the fixed point
of a feedback loop under ideal cache conditions. The operational shape — one
cold block to seed a DRBG — is not measured here and should be expected to be
slower.

Criterion flagged 2 mild outliers in 10 samples. That is the right shape: timing
variability is the signal the source exists to harvest, so a perfectly stable
number here would be evidence of a problem rather than of a good measurement.

## `maxwell` assessment cost

What the off-boundary assessment tool costs for one capture. `iid_gate` routes
on the data: an IID verdict pays the §5 battery, a non-IID verdict pays the §6.3
suite. Both are measured, because an operator's capture takes whichever branch
its data dictates and a single averaged figure would describe neither.

| Branch | Symbols | Width | Time | Peak RSS | Source |
|---|---|---|---|---|---|
| non-IID | 1 000 000 | **4-bit — the module's own width** | **1829.27 s ≈ 30.5 min** | 181 MB | single wall-clock `maxwell iid-gate` run |
| non-IID | 1 000 000 | 8-bit | 2417.75 s ≈ 40.3 min | 344 MB | single wall-clock `maxwell iid-gate` run |
| IID | 1 000 000 | 8-bit | **8.9882 s** (8.9326–9.0385), 108.65 KiB/s | — | criterion, 10 samples |

**Plan per-OE assessment time on the 4-bit non-IID row — about half an hour per
capture.** That is the module's own configuration: the jitter source emits 4-bit
samples (`SourceSpec::sample_width_bits` = 4), and a real entropy-source capture
is what the non-IID branch exists for.

The 8-bit row is kept for comparison because it shows the alphabet's price:
widening from 4 to 8 bits costs **+32% wall-clock and +90% peak memory**, which
is why an assessment figure without its symbol width is not a figure.

**At 8-bit the branches are ~270× apart, and that asymmetry is the other
headline.** Which branch a capture takes is decided by its data, not by the
operator. That figure divides like against like — 2417.75 s against 8.99 s, both
rows at 8-bit. The 4-bit non-IID row has no same-width IID counterpart, so it
yields no comparable ratio; dividing it by the 8-bit IID figure gives ~203×, but
that mixes two symbol widths and understates the real 4-bit asymmetry, since a
4-bit IID run would itself be cheaper than 8.99 s.

### Three qualifications that matter more than the digits

**The IID figure is a best case with no stated upper bound.** `permutation_test`
stops early — it breaks out once all 19 statistics are *decided*, where decided
means `(C0 + C1 > 5) && (C1 + C2 > 5)`. On the clean PRNG output the benchmark
feeds it, all 19 decide within tens of shuffles, so the run never approaches the
10 000-permutation ceiling. A full 10 000-shuffle sweep over 1 M bytes is on the
order of 10^10 RNG-and-swap operations — by itself longer than the entire 8.99 s
measurement above. A statistic whose permuted value is *always* greater never
decides, runs all 10 000, and still routes IID. **So 8.99 s is what a
comfortably-IID capture costs, not what the IID branch can cost.**

**Only the non-IID rows cover the module's own 4-bit width.** The IID figure and
the criterion bench still use 8-bit symbols. §6.3 dictionary and estimator costs
are alphabet-dependent — measurably so, per the +32%/+90% above — so the IID
number is not yet a per-boundary cost.

**The non-IID branch runs more than the ten §6.3 estimators.** It also runs the
bitstring suite and `h_original`, roughly 17 estimator passes in total. The
figure covers all of it; the "§6.3 suite" shorthand undersells the work.

### Reproducing the non-IID figure

The criterion path cannot produce it: criterion's floor is 10 samples, which for
this case means ~6.5 hours (its own estimate during the attempt was 23 339 s,
consistent with the 2417.75 s measured per iteration). So it is a single timed
CLI run, and is labelled wall-clock rather than as a criterion statistic —
including the six significant figures, which are one sample's precision, not a
confidence interval.

```sh
# 4-bit — the module's own sample width, and the row to plan against
cargo run -p oxicrypt-bench --features entropy-bench --example gen_noniid -- /tmp/noniid4.bin 1000000 4
cargo build --release -p oxicrypt-maxwell
/usr/bin/time -f 'WALL=%e s  MAXRSS=%M KB' ./target/release/maxwell iid-gate /tmp/noniid4.bin 4

# 8-bit — the comparison row
cargo run -p oxicrypt-bench --features entropy-bench --example gen_noniid -- /tmp/noniid8.bin 1000000 8
/usr/bin/time -f 'WALL=%e s  MAXRSS=%M KB' ./target/release/maxwell iid-gate /tmp/noniid8.bin 8
```

The input is a first-order Markov chain with a 5% switch probability. It routes
non-IID for the right reason rather than by construction: both observed runs
reported §5.1, §5.2 and §5.3 all failing.

### Default bench sizes

Because of the cost asymmetry, the default `cargo bench` run measures the IID
branch at the full 1 M and the non-IID branch at 100 k. Set
`OXICRYPT_BENCH_MAXWELL_FULL=1` to raise the non-IID case to 1 M and accept the
hours.

## What these figures do not cover

- **The pilot operational environment.** Every number here is from a KVM guest;
  the per-OE conditioned-output figure requires a run on the bare-metal host.
- **The module's own 4-bit symbol width** for the IID figure and the criterion
  bench; only the non-IID CLI rows cover it.
- **The IID branch's worst case**, which the early exit hides.
- **The cold, one-block-at-a-time shape** of conditioned output, as opposed to
  the hot back-to-back loop measured here.
- **Frequency behaviour**, which is not observable from inside the guest.
- **Non-default builds.** `parallel` and `accel-*` are off, matching the
  validation-target configuration; neither measured path is parallelised anyway.
- **End-to-end DRBG seeding.** Conditioned-output throughput is measured at the
  pipeline boundary; the seeding integration it feeds is marked pending in the
  Security Policy.
