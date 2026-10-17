# Power-up self-test performance

Measured figures for how long each entry point spends on its power-up
self-tests before the module becomes operational. The entry points are
`oxi_init` in the C library, the ACVP harness and the `oxi` command-line tool.
Each runs two groups, in this order:

- **The integrity group** (`oxicrypt_integrity::KATS`): the ML-DSA-87
  signature-verification CAST, the SHA-256 CAST, and the integrity test itself,
  an ML-DSA-87 verification over the signed extent of the artifact.
- **The algorithm self-tests**: the known-answer tests of every approved
  algorithm crate the entry point links.

The two are measured differently, because the integrity test only passes inside
a signed artifact and a benchmark binary is not one.

As with [`entropy-performance.md`](entropy-performance.md), read the qualifiers
beside each figure, not only the figure.

## Reference platform

| | |
|---|---|
| CPU | AMD Ryzen 7 4800H, 8 vCPU exposed to the guest, reporting 2899.518 MHz |
| Virtualization | **KVM guest**, clocksource `kvm-clock`; `tsc_known_freq` and `tsc_scale` present |
| Frequency control | **Not recorded.** The guest exposes no `cpufreq` interface, so governor and boost state are unknown, and host-side frequency and load are not visible from the guest at all. |
| Machine state | Not controlled; no other benchmark or build ran during the measurements |
| OS | Ubuntu 26.04.1 LTS, kernel 7.0.0-38-generic |
| Toolchain | rustc 1.97.1 (2026-07-14), criterion 0.5.1, hyperfine 2.0.0, release profile |
| Build | default features; no `parallel`, no `accel-*` |

> **Keep the virtualization and frequency rows when copying this table.** These
> figures characterise this VM. Self-tests are ordinary compute, so a KVM guest
> is less distorting here than for the entropy source, but the unrecorded
> frequency behaviour still applies, and nothing here is a figure for any
> operational environment.

## Algorithm self-tests

```sh
cargo bench -p oxicrypt-bench --bench power_up
```

The `power_up` benchmark compiles each entry point's own power-up list, so it
times the set that entry point runs. Criterion point estimate and 95%
confidence interval, 10 samples each:

| Entry point | Algorithm self-tests |
|---|---|
| `oxi_init` (C library) | **181.80 ms** (180.68–183.00) |
| ACVP harness | **181.55 ms** (180.69–182.53) |
| `oxi` | **4.2747 ms** (4.2347–4.3113) |

`oxi_init` and the harness link every approved algorithm crate. `oxi` links
only what its subcommands use: SHA, HMAC, AES, the DRBG, SHAKE and ML-DSA.

Per crate, in the order the harness runs them:

| Crate | Time | Crate | Time |
|---|---|---|---|
| `sha` | 3.8516 µs (3.8342–3.8786) | `rsa` | 15.507 ms (15.396–15.631) |
| `xof` | 17.787 µs (17.668–17.994) | `ecdh` | 1.7565 ms (1.7504–1.7622) |
| `hmac` | 18.327 µs (18.199–18.437) | `tls-kdf` | 7.7813 µs (7.7394–7.8211) |
| `kdf` | 1.1159 ms (1.0944–1.1370) | `dh` | 31.743 ms (31.610–31.890) |
| `aes` | 128.33 µs (127.62–129.95) | `ml-kem` | 410.87 µs (407.79–414.82) |
| `cmac` | 5.2314 µs (5.1805–5.2908) | `ml-dsa` | 3.7821 ms (3.7415–3.8216) |
| `drbg` | 358.72 µs (347.24–371.56) | `slh-dsa` | **117.19 ms** (116.51–117.77) |
| `ecdsa` | 5.5033 ms (5.4842–5.5485) | `lms` | 628.71 µs (624.69–633.76) |
| `eddsa` | 1.1248 ms (1.1057–1.1441) | `xmss` | 2.1197 ms (2.1046–2.1413) |

**SLH-DSA is about two thirds of the full set**, then finite-field DH and RSA.
The full set is about 180 ms; without those three it would be under 20 ms.

**These are warm, back-to-back figures.** Each iteration re-runs a set whose
code and tables are already in cache. An entry point runs its set once, cold,
in a new process.

## Integrity group

Measured on a signed `oxi`, as whole-process wall-clock time, because the
integrity test runs once per process and only a signed artifact passes it.

Wall clock as hyperfine reports it, 500 runs each:

| Command | What it runs | Median | Mean ± σ |
|---|---|---|---|
| `oxi` (no arguments) | process start, usage message, exit; no module initialisation | 1.973 ms | 2.179 ± 0.808 ms |
| `oxi --integrity` | full power-up: integrity group, then algorithm self-tests | 19.241 ms | 19.836 ± 2.015 ms |
| `oxi selftest --quiet` | full power-up, then every power-up self-test again except the image check | 24.401 ms | 25.068 ± 2.323 ms |

`oxi selftest` re-runs the whole power-up list, the two integrity CASTs
included, and reports the image check's verdict from process start rather than
running it again. The differences of the medians:

- **Power-up in total: 17.268 ms**, `oxi --integrity` less the
  no-initialisation baseline.
- **Algorithm self-tests plus the two integrity CASTs, re-run warm in the same
  process: 5.160 ms**, `oxi selftest --quiet` less `oxi --integrity`.
- **Image check alone: about 12.1 ms**, the total less that re-run.
- **Integrity group (the two CASTs and the image check): about 13.0 ms**, the
  total less the criterion figure for `oxi`'s algorithm self-tests (4.27 ms).

**The extent it was measured on: 1,646,288 bytes in 486 entries**, 96.17% of
the 1,711,824 bytes the loader maps, from a 5,777,552-byte release `oxi`.
`oxicrypt-integrity-sign --show` prints the same breakdown for any signed
artifact. The integrity test reads every byte of the extent, and the ML-DSA-87
verification hashes all of it as part of the signed message, so its time grows
with the extent. The C library and the ACVP harness have extents of their own
and are not covered by this figure.

Both subtractions are estimates, not direct measurements. They assume the rest
of `oxi --integrity` (reading the slot to print the extent, four lines of
output) is negligible against 17 ms, and the group estimate mixes a
whole-process figure with a warm in-process one.

**Run-to-run variation is several percent.** A second
500-run measurement on the same guest gave a total of 16.621 ms (3.7% lower)
and a re-run of 5.611 ms (8.7% higher). Taken from that run, the image check
is 11.0 ms and the group 12.3 ms, so read the two estimates as about 11–12 ms
and about 12–13 ms.

### Reproducing the integrity figures

With a scratch key generated outside the tree, as
[`integrity-signing.md`](integrity-signing.md) describes:

```sh
cargo build --release -p oxicrypt-integrity-sign
./target/release/oxicrypt-integrity-sign --keygen /tmp/oxi-bench-keys
OXICRYPT_INTEGRITY_VERIFY_KEY=/tmp/oxi-bench-keys/integrity-verify.pub \
  cargo build --release -p oxicrypt-cli
./target/release/oxicrypt-integrity-sign --sign \
  --key /tmp/oxi-bench-keys/integrity-signing.key target/release/oxi
./target/release/oxi --integrity    # must report "integrity: passed"
hyperfine -N --warmup 20 --runs 500 -i --export-json power-up.json \
  'target/release/oxi' 'target/release/oxi --integrity' \
  'target/release/oxi selftest --quiet'
jq -r '.results[]
  | (if (.command | test(" --integrity$| selftest --quiet$")) then 0 else 2 end) as $want
  | if all(.measurements[]; .exit_code == $want) then . else error("\(.command): an exit code is not \($want)") end
  | .summary.time_wall_clock as $t
  | [.command, $t.median * 1e3, $t.mean * 1e3, $t.stddev * 1e3, $t.count] | @tsv' \
  power-up.json
```

`-i` is needed because `oxi` with no arguments prints its usage and exits 2.
It applies to every command, so hyperfine would also time a failed
`--integrity` or `selftest` run without complaint. The `jq` step is the check:
it exits non-zero unless every run of the baseline exited 2 and every run of
the other two exited 0.

## Per entry point

| Entry point | Algorithm self-tests (warm) | Integrity group | Measured end to end |
|---|---|---|---|
| `oxi` | 4.27 ms | about 12–13 ms, on a 1.6 MB extent | **17.27 ms** |
| `oxi_init` (C library) | 181.80 ms | not measured; depends on the library's extent | no |
| ACVP harness | 181.55 ms | not measured; depends on the harness's extent | no |

## What these figures do not cover

- **Any operational environment.** Every number here is from a KVM guest.
- **The integrity group in the C library and the ACVP harness**, whose
  extents differ from `oxi`'s.
- **The cold, first-in-process cost of the algorithm self-tests** for
  `oxi_init` and the harness. Only `oxi` has a whole-process measurement.
- **Non-default builds.** `parallel` and `accel-*` are off, matching the
  validation-target configuration. Both affect algorithms these self-tests
  exercise, SLH-DSA among them, and neither is measured here.
- **The module's state machine**, which is a few atomic operations.
- **The entropy source's start-up health tests**, which run when a pipeline
  starts rather than at module power-up. Their figure is in
  [`entropy-performance.md`](entropy-performance.md#start-up-health-test-time).
