# Independence Analysis (2D/3D min-entropy) — Design of Record — 2026-07-09 (rev 2, post-panel — **RATIFIED, caraka 2026-07-09**: F1 pair-suite leg + dual-phase + dual reporting · F2 shuffled null with K=10 MCV ensemble · F3 revised oracles · F4 the full bundle)

> **Graduated to the repo from the vault design draft `independence-analysis-design-2026-07-09.md`
> on 2026-07-10, with the `maxwell independence` build commit.** One build-time reconciliation is
> marked inline (the suite-leg phase count; see the FLAG in Method §2). Otherwise verbatim.


> **Vault-side design draft** for the unbuilt half of entropy-ISA ISC-121: `maxwell`'s
> pairs/triplets (2D/3D) min-entropy evidence subcommand, which gates ISC-120 (the ≥10M-delta
> per-OE independence analysis). Graduates to repo `docs/design/independence-analysis.md` with
> the build commit (the esv-harness-design pattern). Frozen in Fable week-3 session ②;
> rev 2 folds the three-lens adversarial panel (statistical / CMVP-reviewer / build-soundness,
> 2026-07-09). Ratification record: entropy-ISA Decisions 2026-07-09 + session ISA
> `PAI/MEMORY/WORK/20260709-oxicrypt-isc121-independence-design/ISA.md`.

## Provenance (dated fetched sources)

- **jent v3.7.0 design doc** (`CPU-Jitter-NPTRNG.pdf`, chronox.de, CC BY 4.0) — **fetched
  2026-07-09**, text-extracted; §4.1 is the method precedent (quoted below).
- SP 800-90B §6.3 estimators — as transcribed in the shipped, EA-parity-proven
  `oxicrypt-maxwell` suite (parity ≤1e-6 on the 11 EA datasets; ISC-71..80, 9.1).
- maxwell architectural conventions — surveyed 2026-07-09 (file:line refs inline).
- Session-① freshness sweep (2026-07-09): no IG/90-series change since April 2026.

## The precedent, verbatim (jent v3.7.0 §4.1)

> "the entropy analysis also calculates the min-entropy of **pairs and triplets of adjacent
> time deltas**. These two and three-dimensional min-entropy values are provided to give the
> reader an idea whether the time deltas are relatively independent of each other. I.e. **if
> the different min-entropy values are in relative close proximity to each other, the adjacent
> time deltas are considered to have very little mutual dependencies.** However, the reader
> should understand that for a representative value of the min-entropy of pairs and triplets,
> large numbers of time deltas are required: **at the very least 10,000,000** should be
> collected for obtaining meaningful values."

with the 1D formula stated as `Hmin(X) = −log₂(max Prob(X = ωᵢ))`, and the FFT ("rectangular
spectrum = no dependencies") as the spectral complement — already shipped as
`maxwell periodicity` (the FFT half of ISC-121).

## What this analysis is — and is not (semantics, frozen)

**It is reviewer-facing evidence that higher-order (joint-alphabet) structure does not
threaten the ratified per-OE claim, established with the same estimator class that set the
claim.** It never claims the source is independent — the pilot source is assessed **non-IID**
(all three §5 tests fail; the predictors bind), so joint-alphabet values are *expected* to
reflect dependence. Three layers, in strength order:

1. **The pair-suite leg (the probative core — panel finding C1 applied):** the full literal
   §6.3 non-IID estimator battery (MCV + t-Tuple, LRS, MultiMCW, Lag, MultiMMC, LZ78Y — the
   `h_original` set for 8-bit data, every one EA-parity-proven) runs on the disjoint-pair
   stream at **both phase offsets** (advisor: the one detection-coverage decision — a
   phase-locked pair structure cannot hide in the blocking alignment; minutes-class runtime
   accepted). `pair_suite_min / 2` (min over estimators and phases) is the per-delta value.
   **The tool also computes the 1-D literal suite min on the original symbol stream**
   (same code, one pass) so the structure comparison is methodology-matched (advisor):
   *structure evidence* = `pair_suite_min/2 − suite_min_1d` (both suite-derived, same tool);
   *credit evidence* = `pair_suite_min/2` vs the ratified claim. Both are reported and
   sidecar-carried — a flag's cause is legible (2-D structure vs estimator-methodology
   mismatch). Reading: if pair-level structure adds nothing beyond what the 1-D assessment
   priced, the structure deficit ≈ 0; a material drop exposes higher-order structure the 1-D
   pass missed. The claim comparison is the gate (below).
2. **The tuple-MCV leg (the precedent artifact):** §6.3.1 confidence-bound MCV on pairs AND
   triplets, plus the plain `−log₂(max p̂)` precedent form. **Triplet asymmetry, explicit
   (advisor fork):** triplets get MCV-only — the predictor battery's power collapses on a
   4096-symbol alphabet at ~3.3M draws, and 12-bit symbols exceed the estimator wire; the
   flag therefore mixes a suite-min (pairs, more conservative by construction) against a
   single-estimator value (triplets) — intended: the pair side is deliberately the more
   sensitive trigger. Multi-phase-disjoint vs native overlapping for MCV (one-sentence
   rationale, advisor): 90B's own t-Tuple counts overlapping tuples; our per-phase-disjoint
   ensemble recovers overlapping's phase coverage while keeping each histogram's draws
   non-overlapping — and native overlapping is unavailable anyway once the suite leg exists
   (shared symbols corrupt the predictors).
3. **The shuffled-baseline control (panel Stat-A/C3/C4; advisor-hardened):** every measured
   value in legs 1–2 is paired with the same statistic computed on **deterministically
   shuffled copies** of the input (maxwell's ISC-134 shuffle discipline — one documented
   master seed, bit-reproducible). Shuffling preserves the marginal distribution and destroys
   serial dependence, and — being same-n, same-alphabet — carries **identical finite-sample
   bias**; it also neutralizes slow drift/nonstationarity confounds. The reviewer-facing
   proximity evidence is the **measured-vs-null deficit**. Precedent anchor (advisor): SP
   800-90B §5's IID track is itself permutation testing — shuffle-to-build-a-null is
   NIST-endorsed technique, not novelty. **Ensemble (advisor):** one shuffle is a single draw
   from the null, not the null — the MCV legs use a **K = 10 shuffle ensemble** under the
   master seed, reporting null mean ± spread (cheap histogram passes; the 4096-bin triplet
   leg is exactly where the one-draw null is noisiest); the pair-suite leg pairs with a
   **single** shuffled run, documented as a one-draw null (suite runtime bounds it; the suite
   leg's gate is its absolute claim comparison, not its deficit). **Caveat carried in the
   report wording:** a deficit (or FLAG) can be driven by benign nonstationary drift, not
   only exploitable dependence — the FFT half and the reviewer decide which.

**Gate (claim-anchored FLAG, engineering-not-spec):** with `--claim H` supplied, FLAG when
`min(pair_suite_min/2, H₃_mcv/3) < H` → verdict + exit FAILURE (the `periodicity`
acceptance-fails contract). Without `--claim`: report-only, exit SUCCESS (the `iid-gate`
reporting-tool contract). **Below the 10M precedent minimum the flag is advisory-only:**
verdict computed and printed, exit stays SUCCESS, sidecar carries `"advisory_only": true`
(panel Stat-E applied — a smoke run on 1M pilot data can never fake an acceptance failure).

**Stated limitations (frozen wording, panel Stat-C/D):** the tuple view covers k ≤ 3;
longer-range and periodic structure is delegated to the FFT half and the 1-D §6.3 predictors
(lag ≤ 128) — this delegation is load-bearing and is stated in the module doc and report. The
claim-anchored flag is a floor detector; between "consistent with the 1-D assessment" and
"claim-threatening" the evidence is the deficit numbers, not the flag.

## Method (frozen)

1. **Substrate:** the credited 4-bit symbol stream (general over `bits_per_symbol` 1..=8) —
   the same stream the health tests, claim, and raw datasets carry (G22 one-stream doctrine).
   Departure from the precedent's literal object (raw time deltas) is deliberate and stated:
   the claim rides on these symbols, so their joint structure is what matters (panel CMVP-3).
2. **Tuple formation: disjoint adjacent tuples** — pairs (s₀s₁)(s₂s₃)…, triplets
   (s₀s₁s₂)(s₃s₄s₅)…, tail partial tuple dropped. **Corrected rationale (panel Stat-2):**
   NOT "independent draws" — disjoint tuples of a dependent source remain dependent. The real
   reasons: (a) disjoint blocking yields a stationary block process whose per-tuple entropy
   rate is k× the per-symbol rate, so suite estimates are interpretable per-delta; (b)
   overlapping tuples share symbols between consecutive tuple-symbols, injecting artificial
   dependence that would corrupt the pair-suite predictors; (c) the confidence bound is
   computed as-if-independent-draws — a stated approximation whose error is second-order at
   these n and is dominated by (and bundled into) the pre-registered bias windows below.
   **Phase coverage (panel Stat-B):** the tuple-MCV leg is computed at every phase offset
   (2 phases for pairs, 3 for triplets); the report shows all and the per-delta value takes
   the minimum — a phase-locked artifact cannot hide in the sampling alignment. (The suite leg runs at **both phase offsets** — per the pair-suite finding
   (layer 1 / panel C1) above and the `per_estimator_per_phase` sidecar schema. An
   earlier draft read "phase 0 only" here; **reconciled to both-phases at build,
   2026-07-10** — the ratified draft carried this internal contradiction. **FLAG for
   caraka's morning gate: confirm both-phases is intended** (the build implements
   both; the FFT half still owns periodic structure).)
3. **Tuple encoding (byte-exact):** big-endian symbol packing — pair code
   `(s₀ << bits) | s₁`; triplet code `(s₀ << 2·bits) | (s₁ << bits) | s₂`. Alphabet
   `2^(k·bits)`; histogram `2^(k·bits)` u64 slots via `.get_mut()` (4-bit data: 256 B /
   32 KiB; 8-bit-symbol triplet worst case 2²⁴ slots = 128 MiB, documented, offline-tool
   acceptable). Checked/explicit shift arithmetic per the crate's `arithmetic_side_effects`
   wall (the periodicity.rs precedent).
4. **Estimators:**
   - Pair-suite leg: the existing literal-track estimator functions on the pair-encoded
     `&[u8]` at `bits_per_symbol = 2·bits` (≤ 8 required: source bits ≤ 4 → suite leg
     available; for wider sources the suite leg reports "unavailable — symbol width" and the
     MCV legs stand alone). Reuses the `iid_gate` non-IID `h_original` composition.
   - Tuple-MCV leg: histogram → `mode_count`/`total` → the shared `mcv_from_mode` core
     (exposure widens to `pub(crate)`; verified present as `oxicrypt_maxwell::mcv_from_mode`) — identical math to
     the parity-proven `mcv()`. Plain form `−log₂(max p̂)` computed alongside.
   - Proximity ratios r₂, r₃ are computed from the **plain** form (matching the precedent's
     formula — panel C3) and always displayed next to their shuffled-baseline counterparts.
5. **Normalization plane:** per-delta — H₁, H₂/2, H₃/3 (and pair_suite_min/2); deficits
   Δₖ = (shuffled Hₖ − measured Hₖ)/k.
6. **Sample-size doctrine:** ≥10,000,000 deltas (precedent, quoted). Below: the printed
   warning + advisory-only flag semantics above.
7. **Degenerate inputs:** infallible, sentinel-based (periodicity `degenerate(n)` pattern);
   the fuzz target gains the new entry point (ISC-54 convention).

## CLI + evidence surface (frozen)

```
maxwell independence <FILE> <BITS_PER_SYMBOL> [--claim <H>] [--metadata <FILE>] [--sidecar <DIR>]
```

- Positional parsing via `read_file_and_bits` + the `--flag` loop (main.rs conventions).
- **Report:** n, tuple counts per leg, alphabet sizes + occupancy, the pair-suite table
  (per-estimator + min), tuple-MCV per phase, plain-form values, per-delta plane, shuffled
  baselines + deficits, r₂/r₃ (plain, with baseline), claim comparison + verdict (or
  advisory), the below-10M warning when applicable, and the standing "evidence screen —
  engineering choices, not spec constants" note.
- **Sidecar `independence-results.json`** (written to `--sidecar DIR`, default beside input):
  `{maxwell_version, run_utc, input_sha256, oe_id?, boundary?, timer_source?, n,
  bits_per_symbol, tuple_mode: "disjoint", phases, estimator_labels, shuffle: {master_seed,
  k_mcv: 10, k_suite: 1}, suite_1d: {per_estimator, min}, pair_suite: {per_estimator_per_phase,
  min, min_per_delta, structure_deficit_vs_1d, null_min, deficit_vs_null},
  mcv: {h1, h2, h3, per_delta_per_phase, plain, null_mean, null_spread, deficits,
  r2_plain, r3_plain}, claim?, flagged?, flag_cause?, advisory_only, degenerate}` — provenance fields copied from the
  collection metadata sidecar when `--metadata` is given (the ISC-120 recipe always gives
  it; panel C6 applied). Hand-written JSON, minimal-dependency posture, with the frozen
  serialization rules: **non-finite f64 → JSON `null` + `"degenerate": true`** (panel Build-2
  applied); floats via Rust default shortest-roundtrip `Display` (deterministic, bit-stable —
  pinned here); `determinism_bit_exact` extends to the sidecar bytes.
- **Anti:** `maxwell gate`'s four NIST-transcribed conditions untouched; the sidecar is read
  by humans and the evidence package, never by `gate`.

## Oracle set (tolerances pre-registered HERE — revised per panel; ISC-93 discipline)

- **O1 — analytic recovery, two regimes (panel Stat-1/Build-1 applied — the naive uniform
  ≤0.01 tolerance is unachievable and is withdrawn):**
  - *(a) concentrated distributions* (heavy mode, e.g. max-symbol-prob 0.5): measured
    bounded-MCV per-delta within **≤0.01 bit** of analytic (verified reachable: recovery
    ≈0.995/0.994 at n=1M).
  - *(b) uniform / near-uniform:* two-sided **per-alphabet windows** — measured ∈
    [analytic − Δ, analytic], with Δ pre-registered from the max-of-bins + confidence-width
    math at the test n (n = 1M synthetic): **Δ(pairs, 256 bins) = 0.15 bit; Δ(triplets,
    4096 bins) = 0.30 bit**; plus the one-sided conservatism assertion (bounded form never
    exceeds analytic — both biases push conservative). Sign/normalization/packing bugs
    produce misses ≫ these windows; the windows are generous to bias, not to defects.
  - *(c) plain-form uniform recovery:* within **0.05 bit** at n = 1M (mode bias only).
- **O2 — analytic dependence detection.** First-order Markov chain, known transition matrix,
  deterministic synthesis: exact analytic max pair prob = max(πᵢPᵢⱼ), triplet =
  max(πᵢPᵢⱼPⱼₖ). Plain-form recovery within the O1(c)/window regime AND the shuffled-baseline
  deficit must be positive and ≥ half the analytic dependence gap (detection direction
  proven). Kills the "reports independence for everything" class.
- **O3 — internal bit-identity + inherited EA parity.** The pair-MCV path must equal
  `mcv(pair_encoded_buf, 2·bits).literal` **bit-exactly** (same core; verified sound against
  `oxicrypt_maxwell::mcv` / `mcv_literal`). The pair-suite leg must equal the existing per-estimator functions run
  directly on the encoded buffer, bit-exactly (code-path consistency). Optional
  `parity`-style extension (Skip-if-absent): EA MCV on a pair-encoded reference file, ≤1e-6.
  **Triplets have no external reference (12-bit exceeds EA's wire)** — mitigated by the
  shared-core argument + O1/O2 + the one-time independent replication in the ISC-120 recipe
  (below; panel C5 applied).
- **O4 — determinism + encoder KATs.** `determinism_bit_exact` (report AND sidecar bytes);
  byte-exact known-answer vectors for the encoder asserting the **full tuple-code sequence**
  (stride + phase + tail semantics, not just the mapping — panel Build-risk applied), with an
  **odd-length pair vector (9 symbols)** and a non-multiple-of-3 triplet vector (8 symbols)
  so tail truncation is exercised on both paths (panel Build-3 applied).
- Registered in `~/repos/oxicrypt/docs/estimator-parity-tolerances.md` at build, before the
  first oracle run.

## ISC-120 run integration (the ≥10M collection rider)

- **Collection rider — separate, review-gated slice (panel applied: NOT night-scoped).** The
  `collect` binary gains a characterization mode: contract frozen as `--characterization N`
  → contiguous single-run `characterization.bin` (N one-byte symbols) + metadata sidecar
  marked `"characterization": true` (schema-versioned per ISC-14; G16 semantics — health
  battery live, trips recorded, no filtering; prefer a trip-free run for the package,
  re-collect on trip). Implementation details follow a build-time survey of `collection.rs`;
  because that survey is a judgment point, this slice runs attended-or-reviewed, not in an
  unattended night.
- **The run (attended, bare metal):** both boundaries × ≥10M; then per boundary
  `maxwell independence characterization.bin 4 --claim 0.5 --metadata metadata.json` +
  `maxwell periodicity` on the same capture (10M pads to 16.7M complex ≈ 400 MiB —
  documented; fine on the bare-metal host). Sidecars land beside `gate-results.json` in the per-OE
  layout (ISC-61); **both boundaries are required** for the evidence package entry (panel
  C6/Risk-4).
- **One-time independent replication (panel C5):** on the banked 10M datasets, the tuple-MCV
  numbers (pairs + triplets, measured + shuffled-baseline) are replicated once in an
  independent implementation (numpy — the #102 periodicity precedent) and the match recorded
  in the assessment note. This is the external check the triplet path otherwise lacks.
- **What flips when:** ISC-121 → [x] at build + oracles green; ISC-120 → [x] at the bare-metal
  run with both boundaries' sidecars + the replication note banked.

## Build plan (night-runnable except where marked, oracle-gated)

- S1: tuple encoder (+ phases, tail semantics) + histogram + `mcv_from_mode` `pub(crate)`
  exposure; O4 encoder KATs (odd-tail vectors).
- S2: legs — tuple-MCV (bounded + plain, per phase) + pair-suite composition (reuse literal
  estimator fns) + shuffled-baseline (ISC-134 fixed-seed shuffle, documented constant).
- S3: report + flag/advisory semantics + degenerate handling.
- S4: CLI subcommand + sidecar writer (serialization rules above; `--metadata` copy-through).
- S5: oracles O1–O4 + fuzz-target line + tolerances-doc entry (before first oracle run).
- S6: doc-sync — CHANGELOG `[Unreleased]`, module `//!` header (semantics + limitations
  wording from this doc), entropy-ISA ISC-121 annotation, `ea-cli-mapping.md` note ("no EA
  analog — evidence subcommand"), design doc graduates to `docs/design/`.
- SEPARATE (attended-or-reviewed): the `collect --characterization` rider slice.
- Gates: fmt, crate-local clippy `--all-targets -D warnings` (the workspace-vs-crate gap),
  nextest, fuzz smoke.

## Panel triage record (2026-07-09)

Applied: Stat-1/Build-1 (O1 restructured — windows + one-sided conservatism + concentrated
regime), Stat-2 (disjoint rationale corrected), Stat-A/C3/C4 (shuffled-baseline control;
plain-form ratios), Stat-B (multi-phase MCV), Stat-E (advisory-only below 10M), CMVP-C1
(pair-suite leg — the probative upgrade), CMVP-C2 (semantics reframed; G18 wording touch at
injection), CMVP-C5 (numpy one-time replication), CMVP-C6 (sidecar provenance via
--metadata + run_utc + labels), CMVP-Risk-2 (disjoint mass loss priced into windows; stated),
CMVP-Risk-3 (substrate departure stated), CMVP-Risk-4 (both-boundary requirement),
CMVP-Risk-5 (10M FFT with ratified #102 screen), Build-2 (non-finite JSON → null+flag;
format pinned), Build-3 (odd-tail KATs), Build-risks (stride-asserting KATs; rider
de-scoped from nights; shift-arithmetic note).
Accepted-documented (declined to change): Stat-C/D (k≤3 + flag floor-detector nature —
inherent to the precedent method; delegation stated), periodicity 400 MiB at 10M (offline
tool, bare-metal headroom).

## Deliberately not in scope

Lag>1 tuple variants (FFT + the 1-D Lag estimator own lagged/periodic structure); formal
hypothesis tests; overlapping-tuple variants (corrupts the suite leg; see Method 2);
any `maxwell gate` change; EA parity for triplets (wire-format impossible); streaming
readers (10 MB fits the whole-file convention).
