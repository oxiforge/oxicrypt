# Estimator Parity Tolerances — Pre-Registration

Pre-registered acceptance thresholds for the `oxicrypt-maxwell` estimator
suite's parity verification against the NIST SP 800-90B Entropy Assessment
reference tool. Recorded **before any parity result exists**, so that
acceptance criteria cannot drift toward observed outcomes. The git history
of this file is the evidence that the thresholds predate the results.

## Oracle

- **Reference implementation:** NIST `SP800-90B_EntropyAssessment` ("EA
  tool"), version 1.1.8.
- **Datasets:** the 11 sample datasets bundled with the EA distribution.
- **Reference values:** EA tool output on those files, identical parameters,
  recorded per run alongside the EA tool version (provenance requirement).

## Thresholds

1. **Numeric estimators** — most common value, collision, Markov,
   compression, t-tuple, LRS, multiMCW prediction, lag prediction,
   multiMMC prediction, LZ78Y prediction: per-estimator **absolute delta
   ≤ 1.0e-6 bits** of min-entropy versus the EA estimate, on every bundled
   dataset.
2. **IID-track permutation-testing battery:** **verdict equality** with the
   EA tool per dataset (pass/fail match; no numeric tolerance applies).
3. **Restart analysis (row/column):** the same **≤ 1.0e-6 bits** absolute
   delta on the row and column estimates.

## Independence analysis (ISC-121 — 2D/3D min-entropy oracles O1–O4)

Pre-registered **before the first oracle run** for the `maxwell independence`
subcommand (design of record: `docs/design/independence-analysis.md`; ratified
2026-07-09). These are oracle tolerances for a reviewer-facing evidence
subcommand, not EA-parity bounds — the naive uniform ≤ 0.01 tolerance was proven
unachievable and is withdrawn (panel Stat-1/Build-1); the pairs/triplets bias
windows below were derived from the max-of-bins + confidence-width math at the
test `n`.

- **O1 — analytic recovery, two regimes (test n = 1,000,000):**
  - *(a) concentrated distributions* (heavy mode, max-symbol-prob 0.5): measured
    bounded-MCV per-delta (pairs and triplets) within **≤ 0.01 bit** of the
    analytic per-delta 1.0, and never exceeding it (one-sided conservatism —
    both finite-sample bias and the confidence bound push down).
  - *(b) uniform / near-uniform:* two-sided **per-alphabet windows** — measured
    per-delta ∈ `[analytic − Δ, analytic]`, with **Δ(pairs, 256 bins) = 0.15
    bit** and **Δ(triplets, 4096 bins) = 0.30 bit**, plus the one-sided
    conservatism assertion (bounded form never exceeds analytic).
  - *(c) plain-form 1-D uniform recovery:* within **0.05 bit** at n = 1M (mode
    bias only).
- **O2 — analytic dependence detection.** First-order Markov chain, known
  transition matrix, deterministic synthesis: plain-form recovery within the
  O1(c)/window regime AND the shuffled-baseline deficit **positive and ≥ half the
  analytic dependence gap** (detection direction proven).
- **O3 — internal bit-identity.** The pair-MCV path equals
  `mcv(pair_encoded_buf, 2·bits).literal` **bit-exactly**; the pair-suite leg
  equals the per-estimator functions run directly on the encoded buffer,
  **bit-exactly**. Triplets have no external reference (12-bit exceeds EA's wire);
  the EA-parity extension is Skip-if-absent (no forced triplet reference).
- **O4 — determinism + encoder KATs.** `determinism_bit_exact` over BOTH the
  report and the sidecar bytes (with a fixed `run_utc`); byte-exact encoder KATs
  asserting the **full tuple-code sequence** (stride + phase + tail) with an
  odd-length (9-symbol) pair vector and a non-multiple-of-3 (8-symbol) triplet
  vector so tail truncation is exercised on both paths.

The shuffled-baseline control (both legs) uses the ISC-134 deterministic shuffle
under a documented master seed (`independence::INDEPENDENCE_MASTER_SEED`, the
SHA-512 √11/√13/√17/√19 IV words), reusing the vetted xoshiro256** +
Lemire `randomRange64` + Fisher–Yates machinery — no new RNG.

## Escape hatch (pre-registered)

Any looser per-estimator bound requires a **written numerical-analysis
rationale and project-lead sign-off BEFORE that estimator's parity
verification is attempted** — never after observing a failure. A bound
loosened in response to a failing result would be goalpost-moving and is
categorically excluded.

## Rationale for 1.0e-6

The bound matches the acceptance bar used by the EA distribution's own
selftest (observed selftest deltas on a conforming build run in the
1e-16 … 1e-13 range — three to ten orders of magnitude inside the bound).
The EA tool is compiled with `-ffloat-store` precisely because its own
floating-point results are platform-sensitive; a tolerance at the EA
selftest bar absorbs that nondeterminism while remaining far below any
difference that could matter to an entropy claim.
