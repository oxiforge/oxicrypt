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
