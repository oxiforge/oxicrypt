# maxwell ↔ NIST EA-tool CLI mapping

`oxicrypt-maxwell` reproduces the analyses of the three NIST
`SP800-90B_EntropyAssessment` ("EA tool", v1.1.8) command-line programs. The EA
tool uses three flag-driven binaries; maxwell uses one binary with a subcommand
per analysis (so each estimator/test is independently runnable and scriptable).
This table maps each EA invocation to its maxwell equivalent. All maxwell
estimator output is full-precision and on the same track the EA parity table
records; `maxwell parity` cross-checks every value against the EA tool.

## ea_iid — IID-track assessment

EA: `ea_iid [-i|-c] [-a|-t] [-v] [-q] [-l idx,n] <file> [bits]`

| EA analysis | maxwell |
|-------------|---------|
| §6.1 most-common-value estimate | `maxwell mcv <file> <bits>` |
| §5.1 permutation battery (19-stat IID test) | `maxwell iid-permutation <file>` |
| §5.2 chi-square (independence + goodness-of-fit) | `maxwell chi-square <file>` |
| §5.3 longest-repeated-substring IID test | `maxwell lrs-iid <file>` |
| combined §5 verdict + routed assessment (the `ea_iid` top-level result) | `maxwell iid-gate <file> <bits>` |

## ea_non_iid — non-IID-track assessment

EA: `ea_non_iid [-i|-c] [-a|-t] [-v] [-q] [-l idx,n] <file> [bits]`

| EA §6.3 estimator | maxwell |
|-------------------|---------|
| §6.3.1 Most Common Value | `maxwell mcv <file> <bits>` |
| §6.3.2 Collision | `maxwell collision <file> <bits>` |
| §6.3.3 Markov | `maxwell markov <file> <bits>` |
| §6.3.4 Compression | `maxwell compression <file> <bits>` |
| §6.3.5 t-Tuple | `maxwell t-tuple <file> <bits>` |
| §6.3.6 LRS | `maxwell lrs <file> <bits>` |
| §6.3.7 MultiMCW prediction | `maxwell multi-mcw <file> <bits>` |
| §6.3.8 Lag prediction | `maxwell lag <file> <bits>` |
| §6.3.9 MultiMMC prediction | `maxwell multi-mmc <file> <bits>` |
| §6.3.10 LZ78Y prediction | `maxwell lz78y <file> <bits>` |
| the full suite at once (the `ea_non_iid` result = min over all) | `maxwell parity` (cross-checks every estimator vs the EA reference) |

## ea_restart — restart-data analysis

EA: `ea_restart [-i|-n] [-v] [-q] [-s sim] <file> [bits] <H_I>`

| EA analysis | maxwell |
|-------------|---------|
| §3.1.4.3 sanity check + §5 row/col battery + min(H_r,H_c,H_I) gate | `maxwell restart <file> <bits> <H_I>` |

Argument order matches EA: `<file> <bits> <H_I>`.

## Flag mapping

| EA flag | maxwell |
|---------|---------|
| `-i` (initial entropy estimate) | the default and only mode — maxwell assesses the raw symbols directly |
| `-c` (conditioned sequential dataset) | not implemented (out of scope for this tool) |
| `-a` / `-t` (assess all bits / truncate) | maxwell reports both the literal and bitstring tracks per estimator where the EA tool does; no truncation mode |
| `-v` (verbose) | maxwell always prints full-precision values (no quiet/verbose levels) |
| `-q` (quiet) | not applicable |
| `-s <sim>` (restart simulation count) | the EA default (5,000,000) is built in; not currently a flag |
| `[bits]` inferred from data | maxwell takes `<bits>` explicitly (1..=8) |

## Notes

- The EA tool requires ≥1,000,000 samples; maxwell does not enforce a minimum
  (it is also used on the 10k EA self-test datasets and on synthetic fixtures).
- maxwell's shuffle (§5.1) and restart sanity Monte-Carlo use a fixed seed, so
  every run is bit-reproducible — unlike the EA tool, which seeds from
  `/dev/urandom`. Statistic values and stable-dataset verdicts match the EA tool;
  the stochastic shuffle counts do not (by construction).
