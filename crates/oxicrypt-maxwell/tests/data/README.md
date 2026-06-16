# maxwell §5 IID oracle datasets

Deterministic synthetic datasets used to exercise the SP 800-90B §5 IID
verdict layer (permutation battery, chi-square, LRS) with unambiguous,
order-dependent ground truth. The 11 NIST EA-distribution datasets are all
non-IID-oriented, leaving the IID branch of the verdict logic with nothing
clearly-passing to test against — these fill that gap.

| File | Source model | Expected §5 verdict |
|------|--------------|---------------------|
| `oracle_iid.bin` | SplitMix64 stream, low byte (8-bit uniform, no serial dependence) | **IID** (passes permutation, chi-square, LRS) |
| `oracle_noniid.bin` | serially-correlated random walk mod 256 | **non-IID** (fails permutation, chi-square, LRS) |

Each is 100,000 samples, one byte per sample. Sizes chosen for a stable
verdict while keeping the 10,000-shuffle permutation run tractable.

## Provenance

```
SHA-256(oracle_iid.bin)    = 5dc8eb2358f7478644aefbbf8615d9dcce9082f6890e304e11254faede818962
SHA-256(oracle_noniid.bin) = e9f07e05e752bb14dc368b729a25add38ba9a6304b58b25943f2d5d1bce7ccaa
```

Ground-truth verdicts confirmed against the NIST `ea_iid` reference tool
(SP800-90B_EntropyAssessment v1.1.8, `-i -v`):

- `oracle_iid.bin`   → *Passed* chi square tests, *Passed* LRS test, *Passed* IID permutation tests.
- `oracle_noniid.bin` → *Failed* chi square tests, *Failed* LRS test, *Failed* IID permutation tests.

## Regeneration

`oracle_generator.rs` is the standalone generator (fixed seeds → byte-identical
output). It is not part of the crate build (data directory, not a test target):

```
rustc -O -o /tmp/gen_oracle oracle_generator.rs
/tmp/gen_oracle   # writes /tmp/oracle_iid.bin and /tmp/oracle_noniid.bin
```
