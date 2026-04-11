# DRBG CAVP traceability

This document records the exact vendored source of every power-up
known-answer test currently wired into `fips-drbg` under the
`KATS` inventory exported by `crates/fips-drbg/src/kat.rs`.

Each row identifies the vector by:

 - the SP 800-90A mechanism and configuration exercised,
 - the vendored `.rsp` file under `vendor/nist/cavp-drbg/`,
 - the CAVS section header and `COUNT` index inside that file,
 - the starting line number of the test block in the vendored file.

All vectors are drawn from the NIST CAVP DRBG Validation System
(DRBGVS) test set `drbgtestvectors`, `drbgvectors_no_reseed/`
family. The vendored `.rsp` files live under
`vendor/nist/cavp-drbg/no_reseed/`.

## Vendored source files

| File                                          | SHA-256                                                            |
| --------------------------------------------- | ------------------------------------------------------------------ |
| `vendor/.../no_reseed/CTR_DRBG.rsp`           | `93676a5cb2dd890edbd2b43386e6c627123f35333de0b09d9fb107578ca7f5d2` |
| `vendor/.../no_reseed/Hash_DRBG.rsp`          | `3b1c535abe7d56b5883e413fe2d62359e02a1bcf80097d19276f75a0c5b75939` |
| `vendor/.../no_reseed/HMAC_DRBG.rsp`          | `9fdd7f11dbbe75e0a7e19c6ae57660008dd4e74672ebb67119cab287c7aa5a79` |

## KAT inventory

### CTR_DRBG (SP 800-90A §10.2)

All six CTR_DRBG KATs use `PredictionResistance = False`,
`PersonalizationStringLen = 0`, and `AdditionalInputLen = 0`.
Each test drives one `Instantiate` call followed by two `Generate`
calls, matching the CAVS test block layout.

| KAT name (as reported by harness)                                          | Mechanism          | Variant   | `EntropyInputLen` | `NonceLen` | `ReturnedBitsLen` | Source section       | `COUNT` | First line |
| -------------------------------------------------------------------------- | ------------------ | --------- | ----------------- | ---------- | ----------------- | -------------------- | ------- | ---------- |
| `CTR_DRBG AES-128 no df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`       | CTR_DRBG / AES-128 | `no df`   | 256               | 0          | 512               | `[AES-128 no df]`    | 0       | 10248      |
| `CTR_DRBG AES-192 no df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`       | CTR_DRBG / AES-192 | `no df`   | 320               | 0          | 512               | `[AES-192 no df]`    | 0       | 12296      |
| `CTR_DRBG AES-256 no df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`       | CTR_DRBG / AES-256 | `no df`   | 384               | 0          | 512               | `[AES-256 no df]`    | 0       | 14344      |
| `CTR_DRBG AES-128 use df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`      | CTR_DRBG / AES-128 | `use df`  | 128               | 64         | 512               | `[AES-128 use df]`   | 0       | 2056       |
| `CTR_DRBG AES-192 use df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`      | CTR_DRBG / AES-192 | `use df`  | 192               | 96         | 512               | `[AES-192 use df]`   | 0       | 4104       |
| `CTR_DRBG AES-256 use df KAT (NIST CAVP DRBGVS CTR_DRBG.rsp Count=0)`      | CTR_DRBG / AES-256 | `use df`  | 256               | 128        | 512               | `[AES-256 use df]`   | 0       | 6152       |

The six CTR_DRBG KAT vector constants are embedded directly in
`crates/fips-drbg/src/kat.rs` as `AES{128,192,256}_{NO,USE}_DF_*`
byte arrays. The CAVS block defines `EntropyInput`, `Nonce`,
`PersonalizationString`, two `AdditionalInput` strings (one per
Generate call), and a single `ReturnedBits` field that carries the
output of the *second* Generate call. The harness therefore runs
two back-to-back `generate_{no,use}_df(None, &mut out)` calls and
compares only the second against `ReturnedBits`, exactly matching
CAVS semantics.

### Hash_DRBG (SP 800-90A §10.1.1)

All three Hash_DRBG KATs use `PredictionResistance = False`,
`PersonalizationStringLen = 0`, and `AdditionalInputLen = 0`. Each
test drives `Instantiate` + two `Generate` calls; the harness
compares the output of the second Generate against
`ReturnedBits`, matching the CAVS block layout.

| KAT name (as reported by harness)                                   | Digest    | `EntropyInputLen` | `NonceLen` | `ReturnedBitsLen` | Source section | `COUNT` | First line |
| ------------------------------------------------------------------- | --------- | ----------------- | ---------- | ----------------- | -------------- | ------- | ---------- |
| `Hash_DRBG SHA-256 KAT (NIST CAVP DRBGVS Hash_DRBG.rsp Count=0)`   | SHA-256   | 256               | 128        | 1024              | `[SHA-256]`    | 0       | 4104       |
| `Hash_DRBG SHA-384 KAT (NIST CAVP DRBGVS Hash_DRBG.rsp Count=0)`   | SHA-384   | 256               | 128        | 1536              | `[SHA-384]`    | 0       | 6152       |
| `Hash_DRBG SHA-512 KAT (NIST CAVP DRBGVS Hash_DRBG.rsp Count=0)`   | SHA-512   | 256               | 128        | 2048              | `[SHA-512]`    | 0       | 8200       |

### HMAC_DRBG (SP 800-90A §10.1.2)

All three HMAC_DRBG KATs use `PredictionResistance = False`,
`PersonalizationStringLen = 0`, and `AdditionalInputLen = 0`. Each
test drives `Instantiate` + two `Generate` calls; the harness
compares the output of the second Generate against
`ReturnedBits`.

| KAT name (as reported by harness)                                    | HMAC         | `EntropyInputLen` | `NonceLen` | `ReturnedBitsLen` | Source section | `COUNT` | First line |
| -------------------------------------------------------------------- | ------------ | ----------------- | ---------- | ----------------- | -------------- | ------- | ---------- |
| `HMAC_DRBG SHA-256 KAT (NIST CAVP DRBGVS HMAC_DRBG.rsp Count=0)`    | HMAC-SHA-256 | 256               | 128        | 1024              | `[SHA-256]`    | 0       | 4104       |
| `HMAC_DRBG SHA-384 KAT (NIST CAVP DRBGVS HMAC_DRBG.rsp Count=0)`    | HMAC-SHA-384 | 256               | 128        | 1536              | `[SHA-384]`    | 0       | 6152       |
| `HMAC_DRBG SHA-512 KAT (NIST CAVP DRBGVS HMAC_DRBG.rsp Count=0)`    | HMAC-SHA-512 | 256               | 128        | 2048              | `[SHA-512]`    | 0       | 8200       |

## SP 800-90A §11.3 health tests

Three additional entries in the DRBG KAT inventory are synthetic
error-path health tests drawn directly from SP 800-90A §11.3.2, not
from CAVP. They exercise the four behaviours §11.3.2 calls out:
generate-before-instantiate → `DrbgError::Uninstantiated`, normal
`Instantiate` + `Generate` success, forced reseed-counter ceiling →
`DrbgError::ReseedRequired`, and post-`Uninstantiate` access →
`DrbgError::Uninstantiated`. Entropy inputs for these tests are
arbitrary (`0x5a` / `0xa5` byte patterns) because value-level
correctness is covered by the CAVP KATs above.

| KAT name                                                       | Mechanism              | Spec section |
| -------------------------------------------------------------- | ---------------------- | ------------ |
| `CTR_DRBG (AES-128 use df) SP 800-90A §11.3 health test`      | CTR_DRBG / AES-128 df  | §11.3.2      |
| `Hash_DRBG (SHA-256) SP 800-90A §11.3 health test`            | Hash_DRBG / SHA-256    | §11.3.2      |
| `HMAC_DRBG (SHA-256) SP 800-90A §11.3 health test`            | HMAC_DRBG / SHA-256    | §11.3.2      |

These live in `crates/fips-drbg/src/health.rs` and are wired into
the power-up KAT path alongside the CAVP KATs so that FIPS 140-3 IG
10.3.A's "known-answer tests run at power-up" requirement covers
both the value-level KATs and the §11.3 error-path tests in a
single initialization call.

## Gaps / open items

- **Prediction-resistance KATs.** `fips-drbg` now implements the
  SP 800-90A §9.3 prediction-resistance generate wrappers
  (`generate_pr`, `generate_df_pr`, `generate_no_df_pr`), but
  power-up KATs against the CAVP `drbgvectors_pr_true/*.rsp` files
  are not wired yet. Consistency unit tests
  (`generate_pr_matches_reseed_then_generate`) verify that the
  wrappers are equivalent to explicit `reseed` + `generate` calls;
  real CAVP KATs will be added once the `pr_true` vectors are
  vendored into `vendor/nist/cavp-drbg/`.
- **Reseed-only KATs.** `drbgvectors_pr_false/*.rsp` contains
  vectors that exercise `Instantiate` + `Reseed` + `Generate`.
  These are not vendored or wired.
- **Larger `COUNT` indices.** Only `COUNT = 0` is currently wired
  per configuration. FIPS 140-3 IG 10.3.A requires one KAT per
  approved security function, not one per vector, so the current
  coverage satisfies the IG; additional counts would improve
  assurance but are not compliance-driven.
