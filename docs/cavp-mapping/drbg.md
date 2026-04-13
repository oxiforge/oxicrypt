# DRBG CAVP traceability

This document records the exact vendored source of every power-up
known-answer test currently wired into `oxicrypt-drbg` under the
`KATS` inventory exported by `crates/oxicrypt-drbg/src/kat.rs`.

Each row identifies the vector by:

 - the SP 800-90A mechanism and configuration exercised,
 - the vendored `.rsp` file under `vendor/nist/cavp-drbg/`,
 - the CAVS section header and `COUNT` index inside that file,
 - the starting line number of the test block in the vendored file.

All vectors are drawn from the NIST CAVP DRBG Validation System
(DRBGVS) test set `drbgtestvectors`, families
`drbgvectors_no_reseed/` (non-PR value-level KATs) and
`drbgvectors_pr_true/` (prediction-resistance KATs per
SP 800-90A §9.3). The vendored `.rsp` files live under
`vendor/nist/cavp-drbg/no_reseed/` and
`vendor/nist/cavp-drbg/pr_true/`.

## Vendored source files

| File                                          | SHA-256                                                            |
| --------------------------------------------- | ------------------------------------------------------------------ |
| `vendor/.../no_reseed/CTR_DRBG.rsp`           | `93676a5cb2dd890edbd2b43386e6c627123f35333de0b09d9fb107578ca7f5d2` |
| `vendor/.../no_reseed/Hash_DRBG.rsp`          | `3b1c535abe7d56b5883e413fe2d62359e02a1bcf80097d19276f75a0c5b75939` |
| `vendor/.../no_reseed/HMAC_DRBG.rsp`          | `9fdd7f11dbbe75e0a7e19c6ae57660008dd4e74672ebb67119cab287c7aa5a79` |
| `vendor/.../pr_true/CTR_DRBG.rsp`             | `66ff3e16a93b74896d180d683e0057ed2eb5943443693963064ac245bad46f0c` |
| `vendor/.../pr_true/Hash_DRBG.rsp`            | `d0f1bb75d8745849baa3e72eaa58d729be2b713d0d250bcf23ce90380ca62da4` |
| `vendor/.../pr_true/HMAC_DRBG.rsp`            | `806f71be8d100702450191d847bbfe3c405f31cdaca219eee6918cb77a7a2f55` |

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
`crates/oxicrypt-drbg/src/kat.rs` as `AES{128,192,256}_{NO,USE}_DF_*`
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

## Prediction-resistance KATs (SP 800-90A §9.3)

Nine additional CAVP KATs exercise the SP 800-90A §9.3
prediction-resistance path via the `generate_pr` / `generate_df_pr`
wrappers on each DRBG. All use `PredictionResistance = True`,
`PersonalizationStringLen = 0`, and `AdditionalInputLen = 0`.

The CAVS record for a PR test contains two `(AdditionalInput,
EntropyInputPR)` pairs per `COUNT`, one per PR-Generate call. Each
PR-Generate first runs `Reseed(entropy_input, additional_input)`
and then `Generate(NULL)` (per §9.3.1 process step 7). With
`AdditionalInputLen = 0` both additional inputs are empty. The
harness calls the `*_pr` wrapper twice per test and compares only
the second call's output against `ReturnedBits`, matching CAVS
semantics.

| KAT name (as reported by harness)                                                | Mechanism              | Variant   | `EntropyInputLen` | `NonceLen` | `ReturnedBitsLen` | Source section       | `COUNT` | First line |
| -------------------------------------------------------------------------------- | ---------------------- | --------- | ----------------- | ---------- | ----------------- | -------------------- | ------- | ---------- |
| `CTR_DRBG AES-128 use df PR KAT (NIST CAVP DRBGVS pr_true CTR_DRBG.rsp Count=0)` | CTR_DRBG / AES-128     | `use df`  | 128               | 64         | 512               | `[AES-128 use df]`   | 0       | 2536       |
| `CTR_DRBG AES-192 use df PR KAT (NIST CAVP DRBGVS pr_true CTR_DRBG.rsp Count=0)` | CTR_DRBG / AES-192     | `use df`  | 192               | 128        | 512               | `[AES-192 use df]`   | 0       | 5064       |
| `CTR_DRBG AES-256 use df PR KAT (NIST CAVP DRBGVS pr_true CTR_DRBG.rsp Count=0)` | CTR_DRBG / AES-256     | `use df`  | 256               | 128        | 512               | `[AES-256 use df]`   | 0       | 7592       |
| `Hash_DRBG SHA-256 PR KAT (NIST CAVP DRBGVS pr_true Hash_DRBG.rsp Count=0)`      | Hash_DRBG / SHA-256    |     —     | 256               | 128        | 1024              | `[SHA-256]`          | 0       | 5064       |
| `Hash_DRBG SHA-384 PR KAT (NIST CAVP DRBGVS pr_true Hash_DRBG.rsp Count=0)`      | Hash_DRBG / SHA-384    |     —     | 256               | 128        | 1536              | `[SHA-384]`          | 0       | 7592       |
| `Hash_DRBG SHA-512 PR KAT (NIST CAVP DRBGVS pr_true Hash_DRBG.rsp Count=0)`      | Hash_DRBG / SHA-512    |     —     | 256               | 128        | 2048              | `[SHA-512]`          | 0       | 10120      |
| `HMAC_DRBG SHA-256 PR KAT (NIST CAVP DRBGVS pr_true HMAC_DRBG.rsp Count=0)`      | HMAC_DRBG / SHA-256    |     —     | 256               | 128        | 1024              | `[SHA-256]`          | 0       | 5064       |
| `HMAC_DRBG SHA-384 PR KAT (NIST CAVP DRBGVS pr_true HMAC_DRBG.rsp Count=0)`      | HMAC_DRBG / SHA-384    |     —     | 256               | 128        | 1536              | `[SHA-384]`          | 0       | 7592       |
| `HMAC_DRBG SHA-512 PR KAT (NIST CAVP DRBGVS pr_true HMAC_DRBG.rsp Count=0)`      | HMAC_DRBG / SHA-512    |     —     | 256               | 128        | 2048              | `[SHA-512]`          | 0       | 10120      |

CTR_DRBG `no df` PR KATs are not yet wired; the `use df` path
exercises both the Block_Cipher_df derivation function (via
Instantiate) and the CTR_DRBG_Update / Generate state machine, so
the PR reseed path is fully covered for every AES key size. The
`no df` PR vectors are still in `vendor/.../pr_true/CTR_DRBG.rsp`
and can be wired later if deeper CTR-mode coverage is wanted.

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

These live in `crates/oxicrypt-drbg/src/health.rs` and are wired into
the power-up KAT path alongside the CAVP KATs so that FIPS 140-3 IG
10.3.A's "known-answer tests run at power-up" requirement covers
both the value-level KATs and the §11.3 error-path tests in a
single initialization call.

## Gaps / open items

- **CTR_DRBG `no df` prediction-resistance KATs.** Only the
  `use df` variant is wired for the PR path. The `no df` PR
  vectors are present in `vendor/.../pr_true/CTR_DRBG.rsp`; wiring
  them would add three KATs (AES-128/192/256 `no df` PR) but is
  not compliance-driven — FIPS 140-3 IG 10.3.A requires exercising
  each approved security function at power-up, and the `no df`
  state machine is already covered by the non-PR KATs.
- **Reseed-only KATs.** `drbgvectors_pr_false/*.rsp` contains
  vectors that exercise `Instantiate` + explicit `Reseed` +
  `Generate` (without prediction resistance). These are vendored
  in `drbgvectors_pr_false.zip` but not extracted or wired. The
  §9.3 PR KATs already exercise the reseed path; non-PR reseed
  KATs would primarily exercise the explicit `reseed()` API
  surface.
- **Larger `COUNT` indices.** Only `COUNT = 0` is currently wired
  per configuration. FIPS 140-3 IG 10.3.A requires one KAT per
  approved security function, not one per vector, so the current
  coverage satisfies the IG; additional counts would improve
  assurance but are not compliance-driven.
