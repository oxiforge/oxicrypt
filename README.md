# oxicrypt

Pure-Rust FIPS 140-3 Level 1 cryptographic module.

oxicrypt implements FIPS-approved cryptographic algorithms in pure Rust
with `no_std` support, a formal module boundary, power-up self-tests, and
an ACVP test harness — targeting CAVP algorithm validation and CMVP module
validation through an accredited CST laboratory.

**Target:** FIPS 140-3 Level 1, following FIPS 140-3 Implementation
Guidance D.G (March 2026).

## Quick start

```bash
# Build the module and ACVP harness
cargo build --workspace

# Sign the harness binary for the integrity self-test
cargo build -p oxicrypt-integrity
./target/debug/fips-integrity-sign --sign target/debug/acvp-harness

# Run all 183 power-up self-tests + software integrity check
./target/debug/acvp-harness

# Run the full test suite (120 ACVP round-trip + 7 CAVP SHS + unit tests)
cargo test --workspace
```

### Requirements

- **Rust 1.95+** (MSRV enforced in `Cargo.toml`; toolchain pinned via `rust-toolchain.toml`; workspace targets edition 2024)
- No third-party dependencies — all cryptography is pure Rust, written in-tree
- Builds on Linux, macOS, and Windows; `no_std` core crates work on any target

### Installing the git hooks

Contributors should enable the versioned hooks on a fresh clone — this
activates the pre-commit doc-sync guard that keeps
`docs/llm-api-manifest/llm-api.yaml` in step with the public API:

```bash
git config core.hooksPath scripts/git-hooks
```

The hooks live under `scripts/git-hooks/` so they are reviewable in
PRs rather than hidden in each contributor's `.git/hooks/`.

## Algorithms

| Family | Algorithms | Standard |
|--------|-----------|----------|
| Hashing | SHA-1, SHA-2 (224/256/384/512/512-224/512-256), SHA-3 (224/256/384/512), SHAKE128, SHAKE256 | FIPS 180-4, FIPS 202 |
| MAC | HMAC over all 11 approved hashes, AES-CMAC (128/192/256) | FIPS 198-1, SP 800-38B |
| Symmetric | AES-128/192/256 in ECB, CBC, CTR, GCM, CCM, KW, KWP modes | FIPS 197, SP 800-38A/C/D/F |
| DRBG | CTR_DRBG (AES-128/192/256), Hash_DRBG (SHA-256/384/512), HMAC_DRBG (SHA-256/384/512) | SP 800-90A Rev. 1 |
| KDF | SP 800-108r1 (counter/feedback/double-pipeline), SP 800-56C Rev 2 KDA-HKDF, TLS 1.2 KDF, TLS 1.3 KDF, PBKDF2 | SP 800-108, SP 800-56Cr2, SP 800-132, RFC 8446 |
| SP 800-185 | cSHAKE, KMAC, TupleHash, ParallelHash (+ XOF variants) | SP 800-185 |
| RSA | RSA-2048/3072/4096 PKCS#1 v1.5 and PSS sign/verify, OAEP encrypt/decrypt, keygen with CRT + Bellcore | FIPS 186-5, SP 800-56Br2 |
| ECDSA | P-256 and P-384 sign/verify/keygen with DRBG-backed rejection sampling | FIPS 186-5 |
| ECDH | P-256 and P-384 CDH shared secret computation | SP 800-56Ar3 |
| EdDSA | Ed25519 deterministic sign/verify/keygen | RFC 8032, FIPS 186-5 §7.8 |
| ML-KEM | ML-KEM-512/-768/-1024 keygen/encaps/decaps | FIPS 203 |
| ML-DSA | ML-DSA-44/-65/-87 sign/verify/keygen | FIPS 204 |
| SLH-DSA | SLH-DSA full family — SHA2 (128s/f, 192s/f, 256s/f) and SHAKE (128s/f, 192s/f, 256s/f) sign/verify/keygen | FIPS 205 |
| LMS | LMS sign/verify across the complete SP 800-208 §A.3 grid (80 pairs: 4 hash families × 5 tree heights × 4 Winternitz parameters); CNSA-restricted profiles permit 8 pairs (SHA-256/M=32 × H{10,15,20,25} × W{4,8}) | SP 800-208 (RFC 8554, RFC 8708) |
| XMSS | XMSS sign/verify (XMSS-SHA2_10_256) | SP 800-208 (RFC 8391) |
| DH | DH-3072 key agreement and keygen (RFC 3526 Group 15) | SP 800-56Ar3, RFC 3526 |
| Integrity | HMAC-SHA-256 software integrity check | FIPS 140-3 IG 10.3.A |

Every algorithm runs a known-answer test at module power-up. The 183
power-up self-tests include CAVP-sourced vectors (with 9 SP 800-90A §9.3
prediction-resistance DRBG KATs), plus 3 SP 800-90A §11.3 DRBG health
tests, each traceable to its published source.

## Architecture

oxicrypt is organized as a Cargo workspace with 23 crates — 18 algorithm
crates, a module crate, and 4 supporting crates — plus tools:

```
crates/
  oxicrypt-module        State machine, algorithm-profile gating, self-test runner
  oxicrypt-integrity     Power-up software integrity check (IG 10.3.A)
  oxicrypt-sha           SHA-1, SHA-2, SHA-3 hash families
  oxicrypt-xof           SHAKE128, SHAKE256, cSHAKE, KMAC, TupleHash, ParallelHash
  oxicrypt-hmac          HMAC over all 11 approved hashes
  oxicrypt-cmac          AES-CMAC (SP 800-38B)
  oxicrypt-aes           AES block cipher and all approved modes
  oxicrypt-drbg          CTR_DRBG, Hash_DRBG, HMAC_DRBG
  oxicrypt-kdf           SP 800-108 KBKDF, HKDF, PBKDF2
  oxicrypt-tls-kdf       TLS 1.2 KDF (RFC 5246) + TLS 1.3 KDF (RFC 8446 §7.1)
  oxicrypt-rsa           RSA-2048/3072/4096 sign/verify/encrypt/decrypt/keygen with CRT + Bellcore
  oxicrypt-ecdsa         ECDSA P-256 + P-384 (FIPS 186-5)
  oxicrypt-ecdh          ECDH P-256 + P-384 (SP 800-56Ar3)
  oxicrypt-eddsa         Ed25519 (RFC 8032)
  oxicrypt-ml-kem        ML-KEM-512/-768/-1024 (FIPS 203)
  oxicrypt-ml-dsa        ML-DSA-44/-65/-87 (FIPS 204)
  oxicrypt-slh-dsa       SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f} (FIPS 205)
  oxicrypt-lms           LMS hash-based signatures (SP 800-208)
  oxicrypt-xmss          XMSS hash-based signatures (SP 800-208)
  oxicrypt-dh            Finite-field DH-3072 key agreement and keygen (RFC 3526 Group 15)
  oxicrypt-ffi           C ABI wrappers (cdylib + staticlib) with profile selection
  oxicrypt-test-vectors  Generated KAT constants from vendored NIST vectors
  oxicrypt-zeroize       Volatile zeroization for sensitive security parameters

acvp-harness/           ACVP protocol handler with 86 registered algorithm handlers
benches/                Criterion benchmarks for hot paths (SHA, AES-GCM, HMAC, ECDSA, etc.)
tools/ct-validation/    dudect-style constant-time timing validation
tools/acvp-gen/         KAT constant generator from vendored vectors
```

The cryptographic boundary encompasses the `oxicrypt-*` crates compiled into a
single module binary. The ACVP harness and tools are outside the boundary.

### Design principles

**Zero third-party dependencies.** Phase 1 requires every line of cryptographic
code to be written in-tree in pure Rust. Dependencies will be re-evaluated
per-crate in later phases and must be justified in the Security Policy before
adoption.

**`no_std` by default.** The core algorithm crates use `#![no_std]` with
`alloc` where necessary, making them suitable for embedded and `wasm32` targets.
The module crate and integrity crate use `std` for file I/O and self-test
orchestration.

**Constant-time discipline.** At Level 1, FIPS 140-3 does not require
side-channel resistance, but oxicrypt discloses its posture and actively
validates it. A dudect-style timing harness (`tools/ct-validation`) runs
Welch's t-test across seven CSP-touching primitives. Two real timing leaks
were discovered and fixed by this harness.

## ACVP harness

The ACVP harness is a zero-dependency binary that processes NIST ACVP vector
sets end-to-end. It currently has 86 registered algorithm handlers covering
all test types the demo server is expected to send:

| Test type | Algorithms |
|-----------|-----------|
| AFT | All registered algorithms |
| MCT | SHA-3 family, AES-ECB, AES-CBC, cSHAKE-128/256, TupleHash-128/256, ParallelHash-128/256 |
| MVT | All 11 HMAC variants, KMAC-128/256, KMACXOF-128/256 |
| CTR | AES-CTR (counter-overflow/uniqueness) |
| VOT | SHAKE-128, SHAKE-256 |
| LDT | SHA-3 family, SHAKE family |
| GDT | RSA SigVer, RSA SigGen |

121 ACVP round-trip tests plus 7 CAVP SHS tests verify every handler
reproduces the vendored answer fields byte-for-byte.

### Dispatching vectors

```bash
# ACVP-style JSON vectors
./target/debug/acvp-harness dispatch \
    vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/kat-slice.json \
    /tmp/sha3_response.json

# CAVP SHS .rsp byte vectors
./target/debug/acvp-harness dispatch-shs SHA-256 \
    vendor/nist/cavp-shs/shabytetestvectors/SHA256ShortMsg.rsp \
    /tmp/sha256_response.json
```

### ACVP demo-server session (end-to-end)

```bash
# Single-algorithm, single-mode session — the standard form
./target/debug/acvp-harness demo-run \
    --cert client.pem --key client.key --totp-secret <hex> \
    --algorithm SHA3-256 --mode AFT

# Hardware-key (PKCS#11 / YubiKey) session — adds --pkcs11-key
./target/debug/acvp-harness demo-run \
    --cert client.pem --pkcs11-key 'pkcs11:object=...' --totp-secret <hex> \
    --algorithm ACVP-AES-CTR --mode AFT
```

The `demo-run` subcommand implements the full ACVP REST protocol: login
with TOTP-signed JWT, register a single algorithm/mode capability, fetch
the resulting vector sets, dispatch them through the registered handler,
submit answers, and poll for verdicts.

`--algorithm` and `--mode` scope each invocation to a single algorithm
and a single test type (AFT / VAL / GDT / MCT / CTR / VOT / LDT / MVT).
This matches the demo server's per-session etiquette — the documented
guidance from NIST is one vector set per session; back-to-back
multi-algo sessions trip a `/login` rate-limit on the second-plus
session, and the `--mode` filter exists to keep each session inside
that envelope. Plan multi-algorithm campaigns as a sequence of separate
`demo-run` invocations, one per algorithm/mode pair.

HTTPS with mutual TLS is provided by `curl(1)` for file-based PEM keys
(default) and OpenSSL `s_client` when a hardware key is supplied via
`--pkcs11-key` (the NIST CDN filters curl's TLS fingerprint when curl
signs CertVerify via PKCS#11; `s_client`'s handshake is accepted).
Override with `--http-backend curl|s_client` if needed. Session
transcripts stream to `acvp-session.json` (configurable with `--log`)
with incremental flush at registration and submit boundaries.

### Constant-time validation

```bash
# Run all seven targets (default 300k samples each)
cargo run -p ct-validation --release

# Deep-dive a specific target
cargo run -p ct-validation --release -- --samples 500000 ecdsa_p256_scalar_invert
```

Verdicts: `|t| >= 5` is LEAK, `|t| >= 3` is WARN, else CLEAN. All seven
targets pass at 300k samples. Full methodology and verdict table are in
§12.1 of the security policy.

## Documentation

**Rustdoc.** Every crate's `lib.rs` header follows a common template:
approved-services table, power-up self-tests, conditional self-tests,
sensitive security parameters, side-channel posture, and FIPS-module gating.
Build the full doc tree with:

```bash
cargo doc --workspace --no-deps
open target/doc/oxicrypt_module/index.html
```

**Security Policy (draft).** [`docs/security-policy/security-policy.md`](docs/security-policy/security-policy.md)
follows the SP 800-140Br1 Annex A section order. Sections that still need a
human decision are marked `TODO`.

**CAVP traceability.** [`docs/cavp-mapping/`](docs/cavp-mapping/) maps every
KAT back to its published NIST source document with SHA-256 hashes of the
vendored vector files.

### Vector provenance

NIST `usnistgov/ACVP-Server` is vendored at pinned commit
`3611942ea10c070dd8bc6afec5682d56c307de8a` under `vendor/nist/` using a
slim-slice strategy — per-algorithm `kat-slice.json` files plus a
`MANIFEST.toml` carrying SHA-256 metadata and selected tgId/tcIds. Every
KAT carries a citation to its source document (FIPS 197 Appendix C,
SP 800-38A Appendix F, McGrew-Viega Appendix B, SP 800-38B Appendix D,
RFC 3394 §4, RFC 5649 §6, NIST CAVP CCMVS VPT vectors, and the
ACVP-Server slim slices).

## Roadmap

**Phase 1 (complete)** — Foundation. Workspace structure, module state
machine, power-up self-test framework, core classical algorithms (SHA,
HMAC, AES, DRBG, KDF, ECDSA P-256, Ed25519, RSA-2048), ACVP harness,
integrity check, constant-time validation tooling.

**Phase 2 (complete)** — Full algorithm coverage. All 18 algorithm crates
are fully implemented: P-384 ECDSA/ECDH, RSA-3072/4096 (PKCS#1 v1.5,
PSS, OAEP, keygen with CRT + Bellcore verify-after-sign per IG D.G),
DH-3072 (RFC 3526 Group 15), ML-KEM-512/-768/-1024 (FIPS 203),
ML-DSA-44/-65/-87 (FIPS 204), SLH-DSA full family — SHA2 + SHAKE — (FIPS 205), LMS — complete SP 800-208 §A.3 grid (80 pairs) — and XMSS
(SP 800-208). CNSA 2.0 / CNSA 1.0 algorithm-profile gating enforced
across all algorithm crates and the C ABI (`oxicrypt-ffi`). 86 ACVP
handlers, 183 power-up self-tests, 127 ACVP/CAVP round-trip tests — all
green.

**Phase 3 (current)** — ACVP validation. Demo-server dry run, gap
resolution, and preparation of the validation submission package.

**Phase 4 (next)** — CST lab engagement. CAVP algorithm certificates,
CMVP module submission, and lab review cycle.

**Phase 5 (future)** — Extensions. Performance hardening (AES-NI,
bitsliced AES fallback), additional parameter sets and curves (Ed448,
P-521), and additional language bindings (Python, Go, Node).

## C ABI (`oxicrypt-ffi`)

The module exposes a C ABI for non-Rust consumers via the
`oxicrypt-ffi` crate. The full design is documented in
[`docs/c-api-design.md`](docs/c-api-design.md); the cbindgen-generated
header lives at
[`crates/oxicrypt-ffi/include/oxicrypt.h`](crates/oxicrypt-ffi/include/oxicrypt.h).

All exported symbols use the `oxi_` prefix. Status codes are
`OxiResult` discriminants (0 = `Ok`; non-zero values are distinct
failure modes — see `crates/oxicrypt-ffi/src/error.rs`). All AES-256
modes (GCM, CBC, CTR, CCM, KW, KWP) and CMAC-AES-256 share a single
opaque `OxiAes256Key` handle allocated via `oxi_aes256_new` and
released via `oxi_aes256_free` (NULL-safe); a key constructed once
can be reused across modes.

Build the C library:

```bash
cargo build --release -p oxicrypt-ffi
# Outputs:
#   target/release/liboxicrypt_ffi.so   (cdylib — dynamic linking)
#   target/release/liboxicrypt_ffi.a    (staticlib — static linking)
```

Sign both artifacts with `fips-integrity-sign` before use in a
FIPS-validated context (the embedded HMAC-SHA-256 slot is populated
in place):

```bash
cargo build --release -p oxicrypt-integrity --bin fips-integrity-sign
./target/release/fips-integrity-sign --sign \
    --cdylib-target    target/release/liboxicrypt_ffi.so \
    --staticlib-target target/release/liboxicrypt_ffi.a
```

C integration tests live at
`crates/oxicrypt-ffi/tests/c-integration/`. Run them after building +
signing:

```bash
make -C crates/oxicrypt-ffi/tests/c-integration test-cdylib
make -C crates/oxicrypt-ffi/tests/c-integration test-staticlib
```

The harness exercises the McGrew/Viega "GCM" reference Case 15
(AES-256) — the same vector the underlying primitive's power-up KAT
trusts — plus decrypt round-trip and tag-tamper rejection. The
companion `test_aes_modes` covers the AES-256 non-GCM mode suite
(CBC, CTR, CCM, CMAC, KW, KWP) against the same KAT vectors the
underlying `oxicrypt-aes` and `oxicrypt-cmac` self-tests use
(SP 800-38A F.2.5 / F.5.5, SP 800-38B D.3, RFC 3394 §4.3 + §4.6,
plus round-trip + AIV-tamper for KWP), so every C-side mode test
is verified against a value the Rust core's self-test trusts.

The `oxicrypt-ffi` crate currently exposes:

| Family | Surface | Standard |
|--------|---------|----------|
| Module lifecycle | `oxi_init`, `oxi_active_profile`, `oxi_is_operational` | FIPS 140-3 |
| Hash one-shots | SHA-2 family + SHA-3 family | FIPS 180-4, FIPS 202 |
| HMAC one-shots | HMAC over 7 SHA-2/SHA-3 hashes | FIPS 198-1 |
| AES-256 (opaque key handle) | GCM, CBC, CTR, CCM, CMAC, KW, KWP — one `OxiAes256Key` shared across modes | FIPS 197, SP 800-38A/B/C/D/F |
| KDF | HKDF (extract/expand) + TLS 1.3 HKDF-Expand-Label / Derive-Secret | RFC 5869, RFC 8446 §7.1 |
| ECDSA | P-256 / P-384 stateless (`derive_public_key`, `sign_with_k`, `verify`) + DRBG-driven handle (`new_generate`, `public_key`, `sign_sha*`, `free`) | FIPS 186-5, IG 10.3.A |
| EdDSA | Ed25519 deterministic keygen / sign / verify | RFC 8032, FIPS 186-5 §7.8 |
| ECDH | P-256 / P-384 raw shared secret + DRBG-driven keygen | SP 800-56Ar3, FIPS 186-5 §A.2.2, IG 10.3.A |
| DH | DH-3072 shared secret + DRBG-driven keygen | RFC 3526 Group 15, SP 800-56Ar3 |
| RSA (opaque key handle) | 2048/3072/4096 verify (PKCS#1 v1.5, PSS) + DRBG-driven keygen + sign + OAEP encrypt/decrypt + `n`/`e` accessors | FIPS 186-5, RFC 8017, IG D.G |
| ML-KEM | ML-KEM-512/-768/-1024 keygen / encaps / decaps | FIPS 203 |
| ML-DSA | ML-DSA-44/-65/-87 keygen / sign / verify | FIPS 204 |
| SLH-DSA | SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f} keygen / sign / verify | FIPS 205 |
| LMS (stateful, complete §A.3 grid) | 243 C entry points: 3 baseline `oxi_lms_*` (LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4 dispatch) + 240 per-pair `oxi_lms_<family>_m<N>_h<H>_w<W>_{keygen,sign,verify}` across 80 pairs; byte-buffer pass-through with explicit pre/post-state encoding | SP 800-208, RFC 8554, RFC 8708 |
| XMSS (stateful) | XMSS-SHA2_10_256 — byte-buffer pass-through with explicit pre/post-state encoding | SP 800-208, RFC 8391 |
| HMAC-DRBG (opaque handle) | SHA-256 / -384 / -512 — `new`, `instantiate`, `reseed`, `generate`, `free` | SP 800-90A §10.1.2 |
| Hash-DRBG (opaque handle) | SHA-256 / -384 / -512 — same lifecycle | SP 800-90A §10.1.1 |
| CTR-DRBG (opaque handle) | AES-128 / -192 / -256 — same lifecycle, with distinct `_no_df` and `_df` derivation entry points per stage | SP 800-90A §10.2 |

Verify-style mismatches collapse to `OxiResult::TagMismatch = 22`
across every signature family (RSA, ECDSA, EdDSA, ML-DSA, SLH-DSA,
LMS, XMSS, AEAD), so a single discriminant covers "well-formed-but-
invalid signature/tag" everywhere a verify result is exposed.

Per-function signatures, parameter constraints, buffer sizes, and
the full `OxiResult` discriminant mapping live in
[`docs/llm-api-manifest/llm-api.yaml`](docs/llm-api-manifest/llm-api.yaml)
(full manifest) and the cbindgen-generated
[`crates/oxicrypt-ffi/include/oxicrypt.h`](crates/oxicrypt-ffi/include/oxicrypt.h).
The C ABI is hand-aligned with the Rust public API surface; for
algorithmic specification consult the upstream crate's rustdoc and
the security-policy `§4.8 C ABI` row.

## `oxi` CLI

A lightweight command-line tool that exposes the module's approved
services to the terminal:

```bash
# Hash stdin with SHA-256
echo -n "abc" | cargo run -p oxi -- hash sha256

# HMAC-SHA-256 with a hex key
echo -n "msg" | cargo run -p oxi -- hmac sha256 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b

# Generate 32 random bytes from HMAC_DRBG-SHA-256
cargo run -p oxi -- rand 32

# Dump the LAMA manifest
cargo run -p oxi -- --lama
```

## Runnable examples

Each algorithm crate ships a self-contained example:

```bash
cargo run -p oxicrypt-sha   --example sha256_hash
cargo run -p oxicrypt-hmac  --example hmac_sha256
cargo run -p oxicrypt-aes   --example aes_gcm
cargo run -p oxicrypt-drbg  --example hmac_drbg
cargo run -p oxicrypt-ecdsa --example ecdsa_sign
cargo run -p oxicrypt-eddsa --example ed25519_sign
cargo run -p oxicrypt-ecdh  --example ecdh_p256
```

## Benchmarks

Criterion benchmarks cover the hot paths: SHA-256/512 (one-shot and streaming),
SHA3-256, HMAC-SHA-256, AES-256-GCM and ECB, HMAC_DRBG-SHA-256, ECDSA P-256
(sign/verify/keygen), Ed25519 (sign/verify), and ECDH P-256.

```bash
# Run all benchmarks
cargo bench

# Run a specific benchmark group
cargo bench --bench hash
cargo bench --bench ecdsa
```

HTML reports are generated in `target/criterion/`.

## LAMA — AI agent discovery

oxicrypt ships a [LAMA](https://github.com/lamaspec/lama) manifest so
AI coding agents can discover and correctly use the library without
hallucinating function names or missing constraints. Four discovery
vectors are supported:

- **`lama.yaml`** at the repository root — capabilities summary for fast triage
- **`--lama` flag** on the ACVP harness binary — full manifest for the exact build
- **`[workspace.metadata.lama]`** in `Cargo.toml` — pointer for crates.io discovery
- **Full manifest** at `docs/llm-api-manifest/llm-api.yaml` — every function, type,
  constraint, and pitfall

Commonly-used items are re-exported at each crate's root for natural import
paths: `use oxicrypt_sha::sha256`, `use oxicrypt_ecdsa::verify`,
`use oxicrypt_eddsa::Ed25519PrivateKey`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

The `oxicrypt` and `OxiTLS` names are intended to be filed as trademarks
and reserved for the upstream-validated build lineage; consumers may use
the source under the terms above and rebrand any redistributed builds.
A trademark policy will be published at <https://oxicrypt.dev> alongside
the public launch.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms
or conditions.
