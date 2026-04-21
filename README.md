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

- **Rust 1.94+** (MSRV enforced in `Cargo.toml`)
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
| KDF | SP 800-108r1 (counter/feedback/double-pipeline), SP 800-56C Rev 2 KDA-HKDF, TLS 1.2 KDF, PBKDF2 | SP 800-108, SP 800-56Cr2, SP 800-132 |
| SP 800-185 | cSHAKE, KMAC, TupleHash, ParallelHash (+ XOF variants) | SP 800-185 |
| RSA | RSA-2048/3072/4096 PKCS#1 v1.5 and PSS sign/verify, OAEP encrypt/decrypt, keygen with CRT + Bellcore | FIPS 186-5, SP 800-56Br2 |
| ECDSA | P-256 and P-384 sign/verify/keygen with DRBG-backed rejection sampling | FIPS 186-5 |
| ECDH | P-256 and P-384 CDH shared secret computation | SP 800-56Ar3 |
| EdDSA | Ed25519 deterministic sign/verify/keygen | RFC 8032, FIPS 186-5 §7.8 |
| ML-KEM | ML-KEM-1024 keygen/encaps/decaps | FIPS 203 |
| ML-DSA | ML-DSA-87 sign/verify/keygen | FIPS 204 |
| SLH-DSA | SLH-DSA-SHA2-256s sign/verify/keygen | FIPS 205 |
| LMS | LMS sign/verify (LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4) | SP 800-208 (RFC 8554) |
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
  oxicrypt-tls-kdf       TLS 1.2 KDF (RFC 5246)
  oxicrypt-rsa           RSA-2048/3072/4096 sign/verify/encrypt/decrypt/keygen with CRT + Bellcore
  oxicrypt-ecdsa         ECDSA P-256 + P-384 (FIPS 186-5)
  oxicrypt-ecdh          ECDH P-256 + P-384 (SP 800-56Ar3)
  oxicrypt-eddsa         Ed25519 (RFC 8032)
  oxicrypt-ml-kem        ML-KEM-1024 (FIPS 203)
  oxicrypt-ml-dsa        ML-DSA-87 (FIPS 204)
  oxicrypt-slh-dsa       SLH-DSA-SHA2-256s (FIPS 205)
  oxicrypt-lms           LMS hash-based signatures (SP 800-208)
  oxicrypt-xmss          XMSS hash-based signatures (SP 800-208)
  oxicrypt-dh            Finite-field DH-3072 key agreement and keygen (RFC 3526 Group 15)
  oxicrypt-ffi           C ABI wrappers (cdylib + staticlib) with profile selection
  oxicrypt-test-vectors  Generated KAT constants from vendored NIST vectors
  oxicrypt-zeroize       Volatile zeroization for sensitive security parameters

acvp-harness/           ACVP protocol handler with 78 registered algorithm handlers
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
sets end-to-end. It currently has 78 registered algorithm handlers covering
all test types the demo server is expected to send:

| Test type | Algorithms |
|-----------|-----------|
| AFT | All registered algorithms |
| MCT | SHA-3 family, AES-ECB, AES-CBC |
| MVT | All 11 HMAC variants, KMAC-128/256, KMACXOF-128/256 |
| CTR | AES-CTR (counter-overflow/uniqueness) |
| VOT | SHAKE-128, SHAKE-256 |
| LDT | SHA-3 family, SHAKE family |
| GDT | RSA SigVer, RSA SigGen |

120 ACVP round-trip tests plus 7 CAVP SHS tests verify every handler
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
# Full session against the NIST ACVP demo server
./target/debug/acvp-harness demo-run \
    --cert client.pem --key client.key --totp-secret <hex>

# Single-algorithm dry run
./target/debug/acvp-harness demo-run \
    --cert client.pem --key client.key --totp-secret <hex> \
    --algorithm SHA3-256
```

The `demo-run` subcommand implements the full ACVP REST protocol: login
with TOTP-signed JWT, register capabilities, fetch/process/submit vector
sets, and poll for verdicts.  All 78 handlers declare registration
capabilities, so the demo server receives the complete algorithm suite
in a single session.  Uses `curl(1)` for HTTPS with mutual TLS,
keeping zero third-party deps. Session transcripts are written to
`acvp-session.json` (configurable with `--log`).

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
DH-3072 (RFC 3526 Group 15), ML-KEM-1024 (FIPS 203), ML-DSA-87
(FIPS 204), SLH-DSA-SHA2-256s (FIPS 205), LMS (SP 800-208), and XMSS
(SP 800-208). CNSA 2.0 / CNSA 1.0 algorithm-profile gating enforced
across all algorithm crates and the C ABI (`oxicrypt-ffi`). 78 ACVP
handlers, 183 power-up self-tests, 127 ACVP/CAVP round-trip tests — all
green.

**Phase 3 (current)** — ACVP validation. Demo-server dry run, gap
resolution, and preparation of the validation submission package.

**Phase 4 (next)** — CST lab engagement. CAVP algorithm certificates,
CMVP module submission, and lab review cycle.

**Phase 5 (future)** — Extensions. Performance hardening (AES-NI,
bitsliced AES fallback), additional parameter sets and curves (Ed448,
P-521), and additional language bindings (Python, Go, Node).

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

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.
See [`LICENSE`](LICENSE) for the full text.

In short: you may use, modify, and share this software for any
noncommercial purpose. Commercial use requires a separate license —
please open an issue if you would like to discuss commercial terms.
