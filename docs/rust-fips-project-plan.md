# Rust FIPS 140-3 Level 1 Cryptographic Module — Project Plan & Specification

## Executive Summary

This project aims to develop a pure-Rust cryptographic library that meets FIPS 140-3 Level 1 requirements and is suitable for submission to CAVP (algorithm validation) and subsequently to CMVP (module validation) through an accredited CST laboratory. The library will implement all mandatory approved algorithms, enforce a FIPS module boundary with self-tests and state management, and include an ACVP-compatible test harness for automated algorithm validation.

---

## 0. Current Status (as of 2026-04-11)

**Phase position:** Phase 1 closed; solidly into Phase 2 (Asymmetric + DRBG). All P0 symmetric/hash/DRBG/KDF work has landed, ECDSA/ECDH are done, and `fips-rsa` now has a full PKCS#1 v1.5 and PSS sign/verify pipeline with both a non-CRT ladder and a CRT-form Garner recombine path carrying Shamir/Bellcore verify-after-sign, plus probable-prime key generation that lands freshly-generated keys directly on the CRT path. Chunk **D1** (documentation pass) has landed: every fleshed-out crate's rustdoc header follows a common SP 800-140Br1-shaped template, and `docs/security-policy/security-policy.md` is an alpha draft that tracks the code at each commit.

**Implemented and landed on `main`:**

- `fips-module` — state machine (`PowerOff → SelfTest → Operational | Error`), power-up KAT registry, approved-mode indicator.
- `fips-sha` — SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, full SHA-3 family.
- `fips-xof` — SHAKE128, SHAKE256.
- `fips-hmac` — HMAC over all 11 approved hash variants.
- `fips-kdf` — HKDF (RFC 5869) over all 11 HMACs, SP 800-108r1 KBKDF **Counter**, **Feedback**, and **Double-Pipeline Iteration** modes over all 11 HMACs.
- `fips-aes` — AES-128/192/256 in ECB, CBC, CTR, GCM, CCM, KW, KWP modes with power-up KATs.
- `fips-cmac` — AES-CMAC.
- `fips-drbg` — CTR_DRBG (AES-128/192/256, no df + use df), Hash_DRBG (SHA-256/384/512), HMAC_DRBG (SHA-256/384/512), SP 800-90A §11.3 health tests, §9.3 prediction-resistance generate API.
- `fips-ecdsa` — ECDSA P-256/SHA-256 sign (caller-supplied `k` and DRBG-backed random-`k` wrapper), verify, and power-up KAT. FIPS 186-5 §A.2.2 DRBG-backed key generation via `EcdsaP256PrivateKey::generate` with an IG 10.3.A pairwise consistency test on every constructor path (keygen + import); the PCT uses the same rejection sampler that the production sign path consumes, so one code path covers both.
- `fips-ecdh` — ECDH P-256 with full public-key validation and KAT (SP 800-56Ar3).
- `fips-rsa` — RSA-2048 PKCS#1 v1.5 verify, sign (non-CRT) via constant-time 4-bit windowed Montgomery ladder, RSASSA-PSS SHA-256 sign/verify with MGF1 (sLen=hLen=32, emBits=2047), FIPS 186-5 §A.1.1 / §B.3.1 probable-prime key generation with 5-round Miller-Rabin (Table B.1 nlen=2048), DRBG-backed `sign_pss_sha256` wrapper that samples a fresh salt, IG 10.3.A pairwise consistency test on all generated and imported keys. RSAES-OAEP encrypt/decrypt (RFC 8017 §7.1, SP 800-56Br2 KTS-OAEP) with SHA-256/MGF1-SHA-256, a Manger-resistant single-accumulator decode, and a CRT decrypt path that shares the Bellcore-protected private-exponent primitive with CRT sign. Uses `bigint2048` / `mont2048` and narrow `bigint1024` / `mont1024` twins for Miller-Rabin.
- `fips-test-vectors` — generated KAT constants sourced from vendored NIST ACVP-Server vectors.
- `fips-integrity` — software/firmware integrity self-test (HMAC-SHA-256 over `current_exe()` with an **embedded** 64-byte reserved slot `[HDR | MAC | FTR]`, populated at sign time and validated by magic-marker scan at boot) per FIPS 140-3 IG 10.3.A. The embedded-slot design (in place of a sidecar file) is what lets the same mechanism work on Linux/macOS/Windows command-line tools **and** on code-signed iOS `.app` bundles and Android APKs where post-install files cannot be added.
- `acvp-harness` — power-up KAT runner executing 122 KATs green across SHA/SHA-3/SHAKE/HMAC/HKDF/KBKDF/AES (ECB/CBC/CTR/GCM/CCM/KW/KWP)/AES-CMAC/CTR/Hash/HMAC_DRBG (including 9 SP 800-90A §9.3 prediction-resistance DRBG KATs from `drbgvectors_pr_true`), the three SP 800-90A §11.3 DRBG health tests, and the module binary integrity check. RSA/ECDSA/ECDH KAT wiring into the harness is still pending.

**ACVP/CAVP traceability (Phase 3 work pulled forward):**

- NIST `usnistgov/ACVP-Server` vendored at pinned commit `3611942ea10c070dd8bc6afec5682d56c307de8a` under `vendor/nist/` with a slim-slice strategy (per-algorithm `kat-slice.json` + `MANIFEST.toml` with SHA-256 metadata and selected tgId/tcIds).
- Generator tooling in `tools/acvp-gen/` emits `crates/fips-test-vectors/src/generated.rs` from the vendored vectors, cross-validated against Python reference implementations.
- Power-up KATs for SHA-1/2/3, SHAKE, HMAC, and HKDF have been retrofitted off legacy "OpenSSL-derived" / "RFC 5869" / "FIPS 180-4 Appendix" vectors onto ACVP-Server vectors, with the HKDF retrofit landing on SP 800-56C Rev 2 Two-Step KDA-HKDF (hybrid form, §5.9.2). The sole remaining non-ACVP KAT is `hkdf_self_test_sha1` on RFC 5869 §A.1 Test Case 1, because SHA-1 is out of scope for SP 800-56C Rev 2 — kept and explicitly labeled for auditors.

**Not yet started (stub crates exist):** `fips-eddsa`, `fips-tls-kdf`.

**Phase 2 remaining before it can be called closed:**

- ~~`fips-rsa` CRT-form private keys (p, q, dP, dQ, qInv) with Shamir-style verify-after-sign Bellcore fault-detection on the CRT sign path.~~ **Landed in R5.** Garner recombine runs on `MontCtx1024` with the secret-exponent ladder `pow_secret`, qInv is computed by keygen via Fermat (`q^(p−2) mod p`) to sidestep a latent overflow bug in `bigint1024::modinv_odd` for top-bit-set moduli, and `RsaPrivateKey2048` now carries an `Option<CrtComponents>` so both construction pathways (`from_components` non-CRT / `from_components_crt` CRT) and `sign_pkcs1_v15_sha256` / `sign_pss_sha256_with_salt` dispatch automatically. Fresh `generate` output lands on the CRT path by default.
- ~~Pairwise consistency test coverage for ECDSA keygen at the same IG 10.3.A level as the RSA PCT.~~ **Landed in R7.** A new `p256_keygen` module owns the FIPS 186-5 §A.2.2 rejection sampler, and `EcdsaP256PrivateKey::{generate, from_bytes}` run a sign-and-verify PCT against a fixed probe using a freshly DRBG-sampled `k`. The same sampler backs the random-`k` `sign_sha256` wrapper, so the PCT exercises the exact code path production sign calls will use. EdDSA PCT follows when the `fips-eddsa` crate lands.
- `dudect`-style constant-time validation across the three asymmetric crates.

**Documentation policy (applies from D1 forward):** every commit that
touches a crate also refreshes (1) that crate's rustdoc header, (2)
the Security Policy draft at `docs/security-policy/security-policy.md`,
(3) the README if user-facing status changes, and (4) this project
plan. The four doc updates ship in the same commit as the code — see
`CLAUDE.md` for the full rule.

---

## 1. Project Scope

### 1.1 In Scope

- Pure-Rust implementations of all FIPS-approved cryptographic algorithms required for a general-purpose module
- FIPS 140-3 Level 1 software module boundary (logical boundary)
- Power-up self-tests (Known Answer Tests) and conditional self-tests
- Approved/non-approved mode enforcement and algorithm indicator mechanism
- Cryptographic key zeroization using Rust memory semantics (`Zeroize` trait)
- ACVP test harness for all implemented algorithms
- CAVP test vector generation and validation tooling
- Draft Security Policy document (SP) per FIPS 140-3 / SP 800-140D
- Comprehensive documentation suitable for CST lab review
- `no_std` compatible core (with `alloc`) for embedded and kernel use cases

### 1.2 Out of Scope

- FIPS 140-3 Level 2–4 (physical security, tamper evidence, EFP/EFT)
- Actual CST lab engagement and validation submission (human-driven process)
- Hardware security module integration
- TLS/DTLS protocol implementation (module provides primitives only)
- Certificate parsing / X.509 (separate crate concern)

---

## 2. Architecture Overview

### 2.1 Crate Structure

```
rust-fips-crypto/
├── crates/
│   ├── fips-module/          # Module boundary, state machine, self-tests
│   ├── fips-aes/             # AES-ECB, CBC, CTR, GCM, CCM, KW, KWP
│   ├── fips-sha/             # SHA-1 (legacy), SHA-2 (224/256/384/512), SHA-3, SHAKE
│   ├── fips-hmac/            # HMAC (all SHA variants)
│   ├── fips-drbg/            # CTR_DRBG, HMAC_DRBG, Hash_DRBG
│   ├── fips-rsa/             # RSA keygen, PKCS#1 v1.5, PSS, OAEP
│   ├── fips-ecdsa/           # ECDSA sign/verify (P-256, P-384, P-521)
│   ├── fips-ecdh/            # ECDH (SP 800-56Ar3)
│   ├── fips-eddsa/           # Ed25519, Ed448 (FIPS 186-5)
│   ├── fips-kdf/             # SP 800-108 KDF, SP 800-56C, HKDF, PBKDF2 (conditional)
│   ├── fips-xof/             # SHAKE128, SHAKE256, cSHAKE, KMAC
│   ├── fips-cmac/            # AES-CMAC
│   └── fips-tls-kdf/         # TLS 1.2/1.3 KDF (SP 800-135)
├── acvp-harness/             # ACVP JSON test vector client
├── tests/                    # KAT vectors, regression, fuzzing entry points
├── docs/
│   ├── security-policy/      # Draft FIPS 140-3 Security Policy
│   ├── architecture/         # Design documents
│   └── cavp-mapping/         # Mapping of CAVP certs to implementations
└── Cargo.toml                # Workspace root
```

### 2.2 Module Boundary

The `fips-module` crate defines the cryptographic boundary per FIPS 140-3 Section 7.2:

- **Single entry point**: All cryptographic services accessed through the module API
- **State machine**: `PowerOff → SelfTest → Operational | Error`
- **Approved mode indicator**: Runtime queryable; non-approved algorithms gated behind feature flags that disable FIPS mode
- **No algorithm accessible before self-tests pass**

### 2.3 State Machine

```
┌──────────┐   power-up    ┌───────────┐  all KATs pass  ┌──────────────┐
│ PowerOff │──────────────→│ SelfTest  │────────────────→│ Operational  │
└──────────┘               └───────────┘                 └──────────────┘
                                │                              │
                           KAT failure                  conditional self-test
                                │                          failure
                                ▼                              │
                           ┌─────────┐◄────────────────────────┘
                           │  Error  │  (zeroize all keys, halt)
                           └─────────┘
```

---

## 3. Algorithm Inventory

Each row maps to a CAVP algorithm validation and corresponding ACVP test spec.

| Algorithm | Standard | ACVP Spec ID | Priority |
|-----------|----------|-------------|----------|
| AES-ECB/CBC/CTR | FIPS 197 | acvp-aes-ecb/cbc/ctr | P0 |
| AES-GCM | SP 800-38D | acvp-aes-gcm | P0 |
| AES-CCM | SP 800-38C | acvp-aes-ccm | P0 |
| AES-KW / KWP | SP 800-38F | acvp-aes-kw | P1 |
| AES-CMAC | SP 800-38B | acvp-cmac-aes | P1 |
| SHA-1 | FIPS 180-4 | acvp-sha | P0 (legacy) |
| SHA-2 (all) | FIPS 180-4 | acvp-sha | P0 |
| SHA-3 (all) | FIPS 202 | acvp-sha3 | P0 |
| SHAKE128/256 | FIPS 202 | acvp-shake | P1 |
| cSHAKE / KMAC | SP 800-185 | acvp-cshake/kmac | P2 |
| HMAC | FIPS 198-1 | acvp-hmac | P0 |
| CTR_DRBG | SP 800-90A | acvp-drbg | P0 |
| HMAC_DRBG | SP 800-90A | acvp-drbg | P0 |
| RSA KeyGen | FIPS 186-5 | acvp-rsa-keygen | P0 |
| RSA SigGen/Ver | FIPS 186-5 | acvp-rsa-siggen/sigver | P0 |
| RSA OAEP | SP 800-56Br2 | acvp-rsa-oaep | P1 |
| ECDSA KeyGen | FIPS 186-5 | acvp-ecdsa-keygen | P0 |
| ECDSA SigGen/Ver | FIPS 186-5 | acvp-ecdsa-siggen/sigver | P0 |
| ECDH | SP 800-56Ar3 | acvp-ecdh (kas-ecc) | P0 |
| EdDSA | FIPS 186-5 | acvp-eddsa | P1 |
| KDF (108) | SP 800-108r1 | acvp-kdf108 | P1 |
| KDF (56C) | SP 800-56Cr2 | acvp-kdf56c | P1 |
| TLS 1.2 KDF | SP 800-135 | acvp-tls12-kdf | P1 |
| TLS 1.3 KDF | SP 800-135 | acvp-tls13-kdf | P1 |
| PBKDF2 | SP 800-132 | acvp-pbkdf | P2 |

**Priority key:** P0 = must-have for initial validation, P1 = expected for general-purpose module, P2 = nice-to-have

---

## 4. FIPS 140-3 Compliance Mapping

### 4.1 SP 800-140 Series Requirements

| Document | Covers | Implementation Approach |
|----------|--------|------------------------|
| SP 800-140A | Module types & boundaries | Software module, logical boundary defined in `fips-module` crate |
| SP 800-140B | Self-tests | KATs at power-up for every approved algorithm; pairwise consistency for key generation; conditional tests for DRBG health |
| SP 800-140C | Approved security functions | Algorithm inventory above; non-approved functions gated |
| SP 800-140D | Security Policy | Draft SP document in `docs/security-policy/` |
| SP 800-140E | Roles, services & authentication | Level 1: implicit operator role, no authentication required |
| SP 800-140F | Physical security | Level 1: N/A for software module |

### 4.2 Self-Test Inventory

**Power-Up Self-Tests (KATs):**

Each algorithm requires at least one Known Answer Test using a hardcoded input/output pair. These run automatically when the module initializes.

- AES-GCM encrypt + decrypt KAT
- AES-CBC encrypt + decrypt KAT
- SHA-256 KAT
- SHA-3-256 KAT
- HMAC-SHA-256 KAT
- CTR_DRBG generate KAT
- RSA SigGen + SigVer KAT
- ECDSA SigGen + SigVer KAT (P-256)
- ECDH KAT
- Software integrity check (HMAC-SHA-256 of module binary)

**Conditional Self-Tests:**

- Pairwise consistency test on every RSA, ECDSA, EdDSA key generation
- DRBG health tests per SP 800-90A §11.3 (instantiate/generate/reseed
  error paths, reseed-counter ceiling, post-uninstantiate access) —
  wired as three power-up KATs in `fips-drbg::health`
- Continuous Random Number Generator Test (CRNGT) — **not applicable**
  under FIPS 140-3 IG D.G (March 2026). IG D.G removes CRNGT-on-DRBG-
  output as a required conditional test (SP 800-90A DRBGs are
  designed not to emit duplicate output blocks, and the §11.3 error-
  path health tests already cover the DRBG health-check line item).
  SP 800-90B §4.4 entropy-source health tests (Repetition Count Test,
  Adaptive Proportion Test) remain a requirement for modules that
  bundle a noise source, but per §4.4 below pqclib consumes
  caller-supplied entropy and does not include a noise source inside
  the cryptographic boundary, so those tests are the responsibility
  of the upstream entropy source (the OS CSPRNG or hardware RNG that
  the caller has CAVP-validated separately)

### 4.3 Key Zeroization

- All secret key material wraps in a `ZeroizeOnDrop` newtype
- Leverages the `zeroize` crate's compiler-fence approach to prevent dead-store elimination
- Module error state triggers bulk zeroization of all cached key material
- Verification: unit tests that inspect memory post-drop (using `unsafe` read in test-only code)

### 4.4 Entropy Source

- Module will **not** bundle its own entropy source for FIPS purposes
- DRBG is seeded externally; the calling application provides entropy from an approved source (e.g., OS CSPRNG that is itself FIPS-validated, or a hardware RNG)
- Documentation specifies the entropy interface and caller responsibilities
- Optional: `OsRng` integration gated behind a feature flag with clear documentation that the OS RNG must itself be validated

---

## 5. ACVP Test Harness

### 5.1 Architecture

The `acvp-harness` binary implements the ACVP protocol client:

1. **Registration**: Declares supported algorithms and capabilities to the ACVP server
2. **Vector processing**: Deserializes test vectors (JSON), dispatches to the appropriate algorithm implementation, serializes results
3. **Submission**: Returns results to server for automated validation

### 5.2 Implementation Plan

- **Zero third-party dependencies**: ACVP JSON handling uses an in-tree recursive-descent parser (`acvp-harness/src/json.rs`, R10) and an in-tree uppercase-hex codec (`acvp-harness/src/hex.rs`); `serde` / `serde_json` are deliberately not used so the CMVP supply-chain story on the validation binary matches the story on the module
- One module per algorithm family matching ACVP spec IDs
- Test locally against NIST's sample vectors (available on GitHub: `usnistgov/ACVP-Server`)
- Integration test suite that runs all sample vectors and compares against expected outputs

---

## 6. Development Phases

### Phase 1: Foundation (Weeks 1–4)

**Goal:** Module boundary + core symmetric algorithms + self-test framework

- [x] Workspace scaffolding, CI pipeline (clippy, miri, cargo-fuzz)
- [x] `fips-module`: State machine, self-test runner, approved-mode indicator
- [x] `fips-aes`: AES-128/192/256 in ECB, CBC, CTR modes
- [x] `fips-aes`: AES-GCM (GHASH + CTR combination)
- [x] `fips-sha`: SHA-1, SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
- [x] `fips-hmac`: HMAC for all SHA variants (11 approved hash variants, including SHA-3)
- [x] Power-up KATs for Phase 1 hash/MAC/KDF/AES algorithms
- [x] Software integrity self-test mechanism (`fips-integrity`: HMAC-SHA-256 over `current_exe()` with an embedded `[HDR | MAC | FTR]` slot populated by the external `fips-integrity-sign` tool, IG 10.3.A). Uniform mechanism across desktop, server, and code-signed mobile bundles — no sidecar files and no platform-specific ELF/Mach-O/PE parsing.

### Phase 2: Asymmetric + DRBG (Weeks 5–10)

**Goal:** All P0 asymmetric algorithms and random number generation

- [x] `fips-drbg`: CTR_DRBG (AES-128/192/256, no df + use df)
- [x] `fips-drbg`: Hash_DRBG (SHA-256/384/512, §10.3.1 Hash_df)
- [x] `fips-drbg`: HMAC_DRBG (SHA-256/384/512)
- [x] `fips-drbg`: SP 800-90A §11.3 error-path health tests (CTR/Hash/HMAC_DRBG)
- [x] `fips-drbg`: SP 800-90A §9.3 prediction-resistance generate API (CTR/Hash/HMAC_DRBG); power-up KATs pending vendoring of `drbgvectors_pr_true`
- [~] CRNGT on DRBG output — deferred as not required by FIPS 140-3 IG D.G (March 2026); see §4.2 note
- [x] `fips-rsa`: PKCS#1 v1.5 verify and sign (non-CRT, constant-time windowed Montgomery ladder)
- [x] `fips-rsa`: RSASSA-PSS SHA-256 sign/verify with MGF1
- [x] `fips-rsa`: Key generation via FIPS 186-5 §A.1.1 / §B.3.1 probable primes + DRBG-backed `sign_pss_sha256` wrapper
- [x] `fips-rsa`: CRT-form private keys with Bellcore/Shamir verify-after-sign fault-detection (R5 — Garner recombine over mont1024, wired through PKCS#1 v1.5 and PSS sign entry points, with a byte-exact CRT↔non-CRT equivalence test and a dP-tamper fault-injection test)
- [~] `fips-ecdsa`: P-256/SHA-256 keygen (DRBG-backed via FIPS 186-5 §A.2.2 rejection sampler, R7), caller-`k` and DRBG-backed random-`k` sign, verify all landed; P-384 and P-521 deferred
- [x] `fips-ecdh`: ECDH per SP 800-56Ar3 (P-256)
- [x] Pairwise consistency tests for RSA keygen (IG 10.3.A, wired inside `from_components`)
- [x] Pairwise consistency tests for ECDSA keygen (IG 10.3.A, wired inside `EcdsaP256PrivateKey::{generate, from_bytes}`, R7) and for Ed25519 keygen (IG 10.3.A sign-and-verify wired inside `Ed25519PrivateKey::{generate, from_seed}`, R9)
- [x] Constant-time validation: `tools/ct-validation` dudect harness landed (R8) — Welch's t-test with percentile cropping, seven targets (R9 added Ed25519) covering `mont2048::pow_secret`, `mont1024::pow_secret`, `emsa_oaep_decode`, `Point::mul`, `Scalar::invert`, ECDH CDH, and `EdwardsPoint::mul` on the Ed25519 base point; at 300k samples every target reports `|t| < 3` except `ecdsa_p256_scalar_invert` which fluctuates in the noise band and is non-monotone with sample count. Two real leaks were found and fixed in R8: a data-dependent `if carry == 0 { break; }` in the Montgomery-reduction carry-propagation loop (`p256_field.rs`, `p256_scalar.rs` — observed as multi-thousand-sigma) and an identity short-circuit in `Point::add_mixed` that made the scalar-mul ladder's per-iteration cost depend on the number of leading zero bits of the secret scalar (`Point::mul` now uses `add_mixed_ct` which runs the full formula unconditionally and CT-selects). See §12.1 for the reporting protocol and the current verdict table.

### Phase 3: Extended Algorithms + ACVP (Weeks 11–16)

**Goal:** P1 algorithms, ACVP harness, comprehensive test coverage

- [x] `fips-aes`: AES-CCM
- [x] `fips-aes`: AES-KW, AES-KWP
- [x] `fips-cmac`: AES-CMAC
- [x] `fips-sha`: SHA-3 family, SHAKE128, SHAKE256 (SHAKE lives in `fips-xof`)
- [~] `fips-eddsa`: Ed25519 landed (R9 — deterministic RFC 8032 sign/verify per FIPS 186-5 §7.8, DRBG-backed `Ed25519PrivateKey` handle with IG 10.3.A sign-and-verify PCT, non-cofactored verify equation, canonical-`S` rejection, ct-validation target `eddsa_ed25519_scalar_mul` CLEAN at 300k worst |t|=1.418 crop=0.900); Ed448 deferred
- [x] `fips-kdf`: SP 800-108r1 (Counter, Feedback, Double-Pipeline Iteration modes), SP 800-56Cr2 (HKDF KAT retrofit); HKDF (RFC 5869) over all 11 HMACs
- [ ] `fips-tls-kdf`: TLS 1.2 / 1.3 PRF/HKDF
- [x] `fips-rsa`: OAEP (R6 — RFC 8017 §7.1 RSAES-OAEP with SHA-256/MGF1-SHA-256, Manger-resistant decode with single-accumulator structural checks, CRT decrypt path sharing the Bellcore-protected private-exponent primitive with CRT sign, DRBG-backed `rsa_oaep_encrypt_2048_sha256` entry point, `RsaPrivateKey2048::decrypt_oaep_sha256` method)
- [x] ACVP harness: scaffolding + power-up KAT runner (122 KATs wired, including §9.3 PR DRBG KATs)
- [~] ACVP harness: vector-set dispatch (R10 — hand-rolled in-tree JSON parser with bounded-depth recursive descent, typed envelope layer over `algorithm`/`revision`/`testGroups`, `AlgorithmHandler` trait + registry, `acvp-harness dispatch <prompt.json> <response.json>` CLI subcommand gated on `require_operational`, two algorithms wired end-to-end at R10: SHA3-256 revision 2.0 AFT and HMAC-SHA2-256 revision 1.0 AFT; zero third-party dependencies preserved — no `serde_json`). R12-A expanded the ACVP handler set to seventeen AFT dispatchers total by landing SHA3-{224,384,512} revision 2.0, SHAKE-{128,256} revision FIPS202, HMAC-SHA-1 revision 1.0, HMAC-SHA2-{224,384,512,512/224,512/256} revision 1.0, and HMAC-SHA3-{224,256,384,512} revision 1.0, all sharing the R10 envelope layer with no new JSON shapes; each new family collapses into a single module (`handlers/sha3.rs`, `handlers/shake.rs`, `handlers/hmac.rs`) with a private shared group driver. R12-B then landed the **second envelope shape** R11′ promised: a hand-rolled CAVP SHS `.rsp` parser (`acvp-harness/src/rsp.rs`) over byte-oriented short-message vectors, a parallel `ShsHandler` trait + `ShsRegistry` + `process_shs` dispatcher (`acvp-harness/src/shs.rs`), seven handlers for the SHA-1 / SHA-2 family (`handlers/shs.rs` — SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256), and a new `acvp-harness dispatch-shs <algorithm> <prompt.rsp> <response.json>` CLI subcommand, all gated on the same `require_operational` re-check. Data-driven round-trip integration tests in `acvp-harness/tests/round_trip.rs` (eighteen tests — seventeen ACVP handlers plus an envelope-preservation test) and `acvp-harness/tests/shs_round_trip.rs` (seven tests — one per vendored `ShortMsg.rsp` file) assert every produced `md` / `mac` matches the vendored expected value byte-for-byte. Zero third-party dependencies preserved across both envelope shapes. R13 then landed the first KDF family handler, `KDA-HKDF-Sp800-56Cr2`, which is also the first ACVP family in pqclib that keys dispatch on the optional `mode` slot: the envelope publishes across two top-level fields (`algorithm = "KDA"`, `mode = "HKDF"`) rather than just `algorithm`. Instead of hard-coding a `KDA-HKDF` composite string, R13 generalised [`dispatch::Registry::find`] to key on `(algorithm, Option<&str>, revision)` and added a default `AlgorithmHandler::mode() -> Option<&'static str>` that returns `None`, so every R10/R12-A/R12-B handler slots into the same three-tuple without churn; [`envelope::VectorSet::mode`] exposes the optional field off the prompt, and [`dispatch::process`] conditionally threads it through the response envelope. The `handlers/kda_hkdf.rs` driver implements SP 800-56C Rev 2 §5.9.2's hybrid two-step KDF (`IKM = Z || T`, `PRK = HMAC(salt, IKM)` HKDF-Extract, fixedInfo per §5.8 pattern grammar, `OKM = HKDF-Expand(PRK, fixedInfo, L/8)`) and supports the ten HMAC instantiations legal under SP 800-56Cr2 — `SHA2-{224, 256, 384, 512, 512/224, 512/256}` and `SHA3-{224, 256, 384, 512}`, explicitly rejecting SHA-1 — reusing the existing `fips_kdf::Hkdf*` type aliases. The `fixedInfoPattern` encoder supports `uPartyInfo`, `vPartyInfo`, `l` (32-bit big-endian in bits), `algorithmId`, `context`, `label`, and `literal[HEX]` tokens per §5.8; unsupported tokens error loudly rather than silently drop bytes. A nineteenth round-trip test (`kda_hkdf_aft_round_trip`) reproduces every vendored `dkm` field byte-for-byte across all ten groups in `KDA-HKDF-Sp800-56Cr2/kat-slice.json`. `JsonValue` also gained an `as_bool` accessor to read `usesHybridSharedSecret` / `multiExpansion`. Zero third-party dependencies preserved. R14-A then landed the first symmetric-cipher AFT handlers — `ACVP-AES-{ECB, CBC, CTR}-1.0` (`handlers/aes.rs`) — bringing the registered handler count to twenty-one. Each AFT group declares a `direction` (`encrypt` / `decrypt`) and a `keyLen` (128 / 192 / 256); the handler dispatches via monomorphised `run_mode<B: BlockCipher>` to avoid boxing per-test. CTR tests with non-byte-aligned `payloadLen` are explicitly rejected as `Unsupported`; MCT groups are rejected as `UnsupportedTestType`. Three new vendored slices (`ACVP-AES-{ECB, CBC, CTR}-1.0/kat-slice.json`, six groups × three tests = eighteen tests each) and three round-trip tests (`aes_{ecb,cbc,ctr}_aft_round_trip`) verify every produced `ct` / `pt` matches byte-for-byte, now totalling twenty-two ACVP round-trip tests. R14-B then completed the AES mode set with `ACVP-AES-{GCM, CCM, KW, KWP}-1.0` AFT handlers (`handlers/aes.rs`), bringing the total to twenty-five registered handlers. GCM is filtered for the Phase-1 constraint of 96-bit IV + 128-bit tag; CCM supports all seven valid tag lengths (4–16 bytes) and nonce lengths (7–13 bytes). AEAD decrypt / key-unwrap tests carry `testPassed` fields indicating whether tag/ICV verification should succeed or fail — the handler catches `ModeError::TagMismatch` and returns `{tcId, testPassed: false}` for expected failures. Four new vendored slices and four round-trip tests (`aes_{gcm,ccm,kw,kwp}_aft_round_trip`) now total twenty-six ACVP round-trip tests. R15 then landed the MCT (Monte Carlo Test) engine for ECB and CBC (`handle_aes_mct_group`, `mct_ecb`, `mct_cbc` in `handlers/aes.rs`), implementing the standard 100×1000 iteration loop with per-key-size key-schedule update (128-bit: XOR Output[999]; 192-bit: XOR last-8-bytes(Output[998]) || Output[999]; 256-bit: XOR Output[998] || Output[999]) and direction-aware CBC IV feedback (encrypt IV = CT[j], decrypt IV = CT[j] which is the input, not the output). Six vendored MCT groups per mode (3 key sizes × 2 directions) are trimmed to 5 resultsArray entries; two new round-trip tests (`aes_{ecb,cbc}_mct_round_trip`) compare the handler's output against the vendored reference entries, now totalling twenty-eight ACVP round-trip tests. Remaining: DRBG, ECDSA, EdDSA, RSA handler families, plus MCT for remaining modes and LDT test type. The R11′ framing stands: upstream `usnistgov/ACVP-Server` ships no top-level `SHA-*`, `SHA1-*`, or `SHA2-*` vector directories at the pinned commit `3611942ea10c070dd8bc6afec5682d56c307de8a` and never has — plain FIPS 180-4 hashing is published only as CAVP byte-oriented SHS vectors, which is exactly what the R12-B second envelope consumes. There is no ACVP-Server re-pin in the path.
- [ ] ACVP harness: registration + remaining algorithm families (continued from above)
- [x] Run against NIST sample vectors from `usnistgov/ACVP-Server` (vendored at pinned commit `3611942e`; KATs sourced from vendored vectors with CAVP traceability)

### Phase 4: Hardening & Documentation (Weeks 17–22)

**Goal:** Security policy, side-channel hardening, audit readiness

- [ ] `fips-xof`: cSHAKE, KMAC (P2 algorithms)
- [ ] PBKDF2 (P2)
- [ ] Constant-time audit of all secret-dependent operations
- [ ] Fuzzing campaign: all algorithm entry points via `cargo-fuzz`
- [ ] Memory safety analysis with Miri
- [x] Draft Security Policy skeleton (alpha, SP 800-140Br1 section order) — pulled forward into chunk D1 on 2026-04-11; lives at `docs/security-policy/security-policy.md`. Needs human editing to resolve TODO markers before formal versioning.
- [x] First rustdoc pass across all fleshed-out crates (chunk D1, 2026-04-11)
- [ ] Finalize API documentation (post-human-editing)
- [ ] Non-approved mode testing and mode indicator verification
- [ ] Performance benchmarks and optimization pass

### Phase 5: Pre-Submission (Weeks 23–26)

**Goal:** Ready for CST lab engagement

- [ ] Full ACVP dry run against NIST demo server
- [ ] Internal review of Security Policy against IG (Implementation Guidance)
- [ ] Gap analysis against latest FIPS 140-3 IG updates
- [ ] Package submission materials
- [ ] Identify and engage CST lab

---

## 7. Key Technical Decisions

### 7.1 Constant-Time Implementation

All operations on secret data must be constant-time:

- No secret-dependent branches or memory access patterns
- Use `subtle` crate patterns for conditional selection
- Barrett/Montgomery reduction for modular arithmetic (RSA, ECC)
- Validate with `dudect`-style statistical timing tests in CI

### 7.2 `unsafe` Budget

Minimal `unsafe` usage, each instance documented and audited:

- Assembly intrinsics for AES-NI / CLMUL (with pure-Rust fallback)
- Memory zeroization (compiler fence)
- Potential: `core::arch` SIMD for SHA-NI

All `unsafe` blocks will carry `// SAFETY:` comments and be auditable.

### 7.3 Feature Flags

```toml
[features]
default = ["fips"]
fips = []              # Enforces approved-only mode, enables self-tests
aesni = []             # AES-NI hardware acceleration
shani = []             # SHA-NI hardware acceleration  
std = []               # Enables std-dependent features (OsRng, etc.)
non-approved = []      # Enables non-approved algorithms (disables FIPS indicator)
```

### 7.4 No `alloc` Core Path

The core algorithm crates should work without `alloc` for embedded targets. RSA (variable-length bignum) is the exception and requires `alloc`.

---

## 8. Reference Documents

All publicly available from NIST:

| Document | URL / Source |
|----------|-------------|
| FIPS 140-3 | csrc.nist.gov/publications/detail/fips/140/3/final |
| FIPS 140-3 Implementation Guidance | csrc.nist.gov/projects/cryptographic-module-validation-program |
| SP 800-140A–F | csrc.nist.gov/publications (search 800-140) |
| FIPS 197 (AES) | csrc.nist.gov/publications/detail/fips/197/final |
| FIPS 180-4 (SHA) | csrc.nist.gov/publications/detail/fips/180/4/final |
| FIPS 186-5 (DSA/ECDSA/EdDSA) | csrc.nist.gov/publications/detail/fips/186/5/final |
| FIPS 198-1 (HMAC) | csrc.nist.gov/publications/detail/fips/198/1/final |
| FIPS 202 (SHA-3) | csrc.nist.gov/publications/detail/fips/202/final |
| SP 800-38A–F (Block cipher modes) | csrc.nist.gov/publications/detail/sp/800-38a/final (etc.) |
| SP 800-56Ar3 (ECC DH) | csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final |
| SP 800-56Cr2 (Key derivation) | csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final |
| SP 800-90Ar1 (DRBG) | csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final |
| SP 800-108r1 (KDF) | csrc.nist.gov/publications/detail/sp/800-108/rev-1/final |
| SP 800-132 (PBKDF) | csrc.nist.gov/publications/detail/sp/800-132/final |
| SP 800-135r1 (TLS KDF) | csrc.nist.gov/publications/detail/sp/800-135/rev-1/final |
| SP 800-185 (SHA-3 derived) | csrc.nist.gov/publications/detail/sp/800-185/final |
| ACVP Protocol Spec | github.com/usnistgov/ACVP |
| ACVP Server (sample vectors) | github.com/usnistgov/ACVP-Server |

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NIST updates IG during development | High | Medium | Monitor IG updates monthly; design for flexibility |
| Constant-time regression on new Rust/LLVM version | Medium | High | `dudect` tests in CI; pin LLVM version for release builds |
| Pure-Rust ECC performance insufficient | Medium | Low | Acceptable for L1; optimize hot paths; AES-NI/SHA-NI compensate |
| ACVP protocol changes | Low | Medium | Pin to known-good ACVP spec version; update incrementally |
| CST lab requires changes to module boundary | High | Medium | Design boundary to be easily adjustable; budget rework time |
| `unsafe` audit findings | Medium | Medium | Minimize `unsafe`; document every instance; consider formal verification for critical paths |

---

## 10. Success Criteria

1. All P0 and P1 algorithms pass ACVP validation against NIST sample vectors
2. Module state machine enforces approved-mode-only operation in FIPS configuration
3. All power-up and conditional self-tests implemented and verified
4. Zero `unsafe` blocks without documented safety justification
5. No timing side-channels detected by `dudect` in CI
6. Draft Security Policy reviewed against SP 800-140D template
7. CST lab engagement initiated with complete submission package

---

## 11. Claude Code Suitability Assessment

**Well-suited tasks (can be directly implemented by Claude Code):**

- All algorithm implementations given the NIST specs and test vectors
- ACVP harness with JSON schema handling
- Module state machine and self-test framework
- KAT test generation from published vectors
- Zeroization wrappers and memory safety patterns
- CI configuration (clippy, miri, fuzz targets)
- API design and documentation

**Tasks requiring human guidance:**

- Constant-time implementation review and `dudect` threshold tuning
- `unsafe` justification review
- Security Policy narrative sections (operational environment, threat model)
- Architecture trade-off decisions (e.g., bignum library choice for RSA)
- CST lab communication and requirements interpretation

**Recommended workflow:**

Use Claude Code for implementation with human review at phase gates. Each algorithm should follow: spec reading → implementation → KAT verification → ACVP vector test → constant-time check → code review.
