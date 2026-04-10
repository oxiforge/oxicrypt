# Rust FIPS 140-3 Level 1 Cryptographic Module — Project Plan & Specification

## Executive Summary

This project aims to develop a pure-Rust cryptographic library that meets FIPS 140-3 Level 1 requirements and is suitable for submission to CAVP (algorithm validation) and subsequently to CMVP (module validation) through an accredited CST laboratory. The library will implement all mandatory approved algorithms, enforce a FIPS module boundary with self-tests and state management, and include an ACVP-compatible test harness for automated algorithm validation.

---

## 0. Current Status (as of 2026-04-10)

**Phase position:** Most of the way through Phase 1 (Foundation), with an early pull-forward of ACVP/CAVP traceability work that formally belongs to Phase 3.

**Implemented and landed on `main`:**

- `fips-module` — state machine (`PowerOff → SelfTest → Operational | Error`), power-up KAT registry, approved-mode indicator.
- `fips-sha` — SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, full SHA-3 family.
- `fips-xof` — SHAKE128, SHAKE256.
- `fips-hmac` — HMAC over all 11 approved hash variants.
- `fips-kdf` — HKDF (RFC 5869) over all 11 HMACs, SP 800-108r1 KBKDF **Counter**, **Feedback**, and **Double-Pipeline Iteration** modes over all 11 HMACs.
- `fips-test-vectors` — generated KAT constants sourced from vendored NIST ACVP-Server vectors.
- `fips-integrity` — software/firmware integrity self-test (HMAC-SHA-256 over `current_exe()` with an **embedded** 64-byte reserved slot `[HDR | MAC | FTR]`, populated at sign time and validated by magic-marker scan at boot) per FIPS 140-3 IG 10.3.A. The embedded-slot design (in place of a sidecar file) is what lets the same mechanism work on Linux/macOS/Windows command-line tools **and** on code-signed iOS `.app` bundles and Android APKs where post-install files cannot be added.
- `acvp-harness` — power-up KAT runner executing 69 KATs green across SHA/SHA-3/SHAKE/HMAC/HKDF/KBKDF and the module binary integrity check.

**ACVP/CAVP traceability (Phase 3 work pulled forward):**

- NIST `usnistgov/ACVP-Server` vendored at pinned commit `3611942ea10c070dd8bc6afec5682d56c307de8a` under `vendor/nist/` with a slim-slice strategy (per-algorithm `kat-slice.json` + `MANIFEST.toml` with SHA-256 metadata and selected tgId/tcIds).
- Generator tooling in `tools/acvp-gen/` emits `crates/fips-test-vectors/src/generated.rs` from the vendored vectors, cross-validated against Python reference implementations.
- Power-up KATs for SHA-1/2/3, SHAKE, HMAC, and HKDF have been retrofitted off legacy "OpenSSL-derived" / "RFC 5869" / "FIPS 180-4 Appendix" vectors onto ACVP-Server vectors, with the HKDF retrofit landing on SP 800-56C Rev 2 Two-Step KDA-HKDF (hybrid form, §5.9.2). The sole remaining non-ACVP KAT is `hkdf_self_test_sha1` on RFC 5869 §A.1 Test Case 1, because SHA-1 is out of scope for SP 800-56C Rev 2 — kept and explicitly labeled for auditors.

**Not yet started (stub crates exist):** `fips-aes`, `fips-cmac`, `fips-drbg`, `fips-ecdh`, `fips-ecdsa`, `fips-eddsa`, `fips-rsa`, `fips-tls-kdf`.

**Phase 1 remaining before it can be called closed:**

- `fips-aes` ECB/CBC/CTR/GCM implementations and KATs.

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
- DRBG health test on instantiate and reseed
- Continuous Random Number Generator Test (CRNGT) on DRBG output — note: required under FIPS 140-3 IG

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

- Use `serde` / `serde_json` for ACVP JSON schema handling
- One module per algorithm family matching ACVP spec IDs
- Test locally against NIST's sample vectors (available on GitHub: `usnistgov/ACVP-Server`)
- Integration test suite that runs all sample vectors and compares against expected outputs

---

## 6. Development Phases

### Phase 1: Foundation (Weeks 1–4)

**Goal:** Module boundary + core symmetric algorithms + self-test framework

- [x] Workspace scaffolding, CI pipeline (clippy, miri, cargo-fuzz)
- [x] `fips-module`: State machine, self-test runner, approved-mode indicator
- [ ] `fips-aes`: AES-128/192/256 in ECB, CBC, CTR modes
- [ ] `fips-aes`: AES-GCM (GHASH + CTR combination)
- [x] `fips-sha`: SHA-1, SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
- [x] `fips-hmac`: HMAC for all SHA variants (11 approved hash variants, including SHA-3)
- [x] Power-up KATs for Phase 1 hash/MAC/KDF algorithms (AES pending)
- [x] Software integrity self-test mechanism (`fips-integrity`: HMAC-SHA-256 over `current_exe()` with an embedded `[HDR | MAC | FTR]` slot populated by the external `fips-integrity-sign` tool, IG 10.3.A). Uniform mechanism across desktop, server, and code-signed mobile bundles — no sidecar files and no platform-specific ELF/Mach-O/PE parsing.

### Phase 2: Asymmetric + DRBG (Weeks 5–10)

**Goal:** All P0 asymmetric algorithms and random number generation

- [ ] `fips-drbg`: CTR_DRBG, HMAC_DRBG with prediction resistance
- [ ] CRNGT on DRBG output
- [ ] `fips-rsa`: Key generation (provable/probable primes per FIPS 186-5 Appendix A), PKCS#1 v1.5, PSS
- [ ] `fips-ecdsa`: P-256, P-384, P-521 field arithmetic, keygen, sign, verify
- [ ] `fips-ecdh`: ECDH per SP 800-56Ar3
- [ ] Pairwise consistency tests for all keygen operations
- [ ] Constant-time validation: verify with `dudect` or timing leak tests

### Phase 3: Extended Algorithms + ACVP (Weeks 11–16)

**Goal:** P1 algorithms, ACVP harness, comprehensive test coverage

- [ ] `fips-aes`: AES-CCM, AES-KW, AES-KWP
- [ ] `fips-cmac`: AES-CMAC
- [x] `fips-sha`: SHA-3 family, SHAKE128, SHAKE256 (SHAKE lives in `fips-xof`)
- [ ] `fips-eddsa`: Ed25519, Ed448
- [x] `fips-kdf`: SP 800-108r1 (Counter, Feedback, Double-Pipeline Iteration modes), SP 800-56Cr2 (HKDF KAT retrofit); HKDF (RFC 5869) over all 11 HMACs
- [ ] `fips-tls-kdf`: TLS 1.2 / 1.3 PRF/HKDF
- [ ] `fips-rsa`: OAEP
- [x] ACVP harness: scaffolding + power-up KAT runner (46 KATs wired)
- [ ] ACVP harness: registration + vector processing for remaining algorithm families
- [x] Run against NIST sample vectors from `usnistgov/ACVP-Server` (vendored at pinned commit `3611942e`; KATs sourced from vendored vectors with CAVP traceability)

### Phase 4: Hardening & Documentation (Weeks 17–22)

**Goal:** Security policy, side-channel hardening, audit readiness

- [ ] `fips-xof`: cSHAKE, KMAC (P2 algorithms)
- [ ] PBKDF2 (P2)
- [ ] Constant-time audit of all secret-dependent operations
- [ ] Fuzzing campaign: all algorithm entry points via `cargo-fuzz`
- [ ] Memory safety analysis with Miri
- [ ] Draft Security Policy document per SP 800-140D template
- [ ] Finalize API documentation
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
