# oxicrypt — Rust FIPS 140-3 Project Plan

## Current status

**Phase 2: Algorithm implementation and ACVP validation.**

All fifteen algorithm crates are implemented, self-tested, and passing
clippy with workspace-wide `pedantic + deny` settings. The ACVP harness
has 62 registered handlers covering AFT, MCT, MVT, CTR, VOT, LDT, and
GDT test types. 120 ACVP round-trip tests and 7 CAVP SHS tests verify
every handler reproduces vendored answer fields byte-for-byte.

139 power-up KATs run at module initialisation, including 9 SP 800-90A
§9.3 prediction-resistance DRBG KATs and 3 §11.3 health-test KATs.

The `oxi` CLI binary exposes hash, HMAC, DRBG, and LAMA discovery from
the command line. Seven algorithm crates ship runnable examples.

### Recently landed

- LAMA (LLM API Manifest) spec and four discovery vectors
- Crate-root re-exports for agent-friendly import paths
- Display impls on all public error types (actionable messages)
- oxi CLI binary (hash, hmac, rand, --lama)
- Runnable examples for sha, hmac, aes, drbg, ecdsa, eddsa, ecdh
- Playground standalone crate using re-exports

## Phase breakdown

### Phase 1 — Workspace scaffolding (complete)

- [x] Cargo workspace with zero third-party deps policy
- [x] oxicrypt-module state machine (Power-On → SelfTest → Operational / Error)
- [x] KAT runner framework with `KatEntry` and `initialize_with_tests`
- [x] Workspace-wide lint configuration (pedantic + crypto-specific denies)
- [x] `no_std` by default for all algorithm crates

### Phase 2 — Algorithm implementation and ACVP (current)

#### Hashing
- [x] SHA-1 (FIPS 180-4 §6.1)
- [x] SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- [x] SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
- [x] SHAKE128, SHAKE256 (FIPS 202)
- [x] cSHAKE, KMAC, TupleHash, ParallelHash + XOF variants (SP 800-185)
- [x] Power-up KATs for all hash variants

#### MAC
- [x] HMAC over all 11 approved hashes (FIPS 198-1)
- [x] AES-CMAC 128/192/256 (SP 800-38B)
- [x] Power-up KATs for all MAC variants
- [x] ACVP MVT support for all 11 HMAC + 4 KMAC variants

#### Symmetric encryption
- [x] AES-128/192/256 block cipher (FIPS 197)
- [x] ECB, CBC, CTR modes (SP 800-38A)
- [x] GCM authenticated encryption/decryption (SP 800-38D, 96-bit IV, 128-bit tag)
- [x] CCM authenticated encryption/decryption (SP 800-38C)
- [x] Key Wrap / Key Wrap with Padding (SP 800-38F)
- [x] Power-up KATs per mode × key size
- [x] ACVP MCT for ECB and CBC
- [x] ACVP CTR counter-overflow/uniqueness tests

#### DRBG
- [x] CTR_DRBG AES-128/192/256 (both `no df` and `use df`) (SP 800-90A §10.2)
- [x] Hash_DRBG SHA-256/384/512 (SP 800-90A §10.1.1)
- [x] HMAC_DRBG SHA-256/384/512 (SP 800-90A §10.1.2)
- [x] Continuous health tests (SP 800-90A §11.3)
- [x] Power-up KATs + prediction-resistance KATs

#### KDF
- [x] SP 800-108r1 KBKDF (counter, feedback, double-pipeline modes)
- [x] SP 800-56Cr2 KDA-HKDF (extract-then-expand)
- [x] TLS 1.2 KDF (RFC 5246)
- [x] PBKDF2 (SP 800-132)

#### Asymmetric
- [x] RSA-2048 PKCS#1 v1.5 sign/verify (FIPS 186-5)
- [x] RSA-2048 PSS sign/verify (FIPS 186-5)
- [x] RSA OAEP encrypt/decrypt (SP 800-56Br2)
- [x] RSA keygen (FIPS 186-5 Appendix B.3)
- [x] ECDSA P-256 sign/verify/keygen (FIPS 186-5)
- [x] ECDH P-256 CDH (SP 800-56Ar3)
- [x] Ed25519 sign/verify/keygen (RFC 8032, FIPS 186-5 §7.8)
- [x] ACVP GDT for RSA SigVer and SigGen

#### ACVP harness
- [x] 62 registered algorithm handlers
- [x] 120 ACVP round-trip tests + 7 CAVP SHS tests
- [x] All test types: AFT, MCT, MVT, CTR, VOT, LDT, GDT
- [ ] ACVP demo server dry-run submission

#### Developer experience
- [x] LAMA manifest with four discovery vectors
- [x] Crate-root re-exports for agent-friendly paths
- [x] Display impls on all public error types
- [x] oxi CLI binary
- [x] Runnable examples for 7 algorithm crates
- [x] Playground standalone crate

#### Remaining Phase 2 work
- [ ] ACVP demo server dry-run (pending server access)
- [ ] Zeroization of CSPs on drop (planned, deferred to hardening pass)
- [ ] Complete security policy human review pass

### Phase 3 — CST lab engagement (not started)

- [ ] CAVP algorithm certificate applications
- [ ] CST lab selection and engagement
- [ ] CMVP module submission
- [ ] Security policy finalization with lab feedback
- [ ] Entropy source design for operational deployments

### Phase 4 — Hardening and expansion (not started)

- [ ] AES-NI support with safe fallback (constant-time)
- [ ] Bitsliced AES pure-Rust fallback
- [ ] Additional curves: Ed448, P-384, P-521
- [ ] Language bindings: C ABI, Python, Go, Node
- [ ] Performance benchmarking and optimization
- [ ] Formal zeroization audit
