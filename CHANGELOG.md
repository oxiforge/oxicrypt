# Changelog

All notable changes to **oxicrypt** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Release tags vs. internal-build tags.** Released versions tag `vX.Y.Z` (semver,
> eventually published to crates.io). Between releases, internal builds tag `vX.Y.Z.A`
> in git-tag space only — the `.A` increments per merged PR and resets when `X.Y.Z`
> changes (see [`CONTRIBUTING.md`](CONTRIBUTING.md)). This changelog tracks **releases**;
> the `0.1.0` entry folds in the pre-1.0 `v0.0.0.A` internal builds that preceded the
> first minor bump.

## [Unreleased]

_Nothing yet._

## [0.14.0] - 2026-06-15

SP 800-90B §5 IID permutation-testing battery + §3.1.4 restart analysis — closing the
two items the 0.13.0 entry deferred (Phase 0 pre-validation, out-of-boundary tooling).

### Added
- **`oxicrypt-maxwell` (out-of-boundary tooling):** the SP 800-90B §5.1 IID
  permutation-testing battery and the §3.1.4 restart-test row/column analysis. 18 of the
  19 §5.1 statistics are implemented and parity-checked against the NIST Entropy
  Assessment reference tool v1.1.8; the §5.1.11 bzip2 "compression" statistic is a
  documented STOP-AND-LEAVE — a NaN sentinel excluded from the verdict, because matching
  libbz2's compressed length bit-for-bit would require a C/third-party dependency the
  Phase-1 policy forbids, and the other 18 statistics determine the IID verdict on the
  bundled datasets. Plus the cleanup tail: t-Tuple/LRS CLI subcommands, the analytic
  min-entropy recovery path, a cargo-fuzz target, and EA-CLI documentation.

_PR #90._

## [0.13.0] - 2026-06-14

SP 800-90B raw-data collection + the complete non-IID min-entropy estimator suite (Phase 0 pre-validation).

### Added
- **`oxicrypt-entropy` (in-boundary):** raw-data collection mode — crate-private
  `RawCollector`, the 1,000,000-sample ESV wire format, and a vendored versioned
  metadata JSON schema (measured counter frequency); default-off `collection` feature
  and `collect` binary.
- **`oxicrypt-maxwell` (out-of-boundary tooling):** the SP 800-90B §6.3 per-OE
  acceptance gate; an FFT + autocorrelation periodicity screen; and the complete §6.3
  non-IID min-entropy estimator suite (Markov, Compression, t-Tuple, LRS, MultiMCW, Lag,
  MultiMMC, LZ78Y) — all matching the NIST Entropy Assessment reference tool v1.1.8 to
  ≤ 1e-6 bits on all 11 bundled datasets, most bit-exact.

_PR #89. Deferred (design-first): IID permutation-testing battery and the restart
row+column Section-5 analysis._

## [0.12.0] - 2026-06-12

SP 800-90B entropy-source subsystem (Wave 1+2) — first invocation of the
"new validation-track subsystem completion" minor-bump trigger.

### Added
- **`oxicrypt-entropy`:** sealed `NoiseSource` trait, cited 90B/90C constants, RCT/APT
  health tests with permanent poisoning, a CPU jitter source, and vetted SHA-256
  conditioning under the SP 800-90C full-entropy input margin.
- **`oxicrypt-timer`:** the fourth audited in-boundary `unsafe` crate (read-only CPU
  timer/counter intrinsics for the entropy source).

### Security
- Security-policy conformance gems R78–R82 and Appendix B added.

## [0.11.0] - 2026-05-17

### Added
- **LMS** expansion arc closeout — the full 80-pair parameter grid.

## [0.10.0] - 2026-05-16

SLH-DSA expansion arc closeout — the full FIPS 205 §11 stateless hash-based signature family.

### Added
- All **12 of 12** SLH-DSA parameter sets across SHA-2 and SHAKE families
  (`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`), built from a single `slh_dsa_impl!` macro
  instantiated 12 times.
- C ABI exports for 36 `oxi_slh_dsa_*` entry points.
- NIST grading: 372 cases across 12 parameter sets × keyGen/sigGen/sigVer graded `passed`.

_PR #78 (merge `115ca45`)._

## [0.9.0] - 2026-05-15

ML-DSA family closeout.

### Added
- **ML-DSA-44** and **ML-DSA-65** alongside the ML-DSA-87 baseline, from a single
  `ml_dsa_impl!` macro source.
- R69 `make_hint` shortcut form (FIPS 204 fence-case conformance at `a0 == -γ_2 && w_1 != 0`).
- ACVTS grading: 3 sessions, 192 cases, all `passed` (keyGen 75/75, sigGen 72/72, sigVer 45/45).

_PR #75 (merge `8f80699`)._

## [0.8.0] - 2026-05-14

ML-KEM grid closeout.

### Added
- **ML-KEM-512** and **ML-KEM-768** alongside the ML-KEM-1024 baseline (FIPS 203 Table 2,
  3/3), all three generated from one declarative `ml_kem_impl!` macro template.
- C ABI per-variant symbols plus 3 C round-trip and implicit-rejection smoke tests.
- ACVTS grading: 180 cases (75 keyGen AFT + 75 encaps AFT + 30 decaps VAL implicit-rejection), `passed` first-try.

### Security
- Phase 2 zeroize coverage closed across all three variants; three CMVP gems captured
  (macro-template parameter-set integrity, intermediate-state zeroize ordering, PQ C ABI smoke-test precedent).

_PR #74 (merge `7acd239`)._

## [0.7.0] - 2026-05-14

RSA family closeout (capability-matrix Section 12, 6/6).

### Added
- **KTS-IFC OAEP** key-transport handler, completing the deferred OAEP arc. RSA modes now
  6/6 graded: sigVer, keyGen, sigGen, sigPrim, decPrim, OAEP.
- Live-graded clean first-try (3 groups / 30 cases across 2048/3072/4096 moduli, both kasRoles).

_PR #73 (merge `9b6040f`)._

## [0.6.0] - 2026-05-13

DRBG family closeout (capability-matrix Section 7, 3/3).

### Added
- **hashDRBG** and **hmacDRBG** (720 cases each across SHA2-{256,384,512} × PR-{true,false}),
  live-graded `passed` first-try.

### Fixed
- Per-mode `returnedBitsLen` capability-shape (draft-vassilev-acvp-drbg Table 4: per-mode
  minimum = hash output length — SHA2-256→256, SHA2-384→384, SHA2-512→512).

## [0.5.0] - 2026-05-13

KDF + KAS double-section closeout (Section 8 KDF 3/3, Section 13 KAS 2/2).

### Added
- **KBKDF** counter + feedback + double-pipeline modes, first-live-graded (1,300 cases across all 11 HMAC PRFs).
- **KAS-FFC-SSC** (25 cases: AFT responder + VAL initiator), generalised verbatim from the KAS-ECC-SSC dispatch pattern.

## [0.4.0] - 2026-05-12

### Changed
- Toolchain: `rust-version` 1.95, edition 2024, and a pinned `rust-toolchain.toml`.

_PR #69._

## [0.3.0] - 2026-05-11

SP 800-185 / XOF family closeout (capability-matrix Section 4, 10/10).

### Added
- **SHAKE-{128,256}**, **KMAC-{128,256}**, **cSHAKE-{128,256}**, **TupleHash-{128,256}**,
  and **ParallelHash-{128,256}** (TupleHash and ParallelHash unified onto the XOF path).
  2,010 new ACVTS test cases.

### Fixed
- Conformance gems R65–R68 (security-policy.md §11): cSHAKE non-empty `functionName` +
  `customizationHex` field-name; TupleHash/ParallelHash capability-shape completeness
  (`msgLen`, `hexCustomization`); TupleHash MCT tuple-field + digest carry-forward.

## [0.2.0] - 2026-05-09

C ABI arc completion and a permissive relicense.

### Added
- **C ABI** surface across SHA-3, HMAC-SHA, AES, SHA-2, KDF, ECDSA, and EdDSA
  (8-PR arc: foundation + AES, CMAC, HMAC-SHA, SHA-2, KDF, ECDSA, EdDSA; DRBG deferred).
- ACVTS bring-up of ML-KEM, SLH-DSA, ML-DSA, and LMS.
- Capability-matrix preflight artifact.

### Changed
- **Relicensed to `Apache-2.0 OR MIT`** (Rust-ecosystem default), retiring PolyForm
  Noncommercial 1.0.0 (PR #63).

### Fixed
- ML-KEM decaps implicit-rejection (PR #59).

## [0.1.0] - 2026-04-27

First minor release. Recognises the cumulative substance shipped on the pre-1.0
`v0.0.0.A` internal-build train — a contribution model, CI hygiene, an HMAC regression
fix, and the first new primitive (TLS 1.3 KDF) — and retires that train.

### Added
- **TLS 1.3 KDF** per RFC 8446 §7.1: `tls13_hkdf_expand_label_internal` and
  `tls13_derive_secret_internal` (`oxicrypt-tls-kdf`), with the matching ACVP
  `TLS-v1.3 / KDF / RFC8446` harness handler. Live-graded `passed` first-try
  (ACVTS session 724216).
- Contribution model: `CONTRIBUTING.md` (GitHub Flow, squash-merge, local gate stack),
  the PR template, the internal-build tagging convention (`vX.Y.Z.A`), and
  `scripts/tag-next-build.sh`.

### Fixed
- HMAC handlers read `macLen` per-test with group-level fallback, restoring 11 offline
  MVT round-trip tests (PR #1).
- CI hygiene: rustfmt drift across five files and two Rust 1.95 clippy regressions (PR #2).

### Changed
- Workspace version `0.0.0` → `0.1.0`.

[Unreleased]: https://github.com/oxiforge/oxicrypt/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/oxiforge/oxicrypt/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/oxiforge/oxicrypt/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/oxiforge/oxicrypt/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/oxiforge/oxicrypt/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/oxiforge/oxicrypt/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/oxiforge/oxicrypt/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/oxiforge/oxicrypt/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/oxiforge/oxicrypt/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/oxiforge/oxicrypt/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/oxiforge/oxicrypt/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/oxiforge/oxicrypt/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/oxiforge/oxicrypt/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/oxiforge/oxicrypt/compare/v0.1.0.1...v0.2.0
[0.1.0]: https://github.com/oxiforge/oxicrypt/releases/tag/v0.1.0.1
</content>
