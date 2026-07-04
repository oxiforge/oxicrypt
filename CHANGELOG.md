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

### Added

- `tools/doc-guard`: test-gate drift guard whose tests recompute the boundary/`unsafe` accounting from the workspace on disk (crate count, out-of-boundary set, `forbid(unsafe_code)` ratio, audited-exception names, exported-FFI-function count) and assert the values stated in `security-policy.md` §1/§9.2/§3.1, `AGENTS.md`, and `README.md` match (#101).
- `esv-harness`: new out-of-boundary ESV submission client for SP 800-90B entropy-source validation, driving the full ESVP 1.0 flow over `acvp-harness`'s curl(1)/mutual-TLS transport with zero network and zero third-party dependencies in every automated path. Authentication: ESVP login, single-token and bulk token refresh (tunable proactive margin, reactive 401/403 retry, TOTP-window-reuse retry, and a fresh-login fallback when a stale-token refresh is rejected). Registration: the entropy-source metadata payload builder (multi-OE, vetted SHA2-256 conditioning with a required CAVP validation number) plus the multi-OE response parser. Preflight (offline, before any server contact): a payload preflight drift-guarded against the vendored NIST metadata schema, and a data-file preflight — exactly 1,000,000 one-byte-per-sample symbols, symbols within the effective `min(bitsPerSample, 8)` width, the mandated 1000×1000 restart layout, and `DataFileSampleSize` consistency — checked against the module's own SP 800-90B constants so validator and dataset emitter cannot drift. Data files: the multipart upload builder (capitalized `DataFileSampleSize` for server v1.8), a bounded processing-status poll over all seven documented statuses that captures NIST's returned assessment as an independent entropy-assessment oracle, and a typed refusal of any conditioned-bits upload under vetted conditioning. Supporting documents: a PDF-only upload with the supporting-document-type enumeration. Certify: the full-submission, add-operating-environment, and update-PUD request builders enforcing exactly-one-EAR / exactly-one-PUD / at-most-one-attestation cardinality and the required cross-program identifiers. Session: a resumable per-submission store with a persist-before-submit event log. `hminEstimate` is serialized exactly from the module's fixed-point min-entropy type (1/256-bit steps) as a finite decimal with no float on the claim path, round-tripped byte-for-byte through a lossless response reader.

### Fixed

- `security-policy.md`: §1 boundary accounting made explicit (29 library crates, two out-of-boundary, `oxicrypt-test-vectors` ruled in-boundary — its KAT constants compile into the power-up self-tests), resolving a latent §1-vs-§9.2 denominator contradiction; module-version field annotated as assigned-at-submission; §3.1 states the as-built 451-function FFI surface; Appendix B scoped to design/boundary rationale with release history pointed at `CHANGELOG.md`. `AGENTS.md` and `README.md` synced to the same accounting (#101).

## [0.19.0] - 2026-06-28

### Added

- `oxicrypt-keccak-accel`: new audited-unsafe crate carrying an x86_64 AVX2 4-way batched Keccak-f[1600] permutation (`keccak_f1600_x4` / `keccak_f1600_x4_available`), CPUID-gated and byte-exact to the portable `keccak_f1600` (1000-trial cross-path equality oracle against the real scalar permutation); the fifth audited in-boundary acceleration crate, default-off and out of the validated default build graph (#110).
- `oxicrypt-sha`: batched `Sponge4` four-way Keccak sponge API (`absorb_4` / `finalize_4` / `squeeze_4` over four equal-length streams); its single permutation point dispatches to the AVX2 4-way path behind the new default-off `accel-keccak` feature, byte-identical to four independent `Sponge`s (cross-path oracle, feature on and off) (#110).
- `oxicrypt-ml-dsa`: default-off `accel-keccak` feature batches `ExpandA` four independent SHAKE-128 cell streams at a time through `Sponge4` (the first in-boundary caller of the batched Keccak path); the crate stays `#![forbid(unsafe_code)]` and Â is byte-identical to the scalar build (direct accel-vs-scalar differential oracle for ML-DSA-44/65/87, feature on and off) (#110).

## [0.18.1] - 2026-06-24

### Changed

- `oxicrypt-maxwell`: relicensed back to the workspace `Apache-2.0 OR MIT`, reverting the 0.18.0 PolyForm Noncommercial license. It is commodity out-of-boundary tooling that competes with the free authoritative NIST `SP800-90B_EntropyAssessment` reference, so a noncommercial gate protected nothing while forfeiting adoption; `publish = false` is retained (it stays off crates.io as internal tooling — a publish-status choice independent of the license).

## [0.18.0] - 2026-06-24

### Added

- `oxicrypt-ffi`: C-ABI integration smoke test for the SP 800-90A DRBG families (`oxi_{hmac,hash,ctr}_drbg_*`) — full `new → instantiate → generate → reseed → generate → free` lifecycle per family with a non-trivial-output assertion and the documented `NullPointer` guard on a NULL handle (#98).
- `oxicrypt-aes-accel`: PCLMULQDQ-accelerated constant-time GCM GHASH multiply (`ghash_available` / `ghash_mul`), CPUID-gated (PCLMULQDQ + SSSE3 + SSE2) and dispatched from `oxicrypt-aes`'s `gf_mul` behind the default-off `accel-aes` feature; byte-exact to the portable schoolbook reduction (50 000-pair differential oracle + GCM KATs feature-on), fail-portable on absence, out of the validated default build graph (#109).

### Changed

- LAMA manifests (`lama.yaml`, `docs/llm-api-manifest/llm-api.yaml`): descriptions reduced to one declarative sentence each per the LAMA spec's declarative-not-narrative principle (the 287 remaining multi-sentence descriptions collapsed), and `library.version` stamped to 0.18.0; no API or structured-fact change (#116, #118).
- `oxicrypt-maxwell`: relicensed to **PolyForm Noncommercial 1.0.0** (`license-file` + `publish = false`), overriding the workspace `Apache-2.0 OR MIT`. Out-of-boundary tooling and a dependency-leaf with no in-tree dependents, so no library crate's licensing changes; noncommercial use is free, commercial use requires a separate license.

### Fixed

- `tools/acvp-gen`: the KAT-constant generator wrote to the dead `crates/fips-test-vectors/src/generated.rs` path (missed by the `pqclib → oxicrypt` rename), so it created a stray crate directory and never regenerated the live file; the output now targets `crates/oxicrypt-test-vectors/src/generated.rs` (#100).

## [0.17.0] - 2026-06-22

### Added

- `oxicrypt-xmss`: optional `parallel` feature (default off) — `rayon` fork-join over the recursive Merkle tree build for keygen throughput, byte-identical to the validated single-threaded build (security policy R83).
- `oxicrypt-ml-kem`: optional `parallel` feature (default off) — `rayon` row-disjoint expansion of the k×k matrix Â in `expand_a`, byte-identical to the validated single-threaded build (security policy R84).
- `oxicrypt-ml-dsa`: optional `parallel` feature (default off) — `rayon` row-disjoint expansion of the k×ℓ matrix Â in `expand_a`, byte-identical to the validated single-threaded build (security policy R85).
- `oxicrypt-entropy`: optional `rand-core` feature (default off) — `rand_core_compat::EntropyRng` exposes the pipeline's vetted conditioned output as a fallible `rand_core` 0.9 `TryRngCore` (+ `TryCryptoRng`), fail-closed and `no_std`-preserving. No new entropy claim — a convenience adapter over the existing `conditioned_block` output.

## [0.16.0] - 2026-06-19

Closes the SP 800-90B §5.1 compression statistic (statistic 18) in `oxicrypt-maxwell`, so the IID
permutation test now evaluates all nineteen statistics; adds post-quantum criterion benchmarks; and
refreshes the public-API and ACVP-mapping documentation (out-of-boundary tooling and docs only — the
cryptographic boundary is unchanged).

### Added
- **§5.1 compression statistic (statistic 18) in `oxicrypt-maxwell`:** previously a `NaN` sentinel
  excluded from the IID verdict, now computed bit-exactly. The samples are formatted as the NIST
  Entropy Assessment tool does (space-separated decimal text) and bzip2-compressed at level 5,
  matching `ea_iid -v -v -v` "Unpermuted result compression" byte-for-byte (rand1_short = 1611,
  rand4_short = 5520, rand8_short = 10987). All nineteen statistics now participate in the verdict.
- **Post-quantum criterion benchmarks:** ML-KEM, ML-DSA, SLH-DSA, and XMSS.

### Changed
- **`oxicrypt-maxwell`** centralizes the value-sorted-alphabet helper shared across estimators
  (EA-parity ≤ 1e-6 preserved).
- **Documentation:** `api.md` and `usage.md` refreshed to the current public-API surface
  (post-quantum, Diffie–Hellman, XOF families); the LAMA manifest gains full `oxicrypt-xof` coverage;
  per-family ACVP-algorithm → handler dispatch notes added.
- **First third-party dependency in the workspace:** the pure-Rust `bzip2` crate (libbz2-rs-sys
  backend — no C, no `bzip2-sys`), confined to the out-of-boundary `oxicrypt-maxwell` tool. The
  cryptographic boundary and `acvp-harness` remain dependency-free; the Security Policy records the
  scoping. With compression now scored per shuffle, the `oxicrypt-maxwell` permutation suite roughly
  doubles in wall-clock (≈490s → ≈972s) — the inherent cost of a complete nineteen-statistic §5.1
  verdict, matching the reference tool.

## [0.15.0] - 2026-06-17

Completes the SP 800-90B §6.3 multi-bit entropy assessment in `oxicrypt-maxwell`: the
literal-symbol track for every estimator EA computes on it, the assembled `H_original`, and
the per-symbol "Assessed min entropy" headline on the IID gate (out-of-boundary tooling).

### Added
- **`oxicrypt-maxwell` literal-symbol track (§6.3):** t-Tuple, LRS, MultiMCW, Lag, MultiMMC,
  and LZ78Y now compute a literal-track estimate for multi-bit data, each parity-checked against
  the NIST Entropy Assessment reference tool v1.1.8 within 1e-6. (Collision, Markov, and
  Compression have no distinct multi-bit literal value in EA and are correctly excluded.)
- **`h_original`:** the minimum over the MCV-literal and the six literal-track estimates.
- **Per-symbol assessed min-entropy on the IID gate:** `IidGateResult` gains an
  `AssessedMinEntropy { per_symbol, h_original, h_bitstring, word_size }` field beside the
  per-bit `min_entropy`. `iid_gate()` assembles the EA headline
  `min(H_original, H_bitstring × word_size)` per branch (MCV-literal `H_original` on the IID
  branch, the §6.3 literal-suite minimum on the non-IID branch), reproducing EA's "Assessed min
  entropy" line within 1e-6 on the multi-bit reference datasets, branch-matched (the gate's
  IID/non-IID verdict agrees with EA's per dataset).
- **`maxwell iid-gate` CLI:** reports both the per-bit routed value and the per-symbol assessed
  headline with its `min(...)` breakdown.

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

[Unreleased]: https://github.com/oxiforge/oxicrypt/compare/v0.19.0...HEAD
[0.19.0]: https://github.com/oxiforge/oxicrypt/compare/v0.18.1...v0.19.0
[0.18.1]: https://github.com/oxiforge/oxicrypt/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/oxiforge/oxicrypt/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/oxiforge/oxicrypt/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/oxiforge/oxicrypt/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/oxiforge/oxicrypt/compare/v0.14.0...v0.15.0
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
