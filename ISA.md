---
task: oxicrypt FIPS 140-3 cryptographic-module ideal-state contract and system of record
project: oxicrypt
effort: E3
phase: seed
progress: 0/0
mode: interactive
started: 2026-06-06T00:00:00Z
updated: 2026-06-10T00:00:00Z
---

# oxicrypt — ISA (Ideal State Artifact)

> **Placeholder, seeded 2026-06-06.** System of record for the oxicrypt cryptographic module: the
> articulated ideal state, the contributor contract, and the done-condition for CAVP/CMVP validation.
> Read it to understand *where the boundaries are and why they hold* before changing anything. The
> Criteria below are an initial draft seeded from the existing design — the security-design detail lives
> in `docs/security-policy/security-policy.md`; this file is the boundary contract. Refine the Criteria
> into the full per-algorithm / per-service ISC inventory as validation work proceeds.

## Problem

Post-quantum cryptography is now mandated (CNSA 2.0), but a pure-Rust, FIPS 140-3-validatable module
that covers both the classical FIPS-approved algorithm set and the PQC suite (ML-KEM, ML-DSA, SLH-DSA,
LMS, XMSS) — with a formal module boundary, power-up self-tests, and an ACVP harness — does not exist in
a form ready for CAVP/CMVP submission. oxicrypt is that module: pure Rust, `no_std`-capable,
`forbid(unsafe_code)`, built to pass an accredited CST lab.

## Vision

A reviewer — NIST/CST auditor, downstream integrator, or LLM agent — opens oxicrypt and finds a module
whose every approved service, self-test, zeroization invariant, and conformance claim is stated once,
verifiable, and backed by ACVP vectors or a power-up self-test. The euphoric surprise is that FIPS
conformance is *demonstrable from the source*, not asserted in a PDF: the security policy, the manifests,
and the code agree because the commit gate forces them to.

## Out of Scope

- **FIPS levels above 1** — Level 1 is the target; physical-security and higher operational-environment
  requirements are not in scope.
- **Non-approved / experimental algorithms** in the validated boundary — approved algorithm set only.
- **TLS / protocol layers** — those live in sibling crates (`oxitls`), built *on* oxicrypt, not in it.

## Principles

- **`forbid(unsafe_code)` is the in-boundary default**, not a style choice — 21 of 24 in-boundary crates
  carry it. It is a build-time control that enters the conformance argument. Exactly two sanctioned
  `unsafe` categories exist, isolated in three small audited crates: (1) **volatile CSP
  zeroization** — `oxicrypt-zeroize`, one audited `unsafe` mechanism for `write_volatile`; and
  (2) **CPU-intrinsic acceleration** — `oxicrypt-sha-accel`: feature-gated, default-off,
  runtime-detected, equivalence to the portable path proven by KAT + cross-path oracle. The default
  build graph contains no acceleration crate; the validated portable baseline is the shipping default.
  The C-ABI crate (`oxicrypt-ffi`) sits outside the boundary and necessarily carries unsafe.
- **One home per security claim** — the CMVP claims live in `docs/security-policy/security-policy.md`;
  code and rustdoc point at it, never restate it.
- **Conformance is falsifiable** — every approved service has a known-answer / ACVP vector that fails if
  the implementation drifts.

## Constraints

- **FIPS 140-3 Level 1**, Implementation Guidance D.G (March 2026) — reconcile on IG updates.
- **`no_std`-capable**, `forbid(unsafe_code)` at every crate root, deny-level workspace lints.
- **License:** Apache-2.0 OR MIT.
- **Public repository** — no host paths, no private-project names, no internal/vault context.

## Goal

Be a pure-Rust FIPS 140-3 Level 1 cryptographic module — classical + PQC approved algorithms, formal
module boundary, power-up self-tests, ACVP harness — that passes CAVP algorithm validation and CMVP
module validation through an accredited CST lab, with security policy, manifests, and code kept in lockstep
by the commit-is-the-gate doc-sync discipline.

## Criteria

> Placeholder set — expand into the full per-algorithm / per-service inventory during validation.

- [ ] ISC-1: 22 of the 26 in-boundary crates carry `#![forbid(unsafe_code)]`; the four audited exceptions are `oxicrypt-zeroize` (volatile CSP zeroization via `write_volatile`), the two CPU-intrinsic-acceleration crates `oxicrypt-sha-accel` / `oxicrypt-aes-accel` (sanctioned category: feature-gated, default-off, runtime-detected, KAT + cross-path-oracle equivalence), and `oxicrypt-timer` (sanctioned category: read-only CPU timer/counter intrinsics, side-effect-free, no cryptographic logic). `oxicrypt-ffi` lives outside the boundary to offer a C ABI, where `unsafe extern "C"` is unavoidable; `no_std` where applicable
- [ ] ISC-2: every approved algorithm has known-answer / ACVP vectors that pass (`oxicrypt-test-vectors`, `acvp-harness/`)
- [ ] ISC-3: power-up self-tests run and gate operation (`oxicrypt-integrity`)
- [ ] ISC-4: the module boundary is formally defined (`oxicrypt-module`)
- [ ] ISC-5: SSPs are zeroized on drop; the zeroization invariant is documented and tested (`oxicrypt-zeroize`)
- [ ] ISC-6: `docs/security-policy/security-policy.md` describes every approved service and self-test
- [ ] ISC-7: root `lama.yaml` + `docs/llm-api-manifest/llm-api.yaml` match the public API surface
- [ ] ISC-8: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] ISC-9: Anti: no non-approved algorithm is reachable through the validated module boundary
- [ ] ISC-10: Anti: no host path / private-project name / internal context appears in any tracked file
- [ ] ISC-11: `oxicrypt-entropy` noise sources declare only a design-anchored ceiling — no claimed-H constant appears in any source implementation; the claim is injected at pipeline construction
- [ ] ISC-12: entropy-pipeline construction with a claim above the source ceiling or above the declared sample width fails with a typed error
- [ ] ISC-13: every SP 800-90B numeric lives in `oxicrypt_entropy::sp800_90b` with a clause citation; no 90B numeric is restated elsewhere in the workspace
- [ ] ISC-14: every `oxicrypt-entropy` health-test failure is permanent — the failing sample is never released, no sample is released afterward, only re-instantiation clears
- [ ] ISC-15: no sample leaves an entropy pipeline before startup tests pass over ≥1024 consecutive samples; startup-tested samples are discarded
- [ ] ISC-16: the pipeline's emission method is the only sample path — every released sample passed RCT and APT
- [ ] ISC-17: every 256-bit conditioned output block consumes health-tested samples carrying at least n_out + 64 bits of assessed min-entropy (SP 800-90C §3.2.2.2 input margin), the per-block count derived from the injected claim by exact integer arithmetic
- [ ] ISC-18: the conditioner is stateless across output blocks (fresh hash per block, config-only struct) and a startup conditioning-KAT mismatch is a permanent refusal

## Test Strategy

| isc | type | check | threshold | tool |
|-----|------|-------|-----------|------|
| 1 | constraint | grep crate roots for forbid(unsafe_code) | all crates | Grep |
| 2 | functional | KAT/ACVP vectors pass | all approved algs | cargo test / acvp-harness |
| 3 | functional | self-tests gate operation | pass | cargo test |
| 4,5 | structure | module boundary + zeroization defined/tested | present | Read/test |
| 6,7 | content | security policy + manifests match code | in sync | Read/Grep |
| 8 | mechanical | fmt + clippy clean | 0 issues | Bash |
| 9,10 | anti | boundary + leakage checks | 0 violations | Grep/review |
| 11 | structure | API shape + grep for H literals in source impls | zero | Grep |
| 12 | functional | ceiling/width refusal unit tests | green | cargo test |
| 13 | constraint | grep 90B numerics outside sp800_90b | zero restatements | Grep + cargo test |
| 14 | functional | poisoning permanence unit tests (RCT-fail + APT-fail paths) | green | cargo test |
| 15 | functional | startup-gating + discard unit tests | green | cargo test |
| 16 | structure | API-surface inspection — no bypass emission path | single path | Read + cargo test |
| 17 | functional | margin + minimality sweep across the claim grid | green | cargo test |
| 18 | functional | block-independence + corrupted-KAT refusal unit tests | green | cargo test |

## Features

> Placeholder — derive the real breakdown from the validation work plan.

| name | satisfies | depends_on | parallelizable |
|------|-----------|------------|----------------|
| module-boundary | ISC-4,9 | — | no |
| self-tests | ISC-3 | module-boundary | no |
| algorithm-vectors | ISC-2 | — | yes |
| security-policy | ISC-6 | module-boundary, self-tests | no |
| manifests | ISC-7 | — | yes |
| entropy-scaffolding | ISC-11,12,13,14,15,16,17,18 | — | yes |

## Decisions

- 2026-06-06: ISA seeded as a placeholder during the AGENTS.md rollout. Boundary contract here; CMVP
  security-design detail stays in `docs/security-policy/security-policy.md` (its canonical home). Expand
  Criteria into the full per-service inventory as CAVP/CMVP work proceeds.
- 2026-06-10: Project-lead ruling — a second sanctioned `unsafe` category, **CPU-intrinsic
  acceleration** (feature-gated, default-off, runtime-detected, equivalence proven by KAT +
  cross-path oracle), implemented as the new audited crate `oxicrypt-sha-accel`, mirroring the
  `oxicrypt-zeroize` exception precedent. ISC-1 accounting amended from 21-of-22 to 21-of-23
  in-boundary (two audited exceptions). Scope: SHA-256 compression only (SHA-224 inherits via the
  shared FIPS 180-4 compression function); SHA-1 acceleration explicitly out (legacy-use). x86_64
  SHA-NI first; AArch64 SHA2 intrinsics are a documented follow-up under the same category. Each
  accel path is a distinct CAVP-tested operational-environment configuration when validation comes
  (see security-policy R74).

- 2026-06-11 (night loop, PROPOSED — merging this branch constitutes the project-lead ruling):
  second implementation under the 2026-06-10 CPU-intrinsic acceleration category —
  `oxicrypt-aes-accel` (x86_64 AES-NI single-block encrypt/decrypt), consumed by `oxicrypt-aes`
  behind default-off `accel-aes`. ISC-1 accounting amended 21-of-23 → 21-of-24 (three audited
  crates, still two sanctioned categories). Correctness oracle placement diverges from the SHA
  precedent by necessity: FIPS 197 Appendix C KATs + 512-block dispatch≡portable cross-path tests
  live in `oxicrypt-aes`'s feature-gated tests because the key schedule is deliberately private.
  Measured 13.1× on AES-256 single-block (73.7 → 961.8 MiB/s, byte-identical outputs). Follow-ups
  under the same category: multi-block pipelining for CTR/GCM bulk paths; AArch64 AES intrinsics.
  See security-policy R76 + §9.2 item 3.

- 2026-06-12: `oxicrypt-entropy` scaffolding landed (in-boundary; ISC-1 accounting 21-of-24 →
  22-of-25, exceptions unchanged). Ratified trait shape: three-stage pipeline (noise source →
  health tests → conditioner); sources are dumb emitters declaring only a design-anchored
  `max_claimable_h()` ceiling; claimed min-entropy is injected at pipeline construction and
  refused with a typed error above the ceiling or the declared sample width; min-entropy is
  exact fixed-point (1/256-bit steps, floor rounding) with no floats on the claim/cutoff path.
  SP 800-90B constants transcribed into the single cited module `sp800_90b` from the published
  document plus same-day errata check (security-policy R78). Health tests, jitter source,
  conditioning, and the 90B estimator suite follow as separate landings; ISC-11–13 added.

- 2026-06-12: `oxicrypt-entropy` health layer landed: §4.4 approved tests (RCT closed-form
  integer cutoff; APT precomputed-table cutoffs with typed refusal for uncovered (α, alphabet, H)
  points — no runtime binomial), §4.3 startup gating (≥1024 samples, tested samples discarded)
  and on-demand re-testing on fresh state, all failures permanent (terminal poisoned state,
  re-instantiation only). Health-test KAT vector files shipped with documented generation and
  known outcomes. ISC-14–16 added (security-policy R79). The APT table's α = 2⁻³⁰ default rows
  arrive from the out-of-boundary cutoff-table generator; until then the seeded spec-reference
  rows (α = 2⁻²⁰) are the covered grid.

- 2026-06-12: Project-lead ruling — a third sanctioned `unsafe` category, **CPU timer/counter
  intrinsics** (read-only, side-effect-free register/counter reads, no cryptographic logic,
  dedicated audited crate), implemented as `oxicrypt-timer` (serialized TSC on x86_64,
  CNTVCT_EL0 on aarch64; exactly two unsafe blocks with SAFETY comments). ISC-1 accounting
  22-of-25 → 22-of-26 (four audited exceptions, three categories; security-policy §9.2 item 4 +
  R80). The entropy crate's timer layer (safe Rust, forbid-clean) adds per-arch defaults with
  documented rationale, the measured-never-assumed adequacy self-check with typed refusals, and
  width-aware wrapping-delta semantics with backwards classification. aarch64 paths compile via
  cfg; their runtime verification rides the CI matrix when it lands.

- 2026-06-12: `oxicrypt-entropy` jitter source landed — the first real noise source behind
  the sealed abstraction, design-derived CPU execution-time jitter (black_box-disciplined
  SHA-256 + data-dependent memory-walk workload with a release-build variance guard; 4-LSB
  digitization with one symbol stream end to end and the digitization-transparency
  justification in the module rustdoc; 1 bit/sample design ceiling, no claimed-H constants;
  construction-time timer-adequacy refusal; bounded backwards-delta retry yielding a typed
  Unavailable on exhaustion). Independent design review confirmed the source fails closed.
  Security-policy R81. (Entry recorded with the conditioning landing — same-day doc-sync
  backfill.)

- 2026-06-12: `oxicrypt-entropy` vetted conditioning landed: SHA-256 conditioning component
  (90B §3.1.5.1.1 Table 1, via `oxicrypt-sha`) with per-block sample count derived from the
  injected claim under the SP 800-90C §3.2.2.2 full-entropy input margin (h_in ≥ n_out + 64;
  90C September 2025 final transcribed into `sp800_90b` with fetched-document provenance),
  stateless per-block hashing (fresh hash instance per block, config-only conditioner struct),
  startup conditioning KAT with permanent refusal on mismatch, and conditioned output drawing
  every sample through the single health-tested emission path. ISC-17–18 added
  (security-policy R82).

## Changelog

(future)

## Verification

(future)
