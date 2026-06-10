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

- **`forbid(unsafe_code)` is the in-boundary default**, not a style choice — 21 of 23 in-boundary crates
  carry it. It is a build-time control that enters the conformance argument. Exactly two sanctioned
  `unsafe` categories exist, each isolated in its own small audited crate: (1) **volatile CSP
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

- [ ] ISC-1: 21 of the 23 in-boundary crates carry `#![forbid(unsafe_code)]`; the two audited exceptions are `oxicrypt-zeroize` (volatile CSP zeroization via `write_volatile`) and `oxicrypt-sha-accel` (sanctioned CPU-intrinsic acceleration: feature-gated, default-off, runtime-detected, KAT + cross-path-oracle equivalence; one audited `unsafe` block). `oxicrypt-ffi` lives outside the boundary to offer a C ABI, where `unsafe extern "C"` is unavoidable; `no_std` where applicable
- [ ] ISC-2: every approved algorithm has known-answer / ACVP vectors that pass (`oxicrypt-test-vectors`, `acvp-harness/`)
- [ ] ISC-3: power-up self-tests run and gate operation (`oxicrypt-integrity`)
- [ ] ISC-4: the module boundary is formally defined (`oxicrypt-module`)
- [ ] ISC-5: SSPs are zeroized on drop; the zeroization invariant is documented and tested (`oxicrypt-zeroize`)
- [ ] ISC-6: `docs/security-policy/security-policy.md` describes every approved service and self-test
- [ ] ISC-7: root `lama.yaml` + `docs/llm-api-manifest/llm-api.yaml` match the public API surface
- [ ] ISC-8: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] ISC-9: Anti: no non-approved algorithm is reachable through the validated module boundary
- [ ] ISC-10: Anti: no host path / private-project name / internal context appears in any tracked file

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

## Features

> Placeholder — derive the real breakdown from the validation work plan.

| name | satisfies | depends_on | parallelizable |
|------|-----------|------------|----------------|
| module-boundary | ISC-4,9 | — | no |
| self-tests | ISC-3 | module-boundary | no |
| algorithm-vectors | ISC-2 | — | yes |
| security-policy | ISC-6 | module-boundary, self-tests | no |
| manifests | ISC-7 | — | yes |

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

## Changelog

(future)

## Verification

(future)
