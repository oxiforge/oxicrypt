# Project instructions — oxicrypt

Standing rules for any AI assistant working in this repository. Loaded automatically at the start of
every session by any agent that respects `AGENTS.md`. Model-agnostic — phrase everything in terms of
"the assistant" or imperative; do not assume a specific tool or vendor.

## Project context

oxicrypt is a **pure-Rust FIPS 140-3 Level 1 cryptographic module**. It implements FIPS-approved
algorithms across a 27-crate workspace (AES, SHA, SHA-3/XOF, HMAC, CMAC, KDF, TLS-KDF, DRBG, ECDH,
ECDSA, EdDSA, RSA, DH, ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS, plus `zeroize`, `sha-accel`, `integrity`,
`ffi`, `module`, `test-vectors`, and the SP 800-90B `entropy` scaffolding). The crate is `no_std`-capable and
disciplined about `unsafe`: **22 of the 26 crates inside the cryptographic boundary are
`#![forbid(unsafe_code)]`.** The four audited in-boundary exceptions, each isolating sanctioned
`unsafe` in a small dedicated crate, are `oxicrypt-zeroize` (volatile zeroization of critical
security parameters), the two CPU-intrinsic acceleration crates `oxicrypt-sha-accel` /
`oxicrypt-aes-accel` (feature-gated, default-off, runtime-detected, equivalence proven by KAT +
cross-path oracle), and `oxicrypt-timer` (read-only CPU timer/counter intrinsics for the entropy
source). Separately,
`oxicrypt-ffi` sits **outside** the boundary to offer a C ABI, where `unsafe extern "C"` is an
unavoidable requirement of exposing the module to C callers. (See `docs/security-policy/security-policy.md`
for the authoritative unsafe-code accounting.) It
defines a formal module boundary with power-up self-tests, and ships an ACVP test harness — targeting
**CAVP algorithm validation** and **CMVP module validation** through an accredited CST laboratory.

**Compliance target:** FIPS 140-3, following the current **Implementation Guidance** release (IG
**D.G** as of March 2026). When the IG updates, reconcile any affected design decisions against the new
text before shipping further work. This is load-bearing: it is the standard the module is built to.

## Key paths

- **Repo:** this repository — <https://github.com/oxiforge/oxicrypt>
- **Engineering standards (inherited):** <https://github.com/oxiforge/standards> — the gem-rule
  doc-sync pattern and the `SECURITY.md` fixed/fill-in template this crate adopts by reference.
- **LAMA spec:** <https://github.com/lamaspec/lama> — the API-manifest format `lama.yaml` and
  `docs/llm-api-manifest/` conform to. oxicrypt is the LAMA reference adoption.
- **Security policy (in-repo):** `docs/security-policy/security-policy.md`
- **LAMA manifests (in-repo):** root `lama.yaml` (discovery summary) + `docs/llm-api-manifest/llm-api.yaml` (full)
- **ACVP harness (in-repo):** `acvp-harness/`

Reference code by LAMA module notation (`oxicrypt_<crate>::path::Item`), not file paths — it survives
file moves and teaches the manifest.

## Session bootstrap

At the start of every session — or after a context reset — read these in order before doing anything else:

1. **`ISA.md`** (this repo) — the Ideal State Artifact: the authoritative design contract and system of
   record. Read its Problem / Vision / Principles / Constraints / Out of Scope before changing any
   boundary. Each ISC is a verifiable end-state; IDs are permanent (never renumbered).
2. **`docs/security-policy/security-policy.md`** — the CMVP Security Policy draft: approved services,
   SSPs, self-tests, state machine, side-channel posture. The security-design home.
3. **`docs/llm-api-manifest/llm-api.yaml`** — the full LAMA manifest describing the public API surface.

## Canonical homes

Every kind of project fact has exactly **one** canonical home. Do not duplicate a fact across surfaces
— copies drift, and a drifted copy is worse than no copy. To read a fact, read its home; to change it,
update only its home (and any *pointer* that names it — never a second copy of the value). If the right
home for something isn't obvious — or doesn't exist yet — propose one and raise it, rather than silently
picking a home or copying the fact into several places.

| Fact | Canonical home | Everything else |
|------|----------------|-----------------|
| **Design contract** — Problem, Vision, Principles, Constraints, Criteria, Out of Scope | **`ISA.md`** | pointer only |
| **CMVP security claims** — approved services, SSPs, self-tests, state machine, side-channel posture | **`docs/security-policy/security-policy.md`** | rustdoc/README carry a pointer |
| **Public API surface** (per crate) | **`docs/llm-api-manifest/llm-api.yaml`** | the full LAMA manifest |
| **API-discovery summary** | **root `lama.yaml`** — concise capabilities + manifest pointer, conformant to the LAMA spec; no milestone/coverage/status | pointer only |
| **Compliance target** (FIPS 140-3 IG revision) | **`ISA.md`** + `docs/security-policy/` | never restated as an inline constant |
| **Release history** — what shipped, when, under which tag | **git tags + `CHANGELOG.md`** | README/lama.yaml carry a pointer, never a milestone table |
| **Release version** | **git tags** | `lama.yaml` / `README.md` stamped at release from the tag |

## Definition of done

Every task is incomplete until all of these pass. Run them as the last step before handing control back,
and re-run after any post-review fix-ups:

1. `cargo fmt --all --check` — no unformatted code (run `cargo fmt --all` to fix, then re-check).
2. `cargo clippy --workspace --all-targets -- -D warnings` — no warnings.
3. **Crypto correctness** — for any change to an approved-algorithm crate, its known-answer / ACVP
   vectors stay green (`oxicrypt-test-vectors`, `acvp-harness/`) and power-up self-tests pass
   (`oxicrypt-integrity`). A green lint pass does not substitute for green vectors on a crypto change.
4. **Doc-sync** — the commit is the gate: every commit lands with its documentation already true (see
   **Documentation sync** below). This is the judgment gate alongside the mechanical checks.

## Documentation sync

At each commit boundary, refresh documentation while the context is fresh. oxicrypt adopts the
**gem-rule** doc-sync pattern from [`oxiforge/standards`](https://github.com/oxiforge/standards)
(`doc-sync-rules.md`) — do not inline the pattern here; reference it. For any commit that touches a
crate — directly or by reference — do all that apply:

1. **Rustdoc.** Update the `lib.rs` header and affected item docs of every crate changed or referenced
   so the approved-services, SSP, self-test, and gating sections match the code. Run
   `cargo doc --workspace --no-deps` and resolve new warnings in touched crates.
2. **CMVP Security Policy (`cmvp-gem`).** Update `docs/security-policy/security-policy.md` for any change
   to approved services, SSPs, self-tests, state-machine behavior, or side-channel posture. This document
   follows the **NIST-dictated CMVP Security Policy format** — it is unique to oxicrypt and deliberately
   does *not* follow the org `SECURITY.md` template (despite the similar name); do not reshape it to match
   other repos. The pre-commit hook (`scripts/git-hooks/pre-commit`) enforces it by requiring the policy to
   be staged alongside any change under `crates/*/src/`. When a change surfaces no new claim, bypass with
   `git commit --no-verify` and state the rationale in the commit body ("pure refactor, no new invariant").
3. **README.** Update `README.md` when a commit changes user-facing status — algorithm coverage, build
   instructions, workspace layout, project phase.
4. **LAMA manifests (`lama-gem`).** Update root `lama.yaml` (concise discovery summary) and
   `docs/llm-api-manifest/llm-api.yaml` (full) for any add/remove/rename/signature-change of a public
   item. The pre-commit hook enforces `llm-api.yaml` on any `pub fn|struct|enum|const|type|trait`
   change under `crates/*/src/`. Conform both to the LAMA spec; the root file stays a concise
   capabilities + manifest pointer — never a milestone/coverage/status board. **No human names in LAMA.**
5. **Release history (`changelog-gem`).** On any commit that ships a release (the version bump + signed
   `vX.Y.Z` tag), add a new dated, Keep-a-Changelog entry to `CHANGELOG.md` in the same commit. This is
   the *one* home for human-readable release history (see Canonical homes); README/lama.yaml carry a
   pointer, never a milestone table. Inter-release commits do not touch it. The org `changelog-gem`
   instance in [`oxiforge/standards/doc-sync-rules.md`](https://github.com/oxiforge/standards) is the
   full framing.

**Insight capture (the gem).** Before staging any commit, ask: did this session surface a mechanistic
insight a NIST/CST reviewer would need to accept a claim — a compiler guarantee that enforces a security
property, a composition pattern that extends coverage transitively, a rationale for why a zeroization or
self-test approach is complete, or an intentional conformance divergence? If yes, write it into
`docs/security-policy/security-policy.md` as prose in the same commit. Insights surface during code work,
not policy work — so this runs at every commit gate. A gem deferred is usually a gem lost.

## Doc-sync reconciliation — the commit IS the gate

There is no separate, deferrable gate. **The commit is the doc-sync gate.** Every commit lands with its
documentation already true — the same discipline for a feature, a refactor, a manifest-only fix, or a
release. The completion gate is per-commit: a commit is not done until every applicable surface above is
updated or explicitly confirmed unaffected, and that reconciliation ships *in the commit*, not as a later
pass. State it in the commit body when substantive (e.g. "doc-sync: security-policy SSP table + ml-kem
API manifest"). If you ever find a doc surface stale at a boundary, a prior commit skipped its gate — fix
it hot in the next commit. See `oxiforge/standards/doc-sync-rules.md` for the full framing.

## License posture

- **Dual-licensed Apache-2.0 OR MIT** (Rust-ecosystem default). Repo root carries `LICENSE-APACHE` and
  `LICENSE-MIT`; per-crate `Cargo.toml` `license` fields select both.
- **Git identity:** `caraka <caraka@oxicrypt.dev>`.
