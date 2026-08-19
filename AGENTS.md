# Project instructions — oxicrypt

Standing rules for any AI assistant working in this repository. Loaded automatically at the start of
every session by any agent that respects `AGENTS.md`. Model-agnostic — phrase everything in terms of
"the assistant" or imperative; do not assume a specific tool or vendor.

## Project context

oxicrypt is a **pure-Rust cryptographic module targeting FIPS 140-3 Level 1**. It implements FIPS-approved
algorithms across a 30-crate workspace (AES, SHA, SHA-3/XOF, HMAC, CMAC, KDF, TLS-KDF, DRBG, ECDH,
ECDSA, EdDSA, RSA, DH, ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS, plus `zeroize`, `sha-accel`, `integrity`,
`ffi`, `module`, `test-vectors`, and the SP 800-90B `entropy` scaffolding). The crate is `no_std`-capable and
disciplined about `unsafe`: **22 of the 28 crates inside the cryptographic boundary are
`#![forbid(unsafe_code)]`.** The six readily auditable in-boundary exceptions, each isolating sanctioned
`unsafe` in a small dedicated crate, are `oxicrypt-zeroize` (volatile zeroization of critical
security parameters), the three CPU-intrinsic acceleration crates `oxicrypt-sha-accel` /
`oxicrypt-aes-accel` / `oxicrypt-keccak-accel` (feature-gated, default-off, runtime-detected,
equivalence proven by KAT + cross-path oracle), `oxicrypt-timer` (read-only CPU timer/counter
intrinsics for the entropy source), and `oxicrypt-imageread` (kernel-mediated reads of the module's
own loaded image on Darwin and Windows, which expose no file-shaped route to it). Separately,
`oxicrypt-ffi` sits **outside** the boundary to offer a C ABI, where `unsafe extern "C"` is an
unavoidable requirement of exposing the module to C callers. (See the Security Policy — withheld from this
repository, see `docs/security-policy/README.md` — for the authoritative unsafe-code accounting;
`tools/doc-guard` asserts it against the workspace on every test run.) It
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
- **Security policy (withheld — private repo):** `docs/security-policy/README.md` explains where it
  lives and how to request access; resolved at `$OXICRYPT_SECURITY_POLICY`
- **LAMA manifests (in-repo):** root `lama.yaml` (discovery summary) + `docs/llm-api-manifest/llm-api.yaml` (full)
- **ACVP harness (in-repo):** `acvp-harness/`

Reference code by LAMA module notation (`oxicrypt_<crate>::path::Item`), not file paths — it survives
file moves and teaches the manifest.

## Session bootstrap

At the start of every session — or after a context reset — read these in order before doing anything else:

1. **`ISA.md`** (this repo) — the Ideal State Artifact: the authoritative design contract and system of
   record. Read its Problem / Vision / Principles / Constraints / Out of Scope before changing any
   boundary. Each ISC is a verifiable end-state; IDs are permanent (never renumbered).
2. **The CMVP Security Policy** — approved services, SSPs, self-tests, state machine, side-channel
   posture. The security-design home. Withheld from this repository; see
   `docs/security-policy/README.md`.
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
| **CMVP security claims** — approved services, SSPs, self-tests, state machine, side-channel posture | **the Security Policy** (withheld — `docs/security-policy/README.md`) | rustdoc/README carry a pointer |
| **Public API surface** (per crate) | **`docs/llm-api-manifest/llm-api.yaml`** | the full LAMA manifest |
| **API-discovery summary** | **root `lama.yaml`** — concise capabilities + manifest pointer, conformant to the LAMA spec; no milestone/coverage/status | pointer only |
| **Compliance target** (FIPS 140-3 IG revision) | **`ISA.md`** + `docs/security-policy/` | never restated as an inline constant |
| **Release history** — what shipped, when, under which tag | **git tags + `CHANGELOG.md`** | README/lama.yaml carry a pointer, never a milestone table |
| **Release version** | **git tags** | `lama.yaml` / `README.md` stamped at release from the tag |
| **Internal dependency version requirement** | **root `Cargo.toml` `[workspace.dependencies]`** — one `{ path, version }` entry per internal crate | members declare `{ workspace = true }`. One member (`esv-harness`) cannot inherit and states its own version; see below |
| **Pending work** — concrete, scoped deliverables | **GitHub Issues** (`tier:` labels) | closed via `Closes #N`; `ROADMAP.md` holds not-yet-deliverable work |
| **Forward-looking, not-yet-a-deliverable work** | **`ROADMAP.md`** (Ideas / Designs / Features) | becomes GitHub issue(s) when scoped, then removed |
| **Design-of-record** — design-first epics | **`docs/design/*.md`** | `ROADMAP.md` Designs carries a one-line pointer |

### Internal dependencies and packaging

A path-only dependency cannot be packaged: `cargo package` strips the path and records a registry
requirement, which needs a version. Internal crates therefore carry both, declared once in
`[workspace.dependencies]`.

- **Normal and build dependencies** on an internal crate: `name = { workspace = true }`, plus
  `optional = true` where it applies.
- **Dev-dependencies** on an internal crate: leave them `{ path = "..." }` with **no version**. Cargo
  drops a path-only dev-dependency when packaging; adding a version makes it a real registry
  requirement that cannot be satisfied on a first publish, and `oxicrypt-sha` ↔ `oxicrypt-keccak-accel`
  is a cycle.
- A member that needs `default-features = false` keeps its own declaration with an explicit `version`
  — an inherited dependency cannot turn default features back off. One such case exists
  (`esv-harness` → `oxicrypt-entropy`).
- `playground/` is outside the workspace, so `workspace = true` does not resolve there.

`scripts/check-internal-deps.sh` asserts the two bullets above, and a third case: a path dependency
pointing outside the workspace must carry a version, since nothing can supply one for it. The
pre-push hook runs it above the tag-only short-circuit and the stamp cache, against **the revisions
being pushed** rather than the checked-out tree — `git push origin other:main` sends a tree that is
not `HEAD`. It reads `cargo metadata` rather than the manifest text, so every TOML spelling —
sub-tables, multi-line inline tables, unspaced values, renames — arrives normalised, and a newly
added crate is covered the moment it joins the workspace.

What it does **not** cover: whether a crate can actually be *built* from its packaged copy. That
needs `cargo package` without `--no-verify`, which cannot run until the dependencies exist on
crates.io.

### Embedded files must live inside the package root

`cargo publish` uploads a tarball of the package directory, and that tarball is the whole world for
a crates.io consumer — the registry never fetches from GitHub, and `repository` in the manifest is a
link for humans, not a build input. So an `include_str!`/`include_bytes!` path that reaches outside
the package root compiles here and fails for everyone downstream. A published version is immutable,
so that cannot be corrected in place; only a new version fixes it.

The canonical LAMA manifest stays at `docs/llm-api-manifest/llm-api.yaml`. The four crates that
embed it — `oxicrypt-ffi`, `oxi`, `acvp-harness`, `esv-harness`, each exposing a runtime `--lama`
surface — reach it through a **symlink in their own package root** and embed
`include_str!("../llm-api.yaml")`. `cargo package` materialises the symlink's *content* into the
tarball, so there is one copy in git and a real file for every consumer. The other 31 crates need no
copy: their discovery is the `[package.metadata.lama]` URL, which is metadata rather than code.

`doc-guard` asserts both halves — no embed escapes its package root (workspace-wide, not scoped to
the crates.io roster, since a roster-conditional rule changes meaning when a `publish` flag moves),
and each embedded manifest is byte-identical to the canonical file. The second one matters because
git on Windows without `core.symlinks` checks a symlink out as a text file containing the target
path, which would otherwise be embedded and published as the manifest with no error anywhere.

`jq` is required (`scripts/check-internal-deps.sh` is the only consumer).

`scripts/bump-version.sh` moves these version literals; its stale-literal guard fails the release if
one survives.

## Issue tracking, roadmap & design docs

Three surfaces, one direction of flow — speculative → designed → actionable:

- **GitHub Issues** hold every *concrete, scoped deliverable* (bugs, enhancements, docs). Type label
  (`bug` / `enhancement` / `documentation`) + tier label (`tier:punchlist` hot → `tier:candidate` warm
  → `tier:backlog` cold; **unlabeled tier = needs triage**). A PR closes its issue the ordinary way —
  `Closes #N` / `Fixes #N` in the PR or commit body, auto-closing on merge to `main`.
- **`ROADMAP.md`** (root) holds *forward-looking work that is not yet a deliverable*: `Ideas`
  (speculative), `Designs` (design-first epics — one-line pointers to `docs/design/`), `Features`
  (wanted-but-deferred). Forward-only, no status/history. When an item is decomposed into actionable
  work it **becomes GitHub issue(s) and is removed** from `ROADMAP.md`.
- **`docs/design/*.md`** hold the *design-of-record* for design-first epics (RFC-lite: problem →
  constraints / ISC invariants → approach → open questions). An accepted design spawns issues; the doc
  **persists** as rationale. (None yet — created when the first design-first epic appears.)

So: an idea enters `ROADMAP.md`; if it needs design, it gets a `docs/design/` doc; once actionable, it
graduates into GitHub issues (the roadmap entry is removed, the design doc stays). Nothing here records
*status* or *history* — that is issues + git tags + `CHANGELOG.md`.

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

### Test iteration — the `quick` nextest profile

`cargo nextest run --profile quick` skips the long-running maxwell entropy tests for a fast inner
loop; the profiles and the exact exclusions live in `.config/nextest.toml`. It is a latency
optimization for iteration, never a correctness shortcut:

- **Use it** while iterating on a crate and re-running tests often — fast signal on the bulk of the
  suite without waiting on the multi-minute entropy oracles.
- **Do not use it** as the basis for any "tests pass" claim, PR evidence, or definition-of-done
  sign-off — and never on a change to the maxwell entropy estimators, parity table, or IID gate,
  because the excluded tests (including the EA parity oracle) are exactly what validate that code, so
  `quick` would hide the regression it should catch.
- The full **default** profile is the gate. The pre-push hook always runs it; never reach for
  `quick` (or `--no-verify`) to get a push past the gate faster. **CI runs the default profile but
  not at full strength** — see the SP 800-90B reference datasets below.

### SP 800-90B reference datasets

`oxicrypt-maxwell`'s parity table, every per-estimator anchor and the assessed-assembly parity read
the **EA v1.1.8 bundle** — the 11 `.bin` files from `usnistgov/SP800-90B_EntropyAssessment`.
Resolution order is `$OXICRYPT_EA_DATA`, then `~/repos/SP800-90B_EntropyAssessment/bin`.

Without them the suite does not fail; it *skips*, and a skip prints to stderr, which is discarded on
a passing test. So an unprovisioned checkout produces a green run that compared nothing.
`parity::tests::ea_dataset_suite_is_provisioned` exists to stop that: it fails in milliseconds
naming exactly what is absent or unreadable. It is deliberately **not** in the `quick` exclusion
list, so the fast inner loop refuses to be green without the data too.

`OXICRYPT_EA_DATA_OPTIONAL=1` downgrades the completeness check to a warning. Setting it forfeits
the parity evidence claim entirely — a run under that flag must never be cited as tests-pass
evidence. CI sets it, because the runner has no bundle; whether to provision one there is tracked
in the issue tracker.

### The Security Policy is not in this repository

The FIPS 140-3 Security Policy is withheld from the public tree and held in a private repository;
`docs/security-policy/README.md` explains why and how to request access. Its protection is
non-publication rather than a license, and the bounds of that are stated honestly there.

Resolution order is `$OXICRYPT_SECURITY_POLICY` — the file itself, or a directory containing
`security-policy.md` — then `~/repos/oxicrypt-policy/security-policy.md`.

This is the same *shape* as the EA datasets above, with one deliberate difference. The five
`tools/doc-guard` tests that assert the policy's numerals against the workspace *skip* when it is
unreachable, so an ordinary clone runs green with no configuration — and a skip prints to a stream
a passing test discards, so the skip alone is not the safety net.
`doc_guard::tests::security_policy_is_provisioned` is; but unlike the EA gate it fires on **claimed**
provisioning, not on absence. The EA datasets are public and fetchable, so failing on absence there
is right. This document cannot be obtained by an outside contributor at all, and failing on its
absence would put back — as a single failure — the hard failures that removing it from the tree
exists to prevent.

A checkout claims the policy in exactly two ways: `$OXICRYPT_SECURITY_POLICY` is set, or the sibling
clone directory is on disk. Either one with the document unreadable **fails**, because that is a
maintainer's own checkout going quiet. Neither one passes with a note.
`OXICRYPT_SECURITY_POLICY_OPTIONAL=1` withdraws the claim explicitly. The residual is stated rather
than hidden: deleting the clone directory outright silences the gate on the maintainer's machine.

Two further guards have no EA analogue. `the_security_policy_is_not_in_the_public_tree` is the
inverse check — it fails if the document reappears here under any name, because publication is the
one direction that cannot be undone. Because `nextest` is opt-in in `pre-push` as of 2026-08-10, that
check does not run locally on an ordinary push at all, so the same containment scan is duplicated in
`scripts/git-hooks/pre-push`, ahead of the tag short-circuit and the stamp cache, on the reasoning
the deny-list scan already uses: a leak check a cache can skip is not a leak check. CI runs
`doc-guard` on every pull request, but it runs *after* the push, and publication is the one
direction that cannot be undone. Neither says anything about git history.
`policy_resolution_precedence_holds` pins the resolution order itself, since a resolver that
resolved nothing would be indistinguishable from a clean skip.

## Documentation sync

At each commit boundary, refresh documentation while the context is fresh. oxicrypt adopts the
**gem-rule** doc-sync pattern from [`oxiforge/standards`](https://github.com/oxiforge/standards)
(`doc-sync-rules.md`) — do not inline the pattern here; reference it. For any commit that touches a
crate — directly or by reference — do all that apply:

1. **Rustdoc.** Update the `lib.rs` header and affected item docs of every crate changed or referenced
   so the approved-services, SSP, self-test, and gating sections match the code. Run
   `cargo doc --workspace --no-deps` and resolve new warnings in touched crates.
2. **CMVP Security Policy (`cmvp-gem`).** Update the Security Policy — withheld from this repository,
   see `docs/security-policy/README.md` — for any change
   to approved services, SSPs, self-tests, state-machine behavior, or side-channel posture. This document
   follows the **NIST-dictated CMVP Security Policy format** — it is unique to oxicrypt and deliberately
   does *not* follow the org `SECURITY.md` template (despite the similar name); do not reshape it to match
   other repos. The pre-commit hook (`scripts/git-hooks/pre-commit`) enforces it by requiring the policy to
   have been modified since the last commit, alongside any change under `crates/*/src/`. Git cannot stage a
   file it does not track, so the signal is mtime rather than staged-ness; when the policy is not
   provisioned at all — the normal case for an outside contributor — the check is skipped and says so. When a
   change surfaces no new claim, bypass with `git commit --no-verify` and write nothing about it in the commit
   body; no note is expected here, unlike the manifest check in step 4. Rationale for the asymmetry:
   the `Bypass` block in `scripts/git-hooks/pre-commit`.
3. **README.** Update `README.md` when a commit changes user-facing status — algorithm coverage, build
   instructions, workspace layout, project phase.
4. **LAMA manifests (`lama-gem`).** Update root `lama.yaml` (concise discovery summary) and
   `docs/llm-api-manifest/llm-api.yaml` (full) for any add/remove/rename/signature-change of a public
   item. The pre-commit hook enforces `llm-api.yaml` on any `pub fn|struct|enum|const|type|trait`
   change under `crates/*/src/`. Bypassing that check with `git commit --no-verify` **does** require a
   line in the commit body ("internal change, no manifest delta") — unlike the policy check in step 2.
   Conform both to the LAMA spec; the root file stays a concise
   capabilities + manifest pointer — never a milestone/coverage/status board. **No human names in LAMA.**

   **Coverage rule — what the manifest describes, and what it deliberately does not.** Stated here
   because without it nothing distinguishes a deliberate exclusion from an oversight.

   - **Every workspace crate gets a `modules:` entry; only crates on the crates.io roster get
     members.** No exceptions list, deliberately: an absent crate is then always a defect rather
     than possibly an intention, which is what makes the rule checkable. #174 is why — a publishable
     crate with 14 public items was simply missing, and nothing distinguished that from a deliberate
     omission. A crate carrying its own `publish = false` states in its `description:` that it is
     out-of-boundary tooling and carries no members.
   - Every publishable crate's public API surface appears in `llm-api.yaml`, with two standing
     exclusions: gateless `*_internal` variants, which exist for the harness rather than for callers,
     and `*_self_test` functions with their `KATS` constants, which are power-up machinery no caller
     invokes directly.
   - Two crates on the roster carry no members, each for a stated reason in its `description:`.
     `oxicrypt-test-vectors` is test-support data rather than API. `oxi` is a binary with no public
     Rust items at all, so there is nothing a `functions:` entry could describe — its interface is a
     CLI, which this schema has no slot for, and inventing `functions:` entries for CLI verbs would
     hand an agent a `signature:` for a call site that does not exist.
   - The never-published protocol clients keep their own draft manifests beside them —
     `acvp-harness/llm-api-draft.yaml` and `esv-harness/llm-api-draft.yaml`. They describe real
     library surfaces and would need manifests of their own if either is ever split out, so the work
     is kept rather than deleted; it simply does not belong in a manifest describing the module a
     consumer links against.
   - Serialization follows the spec: block style for every multi-element collection, flow style only
     for single-element arrays; `types[].kind` uses only `struct` / `enum` / `alias` / `trait` /
     `opaque`; `error_variants` nests under `returns:`; `constants:` holds constants alone —
     an entry with a `signature:` is a function and belongs in `functions:`.

   **Conformance is checked mechanically, at every push.** `scripts/check-lama-manifests.sh` runs
   the LAMA conformance linter over every manifest in the tree and fails on any finding; the
   pre-push hook calls it against the revisions being pushed. Run it by hand any time:

   ```bash
   ./scripts/check-lama-manifests.sh          # working tree
   ./scripts/check-lama-manifests.sh <rev>    # a specific revision
   ```

   Three things worth knowing about it.

   It runs the linter in **strict** mode, so a warning fails the push. Four of the six LAMA rules
   are advisory upstream and never move an exit code, and those four are the narrative-creep rules
   — a gate on the default contract would enforce two rules while appearing to enforce six. These
   manifests are at zero findings and are held there.

   The linter itself is **vendored, not maintained here**: `scripts/lama-validate.ts` is a
   byte-identical copy of the upstream file recorded in `scripts/lama-validate.provenance`, and its
   checksum is verified on every run. Fixes and new rules go upstream first, then get re-vendored
   by copying the file and updating all three provenance fields. A local edit to the vendored copy
   fails the check by design — a linter quietly weakened in-tree reports no findings, which is
   indistinguishable from conformance.

   It checks **prose conformance, not coverage**. A manifest can pass here with every rule clear
   and still omit an entire crate; that is what the coverage rule above is for, and it is not
   mechanised. A green run must never be read as "the manifest is complete."
5. **Release history (`changelog-gem`).** `CHANGELOG.md` follows Keep-a-Changelog with a standing
   `## [Unreleased]` section. Every PR that changes user-facing behavior adds its line under
   `[Unreleased]` **in that same PR**, citing its issue/PR number (`… (#N)`) and closing the issue via
   `Closes #N` / `Fixes #N`. At release, `[Unreleased]` is renamed to the dated `vX.Y.Z` heading (with
   its `compare/` link) and a fresh empty `[Unreleased]` is opened — the version bump + signed tag ship
   in that same commit. `CHANGELOG.md` is the *one* home for human-readable release history (see
   Canonical homes); README/lama.yaml carry a pointer, never a milestone table. The org `changelog-gem`
   instance in [`oxiforge/standards/doc-sync-rules.md`](https://github.com/oxiforge/standards) is the
   full framing.

6. **Code comments (`comment-gem`).** The comments wrapping the changed code are themselves a doc-sync
   artefact — the only instance whose doc is co-located with its trigger, so it cannot be satisfied by
   editing something else. A comment states what **is**: the contract, the invariant, the reason the
   code is this way, never what it used to be or what changed. Why it *changed* goes in the commit
   body. And a comment asserting a property — constant-time, zeroized, bounded, checked, validated —
   is backed by a probe that fails when the property breaks, confirmed in that commit; where no probe
   exists, the comment says the property is unproven or it is cut. Reading the code and agreeing with
   it is not a probe. `# Safety` preconditions are exempt from removal: they state what a *caller*
   must guarantee, which is an obligation rather than a claim about this code. The org `comment-gem`
   instance in [`oxiforge/standards/doc-sync-rules.md`](https://github.com/oxiforge/standards) is the
   full framing.

**Insight capture (the gem).** Before staging any commit, ask: did this session surface a mechanistic
insight a NIST/CST reviewer would need to accept a claim — a compiler guarantee that enforces a security
property, a composition pattern that extends coverage transitively, a rationale for why a zeroization or
self-test approach is complete, or an intentional conformance divergence? If yes, write it into
the Security Policy as prose in the same commit — it lives in the private policy repository, so that is
a commit there rather than here. Insights surface during code work,
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
  `LICENSE-MIT`; every crate selects both via `license.workspace = true`. The out-of-boundary
  `oxicrypt-maxwell` tool carries `publish = false` (kept off crates.io as internal tooling) but is
  licensed the same Apache-2.0 OR MIT as the rest of the workspace.
- **Git identity:** `caraka <caraka@oxicrypt.dev>`.
