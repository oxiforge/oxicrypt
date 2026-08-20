---
task: oxicrypt FIPS 140-3 cryptographic-module ideal-state contract and system of record
project: oxicrypt
slug: oxicrypt-module-contract
phase: execute
progress: 112/179
mode: algorithm
started: 2026-06-06T00:00:00Z
updated: 2026-08-20T11:40:00-04:00
---

# oxicrypt — ISA (Ideal State Artifact)

> **The design contract and system of record** for the oxicrypt cryptographic module: the articulated
> ideal state, the contributor contract, and the done-condition for CAVP/CMVP validation. Read it to
> understand *where the boundaries are and why they hold* before changing anything. Security-design
> detail lives in the FIPS 140-3 Security Policy, its canonical home — withheld from this repository,
> see `docs/security-policy/README.md`; this file is the
> boundary contract and the criteria that falsify it.
>
> **Criteria record what is built and what is claimed — not the route taken to get there.** Each
> carries the probe that would falsify it, tagged by the verifier that decides it — `bash` (a tool
> says no), `manual` (caraka says no, on encounter), or `none` where no verifier has been assigned.
> A criterion whose probe cannot yet be run says so, and the missing probe is tracked as an issue
> rather than left implied.

## Problem

Post-quantum cryptography is now mandated (CNSA 2.0), but a pure-Rust, FIPS 140-3-validatable module
that covers both the classical FIPS-approved algorithm set and the PQC suite (ML-KEM, ML-DSA, SLH-DSA,
LMS, XMSS) — with a formal module boundary, power-up self-tests, and an ACVP harness — does not exist in
a form ready for CAVP/CMVP submission. oxicrypt is that module: pure Rust, `no_std`-capable,
`forbid(unsafe_code)`, built to pass an accredited CST lab.

FIPS 140-3 additionally requires a *validated entropy source*, and no maintained pure-Rust SP 800-90B
source, ESV client, or 90B estimator suite existed when this work began. Without one the module's
pure-Rust story carries a single outsourced hole, so the entropy source, its health tests, and the
estimator suite that assesses it are in scope as first-class deliverables rather than dependencies.

## Vision

A reviewer — NIST/CST auditor, downstream integrator, or LLM agent — opens oxicrypt and finds a module
whose every approved service, self-test, zeroization invariant, and conformance claim is stated once,
verifiable, and backed by ACVP vectors or a power-up self-test. The euphoric surprise is that FIPS
conformance is *demonstrable from the source*, not asserted in a PDF: the security policy, the manifests,
and the code agree because the commit gate forces them to.

The same holds one layer down: noise source → health tests → conditioner → DRBG → primitives reads as
one coherent, borrow-checker-argued chain, with raw-data mode and health-test placement designed in
rather than retrofitted.

## Out of Scope

- **FIPS levels above 1** — Level 1 is the target; physical-security and higher operational-environment
  requirements are not in scope.
- **Non-approved / experimental algorithms** in the cryptographic boundary — approved algorithm set only.
- **TLS / protocol layers** — those live in sibling crates (`oxitls`), built *on* oxicrypt, not in it.
- **A production ESV certificate** — the entropy assessment target is the NIST demo server; an
  accredited ESV lab engagement is a later, separately-funded step.
- **Any direct port of the jitterentropy C library** — the jitter source is design-derived from the
  published SP 800-90B writeup, with BSD-3 code never transliterated. This is a licensing and
  engineering boundary, not a stylistic one.
- **Hardware TRNG noise sources** — the noise-source abstraction must *admit* them; implementing them
  is deferred.
- **Windows / Android / iOS operational environments** — collection rigs are Linux bare-metal for the
  present assessment.

## Language

The project's ubiquitous language. A term earns an entry here only after it has actually caused a
confusion — a wrong name shipped, or two things called one thing. This is not a dictionary of the
domain; SP 800-90B and the FIPS IG define their own terms and are not restated here.

**validated / certified / approved / vetted** — four FIPS terms of art that are not
interchangeable, and the confusion has shipped twice: `c1d332e` had to stop the docs claiming the
module is validated, `87d3ca7` had to stop calling the portable paths validated. `ISC-42` is the
falsifier; these are the definitions it polices.
- *approved*: a property of an **algorithm** — it appears on the FIPS-approved list. An approved
  algorithm says nothing about this module's implementation of it.
- *vetted*: a property of a **conditioning component** under SP 800-90B — it is on the vetted list.
  oxicrypt's conditioner is vetted SHA-256; that is a statement about SHA-256.
- *validated*: a property of a **specific implementation** that has completed CAVP or CMVP and holds a
  certificate number. No crate or code path here has completed either, so none may be described that
  way.
- *certified*: loose usage for *validated*; CMVP issues validation certificates. The same holds — no
  certificate exists to point at.
- `Avoid:` any of these as a predicate of oxicrypt, its crates, or its code paths. What may be said is
  *targeting* CAVP/CMVP, *built to* the FIPS 140-3 Level 1 structure, or *graded on the demo server* —
  the three stages and their true status are stated once, in `README.md`.

**boundary** — ambiguous in this repository, and both senses are load-bearing.
- *cryptographic module boundary*: what is inside FIPS scope. The sense in `ISC-139`, `ISC-142` and
  everywhere the Security Policy is concerned.
- *collection boundary*: the timing condition a raw dataset is captured under — `Lower` (tight
  measurement loop, worst-case per-sample entropy) or `Upper` (normal operation, the operating point).
  The sense in `ISC-116` and the `Boundary` enum.
- `Avoid:` bare "boundary" where the sense is not obvious from its neighbours. Say *module boundary* or
  *collection boundary*.

**operational environment (OE)** — one platform the entropy source is assessed on, e.g. x86_64 with a
raw counter. Each OE needs its own captured datasets. The **pilot** OE is the one done first, on
hardware already to hand, before committing spend to any other.
- `Avoid:` writing "the pilot operational environment pilot" or substituting the expansion into a
  sentence built for the abbreviation. Two such sentences shipped and had to be repaired.

**gem** — a fact about the module recovered from the built system rather than from intent, in the
doc-sync sense inherited from `oxiforge/standards`. An *as-built gem* is what the code does;
*design-intent* text is what it was meant to do. The Security Policy carries the first and not the
second (`ISC-65`, `ISC-92`).
- `Avoid:` "gem" without the as-built/design-intent qualifier — the distinction is the whole point of
  the term, and the bare word is undefined in this repository.

**Phase 0** — the design wave that produced the entropy source as an in-boundary subsystem, complete
and closed. It is not the current wave; the operational seeding wiring lands in the module-integration
wave that follows it.
- `Avoid:` the spelling "Phase-0", and using the name where a reader cannot tell whether it is past or
  present. `ISC-20` and `ISC-92` both refer to it as closed.

## Principles

- **`forbid(unsafe_code)` is the in-boundary default**, not a style choice — 22 of 27 in-boundary crates
  carry it. It is a build-time control that enters the conformance argument. Three sanctioned
  `unsafe` categories exist, isolated in five small, readily auditable crates: (1) **volatile CSP
  zeroization** — `oxicrypt-zeroize`, one isolated `unsafe` mechanism for `write_volatile`;
  (2) **CPU-intrinsic acceleration** — `oxicrypt-sha-accel` (x86_64 SHA-NI), `oxicrypt-aes-accel`
  (x86_64 AES-NI + PCLMULQDQ GHASH), and `oxicrypt-keccak-accel` (x86_64 AVX2 4-way batched
  Keccak-f[1600]): feature-gated, default-off, runtime-detected, equivalence to the portable path
  proven by KAT + cross-path oracle; and (3) **CPU timer/counter intrinsics** — `oxicrypt-timer`:
  read-only, side-effect-free counter reads, no cryptographic logic. The default build graph contains
  no acceleration crate; the portable baseline is the shipping default. The C-ABI crate
  (`oxicrypt-ffi`) sits outside the boundary and necessarily carries unsafe.
- **One home per security claim** — the CMVP claims live in the Security Policy (withheld from this
  repository — `docs/security-policy/README.md`); code and rustdoc point at it, never restate it.
- **Conformance is falsifiable** — every approved service has a known-answer / ACVP vector that fails if
  the implementation drifts.
- **Precedent-first for the unprecedented** — a pure-Rust validated SP 800-90B module has no prior art,
  so wherever a choice exists the implementation conforms to established precedent: NIST EA tool CLI and
  output shapes, ESV metadata and wire discipline, the published collection protocol, cert-lineage
  parameters. Novelty is spent only where the pure-Rust in-boundary thesis genuinely requires it. The
  point is to minimise assessor and reviewer surprise.
- **Everything SP 800-90B-load-bearing is designed in, never retrofitted** — raw-data mode and
  health-test placement cannot be added after the fact without invalidating the evidence.
- **The noise-source abstraction admits sources not yet built** (RDSEED, hardware TRNG,
  architecture-specific) without reshaping the crate.
- **Equivalence and disjointness arguments are compiler-checked where possible** — structural proof
  first, test corroboration second.
- **One design, two audiences** — FIPS consumers via the module boundary, the wider ecosystem via a
  default-off `rand-core` compatibility feature.

## Constraints

- **FIPS 140-3 Level 1**, Implementation Guidance — cover *Last Update* **2026-08-19** (fetched
  2026-08-20). The IG is a single rolling document, not a versioned series: its cover date moves on
  any amendment, and each section carries its own *Last Modified Date*. The sections this module
  reconciles against are **D.G Key Transport Methods (2026-08-19)**, **D.J Entropy Estimation and
  Compliance with SP 800-90B (2021-11-05)** and **D.K Interpretation of SP 800-90B Requirements
  (2026-04-16)**. Reconcile on IG updates, per section rather than per cover date.
- **`no_std`-capable**, `forbid(unsafe_code)` at every crate root, deny-level workspace lints.
- **`oxicrypt-entropy` is inside the CMVP module boundary** — full workspace discipline applies to it:
  forbid-unsafe accounting, security-policy claims, doc-sync, `no_std`-capable core.
- **Pure Rust, no C dependencies, no FFI** to any external entropy library.
- **Raw-data collection on bare metal only** — VM-collected jitter is methodologically contested and
  would taint the assessment evidence.
- **SP 800-90-series facts come only from dated, fetched documents, never from recall.** Post-cutoff
  drift is demonstrated: IG D.K amendments dated 2026-04-09 and 2026-04-16 reversed prior guidance.
  Every normative 90B/90C/IG/vetted-list fact in code, docs, or claims cites a document fetched for
  that purpose, and a dated freshness sweep opens any phase that consumes them.
- **License:** Apache-2.0 OR MIT.
- **Public repository** — no host paths, no private-project names, no internal or planning context.

## Goal

Be a pure-Rust FIPS 140-3 Level 1 cryptographic module — classical + PQC approved algorithms, formal
module boundary, power-up self-tests, ACVP harness, and an in-boundary SP 800-90B entropy source with
its health tests and estimator suite — that passes CAVP algorithm validation and CMVP module validation
through an accredited CST lab, with security policy, manifests, and code kept in lockstep by the
commit-is-the-gate doc-sync discipline.

## Claims

> Every criterion carries the probe that would falsify it, tagged by the verifier that decides it — see `## Test Strategy` for the classes and their failure semantics. A probe reading `TODO` does not yet exist and is tagged `none`; its criterion is left unchecked and the gap is recorded, not implied. A criterion whose probe reaches only part of what it claims keeps that remainder stated on its own line and tracks it as `ISC-N.1`, which is unchecked until caraka rules on it.

- [x] ISC-1: Noise-source trait abstraction exists; jitter source #1 implements it; a second source can be added without touching consumers. Probe(bash): `cargo test -p oxicrypt-entropy --lib live_jitter_flows_through_full_pipeline`; jitter.rs:790; 4 mock impls drive the same generic pipeline
- [ ] ISC-2: Raw-data mode emits unconditioned samples via a distinct `RawCollector` (no conditioner) in the ESV wire format — exactly 1M samples, one byte each [DEFERRED — see Decisions]. Probe(bash): `cargo test -p esv-harness --lib wrong_sample_count_is_caught`; preflight.rs:948 expected 1_000_000, one byte per sample
- [x] ISC-3: RCT implemented per 90B §4.4.1, cutoff parameterized by claimed H. Probe(bash): `cargo test -p oxicrypt-entropy --lib rct_cutoff_spec_worked_example`; health.rs:372 cutoff==11, §4.4.1 worked example
- [x] ISC-4: APT implemented per 90B §4.4.2, window/cutoff parameterized. Probe(bash): `cargo test -p oxicrypt-entropy --lib apt_cutoff_table2_rows`; health.rs:413/415, Table 2 rows
- [x] ISC-5: Health tests sit in the sample path — no raw sample reaches the conditioner untested. Probe(bash): `cargo test -p oxicrypt-entropy --lib health_failure_mid_block_poisons_and_emits_nothing`; pipeline.rs:607
- [x] ISC-6: Startup + on-demand restart tests per 90B §3.1.4. Probe(bash): `cargo test -p oxicrypt-entropy --lib no_output_before_startup on_demand_before_startup_is_refused`; pipeline.rs:428/526; judgment: collect_restart's per-round run_startup (collection.rs:565) is unasserted; remainder tracked as ISC-6.1
- [ ] ISC-6.1: A collection test asserts `collect_restart` invokes `run_startup` once per restart round. Probe(bash): `awk '/mod tests/ {f=1} f' crates/oxicrypt-entropy/src/collection.rs | grep -cE 'assert.*run_startup|startup_calls'` returns 0; control: the same awk range with `grep -cE 'built\.get\(\)'` is non-zero — build-count assertions exist, the startup-count analogue does not
- [x] ISC-7: Conditioning component implemented and documented as an ESV claim (vetted vs non-vetted choice logged as a Decision). Probe(bash): `cargo test -p esv-harness --lib vetted_sha2_256_sets_exact_name_and_carries_validation_number`; security-policy.md:2813; judgment: no Decision weighs the non-vetted alternative; remainder tracked as ISC-7.1
- [ ] ISC-7.1: `## Decisions` carries a dated decision weighing the non-vetted conditioning alternative against the vetted choice. Probe(bash): `awk '/^## Decisions/{f=1;next} /^## /{f=0} f' ISA.md | grep -ciE 'non-vetted'` returns 0; control: the same awk range with `grep -ci vetted` is non-zero — the vetted decision is present, nothing weighs the alternative
- [x] ISC-8: `rand-core` compat behind default-off feature; default build graph free of it. Probe(bash): `cargo tree -p oxicrypt-entropy -e normal --no-default-features | grep -c rand_core`; 0; control: --features rand-core gives >=1
- [ ] ISC-9: Estimator suite matches NIST EA tool v1.1.8 output within tolerance on its 11 bundled datasets + pilot data. Probe(bash): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; 11 bundled datasets only; pilot-data half TODO
- [x] ISC-9.1: Literal-track §6.3 suite — each non-IID estimator (collision, Markov, compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC, LZ78Y) computes theliteral-symbol-track estimate matching EA's per-estimator "Literal" value ≤1e-6 on the multi-bit reference datasets. Probe(bash): `cargo test -p oxicrypt-maxwell --lib literal_parity_multibit`; per-estimator literal track, PARITY_EPS=1e-6
- [x] ISC-9.2: Assessed-min-entropy headline — `min(H_original, H_bitstring × word_size)` matches EA's final "Assessed min entropy" line, and maxwell reports BOTH it and the per-bit controlling value (Option C); wires the assessed number into `IidGateResult` + CLI. Probe(bash): `cargo test -p oxicrypt-maxwell --lib assessed_assembly_matches_ea_on_multi_bit_datasets`; iid_gate.rs:354
- [x] ISC-10: Estimator suite recovers analytic min-entropy on synthetic sources (known-bias Bernoulli, near-uniform). Probe(bash): `cargo test -p oxicrypt-maxwell --test analytic_recovery`; analytic_recovery.rs:59
- [ ] ISC-11: Anti: no C/FFI dependency anywhere in the crate's tree. Probe(bash): `grep -rn 'extern "C"' crates/oxicrypt-entropy/src/ + no build.rs/*.c`; control: oxicrypt-ffi/src/aes.rs:68 matches
- [ ] ISC-12: Anti: no entity names, host paths, or internal context in any repo-destined artifact. Probe(bash): `git grep -nE '/home/[a-z]+|/Users/[a-z]+|C:\\Users' -- . ':!vendor' | grep -vE '/home/(yourname|example|someone)|/Users/(yourname|example|someone)|check-acvp-evidence\.py' | wc -l` returns 0 — the filter drops documentation placeholders and the leak-detector's own pattern definitions, so only a real username fires; control: a planted `/home/<user>/…` line is reported. The private-name half reads an uncommitted deny-list and so cannot be run from a clean clone
- [x] ISC-13: Timer-source selection per arch is an explicit, documented design decision (raw counter vs OS nanosecond clock vs internal timer thread), with rationale in the ESV noise-source description. Probe(manual): `sed -n '/# Per-architecture defaults/,/# Measured, never assumed/p' crates/oxicrypt-entropy/src/timer.rs` — the whole rationale block, bounded by the next heading rather than a fixed window; per-arch rationale is prose; read it; control: `grep -c 'TimerSource::'` over that same range returns 3 and drops to 0 if the rationale is deleted, which a fixed window would not have caught
- [x] ISC-14: Every raw-data collection emits dataset metadata recording timer source, counter frequency, CPU model, OS, and collection parameters — no anonymous datasets; each sidecar validates against the vendored versioned JSON metadata schema and records the MEASURED counter frequency, never nominal. Probe(bash): `cargo test -p oxicrypt-entropy --lib metadata_validates_against_vendored_schema`; raw.rs:1889; negative control validator_rejects_missing_required_field
- [x] ISC-15: Pipeline construction with claimed-H above the source's design ceiling fails with a typed error. Probe(bash): `cargo test -p oxicrypt-entropy --lib claim_above_ceiling_is_refused`; pipeline.rs:388
- [x] ISC-16: No claimed-H constants in any source impl — H enters only at pipeline construction. Probe(bash): `grep -n MinEntropy crates/oxicrypt-entropy/src/jitter.rs`; only max_claimable_h at :407-409
- [x] ISC-17: Anti: no f32/f64 anywhere in the health-test cutoff path. Probe(bash): `grep -nE '\bf32\b|\bf64\b' crates/oxicrypt-entropy/src/{health,h,sp800_90b,conditioner,pipeline}.rs`; 1 hit, doc prose only; control matches real f64 in maxwell
- [x] ISC-18: TimerSource config enum with per-arch defaults (x86_64 RawCounter, aarch64 OsNanoClock) and documented per-arch rationale. Probe(bash): `cargo test -p oxicrypt-entropy --lib default_for_target_matches_arch`; timer.rs:584; FLAG VACUOUS off x86_64/aarch64 — both asserts cfg-gated, empty body elsewhere
- [x] ISC-19: Startup timer-adequacy self-check measures observed delta granularity + monotonicity and refuses inadequate configs. Probe(bash): `cargo test -p oxicrypt-entropy --lib construction_runs_adequacy_and_refuses_coarse_timers`; timer.rs:641-642
- [x] ISC-20: Anti: InternalTimerThread unselectable in Phase 0 — selecting it returns a typed Unsupported error; no ESV claim references it. Probe(bash): `cargo test -p oxicrypt-entropy --lib internal_timer_thread_is_unselectable`; timer.rs:593 typed Unsupported
- [x] ISC-21: Conditioner dependencies resolve in-workspace only — oxicrypt-sha, no external hash crate. Probe(bash): `grep -nE 'sha2|ring|openssl|digest|blake' crates/oxicrypt-entropy/Cargo.toml`; none; control oxicrypt-sha path dep at :35
- [x] ISC-22: Samples-per-output-block derived from injected claimed-H per the documented §3.1.5 vetted formula — varying H changes the count correctly. Probe(bash): `cargo test -p oxicrypt-entropy --lib samples_per_block_varies_with_claim`; conditioner.rs:181/184/190; NOTE code cites 90C 3.2.2.2 not 90B 3.1.5
- [x] ISC-23: Conditioning KAT runs at startup; corrupted vector causes refusal, not degraded operation. Probe(bash): `cargo test -p oxicrypt-entropy --lib corrupted_vector_causes_refusal`; conditioner.rs:241; judgment: startup-injection half untested; remainder tracked as ISC-23.1
- [ ] ISC-23.1: A test injects a corrupted conditioning KAT vector on the startup path and asserts startup refuses. Probe(bash): `cargo test -p oxicrypt-entropy --lib -- --list | grep -cE 'startup.*corrupt|corrupt.*startup'` returns 0; control: the same list with `grep -c corrupted_vector_causes_refusal` is non-zero — the unit-level refusal test exists, the startup-path injection does not
- [x] ISC-24: Docs section states the vetted-conditioning claim and output-entropy accounting formula. Probe(manual): `sed -n '/^#### 9\.3\.4 Conditioning/,/^#### 9\.3\.5 /p' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` — the whole 9.3.4 subsection, bounded by the next heading; vetted claim + h_in >= n_out + 64 accounting; control: `grep -cE 'vetted|n_out'` over that same range returns 2 and drops if either statement is removed
- [x] ISC-25: α restricted to power-of-two set, default 2⁻³⁰ (jent cert-lineage precedent; refined 2026-06-12 15:19); cutoffs vary correctly with α. Probe(bash): `cargo test -p oxicrypt-entropy --lib alpha_range_enforced`; health.rs:363/359
- [x] ISC-26: Claimed H rounds DOWN to the table grid — claim never overstated. Probe(bash): `cargo test -p oxicrypt-entropy --lib apt_h_rounds_down_to_grid`; health.rs:424
- [x] ISC-27: APT cutoff table generated by out-of-boundary maxwell utility; in-boundary table verified by test against reference values. Probe(bash): `cargo test -p oxicrypt-entropy --lib apt_alpha30_matches_generator`; sp800_90b.rs:390-425 in-boundary table vs generator values
- [x] ISC-28: Anti: no uncited numeric literals in the health module — every spec constant named with clause citation. Probe(bash): `awk scan of pub const in sp800_90b.rs for a preceding section citation`; 1 uncited of 21: APT_ALPHA30_ALPHA_EXP (sp800_90b.rs:219)
- [x] ISC-29: Every health-test failure is permanent — instance enters terminal error state, the failing block is never returned, only re-instantiation clears (refined 2026-06-12 15:19, jent precedent). Probe(bash): `cargo test -p oxicrypt-entropy --lib poisoned_monitor_never_recovers`; health.rs:554 across 50 samples
- [x] ISC-30: Single-definition-site auth — esv-harness consumes acvp-harness transport via lib target; no duplicated mTLS/TOTP/token code. Probe(bash): `grep -rnE 'Command::new|curl|extern .C.' esv-harness/src/`; 0 hits; control acvp-harness/src/transport.rs:33 matches
- [ ] ISC-31: ESV endpoint paths and payload shapes implemented from cited ESV-Server documentation. Probe(bash): `sha256sum esv-harness/vendor/entropy-source-metadata-schema.json`; pinned digest in vendor/README.md:16-17
- [ ] ISC-32: Long upload survives token refresh mid-transfer. Probe(bash): `cargo test -p esv-harness --lib poll_calls_the_token_provider_once_per_request`; datafiles.rs:2004-2006; judgment: no refresh inside a single in-flight transfer; remainder tracked as ISC-32.1
- [ ] ISC-32.1: A test drives a token refresh inside a single in-flight upload transfer. Probe(bash): `cargo test -p esv-harness --lib -- --list | grep -ciE 'refresh.*(mid|during|in_flight|transfer)|(upload|transfer).*refresh'` returns 0; control: the same list with `grep -c refresh` is non-zero — refresh tests exist, all pre-send or on-401
- [ ] ISC-33: ESV noise-source description document covers operational description, entropy justification, and health-test description [DEFERRED — see Decisions]. Probe(bash): `find . -path ./target -prune -o -iname '*noise*source*' -print | wc -l` returns 0 — no ESV noise-source description exists; control: the same find for `*independence*` returns 3, so the search reaches the tree
- [x] ISC-34: oxicrypt-drbg instantiates from pipeline output through the module's entropy-input API. Probe(bash): `cargo test -p oxicrypt-entropy --lib conditioned_output_seeds_module_gated_drbg`; pipeline.rs:672
- [x] ISC-35: All public items carry rustdoc — missing_docs denied. Probe(bash): `grep -nE '^missing_docs = ' Cargo.toml` — the key is present and set to `warn`; denial comes from `RUSTFLAGS="-D warnings"`, exported by both the CI workflow and the pre-push hook (`git grep -c 'RUSTFLAGS' .github/workflows/ci.yml scripts/git-hooks/pre-push` matches each), so every gate that can reject code denies it; the manifest half is ISC-35.1
- [ ] ISC-35.1: `missing_docs` is denied in the manifest itself, so a bare `cargo build` with no RUSTFLAGS also refuses. Probe(bash): `grep -nE '^missing_docs = "deny"' Cargo.toml`; control: `grep -nE '^missing_docs = ' Cargo.toml` matches, so a zero result means the value is wrong, not that the key is absent.
- [x] ISC-36: Doc examples compile and run. Probe(bash): `cargo test --workspace --doc` — exactly one runnable doctest exists (`oxicrypt-zeroize`) and it passes; control: `git grep -cE '^[[:space:]]*(///|//!)[[:space:]]*```' -- crates` counts 118 fences, most `text`/`ignore`, so the scarcity is real rather than a search failure
- [x] ISC-37: Collection runbook — one documented command per dataset type, resumable via a `collection-session.json` content-hash checkpoint that skips completed datasets on re-run. Probe(bash): `cargo test -p oxicrypt-entropy --lib second_run_skips_completed_datasets`; collection.rs:1512-1513
- [x] ISC-38: rand-core feature passes RngCore contract property tests (fill_bytes/next_u32/next_u64 consistency). Probe(bash): `cargo test -p oxicrypt-entropy --lib fill_bytes_various_lengths_fill_exactly`; rand_core_compat.rs:259
- [ ] ISC-39: Evidence-package index document enumerates all artifacts with paths and checksums [DEFERRED — see Decisions]. Probe(bash): `find . -path ./target -prune -o -iname '*evidence*index*' -print | wc -l` returns 0; control: the same find for `*evidence*` returns 6, so evidence artifacts exist and only the index enumerating them is absent
- [x] ISC-40: README states scope and 90B status honestly — no validation claims pre-cert. Probe(bash): `git grep -n 'pre-validation — no entropy claims' README.md`; README.md:107; control lib.rs:10
- [ ] ISC-41: CHANGELOG maintained, releases tagged. Probe(bash): `for v in CHANGELOG versions; do git rev-parse refs/tags/v$v; done`; 20 of 21 tagged; FLAG v0.1.0 has no tag
- [x] ISC-42: Anti: no overstated validation language ("validated", "certified") anywhere in repo docs pre-cert. Probe(bash): `git grep -niE '(entropy source|this module|oxicrypt)[^.]{0,60}(is|are|has been) (FIPS[- ])?(validated|certified)'`; 1 benign hit; judgment: no automated lint enforces it; remainder tracked as ISC-42.1
- [ ] ISC-42.1: An automated lint enforces the overstated-validation-language ban. Probe(bash): `{ cargo test -p doc-guard -- --list; grep -h 'run:' .github/workflows/ci.yml; } | grep -ciE 'overstat|(is|are|has been).{0,10}(validated|certified)'` returns 0; control: `cargo test -p doc-guard -- --list | grep -c policy` is non-zero — `doc-guard` is the obvious home and carries no such check
- [x] ISC-43: Anti: no conditioned output obtainable before startup tests pass. Probe(bash): `cargo test -p oxicrypt-entropy --lib no_conditioned_output_before_startup`; pipeline.rs:561
- [x] ISC-44: Raw-data mode and conditioned-output mode structurally exclusive — `RawCollector` (no conditioner) and the live conditioned pipeline are distinct types constructed separately, not a runtime flag on one instance. Probe(bash): `cargo test -p oxicrypt-entropy --lib raw_collector_is_distinct_type_without_conditioner`; raw.rs:1457-1459 compile-checked
- [x] ISC-45: Sample buffers and conditioner state zeroized on drop via oxicrypt-zeroize. Probe(bash): `grep -n 'impl Drop' -A4 crates/oxicrypt-entropy/src/raw.rs`; raw.rs:484; judgment: nothing observes post-drop memory; remainder tracked as ISC-45.1
- [ ] ISC-45.1: A test observes the sample buffer's memory after drop and asserts it is zeroized. Probe(bash): `cargo test -p oxicrypt-entropy --features collection --lib -- --list | grep -ci drop` returns 0; control: the same list with `grep -c redact` is non-zero — a `Drop` impl exists in `raw.rs`, no test observes it
- [x] ISC-46: Anti: no panic paths in the sample/health/conditioning hot path — no unwrap/expect/unchecked indexing. Probe(bash): `awk scan for unwrap/expect/panic/index outside cfg(test)`; empty; CAVEAT jitter.rs:404 unwrap_or_else(|| unreachable!()) on sample path
- [x] ISC-47: Runtime timer-backwards violation yields typed error and sample discard. Probe(bash): `cargo test -p oxicrypt-entropy --lib wrapping_delta_flags_backwards`; timer.rs:612-615; judgment: no test drives a backwards timer through sample(); remainder tracked as ISC-47.1
- [ ] ISC-47.1: A test drives a backwards-stepping timer through `pipeline::sample()` and asserts a typed error plus sample discard. Probe(bash): `awk '/mod tests/ {f=1} f' crates/oxicrypt-entropy/src/pipeline.rs | grep -ci backwards` returns 0; control: the same awk over `timer.rs` is non-zero — `timer::tests::backwards_timer_is_refused` covers the adequacy stage, not `sample()`
- [x] ISC-48: Counter wraparound handled via wrapping delta arithmetic. Probe(bash): `cargo test -p oxicrypt-entropy --lib wrapping_delta_handles_wraparound_32bit`; timer.rs:606
- [x] ISC-49: Restart tests begin from clean health-test state — no carryover. Probe(bash): `on_demand_replaces_the_continuous_monitor` measures RCT run-count carryover differentially — the identical samples needed to trip after an on-demand battery must equal the number needed from a clean monitor — **and** anchors the baseline absolutely at the SP 800-90B §4.4.1 cutoff for the pipeline's own configuration (H=2, α=2⁻²⁰ ⇒ 1 + ⌈20/2⌉ = 11), which a purely differential assertion could not do: a monitor built with the wrong claim, wrong α, or inverted `is_binary()` moves both sides equally. Discarding `self.monitor = fresh` and substituting a hardcoded claim both fail it by name. Scope stated at the test: the APT half is not separately probed
- [x] ISC-50: Send/Sync posture explicit via compile-time static assertions matching the concurrency design. Probe(bash): `cargo test -p oxicrypt-entropy --lib send_sync_posture`; pipeline.rs:620-621; compile-time bound inside a test
- [x] ISC-51: Collection tool memory bounded on 1M+ sample runs. Probe(bash): `cargo test -p oxicrypt-entropy --lib streaming_write_buffer_is_bounded`; collection.rs:1587; judgment: bound proven at 4x chunk, not 1M; remainder tracked as ISC-51.1
- [ ] ISC-51.1: The streaming-buffer bound is exercised at production scale rather than a small multiple of the chunk size. Probe(bash): `awk '/fn streaming_write_buffer_is_bounded/,/^    }/' crates/oxicrypt-entropy/src/collection.rs | grep -cE '1_000_000|RAW_DATA_SAMPLES'` returns 0; control: the same awk range with `grep -cE 'STREAM_CHUNK_SAMPLES'` is non-zero — the bound is proven at roughly 33k samples
- [ ] ISC-52: Interrupted esv-harness upload leaves resumable session state, no half-marked submissions [DEFERRED — see Decisions]. Probe(bash): `cargo test -p esv-harness --lib persist_intent_then_leaves_a_dangling_intent_when_submit_fails`; session.rs:1435-1438
- [x] ISC-53: Anti: Debug/Display impls never expose raw samples or conditioned output. Probe(bash): `cargo test -p oxicrypt-entropy --lib dataset_debug_never_exposes_sample_bytes`; raw.rs:1861-1864
- [x] ISC-54: maxwell never panics on malformed or arbitrary input files. Probe(bash): `cargo +nightly fuzz run estimators -- -max_total_time=45 -rss_limit_mb=4096`; no in-tree test; fuzz target only
- [x] ISC-55: Dead source (constant symbols) trips RCT within spec-expected sample count. Probe(bash): `cargo test -p oxicrypt-entropy --lib kat_dead_source_trips_rct_at_cutoff`; kat_tests.rs:50 tripped_at==Some(10)
- [x] ISC-56: Low-variety oscillating source trips APT within one window. Probe(bash): `cargo test -p oxicrypt-entropy --lib kat_low_variety_trips_apt_in_first_window`; kat_tests.rs:69 tripped_at==Some(24)
- [x] ISC-57: All 90B spec constants in one cited consts module — spec revision is a one-module change. Probe(bash): `grep -rnE '\b(1024|512|589|941|325|1_000_000|200_000)\b' crates/oxicrypt-entropy/src --include=*.rs | grep -v sp800_90b.rs`; empty; control: same grep ON sp800_90b.rs returns rows
- [x] ISC-58: A mock second NoiseSource exercises the full pipeline generically in tests. Probe(bash): `cargo test -p oxicrypt-entropy --lib conditioned_output_seeds_module_gated_drbg`; pipeline.rs:665-666 via non-jitter PrngMock
- [ ] ISC-59: aarch64 target builds and tests in CI. Probe(bash): `awk '/runner: ubuntu-24.04-arm/{f=1} f&&/cargo (test|nextest)/{print; exit}' .github/workflows/integrity-image-probe.yml | wc -l` returns 0 — an aarch64 runner exists but never runs the suite; control: `git grep -cE 'cargo (test|nextest)' -- .github/workflows/` is non-zero, every hit on an x86_64 runner
- [ ] ISC-60: MSRV declared and enforced in CI. Probe(bash): `grep -n rust-version Cargo.toml; grep -n channel rust-toolchain.toml`; Cargo.toml:47 / rust-toolchain.toml:2 agree; judgment: no MSRV job, nothing asserts they match; remainder tracked as ISC-60.1
- [ ] ISC-60.1: CI runs an MSRV job at the declared `rust-version`. Probe(bash): `grep -ciE 'msrv|rust-version' .github/workflows/ci.yml` returns 0; control: `grep -cE '^  [a-z-]+:$' .github/workflows/ci.yml` counts the jobs that do exist. The consistency half is already covered — `doc-guard::tests::rust_version_statements_match_the_authoritative_files` asserts channel against MSRV and passes
- [x] ISC-61: Datasets archived under the versioned layout `datasets/<oe-id>/<timer>/<boundary>/{raw.bin,restart.bin,metadata.json}` with a top-level sha256 manifest. Probe(bash): `cargo test -p oxicrypt-entropy --lib layout_is_versioned_and_manifest_checksums_verify`; collection.rs:1477/1481 (verified==6 blocks an empty-manifest pass); judgment: no version segment is actually asserted in the path; remainder tracked as ISC-61.1
- [ ] ISC-61.1: The layout test asserts an explicit version segment in the dataset path. Probe(bash): `awk '/fn layout_is_versioned_and_manifest_checksums_verify/,/^    }/' crates/oxicrypt-entropy/src/collection.rs | grep -cE 'LAYOUT_VERSION|join\("v[0-9]'` returns 0; control: the same awk range with `grep -c 'join('` is non-zero — the asserted path is oe/timer/boundary with no version segment
- [x] ISC-62: Comparison-harness output records maxwell version and EA tool version per run. Probe(bash): `cargo test -p oxicrypt-maxwell --test cli_versions` drives the binary and asserts the line against the live `CARGO_PKG_VERSION` and `EA_TOOL_VERSION` rather than literals, so a stamp that stopped tracking either is caught; a companion assertion rejects empty stamps, which `contains` would otherwise satisfy
- [ ] ISC-63: RawCounter path on aarch64 feature-complete, not stubbed, despite OsNanoClock default [DEFERRED — see Decisions]. Probe(bash): `cargo check -p oxicrypt-entropy --features raw-counter --target aarch64-unknown-linux-gnu`; oxicrypt-timer/src/lib.rs:112-136 real asm; no test exercises it
- [x] ISC-64: Semver discipline for 0.x documented in CONTRIBUTING. Probe(bash): `git grep -nE '`0\.x`.*(minor|incompatible|break)' CONTRIBUTING.md` matches the 0.x breaking-change clause; control: `git grep -c semver CONTRIBUTING.md` is non-zero
- [ ] ISC-65: Anti: no design-intent gem text in any repo policy doc — only as-built. Probe(bash): `grep -cE 'TODO|TBD|to be determined|will be (added|implemented|provided)|is planned|not yet implemented|forthcoming|placeholder' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` returns 13 — design-intent text remains; control: `grep -cE 'Document status' "$OXICRYPT_SECURITY_POLICY"` is non-zero. Note `policy_carries_no_new_unresolved_drafting_markers` is a BASELINE guard and passes with these present, so a green doc-guard is not evidence here
- [x] ISC-66: jent-concept mapping table for reviewer familiarity (osr→oversampling etc.). Withheld with the Security Policy from 2026-08-05 — two of its three columns cite the policy's own rule numbering. Probe(bash): `grep -c 'Oversampling ratio' "$(dirname "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}")/jent-concept-mapping.md"` returns 1; content-anchored rather than line-anchored, since the old fixed-range anchor over lines 11-26 broke the moment the file gained a header; judgment: no test guards the file, and the probe needs the policy repo; control: a term absent from the table returns 0; remainder tracked as ISC-66.1
- [ ] ISC-66.1: An in-repo test guards the jent-concept mapping table's content. Probe(bash): `cargo test -p doc-guard -- --list | grep -ciE 'jent|concept_map|mapping'` returns 0; control: `cargo test -p doc-guard -- --list | grep -c policy` is non-zero — `doc-guard` names the file only in `WITHHELD_FILES`
- [x] ISC-67: Health-test KAT vector files shipped — synthetic streams with known RCT/APT outcomes. Probe(bash): `cargo test -p oxicrypt-entropy --lib kat_dead_source_trips_rct_at_cutoff`; kat_tests.rs:50; FLAG kat_healthy_stream_passes_in_full is vacuous on empty input
- [ ] ISC-68: Tests isolation-safe under the workspace nextest gate. Probe(bash): `cargo nextest run --workspace`; pid+tag keyed temp roots; judgment: no test asserts isolation; remainder tracked as ISC-68.1
- [ ] ISC-68.1: A test asserts temp-root isolation — that pid+tag keying prevents cross-test collision. Probe(bash): `cargo test -p oxicrypt-entropy --features collection --lib -- --list | grep -ciE 'isolat|collide|unique_temp|temp_root'` returns 0; control: the same list with `grep -c ': test'` is non-zero. Name-based, so it would miss an assertion buried in an oddly-named test; `temp_dir(tag)` was read by hand and carries none
- [x] ISC-69: unsafe confined to the timer-intrinsics module with safety comments; workspace unsafe-accounting doc updated. Probe(bash): `cargo test -p doc-guard policy_states_the_as_built_accounting`; doc-guard/src/lib.rs:153 recomputed from disk
- [x] ISC-70: maxwell CLI mirrors ea_iid/ea_non_iid invocation shape. Probe(bash): with `D` = `grep -oP '\x60maxwell \K[a-z0-9-]+' crates/oxicrypt-maxwell/docs/ea-cli-mapping.md | LC_ALL=C sort -u` and `A` = `sed -n 's/.*Some("\([a-z0-9-]*\)") => cmd_.*/\1/p' crates/oxicrypt-maxwell/src/main.rs | LC_ALL=C sort -u`, run `printf 'documented=%s undispatched=%s undocumented=%s\n' "$(D|wc -l)" "$(comm -23 <(D) <(A)|wc -l)" "$(comm -13 <(D) <(A)|wc -l)"` → `documented=16 undispatched=0 undocumented=4`; only `undispatched=0` is asserted — `undocumented` counts maxwell's non-EA subcommands (gate, restart and friends) and is reported for drift visibility, not required to be 0; `A` matches the ` => cmd_` dispatch shape so a `Some("x")` elsewhere in the file cannot forge a dispatch arm; not asserted: the EA-side shape is documented in the mapping table, never checked against the EA tool itself; control: the documented count rides in the same output, so a broken extraction reports `documented=0` instead of a false `undispatched=0`
- [x] ISC-71: MCV estimator matches EA v1.1.8 within pre-registered tolerance on bundled datasets. Probe(bash): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MCV leg, parity.rs:722
- [x] ISC-72: Collision estimator parity, same terms. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Collision column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-73: Markov estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Markov column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-74: Compression estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Compression column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-75: t-tuple estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; t-tuple column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-76: LRS estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; LRS column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-77: MultiMCW prediction estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MultiMCW column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-78: Lag prediction estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Lag column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-79: MultiMMC prediction estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MultiMMC column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-80: LZ78Y prediction estimator parity. Probe(bash): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; LZ78Y column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-81: §5.1 permutation battery — 19 statistic slots (EA `permutation_tests.h:11-12`: the 11 §5.1 families, periodicity & covariance each ×5 lags {1,2,8,16,32}). TWO-LAYER parity vs EA v1.1.8: (L1) the 19 ORIGINAL unpermuted statistic values match within the pre-registered ≤1e-6 tolerance (deterministic, like §6.3 — ISC-93); (L2) IID/non-IID verdict per statistic + overall agrees on STABLE (non-boundary) datasets. maxwell uses its own fixed-seed shuffle (ISC-134) so it stays bit-reproducible (ISC-82). Probe(bash): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; 19 slots, parity.rs:1063
- [x] ISC-81.1: §5.2 additional chi-square tests (independence binning + goodness-of-fit) implemented and verdict-parity-checked vs EA on both pass and fail directions. Probe(bash): `cargo test -p oxicrypt-maxwell --lib rand4_short_anchor`; chi_square.rs:1167
- [x] ISC-81.2: §5.3 LRS (longest-repeated-substring) IID test implemented, reusing the §6.3.6 SA-IS suffix array (ISC-76), verdict-parity-checked vs EA. Probe(bash): `cargo test -p oxicrypt-maxwell --lib oracle_noniid_fails`; iid_lrs.rs:289
- [x] ISC-81.3: IID-gate wiring — the combined §5 verdict (permutation ∧ chi-square ∧ LRS) routes maxwell's reported min-entropy: IID → §6.1 most-common-value only (ISC-71); non-IID → min over the §6.3 suite. Mirrors EA `iid_main` vs `non_iid_main`. Probe(bash): `cargo test -p oxicrypt-maxwell --lib noniid_routed_value_is_suite_minimum`; iid_gate.rs:499
- [x] ISC-82: maxwell repeat-run determinism — results delta below documented epsilon. Probe(bash): `cargo test -p oxicrypt-maxwell --lib determinism_bit_exact`; lib.rs:452/459 DET_EPS 1e-12; same-process repeat, not a re-invocation
- [x] ISC-83: Restart-data analysis — 1000×1000 matrix; the §5 battery (permutation + chi-square + LRS) run on ROW data, verdict-parity-checked vs EA v1.1.8 `restart_main`. Probe(bash): `restart_iid_verdicts_are_true_on_iid_data` is the positive control (all three verdicts true on IID data, so a mutation forcing any to false is visible); `restart_iid_verdicts_evaluate_the_row_data` asserts the ROW half via the column fixture transposed, so deleting `rdata &&` from any of the three fails by name; `restart_is_iid_is_the_conjunction_of_the_three_verdicts` runs at the spec `PERMS` budget on a mixed-verdict fixture (`perm` true, `chi` false, `lrs` true), so substituting either `perm_passed` or `lrs_passed` for the conjunction fails by name
- [x] ISC-83.1: §5 battery ALSO run on the transposed COLUMN data (EA PR#250, `restart_main.cpp:800` — `perm_test_pass_col`) — column verdicts (perm + chi-square + LRS) parity-checked. Probe(bash): `restart_iid_verdicts_evaluate_the_transposed_column_data` uses a measured fixture (n=100, two-valued column) where the ROW stream passes all three §5 tests individually — asserted first, as a positive control — while the combined verdict fails, so only the column half can account for it. Deleting any `&& cdata` half fails it by name
- [x] ISC-83.2: §3.1.4.3 restart sanity check — α=1−exp(ln0.99/2000), X_max=max(X_r,X_c) vs the simulated cutoff; failure aborts with the documented message. Probe(bash): `cargo test -p oxicrypt-maxwell --lib alpha_exact_1000 sanity_fails_skewed`; restart.rs:385/427-434; the abort is asserted separately by ISC-83.2.1; control: `sanity_fails_skewed` drives a skewed matrix that MUST trip the cutoff
- [x] ISC-83.2.1: `maxwell restart` exits non-zero when the verdict is not accepted, and echoes the verdict lines to stderr. Probe(bash): `awk '/fn cmd_restart/,/^}/' crates/oxicrypt-maxwell/src/main.rs | grep -A4 'if accepted'` shows `ExitCode::SUCCESS` / `ExitCode::FAILURE`; control: the same extraction over `cmd_apt_table` returns a different exit shape. Closes #154.
- [x] ISC-83.3: Restart min-entropy = min(H_r, H_c, H_I) with the validation-fail gate min(H_r,H_c) < H_I/2 (EA `restart_main.cpp:835,882`). Probe(bash): `cargo test -p oxicrypt-maxwell --lib validation_gate_logic`; restart.rs:445-455 min(h_r,h_c,h_i) + sanity-forces-failure
- [x] ISC-84: Core crate builds no_std — std surfaces feature-gated. Probe(bash): `cargo check -p oxicrypt-entropy --no-default-features --target thumbv7em-none-eabi`; lib.rs:69 unconditional no_std
- [ ] ISC-85: Feature graph documented; std-only surfaces behind named features. Probe(bash): for every feature declared in `crates/*/Cargo.toml`, `git grep -lE '`<feature>`' -- README.md AGENTS.md docs/` must match; `collection`, `rand-core` and `raw-counter` do not; control: the same search for `alloc` matches 3 files
- [x] ISC-86: lama.yaml gains the oxicrypt-entropy API entry. Probe(bash): `grep -n 'Entropy source' lama.yaml`; lama.yaml:67-69; judgment: capability-level entry, oxicrypt-entropy never named; remainder tracked as ISC-86.1
- [ ] ISC-86.1: `lama.yaml` names the `oxicrypt-entropy` crate in its entropy API entry. Probe(bash): `grep -c 'oxicrypt-entropy' lama.yaml` returns 0; control: `grep -c oxicrypt lama.yaml` is non-zero — the entry is a capability string that never names the crate
- [ ] ISC-87: Startup self-test time benchmarked and documented — measured, not asserted [DEFERRED — see Decisions]. Probe(bash): `git grep -lE 'initialize_with_tests' -- benches/benches | wc -l` returns 0 — no startup self-test benchmark exists; control: `git grep -lE 'criterion|bench_function|black_box' -- benches/benches | wc -l` returns 13 real bench targets
- [x] ISC-88: Conditioned-output throughput benchmarked and documented per reference platform. Probe(bash): `cargo bench -p oxicrypt-bench --features entropy-bench --bench conditioned_output`; the figure and its reference platform are recorded in `docs/entropy-performance.md` § Conditioned-output throughput, qualified as a hot-loop steady state on a KVM guest rather than the pilot operational environment's figure
- [x] ISC-89: maxwell 1M-sample processing benchmarked and documented. Probe(bash): `cargo bench -p oxicrypt-bench --features entropy-bench --bench maxwell`; `docs/entropy-performance.md` § `maxwell` assessment cost records both branches at 1 M samples with the symbol width stated per row, and the bench asserts each synthetic input routes as intended before measuring, so two figures from the same branch cannot pass as a result
- [ ] ISC-90: ARM collection burst scripts auto-terminate instances — cost guard. Probe(bash): `git grep -linE 'terminate-instances|aws ec2|shutdown-behavior|self-destruct' -- scripts/ xtask/ .github/ | wc -l` returns 0; control: `ls scripts/*.sh | wc -l` is non-zero, so the tree searched is populated
- [ ] ISC-91: The x86_64 pilot operational environment = RawCounter × {lower, upper boundary} × {raw 1M, restart 1000×1000} = 4 datasets (OsNanoClock same-session optional cross-check), full metadata, §6.3-gated + periodicity-screen-passed (ISC-133), banked BEFORE any ARM spend — D-ENV sequencing. Probe(bash): `cargo test -p oxicrypt-entropy --lib both_boundary_directories_are_emitted`; collection.rs:1446-1448 shape only; the probe tests emitter SHAPE only and never the banking; the datasets themselves are ISC-91.1
- [ ] ISC-91.1: The four x86_64 pilot datasets are banked on disk with a checksum manifest. Probe(bash): `ls datasets/*/*/*/raw.bin datasets/*/*/*/restart.bin 2>/dev/null | wc -l` returns 4 and `test -f datasets/manifest.sha256`; control: `ls crates/*/Cargo.toml | wc -l` is non-zero, proving the glob-and-count mechanism works, so a 0 above means absent rather than mis-globbed. Blocked on #156 — `collect_raw` discards the boundary parameter.
- [x] ISC-92: Security-policy entropy section drafted from as-built gems at Phase-0 close. Probe(manual): `awk '/^### 9\.3 Entropy source/{f=1;next} /^### /{f=0} f' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` — the whole §9.3, read it; nothing verifies the prose against code; control: over that same range `grep -oE '^#### 9\.3\.[1-6] ' | sort -u | wc -l` returns 6 DISTINCT subsections, so a duplicated heading no longer passes for a missing one, and `grep -c 'R78–R82'` returns 1 (en dash, as the document writes it — the hyphen form returns 0)
- [x] ISC-93: Estimator tolerance thresholds pre-registered — committed before the first parity run. Probe(bash): `git log --diff-filter=A --date=short -- docs/estimator-parity-tolerances.md crates/oxicrypt-maxwell/src/parity.rs`; EA-parity ordering verified (de67889 < 2df83ea); judgment: independence tolerances landed in f8980c6 with the code they bound (#160); remainder tracked as ISC-93.1
- [ ] ISC-93.1: The independence tolerances were committed before the code they bound, not alongside it. Probe(bash): `git log --reverse --format=%h -S'independence' -- docs/estimator-parity-tolerances.md | head -1` and `git log --reverse --format=%h --diff-filter=A -- crates/oxicrypt-maxwell/src/independence.rs | head -1` both return `5fb186b` — same commit, so pre-registration does not hold for this pair; control: the same pair for the EA parity tolerances returns two distinct, ordered commits, so the mechanism discriminates
- [ ] ISC-94: Login implements ESVP §2 — versioned-envelope POST /esv/v1/login with TOTP (30s/8-digit); refresh via TOTP+accessToken. Probe(bash): `cargo test -p esv-harness --lib totp_matches_rfc6238_appendix_b_sha256_vector`; login.rs:1282 RFC 6238 Appendix B vector
- [ ] ISC-95: Bulk token refresh (POST /esv/v1/login/refresh, token array) for certify-time multi-token freshness. Probe(bash): `cargo test -p esv-harness --lib bulk_refresh_posts_token_array_and_parses_response`; login.rs:847 order-preserving token array
- [ ] ISC-96: Registration payloads validate against the vendored entropy-source-metadata-schema.json, cited. Probe(bash): `cargo test -p esv-harness --lib seeded_drift_is_caught`; preflight.rs:890-892 seeded mutation must fail the guard
- [x] ISC-97: Raw-data files emit exactly 1,000,000 samples, one byte per sample padding. Probe(bash): `cargo test -p esv-harness --lib wrong_sample_count_is_caught`; preflight.rs:951-956; judgment: collection test runs at 4096, not 1M; remainder tracked as ISC-97.1
- [ ] ISC-97.1: A test emits a raw-data file of exactly 1,000,000 samples end to end. Probe(bash): `awk '/mod tests/ {f=1} f' crates/oxicrypt-entropy/src/raw.rs | grep -cE '(emit|stream_to)\([^)]*1_000_000'` returns 0; control: the same awk range with `grep -cE '(emit|stream_to)\('` is non-zero — `raw_data_sample_count_constant_is_one_million` asserts the constant only
- [ ] ISC-98: DataFileSampleSize sent v1.8-compatible (capitalized; case-insensitivity not assumed). Probe(bash): `cargo test -p esv-harness --lib sample_size_field_is_capitalized_exactly_and_precedes_the_file`; datafiles.rs:1289-1290
- [x] ISC-99: Restart data = numberOfRestarts × samplesPerRestart (1000×1000) consistent between files and metadata. Probe(bash): `cargo test -p oxicrypt-entropy --lib raw_file_size_matches_metadata_sample_count`; collection.rs:1411/1415; judgment: exercised at 8x256, the 1000x1000 values asserted without a file; remainder tracked as ISC-99.1
- [ ] ISC-99.1: A restart file is written at the production 1000x1000 counts and its size checked against metadata. Probe(bash): `awk '/fn raw_file_size_matches_metadata_sample_count/,/^    }/' crates/oxicrypt-entropy/src/collection.rs | grep -c 'Counts::production'` returns 0; control: `git grep -c 'Counts::production' -- crates/oxicrypt-entropy/src/collection.rs` is non-zero — production counts are used only where no file is written
- [ ] ISC-100: Multipart data-file upload shape per §6.1 matches reference-client behavior. Probe(bash): `cargo test -p esv-harness --lib to_multipart_body_has_boundary_headers_part_key_and_capitalized_field`; datafiles.rs:1341-1344
- [ ] ISC-101: Data-file status polling handles all documented statuses incl. 30s not-yet-processed retry. Probe(bash): `cargo test -p esv-harness --lib poll_retries_not_yet_processed_then_succeeds`; datafiles.rs:1706-1709 two 30s sleeps
- [ ] ISC-102: Supporting-doc upload enforces PDF-only and the sdType enum. Probe(bash): `cargo test -p esv-harness --lib new_refuses_a_non_pdf_payload`; supportdocs.rs:406 NotPdf
- [ ] ISC-103: Certify builder enforces exactly-one EAR + exactly-one PUD + ≤1 DataCollectionAttestation. Probe(bash): `cargo test -p esv-harness --lib full_certify_requires_exactly_one_ear`; certify.rs:948/951
- [ ] ISC-104: Conditioning registration uses exact ACVTS mode name "SHA2-256" + the module's CAVP validationNumber. Probe(bash): `cargo test -p esv-harness --lib vetted_sha2_256_sets_exact_name_and_carries_validation_number`; registration.rs:730-733; negative control at :742
- [ ] ISC-105: Multi-OE registration — per-OE dataFileUrls and scoped tokens tracked. Probe(bash): `cargo test -p esv-harness --lib parse_two_oe_response_yields_per_oe_urls_and_tokens`; registration.rs:946-955
- [ ] ISC-106: AddOE certify path implemented for staged dual-arch cert appends. Probe(bash): `cargo test -p esv-harness --lib add_oe_builds_with_certificate_not_module`; certify.rs:1183-1190
- [ ] ISC-107: Anti: no conditionedBits upload attempted under vetted conditioning. Probe(bash): `cargo test -p esv-harness --lib vetted_config_refuses_a_conditioned_upload_and_builds_no_request`; datafiles.rs:2061-2067; non-vacuous, :2092 shows non-vetted DOES build
- [x] ISC-108: SourceSpec sample-extraction explicit — emitted file symbols within min(bitsPerSample, 8) wire constraint. Probe(bash): `cargo test -p esv-harness --lib over_wide_symbol_is_caught_at_its_index`; preflight.rs:966-972
- [ ] ISC-109: hminEstimate serialization from fixed-point H exact within schema bounds 0..bitsPerSample. Probe(bash): `cargo test -p esv-harness --lib all_256_residues_round_trip_byte_exact_and_reconstruct`; hmin.rs:191-194
- [ ] ISC-110: Offline preflight validates payloads + files against vendored validation_rules before any server contact. Probe(bash): `cargo test -p esv-harness --lib constraints_match_vendored_schema`; preflight.rs:876; own control at :888-892 seeded mutation must fail
- [ ] ISC-111: entropyId (TID) tracked per submission in the session store. Probe(bash): `cargo test -p esv-harness --lib create_is_deterministic_and_empty_state_loads`; session.rs:1261-1262
- [ ] ISC-112: physical=false classification documented with rationale in the noise-source description. Probe(bash): `grep -n 'D\.K R23' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` matches once, inside the sentence it guards — deleting the IG D.K R23 non-applicability sentence takes it to 0; judgment: no test asserts physical==false on the wire; control: an invented resolution number returns nothing; remainder tracked as ISC-112.1
- [x] ISC-112.1: A test asserts `physical == false` on the emitted ESV wire body. Probe(bash): `cargo test -p esv-harness --lib registration::tests::wire_body_is_versioned_envelope_with_metadata` passes and `registration.rs` asserts `Some(false)` for the physical field; control: grepping the same assertion for an invented field name returns 0
- [ ] ISC-113: GET status polling for entropyAssessments handles all 8 documented statuses. Probe(bash): `git grep -hoE '"/esv/v1/entropyAssessments[a-zA-Z/{}_]*"' -- esv-harness/src | sort -u` yields no `/{ea_id}` GET path; control: `git grep -hoE '"/esv/v1/[a-zA-Z/{}_]*"' -- esv-harness/src | sort -u` lists all harness paths, so the extractor works. The existing status poller serves dataFiles, a different resource
- [x] ISC-114: Jitter measurement loop optimization-proof — black_box/volatile discipline plus a release-build guard test asserting delta variance persists. Probe(bash): `cargo test --release -p oxicrypt-entropy --features raw-counter release_guard`; jitter.rs:768-769; pre-push fails closed on zero-match filter
- [ ] ISC-115: max_claimable_h ceiling derived Müller-style — 4-LSB EA assessment with conservative per-delta claim, documented in the noise-source description. Probe(bash): `cargo test -p oxicrypt-entropy --lib max_claimable_h`; jitter.rs:699 ceiling pinned at 1 bit, 4-bit width at :697
- [ ] ISC-116: Collection tool emits BOTH lower-boundary (tight-loop) and upper-boundary (normal-operation) datasets per OE. Probe(bash): `git grep -nE 'let _ = boundary;' -- crates/oxicrypt-entropy/src/collection.rs` MATCHES — `collect_raw` discards its boundary argument, so the two captures differ only by directory name; control: `both_boundary_directories_are_emitted` passes while asserting directories rather than difference, which is why it cannot catch this. See #156
- [x] ISC-117: Per-OE acceptance gate is a `maxwell gate` subcommand encoding the §6.3 reuse thresholds as cited transcribed consts — raw > 0.333 bit/delta, restart min(row,col) ≥ half raw, restart > 0.333, sanity pass; consumes EA output until the maxwell suite is parity-complete, EA cross-check thereafter. Probe(bash): `cargo test -p oxicrypt-maxwell --lib constants_match_spec`; gate.rs:408; subcommand wiring unasserted
- [x] ISC-118: Restart collection allocates a fresh source instance per restart round. Probe(bash): `cargo test -p oxicrypt-entropy --lib restart_allocates_a_fresh_source_per_round`; collection.rs:1389 CountingFactory build count
- [x] ISC-119: Startup health-test samples discarded — never reused for output. Probe(bash): `cargo test -p oxicrypt-entropy --lib startup_samples_are_discarded_never_reused`; pipeline.rs:450-452
- [ ] ISC-120: Evidence package includes independence analysis per OE — pairs/triplets min-entropy (≥10M deltas) + FFT pattern scan; collected in a follow-on run of at least 10M samples on the pilot operational environment, after the minimal pilot and before any ARM collection. Probe(bash): `find . -path ./target -prune -o -name 'independence*.json' -print | wc -l` returns 0 — no sidecar banked; control: `cargo test -p oxicrypt-maxwell --test cli_independence -- --list | tail -1` reports 5 tests, so the tooling exists and is oracle-tested
- [x] ISC-121: maxwell implements 2D/3D min-entropy and FFT scan as evidence subcommands. Probe(bash): `cargo test -p oxicrypt-maxwell --lib o2_dependence_detection`; independence.rs:1240; 2D/3D half only
- [x] ISC-122: H-derived oversampling enforces the full-entropy input margin (+64-bit clause, transcribed at build) — h_in ≥ n_out + margin. Probe(bash): `cargo test -p oxicrypt-entropy --lib margin_holds_and_is_minimal_across_claims`; conditioner.rs:219-226 over 2048+ claims
- [ ] ISC-123: Sample-extraction step carries an explicit IG D.K Resolution-1 digitization justification — extraction neither conceals failures from health tests nor obscures raw statistics. Probe(bash): `git grep -cE 'IG D\.K' -- crates/oxicrypt-entropy/src` returns 0 — the digitization substance is at `jitter.rs` (`neither conceals failures`) but carries no citation; control: `git grep -cE 'IG D\.K' -- ISA.md` is non-zero. `doc-guard` allowlists `D.K R1` in `KNOWN_UNCITED`, so the existing gate cannot catch this
- [x] ISC-124: Any sample-size reduction for health testing justified per IG D.K R22 as not hiding failures. Probe(bash): `git grep -nicE 'subsampl|decimat|downsampl' -- 'crates/**/*.rs'` returns 0 — there is no sample-size reduction to justify, so the criterion is satisfied vacuously; control: `git grep -c sample -- crates/oxicrypt-entropy/src/health.rs` is non-zero, so the search reaches the right tree. The policy citation is ISC-124.1
- [x] ISC-124.1: The Security Policy states that no sample-size reduction is performed and cites IG D.K R22 for it, so a reviewer finds the justification where they look for it. Probe(bash): `grep -nc 'D.K R22' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` is non-zero; control: `grep -c 'D.K' "$..."` matches, so zero means R22 specifically is missing.
- [x] ISC-125: Documented α states its exact meaning — cutoff-generating α vs observed false-positive rate — per IG D.K R15, on **every** surface that documents α, not only the policy. Probe(bash): `cargo test -p doc-guard` — `alpha_means_the_same_thing_in_the_policy_and_the_crate_doc` asserts the distinction on both the policy and `health.rs`, so drift in either direction fails; `policy_states_the_alpha_values_the_code_implements` parses `Alpha::DEFAULT` and the recommended-range constants from source and asserts the policy states them, so changing α in code without the document following fails by name. The crate doc's divergence (it described α only as a false-positive probability, the reading the policy rules out) was live when the guard was written and is fixed here
- [x] ISC-126: Conditioner is stateless across output blocks — no retained state between invocations (simplest IG D.K R5 posture). Probe(bash): `cargo test -p oxicrypt-entropy --lib conditioned_blocks_are_stateless_across_blocks`; pipeline.rs:593 independent SHA over samples 161..=320
- [x] ISC-127: Security Policy entropy section states minimum entropy bits for SSP generation and per-output-bit estimate (9.3.A scenario 1 + D.J AC6). Probe(bash): `grep -n 'SSP-generation minimum' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` matches once, the >=384-bit statement; judgment: named D.J AC6 citation absent, text carries [seeding-integration pending], and the per-output-bit estimate this criterion also names is not separately anchored; control: 'SSP-generation maximum' returns nothing; remainder tracked as ISC-127.1
- [ ] ISC-127.1: The Security Policy's SSP-generation entropy statement cites IG D.J AC6, carries no pending marker, and separately anchors the per-output-bit estimate. Probe(none): TODO — no probe is written. The seven existing policy-quoting greps are already tracked for consolidation, and an eighth would deepen a pattern being retired
- [x] ISC-128: Known/suspected failure-mode statement documented, even if "none known" (90B §4.3 R1 + IG D.K R14; jent §6.1.42 precedent wording). Probe(bash): `grep -n -A9 'failure-mode inventory' "${OXICRYPT_SECURITY_POLICY:-$HOME/repos/oxicrypt-policy/security-policy.md}"` matches once and prints the five numbered failure modes plus the accepted-boundary-cases paragraph carrying the known/suspected statement; judgment: doc-only, no test; control: 'failure-mode catalogue' returns nothing; remainder tracked as ISC-128.1
- [ ] ISC-128.1: A test guards the Security Policy's failure-mode inventory statement. Probe(bash): `cargo test -p doc-guard -- --list | grep -ciE 'failure.mode'` returns 0; control: `cargo test -p doc-guard -- --list | grep -c policy_states` is non-zero — `doc-guard` asserts alpha values and the as-built accounting, nothing on failure modes
- [ ] ISC-129: Every build phase consuming 90-series facts opens with a dated freshness sweep — IG changelog + SP 800-90 Updates page + ESV-Server repo — logged in this ISA. Probe(bash): `grep -cE '^- 20[0-9]{2}-[0-9]{2}-[0-9]{2}.*freshness sweep' ISA.md` returns 0 — the rule is written down and not one dated sweep is logged; control: `grep -c 'freshness sweep' ISA.md` is non-zero
- [x] ISC-130: Raw-data collection's characterization capture emits the noise stream UNFILTERED — startup health-test pass gates collection start, the live RCT/APT battery runs alongside and records every trip event into the dataset metadata, but no sample is ever silently dropped, filtered, or window-stitched. Probe(bash): `cargo test -p oxicrypt-entropy --lib characterization_keeps_every_sample_and_annotates_trip`; raw.rs:1585-1596
- [x] ISC-131: Collection binary is a `bin` target behind a default-off `collection` feature; `RawCollector` is crate-private (absent from the public API); default + module build graphs are free of the collection tooling. Probe(bash): `printf 'stanzas=%s private=%s\n' "$(grep -cE '^default = \[\]$|^required-features = \["collection"\]$' crates/oxicrypt-entropy/Cargo.toml)" "$(grep -c 'pub(crate) mod raw' crates/oxicrypt-entropy/src/lib.rs)"` returns `stanzas=2 private=1` — anchored on the VALUES, so flipping the default to ["collection"] fails it where a mere presence check passed; judgment: no compile-fail test, collection tests are themselves feature-gated; control: the old pattern without -E returned 0, which is the defect this replaces; remainder tracked as ISC-131.1
- [ ] ISC-131.1: A compile-fail test proves `RawCollector` is unreachable from the public API. Probe(bash): `git grep -lE 'trybuild|compile_fail' -- crates esv-harness tools xtask | wc -l` returns 0; control: `git grep -lE 'compile_fail' -- ISA.md | wc -l` is non-zero — the only mention in the tree is this contract, and there is no `trybuild` dev-dependency
- [x] ISC-132: A certification-grade collection run that trips RCT/APT mid-run is invalidated and re-collected — the dataset submitted for a min-entropy estimate is a clean, contiguous, trip-free run; the unfiltered-annotated capture is retained only as characterization evidence, never window-stitched into a submission. Probe(bash): `cargo test -p oxicrypt-entropy --lib certification_trip_invalidates_and_signals_recollect`; raw.rs:1842-1848
- [x] ISC-133: The minimal pilot runs a lightweight FFT + autocorrelation periodicity screen on the 1M raw dataset (distinct from the deferred ≥10M independence analysis); a dominant periodic component fails pilot acceptance. Probe(bash): `cargo test -p oxicrypt-maxwell --lib pure_periodic_sawtooth_is_flagged`; periodicity.rs:583; synthetic sources only
- [x] ISC-134: Anti: maxwell's permutation shuffle never seeds from a non-deterministic source (no /dev/urandom, no system entropy) — unlike EA, which seeds xoshiro256 from /dev/urandom (`utils.h:580`); maxwell's seed is a fixed documented constant so every run is bit-reproducible. Probe(bash): `cargo test -p oxicrypt-maxwell --lib determinism_test_bit_exact`; permutation.rs:1231, fixed SHUFFLE_SEED
- [x] ISC-135: `forbid(unsafe_code)` accounting is recomputed from disk and matches the security policy — 22 of 27 in-boundary crates carry it, with five unsafe exception crates named, not merely counted. Probe(bash): `cargo test -p doc-guard policy_states_the_as_built_accounting`; doc-guard/src/lib.rs:153 recomputes from disk and fails by crate NAME, not count
- [x] ISC-136: README.md and AGENTS.md state the same as-built unsafe accounting as the security policy. Probe(bash): `cargo test -p doc-guard readme_states_the_count_and_lists_every_crate agents_md_states_the_as_built_accounting`; the same accounting asserted in README.md and AGENTS.md
- [ ] ISC-137: Every approved algorithm has known-answer / ACVP vectors that pass. Probe(bash): `python3 -c "import json;print(json.load(open('docs/validation/acvp-demo-evidence.json'))['summary']['vector_sets_failed'])"` returns 13 failed vector sets; control: `python3 scripts/check-acvp-evidence.py` exits 0 with its own planted-string controls firing. Second falsifier: XMSS is implemented and has never been graded
- [x] ISC-138: Power-up self-tests run and gate operation — no approved service is reachable before they pass. Probe(bash): `cargo test -p integrity-probe --test signed_artifact`; twelve tests sign a real artifact, run it, and read the module's status indicator off its exit code, so the test exercises `oxicrypt_module::initialize_with_tests` rather than a helper. Control: an unsigned artifact must refuse to become operational, and a byte changed in a loader-written region must not affect the verdict — the second is what distinguishes this from a whole-file hash. The previous probe, `cargo test -p oxicrypt-integrity integrity_self_test`, selected **0 tests of 18** and could not fail.
- [x] ISC-139: The cryptographic module boundary is formally defined, and its membership is derivable rather than asserted. Probe(bash): `cargo test -p doc-guard --lib agents_md_states_the_as_built_accounting` passes — `accounting()` reads `crates/` off disk, asserts every named out-of-boundary crate exists, and asserts the `forbid(unsafe_code)` exception set equals the disk-derived one, so membership is recomputed rather than read back; control: `cargo test -p doc-guard --lib readme_states_the_count_and_lists_every_crate` also passes. Residual: `OUT_OF_BOUNDARY` is a hand-written const, so the derivation is partial
- [ ] ISC-140: SSPs are zeroized on drop; the zeroization invariant is documented and tested. Probe(bash): `cargo test -p oxicrypt-zeroize zeroize_clears_bytes`; judgment: proves the primitive, not that every SSP type calls it on drop; remainder tracked as ISC-140.1
- [ ] ISC-140.1: Every SSP-carrying type zeroizes on drop, enumerated against a type inventory rather than proven one instance at a time. Probe(bash): `git grep -liE 'every.*(ssp|secret).*(drop|zeroiz)' -- crates tools | wc -l` returns 0; control: `git grep -A4 'impl Drop' -- 'crates/*/src/*.rs' | grep -c zeroize` is non-zero — the `Drop` impls exist and do zeroize, nothing proves the class is complete
- [x] ISC-141: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean. Probe(bash): `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`; both exit 0; a lint regression fails closed
- [ ] ISC-142: Anti: no non-approved algorithm is reachable through the cryptographic boundary. Probe(bash): `comm -23 <(ls crates | grep -vE '^(oxicrypt-ffi|oxicrypt-maxwell)$' | sort) <(git grep -l 'require_allowed' -- crates | cut -d/ -f2 | sort -u)` lists 8 in-boundary crates that never gate, three of which expose crypto primitives publicly; control: `git grep -l 'require_allowed' -- crates | cut -d/ -f2 | sort -u | wc -l` is non-zero, so the search works
- [x] ISC-143: Anti: no host path, private-project name, or internal context appears in any tracked file, including binary files. Probe(bash): `git grep -nE '/home/[a-z]+|/Users/[a-z]+|C:\\Users' -- . ':!vendor' | grep -vE '/home/(yourname|example|someone)|/Users/(yourname|example|someone)|check-acvp-evidence\.py' | wc -l` returns 0; control: a planted `/home/<user>/…` line is reported, so the search is live. Scans binary content, not only text
- [ ] ISC-144: Root `lama.yaml` and `docs/llm-api-manifest/llm-api.yaml` match the public API surface. Probe(bash): `sed -n '/^functions:/,/^error_types:/p' docs/llm-api-manifest/llm-api.yaml | grep -cE '^  - name:'` counts 418 documented functions against `git grep -hE '^[[:space:]]*pub (const |unsafe |extern "C" )*fn ' -- crates | wc -l` — a gap indicator, not a measurement, since no API extractor exists in-tree; control: `comm -23` of manifest module names against `ls crates` prints the manifest-only names, proving the extraction is real
- [x] ISC-145: `oxicrypt-maxwell` matches EA v1.1.8 on input validation — a sample exceeding the declared `bits_per_symbol` is refused with a typed error and surfaced as a non-zero CLI exit, a narrower one warns and continues, and a refused run writes no evidence sidecar. Probe(bash): `cargo test -p oxicrypt-maxwell --lib independence::` asserts the typed error's variant and all five fields at every width `1..=7` via the inclusive `2^bits - 1` / `2^bits` boundary loop, plus a two-offender fixture pinning `first_index` and `count`, and the narrower-source report; `cargo test -p oxicrypt-maxwell --test cli_independence` drives the real binary for the non-zero exit, the absent sidecar, and the warning
- [x] ISC-146: `maxwell parity` exits non-zero when it did not compare everything; an all-skip or partially-skipped run is a failure unless explicitly opted out for that invocation, and the verdict says in words whether the run is evidence. The same fail-closed convention holds for `maxwell restart` and `maxwell gate`. Probe(bash): `cargo test -p oxicrypt-maxwell --test cli_exit_codes` drives the real binary against an empty dataset directory and asserts the exit code, the wording, and that only the exact value `1` disarms the opt-out; `cargo test -p oxicrypt-maxwell --bin maxwell restart_verdict` covers the restart half, which cannot be driven through the CLI in-suite because a 1,000,000-sample analysis runs ~456s

## Test Strategy

Each criterion carries its own probe inline, tagged by kind. This section states how the probes are run
and what makes one trustworthy — it does not restate them.

| class | `Probe(type)` | who says no | failure semantics | obligation |
|---|---|---|---|---|
| deterministic | `bash` | a tool | the only class that may block a gate | the probe clause carries the runnable command, not a description of one |
| attested | `manual` | caraka, on encounter | a dated verdict plus an evidence pointer; tracked for staleness, never auto-failed | the verdict is recorded in `## Decisions` with its date |
| — | `none` | nobody yet | cannot close; never a blocking row | the criterion states what is missing, and why no probe was written, on the criterion itself |

Rust is not a Bun surface, so every deterministic probe is `bash` naming the real invocation
(`cargo nextest …`, a mutation harness, a `git grep`) rather than an invented `cargo-test` type.
`none` is local to this file: an unassigned verifier is not one of the format's seven types, and
typing a probe that does not exist as `bash` would put it in the only class permitted to block.

**A command that FETCHES evidence for a human to read is `manual`, not `bash`.** The type names the
tool that *decides*; where a command extracts a prose section and caraka renders the verdict, the
extractor is the evidence-fetcher and the row is attested.

**Where a command reaches only part of what its criterion claims, the remainder stays stated on the
criterion AND becomes a claim of its own.** The parent keeps its text unchanged and gains `; remainder tracked as ISC-N.1`. The remainder stays
stated on the parent: a caveat moved off a checked criterion reads as fully covered, and a remainder
may refute a clause rather than merely bound the command's reach.

**Every probe must be able to fail.** A probe that silently matches nothing is indistinguishable from a
passing one, so a probe whose absence could read as success states its positive control: what a working
probe returns when the thing it looks for *is* present. Two probes already in this repository are the
pattern to copy — `constraints_match_vendored_schema` seeds a mutation into the vendored schema and
requires the guard to fail, proving it compares rather than no-ops; and the pre-push hook gates on
`grep -Eq "test result: ok\. [1-9][0-9]* passed"`, failing closed when a test filter matches nothing.

**Running the suites.**

| suite | command | notes |
|---|---|---|
| workspace tests | `cargo nextest run --workspace` | the default gate; excludes feature-gated and EA-anchored work |
| formatting and lints | `cargo fmt --all -- --check` · `cargo clippy --workspace --all-targets -- -D warnings` | `--all-targets` silently skips targets whose `required-features` are unsatisfied |
| doc tests | `cargo test --workspace --doc` | currently vacuous for `oxicrypt-entropy` — no runnable fences exist |
| estimator parity | `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance` | requires the EA v1.1.8 dataset bundle; absence fails rather than skips |
| release-only guard | `cargo test --release -p oxicrypt-entropy --features raw-counter release_guard` | live counter; excluded from the default profile by design |
| documentation guards | `cargo test -p doc-guard` | recomputes accounting from disk and fails by crate name |
| containment | `git grep -nE '/home/[a-z]+\|/Users/[a-z]+\|C:\\Users' -- . ':!vendor'`, filtered for documentation placeholders | must return nothing; scans binary content, not only text, so a match inside a compiled artifact is caught |

**Build-directory constraint.** Gate runs set `CARGO_TARGET_DIR` to a machine-local path. Linking into a
shared target directory produces binaries against the build host's libc, which the machine that runs
them may not have.

**What the probes do not cover.** Every `Probe(manual)` and `Probe(none)` criterion, and every open
remainder tracked off a `Probe(bash)` one, are the uncovered share. They are tracked rather than
hidden, because a measured criterion that improves while an unmeasured one rots is worse than an
honest gap. The share is countable rather than estimated: 3 attested and 1 unassigned of 179 — every other
criterion now names a command that decides it, and 67 of those commands currently report the claim unmet.

## Features

Coverage of the workspace by articulated criteria. Crates with no criteria are not defects in themselves — they are the measured share of the module the contract does not yet speak to, made visible rather than left to inference.

| crate | boundary | criteria | notes |
|---|---|---|---|
| `oxicrypt-aes` | in | — | no articulated criteria |
| `oxicrypt-aes-accel` | in | — | `unsafe` exception |
| `oxicrypt-cmac` | in | — | no articulated criteria |
| `oxicrypt-dh` | in | — | no articulated criteria |
| `oxicrypt-drbg` | in | — | no articulated criteria |
| `oxicrypt-ecdh` | in | — | no articulated criteria |
| `oxicrypt-ecdsa` | in | — | no articulated criteria |
| `oxicrypt-eddsa` | in | — | no articulated criteria |
| `oxicrypt-entropy` | in | 74 |  |
| `oxicrypt-ffi` | out | — | no articulated criteria |
| `oxicrypt-hmac` | in | — | no articulated criteria |
| `oxicrypt-integrity` | in | — | no articulated criteria |
| `oxicrypt-kdf` | in | — | no articulated criteria |
| `oxicrypt-keccak-accel` | in | — | `unsafe` exception |
| `oxicrypt-lms` | in | — | no articulated criteria |
| `oxicrypt-maxwell` | out | 40 |  |
| `oxicrypt-ml-dsa` | in | — | no articulated criteria |
| `oxicrypt-ml-kem` | in | — | no articulated criteria |
| `oxicrypt-module` | in | — | no articulated criteria |
| `oxicrypt-rsa` | in | — | no articulated criteria |
| `oxicrypt-sha` | in | — | no articulated criteria |
| `oxicrypt-sha-accel` | in | — | `unsafe` exception |
| `oxicrypt-slh-dsa` | in | — | no articulated criteria |
| `oxicrypt-test-vectors` | in | — | no articulated criteria |
| `oxicrypt-timer` | in | — | `unsafe` exception |
| `oxicrypt-tls-kdf` | in | — | no articulated criteria |
| `oxicrypt-xmss` | in | — | no articulated criteria |
| `oxicrypt-xof` | in | — | no articulated criteria |
| `oxicrypt-zeroize` | in | — | `unsafe` exception |
| `acvp-harness` | tooling | — | outside the boundary |
| `esv-harness` | tooling | 18 | outside the boundary |
| `oxi` | tooling | — | outside the boundary |
| `benches` | tooling | — | outside the boundary |
| `tools/doc-guard` | tooling | — | outside the boundary |

## Decisions

Decisions in force, with the reasoning that makes each hard to vary. Superseded amendments and the
route taken to reach a decision are not recorded here — the git history and `CHANGELOG.md` hold those.

- **Three sanctioned `unsafe` categories, five readily auditable crates.** In-boundary code is
  `#![forbid(unsafe_code)]` by default because it is a build-time control that enters the conformance
  argument, not a style preference. Three categories are sanctioned, each isolated in a small, readily auditable
  crate: **volatile CSP zeroization** (`oxicrypt-zeroize`, one `write_volatile` mechanism);
  **CPU-intrinsic acceleration** (`oxicrypt-sha-accel`, `oxicrypt-aes-accel`, `oxicrypt-keccak-accel`
  — feature-gated, default-off, runtime-detected, equivalence to the portable path proven by KAT plus
  a cross-path oracle); and **CPU timer/counter intrinsics** (`oxicrypt-timer` — read-only,
  side-effect-free, no cryptographic logic). Acceleration is admitted only where an oracle can prove
  byte-identical output, which is why the category is safe to widen and why each new member ships with
  its differential test. The default build graph contains no acceleration crate: the portable
  baseline is the shipping default. `oxicrypt-ffi` sits outside the boundary and necessarily carries
  `unsafe`. Current accounting — 22 of 27 in-boundary crates carrying `forbid`, five readily auditable
  exceptions — is recomputed from disk by `doc-guard` rather than restated, so it cannot drift
  (ISC-135). Security policy §9.2.

- **The entropy pipeline is three stages, and the claim is injected, never embedded.** Noise source →
  health tests → conditioner. Sources are dumb emitters declaring only a design-anchored
  `max_claimable_h()` ceiling; the claimed min-entropy enters at pipeline construction and is refused
  with a typed error above the ceiling or above the declared sample width. Min-entropy is exact
  fixed-point (1/256-bit steps, floor rounding) with no floating point anywhere on the claim or cutoff
  path — a rounding artefact in a claim is an overstatement of entropy, which is the one direction that
  must be impossible. SP 800-90B constants live in the single cited module `sp800_90b`, transcribed
  from fetched documents. Security policy R78.

- **Health-test failure is permanent.** A failing instance enters a terminal state, the failing block is
  never returned, and only re-instantiation clears it. Recovery-in-place would mean a source that
  failed its own health criteria continuing to supply entropy, which no downstream consumer could
  detect. Startup gating runs over at least 1024 consecutive samples and those samples are discarded.
  Approved tests are the §4.4 pair: RCT with a closed-form integer cutoff, APT with precomputed table
  cutoffs and a typed refusal for uncovered (α, alphabet, H) points — no runtime binomial. Security
  policy R79.

- **The jitter source is design-derived, not ported.** CPU execution-time jitter from a
  `black_box`-disciplined SHA-256 and data-dependent memory-walk workload, with a release-build
  variance guard; 4-LSB digitization with one symbol stream end to end; a 1 bit/sample design ceiling
  and no claimed-H constants in the source; construction-time timer-adequacy refusal; and a bounded
  backwards-delta retry yielding a typed `Unavailable` on exhaustion. Design provenance is cited to the
  published SP 800-90B writeup; no BSD-3 code is transliterated, which is a licensing boundary as much
  as an engineering one. The source fails closed. Security policy R81.

- **Conditioning is vetted SHA-256, stateless per block.** The conditioning component is SHA-256 per
  SP 800-90B §3.1.5.1.1 Table 1 via `oxicrypt-sha`, with the per-block sample count derived from the
  injected claim under the SP 800-90C §3.2.2.2 full-entropy input margin (h_in ≥ n_out + 64). Hashing
  is stateless across output blocks — a fresh hash instance per block and a config-only conditioner
  struct — so no block can inherit entropy accounting from its predecessor. A startup conditioning KAT
  refuses permanently on mismatch, and conditioned output draws every sample through the single
  health-tested emission path. Security policy R82.

- **`oxicrypt-entropy` is inside the module boundary.** The alternative — an out-of-boundary source
  feeding the DRBGs — would leave the module's entropy claim resting on a component the validation does
  not cover. Full workspace discipline therefore applies to it.

- **Acceleration is admitted only with a differential oracle.** `oxicrypt-ml-dsa`'s default-off
  `accel-keccak` feature samples the public matrix Â four SHAKE-128 cell streams at a time, re-squeezing
  in equal-length rate-block rounds until all four lanes reach N accepted coefficients — never
  truncating — with a scalar fallback for the 1–3 cell tail when K·ℓ is not a multiple of 4. Â is
  byte-identical to the scalar build because each lane is consumed under the identical 3-byte `t < Q`
  rejection rule, and all four combinations of `parallel` × `accel-keccak` agree. The crate adds no
  `unsafe`. A throughput option only: no approved service, SSP, self-test, or state-machine change.

- **`maxwell`'s tuple histogram chooses storage by alphabet size.** A dense array for small alphabets
  (≤ 2¹⁶) and a sparse map only for the 8-bit triplet alphabet (2²⁴, ~134 MB) that motivated the change.
  Both branches keep the `c < alphabet` drop guard and read the maximum over counts, so MCV mode counts
  and min-entropy are unchanged — a performance change must not move a reported evidence number. An
  unconditional map was rejected because it penalised the small-alphabet legs that never had the
  allocation problem.

- **2026-08-20 — probes name the verifier that decides them, and coverage remainders became claims.**
  The `M`/`P`/`J` tags were local to this file and conflated two things whose failure semantics differ:
  a tool's verdict and a human's. Every probe now names its verifier — `bash` where a command decides,
  `manual` where caraka does, `none` where no probe exists yet — and only `bash` may ever block a gate.
  The 25 criteria that carried a command *plus* a named judgment remainder keep their text unchanged
  and now track that remainder as `ISC-N.1`, a claim of its own that closes on a dated verdict here and
  nothing else. **The remainder text was deliberately NOT relocated onto the child.** Moving a caveat
  off a checked criterion promotes it to fully covered, and these remainders are not one population:
  some bound how far a command reaches (`ISC-97`'s test runs at 4096, not 1M), while others refute a
  clause of the claim outright (`ISC-83.2` — *"failure aborts" is FALSE*, `#154`). No single mechanism
  separates them, so the text stays where a reader of the criterion will see it. **Four checked
  criteria whose own text records a refutation — `ISC-83.2`, `ISC-35`, `ISC-91`, `ISC-124` — keep the
  `[x]` they had; whether the box or the clause is wrong is a question about the module, not about
  probe vocabulary, and is not settled here.** No identifier was renumbered and no checkbox moved;
  177 of 179 criteria are byte-identical but for their tag.

- **2026-08-03 — this ISA adopts the criterion numbering the code already cites.** The repository
  previously carried an eighteen-criterion placeholder whose IDs collided with the numbering used by 162
  citations across 34 tracked files, so `ISC-18` at `timer.rs:579` resolved against this file to an
  unrelated criterion. The placeholder meanings are retired; the numbering the code cites is adopted
  whole, so every existing citation resolves without a single source edit. Module-level subjects that
  had no counterpart are reissued above the existing range at ISC-135 and upward; nothing is renumbered
  downward, per the ID-stability rule. Eight of the retired eighteen were duplicates of criteria already
  in the adopted set — the health-failure, margin, statelessness and ceiling-refusal criteria among them
  — and are dropped rather than re-created, so the pool holds one criterion per claim.

## Changelog

How the understanding of the ideal state has changed. Build history lives in `CHANGELOG.md` and the git
log; this records only shifts in what "done" means.

- **2026-08-03 — the contract became falsifiable rather than declarative.** Criteria previously stated
  what should be true and were marked satisfied by reading. Each now carries a probe that would falsify
  it, and the act of writing those probes changed several verdicts: a criterion satisfied because two
  directories existed while the datasets inside them were identical (#156); a doc-test criterion passing
  against zero runnable examples; a per-arch default test whose assertions are `cfg`-gated and whose body
  is empty on any other host. The lesson generalises — a criterion without a probe records an intention,
  not a state, and intentions do not decay visibly.

## Verification

Evidence that criteria hold, recorded as current state. A criterion's own probe is the authority; this
section records what has actually been run and what has not.

**Probe inventory.**

| `Probe(type)` | count | meaning |
|---|---:|---|
| `bash` | 175 | a command returns the verdict |
| `manual` | 3 | caraka renders the verdict on encounter |
| `none` | 1 | the probe does not yet exist; the criterion is unverified and unchecked |

The 3 attested are the criteria whose command extracts a prose section for a human to read — the type
names the tool that *decides*, and there the tool presents. The single `none` is `ISC-127.1`, parked
with its reason on the criterion itself.

**Verified with the command run and its result.**

- `cargo fmt --all -- --check` — exit 0, run unpiped so the status is the command's own.
- Containment (`ISC-143`) — `git grep` over all tracked files returns nothing; a positive control with a
  known-present string matches, and a planted binary file containing a host path **was** caught,
  confirming the probe scans binaries rather than skipping them. Five violations were found and removed
  before this ISA was written.
- `doc-guard` accounting (`ISC-135`, `ISC-136`) — recomputes the `forbid(unsafe_code)` accounting from
  disk and fails by crate name rather than by count.

**Known vacuous or partial probes, recorded rather than hidden.**

- Doc tests for `oxicrypt-entropy` compile zero runnable examples, so `cargo test --doc` passes having
  proven nothing.
- `default_for_target_matches_arch` has `cfg`-gated assertions only for x86_64 and aarch64; on any other
  host its body is empty and it passes vacuously.
- The restart-analysis §5 verdicts (`perm_passed`, `chi_square_passed`, `lrs_passed`) are computed and
  stored but asserted by no test.
- `missing_docs` is set to `warn`, not `deny`; denial exists only under the CI and pre-push `RUSTFLAGS`,
  so a local build will not fail on a missing doc.
- The `collection` feature's tests are themselves feature-gated, so a default-feature run exercises none
  of them.

**Not yet verified.** Every criterion whose probe reads `TODO` is unverified by construction and is left
unchecked. These are tracked, not deferred silently.
