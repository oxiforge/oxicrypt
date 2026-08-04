---
task: oxicrypt FIPS 140-3 cryptographic-module ideal-state contract and system of record
project: oxicrypt
slug: oxicrypt-module-contract
phase: execute
progress: 99/154
mode: algorithm
started: 2026-06-06T00:00:00Z
updated: 2026-08-03T00:00:00Z
---

# oxicrypt — ISA (Ideal State Artifact)

> **The design contract and system of record** for the oxicrypt cryptographic module: the articulated
> ideal state, the contributor contract, and the done-condition for CAVP/CMVP validation. Read it to
> understand *where the boundaries are and why they hold* before changing anything. Security-design
> detail lives in `docs/security-policy/security-policy.md`, its canonical home; this file is the
> boundary contract and the criteria that falsify it.
>
> **Criteria record what is built and what is claimed — not the route taken to get there.** Each
> carries the probe that would falsify it, tagged `M` (a command returns the verdict), `P` (a command
> plus a named judgment remainder), or `J` (judgment only). A criterion whose probe cannot yet be run
> says so, and the missing probe is tracked as an issue rather than left implied.

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
- **Non-approved / experimental algorithms** in the validated boundary — approved algorithm set only.
- **TLS / protocol layers** — those live in sibling crates (`oxitls`), built *on* oxicrypt, not in it.
- **A production ESV certificate** — the entropy assessment target is the NIST demo server; an
  accredited 17ESV lab engagement is a later, separately-funded step.
- **Any direct port of the jitterentropy C library** — the jitter source is design-derived from the
  published SP 800-90B writeup, with BSD-3 code never transliterated. This is a licensing and
  engineering boundary, not a stylistic one.
- **Hardware TRNG noise sources** — the noise-source abstraction must *admit* them; implementing them
  is deferred.
- **Windows / Android / iOS operational environments** — collection rigs are Linux bare-metal for the
  present assessment.

## Principles

- **`forbid(unsafe_code)` is the in-boundary default**, not a style choice — 22 of 27 in-boundary crates
  carry it. It is a build-time control that enters the conformance argument. Three sanctioned
  `unsafe` categories exist, isolated in five small audited crates: (1) **volatile CSP
  zeroization** — `oxicrypt-zeroize`, one audited `unsafe` mechanism for `write_volatile`;
  (2) **CPU-intrinsic acceleration** — `oxicrypt-sha-accel` (x86_64 SHA-NI), `oxicrypt-aes-accel`
  (x86_64 AES-NI + PCLMULQDQ GHASH), and `oxicrypt-keccak-accel` (x86_64 AVX2 4-way batched
  Keccak-f[1600]): feature-gated, default-off, runtime-detected, equivalence to the portable path
  proven by KAT + cross-path oracle; and (3) **CPU timer/counter intrinsics** — `oxicrypt-timer`:
  read-only, side-effect-free counter reads, no cryptographic logic. The default build graph contains
  no acceleration crate; the validated portable baseline is the shipping default. The C-ABI crate
  (`oxicrypt-ffi`) sits outside the boundary and necessarily carries unsafe.
- **One home per security claim** — the CMVP claims live in `docs/security-policy/security-policy.md`;
  code and rustdoc point at it, never restate it.
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

- **FIPS 140-3 Level 1**, Implementation Guidance D.G (March 2026) — reconcile on IG updates.
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

## Criteria

> Every criterion carries the probe that would falsify it. `M` = a command returns the verdict; `P` = a command plus a named judgment remainder; `J` = judgment only. A probe reading `TODO` does not yet exist, and its criterion is left unchecked — the gap is recorded, not implied.

- [x] ISC-1: Noise-source trait abstraction exists; jitter source #1 implements it; a second source can be added without touching consumers. Probe(M): `cargo test -p oxicrypt-entropy --lib live_jitter_flows_through_full_pipeline`; jitter.rs:790; 4 mock impls drive the same generic pipeline
- [ ] ISC-2: Raw-data mode emits unconditioned samples via a distinct `RawCollector` (no conditioner) in the ESV wire format — exactly 1M samples, one byte each [DEFERRED — see Decisions]. Probe(M): `cargo test -p esv-harness --lib wrong_sample_count_is_caught`; preflight.rs:948 expected 1_000_000, one byte per sample
- [x] ISC-3: RCT implemented per 90B §4.4.1, cutoff parameterized by claimed H. Probe(M): `cargo test -p oxicrypt-entropy --lib rct_cutoff_spec_worked_example`; health.rs:372 cutoff==11, §4.4.1 worked example
- [x] ISC-4: APT implemented per 90B §4.4.2, window/cutoff parameterized. Probe(M): `cargo test -p oxicrypt-entropy --lib apt_cutoff_table2_rows`; health.rs:413/415, Table 2 rows
- [x] ISC-5: Health tests sit in the sample path — no raw sample reaches the conditioner untested. Probe(M): `cargo test -p oxicrypt-entropy --lib health_failure_mid_block_poisons_and_emits_nothing`; pipeline.rs:607
- [x] ISC-6: Startup + on-demand restart tests per 90B §3.1.4. Probe(P): `cargo test -p oxicrypt-entropy --lib no_output_before_startup on_demand_before_startup_is_refused`; pipeline.rs:428/526; judgment: collect_restart's per-round run_startup (collection.rs:565) is unasserted
- [x] ISC-7: Conditioning component implemented and documented as an ESV claim (vetted vs non-vetted choice logged as a Decision). Probe(P): `cargo test -p esv-harness --lib vetted_sha2_256_sets_exact_name_and_carries_validation_number`; security-policy.md:2813; judgment: no Decision weighs the non-vetted alternative
- [x] ISC-8: `rand-core` compat behind default-off feature; default build graph free of it. Probe(M): `cargo tree -p oxicrypt-entropy -e normal --no-default-features | grep -c rand_core`; 0; control: --features rand-core gives >=1
- [ ] ISC-9: Estimator suite matches NIST EA tool v1.1.8 output within tolerance on its 11 bundled datasets + pilot data. Probe(M): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; 11 bundled datasets only; pilot-data half TODO
- [x] ISC-9.1: Literal-track §6.3 suite — each non-IID estimator (collision, Markov, compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC, LZ78Y) computes theliteral-symbol-track estimate matching EA's per-estimator "Literal" value ≤1e-6 on the multi-bit reference datasets. Probe(M): `cargo test -p oxicrypt-maxwell --lib literal_parity_multibit`; per-estimator literal track, PARITY_EPS=1e-6
- [x] ISC-9.2: Assessed-min-entropy headline — `min(H_original, H_bitstring × word_size)` matches EA's final "Assessed min entropy" line, and maxwell reports BOTH it and the per-bit controlling value (Option C); wires the assessed number into `IidGateResult` + CLI. Probe(M): `cargo test -p oxicrypt-maxwell --lib assessed_assembly_matches_ea_on_multi_bit_datasets`; iid_gate.rs:354
- [x] ISC-10: Estimator suite recovers analytic min-entropy on synthetic sources (known-bias Bernoulli, near-uniform). Probe(M): `cargo test -p oxicrypt-maxwell --test analytic_recovery`; analytic_recovery.rs:59
- [ ] ISC-11: Anti: no C/FFI dependency anywhere in the crate's tree. Probe(M): `grep -rn 'extern "C"' crates/oxicrypt-entropy/src/ + no build.rs/*.c`; control: oxicrypt-ffi/src/aes.rs:68 matches
- [ ] ISC-12: Anti: no entity names, host paths, or internal context in any repo-destined artifact. Probe(M): `git grep -nE '/home/[a-z]+|/Users/[a-z]+|C:\\Users' -- . ':!vendor'` returns nothing, plus the private-name patterns read from the uncommitted deny-list; positive control — adding `|oxicrypt` matches `README.md`
- [x] ISC-13: Timer-source selection per arch is an explicit, documented design decision (raw counter vs OS nanosecond clock vs internal timer thread), with rationale in the ESV noise-source description. Probe(J): `sed -n '4,19p' crates/oxicrypt-entropy/src/timer.rs`; per-arch rationale is prose; read it
- [x] ISC-14: Every raw-data collection emits dataset metadata recording timer source, counter frequency, CPU model, OS, and collection parameters — no anonymous datasets; each sidecar validates against the vendored versioned JSON metadata schema and records the MEASURED counter frequency, never nominal. Probe(M): `cargo test -p oxicrypt-entropy --lib metadata_validates_against_vendored_schema`; raw.rs:1889; negative control validator_rejects_missing_required_field
- [x] ISC-15: Pipeline construction with claimed-H above the source's design ceiling fails with a typed error. Probe(M): `cargo test -p oxicrypt-entropy --lib claim_above_ceiling_is_refused`; pipeline.rs:388
- [x] ISC-16: No claimed-H constants in any source impl — H enters only at pipeline construction. Probe(M): `grep -n MinEntropy crates/oxicrypt-entropy/src/jitter.rs`; only max_claimable_h at :407-409
- [x] ISC-17: Anti: no f32/f64 anywhere in the health-test cutoff path. Probe(M): `grep -nE '\bf32\b|\bf64\b' crates/oxicrypt-entropy/src/{health,h,sp800_90b,conditioner,pipeline}.rs`; 1 hit, doc prose only; control matches real f64 in maxwell
- [x] ISC-18: TimerSource config enum with per-arch defaults (x86_64 RawCounter, aarch64 OsNanoClock) and documented per-arch rationale. Probe(M): `cargo test -p oxicrypt-entropy --lib default_for_target_matches_arch`; timer.rs:584; FLAG VACUOUS off x86_64/aarch64 — both asserts cfg-gated, empty body elsewhere
- [x] ISC-19: Startup timer-adequacy self-check measures observed delta granularity + monotonicity and refuses inadequate configs. Probe(M): `cargo test -p oxicrypt-entropy --lib construction_runs_adequacy_and_refuses_coarse_timers`; timer.rs:641-642
- [x] ISC-20: Anti: InternalTimerThread unselectable in Phase 0 — selecting it returns a typed Unsupported error; no ESV claim references it. Probe(M): `cargo test -p oxicrypt-entropy --lib internal_timer_thread_is_unselectable`; timer.rs:593 typed Unsupported
- [x] ISC-21: Conditioner dependencies resolve in-workspace only — oxicrypt-sha, no external hash crate. Probe(M): `grep -nE 'sha2|ring|openssl|digest|blake' crates/oxicrypt-entropy/Cargo.toml`; none; control oxicrypt-sha path dep at :35
- [x] ISC-22: Samples-per-output-block derived from injected claimed-H per the documented §3.1.5 vetted formula — varying H changes the count correctly. Probe(M): `cargo test -p oxicrypt-entropy --lib samples_per_block_varies_with_claim`; conditioner.rs:181/184/190; NOTE code cites 90C 3.2.2.2 not 90B 3.1.5
- [x] ISC-23: Conditioning KAT runs at startup; corrupted vector causes refusal, not degraded operation. Probe(P): `cargo test -p oxicrypt-entropy --lib corrupted_vector_causes_refusal`; conditioner.rs:241; judgment: startup-injection half untested
- [x] ISC-24: Docs section states the vetted-conditioning claim and output-entropy accounting formula. Probe(J): `sed -n '2812,2815p' docs/security-policy/security-policy.md`; vetted claim + h_in >= n_out + 64 accounting
- [x] ISC-25: α restricted to power-of-two set, default 2⁻³⁰ (jent cert-lineage precedent; refined 2026-06-12 15:19); cutoffs vary correctly with α. Probe(M): `cargo test -p oxicrypt-entropy --lib alpha_range_enforced`; health.rs:363/359
- [x] ISC-26: Claimed H rounds DOWN to the table grid — claim never overstated. Probe(M): `cargo test -p oxicrypt-entropy --lib apt_h_rounds_down_to_grid`; health.rs:424
- [x] ISC-27: APT cutoff table generated by out-of-boundary maxwell utility; in-boundary table verified by test against reference values. Probe(M): `cargo test -p oxicrypt-entropy --lib apt_alpha30_matches_generator`; sp800_90b.rs:390-425 in-boundary table vs generator values
- [x] ISC-28: Anti: no uncited numeric literals in the health module — every spec constant named with clause citation. Probe(M): `awk scan of pub const in sp800_90b.rs for a preceding section citation`; 1 uncited of 21: APT_ALPHA30_ALPHA_EXP (sp800_90b.rs:219)
- [x] ISC-29: Every health-test failure is permanent — instance enters terminal error state, the failing block is never returned, only re-instantiation clears (refined 2026-06-12 15:19, jent precedent). Probe(M): `cargo test -p oxicrypt-entropy --lib poisoned_monitor_never_recovers`; health.rs:554 across 50 samples
- [x] ISC-30: Single-definition-site auth — esv-harness consumes acvp-harness transport via lib target; no duplicated mTLS/TOTP/token code. Probe(M): `grep -rnE 'Command::new|curl|extern .C.' esv-harness/src/`; 0 hits; control acvp-harness/src/transport.rs:33 matches
- [ ] ISC-31: ESV endpoint paths and payload shapes implemented from cited ESV-Server documentation. Probe(M): `sha256sum esv-harness/vendor/entropy-source-metadata-schema.json`; pinned digest in vendor/README.md:16-17
- [ ] ISC-32: Long upload survives token refresh mid-transfer. Probe(P): `cargo test -p esv-harness --lib poll_calls_the_token_provider_once_per_request`; datafiles.rs:2004-2006; judgment: no refresh inside a single in-flight transfer
- [ ] ISC-33: ESV noise-source description document covers operational description, entropy justification, and health-test description [DEFERRED — see Decisions]. Probe(M): TODO — ESV noise-source description document does not exist; registration.rs:38 forward-references it
- [x] ISC-34: oxicrypt-drbg instantiates from pipeline output through the module's entropy-input API. Probe(M): `cargo test -p oxicrypt-entropy --lib conditioned_output_seeds_module_gated_drbg`; pipeline.rs:672
- [x] ISC-35: All public items carry rustdoc — missing_docs denied. Probe(P): `grep -n missing_docs Cargo.toml`; Cargo.toml:64 is warn not deny; judgment: denial only via CI/pre-push RUSTFLAGS
- [ ] ISC-36: Doc examples compile and run. Probe(M): TODO — VACUOUS: zero runnable doc fences, cargo test --doc passes having compiled nothing
- [x] ISC-37: Collection runbook — one documented command per dataset type, resumable via a `collection-session.json` content-hash checkpoint that skips completed datasets on re-run. Probe(M): `cargo test -p oxicrypt-entropy --lib second_run_skips_completed_datasets`; collection.rs:1512-1513
- [x] ISC-38: rand-core feature passes RngCore contract property tests (fill_bytes/next_u32/next_u64 consistency). Probe(M): `cargo test -p oxicrypt-entropy --lib fill_bytes_various_lengths_fill_exactly`; rand_core_compat.rs:259
- [ ] ISC-39: Evidence-package index document enumerates all artifacts with paths and checksums [DEFERRED — see Decisions]. Probe(M): TODO — no evidence-index document exists
- [x] ISC-40: README states scope and 90B status honestly — no validation claims pre-cert. Probe(M): `git grep -n 'pre-validation — no entropy claims' README.md`; README.md:107; control lib.rs:10
- [ ] ISC-41: CHANGELOG maintained, releases tagged. Probe(M): `for v in CHANGELOG versions; do git rev-parse refs/tags/v$v; done`; 20 of 21 tagged; FLAG v0.1.0 has no tag
- [x] ISC-42: Anti: no overstated validation language ("validated", "certified") anywhere in repo docs pre-cert. Probe(P): `git grep -niE '(entropy source|this module|oxicrypt)[^.]{0,60}(is|are|has been) (FIPS[- ])?(validated|certified)'`; 1 benign hit; judgment: no automated lint enforces it
- [x] ISC-43: Anti: no conditioned output obtainable before startup tests pass. Probe(M): `cargo test -p oxicrypt-entropy --lib no_conditioned_output_before_startup`; pipeline.rs:561
- [x] ISC-44: Raw-data mode and conditioned-output mode structurally exclusive — `RawCollector` (no conditioner) and the live conditioned pipeline are distinct types constructed separately, not a runtime flag on one instance. Probe(M): `cargo test -p oxicrypt-entropy --lib raw_collector_is_distinct_type_without_conditioner`; raw.rs:1457-1459 compile-checked
- [x] ISC-45: Sample buffers and conditioner state zeroized on drop via oxicrypt-zeroize. Probe(P): `grep -n 'impl Drop' -A4 crates/oxicrypt-entropy/src/raw.rs`; raw.rs:484; judgment: nothing observes post-drop memory
- [x] ISC-46: Anti: no panic paths in the sample/health/conditioning hot path — no unwrap/expect/unchecked indexing. Probe(M): `awk scan for unwrap/expect/panic/index outside cfg(test)`; empty; CAVEAT jitter.rs:404 unwrap_or_else(|| unreachable!()) on sample path
- [x] ISC-47: Runtime timer-backwards violation yields typed error and sample discard. Probe(P): `cargo test -p oxicrypt-entropy --lib wrapping_delta_flags_backwards`; timer.rs:612-615; judgment: no test drives a backwards timer through sample()
- [x] ISC-48: Counter wraparound handled via wrapping delta arithmetic. Probe(M): `cargo test -p oxicrypt-entropy --lib wrapping_delta_handles_wraparound_32bit`; timer.rs:606
- [ ] ISC-49: Restart tests begin from clean health-test state — no carryover. Probe(M): TODO — on_demand_runs_from_clean_state asserts only the emitted count; its own comment promises to verify the monitor was REPLACED and never does
- [x] ISC-50: Send/Sync posture explicit via compile-time static assertions matching the concurrency design. Probe(M): `cargo test -p oxicrypt-entropy --lib send_sync_posture`; pipeline.rs:620-621; compile-time bound inside a test
- [x] ISC-51: Collection tool memory bounded on 1M+ sample runs. Probe(P): `cargo test -p oxicrypt-entropy --lib streaming_write_buffer_is_bounded`; collection.rs:1587; judgment: bound proven at 4x chunk, not 1M
- [ ] ISC-52: Interrupted esv-harness upload leaves resumable session state, no half-marked submissions [DEFERRED — see Decisions]. Probe(M): `cargo test -p esv-harness --lib persist_intent_then_leaves_a_dangling_intent_when_submit_fails`; session.rs:1435-1438
- [x] ISC-53: Anti: Debug/Display impls never expose raw samples or conditioned output. Probe(M): `cargo test -p oxicrypt-entropy --lib dataset_debug_never_exposes_sample_bytes`; raw.rs:1861-1864
- [x] ISC-54: maxwell never panics on malformed or arbitrary input files. Probe(M): `cargo +nightly fuzz run estimators -- -max_total_time=45 -rss_limit_mb=4096`; no in-tree test; fuzz target only
- [x] ISC-55: Dead source (constant symbols) trips RCT within spec-expected sample count. Probe(M): `cargo test -p oxicrypt-entropy --lib kat_dead_source_trips_rct_at_cutoff`; kat_tests.rs:50 tripped_at==Some(10)
- [x] ISC-56: Low-variety oscillating source trips APT within one window. Probe(M): `cargo test -p oxicrypt-entropy --lib kat_low_variety_trips_apt_in_first_window`; kat_tests.rs:69 tripped_at==Some(24)
- [x] ISC-57: All 90B spec constants in one cited consts module — spec revision is a one-module change. Probe(M): `grep -rnE '\b(1024|512|589|941|325|1_000_000|200_000)\b' crates/oxicrypt-entropy/src --include=*.rs | grep -v sp800_90b.rs`; empty; control: same grep ON sp800_90b.rs returns rows
- [x] ISC-58: A mock second NoiseSource exercises the full pipeline generically in tests. Probe(M): `cargo test -p oxicrypt-entropy --lib conditioned_output_seeds_module_gated_drbg`; pipeline.rs:665-666 via non-jitter PrngMock
- [ ] ISC-59: aarch64 target builds and tests in CI. Probe(M): TODO — no aarch64 CI runner; every job runs-on ubuntu-latest
- [ ] ISC-60: MSRV declared and enforced in CI. Probe(P): `grep -n rust-version Cargo.toml; grep -n channel rust-toolchain.toml`; Cargo.toml:47 / rust-toolchain.toml:2 agree; judgment: no MSRV job, nothing asserts they match
- [x] ISC-61: Datasets archived under the versioned layout `datasets/<oe-id>/<timer>/<boundary>/{raw.bin,restart.bin,metadata.json}` with a top-level sha256 manifest. Probe(P): `cargo test -p oxicrypt-entropy --lib layout_is_versioned_and_manifest_checksums_verify`; collection.rs:1477/1481 (verified==6 blocks an empty-manifest pass); judgment: no version segment is actually asserted in the path
- [ ] ISC-62: Comparison-harness output records maxwell version and EA tool version per run. Probe(M): TODO — no test asserts the version line at main.rs:588
- [ ] ISC-63: RawCounter path on aarch64 feature-complete, not stubbed, despite OsNanoClock default [DEFERRED — see Decisions]. Probe(M): `cargo check -p oxicrypt-entropy --features raw-counter --target aarch64-unknown-linux-gnu`; oxicrypt-timer/src/lib.rs:112-136 real asm; no test exercises it
- [ ] ISC-64: Semver discipline for 0.x documented in CONTRIBUTING. Probe(M): TODO — no 0.x breaking-change clause in CONTRIBUTING.md
- [ ] ISC-65: Anti: no design-intent gem text in any repo policy doc — only as-built. Probe(M): TODO — no banned-phrase grep; policy carries pending/TODO text at 2794/2881
- [x] ISC-66: jent-concept mapping table in design docs (osr→oversampling etc.) for reviewer familiarity. Probe(P): `sed -n '11,26p' docs/jent-concept-mapping.md`; :18 lineage->as-built row; judgment: no test guards the file
- [x] ISC-67: Health-test KAT vector files shipped — synthetic streams with known RCT/APT outcomes. Probe(M): `cargo test -p oxicrypt-entropy --lib kat_dead_source_trips_rct_at_cutoff`; kat_tests.rs:50; FLAG kat_healthy_stream_passes_in_full is vacuous on empty input
- [ ] ISC-68: Tests isolation-safe under the workspace nextest gate. Probe(P): `cargo nextest run --workspace`; pid+tag keyed temp roots; judgment: no test asserts isolation
- [x] ISC-69: unsafe confined to the timer-intrinsics module with safety comments; workspace unsafe-accounting doc updated. Probe(M): `cargo test -p doc-guard policy_states_the_as_built_accounting`; doc-guard/src/lib.rs:153 recomputed from disk
- [x] ISC-70: maxwell CLI mirrors ea_iid/ea_non_iid invocation shape. Probe(M): `shell diff of docs/ea-cli-mapping.md against main.rs dispatch`; shape documented, not asserted
- [x] ISC-71: MCV estimator matches EA v1.1.8 within pre-registered tolerance on bundled datasets. Probe(M): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MCV leg, parity.rs:722
- [x] ISC-72: Collision estimator parity, same terms. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Collision column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-73: Markov estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Markov column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-74: Compression estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Compression column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-75: t-tuple estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; t-tuple column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-76: LRS estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; LRS column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-77: MultiMCW prediction estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MultiMCW column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-78: Lag prediction estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; Lag column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-79: MultiMMC prediction estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; MultiMMC column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-80: LZ78Y prediction estimator parity. Probe(M): `OXICRYPT_EA_DATA=<bundle> cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; LZ78Y column across all 11 datasets; empty dataset dir fails ea_dataset_suite_is_provisioned
- [x] ISC-81: §5.1 permutation battery — 19 statistic slots (EA `permutation_tests.h:11-12`: the 11 §5.1 families, periodicity & covariance each ×5 lags {1,2,8,16,32}). TWO-LAYER parity vs EA v1.1.8: (L1) the 19 ORIGINAL unpermuted statistic values match within the pre-registered ≤1e-6 tolerance (deterministic, like §6.3 — ISC-93); (L2) IID/non-IID verdict per statistic + overall agrees on STABLE (non-boundary) datasets. maxwell uses its own fixed-seed shuffle (ISC-134) so it stays bit-reproducible (ISC-82). Probe(M): `cargo test -p oxicrypt-maxwell --lib parity_table_within_tolerance`; 19 slots, parity.rs:1063
- [x] ISC-81.1: §5.2 additional chi-square tests (independence binning + goodness-of-fit) implemented and verdict-parity-checked vs EA on both pass and fail directions. Probe(M): `cargo test -p oxicrypt-maxwell --lib rand4_short_anchor`; chi_square.rs:1167
- [x] ISC-81.2: §5.3 LRS (longest-repeated-substring) IID test implemented, reusing the §6.3.6 SA-IS suffix array (ISC-76), verdict-parity-checked vs EA. Probe(M): `cargo test -p oxicrypt-maxwell --lib oracle_noniid_fails`; iid_lrs.rs:289
- [x] ISC-81.3: IID-gate wiring — the combined §5 verdict (permutation ∧ chi-square ∧ LRS) routes maxwell's reported min-entropy: IID → §6.1 most-common-value only (ISC-71); non-IID → min over the §6.3 suite. Mirrors EA `iid_main` vs `non_iid_main`. Probe(M): `cargo test -p oxicrypt-maxwell --lib noniid_routed_value_is_suite_minimum`; iid_gate.rs:499
- [x] ISC-82: maxwell repeat-run determinism — results delta below documented epsilon. Probe(M): `cargo test -p oxicrypt-maxwell --lib determinism_bit_exact`; lib.rs:452/459 DET_EPS 1e-12; same-process repeat, not a re-invocation
- [ ] ISC-83: Restart-data analysis — 1000×1000 matrix; the §5 battery (permutation + chi-square + LRS) run on ROW data, verdict-parity-checked vs EA v1.1.8 `restart_main`. Probe(M): TODO — restart ROW-data §5 verdict unasserted (restart.rs:302-304)
- [ ] ISC-83.1: §5 battery ALSO run on the transposed COLUMN data (EA PR#250, `restart_main.cpp:800` — `perm_test_pass_col`) — column verdicts (perm + chi-square + LRS) parity-checked. Probe(M): TODO — restart COLUMN-data §5 verdict unasserted (same site)
- [x] ISC-83.2: §3.1.4.3 restart sanity check — α=1−exp(ln0.99/2000), X_max=max(X_r,X_c) vs the simulated cutoff; failure aborts with the documented message. Probe(P): `cargo test -p oxicrypt-maxwell --lib alpha_exact_1000 sanity_fails_skewed`; restart.rs:385/427-434; judgment: "failure aborts" is FALSE — maxwell restart exits SUCCESS on FAILED (#154)
- [x] ISC-83.3: Restart min-entropy = min(H_r, H_c, H_I) with the validation-fail gate min(H_r,H_c) < H_I/2 (EA `restart_main.cpp:835,882`). Probe(M): `cargo test -p oxicrypt-maxwell --lib validation_gate_logic`; restart.rs:445-455 min(h_r,h_c,h_i) + sanity-forces-failure
- [x] ISC-84: Core crate builds no_std — std surfaces feature-gated. Probe(M): `cargo check -p oxicrypt-entropy --no-default-features --target thumbv7em-none-eabi`; lib.rs:69 unconditional no_std
- [ ] ISC-85: Feature graph documented; std-only surfaces behind named features. Probe(M): TODO — documented feature graph omits rand-core declared at Cargo.toml:27
- [x] ISC-86: lama.yaml gains the oxicrypt-entropy API entry. Probe(P): `grep -n 'Entropy source' lama.yaml`; lama.yaml:67-69; judgment: capability-level entry, oxicrypt-entropy never named
- [ ] ISC-87: Startup self-test time benchmarked and documented — measured, not asserted [DEFERRED — see Decisions]. Probe(M): TODO — no startup-time benchmark exists
- [ ] ISC-88: Conditioned-output throughput benchmarked and documented per reference platform. Probe(M): TODO — no conditioned-output throughput measured anywhere
- [ ] ISC-89: maxwell 1M-sample processing benchmarked and documented. Probe(M): TODO — no maxwell bench target and no documented 1M processing figure
- [ ] ISC-90: ARM collection burst scripts auto-terminate instances — cost guard. Probe(M): TODO — no ARM burst / instance-termination tooling
- [x] ISC-91: x86_64 the pilot operational environment pilot = RawCounter × {lower, upper boundary} × {raw 1M, restart 1000×1000} = 4 datasets (OsNanoClock same-session optional cross-check), full metadata, §6.3-gated + periodicity-screen-passed (ISC-133), banked BEFORE any ARM spend — D-ENV sequencing. Probe(P): `cargo test -p oxicrypt-entropy --lib both_boundaries_emitted_per_oe`; collection.rs:1446-1448 shape only; judgment: no restart-dataset pilot figure or manifest committed; see #156
- [x] ISC-92: Security-policy entropy section drafted from as-built gems at Phase-0 close. Probe(J): `sed -n '2790,2830p' docs/security-policy/security-policy.md`; 9.3.1-9.3.6 + R78-R82; nothing verifies the prose against code
- [x] ISC-93: Estimator tolerance thresholds pre-registered — committed before the first parity run. Probe(P): `git log --diff-filter=A --date=short -- docs/estimator-parity-tolerances.md crates/oxicrypt-maxwell/src/parity.rs`; EA-parity ordering verified (de67889 < 2df83ea); judgment: independence tolerances landed in f8980c6 with the code they bound (#160)
- [ ] ISC-94: Login implements ESVP §2 — versioned-envelope POST /esv/v1/login with TOTP (30s/8-digit); refresh via TOTP+accessToken. Probe(M): `cargo test -p esv-harness --lib totp_matches_rfc6238_appendix_b_sha256_vector`; login.rs:1282 RFC 6238 Appendix B vector
- [ ] ISC-95: Bulk token refresh (POST /esv/v1/login/refresh, token array) for certify-time multi-token freshness. Probe(M): `cargo test -p esv-harness --lib bulk_refresh_posts_token_array_and_parses_response`; login.rs:847 order-preserving token array
- [ ] ISC-96: Registration payloads validate against the vendored entropy-source-metadata-schema.json, cited. Probe(M): `cargo test -p esv-harness --lib seeded_drift_is_caught`; preflight.rs:890-892 seeded mutation must fail the guard
- [x] ISC-97: Raw-data files emit exactly 1,000,000 samples, one byte per sample padding. Probe(P): `cargo test -p esv-harness --lib wrong_sample_count_is_caught`; preflight.rs:951-956; judgment: collection test runs at 4096, not 1M
- [ ] ISC-98: DataFileSampleSize sent v1.8-compatible (capitalized; case-insensitivity not assumed). Probe(M): `cargo test -p esv-harness --lib sample_size_field_is_capitalized_exactly_and_precedes_the_file`; datafiles.rs:1289-1290
- [x] ISC-99: Restart data = numberOfRestarts × samplesPerRestart (1000×1000) consistent between files and metadata. Probe(P): `cargo test -p oxicrypt-entropy --lib raw_file_size_matches_metadata_sample_count`; collection.rs:1411/1415; judgment: exercised at 8x256, the 1000x1000 values asserted without a file
- [ ] ISC-100: Multipart data-file upload shape per §6.1 matches reference-client behavior. Probe(M): `cargo test -p esv-harness --lib to_multipart_body_has_boundary_headers_part_key_and_capitalized_field`; datafiles.rs:1341-1344
- [ ] ISC-101: Data-file status polling handles all documented statuses incl. 30s not-yet-processed retry. Probe(M): `cargo test -p esv-harness --lib poll_retries_not_yet_processed_then_succeeds`; datafiles.rs:1706-1709 two 30s sleeps
- [ ] ISC-102: Supporting-doc upload enforces PDF-only and the sdType enum. Probe(M): `cargo test -p esv-harness --lib new_refuses_a_non_pdf_payload`; supportdocs.rs:406 NotPdf
- [ ] ISC-103: Certify builder enforces exactly-one EAR + exactly-one PUD + ≤1 DataCollectionAttestation. Probe(M): `cargo test -p esv-harness --lib full_certify_requires_exactly_one_ear`; certify.rs:948/951
- [ ] ISC-104: Conditioning registration uses exact ACVTS mode name "SHA2-256" + the module's CAVP validationNumber. Probe(M): `cargo test -p esv-harness --lib vetted_sha2_256_sets_exact_name_and_carries_validation_number`; registration.rs:730-733; negative control at :742
- [ ] ISC-105: Multi-OE registration — per-OE dataFileUrls and scoped tokens tracked. Probe(M): `cargo test -p esv-harness --lib parse_two_oe_response_yields_per_oe_urls_and_tokens`; registration.rs:946-955
- [ ] ISC-106: AddOE certify path implemented for staged dual-arch cert appends. Probe(M): `cargo test -p esv-harness --lib add_oe_builds_with_certificate_not_module`; certify.rs:1183-1190
- [ ] ISC-107: Anti: no conditionedBits upload attempted under vetted conditioning. Probe(M): `cargo test -p esv-harness --lib vetted_config_refuses_a_conditioned_upload_and_builds_no_request`; datafiles.rs:2061-2067; non-vacuous, :2092 shows non-vetted DOES build
- [x] ISC-108: SourceSpec sample-extraction explicit — emitted file symbols within min(bitsPerSample, 8) wire constraint. Probe(M): `cargo test -p esv-harness --lib over_wide_symbol_is_caught_at_its_index`; preflight.rs:966-972
- [ ] ISC-109: hminEstimate serialization from fixed-point H exact within schema bounds 0..bitsPerSample. Probe(M): `cargo test -p esv-harness --lib all_256_residues_round_trip_byte_exact_and_reconstruct`; hmin.rs:191-194
- [ ] ISC-110: Offline preflight validates payloads + files against vendored validation_rules before any server contact. Probe(M): `cargo test -p esv-harness --lib constraints_match_vendored_schema`; preflight.rs:876; own control at :888-892 seeded mutation must fail
- [ ] ISC-111: entropyId (TID) tracked per submission in the session store. Probe(M): `cargo test -p esv-harness --lib create_is_deterministic_and_empty_state_loads`; session.rs:1261-1262
- [ ] ISC-112: physical=false classification documented with rationale in the noise-source description. Probe(P): `sed -n '2797p' docs/security-policy/security-policy.md`; IG D.K R23 non-applicability; judgment: no test asserts physical==false on the wire
- [ ] ISC-113: GET status polling for entropyAssessments handles all 8 documented statuses. Probe(M): TODO — no entropyAssessments status poller exists
- [x] ISC-114: Jitter measurement loop optimization-proof — black_box/volatile discipline plus a release-build guard test asserting delta variance persists. Probe(M): `cargo test --release -p oxicrypt-entropy --features raw-counter release_guard`; jitter.rs:768-769; pre-push fails closed on zero-match filter
- [ ] ISC-115: max_claimable_h ceiling derived Müller-style — 4-LSB EA assessment with conservative per-delta claim, documented in the noise-source description. Probe(M): `cargo test -p oxicrypt-entropy --lib max_claimable_h`; jitter.rs:699 ceiling pinned at 1 bit, 4-bit width at :697
- [ ] ISC-116: Collection tool emits BOTH lower-boundary (tight-loop) and upper-boundary (normal-operation) datasets per OE. Probe(M): TODO — UNTICKED 2026-08-03 — collect_raw discards boundary (#156); probe must assert captures DIFFER
- [x] ISC-117: Per-OE acceptance gate is a `maxwell gate` subcommand encoding the §6.3 reuse thresholds as cited transcribed consts — raw > 0.333 bit/delta, restart min(row,col) ≥ half raw, restart > 0.333, sanity pass; consumes EA output until the maxwell suite is parity-complete, EA cross-check thereafter. Probe(M): `cargo test -p oxicrypt-maxwell --lib constants_match_spec`; gate.rs:408; subcommand wiring unasserted
- [x] ISC-118: Restart collection allocates a fresh source instance per restart round. Probe(M): `cargo test -p oxicrypt-entropy --lib restart_allocates_a_fresh_source_per_round`; collection.rs:1389 CountingFactory build count
- [x] ISC-119: Startup health-test samples discarded — never reused for output. Probe(M): `cargo test -p oxicrypt-entropy --lib startup_samples_are_discarded_never_reused`; pipeline.rs:450-452
- [ ] ISC-120: Evidence package includes independence analysis per OE — pairs/triplets min-entropy (≥10M deltas) + FFT pattern scan; collected in a follow-on ≥10M the pilot operational environment run after the minimal pilot and before ARM (A4/Q7 deferral). Probe(M): TODO — tooling exists and is oracle-tested; no >=10M capture, sidecar or replication note banked
- [x] ISC-121: maxwell implements 2D/3D min-entropy and FFT scan as evidence subcommands. Probe(M): `cargo test -p oxicrypt-maxwell --lib o2_dependence_detection`; independence.rs:1240; 2D/3D half only
- [x] ISC-122: H-derived oversampling enforces the full-entropy input margin (+64-bit clause, transcribed at build) — h_in ≥ n_out + margin. Probe(M): `cargo test -p oxicrypt-entropy --lib margin_holds_and_is_minimal_across_claims`; conditioner.rs:219-226 over 2048+ claims
- [ ] ISC-123: Sample-extraction step carries an explicit IG D.K Resolution-1 digitization justification — extraction neither conceals failures from health tests nor obscures raw statistics. Probe(M): TODO — substance uncited at jitter.rs:92-95; grep for IG D.K in *.rs returns 0
- [x] ISC-124: Any sample-size reduction for health testing justified per IG D.K R22 as not hiding failures. Probe(P): `grep -n 'no subsampling, windowed skipping, or reduced-rate testing' docs/security-policy/security-policy.md`; :2797; judgment: vacuous-by-design, and IG D.K R22 is cited nowhere
- [x] ISC-125: Documented α states its exact meaning — cutoff-generating α vs observed false-positive rate — per IG D.K R15. Probe(P): `sed -n '2800p' docs/security-policy/security-policy.md`; alpha meaning; judgment: crate doc health.rs:39-45 lacks the distinction
- [x] ISC-126: Conditioner is stateless across output blocks — no retained state between invocations (simplest IG D.K R5 posture). Probe(M): `cargo test -p oxicrypt-entropy --lib conditioned_blocks_are_stateless_across_blocks`; pipeline.rs:593 independent SHA over samples 161..=320
- [x] ISC-127: Security Policy entropy section states minimum entropy bits for SSP generation and per-output-bit estimate (9.3.A scenario 1 + D.J AC6). Probe(P): `sed -n '2822,2823p' docs/security-policy/security-policy.md`; :2823 >=384 bits; judgment: named D.J AC6 citation absent, and text carries [seeding-integration pending]
- [x] ISC-128: Known/suspected failure-mode statement documented, even if "none known" (90B §4.3 R1 + IG D.K R14; jent §6.1.42 precedent wording). Probe(P): `sed -n '2802,2810p' docs/security-policy/security-policy.md`; failure-mode inventory; judgment: doc-only, no test
- [ ] ISC-129: Every build phase consuming 90-series facts opens with a dated freshness sweep — IG changelog + SP 800-90 Updates page + ESV-Server repo — logged in this ISA. Probe(M): TODO — no per-phase freshness-sweep log; no rule requires one
- [x] ISC-130: Raw-data collection's characterization capture emits the noise stream UNFILTERED — startup health-test pass gates collection start, the live RCT/APT battery runs alongside and records every trip event into the dataset metadata, but no sample is ever silently dropped, filtered, or window-stitched. Probe(M): `cargo test -p oxicrypt-entropy --lib characterization_keeps_every_sample_and_annotates_trip`; raw.rs:1585-1596
- [x] ISC-131: Collection binary is a `bin` target behind a default-off `collection` feature; `RawCollector` is crate-private (absent from the public API); default + module build graphs are free of the collection tooling. Probe(P): `grep -n 'required-features|^default =' crates/oxicrypt-entropy/Cargo.toml`; Cargo.toml:16/51-53 + lib.rs:80; judgment: no compile-fail test, collection tests are themselves feature-gated
- [x] ISC-132: A certification-grade collection run that trips RCT/APT mid-run is invalidated and re-collected — the dataset submitted for a min-entropy estimate is a clean, contiguous, trip-free run; the unfiltered-annotated capture is retained only as characterization evidence, never window-stitched into a submission. Probe(M): `cargo test -p oxicrypt-entropy --lib certification_trip_invalidates_and_signals_recollect`; raw.rs:1842-1848
- [x] ISC-133: The minimal pilot runs a lightweight FFT + autocorrelation periodicity screen on the 1M raw dataset (distinct from the deferred ≥10M independence analysis); a dominant periodic component fails pilot acceptance. Probe(M): `cargo test -p oxicrypt-maxwell --lib pure_periodic_sawtooth_is_flagged`; periodicity.rs:583; synthetic sources only
- [x] ISC-134: Anti: maxwell's permutation shuffle never seeds from a non-deterministic source (no /dev/urandom, no system entropy) — unlike EA, which seeds xoshiro256 from /dev/urandom (`utils.h:580`); maxwell's seed is a fixed documented constant so every run is bit-reproducible. Probe(M): `cargo test -p oxicrypt-maxwell --lib determinism_test_bit_exact`; permutation.rs:1231, fixed SHUFFLE_SEED
- [x] ISC-135: `forbid(unsafe_code)` accounting is recomputed from disk and matches the security policy — 22 of 27 in-boundary crates carry it, with five audited exception crates named, not merely counted. Probe(M): `cargo test -p doc-guard policy_states_the_as_built_accounting`; doc-guard/src/lib.rs:153 recomputes from disk and fails by crate NAME, not count
- [x] ISC-136: README.md and AGENTS.md state the same as-built unsafe accounting as the security policy. Probe(M): `cargo test -p doc-guard readme_states_the_count_and_lists_every_crate agents_md_states_the_as_built_accounting`; the same accounting asserted in README.md and AGENTS.md
- [ ] ISC-137: Every approved algorithm has known-answer / ACVP vectors that pass. Probe(M): TODO — no single probe asserts every approved algorithm has passing KAT/ACVP vectors
- [x] ISC-138: Power-up self-tests run and gate operation — no approved service is reachable before they pass. Probe(M): `cargo test -p oxicrypt-integrity integrity_self_test`; power-up self-test executes and gates operation
- [ ] ISC-139: The cryptographic module boundary is formally defined, and its membership is derivable rather than asserted. Probe(M): TODO — module boundary is defined in prose; no probe recomputes its membership
- [ ] ISC-140: SSPs are zeroized on drop; the zeroization invariant is documented and tested. Probe(P): `cargo test -p oxicrypt-zeroize zeroize_clears_bytes`; judgment: proves the primitive, not that every SSP type calls it on drop
- [x] ISC-141: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean. Probe(M): `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`; both exit 0; a lint regression fails closed
- [ ] ISC-142: Anti: no non-approved algorithm is reachable through the validated module boundary. Probe(M): TODO — no probe asserts non-approved algorithms are unreachable through the boundary
- [x] ISC-143: Anti: no host path, private-project name, or internal context appears in any tracked file, including binary files. Probe(M): `git grep -nE '/home/[a-z]+|/Users/[a-z]+|C:\\Users' -- . ':!vendor'`; no output, exit 1; control: adding |oxicrypt matches README.md; VERIFIED to scan binary files, which is how the .pyc leak was found
- [ ] ISC-144: Root `lama.yaml` and `docs/llm-api-manifest/llm-api.yaml` match the public API surface. Probe(M): TODO — no probe compares lama.yaml / llm-api.yaml against the public API surface
- [ ] ISC-145: `oxicrypt-maxwell` matches EA v1.1.8 on input validation — a sample exceeding the declared `bits_per_symbol` is refused with a typed error and surfaced as a non-zero CLI exit, a narrower one warns and continues. Probe(M): `TODO(#152)`; maxwell must refuse a symbol wider than the declared bits_per_symbol, matching EA v1.1.8
- [x] ISC-146: `maxwell parity` exits non-zero when it did not compare everything; an all-skip or partially-skipped run is a failure unless explicitly opted out for that invocation, and the verdict says in words whether the run is evidence. The same fail-closed convention holds for `maxwell restart` and `maxwell gate`. Probe(M): `cargo test -p oxicrypt-maxwell --test cli_exit_codes` drives the real binary against an empty dataset directory and asserts the exit code, the wording, and that only the exact value `1` disarms the opt-out; `cargo test -p oxicrypt-maxwell --bin maxwell restart_verdict` covers the restart half, which cannot be driven through the CLI in-suite because a 1,000,000-sample analysis runs ~456s

## Test Strategy

Each criterion carries its own probe inline, tagged by kind. This section states how the probes are run
and what makes one trustworthy — it does not restate them.

| kind | meaning | obligation |
|---|---|---|
| `M` | a command returns the verdict | the probe clause carries the runnable command, not a description of one |
| `P` | a command plus a named judgment remainder | the command for the checkable part, and the judgment stated explicitly |
| `J` | judgment only | no command; naming it `J` is the point — it marks what the score does not cover |

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
| containment | `git grep -nE '/home/[a-z]+\|/Users/[a-z]+\|C:\\Users' -- . ':!vendor'` | must return nothing; scans binary files, which is how a committed `.pyc` leak was found |

**Build-directory constraint.** Gate runs set `CARGO_TARGET_DIR` to a machine-local path. Linking into a
shared target directory produces binaries against the build host's libc, which the machine that runs
them may not have.

**What the probes do not cover.** Criteria tagged `P` and `J`, and every criterion whose probe reads
`TODO`, are the uncovered share. They are tracked rather than hidden, because a measured criterion that
improves while an unmeasured one rots is worse than an honest gap.

## Features

Coverage of the workspace by articulated criteria. Crates with no criteria are not defects in themselves — they are the measured share of the module the contract does not yet speak to, made visible rather than left to inference.

| crate | boundary | criteria | notes |
|---|---|---|---|
| `oxicrypt-aes` | in | — | no articulated criteria |
| `oxicrypt-aes-accel` | in | — | audited `unsafe` exception |
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
| `oxicrypt-keccak-accel` | in | — | audited `unsafe` exception |
| `oxicrypt-lms` | in | — | no articulated criteria |
| `oxicrypt-maxwell` | out | 40 |  |
| `oxicrypt-ml-dsa` | in | — | no articulated criteria |
| `oxicrypt-ml-kem` | in | — | no articulated criteria |
| `oxicrypt-module` | in | — | no articulated criteria |
| `oxicrypt-rsa` | in | — | no articulated criteria |
| `oxicrypt-sha` | in | — | no articulated criteria |
| `oxicrypt-sha-accel` | in | — | audited `unsafe` exception |
| `oxicrypt-slh-dsa` | in | — | no articulated criteria |
| `oxicrypt-test-vectors` | in | — | no articulated criteria |
| `oxicrypt-timer` | in | — | audited `unsafe` exception |
| `oxicrypt-tls-kdf` | in | — | no articulated criteria |
| `oxicrypt-xmss` | in | — | no articulated criteria |
| `oxicrypt-xof` | in | — | no articulated criteria |
| `oxicrypt-zeroize` | in | — | audited `unsafe` exception |
| `acvp-harness` | tooling | — | outside the boundary |
| `esv-harness` | tooling | 18 | outside the boundary |
| `oxi` | tooling | — | outside the boundary |
| `benches` | tooling | — | outside the boundary |
| `tools/doc-guard` | tooling | — | outside the boundary |

## Decisions

Decisions in force, with the reasoning that makes each hard to vary. Superseded amendments and the
route taken to reach a decision are not recorded here — the git history and `CHANGELOG.md` hold those.

- **Three sanctioned `unsafe` categories, five audited crates.** In-boundary code is
  `#![forbid(unsafe_code)]` by default because it is a build-time control that enters the conformance
  argument, not a style preference. Three categories are sanctioned, each isolated in a small audited
  crate: **volatile CSP zeroization** (`oxicrypt-zeroize`, one `write_volatile` mechanism);
  **CPU-intrinsic acceleration** (`oxicrypt-sha-accel`, `oxicrypt-aes-accel`, `oxicrypt-keccak-accel`
  — feature-gated, default-off, runtime-detected, equivalence to the portable path proven by KAT plus
  a cross-path oracle); and **CPU timer/counter intrinsics** (`oxicrypt-timer` — read-only,
  side-effect-free, no cryptographic logic). Acceleration is admitted only where an oracle can prove
  byte-identical output, which is why the category is safe to widen and why each new member ships with
  its differential test. The default build graph contains no acceleration crate: the validated portable
  baseline is the shipping default. `oxicrypt-ffi` sits outside the boundary and necessarily carries
  `unsafe`. Current accounting — 22 of 27 in-boundary crates carrying `forbid`, five audited
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

**Probe inventory, 2026-08-03.**

| kind | count | meaning |
|---|---|---|
| `M` | see Criteria | a command returns the verdict |
| `P` | see Criteria | a command plus a named judgment remainder |
| `J` | see Criteria | judgment only — the share the score does not cover |
| `TODO` | see Criteria | the probe does not yet exist; the criterion is unverified and unchecked |

**Verified this session, with the command run and its result.**

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
