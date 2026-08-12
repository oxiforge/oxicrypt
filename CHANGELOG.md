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

- Fixed a panic in the CTR_DRBG derivation function on combined `entropy || nonce ||
  personalization` inputs of 152 to 192 bytes, across `instantiate_df`, `reseed_df`,
  `generate_df` and their C ABI mirrors. (#250)
- Corrected twelve SP 800-108 citations in `oxicrypt-kdf`. That document numbers the modes §4.1
  counter, §4.2 feedback and §4.3 double-pipeline; its §5 is Key Hierarchy. (#242)
- Corrected `oxicrypt-kdf`'s counter-width documentation. SP 800-108r1 permits any `1 <= r <= 32`;
  the restriction to byte-aligned widths is this implementation's. (#242)
- Corrected three SP 800-56C Rev. 2 citations in `oxicrypt-kdf` that named sections which do not
  exist. (#242)
- Corrected `oxicrypt-drbg`'s conditional-self-test section, which described repetition-count and
  adaptive-proportion tests. Neither exists here, and both are SP 800-90B entropy-source tests. (#242)
- Corrected `oxicrypt-drbg`'s module-gating claim. Four of twenty-two public entry points gate; the
  instantiate paths do, reseed and generate do not. (#242)
- Corrected `oxicrypt-drbg`'s health-test attribution. SP 800-90A §11.3 does not require error-path
  or uninstantiate testing; these checks exceed it. (#242)

- Corrected `oxicrypt-dh`'s rejection-sampling rationale, which gave the acceptance probability as
  about 50%. Computed from the group's own `q`, rejection is about 2^-66. (#242)
- Corrected three SP 800-56Ar3 citations in `oxicrypt-dh` from §5.6.2.3.1 to §5.6.2.3.2. The crate
  implements partial public-key validation. (#242)
- Corrected the description of `oxicrypt-dh`'s self-test, whose negative case is the order-2 element
  `p - 1` rather than a tampered peer key. (#242)
- Removed `oxicrypt-ecdh`'s claim that its pairwise-consistency comparison is constant-time. It is
  the derived equality on a byte array. The scalar-multiplication timing claims stand: ct-validation
  measures both CDH paths. (#242)
- Added `AlgorithmRestricted` to both `oxicrypt-ecdh` shared-secret error lists. (#242)
- Corrected `oxicrypt-tls-kdf`, documented as the TLS 1.2 KDF under SP 800-135. It also implements
  the TLS 1.3 KDF, which that document does not cover. (#242)

- Corrected `oxicrypt-eddsa`'s documentation, which described reduction, `muladd`, scalar
  multiplication and point compression as still to come. All of them ship. (#242)
- Removed three constant-time claims from `oxicrypt-eddsa` that no measurement covers: the field
  module's blanket claim, `ct_eq`, and `decompress`. (#242)

## [0.23.1] - 2026-08-10

- Every published crate carries a README. crates.io rendered a blank page for all of them.
- Crates inherit `homepage`, `keywords` and `categories`. All three reached the registry unset.
- The post-quantum crates carry their own keywords instead of the workspace set.
- `oxicrypt-cli` no longer advertises an `encrypt` command. There is none.
- The C header, both LAMA manifests and the crate descriptions say the module targets
  FIPS 140-3 Level 1 rather than asserting it.

## [0.23.0] - 2026-08-09

### Fixed

- SLH-DSA is no longer permitted under the CNSA profiles. **Breaking: a CNSA 2.0 caller invoking an SLH-DSA service now receives `AlgorithmRestricted`.** (#229)

- The CNSA profiles permit all 160 LMS services, previously 16. (#228)

- Module lifecycle tests no longer race on the process-global state. (#230)

## [0.22.0] - 2026-08-07

### Added

- The 29 crates making up the module's public surface are published to crates.io. The workspace set `publish = false` throughout development, so the roster was implied rather than stated; it is now a `publish = true` default with an explicit `publish = false` on the seven in-repo tools — `acvp-harness`, `esv-harness`, `oxicrypt-bench`, `oxicrypt-maxwell`, `ct-validation`, `doc-guard` and `quickstarts` — which never reach a registry. The test applied is whether a third party would name the crate in their own `Cargo.toml`, plus anything transitively required by one that would (#196).

- Prebuilt C libraries are published as release attachments: `.so`/`.dylib`/`.dll`, `.a`/`.lib` and `oxicrypt.h` for linux x86_64/aarch64, macOS x86_64/aarch64 and windows x86_64, each with its integrity slot signed, a `BUILD-PROVENANCE.txt` recording the toolchain and integrity MACs, and a SHA-256 checksum. Consuming the module from C no longer requires a Rust toolchain, and the artifact a user links is the one that was built here rather than one they compiled themselves (#205).
- LAMA manifest conformance is checked mechanically on every push. `scripts/check-lama-manifests.sh` runs the specification's conformance linter over every manifest in the tree and fails on any finding; the pre-push hook applies it to the revisions being pushed, and a CI job mirrors it. The linter runs in strict mode, because four of its six rules are advisory upstream and never move an exit code — a gate on the default contract would enforce two rules while appearing to enforce all six. The linter is vendored byte-identically from upstream with its origin and checksum recorded in `scripts/lama-validate.provenance`, verified on every run, so a copy weakened in-tree fails rather than silently reporting nothing (#175).
- The quickstart examples carried in the LAMA manifest are compiled. Each lives as a file under `tools/quickstarts/examples/`, built by the existing `--all-targets` gate, and a test asserts the manifest's copy is byte-identical to it. The check runs both directions, so an example no capability claims fails too and a file cannot be built for nobody. The specification requires a quickstart to compile and run unmodified and nothing compiles a YAML file — of the seven in the specification's own reference adoption, five no longer built against the API they described. Eight of the fourteen capabilities carry one (#192).

### Changed

- The command-line interface publishes as `oxicrypt-cli`; the binary it installs is still `oxi`. The crate name `oxi` has been registered on crates.io by an unrelated project since 2018 and is not available. `cargo install oxicrypt-cli` yields an `oxi` command, and nothing changes for anyone building from this repository.

- The SHA digest and block sizes are re-exported at the crate root of `oxicrypt-sha`, algorithm-prefixed: `SHA256_DIGEST_SIZE`, `SHA384_BLOCK_SIZE` and so on for all seven algorithms. `oxicrypt_sha::DIGEST_SIZE` was the path a caller forms first and it could never resolve — `DIGEST_SIZE` is defined in six submodules with six different values, so the bare name has no correct answer. The prefixed form gives each size one meaning at the root and matches what `sha512_t` already did internally with `DIGEST_SIZE_224`; the module-scoped names are unchanged (#192).
- Test fixtures no longer carry the `pqclib` project name: 77 occurrences across 19 files. All were test-only and reached no shipped artifact — `strings` on the built `.so` returns none — so this changes no behaviour a caller can observe. The `CHANGELOG` entries recording the original rotation keep the old name, being the history of it (#193).
- **The LAMA manifest now describes only what reaches crates.io.** `acvp-harness` and `esv-harness` are ACVP and ESV protocol clients that drive validation rather than part of the surface a consumer links against, and neither can be named in anyone's `Cargo.toml` — yet the manifest carried 36 functions, 50 types and 32 constants for them. Those move to `acvp-harness/llm-api-draft.yaml` and `esv-harness/llm-api-draft.yaml`, kept rather than deleted because both describe real library surfaces that would need manifests of their own if either is split out. `oxi`, `doc-guard`, `ct-validation` and `oxicrypt-bench` gain `modules:` entries so that every workspace crate now has one and an absent crate is unambiguously a defect — the condition that would have caught #174. The coverage rule in `AGENTS.md` collapses to a single sentence with no exceptions list (#208).
- **The integrity key, the slot magics, and the self-test message constants no longer carry the `pqclib` project name.** `FIPS_INTEGRITY_KEY` is now `oxicrypt-fips140-3-integrity-key`, the slot magics are `0xfc OXICRYPT_FIPS_H` / `0xfd OXICRYPT_FIPS_F`, the two RSA power-up KAT messages and the three pairwise-consistency probe messages are `oxicrypt`-prefixed, and the pinned RSA signatures are regenerated to match. **Any binary signed with the previous key or magics will fail its power-up integrity check and must be re-signed** — `fips-integrity-sign --sign` is the same command as before. Rotating these after validation would require re-validation under IG 10.3.A, so this is the last point at which the change costs a re-sign and a test run rather than a submission (#193).
- The `FIPS_INTEGRITY_KEY` doc comment named a key the module did not use: it stated an `oxicrypt-` prefix against a `pqclib-` constant, and the literal it named was 34 bytes where the type is `[u8; 32]`, so its own arithmetic disproved it. The doc now states the compiled literal, and a test reads the doc comment out of the source and asserts both the literal and its stated byte count against the constant, so the two cannot drift apart again (#193).

### Fixed

- `r7_keygen_pinned_regression` asserted only that the public key re-derives from the private scalar and that the scalar is non-zero. Both hold for any valid keypair from any seed, so the test could not detect a change in DRBG consumption order — the one thing it exists to catch. Confirmed by mutating the seed, which produced an entirely different keypair and left the test green. It now pins the `(d, Q)` bytes, and the same mutation fails it (#214).
- The pre-push security-policy containment scan no longer fails when there is nothing to scan. Its revision loop appended an empty string as though it were a revision whenever the enumerated set was empty, so the array was never empty, the fallback to `HEAD` never fired, and the scan's positive control failed against a revision that does not exist. An up-to-date push and a manual invocation of the hook both hit it, the latter meaning the hook could not be exercised by hand at all. Empty and null revisions are now discarded, an empty set is reported and skipped rather than scanned, and a manual invocation falls back to `HEAD` as intended (#198).

## [0.21.0] - 2026-08-06

### Removed

- `docs/jent-concept-mapping.md` is withheld alongside the Security Policy. It maps jitter-entropy lineage vocabulary to oxicrypt's as-built names for a reviewer already fluent in that lineage, and two of its three columns cite the Security Policy's own rule numbering — so most of it read as references a public reader could not follow. The middle column describes the as-built entropy source, which is public and documented in `oxicrypt-entropy`'s rustdoc; nothing is withheld here for its own sake. `docs/security-policy/README.md` says where it went, and the containment guards deny it by name alongside the policy.
- The FIPS 140-3 Security Policy is no longer tracked in this repository. It is held privately and disclosed per person; `docs/security-policy/README.md` takes its place at the path, explaining what the document contains, why non-publication rather than a license is the instrument, the honest bounds of that protection, how to request access, and which assertions a clone without it does not run. The 14 `.rs` sources whose rustdoc points at policy sections keep their pointers, as do `crates/oxicrypt-ffi/include/oxicrypt.h` and `crates/oxicrypt-maxwell/Cargo.toml`: all are prose references inside comments rather than links, and the directory they name now serves the README that explains where the document went.

### Added

- `scripts/check-internal-deps.sh`, run by `pre-push` against the commits being pushed: a normal or build dependency on a workspace member must carry a version requirement, a dev-dependency on one must not, and a path dependency outside the workspace must carry one. It reads `cargo metadata` rather than manifest text, so sub-tables, multi-line inline tables, unspaced values and `package = "..."` renames all arrive normalised, and a crate is covered when it joins the workspace rather than when someone adds it to a list. Placed above the tag-only short-circuit and the stamp cache: a release tag is the push whose version literals were just rewritten, and a manifest-only edit changes no Rust, so a cached state would otherwise skip it. Requires `jq`, and says so by name rather than failing as a workspace defect when it is absent (#196).

- `doc-guard`: `embedded_files_live_inside_their_package_root` and `embedded_lama_manifests_are_the_manifest`. `cargo publish` uploads a tarball of the package directory and the registry never fetches from the repository, so an `include_str!` reaching outside the package root builds here and fails for every consumer — permanently, since a published version is immutable. The first guard asserts no embed escapes, workspace-wide rather than scoped to the crates destined for crates.io: a roster-conditional rule changes meaning when a `publish` flag moves, which is how `oxi` acquired a latent blocker the moment it joined the roster. The second compares each embedded manifest against the canonical file, because git on Windows without `core.symlinks` checks a symlink out as a text file holding the target path, which would otherwise be embedded and published as the manifest with nothing reporting an error (#196).

- `doc-guard`: the Security Policy is resolved at runtime rather than read from the tree. Precedence is `$OXICRYPT_SECURITY_POLICY` — the file, or a directory containing `security-policy.md` — then `~/repos/oxicrypt-policy/security-policy.md`. The five guards asserting its content skip when it is unreachable, so a clone without the document runs green. `policy_resolution_precedence_holds` pins that order against synthetic inputs, because a resolver that resolved nothing would be indistinguishable from a clean skip.
- `doc-guard`: `security_policy_is_provisioned` — the same shape as `ea_dataset_suite_is_provisioned`, for the same reason. A skip prints to a stream a passing test discards, so an unprovisioned checkout would otherwise report the same green result as one that asserted everything about the document a CST lab reads. It departs from that precedent in one way, deliberately: it fires on *claimed* provisioning rather than on absence. The datasets are public, so failing when they are missing is right there; this document cannot be obtained by an outside contributor at all, and failing on its absence would reintroduce as a single failure exactly the hard failures that removing it from the tree exists to prevent. A checkout claims the policy by setting `$OXICRYPT_SECURITY_POLICY` or by having the sibling clone directory on disk; either one with the document unreadable fails, naming the path and the five guards that did not run, and an ordinary clone passes with a note. `OXICRYPT_SECURITY_POLICY_OPTIONAL=1` withdraws the claim explicitly. Its own positive control requires each named guard to carry both a `#[test]` attribute and the skip call that makes it a policy guard, so neither a rename nor a silently de-tested guard leaves the list describing something that no longer runs — `#[ignore]` is the one edit it cannot see, and says so.
- `doc-guard`: `the_security_policy_is_not_in_the_public_tree` — the inverse of every other check here, asserting a document is absent rather than that one is correct. Two detectors: a file-name sweep, and a phrase already present in the guard's own source, which catches a copy restored under a different name. The phrase sweep asserts it finds exactly the one file that legitimately carries the phrase, so a walk that reached nothing fails rather than reporting a clean tree — an earlier form checked the phrase through a separate read and passed with the walk pointed at a non-existent root. `vendor/` is swept, unlike `target/`: it is committed content that ships. A copy reflowed as it was moved evades both detectors, and neither says anything about git history; the guard is a backstop against accident, not an adversary, and says so.
- `pre-push`: the same containment scan, duplicated ahead of the tag short-circuit and the stamp cache and scanning the commits being pushed. The doc-guard test only runs under `cargo nextest run --workspace`, which the hook's Tier A escape skips when a push touches no Rust-relevant path — and `docs/` is not Rust-relevant, so restoring the policy was precisely the push shape that skipped the guard against it. Same reasoning the deny-list scan above it already carries: a leak check a cache can skip is not a leak check.
- `oxicrypt-maxwell`: `ea_dataset_suite_is_provisioned` — a fast provisioning gate that fails when any of the 11 EA v1.1.8 reference datasets, or either git-tracked IID-gate oracle under `tests/data/`, is absent, naming which. 33 skip-on-absence arms across 15 files resolve their data through `resolve_datasets_dir` or a `tests/data/` helper and return quietly when the file is missing, so without them the parity table, every per-estimator anchor and the assessed-assembly parity passed having compared nothing. The gate states that shared precondition once and fails in milliseconds rather than leaving a green suite that proved nothing. The tracked fixtures are not covered by the opt-out — a checkout lacking them is broken, not unprovisioned (#137).

### Changed

- Internal dependencies carry a version requirement. `cargo package` strips a dependency's path and records a registry requirement, which needs a version, so every crate depending on another oxicrypt crate failed to package — 27 of the 35 workspace members. The 29 internally-depended-on crates are now declared once in root `[workspace.dependencies]` with both a path and a version, and 141 member declarations inherit them with `{ workspace = true }`. Dev-dependencies deliberately stay path-only: cargo drops those when packaging, and a version turns one into a registry requirement no first publish can satisfy — `oxicrypt-sha` and `oxicrypt-keccak-accel` dev-depend on each other, so it is also a cycle. `esv-harness` keeps an explicit `oxicrypt-entropy` declaration because it is the only member setting `default-features = false`, which an inherited dependency cannot express. `scripts/bump-version.sh` moves the new literals (#196).

- The crates.io roster is stated in the manifests rather than implied. `oxi` — the command-line interface, which `cargo install` is the distribution path for — moves onto crates.io; `acvp-harness`, `esv-harness` and `oxicrypt-bench` move off it, joining `oxi`'s former company of `doc-guard`, `ct-validation` and `oxicrypt-maxwell` as in-repo tooling that never reaches a registry. The test applied is whether a third party would name the crate in their own `Cargo.toml`, plus anything transitively required by one that would; 27 crates are forced by that closure and the rest were judgement. `oxicrypt-bench` depending on the never-published `oxicrypt-maxwell` was the one structural contradiction, and it dissolves rather than needing a fix.

- The four crates embedding the LAMA manifest reach it through a symlink in their own package root instead of a path climbing out of it. The canonical file stays at `docs/llm-api-manifest/llm-api.yaml`; `cargo package` materialises the symlink's content into the tarball, so there is still one copy in git and now a real file in every published crate. Without this, `oxicrypt-ffi` and `oxi` could not be built from crates.io at all (#196).

- The pre-commit doc-sync hook's security-policy check is keyed on modification time rather than staged-ness, and resolves the policy the same way `doc-guard` does. Git cannot stage a file it does not track, so the previous "is it staged?" test could no longer fire at all. When the policy is not provisioned — the normal case for an outside contributor, who has no access to it — the check is skipped and says so on stderr, rather than blocking a contributor on a document they cannot read.
- CI: the workspace test job sets `OXICRYPT_EA_DATA_OPTIONAL=1`. The EA reference datasets are not provisioned on the runner, so CI has never validated SP 800-90B estimator parity — every EA-anchored test skipped silently. The flag makes that pre-existing fact explicit in the workflow rather than hidden in the skips; it does not change what CI covers. Whether to provision the datasets there is #153 (#137).
- `oxicrypt-maxwell`: the EA parity test is now a full-suite gate — an absent reference dataset fails the run instead of skipping it, so a run that compared nothing no longer reports the same green result as one that compared all 11. The failure names the missing datasets and where they were expected; the per-dataset table and the passed/skipped/failed tally are written to stderr as evidence. A checkout without the EA v1.1.8 bundle can set `OXICRYPT_EA_DATA_OPTIONAL=1` to downgrade the completeness check to a warning that states the run is not evidence of full-suite parity. The evidence table is emitted before the pass/fail assertions, so a genuine parity failure still prints the per-estimator deltas that diagnose it. The `quick` profile still excludes the ~200 s parity test, so the fast inner loop keeps its latency — but the new provisioning gate does run under `quick`, so an unprovisioned checkout now fails there too rather than iterating against nothing. `AGENTS.md` and `CONTRIBUTING.md` document where the datasets come from (#137).

- `oxicrypt-bench`: `conditioned_output` and `maxwell` benchmarks behind a new opt-in `entropy-bench` feature, a `gen_noniid` example that reproduces the timed input, and `docs/entropy-performance.md` recording what they measured on the reference platform (entropy-crate ISC-88/ISC-89). `conditioned_output` times `EntropyPipeline::conditioned_block` end to end — noise-source sampling, the continuous health battery, and SHA-256 conditioning — against the real `raw-counter` jitter source, which is the only source a benchmark can construct because `NoiseSource` is sealed and the mocks are test-only. `maxwell` times a full `iid_gate` assessment on both branches, asserting each synthetic input routes as intended before measuring, so two figures from the same branch cannot pass as a result. The measured asymmetry is ~270x at 8-bit, comparing like with like: a 1 M-sample capture assesses in 8.99 s on the IID branch and 2417.75 s on the non-IID branch, both at 8-bit symbols. At the module's own 4-bit sample width the non-IID branch takes 1829.27 s, with no same-width IID figure to divide it by; widening the alphabet from 4 to 8 bits costs +32% wall-clock and +90% peak memory, so the default run uses 1 M for the former and 100 k for the latter, with `OXICRYPT_BENCH_MAXWELL_FULL=1` raising it. The documented figures carry their qualifiers: the conditioned-output number is a hot-loop steady state on a KVM guest and is not the pilot operational environment's figure; the IID assessment number is a best case, because the §5.1 permutation battery exits early once all 19 statistics are decided; and the IID assessment figure still uses 8-bit symbols, wider than the 4-bit samples this module's jitter source emits (#138).
- The dependencies the entropy benchmarks need are optional and gated on `entropy-bench` rather than plain dependencies of the bench crate. Cargo unifies features across an invocation, so a plain `oxicrypt-entropy = { features = ["raw-counter"] }` would enable `raw-counter` for every `--workspace` command — re-arming the live jitter tests that `scripts/git-hooks/pre-push` deliberately excludes for being load-dependent on a virtualized counter, making `raw_counter_unavailable_without_feature` assert nothing, and overriding `esv-harness`'s explicit `default-features = false` so an audited-`unsafe` crate would enter its binary. The default workspace graph is unchanged (#138).

### Changed

- `oxicrypt-maxwell`: `independence` reads tuple occupancy off the MCV histogram instead of a separate `BTreeSet` walk. `analyze` encoded the phase-0 pair and triplet streams a second time solely to feed that walk; the histogram `mcv_from_codes` already builds holds the same count as its nonzero-slot total, so both extra encodings and the set are gone. Reported occupancy is unchanged: with over-wide input refused at the top of `analyze`, no code can be dropped by the histogram's range guard, so the histogram's count and a plain distinct-count of the same codes coincide. Exact MCV counts and min-entropy are untouched (#127).

### Fixed

- `maxwell parity` no longer exits zero when it compared nothing: an all-skip or
  partially-skipped run is a failure unless `OXICRYPT_EA_DATA_OPTIONAL=1` is set for that
  invocation, and the closing verdict states in words whether the run is parity evidence
  (#154).
- `maxwell restart` no longer prints a FAILED verdict and exits zero; a rejected
  §3.1.4.3 sanity check or §3.1.4.2 validation gate now exits non-zero, matching
  `maxwell gate` (#154).
- `maxwell restart` refuses a degenerate restart matrix — an alphabet of one, or an
  `H_I` implying more equiprobable symbols than the matrix contains — instead of
  tripping a debug assertion (exit 101, no verdict) or, in release, drawing the
  §3.1.4.3 cutoff over symbols the data never contained. A non-finite `H_I` is
  rejected at parse (#154).
- `maxwell independence` refuses a dataset containing a sample wider than the declared
  `BITS_PER_SYMBOL` instead of assessing it, matching the NIST EA v1.1.8 reference. The
  tuple encoder does not mask, so an over-wide sample produced a code outside the
  `2^(k·bits)` alphabet which the histogram discarded while the denominator still
  counted it — the reported min-entropy was computed over a fraction of the data (93%
  of samples discarded at 4 bits/symbol over full-range bytes) and inflated by an
  arbitrary amount. `independence::analyze` now returns `Result` and the CLI exits
  non-zero, naming the widest sample and the index of the first offender; a refused run
  writes no evidence sidecar. A *narrower* observed width warns and continues (#152).

## [0.20.0] - 2026-07-25

### Added

- `acvp-harness`: LMS `sigGen` and `sigVer` registration under the ACVP `SP800-208` revision, alongside the existing `1.0` handlers — a distinct catalog service carrying a top-level `messageLength` domain (variable-length messages) that revision `1.0` does not have; there is no `keyGen` counterpart because key generation has no message. Verification and signing are unchanged: both group handlers already decode each test's `message` without a fixed-size assumption, so the same code paths serve both revisions. `LMS / sigVer / SP800-208` graded passed on the ACVTS demo server (320 cases across all 80 (lmsMode, lmOtsMode) pairs at 128/1024/8192-bit messages) (#143).
- `acvp-harness`: `--revision <rev>` filter for `demo-run`, narrowing registration to one ACVP revision when an `(algorithm, mode)` pair is served by handlers for several. It is how the caller says which revision was meant once a pair serves more than one — `--algorithm LMS --mode sigVer` matches both, which is refused rather than registered twice (see Fixed) (#143).
- `oxicrypt-entropy` (`collection` feature): `collect --claim <H>` — sets the per-OE min-entropy claim, constrained to the non-binary APT grid rows ({0.5, 1, 2, 4, 8}, derived from `APT_ALPHA30_NON_BINARY`); an off-grid or unparseable value is refused with a typed error naming the valid grid (never silently rounded to a neighbouring row), the claim is recorded in the dataset `metadata.json` (`claimed_h_steps`), and absence keeps the tool default (H = 1). α is unchanged. Out-of-boundary tooling; the validated library surface is unchanged (#126).
- `oxicrypt-entropy` (`collection` feature): `collect --characterization <N>` mode — captures, per boundary, a single contiguous `N`-sample run to `characterization.bin` under the characterization posture (health battery live, trips annotated, never dropped or stitched), with the versioned `metadata.json` sidecar marked `"characterization": true`. Backs the per-OE `maxwell independence` / `maxwell periodicity` evidence (ISC-120). Out-of-boundary tooling; the validated library surface and public entry point are unchanged.
- `oxicrypt-maxwell`: `independence` subcommand — 2D/3D (pairs/triplets) min-entropy independence evidence for the per-OE entropy assessment (ISC-121). Three legs: the full literal §6.3 estimator battery on the disjoint-pair stream at both phase offsets (`pair_suite_min/2`), confidence-bound tuple-MCV on pairs and triplets (multi-phase, triplets MCV-only), and a deterministic K=10 shuffled-baseline null; a claim-anchored FLAG (advisory-only below the 10 M precedent minimum), an `independence-results.json` sidecar, and pre-registered O1–O4 oracles (`docs/estimator-parity-tolerances.md`). Out-of-boundary analysis tool; no EA analog (evidence subcommand).
- `tools/doc-guard`: test-gate drift guard whose tests recompute the boundary/`unsafe` accounting from the workspace on disk (crate count, out-of-boundary set, `forbid(unsafe_code)` ratio, audited-exception names, exported-FFI-function count) and assert the values stated in `security-policy.md` §1/§9.2/§3.1, `AGENTS.md`, and `README.md` match (#101).
- `esv-harness`: new out-of-boundary ESV submission client for SP 800-90B entropy-source validation, driving the full ESVP 1.0 flow over `acvp-harness`'s curl(1)/mutual-TLS transport with zero network and zero third-party dependencies in every automated path. Authentication: ESVP login, single-token and bulk token refresh (tunable proactive margin, reactive 401/403 retry, TOTP-window-reuse retry, and a fresh-login fallback when a stale-token refresh is rejected). Registration: the entropy-source metadata payload builder (multi-OE, vetted SHA2-256 conditioning with a required CAVP validation number) plus the multi-OE response parser. Preflight (offline, before any server contact): a payload preflight drift-guarded against the vendored NIST metadata schema, and a data-file preflight — exactly 1,000,000 one-byte-per-sample symbols, symbols within the effective `min(bitsPerSample, 8)` width, the mandated 1000×1000 restart layout, and `DataFileSampleSize` consistency — checked against the module's own SP 800-90B constants so validator and dataset emitter cannot drift. Data files: the multipart upload builder (capitalized `DataFileSampleSize` for server v1.8), a bounded processing-status poll over all seven documented statuses that captures NIST's returned assessment as an independent entropy-assessment oracle, and a typed refusal of any conditioned-bits upload under vetted conditioning. Supporting documents: a PDF-only upload with the supporting-document-type enumeration. Certify: the full-submission, add-operating-environment, and update-PUD request builders enforcing exactly-one-EAR / exactly-one-PUD / at-most-one-attestation cardinality, distinct entropy-assessment ids, the required cross-program identifiers, and a non-IID assessment's restart-test-upload precondition. Session: a resumable per-submission store with an intent-then-outcome event log — each network step records its intent (locally-known data) before the call and its outcome after, both fsync'd, so an interrupted step resumes flagged for verification rather than blindly re-submitted; the log tolerates a torn final line, dedups registration replays, and validates every path component. `hminEstimate` is serialized exactly from the module's fixed-point min-entropy type (1/256-bit steps) as a finite decimal with no float on the claim path, round-tripped byte-for-byte through a lossless response reader whose status read rejects duplicate keys and whose poll absorbs a valid-JSON-but-not-envelope body under its transient budget. Uploads escape and validate multipart part names/filenames against header injection.

### Changed

- `oxicrypt-maxwell`: `independence` analysis allocates sparsely — the tuple-MCV histogram is sized by the codes present via a `HashMap` instead of a dense `2^(k·bits)` array (the 8-bit triplet leg no longer zeros a `1<<24`-slot array per phase, ~33× per run), tuple counts use the closed form `⌊(n−phase)/k⌋` instead of encoding the stream to read its length, and pair encoding writes `u8` directly; exact MCV counts and min-entropy are unchanged (#127).
- `oxicrypt-maxwell`: the periodicity screen's spectral-peak detector searches bins `>= SPECTRAL_MIN_BIN` (8), excluding the lowest bins from both the peak search and the mean-power denominator, so slow low-frequency drift no longer trips the screen; a periodic line at bin 8 or above is unaffected and the autocorrelation detector is unchanged (#102).
- `oxicrypt-lms` (`parallel` feature): `keygen_from_parts` (the ACVP/harness keyGen entry) derives the Merkle root from the parallel `build_node_table` leaf sweep, so a tall-tree keyGen under `--features oxicrypt-lms/parallel` runs multi-threaded instead of single-threaded; the root is byte-identical to the serial recursive `compute_root` by construction (R75). The CMVP-validated default build and the gated `keygen()` / `keygen_internal` remain serial. A parallel-vs-serial keyGen root-equality oracle is added at H=15 and (ignored, pre-submission) H=25 (#129).

### Fixed

- `acvp-harness`: `demo-run` refuses a capability set that registers the same `(algorithm, mode)` under two ACVP revisions, naming them, instead of silently emitting a vector set for each and re-grading coverage that already passed. Registering LMS under a second revision had doubled the long-standing `--algorithm LMS --mode sigVer` invocation from one vector set to two. The check is keyed on that duplicate rather than on a registration count, so several *modes* registering at once stays permitted — `--algorithm ECDSA` without `--mode` has always produced one vector set per mode — and so the remedy stays correct for a mode-less algorithm that gains a second revision, where the fix is `--revision` and demanding `--mode` would register nothing at all. Runs before the transport opens, so a refused invocation costs no login and no YubiKey touch (#144).
- `oxicrypt-entropy`: `collect` default claim uses the ratified `Alpha::DEFAULT` (2⁻³⁰) instead of the 2⁻²⁰ recommended-minimum constant (#126).
- `oxicrypt-entropy`: noise workload is per-round variable — hash-chain iterations (1–8) and steered walk touches (32–95, plus the 32 digest-addressed touches) derive from an XOR-fold of the last measured timer delta; dataset `collection_params` strings name the new workload; `ensure_varied` gains a hard distinct-delta floor of 2 (#125).
- `oxicrypt-entropy`: two-stage timer-adequacy check — bare reads gate monotonicity/coarseness; delta variety is gated on workload-measured deltas via a separate `workload_samples` knob (default 256); `TimerError::Inadequate` carries the measured `AdequacyReport`; `JitterSource` exposes `adequacy()` (workload signal) and `bare_adequacy()`; pre-push gate gains a fail-closed release-profile construction-guard step (#124).
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

[Unreleased]: https://github.com/oxiforge/oxicrypt/compare/v0.23.0...HEAD
[0.23.0]: https://github.com/oxiforge/oxicrypt/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/oxiforge/oxicrypt/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/oxiforge/oxicrypt/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/oxiforge/oxicrypt/compare/v0.19.0...v0.20.0
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
