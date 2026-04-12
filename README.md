# pqclib

Pure-Rust FIPS 140-3 Level 1 cryptographic module.

This project implements FIPS-approved cryptographic algorithms in pure Rust
with a module boundary, power-up self-tests, and an ACVP test harness, with
the goal of supporting CAVP algorithm validation and CMVP module validation
through an accredited CST laboratory.

Target: **FIPS 140-3 Level 1**, following the latest FIPS 140-3 Implementation
Guidance (currently IG D.G as of March 2026).

See [`docs/rust-fips-project-plan.md`](docs/rust-fips-project-plan.md) for the
full project plan, architecture, algorithm inventory, phase breakdown, and
compliance mapping.

## Status

**Phase 2 — in progress.** The cryptographic core is taking shape under the
power-up self-test harness, with 122 KATs running green — 119 CAVP-sourced
known-answer tests (including 9 SP 800-90A §9.3 prediction-resistance DRBG
KATs) plus 3 SP 800-90A §11.3 DRBG health tests, every vector traceable to
its published source.

### Implemented (with power-up KATs)

- **Hashing** — SHA-1, SHA-2 (224/256/384/512/512-224/512-256), SHA-3
  (224/256/384/512), SHAKE128, SHAKE256 (FIPS 180-4, FIPS 202).
- **MAC** — HMAC over all eleven approved hashes (FIPS 198-1), AES-CMAC
  (SP 800-38B, AES-128/192/256).
- **DRBG** — CTR_DRBG (SP 800-90A §10.2) with AES-128/192/256, in both
  `no df` and `use df` variants; Hash_DRBG (SP 800-90A §10.1.1) over
  SHA-256, SHA-384, and SHA-512 with the §10.3.1 `Hash_df` derivation
  function; HMAC_DRBG (SP 800-90A §10.1.2) over HMAC-SHA-256,
  HMAC-SHA-384, and HMAC-SHA-512; SP 800-90A §9.3 prediction-resistance
  generate API with CAVP `drbgvectors_pr_true` KATs for every Hash/HMAC
  mechanism and for each CTR_DRBG AES key size; SP 800-90A §11.3
  error-path health tests (generate-before-instantiate, reseed-counter
  ceiling, post-uninstantiate access) for each mechanism.
- **KDF** — SP 800-108r1 Counter / Feedback / Double-Pipeline Iteration
  modes (`fips-kdf`); SP 800-56C Rev 2 Two-Step KDA-HKDF; RFC 5869 HKDF
  over all eleven HMACs.
- **Symmetric** — AES-128/192/256 block cipher (FIPS 197); ECB, CBC, CTR,
  GCM, and CCM modes (SP 800-38A / SP 800-38C / SP 800-38D); Key Wrap (KW)
  and Key Wrap with Padding (KWP) per SP 800-38F / RFC 3394 / RFC 5649.
- **RSA** — RSA-2048 PKCS#1 v1.5 and PSS sign/verify (FIPS 186-5 §5.4–5.5),
  RSA-2048 probable-prime keygen per FIPS 186-5 §A.1.3 with a pairwise
  consistency test (IG 10.3.A) and a pinned-DRBG-seed regression KAT.
  CRT sign path (Garner recombine over 1024-bit Montgomery contexts)
  with Shamir/Bellcore verify-after-sign per IG D.G, wired through
  both PKCS#1 v1.5 and PSS sign entry points. RSA-2048 OAEP
  encrypt/decrypt with SHA-256/MGF1-SHA-256 (RFC 8017 §7.1,
  SP 800-56Br2 KTS-OAEP), Manger-resistant decode, and CRT decrypt
  path sharing the Bellcore-protected private-exponent primitive.
- **Elliptic curves** — ECDSA P-256 sign (caller-supplied `k` and
  DRBG-backed random-`k` wrapper), verify, public-key derivation,
  and DRBG-backed key generation via FIPS 186-5 §A.2.2 rejection
  sampling with an IG 10.3.A pairwise consistency test on every
  constructed `EcdsaP256PrivateKey` (FIPS 186-5 §6.4, §A.2). Full
  SEC1 public-key validation (SP 800-56Ar3 §5.6.2.3.3) on verify.
  ECDH P-256 (SP 800-56Ar3 §5.7.1.2 ECC CDH) with RFC 5903 §8.1
  power-up KAT. Ed25519 deterministic sign/verify per RFC 8032
  and FIPS 186-5 §7.8 with a DRBG-backed `Ed25519PrivateKey`
  handle, RFC 8032 §5.1.5 scalar clamping, non-cofactored verify
  equation, canonical-`S` rejection, and an IG 10.3.A sign-and-
  verify pairwise consistency test on every constructed handle.
- **Module integrity** — HMAC-SHA-256 software/firmware integrity check
  over `current_exe()` with an embedded 64-byte reserved slot populated at
  sign time and validated by magic-marker scan at boot (FIPS 140-3
  IG 10.3.A). Designed to work identically on Linux/macOS/Windows CLIs and
  on code-signed iOS `.app` bundles and Android APKs.

### Documentation

- **Rustdoc** — every `fips-*` crate's `lib.rs` header follows a common
  template: approved-services table, power-up self-tests, conditional
  self-tests, sensitive security parameters, side-channel posture, and
  FIPS-module gating. Build the full doc tree with
  `cargo doc --workspace --no-deps` and browse `target/doc`.
- **Security Policy (alpha draft)** —
  [`docs/security-policy/security-policy.md`](docs/security-policy/security-policy.md)
  follows the SP 800-140Br1 Annex A section order and is kept in sync
  with the rustdoc headers at every commit. Sections that still need a
  human decision are marked `TODO`.

### ACVP / CAVP traceability

- NIST `usnistgov/ACVP-Server` is vendored at pinned commit
  `3611942ea10c070dd8bc6afec5682d56c307de8a` under `vendor/nist/` using a
  slim-slice strategy (per-algorithm `kat-slice.json` plus a
  `MANIFEST.toml` carrying SHA-256 metadata and selected tgId/tcIds).
- Tooling in `tools/acvp-gen/` regenerates the test-vector constants in
  `crates/fips-test-vectors/src/generated.rs` from the vendored vectors,
  cross-validated against Python reference implementations.
- Every SHA, SHAKE, HMAC, HKDF, AES, and AES-CMAC KAT carries a citation
  to its source document (FIPS 197 Appendix C, SP 800-38A Appendix F,
  McGrew-Viega Appendix B, SP 800-38B Appendix D, RFC 3394 §4,
  RFC 5649 §6, NIST CAVP CCMVS VPT vectors, and the ACVP-Server slim
  slices).

### Running the harness

```bash
cargo build -p acvp-harness -p fips-integrity
./target/debug/fips-integrity-sign --sign target/debug/acvp-harness
./target/debug/acvp-harness
```

The harness performs module-boundary initialization, runs the 122 power-up
KATs, runs the software integrity self-test, and prints the full KAT
inventory. As of R10 it also gains a `dispatch` subcommand that processes
ACVP `internalProjection`-style vector sets end to end:

```bash
./target/debug/acvp-harness dispatch \
    vendor/nist/acvp-server/gen-val/json-files/SHA3-256-2.0/kat-slice.json \
    /tmp/sha3_response.json
```

R10 wired the first two handlers — `SHA3-256` revision `2.0` AFT and
`HMAC-SHA2-256` revision `1.0` AFT — as a proof of the envelope layer.
R12-A expanded that to seventeen AFT handlers (the full SHA-3 hashing
family, both SHAKE XOFs, `HMAC-SHA-1`, and every `HMAC-SHA-2` /
`HMAC-SHA-3` variant). R12-B then adds a **second envelope shape** for
plain FIPS 180-4 hashing: CAVP SHS `.rsp` short-message byte vectors,
accessed via a new `dispatch-shs` subcommand:

```bash
./target/debug/acvp-harness dispatch-shs SHA-256 \
    vendor/nist/cavp-shs/shabytetestvectors/SHA256ShortMsg.rsp \
    /tmp/sha256_response.json
```

Seven CAVP SHS handlers are wired in R12-B — `SHA-1`, `SHA-224`,
`SHA-256`, `SHA-384`, `SHA-512`, `SHA-512/224`, `SHA-512/256` — because
upstream `usnistgov/ACVP-Server` ships no top-level `SHA-*`, `SHA1-*`,
or `SHA2-*` `internalProjection` directories at the pinned commit; R11′
retired the earlier deferral that wrongly framed this as an ACVP-Server
re-pin blocker. R13 then wires the first KDF family handler,
`KDA-HKDF-Sp800-56Cr2`, which is also the first ACVP family in pqclib
to publish across a `(algorithm, mode, revision)` tuple
(`algorithm = "KDA"`, `mode = "HKDF"`) rather than the one-field
`(algorithm, revision)` shape R10/R12-A/R12-B used. The dispatch
registry now keys on all three axes uniformly; single-field families
return the default `mode = None` and keep their existing shape. The
`kda_hkdf` handler implements SP 800-56C Rev 2 §5.9.2's hybrid two-step
KDF (`IKM = Z || T`, `PRK = HMAC-Extract(salt, IKM)`, `OKM =
HKDF-Expand(PRK, fixedInfo, L/8)`) over ten HMAC instantiations —
`SHA2-{224, 256, 384, 512, 512/224, 512/256}` and
`SHA3-{224, 256, 384, 512}`. R14-A then adds the first symmetric-cipher
handlers — `ACVP-AES-{ECB, CBC, CTR}-1.0` AFT across all three key
sizes (128/192/256), in both directions — reaching twenty-one
registered handlers. Round-trip tests in
`acvp-harness/tests/round_trip.rs` and
`acvp-harness/tests/shs_round_trip.rs` prove all four dispatchers
reproduce the vendored `md` / `mac` / `dkm` / `ct` / `pt` fields
byte-for-byte across twenty-two ACVP slices and seven CAVP SHS files. The JSON parser, hex
codec, and CAVP SHS `.rsp` parser used by the harness are all in-tree —
the validation binary has zero third-party dependencies, matching the
module itself. Remaining algorithm families (AES, DRBG, ECDSA,
EdDSA, RSA) and remaining test types (MCT, LDT) slot into the same
dispatchers without touching the envelope layers.

### Constant-time validation

```bash
cargo run -p ct-validation --release --
cargo run -p ct-validation --release -- --samples 500000 ecdsa_p256_scalar_invert
```

`tools/ct-validation` is a dudect-style paired fixed-vs-random timing
harness that runs Welch's t-test with percentile cropping across seven
CSP-touching primitives (`mont2048`/`mont1024` `pow_secret`, OAEP decode,
P-256 scalar-mul, P-256 scalar invert, ECDH P-256 CDH, and Ed25519
base-point scalar mult). Verdicts: `|t|≥5`
is `LEAK`, `|t|≥3` is `WARN`, else `CLEAN`. The harness found and the
same R8 change fixed two real leaks — a data-dependent carry-propagation
early exit in the `fips-ecdsa` Montgomery reducer and an identity
short-circuit in the P-256 mixed-addition that made the scalar-mul
ladder's per-iteration cost depend on the number of leading zero bits of
the secret scalar. Full reporting protocol, verdict table, and the list
of known-noise fluctuations are in §12.1 of the security policy.

### In flight

- Ed448, ECDSA P-384 / P-521
- ACVP harness vector dispatch: DRBG, ECDSA, EdDSA, RSA handlers; MCT and LDT test types; remaining AES modes (GCM/CCM/KW/KWP). The SHA-3 hashing family, both SHAKE XOFs, and every HMAC variant are wired as of R12-A (17 AFT handlers on the ACVP envelope). R12-B then wired the full SHA-1 / SHA-2 family (seven handlers: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) on a second envelope shape over CAVP SHS `.rsp` byte vectors, because upstream `usnistgov/ACVP-Server` does not publish `SHA-*`/`SHA1-*`/`SHA2-*` `internalProjection` directories at all. R13 wired `KDA-HKDF-Sp800-56Cr2` (ten HMAC instantiations, hybrid shared-secret form) as the first mode-keyed ACVP handler. R14-A added the first three AES block-cipher AFT handlers — `ACVP-AES-{ECB, CBC, CTR}-1.0` over all three key sizes in both directions.

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.
See [`LICENSE`](LICENSE) for the full text.

In short: you may use, modify, and share this software for any
noncommercial purpose. Commercial use requires a separate license —
please open an issue if you would like to discuss commercial terms.
