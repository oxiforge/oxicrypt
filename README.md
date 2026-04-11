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
- **Module integrity** — HMAC-SHA-256 software/firmware integrity check
  over `current_exe()` with an embedded 64-byte reserved slot populated at
  sign time and validated by magic-marker scan at boot (FIPS 140-3
  IG 10.3.A). Designed to work identically on Linux/macOS/Windows CLIs and
  on code-signed iOS `.app` bundles and Android APKs.

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
inventory.

### In flight

- RSA (PKCS#1 v1.5, PSS, OAEP), ECDSA, EdDSA, ECDH
- ACVP harness vector dispatch (Phase 3)

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.
See [`LICENSE`](LICENSE) for the full text.

In short: you may use, modify, and share this software for any
noncommercial purpose. Commercial use requires a separate license —
please open an issue if you would like to discuss commercial terms.
