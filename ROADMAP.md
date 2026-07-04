# Roadmap — oxicrypt

Forward-looking work that is **not yet a deliverable**. Concrete, scoped work lives in
[GitHub Issues](https://github.com/oxiforge/oxicrypt/issues) (with `tier:` labels); release
history lives in git tags + `CHANGELOG.md`. This file holds only what is still upstream of an
issue — no status, no history. When an item is decomposed into actionable work it **becomes a
GitHub issue and is removed from here**.

## Ideas

*(speculative — none captured yet.)*

## Designs

*(design-first epics — one-line pointers to `docs/design/*.md`.)*

- **AVX2/AVX-512 Keccak** — tracked in [#110](https://github.com/oxiforge/oxicrypt/issues/110); design-of-record at [`docs/design/avx2-keccak.md`](docs/design/avx2-keccak.md).
- **ESV submission client (`esv-harness`)** — design-of-record at [`docs/design/esv-harness.md`](docs/design/esv-harness.md).

## Features

- **Validate the estimator suite against real collected entropy data.** Parity for the
  SP 800-90B §6.3 estimators is proven against the reference tool's bundled datasets; before the
  suite's numbers back a live assessment it should also be exercised on real collected entropy
  (a source's own samples). Becomes one or more issues once scoped.
- **ARMv8 crypto-extension paths (SHA-Ext + AES-Ext).** The x86 SHA-NI / AES-NI acceleration
  paths exist; the aarch64 equivalents are pending an aarch64 CI runner — becomes an issue once
  the runner exists.
- **PKCS#11 provider crate (`oxicrypt-pkcs11`).** Deployment-surface work so oxicrypt can serve
  as a drop-in for HSM-offload integrations; becomes an issue when scoped.
- **AWS-LC interop test suite.** Run AWS-LC clients against oxicrypt and vice versa to flag
  conformance gaps; becomes an issue when scoped.
- **Supply-chain advisory integration.** `cargo audit` / RustSec hooks with FIPS-aware triage.
- **ARM SVE2 SIMD paths.** Lower priority; pick up when the first ARM customer asks.
