# Roadmap — oxicrypt

Forward-looking work that is **not yet a deliverable**. Concrete, scoped work lives in
[GitHub Issues](https://github.com/oxiforge/oxicrypt/issues) (with `tier:` labels); release
history lives in git tags + `CHANGELOG.md`. This file holds only what is still upstream of an
issue — no status, no history. When an item is decomposed into actionable work it **becomes a
GitHub issue and is removed from here**.

## Ideas

*(speculative — none captured yet.)*

## Designs

- **AVX2 acceleration of Keccak-f[1600]** → [`docs/design/avx2-keccak.md`](docs/design/avx2-keccak.md). The worthwhile form is a 4-way-batched permutation requiring a batched sponge API + caller rewiring (not a drop-in single-stream accel); design-first before any issues.

## Features

- **Validate the estimator suite against real collected entropy data.** Parity for the
  SP 800-90B §6.3 estimators is proven against the reference tool's bundled datasets; before the
  suite's numbers back a live assessment it should also be exercised on real collected entropy
  (a source's own samples). Becomes one or more issues once scoped.
