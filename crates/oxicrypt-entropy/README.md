# oxicrypt-entropy

SP 800-90B entropy-source scaffolding: noise-source abstraction, claimed-H pipeline, cited spec constants.

> **Phase-0 scaffolding. Read this before anything else.** This crate makes **no entropy
> claim and no conformance claim**, and nothing in it has been assessed by any laboratory
> or validation program. It has not been run against NIST's ESV demo server. It is also
> **not a dependency of `oxicrypt-module` or `oxicrypt-drbg`** — the DRBGs take entropy as
> a caller-supplied argument, so nothing in the module is seeded from it.
>
> It supplies the *shape* of an SP 800-90B entropy source — noise-source abstraction,
> health tests, min-entropy accounting, conditioner — not an assessed one. Claimed
> min-entropy is a required argument you must supply and justify yourself; this crate
> will never assert one on your behalf.

Part of [oxicrypt](https://github.com/oxiforge/oxicrypt), a cryptographic module written
entirely in Rust. The module as a whole targets FIPS 140-3 Level 1; this crate is listed
inside its cryptographic boundary at Phase 0, which describes where it sits, not what it
has been validated to do.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-entropy)** — every public item,
with the standard each one implements.

## Installing

```sh
cargo add oxicrypt-entropy
```

New to oxicrypt? Start with
[`oxicrypt-module`](https://crates.io/crates/oxicrypt-module) — it defines the
cryptographic boundary and runs the power-up self-tests.

## Validation status

oxicrypt holds **no NIST certificate**. Its algorithms are graded on NIST's ACVP
*demonstration* server — the real protocol against NIST's own vectors, but not a
route to a CAVP certificate, which is open only to accredited laboratories. Module
validation (CMVP) has not been submitted. The full position, including what that
does and does not entitle you to claim, is in the
[validation status](https://github.com/oxiforge/oxicrypt#validation-status) section.

## Licence

Apache-2.0 OR MIT, at your option. The licences grant rights in the code, not in
the oxicrypt™ name.
