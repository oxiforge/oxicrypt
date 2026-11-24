# oxicrypt-entropy

The SP 800-90B entropy source of the oxicrypt module: a noise-source abstraction, the continuous health tests, the SHA-256 conditioner and the pipeline that runs them, which the DRBG seed path in `oxicrypt-drbg` draws from on an assessed environment.

> **Read this before anything else.** This crate makes **no entropy claim and no
> conformance claim**, and nothing in it has been assessed by any laboratory or
> validation program. On an environment listed in the seed path's assessed-environment
> table, `oxicrypt-drbg` seeds every module DRBG from this crate's pipeline; elsewhere it
> seeds them from the operating system's generator.
>
> Claimed min-entropy is a required argument of the pipeline. The seed path supplies the
> value recorded for its assessed environment; any other caller supplies and justifies its
> own, and this crate never asserts one on the caller's behalf.

Part of [oxicrypt](https://github.com/oxiforge/oxicrypt), a cryptographic module written
entirely in Rust. The module as a whole targets FIPS 140-3 Level 1, and this crate is
listed inside its cryptographic boundary, which describes where it sits, not what it
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
