# oxicrypt-module

The module boundary, targeting FIPS 140-3 Level 1, for [oxicrypt](https://github.com/oxiforge/oxicrypt):
state machine, self-test runner, and approved-mode indicator.

**This is the entry point.** oxicrypt is a family of `oxicrypt-*` crates, and this
one defines what the others are inside of. It holds the cryptographic boundary,
runs the power-up self-tests, and exposes the service indicator that tells a caller
whether a given operation ran in the approved mode.

The whole module is written in Rust. There is no C anywhere, and no FFI into an
existing cryptographic library — the algorithms are implemented in-tree, and every
algorithm crate carries `#![forbid(unsafe_code)]`.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-module)** — every public
item, with the standard it implements and the self-tests it gates on.

## Installing

```sh
cargo add oxicrypt-module
cargo add oxicrypt-sha    # and whichever algorithm crates you need
```

## How it fits together

Algorithm crates — `oxicrypt-aes`, `oxicrypt-sha`, `oxicrypt-ml-kem` and the rest —
implement the primitives. This crate initializes them as a *module*: it runs the
power-up known-answer tests, holds the operational state, and gates the approved
services on that state having been reached. Initialize it first, then call the
algorithm crates.

Algorithm-profile gating is enforced here too, so a build restricted to CNSA 2.0
or CNSA 1.0 refuses services outside its profile rather than silently permitting
them.

The full crate list, feature matrix and C ABI are documented in the
[repository README](https://github.com/oxiforge/oxicrypt#readme).

## Validation status

**oxicrypt holds no NIST certificate.** That sentence is doing real work, so here
is exactly what does and does not exist.

- **Algorithm testing (ACVP).** The harness runs sessions against NIST's ACVP
  *demonstration* server and they are graded by NIST — the real protocol, NIST's
  own vectors, tens of thousands of cases across twenty algorithm families. It is
  not a CAVP certificate: the production server is open only to NVLAP-accredited
  laboratories, and that is the only route to one.
- **Module validation (CMVP).** Not submitted. The module is *built* to the
  FIPS 140-3 Level 1 structure — defined boundary, state machine, power-up
  self-tests, profile gating — but it has not been through a CST laboratory.
- **Entropy source (SP 800-90B).** Work in progress. `oxicrypt-entropy` makes no
  entropy claim, and nothing inside this boundary is seeded from it: the DRBGs
  take entropy as a caller-supplied argument.

If you want the approved algorithms implemented in pure Rust, that is what this is.
If you need to satisfy a requirement for a *validated* module, that means a
certificate number, and there is not one yet.

## Licence

Apache-2.0 OR MIT, at your option. The licences grant rights in the code, not in
the oxicrypt™ name.
