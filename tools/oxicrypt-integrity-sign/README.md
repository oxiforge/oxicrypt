# oxicrypt-integrity-sign

**This is a build tool. It is not part of the oxicrypt cryptographic module,
and it is not FIPS-validated.** It runs on your build machine, after
compilation, and never ships inside the module it signs. oxicrypt itself has
not been submitted for FIPS 140-3 validation; nothing in this crate changes
that.

> **Assembling a module rather than signing one you already have?** Start with
> [Building and signing your own module](https://github.com/oxiforge/oxicrypt/blob/main/docs/integrity-signing.md),
> which works through the whole sequence — which crates to take, how to
> initialize, then signing — from an empty directory. This page is the signer's
> own reference.

## What it does

oxicrypt runs a pre-operational integrity self-test at startup: before any
algorithm will produce output, the module checks that its own code is the code
that was signed. It does that by comparing a fingerprint of the loaded image
against a reference value stored inside the binary.

This tool writes that reference value. Without it, a freshly compiled oxicrypt
binary has an empty slot, the self-test finds nothing to compare against, and
the module refuses to become operational:

```
integrity: integrity slot invalid: slot version 0 — the artifact was never signed
```

So: **build, then sign.** An unsigned build will not run.

## Install

```sh
cargo install oxicrypt-integrity-sign
```

## Use it as a command

```sh
cargo build --release
oxicrypt-integrity-sign --sign target/release/my-app
```

Two more subcommands are useful in a release pipeline:

```sh
oxicrypt-integrity-sign --verify target/release/my-app   # confirm a shipped artifact is signed and intact
oxicrypt-integrity-sign --show   target/release/my-app   # print the slot: version, MAC, range table
```

Sign the final artifact — the executable or shared library you actually ship.
Signing is idempotent: re-signing an unmodified artifact produces the same
reference value, because the slot's own bytes are excluded from what gets
fingerprinted.

## Use it from your own build

The crate is also a library, so a build script or an `xtask` can sign as part
of the build instead of leaving it as a step someone has to remember:

```rust
use oxicrypt_integrity_sign::{elf, sign_image};

let mut image = std::fs::read(&artifact)?;
let mac = sign_image(&mut image)?;
std::fs::write(&artifact, &image)?;
println!("signed: {}", hex(&mac));
```

## What signing does and does not prove

The self-test detects **modification after signing** — corruption at rest, a
partial install, a mismatched build, a patched binary. An artifact whose image
no longer matches its stored reference has changed since it was signed, and the
module will not start.

It does **not** establish *who* signed. The integrity key is a fixed, publicly
known constant, so anyone who can write to an artifact can also compute a valid
reference for it. An artifact that is modified and then re-signed is internally
consistent — it is simply a *different module*, not a defeated test. Proving an
artifact came from a particular publisher is the job of your platform's code
signing and your distribution channel, which are separate from this.

That is also why building oxicrypt yourself and signing the result is entirely
legitimate. The artifact is your module, and the self-test protects it from the
moment you sign it exactly as it would protect one signed by anyone else.

## Platform support

ELF (Linux) today. The signer decides which byte ranges make up the
loader-invariant image for the artifact in front of it and writes that list
into the module, so support for Mach-O and PE is added here, in the tool,
without changing the module.

`--staticlib-target` is deliberately refused: a static library is not a loaded
image, so there is nothing for the runtime test to verify. Sign the executable
or shared library that links it.

## License

Apache-2.0 OR MIT, matching the rest of the workspace.
