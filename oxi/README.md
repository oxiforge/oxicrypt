# oxicrypt-cli

The command-line interface for [oxicrypt](https://github.com/oxiforge/oxicrypt),
a cryptographic module targeting FIPS 140-3 Level 1, written entirely in Rust.

The crate is `oxicrypt-cli`; the binary it installs is `oxi`.

## Installing

⚠️ **`cargo install oxicrypt-cli` alone does not produce a runnable binary.**

`oxi` initializes the module before it does anything, and the module runs a
pre-operational integrity test over its own loaded image. That test needs a MAC
written into the binary after linking, and `cargo install` has no post-link step
in which to write it. An installed but unsigned `oxi` prints

```
fatal: module initialization failed: FIPS power-up self-test failed:
Module image integrity (HMAC-SHA-256 over the loader-invariant image)
```

and exits non-zero. It is behaving correctly: a module that cannot verify its own
image refuses to become operational rather than proceeding untested.

`oxi --integrity` answers the question directly, and is handled before the module
is initialized so that it still works on a binary that cannot start:

```
$ oxi --integrity
integrity: not signed — this binary carries no valid integrity slot
  Sign it:  oxicrypt-integrity-sign --sign <this binary>
  `cargo install` cannot do this: it has no step after linking in which
  to write the slot. See docs/integrity-signing.md.
```

Until signed release artifacts are published, build and sign it yourself:

```sh
git clone https://github.com/oxiforge/oxicrypt && cd oxicrypt
cargo xtask sign oxicrypt-cli --release
./target/release/oxi hash sha256 ./some-file
```

`cargo xtask sign` builds the package and the signer, writes the slot, and
verifies the result. It is the same implementation CI uses, so a local build is
signed the way CI builds one.

The procedure, and what it is doing, is in
[`docs/integrity-signing.md`](https://github.com/oxiforge/oxicrypt/blob/main/docs/integrity-signing.md).

## Commands

```
oxi hash <alg> [FILE]            Hash a file or stdin
oxi hmac <alg> <key-hex> [FILE]  HMAC a file or stdin
oxi rand <nbytes>                Generate random bytes (hex)
oxi --lama                       Dump the LAMA manifest (YAML)
oxi --integrity                  Report the integrity test's outcome
```

Algorithms: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`,
`sha512-256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`.

```sh
$ oxi hash sha256 ./file
$ echo -n "hello" | oxi hash sha3-256
$ oxi hmac sha256 00112233 ./file
$ oxi rand 32
```

## What it is not

This is a small utility over the module's hashing, MAC and RNG surface — not a
general cryptographic toolkit. There is no key generation, signing, verification
or encryption here yet, and the post-quantum algorithms the module implements are
not reachable from the command line.

`oxi` does run the module's full power-up self-tests, including the
pre-operational integrity test — which is why it must be signed before it will
start. See **Installing** below.

## Documentation

**[API documentation on docs.rs](https://docs.rs/oxicrypt-cli)** for the crate, and
the [repository README](https://github.com/oxiforge/oxicrypt#readme) for the module
itself. If you are consuming oxicrypt from Rust rather than the shell, start with
[`oxicrypt-module`](https://crates.io/crates/oxicrypt-module).

## Validation status

oxicrypt holds **no NIST certificate**. Its algorithms are graded on NIST's ACVP
*demonstration* server — the real protocol against NIST's own vectors, but not a
route to a CAVP certificate, which is open only to accredited laboratories. Module
validation (CMVP) has not been submitted. Full detail in the
[validation status](https://github.com/oxiforge/oxicrypt#validation-status) section.

## Licence

Apache-2.0 OR MIT, at your option. The licences grant rights in the code, not in
the oxicrypt™ name.
