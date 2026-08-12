# oxicrypt-cli

The command-line interface for [oxicrypt](https://github.com/oxiforge/oxicrypt),
a cryptographic module targeting FIPS 140-3 Level 1, written entirely in Rust.

The crate is `oxicrypt-cli`; the binary it installs is `oxi`.

```sh
cargo install oxicrypt-cli
```

## Commands

```
oxi hash <alg> [FILE]            Hash a file or stdin
oxi hmac <alg> <key-hex> [FILE]  HMAC a file or stdin
oxi rand <nbytes>                Generate random bytes (hex)
oxi --lama                       Dump the LAMA manifest (YAML)
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

`oxi` also initializes the module **without** running the power-up known-answer
tests, because the binary is not signed. Treat it as a convenience tool, not as a
demonstration of the self-tested path.

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
