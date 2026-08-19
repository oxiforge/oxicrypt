# oxicrypt-cli

The command-line interface for [oxicrypt](https://github.com/oxiforge/oxicrypt),
a cryptographic module targeting FIPS 140-3 Level 1, written entirely in Rust.

The crate is `oxicrypt-cli`; the binary it installs is `oxi`.

## Quickstart

```sh
cargo install oxicrypt-cli oxicrypt-integrity-sign
oxicrypt-integrity-sign --sign "$(command -v oxi)"
oxi hash sha256 ./some-file
```

> The crate is **`oxicrypt-cli`** and the binary it installs is `oxi`.
> `cargo install oxi` fetches an unrelated crate of that name by a different
> author.

The middle command is not boilerplate and is explained under
[Why the extra step](#why-the-extra-step). It is needed once, per installed
binary, and `oxi` tells you to run it if you forget.

Or skip it entirely: the
[releases page](https://github.com/oxiforge/oxicrypt/releases) carries `oxi`
already signed, per platform, as `oxicrypt-cli-<version>-<platform>.tar.gz`.

```sh
$ oxi hash sha256 ./file
$ echo -n "hello" | oxi hash sha3-256
$ oxi hmac sha256 00112233 ./file
$ oxi rand 32
$ oxi --integrity
```

## Commands

```
oxi hash <alg> [FILE]            Hash a file or stdin
oxi hmac <alg> <key-hex> [FILE]  HMAC a file or stdin
oxi rand <nbytes>                Generate random bytes (hex)
oxi selftest [--quiet]           Run the module's self-tests, reporting each one
oxi --integrity                  Report the integrity test's outcome
oxi --lama                       Dump the LAMA manifest (YAML)
```

Algorithms: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`,
`sha512-256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`.

`hmac` takes all eleven: the five above plus `sha512-224`, `sha512-256`,
`sha3-224`, `sha3-256`, `sha3-384`, `sha3-512` — the same set `oxi selftest`
reports.

## Watching the module test itself

`oxi selftest` runs the module's self-tests on demand and reports each one by
name, with the vector it is checked against:

```
$ oxi selftest
integrity (2)
  ok    HMAC-SHA-256 CAST (integrity technique, AS10.20)
  ok    Module image integrity (HMAC-SHA-256 over the loader-invariant image)
sha (11)
  ok    SHA-256 KAT (NIST CAVP SHA256ShortMsg Len=8)
  ...
aes (23)
  ok    AES-256-GCM KAT (SP 800-38D / McGrew-Viega Case 15, encrypt+decrypt)
  ...
71 of 71 self-tests passed
self-test indicator: PASS
```

These are the same tests the module runs at power-up, before it will serve
anything — the integrity test first, then every known-answer test for the
algorithms this binary can reach. `selftest` runs them again so you can see
them, and exits non-zero if any fails. A failure puts the module in the error
state, where it refuses every service until restarted.

It re-runs the tests; it does not re-establish the module's power-up state,
which is one-shot per process by design. Restarting is what repeats the
pre-operational sequence itself — and at FIPS 140-3 Level 1 either is an
acceptable way to initiate the self-tests.

## Why the extra step

`oxi` runs the module's full power-up self-tests before it does anything,
including the pre-operational integrity test — a MAC over the binary's own
loaded image, checked against a reference recorded inside it. That reference
can only be written *after* linking, and `cargo install` has no step after
linking in which to write it. So a freshly installed `oxi` has no reference to
check against, and refuses to become operational rather than proceeding
untested. It is behaving correctly; it is just not yet usable.

`oxicrypt-integrity-sign` writes the reference. `oxi --integrity` says where
things stand at any point:

```
$ oxi --integrity
integrity: not signed — this binary carries no valid integrity slot
  Sign it:  cargo install oxicrypt-integrity-sign
            oxicrypt-integrity-sign --sign <this binary>
```

`oxi` does not sign itself. A binary that can rewrite its own image gains
nothing cryptographically — the key is a published constant — and would both
carry an executable-format parser inside the extent it protects and be able to
re-sign itself after failing the check. The signer stays a separate tool, and
`oxi` is signed the same way any binary linking the module is.

Once signed it says what was compared, which is the part worth seeing — the MAC
covers a strict subset of the file by construction, since the slot holding the
reference and everything the loader rewrites are both excluded:

```
$ oxi --integrity
integrity: passed — this binary matches the reference recorded inside it
  extent: 1299244 bytes in 3 range(s) — 97.08% of the mapped image
```

This attests **integrity, not origin**. The key is a published constant, so the
reference says the binary has not changed since it was written, and nothing
about who produced it — the same property every oxicrypt build carries, however
it was signed. To establish origin, check a release artifact against the
checksum published with it before signing.

Which is why a binary that **fails** the check should be replaced, not
re-signed. Failing means the file carries a reference and no longer matches it:
something rewrote it after signing, so signing again would record the new bytes
as correct rather than undo the change. Re-download and check the published
SHA-256, or rebuild.

A binary that was simply never signed reports something different — *not
signed* rather than *FAILED* — and is the ordinary state after
`cargo install`.

Building from source instead? `cargo xtask sign oxicrypt-cli --release` builds
and signs in one step, which is what CI does:

```sh
git clone https://github.com/oxiforge/oxicrypt && cd oxicrypt
cargo xtask sign oxicrypt-cli --release
./target/release/oxi hash sha256 ./some-file
```

The mechanism, and how to satisfy the same test in your own binaries, is in
[`docs/integrity-signing.md`](https://github.com/oxiforge/oxicrypt/blob/main/docs/integrity-signing.md).

## What it is not

A small utility over the module's hashing, MAC and RNG surface — not a general
cryptographic toolkit. There is no key generation, signing, verification or
encryption here, and the post-quantum algorithms the module implements are not
yet reachable from the command line.

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
