# oxicrypt-cli

The command-line interface for [oxicrypt](https://github.com/oxiforge/oxicrypt),
a cryptographic module targeting FIPS 140-3 Level 1, written entirely in Rust.

The crate is `oxicrypt-cli`; the binary it installs is `oxi`.

## Quickstart

```sh
cargo install oxicrypt-integrity-sign
oxicrypt-integrity-sign --keygen "$HOME/oxicrypt-keys"
OXICRYPT_INTEGRITY_VERIFY_KEY="$HOME/oxicrypt-keys/integrity-verify.pub" cargo install oxicrypt-cli
oxicrypt-integrity-sign --sign --key "$HOME/oxicrypt-keys/integrity-signing.key" "$(command -v oxi)"
codesign --force --sign - "$(command -v oxi)"   # macOS only, after the line above
oxi hash sha256 ./some-file
```

> The crate is **`oxicrypt-cli`** and the binary it installs is `oxi`.
> `cargo install oxi` fetches an unrelated crate of that name by a different
> author.

The `oxicrypt-integrity-sign` commands are not boilerplate and are explained under
[Why the extra step](#why-the-extra-step). `--keygen` makes a key pair once, outside
any git work tree; the build embeds its public half, and `--sign` signs each
installed binary with the private half. `oxi` tells you what to do if you forget. On macOS, the `codesign`
line renews the code signature that writing the integrity slot leaves stale on
Apple silicon, so it must come after the integrity signer.

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
oxi selftest [--quiet]           Report the module's power-up self-tests by name
oxi --integrity                  Report the integrity test's outcome
oxi --lama                       Dump the LAMA manifest (YAML)
```

Algorithms: `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`,
`sha512-256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`.

`oxi --help` lists the exit codes, including `--integrity`'s `4`: the image
matches, but a later algorithm self-test failed.

`hmac` takes the same eleven, which is also the set `oxi selftest` reports.

## Watching the module test itself

`oxi selftest` reports the module's power-up self-tests by name, with the
vector each is checked against:

```
$ oxi selftest
integrity (3)
  ok    ML-DSA-87 CAST (signature verification, FIPS 204, integrity technique)
  ok    SHA-256 CAST (NIST CAVP SHA256ShortMsg Len=8, integrity key fingerprint)
  ok    Module image integrity (ML-DSA-87 signature over the typed extent)
sha (11)
  ok    SHA-256 KAT (NIST CAVP SHA256ShortMsg Len=8)
  ...
aes (23)
  ok    AES-256-GCM KAT (SP 800-38D / McGrew-Viega Case 15, encrypt+decrypt)
  ...
89 of 89 self-tests passed
self-test indicator: PASS
```

These are the tests the module runs at power-up, before it will serve
anything — the integrity test first, then every known-answer test for the
algorithms this binary can reach. The integrity line shows the verdict from
this process's start, because that test runs only at power-up; `selftest` runs
the algorithm self-tests again so you can see them, and exits non-zero if any
fails. A failure puts the module in the error state, where it refuses every
service until restarted.

`oxi` is a test driver. The module tests itself on demand by restarting:
power-up state is one-shot per process by design, and a new process repeats
the whole pre-operational sequence before it serves anything, which FIPS 140-3
accepts at Levels 1 and 2 as a way to initiate the self-tests.

## Why the extra step

`oxi` runs the module's full power-up self-tests before it does anything,
including the pre-operational integrity test — an ML-DSA-87 signature over the
binary's own loaded image, checked against a reference recorded inside it. That reference
can only be written *after* linking, and `cargo install` has no step after
linking in which to write it. So a freshly installed `oxi` has no reference to
check against, and refuses to become operational rather than proceeding
untested. It is behaving correctly; it is just not yet usable.

`oxicrypt-integrity-sign` writes the reference, an ML-DSA-87 signature made
with a key whose public half was built into the binary. `oxi --integrity` says
where things stand at any point:

```
$ oxi --integrity
integrity: not passed — this binary's integrity slot is the unsigned template
  ...
  If you built this binary from source yourself and have not signed it
  yet, sign it with your own key:
  ...
  If you received this binary from anyone else, do NOT sign it: obtain
  a fresh copy from its publisher.
```

`oxi` never tells anyone to sign a binary on the strength of its own status
alone. A binary that was never signed and a signed one whose slot was
overwritten with the unsigned template carry the same bytes, so only the reader
knows which they have: whether they built it themselves.

`oxi` does not sign itself. A binary that can rewrite its own image would carry
an executable-format parser inside the extent it protects and could re-sign
itself after failing the check. The signer stays a separate tool, and `oxi` is
signed the same way any binary linking the module is.

Once signed it says what was compared, which is the part worth seeing. The
signature covers every byte of the file the loader maps, each checked the way
the loader treats it: code and constants as loaded, rebased addresses by their
unslid value, bound imports by what they resolve to, initialised writable data
from the file. Left out are the signature field itself, a few words the
loader overwrites without reading, and any header field the platform's code
signing is measured to rewrite:

```
$ oxi --integrity
integrity: passed — this binary matches the signature recorded inside it
  verify key: sha256:...
  extent: 1646288 bytes in 486 entries, less the slot
  (oxicrypt-integrity-sign --show reports the full breakdown)
```

This attests **integrity relative to the embedded key, not origin**: the binary
has not changed since someone holding that key's private half signed it. The
`verify key` fingerprint says which key that is. To establish origin, check a
release artifact against the checksum published with it.

A binary that **fails** the check (the image, its slot or its key id changed)
should be replaced, never re-signed: signing again would record the new bytes
as correct rather than undo the change. Re-download and check the published
SHA-256, or rebuild.

Building from source instead? `cargo xtask sign` builds and signs in one step,
which is what CI does. On Linux:

```sh
git clone https://github.com/oxiforge/oxicrypt && cd oxicrypt
cargo run -p oxicrypt-integrity-sign -- --keygen "$HOME/oxicrypt-keys"
OXICRYPT_INTEGRITY_VERIFY_KEY="$HOME/oxicrypt-keys/integrity-verify.pub" \
    cargo xtask sign oxicrypt-cli --key "$HOME/oxicrypt-keys/integrity-signing.key" --release
./target/release/oxi hash sha256 ./some-file
```

On macOS and Windows, `cargo xtask sign` first names the link settings the
format needs and refuses to build until they are in the environment.

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
