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
algorithm will produce output, the module verifies an ML-DSA-87 signature (FIPS 204)
over its own loaded image, with a public key compiled into it. The signature is made
under the context string `oxicrypt-integrity`. This tool generates the
key pair and writes the signature.

An oxicrypt binary therefore needs two things from its builder:

1. **A verifying key at build time.** Set `OXICRYPT_INTEGRITY_VERIFY_KEY` to the
   public key file when you build. A build without it compiles, but the module
   reports `NoVerifyKey` and never becomes operational. There is no default key.
2. **A signature after linking**, made with the matching private key. A binary
   built with a key and not yet signed reports that its slot was never signed.

## Install

```sh
cargo install oxicrypt-integrity-sign
```

## Generate a key pair

```sh
oxicrypt-integrity-sign --keygen ~/keys/my-module
```

This writes `integrity-signing.key` (the 32-byte ML-DSA-87 key-generation seed) and
`integrity-verify.pub` (the 2,592-byte public key) and prints the key's fingerprint.
On Unix the private key is created with mode `0600`; on Windows nothing equivalent is
set, and the file takes the directory's default permissions. Reading the private key
derives the pair from the seed and runs a pairwise consistency test before anything is
signed. The directory must not be inside a git work tree, which is what the tool
treats as a source tree and refuses; it never overwrites an existing pair. Keep the
private key out of version control.

## Build and sign

```sh
OXICRYPT_INTEGRITY_VERIFY_KEY=~/keys/my-module/integrity-verify.pub cargo build --release
oxicrypt-integrity-sign --sign --key ~/keys/my-module/integrity-signing.key target/release/my-app
```

`--sign` refuses with `SigningKeyAbsent` when `--key` is missing or unreadable,
or when the key's public half is not the key the artifact was built with, and with
`NoVerifyKey` when the artifact was built without one. Either would otherwise
produce a binary that can never pass its own test.

On Linux and Android the order is build, then `oxicrypt-integrity-sign --sign`. On Windows,
when the DLL or EXE carries an Authenticode signature, it is signed with `signtool` once before
the integrity signer and once after it, and on Apple platforms the artifact is code signed twice
before the integrity signer and once after it, as below. The slot records the signed image's length up to the platform
signature (a Mach-O `LC_CODE_SIGNATURE`'s data, a PE certificate table), so the platform signature
may be added, renewed or grown afterwards without touching anything the integrity signature covers.

`--sign` writes the signed copy to a temporary file beside the artifact, syncs and verifies it, and
only then renames it over the original, so a failure before that rename leaves the original untouched; if the directory cannot be synced after it, `--sign` warns that the signed file is in place but the rename may not yet be durable. Exit codes: `0`
success, `1` usage error (including `--key` outside `--sign` or given twice, or an unreadable `--reserved-against` reference), `2` an artifact failed,
`3` `--sign` refused its key (`SigningKeyAbsent`) before touching any artifact, `4` `--keygen`
failed.

On Apple platforms, renew the code signature afterwards. On Apple silicon the
operating system refuses a binary whose code signature is stale, and the linker
signs every binary ad hoc, so writing the slot leaves that signature stale. The
signed image stops at the code signature, and `--reserved-against <reference>` measures which of the
load-command fields `codesign` rewrites, from the same build code signed once
with the final identity and options while the artifact is the next such
signature:

```sh
codesign --force --sign - --timestamp=none lib.dylib && cp lib.dylib reference.dylib
codesign --force --sign - --timestamp=none lib.dylib
oxicrypt-integrity-sign --sign --key <signing key> --reserved-against reference.dylib lib.dylib
codesign --force --sign - --timestamp=none lib.dylib
```

A Mach-O image must use chained fixups (`-Wl,-fixup_chains`) and keep its
zero-fill sections out of the file; `docs/integrity-signing.md` gives the link
flags.

On Windows, `signtool` rewrites the optional header's `CheckSum` and the
Security directory entry. `--reserved-against <reference>` names the same build
as linked, before any `signtool` run, while the artifact has been signed once
with the final certificate and options; each of the two fields that differs
becomes a hole, and any other difference before the certificate table is
refused:

```sh
cp oxicrypt_ffi.dll linked.dll
signtool sign /fd SHA256 /sha1 <thumbprint> oxicrypt_ffi.dll
oxicrypt-integrity-sign --sign --key <signing key> --reserved-against linked.dll oxicrypt_ffi.dll
signtool sign /fd SHA256 /sha1 <thumbprint> oxicrypt_ffi.dll
```

A PE image must keep its zero-initialised data out of the file and be linked
with full debug information, whose program database the signer reads beside
the artifact; `docs/integrity-signing.md` gives the build.

Two more subcommands are useful in a release pipeline:

```sh
oxicrypt-integrity-sign --verify target/release/my-app   # confirm a shipped artifact is signed and intact
oxicrypt-integrity-sign --show   target/release/my-app   # print both fingerprints, the slot and the extent
```

`--show` prints `verify key: sha256:<fingerprint>` for the key the artifact
embeds, and the slot's key id when it is signed. `oxi --integrity` and the C
function `oxi_integrity_key_fingerprint` report the same fingerprint from inside
the running module.

Sign the final artifact — the executable or shared library you actually ship.
Signing is deterministic: signing the same artifact again with the same key writes
the same 4,627-byte signature, and the signature field is the one part of the slot
the signature does not cover. The tool names a signature by its SHA-256 digest in
what it prints.

## Use it from your own build

The crate is also a library, so a build script or an `xtask` can sign as part
of the build instead of leaving it as a step someone has to remember:

```rust
use std::io::Write as _;
use oxicrypt_integrity_sign::{SignOptions, SigningKey, debug_symbols, sign_image_with, verify_image_for};

let key = SigningKey::read(&signing_key_path)?;
let mut image = std::fs::read(&artifact)?;
// A stripped ELF artifact's symbols come from the debug file its
// .gnu_debuglink names; the library checks that file's CRC. A Mach-O
// artifact's come from <artifact>.dSYM, matched by LC_UUID, and a PE
// artifact's from the PDB its CodeView record names, matched by GUID and age.
let symbols = debug_symbols(&artifact, &image)?;
let options = SignOptions { loader: None, symbols: symbols.as_deref(), reserved_against: None };
sign_image_with(&mut image, &key, &options)?;
// Write a temporary file beside the artifact with its permissions, sync it,
// read it back and verify it, and only then rename it over the artifact and
// sync the directory, as `--sign` does.
let tmp = artifact.with_extension("signing");
let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
file.write_all(&image)?;
file.set_permissions(std::fs::metadata(&artifact)?.permissions())?;
file.sync_all()?;
verify_image_for(&std::fs::read(&tmp)?, options.loader)?;
std::fs::rename(&tmp, &artifact)?;
if let Some(dir) = artifact.parent() {
    std::fs::File::open(dir)?.sync_all()?; // Unix; Windows has no directory handle to sync
}
```

## What signing does and does not prove

The self-test detects **accidental or unauthorised modification after signing**:
corruption at rest or in transit, a partial install, a mismatched build, or an
edit by someone who does not hold the signing key. An artifact whose image no
longer matches its signature has changed since it was signed, and the module will
not start.

Integrity is proven relative to the key the binary was built with. The module
reports that key's fingerprint, so an operator can read which signer a build
trusts. Proving an artifact came from a particular publisher is the job of your
platform's code signing and your distribution channel, which are separate from
this.

That is also why building oxicrypt yourself is entirely legitimate: generate your
own pair, build with the public half, sign with the private half. The artifact is
your module, it reports your fingerprint, and the self-test protects it from the
moment you sign it.

## Platform support

The signer decides which byte ranges make up the extent for the artifact in front
of it and writes that list into the module, so format support is added here, in
the tool, without changing the module. ELF, Mach-O and PE32+ are classified.

**ELF (Linux and Android).** Every file-backed byte of every loaded segment is in
the extent except the slot, typed from `PT_DYNAMIC` and the relocation tables:
read-only segments and RELRO are hashed as they are, relocation destinations are
holes (their tables are hashed), `RELR` destinations and the `.dynamic` pointers
glibc adjusts are hashed as their unslid values, and the rest of the writable
data is hashed from the file. The loader, glibc or bionic, is inferred from the
Android ident note; `--loader glibc|bionic` overrides it for `--sign`,
`--verify` and `--show`. Link with `-z now` and without packed relocations; the signer names
what it refuses.

Signing must be the last change to the file, so split the debug file off, give
the artifact a matching `.gnu_debuglink`, strip it, and sign the stripped
artifact. The signer refuses an ELF artifact in which the module's gate statics,
or any other zero-initialised module static, lie in the file's bytes, and reads
the symbols for that check from the artifact or, once it is stripped, from the
debug file its `.gnu_debuglink` names in the same directory or its `.debug`
subdirectory, checked against the link's CRC:

```sh
objcopy --only-keep-debug libapp.so libapp.debug
strip --strip-all libapp.so
objcopy --add-gnu-debuglink=libapp.debug libapp.so
oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key libapp.so
```

**PE32+ (Windows, x86_64).** Every byte the loader maps from the file is in the
extent except the slot, typed from the headers, the base relocations, the
import directory and the load configuration: the headers and read-only
sections are hashed as they are, `ImageBase` and each `DIR64` relocation
destination are hashed as their unslid values, each import thunk is checked
at startup against `GetProcAddress` of the symbol or ordinal its lookup-table
entry names, the TLS template is hashed as it is, and the rest of the
writable data, the storage the load configuration names for the loader to
write (control-flow guard, XFG, CastGuard, GuardMemcpy) and the file alignment
padding after each section are hashed from the file. The certificate table
is outside the signed image. The signer refuses an image with `HIGHLOW`, `HIGH`
or `LOW` base relocations, bound imports, an import descriptor without a lookup
table, a delay-load IAT in a read-only section, or XFG enabled, and one in
which a zero-initialised module static lies in the file's bytes; it reads the
symbols for that check from the program database the image's CodeView record
names, beside the artifact, accepted only with the record's GUID and age.

`--staticlib-target` is deliberately refused: a static library is not a loaded
image, so there is nothing for the runtime test to verify. Sign the executable
or shared library that links it.

## License

Apache-2.0 OR MIT, matching the rest of the workspace.
