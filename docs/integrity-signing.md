# Building and signing your own module

This page is the one place that describes how to satisfy the pre-operational
integrity test: what to assemble, how to initialize, when to sign, and what to
do in your own test binaries. It opens with a worked example for Linux — an
empty directory to a running module — and the reference material, including
the extra steps Apple platforms and Windows need, follows below.

The short version: the module verifies a signature over its own image before it
will do any work. You generate a key pair once, build with the public half
embedded, and sign the built binary with the private half. A binary you have
just compiled carries no signature yet, so it refuses to start until you sign
it.

If you want the mechanism rather than the recipe, skip to
[What the test actually checks](#what-the-test-actually-checks).

## A module that works, start to finish

Everything here comes from crates.io, so you get the current release. The
commands are for Linux. On Apple platforms and Windows the build needs its
format's link settings, and on Apple platforms signing is a sequence of code
signatures around the integrity signature; `cargo xtask sign` in this
repository runs either, and [Apple platforms](#apple-platforms-integrity-sign-then-code-sign)
and [Windows](#windows-integrity-sign-then-authenticode-sign) give the steps.

**1. A new crate**

```sh
cargo new hello-oxicrypt && cd hello-oxicrypt
```

**2. Take what you need**

```sh
cargo add oxicrypt-module oxicrypt-integrity oxicrypt-sha oxicrypt-hmac oxicrypt-xof oxicrypt-ml-dsa
```

`oxicrypt-module` is the boundary. `oxicrypt-integrity` is the pre-operational
test, and it is not optional — the module will not start without it.
`oxicrypt-sha` is the algorithm this example uses; swap in whichever you want,
and add its `KATS` to the inventory in step 3. `oxicrypt-integrity` links
`oxicrypt-hmac`, `oxicrypt-xof` and `oxicrypt-ml-dsa` itself, so their `KATS`
belong in the inventory too, and adding them here makes them nameable.

**3. Write it** — `src/main.rs`

```rust
use oxicrypt_module::KatEntry;

fn main() {
    // Your power-up inventory: the known-answer tests for every algorithm this
    // binary can reach. Nothing checks that you got this right.
    let groups: &[&[KatEntry]] = &[
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_xof::KATS,
        oxicrypt_ml_dsa::KATS,
    ];
    let algorithms: Vec<KatEntry> = groups.iter().flat_map(|g| g.iter().copied()).collect();

    // The integrity test is a separate argument because it runs first;
    // everything after it depends on its verdict.
    if let Err(e) = oxicrypt_module::initialize_with_tests(
        oxicrypt_integrity::KATS,
        &algorithms,
    ) {
        eprintln!("{e}");
        std::process::exit(1);
    }

    println!("module state: {:?}", oxicrypt_module::state());

    let digest = oxicrypt_sha::sha256(b"hello world").expect("sha256");
    print!("sha256: ");
    for b in digest {
        print!("{b:02x}");
    }
    println!();
}
```

**4. Generate a key pair**

```sh
cargo install oxicrypt-integrity-sign
oxicrypt-integrity-sign --keygen ~/oxicrypt-keys
```

This writes an ML-DSA-87 key pair into a directory outside your source tree:
`integrity-signing.key`, the private key (the 32-byte seed the pair is derived
from), readable only by you, and `integrity-verify.pub`, the 2,592-byte public
key. It prints the public key's fingerprint,
`sha256:` followed by hex, which is how you will recognise this key later. Keep
the private key out of version control. Anyone who holds it can sign a binary
that your builds will accept. You generate the pair once and reuse it for every
build that should trust it.

**5. Build it with the public key embedded, and watch it refuse**

```sh
OXICRYPT_INTEGRITY_VERIFY_KEY=~/oxicrypt-keys/integrity-verify.pub cargo build --release
./target/release/hello-oxicrypt
```

```
FIPS power-up self-test failed: Module image integrity (ML-DSA-87 signature over the typed extent)
```

This is the expected result at this step. The binary carries the public key it
will verify against, but nothing has been signed yet, so a module that cannot
verify itself does not become operational. Nothing is wrong.

A build without `OXICRYPT_INTEGRITY_VERIFY_KEY` fails the same test for a
different reason: the module has no key to verify with, and the signer refuses
such an artifact with `NoVerifyKey`. Set the variable and rebuild.

> A message beginning `this module did not check itself at startup` is a
> different fault: the first argument to `initialize_with_tests` was an empty
> slice rather than `oxicrypt_integrity::KATS`. Signing will not fix it — pass
> the integrity group.

**6. Sign it**

```sh
oxicrypt-integrity-sign --sign --key ~/oxicrypt-keys/integrity-signing.key target/release/hello-oxicrypt
```

The signer prints the signature and the fingerprint of the key the binary
embeds, which must match the key you signed with; if they differ it refuses.

**7. Run it**

```
module state: Operational
sha256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

That is your module. It verified the signature over its own image, ran the
known-answer tests of every algorithm it links, and only then produced a digest.

**8. Prove the check is real**

Change one byte of the signed binary and it stops being a module. Here the
byte is the first letter of the program's own `module state` string, a
constant the signature covers:

```sh
cp target/release/hello-oxicrypt /tmp/backup
off=$(LC_ALL=C grep -oba 'module state' target/release/hello-oxicrypt | head -1 | cut -d: -f1)
printf 'M' | dd of=target/release/hello-oxicrypt bs=1 seek="$off" count=1 conv=notrunc
./target/release/hello-oxicrypt      # refuses again
cp /tmp/backup target/release/hello-oxicrypt
```

On macOS on Apple silicon, run `codesign --force --sign -` on the changed
binary before running it. Otherwise the operating system rejects the stale code
signature first, and you never see the module's own refusal.

Run the integrity signer on the final artifact, after anything that rewrites
it, such as stripping or compression. On Apple platforms, code signing comes
after the integrity signer; see [Apple platforms](#apple-platforms-integrity-sign-then-code-sign).

## What the test actually checks

The signer derives the artifact's **typed extent** — every byte of the file
the loader maps, each classified by what the loader does to it — and writes the
entry table and the fingerprint of the artifact's embedded public key into a
reserved slot. Code, constants, headers and the tables the loader reads are
signed as they are. A word the loader rebases is signed by its unslid value. A
word the loader binds to an import is checked by resolving that import. The
initial image of writable data is signed from the file. Left out are words the
loader overwrites without reading, and the fields of the headers that the
platform's code signing is measured to rewrite (on Mach-O, `codesign`'s
locator fields; on PE, `CheckSum` and the Security directory entry). The signer then signs the slot and
that extent with ML-DSA-87 (FIPS 204) under your private key, under the context
string `oxicrypt-integrity`, and writes the signature into the slot. The
context separates integrity signatures from signatures the same key makes under
any other context string: neither verifies as the other. At startup the module
reads the same entries back from its own loaded image, the writable data from
the image file the loader reports, and verifies the signature with the public
key it was built with.

Two consequences follow, and both matter more than they look:

- **The signature is not over the file.** It is over the extent, which is a
  strict subset. Bytes outside it — a signature appended by a platform tool, a
  debug section — can change without invalidating anything.
- **The extent is derived, not configured.** Ask the tool rather than assuming:
  `oxicrypt-integrity-sign --show <artifact>` prints the ranges, the slot's
  location, and what fraction of the mapped image is covered. It refuses any
  format it cannot classify, and says which format it found.

The typing for each format, the slot format and the reasoning behind both are
in the design record, [`docs/design/integrity-extent-v2.md`](design/integrity-extent-v2.md).

**What it proves, and what it does not.** A passing test shows that the loaded
image is the one signed with the private key matching the public key the binary
was built with. It detects any change to the extent made after signing. It does
not show who built the binary: the public key travels inside the binary, so
someone who rebuilds from source with a key pair of their own produces a module
that verifies against their key. To tell whose key a binary trusts, compare
its fingerprint, which `oxicrypt-integrity-sign --show <artifact>` and
`oxi --integrity` print, with the one you expect.

When the test fails, the module's status indicator says why, for example:

- `SignatureInvalid` — the image no longer matches its signature;
- `SlotInvalid` — the slot is the unsigned template the build emits;
- `NoVerifyKey` — the binary carries no verifying key;
- `SlotDamaged` — the slot, the key record or a bound import is damaged:
  contents the signer never writes, or memory, file bytes or imports the image
  does not have;
- `KeyMismatch` — the slot names a different key than the one the binary
  embeds;
- `Unreadable` — the environment refused a read the test needs, so the test was
  not performed.

**No status is a reason to sign a binary on its own.** `SlotInvalid` and
`NoVerifyKey` are what an unsigned or key-less build reports, and also what a
signed binary reports once its slot has been overwritten with the template or
its key record zeroed, and the module cannot tell those apart. Sign a binary
only if you built it from source yourself and have not signed it yet. If you
received it from anyone else, do not sign it, whatever the status: obtain a
fresh copy from its publisher. For `SignatureInvalid`, `SlotDamaged` and
`KeyMismatch`, never sign it again: replace it. For `KeyMismatch`, compare the
fingerprint `oxi --integrity` reports for the embedded key with the slot's key
id from `oxicrypt-integrity-sign --show`.

## What you must depend on

Depending on `oxicrypt-integrity` pulls these crates, nine including itself:

```
oxicrypt-integrity
├── oxicrypt-ml-dsa      (the signature verification)
│   └── oxicrypt-xof
├── oxicrypt-hmac
├── oxicrypt-imageread   (reading the loaded image)
├── oxicrypt-sha
└── oxicrypt-module
```

with `oxicrypt-zeroize` and `oxicrypt-test-vectors` beneath them. The algorithm
crates you actually use are separate and additional.

How much that adds depends on what you already took: an ML-DSA build already
has all but `oxicrypt-integrity` and `oxicrypt-hmac`, while a minimal AES-only
build goes from 4 crates to 10.

## Assemble, initialize, build, sign, verify

**Assemble** the power-up inventory. Each algorithm crate publishes a `KATS`
constant; the module takes the integrity group separately from the rest, because
the integrity test runs first and everything after it depends on its verdict.

```rust
fn power_up_tests() -> Vec<oxicrypt_module::KatEntry> {
    let groups: &[&[oxicrypt_module::KatEntry]] = &[
        oxicrypt_sha::KATS,
        oxicrypt_hmac::KATS,
        oxicrypt_aes::KATS,
        oxicrypt_drbg::KATS,
        oxicrypt_xof::KATS,
        oxicrypt_ml_dsa::KATS,
    ];
    groups.iter().flat_map(|g| g.iter().copied()).collect()
}
```

Include a group for every algorithm your binary can reach. Nothing checks this
for you. `oxicrypt-integrity` itself links `oxicrypt-ml-dsa`, the SHAKE in
`oxicrypt-xof`, the SHA-256 in `oxicrypt-sha` and `oxicrypt-hmac`, so their
groups belong in every list.

**Initialize** once, before any cryptographic call:

```rust
fn init_module() -> Result<(), oxicrypt_module::Error> {
    match oxicrypt_module::initialize_with_tests(
        oxicrypt_integrity::KATS,
        &power_up_tests(),
    ) {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}
```

**Build** with the public key embedded, then **sign** the artifact that will
ship with the private key. The signer is a separate tool crate, outside the
cryptographic boundary, and it is the artifact you are about to run that must be
signed — not an earlier copy of it. With a key pair from
`oxicrypt-integrity-sign --keygen <dir>`:

```bash
cargo build --release -p oxicrypt-integrity-sign
OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release -p your-application

./target/release/oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key target/release/your-application
```

The variable has to be set for every build of an artifact that links the module,
and changing it rebuilds `oxicrypt-integrity` and everything above it. The
signer refuses an artifact built without it (`NoVerifyKey`), and refuses a key
whose public half is not the one the artifact embeds.

`--sign` writes the signed copy to a temporary file beside the artifact,
verifies it, and only then renames it over the original, so a failed run leaves
the original untouched. The signer's exit codes are `0` for success, `1` for a
usage error, `2` when an artifact failed, `3` when `--sign` refused its key
before touching any artifact, and `4` when `--keygen` failed.

**Verify** offline, which the signer also does to itself as a self-check
immediately after writing the slot:

```bash
./target/release/oxicrypt-integrity-sign --verify target/release/your-application
```

`--verify` exits non-zero and names the defect when the artifact and its slot
disagree. Stripping, compressing or otherwise rewriting the artifact after
signing invalidates the slot, and the module will refuse to become operational,
so run the integrity signer after those steps.

## Platform code signatures: integrity sign first

On every platform the integrity signer runs before the platform's own final
code signature (`codesign` on Apple platforms, `signtool` on Windows). The
integrity slot records the image's length up to where the platform signature
starts (a Mach-O `LC_CODE_SIGNATURE`'s data, a PE certificate table), so the
platform signature can be added, renewed or grown afterwards without touching
anything the integrity signature covers. Both platform signers also rewrite a
few header fields that locate their signature; the sections below measure
which, against a reference, so that the fields they rewrite are holes in the
extent and nothing else is.

## Apple platforms: integrity sign, then code sign

On Apple silicon the operating system refuses a binary whose code signature is
stale, so an Apple artifact is signed by both, the integrity signer before the
final `codesign`. The integrity
extent covers every file-backed byte of the dylib: the Mach-O header and load
commands, `__TEXT`, `__DATA_CONST` with each chained rebase checked by its
unslid value and each chained bind by the address it resolves to, `__LINKEDIT`
up to the code signature, and the rest of `__DATA` read from the file. The code
signature blob itself, from `LC_CODE_SIGNATURE`'s `dataoff` to the end of the
file, is outside it, so the final `codesign` may rewrite or grow the blob. On
Apple silicon the linker signs every binary ad hoc, so even a binary you never
code signed carries a signature that the integrity signer leaves stale, and
macOS will not launch it until it is signed again.

The dylib must be linked with chained fixups and the zero-fill sections in a
segment of their own, so that no module state is a byte of the file:

```bash
RUSTFLAGS='-C llvm-args=-aarch64-enable-global-merge=false -C link-arg=-Wl,-fixup_chains -C link-arg=-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss -C link-arg=-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common' \
  CARGO_PROFILE_RELEASE_DEBUG=full CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed \
  cargo build --release -p oxicrypt-ffi
```

`-aarch64-enable-global-merge=false` keeps each of the module's statics
under its own name on arm64, where LLVM otherwise merges them into one
unnamed local symbol that no symbol table names; the signer then refuses
the image (`StaticsUnchecked`). The signer reads the module's statics from
the image's symbol table, or,
where that does not name them, from the dSYM `dsymutil` writes beside the
image (`liboxicrypt_ffi.dylib.dSYM`), accepted only when its `LC_UUID` is
the image's. Keep `<artifact>.dSYM` beside the artifact when signing.

The signer refuses an image whose fixups are dyld opcodes (`OpcodeFixups`),
whose `__DATA` holds lazily bound pointers (`LazyPointers`), which is arm64e
(`Arm64e`), which binds through a special library ordinal (`SpecialOrdinal`),
or in which a module static the module must start from zero-fill is
file-backed (`FileBackedStatic`); `--show` prints that static's row.

`codesign` also rewrites four fields inside the load commands when it signs:
`LC_CODE_SIGNATURE`'s `dataoff` and `datasize`, and `__LINKEDIT`'s `vmsize` and
`filesize`. Which of them change under your identity and options is measured:
code sign the dylib twice with the final identity and options, and give the
signer the first result as `--reserved-against`. Each of the four fields that
differs between the two becomes a hole; any other difference is refused.

```bash
LIB=target/release/liboxicrypt_ffi.dylib
codesign --force --sign - --timestamp=none "$LIB" && cp "$LIB" reference.dylib
codesign --force --sign - --timestamp=none "$LIB"
./target/release/oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key --reserved-against reference.dylib "$LIB"
codesign --force --sign - --timestamp=none "$LIB"
./target/release/oxicrypt-integrity-sign --verify "$LIB"
codesign --verify "$LIB"
```

`--sign -` is an ad-hoc signature; use your own identity and options in all
three `codesign` steps instead. `--verify` decodes every chain word against the
kind and the import the signed table gives it, so an edited bind ordinal, chain
link or bind bit is refused even though those bits are not hashed.

A universal file is not signed whole. Sign each thin dylib, then join them with
`lipo`: the module finds its own slice in the file it was loaded from, by its
Mach header and integrity slot.

On iOS, Xcode code signs the app as the last step of the build. Run the
integrity signer on the linked binary before that step, for example from a Run
Script build phase, never on the signed app. The module has not been tested
on an iOS device, and iOS is not a supported operational environment.

## Windows: integrity sign, then Authenticode sign

The integrity extent covers every byte the loader maps from a DLL or EXE: the
headers, with `ImageBase` checked by its unslid value; every read-only section
(`.text`, `.rdata`, `.pdata`, `.reloc`); each `DIR64` base-relocation
destination by its unslid value, the load configuration's pointers among them;
each import thunk by the address `GetProcAddress` gives the symbol or ordinal
its lookup-table entry names, through the module `GetModuleHandleExW` returns
for the DLL name the descriptor gives; the TLS template; and the file bytes of `.data` and the other
writable sections, read from the file. Three kinds of byte are read from the
file too, because whether the loader writes or maps them depends on the host:
the words where the load configuration asks the loader to store its
control-flow guard, XFG, CastGuard and GuardMemcpy functions, and the file
alignment padding after each section's data. The certificate table, at the
end of the file, is outside the signed image, so Authenticode may add or grow
it. The signer refuses an image whose `SectionAlignment` is below the page size
or whose `FileAlignment` does not fit it (`Alignment`).

The image must be linked with zero-initialised data in a section of its own,
which has no file bytes, and with full debug information:

```bash
RUSTFLAGS='-C link-arg=/MERGE:.bss=.zbss' CARGO_PROFILE_RELEASE_DEBUG=full \
  cargo build --release -p oxicrypt-ffi
```

By default the linker merges zero-initialised data into `.data`, whose raw data
is rounded up to the file alignment, so the first zero-initialised statics,
the module's state among them, would be bytes of the file. The signer reads the
module's statics from the program database the linker writes
(`oxicrypt_ffi.pdb`), which only full debug information makes name them, and
accepts it only when its GUID and age are the ones the image's CodeView record
names. Keep the PDB beside the artifact when signing.

A DLL built with the GNU toolchain (`x86_64-pc-windows-gnu`) carries its
debug information as DWARF in its own `.debug_info`, `.debug_abbrev` and
`.debug_str` sections. When no file of the name its CodeView record gives
is beside it, the signer reads the module's statics from that DWARF: each
variable's linkage name and path, the address its location names, and its
type's size. A file of that name that is not the DLL's program database is
refused (`StaticsUnchecked`), not passed over. Linked by `cargo zigbuild`,
whose linker is lld, the same two requirements hold. lld merges `.bss`
into `.data` by default, and `zig cc` refuses `-Wl,/MERGE:...`, but lld
reads further options from the `LINK` environment variable, ahead of its
defaults. From the repository root:

```bash
{ echo EXPORTS; grep -oE '\b(oxi|lama)_[a-z0-9_]+\s*\(' crates/oxicrypt-ffi/include/oxicrypt.h \
    | tr -d '( ' | sort -u; } > oxicrypt_ffi.def
LINK=/MERGE:.bss=.zbss CARGO_PROFILE_RELEASE_DEBUG=full \
  RUSTFLAGS="-C link-arg=$PWD/oxicrypt_ffi.def" \
  cargo zigbuild --release -p oxicrypt-ffi --target x86_64-pc-windows-gnu
```

The `.def` file is there because `zig cc`, the linker driver `cargo
zigbuild` uses, does not pass the export list `rustc` writes for a `cdylib`
on to lld, so without one the DLL exports none of the functions the header
declares; the list names every one of them, the `oxi_*` functions and
`lama_manifest`, which the `oxicrypt` crate also calls. `objdump -p` lists
what the DLL exports. lld prints `.bss=.data: already merged
into .zbss` when it applies `LINK`. `cargo xtask sign --target
x86_64-pc-windows-gnu` builds an executable this way, with `cargo zigbuild`,
and checks for `LINK` and full debug information before it does.

Strip nothing: `strip` removes the DWARF the signer reads, and a DLL that
names a program database but carries no DWARF is refused
(`StaticsUnchecked`). lld also writes a program database, under `deps/`,
that matches the DLL's CodeView record but names none of the statics the
module pins; keep it away from the DLL, because the signer reads a matching
program database in preference to the DWARF and refuses this one
(`StaticsUnchecked`). The DWARF sections are mapped read-only sections of
the image, so they lie inside the signed extent and the integrity test
verifies them at power-up with everything else: about 17 MB of the 21 MB
extent of a release `oxicrypt_ffi.dll` built this way.

Read from DWARF, the statics are refused when the DLL names no program
database and carries no DWARF, or its DWARF is malformed (`NoDwarf`); its
DWARF uses an attribute form the signer does not read (`DwarfForm`); two
located variables name one of the statics the module pins, or one variable
names two of them (`DuplicateStatic`); a module static's address lies
outside every section of the image (`StaticOutsideImage`); a module static
is located by anything but a single `DW_OP_addr`, or a pinned static is not
located in a writable section (`StaticUnlocated`); or a module static in a
writable section has a type that gives no size, an array's being its
element's size times its count (`StaticUnsized`). A variable with no
location, or marked as a declaration, has no storage and is not a module
static; a definition that names nothing itself is read under the name of
the declaration it completes, and a static described under a function is
read like any other. The signer reads DWARF version 4 units with 32-bit offsets and
8-byte addresses, as the compilers write them for this target.

The signer refuses an image with `HIGHLOW`, `HIGH` or `LOW` base relocations
(`RelocationType`), bound imports (`BoundImports`), an import descriptor with
no lookup table (`MissingLookupTable`), a delay-load IAT or module handle in
`Plain` bytes, the bytes signed as they load (`DelayLoadIat`,
`DelayLoadHandle`), a TLS index slot in `Plain` bytes (`TlsIndex`), XFG enabled (`Xfg`), or a module static the module must start
from zero-fill in the file's bytes (`FileBackedStatic`); `--show` prints that
static's row.

`signtool` rewrites two fields inside the headers when it signs: the optional
header's `CheckSum` and the Security directory entry, which locates the
certificate table. Two `signtool` runs over the same bytes write the same
`CheckSum`, so the reference is the image as linked: sign the image once with
the final certificate and options, and give the integrity signer the linked
image as `--reserved-against`. Each of the two fields that differs becomes a
hole; any other difference before the certificate table is refused.

```bash
DLL=target/release/oxicrypt_ffi.dll
cp "$DLL" linked.dll
signtool sign /fd SHA256 /sha1 <thumbprint> "$DLL"
./target/release/oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key --reserved-against linked.dll "$DLL"
signtool sign /fd SHA256 /sha1 <thumbprint> "$DLL"
./target/release/oxicrypt-integrity-sign --verify "$DLL"
```

An artifact that is never Authenticode-signed is signed with `--sign` alone.
`--verify` decodes every import lookup table, name and descriptor against the
bound-import records the signed table holds, so an edited import is refused.

## Seeing the tests run

The module tests itself on demand by restarting: a new process initialises the
module, which runs the whole pre-operational sequence before it serves anything.
ISO/IEC 19790:2012 accepts resetting or rebooting as the way to initiate the
self-tests at Security Levels 1 and 2; the further obligations of FIPS 140-3 IG
10.3.E apply at Levels 3 and 4 and are not claimed. The integrity test runs
only inside that sequence: `oxicrypt_integrity::verify_loaded_image()` called at
any other time runs nothing and returns an error.

`oxi selftest` is a test driver's view of the same tests. It reports each
self-test by name and ends with an explicit indicator line. The integrity line
shows the verdict from the process's start; the algorithm self-tests run again
on the operational module. It does not re-enter the pre-operational sequence,
which is one-shot per process. A failure places the module in the error state.

## The project's own CLI

`oxi` is an ordinary instance of everything above, not a special case. It links
the module, so it is a loadable image carrying a signature over itself, and it
is built and signed exactly as your own binary is:

```bash
OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release
oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key \
  target/release/your-application target/release/oxi
```

**The unit is the loadable image, not the crate.** One invocation signs as many
artifacts as you name, each getting its own slot; a static archive is refused,
because it has no loaded image to verify against — you sign the binary it is
linked into. So if you are assembling a module and want the CLI alongside it,
`oxi` is simply one more artifact in that list.

From a source checkout of this repository, with `OXICRYPT_INTEGRITY_VERIFY_KEY`
set, `cargo xtask sign oxicrypt-cli --release --key <dir>/integrity-signing.key`
builds the package and the signer and does the same thing in one step. It is
what CI runs, with a key pair it generates for the run. It does not set link
flags: before building, it checks that the environment carries the settings the
target's format needs (see [Apple platforms](#apple-platforms-integrity-sign-then-code-sign),
with `MACOSX_DEPLOYMENT_TARGET` at least 12.0 on arm64 and 13.0 on x86_64,
[Windows](#windows-integrity-sign-then-authenticode-sign), and
`-C link-arg=-Wl,-z,max-page-size=16384` for Android), and refuses, naming each
one missing, when it does not. It reads `RUSTFLAGS` as cargo does
(`CARGO_ENCODED_RUSTFLAGS`, then `RUSTFLAGS`, then
`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`), and not from a `.cargo/config.toml`.

**`cargo install oxicrypt-cli` has no signing step**, because cargo has none
after linking. Install it with your public key embedded, then sign it:

```sh
OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo install oxicrypt-cli
oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key "$(command -v oxi)"
```

An `oxi` installed without the variable refuses to become operational, says
so, and gives the advice for each way the binary could have reached you (exit
status 3):

```
$ oxi --integrity
integrity: not passed — this binary carries no verifying key
  detail: this module was built without a verifying key (OXICRYPT_INTEGRITY_VERIFY_KEY)
  verify key: none
  The integrity test cannot tell a binary built without a verifying key
  from one whose key was erased after it was signed.
  If you built this binary from source yourself: generate a key pair
  outside the source tree, rebuild with OXICRYPT_INTEGRITY_VERIFY_KEY
  set to its public half, and sign with its private half:
            oxicrypt-integrity-sign --keygen <dir>
            OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build ...
            oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key <this binary>
  If you received this binary from anyone else, do NOT sign it: obtain
  a fresh copy from its publisher. See docs/integrity-signing.md.
```

Downloading a signed `oxi` from the releases page avoids the step entirely. Its
`BUILD-PROVENANCE.txt` names the signature and the fingerprint of the key it was
signed with; [Release artifacts](#release-artifacts) describes how they are made.

**`oxi` does not sign itself, deliberately.** Self-signing would need the
private key inside the binary it signs, where anyone holding the binary could
read it and sign anything, so the signature would attest nothing. It would also
link an executable-format parser into the very extent the integrity test
protects, and it would let a binary that has just failed the check re-sign
itself into passing. Keeping the signer separate means the module never rewrites
itself, which is both the simpler story and the true one.

## Release artifacts

The release workflow (`.github/workflows/release-artifacts.yml`) builds the C
library for Linux x86_64 and arm64 (glibc 2.17 floor), macOS x86_64 and arm64,
Windows x86_64, and Android x86_64 and arm64, and `oxi` for every one of them
but Android. Each artifact is linked with its format's settings, as above, and
signed by `scripts/release-sign.sh` in its format's order:

| Format | Order |
|---|---|
| ELF (Linux, Android) | split the debug information, strip, add a debuglink, `--sign` |
| Mach-O | `codesign` (A), `codesign` (B), `--sign --reserved-against` A, `codesign` (D) |
| PE | with a certificate: `signtool`, `--sign --reserved-against` the image as linked, `signtool`; without one, `--sign` |

macOS artifacts carry an ad-hoc code signature. Release builds carry no
Authenticode signature, because the project has no Authenticode certificate:
a release PE artifact is integrity signed only, and Windows loads it without
one. A dry run Authenticode-signs with a certificate it creates, so the full PE
order is exercised. Android libraries are linked for 16 KiB pages, and a Mach-O
artifact's chained fixups and deployment floor are asserted before it is signed.

Each signed artifact is checked twice before it is staged: offline with
`--verify`, which must report the fingerprint of the key the run signed with,
and by loading it. The library is loaded and `oxi_init` called, and `oxi` is
run, on the runner that built it; Android x86_64 is loaded on an emulator. The
same artifact as linked, unsigned, must be refused, which shows the test runs.
Each check requires both the harness's exit status and its verdict line.
Android arm64 is verified offline only, because no runner the workflow uses
executes it, and its provenance file says so. Each job prints the signature
and the key fingerprint of every artifact as `provenance:` lines, each
tarball's `BUILD-PROVENANCE.txt` records them with the key source and the load
check, and a final job requires every artifact of the run to name the same
verifying key.

**What a run builds, and whether it publishes.** A `guard` job decides both
before any job reads a secret. A run attaches to a release only when it is a
published release, and a dispatched run never does. The tag must have the
form `vX.Y.Z` (or `vX.Y.Z-suffix`), resolve as `refs/tags/<tag>`, and point at a commit on `main`, and every job checks out
that commit. Such a run must sign with `ci-secret`, and `ci-secret` is refused
for any other run. Build jobs have read-only access to the repository and keep
no credentials; a separate `publish` job, which holds no key, attaches the
tarballs. Every action is pinned to a commit.

**The signing key.** `scripts/release-signing-key.sh` is the one place the key
comes from. Before the build it supplies the verifying key every build embeds
and the fingerprint every signed artifact must report. In the one step that
signs, it supplies the path `--sign --key` is given; that step keeps the path
in a shell variable and erases the private key when it exits, and the next
step erases it again whatever happened, before any action runs. Its source is
named by the run:

- `test`: a pair the run generates once and gives to every build job, so all
  of a run's artifacts carry one fingerprint. A dispatched run uses it, as a
  dry run that uploads workflow artifacts and attaches nothing to a release. Its artifacts verify, but the key identifies one run, not the
  project, and their provenance files say so.
- `ci-secret`: the release key. The 32-byte ML-DSA-87 seed is read, base64-encoded,
  from the `OXICRYPT_RELEASE_SIGNING_KEY` secret of the `release` environment,
  which only a job of a publishing run enters, and written to a `0600` file
  that is erased when the signing step ends. On Windows the mode has no effect
  on NTFS; what protects the file there is the runner's ephemeral disk and that
  erasure. The verifying key is `keys/release-integrity-verify.pub` in the
  repository: it is public, its fingerprint is the one releases are checked
  against, and changing it is a reviewed commit rather than a secret's silent
  rotation. A release run without that file, or without the secret, refuses to
  sign. Project releases are signed from this source.
- `hardware-token` and `kms`: named, documented in the script, and not
  implemented; each refuses, naming what it needs.

The `release` environment is repository configuration, not part of the
workflow. It should require a reviewer's approval, admit only tags matching
`v*` as deployment refs, and hold `OXICRYPT_RELEASE_SIGNING_KEY` as the only
copy of the secret. A run that does not publish enters no environment.

To check whose key a downloaded artifact trusts, compare the fingerprint
`oxi --integrity` or `oxicrypt-integrity-sign --show` reports with the release
key's fingerprint.

## From Rust, through the shared library

A Rust program can load the module as the signed shared library instead of
compiling it in, through the `oxicrypt` crate. The library is then the module:
it runs its integrity test on its own image when it is initialised, whatever
program loaded it, and the program is never signed. Build and sign the library
as above, then build the program against it:

```bash
oxicrypt-integrity-sign --keygen <dir>                      # once, outside any source tree
OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release -p oxicrypt-ffi

# Deliver it under its SONAME, liboxicrypt_ffi.so.<ABI>, with the plain name a link to it
name="$(scripts/library-file-name.sh target/release/liboxicrypt_ffi.so)"   # liboxicrypt_ffi.so.1
cp target/release/liboxicrypt_ffi.so <lib>/"$name"
ln -s "$name" <lib>/liboxicrypt_ffi.so
oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key <lib>/"$name"
oxicrypt-integrity-sign --show <lib>/"$name"                # prints the fingerprint

OXICRYPT_LIB_DIR=<lib> OXICRYPT_LIB_FINGERPRINT=sha256:<the fingerprint> cargo build    # your program
```

The program records the library's `SONAME` and asks the loader for that file at
run time; the plain name is what the linker reads at build time. On macOS the
install name is `@rpath/liboxicrypt_ffi.<ABI>.dylib`, delivered the same way.

The crate's build script links the shared library, never the static
archive: by its exact file name on Linux, Android and Windows, and on macOS
and iOS by `-loxicrypt_ffi`, refusing a library directory that also holds
`liboxicrypt_ffi.a`. It refuses to link one without
`OXICRYPT_LIB_FINGERPRINT` or `OXICRYPT_LIB_UNPINNED=1`. `Module::init` refuses
a library reporting another ABI number (`oxi_abi_version`), a library without
that function at another release version, one that failed its integrity test,
and one that embeds another verifying key than the pinned one. Set the program's run-time
search path for the library in its own build, as the crate documentation
shows; the crate cannot set it for a dependent program.

Two probes confirm the program holds no module code of its own:
`oxicrypt-integrity-sign --show <program>` reports no integrity slot, and
`cargo tree -i oxicrypt-module` on the program's dependency graph prints
nothing.

A `cargo test` binary of such a program needs no stub: it loads the signed
library like any other program. `scripts/bindings-fixture.sh <empty dir>`
builds and signs a library with a key pair generated for the run, and a second
one with another key pair, and prints the variables a test run sets; the
crate's own tests run against them.

## In your own test binaries

A `cargo test` binary is never signed, so the real integrity test cannot pass
inside one. The module still requires an integrity group in order to initialize
at all: it offers no way to skip the requirement, because a skip flag is exactly
the thing that would eventually ship enabled.

Declare a stub at the call site, where a reader sees it:

```rust
/// A `cargo test` binary is never signed, so the real integrity test cannot
/// pass inside one.
const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

fn ensure_initialized() {
    let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[/* your KATs */]);
}
```

This is the pattern the module's own crates use. It is deliberately verbose:
the cost of writing it out is what keeps it out of production code.

## Platform reach

`oxicrypt-integrity-sign --show` classifies an artifact the way signing does,
on any host, and prints its slot, the extent it would sign and the module
statics row, or refuses an artifact it cannot classify. For startup
verification, the module reports `Unreadable::NoMechanism` on any target where
it has no way to read its own loaded image, and refuses to become operational
rather than passing a test it did not run.

## See also

- `docs/building.md` — building and testing the workspace.
- `crates/oxicrypt-integrity/src/lib.rs` — the crate documentation states the
  security property, the acquisition mechanisms and their trade-offs.
