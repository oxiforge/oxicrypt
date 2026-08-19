# Building and signing your own module

This page is the one place that describes how to satisfy the pre-operational
integrity test: what to assemble, how to initialize, when to sign, and what to
do in your own test binaries. It opens with a complete worked example — an empty
directory to a running module — and the reference material follows below.

The short version: the module verifies its own image before it will do any work,
so a binary you have just compiled has nothing to verify against and refuses to
start until you sign it. Signing is one command.

If you want the mechanism rather than the recipe, skip to
[What the test actually checks](#what-the-test-actually-checks).

## A module that works, start to finish

Everything here comes from crates.io, so you get the current release.

**1. A new crate**

```sh
cargo new hello-oxicrypt && cd hello-oxicrypt
```

**2. Take what you need**

```sh
cargo add oxicrypt-module oxicrypt-integrity oxicrypt-sha
```

`oxicrypt-module` is the boundary. `oxicrypt-integrity` is the pre-operational
test, and it is not optional — the module will not start without it.
`oxicrypt-sha` is the algorithm this example uses; swap in whichever you want,
and add its `KATS` to the inventory in step 3.

**3. Write it** — `src/main.rs`

```rust
use oxicrypt_module::KatEntry;

fn main() {
    // Your power-up inventory: the known-answer tests for every algorithm this
    // binary can reach. Nothing checks that you got this right.
    let algorithms: Vec<KatEntry> = oxicrypt_sha::KATS.to_vec();

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

**4. Build it, and watch it refuse**

```sh
cargo build --release
./target/release/hello-oxicrypt
```

```
FIPS power-up self-test failed: Module image integrity
```

This is the expected result at this step. The integrity slot is empty, the test
has no reference to compare against, and a module that cannot verify itself does
not become operational. Nothing is wrong.

> A message beginning `this module did not check itself at startup` is a
> different fault: the first argument to `initialize_with_tests` was an empty
> slice rather than `oxicrypt_integrity::KATS`. Signing will not fix it — pass
> the integrity group.

**5. Sign it**

```sh
cargo install oxicrypt-integrity-sign
oxicrypt-integrity-sign --sign target/release/hello-oxicrypt
```

**6. Run it**

```
module state: Operational
sha256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

That is your module. It verified its own image, ran SHA-256's known-answer test,
and only then produced a digest.

**7. Prove the check is real**

Change one byte of the signed binary and it stops being a module:

```sh
cp target/release/hello-oxicrypt /tmp/backup
printf '\x00' | dd of=target/release/hello-oxicrypt bs=1 seek=600000 count=1 conv=notrunc
./target/release/hello-oxicrypt      # refuses again
cp /tmp/backup target/release/hello-oxicrypt
```

Sign last, and re-sign after anything that rewrites the artifact — stripping,
compression, a platform signing tool.

## What the test actually checks

The signer derives the artifact's **loader-invariant extent** — the regions the
loader maps and never modifies — computes HMAC-SHA-256 over exactly those file
bytes, and writes the range table and the MAC into a reserved slot embedded in
the artifact. At startup the module reads those same regions back from its own
loaded image and recomputes the MAC.

Two consequences follow, and both matter more than they look:

- **The MAC is not over the file.** It is over the extent, which is a strict
  subset. Bytes outside it — a signature appended by a platform tool, a
  debug section — can change without invalidating anything.
- **The extent is derived, not configured.** Ask the tool rather than assuming:
  `oxicrypt-integrity-sign --show <artifact>` prints the ranges, the slot's
  location, and what fraction of the mapped image is covered. It refuses any
  format it cannot classify, and says which format it found.

The key is `oxicrypt_integrity::FIPS_INTEGRITY_KEY`, a published constant. This
is an integrity check, not an authenticity one: it detects corruption of the
module's own image, and it is not a signature over your application.

## What you must depend on

Six crates, and no more, are needed for the integrity test itself:

```
oxicrypt-integrity
├── oxicrypt-hmac
│   ├── oxicrypt-module
│   ├── oxicrypt-sha
│   │   ├── oxicrypt-module
│   │   ├── oxicrypt-test-vectors
│   │   └── oxicrypt-zeroize
│   ├── oxicrypt-test-vectors
│   └── oxicrypt-zeroize
└── oxicrypt-module
```

Depending on `oxicrypt-integrity` pulls all six. The algorithm crates you
actually use are separate and additional.

How much that adds depends on what you already took: an ECDSA build reaches
HMAC and SHA through its DRBG anyway, so integrity costs it one further crate,
while a minimal AES-only build goes from 3 crates to 7.

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
    ];
    groups.iter().flat_map(|g| g.iter().copied()).collect()
}
```

Include a group for every algorithm your binary can reach. Nothing checks this
for you.

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

**Build**, then **sign** the artifact that will ship. The signer is a separate
tool crate, outside the cryptographic boundary, and it is the artifact you are
about to run that must be signed — not an earlier copy of it:

```bash
cargo build --release -p oxicrypt-integrity-sign
cargo build --release -p your-application

./target/release/oxicrypt-integrity-sign --sign target/release/your-application
```

**Verify** offline, which the signer also does to itself as a self-check
immediately after writing the slot:

```bash
./target/release/oxicrypt-integrity-sign --verify target/release/your-application
```

`--verify` exits non-zero and names the defect when the artifact and its slot
disagree. Any step that rewrites the artifact after signing — stripping,
compressing, a platform signing tool — invalidates the slot and the module will
refuse to become operational. Sign last.

## Seeing the tests run

`oxi selftest` reports each self-test by name and ends with an explicit
indicator line. It is the *provided service* form of initiating the self-tests,
which ISO/IEC 19790:2012 §7.10.1 and FIPS 140-3 IG 10.3.E accept at Security
Levels 1 and 2 alongside resetting, rebooting and power cycling; the automatic
periodic-testing obligations apply at Levels 3 and 4 and are not claimed. The
indicator is required rather than cosmetic — IG reads `AS02.24` as exempting
self-tests themselves from needing an indicator while requiring one of *a
service that provides them*.

It re-runs the test functions on an already-operational module; it does not
re-enter the pre-operational sequence, which is one-shot per process. A failure
places the module in the error state.

## The project's own CLI

`oxi` is an ordinary instance of everything above, not a special case. It links
the module, so it is a loadable image carrying a MAC over itself, and it is
signed exactly as your own binary is:

```bash
cargo build --release
oxicrypt-integrity-sign --sign target/release/your-application target/release/oxi
```

**The unit is the loadable image, not the crate.** One invocation signs as many
artifacts as you name, each getting its own slot; a static archive is refused,
because it has no loaded image to verify against — you sign the binary it is
linked into. So if you are assembling a module and want the CLI alongside it,
`oxi` is simply one more artifact in that list.

From a source checkout of this repository, `cargo xtask sign oxicrypt-cli
--release` builds the package and the signer and does the same thing in one
step. It is what CI runs.

**`cargo install oxicrypt-cli` is the one path with no signing step**, because
cargo has none after linking. An installed `oxi` therefore refuses to become
operational and says so, naming the two commands that fix it:

```
$ oxi --integrity
integrity: not signed — this binary carries no valid integrity slot
  Sign it:  cargo install oxicrypt-integrity-sign
            oxicrypt-integrity-sign --sign <this binary>
```

Downloading a signed `oxi` from the releases page avoids the step entirely.

**`oxi` does not sign itself, deliberately.** A binary able to rewrite its own
image is a capability with no cryptographic benefit — the key is a published
constant, so self-signing attests nothing a separate signature does not — and
two real costs: it would link an executable-format parser into the very extent
the integrity test protects, and it would let a binary that has just failed the
check re-sign itself into passing. Keeping the signer separate means the module
never rewrites itself, which is both the simpler story and the true one.

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

Signing and startup verification are separate capabilities and do not yet cover
the same platforms.

`oxicrypt-integrity-sign --show` tells you whether an artifact's format can be
classified on the machine you are on. For startup verification, the module
reports `Unreadable::NoMechanism` on any target where it has no way to read its
own loaded image, and refuses to become operational rather than passing a test
it did not run.

## See also

- `docs/building.md` — building and testing the workspace.
- `crates/oxicrypt-integrity/src/lib.rs` — the crate documentation states the
  security property, the acquisition mechanisms and their trade-offs.
