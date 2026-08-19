# Signing an artifact for the integrity test

The module runs a pre-operational integrity test before it becomes operational.
This page is the one place that describes how to satisfy it: what to assemble,
how to initialize, when to sign, and what to do in your own test binaries.

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
