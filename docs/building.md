# Building oxicrypt

This document covers how to compile oxicrypt from source, the supported
platforms and toolchains, and the build options relevant to FIPS 140-3
validation.

## Prerequisites

oxicrypt requires **Rust 1.95 or later**. Install it via
[rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

No other build tools or system libraries are required. oxicrypt has zero
third-party dependencies — all cryptographic code is pure Rust, written
in-tree.

## Installing the git hooks

Enable the versioned hooks on a fresh clone. This activates the pre-commit
doc-sync guard that keeps `docs/llm-api-manifest/llm-api.yaml` in step with the
public API, and the pre-push gate suite:

```bash
git config core.hooksPath scripts/git-hooks
```

The hooks live under `scripts/git-hooks/` so they are reviewable in PRs rather
than hidden in each contributor's `.git/hooks/`.

## Compiling the workspace

```bash
git clone https://github.com/oxiforge/oxicrypt.git
cd oxicrypt
cargo build --workspace
```

This builds all 18 algorithm crates, the ACVP harness, and the
constant-time validation tool in debug mode.

### Release builds

```bash
cargo build --workspace --release
```

The release profile uses `opt-level = 3`, `codegen-units = 1` (for
deterministic output), and `lto = false`. The software integrity self-test
does not depend on reproducible output: each artifact is signed after it is
linked and verified against its own signature, so two builds that differ in
their bytes each verify against their own signature.

### Building individual crates

```bash
# Just the SHA crate
cargo build -p oxicrypt-sha

# Just the module crate
cargo build -p oxicrypt-module

# The ACVP harness
cargo build -p acvp-harness
```

## Supported platforms

oxicrypt is a software-only module. The core algorithm crates
(`oxicrypt-sha`, `oxicrypt-aes`, `oxicrypt-hmac`, etc.) are `no_std` and
build on any Rust target, and so does the module crate (`oxicrypt-module`).
The module compiles there but cannot become operational: on a target that
gives it no operating-system thread id (anything but Linux, Android, Darwin and
Windows), initialisation fails with `SelfTestFailed` naming
`oxicrypt_module::THREAD_ID_CHECK` and the module latches `Error`. The
integrity crate uses `std` for reading the module's own image.

### Tested configurations

| OS | Architecture | Rust toolchain | Status |
|----|-------------|---------------|--------|
| Ubuntu 22.04 | x86_64 | stable 1.95+ | Primary CI |
| macOS 14+ | aarch64 | stable 1.95+ | Tested |
| Windows 11 | x86_64 | stable 1.95+ | Tested |

Additional platforms can be declared as vendor-affirmed operational
environments under FIPS 140-3 IG D.G §3 equivalency. The certificate,
once issued, will list the exact tested configurations.

### Cross-compilation

The `no_std` algorithm crates cross-compile to any Rust target:

```bash
# ARM embedded (no_std)
rustup target add thumbv7em-none-eabihf
cargo build -p oxicrypt-sha --target thumbv7em-none-eabihf

# WebAssembly
rustup target add wasm32-unknown-unknown
cargo build -p oxicrypt-sha --target wasm32-unknown-unknown
```

The integrity crate requires `std` and is not available on `no_std`-only
targets.

## Running tests

The full suite needs nothing beyond the toolchain. Two documents it can assert against are
optional and absent by default — the SP 800-90B reference datasets and the withheld Security Policy
(see [`../CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`security-policy/README.md`](security-policy/README.md)) — and the tests that need them skip and
say so rather than failing.

```bash
# Full test suite
cargo test --workspace

# ACVP round-trip tests only
cargo test -p acvp-harness

# Individual crate tests
cargo test -p oxicrypt-sha
```

The workspace test suite includes 120 ACVP round-trip tests, 7 CAVP SHS
round-trip tests, an ACVP envelope test, and unit tests across all algorithm
crates.

## Linting

oxicrypt enforces strict linting rules appropriate for a cryptographic
module:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Key lint policies (configured in the workspace `Cargo.toml`):

- `clippy::pedantic` enabled globally
- `clippy::indexing_slicing` denied (prevents unchecked array indexing)
- `clippy::unwrap_used` and `clippy::expect_used` denied
- `clippy::panic` denied
- `clippy::arithmetic_side_effects` warned (side-channel hygiene)
- `unsafe_op_in_unsafe_fn` denied

## Software integrity signing

The module runs a pre-operational integrity test, and an artifact that links it
must be signed before it can become operational. The whole procedure — what to
assemble, when to sign, and what to do in test binaries that cannot be signed —
is in [`integrity-signing.md`](integrity-signing.md).

In short: generate a key pair once, outside the source tree, build the
artifact that will ship with the public half embedded, then sign it with the
private half after any stripping or compression.

```bash
cargo build --release -p oxicrypt-integrity-sign
./target/release/oxicrypt-integrity-sign --keygen ~/oxicrypt-keys
OXICRYPT_INTEGRITY_VERIFY_KEY=~/oxicrypt-keys/integrity-verify.pub cargo build --release -p acvp-harness
./target/release/oxicrypt-integrity-sign --sign --key ~/oxicrypt-keys/integrity-signing.key target/release/acvp-harness
```

On Apple platforms the artifact needs its own link settings and is code
signed both before and after the integrity signer, with `--reserved-against`
naming a reference code signed with the final identity and options. On Apple
silicon the operating system refuses a binary whose code signature is stale.
The section linked below gives the order and the link settings.

`cargo xtask sign <package> --key <signing key> --release` builds and signs in
one step, and code signs as well on an Apple target, with
`OXICRYPT_INTEGRITY_VERIFY_KEY` naming the public half; run it without
arguments to see the link settings each format needs. The full rule, including
iOS, is in
[`integrity-signing.md`](integrity-signing.md#apple-platforms-integrity-sign-then-code-sign).

## Generating rustdoc

```bash
cargo doc --workspace --no-deps
open target/doc/oxicrypt_module/index.html
```

Every crate's documentation follows a common template covering approved
services, power-up self-tests, sensitive security parameters, and
side-channel posture.

## Constant-time validation

```bash
# All seven CSP-touching targets (default 300k samples)
cargo run -p ct-validation --release

# Deep-dive a specific target
cargo run -p ct-validation --release -- --samples 500000 ecdsa_p256_scalar_invert
```

The Security Policy holds the full methodology and verdict table;
[`security-policy/README.md`](security-policy/README.md) explains how to
request it.

## Directory structure

```
oxicrypt/
  Cargo.toml              Workspace root
  crates/                 15 algorithm and infrastructure crates
  acvp-harness/           ACVP vector dispatch and round-trip tests
  tools/
    ct-validation/        Constant-time timing harness
    acvp-gen/             KAT constant generator
  vendor/nist/            Vendored NIST test vectors (pinned commit)
  docs/
    security-policy/      Explains where the Security Policy lives (withheld)
    cavp-mapping/         CAVP vector traceability documents
```
