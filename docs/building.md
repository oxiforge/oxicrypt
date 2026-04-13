# Building oxicrypt

This document covers how to compile oxicrypt from source, the supported
platforms and toolchains, and the build options relevant to FIPS 140-3
validation.

## Prerequisites

oxicrypt requires **Rust 1.94 or later**. Install it via
[rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

No other build tools or system libraries are required. oxicrypt has zero
third-party dependencies — all cryptographic code is pure Rust, written
in-tree.

## Compiling the workspace

```bash
git clone https://github.com/caraka/oxicrypt.git
cd oxicrypt
cargo build --workspace
```

This builds all 15 algorithm crates, the ACVP harness, and the
constant-time validation tool in debug mode.

### Release builds

```bash
cargo build --workspace --release
```

The release profile uses `opt-level = 3`, `codegen-units = 1` (for
deterministic output), and `lto = false`. These settings are chosen to
balance performance with build reproducibility — the software integrity
self-test depends on the binary hash being stable across builds with the
same toolchain.

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
build on any Rust target. The module crate and integrity crate use `std`
for file I/O and self-test orchestration.

### Tested configurations

| OS | Architecture | Rust toolchain | Status |
|----|-------------|---------------|--------|
| Ubuntu 22.04 | x86_64 | stable 1.94+ | Primary CI |
| macOS 14+ | aarch64 | stable 1.94+ | Tested |
| Windows 11 | x86_64 | stable 1.94+ | Tested |

Additional platforms can be declared as vendor-affirmed operational
environments under FIPS 140-3 IG D.G §3 equivalency. The validated
certificate will list the exact tested configurations.

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

The module crate (`oxicrypt-module`) and integrity crate require `std`
and are not available on `no_std`-only targets.

## Running tests

```bash
# Full test suite
cargo test --workspace

# ACVP round-trip tests only
cargo test -p acvp-harness

# Individual crate tests
cargo test -p oxicrypt-sha
```

The workspace test suite includes 120 ACVP round-trip tests, 7 CAVP SHS
tests, and unit tests across all algorithm crates.

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

The FIPS 140-3 power-up self-test includes a software integrity check.
After building the harness (or any binary linking `oxicrypt-module`),
sign it:

```bash
cargo build -p oxicrypt-integrity
./target/debug/oxicrypt-integrity-sign --sign target/debug/acvp-harness
```

This embeds an HMAC-SHA-256 tag over the binary contents into a reserved
64-byte slot. The module verifies this tag at power-up before running any
cryptographic operations.

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

See the security policy §12.1 for the full methodology and verdict table.

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
    security-policy/      SP 800-140Br1 draft security policy
    cavp-mapping/         CAVP vector traceability documents
```
