//! Embeds the integrity test's verifying key, a build-time input.
//!
//! The module verifies the signature over its own image with an
//! ML-DSA-87 public key compiled into it. Which key is a decision for
//! whoever builds the module, so it is read from the environment rather
//! than committed:
//!
//! - `OXICRYPT_INTEGRITY_VERIFY_KEY`: the path of a file holding the
//!   2,592-byte encoded public key, as `oxicrypt-integrity-sign --keygen`
//!   writes it.
//! - `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX`: the same 2,592 bytes as 5,184
//!   hex digits, for a pipeline that carries the key inline.
//!
//! Any other length stops the build with a message naming the expected
//! one.
//!
//! With neither set, the build still succeeds and embeds an all-zero key.
//! A module built that way reports `NoVerifyKey` at power-up and never
//! becomes operational: it has no key to verify anything against, and
//! there is deliberately no default key to fall back to.

#![allow(clippy::expect_used, clippy::panic)] // a malformed key must stop the build

#[path = "build_key.rs"]
mod build_key;

fn main() {
    println!("cargo:rerun-if-env-changed=OXICRYPT_INTEGRITY_VERIFY_KEY");
    println!("cargo:rerun-if-env-changed=OXICRYPT_INTEGRITY_VERIFY_KEY_HEX");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_key.rs");

    let file = std::env::var_os("OXICRYPT_INTEGRITY_VERIFY_KEY");
    let hex = std::env::var_os("OXICRYPT_INTEGRITY_VERIFY_KEY_HEX");
    if let Some(path) = &file {
        println!("cargo:rerun-if-changed={}", path.to_string_lossy());
    }
    let key = build_key::resolve_key(file.as_deref(), hex.as_deref(), &|p| std::fs::read(p))
        .unwrap_or_else(|e| panic!("{e}"));

    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
    std::fs::write(
        format!("{out}/verify_key.rs"),
        build_key::emit(key.as_ref()),
    )
    .expect("write the verifying key record");
}
