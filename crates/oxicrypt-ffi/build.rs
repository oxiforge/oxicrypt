//! Generates `include/oxicrypt.h` from the Rust source via cbindgen.
//!
//! The generated header is committed under version control. CI verifies
//! that re-running cbindgen produces a byte-identical match with the
//! committed header — drift between Rust source and shipped header
//! would be a CMVP compliance gap (security policy artifact desyncs
//! from the binary).

#![allow(clippy::expect_used)] // build scripts that fail at compile-time are acceptable

fn main() {
    let crate_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo");
    let config = cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml"))
        .expect("cbindgen.toml must exist and be valid");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen generation failed")
        .write_to_file(format!("{crate_dir}/include/oxicrypt.h"));
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
