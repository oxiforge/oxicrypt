//! Generates `include/oxicrypt.h` from the Rust source via cbindgen.
//!
//! The generated header is committed under version control. CI verifies
//! that re-running cbindgen produces a byte-identical match with the
//! committed header — drift between Rust source and shipped header
//! would be a CMVP compliance gap (security policy artifact desyncs
//! from the binary).

#![allow(clippy::expect_used)] // build scripts that fail at compile-time are acceptable

include!("src/abi_version.rs");

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

    // The library's SONAME (Linux) and install name (macOS) carry the ABI
    // number, so a loader refuses a library of another ABI by name. The file
    // cargo writes keeps its plain name; the delivered file takes the
    // versioned one, with the plain name as a link to it for linking.
    //
    // Android keeps the plain SONAME: an application packages only `lib*.so`
    // names, and bionic looks a library up by the name its SONAME records, so
    // a versioned name would never be found.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match os.as_str() {
        "android" => println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,liboxicrypt_ffi.so"),
        "linux" => {
            println!(
                "cargo:rustc-cdylib-link-arg=-Wl,-soname,liboxicrypt_ffi.so.{OXI_ABI_VERSION}"
            );
        }
        "macos" | "ios" => {
            println!(
                "cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/liboxicrypt_ffi.{OXI_ABI_VERSION}.dylib"
            );
        }
        _ => {}
    }
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
