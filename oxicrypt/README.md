# oxicrypt

The Rust interface to `liboxicrypt_ffi`, the oxicrypt cryptographic module delivered as a separately built and signed shared library. This crate is outside the module's cryptographic boundary and is not the module itself: the module is the `oxicrypt-*` crates, built into that library and signed. This crate contains no cryptographic code and depends on no `oxicrypt-*` crate; it declares the library's C functions, links your program to the library, and gives typed Rust over them.

## Use

1. Get a signed library: download a project release and pin the release key's fingerprint, or build `oxicrypt-ffi` yourself and sign it with your own key (`docs/integrity-signing.md` in the repository).
2. Build your program with `OXICRYPT_LIB_DIR=<directory holding the library>` (the library under its versioned name, `liboxicrypt_ffi.so.<ABI>`, with `liboxicrypt_ffi.so` a link to it, as release tarballs ship it) and `OXICRYPT_LIB_FINGERPRINT=sha256:<…>`, the fingerprint `oxicrypt-integrity-sign --show <library>` prints. `OXICRYPT_LIB_UNPINNED=1` is the explicit alternative to the fingerprint.
3. Give your program a run-time search path for the library (for example `-C link-arg=-Wl,--enable-new-dtags -C link-arg=-Wl,-rpath,<dir>` on Linux), or deploy the library where the loader looks.

```rust,ignore
use oxicrypt::{Module, Profile};

let module = Module::init(Profile::Cnsa2)?;
let digest = module.sha384(b"abc")?;
```

The library tests its own integrity when it is initialised, whatever program loaded it, so your program is never signed. Check that it holds no module code of its own: `oxicrypt-integrity-sign --show <program>` reports no integrity slot, and `cargo tree -i oxicrypt-module` on your program's graph prints nothing.

The crate documentation covers every build variable, the per-platform loader behaviour, which C functions this release wraps, and where key-generation seeds must come from.

## License

Apache-2.0 OR MIT.
