# Design: a Rust binding over the module's shared library

Design-of-record for a crate that lets a Rust program use the cryptographic module through the module's own shared library, `liboxicrypt_ffi` (the C ABI defined in `crates/oxicrypt-ffi` and its generated header `include/oxicrypt.h`), without compiling any module crate into the program. The procedure for building and signing the library is in [`docs/integrity-signing.md`](../integrity-signing.md); the integrity test the library runs on itself is in [`integrity-extent-v2.md`](integrity-extent-v2.md). This document records what the crate is, how it finds the library, what it restores over the C calling convention, and why it is shaped this way.

## Problem

A Rust program that uses the module today depends on the module crates directly and compiles them into itself. The resulting binary is one image that holds both the application and the module, so the pre-operational integrity test covers that whole image, the signature is made over it, and every rebuild of the application is a new artifact to sign.

ISO/IEC 19790:2012 §7.10.2.2 (`[10.17]`) requires every software component within the cryptographic boundary to be verified by an approved integrity technique before the module offers a service; it scopes the test to what is inside the boundary and says nothing about what is outside it. This project's boundary is the set of module crates its security policy lists (§2.1); the C ABI shim `oxicrypt-ffi` is outside it, by the policy's own statement (§2.1, §3) and by the repository's (`AGENTS.md`). The delivered shared library is one image that holds the module and, beside it, the out-of-boundary shim through which a C caller reaches it. The library's integrity test covers every byte the loader maps from that image, so it covers the shim's code alongside the module's. Covering code outside the boundary is more than `[10.17]` requires and is not a claim that the shim is inside the boundary; the module is verified because everything in the image is. An application that loads the library is further outside still, as FIPS 140-3 IG 9.5.A describes for software modules: application software "may reside within the TOEPP but outside of the SCM cryptographic boundary", and "the non-SCM elements (GPC, OE and App) are external to the cryptographic boundary of the SCM". A C program already gets this separation: it loads the separately built and signed shared library, the library verifies itself, and the program is never signed.

A Rust program needs the same path. Rust has no stable ABI between separately compiled binaries, so the only interface a Rust program can hold to a separately built library is the C calling convention. The crate this document designs is that interface: one crate from crates.io, outside the boundary, that declares the C functions of `liboxicrypt_ffi`, links the program to the library, and gives the program typed Rust over the untyped C. Nothing the module needs in order to meet its own requirements is delegated to this crate.

## Scope and threat model

**What the crate is.** A translation layer between Rust types and the C ABI, in the same position relative to the boundary as a C program that includes `oxicrypt.h`: outside it, one step further out than the shim, which is itself outside. It holds no cryptographic code and no module code. The library it calls is the signed shared library the loader bound to the program, identified by the ABI number it reports (`oxi_abi_version`, or for a library without that function its release version), its integrity signature and the fingerprint of the verifying key it embeds (`oxi_integrity_key_fingerprint`). The fingerprint is self-reported by the library: comparing it detects an honestly signed library of another origin, and cannot authenticate code that is already loaded and lying about itself.

**One loaded instance.** The module's state (initialised, profile, error) belongs to the loaded instance of the library, not to the process. A second copy of the library loaded by `dlopen` from another path, or module code compiled into some other component of the process, has its own state and its own self-test outcome. This crate addresses the one instance the loader bound to the program's `oxi_*` references, and a program holding more than one instance is an unsupported configuration this design does not reason about. Everywhere this document says "once", it means once per loaded instance.

**What the crate must never do.** Each of these would move it, or the application, inside the claim the module makes about itself, or would put a second search rule or a second module beside the one the loader chose.

- Implement any cryptography: no hashing, no comparison of tags or signatures, no key derivation, no random generation, and no fallback to a Rust implementation when the library is absent or refuses a call. Constant-time comparison is the library's job; the crate compares nothing secret.
- Hold key material longer than a call needs. A secret the crate owns on the application's behalf is zeroed when the application drops it; every intermediate the crate makes to call the library is zeroed when the call returns, on every path including an error return and an unwinding panic. The crate caches nothing.
- Retry around the module's error state. A failed initialisation is terminal for the loaded instance until the process restarts; the crate reports it and never loops, re-initialises or re-loads.
- Carry a verifying key, a signing key, or any signing step. The library is signed before the crate is built against it.
- Load the library by a path it chooses at run time. The operating system's loader resolves the library; the crate neither calls `dlopen` nor reads an environment variable at run time to find it.
- Pre-check what the library checks. A context longer than 255 bytes, an unknown profile or an HKDF output beyond the bound is refused by the library and mapped, not pre-checked and silently shaped. What the crate must check is what only the caller's side can know: that an output slice is long enough for what the C function will write, and that an allocation the crate is about to make is bounded. Those checks protect memory safety and are the crate's job (obligation U9 below); they decide nothing cryptographic.

**What is outside the crate's claim.** The crate does not establish that the library the loader found is the one the application expects beyond comparing the self-reported fingerprint against a value the application pinned at build time. Modification of the library is the integrity test's claim (the signature over the image); substitution of a library on the loader's search path by someone who controls the file and the launch is outside the integrity test's threat model (integrity-extent-v2.md, *Threat model*) and outside this crate's. Keys the application passes to the library, and keys the library returns to it, cross the boundary in plaintext within one process, as they do for a C caller. IG 9.5.A Table 1 names that path ("CM Software to/from App via TOEPP Path", MD / EE), Table 2 permits plaintext electronic entry and output at Security Levels 1 and 2 (P/E/SE), with ISO/IEC 19790:2012 §7.9.5 `[09.19]` requiring the CSPs to stay within the operational environment and `[09.16]` requiring two independent internal actions of the module to output a plaintext CSP. Those are the module's obligations, for its security policy to state (Q8); the crate, being outside, contributes neither action and makes no claim about them. IG 1.A (binding and embedding of validated modules) does not apply to an application that uses this crate: the application is "App" in 9.5.A's terms, not a module under test. It would apply only to a consumer validating a module of their own that binds to this one, and then on that consumer's side.

## Finding the library

### At build time

The crate's build script reads `OXICRYPT_LIB_DIR`: the directory holding the signed shared library and, on Windows, its import library. It emits `cargo:rustc-link-lib` unconditionally, so that a consumer who never set the variable gets the linker's `cannot find -loxicrypt_ffi` rather than a page of undefined `oxi_*` references, and emits the search path and `cfg(oxicrypt_lib)` (declared with `cargo:rustc-check-cfg`, so a consumer who denies warnings is not tripped by an unexpected cfg) only when the variable is set. `cargo check`, `cargo clippy` and `cargo doc` do not link and succeed either way; docs.rs builds the crate without the library.

When the variable is set, the script looks at the directory and chooses the library file by name, never by the linker's search rules, because every platform's linker has a rule that can pick the static archive and the archive would compile the module into the program while the program still runs:

| Platform | Shared library the consumer built and signed | What the script links | The hazard the choice avoids |
|---|---|---|---|
| Linux (glibc) | `liboxicrypt_ffi.so` | `dylib:+verbatim=liboxicrypt_ffi.so` | `-loxicrypt_ffi` takes `liboxicrypt_ffi.a` when the `.so` is absent |
| Android (bionic) | `liboxicrypt_ffi.so`, linked for 16 KiB pages | `dylib:+verbatim=liboxicrypt_ffi.so` | as Linux |
| macOS | `liboxicrypt_ffi.dylib` | `dylib:+verbatim=liboxicrypt_ffi.dylib` | `-loxicrypt_ffi` takes `liboxicrypt_ffi.a` when the dylib is absent |
| Windows, MSVC | `oxicrypt_ffi.dll` with its import library `oxicrypt_ffi.dll.lib` | `dylib:+verbatim=oxicrypt_ffi.dll.lib` | `oxicrypt_ffi.lib` in the same directory is the static archive |
| Windows, GNU | `oxicrypt_ffi.dll` with its import library `liboxicrypt_ffi.dll.a` | `dylib:+verbatim=liboxicrypt_ffi.dll.a` | GNU ld searches `libxxx.a` before `xxx.dll`, so without the import library it links the archive |

The release workflow builds Windows artifacts with the MSVC toolchain only; the GNU row describes a library the consumer builds and signs themselves. The script refuses, naming the file it wanted, when the shared library (or import library) named above is absent from the directory, whatever else the directory holds. It accepts the static archive beside the shared library only because verbatim naming makes the choice unambiguous; on a target where the toolchain does not honour verbatim naming, the script refuses a directory that holds both and asks for one holding the shared library alone. The directive is not the whole guard: a negative link test (see *Tests and CI*) places the archive alone, and then both, in `OXICRYPT_LIB_DIR` on every platform and requires the archive-only case to fail to link and the both-present case to produce a program with no integrity slot that imports `oxi_init`.

The second variable the script reads is `OXICRYPT_LIB_FINGERPRINT=sha256:<64 hex digits>`, the fingerprint of the verifying key the library embeds, as `oxicrypt-integrity-sign --show <library>` prints it. The script bakes it into the crate with `cargo:rustc-env`, and `Module::init` compares it against the fingerprint the library reports before returning a token (see *Initialisation*). It is required: a build with `OXICRYPT_LIB_DIR` set and no fingerprint is refused, unless `OXICRYPT_LIB_UNPINNED=1` states that the consumer accepts any honestly signed library. A consumer of a release library takes the fingerprint from the crate's documentation, which states it per release as prose beside the version, so that a key rotation is a documentation change and not a crate release carrying a key. The pin catches an honestly built library signed with another key, the case a packaging mistake produces; it does not resist a library that lies about its fingerprint, which no code outside the boundary can.

No header is parsed at build time. The crate declares every function of the C ABI by hand in a private `sys` module, and a workspace test pins those declarations against `include/oxicrypt.h` (see *The sys module*). The consumer therefore needs no C compiler and no header, only the library.

**Run-time search path is the consumer's.** A `cargo:rustc-link-arg` from this crate's build script reaches this crate's own targets, not the dependent application's binary, so the crate cannot embed a run-time search path on the consumer's behalf. The consumer either deploys the library where the loader looks (below) or sets the path in their own build: `-C link-arg=-Wl,-rpath,<dir>` on ELF (with `-Wl,--enable-new-dtags`, so the entry is `RUNPATH` and the environment can still override it for a test) and `-C link-arg=-Wl,-rpath,<dir>` on macOS, from their `build.rs` or `.cargo/config.toml`. The crate's documentation gives both recipes, and the crate's CI tests them with a real external consumer crate (a fixture package outside the workspace that depends on the binding), inspecting that consumer's dynamic section and launching it with the loader's environment variables cleared.

### At run time

The operating system's loader resolves `liboxicrypt_ffi` before the program's `main` runs, by the platform's rule:

- Linux: `DT_RPATH` of the program if present, then `LD_LIBRARY_PATH`, then `DT_RUNPATH`, then the system library directories. The environment therefore overrides a `RUNPATH` and is overridden by an old-style `RPATH`, which is why Evidence E5 could point a `RUNPATH` binary at the unsigned copy. The program's dynamic section records the library's `SONAME`, `liboxicrypt_ffi.so.<ABI>` (D3), so the loader looks for that file; the plain `liboxicrypt_ffi.so` is a link to it for the linker. E3 predates D3 and shows the unversioned `NEEDED liboxicrypt_ffi.so` of a library without a `SONAME`.
- Android: the application's native library directory (`lib/<abi>/` in the package), which bionic searches for a `DT_NEEDED` entry of a library the application loaded; a host build directory and an environment variable say nothing about this, so the Android controls run on packaged libraries (see *Tests and CI*).
- macOS: the dylib's install name, resolved through the program's `rpath` entries when it begins with `@rpath/`. The library's build sets its install name to `@rpath/liboxicrypt_ffi.<ABI>.dylib` (D3), so the program resolves that file through its `rpath`, and the release tarball ships the dylib under that name with the plain name a link to it.
- Windows: modules already loaded in the process and the known-DLL list first; then the application's directory, the system directory, the 16-bit system directory, the Windows directory, the current working directory, and `PATH` last. A stale `oxicrypt_ffi.dll` beside the executable, in the system directory or in the working directory is found before anything `PATH` names, and changing `PATH` cannot displace it. The consumer's deployment places the DLL in the application directory, and may call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)` to remove the working directory from the search.

**When the library is missing.** The loader refuses to start the program, before any Rust code runs, with its own message: on Linux `error while loading shared libraries: liboxicrypt_ffi.so.1: cannot open shared object file`, naming the library's delivered name, exit status 127 (E6, which predates D3, shows the unversioned name). The crate cannot report this itself; that is the trade-off of link-time linking, stated in *Alternatives rejected*. The crate's documentation quotes each platform's message so the consumer recognises it.

**When a symbol is missing.** Rust links programs with full RELRO and immediate binding on Linux (`FLAGS: BIND_NOW`, E3), so a library that lacks a function the program references is refused at load, not at the first call. The linker checks only the symbols a program references, which are the functions the safe layer calls, not every declaration in `sys` (E7 shows the two the experiment's program referenced). The crate's integration test binary therefore holds a `#[used]` table of one function pointer per `sys` declaration, so that loading the test binary checks the library's whole export inventory at once. A consumer's program is checked for the functions it references, and only those: a library missing one of them stops the program at load with the loader's own message, before `main`, rather than returning a typed `InitError`. That is accepted because it is the earlier and the louder failure: no code of the program runs against an incomplete library, and the same-version rule means a released library missing an export is a packaging defect, not a state a program should handle at run time. A library missing a function the program does not reference is not detected in that program, and needs not be.

**When the library is the wrong version.** Symbol resolution does not establish ABI compatibility: a function that keeps its name while its parameters, return type or required output length change still resolves. What establishes it is a number: `oxi_abi_version()` (D1) returns the C interface's ABI number, independent of the release version, which changes only when the interface breaks compatibility (a function removed, a signature or an output size changed) and not when functions are added; the `oxicrypt-ffi` ABI pin (D1) records each function's parameter and return types and each status code at that number, and fails when one is removed or changed while the number stays, or when a recorded line is edited; output sizes and meaning are outside it. Compatibility within a number runs one way: a library of a later release serves a crate built earlier, but a crate that calls a function added later in the same ABI cannot load an older library of that number, which fails at load (immediate binding), not through the number. The crate declares the ABI number it was built against and, before `oxi_init`, calls `oxi_abi_version()` and refuses on inequality with `Error::LibraryAbi { library, crate_ }`. A library that predates the function has no such symbol, so the crate resolves it weakly (through `library_path`'s platform lookup, `dlsym` / `GetProcAddress`, never a link-time reference), and only in the image the program's own `lama_manifest` reference bound to: on Unix the crate finds that image with `dladdr`, opens it by its path with `RTLD_NOLOAD`, looks the symbol up in that handle and accepts it only if `dladdr` places it in the same image; on Windows it calls `GetProcAddress` on the module holding `lama_manifest`'s string. That defeats an accidental or later-loaded foreign definition, a plugin or an object defining `oxi_abi_version` alone; it does not resist a preloaded object that also defines `lama_manifest`, which then is the image the program binds to for every function it defines, at load, before the crate runs. No check inside the crate resists someone who controls the launch, which is outside the threat model (*Scope and threat model*; integrity-extent-v2.md, *Threat model*). The lookup is exercised on Linux only: the macOS `dladdr`→`RTLD_NOLOAD` path and the mismatch test on targets other than x86_64 run only where a CI job provides them, and the CI workflows have no macOS job for the crate. When the symbol is absent the crate falls back to the exact-version rule: `lama_manifest()` returns the library's API manifest, whose `version:` key directly under the top-level `library:` mapping is the workspace version the library was built from (E5 prints that line), and the value must equal `CARGO_PKG_VERSION` exactly, else `Error::LibraryVersion { library, crate_ }`. The parser reads that key and no other `version:` in the document; its positive control is a manifest fixture with a decoy `version:` earlier in the file. A manifest that cannot be parsed, which is what a library built from a checkout where the manifest symlink was materialised as a text file would return, is the same refusal. Both checks call nothing that needs initialisation. The `SONAME` that follows the ABI number (D3) lets the loader refuse a major mismatch before any of this runs, on the platforms that have one.

## Building and signing the library

The consumer either downloads a signed release library and pins the project's verifying-key fingerprint, or builds the library from source and signs it with a key of their own. Both procedures, per platform, are in [`docs/integrity-signing.md`](../integrity-signing.md), and this document does not restate them. What this design adds is where the signer sits relative to the consumer's build.

Cargo has no step after linking, so a signed shared library cannot be produced as a cargo dependency, and the crate's build script never signs: a private key is not a build input of an application. The signer runs in the consumer's own pipeline, outside cargo, between building the library and running anything that loads it:

1. `oxicrypt-integrity-sign --keygen <dir>` once, outside any source tree.
2. `OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release -p oxicrypt-ffi`, with the platform's link settings from `docs/integrity-signing.md`.
3. `oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key <library>`, in the platform's signing order, then `--verify`, and `--show` for the fingerprint.
4. `OXICRYPT_LIB_DIR=<directory holding the signed library> OXICRYPT_LIB_FINGERPRINT=sha256:… cargo build` of the consumer's program.

Steps 1 to 3 are a script or a CI job in the consumer's repository; the signed library is a build artifact they keep. Linking (step 4) needs only the library's exports, which signing does not change, so the order of steps 3 and 4 is free; running the program needs the signed library on the loader's path. A consumer who downloads a release library skips steps 1 to 3 and takes the fingerprint from the crate's documentation.

## Tests against a throwaway key

A `cargo test` binary of the consumer is never signed and does not need to be. The module is the library; the test binary is a C-style host of it, and the library verifies itself whatever loaded it (integrity-extent-v2.md, *Runtime routes*). This differs from a program that compiles the module in, which must declare the unsigned-binary stub `docs/integrity-signing.md` describes; a consumer of this crate never writes that stub.

The consumer's tests therefore run against a library signed with a key their test or CI pipeline generates: `--keygen` into a temporary directory, build with that public key, sign with that private key, set `OXICRYPT_LIB_DIR` and `OXICRYPT_LIB_FINGERPRINT` from `--show`, set the run-time path in the test build or the environment, and `cargo test`. The key identifies one run and is discarded with it. Evidence E1 to E5 is this procedure, on Linux x86_64, from an empty directory.

Two facts about test processes follow from initialisation being once per loaded instance. First, `Module::init` is idempotent, so every test may call it; tests in one test binary share one initialised library. Second, all tests in one binary must agree on the profile: the library accepts a later `oxi_init` with a different profile and keeps the first, and the crate reports that as `Error::ProfileMismatch` to the caller whose request differs (see *Initialisation*), so tests that need another profile go in another test binary.

## The safe layer

### Initialisation

`Module::init(profile) -> Result<Module, InitError>` performs, in order:

The requested profile is first normalised with `Profile::from_code(profile.code())`, so `Unknown(1)` and `Cnsa2` are one request.

1. The version check above, once per loaded instance; its outcome is kept.
2. `oxi_init(profile)`. The first call into the library runs the self-tests and takes about 180 ms on the measured hosts (`docs/power-up-performance.md`); the call blocks for that long, and a C caller initialising the same instance concurrently is safe and makes one side wait.
3. If the code is non-zero: `InitError { code: Error, integrity: Option<IntegrityStatus>, detail: Result<Option<String>, DetailError> }`, built from the code as returned, `oxi_integrity_status()`, and `oxi_integrity_status_detail()`, whose four ways of failing (the sizing call, a text over the crate's 64 KiB bound, the reading call, a reported length over the buffer) are `DetailError` variants rather than an absent text. `integrity` is `None` only when the version check refused the library, which is then called for nothing but `oxi_abi_version` and its manifest. Nothing is invented: a library whose first initialisation (by any caller) failed on an algorithm self-test returns `NotOperational` (1) to a later call, with the integrity indicator `Passed` and no detail, and the error says exactly that; a library that failed its integrity test returns `SelfTestFailed` (2) with the indicator naming why (E5 second run: code 2, indicator `SlotInvalid`). Each call reports what the library returned to that call, and reads the indicator and the text afresh: the library's code differs between calls (an unsigned library returns 2 to the first and 1 to every later one), so a first code is never reported as the current one.
4. If the code is zero: `oxi_is_operational()` is read live, not cached, and must be 1; `oxi_integrity_status()` must read `Passed`, else `IntegrityUnverified`; then, in a pinned build, the fingerprint is checked (below); then `oxi_active_profile()` is read live and compared with this caller's requested profile, else `ProfileMismatch { active, requested }`. The comparison runs on every call, for that call's profile, and is never cached: a first caller refused for a mismatch does not poison a later caller whose profile is the active one. A library with a profile the crate does not know reports `Profile::Unknown(i32)` in `active`.

What is cached is therefore the version check alone. What is read each time is the code, the indicator and its text, the current state, the fingerprint and the active profile. `Module` is a zero-sized `Copy` token; every operation is a method on it, so a call before initialisation does not compile. The library's own gate (`NotOperational` on every service) remains the enforcement, and `Module::is_operational()` reads the live state for an application that wants to know whether a conditional self-test has since moved the instance to its error state.

When the crate was built with `OXICRYPT_LIB_FINGERPRINT`, step 4, after the operational check, calls `oxi_integrity_key_fingerprint` and refuses with `InitError { code: KeyFingerprint { found, expected }, .. }` when the library's self-reported key is not the pinned one. `Module::init_unpinned(profile)` is the explicit opt-out for a crate built with `OXICRYPT_LIB_UNPINNED=1`; a crate built with a pin has no unpinned entry point. `Module::key_fingerprint()` returns the reported value for logging. `Module::integrity_status()` returns the latched indicator as an enum of the eleven values the header lists, plus `Unknown(i32)`. `Module::library_path() -> Option<PathBuf>` reports which file the loader bound, through `dladdr` on the manifest pointer `lama_manifest()` returns, which lies in the library's own image (Linux, Android, macOS) and `GetModuleHandleExW` with `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` plus `GetModuleFileNameW` (Windows), three hand-declared `extern "C"` functions behind `cfg`; it is a diagnostic for a log line and never a check.

`Profile` is a `#[non_exhaustive]` enum with the four values the header defines (`Unrestricted`, `Cnsa2`, `Cnsa1`, `Migration`) and `Unknown(i32)`, which exists for the read side. `Unknown` of a code the crate knows is that profile, by the normalisation above; `Unknown` of any other code is sent as its integer, which the library refuses with `InvalidInput` without initialising. `Error` and `IntegrityStatus` are `#[non_exhaustive]` too, so a later release can add a variant without breaking a caller's `match`.

### Errors

`Error` is an enum with one variant per `OxiResult` discriminant, in the header's order and with the header's meaning: `Ok` is never a variant; codes 1 to 12, 20 to 28 and 255 each have one; `Unknown(i32)` holds any other value, negative or unassigned, a newer library might return; and four crate-level variants exist for `LibraryAbi`, `LibraryVersion`, `ProfileMismatch` and `KeyFingerprint`. The mapping is `fn from_code(code: i32, site: Site) -> Error` with `Site::{AeadDecrypt, SignatureVerify, Other}`, and the round-trip test runs per site.

cbindgen emits only types reachable from exported signatures, and every `oxi_*` returns `int`, so `OxiResult` is exported into `oxicrypt.h` explicitly through the cbindgen configuration (D2): the header carries `OXI_RESULT_TAG_MISMATCH = 22` and the rest. The mapping is pinned by a workspace test that reads those lines of the committed header and requires `from_code(N, site)` to produce the variant named for `N` at every site in which that code is not remapped; a discriminant the header gains that the crate does not map fails that test.

Code 22 (`TagMismatch`) is the one the C ABI reuses across families, for an AEAD tag that did not verify and for a signature that did not verify. The crate knows which function it called, so `Site::AeadDecrypt` maps 22 to `Error::TagMismatch` and `Site::SignatureVerify` maps it to `Error::SignatureInvalid`; `ml_dsa_87_verify` also returns 22 for a signature or key that does not decode, and the tests cover that case by feeding a truncated encoding, since the header says the two are not distinguished. `ml_kem_1024_decapsulate` returns no error for a tampered ciphertext (implicit rejection, by design of the scheme), and the crate invents none. Verification returns `Result<(), Error>`, never `bool`, so an unused result is a compiler warning by default; a program can still discard it with `let _ =`, and no type can stop that.

Every fallible operation returns `Result<T, Error>`. An output is exposed only when the status is 0: the crate allocates the output in its final owner before the call, hands the library a pointer into it, and on any non-zero status drops that owner (zeroing it when it is a secret) and returns the error. A `Copy` token does not make a service infallible: a conditional self-test can move the instance to its error state between calls (`NotOperational`), a profile can forbid an algorithm (`AlgorithmRestricted`), and an input can be refused (`InvalidInput`).

`Error` and `InitError` implement `std::error::Error` and `Display` with the header's wording; `Debug` prints the variant and its fields, none of which is secret.

### Sizes

The header has no `#define` for any length; each size lives in a function's documentation. The crate defines them as `pub const` and types the fixed-size inputs and outputs as arrays, so a buffer of the wrong size does not compile:

| Constant | Value | From |
|---|---|---|
| `SHA384_LEN` | 48 | `oxi_sha384` |
| `HKDF_SHA384_PRK_LEN` | 48 | `oxi_hkdf_sha384_extract` |
| `HKDF_SHA384_MAX_OKM_LEN` | 12,240 | `oxi_hkdf_sha384_expand`, 255 × 48 (RFC 5869 §2.3) |
| `AES256_KEY_LEN` | 32 | `oxi_aes256_new` |
| `AES256_GCM_NONCE_LEN` | 12 | `oxi_aes256_gcm_encrypt` |
| `AES256_GCM_TAG_LEN` | 16 | `oxi_aes256_gcm_encrypt` |
| `HMAC_DRBG_MAX_PROVIDED_LEN` | 768 | `oxi_hmac_drbg_sha256_instantiate` |
| `HMAC_DRBG_MAX_REQUEST_LEN` | 65,536 | `oxi_hmac_drbg_sha256_generate` (SP 800-90A Table 3) |
| `ML_DSA_87_SEED_LEN` | 32 | `oxi_ml_dsa_87_keygen` |
| `ML_DSA_87_PUBLIC_KEY_LEN` | 2,592 | `oxi_ml_dsa_87_keygen` |
| `ML_DSA_87_SECRET_KEY_LEN` | 4,896 | `oxi_ml_dsa_87_keygen` |
| `ML_DSA_87_SIGNATURE_LEN` | 4,627 | `oxi_ml_dsa_87_sign` |
| `ML_DSA_87_MAX_CONTEXT_LEN` | 255 | `oxi_ml_dsa_87_sign` (FIPS 204 §5.2) |
| `ML_KEM_1024_SEED_LEN` | 32 | `oxi_ml_kem_1024_keygen` (each of `d`, `z`, `m`) |
| `ML_KEM_1024_ENCAPSULATION_KEY_LEN` | 1,568 | `oxi_ml_kem_1024_keygen` |
| `ML_KEM_1024_DECAPSULATION_KEY_LEN` | 3,168 | `oxi_ml_kem_1024_keygen` |
| `ML_KEM_1024_CIPHERTEXT_LEN` | 1,568 | `oxi_ml_kem_1024_encapsulate` |
| `ML_KEM_1024_SHARED_SECRET_LEN` | 32 | `oxi_ml_kem_1024_encapsulate` |

Two tests pin them. A behavioural test runs each operation against the real signed library with known-answer inputs from `oxicrypt-test-vectors` (a dev-dependency: vector data, no module code, never compiled into a consumer) and requires the known output, which no wrong length produces. A workspace test compares each constant with the algorithm crate's own constant (`oxicrypt_ml_dsa`, `oxicrypt_ml_kem`, `oxicrypt_sha`, `oxicrypt_kdf`, `oxicrypt_aes`, `oxicrypt_drbg`), also as dev-dependencies, so the crate's numbers cannot drift from the module's. Neither test reaches a consumer's build.

### Secrets

Every type that holds a secret zeroes its bytes on drop and prints only its type name from `Debug`:

| Type | Holds | Produced by |
|---|---|---|
| `Aes256Key` | an opaque handle; the crate makes no copy of the 32 key bytes, which `aes256_key` passes from the caller's array to `oxi_aes256_new` | `Module::aes256_key` |
| `HmacDrbgSha256` | an opaque handle whose `(K, V)` state the library zeroes on free | `Module::hmac_drbg_sha256` |
| `HkdfPrk` | 48 bytes | `hkdf_sha384_extract` |
| `Okm` | `len` bytes, heap | `hkdf_sha384_expand` |
| `MlDsa87SecretKey` | 4,896 bytes, heap (`Box`) | `ml_dsa_87_keygen` |
| `MlKem1024DecapsulationKey` | 3,168 bytes, heap (`Box`) | `ml_kem_1024_keygen` |
| `SharedSecret` | 32 bytes | `ml_kem_1024_encapsulate`, `ml_kem_1024_decapsulate` |
| `MlDsa87KeySeed`, `MlKem1024KeySeedD`, `MlKem1024KeySeedZ`, `MlKem1024EncapsSeed` | 32 bytes, one type per seed role, consumed by the call that uses it | each type's `from_bytes`, or `HmacDrbgSha256::seed` |

**Ownership before the write.** The library writes each secret directly into the storage its final owner will zero: the crate constructs the owner (a zeroing stack array for the small types, a zeroed `Box<[u8; N]>` for the two large keys and `Okm`) before the call and passes a pointer into it. There is no plain intermediate array that is later converted, so there is no earlier location left unwiped. A non-zero status drops the owner, which zeroes it. A panic between the owner's construction and the return unwinds through the owner's `Drop`, which zeroes it. The crate makes no temporary copy of a caller's secret: `aes256_key` hands the caller's key array to `oxi_aes256_new`.

**What zeroing does not cover.** `Drop` zeroes the final resting copy. Moving a value by return may leave an unzeroed copy in a dead stack frame or a register spill, which is why the two large keys are boxed (the move carries a pointer, not the bytes) and why the 32- and 48-byte types are accepted as a stated limitation, the same one the module's security policy states for itself (§9.2 *Limitations*). A seed is taken by value, so the call that uses it consumes it and zeroes it once the library has read it. Moving the 32-byte seed into the call may leave one more unzeroed copy in the caller's dead frame or a register, under the same stated limitation; that is a deliberate trade, because a seed taken by reference could be passed to a second encapsulation, and reuse of `m` across recipients is a break of the scheme where a stale copy in a dead frame is not. Copies the application makes are the application's. Caller-owned buffers the crate wrote on a failed call are wiped before the error returns (see *Coverage*, GCM decrypt).

**Zeroing primitive and its tests.** Zeroing is one function, `wipe(&mut [u8])`: a loop of `core::ptr::write_volatile` over the bytes followed by a compiler fence, implemented in the crate; it does not use `oxicrypt-zeroize`, which is a module crate and must not be linked, and it adds no third-party dependency. Three tests observe it. The primitive is tested on a live buffer: fill, read non-zero (the positive control), `wipe`, read zero. The destructor of a stack-backed type is tested without reading freed or moved-from memory and without a reference to the value: `let mut slot = ManuallyDrop::new(secret); let p: *mut T = (&raw mut slot).cast();` read the byte array field non-zero through `p`, `ptr::drop_in_place(p)`, read it zero through `p`; the storage stays live and every read is of fully initialised bytes. The destructor of a heap-backed type is tested through a test-only `#[global_allocator]` that records whether the bytes of each freed block were zero at `dealloc` time, with the positive control of a plain `Vec` holding non-zero bytes recorded as not zero. The `unsafe` tests run under Miri in CI.

**What secret types do not implement.** No `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Display`, `Deref`, `AsRef<[u8]>` or serialisation. Comparison is the library's. Bytes come out only through the explicit `as_bytes()`, and in only through `from_bytes()`. A decapsulation key used for many ciphertexts is borrowed, never cloned. Public keys, ciphertexts, signatures, digests and tags are plain arrays with ordinary derives.

### Handles

`Aes256Key` owns a `NonNull<sys::OxiAes256Key>` obtained from `oxi_aes256_new` and calls `oxi_aes256_free` exactly once, in `Drop`. The pointer is private, never copied out, and the type is not `Clone`, so a double free cannot be written. It is `Send` and `Sync`: the handle holds only the key schedule, every mode function takes it by `const` pointer, and the module's security policy states the handle has no per-call state (§4.8).

`HmacDrbgSha256` owns a `NonNull<sys::OxiHmacDrbgSha256>` the same way, freed exactly once. Every operation on it mutates the library-side state, so `instantiate`, `reseed`, `generate` and `seed` take `&mut self`; the type is `Send` and not `Sync`.

### The sys module

A private module declares every function in `oxicrypt.h`, all 293 exported symbols (292 `oxi_*` and `lama_manifest`; E2 counted 292 before `oxi_abi_version`), with `unsafe extern "C"` and the header's exact parameter and return types (`*const u8`, `*mut u8`, `usize` for `uintptr_t`, `c_int`, `*const c_char`, opaque `#[repr(C)]` structs for the handle types). A workspace test reads the committed header, extracts each declaration's name, parameter types and return type, and compares the set with the `sys` module's; a function added to the C ABI without a `sys` declaration fails that test, and so does a change to a signature. The header is generated by cbindgen and verified byte-identical in CI, so the test pins the crate to the ABI the library actually exports. The test is an inventory check; what makes the inventory the library's is the ABI number check in *Finding the library* (D1), or the exact-version fallback for a library that predates it.

### Every `unsafe` obligation and its discharge

Each `unsafe` block in the crate cites one of these by number in a `// SAFETY:` comment, and no `unsafe` appears outside the `sys` module's call sites, the handles' `Drop` and their `Send` and `Sync` impls (U7), the zeroing primitive and `library_path`.

| # | Obligation | Discharged by |
|---|---|---|
| U1 | the declared signature matches the function the library exports | the header-pinning test (names, parameters, return types) for the inventory; the ABI number check (D1), with the exact-version fallback, for the ABI; the linker and immediate binding for the referenced subset, and the test binary's function-pointer table for the whole inventory |
| U2 | each `(ptr, len)` pair names `len` readable bytes | taken from a `&[u8]` by `as_ptr()` and `len()`; an empty slice passes NULL with length 0, which every wrapped function accepts as an empty input, and HMAC_DRBG as an absent additional input or personalization string |
| U3 | each fixed-size output pointer names at least the documented number of writable bytes | the output is an array of the constant from *Sizes*, owned as *Secrets* describes, taken by `as_mut_ptr()` |
| U4 | a handle passed to the library is live and was returned by its `_new` | the pointer is private to the handle type, set once from a successful `new`, and freed only in `Drop` |
| U5 | `lama_manifest()` returns a NUL-terminated string valid for the library's lifetime | stated by the header; read with `CStr::from_ptr` and copied before use |
| U6 | `oxi_integrity_status_detail` is called with `out_len` 0 first, then with a buffer of the size it wrote | the two-call sequence in one function |
| U7 | the library is called from several threads | every wrapped one-shot function and `Aes256Key` are read-only on the Rust side and the module's state gate is atomic; `HmacDrbgSha256` takes `&mut self` and is not `Sync` |
| U8 | the zeroing loop writes only inside the type's own bytes | `write_volatile` over `as_mut_ptr()..len()` of the owned storage |
| U9 | a variable-length output the C function sizes from an input length, or from a length the crate passes, has at least that many writable bytes, and an allocation the crate makes for it is bounded | checked by the crate before the call: `ciphertext.len() == plaintext.len()` (and the reverse) for GCM, else `Error::LengthMismatch` without calling; `len <= HKDF_SHA384_MAX_OKM_LEN` before allocating `Okm`, and `out.len() <= HMAC_DRBG_MAX_REQUEST_LEN` before a DRBG `generate`, whose C function allocates a buffer of the requested length before refusing it, else `Error::OutputTooLong` without calling, a resource check the header's bound makes exact |
| U10 | `dladdr` / `GetModuleHandleExW` are given an address inside the library and a buffer they may fill | the address is the pointer `lama_manifest()` returns, not a function's address, which in a program that is not position-independent is the program's own PLT entry; the output structures are zero-initialised locals of the documented size; a failure returns `None` |

## Coverage

The first release wraps module initialisation and the operations below, chosen from a measured consumer workload:

| Operation | C functions | Rust |
|---|---|---|
| initialise with a profile | `oxi_init`, `oxi_active_profile`, `oxi_is_operational`, `oxi_integrity_status`, `oxi_integrity_status_detail`, `oxi_integrity_key_fingerprint`, `lama_manifest` | `Module::init`, `init_unpinned`, `is_operational`, `integrity_status`, `key_fingerprint`, `library_path` |
| SHA-384 | `oxi_sha384` | `sha384(&[u8]) -> Result<[u8; 48], Error>` |
| HKDF-SHA384 extract and expand | `oxi_hkdf_sha384_extract`, `oxi_hkdf_sha384_expand` | `hkdf_sha384_extract(salt: Option<&[u8]>, ikm) -> Result<HkdfPrk, Error>`, `hkdf_sha384_expand(&HkdfPrk, info, len) -> Result<Okm, Error>` |
| AES-256 key, AES-256-GCM | `oxi_aes256_new`, `oxi_aes256_free`, `oxi_aes256_gcm_encrypt`, `oxi_aes256_gcm_decrypt` | `aes256_key(&[u8; 32]) -> Result<Aes256Key, Error>`, `aes256_gcm_encrypt(&key, &nonce, aad, plaintext, ciphertext_out) -> Result<[u8; 16], Error>`, `aes256_gcm_decrypt(&key, &nonce, aad, ciphertext, plaintext_out, &tag) -> Result<(), Error>` with `TagMismatch` its own variant and `plaintext_out` wiped on every non-`Ok` return |
| HMAC_DRBG-SHA-256 | `oxi_hmac_drbg_sha256_new`, `_free`, `_instantiate`, `_reseed`, `_generate` | `hmac_drbg_sha256() -> Result<HmacDrbgSha256, Error>`, `instantiate(entropy, nonce, personalization)`, `reseed(entropy, additional)`, `generate(additional, out: &mut [u8])`, `seed<S: DrbgSeed>() -> Result<S, Error>` |
| ML-DSA-87 | `oxi_ml_dsa_87_keygen`, `oxi_ml_dsa_87_sign`, `oxi_ml_dsa_87_verify` | `ml_dsa_87_keygen(MlDsa87KeySeed) -> Result<(MlDsa87PublicKey, MlDsa87SecretKey), Error>`, `ml_dsa_87_sign(&sk, msg, ctx) -> Result<MlDsa87Signature, Error>` (deterministic, as the C ABI is), `ml_dsa_87_verify(&pk, msg, ctx, &sig) -> Result<(), Error>` |
| ML-KEM-1024 | `oxi_ml_kem_1024_keygen`, `oxi_ml_kem_1024_encapsulate`, `oxi_ml_kem_1024_decapsulate` | `ml_kem_1024_keygen(MlKem1024KeySeedD, MlKem1024KeySeedZ) -> Result<(ek, dk), Error>`, `ml_kem_1024_encapsulate(&ek, MlKem1024EncapsSeed) -> Result<(SharedSecret, Ciphertext), Error>`, `ml_kem_1024_decapsulate(&dk, &ct) -> Result<SharedSecret, Error>` |

**Seeds and approved status.** ML-DSA-87 key generation, ML-KEM-1024 key generation and encapsulation take caller-supplied seeds, as the C ABI does; the crate generates no randomness of its own. The approved status of a key generated through this crate depends on where the seed came from. IG 9.5.A's software-module paragraph states that a key generated inside the module must come from an approved DRBG and that a key generated outside the module is out of scope. The library's HMAC_DRBG-SHA-256 handle is wrapped in the first release so that seeds can be drawn from the module's DRBG (`HmacDrbgSha256::seed`); that DRBG is itself caller-seeded through `instantiate` and `reseed`, the module's entropy source not being wired to the C ABI's DRBG handles, so the consumer supplies entropy meeting SP 800-90A and SP 800-90B and documents its source in their own security policy, as the module's policy requires of every C ABI caller. A seed drawn from an operating-system generator through a seed type's `from_bytes` is a seed from outside the module. The crate's documentation says this beside the keygen functions, not in a footnote.

Encrypt and decrypt write into a caller-supplied output slice of the input's length (U9) and return or take the tag, so a large message is not copied twice; `Vec`-returning conveniences sit on top.

**The rest of the C ABI.** The `sys` module declares all of it from the first release, so the header-pinning test and the test binary's function-pointer table cover the whole inventory; the safe layer grows by family, each family landing with its known-answer tests from `oxicrypt-test-vectors` and its error mapping, in this order: the other SHA-2, SHA-3 and SHAKE digests and HMAC; the remaining AES-256 modes and the AES-128/192 handles; the other DRBG handles; HKDF with the other hashes and the other KDFs; ML-DSA-44/65 and ML-KEM-512/768; ECDSA, EdDSA, ECDH and the finite-field DH; RSA; SLH-DSA, LMS and XMSS verification. A function the safe layer does not yet wrap is reachable through nothing: `sys` is private, and a consumer who needs a function early asks for it or uses the C ABI directly. A list in the crate's documentation names, per release, which header functions the safe layer wraps, and a test keeps that list equal to the set of `sys` functions the safe layer references, so coverage is a checked count.

## Name and versioning

**Name.** The crate is published as `oxicrypt` (D6): one crate, the raw layer a private `sys` module, with `links = "oxicrypt_ffi"` in its manifest so cargo refuses two crates in one dependency graph that both claim the library. `links` does not see an independently built plugin or a second copy of the library a plugin loads by path; those are the unsupported configurations *Scope and threat model* names. The bare name is the one a reader could mistake for the module itself, so the crate's README states in its first lines that it is the Rust interface to a separately built and signed library, outside the boundary, and not the module. A separate `oxicrypt-sys` can be split out later without breaking users of `oxicrypt`, because the `sys` module is private.

**Versioning and the ABI compatibility policy.** The crate is a workspace member with `version.workspace = true` and is published in the same release as `oxicrypt-ffi`, so the header it was pinned against and the library a release ships carry the same number. The compatibility policy is the ABI number (D1): a crate declares the ABI number it was built against, and at run time accepts a library reporting that number, whatever its release version, because the number moves only when the C interface breaks compatibility. What ties the number to the interface is the `oxicrypt-ffi` ABI pin: each function's parameter and return types and each status code value, recorded per number, frozen against editing. What it does not cover is pinned elsewhere or by review: the sizes in *Sizes* by the binding's size and known-answer tests, which compare the binding with the current header and module, and the handle contracts and meanings by review. Compatibility within a number runs one way. A consumer running a library at a fixed version, as a validated library is, can take a later crate while the ABI number holds only if that crate calls no function the library lacks; one that does fails at load, before any check runs. For a library that predates `oxi_abi_version()` the fallback is exact: a crate at version V requires a library at version V, and a fix to the crate alone cannot reach such a consumer.

The crate's `[dependencies]` contain no `oxicrypt-*` crate. A CI check runs `cargo tree -p <crate> -e normal --prefix none | tail -n +2 | grep '^oxicrypt-'` and requires no output (the first line is the crate itself and is skipped); its positive control is the same pipeline on `oxicrypt-ffi`, which must print `oxicrypt-module`, and a second control adds `oxicrypt-zeroize` to a scratch copy of the manifest and must turn the check red. Dev-dependencies on `oxicrypt-test-vectors` and the algorithm crates exist only for the pinning tests and never reach a consumer. As a publishable crate its public items get entries in `docs/llm-api-manifest/llm-api.yaml` under the repository's coverage rule; its `description` states that it is outside the cryptographic boundary.

**The consumer's own graph.** `links` and the crate's dependency check say nothing about a consumer whose graph pulls `oxicrypt-module` and an algorithm crate through some other dependency; that program holds an unsigned copy of module code beside the signed library, and a call to it looks like a call through the binding. The `--show` and `nm` probe does not catch it (no slot, no `oxi_*` symbol defined). The consumer-side probe is `cargo tree -i oxicrypt-module` on the consumer's own graph, which must print nothing; the crate's documentation gives it beside the `--show` probe.

## Tests and CI

The crate's tests prove it against a real signed library, never a stub:

1. **Fixture.** A script in `scripts/` takes a directory, generates a key pair in it, builds `oxicrypt-ffi` with that public key and the platform's link settings, signs the library into `<dir>/signed/` with `scripts/release-sign.sh`, keeps the library as linked in `<dir>/unsigned/`, keeps the static archive in `<dir>/archive/`, and prints the `OXICRYPT_LIB_FINGERPRINT` value from `--show`. CI runs it with the release workflow's test key source; a contributor runs it once per checkout. The pre-push gate runs it only when `scripts/gate-scope.sh` reports that a file the linked tests are built from changed (the binding crate, any crate under `crates/`, the signer, the signing and fixture scripts, the gate itself and the build configuration), and otherwise runs the crate's tests under `OXICRYPT_LIB_OPTIONAL=1` (D5).
2. **Provisioning.** The build script refuses to link the library without a fingerprint or the opt-out, so an unprovisioned checkout builds the crate only with `OXICRYPT_LIB_OPTIONAL=1`, which builds it unlinked; the workspace gates set it, and the crate's unit tests, its header, error-code and version pins among them, run that way. The crate's linked tests need the fixture: the build script sets `cfg(oxicrypt_lib)` when `OXICRYPT_LIB_DIR` is set, and the integration tests are compiled under it. One always-compiled unit test, `library_is_provisioned`, fails when the cfg is absent unless `OXICRYPT_LIB_OPTIONAL=1` withdraws the claim, which covers a pinned build linking a library from the default search path with no `OXICRYPT_LIB_DIR`. The crate's own targets carry a `RUNPATH` to the fixture's library, which the loader's environment still overrides.
3. **Operational.** `Module::init(Profile::Cnsa2)` succeeds, `integrity_status()` is `Passed`, `key_fingerprint()` equals the fixture's, `library_path()` names `<dir>/signed/…`, and each wrapped operation matches its known answer.
4. **Unsigned control.** A small example binary, whose run-time search path is a `RUNPATH` the loader's environment overrides, prints the init result and the integrity status. The test spawns it with the loader's search path pointed at `<dir>/unsigned/` (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`; on Windows a copy of the example in a directory holding the unsigned DLL, since `PATH` cannot displace a DLL beside the executable) and requires `InitError { code: SelfTestFailed, integrity: Some(SlotInvalid), .. }` and exit status 1. On Android the signed and unsigned libraries are packaged separately and the control runs on the emulator against the package, as the release workflow's load check does. This is the probe that shows the integrity test ran against the library (E5, second run).
5. **Tamper and incompatibility controls.** As the release load check does, a copy of the signed library with one byte flipped inside the extent must be refused with `SignatureInvalid`; a library reporting another ABI number must be refused with `LibraryAbi`, and a copy without `oxi_abi_version` whose manifest version is edited must be refused with `LibraryVersion`; a fixture signed with a second key must be refused with `KeyFingerprint` by a crate built with the first key's pin.
6. **Initialisation shapes.** Subprocess tests for: a C caller (the fixture's C harness, linked into the example) initialising first with another profile, which must give `ProfileMismatch` to the crate's caller and `Ok` to a caller with the active profile; a failed first initialisation followed by a crate `init`, which must report `NotOperational` with the latched indicator; and two threads calling `init` with different profiles, exactly one of which succeeds.
7. **Linking.** The negative link tests: `OXICRYPT_LIB_DIR` holding the static archive alone must fail to link naming the shared library; holding both must produce a test binary with no integrity slot (`oxicrypt-integrity-sign --show` reports none) that imports `oxi_init` (`nm`, `dumpbin /imports`, `otool -L`), on every platform (E7 is the Linux shape). An external consumer fixture, a package outside the workspace depending on the crate, is built with the documented search-path recipe, its dynamic section inspected, and launched with the loader's environment cleared.
8. **Pins.** The header-pinning test, the error-code pin against `error.rs`, the per-site round trip, the constants against the algorithm crates, the manifest parser's decoy control, the three zeroing tests under Miri, the function-pointer table, and the `cargo tree` check with its two controls. The compile-time guarantees (a seed used once, seed roles not interchangeable, the `#[non_exhaustive]` enums) are `compile_fail` doctests, each paired with a compiling doctest that uses the same items correctly. Stable rustdoc does not check the error code a `compile_fail` block names, so a block can pass by failing for an unrelated reason; the compiling companion catches a renamed or removed item, and nothing catches a block that breaks for another reason while its companion still compiles. That gap is stated rather than closed, because closing it means a third-party test harness the crate's dependency list does not otherwise need.
9. **Fault controls.** On Linux, a shared object preloaded into the probe overrides one export of the signed library (`oxi_is_operational` returning 0, returning 1 and then 0, and an `oxi_aes256_gcm_encrypt` that writes and then fails), so that the crate's own refusals behind a correct library's guarantees run: the operational check after `oxi_init`, the live `is_operational`, and the wipe of a failed encryption's output. The library itself is unchanged and its integrity test still passes.
10. **Handles.** A handle census through glibc's `mallinfo2` (glibc 2.33 and later) requires that dropped handles are freed and kept ones counted; a handle freed twice aborts in glibc. On older glibc, and on macOS, Windows, Android and every other non-glibc target, there is no handle-free test, and the census test says so when it runs.
11. **Platforms.** Built, signed and tested: Linux x86_64 with glibc only. `scripts/bindings-fixture.sh` builds and signs ELF libraries only; the CI `bindings` job runs on one Linux x86_64 runner; and the linking, export-inventory, control, fault-control and handle tests are Linux-only, because they read ELF dynamic sections and steer the loader through `LD_LIBRARY_PATH` and `LD_PRELOAD`. For macOS, Windows (MSVC and GNU), Android and Linux arm64, the build script's choice of library file is covered by unit tests of that rule alone; nothing on those platforms is built, linked, signed or run, so the loader behaviour this document describes for them is from platform documentation and the release workflow, not from a test of this crate. A CI job per release platform (Linux arm64, macOS x86_64 and arm64, Windows x86_64 MSVC, Android x86_64 on the emulator), reusing the release workflow's build and signing steps, is not yet built; it needs a fixture script for Mach-O and PE and the platforms' own loader controls (`DYLD_LIBRARY_PATH` and `DYLD_INSERT_LIBRARIES` on macOS, a copy of the program beside the DLL on Windows, a packaged library on Android).

## Alternatives rejected

**Loading with `dlopen` at run time (`libloading`), with an explicit path and eager resolution.** The strongest form of this alternative takes the path from the application, not from the environment, resolves every symbol at open time, and keeps the handle for the life of the process, so it defers nothing to first use and reads no run-time variable. It costs one direct dependency on the only path between the application and the module, a table of about twenty-five function pointers for the first release and an indirect call per operation, platform loading flags (`RTLD_NOW`, `LOAD_LIBRARY_SEARCH_*`), and ownership of the library's lifetime. It buys image selection by the application and a typed error for a missing library or symbol, and it buys the path for free, which link-time linking recovers with `library_path()`. It cannot authenticate hostile code any more than the chosen design can. The decision rests on one point: link-time linking leaves exactly one search rule, the loader's, the same one a C consumer and the release workflow's load checks use, and no second mechanism for an auditor to read.

**Generating the declarations with `bindgen`.** At consumer build time this would need libclang on every consumer's machine and a header the consumer must supply. At maintainer time, with the generated module checked in, it would cost only the tool in the maintainer's workflow and would keep the `sys` module equal to the header by construction; the hand-written module with the pinning test gives the same guarantee and keeps the declarations readable as the header is. Either is acceptable; the design chooses the one with no generator in the loop.

**A third-party zeroing crate.** One direct dependency, which removes the maintenance of a twenty-line primitive; it does not remove the compiler-made copies that *Secrets* states as a limitation, which no library can. The design keeps the primitive in-crate because the crate's dependency list is part of what an auditor reads.

**Compiling the module into the application, as today.** Already available, and the right choice for an application that must be one file. It is the thing this design exists beside, not instead of: a program that does it is one signed image, signed by its builder with their own key, and is not the delivered module (security policy §2.1, §4.7.1).

**Linking the static archive `liboxicrypt_ffi.a`.** The same outcome as compiling the module in, through a longer route: the slot lands in the application's binary and the application must be signed. The design refuses it by name, by directive and by probe (*Finding the library*, *Tests and CI* item 7).

**Letting `Module::init` be `unsafe`, or requiring the application to call `oxi_init` itself.** The initialisation sequence (version, init, status, detail, live state, profile, fingerprint) is the part most easily done half-right, and it is exactly what the C harness in `.github/probes/ffi-operational.c` has to get right by hand.

## Decisions

Three changes to `oxicrypt-ffi`, an out-of-boundary crate, are approved and are built after the binding crate; the binding works against the C ABI as it ships and takes each up when it lands.

- **D1. An ABI number. Implemented.** `int oxi_abi_version(void)` in `oxicrypt-ffi`, returning a number independent of the release version that changes only when the C interface breaks compatibility (a function removed, a signature or an output size changed), never when functions are added. `crates/oxicrypt-ffi/abi/v<N>.txt` records every exported function's parameter and return types and every `OXI_RESULT_*` value at ABI N. The `abi_tests` in `oxicrypt-ffi` require the committed header to keep every recorded line and the file to list every header function and status code, and they hold the file's first lines to a line count and digest recorded in the tests, so a recorded line cannot be edited to follow a break: a removed or changed function, or a renumbered status code, fails until the number moves and a new inventory starts. Lines are only ever appended. The inventory pins names and types; an output size documented in prose is pinned by the binding's size and known-answer tests, not by this file. The binding's run-time check is on this number; the exact-workspace-version rule is the fallback for a library that predates the function. The crate's documentation carries a table of the ABI number the crate was built against and the libraries it accepts: any library reporting that number that exports every function the crate calls, and, without `oxi_abi_version`, only a library of the crate's own release version. Rejected: keying the check to the workspace version alone, which refuses a validated library at a fixed version to every later crate.
- **D2. Error codes in the header. Implemented.** `OxiResult` is exported into `oxicrypt.h` through the cbindgen configuration; the crate's error-code pin reads the header. Rejected: leaving C consumers with the codes in prose only.
- **D3. A `SONAME` and a versioned install name. Implemented.** `liboxicrypt_ffi.so.<ABI>` on Linux and a versioned macOS install name, `@rpath/liboxicrypt_ffi.<ABI>.dylib`, both following the ABI number of D1. Android keeps the plain `SONAME` `liboxicrypt_ffi.so`: an application packages only `lib*.so` names and bionic finds a library by the name its `SONAME` records, so a versioned name would not be delivered or found; the Windows DLL name is unchanged. The release tarballs ship the library under that name with the plain name a link to it (`scripts/library-file-name.sh` reads the name from the built file); `release-sign.sh` and `release-load-check.sh` take the file by path and are unchanged.
- **D4. The shim is outside the boundary.** The maintainer's standing ruling: `oxicrypt-ffi` is outside the cryptographic boundary (security policy §2.1 and §3; `AGENTS.md`). The library's integrity test covers every byte the loader maps, the shim's code included, which is more than `[10.17]` requires and is not a claim that the shim is inside. This document's *Problem* and *Scope* are written to that ruling, and the binding is one step further outside than the shim. Rejected: an earlier draft's argument that the shim must be inside the boundary because it implements the module's interface.
- **D5. The pre-push fixture is scoped.** The gate builds and signs the fixture only when `scripts/gate-scope.sh` reports a change under `crates/oxicrypt-ffi/`, the binding crate, the header or the signing scripts, and otherwise runs the crate's tests under `OXICRYPT_LIB_OPTIONAL=1`; the same fail-closed shape the script has for its other optional gates. Rejected: a release build of `oxicrypt-ffi` on every push (14 seconds with the warm cache of E1, minutes from cold).
- **D6. The published name is `oxicrypt`.** A single crate with the raw layer as a private `sys` module; a separate `oxicrypt-sys` can be added later without breaking users. The README states in its first lines that the crate is the Rust interface to a separately built and signed library, outside the boundary, not the module itself. Rejected: `oxicrypt-bindings`, `oxicrypt-client`, and a `-sys`/safe pair published together.
- **D7. The Windows release ships the import library.** The Windows tarball carries the MSVC import library `oxicrypt_ffi.dll.lib` beside `oxicrypt_ffi.dll`, one more artifact. A consumer on the GNU toolchain links through `liboxicrypt_ffi.dll.a`, which a GNU-toolchain build of the library writes beside the DLL; no consumer needs Microsoft tools for the GNU route. Rejected: generating an import library in the consumer's build script, a toolchain obligation on every consumer machine.

## Open questions for the maintainer

- **Q4.** Settled by D3: the library's build sets the macOS install name to `@rpath/liboxicrypt_ffi.<ABI>.dylib`. Asserting it with `otool -D` on a macOS runner remains to be added with the macOS CI job.
- **Q8. Plaintext CSP output through the C ABI, for the policy.** Key generation, decapsulation and HKDF through the C ABI output plaintext CSPs from the module to the application. IG 9.5.A frames that path as Table 1's "CM Software to/from App via TOEPP Path" row and Table 2's P/E/SE entry at Security Levels 1 and 2, with footnote 7 (`[09.19]`: the CSPs stay within the operational environment and meet §7.6.3) and footnote 8 (`[09.16]`: two independent internal actions of the module to output a plaintext CSP). The security policy states neither for the C ABI's outputs. Which two internal actions of the module satisfy `[09.16]` for those services, and where `[09.19]` is stated, are the policy's to answer; the shim and the binding, both outside the boundary, contribute neither action. The `§7.2.3.2 [02.16]` citation the policy uses is not quotable from the IG text, which cites §7.2.3.2 only for hybrid hardware, and should be checked against the standard. IG section dates in the text this document was checked against: 9.5.A April 18, 2025; 1.A July 26, 2024; 2.3.D March 17, 2023; cover August 19, 2026.

## Evidence

The experiment: build `oxicrypt-ffi` as a shared library on Linux x86_64 with a throwaway verifying key, sign it, link a Rust program to it by `extern "C"` declarations alone, call `oxi_init(1)`, and read the result. Toolchain: GCC 15.2.0 and glibc 2.43 on x86_64, with a stable toolchain. `$WORK` is an empty directory outside the source tree; the signer is `oxicrypt-integrity-sign` built from the same source at `--release`. The program's own package carries the `build.rs`, so E3's search-path and `rpath` lines show what a package can do for its own binary and nothing about a dependency's build script; `$WORK/signed/` and `$WORK/unsigned/` received only the `.so`, so E3 does not test selection against the static archive, which *Tests and CI* item 7 does.

**E1. Key, build, sign, verify.**

```sh
oxicrypt-integrity-sign --keygen $WORK/keys
#   fingerprint: sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42

OXICRYPT_INTEGRITY_VERIFY_KEY=$WORK/keys/integrity-verify.pub cargo build --release -p oxicrypt-ffi
#   Finished `release` profile [optimized] target(s) in 14.42s      (warm cache)

cp target/release/liboxicrypt_ffi.so $WORK/unsigned/
cp target/release/liboxicrypt_ffi.so $WORK/signed/
oxicrypt-integrity-sign --sign --key $WORK/keys/integrity-signing.key $WORK/signed/liboxicrypt_ffi.so
#   signed $WORK/signed/liboxicrypt_ffi.so -> signature sha256:9c0b35401a61b9bb9eb79e613710cff7ddd23780764b7e8259a3a5c1a161afa9
#     verify key: sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42
#     extent 3243232 bytes in 534 entries (3243232 of 3308768 mapped bytes, 98.01%)
#     slot table: 70 stored entries of 3800
#   exit 0

oxicrypt-integrity-sign --verify $WORK/signed/liboxicrypt_ffi.so
#   verify ok: $WORK/signed/liboxicrypt_ffi.so (verify key sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42)
#   exit 0
oxicrypt-integrity-sign --verify $WORK/unsigned/liboxicrypt_ffi.so
#   $WORK/unsigned/liboxicrypt_ffi.so: slot invalid: slot version 0: the slot holds no signature
#   exit 2
```

**E2. The library's dynamic section and exports.**

```sh
readelf -d $WORK/unsigned/liboxicrypt_ffi.so | grep -E 'SONAME|NEEDED|FLAGS'
#   (NEEDED)  Shared library: [libgcc_s.so.1]
#   (NEEDED)  Shared library: [libc.so.6]
#   (NEEDED)  Shared library: [ld-linux-x86-64.so.2]
#   (FLAGS)   BIND_NOW
#   (FLAGS_1) Flags: NOW
#   no SONAME entry (the library before D3)
nm -D --defined-only $WORK/unsigned/liboxicrypt_ffi.so | wc -l
#   292
nm -D --defined-only $WORK/unsigned/liboxicrypt_ffi.so | awk '{print $3}' | grep -v '^oxi_'
#   lama_manifest
objdump -T $WORK/unsigned/liboxicrypt_ffi.so | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
#   GLIBC_2.34      (this host's toolchain; the release workflow builds to a 2.17 floor)
```

**E3. The consumer.** Three files, no dependencies.

`Cargo.toml`:

```toml
[package]
name = "consumer"
version = "0.0.0"
edition = "2024"
```

`build.rs`:

```rust
fn main() {
    println!("cargo:rerun-if-env-changed=OXICRYPT_FFI_LIB_DIR");
    let dir = std::env::var("OXICRYPT_FFI_LIB_DIR")
        .expect("set OXICRYPT_FFI_LIB_DIR to the directory holding liboxicrypt_ffi.so");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=oxicrypt_ffi");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
}
```

`src/main.rs`:

```rust
use std::ffi::{c_char, c_int, CStr};

unsafe extern "C" {
    fn lama_manifest() -> *const c_char;
    fn oxi_init(profile: c_int) -> c_int;
    fn oxi_active_profile() -> c_int;
    fn oxi_is_operational() -> c_int;
    fn oxi_integrity_status() -> c_int;
    fn oxi_integrity_key_fingerprint(out: *mut u8, out_len: usize) -> c_int;
    fn oxi_sha384(data: *const u8, data_len: usize, out: *mut u8) -> c_int;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    // SAFETY: every call below matches the declaration in oxicrypt.h; the
    // buffers are stack arrays of the documented sizes.
    unsafe {
        let manifest = CStr::from_ptr(lama_manifest()).to_str().unwrap();
        let version = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("version:"))
            .unwrap_or("version: ?");
        println!("manifest {}", version.trim());

        let rc = oxi_init(1);
        println!(
            "oxi_init(1)={rc} oxi_active_profile={} oxi_is_operational={} oxi_integrity_status={}",
            oxi_active_profile(),
            oxi_is_operational(),
            oxi_integrity_status()
        );

        let mut fp = [0u8; 32];
        let frc = oxi_integrity_key_fingerprint(fp.as_mut_ptr(), fp.len());
        println!("oxi_integrity_key_fingerprint={frc} sha256:{}", hex(&fp));

        let mut out = [0u8; 48];
        let src = oxi_sha384(b"abc".as_ptr(), 3, out.as_mut_ptr());
        println!("oxi_sha384(\"abc\")={src} {}", hex(&out));
        std::process::exit(if rc == 0 { 0 } else { 1 });
    }
}
```

The program's manifest scan takes the first line starting with `version:`, which in this manifest is `library.version`; the crate's parser is specified more narrowly in *Finding the library*.

```sh
OXICRYPT_FFI_LIB_DIR=$WORK/signed cargo build --release
#   Finished `release` profile [optimized] target(s) in 0.42s
readelf -d target/release/consumer | grep -E 'NEEDED|RUNPATH|FLAGS'
#   (RUNPATH) Library runpath: [$WORK/signed]
#   (NEEDED)  Shared library: [liboxicrypt_ffi.so]
#   (NEEDED)  Shared library: [libgcc_s.so.1]
#   (NEEDED)  Shared library: [libc.so.6]
#   (NEEDED)  Shared library: [ld-linux-x86-64.so.2]
#   (FLAGS)   BIND_NOW
#   (FLAGS_1) Flags: NOW PIE
ldd target/release/consumer | grep oxicrypt
#   liboxicrypt_ffi.so => $WORK/signed/liboxicrypt_ffi.so
```

**E4. The reference digest.**

```sh
printf 'abc' | sha384sum
#   cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
```

**E5. The result, and the unsigned control.**

The first output line printed the workspace version the library was built from; it is elided here so that a release does not have to rewrite this record.

```sh
target/release/consumer
#   manifest version: "<the workspace version>"
#   oxi_init(1)=0 oxi_active_profile=1 oxi_is_operational=1 oxi_integrity_status=1
#   oxi_integrity_key_fingerprint=0 sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42
#   oxi_sha384("abc")=0 cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
#   exit 0

LD_LIBRARY_PATH=$WORK/unsigned target/release/consumer
#   manifest version: "<the workspace version>"
#   oxi_init(1)=2 oxi_active_profile=0 oxi_is_operational=0 oxi_integrity_status=3
#   oxi_integrity_key_fingerprint=0 sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42
#   oxi_sha384("abc")=1 0000…0000
#   exit 1
```

The signed library initialises under profile 1 (CNSA 2.0), reports the integrity test `Passed` (1), reports the fingerprint of the key generated in E1, and returns the SHA-384 of `abc` that E4 gives. The library as linked, unsigned, is refused: `oxi_init` returns 2 (`SelfTestFailed`), the integrity status is 3 (`SlotInvalid`), `oxi_active_profile` reports 0 because no profile was ever selected, and `oxi_sha384` returns 1 (`NotOperational`) and writes nothing. `LD_LIBRARY_PATH` is searched before the program's `RUNPATH`, which is the loader's rule and the one the unsigned control in *Tests and CI* relies on. The fingerprint is reported for the unsigned copy too: the header states it is recorded when the integrity test reads the key and is available after `oxi_init` whether or not the test passed.

**E6. The library absent.** With `$WORK/signed/` moved aside:

```sh
target/release/consumer
#   target/release/consumer: error while loading shared libraries: liboxicrypt_ffi.so: cannot open shared object file: No such file or directory
#   exit 127
```

**E7. The consumer is outside the image.**

```sh
nm target/release/consumer | grep -E ' oxi_init| lama_manifest'
#   U lama_manifest
#   U oxi_init
oxicrypt-integrity-sign --show target/release/consumer
#   target/release/consumer: no integrity slot found — the artifact was not linked against oxicrypt-integrity, or the slot was stripped
#   exit 2
oxicrypt-integrity-sign --show $WORK/signed/liboxicrypt_ffi.so | head -4
#   $WORK/signed/liboxicrypt_ffi.so
#     verify key: sha256:12d972260f0b229f98a51a7709d083ec1165f10935fc9a1c3138e375804bfd42
#     slot at file offset 0xca3b6, RVA 0xca3b6
#     typed, slot included: 3308768 bytes of 3308768 mapped (100.00%)
```

The program imports `oxi_init` and defines nothing of the module; the signer finds no slot in it and finds the slot in the library. This pair is the probe *Finding the library* names; it does not see module code pulled into a program as ordinary Rust dependencies, which the consumer-side `cargo tree -i oxicrypt-module` probe does.

**Not measured here.** macOS, Windows and Android were not exercised in this experiment; their link and loader rules above come from the platform documentation and the release workflow, and Q4 names what the macOS CI job must assert first. Selection against the static archive, the dependency-side search path, and the pin and version refusals are stated as tests in *Tests and CI* and were not run.

## References

- ISO/IEC 19790:2012 §7.10.2.2 (`[10.17]`, `[10.18]`, the software integrity test and its scope, as quoted in FIPS 140-3 IG section 10), §7.9.5 (`[09.16]`, `[09.19]`, plaintext CSP entry and output for software modules, as quoted in IG 9.5.A footnotes 7 and 8), §7.2.3.2 (the software module's boundary, as the security policy cites it; see Q8).
- FIPS 140-3 Implementation Guidance (cover date August 19, 2026): 9.5.A SSP Establishment and SSP Entry and Output (Table 1 "CM Software to/from App via TOEPP Path", Table 2, the software-module paragraph); 1.A Binding and Embedding Cryptographic Modules (not applicable to a consumer application).
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), SP 800-90A (HMAC_DRBG), RFC 5869 (HKDF).
- [`docs/integrity-signing.md`](../integrity-signing.md): building and signing a module, per platform; the release artifacts and their load checks.
- [`integrity-extent-v2.md`](integrity-extent-v2.md): what the integrity test covers and its threat model.
- `docs/power-up-performance.md`: the measured cost of `oxi_init`.
- `crates/oxicrypt-ffi/include/oxicrypt.h`: the C ABI; `crates/oxicrypt-ffi/src/error.rs`: the `OxiResult` discriminants.
- `.github/probes/ffi-operational.c` and `scripts/release-load-check.sh`: the C-side load check this crate's tests mirror.
