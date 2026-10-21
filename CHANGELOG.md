# Changelog

All notable changes to **oxicrypt** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Release tags.** From 0.2.0 on, each release is tagged `vX.Y.Z`, and from 0.22.0 on each
> is also published to crates.io. 0.1.0 is tagged `v0.1.0.1` and folds in the `v0.0.0.A`
> internal-build tags before it.

## [Unreleased]

- **Breaking:** HMAC_DRBG, Hash_DRBG and CTR_DRBG with a derivation function refuse an entropy
  input shorter than the instantiated security strength on instantiate, reseed and
  prediction-resistance generate, and a nonce shorter than half of it on instantiate: 32 and 16
  bytes for every Hash_DRBG and HMAC_DRBG variant, so SHA-384 callers that supplied 24-byte
  entropy or a 12-byte nonce are now refused, and the AES key length and half of it for CTR_DRBG.
  The refusals are `Error::EntropyInputTooShort`, `Error::NonceTooShort` and a new
  `DrbgError::EntropyInputTooShort` variant, which breaks exhaustive matches on `DrbgError`, and
  reach the C ABI as `OxiResult::EntropyInputTooShort` (29) and `OxiResult::NonceTooShort` (30).
  An instantiate refused by a length check leaves the DRBG uninstantiated. (#288)
- The `oxicrypt` crate gives a Rust program the module through its separately built and signed
  shared library, without compiling any module crate into the program. It never links the static
  archive: on Linux, Android and Windows it links the shared library by its exact file name, and on
  Apple targets, whose linker takes no exact name, it refuses a library directory that also holds
  the archive. It requires the library's verifying-key fingerprint, or an explicit opt-out, at
  build time. At initialisation it checks the library's ABI number, that the library is
  operational with its integrity indicator reading `Passed`, its fingerprint and its active
  profile. It wraps SHA-384, HKDF-SHA384, AES-256-GCM, HMAC_DRBG-SHA-256, ML-DSA-87 and ML-KEM-1024
  with fixed-size types, single-use seeds and secrets zeroed on drop. The crate is outside the
  cryptographic boundary.
- `oxi_abi_version()` returns the C interface's ABI number, 1, which is independent of the release
  version and changes only when the interface breaks compatibility; within a number, a newer
  library serves an older caller, not the reverse. The `oxicrypt` crate accepts any library that
  reports its ABI number and refuses another with `Error::LibraryAbi`. A library without
  `oxi_abi_version`, as every earlier release is, is accepted only at the crate's own release
  version, so any such library of a different release is refused. `abi/v1.txt` in `oxicrypt-ffi`
  records every exported function's parameter and return types and every status code at that
  number, and a test fails when one is removed or changed while the number stays, or when a
  recorded line is edited. Output sizes are not in that record.
- `oxicrypt.h` defines the status codes as `OXI_RESULT_*` constants of the `OxiResult` enum, with the
  values the C functions return.
- **Breaking for C programs linked against a cargo build of the library on Linux or macOS:** the
  shared library's `SONAME` is `liboxicrypt_ffi.so.<ABI>` on Linux, and its macOS install name
  `@rpath/liboxicrypt_ffi.<ABI>.dylib`, so a loader refuses a library of another ABI by name. Cargo
  still writes the plain `liboxicrypt_ffi.so`, so a program linked with `-loxicrypt_ffi` against
  `target/release` now records `liboxicrypt_ffi.so.1`, and the loader refuses to start it (`cannot
  open shared object file`, exit status 127) until the library is deployed under that name: copy
  the build output to the name `scripts/library-file-name.sh` prints and keep the plain name as a
  link to it. Release tarballs ship that layout, and the Windows tarball also ships the MSVC import
  library `oxicrypt_ffi.dll.lib`. Android keeps the plain `liboxicrypt_ffi.so`, the only form an
  application packages, and the Windows DLL keeps its name.
- The integrity signer signs Windows DLLs built with the GNU toolchain, reading the module's
  statics from the DWARF in the DLL when no program database of the name the DLL records is beside
  it (`NoDwarf`, `DwarfForm`, `DuplicateStatic`, `StaticOutsideImage`, `StaticUnlocated`,
  `StaticUnsized`). The four pinned statics are always located exactly or the DLL is refused. The
  other module statics are covered only on two assumptions the reader cannot check: that the
  compiler gives every static with storage a `DW_AT_location`, and that every module crate is
  built with full debug information; a static that breaks either is not seen, where a program
  database would list it. An image with neither a program database record nor DWARF is now
  refused as `NoDwarf` where it was `StaticsUnchecked`.
- Removed the `oxicrypt-pointer` placeholder crate. The `oxicrypt` crate name on crates.io passes
  to the Rust binding at its first publish, and the placeholder versions 1.40.3 and 0.0.1 are
  yanked then.

## [0.25.0] - 2026-10-17

- **Breaking: the pre-operational integrity test verifies an ML-DSA-87 signature** (FIPS 204)
  over the module's loaded image in place of the HMAC-SHA-256 of 0.24.0, one of the two approved
  integrity techniques ISO/IEC 19790 §7.5 permits at Security Level 2, with the module's own
  self-tested `ML-DSA.Verify_internal`. The signature is made under the context string
  `oxicrypt-integrity`. Its CASTs, ML-DSA-87 signature verification and SHA-256, run first in
  `oxicrypt_integrity::KATS`, and the test reports `CastNotRun` unless both have passed. The slot
  is format version 4, 64 KiB, and slots of earlier versions are refused: a binary you built and
  signed with an earlier version is signed again with this one, and one you received is replaced
  with a fresh copy from its publisher. Removed `oxicrypt_integrity::FIPS_INTEGRITY_KEY`,
  `mac_over_file_ranges`, `encode_hmac_hex` and `constant_time_eq`, and from
  `oxicrypt_integrity::slot` the constants `OFF_MAC`, `RANGE_ENTRY_SIZE` and `MAX_RANGES`.
  `slot::encode` takes the slot's fields and signature, and `slot::extent_len` takes entries.
  `SlotImage` loses `flags`, `slot_rva`, `mac` and `ranges` and gains `fields` and `signature`:
  `flags` and `slot_rva` move into `fields`, the extent is `fields.entries`, and the ML-DSA-87
  signature replaces the MAC. (#285)
- **Breaking:** `oxicrypt_integrity::SlotDefect` describes the version-4 slot: its range variants
  are renamed for entries (`NoEntries`, `TooManyEntries`, `EmptyEntry`, `EntryOverflow`,
  `EntryOutOfBounds`), new variants name the other defects, and it is `#[non_exhaustive]`.
  `oxicrypt_integrity::Unreadable` is `#[non_exhaustive]`, `Unreadable::AllMechanismsFailed` is
  removed, and new variants name the read that failed. A read of mapped memory that the environment
  refuses (on Linux and Android, readable or execute-only memory in the process) reports
  `Unreadable`, the test not performed, not slot damage. On Darwin and Windows,
  where the signature input is bounded by the image file's size, a file shorter than the slot's
  signed length reports `Unreadable::FileLength`. `oxicrypt_imageread::ReadError` gains
  `InvalidName` and `NoImage` and is `#[non_exhaustive]`. (#285)
- **The verifying key is a build-time input.** Set `OXICRYPT_INTEGRITY_VERIFY_KEY` (a 2,592-byte
  ML-DSA-87 public key file) or `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX` (its 5,184 hex digits) when
  building. A key of any other length, an all-zero key and a hex value that is not UTF-8 stop the
  build. A build without either compiles, but the module reports `NoVerifyKey` and never becomes
  operational. (#285)
- **Breaking:** `oxicrypt-integrity-sign` signs with a key you generate. `--keygen <dir>` writes
  a key pair, atomically, outside any git work tree: the private key is the 32-byte ML-DSA-87
  key-generation seed, and reading it runs a pairwise consistency test. `--sign` requires
  `--key <signing key>`, signs deterministically, refuses with `SigningKeyAbsent` when the key is
  missing, unreadable or not the key the artifact embeds and with `NoVerifyKey` for an artifact
  built without one, and replaces an artifact only after the signed copy is synced and verified;
  signing through a symbolic link signs the file it names. It exits 3 when `--sign` is refused
  for its key and 4 when `--keygen` fails, and refuses `--key` outside `--sign` or given twice.
  `--show` and `--verify` print the verifying key's fingerprint, `--sign` and `--show` name the
  signature by its SHA-256, and `--show` names a slot defect, whether the slot's key matches the
  embedded key and whether the entries fit the slot. The library's `sign_image` and
  `write_extent` take the key, an `oxicrypt_integrity_sign::SigningKey`. The signer runs on
  Windows too, drawing from `BCryptGenRandom`. `--sign` reminds you to sign a PE image that
  carries a certificate table again with `signtool`, and `--loader` is refused for a Mach-O or
  PE image. (#285)
- **Breaking:** `IntegrityStatus::Mismatch` and `IntegrityError::Mismatch` are renamed
  `SignatureInvalid` (status 2). The status adds `NoVerifyKey` (8), `KeyMismatch` (9) for a slot
  signed for a different key, `SlotDamaged` (10) for a damaged slot, key record or bound import,
  whose remedy is replacing the artifact, and `Refused` (7) when the module refuses a primitive
  the test uses, which the status records rather than leaving `NotRun`. `SlotInvalid` (3) means
  only that the slot is the unsigned template the build emits, and `Unreadable` (4) that the
  test was not performed. No status prescribes signing: a never-signed build and a signed one
  whose slot was erased read the same, so `oxi`, the C ABI documentation and the guides advise
  signing only a binary you built yourself and otherwise obtaining a fresh copy.
  `oxicrypt_integrity::status_detail()` and the C function `oxi_integrity_status_detail()` give
  the failure in words, and
  `oxicrypt_integrity::verify_key_fingerprint()` and `oxi_integrity_key_fingerprint()`, which
  takes the buffer's length and returns `BufferTooSmall` for one under 32 bytes, give the
  fingerprint of the key the module trusts. (#285)
- `oxi --integrity` prints the key fingerprint, a `detail:` line and any start error. It starts
  the module with the same self-tests as every other command, exits 3 when the test was not
  performed or could not decide, naming the CAST when an integrity CAST failed, and exits 4
  naming the test when the image matches but a later self-test fails. (#285)
- **The integrity extent covers every file-backed byte the loader maps**: ELF on Linux (glibc)
  and Android (bionic) for x86-64 and AArch64, Mach-O dylibs on macOS for arm64 and x86_64, and
  PE32+ DLLs and EXEs on Windows for x86_64. The signer types each byte from the image's own
  relocation, fixup and import tables, records the loader for an ELF image (`--loader
  glibc|bionic` overrides it for `--sign`, `--verify` and `--show`), and `--show` reports the
  bytes and entries of each kind. The signed image ends where a Mach-O code signature or a PE
  certificate table begins, so a platform signature can be added after integrity signing.
  `docs/design/integrity-extent-v2.md` states the typing for each format. (#285)
- The integrity test no longer reads the backing file in place of the loaded image. On Linux
  and Android it reads through `/proc/self/mem` and then `process_vm_readv`, so a non-dumpable
  process still verifies itself, and a process without `/proc/self/maps` reports `Unreadable`.
  Initialised writable data is read from the image file the loader reports, including a library
  mapped from inside an APK and the image's own slice of a universal Mach-O file; thin dylibs are
  signed before `lipo` joins them. A second load of the same library, as by `dlmopen`, does not
  disturb the first one's test. `oxicrypt-imageread` reads the thread id through the `gettid`
  system call, so it links against glibc older than 2.30. (#285)
- `oxicrypt-integrity-sign` refuses, by name, an image whose layout it cannot type, and
  `docs/design/integrity-extent-v2.md` describes the refusals for each format. Among them are an
  ELF segment both writable and executable (`WritableExecutable`), the x86-64 PLT-rewrite tags
  (`PltRewrite`), and a PE TLS index or delay-load module handle in constant bytes (`TlsIndex`,
  `DelayLoadHandle`). It refuses an image in which a module static the module must start from
  zero-fill is file-backed (`FileBackedStatic`), and one whose module statics it cannot name
  (`StaticsUnchecked`). It reads them from the
  image's symbol table or, where that does not name them, from the debug file beside the
  artifact: the file an ELF `.gnu_debuglink` names, there or in `.debug/`, the dSYM whose
  `LC_UUID` is the image's, or the program database a PE CodeView record names, with its GUID
  and age; keep that file beside the artifact when signing. `--verify` verifies the signature
  before it classifies the image, names a slot typed for a different loader than the artifact
  declares (`LoaderMismatch`), and decodes every Mach-O chain word and PE import record against
  the signed table (`FixupMismatch`, `ImportMismatch`). (#285)
- `cargo xtask sign` builds, signs and verifies an artifact, and refuses, before building, an
  environment that lacks a link setting the format needs, naming each one missing: for Apple
  targets chained fixups, the zero-fill segment, unmerged globals on arm64
  (`-C llvm-args=-aarch64-enable-global-merge=false`), full debug information, a packed dSYM and
  a `MACOSX_DEPLOYMENT_TARGET` of at least 12.0 on arm64 and 13.0 on x86_64; for Windows `.bss`
  in a section of its own (`-C link-arg=/MERGE:.bss=.zbss`) and full debug information; for
  Android 16 KiB pages. (#285)
- **Release artifacts cover Android.** The release workflow
  builds the C library for Android arm64 and x86_64 beside Linux, macOS and Windows, and signs
  every shared library and `oxi` in its format's order; the static archive ships unsigned. Each
  shared library is loaded through `oxi_init` and each `oxi` run before release, on the runner
  that built it or, for Android x86_64, an emulator, except Android arm64, which is verified
  offline only. A release is signed with the project's release key, whose public half is
  `keys/release-integrity-verify.pub`, only for a published release whose `vX.Y.Z` (or
  `vX.Y.Z-suffix`) tag names a commit on `main`, and each provenance file records the key
  source, the key's fingerprint and the SHA-256 of the artifact's signature. (#285)
- The integrity check wipes the buffers it owns when they are dropped, and ML-DSA-87
  verification, key generation and signing wipe every intermediate they own, on every return
  path. (#285)
- While the power-up self-tests run, the guarded `*_internal` functions and output points are open
  only to the thread running them. A call from any other thread made while initialisation is
  running, or paused, returns `NotOperational` naming `SelfTest`; once the module is
  `Operational`, every thread is admitted. A service's check in `Operational` is one atomic load.
  A self-test that unwinds out of initialisation leaves the module in `Error`. The `parallel`
  builds of ML-KEM, ML-DSA and SLH-DSA check the module state once on the calling thread and pass
  the proof to their worker threads, which until the module is operational come from a pool each
  crate keeps for its own sweeps, so an application whose rayon workers all wait in `initialize`
  cannot starve the self-tests. (#285)
- **Breaking:** `oxicrypt_module::Error` is `#[non_exhaustive]`. Initialising a module whose
  initialisation failed returns the new `Error::AlreadyFailed` (formerly `NotOperational`), and
  runs no test: a failed initialisation is
  terminal until the process restarts. The C function `oxi_init` still returns `NotOperational`
  for it. A module that fails initialisation because a conditional self-test latched `Error`
  while the power-up tests ran stays in `Error`. `initialize` called from inside a self-test
  returns `NotOperational` naming `SelfTest`. A platform that gives the initialising thread no id
  the module can record fails initialisation with `SelfTestFailed` naming
  `oxicrypt_module::THREAD_ID_CHECK`, and `oxicrypt-module` does not compile for a target without
  64-bit atomics. (#285)
- **Breaking:** the module tests itself on demand by restarting.
  `oxicrypt_integrity::verify_loaded_image()` runs only inside the power-up self-tests; at any
  other time it runs nothing, changes no state and returns `IntegrityError::Module`, carrying
  `AlreadyInitialized` once the module is operational (a call before initialisation no longer
  latches `Error`). A failing `oxicrypt_integrity::ml_dsa_cast()` latches `Error` on every path,
  including a direct call on an operational module; a call the module refuses, before
  initialisation or from another thread during the self-tests, runs nothing and changes nothing.
  `oxi selftest` shows the integrity test's verdict from the process's start instead of running
  it again, and runs the algorithm self-tests again. (#285)

- Added LMS signature verification for all 80 (LMS, LM-OTS) parameter pairs of SP 800-208
  §4.1 (SHA-256), §4.2 (SHA-256/192), §4.3 (SHAKE256/256) and §4.4 (SHAKE256/192), each its own
  approved `Lms…Verify` service, with the service discriminants unchanged. (#281)
- Added four LMS known-answer self-tests to the power-up set, one per hash adapter (SHA-256 and
  SHAKE256 at N = 32 and N = 24). Each verifies a NIST ACVP sigVer vector marked valid and
  rejects one marked invalid, on the pair's H = 5, W = 1 instance. (#281)
- Added `oxicrypt_lms::verify_any` and the C function `oxi_lms_verify_any`, which verify an LMS
  signature under whichever of the 80 parameter pairs the public key's typecodes name. Input
  naming no pair is refused as `VerifyAnyError::Unroutable` (`InvalidInput = 5` in C), distinct
  from a signature that fails to verify (`VerificationFailed`, `TagMismatch = 22` in C). (#277)
- **Removed LMS key generation and signing.** SP 800-208 §8.1 confines both to hardware modules,
  so `oxicrypt-lms` offers verification only. A caller that generates keys or signs with
  `oxicrypt-lms` must move that work to a hardware module. Removed:
  - Rust: `keygen`, `keygen_internal`, `keygen_from_parts`, `sign`, `sign_internal`,
    `LmsPrivateKey`, `LmsSigningKey` and `PRIVATE_KEY_LEN`, from every per-pair module and from
    the crate root, and each per-pair module's `KATS`. The crate-level `oxicrypt_lms::KATS` holds
    the LMS self-tests.
  - The 80 `Lms…Sign` variants of `oxicrypt_module::Service`.
  - The `alloc` and `parallel` features of `oxicrypt-lms`, and with them its `rayon` and
    `oxicrypt-zeroize` dependencies. A build enabling `oxicrypt-lms/alloc` or
    `oxicrypt-lms/parallel` must drop the feature.
  - C ABI: `oxi_lms_keygen`, `oxi_lms_sign`, the 80 per-pair `oxi_lms_<pair>_keygen` and 80
    `oxi_lms_<pair>_sign` functions, and `OXI_LMS_PRIVATE_KEY_LEN`. `oxi_lms_verify` and the 80
    `oxi_lms_<pair>_verify` functions remain.
  - `acvp-harness`: the LMS `keyGen` and `sigGen` handlers, leaving 83 registered handlers. LMS
    `sigVer` is served under revisions `1.0` and `SP800-208`. (#281)
- Fixed `oxi_init` in the C library skipping the power-up self-tests of eight algorithm crates it
  links. It now also runs the known-answer tests for the XOFs (SHAKE, cSHAKE, KMAC, TupleHash and
  ParallelHash), CMAC, the KDFs, the TLS KDFs, ML-KEM, ML-DSA, SLH-DSA and XMSS, so the C library
  self-tests every approved algorithm crate it links, directly or through another dependency,
  before it becomes operational. (#284)
- Fixed `oxicrypt_module::initialize_with_profile` changing the active algorithm profile when
  called after the module was initialised, or while another call was running the power-up
  self-tests. Only the call that initialises the module sets the profile; every other call
  leaves it unchanged, as the `oxi_init` documentation states. (#285)
- Fixed the SLH-DSA power-up self-tests to the form FIPS 140-3 IG 10.3.A item 16 requires.
  `oxicrypt_slh_dsa::KATS` now holds six CASTs: key
  generation compared to a precomputed private key, deterministic signature generation compared
  to a precomputed signature, and verification, which must accept a fixed signature and reject it
  with one bit flipped, each on SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f. The expected values are NIST ACVP-Server vectors, vendored under
  `vendor/nist/` and extracted by `scripts/slh_dsa_cast_extract.py`. **Removed** the
  per-parameter-set `KATS` constants (`slh_dsa_sha2_128f::KATS` and the eleven like it);
  `oxicrypt_slh_dsa::KATS` is the only SLH-DSA self-test slice. (#284)
- Fixed the ML-KEM power-up self-tests to compare against precomputed values, as FIPS 140-3
  IG 10.3.A item 14 requires. `oxicrypt_ml_kem::KATS` now holds four CASTs on ML-KEM-1024: key
  generation from fixed d and z compared to the expected decapsulation key and the encapsulation
  key it contains, encapsulation from a
  fixed encapsulation key and m compared to the expected ciphertext and shared secret, and
  decapsulation of a valid and of a modified ciphertext compared to the expected shared secret,
  which covers the implicit-rejection path. The expected values are NIST ACVP-Server vectors,
  vendored under `vendor/nist/` and extracted by `scripts/ml_kem_ml_dsa_pbkdf_cast_extract.py`.
  **Removed** the per-parameter-set `self_test`, `KAT_ENTRY` and `KATS` items of `ml_kem_512`,
  `ml_kem_768` and `ml_kem_1024`; `oxicrypt_ml_kem::KATS` is the only ML-KEM self-test slice.
  (#284)
- Fixed the ML-DSA power-up self-tests to compare against precomputed values, as FIPS 140-3
  IG 10.3.A item 15 requires. `oxicrypt_ml_dsa::KATS` now holds five CASTs. Three meet item 15 on
  ML-DSA-87 with NIST ACVP-Server vectors: key generation from a fixed ξ compared to the
  expected private key, deterministic signature generation compared byte for byte to the
  expected signature, and verification, which must accept a fixed valid signature and reject it
  with one bit of c̃ flipped. Two more follow the Note 23
  recommendation that signing CASTs cover the rejection-sampling paths, using NIST's list of
  rejection test cases: one on ML-DSA-87 that rejects on the z bound, the r0 bound and the
  number of hints, and one on ML-DSA-44 that also rejects on the ct0 bound. NIST publishes those
  cases as SHA-256 digests of the key pair and the signature, so these two compare digests.
  All vectors are vendored under `vendor/nist/`, with the ACVP ML-DSA specification
  draft-celi-acvp-ml-dsa-01 the rejection cases come from. **Removed** the per-parameter-set
  `self_test`, `KAT_ENTRY` and `KATS` items of `ml_dsa_44`, `ml_dsa_65` and `ml_dsa_87`;
  `oxicrypt_ml_dsa::KATS` is the only ML-DSA self-test slice. (#284)
- Fixed the PBKDF2 power-up self-test to use an iteration count of at least two, as FIPS 140-3
  IG 10.3.A item 8 requires. `oxicrypt_kdf::KATS` now holds one PBKDF2 CAST, a SP 800-132 master
  key derived with PBKDF2-HMAC-SHA2-224 from a NIST ACVP-Server vector with an iteration count of
  398, a 224-bit salt and a 240-bit key, in place of the two iteration-count-1 tests.
  **Removed** `pbkdf2_self_test_sha1` and `pbkdf2_self_test_sha256`, a breaking change for a caller
  of either; `pbkdf2_self_test_sha224`, documented in the API manifest, replaces them. (#284)
- Fixed integrity-signed binaries that macOS on Apple silicon refused to launch. Writing the
  integrity slot leaves the binary's code signature stale, so an Apple artifact is signed in this
  order: code sign, code sign again with the same identity and options, integrity sign with
  `--reserved-against` naming the first result, then code sign a final time with the same
  identity and options. `--reserved-against` measures which of the four load-command fields
  `codesign` rewrites and leaves those out of the extent, so the final code signature disturbs
  nothing the integrity signature covers; any other difference is refused (`ReservationDiff`).
  For a PE image that will be Authenticode-signed, the reference is the image as linked and the
  artifact the image after one `signtool` run. `--reserved-against` applies to `--sign` and
  `--show` of one Mach-O or PE artifact. `cargo xtask sign` follows that order for every Apple
  target,
  `oxicrypt-integrity-sign --sign` reminds you to code sign a Mach-O artifact, `oxi` names the step
  when it refuses to start, and the macOS release artifacts are code signed after integrity
  signing. (#280, reported by @seanok)
- Fixed the `acvp-harness` LMS `sigVer` handler failing a whole test group when one test case
  carried a signature of the wrong length for the group's parameter pair. That test case is now
  graded `testPassed: false`, as the XMSS and ML-DSA handlers grade a malformed signature, and a
  signature whose embedded typecodes are not the group's pair is likewise graded failed. A public
  key of the wrong length still fails the group. (#284)
- **Breaking: the module now refuses to produce output outside `SelfTest` and `Operational`, for
  objects built earlier as well as new ones.** Each output entry point checks the module state
  once per call and returns `Error::NotOperational` in `PowerOff`, `Error` and
  `IntegrityUnverified`, so an object built while the module was operational produces nothing
  after the module enters its error state. Changed signatures:
  - Every public `*_internal` function checks the new
    `oxicrypt_module::require_self_test_started` first and returns `Result`. The sampling and
    arithmetic helpers behind ECDSA, RSA and DH return the refusal as `NotOperational` rather
    than as `InvalidInput` or a failed verification.
  - `finalize` on the SHA-1, SHA-2 and SHA-3 hashers, `finalize` on `Hmac`, `squeeze` and
    `finalize_into` on the SHAKE, cSHAKE, KMAC, TupleHash and ParallelHash types, and `finalize`
    on the LMS hash adapters return `Result`. `update` and `absorb` stay infallible.
  - `encrypt_block` and `decrypt_block` on `Aes128Key`, `Aes192Key` and `Aes256Key`, and
    `oxicrypt_aes::ctr_xor` and `oxicrypt_cmac::cmac_tag`, return `Result`. The `BlockCipher`
    trait's methods are now `encrypt_block_with` and `decrypt_block_with`, which take a
    proof of the new type `SelfTestStarted`.
  - `oxicrypt_rsa::pss` and `oxicrypt_rsa::oaep` encode, decode and verify functions return
    `Result<Option<_>, Error>` or `Result<bool, Error>`.
  - `Conditioner::startup_kat` returns `Result<bool, Error>`.
  - The hidden traits `oxicrypt_hmac::BlockHash` and `oxicrypt_kdf::PrfHmac`, and the public
    traits `oxicrypt_drbg::HashAlg` and `oxicrypt_drbg::HmacAlg`, changed signatures.
  - The key accessors return `Result` and refuse outside `SelfTest` and `Operational`: the CSP
    accessors `private_scalar` (ECDSA P-256 and P-384), `seed` (Ed25519) and `prk` (HKDF), and
    the public-key accessors `public_key` (ECDSA P-256 and P-384, Ed25519) and `modulus_bytes`
    and `public_exponent` (RSA-2048, RSA-3072 and RSA-4096). The C functions that return a
    public key, modulus or exponent from a handle return `NotOperational = 1` in the same
    states.
  - The HKDF, SP 800-108, PBKDF2, TLS 1.2 PRF and TLS 1.3 HKDF-Expand-Label output functions
    zeroize the output buffer when they return an error, so a refusal partway through never
    leaves derived bytes behind.
  - `oxicrypt_rsa::keygen::generate_2048`, `keygen3072::generate_3072` and
    `keygen4096::generate_4096` are renamed `generate_2048_internal`, `generate_3072_internal`
    and `generate_4096_internal`, refuse outside `SelfTest` and `Operational`, and their modules
    are hidden; `KeygenError` gains a `Module` variant. The approved services are
    `RsaPrivateKey2048::generate` and its 3072-bit and 4096-bit counterparts. (#285)
- **Breaking:** new enum variants. `ModeError::Module`, `IntegrityError::Module`,
  `DrbgError::Module`, `EntropyError::Module`, `TimerError::Module` and `SourceError::Module` carry
  the module's refusal. `IntegrityError` is now `#[non_exhaustive]`. An entropy
  pipeline that meets a refusal reports `EntropyError::Module` and is not poisoned, where it
  previously reported `NotReady` or `ConditionerKat`; `JitterSource::new` reports
  `TimerError::Module` where it reported `TimerError::Unavailable`. (#285)
- **Breaking:** the public arithmetic modules `oxicrypt_ecdsa::{p256_point, p256_scalar,
  p384_point, p384_scalar}`, `oxicrypt_eddsa::{edwards, scalar}`, `oxicrypt_rsa::{mont*, bigint*,
  pkcs1_v15, pss, oaep}` and `oxicrypt_sha::keccak`, and the accelerator functions
  `oxicrypt_aes_accel::{encrypt_block, decrypt_block, ghash_mul}` and
  `oxicrypt_sha_accel::sha256_compress`, and the `oxicrypt_aes::modes::BlockCipher` trait, are
  hidden from the documentation. They are building
  blocks outside the module's service interface. (#285)
- **Breaking (C):** the AES functions of the C library, and the HMAC-DRBG `reseed` and
  `generate` functions, return `NotOperational = 1` once the module has left `Operational`, for
  handles created earlier. `oxi_integrity_status` can return `Refused = 7`. (#285)
- Fixed HKDF-Expand never returning in a release build when asked for exactly 255 blocks, the
  RFC 5869 maximum: its one-byte block counter wrapped to 0 after the last block, and the loop
  compared it with 255 again. (A debug build panicked on the overflow instead.) The SP 800-108
  counter-mode loop had the same shape at `u32::MAX` blocks. TLS 1.3 HKDF-Expand-Label and the
  Hash_DRBG derivation function now refuse more than 255 blocks with `InvalidInput`, where they
  previously wrapped their counter and returned output RFC 5869 and SP 800-90A do not define. (#285)
- `tls13_hkdf_expand_label` and `tls13_derive_secret` (and their C functions) refuse an output
  longer than 65535 bytes with `InvalidInput`; HkdfLabel previously stated a saturated length. (#285)
- `tls13_hkdf_expand_label` and `tls13_derive_secret` (and their C functions) refuse a label that
  is empty or longer than 249 bytes, or a context longer than 255 bytes, with `InvalidInput`; they
  previously truncated it silently into a different `HkdfLabel`. RFC 8446 §7.1 bounds the
  prefixed label to 7–255 bytes and the context to 0–255. (#285)
- Hash_DRBG zeroizes its working buffers (the seed material holding the entropy input, copies of
  `V`, and the derivation and generation blocks) on every return path, and PBKDF2 no longer
  increments its block counter past the last block. (#285)
- `EntropyRng` no longer prints its buffered conditioned output in its `Debug` output, and
  zeroizes that buffer as soon as it is drained, and when it is dropped or unwrapped. (#285)
- Fixed `maxwell independence` exiting successfully, with no input hash in its sidecar, when the
  module did not start; it now exits with a failure. The signer, `collect` and `maxwell` also
  run the XOF self-tests. (#285)
- Corrected `docs/api.md`, which listed `oxicrypt-zeroize`, `oxicrypt-sha-accel`,
  `oxicrypt-aes-accel`, `oxicrypt-timer` and `oxicrypt-entropy` as outside the cryptographic
  boundary. They are inside it. It now lists `oxicrypt-keccak-accel` and `oxicrypt-imageread`,
  and marks `oxicrypt-module` as `no_std` (#233).
- Corrected `SECURITY.md`, which listed the C ABI among the things inside the cryptographic
  boundary. It sits outside the boundary and remains in scope for reports (#233).
- The crate documentation of each in-boundary crate that uses `unsafe` points to the accounting in
  `AGENTS.md` and the Security Policy. Four of those crates listed the others and omitted
  `oxicrypt-imageread`, and `oxicrypt-imageread` had no pointer (#194).

## [0.24.0] - 2026-08-19

- **Renamed the release artifacts.** The C library archive is now
  `oxicrypt-ffi-<tag>-<platform>.tar.gz`, was `oxicrypt-<tag>-<platform>.tar.gz` through v0.23.2 — it
  is one delivery form of the module rather than the module, and the bare name said otherwise. A
  script that fetches the latest release by asset name must be updated; releases up to v0.23.2 keep
  their original names. (#274)
- Added the covered extent to `oxi --integrity`, reported where a comparison happened. (#274)
- Added the remaining six HMAC variants to `oxi hmac` — `sha512-224`, `sha512-256` and the four
  SHA3 sizes — so the command reaches every variant the power-up self-tests cover. (#274)
- Added `oxi selftest`, which runs the module's self-tests on demand and reports each one by name
  with the vector it is checked against, ending in an explicit indicator. A failure places the module
  in the error state. (#274)
- Added the remedy to the CLI's startup failure, which now names the two commands that fix it —
  installing the signer and running it against the binary. (#274)
- Added signed `oxi` binaries to the release artifacts, per platform, in their own tarball with a
  provenance record. (#274)
- Added the CLI's case to `docs/integrity-signing.md`, the one home for signing an artifact. (#274)
- Added `verify_image` to `oxicrypt-integrity-sign`, one implementation of the offline check, shared
  by the tool's `--verify` and the CLI's read-back. (#274)
- Added `oxicrypt-imageread`, which reads the module's own loaded image on Darwin and Windows
  through `mach_vm_read_overwrite` and `ReadProcessMemory`. Every other target, Linux and Android
  included, compiles to a stub. (#273)
- Completed the pre-operational integrity test on macOS and Windows. The signer could sign a Mach-O
  or PE artifact that the runtime had no way to verify, so the module never became operational on
  either. (#273)
- Changed the Darwin extent to begin at the first `__TEXT` section, excluding the Mach header and
  load-command table, which `codesign` rewrites. (#273)
- Added `Unreadable::SelfReadFailed`, reported when the kernel refuses to copy the module's own
  image. (#273)
- Changed the in-boundary unsafe accounting to six exception crates of twenty-eight, from five of
  twenty-seven. `oxicrypt-integrity` keeps `#![forbid(unsafe_code)]` on every target. (#273)
- Added a guard deriving each algorithm profile's membership from the three gating
  predicates and failing when the approved-services table or either manifest disagrees.
- Corrected the Rust version stated in the build documentation, which named 1.94 in four
  places where the workspace requires 1.95.
- Added a guard tying every Rust-version statement in the tree to `Cargo.toml` and
  `rust-toolchain.toml`, the two files that own those values.
- Added Mach-O and PE32+ classification to the integrity signer, which previously refused
  both formats by name. Each hashes the region its loader maps executable and non-writable.
- Added a check that `oxi`'s power-up inventory covers every algorithm crate its subcommands
  reach. The module requires an integrity group; it does not require this, so a subcommand
  added without its known-answer tests would have started.
- Added `docs/integrity-signing.md`, the one home for signing an artifact against the
  pre-operational integrity test. `docs/building.md`'s signing section named a build command
  that errors, a slot size 256 times smaller than the real one, and a MAC over the whole file.
- Added `oxi --integrity`, which reports the pre-operational integrity test's outcome and what
  to do about it. Handled before initialization, so it works on a binary that cannot start.
- Added `cargo xtask sign`, one implementation of build-then-sign shared by local builds and CI.
- Corrected `oxicrypt-cli`'s README and a comment in `oxi`, both of which said the CLI skips
  its power-up known-answer tests. It runs them, including the pre-operational integrity test,
  and therefore must be signed before it will start — which `cargo install` cannot do.
- Corrected the intra-doc links across the workspace, which pointed at private items and at
  bracketed text that is not a link. `cargo doc` now builds clean under `-D warnings`.
- Aligned the CNSA 2.0 profile with CNSSP-15 (March 2025) Annex B. The suite names AES-256,
  ML-KEM-1024, ML-DSA-87, SHA-384 or SHA-512, and the SP 800-208 stateful hash-based signatures;
  it names no Keccak-family hash or XOF for a software module, and SHA-3 appears there only for
  internal hardware functionality.
- Aligned the CNSA 1.0 profile with CNSSP-15 (October 2016) Annex B: AES-256, ECDH and ECDSA on
  P-384, SHA-384, and Diffie-Hellman and RSA at a minimum 3072-bit modulus, together with the
  supporting services those need at matching strength.
- Added `AlgorithmProfile::Migration`, the union of the two suites, for a deployment running
  classical and post-quantum algorithms side by side. It is not a CNSA profile; the C ABI selects
  it with profile `3`.
- Each profile membership cites the clause of CNSSP-15 that admits it, and a test asserts each
  profile's membership exactly, over every service, in both directions.
- Removed PBKDF2 and the TLS KDFs from both CNSA profiles. Neither edition of CNSSP-15 names a
  password-based or protocol-specific key derivation function, and neither is required in order to
  operate an algorithm the suites do name.

  **Consumers selecting a CNSA profile should read the two entries above as a behaviour change.**
  Services outside the suite as CNSSP-15 defines it now return `Error::AlgorithmRestricted` where
  earlier versions permitted them — under CNSA 1.0 that includes SHA-256, SHA-512 and their HMAC,
  DRBG and KDF variants, the post-quantum algorithms and the stateful hash-based schemes; under
  CNSA 2.0 it includes the Keccak-family hashes and XOFs. A deployment that needs the previous
  breadth selects `Migration`, or `Unrestricted` for anything beyond the two suites. (#265)
- Scoped `oxicrypt-xmss` to signature verification. **Breaking: `keygen`, `sign` and
  `XmssPrivateKey` are removed from the crate, and `oxi_xmss_keygen` and `oxi_xmss_sign` from the
  C ABI. (#264)**
- Aligned XMSS address encoding with RFC 8391. **Breaking: signatures at any leaf index other than
  zero verify differently than in earlier versions. (#264)**
- Added externally produced XMSS verification vectors from six independent sources, and made the
  power-up self-test a CAST over one of them. (#264)
- Removed the XMSS `keyGen` and `sigGen` ACVP handlers; `sigVer` remains. (#264)

- Added `oxicrypt_integrity::status()` and `IntegrityStatus`, reported across the C ABI as
  `oxi_integrity_status()`, retrieving the pre-operational integrity test's outcome separately from
  `initialize_with_tests` (#262).
- Aligned the release workflow with the signer's one-target interface, and its provenance record now
  states that the static archive ships unsigned (#262).
- Corrected the documents that placed `oxicrypt-ffi` inside the cryptographic boundary. It is
  outside, as Security Policy §1 and `doc-guard` both state (#262).
- Corrected the LAMA manifest, which described `oxicrypt-integrity-sign` as unpublished and omitted
  its seven public items (#262).
- Corrected two comments that said the integrity group cannot be skipped. It cannot be omitted (#262).
- Added a test for the empty-integrity-group refusal, which had a purpose-built control that no test
  invoked (#262).
- Hardened the `integrity-probe` tests against `ETXTBSY` under `cargo test`, which runs them in one
  process where `cargo nextest` gives each its own (#262).
- Added the three integrity `tools/` members to the README's workspace layout (#262).
- Added loader-invariant image verification to the pre-operational software integrity test. The
  module verifies the bytes the loader mapped from the signed artifact rather than the on-disk file,
  so a shared library verifies itself rather than the host process that loaded it. The signer writes
  the extent as a range table into a 16 KiB slot and computes the reference MAC offline from the
  file. **The slot format is not backward compatible: every artifact must be re-signed.** (#262).
- Required the pre-operational integrity test at initialization. `initialize_with_tests(integrity,
  tests)` and `initialize_with_profile` both take the integrity group as a parameter, and a module
  initialized with an empty group enters the new `IntegrityUnverified` state instead of becoming
  operational. No interface exists, at any visibility, to declare the test passed without running
  it. **Breaking: `initialize()` is removed; every caller passes `oxicrypt_integrity::KATS`.** (#262).
- Added `State::IntegrityUnverified` and `Error::IntegrityNotAttested`, reported across the C ABI as
  `OxiResult::IntegrityUnverified` (28) (#262).
- Added a four-value status indicator to the integrity test — `Mismatch`, `SlotInvalid`,
  `Unreadable`, `CastNotRun`. An environment that cannot supply the module's own bytes reports
  `Unreadable` and does not become operational (#262).
- Added the HMAC-SHA-256 CAST to `oxicrypt_integrity::KATS`, ahead of the integrity test. The test
  refuses to run before it has passed (#262).
- Added `oxicrypt-integrity-sign`, the signer, as its own published crate, moved out of
  `oxicrypt-integrity`. An oxicrypt build must be signed before it will run, so the signer installs
  with `cargo install oxicrypt-integrity-sign` and is also a library a build script can call. It is
  a build tool outside the cryptographic module and is not FIPS-validated (#262).
- Removed `--staticlib-target`. A static archive has no loadable image; the consumer signs the
  binary the archive is linked into (#262).
- Corrected the integrity test's citation to ISO/IEC 19790:2012 §7.10.2.2 across the crate metadata,
  README, `docs/api.md`, `oxicrypt-module` and the LAMA manifests. IG 10.3.A remains cited where it
  governs pairwise consistency tests and algorithm CASTs (#262).
- Corrected oxicrypt-slh-dsa's FIPS 205 citations, which named §9 internal functions for the
  external API, Algorithm 17 for internal key generation, §10 for the SHAKE and SHA-2
  instantiations, and a Table 5 the standard does not contain. (#242)

## [0.23.2] - 2026-08-12

- Corrected the description of the five in-boundary `unsafe` exception crates, which called them
  audited across 66 lines. Nothing in the repository records an audit; they are isolated so that
  they are readily auditable. The published `description` of `oxicrypt-aes-accel`,
  `oxicrypt-keccak-accel`, `oxicrypt-sha-accel` and `oxicrypt-timer` carried the claim to
  crates.io. `doc-guard`'s `UNSAFE_EXCEPTIONS` and the phrase it requires in `AGENTS.md` move with
  it. (#242)
- Removed the claim that the module is validated from 37 lines across the rustdoc, `README.md`,
  `ISA.md`, `docs/api.md`, `docs/building.md`, the LAMA manifest and four `Cargo.toml` files. The
  module targets FIPS 140-3 Level 1 and has not completed CMVP. Input validation, wrapper
  shape-checking and measured timing keep the word. (#242)

- Fixed a panic in the CTR_DRBG derivation function on combined `entropy || nonce ||
  personalization` inputs of 152 to 192 bytes, across `instantiate_df`, `reseed_df`,
  `generate_df` and their C ABI mirrors. (#250)
- Corrected twelve SP 800-108 citations in `oxicrypt-kdf`. That document numbers the modes §4.1
  counter, §4.2 feedback and §4.3 double-pipeline; its §5 is Key Hierarchy. (#242)
- Corrected `oxicrypt-kdf`'s counter-width documentation. SP 800-108r1 permits any `1 <= r <= 32`;
  the restriction to byte-aligned widths is this implementation's. (#242)
- Corrected three SP 800-56C Rev. 2 citations in `oxicrypt-kdf` that named sections which do not
  exist. (#242)
- Corrected `oxicrypt-drbg`'s conditional-self-test section, which described repetition-count and
  adaptive-proportion tests. Neither exists here, and both are SP 800-90B entropy-source tests. (#242)
- Corrected `oxicrypt-drbg`'s module-gating claim. Four of twenty-two public entry points gate; the
  instantiate paths do, reseed and generate do not. (#242)
- Corrected `oxicrypt-drbg`'s health-test attribution. SP 800-90A §11.3 does not require error-path
  or uninstantiate testing; these checks exceed it. (#242)

- Corrected `oxicrypt-dh`'s rejection-sampling rationale, which gave the acceptance probability as
  about 50%. Computed from the group's own `q`, rejection is about 2^-66. (#242)
- Corrected three SP 800-56Ar3 citations in `oxicrypt-dh` from §5.6.2.3.1 to §5.6.2.3.2. The crate
  implements partial public-key validation. (#242)
- Corrected the description of `oxicrypt-dh`'s self-test, whose negative case is the order-2 element
  `p - 1` rather than a tampered peer key. (#242)
- Removed `oxicrypt-ecdh`'s claim that its pairwise-consistency comparison is constant-time. It is
  the derived equality on a byte array. The scalar-multiplication timing claims stand: ct-validation
  measures both CDH paths. (#242)
- Added `AlgorithmRestricted` to both `oxicrypt-ecdh` shared-secret error lists. (#242)
- Corrected `oxicrypt-tls-kdf`, documented as the TLS 1.2 KDF under SP 800-135. It also implements
  the TLS 1.3 KDF, which that document does not cover. (#242)

- Corrected `oxicrypt-ml-kem`'s FIPS 203 citations, which carried the initial public draft's
  numbering. K-PKE is Algorithms 13-15 in §5 and the internal ML-KEM functions are 16-18 in §6. (#242)
- Corrected `oxicrypt-ml-kem`'s Barrett-reduction documentation. It reduces to approximately
  `(-q, q)`, not `[0, q)`: `barrett_reduce(-1)` returns `-1`. (#242)
- Corrected `oxicrypt-ml-kem`'s basemul documentation. Its output carries an extra `R^-1` factor,
  not `R`. (#242)
- Corrected `oxicrypt-ml-dsa`'s FIPS 204 citations. That document has no §8; the sampling
  algorithms are §7.3, and ExpandA/RejNTTPoly and ExpandS/RejBoundedPoly were transposed. (#242)
- Corrected `oxicrypt-ml-dsa`'s side-channel documentation, which claimed the norm checks have
  data-independent control flow. They return on the first out-of-bound coefficient. (#242)
- Removed the constant-time claims from `oxicrypt-ml-kem`. No ct-validation target measures either
  post-quantum crate. (#242)

- Corrected `oxicrypt-eddsa`'s documentation, which described reduction, `muladd`, scalar
  multiplication and point compression as still to come. All of them ship. (#242)
- Removed three constant-time claims from `oxicrypt-eddsa` that no measurement covers: the field
  module's blanket claim, `ct_eq`, and `decompress`. (#242)
- Corrected the standard citations across the symmetric crates. FIPS 180-4, FIPS 202, SP 800-38B
  and SP 800-185 hold no example vectors in the appendices these crates cited, and FIPS 197
  Appendix C is a pointer rather than a source. The known-answer values are unchanged. (#242)
- Corrected the FIPS 140-3 IG attributions in `oxicrypt-sha`, `oxicrypt-hmac` and `oxicrypt-cmac`.
  IG 10.3.A requires one CAST per algorithm family, not one per variant, and IG D.G is Key
  Transport Methods. (#242)
- Removed the constant-time claims from `oxicrypt-aes`, `oxicrypt-aes-accel`, `oxicrypt-cmac` and
  `oxicrypt-xof`. No ct-validation target measures AES, GHASH, HMAC, CMAC or the XOFs. (#242)
- Corrected `oxicrypt-aes`: ECB exists for the ACVP harness, not for CTR_DRBG, KW/KWP or CMAC;
  `KATS` holds 23 entries, not 12; AES-NI hardening ships behind `accel-aes`. (#242)
- Removed `oxicrypt-aes-accel`'s claim that its equivalence to the portable path is proven. The
  oracles exist but no gate enables `accel-aes`. (#242)
- Corrected the enumeration of the five `unsafe` exception crates in `oxicrypt-sha-accel`,
  `oxicrypt-keccak-accel` and `oxicrypt-aes-accel`. Each named a subset. (#242)

- Corrected the integrity crate's compliance citations. The module integrity test is governed by
  FIPS 140-3 IG 10.2.A and ISO/IEC 19790:2012 §7.10.2.2; IG 10.3.A covers algorithm self-tests and
  is retained only where the HMAC's own CAST is meant. (#242)
- Corrected the description of the integrity check, which said the MAC covers the exact file bytes.
  The 32-byte MAC field is zeroed before hashing. (#242)
- Corrected the provenance labels on the vendored ACVP vectors. `vendor/nist/MANIFEST.toml` records
  the digest of the upstream `internalProjection.json`, not of the vendored slice; the CAVP `.rsp`
  files are pinned. `tools/acvp-gen/generate.py` emits the corrected label. (#242)
- Corrected the enumeration of the five crates that use `unsafe` in `oxicrypt-timer` and
  `oxicrypt-zeroize`, and the count of `oxicrypt-zeroize`'s own functions and `unsafe` blocks. (#242)
- Corrected `oxicrypt-zeroize`'s zeroisation citation. There is no FIPS 140-3 IG 7.7; the
  requirement is ISO/IEC 19790:2012 §7.9.7. (#242)
- Removed `oxicrypt-pointer`'s claim that every crate requires module initialization. Six published
  crates do not depend on `oxicrypt-module`. (#242)
- Corrected four surviving FIPS 140-3 IG 7.7 citations in `oxicrypt-ml-kem` and `oxicrypt-ml-dsa`.
  Zeroising temporary SSPs is AS09.32 (ISO/IEC 19790:2012 §7.9.7). (#242)
- Removed the last two `audited` claims, in `oxicrypt-ml-kem` and `oxicrypt-rsa`. (#242)

## [0.23.1] - 2026-08-10

- Every published crate carries a README. crates.io rendered a blank page for all of them.
- Crates inherit `homepage`, `keywords` and `categories`. All three reached the registry unset.
- The post-quantum crates carry their own keywords instead of the workspace set.
- `oxicrypt-cli` no longer advertises an `encrypt` command. There is none.
- The C header, both LAMA manifests and the crate descriptions say the module targets
  FIPS 140-3 Level 1 rather than asserting it.

## [0.23.0] - 2026-08-09

### Fixed

- SLH-DSA is no longer permitted under the CNSA profiles. **Breaking: a CNSA 2.0 caller invoking an SLH-DSA service now receives `AlgorithmRestricted`.** (#229)

- The CNSA profiles permit all 160 LMS services, previously 16. (#228)

- Module lifecycle tests no longer race on the process-global state. (#230)

## [0.22.0] - 2026-08-07

### Added

- The 29 crates making up the module's public surface are published to crates.io. The workspace set `publish = false` throughout development, so the roster was implied rather than stated; it is now a `publish = true` default with an explicit `publish = false` on the seven in-repo tools — `acvp-harness`, `esv-harness`, `oxicrypt-bench`, `oxicrypt-maxwell`, `ct-validation`, `doc-guard` and `quickstarts` — which never reach a registry. The test applied is whether a third party would name the crate in their own `Cargo.toml`, plus anything transitively required by one that would (#196).

- Prebuilt C libraries are published as release attachments: `.so`/`.dylib`/`.dll`, `.a`/`.lib` and `oxicrypt.h` for linux x86_64/aarch64, macOS x86_64/aarch64 and windows x86_64, each with its integrity slot signed, a `BUILD-PROVENANCE.txt` recording the toolchain and integrity MACs, and a SHA-256 checksum. Consuming the module from C no longer requires a Rust toolchain, and the artifact a user links is the one that was built here rather than one they compiled themselves (#205).
- LAMA manifest conformance is checked mechanically on every push. `scripts/check-lama-manifests.sh` runs the specification's conformance linter over every manifest in the tree and fails on any finding; the pre-push hook applies it to the revisions being pushed, and a CI job mirrors it. The linter runs in strict mode, because four of its six rules are advisory upstream and never move an exit code — a gate on the default contract would enforce two rules while appearing to enforce all six. The linter is vendored byte-identically from upstream with its origin and checksum recorded in `scripts/lama-validate.provenance`, verified on every run, so a copy weakened in-tree fails rather than silently reporting nothing (#175).
- The quickstart examples carried in the LAMA manifest are compiled. Each lives as a file under `tools/quickstarts/examples/`, built by the existing `--all-targets` gate, and a test asserts the manifest's copy is byte-identical to it. The check runs both directions, so an example no capability claims fails too and a file cannot be built for nobody. The specification requires a quickstart to compile and run unmodified and nothing compiles a YAML file — of the seven in the specification's own reference adoption, five no longer built against the API they described. Eight of the fourteen capabilities carry one (#192).

### Changed

- The command-line interface publishes as `oxicrypt-cli`; the binary it installs is still `oxi`. The crate name `oxi` has been registered on crates.io by an unrelated project since 2018 and is not available. `cargo install oxicrypt-cli` yields an `oxi` command, and nothing changes for anyone building from this repository.

- The SHA digest and block sizes are re-exported at the crate root of `oxicrypt-sha`, algorithm-prefixed: `SHA256_DIGEST_SIZE`, `SHA384_BLOCK_SIZE` and so on for all seven algorithms. `oxicrypt_sha::DIGEST_SIZE` was the path a caller forms first and it could never resolve — `DIGEST_SIZE` is defined in six submodules with six different values, so the bare name has no correct answer. The prefixed form gives each size one meaning at the root and matches what `sha512_t` already did internally with `DIGEST_SIZE_224`; the module-scoped names are unchanged (#192).
- Test fixtures no longer carry the `pqclib` project name: 77 occurrences across 19 files. All were test-only and reached no shipped artifact — `strings` on the built `.so` returns none — so this changes no behaviour a caller can observe. The `CHANGELOG` entries recording the original rotation keep the old name, being the history of it (#193).
- **The LAMA manifest now describes only what reaches crates.io.** `acvp-harness` and `esv-harness` are ACVP and ESV protocol clients that drive validation rather than part of the surface a consumer links against, and neither can be named in anyone's `Cargo.toml` — yet the manifest carried 36 functions, 50 types and 32 constants for them. Those move to `acvp-harness/llm-api-draft.yaml` and `esv-harness/llm-api-draft.yaml`, kept rather than deleted because both describe real library surfaces that would need manifests of their own if either is split out. `oxi`, `doc-guard`, `ct-validation` and `oxicrypt-bench` gain `modules:` entries so that every workspace crate now has one and an absent crate is unambiguously a defect — the condition that would have caught #174. The coverage rule in `AGENTS.md` collapses to a single sentence with no exceptions list (#208).
- **The integrity key, the slot magics, and the self-test message constants no longer carry the `pqclib` project name.** `FIPS_INTEGRITY_KEY` is now `oxicrypt-fips140-3-integrity-key`, the slot magics are `0xfc OXICRYPT_FIPS_H` / `0xfd OXICRYPT_FIPS_F`, the two RSA power-up KAT messages and the three pairwise-consistency probe messages are `oxicrypt`-prefixed, and the pinned RSA signatures are regenerated to match. **Any binary signed with the previous key or magics will fail its power-up integrity check and must be re-signed** — `oxicrypt-integrity-sign --sign` is the same command as before. Rotating these after validation would require re-validation under IG 10.3.A, so this is the last point at which the change costs a re-sign and a test run rather than a submission (#193).
- The `FIPS_INTEGRITY_KEY` doc comment named a key the module did not use: it stated an `oxicrypt-` prefix against a `pqclib-` constant, and the literal it named was 34 bytes where the type is `[u8; 32]`, so its own arithmetic disproved it. The doc now states the compiled literal, and a test reads the doc comment out of the source and asserts both the literal and its stated byte count against the constant, so the two cannot drift apart again (#193).

### Fixed

- `r7_keygen_pinned_regression` asserted only that the public key re-derives from the private scalar and that the scalar is non-zero. Both hold for any valid keypair from any seed, so the test could not detect a change in DRBG consumption order — the one thing it exists to catch. Confirmed by mutating the seed, which produced an entirely different keypair and left the test green. It now pins the `(d, Q)` bytes, and the same mutation fails it (#214).
- The pre-push security-policy containment scan no longer fails when there is nothing to scan. Its revision loop appended an empty string as though it were a revision whenever the enumerated set was empty, so the array was never empty, the fallback to `HEAD` never fired, and the scan's positive control failed against a revision that does not exist. An up-to-date push and a manual invocation of the hook both hit it, the latter meaning the hook could not be exercised by hand at all. Empty and null revisions are now discarded, an empty set is reported and skipped rather than scanned, and a manual invocation falls back to `HEAD` as intended (#198).

## [0.21.0] - 2026-08-06

### Removed

- `docs/jent-concept-mapping.md` is withheld alongside the Security Policy. It maps jitter-entropy lineage vocabulary to oxicrypt's as-built names for a reviewer already fluent in that lineage, and two of its three columns cite the Security Policy's own rule numbering — so most of it read as references a public reader could not follow. The middle column describes the as-built entropy source, which is public and documented in `oxicrypt-entropy`'s rustdoc; nothing is withheld here for its own sake. `docs/security-policy/README.md` says where it went, and the containment guards deny it by name alongside the policy.
- The FIPS 140-3 Security Policy is no longer tracked in this repository. It is held privately and disclosed per person; `docs/security-policy/README.md` takes its place at the path, explaining what the document contains, why non-publication rather than a license is the instrument, the honest bounds of that protection, how to request access, and which assertions a clone without it does not run. The 14 `.rs` sources whose rustdoc points at policy sections keep their pointers, as do `crates/oxicrypt-ffi/include/oxicrypt.h` and `crates/oxicrypt-maxwell/Cargo.toml`: all are prose references inside comments rather than links, and the directory they name now serves the README that explains where the document went.

### Added

- `scripts/check-internal-deps.sh`, run by `pre-push` against the commits being pushed: a normal or build dependency on a workspace member must carry a version requirement, a dev-dependency on one must not, and a path dependency outside the workspace must carry one. It reads `cargo metadata` rather than manifest text, so sub-tables, multi-line inline tables, unspaced values and `package = "..."` renames all arrive normalised, and a crate is covered when it joins the workspace rather than when someone adds it to a list. Placed above the tag-only short-circuit and the stamp cache: a release tag is the push whose version literals were just rewritten, and a manifest-only edit changes no Rust, so a cached state would otherwise skip it. Requires `jq`, and says so by name rather than failing as a workspace defect when it is absent (#196).

- `doc-guard`: `embedded_files_live_inside_their_package_root` and `embedded_lama_manifests_are_the_manifest`. `cargo publish` uploads a tarball of the package directory and the registry never fetches from the repository, so an `include_str!` reaching outside the package root builds here and fails for every consumer — permanently, since a published version is immutable. The first guard asserts no embed escapes, workspace-wide rather than scoped to the crates destined for crates.io: a roster-conditional rule changes meaning when a `publish` flag moves, which is how `oxi` acquired a latent blocker the moment it joined the roster. The second compares each embedded manifest against the canonical file, because git on Windows without `core.symlinks` checks a symlink out as a text file holding the target path, which would otherwise be embedded and published as the manifest with nothing reporting an error (#196).

- `doc-guard`: the Security Policy is resolved at runtime rather than read from the tree. Precedence is `$OXICRYPT_SECURITY_POLICY` — the file, or a directory containing `security-policy.md` — then `~/repos/oxicrypt-policy/security-policy.md`. The five guards asserting its content skip when it is unreachable, so a clone without the document runs green. `policy_resolution_precedence_holds` pins that order against synthetic inputs, because a resolver that resolved nothing would be indistinguishable from a clean skip.
- `doc-guard`: `security_policy_is_provisioned` — the same shape as `ea_dataset_suite_is_provisioned`, for the same reason. A skip prints to a stream a passing test discards, so an unprovisioned checkout would otherwise report the same green result as one that asserted everything about the document a CST lab reads. It departs from that precedent in one way, deliberately: it fires on *claimed* provisioning rather than on absence. The datasets are public, so failing when they are missing is right there; this document cannot be obtained by an outside contributor at all, and failing on its absence would reintroduce as a single failure exactly the hard failures that removing it from the tree exists to prevent. A checkout claims the policy by setting `$OXICRYPT_SECURITY_POLICY` or by having the sibling clone directory on disk; either one with the document unreadable fails, naming the path and the five guards that did not run, and an ordinary clone passes with a note. `OXICRYPT_SECURITY_POLICY_OPTIONAL=1` withdraws the claim explicitly. Its own positive control requires each named guard to carry both a `#[test]` attribute and the skip call that makes it a policy guard, so neither a rename nor a silently de-tested guard leaves the list describing something that no longer runs — `#[ignore]` is the one edit it cannot see, and says so.
- `doc-guard`: `the_security_policy_is_not_in_the_public_tree` — the inverse of every other check here, asserting a document is absent rather than that one is correct. Two detectors: a file-name sweep, and a phrase already present in the guard's own source, which catches a copy restored under a different name. The phrase sweep asserts it finds exactly the one file that legitimately carries the phrase, so a walk that reached nothing fails rather than reporting a clean tree — an earlier form checked the phrase through a separate read and passed with the walk pointed at a non-existent root. `vendor/` is swept, unlike `target/`: it is committed content that ships. A copy reflowed as it was moved evades both detectors, and neither says anything about git history; the guard is a backstop against accident, not an adversary, and says so.
- `pre-push`: the same containment scan, duplicated ahead of the tag short-circuit and the stamp cache and scanning the commits being pushed. The doc-guard test only runs under `cargo nextest run --workspace`, which the hook's Tier A escape skips when a push touches no Rust-relevant path — and `docs/` is not Rust-relevant, so restoring the policy was precisely the push shape that skipped the guard against it. Same reasoning the deny-list scan above it already carries: a leak check a cache can skip is not a leak check.
- `oxicrypt-maxwell`: `ea_dataset_suite_is_provisioned` — a fast provisioning gate that fails when any of the 11 EA v1.1.8 reference datasets, or either git-tracked IID-gate oracle under `tests/data/`, is absent, naming which. 33 skip-on-absence arms across 15 files resolve their data through `resolve_datasets_dir` or a `tests/data/` helper and return quietly when the file is missing, so without them the parity table, every per-estimator anchor and the assessed-assembly parity passed having compared nothing. The gate states that shared precondition once and fails in milliseconds rather than leaving a green suite that proved nothing. The tracked fixtures are not covered by the opt-out — a checkout lacking them is broken, not unprovisioned (#137).

### Changed

- Internal dependencies carry a version requirement. `cargo package` strips a dependency's path and records a registry requirement, which needs a version, so every crate depending on another oxicrypt crate failed to package — 27 of the 35 workspace members. The 29 internally-depended-on crates are now declared once in root `[workspace.dependencies]` with both a path and a version, and 141 member declarations inherit them with `{ workspace = true }`. Dev-dependencies deliberately stay path-only: cargo drops those when packaging, and a version turns one into a registry requirement no first publish can satisfy — `oxicrypt-sha` and `oxicrypt-keccak-accel` dev-depend on each other, so it is also a cycle. `esv-harness` keeps an explicit `oxicrypt-entropy` declaration because it is the only member setting `default-features = false`, which an inherited dependency cannot express. `scripts/bump-version.sh` moves the new literals (#196).

- The crates.io roster is stated in the manifests rather than implied. `oxi` — the command-line interface, which `cargo install` is the distribution path for — moves onto crates.io; `acvp-harness`, `esv-harness` and `oxicrypt-bench` move off it, joining `oxi`'s former company of `doc-guard`, `ct-validation` and `oxicrypt-maxwell` as in-repo tooling that never reaches a registry. The test applied is whether a third party would name the crate in their own `Cargo.toml`, plus anything transitively required by one that would; 27 crates are forced by that closure and the rest were judgement. `oxicrypt-bench` depending on the never-published `oxicrypt-maxwell` was the one structural contradiction, and it dissolves rather than needing a fix.

- The four crates embedding the LAMA manifest reach it through a symlink in their own package root instead of a path climbing out of it. The canonical file stays at `docs/llm-api-manifest/llm-api.yaml`; `cargo package` materialises the symlink's content into the tarball, so there is still one copy in git and now a real file in every published crate. Without this, `oxicrypt-ffi` and `oxi` could not be built from crates.io at all (#196).

- The pre-commit doc-sync hook's security-policy check is keyed on modification time rather than staged-ness, and resolves the policy the same way `doc-guard` does. Git cannot stage a file it does not track, so the previous "is it staged?" test could no longer fire at all. When the policy is not provisioned — the normal case for an outside contributor, who has no access to it — the check is skipped and says so on stderr, rather than blocking a contributor on a document they cannot read.
- CI: the workspace test job sets `OXICRYPT_EA_DATA_OPTIONAL=1`. The EA reference datasets are not provisioned on the runner, so CI has never validated SP 800-90B estimator parity — every EA-anchored test skipped silently. The flag makes that pre-existing fact explicit in the workflow rather than hidden in the skips; it does not change what CI covers. Whether to provision the datasets there is #153 (#137).
- `oxicrypt-maxwell`: the EA parity test is now a full-suite gate — an absent reference dataset fails the run instead of skipping it, so a run that compared nothing no longer reports the same green result as one that compared all 11. The failure names the missing datasets and where they were expected; the per-dataset table and the passed/skipped/failed tally are written to stderr as evidence. A checkout without the EA v1.1.8 bundle can set `OXICRYPT_EA_DATA_OPTIONAL=1` to downgrade the completeness check to a warning that states the run is not evidence of full-suite parity. The evidence table is emitted before the pass/fail assertions, so a genuine parity failure still prints the per-estimator deltas that diagnose it. The `quick` profile still excludes the ~200 s parity test, so the fast inner loop keeps its latency — but the new provisioning gate does run under `quick`, so an unprovisioned checkout now fails there too rather than iterating against nothing. `AGENTS.md` and `CONTRIBUTING.md` document where the datasets come from (#137).

- `oxicrypt-bench`: `conditioned_output` and `maxwell` benchmarks behind a new opt-in `entropy-bench` feature, a `gen_noniid` example that reproduces the timed input, and `docs/entropy-performance.md` recording what they measured on the reference platform (entropy-crate ISC-88/ISC-89). `conditioned_output` times `EntropyPipeline::conditioned_block` end to end — noise-source sampling, the continuous health battery, and SHA-256 conditioning — against the real `raw-counter` jitter source, which is the only source a benchmark can construct because `NoiseSource` is sealed and the mocks are test-only. `maxwell` times a full `iid_gate` assessment on both branches, asserting each synthetic input routes as intended before measuring, so two figures from the same branch cannot pass as a result. The measured asymmetry is ~270x at 8-bit, comparing like with like: a 1 M-sample capture assesses in 8.99 s on the IID branch and 2417.75 s on the non-IID branch, both at 8-bit symbols. At the module's own 4-bit sample width the non-IID branch takes 1829.27 s, with no same-width IID figure to divide it by; widening the alphabet from 4 to 8 bits costs +32% wall-clock and +90% peak memory, so the default run uses 1 M for the former and 100 k for the latter, with `OXICRYPT_BENCH_MAXWELL_FULL=1` raising it. The documented figures carry their qualifiers: the conditioned-output number is a hot-loop steady state on a KVM guest and is not the pilot operational environment's figure; the IID assessment number is a best case, because the §5.1 permutation battery exits early once all 19 statistics are decided; and the IID assessment figure still uses 8-bit symbols, wider than the 4-bit samples this module's jitter source emits (#138).
- The dependencies the entropy benchmarks need are optional and gated on `entropy-bench` rather than plain dependencies of the bench crate. Cargo unifies features across an invocation, so a plain `oxicrypt-entropy = { features = ["raw-counter"] }` would enable `raw-counter` for every `--workspace` command — re-arming the live jitter tests that `scripts/git-hooks/pre-push` deliberately excludes for being load-dependent on a virtualized counter, making `raw_counter_unavailable_without_feature` assert nothing, and overriding `esv-harness`'s explicit `default-features = false` so an audited-`unsafe` crate would enter its binary. The default workspace graph is unchanged (#138).

### Changed

- `oxicrypt-maxwell`: `independence` reads tuple occupancy off the MCV histogram instead of a separate `BTreeSet` walk. `analyze` encoded the phase-0 pair and triplet streams a second time solely to feed that walk; the histogram `mcv_from_codes` already builds holds the same count as its nonzero-slot total, so both extra encodings and the set are gone. Reported occupancy is unchanged: with over-wide input refused at the top of `analyze`, no code can be dropped by the histogram's range guard, so the histogram's count and a plain distinct-count of the same codes coincide. Exact MCV counts and min-entropy are untouched (#127).

### Fixed

- `maxwell parity` no longer exits zero when it compared nothing: an all-skip or
  partially-skipped run is a failure unless `OXICRYPT_EA_DATA_OPTIONAL=1` is set for that
  invocation, and the closing verdict states in words whether the run is parity evidence
  (#154).
- `maxwell restart` no longer prints a FAILED verdict and exits zero; a rejected
  §3.1.4.3 sanity check or §3.1.4.2 validation gate now exits non-zero, matching
  `maxwell gate` (#154).
- `maxwell restart` refuses a degenerate restart matrix — an alphabet of one, or an
  `H_I` implying more equiprobable symbols than the matrix contains — instead of
  tripping a debug assertion (exit 101, no verdict) or, in release, drawing the
  §3.1.4.3 cutoff over symbols the data never contained. A non-finite `H_I` is
  rejected at parse (#154).
- `maxwell independence` refuses a dataset containing a sample wider than the declared
  `BITS_PER_SYMBOL` instead of assessing it, matching the NIST EA v1.1.8 reference. The
  tuple encoder does not mask, so an over-wide sample produced a code outside the
  `2^(k·bits)` alphabet which the histogram discarded while the denominator still
  counted it — the reported min-entropy was computed over a fraction of the data (93%
  of samples discarded at 4 bits/symbol over full-range bytes) and inflated by an
  arbitrary amount. `independence::analyze` now returns `Result` and the CLI exits
  non-zero, naming the widest sample and the index of the first offender; a refused run
  writes no evidence sidecar. A *narrower* observed width warns and continues (#152).

## [0.20.0] - 2026-07-25

### Added

- `acvp-harness`: LMS `sigGen` and `sigVer` registration under the ACVP `SP800-208` revision, alongside the existing `1.0` handlers — a distinct catalog service carrying a top-level `messageLength` domain (variable-length messages) that revision `1.0` does not have; there is no `keyGen` counterpart because key generation has no message. Verification and signing are unchanged: both group handlers already decode each test's `message` without a fixed-size assumption, so the same code paths serve both revisions. `LMS / sigVer / SP800-208` graded passed on the ACVTS demo server (320 cases across all 80 (lmsMode, lmOtsMode) pairs at 128/1024/8192-bit messages) (#143).
- `acvp-harness`: `--revision <rev>` filter for `demo-run`, narrowing registration to one ACVP revision when an `(algorithm, mode)` pair is served by handlers for several. It is how the caller says which revision was meant once a pair serves more than one — `--algorithm LMS --mode sigVer` matches both, which is refused rather than registered twice (see Fixed) (#143).
- `oxicrypt-entropy` (`collection` feature): `collect --claim <H>` — sets the per-OE min-entropy claim, constrained to the non-binary APT grid rows ({0.5, 1, 2, 4, 8}, derived from `APT_ALPHA30_NON_BINARY`); an off-grid or unparseable value is refused with a typed error naming the valid grid (never silently rounded to a neighbouring row), the claim is recorded in the dataset `metadata.json` (`claimed_h_steps`), and absence keeps the tool default (H = 1). α is unchanged. Out-of-boundary tooling; the validated library surface is unchanged (#126).
- `oxicrypt-entropy` (`collection` feature): `collect --characterization <N>` mode — captures, per boundary, a single contiguous `N`-sample run to `characterization.bin` under the characterization posture (health battery live, trips annotated, never dropped or stitched), with the versioned `metadata.json` sidecar marked `"characterization": true`. Backs the per-OE `maxwell independence` / `maxwell periodicity` evidence (ISC-120). Out-of-boundary tooling; the validated library surface and public entry point are unchanged.
- `oxicrypt-maxwell`: `independence` subcommand — 2D/3D (pairs/triplets) min-entropy independence evidence for the per-OE entropy assessment (ISC-121). Three legs: the full literal §6.3 estimator battery on the disjoint-pair stream at both phase offsets (`pair_suite_min/2`), confidence-bound tuple-MCV on pairs and triplets (multi-phase, triplets MCV-only), and a deterministic K=10 shuffled-baseline null; a claim-anchored FLAG (advisory-only below the 10 M precedent minimum), an `independence-results.json` sidecar, and pre-registered O1–O4 oracles (`docs/estimator-parity-tolerances.md`). Out-of-boundary analysis tool; no EA analog (evidence subcommand).
- `tools/doc-guard`: test-gate drift guard whose tests recompute the boundary/`unsafe` accounting from the workspace on disk (crate count, out-of-boundary set, `forbid(unsafe_code)` ratio, audited-exception names, exported-FFI-function count) and assert the values stated in `security-policy.md` §1/§9.2/§3.1, `AGENTS.md`, and `README.md` match (#101).
- `esv-harness`: new out-of-boundary ESV submission client for SP 800-90B entropy-source validation, driving the full ESVP 1.0 flow over `acvp-harness`'s curl(1)/mutual-TLS transport with zero network and zero third-party dependencies in every automated path. Authentication: ESVP login, single-token and bulk token refresh (tunable proactive margin, reactive 401/403 retry, TOTP-window-reuse retry, and a fresh-login fallback when a stale-token refresh is rejected). Registration: the entropy-source metadata payload builder (multi-OE, vetted SHA2-256 conditioning with a required CAVP validation number) plus the multi-OE response parser. Preflight (offline, before any server contact): a payload preflight drift-guarded against the vendored NIST metadata schema, and a data-file preflight — exactly 1,000,000 one-byte-per-sample symbols, symbols within the effective `min(bitsPerSample, 8)` width, the mandated 1000×1000 restart layout, and `DataFileSampleSize` consistency — checked against the module's own SP 800-90B constants so validator and dataset emitter cannot drift. Data files: the multipart upload builder (capitalized `DataFileSampleSize` for server v1.8), a bounded processing-status poll over all seven documented statuses that captures NIST's returned assessment as an independent entropy-assessment oracle, and a typed refusal of any conditioned-bits upload under vetted conditioning. Supporting documents: a PDF-only upload with the supporting-document-type enumeration. Certify: the full-submission, add-operating-environment, and update-PUD request builders enforcing exactly-one-EAR / exactly-one-PUD / at-most-one-attestation cardinality, distinct entropy-assessment ids, the required cross-program identifiers, and a non-IID assessment's restart-test-upload precondition. Session: a resumable per-submission store with an intent-then-outcome event log — each network step records its intent (locally-known data) before the call and its outcome after, both fsync'd, so an interrupted step resumes flagged for verification rather than blindly re-submitted; the log tolerates a torn final line, dedups registration replays, and validates every path component. `hminEstimate` is serialized exactly from the module's fixed-point min-entropy type (1/256-bit steps) as a finite decimal with no float on the claim path, round-tripped byte-for-byte through a lossless response reader whose status read rejects duplicate keys and whose poll absorbs a valid-JSON-but-not-envelope body under its transient budget. Uploads escape and validate multipart part names/filenames against header injection.

### Changed

- `oxicrypt-maxwell`: `independence` analysis allocates sparsely — the tuple-MCV histogram is sized by the codes present via a `HashMap` instead of a dense `2^(k·bits)` array (the 8-bit triplet leg no longer zeros a `1<<24`-slot array per phase, ~33× per run), tuple counts use the closed form `⌊(n−phase)/k⌋` instead of encoding the stream to read its length, and pair encoding writes `u8` directly; exact MCV counts and min-entropy are unchanged (#127).
- `oxicrypt-maxwell`: the periodicity screen's spectral-peak detector searches bins `>= SPECTRAL_MIN_BIN` (8), excluding the lowest bins from both the peak search and the mean-power denominator, so slow low-frequency drift no longer trips the screen; a periodic line at bin 8 or above is unaffected and the autocorrelation detector is unchanged (#102).
- `oxicrypt-lms` (`parallel` feature): `keygen_from_parts` (the ACVP/harness keyGen entry) derives the Merkle root from the parallel `build_node_table` leaf sweep, so a tall-tree keyGen under `--features oxicrypt-lms/parallel` runs multi-threaded instead of single-threaded; the root is byte-identical to the serial recursive `compute_root` by construction (R75). The CMVP-validated default build and the gated `keygen()` / `keygen_internal` remain serial. A parallel-vs-serial keyGen root-equality oracle is added at H=15 and (ignored, pre-submission) H=25 (#129).

### Fixed

- `acvp-harness`: `demo-run` refuses a capability set that registers the same `(algorithm, mode)` under two ACVP revisions, naming them, instead of silently emitting a vector set for each and re-grading coverage that already passed. Registering LMS under a second revision had doubled the long-standing `--algorithm LMS --mode sigVer` invocation from one vector set to two. The check is keyed on that duplicate rather than on a registration count, so several *modes* registering at once stays permitted — `--algorithm ECDSA` without `--mode` has always produced one vector set per mode — and so the remedy stays correct for a mode-less algorithm that gains a second revision, where the fix is `--revision` and demanding `--mode` would register nothing at all. Runs before the transport opens, so a refused invocation costs no login and no YubiKey touch (#144).
- `oxicrypt-entropy`: `collect` default claim uses the ratified `Alpha::DEFAULT` (2⁻³⁰) instead of the 2⁻²⁰ recommended-minimum constant (#126).
- `oxicrypt-entropy`: noise workload is per-round variable — hash-chain iterations (1–8) and steered walk touches (32–95, plus the 32 digest-addressed touches) derive from an XOR-fold of the last measured timer delta; dataset `collection_params` strings name the new workload; `ensure_varied` gains a hard distinct-delta floor of 2 (#125).
- `oxicrypt-entropy`: two-stage timer-adequacy check — bare reads gate monotonicity/coarseness; delta variety is gated on workload-measured deltas via a separate `workload_samples` knob (default 256); `TimerError::Inadequate` carries the measured `AdequacyReport`; `JitterSource` exposes `adequacy()` (workload signal) and `bare_adequacy()`; pre-push gate gains a fail-closed release-profile construction-guard step (#124).
- `security-policy.md`: §1 boundary accounting made explicit (29 library crates, two out-of-boundary, `oxicrypt-test-vectors` ruled in-boundary — its KAT constants compile into the power-up self-tests), resolving a latent §1-vs-§9.2 denominator contradiction; module-version field annotated as assigned-at-submission; §3.1 states the as-built 451-function FFI surface; Appendix B scoped to design/boundary rationale with release history pointed at `CHANGELOG.md`. `AGENTS.md` and `README.md` synced to the same accounting (#101).

## [0.19.0] - 2026-06-28

### Added

- `oxicrypt-keccak-accel`: new audited-unsafe crate carrying an x86_64 AVX2 4-way batched Keccak-f[1600] permutation (`keccak_f1600_x4` / `keccak_f1600_x4_available`), CPUID-gated and byte-exact to the portable `keccak_f1600` (1000-trial cross-path equality oracle against the real scalar permutation); the fifth audited in-boundary acceleration crate, default-off and out of the validated default build graph (#110).
- `oxicrypt-sha`: batched `Sponge4` four-way Keccak sponge API (`absorb_4` / `finalize_4` / `squeeze_4` over four equal-length streams); its single permutation point dispatches to the AVX2 4-way path behind the new default-off `accel-keccak` feature, byte-identical to four independent `Sponge`s (cross-path oracle, feature on and off) (#110).
- `oxicrypt-ml-dsa`: default-off `accel-keccak` feature batches `ExpandA` four independent SHAKE-128 cell streams at a time through `Sponge4` (the first in-boundary caller of the batched Keccak path); the crate stays `#![forbid(unsafe_code)]` and Â is byte-identical to the scalar build (direct accel-vs-scalar differential oracle for ML-DSA-44/65/87, feature on and off) (#110).

## [0.18.1] - 2026-06-24

### Changed

- `oxicrypt-maxwell`: relicensed back to the workspace `Apache-2.0 OR MIT`, reverting the 0.18.0 PolyForm Noncommercial license. It is commodity out-of-boundary tooling that competes with the free authoritative NIST `SP800-90B_EntropyAssessment` reference, so a noncommercial gate protected nothing while forfeiting adoption; `publish = false` is retained (it stays off crates.io as internal tooling — a publish-status choice independent of the license).

## [0.18.0] - 2026-06-24

### Added

- `oxicrypt-ffi`: C-ABI integration smoke test for the SP 800-90A DRBG families (`oxi_{hmac,hash,ctr}_drbg_*`) — full `new → instantiate → generate → reseed → generate → free` lifecycle per family with a non-trivial-output assertion and the documented `NullPointer` guard on a NULL handle (#98).
- `oxicrypt-aes-accel`: PCLMULQDQ-accelerated constant-time GCM GHASH multiply (`ghash_available` / `ghash_mul`), CPUID-gated (PCLMULQDQ + SSSE3 + SSE2) and dispatched from `oxicrypt-aes`'s `gf_mul` behind the default-off `accel-aes` feature; byte-exact to the portable schoolbook reduction (50 000-pair differential oracle + GCM KATs feature-on), fail-portable on absence, out of the validated default build graph (#109).

### Changed

- LAMA manifests (`lama.yaml`, `docs/llm-api-manifest/llm-api.yaml`): descriptions reduced to one declarative sentence each per the LAMA spec's declarative-not-narrative principle (the 287 remaining multi-sentence descriptions collapsed), and `library.version` stamped to 0.18.0; no API or structured-fact change (#116, #118).
- `oxicrypt-maxwell`: relicensed to **PolyForm Noncommercial 1.0.0** (`license-file` + `publish = false`), overriding the workspace `Apache-2.0 OR MIT`. Out-of-boundary tooling and a dependency-leaf with no in-tree dependents, so no library crate's licensing changes; noncommercial use is free, commercial use requires a separate license.

### Fixed

- `tools/acvp-gen`: the KAT-constant generator wrote to the dead `crates/fips-test-vectors/src/generated.rs` path (missed by the `pqclib → oxicrypt` rename), so it created a stray crate directory and never regenerated the live file; the output now targets `crates/oxicrypt-test-vectors/src/generated.rs` (#100).

## [0.17.0] - 2026-06-22

### Added

- `oxicrypt-xmss`: optional `parallel` feature (default off) — `rayon` fork-join over the recursive Merkle tree build for keygen throughput, byte-identical to the validated single-threaded build (security policy R83).
- `oxicrypt-ml-kem`: optional `parallel` feature (default off) — `rayon` row-disjoint expansion of the k×k matrix Â in `expand_a`, byte-identical to the validated single-threaded build (security policy R84).
- `oxicrypt-ml-dsa`: optional `parallel` feature (default off) — `rayon` row-disjoint expansion of the k×ℓ matrix Â in `expand_a`, byte-identical to the validated single-threaded build (security policy R85).
- `oxicrypt-entropy`: optional `rand-core` feature (default off) — `rand_core_compat::EntropyRng` exposes the pipeline's vetted conditioned output as a fallible `rand_core` 0.9 `TryRngCore` (+ `TryCryptoRng`), fail-closed and `no_std`-preserving. No new entropy claim — a convenience adapter over the existing `conditioned_block` output.

## [0.16.0] - 2026-06-19

Closes the SP 800-90B §5.1 compression statistic (statistic 18) in `oxicrypt-maxwell`, so the IID
permutation test now evaluates all nineteen statistics; adds post-quantum criterion benchmarks; and
refreshes the public-API and ACVP-mapping documentation (out-of-boundary tooling and docs only — the
cryptographic boundary is unchanged).

### Added
- **§5.1 compression statistic (statistic 18) in `oxicrypt-maxwell`:** previously a `NaN` sentinel
  excluded from the IID verdict, now computed bit-exactly. The samples are formatted as the NIST
  Entropy Assessment tool does (space-separated decimal text) and bzip2-compressed at level 5,
  matching `ea_iid -v -v -v` "Unpermuted result compression" byte-for-byte (rand1_short = 1611,
  rand4_short = 5520, rand8_short = 10987). All nineteen statistics now participate in the verdict.
- **Post-quantum criterion benchmarks:** ML-KEM, ML-DSA, SLH-DSA, and XMSS.

### Changed
- **`oxicrypt-maxwell`** centralizes the value-sorted-alphabet helper shared across estimators
  (EA-parity ≤ 1e-6 preserved).
- **Documentation:** `api.md` and `usage.md` refreshed to the current public-API surface
  (post-quantum, Diffie–Hellman, XOF families); the LAMA manifest gains full `oxicrypt-xof` coverage;
  per-family ACVP-algorithm → handler dispatch notes added.
- **First third-party dependency in the workspace:** the pure-Rust `bzip2` crate (libbz2-rs-sys
  backend — no C, no `bzip2-sys`), confined to the out-of-boundary `oxicrypt-maxwell` tool. The
  cryptographic boundary and `acvp-harness` remain dependency-free; the Security Policy records the
  scoping. With compression now scored per shuffle, the `oxicrypt-maxwell` permutation suite roughly
  doubles in wall-clock (≈490s → ≈972s) — the inherent cost of a complete nineteen-statistic §5.1
  verdict, matching the reference tool.

## [0.15.0] - 2026-06-17

Completes the SP 800-90B §6.3 multi-bit entropy assessment in `oxicrypt-maxwell`: the
literal-symbol track for every estimator EA computes on it, the assembled `H_original`, and
the per-symbol "Assessed min entropy" headline on the IID gate (out-of-boundary tooling).

### Added
- **`oxicrypt-maxwell` literal-symbol track (§6.3):** t-Tuple, LRS, MultiMCW, Lag, MultiMMC,
  and LZ78Y now compute a literal-track estimate for multi-bit data, each parity-checked against
  the NIST Entropy Assessment reference tool v1.1.8 within 1e-6. (Collision, Markov, and
  Compression have no distinct multi-bit literal value in EA and are correctly excluded.)
- **`h_original`:** the minimum over the MCV-literal and the six literal-track estimates.
- **Per-symbol assessed min-entropy on the IID gate:** `IidGateResult` gains an
  `AssessedMinEntropy { per_symbol, h_original, h_bitstring, word_size }` field beside the
  per-bit `min_entropy`. `iid_gate()` assembles the EA headline
  `min(H_original, H_bitstring × word_size)` per branch (MCV-literal `H_original` on the IID
  branch, the §6.3 literal-suite minimum on the non-IID branch), reproducing EA's "Assessed min
  entropy" line within 1e-6 on the multi-bit reference datasets, branch-matched (the gate's
  IID/non-IID verdict agrees with EA's per dataset).
- **`maxwell iid-gate` CLI:** reports both the per-bit routed value and the per-symbol assessed
  headline with its `min(...)` breakdown.

## [0.14.0] - 2026-06-15

SP 800-90B §5 IID permutation-testing battery + §3.1.4 restart analysis — closing the
two items the 0.13.0 entry deferred (Phase 0 pre-validation, out-of-boundary tooling).

### Added
- **`oxicrypt-maxwell` (out-of-boundary tooling):** the SP 800-90B §5.1 IID
  permutation-testing battery and the §3.1.4 restart-test row/column analysis. 18 of the
  19 §5.1 statistics are implemented and parity-checked against the NIST Entropy
  Assessment reference tool v1.1.8; the §5.1.11 bzip2 "compression" statistic is a
  documented STOP-AND-LEAVE — a NaN sentinel excluded from the verdict, because matching
  libbz2's compressed length bit-for-bit would require a C/third-party dependency the
  Phase-1 policy forbids, and the other 18 statistics determine the IID verdict on the
  bundled datasets. Plus the cleanup tail: t-Tuple/LRS CLI subcommands, the analytic
  min-entropy recovery path, a cargo-fuzz target, and EA-CLI documentation.

_PR #90._

## [0.13.0] - 2026-06-14

SP 800-90B raw-data collection + the complete non-IID min-entropy estimator suite (Phase 0 pre-validation).

### Added
- **`oxicrypt-entropy` (in-boundary):** raw-data collection mode — crate-private
  `RawCollector`, the 1,000,000-sample ESV wire format, and a vendored versioned
  metadata JSON schema (measured counter frequency); default-off `collection` feature
  and `collect` binary.
- **`oxicrypt-maxwell` (out-of-boundary tooling):** the SP 800-90B §6.3 per-OE
  acceptance gate; an FFT + autocorrelation periodicity screen; and the complete §6.3
  non-IID min-entropy estimator suite (Markov, Compression, t-Tuple, LRS, MultiMCW, Lag,
  MultiMMC, LZ78Y) — all matching the NIST Entropy Assessment reference tool v1.1.8 to
  ≤ 1e-6 bits on all 11 bundled datasets, most bit-exact.

_PR #89. Deferred (design-first): IID permutation-testing battery and the restart
row+column Section-5 analysis._

## [0.12.0] - 2026-06-12

SP 800-90B entropy-source subsystem (Wave 1+2) — first invocation of the
"new validation-track subsystem completion" minor-bump trigger.

### Added
- **`oxicrypt-entropy`:** sealed `NoiseSource` trait, cited 90B/90C constants, RCT/APT
  health tests with permanent poisoning, a CPU jitter source, and vetted SHA-256
  conditioning under the SP 800-90C full-entropy input margin.
- **`oxicrypt-timer`:** the fourth audited in-boundary `unsafe` crate (read-only CPU
  timer/counter intrinsics for the entropy source).

### Security
- Security-policy conformance gems R78–R82 and Appendix B added.

## [0.11.0] - 2026-05-17

### Added
- **LMS** expansion arc closeout — the full 80-pair parameter grid.

## [0.10.0] - 2026-05-16

SLH-DSA expansion arc closeout — the full FIPS 205 §11 stateless hash-based signature family.

### Added
- All **12 of 12** SLH-DSA parameter sets across SHA-2 and SHAKE families
  (`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`), built from a single `slh_dsa_impl!` macro
  instantiated 12 times.
- C ABI exports for 36 `oxi_slh_dsa_*` entry points.
- NIST grading: 372 cases across 12 parameter sets × keyGen/sigGen/sigVer graded `passed`.

_PR #78 (merge `115ca45`)._

## [0.9.0] - 2026-05-15

ML-DSA family closeout.

### Added
- **ML-DSA-44** and **ML-DSA-65** alongside the ML-DSA-87 baseline, from a single
  `ml_dsa_impl!` macro source.
- R69 `make_hint` shortcut form (FIPS 204 fence-case conformance at `a0 == -γ_2 && w_1 != 0`).
- ACVTS grading: 3 sessions, 192 cases, all `passed` (keyGen 75/75, sigGen 72/72, sigVer 45/45).

_PR #75 (merge `8f80699`)._

## [0.8.0] - 2026-05-14

ML-KEM grid closeout.

### Added
- **ML-KEM-512** and **ML-KEM-768** alongside the ML-KEM-1024 baseline (FIPS 203 Table 2,
  3/3), all three generated from one declarative `ml_kem_impl!` macro template.
- C ABI per-variant symbols plus 3 C round-trip and implicit-rejection smoke tests.
- ACVTS grading: 180 cases (75 keyGen AFT + 75 encaps AFT + 30 decaps VAL implicit-rejection), `passed` first-try.

### Security
- Phase 2 zeroize coverage closed across all three variants; three CMVP gems captured
  (macro-template parameter-set integrity, intermediate-state zeroize ordering, PQ C ABI smoke-test precedent).

_PR #74 (merge `7acd239`)._

## [0.7.0] - 2026-05-14

RSA family closeout (capability-matrix Section 12, 6/6).

### Added
- **KTS-IFC OAEP** key-transport handler, completing the deferred OAEP arc. RSA modes now
  6/6 graded: sigVer, keyGen, sigGen, sigPrim, decPrim, OAEP.
- Live-graded clean first-try (3 groups / 30 cases across 2048/3072/4096 moduli, both kasRoles).

_PR #73 (merge `9b6040f`)._

## [0.6.0] - 2026-05-13

DRBG family closeout (capability-matrix Section 7, 3/3).

### Added
- **hashDRBG** and **hmacDRBG** (720 cases each across SHA2-{256,384,512} × PR-{true,false}),
  live-graded `passed` first-try.

### Fixed
- Per-mode `returnedBitsLen` capability-shape (draft-vassilev-acvp-drbg Table 4: per-mode
  minimum = hash output length — SHA2-256→256, SHA2-384→384, SHA2-512→512).

## [0.5.0] - 2026-05-13

KDF + KAS double-section closeout (Section 8 KDF 3/3, Section 13 KAS 2/2).

### Added
- **KBKDF** counter + feedback + double-pipeline modes, first-live-graded (1,300 cases across all 11 HMAC PRFs).
- **KAS-FFC-SSC** (25 cases: AFT responder + VAL initiator), generalised verbatim from the KAS-ECC-SSC dispatch pattern.

## [0.4.0] - 2026-05-12

### Changed
- Toolchain: `rust-version` 1.95, edition 2024, and a pinned `rust-toolchain.toml`.

_PR #69._

## [0.3.0] - 2026-05-11

SP 800-185 / XOF family closeout (capability-matrix Section 4, 10/10).

### Added
- **SHAKE-{128,256}**, **KMAC-{128,256}**, **cSHAKE-{128,256}**, **TupleHash-{128,256}**,
  and **ParallelHash-{128,256}** (TupleHash and ParallelHash unified onto the XOF path).
  2,010 new ACVTS test cases.

### Fixed
- Conformance gems R65–R68 (security-policy.md §11): cSHAKE non-empty `functionName` +
  `customizationHex` field-name; TupleHash/ParallelHash capability-shape completeness
  (`msgLen`, `hexCustomization`); TupleHash MCT tuple-field + digest carry-forward.

## [0.2.0] - 2026-05-09

C ABI arc completion and a permissive relicense.

### Added
- **C ABI** surface across SHA-3, HMAC-SHA, AES, SHA-2, KDF, ECDSA, and EdDSA
  (8-PR arc: foundation + AES, CMAC, HMAC-SHA, SHA-2, KDF, ECDSA, EdDSA; DRBG deferred).
- ACVTS bring-up of ML-KEM, SLH-DSA, ML-DSA, and LMS.
- Capability-matrix preflight artifact.

### Changed
- **Relicensed to `Apache-2.0 OR MIT`** (Rust-ecosystem default), retiring PolyForm
  Noncommercial 1.0.0 (PR #63).

### Fixed
- ML-KEM decaps implicit-rejection (PR #59).

## [0.1.0] - 2026-04-27

First minor release. Recognises the cumulative substance shipped on the pre-1.0
`v0.0.0.A` internal-build train — a contribution model, CI hygiene, an HMAC regression
fix, and the first new primitive (TLS 1.3 KDF) — and retires that train.

### Added
- **TLS 1.3 KDF** per RFC 8446 §7.1: `tls13_hkdf_expand_label_internal` and
  `tls13_derive_secret_internal` (`oxicrypt-tls-kdf`), with the matching ACVP
  `TLS-v1.3 / KDF / RFC8446` harness handler. Live-graded `passed` first-try
  (ACVTS session 724216).
- Contribution model: `CONTRIBUTING.md` (GitHub Flow, squash-merge, local gate stack),
  the PR template, the internal-build tagging convention (`vX.Y.Z.A`), and
  `scripts/tag-next-build.sh`.

### Fixed
- HMAC handlers read `macLen` per-test with group-level fallback, restoring 11 offline
  MVT round-trip tests (PR #1).
- CI hygiene: rustfmt drift across five files and two Rust 1.95 clippy regressions (PR #2).

### Changed
- Workspace version `0.0.0` → `0.1.0`.

[Unreleased]: https://github.com/oxiforge/oxicrypt/compare/v0.25.0...HEAD
[0.25.0]: https://github.com/oxiforge/oxicrypt/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/oxiforge/oxicrypt/compare/v0.23.2...v0.24.0
[0.23.2]: https://github.com/oxiforge/oxicrypt/compare/v0.23.1...v0.23.2
[0.23.1]: https://github.com/oxiforge/oxicrypt/compare/v0.23.0...v0.23.1
[0.23.0]: https://github.com/oxiforge/oxicrypt/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/oxiforge/oxicrypt/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/oxiforge/oxicrypt/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/oxiforge/oxicrypt/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/oxiforge/oxicrypt/compare/v0.18.1...v0.19.0
[0.18.1]: https://github.com/oxiforge/oxicrypt/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/oxiforge/oxicrypt/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/oxiforge/oxicrypt/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/oxiforge/oxicrypt/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/oxiforge/oxicrypt/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/oxiforge/oxicrypt/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/oxiforge/oxicrypt/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/oxiforge/oxicrypt/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/oxiforge/oxicrypt/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/oxiforge/oxicrypt/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/oxiforge/oxicrypt/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/oxiforge/oxicrypt/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/oxiforge/oxicrypt/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/oxiforge/oxicrypt/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/oxiforge/oxicrypt/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/oxiforge/oxicrypt/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/oxiforge/oxicrypt/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/oxiforge/oxicrypt/compare/v0.1.0.1...v0.2.0
[0.1.0]: https://github.com/oxiforge/oxicrypt/releases/tag/v0.1.0.1
</content>
