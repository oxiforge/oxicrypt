# An integration guide for the C library: `oxi` post-quantum services, six how-tos, one guide

Status: approved with its acceptance criteria in `ISA.md` by the merge of pull request #309, 2026-11-23.

## Problem

A developer who downloads a library bundle can run SHA-256 from six languages by following `examples/`. Nothing shows them a signature or a key exchange, which is what they came for. Nothing lets them check that what their program produced is what the module produces, because the `oxi` CLI exposes hashes, HMAC and random bytes only. And nothing tells them what the module expects of the program around it: where seeds come from, what a return code means, how long the module lives, what to do with a shared secret, how to ship the library.

## Outcome

A developer in C, Python, Go, Node.js, Java or C# integrates the module into a product from two documents. The how-to for their language, `examples/<language>/README.md`, takes them from downloading the bundle to a program that hashes, signs and verifies with ML-DSA-87 and establishes a shared secret with ML-KEM-1024, with the exact output every step should print and a one-line `oxi` command that independently verifies or reproduces what the program produced. The integration guide, `docs/integration.md`, one document for all languages, tells them everything the how-to does not: the module's contract with the program around it.

### User stories

- A Go developer with a bundle and no Rust toolchain reaches "verify ok" and "secrets match" in one sitting, with every expected value in front of them.
- A security reviewer takes the public key, message and signature a developer's Java program wrote, runs `oxi ml-dsa verify 87` on their own machine, and sees exit 0; then encapsulates to the program's key with `oxi` and watches the program decapsulate to the same secret.
- A scripter uses `oxi ml-dsa verify` in a shell pipeline and gets a distinct exit code for "the signature is not valid", separate from "the module did not start" and from "bad arguments".
- A developer who finished the how-to reads the integration guide and knows, before writing product code, how to draw seeds, what to do with a 32-byte shared secret, when the module refuses service and what their program must do then, and how to package the library for each platform they ship on.
- The release workflow runs, on every host it builds on, each example whose toolchain that host is required to have, against the library it just packed, and fails the release if any output differs from the known answers or a required toolchain is missing.

## Scope

### 1. `oxi` gains two command families

```
oxi ml-dsa keygen <44|65|87>     --pk FILE --sk FILE [--seed HEX | --seed-out FILE]
oxi ml-dsa sign   <44|65|87>     --sk FILE --sig FILE [--ctx HEX] [--] [MESSAGE]
oxi ml-dsa verify <44|65|87>     --pk FILE --sig FILE [--ctx HEX] [--] [MESSAGE]
oxi ml-kem keygen <512|768|1024> --ek FILE --dk FILE [--d HEX --z HEX | --seed-out FILE]
oxi ml-kem encaps <512|768|1024> --ek FILE --ct FILE [--ss FILE]
oxi ml-kem decaps <512|768|1024> --dk FILE --ct FILE [--ss FILE]
```

- `MESSAGE` is a file path, or stdin when absent or when given as `-`. `--` ends flag parsing so a message file whose name begins with `-` can be named; a file literally named `-` is given as `./-`. More than one positional after the set is a usage error.
- Keys, signatures and ciphertexts are raw bytes in files the caller names. The shared secret goes to the file named by `--ss`, or, when `--ss` is absent, to stdout as 64 hex characters on one line with nothing else on stdout. Files holding secret material (`--sk`, `--dk`, `--ss`) are created with owner-only permission where the operating system has file modes.
- `--seed` (ML-DSA) and `--d` with `--z` (ML-KEM keygen) are 64 hex characters (32 bytes) each; `--d` and `--z` are given together or not at all. With them, `keygen` expands the key pair from the supplied seed through the module's key-expansion service (section 3), which exists for keys reconstituted from a stored seed (FIPS 204 §3.6.3, FIPS 203 §3.3) and runs the pairwise consistency test like any key generation. Without them, the seed is drawn inside the module from an HMAC_DRBG-SHA-256 the CLI constructs through the module, which seeds it from the module's own entropy source; the CLI never reads operating-system entropy. `--seed-out FILE` asks `keygen` to also write the module-generated seed (32 bytes, or 64 bytes `d` then `z`) to a new owner-only file for later expansion; it is exclusive with the seed flags. When a seed flag is present the command prints `seed supplied: protect this seed as you would the secret key` on stderr and continues; the help text says the same, and that a seed on the command line is visible to anyone who can read the process list. There is no `--m` flag: encapsulation always draws its randomness inside the module.
- `oxi rand` moves to the same module-seeded DRBG, and its direct `/dev/urandom` read is deleted; no command in `oxi` reads operating-system entropy. The first command in a process that needs randomness pays the entropy source's startup (`prd/drbg-seeding.md`); the measured cost per platform is recorded there.
- `--ctx` is 0 to 255 bytes as hex; absent means the empty context. The CLI checks the length before calling the module.
- Argument parsing stays positional and hand-written, as the existing commands are. The grammar is `oxi <family> <verb> <set> [--flag value]... [--] [MESSAGE]`. An unknown flag, a repeated flag, a flag without a value, or a missing required flag is a usage error. No argument-parsing dependency is added to the workspace.
- `oxi --help`, `oxi/README.md`, the repository `README.md` section on the CLI, and the embedded LAMA manifest list the new commands.
- `oxi` enables no testing feature. Everything it calls is an approved service of the shipped crates.
- `oxi`'s power-up set gains the ML-KEM group (`oxicrypt_ml_kem::KATS`, four ML-KEM-1024 self-tests), so the self-tests run before the module becomes operational, as FIPS 140-3 requires a cryptographic algorithm self-test before an algorithm's first use. `oxi selftest` lists an `ml-kem (4)` group after `ml-dsa`; its total rises by four. The CLI's own inventory test of linked crates gains the crate.

### 2. Module prerequisites this feature depends on

Three gaps in the module's ML-DSA and ML-KEM crates would be exposed to every reader of the how-tos the moment the CLI and the examples exercise key generation and imported keys. All are module changes, reach the C ABI, the Rust binding crate and this CLI alike, and land before or with the CLI commands, never after. A fourth change this feature depends on, the module seeding its own DRBGs, is `prd/drbg-seeding.md` and lands as the shared change before either arc. A fifth, small one rides with this arc: ECDH, ECDSA, Ed25519 and RSA key generation adopt the same pairwise-consistency failure path as the new services (section 3), so the module has one such behaviour.

- **Pairwise consistency test.** FIPS 140-3 (ISO/IEC 19790 §7.10.3.3) requires one on every key pair the module generates for signatures or key establishment. The ECDH and ECDSA crates run one; the ML-DSA and ML-KEM key generation functions return the pair directly. After ML-DSA keygen, sign a fixed message and verify it; after ML-KEM keygen, encapsulate with a fixed `m` and check the decapsulated secret matches. A mismatch is a conditional self-test failure and puts the module in the error state.
- **ML-KEM input checks.** FIPS 203 §7.2 requires the encapsulation key check (every 12-bit coefficient below q, so re-encoding the key reproduces it) before encapsulation, and §7.3 the decapsulation key checks (length, and the stored `H(ek)` equal to the hash of the stored `ek`) before decapsulation. The decoder reduces an out-of-range coefficient modulo q and continues, and decapsulation uses the stored hash without recomputing it, so a malformed imported key is processed rather than refused. Both checks are added, each failing with `InvalidInput`, and the CLI maps that to a usage error naming the file.
- **Randomness drawn inside the module.** FIPS 203 §3.3 states that the sampling of the random values for key generation and encapsulation "shall be performed by the cryptographic module" and that the derandomized internal functions "should not be made available to applications other than for testing purposes"; FIPS 204 §6 states the same for key generation and signing. Today the only key-generation and encapsulation interfaces the module offers, in Rust and at the C ABI, take the seed from the caller, so the application performs the sampling and the seed crosses the boundary in the clear. Conformance needs key-generation and encapsulation entry points that draw `ξ`, `d`, `z` and `m` from a DRBG held inside the module, with the pairwise consistency test inside them, and the seed-taking forms retained for the self-tests, the ACVP harness and reproducible checks and documented as test interfaces. Key generation and encapsulation that draw inside the module become the primary services. Key expansion from a caller-held seed stays, as its own service named for what it is: FIPS 204 §3.6.3 permits storing ξ "for the purpose of later expansion" and requires it be "treated with the same safeguards as a private key", and the IG requires a pairwise consistency test once on a pair expanded from a stored seed; the service runs that test on every call. Encapsulation with a caller-supplied `m` has no such warrant and leaves the C ABI. The derandomized internal forms (`keygen_internal`, `encaps_internal`, `decaps_internal`, `sign_internal`) move behind a default-off `testing-interfaces` cargo feature that the ACVP harness enables; the self-tests reach the crate-internal cores without it. The new functions take the opaque `OxiDrbg` handle `prd/drbg-seeding.md` defines (any of the module's nine DRBGs behind one handle, so a profile that forbids HMAC_DRBG-SHA-256 still has a permitted source) and the output buffers; in Rust they take a mutable reference to any DRBG through `oxicrypt_module::Rbg`. That interface is shared with the AES update and lands first as its own change that both arcs build on. Nothing else of the AES update is in this arc. This is an ABI change (symbols added and removed) and a Security Policy change; it is listed here because the how-tos would otherwise teach the test interface as the production one.

### 3. API shapes

The shared randomness interface and the seeding of every DRBG by the module are specified in `prd/drbg-seeding.md`, which lands as its own change before this one. In short: a trait `oxicrypt_module::Rbg` with `fill` and `strength_bits`, implemented by the nine DRBG types; one opaque C handle `OxiDrbg`; `instantiate_from_module` in Rust and `oxi_drbg_instantiate` in C taking a personalization string only; result codes `RbgTooWeak`, `Busy` and `EntropyUnavailable`; and `Error::Rbg(RbgError)` on the module error. This section specifies what this feature adds on top of it and nothing it already decides.

**Strength.** FIPS 203 §3.3 requires the RBG to have at least 128, 192 or 256 bits of security strength for ML-KEM-512, -768 and -1024. FIPS 204 §3.6.1 requires 192 for ML-DSA-65 and 256 for ML-DSA-87, and for ML-DSA-44 says the RBG "should" have 192 and "shall" have 128, with the claim reduced to category 1 below 192. The module requires 192 for ML-DSA-44, so the claim is never reduced. Every entry point below compares `rbg.strength_bits()` with the parameter set's requirement before any draw and returns `Error::RbgTooWeak` if it is lower; so CTR_DRBG with AES-128 serves ML-KEM-512 only, and AES-192 adds ML-KEM-768, ML-DSA-44 and ML-DSA-65.

**Pairwise consistency test.** Every function that produces a key pair runs it before the pair leaves the module. ML-DSA: sign `PCT_MESSAGE` with the empty context through the internal core and verify with the new public key. ML-KEM: encapsulate against the new encapsulation key with `PCT_M` through the internal core, decapsulate with the new decapsulation key, compare the two secrets in constant time. The constants live in `oxicrypt-module`: `PCT_MESSAGE` is 32 bytes, the 29 ASCII bytes of `oxicrypt pairwise consistency` followed by three zero bytes; `PCT_M` is 32 bytes, the SHA-256 digest of the ASCII bytes of `oxicrypt pairwise consistency m`, computed once and pinned as a literal with that derivation in its comment. On failure the function zeroizes both halves of the pair and every intermediate, returns `Error::ConditionalTestFailed { reason }` with `reason` the parameter set's name followed by ` pairwise consistency`, and the module enters its error state through `enter_error_state`, after which every service returns `NotOperational` until the process restarts. Nothing is written to any output before the test passes. ECDH P-256 and P-384, ECDSA P-256 and P-384, Ed25519 and RSA key generation, which return `InvalidInput` on a PCT mismatch today and leave the module operational, move to the same failure path in this arc (`Error::ConditionalTestFailed { reason: "<algorithm> pairwise consistency" }`, `enter_error_state`), so the module has one conditional-failure behaviour; their C return code for that case changes from `5` to `3`.

**Seeds and intermediates.** Every module-owned copy of ξ, `d`, `z`, `m` and every intermediate lives in zeroizing storage from the moment it is drawn or copied in and is wiped on every exit, including an error from the second draw after the first succeeded. A seed buffer the caller owns and passes by reference is the caller's to wipe; the guide says so.

**Hedged signing is not in this arc, and nothing here forecloses it.** FIPS 204 §3.4 makes the hedged variant the default and permits the deterministic one; the module ships deterministic signing. To keep the hedged variant a pure addition later: the crate-internal signing core takes `rnd: &[u8; 32]` as FIPS 204 Algorithm 7 does, with the deterministic `sign` passing 32 zero bytes; the `Service` enum reserves no identifier but its numbering leaves room per set; the C symbol `oxi_ml_dsa_NN_sign_hedged` is unused and the header's `sign` comment says the hedged form is a planned addition rather than "no randomized variant is exposed"; the ACVP registration keeps `deterministic: [true]` so adding `false` is additive; the Security Policy's signature rows name the variant.

Rust, in `oxicrypt-ml-dsa`, one module per parameter set (`ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`); `NN` stands for the set:

```rust
/// FIPS 204 Algorithm 1: checks strength, draws ξ from `rbg`, expands the
/// pair, runs the pairwise consistency test, never returns ξ.
/// Gated on require_operational and require_allowed(Service::MlDsaNNKeygen).
pub fn keygen<R: oxicrypt_module::Rbg>(rbg: &mut R)
    -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error>;

/// As `keygen`, and also returns ξ so the caller can store it for later
/// expansion (FIPS 204 §3.6.3); ξ is a private key and the caller protects it.
pub fn keygen_with_seed<R: oxicrypt_module::Rbg>(rbg: &mut R)
    -> Result<(oxicrypt_zeroize::Zeroizing<[u8; SEED_LEN]>, [u8; PK_LEN], [u8; SK_LEN]), Error>;   // Zeroizing is defined by prd/drbg-seeding.md

/// FIPS 204 §3.6.3: expands the pair from a stored seed and runs the
/// pairwise consistency test. A seed that did not come from this module's
/// `keygen_with_seed` is a private key imported from outside the boundary.
/// Gated on Service::MlDsaNNExpandKey.
pub fn expand_key(xi: &[u8; SEED_LEN])
    -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error>;

pub fn sign(sk: &[u8; SK_LEN], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error>;   // unchanged behaviour; the core now takes rnd = 0
pub fn verify(pk: &[u8; PK_LEN], message: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), Error>; // unchanged
pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> Result<bool, Error>;   // unchanged and ungated: the integrity test calls it before the module is operational, and FIPS 204 §6 restricts key generation and signing interfaces, not verification

#[cfg(feature = "testing-interfaces")]   // FIPS 204 §6: CAVP testing only
pub fn keygen_internal(xi: &[u8; SEED_LEN]) -> ...;      // as today, no PCT
#[cfg(feature = "testing-interfaces")]
pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8], rnd: &[u8; 32]) -> ...;   // gains rnd
```

Rust, in `oxicrypt-ml-kem`, one module per parameter set (`ml_kem_512`, `ml_kem_768`, `ml_kem_1024`):

```rust
/// FIPS 203 Algorithm 19: checks strength, draws d then z as two 32-byte
/// requests, expands the pair, runs the pairwise consistency test, never
/// returns d or z. Gated on Service::MlKemNNNKeygen.
pub fn keygen<R: oxicrypt_module::Rbg>(rbg: &mut R)
    -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error>;

/// As `keygen`, and also returns (d, z) for storage (FIPS 203 §3.3).
pub fn keygen_with_seed<R: oxicrypt_module::Rbg>(rbg: &mut R)
    -> Result<(oxicrypt_zeroize::Zeroizing<[u8; 64]>, [u8; EK_LEN], [u8; DK_LEN]), Error>;   // d then z

/// Expands the pair from stored (d, z) and runs the pairwise consistency
/// test; a seed from elsewhere is an imported private key.
/// Gated on Service::MlKemNNNExpandKey.
pub fn expand_key(d: &[u8; 32], z: &[u8; 32])
    -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error>;

/// FIPS 203 Algorithm 20: runs the §7.2 encapsulation key check on `ek`
/// (Error::InvalidInput before any computation on failure), then checks the
/// strength (the shared order: validity before strength), draws m from `rbg`,
/// returns (shared secret, ciphertext).
/// Gated on Service::MlKemNNNEncaps.
pub fn encapsulate<R: oxicrypt_module::Rbg>(ek: &[u8; EK_LEN], rbg: &mut R)
    -> Result<([u8; 32], [u8; CT_LEN]), Error>;

/// FIPS 203 Algorithm 21: runs the §7.3 decapsulation input check (lengths
/// by type; stored H(ek) recomputed and compared) and returns the shared
/// secret. Error::InvalidInput on a failed check; never an error for a
/// ciphertext that merely does not match. Gated on Service::MlKemNNNDecaps.
pub fn decapsulate(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> Result<[u8; 32], Error>;

/// The FIPS 203 §7.2 and §7.3 checks on their own, for the ACVP key-check
/// tests and for callers that validate a key once and store it (gated on the
/// set's Encaps / Decaps service).
pub fn check_encapsulation_key(ek: &[u8; EK_LEN]) -> Result<bool, Error>;
pub fn check_decapsulation_key(dk: &[u8; DK_LEN]) -> Result<bool, Error>;

#[cfg(feature = "testing-interfaces")]   // FIPS 203 §3.3: CAVP testing only
pub fn keygen_internal(d, z) / encaps_internal(ek, m) / decaps_internal(dk, ct);   // as today, no PCT, no §7 checks
```

`oxicrypt_module::Service` gains `MlKem512ExpandKey = 660`, `MlKem768ExpandKey = 661`, `MlKem1024ExpandKey = 662`, `MlDsa44ExpandKey = 663`, `MlDsa65ExpandKey = 664` and `MlDsa87ExpandKey = 665` (the first free values after today's highest, 659), each admitted under exactly the profiles its set's key generation is admitted under, with a `Display` string of the form `ML-KEM-512 key expansion`. `Error::Rbg(RbgError)` and `Error::RbgTooWeak` come from `prd/drbg-seeding.md`. Today's seeded `keygen` and `encapsulate` are removed under those names; `expand_key` replaces the first, nothing replaces the second. The header's sentence that ML-KEM key generation can fail with `InvalidInput` on a rare decode failure describes nothing in the implementation (the sampler loops) and is dropped with the symbol it annotated. `oxicrypt-integrity-sign`, which derives the signing key pair from a stored seed, moves to `expand_key`.

**The features.** `testing-interfaces`, default off, declared in `oxicrypt-ml-dsa` and `oxicrypt-ml-kem` here and in `oxicrypt-drbg` by `prd/drbg-seeding.md`; `acvp-harness` enables it in its `Cargo.toml`, as does `oxicrypt-entropy`'s dev-dependency on `oxicrypt-drbg`; nothing else does. `fault-injection`, default off, declared by `prd/drbg-seeding.md` in the crates it names and used here for the pairwise-consistency fault seams, one per crate under a `seam` module compiled under `cfg(any(test, feature = "fault-injection"))`: `oxicrypt_ml_dsa::seam::corrupt_next_pk()`, `oxicrypt_ml_kem::seam::corrupt_next_dk()` (flips byte 0 of `dk_PKE`), `oxicrypt_ecdsa::seam::corrupt_next_pk()`, `oxicrypt_ecdh::seam::corrupt_next_pk()`, `oxicrypt_eddsa::seam::corrupt_next_pk()` (each flips byte 1 of the encoded public key, the first coordinate byte, before the test), `oxicrypt_rsa::seam::corrupt_next_pk()` (flips byte 0 of `n`), each arming the next key generation in the process; the `reason` strings are `ECDSA P-256 pairwise consistency`, `ECDSA P-384 pairwise consistency`, `ECDH P-256 pairwise consistency`, `ECDH P-384 pairwise consistency`, `Ed25519 pairwise consistency`, `RSA pairwise consistency`; a spawned `oxi` built with the feature arms them from `OXI_FAULT=corrupt-next-key`, as `prd/drbg-seeding.md` section 2 defines; the CLI's fault tests build `oxi` with `cargo test -p oxicrypt-cli --features fault-injection`, whose `CARGO_BIN_EXE_oxi` is that build, and the `c-integration` job builds the library with the feature for its fault cases. Release builds compile by package (`cargo build -p oxicrypt-ffi`, `-p oxicrypt-cli`), so workspace feature unification cannot pull either feature in. The checks that make this a fact: a `compile_fail` doctest per crate, run with `cargo test -p <crate> --doc` (per package, so features resolve per package), naming each restricted function without the feature; `cargo tree -p oxicrypt-ffi -e features` and `-p oxicrypt-cli` showing neither feature; and the release workflow's build commands carrying `-p`. The existing tests that call the internal forms (`tests/nist_kat.rs`, `tests/internal_state_guard.rs`, `tests/acvts_regressions.rs` in both crates) are integration tests of their own crate and run with `--features testing-interfaces` in their `cargo test` invocation in CI.

C, in `oxicrypt.h`. The seed-taking `oxi_ml_dsa_NN_keygen`, `oxi_ml_kem_NNN_keygen` and `oxi_ml_kem_NNN_encapsulate` are removed; the new symbols have new names, so an object compiled against the old header fails to link rather than passing a seed where a handle is expected:

```c
int oxi_ml_dsa_87_keygen_rbg(OxiDrbg *rbg, uint8_t *pk_out, uint8_t *sk_out,
                             uint8_t *seed_out);              /* seed_out: 32 bytes, or NULL to withhold ξ; and _44, _65 */
int oxi_ml_dsa_87_expand_key(const uint8_t *seed_ptr, uint8_t *pk_out, uint8_t *sk_out);
int oxi_ml_kem_1024_keygen_rbg(OxiDrbg *rbg, uint8_t *ek_out, uint8_t *dk_out,
                               uint8_t *seed_out);            /* seed_out: 64 bytes d‖z, or NULL; and _512, _768 */
int oxi_ml_kem_1024_expand_key(const uint8_t *d_ptr, const uint8_t *z_ptr,
                               uint8_t *ek_out, uint8_t *dk_out);
int oxi_ml_kem_1024_encapsulate_rbg(const uint8_t *ek_ptr, OxiDrbg *rbg,
                                    uint8_t *ss_out, uint8_t *ct_out);
/* oxi_ml_dsa_NN_sign, _verify and oxi_ml_kem_NNN_decapsulate keep their names and shapes */
```

Return codes follow the shared check order of `prd/drbg-seeding.md` section 5 exactly: pointer rules (`10`, `5`), module operational (`1`), profile (`6`), process id (`5`), busy (`32`), then this feature's input checks (strength `31`; FIPS 203 §7.2 or §7.3 failure `5`), then the operation, with the DRBG's codes (`8`, `12`, `33`; never `9`, since a module-seeded instance reseeds itself) if the draw fails before any key material exists, and `ConditionalTestFailed = 3` when the pairwise consistency test fails, after which every call returns `NotOperational = 1`. Output buffers are written only on success. The header documents each symbol's codes. This change removes symbols, so it advances `OXI_ABI_VERSION` and records its `abi/v<n>.txt`, per the rule in `prd/drbg-seeding.md` section 5.

The `oxicrypt` Rust binding crate wraps the five new symbol families, drops the seeded `encapsulate`, renames its seeded keygen wrappers to `expand_key`, and `tests/pins.rs` gains a test `pq_symbols` that lists every `oxi_ml_dsa_*` and `oxi_ml_kem_*` symbol in the header and fails when the list and the wrappers differ. The binding crate's wrappers are `Module::ml_dsa_87_keygen(&self, rbg: &mut Drbg)`, `::ml_dsa_87_keygen_with_seed`, `::ml_dsa_87_expand_key(&self, seed: &MlDsa87Seed)`, `::ml_kem_1024_keygen`, `::ml_kem_1024_keygen_with_seed`, `::ml_kem_1024_expand_key(&self, seed: &MlKem1024Seed)`, `::ml_kem_1024_encapsulate(&self, ek, rbg: &mut Drbg)`, the same for the other four sets, with the seed types `Zeroizing` newtypes the crate already has for ML-DSA-87 and ML-KEM-1024 (`secret.rs`) extended to the other sets. The ACVP harness drives the crates through the internal forms under the feature, which is what the CAVP vectors require, and its registrations change in two ways: ML-DSA adds `signatureInterfaces: ["external"]` with `contextLength: [{"min": 0, "max": 255, "increment": 1}]` and `preHash: ["pure"]`, dispatched by a new `ml_dsa_sig_gen_external` and `ml_dsa_sig_ver_external` handler pair that call the shipped `sign` and `verify` with the vector's `context`; and ML-KEM adds `encapsulationKeyCheck` and `decapsulationKeyCheck` to its `functions`, dispatched to `check_encapsulation_key` and `check_decapsulation_key`, returning the `testPassed` boolean the vector expects.

`oxi`: every command that needs randomness constructs one HMAC_DRBG-SHA-256 through `HmacDrbgSha256::instantiate_from_module(b"oxi")`; the example programs use `oxi_drbg_instantiate` with the personalization string `oxicrypt example`; `oxi rand` moves to the same construction and the direct `/dev/urandom` read is deleted. `keygen` without seed flags calls `keygen`, or `keygen_with_seed` when `--seed-out FILE` is given, writing the seed owner-only; with seed flags it calls `expand_key`; `encaps` calls `encapsulate`. The pairwise consistency test and the input checks run on every path.

### 3a. Security Policy

The paired `oxicrypt-policy` change lands with the module half, in the same release, and states:

- **Approved services table.** New rows for ML-DSA key generation (RBG, with and without seed output), ML-DSA key expansion from a stored seed, ML-KEM key generation (RBG, with and without seed output), ML-KEM key expansion from a stored seed, and ML-KEM encapsulation (RBG), each naming its FIPS 203 or 204 algorithm, its `Service` identifier, its inputs and outputs, and the CSPs it touches. The rows for the removed seeded services are deleted. The signature rows name the deterministic variant (FIPS 204 §3.4) so a hedged row can be added beside them.
- **Conditional self-tests.** The ML-DSA and ML-KEM pairwise consistency tests, their form (sign-then-verify; encapsulate-then-decapsulate), when they run (on every key pair the module produces, by generation or by expansion), and their failure action (error state); the ECDH and ECDSA rows updated to the same failure action.
- **Pre-operational self-tests.** The CLI's inventory gains the ML-KEM group; the policy's CAST list for the `oxi` configuration states the new count.
- **SSPs.** ξ, `d`, `z` and the stored seed as CSPs with the same protection as the private key (FIPS 204 §3.6.3); `m` as a CSP until encapsulation consumes it; the shared secret as a CSP; zeroization of module-owned copies on every exit; the caller's duty for buffers it owns.
- **Entropy and key generation.** The seeding statements are `prd/drbg-seeding.md` section 7's and are not restated; this arc adds the SP 800-133 Rev. 2 key-generation statement naming the RBG output as the key material for ML-DSA and ML-KEM, and the stored-seed expansion as key import where the seed did not come from the module.
- **Algorithm-specific information (SP 800-140B §2.7).** The FIPS 203 §7.2 and §7.3 input checks are performed by the module on every encapsulation and decapsulation; the RBG strength requirement per parameter set and how the module enforces it, including 192 bits for ML-DSA-44; that the module samples all randomness for key generation and encapsulation internally through its own DRBGs; that a seed given to key expansion that the module did not generate is an imported private key.
- **Operational environment and configuration.** The `testing-interfaces` feature is excluded from the validated configuration, like `accel-aes`; the caller-entropy DRBG instantiate is a testing interface; the compile-fail tests and the per-package release build are the evidence.
- **CAVP.** The ACVP registration changes of section 3 (external ML-DSA interface, ML-KEM key checks) and the sessions that grade them, in the validation evidence.
- **Version.** The module version and `oxi_abi_version()` value the release carries.

Each statement is written against the merged code, cites its clause, and is checked by the policy repository's doc-guard where a check exists.

### 4. Every example grows into a how-to

Each `examples/<language>/README.md` opens with a title, a short preamble (prerequisites and toolchain versions, the "verified on" line, one sentence saying the how-to gets a first call right and the integration guide covers the rest, with the link), and then these six headings, in this order, and no other headings at that level:

1. **Get the bundle** — download URL pattern for the library bundle and for the CLI archive of the same version and platform, the `.sha256` check for each, the file names inside, where the release key fingerprint is recorded (`BUILD-PROVENANCE.txt` and the repository key file) for comparison in step 2, and `oxi --integrity` run from the extracted CLI archive to confirm the CLI used for step 6 is the signed release.
2. **Load and start the module** — loading the library in this language, `oxi_init(0)` and what each non-zero return means for the user (the module refused to start and serves nothing), then the programmatic integrity check: `oxi_integrity_status` and `oxi_integrity_key_fingerprint` compared with the fingerprint from step 1.
3. **Hash** — SHA-256 of `"abc"` and its digest.
4. **Sign and verify** — constructing one of the module's DRBGs (`oxi_hmac_drbg_sha256_new_rbg`, then `oxi_drbg_instantiate` with an empty personalization string; the module seeds it), ML-DSA-87 keygen drawing its seed from that DRBG, signing the fixed message with the empty context, verifying, and verifying a signature with a named byte flipped, which the module rejects. The program writes the public key, the message and the signature to files for step 6.
5. **Establish a shared secret** — ML-KEM-1024 keygen and encapsulation drawing from the same DRBG, decapsulation, equality of the two secrets, and decapsulation of a ciphertext with a named byte flipped, which yields a different secret and no error. The text says why: FIPS 203 implicit rejection keeps a tampered ciphertext from revealing anything through the result, and a real protocol detects mismatch by key confirmation, not by an error from decapsulation. The program writes the decapsulation key and the ciphertext to files for step 6.
6. **Check your output against `oxi`** — `oxi ml-dsa verify 87` on the program's public key, message and signature exits 0, and `oxi ml-kem decaps 1024` on the program's decapsulation key and ciphertext prints the secret the program printed. Then the reverse direction: `oxi ml-kem encaps 1024` against the program's encapsulation key, and the program's `decaps` mode on that ciphertext prints `oxi`'s secret. The text says what this proves: that the program's buffers, lengths and calls agree with an independent consumer of the same library on every byte of every object, with no shared seed. It closes with the one known answer from NIST: `oxi ml-dsa keygen 87 --seed <ACVP vector seed>` followed by `oxi hash sha256` over the public key gives the digest the how-to states.

Two directories are added so that every language has a how-to and a runnable program: `examples/c/` and `examples/python/`. The repository `README.md` keeps its short C and Python snippets and links to them. The release check's example mode gains toolchain entries for both.

Each example program takes the bundle directory and an output directory as its arguments, runs steps 2 to 5, writes `pk.bin`, `message.txt`, `sig.bin`, `ek.bin`, `dk.bin` and `ct.bin` into the output directory, and prints one line per result in this fixed form:

```
sha256 abc ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
drbg instantiated
ml-dsa-87 keygen ok
ml-dsa-87 verify ok
ml-dsa-87 verify-tampered rejected 22
ml-kem-1024 keygen ok
ml-kem-1024 decaps match
ml-kem-1024 decaps-tampered differs
ml-kem-1024 ss <64 hex>
```

Eight of the nine lines are fixed text; the ninth carries the fresh shared secret, which step 6 compares with `oxi`'s. A second invocation, `<program> <bundle-dir> decaps <dk-file> <ct-file>`, prints only `ml-kem-1024 ss <64 hex>`, for the reverse direction of step 6.

Each program exits 1 at the first result that differs from the expected line, printing both values, 1 printing the code if `oxi_init` or `oxi_drbg_instantiate` returns non-zero, and 0 only when every line was produced. `run.sh <bundle-dir> [out-dir]` keeps its first argument and exit contract; without a second argument it supplies a temporary output directory and removes it, with one it writes the six files there and leaves them, which is how the `crosscheck` mode reaches them; its stdout is the nine lines.

The fixed inputs, identical in all six programs and the six how-tos and stated once in `examples/README.md`: the message is the 43 ASCII bytes `The quick brown fox jumps over the lazy dog`; the signature byte flipped is byte 0, XOR `0x01`; the ciphertext byte flipped is byte 0, XOR `0x01`; the NIST known answer in step 6 is ML-DSA-87 ACVP key-generation vector tgId 3, tcId 51 (the seed the module's own self-test embeds), whose public key's SHA-256 is computed once by the build and recorded in `examples/README.md`. The CLI's known answers for the other four sets are the first test case of each set's test group in the NIST ACVP-Server sample files `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` and `ML-KEM-keyGen-FIPS203/internalProjection.json`, committed under `oxi/tests/data/` with tgId and tcId in the file names. No program takes a seed and no program reads operating-system entropy: every key and every encapsulation draws from a DRBG the module seeded, constructed exactly as the integration guide's randomness section shows. The example programs use only the module-sampled services; the one known answer from NIST in step 6 runs through `oxi`'s `--seed` form of `keygen`, which is key expansion from a stored seed.

`examples/README.md` carries the fixed inputs, the nine expected lines and the NIST public-key digest once, and the table of languages gains the two new rows.

### 5. The integration guide

`docs/integration.md`, one document, language-neutral, linked from every how-to's preamble and from the repository `README.md`. It is the home for every contract the how-tos rely on but do not state. Its sections:

1. **What the library is and is not** — the module, its boundary, the two profiles (`oxi_init(0)` unrestricted, `1` CNSA 2.0) and what each admits, what the library does not do (no TLS, no certificates, no key storage, no key encoding).
2. **Process lifetime** — initialise once per process; the power-up sequence and its cost; the error state, which refuses every service until the process restarts; thread safety of the exported functions, stated from the implementation and tested.
3. **Return codes** — every `OxiResult` value with its meaning and what the caller does; which calls distinguish "invalid" from "malformed" and which, by the standard's design, do not (ML-DSA verify, ML-KEM decapsulate).
4. **Randomness** — that the module seeds every DRBG itself and a program never supplies entropy (IG 9.3.A), with the two seed paths and what an unassessed environment means (`prd/drbg-seeding.md`); constructing a handle, the personalization string, the reseed interval and `ReseedRequired`; the first-use startup cost; the per-environment entropy claim and what running on an unassessed environment means; that key generation and encapsulation draw from the DRBG the program passes in and never take a seed; the stored-seed path (`keygen` with seed output, `expand_key`) and that a seed from anywhere else is an imported private key the program must protect as one; where the testing interfaces live and that the shipped library has none.
5. **Keys** — generation, the pairwise consistency test and what its failure means for the process, sizes, which services hold key material in an opaque handle for the handle's lifetime (the AES mode keys) and which return it to the caller and keep nothing (the post-quantum services); storage is the application's; zeroizing in languages with and without deterministic memory release, with the pattern per binding; no PEM, DER, SPKI or PKCS#8 encodings are provided, and what an application that needs them does.
6. **From a shared secret to traffic keys** — the 32-byte shared secret is a 256-bit key and may be used directly for symmetric cryptography (FIPS 203 §3.3); when more keys or bound context are needed, derive them with an approved KDF the library exposes (SP 800-108, SP 800-56C), then use an AEAD the library exposes and confirm the key with the peer; what SP 800-227 says about that step, cited.
7. **Signatures** — deterministic ML-DSA only through this ABI; the context string and when to use it; what a verifier must check beyond the signature.
8. **Shipping** — shared library versus static archive, and that a program linking the static archive carries the module and must be signed with the developer's own key; packaging per platform: runtime search path on Linux and macOS, the Visual C++ runtime dependency on Windows, the NDK library placement on Android; verifying the bundle's provenance in a build pipeline.
9. **Checking an integration** — the `oxi` cross-check from the how-tos, and the limits of that check.

Every statement in the guide is confirmed against the header, the implementation or a test before it is written, or marked as an open item with the probe that settles it. A statement about a standard cites the section.

### 6. The release check covers the grown examples

`scripts/release-archive-check.sh examples` requires each example's stdout to equal the eight fixed lines in `examples/README.md` with a ninth matching `ml-kem-1024 ss` followed by 64 hex characters; the workflow's `examples_required` lists all six languages on every leg that runs the examples (Linux x86_64 and aarch64, macOS aarch64 and x86_64, Windows x86_64), so a missing toolchain fails the release rather than skipping. A new `crosscheck` mode, run on every leg that packs both the library bundle and the CLI archive, runs each example into a temporary directory and then step 6 of its how-to against the extracted `oxi`: `verify` exits 0, `decaps` prints the program's secret, and the reverse direction agrees. The `cli` mode additionally runs an ML-DSA-87 sign and verify round trip and an ML-KEM-1024 encapsulate and decapsulate round trip with the extracted `oxi`, seedless, on every leg including Windows, and fails if `verify` exits non-zero or the two secrets differ.

## Numbers

Every size is fixed by FIPS 203 and FIPS 204 and is already the size the C header declares.

| Parameter set | Public or encapsulation key | Secret or decapsulation key | Signature or ciphertext | Seed inputs |
|---|---|---|---|---|
| ML-DSA-44 | 1312 | 2560 | 2420 | one 32-byte seed |
| ML-DSA-65 | 1952 | 4032 | 3309 | one 32-byte seed |
| ML-DSA-87 | 2592 | 4896 | 4627 | one 32-byte seed |
| ML-KEM-512 | 800 | 1632 | 768 | `d`, `z` 32 bytes each; `m` 32 bytes |
| ML-KEM-768 | 1184 | 2400 | 1088 | same |
| ML-KEM-1024 | 1568 | 3168 | 1568 | same |

- Shared secret: 32 bytes, FIPS 203.
- Context: at most 255 bytes, FIPS 204 §5.2.
- Message: read whole into memory, as `hash` does. No message size limit beyond memory; the how-to messages are under 100 bytes.
- An input file whose length is not exactly the size in the table is a usage error. The message names the expected size.
- Each seed is one 32-byte DRBG request, within HMAC_DRBG's 65536-byte per-request limit. FIPS 203 §3.3 requires `d` and `z` drawn from an approved RBG at the parameter set's security strength; the strength check of section 3 enforces it, and two requests keep the two values distinct outputs.
- The first DRBG instantiate in a process pays the entropy source's startup, specified and measured in `prd/drbg-seeding.md`; the examples and `oxi` pay it once per process.
- Power-up grows by four ML-KEM-1024 self-tests. The added time is measured before approval and recorded in the ISA; the existing bench harness compiles the same inventory file.
- Self-tests listed by `oxi selftest`: 89 today. The seeding change adds the `entropy source (1)` line, this arc adds `ml-kem (4)`, the AES arc adds seven to `aes`; each document states its delta and the release records the total (102 if all three ship together: 89 + 1 + 4 + 8).

## Exit codes

The existing codes keep their meanings for the existing commands. One code is added. The new commands use the codes as the table says; the existing `hash` and `hmac` commands' use of code 1 for an unreadable input is unchanged and out of scope.

| Code | Meaning for the new commands |
|---|---|
| 0 | Success. For `verify`, the signature is valid. For `decaps`, a secret was produced. |
| 1 | The module did not become operational (a power-up test ran and failed), or the module returned an error during the operation, or the module's entropy source was unavailable, or an output could not be written. Stderr says which. |
| 2 | Usage error: unknown family, verb or set; unknown, repeated, valueless or missing flag; a hex value of the wrong length or with a non-hex character; `--ctx` over 255 bytes; `--d` without `--z` or the reverse; an input file missing, unreadable or of the wrong length; an output file that already exists. Nothing is written. |
| 3 | The integrity test was not performed or could not decide. Unchanged. |
| 4 | `--integrity` only. Unchanged. |
| 5 | `ml-dsa verify` only: the module is operational, every input has its exact length, and the signature is not valid for this public key, message and context. FIPS 204 collapses a public key or signature of the right length but malformed content into the same verdict, so those exit 5 too; a wrong length is exit 2 before the module is called. |

## States and transitions

`oxi` is one process per command and the module's power-up state is one-shot per process. There is no daemon, no network, no clock and no persistent state beyond the files the caller names.

| From | Event | To | User sees |
|---|---|---|---|
| Not started | Command invoked | Power-up: integrity test, then every algorithm self-test in the inventory | Nothing yet |
| Power-up | All tests pass | Operational | Arguments are checked, then the command runs |
| Power-up | Integrity test fails | Error state, process exits | Existing integrity diagnosis on stderr, exit 1 or 3 |
| Power-up | An algorithm self-test fails | Error state, process exits | Existing self-test diagnosis on stderr, exit 1 |
| Operational | Usage error | Exit | One-line reason on stderr, exit 2, no output file created |
| Operational | Keygen's pairwise consistency test fails | Error state, process exits | `conditional self-test failed` on stderr, exit 1, no output file |
| Operational | Command completes | Exit | Output files in place, hex on stdout where specified, exit 0 or 5 |
| Operational | Interrupted (SIGINT) or killed while writing | Exit | No partial output at the named path: each output is written to a temporary file in the same directory, created exclusively (`O_EXCL`, or `CREATE_NEW` on Windows) with the final file's permission, and moved into place by `link(temp, target)` then `unlink(temp)` on Unix (a hard link fails with `EEXIST` if the target exists, so the move never replaces, and it needs no `renameat2`, whose wrapper postdates the release's glibc floor) and `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows; a filesystem that refuses hard links (`EPERM`, `EOPNOTSUPP`) falls back to `rename` after a second existence check, and the help text names that filesystem class as the one place the no-replace guarantee is best effort. A leftover temporary is the target's name with `.oxi-partial` appended, which the help text states, so the user knows what to delete |
| Any | Normal exit or handled error | None | Secret key, decapsulation key and shared secret buffers are zeroized on every path the program controls. A signal or an abort ends the process without running any code, as for any process; the operating system reclaims the memory |
| Restart | Next command | Not started | The whole power-up sequence runs again |

Offline: no network access on any path. Wrong clock: no path reads the wall clock; the entropy source reads a monotonic counter or clock for timing deltas only, never a date. User leaves: the process has no interactive state to abandon.

## Failure paths and the user-visible result

| Failure | Result |
|---|---|
| Module refuses to start | Existing diagnosis; no output file is created or truncated; exit 1 or 3 |
| Unknown family, verb or parameter set | `oxi ml-dsa: usage: ...` with the grammar above, exit 2 |
| Required flag missing; unknown, repeated or valueless flag | Names the flag, exit 2 |
| Hex flag of wrong length or invalid | Names the flag and the expected byte count, exit 2 |
| `--d` without `--z`, or the reverse | Says both are required together, exit 2 |
| `--ctx` over 255 bytes | Names the limit and FIPS 204 §5.2, exit 2 |
| Input file missing or unreadable | Operating-system error text with the path, exit 2 |
| Input file of the wrong length | `expected N bytes, got M` with the path, exit 2 |
| Output file already exists | Names the path and says `oxi` will not overwrite it, exit 2, nothing written |
| Output directory missing or unwritable, disk full, or a second output fails after the first is in place | Operating-system error text with the path, exit 1; the outputs already in place stay, the temporary for the failed one is removed, stderr names what was and was not written. Every output path is checked for existence before the first write, so a collision found at the second move is a race with another process, reported the same way. Outputs install in a fixed order (public key, then secret key; encapsulation key, then decapsulation key; ciphertext, then secret file). Two output flags naming the same path, or a path whose `.oxi-partial` sibling already exists, are usage errors (exit 2) found before any write |
| Stdout closed while printing the secret | Error on stderr, exit 1, no abort |
| Pairwise consistency test fails | `oxi <family> keygen: conditional self-test failed: <set> pairwise consistency; the module is in its error state`, exit 1, nothing written |
| Imported ML-KEM key fails the FIPS 203 §7.2 or §7.3 check (right length, wrong content) | `<path>: not a valid ML-KEM-<set> key` on stderr, exit 2 |
| The module's entropy source fails to start or fails a health test | `oxi: the module's entropy source is unavailable; restart the process` on stderr, exit 1, nothing written |
| ML-DSA signing's rejection sampling exceeds its bound of 1000 attempts | `oxi ml-dsa sign: the module reported InvalidInput` on stderr, exit 1. Probability below 2^-64 per signature by FIPS 204's analysis |
| Any other module error (`NotOperational`, `AlgorithmRestricted`) | `oxi <family> <verb>: the module reported <variant>` on stderr, exit 1, nothing written |
| Signature invalid, or public key or signature malformed | `ml-dsa verify: signature not valid` on stderr, exit 5 |
| Tampered ciphertext in `decaps` | No error. A different secret is produced, exit 0. The how-to shows this and says why |
| Example program: `oxi_init` non-zero | Prints the code and exits 1, as today |
| Example program: a result line differs from the known answer | Prints both values and exits 1 |

User data is never sent anywhere. On every error path, each output file is either complete or absent.

## Platform behaviour relied on

Each row names what the feature assumes and how the assumption was or will be confirmed before approval.

| Behaviour | Status |
|---|---|
| Go cgo, Node.js `koffi`, Java FFM, C# P/Invoke each load the library and call `oxi_init` and `oxi_sha256` | Confirmed: the existing four examples run in the release check. C and Python are confirmed as the README snippets the release check compiles and runs |
| Each of the six bindings passes a caller-allocated buffer of 4896 bytes in and receives 4627 bytes out, with no truncation | Open until probed. Probe: each example at step 4 produces a signature that `oxi ml-dsa verify 87` accepts, on Linux x86_64 before approval and on every leg that runs the cross-check at the first release |
| `koffi` declares `uintptr_t` lengths and `const uint8_t *` arrays by prototype string | Confirmed for `oxi_sha256`, whose lengths are `uintptr_t`; the new calls use the same two types |
| Java FFM from Java 22, .NET 10 SDK, Go 1.24, Node.js 22 | Confirmed by the existing examples' READMEs |
| The module seeds a DRBG on every release platform within the cost `prd/drbg-seeding.md` records | Open until that document's measurement lands. Probe here: the `cli` mode's seedless round trip on the five legs that build the CLI (Linux x86_64, Linux aarch64, macOS aarch64, macOS x86_64, Windows x86_64) and `scripts/android-device-check.sh` on the two Android libraries, which gains a keygen and encapsulation round trip |
| A no-replace move exists on each platform: `link` plus `unlink` on Unix, `MoveFileExW` without replace on Windows | Confirmed by platform documentation; probe: a test creates the target between the check and the move and expects exit 1 (an output failure, the earlier outputs retained) with the target's bytes unchanged |
| `oxicrypt_ml_kem::KATS` is a `&[KatEntry]` the power-up set can include unchanged | Confirmed by reading the crate |
| The exported functions are safe to call from several threads of one process | Open until the guide is written. Probe: a test calling two services concurrently after one `oxi_init`, and a read of the module's state handling |

## Out of scope

- Swift and Android examples, the AI-assistant quick start and `llms.txt`.
- Website pages rendered from the how-tos and the guide.
- Key encodings: no PEM, DER, SPKI or PKCS#8 output from `oxi` and none in the examples. The guide says what an application needing them does.
- Hedged ML-DSA signing, HashML-DSA and external-mu signing. FIPS 204 §3.4 makes hedging the default and permits deterministic signing, which is what ships; the guide states the trade-off (deterministic signing "should not be used on platforms where side-channel attacks are a concern and where they cannot be otherwise mitigated"). Hedged signing is its own feature, filed as an issue, and section 3 keeps every interface it will need additive.
- The derandomized internal functions of the other signature crates (SLH-DSA, Ed25519, ECDSA, LMS, XMSS), which FIPS 205 and the other standards restrict the same way; the same treatment is a follow-up.
- A seed-file form for the seed flags; a seed flag on any command other than `keygen`; a caller-supplied `m` for encapsulation anywhere.
- Changes to the existing `hash`, `hmac` and `selftest` behaviour beyond the entropy source and the added inventory group.
- New capability in the `oxicrypt` Rust binding crate beyond wrapping the symbols section 3 names.
- Any C ABI change beyond the symbols section 3 names. The CLI calls the Rust crates directly, as the existing commands do, and the examples call the C ABI as shipped with those symbols.

## Acceptance

The acceptance criteria, with their probes and thresholds, are written into `ISA.md` under this feature's identifier and approved with this document. They cover at least: a FIPS 203 and FIPS 204 known answer per parameter set through `oxi`, from the ACVP vectors available to the test suite; sign-verify round trips per set; a flipped-byte signature exiting 5; the pairwise consistency test firing on an injected fault in each of ML-DSA and ML-KEM keygen; an encapsulation key with one coefficient at or above q and a decapsulation key with a wrong stored hash each refused with `InvalidInput` by the module and exit 2 by the CLI; every example's eight fixed lines equal to `examples/README.md` and its ninth well-formed; `oxi` verifying each example's signature and decapsulating each example's ciphertext to the example's secret, and each example decapsulating `oxi`'s ciphertext to `oxi`'s secret; the derandomized internal forms absent from the shipped library's exports and compiled in Rust only under the testing feature; every RBG strength check refusing a too-weak DRBG, 192 bits for ML-DSA-44 included; `keygen_with_seed` and `expand_key` round-tripping to the same pair; the module seeding its DRBGs with no caller entropy anywhere in `oxi`, the examples or the shipped header; the Security Policy statements of section 3a present and checked; an interrupted write leaving no file at the target path; an existing output file never overwritten, including when created between the check and the rename; `oxi selftest` listing the ML-KEM group and its total four higher than before this change; the seedless `cli` round trip green on every release leg; every section of the integration guide backed by a cited header line, test or standard section; and the release check green with the grown examples on every platform it runs on.
