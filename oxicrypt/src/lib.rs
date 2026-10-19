//! The Rust interface to `liboxicrypt_ffi`, the oxicrypt cryptographic module
//! delivered as a separately built and signed shared library.
//!
//! This crate is outside the module's cryptographic boundary and is not the
//! module itself: the module is the `oxicrypt-*` crates, built into that
//! library and signed. This crate contains no cryptographic code and links no
//! module crate: it declares the C functions of `liboxicrypt_ffi`, links the
//! program to that library, and gives typed Rust over the C calling
//! convention. The module is the library the
//! operating system's loader binds to the program; the library runs its own
//! integrity test and self-tests when it is initialised, whatever program
//! loaded it, so a program using this crate is never signed.
//!
//! # Getting a library
//!
//! Either download a signed release library and pin the project's
//! verifying-key fingerprint, or build the library from source and sign it
//! with a key of your own (`docs/integrity-signing.md` in the repository
//! gives the procedure per platform):
//!
//! ```text
//! oxicrypt-integrity-sign --keygen <dir>                  # once, outside any source tree
//! OXICRYPT_INTEGRITY_VERIFY_KEY=<dir>/integrity-verify.pub cargo build --release -p oxicrypt-ffi
//! oxicrypt-integrity-sign --sign --key <dir>/integrity-signing.key <library>
//! oxicrypt-integrity-sign --verify <library>
//! oxicrypt-integrity-sign --show <library>                # prints the fingerprint
//! ```
//!
//! Project release libraries are signed with the release key
//! `keys/release-integrity-verify.pub` of the repository, whose fingerprint
//! is `sha256:ef4ff23cd2cdd5c9aa97576f928e874b149017485b3a0e74e45aee1155f248fe`.
//!
//! # Building a program
//!
//! The build script reads, at build time only:
//!
//! - `OXICRYPT_LIB_DIR`: the directory holding the signed shared library
//!   (`liboxicrypt_ffi.so`, `liboxicrypt_ffi.dylib`, or on Windows the import
//!   library `oxicrypt_ffi.dll.lib` (MSVC) or `liboxicrypt_ffi.dll.a` (GNU)).
//!   The static archive `liboxicrypt_ffi.a` / `oxicrypt_ffi.lib` is never
//!   linked, because it would compile the module into the program. On
//!   Linux, Android and Windows the shared library is linked by its exact
//!   file name, so an archive beside it cannot be chosen, and the variable
//!   may be left unset to link a library from the linker's default paths by
//!   that name. Apple's linker takes no exact file name, so on macOS and iOS
//!   the library is linked as `-loxicrypt_ffi`, the variable is required,
//!   and a directory that also holds the static archive is refused.
//! - `OXICRYPT_LIB_FINGERPRINT=sha256:<64 hex digits>`: the fingerprint of the
//!   verifying key the library embeds. [`Module::init`] refuses a library
//!   that reports another, with [`Error::KeyFingerprint`].
//! - `OXICRYPT_LIB_UNPINNED=1`: the explicit opt-out from the pin. The crate
//!   then has [`Module::init_unpinned`] and no [`Module::init`].
//!
//! A build that links the library requires exactly one of the fingerprint
//! and the opt-out. `OXICRYPT_LIB_OPTIONAL=1` with no `OXICRYPT_LIB_DIR`
//! builds the crate without linking the library, for running this crate's
//! own unit tests only.
//!
//! The pin catches an honestly built library signed with another key. It does
//! not resist a library that lies about its fingerprint, which no code outside
//! the boundary can.
//!
//! # Running a program
//!
//! The loader resolves `liboxicrypt_ffi` before `main` runs. The crate cannot
//! set a run-time search path for a dependent program; set it in the
//! program's own build (its `build.rs` or `.cargo/config.toml`):
//!
//! ```text
//! # ELF (Linux): RUNPATH, which the loader's environment can still override
//! -C link-arg=-Wl,--enable-new-dtags -C link-arg=-Wl,-rpath,<dir>
//! # macOS
//! -C link-arg=-Wl,-rpath,<dir>
//! ```
//!
//! or deploy the library where the loader looks: on Windows, the
//! application's directory. When the library is missing, the loader refuses
//! to start the program with its own message, before any Rust code runs: on
//! Linux `error while loading shared libraries: liboxicrypt_ffi.so.1: cannot
//! open shared object file`, naming the library's delivered name, exit status
//! 127; on macOS `dyld: Library not
//! loaded`; on Windows a dialog or exit status `0xC0000135`
//! (`STATUS_DLL_NOT_FOUND`).
//!
//! # Checking a program
//!
//! The program must hold no module code of its own:
//!
//! - `oxicrypt-integrity-sign --show <program>` reports no integrity slot in
//!   it, and finds the slot in the library;
//! - `cargo tree -i oxicrypt-module`, run on the program's own dependency
//!   graph, prints nothing. A dependency that pulls module crates in would
//!   put an unsigned copy of module code beside the signed library.
//!
//! # Using the module
//!
//! [`Module::init`] initialises the loaded library once and returns a
//! [`Module`] token; every service is a method on it.
//!
//! ```no_run
//! # #[cfg(any(oxicrypt_pinned, doc))]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use oxicrypt::{Module, Profile};
//!
//! let module = Module::init(Profile::Cnsa2)?;
//! let digest = module.sha384(b"abc")?;
//! assert_eq!(digest.len(), 48);
//! # Ok(())
//! # }
//! # #[cfg(not(any(oxicrypt_pinned, doc)))]
//! # fn main() {}
//! ```
//!
//! Key generation and encapsulation take caller-supplied seeds, as the C ABI
//! does; the crate generates no randomness. The approved status of a key
//! generated through this crate depends on where its seed came from: a seed
//! drawn from the module's DRBG with [`HmacDrbgSha256::seed`] comes from
//! inside the module, a seed passed to `from_bytes` from outside it. Each seed
//! role has its own type ([`MlDsa87KeySeed`], [`MlKem1024KeySeedD`],
//! [`MlKem1024KeySeedZ`], [`MlKem1024EncapsSeed`]), and each is consumed by
//! the call that uses it.
//! The DRBG itself is seeded by the caller through
//! [`HmacDrbgSha256::instantiate`] and [`HmacDrbgSha256::reseed`], so the
//! caller supplies entropy meeting SP 800-90A and SP 800-90B and documents
//! its source in their own security policy.
//!
//! Secrets the crate returns zero themselves when dropped (see [`HkdfPrk`],
//! [`Okm`], [`MlDsa87SecretKey`], [`MlKem1024DecapsulationKey`],
//! [`SharedSecret`] and the seed types); an output is exposed only when the library
//! returned status 0.
//!
//! # Compile-time guarantees
//!
//! Each seed is consumed by the call that uses it, so one encapsulation
//! seed cannot serve two encapsulations:
//!
//! ```compile_fail,E0382
//! fn twice(
//!     m: oxicrypt::Module,
//!     ek: &oxicrypt::MlKem1024EncapsulationKey,
//!     seed: oxicrypt::MlKem1024EncapsSeed,
//! ) {
//!     let _ = m.ml_kem_1024_encapsulate(ek, seed);
//!     let _ = m.ml_kem_1024_encapsulate(ek, seed);
//! }
//! ```
//!
//! and each role has its own type, so seeds cannot be swapped between roles:
//!
//! ```compile_fail,E0308
//! fn swapped(m: oxicrypt::Module, d: oxicrypt::MlKem1024KeySeedD, z: oxicrypt::MlKem1024KeySeedZ) {
//!     let _ = m.ml_kem_1024_keygen(z, d);
//! }
//! ```
//!
//! ```compile_fail,E0308
//! fn crossed(m: oxicrypt::Module, seed: oxicrypt::MlDsa87KeySeed, z: oxicrypt::MlKem1024KeySeedZ) {
//!     let _ = m.ml_kem_1024_keygen(seed, z);
//! }
//! ```
//!
//! The same calls, used as intended, compile:
//!
//! ```
//! fn once(
//!     m: oxicrypt::Module,
//!     d: oxicrypt::MlKem1024KeySeedD,
//!     z: oxicrypt::MlKem1024KeySeedZ,
//!     seed: oxicrypt::MlKem1024EncapsSeed,
//!     dsa: oxicrypt::MlDsa87KeySeed,
//! ) -> Result<(), oxicrypt::Error> {
//!     let (ek, _dk) = m.ml_kem_1024_keygen(d, z)?;
//!     let _ = m.ml_kem_1024_encapsulate(&ek, seed)?;
//!     let _ = m.ml_dsa_87_keygen(dsa)?;
//!     Ok(())
//! }
//! ```
//!
//! [`Error`], [`Profile`] and [`IntegrityStatus`] are `#[non_exhaustive]`, so
//! a later release can add a variant without breaking a caller; a `match`
//! outside this crate needs a wildcard arm:
//!
//! ```compile_fail,E0004
//! fn name(p: oxicrypt::Profile) -> i32 {
//!     match p {
//!         oxicrypt::Profile::Unrestricted => 0,
//!         oxicrypt::Profile::Cnsa2 => 1,
//!         oxicrypt::Profile::Cnsa1 => 2,
//!         oxicrypt::Profile::Migration => 3,
//!         oxicrypt::Profile::Unknown(n) => n,
//!     }
//! }
//! ```
//!
//! ```compile_fail,E0004
//! fn ok(s: oxicrypt::IntegrityStatus) -> bool {
//!     use oxicrypt::IntegrityStatus as S;
//!     match s {
//!         S::Passed => true,
//!         S::NotRun | S::SignatureInvalid | S::SlotInvalid | S::Unreadable | S::CastNotRun
//!         | S::UnknownRecord | S::Refused | S::NoVerifyKey | S::KeyMismatch | S::SlotDamaged
//!         | S::Unknown(_) => false,
//!     }
//! }
//! ```
//!
//! ```compile_fail,E0004
//! fn retry(e: &oxicrypt::Error) -> bool {
//!     use oxicrypt::Error as E;
//!     match e {
//!         E::ReseedRequired => true,
//!         E::NotOperational | E::SelfTestFailed | E::ConditionalTestFailed
//!         | E::AlreadyInitialized | E::InvalidInput | E::AlgorithmRestricted
//!         | E::NotImplemented | E::Uninstantiated | E::NullPointer | E::BufferTooSmall
//!         | E::OutputTooLong | E::NotBlockAligned | E::InvalidIvLength | E::TagMismatch
//!         | E::LengthMismatch | E::InvalidNonceLength | E::InvalidTagLength
//!         | E::InvalidPayloadLength | E::InvalidAadLength | E::IntegrityUnverified
//!         | E::Internal | E::SignatureInvalid | E::Unknown(_) | E::LibraryVersion { .. }
//!         | E::ProfileMismatch { .. } | E::KeyFingerprint { .. } => false,
//!     }
//! }
//! ```
//!
//! ```
//! fn name(p: oxicrypt::Profile) -> i32 {
//!     match p {
//!         oxicrypt::Profile::Cnsa2 => 1,
//!         other => other.code(),
//!     }
//! }
//! ```
//!
//! # Wrapped C functions
//!
//! The safe layer of this release calls exactly these functions of the C ABI;
//! the others are declared and reached by nothing.
//!
//! <!-- wrapped:begin -->
//! - `lama_manifest`
//! - `oxi_init`
//! - `oxi_active_profile`
//! - `oxi_is_operational`
//! - `oxi_integrity_status`
//! - `oxi_integrity_status_detail`
//! - `oxi_integrity_key_fingerprint`
//! - `oxi_sha384`
//! - `oxi_hkdf_sha384_extract`
//! - `oxi_hkdf_sha384_expand`
//! - `oxi_aes256_new`
//! - `oxi_aes256_free`
//! - `oxi_aes256_gcm_encrypt`
//! - `oxi_aes256_gcm_decrypt`
//! - `oxi_hmac_drbg_sha256_new`
//! - `oxi_hmac_drbg_sha256_free`
//! - `oxi_hmac_drbg_sha256_instantiate`
//! - `oxi_hmac_drbg_sha256_reseed`
//! - `oxi_hmac_drbg_sha256_generate`
//! - `oxi_ml_dsa_87_keygen`
//! - `oxi_ml_dsa_87_sign`
//! - `oxi_ml_dsa_87_verify`
//! - `oxi_ml_kem_1024_keygen`
//! - `oxi_ml_kem_1024_encapsulate`
//! - `oxi_ml_kem_1024_decapsulate`
//! <!-- wrapped:end -->
//!
//! # Versions
//!
//! The C interface has an ABI number, independent of the release version,
//! that changes only when the interface breaks compatibility. This crate was
//! built against [`OXI_ABI_VERSION`]; [`Module::init`] calls the library's
//! `oxi_abi_version` before initialising it and refuses any other number with
//! [`Error::LibraryAbi`]. Within one ABI number, compatibility runs one way:
//! a library of a later release serves this crate, while an older release
//! of the same number may lack a function this crate calls, and the program
//! then fails at load (immediate binding) rather than through the number.
//! The function is looked up at run time, not linked, and only in the image
//! the library was loaded from: a library that predates it still loads, and
//! is then held to the exact-version rule, its API manifest's version equal
//! to this crate's, else [`Error::LibraryVersion`].
//!
//! | crate built against | accepts |
//! |---|---|
//! | ABI 1 | a library reporting ABI 1 that exports every function the crate calls; a library without `oxi_abi_version` only at the crate's own release version |
//!
//! On Linux the library's `SONAME` is `liboxicrypt_ffi.so.<ABI>` and on macOS
//! its install name is `@rpath/liboxicrypt_ffi.<ABI>.dylib`: the loader asks
//! for that file, so deploy the library under that name, with the plain name
//! (`liboxicrypt_ffi.so`, `liboxicrypt_ffi.dylib`) as a link to it for the
//! linker, which `OXICRYPT_LIB_DIR` must hold. On Android the `SONAME` is the
//! plain `liboxicrypt_ffi.so`, the only form an application packages.

mod error;
mod module;
mod ops;
mod platform;
mod secret;
mod sys;

#[cfg(test)]
mod tests;

pub use error::{DetailError, Error, InitError, Site};
pub use module::{Fingerprint, IntegrityStatus, Module, Profile};
pub use ops::{Aes256Key, HmacDrbgSha256};
pub use secret::{
    DrbgSeed, HkdfPrk, MlDsa87KeySeed, MlDsa87SecretKey, MlKem1024DecapsulationKey,
    MlKem1024EncapsSeed, MlKem1024KeySeedD, MlKem1024KeySeedZ, Okm, SharedSecret,
};

/// The ABI number of the C interface this crate was built against.
pub const OXI_ABI_VERSION: i32 = 1;

/// SHA-384 digest length.
pub const SHA384_LEN: usize = 48;
/// HKDF-SHA384 pseudorandom key length.
pub const HKDF_SHA384_PRK_LEN: usize = 48;
/// The longest HKDF-SHA384 output, 255 × 48 bytes (RFC 5869 §2.3).
pub const HKDF_SHA384_MAX_OKM_LEN: usize = 12_240;
/// AES-256 key length.
pub const AES256_KEY_LEN: usize = 32;
/// AES-256-GCM nonce length.
pub const AES256_GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM tag length.
pub const AES256_GCM_TAG_LEN: usize = 16;
/// The most entropy, nonce and personalization bytes HMAC_DRBG-SHA-256
/// accepts in one call, combined.
pub const HMAC_DRBG_MAX_PROVIDED_LEN: usize = 768;
/// The most bytes one HMAC_DRBG-SHA-256 generate call returns
/// (SP 800-90A Table 3).
pub const HMAC_DRBG_MAX_REQUEST_LEN: usize = 65_536;
/// ML-DSA-87 key-generation seed length.
pub const ML_DSA_87_SEED_LEN: usize = 32;
/// ML-DSA-87 public key length.
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2_592;
/// ML-DSA-87 secret key length.
pub const ML_DSA_87_SECRET_KEY_LEN: usize = 4_896;
/// ML-DSA-87 signature length.
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4_627;
/// The longest ML-DSA-87 context string (FIPS 204 §5.2).
pub const ML_DSA_87_MAX_CONTEXT_LEN: usize = 255;
/// ML-KEM-1024 seed length, for each of `d`, `z` and `m`.
pub const ML_KEM_1024_SEED_LEN: usize = 32;
/// ML-KEM-1024 encapsulation key length.
pub const ML_KEM_1024_ENCAPSULATION_KEY_LEN: usize = 1_568;
/// ML-KEM-1024 decapsulation key length.
pub const ML_KEM_1024_DECAPSULATION_KEY_LEN: usize = 3_168;
/// ML-KEM-1024 ciphertext length.
pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1_568;
/// ML-KEM-1024 shared secret length.
pub const ML_KEM_1024_SHARED_SECRET_LEN: usize = 32;

/// An ML-DSA-87 public key.
pub type MlDsa87PublicKey = [u8; ML_DSA_87_PUBLIC_KEY_LEN];
/// An ML-DSA-87 signature.
pub type MlDsa87Signature = [u8; ML_DSA_87_SIGNATURE_LEN];
/// An ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey = [u8; ML_KEM_1024_ENCAPSULATION_KEY_LEN];
/// An ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext = [u8; ML_KEM_1024_CIPHERTEXT_LEN];
