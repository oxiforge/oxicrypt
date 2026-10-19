//! C ABI error codes and mapping from per-crate Error types.
//!
//! Each Rust error variant maps to a distinct `OxiResult` discriminant.
//! `OxiResult::Internal = 255` is reserved for "should-never-happen"
//! cases. The mapping is exhaustive, so two failure modes never share a
//! code.
//!
//! Discriminants are banded by source crate so reviewers can locate
//! the originating failure mode at a glance:
//!
//! - 0:           Success
//! - 1-7:         `oxicrypt_module::Error` variants
//! - 8-9:         `oxicrypt_drbg::DrbgError` variants
//! - 10-12:       FFI-layer errors (null pointer, buffer too small, output too long)
//! - 20-27:       `oxicrypt_aes::ModeError` variants
//! - 28-30:       appended after the bands above: `IntegrityUnverified`
//!   (`oxicrypt_module::Error`), then the DRBG minimum-length refusals
//!   `EntropyInputTooShort` and `NonceTooShort`
//! - 255:         Catch-all `Internal` (reserved)
//!
//! Future per-crate error types (sha, hmac, ecdsa, etc.) extend
//! this banded space as their FFI wrappers land in subsequent chunks.

use core::ffi::c_int;

/// C ABI status code returned by every `oxi_*` function that returns an `int`
/// status: `Ok = 0` is success, and non-zero values are distinct failure
/// modes.
///
/// Four functions return a value of their own instead, never an `OxiResult`:
/// `oxi_abi_version` (the ABI number), `oxi_active_profile` (a profile code),
/// `oxi_is_operational` (1 or 0) and `oxi_integrity_status` (the integrity
/// indicator). `lama_manifest` returns a string, and the `_free` functions
/// return nothing.
/// Layout is fixed (`#[repr(C)]`) so the C-side typedef has stable
/// discriminants across cbindgen regenerations.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OxiResult {
    /// Operation succeeded.
    Ok = 0,

    // Module-level errors (oxicrypt_module::Error)
    /// Module not in `Operational` state — call `oxi_init` first.
    NotOperational = 1,
    /// Power-up self-test failed during init. Module is in terminal `Error` state.
    SelfTestFailed = 2,
    /// Conditional self-test failed during operation (e.g. DRBG CRNGT, pairwise consistency).
    ConditionalTestFailed = 3,
    /// `oxi_init` called more than once. The first init's outcome is authoritative.
    AlreadyInitialized = 4,
    /// Cryptographic input was not a valid domain element (invalid scalar, point not on curve, etc.).
    InvalidInput = 5,
    /// Service blocked by the active algorithm profile. Requires process restart with different profile.
    AlgorithmRestricted = 6,
    /// Service exists in the `Service` enum but its implementation is not yet built (stub crate).
    NotImplemented = 7,

    // DRBG errors (oxicrypt_drbg::DrbgError) — state-machine preconditions
    // distinct from `InvalidInput = 5` (input bounds) so callers can
    // structure error-handling correctly: Uninstantiated triggers an
    // `instantiate` call; ReseedRequired triggers a `reseed` call.
    /// `generate` (or `reseed`) called before `instantiate` succeeded on this DRBG handle.
    Uninstantiated = 8,
    /// `reseed_counter` reached the SP 800-90A Table 3 reseed-interval bound; caller MUST
    /// call `reseed` with fresh entropy before `generate` will return more output.
    ReseedRequired = 9,

    // FFI-layer errors
    /// Caller passed a NULL pointer where one is required.
    NullPointer = 10,
    /// Caller-allocated output buffer is smaller than the documented minimum.
    BufferTooSmall = 11,
    /// Output bound exceeded. Reused across families: HKDF-Expand requested more than
    /// `255 * HashLen` bytes (RFC 5869 §2.3); HMAC_DRBG `generate` requested more than
    /// `2^19` bits (SP 800-90A Table 3 `max_number_of_bits_per_request`). Same
    /// cross-family-discriminant-reuse pattern as `TagMismatch = 22`: one code, multiple
    /// upstream sources, all sharing the same caller-recovery semantic ("ask for less").
    OutputTooLong = 12,

    // AES-mode errors (oxicrypt_aes::ModeError)
    /// Input length is not aligned to the cipher block size (where required).
    NotBlockAligned = 20,
    /// IV length doesn't match the mode's specification (e.g. GCM requires exactly 12 bytes).
    InvalidIvLength = 21,
    /// Cryptographic verification mismatched.
    ///
    /// Covers BOTH AEAD tag verification (AES-GCM, AES-CCM, AES-KW, AES-KWP)
    /// AND signature verification (ECDSA `Ok(false)` from FIPS 186-5 §6.4.2,
    /// and future RSA-PSS / EdDSA / ML-DSA / SLH-DSA / LMS / XMSS verify
    /// fns). The semantic is uniform: "the cryptographic verification
    /// primitive ran cleanly but the result disagrees with the claimed
    /// value." Distinct from [`OxiResult::InvalidInput`] (= 5), which
    /// signals input that failed to decode BEFORE any cryptographic
    /// comparison. AEAD plaintext output buffer contents are UNDEFINED
    /// when this code is returned.
    TagMismatch = 22,
    /// Input/output buffer length pair is mismatched (e.g. plaintext.len() != ciphertext.len()).
    LengthMismatch = 23,
    /// Nonce length doesn't match the mode's specification.
    InvalidNonceLength = 24,
    /// Tag length doesn't match the mode's specification.
    InvalidTagLength = 25,
    /// Payload length exceeds the mode's allowed maximum.
    InvalidPayloadLength = 26,
    /// AAD length exceeds the mode's allowed maximum.
    InvalidAadLength = 27,
    /// The module was initialised without the pre-operational software
    /// integrity test, so it was never verified against its integrity
    /// signature. Distinct from `SelfTestFailed`: no test failed, none ran.
    IntegrityUnverified = 28,
    /// A DRBG `_instantiate` or `_reseed` was given an entropy input shorter
    /// than the minimum for the instantiated security strength (SP 800-90A
    /// Rev. 1 Tables 2 and 3). Distinct from `InvalidInput = 5`, which an
    /// over-long input returns, as does CTR_DRBG `_no_df` seed material
    /// that is not exactly `seedlen` bytes.
    EntropyInputTooShort = 29,
    /// A DRBG `_instantiate` was given a nonce shorter than half the
    /// instantiated security strength, the module's nonce floor
    /// (permitted by SP 800-90A Rev. 1 §9.1 step 8; a shorter nonce that
    /// would meet only the uniqueness condition of §8.6.7 is refused).
    NonceTooShort = 30,

    /// Catch-all for "should-never-happen" cases. New error sources should
    /// be paired with new `OxiResult` variants in the same change set —
    /// reaching `Internal` is a flag for reviewer attention.
    Internal = 255,
}

impl From<oxicrypt_module::Error> for OxiResult {
    fn from(e: oxicrypt_module::Error) -> Self {
        match e {
            // A second initialisation of a module whose first one failed
            // reports what a C caller already received for it: the module
            // is not operational.
            oxicrypt_module::Error::NotOperational { .. }
            | oxicrypt_module::Error::AlreadyFailed => OxiResult::NotOperational,
            oxicrypt_module::Error::SelfTestFailed { .. } => OxiResult::SelfTestFailed,
            oxicrypt_module::Error::ConditionalTestFailed { .. } => {
                OxiResult::ConditionalTestFailed
            }
            oxicrypt_module::Error::AlreadyInitialized => OxiResult::AlreadyInitialized,
            oxicrypt_module::Error::InvalidInput => OxiResult::InvalidInput,
            oxicrypt_module::Error::AlgorithmRestricted { .. } => OxiResult::AlgorithmRestricted,
            oxicrypt_module::Error::NotImplemented => OxiResult::NotImplemented,
            oxicrypt_module::Error::IntegrityNotAttested => OxiResult::IntegrityUnverified,
            oxicrypt_module::Error::EntropyInputTooShort => OxiResult::EntropyInputTooShort,
            oxicrypt_module::Error::NonceTooShort => OxiResult::NonceTooShort,
            // `oxicrypt_module::Error` is non-exhaustive, so a variant it
            // adds later reaches this arm and reports `Internal` until it is
            // mapped above. No test here can see such a variant; the test
            // `module_error_maps_to_distinct_oxi_results` checks only the eleven
            // variants it names.
            _ => OxiResult::Internal,
        }
    }
}

impl From<oxicrypt_aes::ModeError> for OxiResult {
    fn from(e: oxicrypt_aes::ModeError) -> Self {
        match e {
            oxicrypt_aes::ModeError::NotBlockAligned => OxiResult::NotBlockAligned,
            oxicrypt_aes::ModeError::InvalidIvLength => OxiResult::InvalidIvLength,
            oxicrypt_aes::ModeError::TagMismatch => OxiResult::TagMismatch,
            oxicrypt_aes::ModeError::LengthMismatch => OxiResult::LengthMismatch,
            oxicrypt_aes::ModeError::InvalidNonceLength => OxiResult::InvalidNonceLength,
            oxicrypt_aes::ModeError::InvalidTagLength => OxiResult::InvalidTagLength,
            oxicrypt_aes::ModeError::InvalidPayloadLength => OxiResult::InvalidPayloadLength,
            oxicrypt_aes::ModeError::InvalidAadLength => OxiResult::InvalidAadLength,
            oxicrypt_aes::ModeError::Module(e) => OxiResult::from(e),
        }
    }
}

/// Convert a `Result<(), oxicrypt_module::Error>` into the C `int` status code.
pub(crate) fn status_module(r: Result<(), oxicrypt_module::Error>) -> c_int {
    match r {
        Ok(()) => OxiResult::Ok as c_int,
        Err(e) => OxiResult::from(e) as c_int,
    }
}

/// Convert a `Result<(), oxicrypt_aes::ModeError>` into the C `int` status code.
pub(crate) fn status_aes(r: Result<(), oxicrypt_aes::ModeError>) -> c_int {
    match r {
        Ok(()) => OxiResult::Ok as c_int,
        Err(e) => OxiResult::from(e) as c_int,
    }
}

impl From<oxicrypt_kdf::KdfError> for OxiResult {
    fn from(e: oxicrypt_kdf::KdfError) -> Self {
        match e {
            oxicrypt_kdf::KdfError::Module(m) => OxiResult::from(m),
            oxicrypt_kdf::KdfError::OutputTooLong => OxiResult::OutputTooLong,
        }
    }
}

/// Convert a `Result<(), oxicrypt_kdf::KdfError>` into the C `int` status code.
pub(crate) fn status_kdf(r: Result<(), oxicrypt_kdf::KdfError>) -> c_int {
    match r {
        Ok(()) => OxiResult::Ok as c_int,
        Err(e) => OxiResult::from(e) as c_int,
    }
}

impl From<oxicrypt_drbg::DrbgError> for OxiResult {
    fn from(e: oxicrypt_drbg::DrbgError) -> Self {
        match e {
            oxicrypt_drbg::DrbgError::Uninstantiated => OxiResult::Uninstantiated,
            oxicrypt_drbg::DrbgError::ReseedRequired => OxiResult::ReseedRequired,
            // SP 800-90A Table 3 max_personalization_string / max_additional_input
            // are length bounds; collapse to InvalidInput=5 (input-bounds family)
            // alongside `oxicrypt_module::Error::InvalidInput` rather than a
            // dedicated discriminant — there is nothing the caller can do
            // structurally different between the two. `InvalidSeedLength` is
            // a CTR_DRBG-specific seed-length mismatch (not exercised by HMAC
            // DRBG) but maps to the same family for the same reason.
            oxicrypt_drbg::DrbgError::InputTooLong
            | oxicrypt_drbg::DrbgError::InvalidSeedLength => OxiResult::InvalidInput,
            // SP 800-90A Table 3 max_number_of_bits_per_request — output bound,
            // semantically identical to KDF's HKDF-Expand 255*HashLen ceiling.
            oxicrypt_drbg::DrbgError::RequestTooLong => OxiResult::OutputTooLong,
            // The reseed form of the instantiate refusal reports the same code.
            oxicrypt_drbg::DrbgError::EntropyInputTooShort => OxiResult::EntropyInputTooShort,
            oxicrypt_drbg::DrbgError::Module(m) => OxiResult::from(m),
        }
    }
}

/// Convert a `Result<(), oxicrypt_drbg::DrbgError>` into the C `int` status code.
#[allow(dead_code)] // call sites land in drbg.rs alongside this impl
pub(crate) fn status_drbg(r: Result<(), oxicrypt_drbg::DrbgError>) -> c_int {
    match r {
        Ok(()) => OxiResult::Ok as c_int,
        Err(e) => OxiResult::from(e) as c_int,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_error_maps_to_distinct_oxi_results() {
        // Each of the eleven oxicrypt_module::Error variants that exist today
        // maps to its own OxiResult, never to the `Internal` catch-all.
        // AlreadyFailed deliberately shares NotOperational. The list is
        // kept by hand: a variant the module adds later is not caught here.
        let mappings = [
            (
                OxiResult::from(oxicrypt_module::Error::NotOperational {
                    current: oxicrypt_module::State::PowerOff,
                }),
                OxiResult::NotOperational,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::SelfTestFailed { test: "test_kat" }),
                OxiResult::SelfTestFailed,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::ConditionalTestFailed {
                    reason: "drbg_crngt",
                }),
                OxiResult::ConditionalTestFailed,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::AlreadyInitialized),
                OxiResult::AlreadyInitialized,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::AlreadyFailed),
                OxiResult::NotOperational,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::InvalidInput),
                OxiResult::InvalidInput,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::NotImplemented),
                OxiResult::NotImplemented,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::AlgorithmRestricted {
                    service: oxicrypt_module::Service::Sha256,
                }),
                OxiResult::AlgorithmRestricted,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::IntegrityNotAttested),
                OxiResult::IntegrityUnverified,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::EntropyInputTooShort),
                OxiResult::EntropyInputTooShort,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::NonceTooShort),
                OxiResult::NonceTooShort,
            ),
        ];
        assert_eq!(mappings.len(), 11, "one case per variant named above");
        for (got, expected) in mappings {
            assert_ne!(got, OxiResult::Internal);
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn drbg_entropy_too_short_maps_apart_from_too_long() {
        assert_eq!(
            OxiResult::from(oxicrypt_drbg::DrbgError::EntropyInputTooShort),
            OxiResult::EntropyInputTooShort
        );
        assert_eq!(
            OxiResult::from(oxicrypt_drbg::DrbgError::InputTooLong),
            OxiResult::InvalidInput
        );
        assert_eq!(OxiResult::EntropyInputTooShort as i32, 29);
        assert_eq!(OxiResult::NonceTooShort as i32, 30);
    }

    #[test]
    fn aes_mode_error_maps_to_distinct_oxi_results() {
        let mappings = [
            (
                OxiResult::from(oxicrypt_aes::ModeError::TagMismatch),
                OxiResult::TagMismatch,
            ),
            (
                OxiResult::from(oxicrypt_aes::ModeError::InvalidIvLength),
                OxiResult::InvalidIvLength,
            ),
            (
                OxiResult::from(oxicrypt_aes::ModeError::LengthMismatch),
                OxiResult::LengthMismatch,
            ),
        ];
        for (got, expected) in mappings {
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn status_helpers_convert_results() {
        let module_ok: Result<(), oxicrypt_module::Error> = Ok(());
        assert_eq!(status_module(module_ok), 0);
        let aes_ok: Result<(), oxicrypt_aes::ModeError> = Ok(());
        assert_eq!(status_aes(aes_ok), 0);
        let module_err: Result<(), oxicrypt_module::Error> =
            Err(oxicrypt_module::Error::InvalidInput);
        assert_eq!(status_module(module_err), OxiResult::InvalidInput as i32);
        let aes_err: Result<(), oxicrypt_aes::ModeError> =
            Err(oxicrypt_aes::ModeError::TagMismatch);
        assert_eq!(status_aes(aes_err), OxiResult::TagMismatch as i32);
    }

    #[test]
    fn kdf_error_maps_to_distinct_oxi_results() {
        // KdfError::OutputTooLong has its own discriminant; the
        // Module(_) wrapper passes through to the inner Error mapping.
        assert_eq!(
            OxiResult::from(oxicrypt_kdf::KdfError::OutputTooLong),
            OxiResult::OutputTooLong
        );
        assert_eq!(
            OxiResult::from(oxicrypt_kdf::KdfError::Module(
                oxicrypt_module::Error::InvalidInput
            )),
            OxiResult::InvalidInput
        );
        let kdf_ok: Result<(), oxicrypt_kdf::KdfError> = Ok(());
        assert_eq!(status_kdf(kdf_ok), 0);
        let kdf_err: Result<(), oxicrypt_kdf::KdfError> =
            Err(oxicrypt_kdf::KdfError::OutputTooLong);
        assert_eq!(status_kdf(kdf_err), OxiResult::OutputTooLong as i32);
    }
}
