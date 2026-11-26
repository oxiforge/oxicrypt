//! C ABI error codes and mapping from per-crate Error types.
//!
//! Each Rust error variant maps to an `OxiResult` discriminant.
//! `OxiResult::Internal = 255` is reserved for "should-never-happen"
//! cases.
//!
//! Discriminants are banded by source crate so reviewers can locate
//! the originating failure mode at a glance:
//!
//! - 0:           Success
//! - 1-7:         `oxicrypt_module::Error` variants
//! - 8-9:         `oxicrypt_drbg::DrbgError` variants
//! - 10-12:       FFI-layer errors (null pointer, buffer too small, output too long)
//! - 20-27:       `oxicrypt_aes::ModeError` variants
//! - 28-30:       `IntegrityUnverified`
//!   (`oxicrypt_module::Error`), then the DRBG minimum-length refusals
//!   `EntropyInputTooShort` and `NonceTooShort`
//! - 31-33:       random bit generator refusals: `RbgTooWeak`
//!   (`oxicrypt_module::Error::RbgTooWeak`), then `Busy` and
//!   `EntropyUnavailable` (`oxicrypt_module::RbgError` variants; `Busy` is
//!   also returned by a DRBG handle another thread is using)
//! - 34:          `KeyExhausted` (`oxicrypt_module::Error`), a key past its
//!   invocation limit
//! - 255:         Catch-all `Internal` (reserved)
//!
//! Four codes are mapped but returned by no exported function at ABI 3:
//! `ReseedRequired = 9`, `EntropyInputTooShort = 29`, `NonceTooShort = 30`
//! and `RbgTooWeak = 31`.
//!
//! `RbgTooWeak` is unreachable because the one service that checks the
//! strength of an `OxiDrbg`, `oxi_aes_gcm_seal`, requires 96 bits and every
//! `OxiDrbg` is instantiated at 128 bits or more, and the one typed DRBG
//! handle the services take, HMAC_DRBG-SHA-256, is instantiated at 256
//! bits, above every service's strength requirement.
//!
//! The other three are unreachable because the C interface takes no
//! entropy input or nonce. Every C DRBG instantiate and reseed function
//! draws from the module's seed path, which supplies a full-length
//! entropy input and nonce, and a module-seeded DRBG reseeds itself at
//! its reseed interval. The forms that return these codes take a
//! caller-supplied entropy input and nonce: the `oxicrypt_drbg` testing
//! interface used by the CAVP tests (its `testing-interfaces` feature),
//! which this crate does not call.

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

    // DRBG errors (oxicrypt_drbg::DrbgError): state preconditions, kept
    // apart from `InvalidInput = 5` because the caller recovers
    // differently (`Uninstantiated` calls for an `instantiate`).
    /// `generate` (or `reseed`) called before `instantiate` succeeded on this DRBG handle.
    Uninstantiated = 8,
    /// The DRBG's reseed counter passed the SP 800-90A Table 3 reseed
    /// interval and the DRBG cannot reseed itself. No exported function
    /// returns it at ABI 3: every C DRBG handle is seeded by the module and
    /// reseeds itself at the interval. It is returned by `generate` on an
    /// `oxicrypt_drbg` instance instantiated through the testing interface
    /// with a caller-supplied entropy input, which does not reseed itself at
    /// the interval.
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
    /// and the other `_verify` functions). The semantic is uniform: "the
    /// cryptographic verification primitive ran cleanly but the result
    /// disagrees with the claimed value." Distinct from
    /// [`OxiResult::InvalidInput`] (= 5), which signals input that failed
    /// to decode BEFORE any cryptographic comparison. The AES mode
    /// symbols write no output when they return this code.
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
    /// A DRBG instantiate or reseed was given an entropy input shorter than
    /// the minimum for the instantiated security strength (SP 800-90A Rev. 1
    /// Tables 2 and 3). No exported function returns it at ABI 3: the C
    /// interface takes no entropy input, and the module's seed path supplies
    /// a full-length one. It is returned by the `oxicrypt_drbg` testing
    /// interface's caller-entropy forms: HMAC_DRBG and Hash_DRBG
    /// `instantiate` and `reseed`, and CTR_DRBG `instantiate_df` and
    /// `reseed_df`. Distinct from `InvalidInput = 5`, which an over-long
    /// input returns, as does CTR_DRBG `instantiate_no_df` or `reseed_no_df`
    /// seed material that is not exactly `seedlen` bytes.
    EntropyInputTooShort = 29,
    /// A DRBG instantiate was given a nonce shorter than half the
    /// instantiated security strength, the module's nonce floor
    /// (permitted by SP 800-90A Rev. 1 §9.1 step 8; a shorter nonce that
    /// would meet only the uniqueness condition of §8.6.7 is refused). No
    /// exported function returns it at ABI 3: the C interface takes no
    /// nonce, and the module's seed path supplies a full-length one. It is
    /// returned by the `oxicrypt_drbg` testing interface's caller-nonce
    /// forms: HMAC_DRBG and Hash_DRBG `instantiate`, and CTR_DRBG
    /// `instantiate_df`.
    NonceTooShort = 30,
    /// The random bit generator handed to a service has a security strength
    /// below what that service requires. Pass a DRBG of a higher strength.
    RbgTooWeak = 31,
    /// The DRBG handle is in use by another call, or the module's seed path
    /// was held by another thread for longer than its wait bound. Nothing
    /// was changed; retry after a pause.
    Busy = 32,
    /// The entropy source failed while seeding or testing. The module has
    /// entered its error state, and every later service returns
    /// `NotOperational = 1` until the process restarts.
    EntropyUnavailable = 33,
    /// The key has reached the number of invocations its mode permits under
    /// one key (2^32 AES-GCM encryptions, SP 800-38D §8.3; 2^61 AES-CCM
    /// block-cipher invocations, SP 800-38C §5.1). Nothing was written and
    /// no IV was generated; the key stays exhausted, so establish a new key.
    KeyExhausted = 34,

    /// Catch-all for "should-never-happen" cases, including an error variant
    /// this mapping does not name.
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
            oxicrypt_module::Error::Rbg(rbg) => match rbg {
                oxicrypt_module::RbgError::Uninstantiated => OxiResult::Uninstantiated,
                oxicrypt_module::RbgError::ReseedRequired => OxiResult::ReseedRequired,
                oxicrypt_module::RbgError::RequestTooLong => OxiResult::OutputTooLong,
                oxicrypt_module::RbgError::EntropyUnavailable => OxiResult::EntropyUnavailable,
                oxicrypt_module::RbgError::NotOperational => OxiResult::NotOperational,
                oxicrypt_module::RbgError::Busy => OxiResult::Busy,
            },
            oxicrypt_module::Error::RbgTooWeak => OxiResult::RbgTooWeak,
            oxicrypt_module::Error::KeyExhausted => OxiResult::KeyExhausted,
            // `oxicrypt_module::Error` is non-exhaustive, so a variant it
            // adds later reaches this arm and reports `Internal` until it is
            // mapped above.
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
            oxicrypt_aes::ModeError::Rbg(e) => OxiResult::from(oxicrypt_module::Error::Rbg(e)),
            oxicrypt_aes::ModeError::RbgTooWeak => OxiResult::RbgTooWeak,
            oxicrypt_aes::ModeError::Module(e) => OxiResult::from(e),
            // `oxicrypt_aes::ModeError` is non-exhaustive, so a variant it
            // adds later reaches this arm and reports `Internal` until it is
            // mapped above.
            _ => OxiResult::Internal,
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
            // The SP 800-90A Table 3 bounds on the personalization string
            // and additional input, and CTR_DRBG's seed-length mismatch,
            // share `InvalidInput = 5` with the module's own input refusal
            // because the caller's recovery is the same.
            oxicrypt_drbg::DrbgError::InputTooLong
            | oxicrypt_drbg::DrbgError::InvalidSeedLength => OxiResult::InvalidInput,
            // SP 800-90A Table 3 max_number_of_bits_per_request — output bound,
            // semantically identical to KDF's HKDF-Expand 255*HashLen ceiling.
            oxicrypt_drbg::DrbgError::RequestTooLong => OxiResult::OutputTooLong,
            oxicrypt_drbg::DrbgError::EntropyInputTooShort => OxiResult::EntropyInputTooShort,
            oxicrypt_drbg::DrbgError::Module(m) => OxiResult::from(m),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_error_maps_to_distinct_oxi_results() {
        // `AlreadyFailed` shares `NotOperational` by design. The list is
        // kept by hand, so a variant the module adds is not caught here.
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
            (
                OxiResult::from(oxicrypt_module::Error::KeyExhausted),
                OxiResult::KeyExhausted,
            ),
        ];
        assert_eq!(mappings.len(), 12, "one case per variant named above");
        for (got, expected) in mappings {
            assert_ne!(got, OxiResult::Internal);
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn rbg_error_codes_map() {
        use oxicrypt_module::{Error, RbgError};
        let mappings = [
            (Error::Rbg(RbgError::Uninstantiated), 8),
            (Error::Rbg(RbgError::ReseedRequired), 9),
            (Error::Rbg(RbgError::RequestTooLong), 12),
            (Error::Rbg(RbgError::EntropyUnavailable), 33),
            (Error::Rbg(RbgError::NotOperational), 1),
            (Error::Rbg(RbgError::Busy), 32),
            (Error::RbgTooWeak, 31),
        ];
        assert_eq!(mappings.len(), 7);
        for (error, code) in mappings {
            assert_eq!(OxiResult::from(error) as i32, code, "{error:?}");
        }
        assert_eq!(OxiResult::RbgTooWeak as i32, 31);
        assert_eq!(OxiResult::Busy as i32, 32);
        assert_eq!(OxiResult::EntropyUnavailable as i32, 33);
        assert_eq!(
            OxiResult::from(oxicrypt_drbg::DrbgError::InputTooLong) as i32,
            5
        );
        assert_eq!(
            OxiResult::from(oxicrypt_drbg::DrbgError::RequestTooLong) as i32,
            12
        );
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
            (
                OxiResult::from(oxicrypt_aes::ModeError::Module(
                    oxicrypt_module::Error::KeyExhausted,
                )),
                OxiResult::KeyExhausted,
            ),
        ];
        for (got, expected) in mappings {
            assert_eq!(got, expected);
        }
        assert_eq!(OxiResult::KeyExhausted as i32, 34);
    }

    /// Every `ModeError` variant has its own code, so none reaches the
    /// wildcard arm that reports `Internal = 255`. The variants come from
    /// `oxicrypt_aes::mode_error_variants`, which does not compile without
    /// every variant of the enum.
    #[test]
    fn every_aes_mode_error_variant_maps_below_internal() {
        let codes: Vec<(oxicrypt_aes::ModeError, i32)> = oxicrypt_aes::mode_error_variants()
            .map(|error| (error, OxiResult::from(error) as i32))
            .collect();
        assert_eq!(codes.len(), 11);
        for (i, &(error, code)) in codes.iter().enumerate() {
            assert!(
                code < OxiResult::Internal as i32,
                "{error:?} maps to {code}"
            );
            for &(other, other_code) in codes.iter().skip(i + 1) {
                assert_ne!(code, other_code, "{error:?} and {other:?} share {code}");
            }
        }
    }

    #[test]
    fn status_helpers_convert_results() {
        let module_ok: Result<(), oxicrypt_module::Error> = Ok(());
        assert_eq!(status_module(module_ok), 0);
        let module_err: Result<(), oxicrypt_module::Error> =
            Err(oxicrypt_module::Error::InvalidInput);
        assert_eq!(status_module(module_err), OxiResult::InvalidInput as i32);
    }

    #[test]
    fn kdf_error_maps_to_distinct_oxi_results() {
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
