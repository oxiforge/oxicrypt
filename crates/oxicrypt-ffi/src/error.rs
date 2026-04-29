//! C ABI error codes and mapping from per-crate Error types.
//!
//! Each Rust error variant maps to a distinct `OxiResult` discriminant.
//! `OxiResult::Internal = 255` is reserved for "should-never-happen"
//! cases — exhaustive mapping prevents the review-time aliasing concern
//! flagged by `feedback_cmvp_reviewer_framing`.
//!
//! Discriminants are banded by source crate so reviewers can locate
//! the originating failure mode at a glance:
//!
//! - 0:           Success
//! - 1-7:         `oxicrypt_module::Error` variants
//! - 10-11:       FFI-layer errors (null pointer, buffer too small)
//! - 20-27:       `oxicrypt_aes::ModeError` variants
//! - 255:         Catch-all `Internal` (reserved)
//!
//! Future per-crate error types (sha, hmac, drbg, ecdsa, etc.) extend
//! this banded space as their FFI wrappers land in subsequent chunks.

use core::ffi::c_int;

/// C ABI status code for every `oxi_*` function.
///
/// `Ok = 0` is success. Non-zero values are distinct failure modes.
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

    // FFI-layer errors
    /// Caller passed a NULL pointer where one is required.
    NullPointer = 10,
    /// Caller-allocated output buffer is smaller than the documented minimum.
    BufferTooSmall = 11,

    // AES-mode errors (oxicrypt_aes::ModeError)
    /// Input length is not aligned to the cipher block size (where required).
    NotBlockAligned = 20,
    /// IV length doesn't match the mode's specification (e.g. GCM requires exactly 12 bytes).
    InvalidIvLength = 21,
    /// AEAD tag verification failed. Plaintext output buffer contents are UNDEFINED.
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

    /// Catch-all for "should-never-happen" cases. New error sources should
    /// be paired with new `OxiResult` variants in the same change set —
    /// reaching `Internal` is a flag for reviewer attention.
    Internal = 255,
}

impl From<oxicrypt_module::Error> for OxiResult {
    fn from(e: oxicrypt_module::Error) -> Self {
        match e {
            oxicrypt_module::Error::NotOperational { .. } => OxiResult::NotOperational,
            oxicrypt_module::Error::SelfTestFailed { .. } => OxiResult::SelfTestFailed,
            oxicrypt_module::Error::ConditionalTestFailed { .. } => {
                OxiResult::ConditionalTestFailed
            }
            oxicrypt_module::Error::AlreadyInitialized => OxiResult::AlreadyInitialized,
            oxicrypt_module::Error::InvalidInput => OxiResult::InvalidInput,
            oxicrypt_module::Error::AlgorithmRestricted { .. } => OxiResult::AlgorithmRestricted,
            oxicrypt_module::Error::NotImplemented => OxiResult::NotImplemented,
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
        }
    }
}

/// Convert a `Result<(), oxicrypt_module::Error>` into the C `int` status code.
#[allow(dead_code)] // call sites land in Task 6 (renamed init) + Task 7 (AES-GCM exposure)
pub(crate) fn status_module(r: Result<(), oxicrypt_module::Error>) -> c_int {
    match r {
        Ok(()) => OxiResult::Ok as c_int,
        Err(e) => OxiResult::from(e) as c_int,
    }
}

/// Convert a `Result<(), oxicrypt_aes::ModeError>` into the C `int` status code.
#[allow(dead_code)] // call sites land in Task 7 (AES-GCM exposure)
pub(crate) fn status_aes(r: Result<(), oxicrypt_aes::ModeError>) -> c_int {
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
        // Every oxicrypt_module::Error variant maps to a distinct
        // OxiResult discriminant — no aliasing.
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
                OxiResult::from(oxicrypt_module::Error::InvalidInput),
                OxiResult::InvalidInput,
            ),
            (
                OxiResult::from(oxicrypt_module::Error::NotImplemented),
                OxiResult::NotImplemented,
            ),
        ];
        for (got, expected) in mappings {
            assert_eq!(got, expected);
        }
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
}
