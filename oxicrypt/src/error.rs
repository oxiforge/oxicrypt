//! The C ABI's status codes as a Rust error type.

use core::fmt;

use crate::module::{Fingerprint, IntegrityStatus, Profile};

/// Which kind of C function returned a status code.
///
/// Code 22 is reused by the C ABI: it means a tag that did not verify when an
/// AEAD decryption returns it, and a signature that did not verify when a
/// signature verification returns it. The crate always knows which function
/// it called, so it maps the code by site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// An AEAD decryption (`oxi_aes256_gcm_decrypt`).
    AeadDecrypt,
    /// A signature verification (`oxi_ml_dsa_87_verify`).
    SignatureVerify,
    /// Any other function.
    Other,
}

/// An error from the library, or from a check the crate makes before calling
/// it.
///
/// Variants up to [`Error::Internal`] are the library's status codes, in the
/// order and with the meaning of `OxiResult` in the C ABI. The last four are
/// the crate's own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Code 1: the module is not in its operational state.
    NotOperational,
    /// Code 2: a power-up self-test failed during initialisation.
    SelfTestFailed,
    /// Code 3: a conditional self-test failed during operation.
    ConditionalTestFailed,
    /// Code 4: initialisation was requested more than once.
    AlreadyInitialized,
    /// Code 5: an input was refused.
    InvalidInput,
    /// Code 6: the active algorithm profile does not permit the service.
    AlgorithmRestricted,
    /// Code 7: the service is not implemented.
    NotImplemented,
    /// Code 8: a DRBG handle was used before it was instantiated.
    Uninstantiated,
    /// Code 9: a DRBG handle must be reseeded before it generates more output.
    ReseedRequired,
    /// Code 10: a required pointer was null.
    NullPointer,
    /// Code 11: an output buffer was smaller than the documented minimum.
    BufferTooSmall,
    /// Code 12: more output was requested than the algorithm permits. Also
    /// returned by the crate, without calling the library, when a requested
    /// length exceeds the bound for an output the crate allocates.
    OutputTooLong,
    /// Code 20: an input was not a whole number of blocks.
    NotBlockAligned,
    /// Code 21: an IV length was not the mode's.
    InvalidIvLength,
    /// Code 22 from an AEAD decryption: the authentication tag did not verify.
    TagMismatch,
    /// Code 23: an input and output buffer differ in length. Also returned by
    /// the crate, without calling the library, when a caller's output slice
    /// is not the input's length.
    LengthMismatch,
    /// Code 24: a nonce length was not the mode's.
    InvalidNonceLength,
    /// Code 25: a tag length was not the mode's.
    InvalidTagLength,
    /// Code 26: a payload was longer than the mode permits.
    InvalidPayloadLength,
    /// Code 27: associated data was longer than the mode permits.
    InvalidAadLength,
    /// Code 28: the module was initialised without its integrity test.
    IntegrityUnverified,
    /// Code 255: an internal error of the library.
    Internal,
    /// Code 22 from a signature verification: the signature did not verify,
    /// or the signature or key did not decode.
    SignatureInvalid,
    /// Any other code: negative, or not assigned by this version of the C ABI.
    Unknown(i32),
    /// The library is not the version this crate was built for.
    LibraryVersion {
        /// The version the library's manifest states, or `None` when the
        /// manifest could not be read.
        library: Option<String>,
        /// The version of this crate.
        crate_: &'static str,
    },
    /// The library is initialised with another profile than the one requested.
    ProfileMismatch {
        /// The profile the library reports as active.
        active: Profile,
        /// The profile this call requested.
        requested: Profile,
    },
    /// The library embeds another verifying key than the one this crate was
    /// built to accept.
    KeyFingerprint {
        /// The fingerprint the library reports.
        found: Fingerprint,
        /// The fingerprint `OXICRYPT_LIB_FINGERPRINT` pinned.
        expected: Fingerprint,
    },
}

impl Error {
    /// Maps a non-zero status code returned by a function of kind `site`.
    ///
    /// Zero is success and is never an error; it maps to `Unknown(0)`.
    #[must_use]
    pub fn from_code(code: i32, site: Site) -> Self {
        match code {
            1 => Self::NotOperational,
            2 => Self::SelfTestFailed,
            3 => Self::ConditionalTestFailed,
            4 => Self::AlreadyInitialized,
            5 => Self::InvalidInput,
            6 => Self::AlgorithmRestricted,
            7 => Self::NotImplemented,
            8 => Self::Uninstantiated,
            9 => Self::ReseedRequired,
            10 => Self::NullPointer,
            11 => Self::BufferTooSmall,
            12 => Self::OutputTooLong,
            20 => Self::NotBlockAligned,
            21 => Self::InvalidIvLength,
            22 => match site {
                Site::SignatureVerify => Self::SignatureInvalid,
                Site::AeadDecrypt | Site::Other => Self::TagMismatch,
            },
            23 => Self::LengthMismatch,
            24 => Self::InvalidNonceLength,
            25 => Self::InvalidTagLength,
            26 => Self::InvalidPayloadLength,
            27 => Self::InvalidAadLength,
            28 => Self::IntegrityUnverified,
            255 => Self::Internal,
            other => Self::Unknown(other),
        }
    }
}

/// `Ok(())` for status 0, else the mapped error.
pub(crate) fn status(code: core::ffi::c_int, site: Site) -> Result<(), Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::from_code(code, site))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOperational => f.write_str("module not in the operational state"),
            Self::SelfTestFailed => f.write_str("power-up self-test failed during initialisation"),
            Self::ConditionalTestFailed => {
                f.write_str("conditional self-test failed during operation")
            }
            Self::AlreadyInitialized => f.write_str("initialisation requested more than once"),
            Self::InvalidInput => f.write_str("invalid input"),
            Self::AlgorithmRestricted => {
                f.write_str("service blocked by the active algorithm profile")
            }
            Self::NotImplemented => f.write_str("service not implemented"),
            Self::Uninstantiated => f.write_str("DRBG used before it was instantiated"),
            Self::ReseedRequired => f.write_str("DRBG must be reseeded before it generates more"),
            Self::NullPointer => f.write_str("a required pointer was null"),
            Self::BufferTooSmall => {
                f.write_str("output buffer smaller than the documented minimum")
            }
            Self::OutputTooLong => f.write_str("output bound exceeded"),
            Self::NotBlockAligned => f.write_str("input not aligned to the cipher block size"),
            Self::InvalidIvLength => f.write_str("IV length does not match the mode"),
            Self::TagMismatch => f.write_str("authentication tag did not verify"),
            Self::LengthMismatch => f.write_str("input and output buffer lengths differ"),
            Self::InvalidNonceLength => f.write_str("nonce length does not match the mode"),
            Self::InvalidTagLength => f.write_str("tag length does not match the mode"),
            Self::InvalidPayloadLength => f.write_str("payload length exceeds the mode's maximum"),
            Self::InvalidAadLength => f.write_str("AAD length exceeds the mode's maximum"),
            Self::IntegrityUnverified => {
                f.write_str("module initialised without the software integrity test")
            }
            Self::Internal => f.write_str("internal error in the library"),
            Self::SignatureInvalid => f.write_str("signature did not verify"),
            Self::Unknown(code) => write!(f, "unknown status code {code}"),
            Self::LibraryVersion { library, crate_ } => match library {
                Some(v) => write!(
                    f,
                    "library version {v} does not match the binding's version {crate_}"
                ),
                None => write!(
                    f,
                    "library manifest states no version; the binding requires {crate_}"
                ),
            },
            Self::ProfileMismatch { active, requested } => write!(
                f,
                "library is initialised with profile {active:?}, not the requested {requested:?}"
            ),
            Self::KeyFingerprint { found, expected } => write!(
                f,
                "library embeds verifying key {found}, not the pinned {expected}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Why [`Module::init`](crate::Module::init) did not return a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitError {
    /// The refusal: the status code `oxi_init` returned, or the crate's own
    /// check that failed.
    pub code: Error,
    /// The integrity test's indicator as the library reported it after this
    /// call, or `None` when the crate refused the library before calling
    /// anything but its manifest, so the indicator was not read.
    pub integrity: Option<IntegrityStatus>,
    /// The library's description of an integrity-test failure: `Ok(None)`
    /// when it has none, and an error when reading it failed.
    pub detail: Result<Option<String>, DetailError>,
}

/// Why the library's integrity-test detail text could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetailError {
    /// The call that sizes the text failed.
    Sizing(Error),
    /// The text is longer than the crate reads (64 KiB).
    TooLong {
        /// The length the library reported.
        needed: usize,
    },
    /// The call that reads the text failed.
    Read(Error),
    /// The library reported writing more than the buffer it was given.
    Overrun {
        /// The length the library reported writing.
        written: usize,
        /// The buffer's length.
        capacity: usize,
    },
}

impl fmt::Display for DetailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sizing(e) => write!(f, "sizing the detail text failed: {e}"),
            Self::TooLong { needed } => write!(f, "detail text of {needed} bytes not read"),
            Self::Read(e) => write!(f, "reading the detail text failed: {e}"),
            Self::Overrun { written, capacity } => write!(
                f,
                "library reported {written} bytes written into {capacity}"
            ),
        }
    }
}

impl std::error::Error for DetailError {}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(integrity) = self.integrity {
            write!(f, " (integrity test: {integrity:?})")?;
        }
        match &self.detail {
            Ok(Some(detail)) => write!(f, ": {detail}"),
            Ok(None) => Ok(()),
            Err(e) => write!(f, " ({e})"),
        }
    }
}

impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.code)
    }
}
