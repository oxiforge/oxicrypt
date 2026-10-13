//! Verification under whichever (LMS, LM-OTS) pair a public key names.
//!
//! An LMS public key begins with its LMS typecode and its LM-OTS typecode
//! (RFC 8554 §5.3). [`verify_any`] reads both, selects the per-pair module
//! that carries them from the generated table in `dispatch_table`, and
//! calls that module's `verify`. It adds no service of its own: the routed
//! `verify` gates on its own `Service::Lms…Verify`.

use oxicrypt_module::Error;

/// Why [`verify_any`] refused a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyAnyError {
    /// The input names no pair this crate verifies: the public key is
    /// shorter than its two typecodes, its (LMS, LM-OTS) typecode pair is
    /// not one of the 80 of SP 800-208 §4.1–§4.4, or the public key or
    /// signature length is not the named pair's. No verifier ran.
    Unroutable,
    /// The named pair's verifier ran and the signature did not verify.
    VerificationFailed,
    /// The module gate refused the named pair's service: the module is not
    /// operational, or the active profile does not permit the service.
    Module(Error),
}

impl core::fmt::Display for VerifyAnyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unroutable => write!(
                f,
                "the public key does not name an SP 800-208 LMS parameter pair, \
                 or the key or signature length is not that pair's"
            ),
            Self::VerificationFailed => write!(f, "the LMS signature did not verify"),
            Self::Module(e) => write!(f, "module error: {e}"),
        }
    }
}

impl From<Error> for VerifyAnyError {
    fn from(value: Error) -> Self {
        Self::Module(value)
    }
}

/// Verify an LMS signature under the parameter pair its public key names.
///
/// Reads the LMS typecode from bytes 0..4 of `public_key` and the LM-OTS
/// typecode from bytes 4..8, and calls the `verify` of the per-pair module
/// carrying both, which gates on that pair's `Service::Lms…Verify`.
///
/// # Errors
///
/// [`VerifyAnyError::Unroutable`] when the typecodes name none of the 80
/// pairs, or when `public_key` or `signature` is not the named pair's
/// length. [`VerifyAnyError::VerificationFailed`] when the named pair's
/// verifier rejects the signature. [`VerifyAnyError::Module`] when the
/// module gate refuses the named pair's service.
pub fn verify_any(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyAnyError> {
    let (Some(lms_type), Some(lmots_type)) = (typecode(public_key, 0), typecode(public_key, 4))
    else {
        return Err(VerifyAnyError::Unroutable);
    };
    crate::dispatch_table::route_by_typecode(lms_type, lmots_type, public_key, message, signature)
}

/// The big-endian `u32` at `at..at + 4`, or `None` when `bytes` is shorter.
fn typecode(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    <[u8; 4]>::try_from(field).ok().map(u32::from_be_bytes)
}

/// A per-pair module's `verify`, for a public key of `PK` bytes and a
/// signature of `SIG` bytes.
pub(crate) type PairVerify<const PK: usize, const SIG: usize> =
    fn(&[u8; PK], &[u8], &[u8; SIG]) -> Result<(), Error>;

/// Call one pair's `verify` on slices, refusing as
/// [`VerifyAnyError::Unroutable`] when either length is not the pair's.
///
/// The pair's `verify` returns [`Error::InvalidInput`] for a signature
/// that does not verify and nothing else for its inputs, so that variant
/// becomes [`VerifyAnyError::VerificationFailed`]; every other error is
/// the module gate's.
pub(crate) fn route<const PK: usize, const SIG: usize>(
    verify: PairVerify<PK, SIG>,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyAnyError> {
    let (Ok(pk), Ok(sig)) = (
        <&[u8; PK]>::try_from(public_key),
        <&[u8; SIG]>::try_from(signature),
    ) else {
        return Err(VerifyAnyError::Unroutable);
    };
    match verify(pk, message, sig) {
        Ok(()) => Ok(()),
        Err(Error::InvalidInput) => Err(VerifyAnyError::VerificationFailed),
        Err(e) => Err(VerifyAnyError::Module(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typecode_reads_big_endian_and_refuses_short_input() {
        let bytes = [0, 0, 0, 5, 0, 0, 0, 3];
        assert_eq!(typecode(&bytes, 0), Some(5));
        assert_eq!(typecode(&bytes, 4), Some(3));
        assert_eq!(typecode(&bytes[..7], 4), None);
        assert_eq!(typecode(&[], 0), None);
        assert_eq!(typecode(&bytes, usize::MAX), None);
    }
}
