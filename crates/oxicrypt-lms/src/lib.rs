//! LMS (SP 800-208) — Leighton-Micali stateful hash-based signatures.
//!
//! Implements the LMS signature scheme with parameter set
//! LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4, as specified by
//! [RFC 8554] and approved for FIPS use by SP 800-208.
//!
//! LMS is a **stateful** scheme: each leaf of the Merkle tree may
//! be used to sign exactly one message. The signer must persist
//! the private key's leaf index after every signature to prevent
//! catastrophic one-time key reuse. This module enforces the
//! state counter and refuses to sign once the tree is exhausted.
//!
//! # Approved services
//!
//! | Service | Standard | Service ID |
//! |---|---|---|
//! | LMS digital signature generation | SP 800-208 (RFC 8554) | `LmsSign` (330) |
//! | LMS digital signature verification | SP 800-208 (RFC 8554) | `LmsVerify` (331) |
//!
//! # Parameter set
//!
//! | Parameter | Value | Meaning |
//! |---|---|---|
//! | LMS type | `LMS_SHA256_M32_H10` (0x0006) | Merkle tree height 10 (1024 signatures) |
//! | OTS type | `LMOTS_SHA256_N32_W4` (0x0003) | 32-byte hash, Winternitz w=4 |
//!
//! Additional parameter sets may be added in a future release.
//!
//! # Self-tests
//!
//! [`KATS`] contains a single power-up KAT that performs a full
//! keygen → sign → verify round trip plus negative verification
//! tests. Because keygen requires hashing all 1024 leaves, the
//! KAT takes approximately 0.5–1 s on modern hardware.
//!
//! # Sensitive security parameters (SSPs)
//!
//! | SSP | Location | Zeroized on Drop |
//! |---|---|---|
//! | Tree seed (32 bytes) | `LmsPrivateKey::seed` | Yes |
//! | Tree identifier I (16 bytes) | `LmsPrivateKey::identifier` | Yes |
//!
//! # FIPS module gating
//!
//! [`sign`] gates on `Service::LmsSign`; [`verify`] gates on
//! `Service::LmsVerify`. Both gate on `require_operational`.

#![no_std]
#![forbid(unsafe_code)]

mod lmots;
mod tree;

use lmots::N;
use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};

// ── Public constants ────────────────────────────────────────────

/// LMS signature length in bytes.
///
/// Layout: q(4) + ots_sig(2180) + lms_type(4) + auth_path(10×32).
pub const SIGNATURE_LEN: usize = 4 + lmots::OTS_SIG_LEN + 4 + tree::H * N;

/// LMS public key length in bytes.
///
/// Layout: lms_type(4) + ots_type(4) + I(16) + root(32).
pub const PUBLIC_KEY_LEN: usize = 4 + 4 + 16 + N;

/// Maximum number of signatures for LMS_SHA256_M32_H10.
pub const MAX_SIGNATURES: u32 = tree::NUM_LEAVES;

// ── Private key ─────────────────────────────────────────────────

/// LMS private key with stateful leaf counter.
///
/// The caller is responsible for persisting the key (including
/// the updated `leaf_index`) after every call to [`sign`] or
/// [`sign_internal`]. Failure to persist before a crash can lead
/// to one-time key reuse, which is a catastrophic security
/// failure for any stateful hash-based signature scheme.
pub struct LmsPrivateKey {
    /// Secret seed from which all LM-OTS private key elements
    /// are derived via `H(I || q || i || 0xff || seed)`.
    seed: [u8; N],
    /// 16-byte tree identifier, unique per key pair.
    identifier: [u8; 16],
    /// Index of the next unused leaf. Starts at 0 and
    /// increments by 1 on each signature. Once it reaches
    /// [`MAX_SIGNATURES`] the key is exhausted.
    leaf_index: u32,
}

impl Drop for LmsPrivateKey {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.seed);
        oxicrypt_zeroize::zeroize(&mut self.identifier);
    }
}

impl LmsPrivateKey {
    /// Returns the current leaf index (number of signatures issued).
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    /// Returns `true` if the key is exhausted (no more leaves).
    pub fn is_exhausted(&self) -> bool {
        self.leaf_index >= MAX_SIGNATURES
    }

    /// Serialize the private key to bytes for persistence.
    ///
    /// Layout: seed(32) + I(16) + leaf_index(4) = 52 bytes.
    pub fn to_bytes(&self) -> [u8; 52] {
        #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        let mut out = [0u8; 52];
        out[..N].copy_from_slice(&self.seed);
        out[N..N + 16].copy_from_slice(&self.identifier);
        out[N + 16..N + 20].copy_from_slice(&self.leaf_index.to_be_bytes());
        out
    }

    /// Deserialize a private key from bytes.
    ///
    /// Returns `None` if `bytes` has the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        if bytes.len() != 52 {
            return None;
        }
        let mut seed = [0u8; N];
        seed.copy_from_slice(&bytes[..N]);
        let mut identifier = [0u8; 16];
        identifier.copy_from_slice(&bytes[N..N + 16]);
        let leaf_index =
            u32::from_be_bytes([bytes[N + 16], bytes[N + 17], bytes[N + 18], bytes[N + 19]]);
        Some(Self {
            seed,
            identifier,
            leaf_index,
        })
    }
}

// ── Key generation ──────────────────────────────────────────────

/// Generate an LMS key pair from a 32-byte seed `xi`.
///
/// The tree seed and identifier are deterministically derived:
///   SEED = SHA-256(xi || 0x00)
///   I    = SHA-256(xi || 0x01)\[0..16\]
///
/// # Errors
///
/// Returns [`Error::NotOperational`] or [`Error::AlgorithmRestricted`]
/// if the module is not ready or the service is restricted.
pub fn keygen(xi: &[u8; 32]) -> Result<(LmsPrivateKey, [u8; PUBLIC_KEY_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::LmsSign)?;
    Ok(keygen_internal(xi))
}

/// Internal keygen that bypasses module gating (for self-tests).
#[doc(hidden)]
pub fn keygen_internal(xi: &[u8; 32]) -> (LmsPrivateKey, [u8; PUBLIC_KEY_LEN]) {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use oxicrypt_sha::sha256::Sha256;

    // Derive seed.
    let mut h = Sha256::new_internal();
    h.update(xi);
    h.update(&[0x00]);
    let seed = h.finalize();

    // Derive identifier I (first 16 bytes of a second hash).
    let mut h = Sha256::new_internal();
    h.update(xi);
    h.update(&[0x01]);
    let i_full = h.finalize();
    let mut identifier = [0u8; 16];
    identifier.copy_from_slice(&i_full[..16]);

    // Compute tree root.
    let root = tree::compute_root(&seed, &identifier);

    // Assemble public key: lms_type(4) + ots_type(4) + I(16) + root(32).
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..4].copy_from_slice(&tree::LMS_TYPE.to_be_bytes());
    pk[4..8].copy_from_slice(&lmots::LMOTS_TYPE.to_be_bytes());
    pk[8..24].copy_from_slice(&identifier);
    pk[24..24 + N].copy_from_slice(&root);

    let sk = LmsPrivateKey {
        seed,
        identifier,
        leaf_index: 0,
    };
    (sk, pk)
}

/// Internal keygen from explicit seed and identifier (for ACVP KAT vectors).
///
/// Unlike [`keygen_internal`], which derives the tree seed and identifier
/// from a 32-byte `xi` via SHA-256, this function accepts them directly.
/// This matches the ACVP keyGen test format, which supplies `seed` and
/// `I` (identifier) as separate fields.
#[doc(hidden)]
pub fn keygen_from_parts(
    seed: &[u8; N],
    identifier: &[u8; 16],
) -> (LmsPrivateKey, [u8; PUBLIC_KEY_LEN]) {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    let root = tree::compute_root(seed, identifier);

    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..4].copy_from_slice(&tree::LMS_TYPE.to_be_bytes());
    pk[4..8].copy_from_slice(&lmots::LMOTS_TYPE.to_be_bytes());
    pk[8..24].copy_from_slice(identifier);
    pk[24..24 + N].copy_from_slice(&root);

    let sk = LmsPrivateKey {
        seed: *seed,
        identifier: *identifier,
        leaf_index: 0,
    };
    (sk, pk)
}

// ── Signing ─────────────────────────────────────────────────────

/// Sign `message` with the LMS private key, advancing the leaf index.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the key is exhausted.
/// Returns [`Error::NotOperational`] or [`Error::AlgorithmRestricted`]
/// if the module is not ready.
pub fn sign(key: &mut LmsPrivateKey, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::LmsSign)?;
    sign_internal(key, message).ok_or(Error::InvalidInput)
}

/// Internal sign that bypasses module gating (for self-tests).
///
/// Returns `None` if the key is exhausted.
#[doc(hidden)]
pub fn sign_internal(key: &mut LmsPrivateKey, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    if key.is_exhausted() {
        return None;
    }

    let q = key.leaf_index;

    // LM-OTS sign.
    let ots_sig = lmots::ots_sign(&key.seed, &key.identifier, q, message);

    // Authentication path.
    let auth = tree::compute_auth_path(&key.seed, &key.identifier, q);

    // Assemble LMS signature:
    //   u32str(q) || ots_sig || u32str(lms_type) || path[0..h-1]
    let mut sig = [0u8; SIGNATURE_LEN];
    let mut pos = 0;

    // q
    sig[pos..pos + 4].copy_from_slice(&q.to_be_bytes());
    pos += 4;

    // OTS signature
    sig[pos..pos + lmots::OTS_SIG_LEN].copy_from_slice(&ots_sig);
    pos += lmots::OTS_SIG_LEN;

    // LMS type
    sig[pos..pos + 4].copy_from_slice(&tree::LMS_TYPE.to_be_bytes());
    pos += 4;

    // Auth path
    for node in &auth {
        sig[pos..pos + N].copy_from_slice(node);
        pos += N;
    }

    // Advance state — MUST persist before using the signature.
    key.leaf_index = q + 1;

    Some(sig)
}

// ── Verification ────────────────────────────────────────────────

/// Verify an LMS signature.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the signature is invalid.
/// Returns [`Error::NotOperational`] or [`Error::AlgorithmRestricted`]
/// if the module is not ready.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::LmsVerify)?;
    if verify_internal(public_key, message, signature) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Internal verify that bypasses module gating (for self-tests).
#[doc(hidden)]
pub fn verify_internal(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    // Parse public key.
    let pk_lms_type =
        u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
    if pk_lms_type != tree::LMS_TYPE {
        return false;
    }
    let pk_ots_type =
        u32::from_be_bytes([public_key[4], public_key[5], public_key[6], public_key[7]]);
    if pk_ots_type != lmots::LMOTS_TYPE {
        return false;
    }
    let mut i_val = [0u8; 16];
    i_val.copy_from_slice(&public_key[8..24]);
    let mut expected_root = [0u8; N];
    expected_root.copy_from_slice(&public_key[24..24 + N]);

    // Parse signature.
    let q = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
    if q >= tree::NUM_LEAVES {
        return false;
    }

    let ots_sig = &signature[4..4 + lmots::OTS_SIG_LEN];

    let sig_lms_type = u32::from_be_bytes([
        signature[4 + lmots::OTS_SIG_LEN],
        signature[4 + lmots::OTS_SIG_LEN + 1],
        signature[4 + lmots::OTS_SIG_LEN + 2],
        signature[4 + lmots::OTS_SIG_LEN + 3],
    ]);
    if sig_lms_type != tree::LMS_TYPE {
        return false;
    }

    // Extract auth path.
    let auth_start = 4 + lmots::OTS_SIG_LEN + 4;
    let mut auth = [[0u8; N]; tree::H];
    for (level, slot) in auth.iter_mut().enumerate() {
        let off = auth_start + level * N;
        slot.copy_from_slice(&signature[off..off + N]);
    }

    // Compute candidate OTS public key.
    let Some(candidate_k) = lmots::ots_verify_candidate(&i_val, q, message, ots_sig) else {
        return false;
    };

    // Walk the authentication path to the root.
    let computed_root = tree::walk_auth_path(&i_val, &candidate_k, q, &auth);

    // Constant-time comparison (leak-free for public values, but
    // good practice nonetheless).
    let mut diff = 0u8;
    for i in 0..N {
        diff |= computed_root[i] ^ expected_root[i];
    }
    diff == 0
}

// ── Power-up self-test ──────────────────────────────────────────

/// Power-up KATs for LMS.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "LMS KAT (LMS_SHA256_M32_H10 keygen+sign+verify round-trip, SP 800-208)",
    run: self_test,
}];

/// KAT seed — fixed 32-byte value for deterministic keygen.
const KAT_XI: [u8; 32] = [
    0x4c, 0x4d, 0x53, 0x2d, 0x4b, 0x41, 0x54, 0x2d, // "LMS-KAT-"
    0x53, 0x50, 0x38, 0x30, 0x30, 0x2d, 0x32, 0x30, // "SP800-20"
    0x38, 0x2d, 0x6f, 0x78, 0x69, 0x63, 0x72, 0x79, // "8-oxicry"
    0x70, 0x74, 0x2d, 0x76, 0x30, 0x2e, 0x30, 0x2e, // "pt-v0.0."
];

/// KAT message.
const KAT_MSG: &[u8] = b"LMS self-test message for SP 800-208 / FIPS 140-3 compliance";

/// Power-up self-test: keygen + sign + verify round trip.
fn self_test() -> Result<(), SelfTestFailure> {
    let (mut sk, pk) = keygen_internal(&KAT_XI);

    // Sign.
    let Some(sig) = sign_internal(&mut sk, KAT_MSG) else {
        return Err(SelfTestFailure);
    };

    // Positive verification.
    if !verify_internal(&pk, KAT_MSG, &sig) {
        return Err(SelfTestFailure);
    }

    // Negative: wrong message must fail.
    if verify_internal(&pk, b"wrong message", &sig) {
        return Err(SelfTestFailure);
    }

    // Negative: tampered signature must fail.
    let mut sig_bad = sig;
    #[allow(clippy::indexing_slicing)]
    {
        sig_bad[100] ^= 0x01;
    }
    if verify_internal(&pk, KAT_MSG, &sig_bad) {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ── Unit tests ──────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oxicrypt_module::{initialize_with_tests, KatEntry};

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "lms-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn keygen_produces_valid_public_key() {
        let xi = [0x42u8; 32];
        let (_sk, pk) = keygen_internal(&xi);
        // Check type codes.
        let lms_type = u32::from_be_bytes([pk[0], pk[1], pk[2], pk[3]]);
        assert_eq!(lms_type, tree::LMS_TYPE);
        let ots_type = u32::from_be_bytes([pk[4], pk[5], pk[6], pk[7]]);
        assert_eq!(ots_type, lmots::LMOTS_TYPE);
    }

    #[test]
    fn sign_advances_leaf_index() {
        let (mut sk, _pk) = keygen_internal(&KAT_XI);
        assert_eq!(sk.leaf_index(), 0);
        let _ = sign_internal(&mut sk, b"msg1");
        assert_eq!(sk.leaf_index(), 1);
        let _ = sign_internal(&mut sk, b"msg2");
        assert_eq!(sk.leaf_index(), 2);
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let (mut sk, _pk) = keygen_internal(&KAT_XI);
        let sig1 = sign_internal(&mut sk, b"message A").unwrap();
        let (mut sk2, _) = keygen_internal(&KAT_XI);
        // Use a different message on leaf 0 — the second key pair
        // starts fresh, so we can compare leaf 0 signatures.
        let sig2 = sign_internal(&mut sk2, b"message B").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn verify_fails_on_wrong_public_key() {
        let (mut sk, _pk) = keygen_internal(&KAT_XI);
        let sig = sign_internal(&mut sk, KAT_MSG).unwrap();
        // Different seed → different public key.
        let (_sk2, pk2) = keygen_internal(&[0xFFu8; 32]);
        assert!(!verify_internal(&pk2, KAT_MSG, &sig));
    }

    #[test]
    fn private_key_round_trips_through_bytes() {
        let (sk, _pk) = keygen_internal(&KAT_XI);
        let bytes = sk.to_bytes();
        let sk2 = LmsPrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.seed, sk2.seed);
        assert_eq!(sk.identifier, sk2.identifier);
        assert_eq!(sk.leaf_index, sk2.leaf_index);
    }

    #[test]
    fn gated_api_works_after_init() {
        ensure_initialized();
        let (mut sk, pk) = keygen(&[0x99u8; 32]).unwrap();
        let sig = sign(&mut sk, b"gated test").unwrap();
        verify(&pk, b"gated test", &sig).unwrap();
    }
}
