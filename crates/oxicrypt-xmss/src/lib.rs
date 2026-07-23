//! XMSS (SP 800-208) — eXtended Merkle Signature Scheme.
//!
//! Implements the XMSS signature scheme with parameter set
//! XMSS-SHA2_10_256 (OID 0x00000001), as specified by
//! [RFC 8391] and approved for FIPS use by SP 800-208.
//!
//! Like LMS, XMSS is a **stateful** scheme: each Merkle tree
//! leaf may sign exactly one message. The signer must persist
//! the private key's leaf index after every signature to prevent
//! catastrophic one-time key reuse. This module enforces the
//! state counter and refuses to sign once the tree is exhausted.
//!
//! # XMSS vs LMS
//!
//! Both are SP 800-208 hash-based signature schemes. XMSS uses
//! WOTS+ (with bitmask-based randomized hashing) and L-trees,
//! making it more complex but providing tighter security
//! reductions. LMS uses LM-OTS with simpler hash constructions.
//! Both are approved for CNSA 2.0 firmware signing.
//!
//! # Approved services
//!
//! | Service | Standard | Service ID |
//! |---|---|---|
//! | XMSS digital signature generation | SP 800-208 (RFC 8391) | `XmssSign` (340) |
//! | XMSS digital signature verification | SP 800-208 (RFC 8391) | `XmssVerify` (341) |
//!
//! # Parameter set
//!
//! | Parameter | Value | Meaning |
//! |---|---|---|
//! | OID | XMSS-SHA2_10_256 (0x00000001) | SHA-256, height 10, n=32 |
//! | w | 16 | Winternitz parameter |
//! | len | 67 | WOTS+ chains (64 msg + 3 checksum) |
//! | h | 10 | Tree height (1024 signatures) |
//!
//! # Self-tests
//!
//! [`KATS`] contains a single power-up KAT that performs a full
//! keygen → sign → verify round trip plus negative tests.
//! Because keygen hashes all 1024 leaves with WOTS+ and L-tree
//! compression, the KAT takes approximately 1–3 s.
//!
//! # Sensitive security parameters (SSPs)
//!
//! | SSP | Location | Zeroized on Drop |
//! |---|---|---|
//! | Secret key seed SK_SEED (32 bytes) | `XmssPrivateKey::sk_seed` | Yes |
//! | PRF secret SK_PRF (32 bytes) | `XmssPrivateKey::sk_prf` | Yes |
//!
//! # FIPS module gating
//!
//! [`sign`] gates on `Service::XmssSign`; [`verify`] gates on
//! `Service::XmssVerify`. Both gate on `require_operational`.
//!
//! # Data-parallel tree build (`parallel` feature, default OFF)
//!
//! The optional `parallel` feature parallelizes the recursive Merkle
//! tree build in [`tree::compute_node`]: above a small height cutoff the
//! two child sub-trees are computed concurrently via a `rayon`
//! fork-join, and the parent recombines them by position (left, right)
//! — never by completion order. Each child sub-tree is a pure function
//! of its `(height, index)` plus the immutable seeds, so the parallel
//! output is byte-identical to the sequential build. The feature pulls
//! in `rayon` (hence `std`), so the crate is `#![no_std]` only when the
//! feature is OFF; the default build graph contains no `rayon` and is
//! the CMVP validation-target single-threaded configuration. `parallel` is a
//! throughput option for keygen (which hashes all 1024 leaves), not a
//! validated path.

#![cfg_attr(not(feature = "parallel"), no_std)]
#![forbid(unsafe_code)]

mod adrs;
mod tree;
mod wots;

use wots::N;

use oxicrypt_module::{Error, KatEntry, SelfTestFailure, Service};

// ── Public constants ────────────────────────────────────────────

/// XMSS signature length in bytes.
///
/// Layout: idx(4) + r(32) + wots_sig(67×32) + auth(10×32) = 2500.
pub const SIGNATURE_LEN: usize = 4 + N + wots::LEN * N + tree::H * N;

/// XMSS public key length in bytes.
///
/// Layout: OID(4) + root(32) + PUB_SEED(32) = 68.
pub const PUBLIC_KEY_LEN: usize = 4 + N + N;

/// Maximum number of signatures for XMSS-SHA2_10_256.
pub const MAX_SIGNATURES: u32 = tree::NUM_LEAVES;

// ── Hash helpers for message randomization ──────────────────────

/// Domain separation for H_msg.
#[allow(clippy::indexing_slicing)]
const PAD_H_MSG: [u8; N] = {
    let mut buf = [0u8; N];
    buf[N - 1] = 2;
    buf
};

/// Domain separation for PRF.
#[allow(clippy::indexing_slicing)]
const PAD_PRF: [u8; N] = {
    let mut buf = [0u8; N];
    buf[N - 1] = 3;
    buf
};

/// toByte(idx, 32): encode a u32 index as a 32-byte big-endian value.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn to_byte_idx(idx: u32) -> [u8; N] {
    let mut buf = [0u8; N];
    let be = idx.to_be_bytes();
    buf[N - 4] = be[0];
    buf[N - 3] = be[1];
    buf[N - 2] = be[2];
    buf[N - 1] = be[3];
    buf
}

/// PRF(KEY, M)
fn prf(key: &[u8; N], m: &[u8]) -> [u8; N] {
    use oxicrypt_sha::sha256::Sha256;
    let mut h = Sha256::new_internal();
    h.update(&PAD_PRF);
    h.update(key);
    h.update(m);
    h.finalize()
}

/// H_msg(r, ROOT, idx, M) — randomized message hash.
///
/// SHA-256(toByte(2,32) || r || ROOT || toByte(idx,32) || M)
fn h_msg(r: &[u8; N], root: &[u8; N], idx: u32, message: &[u8]) -> [u8; N] {
    use oxicrypt_sha::sha256::Sha256;
    let mut h = Sha256::new_internal();
    h.update(&PAD_H_MSG);
    h.update(r);
    h.update(root);
    h.update(&to_byte_idx(idx));
    h.update(message);
    h.finalize()
}

// ── Private key ─────────────────────────────────────────────────

/// XMSS private key with stateful leaf counter.
///
/// The caller must persist the key (including the updated
/// `leaf_index`) after every call to [`sign`]. Failure to persist
/// before a crash can lead to one-time key reuse.
pub struct XmssPrivateKey {
    /// Secret seed for WOTS+ key derivation.
    sk_seed: [u8; N],
    /// Secret seed for pseudo-random message randomizer.
    sk_prf: [u8; N],
    /// Public seed (also in public key, but needed for signing).
    pub_seed: [u8; N],
    /// Cached tree root (also in public key).
    root: [u8; N],
    /// Index of the next unused leaf.
    leaf_index: u32,
}

impl Drop for XmssPrivateKey {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.sk_seed);
        oxicrypt_zeroize::zeroize(&mut self.sk_prf);
    }
}

impl XmssPrivateKey {
    /// Returns the current leaf index.
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    /// Returns `true` if the key is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.leaf_index >= MAX_SIGNATURES
    }

    /// Serialize for persistence.
    ///
    /// Layout: sk_seed(32) + sk_prf(32) + pub_seed(32) + root(32) + idx(4) = 132.
    pub fn to_bytes(&self) -> [u8; 132] {
        #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        let mut out = [0u8; 132];
        out[..N].copy_from_slice(&self.sk_seed);
        out[N..2 * N].copy_from_slice(&self.sk_prf);
        out[2 * N..3 * N].copy_from_slice(&self.pub_seed);
        out[3 * N..4 * N].copy_from_slice(&self.root);
        out[4 * N..4 * N + 4].copy_from_slice(&self.leaf_index.to_be_bytes());
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        if bytes.len() != 132 {
            return None;
        }
        let mut sk_seed = [0u8; N];
        sk_seed.copy_from_slice(&bytes[..N]);
        let mut sk_prf = [0u8; N];
        sk_prf.copy_from_slice(&bytes[N..2 * N]);
        let mut pub_seed = [0u8; N];
        pub_seed.copy_from_slice(&bytes[2 * N..3 * N]);
        let mut root = [0u8; N];
        root.copy_from_slice(&bytes[3 * N..4 * N]);
        let leaf_index = u32::from_be_bytes([
            bytes[4 * N],
            bytes[4 * N + 1],
            bytes[4 * N + 2],
            bytes[4 * N + 3],
        ]);
        Some(Self {
            sk_seed,
            sk_prf,
            pub_seed,
            root,
            leaf_index,
        })
    }
}

// ── Key generation ──────────────────────────────────────────────

/// Generate an XMSS key pair from a 32-byte seed `xi`.
///
/// Derives three sub-seeds deterministically:
///   SK_SEED  = SHA-256(xi || 0x00)
///   SK_PRF   = SHA-256(xi || 0x01)
///   PUB_SEED = SHA-256(xi || 0x02)
///
/// # Errors
///
/// Returns module-gating errors if not ready.
pub fn keygen(xi: &[u8; 32]) -> Result<(XmssPrivateKey, [u8; PUBLIC_KEY_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::XmssSign)?;
    Ok(keygen_internal(xi))
}

/// Internal keygen bypassing module gating (for self-tests).
#[doc(hidden)]
pub fn keygen_internal(xi: &[u8; 32]) -> (XmssPrivateKey, [u8; PUBLIC_KEY_LEN]) {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use oxicrypt_sha::sha256::Sha256;

    let derive = |suffix: u8| -> [u8; N] {
        let mut h = Sha256::new_internal();
        h.update(xi);
        h.update(&[suffix]);
        h.finalize()
    };

    let sk_seed = derive(0x00);
    let sk_prf = derive(0x01);
    let pub_seed = derive(0x02);

    let root = tree::compute_root(&sk_seed, &pub_seed);

    // Public key: OID(4) + root(32) + PUB_SEED(32).
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..4].copy_from_slice(&tree::XMSS_OID.to_be_bytes());
    pk[4..4 + N].copy_from_slice(&root);
    pk[4 + N..4 + 2 * N].copy_from_slice(&pub_seed);

    let sk = XmssPrivateKey {
        sk_seed,
        sk_prf,
        pub_seed,
        root,
        leaf_index: 0,
    };
    (sk, pk)
}

// ── Signing ─────────────────────────────────────────────────────

/// Sign `message`, advancing the leaf index.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the key is exhausted.
pub fn sign(key: &mut XmssPrivateKey, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::XmssSign)?;
    sign_internal(key, message).ok_or(Error::InvalidInput)
}

/// Internal sign bypassing module gating (for self-tests).
#[doc(hidden)]
pub fn sign_internal(key: &mut XmssPrivateKey, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    if key.is_exhausted() {
        return None;
    }

    let idx = key.leaf_index;

    // Randomizer r = PRF(SK_PRF, toByte(idx, 32)).
    let r = prf(&key.sk_prf, &to_byte_idx(idx));

    // Message hash.
    let msg_hash = h_msg(&r, &key.root, idx, message);

    // WOTS+ sign.
    let wots_sig = wots::wots_sign(&msg_hash, &key.sk_seed, &key.pub_seed, idx);

    // Authentication path.
    let auth = tree::compute_auth_path(&key.sk_seed, &key.pub_seed, idx);

    // Assemble signature: idx(4) || r(32) || wots_sig(67*32) || auth(10*32).
    let mut sig = [0u8; SIGNATURE_LEN];
    let mut pos = 0;

    sig[pos..pos + 4].copy_from_slice(&idx.to_be_bytes());
    pos += 4;

    sig[pos..pos + N].copy_from_slice(&r);
    pos += N;

    for elem in &wots_sig {
        sig[pos..pos + N].copy_from_slice(elem);
        pos += N;
    }

    for node in &auth {
        sig[pos..pos + N].copy_from_slice(node);
        pos += N;
    }

    key.leaf_index = idx + 1;

    Some(sig)
}

// ── Verification ────────────────────────────────────────────────

/// Verify an XMSS signature.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the signature is invalid.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::XmssVerify)?;
    if verify_internal(public_key, message, signature) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Internal verify bypassing module gating (for self-tests).
#[doc(hidden)]
pub fn verify_internal(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    // Parse public key.
    let pk_oid = u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
    if pk_oid != tree::XMSS_OID {
        return false;
    }
    let mut expected_root = [0u8; N];
    expected_root.copy_from_slice(&public_key[4..4 + N]);
    let mut pub_seed = [0u8; N];
    pub_seed.copy_from_slice(&public_key[4 + N..4 + 2 * N]);

    // Parse signature.
    let idx = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
    if idx >= tree::NUM_LEAVES {
        return false;
    }

    let mut r = [0u8; N];
    r.copy_from_slice(&signature[4..4 + N]);

    // Parse WOTS+ signature.
    let mut wots_sig = [[0u8; N]; wots::LEN];
    let wots_start = 4 + N;
    for (i, slot) in wots_sig.iter_mut().enumerate() {
        let off = wots_start + i * N;
        slot.copy_from_slice(&signature[off..off + N]);
    }

    // Parse auth path.
    let auth_start = wots_start + wots::LEN * N;
    let mut auth = [[0u8; N]; tree::H];
    for (i, slot) in auth.iter_mut().enumerate() {
        let off = auth_start + i * N;
        slot.copy_from_slice(&signature[off..off + N]);
    }

    // Recompute message hash.
    let msg_hash = h_msg(&r, &expected_root, idx, message);

    // Compute root from signature.
    let computed_root = tree::root_from_sig(&msg_hash, &wots_sig, &pub_seed, idx, &auth);

    // Constant-time comparison.
    let mut diff = 0u8;
    for i in 0..N {
        diff |= computed_root[i] ^ expected_root[i];
    }
    diff == 0
}

// ── Power-up self-test ──────────────────────────────────────────

/// Power-up KATs for XMSS.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "XMSS KAT (XMSS-SHA2_10_256 keygen+sign+verify round-trip, SP 800-208)",
    run: self_test,
}];

/// KAT seed.
const KAT_XI: [u8; 32] = [
    0x58, 0x4d, 0x53, 0x53, 0x2d, 0x4b, 0x41, 0x54, // "XMSS-KAT"
    0x2d, 0x53, 0x50, 0x38, 0x30, 0x30, 0x2d, 0x32, // "-SP800-2"
    0x30, 0x38, 0x2d, 0x6f, 0x78, 0x69, 0x63, 0x72, // "08-oxicr"
    0x79, 0x70, 0x74, 0x2d, 0x76, 0x30, 0x2e, 0x30, // "ypt-v0.0"
];

/// KAT message.
const KAT_MSG: &[u8] = b"XMSS self-test message for SP 800-208 / FIPS 140-3 compliance";

/// Power-up self-test.
fn self_test() -> Result<(), SelfTestFailure> {
    let (mut sk, pk) = keygen_internal(&KAT_XI);

    let Some(sig) = sign_internal(&mut sk, KAT_MSG) else {
        return Err(SelfTestFailure);
    };

    // Positive.
    if !verify_internal(&pk, KAT_MSG, &sig) {
        return Err(SelfTestFailure);
    }

    // Negative: wrong message.
    if verify_internal(&pk, b"wrong message", &sig) {
        return Err(SelfTestFailure);
    }

    // Negative: tampered signature.
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
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "xmss-unit-test-bootstrap",
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
        let oid = u32::from_be_bytes([pk[0], pk[1], pk[2], pk[3]]);
        assert_eq!(oid, tree::XMSS_OID);
    }

    #[test]
    fn sign_advances_leaf_index() {
        let (mut sk, _pk) = keygen_internal(&KAT_XI);
        assert_eq!(sk.leaf_index(), 0);
        let _ = sign_internal(&mut sk, b"msg1");
        assert_eq!(sk.leaf_index(), 1);
    }

    #[test]
    fn verify_fails_on_wrong_public_key() {
        let (mut sk, _pk) = keygen_internal(&KAT_XI);
        let sig = sign_internal(&mut sk, KAT_MSG).unwrap();
        let (_sk2, pk2) = keygen_internal(&[0xFFu8; 32]);
        assert!(!verify_internal(&pk2, KAT_MSG, &sig));
    }

    #[test]
    fn private_key_round_trips_through_bytes() {
        let (sk, _pk) = keygen_internal(&KAT_XI);
        let bytes = sk.to_bytes();
        let sk2 = XmssPrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.sk_seed, sk2.sk_seed);
        assert_eq!(sk.sk_prf, sk2.sk_prf);
        assert_eq!(sk.pub_seed, sk2.pub_seed);
        assert_eq!(sk.root, sk2.root);
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
