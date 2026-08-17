//! XMSS (SP 800-208) — eXtended Merkle Signature Scheme, verification.
//!
//! Verifies XMSS signatures for parameter set XMSS-SHA2_10_256
//! (OID 0x00000001), specified by [RFC 8391] and approved for FIPS
//! use by SP 800-208 §5.1 Table 10.
//!
//! # Verification only
//!
//! This crate implements signature verification and nothing else.
//! SP 800-208 §8.1 requires that implementations of XMSS key
//! generation and signature generation be validated only within
//! hardware cryptographic modules at FIPS 140-3 Level 3 or higher
//! physical security. FIPS 140-3 IG C.N resolution 9 excludes
//! software modules from that, and resolution 6 bars offering a
//! conforming scheme as a non-approved service. §8.2 places no such
//! restriction on verification: a module that verifies XMSS
//! signatures implements Algorithm 14 of RFC 8391 for at least one
//! approved parameter set, which is what this crate does.
//!
//! Signing keys for the signatures verified here are therefore
//! produced elsewhere — in practice by a hardware module, which is
//! the deployment CNSA 2.0 anticipates for firmware signing.
//!
//! # Approved services
//!
//! | Service | Standard | Service ID |
//! |---|---|---|
//! | XMSS digital signature verification | SP 800-208 (RFC 8391) | `XmssVerify` (371) |
//!
//! # Parameter set
//!
//! | Parameter | Value | Meaning |
//! |---|---|---|
//! | OID | XMSS-SHA2_10_256 (0x00000001) | SHA-256, height 10, n=32 |
//! | w | 16 | Winternitz parameter |
//! | len | 67 | WOTS+ chains (64 msg + 3 checksum) |
//! | h | 10 | Tree height (1024 leaves) |
//!
//! # Sensitive security parameters (SSPs)
//!
//! None. A verifier reads only public values: the public key, the
//! message and the signature.

#![no_std]
#![forbid(unsafe_code)]

mod adrs;
mod kat;
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

// ── Hash helper for message randomization ───────────────────────

/// Domain separation for H_msg.
#[allow(clippy::indexing_slicing)]
const PAD_H_MSG: [u8; N] = {
    let mut buf = [0u8; N];
    buf[N - 1] = 2;
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

/// H_msg(r ‖ ROOT ‖ toByte(idx,n), M) — randomized message hash.
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

// ── Verification ────────────────────────────────────────────────

/// Verify an XMSS signature.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if the signature is invalid, and
/// the module-gating errors if the module is not operational or the
/// service is blocked by the active algorithm profile.
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

    // Compare the root recomputed from the signature against the
    // root parsed from `public_key`.
    let mut diff = 0u8;
    for i in 0..N {
        diff |= computed_root[i] ^ expected_root[i];
    }
    diff == 0
}

// ── Power-up self-test ──────────────────────────────────────────

/// Power-up KATs for XMSS.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "XMSS KAT (XMSS-SHA2_10_256 verify, SP 800-208, external vector)",
    run: self_test,
}];

/// Power-up known-answer test for XMSS signature verification.
///
/// Verifies a signature the module did not produce, and rejects the same
/// signature with one bit altered. The vector is compiled in — see
/// [`kat`] for its provenance and for why it is a constant rather than a
/// file read at run time.
fn self_test() -> Result<(), SelfTestFailure> {
    // Known answer: this signature is valid under this key for this message.
    if !verify_internal(&kat::KAT_PUBLIC_KEY, &kat::KAT_MSG, &kat::KAT_SIGNATURE) {
        return Err(SelfTestFailure);
    }

    // Known answer: one altered bit makes it invalid. Without this, a
    // verifier that accepted everything would pass the check above.
    let mut tampered = kat::KAT_SIGNATURE;
    #[allow(clippy::indexing_slicing)]
    {
        tampered[64] ^= 0x01;
    }
    if verify_internal(&kat::KAT_PUBLIC_KEY, &kat::KAT_MSG, &tampered) {
        return Err(SelfTestFailure);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    /// Stands in for the pre-operational integrity test.
    ///
    /// A `cargo test` binary is never signed, so the real integrity test
    /// cannot pass inside one. The module requires an integrity group to
    /// initialise at all, so a test that needs a gated service declares
    /// this stub — visibly, at the call site — rather than the module
    /// offering any way to skip the requirement.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    #[test]
    fn self_test_passes() {
        self_test().expect("power-up KAT failed");
    }

    /// The self-test must fail when the stored answer is wrong. A KAT that
    /// cannot fail is the defect this one replaced, so the property is
    /// pinned rather than assumed.
    #[test]
    fn self_test_fails_on_a_corrupted_vector() {
        let mut sig = kat::KAT_SIGNATURE;
        sig[64] ^= 0x01;
        assert!(!verify_internal(&kat::KAT_PUBLIC_KEY, &kat::KAT_MSG, &sig));

        let mut pk = kat::KAT_PUBLIC_KEY;
        pk[8] ^= 0x01;
        assert!(!verify_internal(&pk, &kat::KAT_MSG, &kat::KAT_SIGNATURE));
    }

    #[test]
    fn gated_api_verifies_after_init() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, KATS);
        verify(&kat::KAT_PUBLIC_KEY, &kat::KAT_MSG, &kat::KAT_SIGNATURE)
            .expect("gated verify rejected the KAT vector");
    }

    /// The gated entry point must REJECT as well as accept. Without this,
    /// replacing `verify`'s whole body with `Ok(())` passes every other
    /// test in the crate: the external vectors all exercise
    /// `verify_internal`, and the acceptance test above only ever feeds a
    /// valid signature.
    #[test]
    fn gated_api_rejects_a_tampered_signature() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, KATS);
        let mut tampered = kat::KAT_SIGNATURE;
        tampered[64] ^= 0x01;
        assert!(matches!(
            verify(&kat::KAT_PUBLIC_KEY, &kat::KAT_MSG, &tampered),
            Err(Error::InvalidInput)
        ));
    }

    /// A public key labelled with a different XMSS parameter set must not
    /// be verified as XMSS-SHA2_10_256. Every external vector carries OID
    /// 0x00000001, so without this the OID guard can be deleted and the
    /// suite stays green — parameter confusion with no probe.
    #[test]
    fn rejects_a_public_key_with_a_foreign_oid() {
        let mut pk = kat::KAT_PUBLIC_KEY;
        pk[3] = 0x02; // XMSS-SHA2_16_256, not this crate's parameter set
        assert!(!verify_internal(&pk, &kat::KAT_MSG, &kat::KAT_SIGNATURE));
    }
}
