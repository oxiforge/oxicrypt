//! LMS ACVP handlers — `keyGen`, `sigGen`, and `sigVer` modes.
//!
//! **LMS** (`LMS` / `keyGen`, `sigGen`, `sigVer` / revision `1.0`):
//! Stateful hash-based signature scheme per SP 800-208 (RFC 8554 +
//! RFC 8708). The full 80-pair grid is now dispatchable — 4 hash
//! families × 5 tree heights × 4 Winternitz parameters. Each group's
//! `(lmsMode, lmOtsMode)` strings route to the per-pair `oxicrypt_lms`
//! module via a closed-form match (no runtime trait dispatch).
//!
//! Three modes for the complete signature lifecycle:
//! - **KeyGen**: Generate a key pair from a server-supplied 32-byte
//!   `seed` plus a 16-byte public-key identifier `i`, both per-test
//!   per spec §8.1.2 Table 8. Returns `pk` per spec §9.1 Table 13.
//! - **SigGen**: Sign messages with an IUT-generated key. **Inverted
//!   protocol model vs ML-DSA / SLH-DSA**: per spec §8.2.1 Table 9
//!   the server prompt has no key information, and §9.2 Table 16
//!   requires the IUT to supply its own `publicKey` at group level
//!   in the response. This is structural for stateful HBS — the
//!   server can't dictate a key for a one-time-leaf scheme. The
//!   handler derives a deterministic per-group seed from `tgId` so
//!   prompt replays produce identical responses.
//! - **SigVer**: Verify a signature against a server-supplied
//!   `publicKey` (group-level per spec §8.3.1 Table 11) and per-test
//!   `message` + `signature` per spec §8.3.2 Table 12.
//!
//! ACVTS time budget note: keyGen and sigGen at H = 25 require a full
//! Merkle-tree walk (2^25 = 33M leaves) per call — minutes per case
//! in debug, ~30 s in release. Run the harness in release mode for
//! ACVTS sessions exercising H ≥ 20 variants.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── KeyGen handler ──────────────────────────────────────────────────

/// LMS KeyGen dispatcher.
pub struct LmsKeyGenHandler;

impl AlgorithmHandler for LmsKeyGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("keyGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_keygen_capability(None))
    }
    fn acvp_capabilities_filtered(&self, caps_filter: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::lms_keygen_capability(caps_filter))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_keygen_group(group)
    }
}

// ── SigGen handler ──────────────────────────────────────────────────

/// LMS SigGen dispatcher.
pub struct LmsSigGenHandler;

impl AlgorithmHandler for LmsSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_siggen_capability(None))
    }
    fn acvp_capabilities_filtered(&self, caps_filter: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::lms_siggen_capability(caps_filter))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── SigVer handler ──────────────────────────────────────────────────

/// LMS SigVer dispatcher.
pub struct LmsSigVerHandler;

impl AlgorithmHandler for LmsSigVerHandler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_capability(None))
    }
    fn acvp_capabilities_filtered(&self, caps_filter: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_capability(caps_filter))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sigver_group(group)
    }
}

// ── Per-pair dispatch helpers ───────────────────────────────────────
//
// Each helper takes the group's `(lmsMode, lmOtsMode)` strings and
// routes to the per-pair module's typed functions. Different pairs
// have different `PUBLIC_KEY_LEN` / `SIGNATURE_LEN` array sizes; the
// helpers normalize to `Vec<u8>` at the response boundary.

#[allow(clippy::too_many_lines)]
fn dispatch_keygen(
    lms_mode: &str,
    lmots_mode: &str,
    seed_bytes: &[u8],
    identifier: &[u8; 16],
) -> Result<Vec<u8>, DispatchError> {
    let pk: Vec<u8> = match (lms_mode, lmots_mode) {
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W1") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W2") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W4") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W8") => {
            let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 32)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W1") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w1::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W2") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w2::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W4") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w4::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W8") => {
            let seed: [u8; 24] = seed_bytes.try_into().map_err(|_| {
                DispatchError::Crypto("LMS KeyGen: seed length mismatch (expected 24)")
            })?;
            let (_sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w8::keygen_from_parts(&seed, identifier);
            pk.to_vec()
        }
        _ => {
            return Err(DispatchError::Crypto(
                "LMS KeyGen: unsupported (lmsMode, lmOtsMode) pair",
            ));
        }
    };
    Ok(pk)
}

/// SigGen dispatcher — returns `(pk_vec, signer)` where `signer` is a
/// closure that consumes one message and produces its signature bytes.
/// The closure owns the mutable per-pair `LmsSigningKey` — the cached
/// signing key that precomputes the Merkle node table once at
/// construction (`LmsSigningKey::new_internal`, cost ≈ one keygen) and
/// thereafter reads authentication paths from the table, taking
/// per-signature tree cost from O(2^H) to O(H). Output is
/// byte-identical to the free `sign` on the plain `LmsPrivateKey` for
/// the same key state and message; the stateful one-leaf-per-signature
/// contract (q auto-advances from 0, one leaf per call) is unchanged.
/// `LmsSigningKey` has type-distinct `seed` / `identifier` array sizes
/// per pair, so the caller never needs to name the per-pair type at the
/// call site.
type LmsSigner = Box<dyn FnMut(&[u8]) -> Option<Vec<u8>>>;

#[allow(clippy::too_many_lines)]
fn dispatch_siggen(
    lms_mode: &str,
    lmots_mode: &str,
    seed: &[u8; 32],
) -> Result<(Vec<u8>, LmsSigner), DispatchError> {
    let out: (Vec<u8>, LmsSigner) = match (lms_mode, lmots_mode) {
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h5_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h10_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h15_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h20_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m32_h25_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h5_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h10_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h15_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h20_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_sha256_m24_h25_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m32_h5_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h10_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h15_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h20_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m32_h25_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8") => {
            let (mut sk, pk) = oxicrypt_lms::lms_shake_m24_h5_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h10_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h15_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h20_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W1") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w1::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W2") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w2::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W4") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w4::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W8") => {
            let (mut sk, pk) =
                oxicrypt_lms::lms_shake_m24_h25_w8::LmsSigningKey::new_internal(seed);
            let signer: LmsSigner = Box::new(move |msg| sk.sign_internal(msg).map(|s| s.to_vec()));
            (pk.to_vec(), signer)
        }
        _ => {
            return Err(DispatchError::Crypto(
                "LMS SigGen: unsupported (lmsMode, lmOtsMode) pair",
            ));
        }
    };
    Ok(out)
}

/// SigVer dispatcher — returns a closure that verifies one signature
/// against the (already-parsed) per-pair public key. The closure
/// captures a typed `[u8; PUBLIC_KEY_LEN]` per pair, so the caller's
/// per-test loop stays uniform.
type LmsVerifier = Box<dyn Fn(&[u8], &[u8]) -> bool>;

#[allow(clippy::too_many_lines)]
fn dispatch_sigver(
    lms_mode: &str,
    lmots_mode: &str,
    pk_bytes: &[u8],
) -> Result<LmsVerifier, DispatchError> {
    let verifier: LmsVerifier =
        match (lms_mode, lmots_mode) {
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h5_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h5_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h5_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h5_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h10_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h10_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h10_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h10_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h15_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h15_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h15_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h15_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h20_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h20_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h20_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h20_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h25_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h25_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h25_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m32_h25_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h5_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h5_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h5_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h5_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h10_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h10_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h10_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h10_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h15_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h15_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h15_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h15_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h20_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h20_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h20_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h20_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h25_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h25_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h25_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_sha256_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_sha256_m24_h25_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h5_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h5_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h5_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h5_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h10_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h10_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h10_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h10_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h15_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h15_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h15_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h15_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h20_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h20_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h20_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h20_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h25_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h25_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h25_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m32_h25_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h5_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h5_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h5_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h5_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h10_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h10_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h10_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h10_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h15_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h15_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h15_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h15_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h20_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h20_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h20_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h20_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W1") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h25_w1::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W2") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h25_w2::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W4") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h25_w4::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W8") => {
                let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
                Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                    <[u8; oxicrypt_lms::lms_shake_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                        .is_ok_and(|sig| {
                            oxicrypt_lms::lms_shake_m24_h25_w8::verify_internal(&pk, msg, &sig)
                        })
                })
            }
            _ => {
                return Err(DispatchError::Crypto(
                    "LMS SigVer: unsupported (lmsMode, lmOtsMode) pair",
                ));
            }
        };
    Ok(verifier)
}

// ── KeyGen group driver ─────────────────────────────────────────────

fn handle_keygen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "AFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let lms_mode = group
        .get("lmsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmsMode"))?;
    let lmots_mode = group
        .get("lmOtsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmOtsMode"))?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        // Per draft-celi-acvp-lms §8.1.2 Table 8 the LMS keyGen test
        // case carries both the OTS `seed` and the public-key
        // identifier `i`. Their lengths are family-and-N-specific;
        // the dispatcher validates them against the per-pair sizes
        // at the typed match arm boundary.
        let seed_bytes = hex::decode(
            t.get("seed")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("seed"))?,
        )?;

        let i_bytes = hex::decode(
            t.get("i")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("i"))?,
        )?;
        let identifier: [u8; 16] = i_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DispatchError::Crypto("LMS KeyGen: i is not 16 bytes"))?;

        let pk = dispatch_keygen(lms_mode, lmots_mode, &seed_bytes, &identifier)?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "publicKey".to_string(),
                JsonValue::String(hex::encode_upper(&pk)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigGen group driver ─────────────────────────────────────────────

/// Derive a deterministic 32-byte seed from a test group's `tgId`.
fn lms_siggen_seed_from_tg_id(tg_id: i64) -> Result<[u8; 32], DispatchError> {
    const PREFIX: &[u8; 28] = b"oxicrypt-lms-acvp-handler-tg";
    let tg_u32 = u32::try_from(tg_id).map_err(|_| {
        DispatchError::Crypto("LMS SigGen: tgId is out of range for u32 seed derivation")
    })?;
    let mut seed = [0u8; 32];
    seed[..28].copy_from_slice(PREFIX);
    seed[28..32].copy_from_slice(&tg_u32.to_be_bytes());
    Ok(seed)
}

fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "AFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let lms_mode = group
        .get("lmsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmsMode"))?;
    let lmots_mode = group
        .get("lmOtsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmOtsMode"))?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let seed = lms_siggen_seed_from_tg_id(tg_id)?;
    let (pk, mut signer) = dispatch_siggen(lms_mode, lmots_mode, &seed)?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;

        let sig = signer(&message).ok_or(DispatchError::Crypto(
            "LMS SigGen: signing failed (key exhausted?)",
        ))?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "signature".to_string(),
                JsonValue::String(hex::encode_upper(&sig)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        (
            "publicKey".to_string(),
            JsonValue::String(hex::encode_upper(&pk)),
        ),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── SigVer group driver ─────────────────────────────────────────────

fn handle_sigver_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "AFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let lms_mode = group
        .get("lmsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmsMode"))?;
    let lmots_mode = group
        .get("lmOtsMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("lmOtsMode"))?;

    let pk_bytes = hex::decode(
        group
            .get("publicKey")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("publicKey"))?,
    )?;

    let verifier = dispatch_sigver(lms_mode, lmots_mode, &pk_bytes)?;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let message = hex::decode(
            t.get("message")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("message"))?,
        )?;

        let sig_bytes = hex::decode(
            t.get("signature")
                .and_then(JsonValue::as_str)
                .ok_or(DispatchError::MissingField("signature"))?,
        )?;

        let passed = verifier(&message, &sig_bytes);

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            ("testPassed".to_string(), JsonValue::Bool(passed)),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}
