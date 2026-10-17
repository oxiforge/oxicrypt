//! LMS ACVP handlers — `sigVer` mode.
//!
//! **LMS** (`LMS` / `sigVer` / revisions `1.0` and `SP800-208`):
//! verification of stateful hash-based signatures per SP 800-208
//! §4.1–§4.4 (RFC 8554, RFC 9858). The full 80-pair grid is dispatchable
//! — 4 hash families × 5 tree heights × 4 Winternitz parameters. Each
//! group's `(lmsMode, lmOtsMode)` strings route to the per-pair
//! `oxicrypt_lms` module via a closed-form match (no runtime trait
//! dispatch).
//!
//! **SigVer** verifies a signature against a server-supplied `publicKey`
//! (group-level per spec §8.3.1 Table 11) and per-test `message` +
//! `signature` per spec §8.3.2 Table 12.
//!
//! There are no keyGen or sigGen handlers. SP 800-208 §8.1 confines LMS
//! key generation and signing to hardware modules, and FIPS 140-3 IG C.N
//! resolutions 6 and 9 rule them out of a software module.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

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

/// LMS SigVer dispatcher for the `SP800-208` revision.
///
/// The registry keys on `(algorithm, mode, revision)`, so this sits
/// alongside [`LmsSigVerHandler`] (revision `1.0`) rather than
/// replacing it — the server advertises both.
///
/// The `SP800-208` revision differs only in declaring a `messageLength`
/// domain (variable-length messages); the verification work is
/// identical, so the group handler is shared. `handle_sigver_group`
/// decodes `message` per test case with no fixed-length assumption.
pub struct LmsSigVerSp800208Handler;

impl AlgorithmHandler for LmsSigVerSp800208Handler {
    fn algorithm(&self) -> &'static str {
        "LMS"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigVer")
    }
    fn revision(&self) -> &'static str {
        "SP800-208"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_sp800_208_capability(None))
    }
    fn acvp_capabilities_filtered(&self, caps_filter: Option<&str>) -> Option<JsonValue> {
        Some(super::caps::lms_sigver_sp800_208_capability(caps_filter))
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

/// SigVer dispatcher — returns a closure that verifies one signature
/// against the (already-parsed) per-pair public key. The closure
/// captures a typed `[u8; PUBLIC_KEY_LEN]` per pair, so the caller's
/// per-test loop stays uniform. It returns `None` when the signature is
/// not the pair's `SIGNATURE_LEN`; the caller grades that test case as
/// failed, as it does a signature whose typecodes are not the pair's. A
/// refusal from the module is an error, not a verdict.
type LmsVerifier = Box<dyn Fn(&[u8], &[u8]) -> Option<Result<bool, oxicrypt_module::Error>>>;

#[allow(clippy::too_many_lines)]
fn dispatch_sigver(
    lms_mode: &str,
    lmots_mode: &str,
    pk_bytes: &[u8],
) -> Result<LmsVerifier, DispatchError> {
    let verifier: LmsVerifier = match (lms_mode, lmots_mode) {
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h5_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h5_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h5_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h5_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h10_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h10_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h10_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h10_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h15_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h15_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h15_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h15_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h20_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h20_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h20_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h20_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h25_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h25_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h25_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m32_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m32_h25_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h5_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h5_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h5_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h5_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h5_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h10_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h10_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h10_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h10_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h15_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h15_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h15_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h15_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h20_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h20_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h20_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h20_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h25_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h25_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h25_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_sha256_m24_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_sha256_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_sha256_m24_h25_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w1::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h5_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w2::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h5_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w4::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h5_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h5_w8::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h5_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h10_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h10_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h10_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h10_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h15_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h15_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h15_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h15_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h20_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h20_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h20_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h20_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h25_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h25_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h25_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m32_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m32_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m32_h25_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w1::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h5_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h5_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w2::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h5_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h5_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w4::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h5_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h5_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h5_w8::PUBLIC_KEY_LEN] =
                pk_bytes
                    .try_into()
                    .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h5_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h5_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h10_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h10_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h10_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h10_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h10_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h10_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h10_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h10_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h10_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h15_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h15_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h15_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h15_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h15_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h15_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h15_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h15_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h15_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h20_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h20_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h20_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h20_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h20_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h20_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h20_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h20_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h20_w8::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W1") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w1::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h25_w1::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h25_w1::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W2") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w2::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h25_w2::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h25_w2::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W4") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w4::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h25_w4::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h25_w4::verify_internal(&pk, msg, &sig))
            })
        }
        ("LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W8") => {
            let pk: [u8; oxicrypt_lms::lms_shake_m24_h25_w8::PUBLIC_KEY_LEN] = pk_bytes
                .try_into()
                .map_err(|_| DispatchError::Crypto("LMS SigVer: publicKey has wrong length"))?;
            Box::new(move |msg: &[u8], sig_bytes: &[u8]| {
                <[u8; oxicrypt_lms::lms_shake_m24_h25_w8::SIGNATURE_LEN]>::try_from(sig_bytes)
                    .ok()
                    .map(|sig| oxicrypt_lms::lms_shake_m24_h25_w8::verify_internal(&pk, msg, &sig))
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

        // A signature of the wrong length for the pair cannot verify, so it
        // fails this test case only, never the whole group.
        let passed = verifier(&message, &sig_bytes).transpose()?.unwrap_or(false);

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
