//! DRBG health tests — NIST SP 800-90A Rev. 1 §11.3.
//!
//! §11.3 requires known-answer testing of the instantiate (§11.3.2),
//! generate (§11.3.3) and reseed (§11.3.4) functions. It also states
//! that error-handling testing is *not* required, and §11.3.5 that
//! uninstantiate testing is not required.
//!
//! This module adds error-path checks beyond that requirement:
//! generate-before-instantiate, the reseed-counter ceiling, and access
//! after uninstantiate. It is
//! deliberately light on valid-input coverage because every DRBG
//! mechanism in this crate already has a CAVP KAT wired into the
//! power-up test set.
//!
//! The individual health checks are aggregated into one per-mechanism
//! `SelfTestFailure`-returning function so they can be plugged into
//! the power-up KAT runner alongside the value-level KATs.
//!
//! [`kat`]: crate::kat

#![allow(clippy::indexing_slicing)]

use oxicrypt_module::SelfTestFailure;

use crate::ctr::{CtrDrbgAes128, DrbgError};
use crate::hash::HashDrbgSha256;
use crate::hmac::HmacDrbgSha256;

/// Minimal entropy blob large enough for any of the mechanisms we
/// drive here. Values are arbitrary (health tests do not need to
/// match any published vector).
const ENTROPY_32: [u8; 32] = [0x5au8; 32];
const NONCE_16: [u8; 16] = [0xa5u8; 16];

/// Exercise CTR_DRBG (AES-128, `use df`) error paths. SP 800-90A does
/// not require error-path testing; these checks are additional assurance.
///
/// # Checks
///
/// 1. `generate_df` on an uninstantiated instance returns
///    `DrbgError::Uninstantiated`.
/// 2. After a clean `instantiate_df`, a normal `generate_df` succeeds.
/// 3. Forcing the internal reseed counter above the SP 800-90A limit
///    makes the next `generate_df` return `DrbgError::ReseedRequired`.
/// 4. `uninstantiate` clears state such that `generate_df` returns
///    `DrbgError::Uninstantiated` again.
pub fn run_ctr_drbg_health() -> Result<(), SelfTestFailure> {
    let mut drbg = CtrDrbgAes128::new();
    let mut out = [0u8; 16];

    // Check (1): generate before instantiate.
    match drbg.generate_df(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    // Check (2): normal instantiate + generate.
    // Use `instantiate_df_internal` because this function runs during
    // power-up self-tests, when the module is in `SelfTest` state and
    // `require_operational()` would reject the gated public API.
    drbg.instantiate_df_internal(&ENTROPY_32[..16], &NONCE_16[..8], &[])
        .map_err(|_| SelfTestFailure)?;
    drbg.generate_df(None, &mut out)
        .map_err(|_| SelfTestFailure)?;

    // Check (3): force reseed-counter ceiling and confirm the DRBG
    // refuses to continue generating.
    drbg.debug_force_reseed_ceiling();
    match drbg.generate_df(None, &mut out) {
        Err(DrbgError::ReseedRequired) => {}
        _ => return Err(SelfTestFailure),
    }

    // Check (4): uninstantiate clears state.
    drbg.uninstantiate();
    match drbg.generate_df(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    Ok(())
}

/// Exercise Hash_DRBG (SHA-256) error paths. SP 800-90A does not require
/// error-path testing; these checks are additional assurance.
pub fn run_hash_drbg_health() -> Result<(), SelfTestFailure> {
    let mut drbg = HashDrbgSha256::new();
    let mut out = [0u8; 16];

    match drbg.generate(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    // Use `instantiate_internal` — runs during self-test, module not yet Operational.
    drbg.instantiate_internal(&ENTROPY_32, &NONCE_16, &[])
        .map_err(|_| SelfTestFailure)?;
    drbg.generate(None, &mut out).map_err(|_| SelfTestFailure)?;

    drbg.debug_force_reseed_ceiling();
    match drbg.generate(None, &mut out) {
        Err(DrbgError::ReseedRequired) => {}
        _ => return Err(SelfTestFailure),
    }

    drbg.uninstantiate();
    match drbg.generate(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    Ok(())
}

/// Exercise HMAC_DRBG (HMAC-SHA-256) error paths. SP 800-90A does not
/// require error-path testing; these checks are additional assurance.
pub fn run_hmac_drbg_health() -> Result<(), SelfTestFailure> {
    let mut drbg = HmacDrbgSha256::new();
    let mut out = [0u8; 16];

    match drbg.generate(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    // Use `instantiate_internal` — runs during self-test, module not yet Operational.
    drbg.instantiate_internal(&ENTROPY_32, &NONCE_16, &[])
        .map_err(|_| SelfTestFailure)?;
    drbg.generate(None, &mut out).map_err(|_| SelfTestFailure)?;

    drbg.debug_force_reseed_ceiling();
    match drbg.generate(None, &mut out) {
        Err(DrbgError::ReseedRequired) => {}
        _ => return Err(SelfTestFailure),
    }

    drbg.uninstantiate();
    match drbg.generate(None, &mut out) {
        Err(DrbgError::Uninstantiated) => {}
        _ => return Err(SelfTestFailure),
    }

    Ok(())
}
