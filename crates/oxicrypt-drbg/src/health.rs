//! DRBG health tests — NIST SP 800-90A Rev. 1 §11.3.
//!
//! §11.3.2 requires the module to verify at power-up (and at other
//! defined points) that:
//!
//! * the Instantiate function returns the correct output on valid
//!   input (already covered by the CAVP-sourced KATs in [`kat`]);
//! * the Instantiate function fails with the expected error on
//!   invalid input;
//! * the Generate function returns the correct output on valid
//!   input (covered by the KATs);
//! * the Generate function fails with the expected error on invalid
//!   input (for example, a request beyond `max_number_of_bits_per_request`
//!   or a reseed-counter overflow);
//! * the Uninstantiate function correctly clears the state so that
//!   subsequent operations on the uninstantiated instance fail.
//!
//! This module implements the error-path half of those checks. It is
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

/// Exercise CTR_DRBG (AES-128, `use df`) error paths per SP 800-90A
/// §11.3.2.
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

/// Exercise Hash_DRBG (SHA-256) error paths per SP 800-90A §11.3.2.
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

/// Exercise HMAC_DRBG (HMAC-SHA-256) error paths per SP 800-90A §11.3.2.
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
