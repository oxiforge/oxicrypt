//! Hash-adapter shims that present a uniform `(new_internal, update,
//! finalize)` API across the four hash families used by the
//! LMS grid (SP 800-208 §4.1–§4.4).
//!
//! Each adapter is a concrete type with a fixed output length, so the
//! `lms_impl!` macro can take the adapter as a `:path` parameter and
//! treat `[u8; N]` as a closed-form output size at every call site.
//! This is what lets the LMS macro stay single-layer: family-and-N
//! dispatch happens at adapter selection (one `:path` arg in the
//! per-pair file), never inside a nested sub-macro with a `:literal`
//! arm.
//!
//! Lints: adapters wrap workspace hashers whose lint posture is already
//! conservative. No new index-dependent or arithmetic-on-secrets code
//! is introduced here.
//!
//! # Family map
//!
//! | Adapter        | Family    | N  | Spec source                |
//! |----------------|-----------|----|----------------------------|
//! | `Sha256N32`    | SHA-256   | 32 | SP 800-208 §4.1 (LMS_SHA256_M32) |
//! | `Sha256N24`    | SHA-256   | 24 | SP 800-208 §4.2 (LMS_SHA256_M24) |
//! | `Shake256N32`  | SHAKE-256 | 32 | SP 800-208 §4.3 (LMS_SHAKE_M32) |
//! | `Shake256N24`  | SHAKE-256 | 24 | SP 800-208 §4.4 (LMS_SHAKE_M24) |
//!
//! Together the four adapters cover the full SP 800-208 LMS grid:
//! 4 family-and-N shapes × 5 heights × 4 Winternitz = 80 pairs.

#![allow(dead_code)]

use oxicrypt_module::{Error, require_self_test_started};
use oxicrypt_sha::sha256::Sha256;
use oxicrypt_xof::Shake256;

/// SHA-256 / N=32 adapter — SP 800-208 §4.1 (LMS_SHA256_M32), defined in RFC 8554.
///
/// Wraps `oxicrypt_sha::sha256::Sha256` to expose a uniform shape that
/// the `lms_impl!` macro can call without family-specific branches.
pub struct Sha256N32 {
    inner: Sha256,
}

impl Sha256N32 {
    /// Construct an adapter without the operational and profile gates.
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests.
    pub fn new_internal() -> Result<Self, Error> {
        require_self_test_started()?;
        Ok(Self {
            inner: Sha256::new_internal()?,
        })
    }

    /// Absorb `data` into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call: in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests.
    pub fn finalize(self) -> Result<[u8; 32], Error> {
        require_self_test_started()?;
        self.inner.finalize()
    }
}

/// SHA-256 / N=24 adapter — SP 800-208 §4.2 (LMS_SHA256_M24).
///
/// Computes SHA-256 of the input and returns the **first 24 bytes** of
/// the 32-byte digest: SHA-256/192 in SP 800-208 §4.2 is SHA-256 with
/// its output truncated to the leftmost 192 bits (`T192`, §2.3). The
/// LMS / LM-OTS construction is identical to the N=32 case except for
/// this truncation.
pub struct Sha256N24 {
    inner: Sha256,
}

impl Sha256N24 {
    /// Construct an adapter without the operational and profile gates.
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests.
    pub fn new_internal() -> Result<Self, Error> {
        require_self_test_started()?;
        Ok(Self {
            inner: Sha256::new_internal()?,
        })
    }

    /// Absorb `data` into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the **first 24 bytes** of the SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call: in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests.
    pub fn finalize(self) -> Result<[u8; 24], Error> {
        require_self_test_started()?;
        let full = self.inner.finalize()?;
        let mut out = [0u8; 24];
        out.copy_from_slice(&full[..24]);
        Ok(out)
    }
}

/// SHAKE-256 / N=32 adapter — SP 800-208 §4.3 (LMS_SHAKE_M32).
///
/// Squeezes 32 bytes of SHAKE-256 output. SP 800-208 §4.3 specifies
/// SHAKE256 as the hash for the SHAKE LMS family at 32-byte output
/// length; the squeeze is unkeyed and consumes the absorbed input as
/// a single message.
pub struct Shake256N32 {
    inner: Shake256,
}

impl Shake256N32 {
    /// Construct an adapter without the operational and profile gates.
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests.
    pub fn new_internal() -> Result<Self, Error> {
        require_self_test_started()?;
        Ok(Self {
            inner: Shake256::new_internal()?,
        })
    }

    /// Absorb `data` into the sponge.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the absorb phase and squeeze 32 bytes of output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call: in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests.
    pub fn finalize(mut self) -> Result<[u8; 32], Error> {
        require_self_test_started()?;
        self.inner.finalize();
        let mut out = [0u8; 32];
        self.inner.squeeze(&mut out)?;
        Ok(out)
    }
}

/// SHAKE-256 / N=24 adapter — SP 800-208 §4.4 (LMS_SHAKE_M24).
///
/// Squeezes **24 bytes** of SHAKE-256 output. The shorter squeeze
/// length is the only structural difference from the N=32 SHAKE
/// adapter — SHAKE's variable-output construction makes the
/// truncation native rather than a post-hoc trim.
pub struct Shake256N24 {
    inner: Shake256,
}

impl Shake256N24 {
    /// Construct an adapter without the operational and profile gates.
    ///
    /// Returns [`Error::NotOperational`] unless [`require_self_test_started`]
    /// admits the call: in `Operational`, or in `SelfTest` on the thread
    /// running the power-up self-tests.
    pub fn new_internal() -> Result<Self, Error> {
        require_self_test_started()?;
        Ok(Self {
            inner: Shake256::new_internal()?,
        })
    }

    /// Absorb `data` into the sponge.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the absorb phase and squeeze 24 bytes of output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call: in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests.
    pub fn finalize(mut self) -> Result<[u8; 24], Error> {
        require_self_test_started()?;
        self.inner.finalize();
        let mut out = [0u8; 24];
        self.inner.squeeze(&mut out)?;
        Ok(out)
    }
}
