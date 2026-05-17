//! Hash-adapter shims that present a uniform `(new_internal, update,
//! finalize) -> [u8; N]` API across the four hash families used by the
//! LMS grid (RFC 8554 + RFC 8708 + SP 800-208).
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
//! | `Sha256N32`    | SHA-256   | 32 | RFC 8554 §A (LMS_SHA256_M32) |
//! | `Sha256N24`    | SHA-256   | 24 | RFC 8708 §4.1 (LMS_SHA256_M24) |
//! | `Shake256N32`  | SHAKE-256 | 32 | RFC 8708 §3.1 (LMS_SHAKE_M32) |
//! | `Shake256N24`  | SHAKE-256 | 24 | RFC 8708 §4.2 (LMS_SHAKE_M24) |
//!
//! All four adapters now ship — `Sha256N32` from B1, `Sha256N24` plus
//! `Shake256N{32,24}` from B3. Together they cover the full SP 800-208
//! LMS grid: 4 family-and-N shapes × 5 heights × 4 Winternitz = 80
//! pairs.

#![allow(dead_code)]

use oxicrypt_sha::sha256::Sha256;
use oxicrypt_xof::Shake256;

/// SHA-256 / N=32 adapter — the legacy LMS family from RFC 8554.
///
/// Wraps `oxicrypt_sha::sha256::Sha256` to expose a uniform shape that
/// the `lms_impl!` macro can call without family-specific branches.
pub struct Sha256N32 {
    inner: Sha256,
}

impl Sha256N32 {
    /// Construct an adapter that bypasses the module gate, matching
    /// `Sha256::new_internal`. LMS keygen/sign/verify call the LMS
    /// gate themselves before invoking the hasher; the adapter must
    /// not double-gate.
    pub fn new_internal() -> Self {
        Self {
            inner: Sha256::new_internal(),
        }
    }

    /// Absorb `data` into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize()
    }
}

/// SHA-256 / N=24 adapter — RFC 8708 §4.1 (LMS_SHA256_M24).
///
/// Computes SHA-256 of the input and returns the **first 24 bytes** of
/// the 32-byte digest. RFC 8708 §4.1: *"SHA-256/192 is the SHA-256 hash
/// function with its output truncated to the leftmost 192 bits"*. The
/// LMS / LM-OTS construction is identical to the N=32 case except for
/// this truncation.
pub struct Sha256N24 {
    inner: Sha256,
}

impl Sha256N24 {
    /// Construct an adapter that bypasses the module gate.
    pub fn new_internal() -> Self {
        Self {
            inner: Sha256::new_internal(),
        }
    }

    /// Absorb `data` into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the **first 24 bytes** of the SHA-256 digest.
    pub fn finalize(self) -> [u8; 24] {
        let full = self.inner.finalize();
        let mut out = [0u8; 24];
        out.copy_from_slice(&full[..24]);
        out
    }
}

/// SHAKE-256 / N=32 adapter — RFC 8708 §3.1 (LMS_SHAKE_M32).
///
/// Squeezes 32 bytes of SHAKE-256 output. RFC 8708 §3.1 specifies
/// SHAKE-256 as the hash for the SHAKE LMS family at 32-byte output
/// length; the squeeze is unkeyed and consumes the absorbed input as
/// a single message.
pub struct Shake256N32 {
    inner: Shake256,
}

impl Shake256N32 {
    /// Construct an adapter that bypasses the module gate.
    pub fn new_internal() -> Self {
        Self {
            inner: Shake256::new_internal(),
        }
    }

    /// Absorb `data` into the sponge.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the absorb phase and squeeze 32 bytes of output.
    pub fn finalize(mut self) -> [u8; 32] {
        self.inner.finalize();
        let mut out = [0u8; 32];
        self.inner.squeeze(&mut out);
        out
    }
}

/// SHAKE-256 / N=24 adapter — RFC 8708 §4.2 (LMS_SHAKE_M24).
///
/// Squeezes **24 bytes** of SHAKE-256 output. The shorter squeeze
/// length is the only structural difference from the N=32 SHAKE
/// adapter — SHAKE's variable-output construction makes the
/// truncation native rather than a post-hoc trim.
pub struct Shake256N24 {
    inner: Shake256,
}

impl Shake256N24 {
    /// Construct an adapter that bypasses the module gate.
    pub fn new_internal() -> Self {
        Self {
            inner: Shake256::new_internal(),
        }
    }

    /// Absorb `data` into the sponge.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the absorb phase and squeeze 24 bytes of output.
    pub fn finalize(mut self) -> [u8; 24] {
        self.inner.finalize();
        let mut out = [0u8; 24];
        self.inner.squeeze(&mut out);
        out
    }
}
