//! ECDSA with P-256 and SHA-256 per FIPS 186-5 §6.4.
//!
//! Three public entry points:
//!
//!   * [`derive_public_key`] — given a 32-byte private scalar `d`,
//!     compute the uncompressed SEC1 public key `[04 || X || Y]`.
//!     This is not a full FIPS keygen (which layers rejection
//!     sampling on top of an approved DRBG, as
//!     [`EcdsaP256PrivateKey::generate`] does); it is the
//!     deterministic scalar-to-point core.
//!   * [`sign_with_k`] — deterministic sign primitive taking an
//!     externally provided per-message secret `k`. This is the shape
//!     needed by KATs and by a FIPS 186-5 sign routine built on top
//!     of an approved DRBG; it is not RFC 6979 deterministic signing
//!     and must not be called with a reused `k`.
//!   * [`verify`] — verify an `(r, s)` signature against a public key
//!     per FIPS 186-5 §6.4.2.
//!
//! All three public entry points gate on
//! [`oxicrypt_module::require_operational`] so callers cannot invoke the
//! algorithm before the module has finished its power-up KATs
//! (FIPS 140-3 IG D.G, SP 800-140F). The KATs themselves go through
//! the `*_internal` helpers, which skip the gate and therefore run
//! while the module is still in `SelfTest`; they call
//! [`oxicrypt_module::require_self_test_started`] instead, so they
//! refuse in every state other than `SelfTest` and `Operational`. SHA-256 is reached via
//! [`oxicrypt_sha::sha256::Sha256::new_internal`] for the same reason.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use oxicrypt_module::{
    Error, Rbg, SelfTestFailure, Service, require_allowed, require_operational,
    require_self_test_started,
};
use oxicrypt_sha::sha256::Sha256;

use crate::p256_field::Fp;
use crate::p256_keygen::{generate_p256_internal, sample_scalar_internal};
use crate::p256_point::Point;
use crate::p256_scalar::Scalar;

/// Length of a P-256 private-key scalar in bytes.
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of an uncompressed SEC1 public-key encoding
/// (`0x04 || X || Y`).
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of a serialized ECDSA signature `r || s`.
pub const SIGNATURE_LEN: usize = 64;

// ------------------------------------------------------------------
// Raw `*_internal` primitives
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for a private scalar
/// `d_bytes`. Returns [`Error::InvalidInput`] if `d_bytes` does not encode a valid
/// non-zero scalar mod `n`.
///
/// This is the `*_internal` primitive that [`derive_public_key`]
/// wraps; it skips the operational and profile gates so KATs and the
/// power-up self test can call it while the module is still in
/// `SelfTest`.
///
/// Returns [`Error::NotOperational`] when the module refuses the call,
/// which it does in every state other than `SelfTest` and `Operational`.
#[doc(hidden)]
pub fn derive_public_key_internal(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
    require_self_test_started()?;
    derive_public_key_internal_unguarded(d_bytes).ok_or(Error::InvalidInput)
}

/// Body of [`derive_public_key_internal`], run once its guard has passed.
fn derive_public_key_internal_unguarded(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let d = Scalar::from_bytes(d_bytes)?;
    if d.is_zero() == 1 {
        return None;
    }
    let q = Point::generator().mul(&d);
    encode_public_key(&q)
}

/// Sign `msg` under private key `d_bytes` using the explicitly
/// provided per-message secret `k_bytes`. Returns [`Error::InvalidInput`] if any of
/// the inputs are out of range or if the resulting `r` or `s`
/// happens to be zero (caller should retry with a fresh `k`, as
/// FIPS 186-5 §6.4.1 specifies).
///
/// `k` **must** be a fresh secret for every signature — reusing or
/// leaking `k` leaks `d`. That discipline is the caller's
/// responsibility in this layer; [`EcdsaP256PrivateKey::sign_sha256`]
/// draws a fresh `k` from a random bit generator.
///
/// Returns [`Error::NotOperational`] when the module refuses the call,
/// which it does in every state other than `SelfTest` and `Operational`.
#[doc(hidden)]
pub fn sign_with_k_internal(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; 32],
) -> Result<[u8; SIGNATURE_LEN], Error> {
    require_self_test_started()?;
    sign_with_k_internal_unguarded(d_bytes, msg, k_bytes)?.ok_or(Error::InvalidInput)
}

/// Body of [`sign_with_k_internal`], run once its guard has passed.
fn sign_with_k_internal_unguarded(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; 32],
) -> Result<Option<[u8; SIGNATURE_LEN]>, Error> {
    let Some(d) = Scalar::from_bytes(d_bytes) else {
        return Ok(None);
    };
    if d.is_zero() == 1 {
        return Ok(None);
    }
    let Some(k) = Scalar::from_bytes(k_bytes) else {
        return Ok(None);
    };
    if k.is_zero() == 1 {
        return Ok(None);
    }

    // FIPS 186-5 §6.4.1: e from SHA-256(msg), r = x(k·G) mod n,
    // s = k⁻¹(e + r·d) mod n.
    let e = hash_message_to_scalar(msg)?;

    let big_r = Point::generator().mul(&k);
    let Some((x1, _y1)) = big_r.to_affine() else {
        return Ok(None);
    };
    let x1_bytes = x1.to_bytes();
    let r = Scalar::from_bytes_reduced(&x1_bytes);
    if r.is_zero() == 1 {
        return Ok(None);
    }

    let k_inv = k.invert();
    let rd = r.mul(&d);
    let sum = e.add(&rd);
    let s = k_inv.mul(&sum);
    if s.is_zero() == 1 {
        return Ok(None);
    }

    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..32].copy_from_slice(&r.to_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    Ok(Some(sig))
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2. Returns `true`
/// iff `sig` is a valid signature of `msg` under `pk_bytes`.
///
/// Returns [`Error::NotOperational`] unless
/// [`oxicrypt_module::require_self_test_started`] admits the call: in
/// `Operational`, or in `SelfTest` on the thread running the power-up
/// self-tests.
#[doc(hidden)]
pub fn verify_internal(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, Error> {
    require_self_test_started()?;
    verify_internal_unguarded(pk_bytes, msg, sig)
}

/// Body of [`verify_internal`], run once its guard has passed.
fn verify_internal_unguarded(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, Error> {
    // Every temporary lives in `t`, whose `Drop` zeroizes it on each return
    // path, so no intermediate of a verification outlives it (unproven: no
    // test observes the cleared memory).
    let mut t = VerifyTemporaries::new();

    // The steps of FIPS 186-5 §6.4.2, in order.
    // 1. Decode public key.
    t.q = match decode_public_key(pk_bytes) {
        Some(q) => q,
        None => return Ok(false),
    };

    // 2. Parse (r, s) and enforce r, s in [1, n-1].
    t.r_bytes.copy_from_slice(&sig[..32]);
    t.s_bytes.copy_from_slice(&sig[32..]);
    t.r = match Scalar::from_bytes(&t.r_bytes) {
        Some(r) => r,
        None => return Ok(false),
    };
    t.s = match Scalar::from_bytes(&t.s_bytes) {
        Some(s) => s,
        None => return Ok(false),
    };
    if t.r.is_zero() == 1 || t.s.is_zero() == 1 {
        return Ok(false);
    }

    // 3. e = SHA-256(msg) mod n.
    t.e = hash_message_to_scalar(msg)?;

    // 4. w = s^-1 mod n ; u1 = e*w ; u2 = r*w.
    t.w = t.s.invert();
    t.u1 = t.e.mul(&t.w);
    t.u2 = t.r.mul(&t.w);

    // 5. (x1, y1) = u1*G + u2*Q. Reject if the sum is the identity.
    t.p1 = Point::generator().mul(&t.u1);
    t.p2 = t.q.mul(&t.u2);
    t.sum = point_add(&t.p1, &t.p2);
    let Some(mut affine) = t.sum.to_affine() else {
        return Ok(false);
    };
    (t.x1, t.y1) = affine;
    // The coordinates are `Copy`; the copies in `t` are wiped by its `Drop`,
    // and this binding's are wiped here.
    affine.0.wipe();
    affine.1.wipe();

    // 6. Accept iff (x1 mod n) == r.
    t.x1_bytes = t.x1.to_bytes();
    t.x1_mod_n = Scalar::from_bytes_reduced(&t.x1_bytes);
    Ok(t.x1_mod_n.ct_eq(&t.r) == 1)
}

/// The temporaries of [`verify_internal_unguarded`], zeroized when they go
/// out of scope so that none outlives the verification on any path
/// (unproven: no test observes the cleared memory).
struct VerifyTemporaries {
    r_bytes: [u8; 32],
    s_bytes: [u8; 32],
    x1_bytes: [u8; 32],
    r: Scalar,
    s: Scalar,
    e: Scalar,
    w: Scalar,
    u1: Scalar,
    u2: Scalar,
    x1_mod_n: Scalar,
    q: Point,
    p1: Point,
    p2: Point,
    sum: Point,
    x1: Fp,
    y1: Fp,
}

impl VerifyTemporaries {
    const fn new() -> Self {
        Self {
            r_bytes: [0; 32],
            s_bytes: [0; 32],
            x1_bytes: [0; 32],
            r: Scalar::ZERO,
            s: Scalar::ZERO,
            e: Scalar::ZERO,
            w: Scalar::ZERO,
            u1: Scalar::ZERO,
            u2: Scalar::ZERO,
            x1_mod_n: Scalar::ZERO,
            q: Point::identity(),
            p1: Point::identity(),
            p2: Point::identity(),
            sum: Point::identity(),
            x1: Fp::ZERO,
            y1: Fp::ZERO,
        }
    }
}

impl Drop for VerifyTemporaries {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.r_bytes);
        oxicrypt_zeroize::zeroize(&mut self.s_bytes);
        oxicrypt_zeroize::zeroize(&mut self.x1_bytes);
        for scalar in [
            &mut self.r,
            &mut self.s,
            &mut self.e,
            &mut self.w,
            &mut self.u1,
            &mut self.u2,
            &mut self.x1_mod_n,
        ] {
            scalar.wipe();
        }
        for point in [&mut self.q, &mut self.p1, &mut self.p2, &mut self.sum] {
            point.wipe();
        }
        self.x1.wipe();
        self.y1.wipe();
    }
}

// ------------------------------------------------------------------
// Public gated entry points
// ------------------------------------------------------------------

/// Derive the uncompressed SEC1 public key for private scalar `d`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the FIPS module has
/// not completed its power-up self-tests, or
/// [`Error::InvalidInput`] if `d` is not a valid non-zero scalar.
pub fn derive_public_key(d_bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP256Keygen)?;
    derive_public_key_internal(d_bytes)
}

/// Sign `msg` with private key `d` and per-message secret `k`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module has not
/// completed its power-up self-tests, or [`Error::InvalidInput`] if
/// the scalars are out of range or the signing equation produces a
/// zero `r` or `s` (retry with a fresh `k`).
pub fn sign_with_k(
    d_bytes: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    k_bytes: &[u8; 32],
) -> Result<[u8; SIGNATURE_LEN], Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP256Sign)?;
    sign_with_k_internal(d_bytes, msg, k_bytes)
}

/// Verify an ECDSA signature per FIPS 186-5 §6.4.2.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module has not
/// completed its power-up self-tests. A well-formed-but-invalid
/// signature returns `Ok(false)`.
pub fn verify(
    pk_bytes: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool, Error> {
    require_operational()?;
    require_allowed(Service::EcdsaP256Verify)?;
    verify_internal(pk_bytes, msg, sig)
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Hash `msg` with SHA-256 and reduce the resulting 32-byte digest
/// mod `n`. For P-256 the digest width and field width are both 256
/// bits, so FIPS 186-5 §6.4.1's left-truncation step is a no-op and
/// only the modular reduction remains.
fn hash_message_to_scalar(msg: &[u8]) -> Result<Scalar, Error> {
    let mut h = Sha256::new_internal()?;
    h.update(msg);
    let mut digest = h.finalize()?;
    let e = Scalar::from_bytes_reduced(&digest);
    oxicrypt_zeroize::zeroize(&mut digest);
    Ok(e)
}

/// Encode a Jacobian point as the uncompressed SEC1 public-key
/// format `0x04 || X || Y`. Returns `None` if the point is the
/// identity.
fn encode_public_key(q: &Point) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let (ax, ay) = q.to_affine()?;
    let mut out = [0u8; PUBLIC_KEY_LEN];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&ax.to_bytes());
    out[33..65].copy_from_slice(&ay.to_bytes());
    Some(out)
}

/// Decode an uncompressed SEC1 public-key encoding with full SP
/// 800-56Ar3 §5.6.2.3.3 public-key validation. Delegates to
/// [`Point::from_sec1_uncompressed_validated`]; any off-curve or
/// non-canonical input returns `None` and causes `verify` to return
/// `false`.
fn decode_public_key(pk_bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<Point> {
    Point::from_sec1_uncompressed_validated(pk_bytes)
}

/// Sum two Jacobian points by converting the right-hand operand to
/// affine and calling [`Point::add_mixed`]. Only used by `verify`
/// where operand-dependent timing is not a concern (both `u1` and
/// `u2` are derived from public values).
fn point_add(p1: &Point, p2: &Point) -> Point {
    if p2.is_identity() == 1 {
        return *p1;
    }
    let Some((ax, ay)) = p2.to_affine() else {
        return *p1;
    };
    p1.add_mixed(&ax, &ay)
}

// ------------------------------------------------------------------
// EcdsaP256PrivateKey handle (DRBG keygen + PCT + random-k sign)
// ------------------------------------------------------------------

/// Fixed probe message used by the IG 10.3.A pairwise consistency
/// test.
const PCT_PROBE_MSG: &[u8] = b"oxicrypt-ecdsa-p256-pct";

/// The `reason` of a pairwise consistency failure in key generation.
const PCT_REASON: &str = "ECDSA P-256 pairwise consistency";

/// A P-256 ECDSA private key handle that has passed an IG 10.3.A
/// pairwise consistency test at construction time.
///
/// The handle carries both the private scalar `d` and its derived
/// uncompressed SEC1 public key `Q`. The public key stored here is the
/// one the test verified against, so a later call to `sign_sha256` is
/// consistent with `public_key()`.
///
/// Both constructors sign a fixed probe with a nonce drawn from the
/// caller's random bit generator and verify it under the derived public
/// key. A failure in [`Self::generate`] is a conditional self-test
/// failure that puts the module in its error state and produces no
/// handle.
#[derive(Clone)]
pub struct EcdsaP256PrivateKey {
    d: [u8; PRIVATE_KEY_LEN],
    q: [u8; PUBLIC_KEY_LEN],
}

impl EcdsaP256PrivateKey {
    /// Import a private key from its 32-byte scalar representation,
    /// derive the public key, and run the IG 10.3.A pairwise
    /// consistency test, whose nonce is drawn from `drbg`, a random
    /// bit generator implementing [`Rbg`]. Returns
    /// `Error::InvalidInput` if `d` is out of range, if public-key
    /// derivation fails, or if the PCT sign-verify round-trip fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the module has not
    /// completed its power-up self-tests, [`Error::RbgTooWeak`] before
    /// any draw if the random bit generator reports less than
    /// [`crate::p256_keygen::RBG_STRENGTH_BITS`], [`Error::Rbg`] if the random
    /// bit generator produces no output, or [`Error::InvalidInput`] on
    /// any of the construction / PCT failure modes above.
    pub fn from_bytes<R: Rbg>(
        drbg: &mut R,
        d_bytes: &[u8; PRIVATE_KEY_LEN],
    ) -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::EcdsaP256Keygen)?;
        Self::from_bytes_internal(drbg, d_bytes)
    }

    /// Generate a fresh P-256 private key via the FIPS 186-5 §A.2.2
    /// rejection sampler on `drbg`, a random bit generator
    /// implementing [`Rbg`], derive its public key, and run the
    /// IG 10.3.A pairwise consistency test.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the module has not
    /// completed its power-up self-tests, [`Error::RbgTooWeak`] before
    /// any draw if the random bit generator reports less than
    /// [`crate::p256_keygen::RBG_STRENGTH_BITS`], [`Error::Rbg`] if the random
    /// bit generator produces no output, [`Error::InvalidInput`] on
    /// scalar-sampling exhaustion, or [`Error::ConditionalTestFailed`]
    /// with the reason `ECDSA P-256 pairwise consistency` if the pairwise
    /// consistency test fails (ISO/IEC 19790 §7.10.3.3, FIPS 140-3
    /// IG 10.3.A). On that failure the pair is zeroized (unproven: no
    /// test observes the cleared memory) and the module enters its error
    /// state, after which every service returns [`Error::NotOperational`].
    pub fn generate<R: Rbg>(drbg: &mut R) -> Result<Self, Error> {
        let corrupt = crate::take_corrupt_next_pk();
        require_operational()?;
        require_allowed(Service::EcdsaP256Keygen)?;
        Self::generate_internal(drbg, corrupt)
    }

    /// Sign `msg` with SHA-256 under this private key, sampling a
    /// fresh per-signature nonce `k` from `drbg`, a random bit
    /// generator implementing [`Rbg`], via the FIPS 186-5 §A.2.2
    /// rejection sampler. If the sampled `k` produces `r == 0` or
    /// `s == 0` (mathematically possible but astronomically
    /// unlikely), the call retries with a fresh draw up to a small cap.
    /// Each `k` is zeroized after its use, on every exit (unproven: no
    /// test observes the cleared memory).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the module has not
    /// completed its power-up self-tests, [`Error::RbgTooWeak`] before
    /// any draw if the random bit generator reports less than
    /// [`crate::p256_keygen::RBG_STRENGTH_BITS`], [`Error::Rbg`] if the random
    /// bit generator produces no output, or [`Error::InvalidInput`] if
    /// it fails to produce a working `k`.
    pub fn sign_sha256<R: Rbg>(
        &self,
        drbg: &mut R,
        msg: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], Error> {
        require_operational()?;
        require_allowed(Service::EcdsaP256Sign)?;
        self.sign_sha256_internal(drbg, msg)
    }

    /// Return the uncompressed SEC1 public key this handle commits to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call (in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests), so a key built before a failure outputs nothing after it.
    pub fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
        require_self_test_started()?;
        Ok(self.q)
    }

    /// Return a reference to the private scalar bytes. Intended for
    /// callers that need to hand `d` to another approved service
    /// (e.g., ECDH via `oxicrypt-ecdh`). The reference borrows the
    /// handle's own storage; zeroization of any copy the caller makes
    /// is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] unless
    /// [`oxicrypt_module::require_self_test_started`] admits the call (in
    /// `Operational`, or in `SelfTest` on the thread running the power-up
    /// self-tests), so a CSP is not output in `PowerOff`, `Error` or
    /// `IntegrityUnverified`.
    pub fn private_scalar(&self) -> Result<&[u8; PRIVATE_KEY_LEN], Error> {
        require_self_test_started()?;
        Ok(&self.d)
    }

    // -- internal helpers, reached after a gate or guard has passed --

    fn from_bytes_internal<R: Rbg>(
        drbg: &mut R,
        d_bytes: &[u8; PRIVATE_KEY_LEN],
    ) -> Result<Self, Error> {
        let pk = derive_public_key_internal(d_bytes)?;
        let handle = EcdsaP256PrivateKey { d: *d_bytes, q: pk };
        if !handle.pairwise_consistency(drbg)? {
            return Err(Error::InvalidInput);
        }
        Ok(handle)
    }

    /// Generates the pair and runs the pairwise consistency test. The
    /// module state is checked again after the test, so a pair is not
    /// returned once another thread has put the module in its error state.
    fn generate_internal<R: Rbg>(
        drbg: &mut R,
        #[cfg_attr(not(any(test, feature = "fault-injection")), allow(unused_variables))]
        corrupt: bool,
    ) -> Result<Self, Error> {
        let (mut d, q) = generate_p256_internal(drbg)?;
        #[cfg_attr(not(any(test, feature = "fault-injection")), allow(unused_mut))]
        let mut handle = EcdsaP256PrivateKey { d, q };
        oxicrypt_zeroize::zeroize(&mut d);
        #[cfg(any(test, feature = "fault-injection"))]
        if corrupt {
            handle.q[1] ^= 0xFF;
        }
        if !handle.pairwise_consistency(drbg)? {
            return Err(handle.pairwise_consistency_failed());
        }
        require_operational()?;
        Ok(handle)
    }

    /// The pairwise consistency test (ISO/IEC 19790 §7.10.3.3, FIPS 140-3
    /// IG 10.3.A): signs [`PCT_PROBE_MSG`] with a nonce drawn from `drbg`
    /// and verifies the signature under the handle's public key. `false`
    /// when the signature does not verify, or when no nonce within
    /// [`MAX_SIGN_RETRIES`] draws yields a signature. Each nonce is
    /// zeroized after its use (unproven: no test observes the cleared
    /// memory).
    fn pairwise_consistency<R: Rbg>(&self, drbg: &mut R) -> Result<bool, Error> {
        for _ in 0..MAX_SIGN_RETRIES {
            let mut k = sample_scalar_internal(drbg)?;
            let signed = sign_with_k_internal(&self.d, PCT_PROBE_MSG, &k);
            oxicrypt_zeroize::zeroize(&mut k);
            match signed {
                Ok(sig) => return verify_internal(&self.q, PCT_PROBE_MSG, &sig),
                // A zero `r` or `s`: FIPS 186-5 §6.4.1 draws a fresh `k`.
                Err(Error::InvalidInput) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    /// Wipes both halves of a generated pair that failed the pairwise
    /// consistency test (unproven: no test observes the cleared memory),
    /// then puts the module in its error state (ISO/IEC 19790 §7.10.3.3,
    /// FIPS 140-3 IG 10.3.A), and returns the error to report.
    fn pairwise_consistency_failed(mut self) -> Error {
        oxicrypt_zeroize::zeroize(&mut self.q);
        drop(self);
        oxicrypt_module::enter_error_state(PCT_REASON);
        Error::ConditionalTestFailed { reason: PCT_REASON }
    }

    fn sign_sha256_internal<R: Rbg>(
        &self,
        drbg: &mut R,
        msg: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], Error> {
        for _ in 0..MAX_SIGN_RETRIES {
            let mut k = sample_scalar_internal(drbg)?;
            let signed = sign_with_k_internal(&self.d, msg, &k);
            oxicrypt_zeroize::zeroize(&mut k);
            match signed {
                Ok(sig) => return Ok(sig),
                // A zero `r` or `s`: FIPS 186-5 §6.4.1 draws a fresh `k`.
                Err(Error::InvalidInput) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::InvalidInput)
    }
}

impl Drop for EcdsaP256PrivateKey {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.d);
    }
}

/// Bound on the number of fresh-`k` retries inside a single sign
/// (or PCT) call. With P-256 the probability that any one draw
/// yields `r == 0` or `s == 0` is on the order of `2^(−256)`, so a
/// chain of 8 failures is a DRBG fault, not bad luck.
const MAX_SIGN_RETRIES: usize = 8;

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// Private key `d` from RFC 6979 §A.2.5 (P-256, SHA-256).
const KAT_D: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];

/// Per-message secret `k` from RFC 6979 §A.2.5 (P-256, SHA-256,
/// message "sample"). Not derived via RFC 6979's HMAC construction
/// in this code — the value is pinned here and the sign primitive
/// consumes it as given.
const KAT_K: [u8; 32] = [
    0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd, 0x4c,
    0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60,
];

/// KAT message: the ASCII bytes of "sample", per RFC 6979 §A.2.5.
const KAT_MSG: &[u8] = b"sample";

/// Expected uncompressed SEC1 public key for [`KAT_D`]: `U` from
/// RFC 6979 §A.2.5.
const KAT_PUBLIC_KEY: [u8; 65] = [
    0x04, //
    // Ux
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    // Uy
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
];

/// Expected `r || s` signature for `(KAT_D, KAT_MSG, KAT_K)`.
const KAT_SIGNATURE: [u8; 64] = [
    // r
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
    // s
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
];

/// Power-up known-answer test for ECDSA P-256 / SHA-256. Runs the
/// RFC 6979 §A.2.5 "sample" vector through all three primitives
/// (public-key derivation, sign with fixed `k`, verify) and checks a
/// tampered signature is rejected. Wired into the module state
/// machine via a [`oxicrypt_module::KatEntry`].
pub fn self_test() -> Result<(), SelfTestFailure> {
    let pk = derive_public_key_internal(&KAT_D).map_err(|_| SelfTestFailure)?;
    if pk != KAT_PUBLIC_KEY {
        return Err(SelfTestFailure);
    }
    let sig = sign_with_k_internal(&KAT_D, KAT_MSG, &KAT_K).map_err(|_| SelfTestFailure)?;
    if sig != KAT_SIGNATURE {
        return Err(SelfTestFailure);
    }
    if !verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE).map_err(|_| SelfTestFailure)? {
        return Err(SelfTestFailure);
    }

    let mut tampered = KAT_SIGNATURE;
    tampered[0] ^= 0x01;
    if verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered).map_err(|_| SelfTestFailure)? {
        return Err(SelfTestFailure);
    }

    Ok(())
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use oxicrypt_module::KatEntry;

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

    fn init_with_tests(tests: &[KatEntry]) -> Result<(), oxicrypt_module::Error> {
        oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, tests)
    }

    /// Brings the module out of `PowerOff` so that a test can call the
    /// `*_internal` functions, which refuse until the self-tests have
    /// started. A second call in the same process is a no-op.
    fn start_module() {
        let _ = init_with_tests(&[]);
        assert_eq!(oxicrypt_module::require_self_test_started(), Ok(()));
    }

    #[test]
    fn kat_public_key_matches_rfc6979() {
        start_module();
        let pk = derive_public_key_internal(&KAT_D).unwrap();
        assert_eq!(pk, KAT_PUBLIC_KEY);
    }

    #[test]
    fn kat_signature_matches_rfc6979() {
        start_module();
        let sig = sign_with_k_internal(&KAT_D, KAT_MSG, &KAT_K).unwrap();
        assert_eq!(sig, KAT_SIGNATURE);
    }

    #[test]
    fn verify_accepts_valid_kat_signature() {
        start_module();
        assert!(verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        start_module();
        let mut tampered = KAT_SIGNATURE;
        tampered[0] ^= 0x01;
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered).unwrap());

        let mut tampered2 = KAT_SIGNATURE;
        tampered2[63] ^= 0x01;
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &tampered2).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        start_module();
        assert!(!verify_internal(&KAT_PUBLIC_KEY, b"not sample", &KAT_SIGNATURE).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        start_module();
        let mut wrong_pk = KAT_PUBLIC_KEY;
        wrong_pk[1] ^= 0x01;
        assert!(!verify_internal(&wrong_pk, KAT_MSG, &KAT_SIGNATURE).unwrap());
    }

    #[test]
    fn verify_rejects_zero_r() {
        start_module();
        let mut sig = KAT_SIGNATURE;
        for b in &mut sig[..32] {
            *b = 0;
        }
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_zero_s() {
        start_module();
        let mut sig = KAT_SIGNATURE;
        for b in &mut sig[32..] {
            *b = 0;
        }
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_r_equal_to_n() {
        start_module();
        let mut sig = KAT_SIGNATURE;
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        sig[..32].copy_from_slice(&n_bytes);
        assert!(!verify_internal(&KAT_PUBLIC_KEY, KAT_MSG, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_pk_with_wrong_header_byte() {
        start_module();
        let mut bad_pk = KAT_PUBLIC_KEY;
        bad_pk[0] = 0x02;
        assert!(!verify_internal(&bad_pk, KAT_MSG, &KAT_SIGNATURE).unwrap());
    }

    #[test]
    fn self_test_passes() {
        start_module();
        self_test().unwrap();
    }

    #[test]
    fn public_api_gated_on_operational() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let pk = derive_public_key(&KAT_D).expect("module operational");
        assert_eq!(pk, KAT_PUBLIC_KEY);
        let sig = sign_with_k(&KAT_D, KAT_MSG, &KAT_K).expect("sign ok");
        assert_eq!(sig, KAT_SIGNATURE);
        assert!(verify(&KAT_PUBLIC_KEY, KAT_MSG, &KAT_SIGNATURE).expect("verify ok"));
    }

    // --------------------------------------------------------------
    // DRBG-backed keygen + PCT + random-k sign
    // --------------------------------------------------------------

    fn pct_drbg(personalization: &[u8]) -> oxicrypt_drbg::HmacDrbgSha256 {
        oxicrypt_drbg::HmacDrbgSha256::instantiate_from_module(personalization)
            .expect("drbg instantiates")
    }

    /// Two consecutive 32-byte generate calls, with no additional
    /// input, of HMAC_DRBG-SHA-256 (SP 800-90A Rev. 1 §10.1.2): the
    /// scalar `d` keygen draws, then the nonce `k` its pairwise
    /// consistency test draws. The instance is instantiated from the
    /// ASCII bytes of `oxicrypt-r7-ecdsa-entropy-input` (31 bytes)
    /// joined to `oxicrypt-r7-ecdsa-nonce` (23 bytes), split into a
    /// 32-byte entropy input (the first 32 bytes of the joined string)
    /// and a 22-byte nonce (the remaining bytes), with personalization
    /// string `r7-keygen-pinned`. The split leaves the seed material,
    /// `entropy || nonce || personalization`, equal to the three
    /// strings concatenated in that order, so any SP 800-90A
    /// HMAC_DRBG-SHA-256 implementation seeded with that string and
    /// asked for two 32-byte outputs regenerates the 64 bytes.
    static PINNED_KEYGEN_STREAM: [u8; 64] = [
        0x7a, 0xcd, 0x58, 0x6a, 0x22, 0x6d, 0x77, 0x61, 0xac, 0x38, 0xad, 0x16, 0x0b, 0xce, 0x29,
        0xfd, 0xe8, 0xb0, 0xdd, 0xf5, 0x99, 0x47, 0xb6, 0x97, 0x92, 0xe8, 0xf6, 0xd9, 0x1f, 0x74,
        0xee, 0xe0, 0xc7, 0xba, 0x2c, 0x73, 0x93, 0x95, 0x4a, 0x04, 0xdb, 0x10, 0x00, 0xcd, 0x67,
        0xf2, 0xe3, 0xa8, 0x9d, 0xe3, 0x2e, 0x9e, 0x85, 0x4e, 0x6a, 0xff, 0xa6, 0x50, 0xbc, 0x2a,
        0x9f, 0xac, 0xd7, 0x63,
    ];

    #[test]
    fn rbg_at_128_bits_meets_the_p256_strength() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::CtrDrbgAes128::instantiate_from_module(b"p256-ctr128")
            .expect("drbg instantiates");
        let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("generate ok");
        let sig = sk.sign_sha256(&mut drbg, b"p256 ctr128").expect("sign ok");
        assert!(verify(&sk.public_key().unwrap(), b"p256 ctr128", &sig).expect("verify ok"));
    }

    /// An [`Rbg`] reporting a strength the caller chooses; `fill`
    /// refuses, so a call that draws from it fails with [`Error::Rbg`].
    struct ReportsStrength(u32);

    impl Rbg for ReportsStrength {
        fn fill(&mut self, _out: &mut [u8]) -> Result<(), oxicrypt_module::RbgError> {
            Err(oxicrypt_module::RbgError::Uninstantiated)
        }

        fn strength_bits(&self) -> u32 {
            self.0
        }
    }

    #[test]
    fn rbg_below_128_bits_is_refused_by_every_drawing_entry_before_drawing() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::CtrDrbgAes128::instantiate_from_module(b"p256-refusal")
            .expect("drbg instantiates");
        let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("generate ok");
        let drew = Error::Rbg(oxicrypt_module::RbgError::Uninstantiated);
        for (bits, expected) in [(127, Error::RbgTooWeak), (128, drew)] {
            assert_eq!(
                EcdsaP256PrivateKey::generate(&mut ReportsStrength(bits)).err(),
                Some(expected)
            );
            assert_eq!(
                EcdsaP256PrivateKey::from_bytes(&mut ReportsStrength(bits), &KAT_D).err(),
                Some(expected)
            );
            assert_eq!(
                sk.sign_sha256(&mut ReportsStrength(bits), b"p256 refusal"),
                Err(expected)
            );
        }
    }

    #[test]
    fn keygen_output_is_pinned_for_a_fixed_stream() {
        // Pin the random bit stream and assert that `generate` + PCT
        // produces a byte-stable `(d, Q)`. This guards against any
        // future refactor silently changing the order of random bit
        // consumption inside the keygen / PCT / first-sign path.
        //
        // The two constants below are the pin. Without them the test
        // asserts only properties that hold for ANY valid keypair from
        // ANY seed, so it cannot see the reordering it exists to catch.
        // If this breaks intentionally, re-capture the bytes, as the RSA
        // keygen pin documents.
        const EXPECTED_D: [u8; PRIVATE_KEY_LEN] = [
            0x7a, 0xcd, 0x58, 0x6a, 0x22, 0x6d, 0x77, 0x61, 0xac, 0x38, 0xad, 0x16, 0x0b, 0xce,
            0x29, 0xfd, 0xe8, 0xb0, 0xdd, 0xf5, 0x99, 0x47, 0xb6, 0x97, 0x92, 0xe8, 0xf6, 0xd9,
            0x1f, 0x74, 0xee, 0xe0,
        ];
        const EXPECTED_Q: [u8; PUBLIC_KEY_LEN] = [
            0x04, 0xb1, 0x79, 0x37, 0x9a, 0x4d, 0xbc, 0xa0, 0x8e, 0x69, 0x8c, 0x37, 0xab, 0x68,
            0x4b, 0x1f, 0x39, 0xbd, 0x26, 0x07, 0x2e, 0x3a, 0x52, 0x35, 0xc0, 0x03, 0x1f, 0xdc,
            0x32, 0x4d, 0xde, 0x5e, 0x2e, 0x68, 0xaa, 0x24, 0x90, 0xba, 0x06, 0x96, 0x9c, 0xcd,
            0x62, 0x23, 0x7a, 0x29, 0x2d, 0xdb, 0x48, 0xd7, 0x4c, 0x97, 0x90, 0x69, 0xa5, 0xa4,
            0x1c, 0xde, 0xdc, 0x5d, 0x7d, 0x06, 0x48, 0x50, 0x25,
        ];

        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::testing::FixedStream::new(&PINNED_KEYGEN_STREAM, 256);
        let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("generate ok");

        assert_eq!(*sk.private_scalar().unwrap(), EXPECTED_D, "keygen d drift");
        assert_eq!(sk.public_key().unwrap(), EXPECTED_Q, "keygen Q drift");

        let pk_rederived =
            derive_public_key_internal(sk.private_scalar().unwrap()).expect("rederive ok");
        assert_eq!(sk.public_key().unwrap(), pk_rederived);
        let d = Scalar::from_bytes(sk.private_scalar().unwrap()).expect("scalar in range");
        assert_eq!(d.is_zero(), 0);
    }

    #[test]
    fn generate_then_sign_and_verify_roundtrips() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"roundtrip");
        let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("generate ok");
        let msg = b"oxicrypt: random-k sign and verify";
        let sig = sk.sign_sha256(&mut drbg, msg).expect("sign ok");
        assert!(verify(&sk.public_key().unwrap(), msg, &sig).expect("verify ok"));
    }

    #[test]
    fn sign_sha256_randomizes_across_calls() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"randomises");
        let sk = EcdsaP256PrivateKey::generate(&mut drbg).expect("generate ok");
        let msg = b"oxicrypt: drbg must randomise k per call";
        let sig1 = sk.sign_sha256(&mut drbg, msg).expect("sign #1");
        let sig2 = sk.sign_sha256(&mut drbg, msg).expect("sign #2");
        assert_ne!(sig1, sig2, "DRBG-backed sigs must differ on fresh k");
        assert!(verify(&sk.public_key().unwrap(), msg, &sig1).expect("verify #1"));
        assert!(verify(&sk.public_key().unwrap(), msg, &sig2).expect("verify #2"));
    }

    #[test]
    fn from_bytes_of_the_kat_scalar_derives_its_public_key_and_signs() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"from-bytes");
        let sk = EcdsaP256PrivateKey::from_bytes(&mut drbg, &KAT_D).expect("from_bytes + PCT");
        assert_eq!(sk.public_key().unwrap(), KAT_PUBLIC_KEY);

        let sig = sk
            .sign_sha256(&mut drbg, b"probe-message")
            .expect("sign ok");
        assert!(verify(&sk.public_key().unwrap(), b"probe-message", &sig).expect("verify ok"));
    }

    #[test]
    fn from_bytes_rejects_zero_scalar() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"reject-zero");
        let zero = [0u8; PRIVATE_KEY_LEN];
        match EcdsaP256PrivateKey::from_bytes(&mut drbg, &zero) {
            Err(Error::InvalidInput) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("zero scalar must be rejected"),
        }
    }

    #[test]
    fn from_bytes_rejects_scalar_equal_to_n() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"reject-n");
        // P-256 group order `n`, big-endian.
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        match EcdsaP256PrivateKey::from_bytes(&mut drbg, &n_bytes) {
            Err(Error::InvalidInput) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("scalar == n must be rejected"),
        }
    }

    #[test]
    fn pairwise_consistency_rejects_a_foreign_public_key() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"pct-tampered");
        let honest = EcdsaP256PrivateKey::generate(&mut drbg).expect("honest generate ok");
        let decoy = EcdsaP256PrivateKey::generate(&mut drbg).expect("decoy generate ok");

        // Built through the raw struct, which skips the constructors'
        // test, so that the test itself is what rejects the pair.
        let forged = EcdsaP256PrivateKey {
            d: *honest.private_scalar().unwrap(),
            q: decoy.public_key().unwrap(),
        };
        assert_eq!(
            forged.pairwise_consistency(&mut drbg),
            Ok(false),
            "PCT must reject an inconsistent (d, Q) handle"
        );
        assert_eq!(honest.pairwise_consistency(&mut drbg), Ok(true));
    }

    #[test]
    fn sample_scalar_produces_in_range_values() {
        let _ = init_with_tests(&[KatEntry {
            name: "ecdsa-p256-sha256",
            run: self_test,
        }]);
        let mut drbg = pct_drbg(b"sampler-range");
        for _ in 0..32 {
            let bytes = crate::p256_keygen::sample_scalar_internal(&mut drbg)
                .expect("sampler must succeed");
            let s = Scalar::from_bytes(&bytes).expect("scalar in range");
            assert_eq!(s.is_zero(), 0);
        }
    }
}
