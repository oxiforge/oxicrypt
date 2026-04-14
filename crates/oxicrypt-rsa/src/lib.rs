//! RSA-2048 signature generation, verification, and key generation
//! per FIPS 186-5 / RFC 8017.
//!
//! # Approved services
//!
//! | Service | Spec | Entry point |
//! |---------|------|-------------|
//! | RSASSA-PKCS1-v1_5 verify, SHA-256 | FIPS 186-5 §5.4 / RFC 8017 §8.2 | [`rsa_pkcs1_v15_verify_2048_sha256`] |
//! | RSASSA-PKCS1-v1_5 sign, SHA-256   | FIPS 186-5 §5.4 / RFC 8017 §8.2 | [`RsaPrivateKey2048::sign_pkcs1_v15_sha256`] |
//! | RSASSA-PSS verify, SHA-256, MGF1  | FIPS 186-5 §5.4 / RFC 8017 §8.1 | [`rsa_pss_verify_2048_sha256`] |
//! | RSASSA-PSS sign, SHA-256, MGF1    | FIPS 186-5 §5.4 / RFC 8017 §8.1 | [`RsaPrivateKey2048::sign_pss_sha256_with_salt`] and [`RsaPrivateKey2048::sign_pss_sha256`] |
//! | RSA key generation                | FIPS 186-5 §A.1.1 / §B.3.1      | [`RsaPrivateKey2048::generate`] |
//! | RSA CRT sign w/ Bellcore check    | FIPS 186-5 §5.4 / IG D.G         | [`RsaPrivateKey2048::from_components_crt`] |
//!
//! The PSS scheme uses MGF1-SHA-256 with `sLen = hLen = 32` and
//! `emBits = 2047` per FIPS 186-5 §5.4 and RFC 8017 §9.1. The PSS
//! sign surface is duplicated: a caller-supplied-salt form (used
//! by the power-up KAT and by deterministic-reproducibility tests)
//! and a DRBG-backed form that samples a fresh salt per call.
//!
//! # FIPS 186-5 §5.1 modulus size
//!
//! Only `|n| = 2048` bits is accepted. Verification of legacy
//! 1024- or 1280-bit RSA signatures is outside the approved
//! boundary and this crate deliberately has no code path for it.
//! Extension to RSA-3072 / RSA-4096 is scheduled for a later
//! chunk and requires new fixed-width big-int types; the code is
//! structured so `mont2048` / `mont1024` can be forked by
//! width without disturbing the higher-level scheme code.
//!
//! # Power-up self-tests
//!
//! [`self_test`] runs one pinned PKCS#1 v1.5 sign-and-verify KAT
//! and one pinned PSS sign-and-verify KAT. Both use hidden
//! `*_internal` primitives that bypass
//! [`oxicrypt_module::require_operational`] so they can execute while
//! the module is still in `SelfTest`. Keygen is **not** on the
//! power-up path — it is too slow in debug builds — but is
//! regression-covered by a pinned-DRBG-seed KAT in
//! [`keygen`]'s test module.
//!
//! # Conditional self-tests
//!
//! Every [`RsaPrivateKey2048`] — whether constructed from bytes
//! via [`RsaPrivateKey2048::from_components`] or freshly
//! generated via [`RsaPrivateKey2048::generate`] — goes through
//! the FIPS 140-3 IG 10.3.A **pairwise consistency test** before
//! the handle is returned: the constructor signs a fixed
//! all-zeros message, verifies the signature back with the
//! public key, and rejects the key on any mismatch. This
//! catches both import-time corruption and any accidental
//! divergence in a freshly-generated `(n, d)` pair.
//!
//! # Sensitive security parameters (SSPs)
//!
//! - **Public key components** (`n`, `e`) — public, not SSPs.
//! - **Private exponent** (`d`) — CSP. Held inside
//!   [`RsaPrivateKey2048`] as a fixed-width byte array; the
//!   constant-time Montgomery ladder in
//!   [`mont2048::MontCtx2048::pow_secret`] is the only path that
//!   ever observes it during signing.
//! - **Prime factors and CRT components** (`p`, `q`, `dP`, `dQ`,
//!   `qInv`) — CSPs. Retained inside the private-key handle when
//!   the key is built through [`RsaPrivateKey2048::generate`] or
//!   [`RsaPrivateKey2048::from_components_crt`]. Used only by the
//!   CRT sign primitive; `p` and `q` enter [`mont1024::MontCtx1024`]
//!   and `dP`/`dQ` are consumed by
//!   [`mont1024::MontCtx1024::pow_secret`] under the same
//!   constant-time contract as the direct `d`-based ladder.
//! - **PSS salt** — ephemeral CSP; sampled from the caller's
//!   HMAC_DRBG, consumed inside a single signing operation, and
//!   dropped when the stack frame unwinds.
//!
//! Zeroization of the long-lived private-key storage is tracked
//! separately by the crate-wide hardening pass; all short-lived
//! intermediates live on the stack and go away with the frame.
//!
//! # Side-channel posture
//!
//! - Non-CRT signing uses
//!   [`mont2048::MontCtx2048::pow_secret`] — a 4-bit windowed
//!   constant-time Montgomery ladder that never branches on
//!   private-exponent bits and never indexes a table with a
//!   secret.
//! - CRT signing uses
//!   [`mont1024::MontCtx1024::pow_secret`] twice (once mod `p`,
//!   once mod `q`) — the same constant-time 4-bit windowed ladder
//!   at 16-limb width. The Garner recombine step mixes only
//!   CSP values against other CSP values, so its non-constant-time
//!   reduction branches do not cross a public boundary. The
//!   Bellcore verify step reduces `m mod p` and `m mod q` via a
//!   public-data bitwise reducer (`m` is EM, not a secret).
//! - Verification uses `mont2048::MontCtx2048::pow_public_u64`,
//!   which is explicitly **not** constant-time in the public
//!   exponent `e`; that is acceptable because `e` is public.
//! - Miller-Rabin during keygen uses
//!   [`mont1024::MontCtx1024::pow_public_u1024`], which is
//!   non-constant-time in the witness exponent; that is
//!   acceptable because the candidate prime is not yet a
//!   committed key and timing information cannot be correlated
//!   with any bit of a final key.
//!
//! # FIPS module gating
//!
//! Every public service routes through
//! [`oxicrypt_module::require_operational`]. A hidden `*_internal`
//! twin of each primitive bypasses the gate so
//! [`self_test`] can run while the module is still in
//! `SelfTest`. Callers in application code should never need to
//! touch the `*_internal` surface; it is `#[doc(hidden)]`.
#![no_std]
#![forbid(unsafe_code)]

pub mod bigint1024;
pub mod bigint2048;
pub mod keygen;
pub mod mont1024;
pub mod mont2048;
pub mod oaep;
pub mod pkcs1_v15;
pub mod pss;

use bigint1024::{U1024, BYTES as U1024_BYTES, LIMBS as LIMBS1024};
use bigint2048::{U2048, BYTES as U2048_BYTES, LIMBS as LIMBS2048};
use oxicrypt_module::{require_operational, Error, KatEntry, SelfTestFailure};
use oxicrypt_sha::sha256::DIGEST_SIZE as SHA256_DIGEST_SIZE;
use mont1024::MontCtx1024;
use mont2048::MontCtx2048;

/// Fixed byte length of each 1024-bit half (`p`, `q`, `dP`, `dQ`,
/// `qInv`) in the CRT-form private key.
pub const RSA_2048_CRT_HALF_BYTES: usize = U1024_BYTES;

/// Fixed modulus byte length for RSA-2048.
pub const RSA_2048_MODULUS_BYTES: usize = U2048_BYTES;
/// Fixed signature byte length for RSA-2048 (equal to the modulus
/// length per PKCS#1 §8.2).
pub const RSA_2048_SIGNATURE_BYTES: usize = U2048_BYTES;

// ------------------------------------------------------------------
// Core verify primitive (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 verify for RSA-2048 / SHA-256, bypassing the
/// FIPS module state gate. Intended for power-up KAT use only;
/// production callers use [`rsa_pkcs1_v15_verify_2048_sha256`].
///
/// Returns `true` iff:
///   * `n` is a valid 2048-bit odd integer with the top bit set
///     (accepted by [`MontCtx2048::new`]),
///   * `s < n` where `s` is the signature integer,
///   * `RSAVP1(s) = s^e mod n = EM`, and
///   * `EM` matches the canonical EMSA-PKCS1-v1_5 encoding of
///     `SHA-256(msg)` at length 256 bytes.
#[doc(hidden)]
pub fn rsa_pkcs1_v15_verify_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> bool {
    // Decode the modulus and build a Montgomery context. `MontCtx2048::new`
    // enforces oddness and the strict-2048-bit size requirement from
    // FIPS 186-5 §5.1.
    let n = U2048::from_be_bytes(n_bytes);
    let Some(ctx) = MontCtx2048::new(n) else {
        return false;
    };

    // RFC 8017 §8.2.2 step 1: length check is implicit in the fixed
    // array sizes. Step 2a: convert signature to integer `s`.
    let s = U2048::from_be_bytes(sig_bytes);

    // RFC 8017 §5.2.2 RSAVP1 step 1: s must be in `[0, n-1]`. An
    // attacker-controlled `s ≥ n` would otherwise be accepted by the
    // Montgomery ladder (which reduces mod n and forgets the top
    // bits), letting them construct unlimited signature aliases.
    if s.ct_lt(&ctx.n) != 1 {
        return false;
    }

    // RSAVP1 / RSAEP: m = s^e mod n. `pow_public_u64` is explicitly
    // non-constant-time in `e`, which is fine here because `e` is
    // part of the public key.
    let m = ctx.pow_public_u64(&s, e);
    let em_recovered = m.to_be_bytes();

    // Build the expected EM from SHA-256(msg) and compare byte-exact.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em_expected = [0u8; RSA_2048_MODULUS_BYTES];
    if pkcs1_v15::encode_sha256(&digest, &mut em_expected).is_none() {
        return false;
    }
    pkcs1_v15::ct_eq(&em_recovered, &em_expected) == 1
}

// ------------------------------------------------------------------
// Core sign primitive (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 sign for RSA-2048 / SHA-256, bypassing the FIPS
/// module state gate and the pairwise consistency test. Intended for
/// power-up KAT use only.
///
/// Returns `None` if `n` is not a valid 2048-bit modulus accepted by
/// [`MontCtx2048::new`], if `d >= n` (which would let the ladder
/// silently wrap), or if the EMSA encoding step fails (it cannot
/// fail for an RSA-2048 SHA-256 configuration, but we plumb the
/// error anyway for symmetry with the verify path).
#[doc(hidden)]
pub fn rsa_pkcs1_v15_sign_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    msg: &[u8],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    // FIPS 186-5 §5.1 / PKCS#1 §3.2 require d ∈ [1, n−1]. Reject
    // d ≥ n here so the ladder never accepts an out-of-range secret.
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    // EMSA-PKCS1-v1_5 encode the message digest into an EM buffer
    // that's already one modulus-length wide.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; RSA_2048_MODULUS_BYTES];
    pkcs1_v15::encode_sha256(&digest, &mut em)?;

    // RFC 8017 §9.2 step 6: convert EM → m, §5.2.1 RSASP1: s = m^d mod n.
    // The message representative always satisfies m < n because the
    // canonical EM starts with 0x00 0x01 and n has its top bit set.
    let m = U2048::from_be_bytes(&em);
    let s = ctx.pow_secret(&m, &d);
    Some(s.to_be_bytes())
}

// ------------------------------------------------------------------
// Core PSS primitives (state-gate-free)
// ------------------------------------------------------------------

/// RSASSA-PSS sign for RSA-2048 / SHA-256 with `sLen = hLen = 32`,
/// bypassing the FIPS module state gate. Intended for power-up KAT
/// and for the gated public API wrappers.
///
/// The caller supplies the salt. The KAT path passes a pinned salt;
/// production callers supply fresh randomness. Returns `None` for the
/// same structural reasons as [`rsa_pkcs1_v15_sign_2048_sha256_internal`]
/// (bad modulus, `d ≥ n`, or EMSA-PSS encode failure, which again
/// cannot happen for the pinned parameter triple but is plumbed for
/// symmetry).
#[doc(hidden)]
pub fn rsa_pss_sign_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    msg: &[u8],
    salt: &[u8; pss::SLEN],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    // EMSA-PSS-ENCODE the SHA-256 digest of msg into a 256-byte EM.
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; pss::EM_LEN];
    pss::emsa_pss_encode(&digest, salt, &mut em)?;

    // RFC 8017 §8.1.1 step 2a/b: m = OS2IP(EM), s = RSASP1(K, m).
    // The top bit of EM is cleared (emBits = 2047 < 8·emLen = 2048),
    // so m < 2^2047 < n and the ladder never wraps.
    let m = U2048::from_be_bytes(&em);
    let s = ctx.pow_secret(&m, &d);
    Some(s.to_be_bytes())
}

// ------------------------------------------------------------------
// CRT sign primitive with Bellcore fault-detection (state-gate-free)
// ------------------------------------------------------------------

/// CRT-form private-key material used by the Garner-recombine sign
/// primitive. Byte layouts mirror the public API: big-endian, fixed
/// width. All five components are CSPs.
#[derive(Clone, Copy, Debug)]
struct CrtComponentsRaw<'a> {
    p: &'a [u8; U1024_BYTES],
    q: &'a [u8; U1024_BYTES],
    dp: &'a [u8; U1024_BYTES],
    dq: &'a [u8; U1024_BYTES],
    qinv: &'a [u8; U1024_BYTES],
}

/// Zero-extend a `U1024` into the low half of a `U2048`. Used by the
/// CRT recombine step to add `q · h` (a 2048-bit product) to `s_q` (a
/// 1024-bit value).
#[inline]
fn u1024_into_u2048_low(x: &U1024) -> U2048 {
    let mut limbs = [0u64; LIMBS2048];
    limbs[..LIMBS1024].copy_from_slice(&x.limbs);
    U2048 { limbs }
}

/// Core CRT private-exponent primitive: raise a 256-byte input
/// representative `x` to `d mod n` via the Chinese-Remainder
/// decomposition and run a Bellcore / Shamir verify-after-exponent
/// check before returning.
///
/// # Shared math for sign and decrypt
///
/// RSASSA sign (`s = EM^d mod n`) and RSAES decrypt (`m = C^d mod n`)
/// are the same primitive up to the name of the input buffer. This
/// routine is the single implementation both paths dispatch through.
/// The Bellcore check is symmetric as well: sign verifies
/// `s^e mod n == EM`, decrypt verifies `m^e mod n == C`. In both cases
/// a single fault on either CRT half flips exactly one of the two
/// congruences and is caught.
///
/// # Mathematics
///
/// Given the CRT key material `(p, q, dP, dQ, qInv)` with
/// `dP = d mod (p − 1)`, `dQ = d mod (q − 1)`, and
/// `qInv = q^(−1) mod p`, Garner's recombine formula computes
///
/// ```text
///   x_p  = x mod p
///   x_q  = x mod q
///   y_p  = x_p^dP mod p         — constant-time mont1024 ladder
///   y_q  = x_q^dQ mod q         — constant-time mont1024 ladder
///   h    = qInv · (y_p − y_q mod p) mod p
///   y    = y_q + q · h
/// ```
///
/// which satisfies `y ≡ x^d (mod n)` by the CRT. `y_q` is first
/// reduced mod `p` before the subtraction (`q` and `p` have equal
/// bit-length, so at most one conditional subtract is required).
///
/// # Bellcore / Shamir countermeasure
///
/// CRT sign/decrypt is vulnerable to single-fault attacks: if either
/// `x_p^dP` or `x_q^dQ` is corrupted (a bit-flip injected by the
/// attacker, cosmic ray, etc.), the recombined `y` satisfies
/// `y ≡ x^d (mod p)` but `y ≢ x^d (mod q)` (or vice versa), and
/// `gcd(y^e − x, n)` yields `p` or `q` — an immediate full-key
/// recovery.
///
/// FIPS 140-3 IG D.G calls out RSA CRT faults explicitly. We mitigate
/// by re-verifying the output before returning: compute
/// `x_check = y^e mod n` using the non-CRT public ladder and compare
/// against the original `x`. A single fault on either half diverges
/// the check; a correlated two-point fault has negligible probability
/// under the IG threat model.
///
/// # Returns
///
/// `None` on any of: bad modulus, bad prime factor, `x ≥ n`, or a
/// failed Bellcore check (indicating either an injected fault or a
/// structurally inconsistent key). The caller converts `None` into
/// [`Error::InvalidInput`].
#[doc(hidden)]
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::single_char_lifetime_names
)]
fn rsa_crt_2048_private_exp_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    crt: CrtComponentsRaw<'_>,
    input: &[u8; RSA_2048_MODULUS_BYTES],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    // 1. Build Montgomery contexts for n, p, q. `MontCtx*::new`
    //    enforces top-bit-set / odd, which is exactly the FIPS 186-5
    //    §A.1.1 shape for 2048-bit RSA prime factors.
    let n = U2048::from_be_bytes(n_bytes);
    let ctx_n = MontCtx2048::new(n)?;

    let p = U1024::from_be_bytes(crt.p);
    let q = U1024::from_be_bytes(crt.q);
    let ctx_p = MontCtx1024::new(p)?;
    let ctx_q = MontCtx1024::new(q)?;

    let dp = U1024::from_be_bytes(crt.dp);
    let dq = U1024::from_be_bytes(crt.dq);
    let qinv = U1024::from_be_bytes(crt.qinv);

    // 2. Load the input representative and range-check.
    let x = U2048::from_be_bytes(input);
    if x.ct_lt(&ctx_n.n) != 1 {
        return None;
    }

    // 3. Reduce x mod p and x mod q. The reducer is not constant time
    //    in its inputs, but `x` is either EM (derived from a public
    //    message digest) or a ciphertext (already on the wire) — in
    //    both cases it is public input, not a secret.
    let x_p = keygen::u2048_mod_u1024(&x, &p);
    let x_q = keygen::u2048_mod_u1024(&x, &q);

    // 4. Secret-exponent exponentiations mod p and mod q via the
    //    constant-time 4-bit windowed ladder.
    let y_p = ctx_p.pow_secret(&x_p, &dp);
    let y_q = ctx_q.pow_secret(&x_q, &dq);

    // 5. Garner recombine.
    //
    //    `y_q` is in `[0, q)`. Reduce mod p with at most one subtract:
    //    p and q are both strictly 1024-bit (top bit set), so
    //    `q < 2^1024 ≤ 2·p`.
    let y_q_mod_p = if y_q.ct_lt(&p) == 1 {
        y_q
    } else {
        y_q.subtracting(&p).0
    };

    //    `diff = (y_p − y_q_mod_p) mod p`.
    let diff = if y_p.ct_lt(&y_q_mod_p) == 1 {
        // y_p < y_q_mod_p: add p first, then subtract.
        let (sum, _) = y_p.adding(&p);
        sum.subtracting(&y_q_mod_p).0
    } else {
        y_p.subtracting(&y_q_mod_p).0
    };

    //    `h = (qInv · diff) mod p` via the Montgomery context on p.
    let diff_mont = ctx_p.to_mont(&diff);
    let qinv_mont = ctx_p.to_mont(&qinv);
    let h_mont = ctx_p.mont_mul(&qinv_mont, &diff_mont);
    let h = ctx_p.from_mont(&h_mont);

    //    `y = y_q + q · h`, where `q · h` is a 2048-bit product and
    //    `y_q` is zero-extended into the low half.
    let qh = q.widening_mul(&h);
    let yq_wide = u1024_into_u2048_low(&y_q);
    let (y, _carry) = qh.adding(&yq_wide);

    // 6. Bellcore / Shamir verify-after-exponent: recompute `x` from
    //    `y` under the public exponent and compare. Any single bit-flip
    //    inside step 4 (or elsewhere in the CRT machinery) produces
    //    an output that only satisfies one of the two half
    //    congruences and fails this check. Applies identically to
    //    sign (y = signature, x = EM) and decrypt (y = message
    //    representative, x = ciphertext).
    let x_check = ctx_n.pow_public_u64(&y, e);
    if x_check.ct_eq(&x) != 1 {
        return None;
    }

    Some(y.to_be_bytes())
}

/// RSASSA-PKCS1-v1_5 sign for RSA-2048 / SHA-256 via the CRT path
/// with Bellcore verify-after-sign. Bypasses the FIPS module state
/// gate; intended for internal use by
/// [`RsaPrivateKey2048::sign_pkcs1_v15_sha256`] when CRT components
/// are available.
#[doc(hidden)]
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    p_bytes: &[u8; U1024_BYTES],
    q_bytes: &[u8; U1024_BYTES],
    dp_bytes: &[u8; U1024_BYTES],
    dq_bytes: &[u8; U1024_BYTES],
    qinv_bytes: &[u8; U1024_BYTES],
    msg: &[u8],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; RSA_2048_MODULUS_BYTES];
    pkcs1_v15::encode_sha256(&digest, &mut em)?;
    let crt = CrtComponentsRaw {
        p: p_bytes,
        q: q_bytes,
        dp: dp_bytes,
        dq: dq_bytes,
        qinv: qinv_bytes,
    };
    rsa_crt_2048_private_exp_internal(n_bytes, e, crt, &em)
}

/// RSASSA-PSS sign for RSA-2048 / SHA-256 via the CRT path with
/// Bellcore verify-after-sign. Bypasses the FIPS module state gate.
#[doc(hidden)]
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn rsa_pss_sign_2048_sha256_crt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    p_bytes: &[u8; U1024_BYTES],
    q_bytes: &[u8; U1024_BYTES],
    dp_bytes: &[u8; U1024_BYTES],
    dq_bytes: &[u8; U1024_BYTES],
    qinv_bytes: &[u8; U1024_BYTES],
    msg: &[u8],
    salt: &[u8; pss::SLEN],
) -> Option<[u8; RSA_2048_SIGNATURE_BYTES]> {
    let digest = pkcs1_v15::sha256_internal(msg);
    let mut em = [0u8; pss::EM_LEN];
    pss::emsa_pss_encode(&digest, salt, &mut em)?;
    let crt = CrtComponentsRaw {
        p: p_bytes,
        q: q_bytes,
        dp: dp_bytes,
        dq: dq_bytes,
        qinv: qinv_bytes,
    };
    rsa_crt_2048_private_exp_internal(n_bytes, e, crt, &em)
}

// ------------------------------------------------------------------
// OAEP primitives (state-gate-free)
// ------------------------------------------------------------------

/// RSAES-OAEP encrypt for RSA-2048 / SHA-256 with a caller-supplied
/// OAEP seed, bypassing the FIPS module state gate.
///
/// The caller owns the randomness contract: in production callers the
/// seed must be a fresh `hLen`-byte draw from an approved DRBG; in
/// KAT and test harnesses a pinned seed is passed so the encryption
/// output is byte-reproducible. The encode→integer conversion always
/// yields `m < n` because `EM[0] = 0x00`, so `m < 2^2040 < n`.
///
/// Returns `None` if the modulus is not a strict 2048-bit odd integer,
/// if `msg.len() > oaep::MAX_MSG_LEN`, or (for completeness) if the
/// OAEP encode step fails internally.
#[doc(hidden)]
pub fn rsa_oaep_encrypt_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    label: &[u8],
    msg: &[u8],
    seed: &[u8; oaep::HLEN],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx_n = MontCtx2048::new(n)?;

    // EME-OAEP-ENCODE into a k-byte buffer.
    let mut em = [0u8; oaep::K];
    oaep::emsa_oaep_encode(label, msg, seed, &mut em)?;

    // RSAEP: c = m^e mod n via the public-exponent ladder. `pow_public_u64`
    // is explicitly non-constant-time in `e`, which is fine because `e`
    // is part of the public key and the input `m` is attacker-known.
    let m = U2048::from_be_bytes(&em);
    let c = ctx_n.pow_public_u64(&m, e);
    Some(c.to_be_bytes())
}

// ------------------------------------------------------------------
// Raw RSA Decryption Primitive — RSADP (SP 800-56Br2 §7.1.2)
// ------------------------------------------------------------------

/// Raw RSA Decryption Primitive (RSADP) for 2048-bit keys via the
/// **non-CRT** secret-exponent path, bypassing the FIPS module state
/// gate. Computes `pt = ct^d mod n` — no padding decode.
///
/// Enforces the SP 800-56Br2 §7.1.2.1 range check:
/// **`1 < ct < (n − 1)`**. Returns `None` if `ct ∈ {0, 1}`,
/// `ct ≥ n − 1`, or the modulus / private exponent fails structural
/// checks.
///
/// # ACVP / CAVP
///
/// This is the primitive tested by the `RSA / decryptionPrimitive /
/// Sp800-56Br2` ACVP vector set (`keyMode = "standard"`).
#[doc(hidden)]
pub fn rsa_decryption_primitive_2048_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    ct: &[u8; RSA_2048_MODULUS_BYTES],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    let c = U2048::from_be_bytes(ct);
    // SP 800-56Br2 §7.1.2.1: reject c outside (1, n − 1).
    if !sp800_56br2_range_check(&c, &ctx.n) {
        return None;
    }

    let m = ctx.pow_secret(&c, &d);
    Some(m.to_be_bytes())
}

/// Raw RSA Decryption Primitive (RSADP) for 2048-bit keys via the
/// **CRT** path with Bellcore verify-after-decrypt per FIPS 140-3
/// IG D.G, bypassing the FIPS module state gate.
///
/// Enforces the SP 800-56Br2 §7.1.2.1 range check:
/// **`1 < ct < (n − 1)`**. Dispatches through
/// [`rsa_crt_2048_private_exp_internal`] — the same primitive that
/// sign and OAEP-decrypt use. Returns `None` on bad key material,
/// out-of-range `ct`, or a failed Bellcore check.
///
/// # ACVP / CAVP
///
/// This is the primitive tested by the `RSA / decryptionPrimitive /
/// Sp800-56Br2` ACVP vector set (`keyMode = "crt"`).
#[doc(hidden)]
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn rsa_decryption_primitive_2048_crt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    p_bytes: &[u8; U1024_BYTES],
    q_bytes: &[u8; U1024_BYTES],
    dp_bytes: &[u8; U1024_BYTES],
    dq_bytes: &[u8; U1024_BYTES],
    qinv_bytes: &[u8; U1024_BYTES],
    ct: &[u8; RSA_2048_MODULUS_BYTES],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    // SP 800-56Br2 §7.1.2.1 range check before CRT dispatch.
    let n = U2048::from_be_bytes(n_bytes);
    let c = U2048::from_be_bytes(ct);
    if !sp800_56br2_range_check(&c, &n) {
        return None;
    }
    let crt = CrtComponentsRaw {
        p: p_bytes,
        q: q_bytes,
        dp: dp_bytes,
        dq: dq_bytes,
        qinv: qinv_bytes,
    };
    rsa_crt_2048_private_exp_internal(n_bytes, e, crt, ct)
}

/// Raw RSA Signature Primitive (RSASP1) for 2048-bit keys via the
/// **non-CRT** private-exponent path, bypassing the FIPS module
/// state gate.
///
/// Enforces the RFC 8017 §5.2.1 range check: **`0 ≤ msg < n`**.
/// Returns `None` on bad key material or out-of-range `msg`.
///
/// # ACVP / CAVP
///
/// This is the primitive tested by the `RSA / signaturePrimitive /
/// 2.0` ACVP vector set when the per-test CRT components are absent.
#[doc(hidden)]
pub fn rsa_signature_primitive_2048_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    msg: &[u8; RSA_2048_MODULUS_BYTES],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    if d.ct_lt(&ctx.n) != 1 {
        return None;
    }

    let m = U2048::from_be_bytes(msg);
    // RFC 8017 §5.2.1: 0 ≤ m < n.
    if m.ct_lt(&ctx.n) != 1 {
        return None;
    }

    let s = ctx.pow_secret(&m, &d);
    Some(s.to_be_bytes())
}

/// Raw RSA Signature Primitive (RSASP1) for 2048-bit keys via the
/// **CRT** path with Bellcore verify-after-sign per FIPS 140-3
/// IG D.G, bypassing the FIPS module state gate.
///
/// Enforces the RFC 8017 §5.2.1 range check: **`0 ≤ msg < n`**.
/// Returns `None` on bad key material, out-of-range `msg`, or a
/// failed Bellcore check.
///
/// # ACVP / CAVP
///
/// This is the primitive tested by the `RSA / signaturePrimitive /
/// 2.0` ACVP vector set.
#[doc(hidden)]
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn rsa_signature_primitive_2048_crt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    p_bytes: &[u8; U1024_BYTES],
    q_bytes: &[u8; U1024_BYTES],
    dp_bytes: &[u8; U1024_BYTES],
    dq_bytes: &[u8; U1024_BYTES],
    qinv_bytes: &[u8; U1024_BYTES],
    msg: &[u8; RSA_2048_MODULUS_BYTES],
) -> Option<[u8; RSA_2048_MODULUS_BYTES]> {
    // RFC 8017 §5.2.1: 0 ≤ msg < n. The CRT internal function
    // already checks x < n (line 393 of rsa_crt_2048_private_exp_internal),
    // so we delegate directly.
    let crt = CrtComponentsRaw {
        p: p_bytes,
        q: q_bytes,
        dp: dp_bytes,
        dq: dq_bytes,
        qinv: qinv_bytes,
    };
    rsa_crt_2048_private_exp_internal(n_bytes, e, crt, msg)
}

/// SP 800-56Br2 §7.1.2.1 ciphertext range check:
/// returns `true` iff `1 < c < (n − 1)`.
fn sp800_56br2_range_check(c: &U2048, n: &U2048) -> bool {
    let one = {
        let mut limbs = [0u64; bigint2048::LIMBS];
        limbs[0] = 1;
        U2048 { limbs }
    };
    // c must be > 1: reject c ∈ {0, 1}.
    if c.ct_lt(&one) == 1 || c.ct_eq(&one) == 1 {
        return false;
    }
    // c must be < n − 1: compute n − 1 and check c < n − 1.
    let (n_minus_1, _) = n.subtracting(&one);
    // If n ≤ 2 the key is structurally invalid; also reject.
    if n_minus_1.ct_eq(&U2048::ZERO) == 1 || n_minus_1.ct_eq(&one) == 1 {
        return false;
    }
    c.ct_lt(&n_minus_1) == 1
}

/// RSAES-OAEP decrypt for RSA-2048 / SHA-256 via the **non-CRT**
/// private-exponent path, bypassing the FIPS module state gate.
///
/// Used by [`RsaPrivateKey2048::decrypt_oaep_sha256`] when the private
/// key handle was built via [`RsaPrivateKey2048::from_components`]
/// (no CRT material). Writes the recovered plaintext into `out` and
/// returns `Some(mLen)` on success, `None` on any failure.
///
/// Every failure mode collapses to `None` without revealing which
/// check failed — this is the crate-side half of the Manger-resistance
/// contract; the OAEP decoder handles the per-byte half.
///
/// Unlike the CRT path, there is no Bellcore verify-after-decrypt
/// here: with only a single 2048-bit ladder there is no CRT halves to
/// disagree on, so a single injected fault simply yields a wrong
/// plaintext that fails the OAEP structural checks and is rejected by
/// the decoder. There is no routine that leaks `p` or `q` from a
/// non-CRT fault.
#[doc(hidden)]
pub fn rsa_oaep_decrypt_2048_sha256_nocrt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    label: &[u8],
    ct: &[u8; RSA_2048_MODULUS_BYTES],
    out: &mut [u8; oaep::MAX_MSG_LEN],
) -> Option<usize> {
    let n = U2048::from_be_bytes(n_bytes);
    let ctx_n = MontCtx2048::new(n)?;

    let d = U2048::from_be_bytes(d_bytes);
    if d.ct_lt(&ctx_n.n) != 1 {
        return None;
    }

    // §7.1.2 step 1 length check is implicit in the fixed array size.
    // §5.1.2 RSADP step 1: c ∈ [0, n − 1].
    let c = U2048::from_be_bytes(ct);
    if c.ct_lt(&ctx_n.n) != 1 {
        return None;
    }

    // RSADP: m = c^d mod n via the constant-time secret-exponent ladder.
    let m = ctx_n.pow_secret(&c, &d);
    let em = m.to_be_bytes();

    oaep::emsa_oaep_decode(label, &em, out)
}

/// RSAES-OAEP decrypt for RSA-2048 / SHA-256 via the **CRT** path with
/// Bellcore verify-after-decrypt per FIPS 140-3 IG D.G, bypassing the
/// FIPS module state gate.
///
/// Dispatches through the same
/// [`rsa_crt_2048_private_exp_internal`] that the CRT sign path uses —
/// the math is identical. The Bellcore check here reads as
/// `m^e mod n == c`: a single fault on either `dP` or `dQ` half will
/// fail the check and the routine returns `None` rather than handing
/// back a message that leaks `p` or `q`.
#[doc(hidden)]
#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn rsa_oaep_decrypt_2048_sha256_crt_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    p_bytes: &[u8; U1024_BYTES],
    q_bytes: &[u8; U1024_BYTES],
    dp_bytes: &[u8; U1024_BYTES],
    dq_bytes: &[u8; U1024_BYTES],
    qinv_bytes: &[u8; U1024_BYTES],
    label: &[u8],
    ct: &[u8; RSA_2048_MODULUS_BYTES],
    out: &mut [u8; oaep::MAX_MSG_LEN],
) -> Option<usize> {
    let crt = CrtComponentsRaw {
        p: p_bytes,
        q: q_bytes,
        dp: dp_bytes,
        dq: dq_bytes,
        qinv: qinv_bytes,
    };
    // CRT exponent + Bellcore verify-after-decrypt on the ciphertext.
    let em = rsa_crt_2048_private_exp_internal(n_bytes, e, crt, ct)?;
    oaep::emsa_oaep_decode(label, &em, out)
}

/// RSASSA-PSS verify for RSA-2048 / SHA-256, bypassing the FIPS module
/// state gate. Intended for power-up KAT use only; production callers
/// use [`rsa_pss_verify_2048_sha256`].
#[doc(hidden)]
pub fn rsa_pss_verify_2048_sha256_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> bool {
    let n = U2048::from_be_bytes(n_bytes);
    let Some(ctx) = MontCtx2048::new(n) else {
        return false;
    };

    // RFC 8017 §8.1.2 step 1: length check is implicit; step 2a: OS2IP.
    let s = U2048::from_be_bytes(sig_bytes);
    if s.ct_lt(&ctx.n) != 1 {
        return false;
    }

    // §5.2.2 RSAVP1: m = s^e mod n.
    let m = ctx.pow_public_u64(&s, e);
    let em = m.to_be_bytes();

    let digest = pkcs1_v15::sha256_internal(msg);
    pss::emsa_pss_verify(&digest, &em)
}

// ------------------------------------------------------------------
// Public verify API (gated)
// ------------------------------------------------------------------

/// Verify an RSASSA-PKCS1-v1_5 signature over `msg` under the 2048-bit
/// public key `(n_bytes, e)` using SHA-256 as the message digest.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the containing FIPS module
/// has not finished its power-up self-tests. Returns
/// [`Error::InvalidInput`] if the signature fails to verify for any
/// reason — invalid modulus, out-of-range signature integer, digest
/// mismatch, or malformed EM.
///
/// On a successful verification, returns `Ok(())`.
pub fn rsa_pkcs1_v15_verify_2048_sha256(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> Result<(), Error> {
    require_operational()?;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, msg, sig_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Verify an RSASSA-PSS signature over `msg` under the 2048-bit public
/// key `(n_bytes, e)` using SHA-256 as both the message hash and the
/// MGF1 hash, with salt length fixed to `hLen = 32` bytes.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the FIPS module has not
/// finished power-up self-tests. Returns [`Error::InvalidInput`] if
/// the signature does not verify for any reason.
pub fn rsa_pss_verify_2048_sha256(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    msg: &[u8],
    sig_bytes: &[u8; RSA_2048_SIGNATURE_BYTES],
) -> Result<(), Error> {
    require_operational()?;
    if rsa_pss_verify_2048_sha256_internal(n_bytes, e, msg, sig_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Encrypt `msg` under the 2048-bit public key `(n_bytes, e)` using
/// RSAES-OAEP with SHA-256 for both the label hash and the MGF1 hash.
/// The caller supplies an HMAC-DRBG-SHA-256 from which a fresh
/// `hLen = 32`-byte OAEP seed is drawn per call.
///
/// `msg.len()` must be at most [`oaep::MAX_MSG_LEN`] = 190 bytes;
/// longer messages are rejected with [`Error::InvalidInput`]. The
/// `label` parameter is bound into the ciphertext via `lHash` per RFC
/// 8017 §7.1.1 — decryption with a different label will fail.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the FIPS module has not
/// completed power-up self-tests. Returns [`Error::InvalidInput`] on
/// modulus rejection, DRBG failure, or oversize message.
pub fn rsa_oaep_encrypt_2048_sha256(
    drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    label: &[u8],
    msg: &[u8],
) -> Result<[u8; RSA_2048_MODULUS_BYTES], Error> {
    require_operational()?;
    let mut seed = [0u8; oaep::HLEN];
    drbg.generate(None, &mut seed)
        .map_err(|_| Error::InvalidInput)?;
    rsa_oaep_encrypt_2048_sha256_internal(n_bytes, e, label, msg, &seed)
        .ok_or(Error::InvalidInput)
}

// ------------------------------------------------------------------
// Private-key handle + pairwise consistency test
// ------------------------------------------------------------------

/// Run a pairwise consistency test for an RSA-2048 keypair
/// `(n, e, d)`, bypassing the operational gate. Returns `true` iff
/// signing a fixed probe message with `(n, d)` produces a signature
/// that verifies under `(n, e)`.
///
/// Used both by the power-up KAT (where the KAT tuple is already
/// pinned but we still re-run the test as a structural health
/// check) and by [`RsaPrivateKey2048::from_components`] after the
/// operational gate has released.
#[doc(hidden)]
pub fn pairwise_consistency_test_2048_internal(
    n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
) -> bool {
    // The probe message is arbitrary but fixed; IG 10.3.A only
    // requires that the PCT cover the sign→verify roundtrip. We pick
    // a short ASCII string that is obviously not a secret.
    const PROBE: &[u8] = b"fips-rsa PCT probe / RSA-2048 / PKCS#1 v1.5 / SHA-256";
    let Some(sig) = rsa_pkcs1_v15_sign_2048_sha256_internal(n_bytes, d_bytes, PROBE) else {
        return false;
    };
    rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, PROBE, &sig)
}

/// Private CRT components held inside an [`RsaPrivateKey2048`]. All
/// five fields are 1024-bit CSPs. When present, signing routes
/// through the Garner-recombine path with Bellcore verify-after-sign;
/// when absent, signing falls back to the direct `m^d mod n` ladder
/// on the 2048-bit context.
#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct CrtComponents {
    p_bytes: [u8; U1024_BYTES],
    q_bytes: [u8; U1024_BYTES],
    dp_bytes: [u8; U1024_BYTES],
    dq_bytes: [u8; U1024_BYTES],
    qinv_bytes: [u8; U1024_BYTES],
}

impl Drop for CrtComponents {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.p_bytes);
        oxicrypt_zeroize::zeroize(&mut self.q_bytes);
        oxicrypt_zeroize::zeroize(&mut self.dp_bytes);
        oxicrypt_zeroize::zeroize(&mut self.dq_bytes);
        oxicrypt_zeroize::zeroize(&mut self.qinv_bytes);
    }
}

/// A validated RSA-2048 private key suitable for signing.
///
/// Construction runs the FIPS 140-3 IG 10.3.A pairwise consistency
/// test against the public components `(n, e)` and fails if the
/// key does not sign-and-verify a probe message. Once constructed,
/// the handle can produce signatures without re-running the PCT on
/// each call.
///
/// # CRT sign path
///
/// When the handle carries CRT components (either from
/// [`Self::from_components_crt`] or from a fresh [`Self::generate`]
/// call), signing uses the Chinese-Remainder decomposition with a
/// Bellcore / Shamir verify-after-sign fault check. When the handle
/// was constructed through the non-CRT [`Self::from_components`]
/// path, signing uses the direct `m^d mod n` ladder and does not
/// run the Bellcore check — it is structurally impossible to fault
/// into a half-congruence when there are no halves.
#[derive(Clone)]
pub struct RsaPrivateKey2048 {
    n_bytes: [u8; RSA_2048_MODULUS_BYTES],
    d_bytes: [u8; RSA_2048_MODULUS_BYTES],
    e: u64,
    crt: Option<CrtComponents>,
}

impl Drop for RsaPrivateKey2048 {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.d_bytes);
        // CrtComponents has its own Drop; dropping Option<CrtComponents>
        // invokes it when Some.
    }
}

impl RsaPrivateKey2048 {
    /// Build a validated private-key handle from the raw `(n, e, d)`
    /// components.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module has not
    /// completed power-up self-tests. Returns [`Error::InvalidInput`]
    /// if the pairwise consistency test fails — which covers any of
    /// the following:
    ///
    ///   * `n` is not a strict 2048-bit odd integer;
    ///   * `d` is outside the range `[1, n − 1]`;
    ///   * `(n, e, d)` are structurally inconsistent (for example, a
    ///     `d` from a different keypair);
    ///   * any of the primitive subroutines encountered an internal
    ///     corruption.
    pub fn from_components(
        n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
        e: u64,
        d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
    ) -> Result<Self, Error> {
        require_operational()?;
        if !pairwise_consistency_test_2048_internal(n_bytes, e, d_bytes) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            n_bytes: *n_bytes,
            d_bytes: *d_bytes,
            e,
            crt: None,
        })
    }

    /// Build a validated CRT-form private-key handle from the raw
    /// `(n, e, d, p, q, dP, dQ, qInv)` components.
    ///
    /// The pairwise consistency test runs on the CRT sign path (with
    /// Bellcore verify-after-sign) so that a handle returned from
    /// this constructor is guaranteed to produce signatures along
    /// the same path that production calls will use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module has not
    /// completed power-up self-tests. Returns [`Error::InvalidInput`]
    /// if the CRT PCT fails for any reason.
    #[allow(clippy::too_many_arguments, clippy::similar_names, clippy::items_after_statements)]
    pub fn from_components_crt(
        n_bytes: &[u8; RSA_2048_MODULUS_BYTES],
        e: u64,
        d_bytes: &[u8; RSA_2048_MODULUS_BYTES],
        p_bytes: &[u8; U1024_BYTES],
        q_bytes: &[u8; U1024_BYTES],
        dp_bytes: &[u8; U1024_BYTES],
        dq_bytes: &[u8; U1024_BYTES],
        qinv_bytes: &[u8; U1024_BYTES],
    ) -> Result<Self, Error> {
        require_operational()?;
        // PCT on the CRT path: sign a fixed probe, verify with the
        // public key. The Bellcore check inside the CRT primitive
        // provides an additional structural guard at construction
        // time — a CRT tuple that is inconsistent with `d` will
        // fail the verify-after-sign step before the signature
        // even reaches the outer verify.
        const PROBE: &[u8] =
            b"fips-rsa CRT PCT probe / RSA-2048 / PKCS#1 v1.5 / SHA-256";
        let Some(sig) = rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
            n_bytes, e, p_bytes, q_bytes, dp_bytes, dq_bytes, qinv_bytes, PROBE,
        ) else {
            return Err(Error::InvalidInput);
        };
        if !rsa_pkcs1_v15_verify_2048_sha256_internal(n_bytes, e, PROBE, &sig) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            n_bytes: *n_bytes,
            d_bytes: *d_bytes,
            e,
            crt: Some(CrtComponents {
                p_bytes: *p_bytes,
                q_bytes: *q_bytes,
                dp_bytes: *dp_bytes,
                dq_bytes: *dq_bytes,
                qinv_bytes: *qinv_bytes,
            }),
        })
    }

    /// Public modulus, big-endian, 256 bytes.
    #[must_use]
    pub fn modulus_bytes(&self) -> &[u8; RSA_2048_MODULUS_BYTES] {
        &self.n_bytes
    }

    /// Public exponent.
    #[must_use]
    pub fn public_exponent(&self) -> u64 {
        self.e
    }

    /// Sign `msg` with RSASSA-PKCS1-v1_5 using SHA-256 as the message
    /// digest. Returns a 256-byte signature on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational at call time, or [`Error::InvalidInput`] if
    /// the internal sign primitive rejects the pinned modulus or the
    /// pinned private exponent (which should never happen for a
    /// handle successfully returned from [`Self::from_components`] —
    /// if it does, the module is corrupted).
    pub fn sign_pkcs1_v15_sha256(
        &self,
        msg: &[u8],
    ) -> Result<[u8; RSA_2048_SIGNATURE_BYTES], Error> {
        require_operational()?;
        if let Some(crt) = self.crt.as_ref() {
            // CRT + Bellcore path.
            rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
                &self.n_bytes,
                self.e,
                &crt.p_bytes,
                &crt.q_bytes,
                &crt.dp_bytes,
                &crt.dq_bytes,
                &crt.qinv_bytes,
                msg,
            )
            .ok_or(Error::InvalidInput)
        } else {
            rsa_pkcs1_v15_sign_2048_sha256_internal(&self.n_bytes, &self.d_bytes, msg)
                .ok_or(Error::InvalidInput)
        }
    }

    /// Sign `msg` with RSASSA-PSS using SHA-256 as both the message
    /// hash and the MGF1 hash, with the caller-supplied salt. Returns
    /// a 256-byte signature on success.
    ///
    /// # Salt sourcing
    ///
    /// Exposing the salt to the caller rather than internally sampling
    /// it keeps the crate free of a randomness dependency in R3. The
    /// R4 keygen chunk will add a DRBG-backed wrapper
    /// (`sign_pss_sha256`) that samples a fresh `hLen`-byte salt and
    /// then calls this method. FIPS 186-5 §5.4 permits any
    /// `sLen ∈ [0, hLen]`; we fix it at `hLen` to keep the KAT
    /// deterministic and match the IG 10.3.A recommendation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational at call time, or [`Error::InvalidInput`] if
    /// the internal primitive rejects the pinned key material.
    pub fn sign_pss_sha256_with_salt(
        &self,
        msg: &[u8],
        salt: &[u8; pss::SLEN],
    ) -> Result<[u8; RSA_2048_SIGNATURE_BYTES], Error> {
        require_operational()?;
        if let Some(crt) = self.crt.as_ref() {
            rsa_pss_sign_2048_sha256_crt_internal(
                &self.n_bytes,
                self.e,
                &crt.p_bytes,
                &crt.q_bytes,
                &crt.dp_bytes,
                &crt.dq_bytes,
                &crt.qinv_bytes,
                msg,
                salt,
            )
            .ok_or(Error::InvalidInput)
        } else {
            rsa_pss_sign_2048_sha256_internal(&self.n_bytes, &self.d_bytes, msg, salt)
                .ok_or(Error::InvalidInput)
        }
    }

    /// Sign `msg` with RSASSA-PSS SHA-256, sampling a fresh `hLen`-byte
    /// salt from the caller-supplied DRBG. This is the R4 DRBG-backed
    /// PSS wrapper that FIPS 186-5 §5.4 recommends: the salt is fresh
    /// per-signature so that signing the same message twice produces
    /// two different signatures, avoiding multi-target attacks.
    ///
    /// The DRBG must be instantiated before calling. It is advanced by
    /// exactly one `generate` call of [`pss::SLEN`] = 32 bytes per
    /// invocation — callers running long signing campaigns should
    /// re-seed according to their SP 800-90A reseed policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational, or [`Error::InvalidInput`] if the DRBG
    /// reports a failure or the internal primitive rejects the pinned
    /// key material.
    pub fn sign_pss_sha256(
        &self,
        drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
        msg: &[u8],
    ) -> Result<[u8; RSA_2048_SIGNATURE_BYTES], Error> {
        require_operational()?;
        let mut salt = [0u8; pss::SLEN];
        drbg.generate(None, &mut salt).map_err(|_| Error::InvalidInput)?;
        rsa_pss_sign_2048_sha256_internal(&self.n_bytes, &self.d_bytes, msg, &salt)
            .ok_or(Error::InvalidInput)
    }

    /// Decrypt an RSAES-OAEP ciphertext using SHA-256 for both the
    /// label hash and the MGF1 hash. Writes the recovered plaintext
    /// into `out` and returns the plaintext length on success.
    ///
    /// The `label` must match the one used at encryption time — an
    /// empty label is the conventional default for KEM-style use.
    /// The `out` buffer is sized to [`oaep::MAX_MSG_LEN`] = 190 bytes,
    /// the largest plaintext an RSA-2048 SHA-256 OAEP ciphertext can
    /// carry; the returned length may be anywhere in `[0, 190]`.
    ///
    /// # Bellcore protection
    ///
    /// If this handle was built through [`Self::from_components_crt`]
    /// or [`Self::generate`] (both of which retain the CRT components),
    /// decryption runs through the same Garner recombine + Bellcore
    /// verify-after-decrypt primitive as the sign path per FIPS 140-3
    /// IG D.G. A single fault on either CRT half is caught and
    /// collapsed into a generic `InvalidInput`, so a corrupted
    /// decryption never leaks `p` or `q` to the caller.
    ///
    /// # Manger resistance
    ///
    /// All OAEP decode failures — bad `Y` byte, `lHash'` mismatch,
    /// malformed `PS`, missing `0x01` delimiter, wrong label — return
    /// the same [`Error::InvalidInput`] without revealing which check
    /// failed, and the decode routine runs MGF1 unmask to completion
    /// regardless of where the first failure occurred. See
    /// [`oaep::emsa_oaep_decode`] for the contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is no
    /// longer operational at call time, or [`Error::InvalidInput`] on
    /// any decode failure or internal rejection by the private-key
    /// primitive.
    pub fn decrypt_oaep_sha256(
        &self,
        label: &[u8],
        ct: &[u8; RSA_2048_MODULUS_BYTES],
        out: &mut [u8; oaep::MAX_MSG_LEN],
    ) -> Result<usize, Error> {
        require_operational()?;
        if let Some(crt) = self.crt.as_ref() {
            rsa_oaep_decrypt_2048_sha256_crt_internal(
                &self.n_bytes,
                self.e,
                &crt.p_bytes,
                &crt.q_bytes,
                &crt.dp_bytes,
                &crt.dq_bytes,
                &crt.qinv_bytes,
                label,
                ct,
                out,
            )
            .ok_or(Error::InvalidInput)
        } else {
            rsa_oaep_decrypt_2048_sha256_nocrt_internal(
                &self.n_bytes,
                &self.d_bytes,
                label,
                ct,
                out,
            )
            .ok_or(Error::InvalidInput)
        }
    }

    /// Generate a fresh RSA-2048 keypair using the caller-supplied
    /// HMAC_DRBG-SHA-256 for all randomness, per FIPS 186-5 §A.1.1 /
    /// §B.3.1. `e` must be an odd prime in `[65537, 2^64)` (in
    /// practice, pass `65537`).
    ///
    /// The generated keypair is run through the IG 10.3.A pairwise
    /// consistency test before the handle is returned — a `generate`
    /// call that succeeds has already produced a sign/verify pair
    /// that roundtrips a probe message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotOperational`] if the FIPS module is not
    /// yet operational. Returns [`Error::InvalidInput`] on any of:
    ///
    ///   * `e` fails the structural check (`e < 65537` or `e` even);
    ///   * the DRBG rejects a request (e.g. not instantiated or
    ///     reseed required);
    ///   * the prime-candidate retry budget is exceeded;
    ///   * the resulting keypair fails the pairwise consistency
    ///     test (which indicates internal corruption).
    #[allow(clippy::similar_names)]
    pub fn generate(
        drbg: &mut oxicrypt_drbg::HmacDrbgSha256,
        e: u64,
    ) -> Result<Self, Error> {
        require_operational()?;
        let km = keygen::generate_2048(drbg, e).map_err(|_| Error::InvalidInput)?;
        let n_bytes = km.n.to_be_bytes();
        let d_bytes = km.d.to_be_bytes();
        let p_bytes = km.p.to_be_bytes();
        let q_bytes = km.q.to_be_bytes();
        let dp_bytes = km.dp.to_be_bytes();
        let dq_bytes = km.dq.to_be_bytes();
        let qinv_bytes = km.qinv.to_be_bytes();
        Self::from_components_crt(
            &n_bytes, e, &d_bytes, &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes,
        )
    }
}

// ------------------------------------------------------------------
// Pinned KAT material
// ------------------------------------------------------------------

/// Pinned RSA-2048 public modulus used by the power-up KAT. Generated
/// deterministically from a fixed PRNG seed.
const KAT_N_BYTES: [u8; 256] = [
    0xb1, 0xb2, 0x5f, 0x95, 0x6b, 0xa0, 0x4b, 0x22, 0xdf, 0x1c, 0x8b, 0x1f, 0xee, 0x4a, 0x47, 0x28,
    0x48, 0x92, 0xac, 0x1a, 0xe1, 0x6b, 0x62, 0x05, 0xba, 0x30, 0x2c, 0xdf, 0x03, 0x32, 0x43, 0xf3,
    0xcb, 0x96, 0x8c, 0x6d, 0x6f, 0x3b, 0xe4, 0xda, 0xb6, 0xf8, 0x61, 0x98, 0x36, 0x66, 0xfa, 0x06,
    0x9b, 0x37, 0xd0, 0x15, 0x6d, 0x61, 0x6f, 0xd8, 0x37, 0xae, 0x8a, 0x52, 0x4c, 0xf5, 0xee, 0x66,
    0x20, 0x27, 0xa0, 0xde, 0x1a, 0xf6, 0x7b, 0xb3, 0x7d, 0x5d, 0x18, 0xe3, 0x10, 0xcd, 0x37, 0xa8,
    0x67, 0x9b, 0xe3, 0x1d, 0x66, 0x19, 0xe1, 0xfa, 0x8a, 0x9b, 0xd4, 0x46, 0x8a, 0x16, 0x65, 0x72,
    0xf5, 0xa2, 0x75, 0xca, 0x23, 0x8e, 0x99, 0x98, 0xce, 0xf3, 0x1f, 0x24, 0xb3, 0x37, 0x61, 0x77,
    0xae, 0xad, 0x1f, 0x41, 0xa7, 0x0b, 0xe3, 0xd5, 0x2b, 0xb3, 0x77, 0x32, 0x51, 0x24, 0x5c, 0x2f,
    0xd0, 0x1b, 0xb6, 0x89, 0x52, 0x49, 0xa8, 0x60, 0x39, 0xf4, 0xdb, 0x74, 0xdd, 0x84, 0x24, 0x62,
    0xb7, 0xba, 0x2d, 0x8a, 0x77, 0x63, 0x41, 0x3b, 0x26, 0x18, 0x7a, 0x16, 0x18, 0x32, 0x62, 0x91,
    0x44, 0xf6, 0x1f, 0x59, 0x33, 0x39, 0x62, 0xe3, 0x3e, 0x75, 0x6c, 0xb7, 0xa2, 0xf4, 0x61, 0xf1,
    0xba, 0xd9, 0x54, 0xc2, 0x92, 0xda, 0x40, 0x5f, 0x0a, 0x07, 0x19, 0xbc, 0x73, 0xa6, 0xda, 0x88,
    0x7d, 0x13, 0x31, 0xd0, 0x91, 0x73, 0xa0, 0x19, 0x12, 0xfb, 0x3a, 0x4d, 0x27, 0xe8, 0x3d, 0xb4,
    0xd0, 0xf4, 0x8c, 0x7b, 0x0f, 0x5d, 0x13, 0xce, 0x35, 0xd4, 0x23, 0xd4, 0x2e, 0x78, 0x1a, 0xda,
    0x29, 0x95, 0x50, 0x2a, 0xb5, 0x09, 0xd7, 0x95, 0x39, 0xda, 0x50, 0x7a, 0xe2, 0xa2, 0x08, 0xbb,
    0x1c, 0xcc, 0xf0, 0x43, 0xe2, 0xfc, 0x0f, 0xcc, 0x4a, 0x05, 0xd8, 0xd4, 0xda, 0x45, 0x6c, 0x6d,
];

/// Pinned public exponent for the KAT.
const KAT_E: u64 = 65537;

/// Pinned RSA-2048 private exponent matching `(KAT_N_BYTES, KAT_E)`.
///
/// Kept inside the module so the KAT can exercise the sign path
/// alongside the verify path. The primes `p` and `q` that generated
/// this `d` are not retained: the non-CRT sign path only needs
/// `(n, d)`, and we intentionally keep the KAT tuple minimal until
/// the CRT path lands in R3.
const KAT_D_BYTES: [u8; 256] = [
    0x22, 0xc2, 0x95, 0xd8, 0x10, 0xd9, 0xa6, 0x59, 0x07, 0xf3, 0xf9, 0x73, 0x21, 0x95, 0xfe, 0x1d,
    0x6f, 0x34, 0xe1, 0xdd, 0xd0, 0x42, 0xc5, 0x46, 0x01, 0x89, 0xf2, 0xfd, 0x1d, 0x0e, 0xf4, 0x23,
    0xf8, 0xab, 0x56, 0x85, 0x01, 0xc1, 0x61, 0x9f, 0x37, 0x33, 0x97, 0x43, 0xc3, 0x40, 0x99, 0xa0,
    0x39, 0x34, 0xcd, 0xcb, 0xa3, 0x3d, 0xf0, 0x37, 0x07, 0x8d, 0x69, 0x19, 0x78, 0x5c, 0x93, 0x69,
    0xfe, 0xd8, 0x41, 0xab, 0xb0, 0xf2, 0x8e, 0x78, 0x2a, 0x09, 0xd0, 0x18, 0x7a, 0xec, 0xe9, 0xfa,
    0x53, 0x6a, 0x37, 0x1f, 0x45, 0x1d, 0xc3, 0x0a, 0xd3, 0x9a, 0x70, 0x07, 0xec, 0x73, 0x3d, 0x1d,
    0x23, 0xd7, 0xc7, 0xda, 0xe6, 0xe1, 0xba, 0x42, 0x1e, 0x19, 0x88, 0xfa, 0x10, 0xe4, 0xc0, 0x78,
    0x3c, 0xff, 0x38, 0xa2, 0x0b, 0x1f, 0x54, 0x4e, 0x1a, 0xe2, 0x5c, 0x6a, 0xc7, 0x5c, 0xa9, 0x7b,
    0x8d, 0x31, 0x7a, 0x17, 0x14, 0x91, 0xeb, 0x54, 0xdf, 0xf3, 0x2b, 0x0e, 0x5c, 0x44, 0xf2, 0xe7,
    0xed, 0x99, 0x7e, 0x27, 0x08, 0x2b, 0xb1, 0x4f, 0x90, 0x00, 0xc4, 0xc4, 0xf3, 0xc2, 0x01, 0x18,
    0xbc, 0x63, 0x16, 0x9e, 0x64, 0xdb, 0xb3, 0x1f, 0xe1, 0x84, 0x70, 0x60, 0x1d, 0xc4, 0xb7, 0x7c,
    0x1e, 0x3f, 0x3f, 0x22, 0xc3, 0xb5, 0x35, 0xfb, 0x27, 0x27, 0xcd, 0x57, 0xf0, 0x34, 0xc3, 0x32,
    0xb0, 0x71, 0xfd, 0x87, 0x59, 0x76, 0x47, 0xb2, 0x26, 0xe5, 0x06, 0xe2, 0xec, 0x5a, 0x86, 0xfa,
    0xcc, 0x51, 0xce, 0xb0, 0x0b, 0xb7, 0xc5, 0xaa, 0xb7, 0xc4, 0x0e, 0xcf, 0xf8, 0x63, 0xad, 0x40,
    0x5d, 0x27, 0x54, 0x36, 0xbf, 0xb4, 0x6d, 0x8b, 0x03, 0x6d, 0x7b, 0x1f, 0x70, 0x91, 0x17, 0x2b,
    0xe1, 0x88, 0x16, 0x4c, 0xaf, 0x14, 0xf0, 0xc2, 0x3e, 0x64, 0x4c, 0x4a, 0x1e, 0xfd, 0xc3, 0xb1,
];

/// Message covered by the KAT signature.
const KAT_MSG: &[u8] = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT";

/// Pinned RSASSA-PKCS1-v1_5 signature of `KAT_MSG` under `(KAT_N, KAT_E)`.
const KAT_SIG_BYTES: [u8; 256] = [
    0x12, 0x26, 0x65, 0x1f, 0x47, 0x0b, 0xc2, 0x86, 0x25, 0x6c, 0x3a, 0x92, 0xdb, 0x77, 0xee, 0x9a,
    0xeb, 0x44, 0x7b, 0xf0, 0x26, 0x57, 0xe3, 0xb3, 0x4a, 0x9d, 0x60, 0xba, 0xfd, 0x00, 0xb2, 0xae,
    0xc7, 0x54, 0xed, 0x16, 0x3d, 0x1a, 0x9c, 0x1e, 0xe1, 0x7e, 0xa9, 0x70, 0xdd, 0xa3, 0x9c, 0x5d,
    0x04, 0xa4, 0x56, 0xc7, 0x7e, 0x0c, 0x78, 0x5a, 0x22, 0x52, 0x29, 0x73, 0x0c, 0xc9, 0xa7, 0xc6,
    0x5f, 0xc0, 0x76, 0xe9, 0xc2, 0x3d, 0xa8, 0x2c, 0xf7, 0xfb, 0xc1, 0x13, 0xea, 0x7e, 0xef, 0xb7,
    0xf0, 0x50, 0xc8, 0x3b, 0xdb, 0x08, 0xfe, 0xd2, 0x7f, 0xa2, 0xe8, 0x20, 0x39, 0x9c, 0xfe, 0x5a,
    0x45, 0x91, 0xd9, 0xde, 0xf9, 0x21, 0xe6, 0x09, 0xb6, 0xb9, 0xc5, 0x1d, 0xb6, 0x39, 0x14, 0x3f,
    0xc9, 0x46, 0x07, 0x66, 0xb2, 0xb1, 0x70, 0x2d, 0x4c, 0x27, 0x94, 0x60, 0xc1, 0x5d, 0x3b, 0x8c,
    0xfd, 0x79, 0x5a, 0xff, 0xd1, 0xa3, 0x0e, 0xc2, 0xd9, 0xa5, 0x6f, 0xd2, 0xb4, 0x90, 0xa4, 0x8b,
    0x50, 0xab, 0x69, 0xad, 0xf1, 0x9f, 0x7a, 0xf2, 0x10, 0xa6, 0x9a, 0x27, 0x50, 0xc1, 0x11, 0x7b,
    0xaf, 0x77, 0x8b, 0xdd, 0x84, 0x93, 0xa3, 0xc3, 0x25, 0x9e, 0xda, 0x69, 0xb3, 0x32, 0x85, 0xeb,
    0x00, 0x08, 0x9f, 0x9d, 0xa8, 0x6d, 0x2a, 0x21, 0xd2, 0x97, 0xf4, 0x4a, 0xeb, 0xbb, 0x3d, 0x70,
    0x18, 0x42, 0xac, 0xb9, 0x04, 0xac, 0x93, 0x95, 0x6d, 0x43, 0x01, 0x70, 0xfe, 0x91, 0xd8, 0x44,
    0x97, 0xe3, 0x77, 0x29, 0x57, 0x8c, 0xf6, 0x48, 0x02, 0x35, 0xa4, 0x7a, 0x6a, 0x02, 0x60, 0x68,
    0x12, 0x94, 0x3e, 0x5f, 0x37, 0xb0, 0x70, 0x57, 0x90, 0xed, 0x50, 0x42, 0x96, 0x85, 0x1e, 0x1c,
    0x2c, 0x27, 0xc7, 0xa1, 0x6a, 0x87, 0xa7, 0x21, 0x86, 0x89, 0xec, 0xe6, 0x73, 0x3d, 0xf4, 0xcd,
];

/// Pinned PSS salt used by the power-up KAT. Derived deterministically
/// from `SHA-256("oxicrypt-pss-kat-salt-v1")` and fixed at 32 bytes
/// (`sLen = hLen`). The value itself is not secret — it is the fresh
/// salt a correctly-implemented PSS signer would have sampled on the
/// one invocation that produced `KAT_PSS_SIG_BYTES`.
const KAT_PSS_SALT: [u8; 32] = [
    0x2f, 0x2f, 0x43, 0x3a, 0xbc, 0x18, 0x81, 0x24, 0x32, 0xdd, 0x17, 0xa9, 0x40, 0xb3, 0x88, 0xb6,
    0x39, 0x3b, 0x39, 0x98, 0x63, 0x5e, 0xce, 0x23, 0x89, 0xca, 0xf0, 0x7d, 0x34, 0x78, 0xb7, 0x27,
];

/// Message covered by the PSS KAT signature.
const KAT_PSS_MSG: &[u8] = b"pqclib FIPS RSA-2048 PSS SHA-256 power-up KAT";

/// Pinned RSASSA-PSS signature of `KAT_PSS_MSG` under `(KAT_N, KAT_D)`
/// with salt `KAT_PSS_SALT`.
const KAT_PSS_SIG_BYTES: [u8; 256] = [
    0x97, 0x9a, 0x30, 0xd1, 0xd9, 0x2e, 0x5b, 0x7f, 0x23, 0x5f, 0x53, 0xf0, 0xc8, 0x27, 0xbd, 0xe1,
    0xee, 0x89, 0x06, 0xc4, 0x4d, 0x80, 0xba, 0x1b, 0x8d, 0x65, 0xc9, 0x4e, 0xbd, 0x34, 0x00, 0xd9,
    0x33, 0xa3, 0xf4, 0x76, 0xe0, 0x71, 0x5d, 0xea, 0xc4, 0x56, 0x8c, 0xda, 0xcb, 0x4b, 0xee, 0xea,
    0x1b, 0xaf, 0x47, 0xbd, 0x0d, 0xcc, 0x3d, 0x40, 0x8f, 0x79, 0xc7, 0xa9, 0x6d, 0x0d, 0xe2, 0x7f,
    0x07, 0x23, 0x05, 0x10, 0x65, 0xfd, 0x38, 0xab, 0x6c, 0x6c, 0x5d, 0x1a, 0x67, 0x1d, 0xa4, 0xd9,
    0x2a, 0x61, 0x84, 0xb1, 0xbf, 0xf0, 0x7a, 0xba, 0x53, 0xf4, 0xb5, 0x50, 0x98, 0x90, 0x22, 0xcb,
    0x6a, 0xb2, 0x9e, 0x6c, 0x0d, 0xf9, 0x0b, 0x41, 0xdd, 0x4c, 0x45, 0x66, 0x13, 0x20, 0xfc, 0x77,
    0x1e, 0x49, 0x4a, 0x2b, 0xcc, 0x2f, 0xc1, 0xde, 0x86, 0x50, 0xe7, 0x47, 0x44, 0xc1, 0xf7, 0xeb,
    0x92, 0x8c, 0xbb, 0xb3, 0x48, 0xff, 0x0c, 0xdb, 0xce, 0xb7, 0x8f, 0xb4, 0x45, 0xb5, 0xad, 0xfa,
    0xd6, 0x53, 0xef, 0xd6, 0x89, 0x6a, 0x59, 0x6c, 0x3a, 0x90, 0xa9, 0x71, 0xdd, 0x15, 0x41, 0x8c,
    0x51, 0x01, 0x0a, 0xea, 0xc6, 0x30, 0x67, 0x5a, 0xec, 0x1b, 0x06, 0xbc, 0xb8, 0xf9, 0x75, 0x24,
    0x4c, 0xbc, 0x3e, 0x3d, 0x5c, 0x84, 0x8e, 0xce, 0x23, 0xe8, 0x54, 0x03, 0x64, 0xb6, 0xef, 0x30,
    0xfd, 0x9e, 0xd4, 0x6c, 0x91, 0x94, 0x9d, 0x6c, 0xb5, 0x83, 0xfa, 0xc4, 0x69, 0xb6, 0x6b, 0x62,
    0x2f, 0x91, 0x8d, 0xb7, 0x02, 0xbc, 0xbf, 0xd5, 0x8c, 0x39, 0xa6, 0xc6, 0x4e, 0xc1, 0xf3, 0x8e,
    0x1c, 0x9c, 0xb2, 0x46, 0xed, 0x07, 0xf8, 0xe1, 0xa2, 0xf2, 0x82, 0x09, 0xf5, 0xbf, 0xe2, 0x5d,
    0x56, 0xbd, 0x5d, 0xe2, 0x2c, 0x70, 0x39, 0xfe, 0xb1, 0x1b, 0xde, 0x87, 0x74, 0x2a, 0x89, 0x31,
];

// ------------------------------------------------------------------
// Power-up known-answer test
// ------------------------------------------------------------------

/// Power-up KAT for the RSA-2048 PKCS#1 v1.5 / PSS SHA-256 services.
///
/// Runs, against the pinned `(n, e, d)` keypair:
///
/// 1. PKCS#1 v1.5 verify of the pinned signature.
/// 2. PKCS#1 v1.5 tamper-rejection (flip the trailing byte).
/// 3. PKCS#1 v1.5 sign reproduces the pinned signature byte-for-byte,
///    exercising the constant-time windowed ladder and EMSA encoder.
/// 4. Pairwise consistency on `(n, e, d)` for PKCS#1 v1.5.
/// 5. PSS sign with the pinned salt reproduces the pinned PSS
///    signature byte-for-byte, exercising MGF1, EMSA-PSS-ENCODE and
///    the same ladder path.
/// 6. PSS verify of the pinned PSS signature succeeds, exercising
///    EMSA-PSS-VERIFY and the public-exponent ladder.
/// 7. PSS tamper-rejection: flipping a byte in the `maskedDB` portion
///    of the signature is rejected — this specifically catches
///    breakage in the MGF1 mask recovery path, which a tamper on the
///    trailing `0xbc` would not.
pub fn self_test() -> Result<(), SelfTestFailure> {
    // PKCS#1 v1.5 verify (positive).
    if !rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES) {
        return Err(SelfTestFailure);
    }
    // PKCS#1 v1.5 verify (tamper).
    let mut tampered = KAT_SIG_BYTES;
    tampered[255] ^= 0x01;
    if rsa_pkcs1_v15_verify_2048_sha256_internal(&KAT_N_BYTES, KAT_E, KAT_MSG, &tampered) {
        return Err(SelfTestFailure);
    }
    // PKCS#1 v1.5 sign (KAT reproduction).
    let Some(produced) =
        rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, KAT_MSG)
    else {
        return Err(SelfTestFailure);
    };
    if produced != KAT_SIG_BYTES {
        return Err(SelfTestFailure);
    }
    // PCT.
    if !pairwise_consistency_test_2048_internal(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES) {
        return Err(SelfTestFailure);
    }
    // PSS sign (KAT reproduction).
    let Some(pss_produced) = rsa_pss_sign_2048_sha256_internal(
        &KAT_N_BYTES,
        &KAT_D_BYTES,
        KAT_PSS_MSG,
        &KAT_PSS_SALT,
    ) else {
        return Err(SelfTestFailure);
    };
    if pss_produced != KAT_PSS_SIG_BYTES {
        return Err(SelfTestFailure);
    }
    // PSS verify (positive).
    if !rsa_pss_verify_2048_sha256_internal(
        &KAT_N_BYTES,
        KAT_E,
        KAT_PSS_MSG,
        &KAT_PSS_SIG_BYTES,
    ) {
        return Err(SelfTestFailure);
    }
    // PSS verify (tamper inside maskedDB, not the trailer).
    let mut pss_tampered = KAT_PSS_SIG_BYTES;
    pss_tampered[10] ^= 0x01;
    if rsa_pss_verify_2048_sha256_internal(
        &KAT_N_BYTES,
        KAT_E,
        KAT_PSS_MSG,
        &pss_tampered,
    ) {
        return Err(SelfTestFailure);
    }
    Ok(())
}

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "RSA KAT (PKCS#1v1.5+PSS sign+verify+tamper+PCT, FIPS 186-5)",
    run: self_test,
}];

// Silence an otherwise-unused re-export: downstream users of the
// crate may want the hash length constant without pulling in
// `fips-sha` directly.
#[doc(hidden)]
pub const __SHA256_DIGEST_SIZE: usize = SHA256_DIGEST_SIZE;

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use oxicrypt_module::{initialize_with_tests, KatEntry};

    #[test]
    fn kat_positive_verifies() {
        assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_flipped_signature() {
        let mut bad = KAT_SIG_BYTES;
        bad[128] ^= 0x80;
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &bad
        ));
    }

    #[test]
    fn kat_rejects_wrong_message() {
        let bad_msg = b"pqclib FIPS RSA-2048 PKCS1v15 SHA-256 power-up KAT (tampered)";
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, bad_msg, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_even_modulus() {
        let mut bad_n = KAT_N_BYTES;
        bad_n[255] &= 0xfe;
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &bad_n, KAT_E, KAT_MSG, &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn kat_rejects_signature_ge_modulus() {
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES, KAT_E, KAT_MSG, &KAT_N_BYTES
        ));
    }

    #[test]
    fn sign_reproduces_pinned_signature() {
        let produced =
            rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, KAT_MSG).unwrap();
        assert_eq!(produced, KAT_SIG_BYTES);
    }

    #[test]
    fn sign_then_verify_roundtrips_for_multiple_messages() {
        let messages: [&[u8]; 4] = [
            b"",
            b"a",
            b"The quick brown fox jumps over the lazy dog",
            &[0xa5u8; 256],
        ];
        for msg in messages {
            let sig =
                rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_D_BYTES, msg).unwrap();
            assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
                &KAT_N_BYTES, KAT_E, msg, &sig
            ));
        }
    }

    #[test]
    fn sign_rejects_d_equal_to_n() {
        // d must be strictly less than n; using n-as-d should be
        // rejected for the same reason signatures are.
        assert!(
            rsa_pkcs1_v15_sign_2048_sha256_internal(&KAT_N_BYTES, &KAT_N_BYTES, KAT_MSG).is_none()
        );
    }

    #[test]
    fn pct_passes_on_pinned_keypair() {
        assert!(pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, KAT_E, &KAT_D_BYTES
        ));
    }

    #[test]
    fn pct_fails_when_d_is_tampered() {
        let mut bad_d = KAT_D_BYTES;
        bad_d[0] ^= 0x01;
        assert!(!pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, KAT_E, &bad_d
        ));
    }

    #[test]
    fn pct_fails_when_e_is_wrong() {
        // Using e = 3 against a key that was generated with e = 65537
        // must fail the PCT because 3 is coprime with phi and the
        // wrong exponent will produce nonsense signatures.
        assert!(!pairwise_consistency_test_2048_internal(
            &KAT_N_BYTES, 3, &KAT_D_BYTES
        ));
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn private_key_construction_runs_pct_and_signs() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES)
            .expect("pinned keypair passes PCT");
        let sig = sk
            .sign_pkcs1_v15_sha256(KAT_MSG)
            .expect("module operational, sign succeeds");
        assert_eq!(sig, KAT_SIG_BYTES);
        rsa_pkcs1_v15_verify_2048_sha256(&KAT_N_BYTES, KAT_E, KAT_MSG, &sig)
            .expect("freshly produced signature verifies");
    }

    #[test]
    fn pss_kat_sign_reproduces_pinned_signature() {
        let produced = rsa_pss_sign_2048_sha256_internal(
            &KAT_N_BYTES,
            &KAT_D_BYTES,
            KAT_PSS_MSG,
            &KAT_PSS_SALT,
        )
        .unwrap();
        assert_eq!(produced, KAT_PSS_SIG_BYTES);
    }

    #[test]
    fn pss_kat_positive_verifies() {
        assert!(rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &KAT_PSS_SIG_BYTES
        ));
    }

    #[test]
    fn pss_rejects_flipped_trailer() {
        let mut bad = KAT_PSS_SIG_BYTES;
        bad[255] ^= 0x01;
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &bad
        ));
    }

    #[test]
    fn pss_rejects_tamper_in_masked_db() {
        // A flip inside the maskedDB half of the signature perturbs
        // the recovered DB once MGF1 unmasks it, which should fail
        // either the PS-zeroes check or the H' compare.
        let mut bad = KAT_PSS_SIG_BYTES;
        bad[0] ^= 0x40;
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &bad
        ));
    }

    #[test]
    fn pss_rejects_wrong_message() {
        let bad_msg = b"pqclib FIPS RSA-2048 PSS SHA-256 power-up KAT (tampered)";
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            bad_msg,
            &KAT_PSS_SIG_BYTES
        ));
    }

    #[test]
    fn pss_sign_verify_roundtrips_across_salts_and_messages() {
        let messages: [&[u8]; 4] = [
            b"",
            b"a",
            b"The quick brown fox jumps over the lazy dog",
            &[0x5au8; 512],
        ];
        let salts: [[u8; 32]; 2] = [[0u8; 32], [0xa5u8; 32]];
        for msg in messages {
            for salt in &salts {
                let sig = rsa_pss_sign_2048_sha256_internal(
                    &KAT_N_BYTES,
                    &KAT_D_BYTES,
                    msg,
                    salt,
                )
                .unwrap();
                assert!(rsa_pss_verify_2048_sha256_internal(
                    &KAT_N_BYTES,
                    KAT_E,
                    msg,
                    &sig
                ));
            }
        }
    }

    #[test]
    fn pss_cross_scheme_signature_does_not_verify_as_pkcs1() {
        // A PSS signature must not accidentally verify as a PKCS#1
        // v1.5 signature over the same message, and vice-versa.
        assert!(!rsa_pkcs1_v15_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_PSS_MSG,
            &KAT_PSS_SIG_BYTES
        ));
        assert!(!rsa_pss_verify_2048_sha256_internal(
            &KAT_N_BYTES,
            KAT_E,
            KAT_MSG,
            &KAT_SIG_BYTES
        ));
    }

    #[test]
    fn private_key_sign_pss_then_public_verify() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES)
            .expect("pinned keypair passes PCT");
        let sig = sk
            .sign_pss_sha256_with_salt(KAT_PSS_MSG, &KAT_PSS_SALT)
            .expect("module operational, PSS sign succeeds");
        assert_eq!(sig, KAT_PSS_SIG_BYTES);
        rsa_pss_verify_2048_sha256(&KAT_N_BYTES, KAT_E, KAT_PSS_MSG, &sig)
            .expect("pinned PSS signature verifies via gated API");
    }

    #[test]
    fn private_key_construction_rejects_bad_d() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-pkcs1v15-sha256",
            run: self_test,
        }]);
        let mut bad_d = KAT_D_BYTES;
        bad_d[255] ^= 0x01;
        match RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &bad_d) {
            Err(Error::InvalidInput) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("PCT must reject a tampered d"),
        }
    }

    /// End-to-end R4 smoke: generate a fresh keypair from a DRBG,
    /// sign via the DRBG-backed PSS wrapper, verify with the gated
    /// public API. This exercises the whole R4 surface in one shot.
    #[test]
    fn generate_then_pss_sign_and_verify() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r4-gen-pss",
            run: self_test,
        }]);

        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(
            b"pqclib-r4-e2e-entropy-input-001",
            b"pqclib-r4-e2e-nonce",
            b"",
        )
        .expect("drbg instantiates");

        let sk =
            RsaPrivateKey2048::generate(&mut drbg, 65537).expect("keygen + PCT succeeds");

        // Two signatures over the same message must differ because
        // the salt is sampled fresh per call, then both must verify.
        let msg = b"pqclib R4: generate + PSS sign e2e";
        let sig1 = sk
            .sign_pss_sha256(&mut drbg, msg)
            .expect("drbg-backed PSS sign #1");
        let sig2 = sk
            .sign_pss_sha256(&mut drbg, msg)
            .expect("drbg-backed PSS sign #2");
        assert_ne!(sig1, sig2, "PSS signatures must differ (fresh salt)");

        let n = sk.modulus_bytes();
        rsa_pss_verify_2048_sha256(n, 65537, msg, &sig1)
            .expect("sig1 verifies");
        rsa_pss_verify_2048_sha256(n, 65537, msg, &sig2)
            .expect("sig2 verifies");
    }

    /// R5: a freshly-generated key exposes the CRT path and the CRT
    /// sign primitive produces a signature that matches what the
    /// non-CRT `d`-based primitive would produce over the same
    /// keypair. This is the byte-exact CRT↔non-CRT equivalence
    /// property that FIPS 186-5 §5.4 implicitly requires.
    #[test]
    #[allow(clippy::similar_names)]
    fn r5_crt_sign_equals_non_crt_sign_for_fresh_keypair() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r5-crt-equiv",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r5-crt-equiv-entropy-v1", b"pqclib-r5-crt-nonce", b"")
            .unwrap();

        // Pull raw keygen material so we can exercise both paths on
        // the same (n, e, d) with and without CRT plumbing.
        let km = keygen::generate_2048(&mut drbg, 65537).unwrap();
        let n_bytes = km.n.to_be_bytes();
        let d_bytes = km.d.to_be_bytes();
        let p_bytes = km.p.to_be_bytes();
        let q_bytes = km.q.to_be_bytes();
        let dp_bytes = km.dp.to_be_bytes();
        let dq_bytes = km.dq.to_be_bytes();
        let qinv_bytes = km.qinv.to_be_bytes();

        let msg = b"pqclib R5 CRT equivalence probe";
        let sig_non_crt =
            rsa_pkcs1_v15_sign_2048_sha256_internal(&n_bytes, &d_bytes, msg).unwrap();
        let sig_crt = rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
            &n_bytes, 65537, &p_bytes, &q_bytes, &dp_bytes, &dq_bytes, &qinv_bytes, msg,
        )
        .unwrap();
        assert_eq!(
            sig_non_crt, sig_crt,
            "CRT and non-CRT sign must agree byte-for-byte"
        );

        // And both signatures must verify via the public path.
        assert!(rsa_pkcs1_v15_verify_2048_sha256_internal(
            &n_bytes, 65537, msg, &sig_crt
        ));
    }

    /// R5 Bellcore fault injection: a single-byte tamper on `dP` (or
    /// `dQ`) that preserves the modulus length must be caught by the
    /// verify-after-sign check inside the CRT primitive — a
    /// faulted CRT signature satisfies `s ≡ m^d (mod q)` but not
    /// `s ≡ m^d (mod p)`, and `s^e mod n ≠ m`.
    #[test]
    #[allow(clippy::similar_names)]
    fn r5_bellcore_rejects_tampered_dp() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r5-bellcore",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r5-bellcore-entropy-v1", b"pqclib-r5-bellcore-nonce", b"")
            .unwrap();
        let km = keygen::generate_2048(&mut drbg, 65537).unwrap();
        let n_bytes = km.n.to_be_bytes();
        let p_bytes = km.p.to_be_bytes();
        let q_bytes = km.q.to_be_bytes();
        let mut dp_bad = km.dp.to_be_bytes();
        dp_bad[100] ^= 0x01;
        let dq_bytes = km.dq.to_be_bytes();
        let qinv_bytes = km.qinv.to_be_bytes();

        let result = rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
            &n_bytes, 65537, &p_bytes, &q_bytes, &dp_bad, &dq_bytes, &qinv_bytes,
            b"pqclib R5 Bellcore probe",
        );
        assert!(
            result.is_none(),
            "Bellcore verify must catch a faulted dP"
        );
    }

    /// R5: PSS sign via a CRT-form handle must produce a signature
    /// that verifies under the public key. Smoke that the CRT wire
    /// through `sign_pss_sha256_with_salt` works end-to-end.
    #[test]
    fn r5_crt_handle_pss_sign_verifies() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r5-crt-pss",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r5-crt-pss-entropy", b"pqclib-r5-crt-pss-nonce", b"")
            .unwrap();
        let sk = RsaPrivateKey2048::generate(&mut drbg, 65537).unwrap();
        let salt = [0x42u8; pss::SLEN];
        let sig = sk
            .sign_pss_sha256_with_salt(b"R5 CRT PSS probe", &salt)
            .unwrap();
        rsa_pss_verify_2048_sha256(sk.modulus_bytes(), 65537, b"R5 CRT PSS probe", &sig)
            .unwrap();
    }

    /// Sanity check: the `RsaPrivateKey2048::generate` path rejects
    /// an invalid public exponent (even) without touching the DRBG.
    #[test]
    fn generate_rejects_even_exponent() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r4-reject-e",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r4-reject-e-entropy", b"nonce", b"")
            .unwrap();
        match RsaPrivateKey2048::generate(&mut drbg, 4) {
            Err(Error::InvalidInput) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(_) => panic!("even e must be rejected"),
        }
    }

    // --------------------------------------------------------------
    // R6: RSAES-OAEP encrypt/decrypt (SHA-256, MGF1-SHA-256)
    // --------------------------------------------------------------

    /// R6: non-CRT round-trip with a pinned seed. Encrypts under the
    /// power-up KAT public key and decrypts through the non-CRT handle
    /// to reach the `pow_secret` ladder path.
    #[test]
    fn r6_oaep_roundtrip_nocrt_handle() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-nocrt",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES).unwrap();
        let seed = [0x5au8; oaep::HLEN];
        let label: &[u8] = b"";
        let msg: &[u8] = b"R6 OAEP non-CRT roundtrip payload";
        let ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            label,
            msg,
            &seed,
        )
        .unwrap();
        let mut out = [0u8; oaep::MAX_MSG_LEN];
        let mlen = sk.decrypt_oaep_sha256(label, &ct, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], msg);
    }

    /// R6: CRT round-trip via a freshly generated keypair. Exercises
    /// the `rsa_oaep_decrypt_2048_sha256_crt_internal` path and its
    /// Bellcore verify-after-decrypt.
    #[test]
    fn r6_oaep_roundtrip_crt_handle() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-crt",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r6-oaep-crt-entropy", b"pqclib-r6-oaep-crt-nonce", b"")
            .unwrap();
        let sk = RsaPrivateKey2048::generate(&mut drbg, 65537).unwrap();

        let seed = [0xc3u8; oaep::HLEN];
        let label: &[u8] = b"context-R6";
        let msg: &[u8] = b"R6 OAEP CRT path payload, variable length.";
        let ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            label,
            msg,
            &seed,
        )
        .unwrap();

        let mut out = [0u8; oaep::MAX_MSG_LEN];
        let mlen = sk.decrypt_oaep_sha256(label, &ct, &mut out).unwrap();
        assert_eq!(mlen, msg.len());
        assert_eq!(&out[..mlen], msg);
    }

    /// R6: CRT and non-CRT decrypt paths recover the same plaintext
    /// from the same ciphertext. Proves the `rsa_crt_2048_private_exp_internal`
    /// shared core is byte-exact equivalent to the direct
    /// `mont2048::pow_secret` ladder on decrypt too.
    #[test]
    fn r6_oaep_crt_and_nocrt_agree_on_decryption() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-agree",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r6-oaep-agree-entropy", b"pqclib-r6-oaep-agree-nonce", b"")
            .unwrap();
        let sk_crt = RsaPrivateKey2048::generate(&mut drbg, 65537).unwrap();
        let sk_nocrt = RsaPrivateKey2048::from_components(
            sk_crt.modulus_bytes(),
            sk_crt.public_exponent(),
            &sk_crt.d_bytes,
        )
        .unwrap();

        let seed = [0x77u8; oaep::HLEN];
        let label: &[u8] = b"equivalence";
        let msg: &[u8] = b"same ct, two paths, one plaintext";
        let ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk_crt.modulus_bytes(),
            sk_crt.public_exponent(),
            label,
            msg,
            &seed,
        )
        .unwrap();

        let mut out_crt = [0u8; oaep::MAX_MSG_LEN];
        let mlen_crt = sk_crt.decrypt_oaep_sha256(label, &ct, &mut out_crt).unwrap();

        let mut out_nocrt = [0u8; oaep::MAX_MSG_LEN];
        let mlen_nocrt = sk_nocrt
            .decrypt_oaep_sha256(label, &ct, &mut out_nocrt)
            .unwrap();

        assert_eq!(mlen_crt, mlen_nocrt);
        assert_eq!(&out_crt[..mlen_crt], &out_nocrt[..mlen_nocrt]);
        assert_eq!(&out_crt[..mlen_crt], msg);
    }

    /// R6: flipping a bit in `dP` on a CRT handle causes the Bellcore
    /// verify-after-decrypt to fail, matching the analogous R5 test
    /// for sign. Proves the CRT decrypt path is fault-protected.
    #[test]
    fn r6_oaep_bellcore_rejects_tampered_dp() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-bellcore",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(
            b"pqclib-r6-oaep-bellcore-entropy",
            b"pqclib-r6-oaep-bellcore-nonce",
            b"",
        )
        .unwrap();
        let sk = RsaPrivateKey2048::generate(&mut drbg, 65537).unwrap();

        // Build a legitimate ciphertext first.
        let seed = [0x11u8; oaep::HLEN];
        let label: &[u8] = b"";
        let msg: &[u8] = b"R6 bellcore-on-decrypt probe";
        let ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            label,
            msg,
            &seed,
        )
        .unwrap();

        // Tamper `dP` on a clone of the CRT material and build a
        // handle via the direct internal to avoid the PCT rejecting
        // at construction time.
        let crt = sk.crt.as_ref().unwrap();
        let mut bad_dp = crt.dp_bytes;
        bad_dp[0] ^= 0x01;

        let mut out = [0u8; oaep::MAX_MSG_LEN];
        let result = rsa_oaep_decrypt_2048_sha256_crt_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            &crt.p_bytes,
            &crt.q_bytes,
            &bad_dp,
            &crt.dq_bytes,
            &crt.qinv_bytes,
            label,
            &ct,
            &mut out,
        );
        assert!(
            result.is_none(),
            "Bellcore verify-after-decrypt must reject a tampered dP"
        );
    }

    /// R6: decryption with a different label than the one bound into
    /// the ciphertext must fail — this tests the `lHash'` compare
    /// rather than the structural `PS`/`0x01` checks.
    #[test]
    fn r6_oaep_decrypt_rejects_wrong_label() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-label",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES).unwrap();
        let seed = [0u8; oaep::HLEN];
        let ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            b"alpha",
            b"test",
            &seed,
        )
        .unwrap();

        let mut out = [0u8; oaep::MAX_MSG_LEN];
        match sk.decrypt_oaep_sha256(b"beta", &ct, &mut out) {
            Err(Error::InvalidInput) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(n) => panic!("label mismatch must reject, got mLen={n}"),
        }
    }

    /// R6: decryption of a ciphertext that has been modified on the
    /// wire must fail. A single bit-flip in the ciphertext propagates
    /// through the ladder into a completely randomised EM; the OAEP
    /// decoder rejects it via one or more of its structural checks.
    #[test]
    fn r6_oaep_decrypt_rejects_tampered_ciphertext() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-ct-tamper",
            run: self_test,
        }]);
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES).unwrap();
        let seed = [0u8; oaep::HLEN];
        let mut ct = rsa_oaep_encrypt_2048_sha256_internal(
            sk.modulus_bytes(),
            sk.public_exponent(),
            b"",
            b"tamper-me",
            &seed,
        )
        .unwrap();
        ct[128] ^= 0x01;
        let mut out = [0u8; oaep::MAX_MSG_LEN];
        assert!(sk.decrypt_oaep_sha256(b"", &ct, &mut out).is_err());
    }

    /// R6: the public DRBG-backed encrypt entry point advances the
    /// DRBG and produces a different ciphertext from the same
    /// plaintext on two consecutive calls — i.e. OAEP is genuinely
    /// randomised through the caller-supplied DRBG.
    #[test]
    fn r6_oaep_encrypt_drbg_produces_distinct_ciphertexts() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-drbg",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(b"pqclib-r6-oaep-drbg-entropy", b"pqclib-r6-oaep-drbg-nonce", b"")
            .unwrap();
        let msg: &[u8] = b"randomised OAEP";
        let ct1 =
            rsa_oaep_encrypt_2048_sha256(&mut drbg, &KAT_N_BYTES, KAT_E, b"", msg).unwrap();
        let ct2 =
            rsa_oaep_encrypt_2048_sha256(&mut drbg, &KAT_N_BYTES, KAT_E, b"", msg).unwrap();
        assert_ne!(ct1, ct2);

        // Both still decrypt to the same plaintext.
        let sk = RsaPrivateKey2048::from_components(&KAT_N_BYTES, KAT_E, &KAT_D_BYTES).unwrap();
        let mut out1 = [0u8; oaep::MAX_MSG_LEN];
        let mut out2 = [0u8; oaep::MAX_MSG_LEN];
        let l1 = sk.decrypt_oaep_sha256(b"", &ct1, &mut out1).unwrap();
        let l2 = sk.decrypt_oaep_sha256(b"", &ct2, &mut out2).unwrap();
        assert_eq!(l1, msg.len());
        assert_eq!(l2, msg.len());
        assert_eq!(&out1[..l1], msg);
        assert_eq!(&out2[..l2], msg);
    }

    /// R6: encrypting an oversize message must be rejected by the
    /// public entry point without touching the DRBG past the single
    /// seed draw. (We don't observe the DRBG state here, but we do
    /// observe the error.)
    #[test]
    fn r6_oaep_encrypt_rejects_oversize_message() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "rsa-2048-r6-oaep-oversize",
            run: self_test,
        }]);
        let mut drbg = oxicrypt_drbg::HmacDrbgSha256::default();
        drbg.instantiate(
            b"pqclib-r6-oaep-oversize-entropy",
            b"pqclib-r6-oaep-oversize-nonce",
            b"",
        )
        .unwrap();
        let too_big = [0u8; oaep::MAX_MSG_LEN + 1];
        match rsa_oaep_encrypt_2048_sha256(&mut drbg, &KAT_N_BYTES, KAT_E, b"", &too_big) {
            Err(Error::InvalidInput) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(_) => panic!("oversize OAEP plaintext must be rejected"),
        }
    }
}
