//! SLH-DSA (FIPS 205) — stateless hash-based digital signature.
//!
//! # Overview
//!
//! SLH-DSA is the third NIST post-quantum signature standard. Unlike
//! LMS/XMSS it is **stateless**: the signer does not need to track
//! which leaf indices have been used.  Security rests entirely on the
//! collision resistance and preimage resistance of the underlying
//! hash functions.  For the SHA2-256s parameter set, F and PRF use
//! SHA-256 while H, T_l, PRF_msg, and H_msg use SHA-512 (truncated
//! to n=32 bytes), per FIPS 205 §10.1.
//!
//! # Parameter set
//!
//! This crate implements **SLH-DSA-SHA2-256s** ("small signatures"):
//!
//! | Parameter | Value | Meaning |
//! |-----------|-------|---------|
//! | n         | 32    | Hash output / security parameter (bytes) |
//! | h         | 64    | Total hyper-tree height |
//! | d         | 8     | Number of hyper-tree layers |
//! | h'        | 8     | Tree height per layer |
//! | a         | 14    | FORS tree height |
//! | k         | 22    | Number of FORS trees |
//! | w         | 16    | Winternitz parameter |
//! | pk        | 64 B  | Public key |
//! | sk        | 128 B | Secret key |
//! | sig       | 29792 B | Signature |
//!
//! # Approved services
//!
//! | Service | Standard | Profile |
//! |---------|----------|---------|
//! | SLH-DSA keygen | FIPS 205 | Unrestricted |
//! | SLH-DSA sign   | FIPS 205 | Unrestricted |
//! | SLH-DSA verify | FIPS 205 | Unrestricted |
//!
//! # External vs internal API
//!
//! The public [`sign`] and [`verify`] functions implement the
//! **external** `slh_sign` / `slh_verify` API defined in FIPS 205 §9.2
//! / §9.3 (Algorithms 22 and 24): they accept a `ctx` byte string and
//! frame the message as `M' = 0x00 || |ctx| || ctx || M` before
//! invoking the internal primitive.  This is the shape consumed by
//! X.509, CMS, the LAMPS profile, OpenSSL 3.5, and any other
//! spec-conformant caller — `ctx` is `b""` for those use cases.
//!
//! The `*_internal` surface ([`sign_internal`], [`verify_internal`])
//! exposes Algorithms 19 and 20 directly (`slh_sign_internal` /
//! `slh_verify_internal`) — the raw-message primitive with no framing.
//! These are `#[doc(hidden)]` and intended for FIPS 205 CAVP / ACVP
//! test harnesses that exercise the internal primitive.
//!
//! # Self-tests
//!
//! Power-up KAT: deterministic keygen → sign → verify round-trip
//! with a fixed seed (FIPS 140-3 IG D.G).

#![no_std]
#![forbid(unsafe_code)]
// Cryptographic code requires pervasive index arithmetic, bitwise
// operations, and controlled truncation that are safe by construction
// (all indices are bounded by compile-time constants).  Large stack
// arrays are unavoidable for signature buffers in `no_std`.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::large_stack_arrays,
    clippy::manual_div_ceil,
    clippy::needless_range_loop,
    clippy::unnecessary_cast,
    clippy::unwrap_used
)]

mod adrs;
mod fors;
mod hypertree;
mod params;
mod thash;
mod wots;
mod xmss;

pub use params::{PK_LEN, SIG_LEN, SK_LEN};

use adrs::{Adrs, AdrsType};
use oxicrypt_module::{Error, KatEntry, Service};
use params::N;

// ── Key generation (Algorithm 17) ───────────────────────────────────

/// Generate an SLH-DSA-SHA2-256s key pair from a 96-byte seed.
///
/// `xi` must contain 3 × 32 = 96 bytes of fresh randomness:
/// `SK.seed ‖ SK.prf ‖ PK.seed`.
///
/// Returns `(public_key, secret_key)`.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if `xi` is not 96 bytes.
pub fn keygen(xi: &[u8]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaKeygen)?;
    if xi.len() != 3 * N {
        return Err(Error::InvalidInput);
    }
    let mut seed = [0u8; 3 * N];
    seed.copy_from_slice(xi);
    let (pk, sk) = keygen_internal(&seed);
    Ok((pk, sk))
}

/// Gate-free key generation for self-tests.
#[doc(hidden)]
pub fn keygen_internal(xi: &[u8; 96]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    let sk_seed: &[u8; N] = xi[..N].try_into().unwrap();
    let sk_prf: &[u8; N] = xi[N..2 * N].try_into().unwrap();
    let pk_seed: &[u8; N] = xi[2 * N..3 * N].try_into().unwrap();

    // Compute the top-level XMSS tree root at layer D-1.
    let adrs = Adrs::zero();
    let mut top_adrs = adrs;
    top_adrs.set_layer_address((params::D - 1) as u32);
    let pk_root = xmss::xmss_node(pk_seed, sk_seed, 0, params::H_PRIME as u32, &top_adrs);

    // Public key: PK.seed ‖ PK.root.
    let mut pk = [0u8; PK_LEN];
    pk[..N].copy_from_slice(pk_seed);
    pk[N..].copy_from_slice(&pk_root);

    // Secret key: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root.
    let mut sk = [0u8; SK_LEN];
    sk[..N].copy_from_slice(sk_seed);
    sk[N..2 * N].copy_from_slice(sk_prf);
    sk[2 * N..3 * N].copy_from_slice(pk_seed);
    sk[3 * N..].copy_from_slice(&pk_root);

    (pk, sk)
}

// ── Signing (Algorithm 18) ──────────────────────────────────────────

/// Sign a message with SLH-DSA-SHA2-256s (deterministic mode).
///
/// This is the **external** `slh_sign` API defined in FIPS 205 §9.2
/// Algorithm 22: it frames the message as
/// `M' = 0x00 || |ctx| || ctx || M` (pure SLH-DSA, empty or
/// caller-supplied context) before applying the internal signing
/// primitive (Algorithm 19).
///
/// `ctx` is the application-supplied context string.  Pass `b""` for
/// the empty context used by X.509, CMS, and other LAMPS-conformant
/// callers.
///
/// Returns the signature (29 792 bytes).
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if `sk` is not `SK_LEN` bytes or
///   `ctx.len() > 255` (FIPS 205 §9.2 limit).
pub fn sign(sk: &[u8], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaSign)?;
    let sk_arr: &[u8; SK_LEN] = sk.try_into().map_err(|_| Error::InvalidInput)?;
    let prefix = build_external_prefix(ctx)?;
    Ok(sign_with_prefix(sk_arr, prefix.as_slice(), message))
}

/// Gate-free signing — FIPS 205 §9.1 Algorithm 19 (`slh_sign_internal`).
///
/// Operates directly on the raw message with no external-API framing,
/// matching the internal primitive exercised by FIPS 205 CAVP / ACVP
/// test vectors.
#[doc(hidden)]
pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8]) -> [u8; SIG_LEN] {
    sign_with_prefix(sk, &[], message)
}

/// Shared signing core.  `m_prefix` is absorbed into both `PRF_msg` and
/// `H_msg` before `message`; pass `&[]` for the internal primitive or
/// `0x00 || |ctx| || ctx` for the external API.
fn sign_with_prefix(sk: &[u8; SK_LEN], m_prefix: &[u8], message: &[u8]) -> [u8; SIG_LEN] {
    let sk_seed: &[u8; N] = sk[..N].try_into().unwrap();
    let sk_prf: &[u8; N] = sk[N..2 * N].try_into().unwrap();
    let pk_seed: &[u8; N] = sk[2 * N..3 * N].try_into().unwrap();
    let pk_root: &[u8; N] = sk[3 * N..4 * N].try_into().unwrap();

    let mut sig = [0u8; SIG_LEN];

    // Deterministic mode: opt_rand = PK.seed.
    let opt_rand = pk_seed;

    // R = PRF_msg(SK.prf, opt_rand, m_prefix ‖ M).
    let r = thash::prf_msg(sk_prf, opt_rand, m_prefix, message);
    sig[..N].copy_from_slice(&r);

    // Derive FORS digest and tree/leaf indices.
    let h_out = thash::h_msg(&r, pk_seed, pk_root, m_prefix, message);

    // FORS signature.
    let mut fors_adrs = Adrs::zero();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(h_out.tree_idx);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_keypair_address(h_out.leaf_idx);

    let fors_sig = fors::fors_sign(pk_seed, sk_seed, &h_out.md, &fors_adrs);
    sig[N..N + fors::FORS_SIG_LEN].copy_from_slice(&fors_sig);

    // Compute FORS public key (the message that the hyper-tree signs).
    let fors_pk = fors::fors_pk_from_sig(pk_seed, &h_out.md, &fors_sig, &fors_adrs);

    // Hyper-tree signature.
    let ht_sig = hypertree::ht_sign(pk_seed, sk_seed, &fors_pk, h_out.tree_idx, h_out.leaf_idx);
    sig[N + fors::FORS_SIG_LEN..].copy_from_slice(&ht_sig);

    sig
}

// ── Verification (Algorithm 19) ─────────────────────────────────────

/// Verify an SLH-DSA-SHA2-256s signature.
///
/// This is the **external** `slh_verify` API defined in FIPS 205 §9.3
/// Algorithm 24: it frames the message as
/// `M' = 0x00 || |ctx| || ctx || M` (pure SLH-DSA, empty or
/// caller-supplied context) before applying the internal verification
/// primitive (Algorithm 20).
///
/// `ctx` is the application-supplied context string.  Pass `b""` for
/// the empty context used by X.509, CMS, and other LAMPS-conformant
/// callers.
///
/// Returns `Ok(())` if the signature is valid, `Err(InvalidInput)` otherwise.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile forbids SLH-DSA.
/// - [`Error::InvalidInput`] if any input has the wrong length,
///   `ctx.len() > 255` (FIPS 205 §9.3 limit), or the signature fails
///   verification.
pub fn verify(pk: &[u8], message: &[u8], ctx: &[u8], signature: &[u8]) -> Result<(), Error> {
    oxicrypt_module::require_operational()?;
    oxicrypt_module::require_allowed(Service::SlhDsaVerify)?;
    let pk_arr: &[u8; PK_LEN] = pk.try_into().map_err(|_| Error::InvalidInput)?;
    let sig_arr: &[u8; SIG_LEN] = signature.try_into().map_err(|_| Error::InvalidInput)?;
    let prefix = build_external_prefix(ctx)?;
    if verify_with_prefix(pk_arr, prefix.as_slice(), message, sig_arr) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Gate-free verification — FIPS 205 §9.1 Algorithm 20
/// (`slh_verify_internal`).
///
/// Operates directly on the raw message with no external-API framing,
/// matching the internal primitive exercised by FIPS 205 CAVP / ACVP
/// test vectors.
#[doc(hidden)]
pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    verify_with_prefix(pk, &[], message, sig)
}

/// Shared verification core.  `m_prefix` is absorbed into `H_msg`
/// before `message`; pass `&[]` for the internal primitive or
/// `0x00 || |ctx| || ctx` for the external API.
fn verify_with_prefix(
    pk: &[u8; PK_LEN],
    m_prefix: &[u8],
    message: &[u8],
    sig: &[u8; SIG_LEN],
) -> bool {
    let pk_seed: &[u8; N] = pk[..N].try_into().unwrap();
    let pk_root: &[u8; N] = pk[N..2 * N].try_into().unwrap();

    // Extract R from signature.
    let r: &[u8; N] = sig[..N].try_into().unwrap();

    // Derive FORS digest and indices.
    let h_out = thash::h_msg(r, pk_seed, pk_root, m_prefix, message);

    // Reconstruct FORS public key.
    let mut fors_adrs = Adrs::zero();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(h_out.tree_idx);
    fors_adrs.set_type(AdrsType::ForsTree);
    fors_adrs.set_keypair_address(h_out.leaf_idx);

    let fors_sig = &sig[N..N + fors::FORS_SIG_LEN];
    let fors_pk = fors::fors_pk_from_sig(pk_seed, &h_out.md, fors_sig, &fors_adrs);

    // Verify hyper-tree signature.
    let ht_sig = &sig[N + fors::FORS_SIG_LEN..];
    hypertree::ht_verify(
        pk_seed,
        pk_root,
        &fors_pk,
        ht_sig,
        h_out.tree_idx,
        h_out.leaf_idx,
    )
}

// ── External-API prefix helper (FIPS 205 §9.2 / §9.3) ───────────────

/// Maximum size of the external API framing prefix: 2 header bytes
/// (`0x00` domain separator + `|ctx|` length byte) plus the 255-byte
/// ctx cap from FIPS 205 §9.2.
const EXT_PREFIX_MAX: usize = 2 + 255;

/// Stack-allocated `0x00 || |ctx| || ctx` buffer for the external
/// `slh_sign` / `slh_verify` framing.  Keeps the crate free of any
/// heap allocation while still supporting the full FIPS 205 ctx range.
struct ExternalPrefix {
    buf: [u8; EXT_PREFIX_MAX],
    len: usize,
}

impl ExternalPrefix {
    // Range slice is sound by construction: `len` is written exactly
    // once by `build_external_prefix` as `2 + ctx.len()` with
    // `ctx.len() ≤ 255`, so `len ≤ EXT_PREFIX_MAX`.
    #[allow(clippy::indexing_slicing)]
    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

// Arithmetic and slicing are sound by construction: the early-return
// on `ctx.len() > 255` establishes `2 + ctx.len() ≤ EXT_PREFIX_MAX`,
// so the following index operations cannot overflow or panic.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
fn build_external_prefix(ctx: &[u8]) -> Result<ExternalPrefix, Error> {
    if ctx.len() > 255 {
        return Err(Error::InvalidInput);
    }
    let mut buf = [0u8; EXT_PREFIX_MAX];
    buf[0] = 0x00; // pure SLH-DSA (HashSLH-DSA would use 0x01)
    buf[1] = ctx.len() as u8;
    buf[2..2 + ctx.len()].copy_from_slice(ctx);
    Ok(ExternalPrefix { buf, len: 2 + ctx.len() })
}

// ── Self-tests ──────────────────────────────────────────────────────

/// Power-up KATs for SLH-DSA-SHA2-256s.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "SLH-DSA-SHA2-256s KAT (keygen + sign + verify round-trip, FIPS 205)",
    run: self_test,
}];

/// Run the SLH-DSA power-up self-test.
///
/// Uses a deterministic seed so the test is reproducible.
fn self_test() -> Result<(), oxicrypt_module::SelfTestFailure> {
    // Fixed 96-byte seed (arbitrary but deterministic).
    let mut xi = [0u8; 96];
    // Fill with a simple pattern for reproducibility.
    for (i, b) in xi.iter_mut().enumerate() {
        *b = ((i & 0xFF) as u8).wrapping_mul(37).wrapping_add(7);
    }

    let (pk, sk) = keygen_internal(&xi);

    // Sign a test message.
    let msg = b"SLH-DSA-SHA2-256s self-test message (FIPS 205)";
    let sig = sign_internal(&sk, msg);

    // Verify must succeed.
    if !verify_internal(&pk, msg, &sig) {
        return Err(oxicrypt_module::SelfTestFailure);
    }

    // Verify with a wrong message must fail.
    let bad_msg = b"tampered message";
    if verify_internal(&pk, bad_msg, &sig) {
        return Err(oxicrypt_module::SelfTestFailure);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Fill a 96-byte seed with a simple deterministic pattern.
    fn test_seed() -> [u8; 96] {
        let mut xi = [0u8; 96];
        for (i, b) in xi.iter_mut().enumerate() {
            *b = ((i & 0xFF) as u8).wrapping_mul(37).wrapping_add(7);
        }
        xi
    }

    /// Round-trip: keygen → sign → verify with the same deterministic
    /// seed as the power-up KAT.
    #[test]
    fn round_trip() {
        let xi = test_seed();
        let (pk, sk) = keygen_internal(&xi);

        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sk.len(), SK_LEN);

        let msg = b"SLH-DSA-SHA2-256s round-trip test";
        let sig = sign_internal(&sk, msg);
        assert_eq!(sig.len(), SIG_LEN);

        assert!(verify_internal(&pk, msg, &sig));
        assert!(!verify_internal(&pk, b"wrong", &sig));
    }

    /// Verify that different messages produce different signatures.
    #[test]
    fn different_messages() {
        let xi = test_seed();
        let (_pk, sk) = keygen_internal(&xi);

        let sig1 = sign_internal(&sk, b"message A");
        let sig2 = sign_internal(&sk, b"message B");
        assert_ne!(sig1[..32], sig2[..32]); // R values differ (deterministic on msg)
    }

    /// KAT function runs without panic.
    #[test]
    fn kat_passes() {
        self_test().expect("SLH-DSA KAT failed");
    }
}
