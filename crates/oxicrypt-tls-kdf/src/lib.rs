//! TLS 1.2 KDF per SP 800-135 Rev. 1 §4.2.2 and RFC 5246 §5, and the
//! TLS 1.3 KDF (HKDF-Expand-Label, Derive-Secret) per RFC 8446 §7.1.
//!
//! Implements the TLS 1.2 PRF (`P_hash` expansion) used for both
//! standard master-secret derivation (RFC 5246 §8.1) and RFC 7627
//! Extended Master Secret derivation. The `key expansion` step
//! (RFC 5246 §6.3) uses the same PRF core.
//!
//! # Algorithm
//!
//! ```text
//! PRF(secret, label, seed) = P_hash(secret, label ‖ seed)
//!
//! P_hash(secret, seed) = HMAC(secret, A(1) ‖ seed) ‖
//!                         HMAC(secret, A(2) ‖ seed) ‖ …
//! A(0) = seed
//! A(i) = HMAC(secret, A(i−1))
//! ```
//!
//! The PRF is generic over the underlying HMAC via the
//! [`oxicrypt_kdf::PrfHmac`] trait.
#![no_std]
#![forbid(unsafe_code)]

use oxicrypt_kdf::PrfHmac;
use oxicrypt_module::{
    Error, KatEntry, SelfTestFailure, Service, require_allowed, require_operational,
    require_self_test_started,
};

// ── Core PRF ──────────────────────────────────────────────────────

/// TLS 1.2 PRF expansion (RFC 5246 §5).
///
/// Fills `out` with `PRF(secret, label, seed)` — the `P_hash`
/// iterated-HMAC expansion. `label` and `seed` are concatenated
/// internally (no caller allocation needed).
///
/// This is the internal variant without the operational and profile
/// gates; callers in the ACVP harness (which runs behind its own
/// `require_operational` gate) use this directly. It returns
/// [`Error::NotOperational`] unless [`require_self_test_started`] admits
/// the call: in `Operational`, or in `SelfTest` on the thread running the
/// power-up self-tests.
///
/// # Safety invariant
///
/// The `while offset < out.len()` loop guard guarantees all slice
/// accesses stay in bounds. `offset` advances by at most `L` per
/// iteration. Arithmetic is bounded by `out.len()` which fits in
/// `usize` — no wrapping.
// Allow: loop invariant guarantees in-bounds; arithmetic bounded by len.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_prf_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_self_test_started()?;
    let result = tls12_prf_internal_unwiped::<P, L>(secret, label, seed, out);
    if result.is_err() {
        oxicrypt_zeroize::zeroize(out);
    }
    result
}

/// Body of [`tls12_prf_internal`]. That function wipes `out` when this one returns `Err`.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn tls12_prf_internal_unwiped<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // A(0) = label ‖ seed
    // A(i) = HMAC(secret, A(i−1))
    let mut a = Wiped({
        let mut mac = P::prf_new(secret)?;
        mac.prf_update(label);
        mac.prf_update(seed);
        mac.prf_finalize()?
    });

    let mut offset = 0;
    while offset < out.len() {
        // P_i = HMAC(secret, A(i) ‖ label ‖ seed)
        let mut mac = P::prf_new(secret)?;
        mac.prf_update(&a);
        mac.prf_update(label);
        mac.prf_update(seed);
        let p = Wiped(mac.prf_finalize()?);

        let remaining = out.len() - offset;
        let to_copy = if remaining < L { remaining } else { L };
        out[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        // A(i+1) = HMAC(secret, A(i)), only when another block follows,
        // so no fallible step runs after the final output is written.
        if offset < out.len() {
            let mut mac_a = P::prf_new(secret)?;
            mac_a.prf_update(&a);
            a.0 = mac_a.prf_finalize()?;
        }
    }
    Ok(())
}

/// TLS 1.2 PRF expansion with module-state gating (RFC 5246 §5).
///
/// Gated wrapper around [`tls12_prf_internal`] that enforces the module
/// state machine via [`require_operational`] and algorithm-profile
/// gating via [`require_allowed`].
///
/// Fills `out` with `PRF(secret, label, seed)` — the `P_hash`
/// iterated-HMAC expansion. `label` and `seed` are concatenated
/// internally (no caller allocation needed).
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module is not in the
/// `Operational` state, or [`Error`] if the service is blocked by the
/// current algorithm profile.
///
/// # Safety invariant
///
/// The `while offset < out.len()` loop guard guarantees all slice
/// accesses stay in bounds. `offset` advances by at most `L` per
/// iteration. Arithmetic is bounded by `out.len()` which fits in
/// `usize` — no wrapping.
// Allow: loop invariant guarantees in-bounds; arithmetic bounded by len.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_prf<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_operational()?;
    require_allowed(Service::Tls12Kdf)?;
    tls12_prf_internal::<P, L>(secret, label, seed, out)
}

// ── RFC 7627 Extended Master Secret ───────────────────────────────

/// Master-secret length per RFC 5246 §8.1 — always 48 bytes.
pub const MASTER_SECRET_LEN: usize = 48;

/// Derive master secret and key block per TLS 1.2 with RFC 7627
/// Extended Master Secret.
///
/// 1. `master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// Returns the 48-byte master secret and fills `key_block_out`.
///
/// # Panics
///
/// Panics if `server_random.len() + client_random.len() > 64`.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_extended_master_secret_internal<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    session_hash: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> Result<[u8; MASTER_SECRET_LEN], Error> {
    require_self_test_started()?;
    // The random lengths are checked before anything is derived.
    let sr_len = server_random.len();
    let cr_len = client_random.len();
    assert!(sr_len + cr_len <= 64, "TLS randoms exceed 64 bytes");

    // Step 1: extended master secret, held so it is zeroized on every
    // return path; the caller receives a copy.
    let mut master_secret = Wiped([0u8; MASTER_SECRET_LEN]);
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"extended master secret",
        session_hash,
        &mut master_secret,
    )?;

    // Step 2: key expansion
    // seed = server_random ‖ client_random (RFC 5246 §6.3)
    let mut seed = [0u8; 64];
    seed[..sr_len].copy_from_slice(server_random);
    seed[sr_len..sr_len + cr_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &seed[..sr_len + cr_len],
        key_block_out,
    )?;

    Ok(master_secret.0)
}

/// Derive master secret and key block with module-state gating
/// (TLS 1.2 RFC 7627 EMS).
///
/// Gated wrapper around [`tls12_extended_master_secret_internal`] that
/// enforces the module state machine via [`require_operational`] and
/// algorithm-profile gating via [`require_allowed`].
///
/// 1. `master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// Returns the 48-byte master secret and fills `key_block_out`.
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module is not in the
/// `Operational` state, or [`Error`] if the service is blocked by the
/// current algorithm profile.
///
/// # Panics
///
/// Panics if `server_random.len() + client_random.len() > 64`.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_extended_master_secret<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    session_hash: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> Result<[u8; MASTER_SECRET_LEN], Error> {
    require_operational()?;
    require_allowed(Service::Tls12Kdf)?;
    tls12_extended_master_secret_internal::<P, L>(
        pre_master_secret,
        session_hash,
        server_random,
        client_random,
        key_block_out,
    )
}

// ── Standard (non-EMS) Master Secret ──────────────────────────────

/// Derive master secret and key block per standard TLS 1.2
/// (RFC 5246 §8.1, no EMS extension).
///
/// 1. `master_secret = PRF(pre_master_secret, "master secret", client_hello_random ‖ server_hello_random)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// # Panics
///
/// Panics if any concatenated seed pair exceeds 64 bytes.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_master_secret_internal<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    client_hello_random: &[u8],
    server_hello_random: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> Result<[u8; MASTER_SECRET_LEN], Error> {
    require_self_test_started()?;
    // Both seed lengths are checked before anything is derived.
    let chr_len = client_hello_random.len();
    let shr_len = server_hello_random.len();
    assert!(chr_len + shr_len <= 64, "TLS hello randoms exceed 64 bytes");
    let server_len = server_random.len();
    let client_len = client_random.len();
    assert!(server_len + client_len <= 64, "TLS randoms exceed 64 bytes");

    // Step 1: master secret — seed = clientHelloRandom ‖ serverHelloRandom
    let mut ms_seed = [0u8; 64];
    ms_seed[..chr_len].copy_from_slice(client_hello_random);
    ms_seed[chr_len..chr_len + shr_len].copy_from_slice(server_hello_random);

    // Held so it is zeroized on every return path; the caller receives a
    // copy.
    let mut master_secret = Wiped([0u8; MASTER_SECRET_LEN]);
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"master secret",
        &ms_seed[..chr_len + shr_len],
        &mut master_secret,
    )?;

    // Step 2: key expansion — seed = serverRandom ‖ clientRandom
    let mut ke_seed = [0u8; 64];
    ke_seed[..server_len].copy_from_slice(server_random);
    ke_seed[server_len..server_len + client_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &ke_seed[..server_len + client_len],
        key_block_out,
    )?;

    Ok(master_secret.0)
}

/// Derive master secret and key block with module-state gating
/// (standard TLS 1.2, no EMS extension).
///
/// Gated wrapper around [`tls12_master_secret_internal`] that enforces
/// the module state machine via [`require_operational`] and
/// algorithm-profile gating via [`require_allowed`].
///
/// 1. `master_secret = PRF(pre_master_secret, "master secret", client_hello_random ‖ server_hello_random)[0..48]`
/// 2. `key_block = PRF(master_secret, "key expansion", server_random ‖ client_random)[0..key_block_len]`
///
/// # Errors
///
/// Returns [`Error::NotOperational`] if the module is not in the
/// `Operational` state, or [`Error`] if the service is blocked by the
/// current algorithm profile.
///
/// # Panics
///
/// Panics if any concatenated seed pair exceeds 64 bytes.
// Allow: seed assembly is bounded (TLS randoms are 32 bytes each).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls12_master_secret<P: PrfHmac<L>, const L: usize>(
    pre_master_secret: &[u8],
    client_hello_random: &[u8],
    server_hello_random: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    key_block_out: &mut [u8],
) -> Result<[u8; MASTER_SECRET_LEN], Error> {
    require_operational()?;
    require_allowed(Service::Tls12Kdf)?;
    tls12_master_secret_internal::<P, L>(
        pre_master_secret,
        client_hello_random,
        server_hello_random,
        server_random,
        client_random,
        key_block_out,
    )
}

// ── TLS 1.3 KDF (RFC 8446 §7.1) ──────────────────────────────────
//
// HKDF-Expand-Label and Derive-Secret. Built on the HMAC-iterated
// HKDF-Expand of RFC 5869 §2.3, kept inline (rather than calling
// oxicrypt-kdf::Hkdf) to match the style of the tls12_* family above
// and to avoid the module-state gating layer inside the harness,
// which already runs behind `require_operational`.
//
// Public gated wrappers (`tls13_hkdf_expand_label`,
// `tls13_derive_secret`) sit alongside the `*_internal` entry points,
// which carry only the self-test-started guard: the public surface enforces `require_operational` +
// `require_allowed(Service::Tls13Kdf)`, while the ACVP harness
// continues to dispatch through `_internal` directly so its test
// runs do not depend on the module's profile-gating state. Same
// architectural separation as ML-DSA / SLH-DSA / EdDSA.

/// A key-derived block, zeroized when it goes out of scope on success and
/// on an early return alike.
struct Wiped<const N: usize>([u8; N]);

impl<const N: usize> core::ops::Deref for Wiped<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for Wiped<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Drop for Wiped<N> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.0);
    }
}

/// Maximum HkdfLabel wire size on the stack. Per RFC 8446 §7.1:
/// `uint16 length` (2) + `opaque label<7..255>` (1 + ≤255) +
/// `opaque context<0..255>` (1 + ≤255). Realistic TLS 1.3 use is
/// far smaller — labels are ≤16 chars, context is a 32- or 48-byte
/// transcript hash — but the upper bound is the spec maximum.
const HKDF_LABEL_SCRATCH: usize = 2 + 1 + 255 + 1 + 255;

/// Internal HKDF-Expand-Label per RFC 8446 §7.1.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out`.
///
/// Returns [`Error::InvalidInput`] if `out.len()` exceeds 65535 bytes,
/// the most the HkdfLabel `uint16 length` field can state, or 255 blocks
/// of `L` bytes, the most the one-byte HKDF counter can number, if `label` is
/// empty or longer than 249 bytes, or if `context` is longer than 255 bytes
/// (RFC 8446 §7.1 bounds the prefixed label to 7–255 bytes and the context
/// to 0–255).
///
/// This is the variant without the operational and profile gates,
/// used by the ACVP harness and the power-up self-test. It returns
/// [`Error::NotOperational`] unless [`require_self_test_started`] admits
/// the call: in `Operational`, or in `SelfTest` on the thread running the
/// power-up self-tests. The public, FIPS-gated counterpart
/// [`tls13_hkdf_expand_label`] wraps this with `require_operational`
/// + `require_allowed(Service::Tls13Kdf)` for normal-call use.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls13_hkdf_expand_label_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_self_test_started()?;
    let result = tls13_hkdf_expand_label_internal_unwiped::<P, L>(secret, label, context, out);
    if result.is_err() {
        oxicrypt_zeroize::zeroize(out);
    }
    result
}

/// Body of [`tls13_hkdf_expand_label_internal`]. That function wipes `out` when this one returns `Err`.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn tls13_hkdf_expand_label_internal_unwiped<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // RFC 8446 §7.1: `opaque label<7..255> = "tls13 " + Label` and
    // `opaque context<0..255>`, so Label is 1 to 249 bytes and the context
    // at most 255. A value outside those bounds is refused rather than
    // truncated into a different HkdfLabel.
    if label.is_empty() || label.len() > 255 - 6 || context.len() > 255 {
        return Err(Error::InvalidInput);
    }
    // Build HkdfLabel into a stack scratch buffer.
    let mut scratch = [0u8; HKDF_LABEL_SCRATCH];
    // HkdfLabel states the output length in a `uint16`, so a longer output
    // is refused rather than described by a different length.
    let Ok(length) = u16::try_from(out.len()) else {
        return Err(Error::InvalidInput);
    };
    scratch[0..2].copy_from_slice(&length.to_be_bytes());
    // The bounds checked above make both length bytes fit in a `u8`.
    let Ok(full_label_len) = u8::try_from(6 + label.len()) else {
        return Err(Error::InvalidInput);
    };
    let Ok(context_len) = u8::try_from(context.len()) else {
        return Err(Error::InvalidInput);
    };
    scratch[2] = full_label_len;
    scratch[3..9].copy_from_slice(b"tls13 ");
    scratch[9..9 + label.len()].copy_from_slice(label);
    let context_off = 9 + label.len();
    scratch[context_off] = context_len;
    scratch[context_off + 1..context_off + 1 + context.len()].copy_from_slice(context);
    let info_len = context_off + 1 + context.len();
    let info = &scratch[..info_len];

    // HKDF-Expand (RFC 5869 §2.3): OKM = T(1) || T(2) || ... truncated
    //   T(0) = empty
    //   T(i) = HMAC(secret, T(i-1) || info || i)
    //
    // The one-byte counter covers at most 255 blocks (RFC 5869 §2.3).
    if out.len() > 255 * L {
        return Err(Error::InvalidInput);
    }
    let mut prev_block = Wiped([0u8; L]);
    let mut have_prev = false;
    let mut counter: u8 = 1;
    let mut offset = 0;
    while offset < out.len() {
        let mut mac = P::prf_new(secret)?;
        if have_prev {
            mac.prf_update(&prev_block);
        }
        mac.prf_update(info);
        mac.prf_update(&[counter]);
        let t = Wiped(mac.prf_finalize()?);

        let remaining = out.len() - offset;
        let to_copy = if remaining < L { remaining } else { L };
        out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;

        prev_block.copy_from_slice(&t);
        have_prev = true;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// Internal Derive-Secret per RFC 8446 §7.1:
///
/// ```text
/// Derive-Secret(secret, label, messages)
///   = HKDF-Expand-Label(secret, label, Hash(messages), Hash.length)
/// ```
///
/// Caller computes `Hash(messages)` (the running transcript hash)
/// and passes it as `transcript_hash`. Keeping the transcript-hash
/// computation outside this crate matches how TLS 1.3 stacks
/// already maintain a transcript-hash context separately from the
/// KDF, and keeps `oxicrypt-tls-kdf` free of a dependency on
/// `oxicrypt-sha`.
///
/// # Errors
///
/// As [`tls13_hkdf_expand_label_internal`], with `transcript_hash` as the
/// context.
pub fn tls13_derive_secret_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_self_test_started()?;
    tls13_hkdf_expand_label_internal::<P, L>(secret, label, transcript_hash, out)
}

/// HKDF-Expand-Label per RFC 8446 §7.1 — FIPS-gated public entry point.
///
/// Builds the HkdfLabel wire structure
/// `length || "tls13 " + label || context` and runs HKDF-Expand
/// (RFC 5869 §2.3) to fill `out`.
///
/// Wraps [`tls13_hkdf_expand_label_internal`] with the FIPS 140-3
/// algorithm-profile gating via [`require_allowed`]. Returns
/// [`Error::AlgorithmRestricted`] if the active profile forbids
/// `Service::Tls13Kdf`, and [`Error::NotOperational`] if the module
/// has not yet completed power-up self-tests.
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in the
///   `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile does not
///   allow [`Service::Tls13Kdf`].
/// - [`Error::InvalidInput`] if `out.len()` exceeds 65535 bytes or 255
///   blocks of `L` bytes, if `label` is empty or longer than 249 bytes, or
///   if the context (the transcript hash) is longer than 255 bytes
///   (RFC 8446 §7.1).
///
/// `out` is zeroized when the derivation itself fails, which is the
/// `InvalidInput` case or a module refusal partway through. A
/// `NotOperational` or `AlgorithmRestricted` from the entry checks returns
/// before anything is written, and leaves `out` as the caller passed it.
pub fn tls13_hkdf_expand_label<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_operational()?;
    require_allowed(Service::Tls13Kdf)?;
    tls13_hkdf_expand_label_internal::<P, L>(secret, label, context, out)
}

/// Derive-Secret per RFC 8446 §7.1 — FIPS-gated public entry point.
///
/// ```text
/// Derive-Secret(secret, label, messages)
///   = HKDF-Expand-Label(secret, label, Hash(messages), Hash.length)
/// ```
///
/// Caller computes `Hash(messages)` (the running transcript hash) and
/// passes it as `transcript_hash`. Wraps
/// [`tls13_derive_secret_internal`] with the FIPS 140-3
/// algorithm-profile gating via [`require_allowed`].
///
/// # Errors
///
/// - [`Error::NotOperational`] if the module is not in the
///   `Operational` state.
/// - [`Error::AlgorithmRestricted`] if the active profile does not
///   allow [`Service::Tls13Kdf`].
/// - [`Error::InvalidInput`] if `out.len()` exceeds 65535 bytes or 255
///   blocks of `L` bytes, if `label` is empty or longer than 249 bytes, or
///   if the context (the transcript hash) is longer than 255 bytes
///   (RFC 8446 §7.1).
///
/// `out` is zeroized when the derivation itself fails, which is the
/// `InvalidInput` case or a module refusal partway through. A
/// `NotOperational` or `AlgorithmRestricted` from the entry checks returns
/// before anything is written, and leaves `out` as the caller passed it.
pub fn tls13_derive_secret<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_operational()?;
    require_allowed(Service::Tls13Kdf)?;
    tls13_derive_secret_internal::<P, L>(secret, label, transcript_hash, out)
}

// ── Power-up KAT ─────────────────────────────────────────────────

/// KAT secret: 48 bytes of `0x0b`.
const KAT_SECRET: [u8; 48] = [0x0b; 48];
/// KAT label: `"master secret"` (standard TLS 1.2 label).
const KAT_LABEL: &[u8] = b"master secret";
/// KAT seed: 64 bytes of `0xaa`.
const KAT_SEED: [u8; 64] = [0xaa; 64];
/// Expected PRF output (48 bytes, HMAC-SHA-256).
const KAT_PRF_EXPECTED: [u8; 48] = [
    0xf6, 0xfe, 0xf7, 0xc3, 0x30, 0x0b, 0x19, 0x74, 0xb4, 0xc3, 0x1d, 0xf2, 0xfa, 0xef, 0xaf, 0xce,
    0xe0, 0xa8, 0xe8, 0xfb, 0xe2, 0x91, 0xae, 0x1c, 0x43, 0x0d, 0x69, 0xad, 0xc2, 0x59, 0x25, 0x52,
    0x15, 0x89, 0xe3, 0xcd, 0xaa, 0x58, 0x5d, 0x22, 0x62, 0xe6, 0x37, 0xcd, 0xe0, 0x36, 0x7c, 0x0c,
];

/// Power-up known-answer test for TLS 1.2 PRF with HMAC-SHA-256.
///
/// Exercises `tls12_prf_internal` with a fixed `(secret, label, seed)`
/// triple and verifies the 48-byte output matches the pinned reference
/// value.
pub fn self_test() -> Result<(), SelfTestFailure> {
    use oxicrypt_hmac::HmacSha256;
    let mut out = [0u8; 48];
    tls12_prf_internal::<HmacSha256, 32>(&KAT_SECRET, KAT_LABEL, &KAT_SEED, &mut out)
        .map_err(|_| SelfTestFailure)?;
    if out != KAT_PRF_EXPECTED {
        return Err(SelfTestFailure);
    }
    Ok(())
}

/// RFC 8448 §3 (1-RTT handshake) PRK for the client handshake-traffic-secret
/// expansion. Pinned reference for the TLS 1.3 KDF KAT.
const TLS13_KAT_PRK: [u8; 32] = [
    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
];

/// RFC 8448 §3 transcript hash — `SHA-256(ClientHello || ServerHello)`.
const TLS13_KAT_TRANSCRIPT_HASH: [u8; 32] = [
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
];

/// RFC 8448 §3 expected client handshake-traffic-secret (32 bytes).
const TLS13_KAT_EXPECTED: [u8; 32] = [
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
];

/// Power-up known-answer test for TLS 1.3 KDF (HKDF-Expand-Label and
/// Derive-Secret) over HMAC-SHA-256.
///
/// Exercises both `tls13_hkdf_expand_label_internal` and
/// `tls13_derive_secret_internal` against the RFC 8448 §3 client
/// handshake-traffic-secret derivation: HKDF-Expand-Label with label
/// `"c hs traffic"` and `SHA-256(ClientHello || ServerHello)` as the
/// context, expanding to a 32-byte output. Because the output is
/// exactly `Hash.length`, `tls13_derive_secret_internal` must produce
/// byte-identical bytes to `tls13_hkdf_expand_label_internal` for the
/// same inputs (RFC 8446 §7.1) — the KAT verifies both invariants.
pub fn tls13_self_test() -> Result<(), SelfTestFailure> {
    use oxicrypt_hmac::HmacSha256;
    let mut via_expand = [0u8; 32];
    tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
        &TLS13_KAT_PRK,
        b"c hs traffic",
        &TLS13_KAT_TRANSCRIPT_HASH,
        &mut via_expand,
    )
    .map_err(|_| SelfTestFailure)?;
    if via_expand != TLS13_KAT_EXPECTED {
        return Err(SelfTestFailure);
    }
    let mut via_derive = [0u8; 32];
    tls13_derive_secret_internal::<HmacSha256, 32>(
        &TLS13_KAT_PRK,
        b"c hs traffic",
        &TLS13_KAT_TRANSCRIPT_HASH,
        &mut via_derive,
    )
    .map_err(|_| SelfTestFailure)?;
    if via_derive != TLS13_KAT_EXPECTED {
        return Err(SelfTestFailure);
    }
    Ok(())
}

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "TLS 1.2 PRF KAT (HMAC-SHA-256 P_hash expansion, SP 800-135r1)",
        run: self_test,
    },
    KatEntry {
        name: "TLS 1.3 KDF KAT (HKDF-Expand-Label + Derive-Secret, RFC 8446 §7.1; RFC 8448 §3 vector)",
        run: tls13_self_test,
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use oxicrypt_hmac::HmacSha256;

    /// HKDF-Expand-Label refuses a label or context outside the RFC 8446
    /// §7.1 bounds instead of truncating it, and accepts the bounds
    /// themselves.
    #[test]
    fn expand_label_refuses_out_of_range_label_and_context() {
        crate::test_support::start_module();
        let secret = [0x0b; 32];
        let mut out = [0u8; 32];
        let long_label = [b'a'; 250];
        let long_context = [0u8; 256];
        for (label, context) in [
            (&b""[..], &b""[..]),
            (&long_label[..], &b""[..]),
            (&b"key"[..], &long_context[..]),
        ] {
            assert_eq!(
                tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
                    &secret, label, context, &mut out
                ),
                Err(Error::InvalidInput)
            );
        }
        tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
            &secret,
            &long_label[..249],
            &long_context[..255],
            &mut out,
        )
        .unwrap();
    }

    /// HKDF-Expand-Label finishes at 255 blocks, the most its one-byte
    /// counter numbers, and refuses one byte more.
    #[test]
    fn expand_label_reaches_255_blocks_and_refuses_more() {
        crate::test_support::start_module();
        let secret = [0x0b; 32];
        let mut out = [0u8; 255 * 32];
        tls13_hkdf_expand_label_internal::<HmacSha256, 32>(&secret, b"max", b"", &mut out).unwrap();
        assert_ne!(&out[254 * 32..], &[0u8; 32][..]);
        let mut too_long = [0u8; 255 * 32 + 1];
        assert_eq!(
            tls13_hkdf_expand_label_internal::<HmacSha256, 32>(&secret, b"max", b"", &mut too_long),
            Err(Error::InvalidInput)
        );
    }

    /// Smoke test: PRF produces deterministic, non-zero output.
    #[test]
    fn prf_produces_output() {
        crate::test_support::start_module();
        let secret = [0x0bu8; 16];
        let label = b"test label";
        let seed = [0xaau8; 32];
        let mut out = [0u8; 64];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out).unwrap();
        assert_ne!(out, [0u8; 64]);
    }

    #[test]
    fn self_test_passes() {
        crate::test_support::start_module();
        self_test().unwrap();
    }

    #[test]
    fn tls13_self_test_passes() {
        crate::test_support::start_module();
        tls13_self_test().unwrap();
    }

    /// PRF is deterministic.
    #[test]
    fn prf_deterministic() {
        crate::test_support::start_module();
        let secret = [0x01u8; 48];
        let label = b"key expansion";
        let seed = [0xffu8; 64];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out1).unwrap();
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    /// RFC 8448 §3 (1-RTT handshake), client handshake-traffic-secret
    /// expansion: HKDF-Expand-Label using "c hs traffic" + transcript
    /// hash of `ClientHello || ServerHello`. Authoritative byte-perfect
    /// vector from the published TLS 1.3 example handshakes.
    #[test]
    fn tls13_hkdf_expand_label_rfc8448_c_hs_traffic() {
        crate::test_support::start_module();
        let prk: [u8; 32] = [
            0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74,
            0x1b, 0x01, 0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca,
            0x04, 0x3f, 0xbe, 0xac,
        ];
        let transcript_hash: [u8; 32] = [
            0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c,
            0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c,
            0xf0, 0xe1, 0xca, 0xd8,
        ];
        let expected: [u8; 32] = [
            0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e,
            0x2d, 0x8f, 0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e,
            0x27, 0xa5, 0x5a, 0x21,
        ];
        let mut out = [0u8; 32];
        tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
            &prk,
            b"c hs traffic",
            &transcript_hash,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, expected);
    }

    /// `tls13_derive_secret_internal(secret, label, transcript_hash)`
    /// is defined as `HKDF-Expand-Label(secret, label, transcript_hash,
    /// HashLen)`. With output sized to the hash length, the two must
    /// produce identical bytes for the same inputs (RFC 8446 §7.1).
    #[test]
    fn tls13_derive_secret_matches_expand_label_with_hashlen_output() {
        crate::test_support::start_module();
        let secret = [0x42u8; 32];
        let label = b"derived";
        let transcript_hash = [0xa5u8; 32];
        let mut via_derive = [0u8; 32];
        let mut via_expand = [0u8; 32];
        tls13_derive_secret_internal::<HmacSha256, 32>(
            &secret,
            label,
            &transcript_hash,
            &mut via_derive,
        )
        .unwrap();
        tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
            &secret,
            label,
            &transcript_hash,
            &mut via_expand,
        )
        .unwrap();
        assert_eq!(via_derive, via_expand);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use oxicrypt_module::{KatEntry, initialize_with_tests, require_self_test_started};

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Brings the module out of `PowerOff` so that a test can call the
    /// `*_internal` functions, which refuse until the self-tests have
    /// started. A second call in the same process is a no-op.
    pub(crate) fn start_module() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        assert_eq!(require_self_test_started(), Ok(()));
    }
}

/// Both TLS KDFs wipe their output on an error: a PRF stand-in fails
/// part-way, after a block of output has been written, and the output is
/// all zero afterwards. The `_unwiped` body on the same inputs is the
/// control: it leaves the written block in place.
#[cfg(test)]
mod wipe_on_error_tests {
    extern crate std;
    use super::{
        tls12_prf_internal, tls12_prf_internal_unwiped, tls13_hkdf_expand_label_internal,
        tls13_hkdf_expand_label_internal_unwiped,
    };
    use oxicrypt_kdf::PrfHmac;
    use oxicrypt_module::{Error, KatEntry, Service, initialize_with_tests};

    /// Output length of the stand-in PRF.
    const L: usize = 16;

    std::thread_local! {
        static CALLS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    }

    /// A PRF whose third and later instantiations fail, and whose every
    /// output is `0x5a` bytes.
    struct FailingPrf;

    impl PrfHmac<L> for FailingPrf {
        const KDF_SERVICE: Service = Service::Tls13Kdf;
        fn prf_new(_key: &[u8]) -> Result<Self, Error> {
            let n = CALLS.with(|c| {
                c.set(c.get().saturating_add(1));
                c.get()
            });
            if n >= 3 {
                Err(Error::InvalidInput)
            } else {
                Ok(Self)
            }
        }
        fn prf_update(&mut self, _data: &[u8]) {}
        fn prf_finalize(&mut self) -> Result<[u8; L], Error> {
            Ok([0x5a; L])
        }
    }

    /// Runs `unwiped`, then `wiped`, each from a fresh call count on a
    /// zeroed output of four blocks: both must fail, `unwiped` must leave
    /// output behind, and `wiped` must leave none.
    fn check(
        what: &str,
        wiped: impl Fn(&mut [u8]) -> Result<(), Error>,
        unwiped: impl Fn(&mut [u8]) -> Result<(), Error>,
    ) {
        const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
            name: "integrity not verifiable in an unsigned test binary",
            run: || Ok(()),
        }];
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        let mut out = [0u8; 4 * L];
        CALLS.with(|c| c.set(0));
        assert!(
            unwiped(&mut out).is_err(),
            "{what}: the stand-in did not fail"
        );
        assert!(
            out.iter().any(|&b| b != 0),
            "{what}: control wrote nothing before failing"
        );
        let mut out = [0u8; 4 * L];
        CALLS.with(|c| c.set(0));
        assert!(wiped(&mut out).is_err(), "{what}: did not fail");
        assert!(
            out.iter().all(|&b| b == 0),
            "{what}: output left after an error"
        );
    }

    #[test]
    fn tls12_prf_wipes_its_output_on_error() {
        check(
            "TLS 1.2 PRF",
            |out| tls12_prf_internal::<FailingPrf, L>(b"secret", b"label", b"seed", out),
            |out| tls12_prf_internal_unwiped::<FailingPrf, L>(b"secret", b"label", b"seed", out),
        );
    }

    #[test]
    fn tls13_expand_label_wipes_its_output_on_error() {
        check(
            "TLS 1.3 HKDF-Expand-Label",
            |out| tls13_hkdf_expand_label_internal::<FailingPrf, L>(&[1; L], b"key", b"", out),
            |out| {
                tls13_hkdf_expand_label_internal_unwiped::<FailingPrf, L>(&[1; L], b"key", b"", out)
            },
        );
    }
}
