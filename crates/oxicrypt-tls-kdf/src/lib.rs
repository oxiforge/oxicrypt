//! TLS 1.2 KDF per SP 800-135 Rev. 1 §4 and RFC 5246 §5.
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
    require_allowed, require_operational, Error, KatEntry, SelfTestFailure, Service,
};

// ── Core PRF ──────────────────────────────────────────────────────

/// TLS 1.2 PRF expansion (RFC 5246 §5).
///
/// Fills `out` with `PRF(secret, label, seed)` — the `P_hash`
/// iterated-HMAC expansion. `label` and `seed` are concatenated
/// internally (no caller allocation needed).
///
/// This is the internal variant that bypasses module-state gating;
/// callers in the ACVP harness (which runs behind its own
/// `require_operational` gate) use this directly.
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
) {
    // A(0) = label ‖ seed
    // A(i) = HMAC(secret, A(i−1))
    let mut a = {
        let mut mac = P::prf_new(secret);
        mac.prf_update(label);
        mac.prf_update(seed);
        mac.prf_finalize()
    };

    let mut offset = 0;
    while offset < out.len() {
        // P_i = HMAC(secret, A(i) ‖ label ‖ seed)
        let mut mac = P::prf_new(secret);
        mac.prf_update(&a);
        mac.prf_update(label);
        mac.prf_update(seed);
        let p = mac.prf_finalize();

        let remaining = out.len() - offset;
        let to_copy = if remaining < L { remaining } else { L };
        out[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        let mut mac_a = P::prf_new(secret);
        mac_a.prf_update(&a);
        a = mac_a.prf_finalize();
    }
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
    tls12_prf_internal::<P, L>(secret, label, seed, out);
    Ok(())
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
) -> [u8; MASTER_SECRET_LEN] {
    // Step 1: extended master secret
    let mut master_secret = [0u8; MASTER_SECRET_LEN];
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"extended master secret",
        session_hash,
        &mut master_secret,
    );

    // Step 2: key expansion
    // seed = server_random ‖ client_random (RFC 5246 §6.3)
    let sr_len = server_random.len();
    let cr_len = client_random.len();
    assert!(sr_len + cr_len <= 64, "TLS randoms exceed 64 bytes");
    let mut seed = [0u8; 64];
    seed[..sr_len].copy_from_slice(server_random);
    seed[sr_len..sr_len + cr_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &seed[..sr_len + cr_len],
        key_block_out,
    );

    master_secret
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
    Ok(tls12_extended_master_secret_internal::<P, L>(
        pre_master_secret,
        session_hash,
        server_random,
        client_random,
        key_block_out,
    ))
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
) -> [u8; MASTER_SECRET_LEN] {
    // Step 1: master secret — seed = clientHelloRandom ‖ serverHelloRandom
    let chr_len = client_hello_random.len();
    let shr_len = server_hello_random.len();
    assert!(chr_len + shr_len <= 64, "TLS hello randoms exceed 64 bytes");
    let mut ms_seed = [0u8; 64];
    ms_seed[..chr_len].copy_from_slice(client_hello_random);
    ms_seed[chr_len..chr_len + shr_len].copy_from_slice(server_hello_random);

    let mut master_secret = [0u8; MASTER_SECRET_LEN];
    tls12_prf_internal::<P, L>(
        pre_master_secret,
        b"master secret",
        &ms_seed[..chr_len + shr_len],
        &mut master_secret,
    );

    // Step 2: key expansion — seed = serverRandom ‖ clientRandom
    let server_len = server_random.len();
    let client_len = client_random.len();
    assert!(server_len + client_len <= 64, "TLS randoms exceed 64 bytes");
    let mut ke_seed = [0u8; 64];
    ke_seed[..server_len].copy_from_slice(server_random);
    ke_seed[server_len..server_len + client_len].copy_from_slice(client_random);
    tls12_prf_internal::<P, L>(
        &master_secret,
        b"key expansion",
        &ke_seed[..server_len + client_len],
        key_block_out,
    );

    master_secret
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
    Ok(tls12_master_secret_internal::<P, L>(
        pre_master_secret,
        client_hello_random,
        server_hello_random,
        server_random,
        client_random,
        key_block_out,
    ))
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
// `tls13_derive_secret`) sit alongside the gateless `*_internal`
// entry points: the public surface enforces `require_operational` +
// `require_allowed(Service::Tls13Kdf)`, while the ACVP harness
// continues to dispatch through `_internal` directly so its test
// runs do not depend on the module's profile-gating state. Same
// architectural separation as ML-DSA / SLH-DSA / EdDSA.

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
/// (RFC 5869 §2.3) to fill `out`. `out.len()` must fit in `u16`;
/// realistic TLS 1.3 outputs are ≤96 bytes, far below the cap.
///
/// This is the gateless variant used by the ACVP harness and the
/// power-up self-test. The public, FIPS-gated counterpart
/// [`tls13_hkdf_expand_label`] wraps this with `require_operational`
/// + `require_allowed(Service::Tls13Kdf)` for normal-call use.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn tls13_hkdf_expand_label_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    // Build HkdfLabel into a stack scratch buffer.
    let mut scratch = [0u8; HKDF_LABEL_SCRATCH];
    // `out.len()` is bounded above by realistic TLS 1.3 use (≤96 bytes);
    // the `u16::MAX` saturation handles theoretical overflow.
    let length: u16 = u16::try_from(out.len()).unwrap_or(u16::MAX);
    scratch[0..2].copy_from_slice(&length.to_be_bytes());
    // `full_label_len` is clamped to 255 by the `.min(255)` above, so the
    // `u8::try_from` cannot fail in practice; the `unwrap_or` is belt-and-
    // suspenders matching the same saturation guarantee.
    let full_label_len = 6usize.saturating_add(label.len()).min(255);
    scratch[2] = u8::try_from(full_label_len).unwrap_or(u8::MAX);
    scratch[3..9].copy_from_slice(b"tls13 ");
    let label_take = full_label_len.saturating_sub(6);
    scratch[9..9 + label_take].copy_from_slice(&label[..label_take]);
    let context_off = 9 + label_take;
    // Same saturation reasoning as `full_label_len`: clamped to 255.
    let context_take = context.len().min(255);
    scratch[context_off] = u8::try_from(context_take).unwrap_or(u8::MAX);
    scratch[context_off + 1..context_off + 1 + context_take]
        .copy_from_slice(&context[..context_take]);
    let info_len = context_off + 1 + context_take;
    let info = &scratch[..info_len];

    // HKDF-Expand (RFC 5869 §2.3): OKM = T(1) || T(2) || ... truncated
    //   T(0) = empty
    //   T(i) = HMAC(secret, T(i-1) || info || i)
    let mut prev_block = [0u8; L];
    let mut have_prev = false;
    let mut counter: u8 = 1;
    let mut offset = 0;
    while offset < out.len() {
        let mut mac = P::prf_new(secret);
        if have_prev {
            mac.prf_update(&prev_block);
        }
        mac.prf_update(info);
        mac.prf_update(&[counter]);
        let t = mac.prf_finalize();

        let remaining = out.len() - offset;
        let to_copy = if remaining < L { remaining } else { L };
        out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;

        prev_block.copy_from_slice(&t);
        have_prev = true;
        counter = counter.wrapping_add(1);
    }
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
pub fn tls13_derive_secret_internal<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) {
    tls13_hkdf_expand_label_internal::<P, L>(secret, label, transcript_hash, out);
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
pub fn tls13_hkdf_expand_label<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_operational()?;
    require_allowed(Service::Tls13Kdf)?;
    tls13_hkdf_expand_label_internal::<P, L>(secret, label, context, out);
    Ok(())
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
pub fn tls13_derive_secret<P: PrfHmac<L>, const L: usize>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    require_operational()?;
    require_allowed(Service::Tls13Kdf)?;
    tls13_derive_secret_internal::<P, L>(secret, label, transcript_hash, out);
    Ok(())
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
/// value computed independently.
pub fn self_test() -> Result<(), SelfTestFailure> {
    use oxicrypt_hmac::HmacSha256;
    let mut out = [0u8; 48];
    tls12_prf_internal::<HmacSha256, 32>(&KAT_SECRET, KAT_LABEL, &KAT_SEED, &mut out);
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
    );
    if via_expand != TLS13_KAT_EXPECTED {
        return Err(SelfTestFailure);
    }
    let mut via_derive = [0u8; 32];
    tls13_derive_secret_internal::<HmacSha256, 32>(
        &TLS13_KAT_PRK,
        b"c hs traffic",
        &TLS13_KAT_TRANSCRIPT_HASH,
        &mut via_derive,
    );
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
        name:
            "TLS 1.3 KDF KAT (HKDF-Expand-Label + Derive-Secret, RFC 8446 §7.1; RFC 8448 §3 vector)",
        run: tls13_self_test,
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use oxicrypt_hmac::HmacSha256;

    /// Smoke test: PRF produces deterministic, non-zero output.
    #[test]
    fn prf_produces_output() {
        let secret = [0x0bu8; 16];
        let label = b"test label";
        let seed = [0xaau8; 32];
        let mut out = [0u8; 64];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out);
        assert_ne!(out, [0u8; 64]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn tls13_self_test_passes() {
        tls13_self_test().unwrap();
    }

    /// PRF is deterministic.
    #[test]
    fn prf_deterministic() {
        let secret = [0x01u8; 48];
        let label = b"key expansion";
        let seed = [0xffu8; 64];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out1);
        tls12_prf_internal::<HmacSha256, 32>(&secret, label, &seed, &mut out2);
        assert_eq!(out1, out2);
    }

    /// RFC 8448 §3 (1-RTT handshake), client handshake-traffic-secret
    /// expansion: HKDF-Expand-Label using "c hs traffic" + transcript
    /// hash of `ClientHello || ServerHello`. Authoritative byte-perfect
    /// vector from the published TLS 1.3 example handshakes.
    #[test]
    fn tls13_hkdf_expand_label_rfc8448_c_hs_traffic() {
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
        );
        assert_eq!(out, expected);
    }

    /// `tls13_derive_secret_internal(secret, label, transcript_hash)`
    /// is defined as `HKDF-Expand-Label(secret, label, transcript_hash,
    /// HashLen)`. With output sized to the hash length, the two must
    /// produce identical bytes for the same inputs (RFC 8446 §7.1).
    #[test]
    fn tls13_derive_secret_matches_expand_label_with_hashlen_output() {
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
        );
        tls13_hkdf_expand_label_internal::<HmacSha256, 32>(
            &secret,
            label,
            &transcript_hash,
            &mut via_expand,
        );
        assert_eq!(via_derive, via_expand);
    }
}
