//! Verification-hardening tests for the SP 800-208 §6.2 deterministic
//! LM-OTS randomizer `C` on LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4.
//!
//! # Why these tests exist (and why they are *not* an external KAT)
//!
//! LMS *sign* output cannot be byte-anchored to any public external
//! vector. RFC 8554 Appendix F predates SP 800-208 §6.2's mandate that
//! the LM-OTS randomizer `C` be derived *deterministically* from the
//! private seed (the RFC permits a freshly-random `C`), so its published
//! signatures carry a `C` that differs from the deterministic `C` this
//! module emits — proven empirically: published `C` != deterministic `C`.
//! And no NIST ACVP vector pairs a `seed` with a deterministic-`C`
//! signature (the ACVP LMS sigGen flow is IUT-key, so the server never
//! dictates a seed→signature mapping). External byte-anchoring is thus
//! *structurally unavailable* for the sign path.
//!
//! An external reviewer prescribed the strongest available substitute,
//! the two tests in this file:
//!
//! 1. [`deterministic_c_matches_spec_recomputation`] — a **spec-traced**
//!    test: it extracts the emitted `C` from a real signature and asserts
//!    it equals an *independent* recomputation of `C` performed by direct
//!    `oxicrypt_sha::sha256::Sha256` primitive calls over the documented
//!    concatenation (a second code path through the raw hash, NOT a call
//!    to the crate's internal `compute_c`). This anchors the
//!    deterministic-`C` construction to the SP 800-208 §6.2 spec text.
//!
//! 2. [`golden_regression_pin_both_paths`] — a **self-generated
//!    regression pin** of the full signature bytes (see its own rustdoc
//!    for the explicit non-KAT disclaimer).
//!
//! Signature *validity* is externally grounded elsewhere — by the NIST
//! ACVP sigVer KATs in `nist_kat.rs`. These two tests add: `C` anchored
//! to the spec text, and the full byte-output frozen against regression.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use oxicrypt_lms::{SIGNATURE_LEN, keygen_from_parts, sign_internal, verify_internal};
use oxicrypt_sha::sha256::Sha256;

// ── Fixed, documented test inputs (recognizable bytes) ───────────────

/// Tree seed — recognizable fixed bytes (`0x42` repeated).
const SEED: [u8; 32] = [0x42u8; 32];
/// Tree identifier `I` — recognizable fixed bytes (`0x07` repeated).
const IDENTIFIER: [u8; 16] = [0x07u8; 16];
/// Target message — short fixed ASCII string.
const TARGET_MSG: &[u8] = b"oxicrypt LMS deterministic-C regression pin";

/// Throwaway messages used to advance the key to `q = 3`, each paired
/// with the `leaf_index` value expected *after* signing it. Each LMS leaf
/// is independent, so the content of these does not affect the `q = 3`
/// signature; they only step `leaf_index` forward. The paired expected
/// index is a `u32` literal so the test never casts `usize`→`u32` or does
/// arithmetic on the loop counter (keeps strict clippy happy).
const THROWAWAY: [(&[u8], u32); 3] = [
    (b"throwaway-q0", 1),
    (b"throwaway-q1", 2),
    (b"throwaway-q2", 3),
];

/// The fixed leaf index under test.
const Q: u32 = 3;

// ── Parameter-set constants for the pair under test ──────────────────
//
// LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4 (the NIST KAT pair).

/// Digest / randomizer length `N` (bytes) for this pair.
const N: usize = 32;
/// LM-OTS typecode (`LMOTS_SHA256_N32_W4`), the "otstype" field.
const LMOTS_TYPE: u32 = 0x0000_0003;

// Signature layout (RFC 8554 §3.3, this pair):
//   [0..4]   u32(q)
//   [4..8]   u32(otstype = LMOTS_TYPE)
//   [8..40]  C            (N = 32 bytes)   <- field under test
//   [40..]   y_0 .. y_{P-1}, u32(lmstype), auth path
/// Byte offset of the `q` field.
const OFF_Q: usize = 0;
/// Byte offset of the `otstype` field.
const OFF_OTSTYPE: usize = 4;
/// Byte offset of the `C` field.
const OFF_C: usize = 8;

// ── Helpers ──────────────────────────────────────────────────────────

/// Build a fresh key and advance it to `q = 3` by signing the three
/// throwaway messages, then sign `TARGET_MSG`. Returns the public key
/// and the `q = 3` signature.
fn sign_at_q3() -> ([u8; oxicrypt_lms::PUBLIC_KEY_LEN], [u8; SIGNATURE_LEN]) {
    let (mut sk, pk) = keygen_from_parts(&SEED, &IDENTIFIER);
    for (m, expected_index) in &THROWAWAY {
        sign_internal(&mut sk, m).expect("throwaway sign must succeed");
        assert_eq!(sk.leaf_index(), *expected_index, "leaf index must advance");
    }
    assert_eq!(sk.leaf_index(), Q, "key must be positioned at q = 3");
    let sig = sign_internal(&mut sk, TARGET_MSG).expect("target sign must succeed");
    (pk, sig)
}

/// **Independent** recomputation of the SP 800-208 §6.2 deterministic
/// LM-OTS randomizer `C`, via direct `oxicrypt_sha` SHA-256 primitive
/// calls — a second code path that does NOT route through the crate's
/// internal `compute_c`.
///
/// SP 800-208 §6.2 (deterministic LM-OTS signatures) replaces RFC 8554's
/// random `C` with the keyed derivation
///
/// ```text
/// C = H( I || u32str(q) || u16str(0xFFFD) || SEED || message )
/// ```
///
/// where `H` is the parameter set's hash (SHA-256 here), `I` is the
/// 16-byte tree identifier, `q` is the 32-bit leaf index, `0xFFFD` is the
/// §6.2 randomizer diversifier (`D_C`, distinct from RFC 8554's
/// `D_PBLC` / `D_MESG` / `D_LEAF` / `D_INTR`), `SEED` is the N-byte
/// private tree seed, and `message` is the message being signed. All
/// integers are big-endian (`u32str` / `u16str` per RFC 8554 §3.1).
fn recompute_c_per_spec(identifier: &[u8; 16], q: u32, seed: &[u8; N], message: &[u8]) -> [u8; N] {
    /// SP 800-208 §6.2 randomizer diversifier `D_C`.
    const D_C: u16 = 0xFFFD;

    let mut h = Sha256::new_internal();
    h.update(identifier); // I
    h.update(&q.to_be_bytes()); // u32str(q)
    h.update(&D_C.to_be_bytes()); // u16str(0xFFFD)
    h.update(seed); // SEED
    h.update(message); // message
    h.finalize()
}

// ── Test 1: spec-traced C derivation ─────────────────────────────────

/// Spec-traced deterministic-`C` test for LMS_SHA256_M32_H10 /
/// LMOTS_SHA256_N32_W4.
///
/// Builds the NIST-KAT-pair key from `(SEED, I)`, advances to a fixed
/// `q = 3`, signs `TARGET_MSG`, parses the emitted signature
/// (`u32(q) || u32(otstype) || C(32) || ...`), and extracts the `C`
/// field. It then **independently** recomputes the expected `C` per the
/// SP 800-208 §6.2 deterministic construction via raw `oxicrypt_sha`
/// SHA-256 calls (see [`recompute_c_per_spec`]) — a second code path
/// through the raw hash, not a call to the crate's internal `compute_c`.
///
/// Asserts: extracted `C` == independently recomputed `C`; the `q` field
/// == 3; the `otstype` field == `LMOTS_TYPE`; and the signature verifies.
/// This anchors the deterministic-`C` construction to the spec text via
/// an independent computation path.
#[test]
fn deterministic_c_matches_spec_recomputation() {
    let (pk, sig) = sign_at_q3();

    // Parse the q and otstype header fields.
    let q_field = u32::from_be_bytes([sig[OFF_Q], sig[OFF_Q + 1], sig[OFF_Q + 2], sig[OFF_Q + 3]]);
    assert_eq!(q_field, Q, "signature q field must be the fixed q = 3");

    let otstype = u32::from_be_bytes([
        sig[OFF_OTSTYPE],
        sig[OFF_OTSTYPE + 1],
        sig[OFF_OTSTYPE + 2],
        sig[OFF_OTSTYPE + 3],
    ]);
    assert_eq!(
        otstype, LMOTS_TYPE,
        "signature otstype field must be LMOTS_SHA256_N32_W4 (0x03)"
    );

    // Extract the emitted C field (bytes 8..40).
    let mut emitted_c = [0u8; N];
    emitted_c.copy_from_slice(&sig[OFF_C..OFF_C + N]);

    // Independently recompute C per SP 800-208 §6.2 via raw SHA-256.
    let expected_c = recompute_c_per_spec(&IDENTIFIER, Q, &SEED, TARGET_MSG);

    assert_eq!(
        emitted_c, expected_c,
        "emitted deterministic C does not match the independent \
         SP 800-208 §6.2 recomputation (I || u32str(q) || u16str(0xFFFD) \
         || SEED || message)"
    );

    // The signature must also be a valid LMS signature.
    assert!(
        verify_internal(&pk, TARGET_MSG, &sig),
        "the q = 3 deterministic-C signature must verify"
    );
}

// ── Test 2: golden regression pin (both signing paths) ───────────────

/// Load the vendored golden signature fixture.
fn load_golden() -> [u8; SIGNATURE_LEN] {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/lms_sha256_m32_h10_w4_deterministic_c_q3_sig.bin"
    );
    let v = std::fs::read(path).expect("golden fixture not found");
    assert_eq!(v.len(), SIGNATURE_LEN, "golden fixture has wrong length");
    v.try_into().unwrap()
}

/// Golden regression pin of the full SP 800-208 deterministic-`C`
/// signature bytes for the fixed `(SEED, I, q = 3, TARGET_MSG)` on
/// LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4, asserted byte-for-byte
/// through **all three** signing paths.
///
/// **This is a self-generated REGRESSION PIN of the SP 800-208
/// deterministic-`C` output — it is NOT an independent known-answer
/// test.** The fixture bytes were produced by this very implementation
/// and committed; the test only guards against unintended future change
/// to the emitted signature. External byte-anchoring is structurally
/// unavailable: RFC 8554 predates the deterministic-`C` mandate (its
/// published `C` differs from the deterministic `C`), and no public
/// vector pairs a seed with a deterministic-`C` signature. Independent
/// grounding comes from elsewhere — signature *validity* is externally
/// grounded by the NIST ACVP sigVer KATs (`nist_kat.rs`), and the `C`
/// field is anchored to the spec text by the spec-traced test
/// [`deterministic_c_matches_spec_recomputation`] above.
///
/// All three paths sign the same fixed inputs and must equal the fixture:
///
/// * **Free path** — a freshly built `LmsPrivateKey` advanced to `q = 3`
///   and signed once.
/// * **Reused-key path** — a single `LmsPrivateKey` reused across the
///   group, signing `q = 0, 1, 2` (throwaways) then `q = 3` (target) by
///   implicit sequential auto-advance.
/// * **Node-table cached path** — the same key wrapped in
///   `LmsSigningKey` (the precomputed-Merkle-table signer the ACVP
///   harness sigGen handlers use). This is the path whose leaf sweep the
///   `parallel` feature parallelizes, so under `--features parallel`
///   this assertion byte-anchors the rayon-built node table to the same
///   frozen fixture.
///
/// (Each LMS leaf is independent, so the throwaway messages at `q < 3` do
/// not influence the `q = 3` signature; all paths are therefore required
/// to be byte-identical to each other and to the fixture.)
#[test]
fn golden_regression_pin_all_paths() {
    let golden = load_golden();

    // ── Free path: fresh key, advance to q=3, sign target. ──────────
    let (_pk_free, sig_free) = sign_at_q3();
    assert_eq!(
        sig_free, golden,
        "free-path q = 3 signature drifted from the golden fixture"
    );

    // ── Cached path: one reused key, sequential auto-advance. ───────
    let (pk_cached, mut sk_cached) = {
        let (sk, pk) = keygen_from_parts(&SEED, &IDENTIFIER);
        (pk, sk)
    };
    // q = 0, 1, 2 throwaways on the SAME key object (cached/auto-advance).
    for (m, expected_index) in &THROWAWAY {
        sign_internal(&mut sk_cached, m).expect("cached throwaway sign");
        assert_eq!(sk_cached.leaf_index(), *expected_index);
    }
    assert_eq!(sk_cached.leaf_index(), Q);
    let sig_cached = sign_internal(&mut sk_cached, TARGET_MSG).expect("cached target sign");

    assert_eq!(
        sig_cached, golden,
        "cached-path q = 3 signature drifted from the golden fixture"
    );

    // ── Node-table cached path: `LmsSigningKey` wrapping the same key.
    // The harness sigGen path, and the path the `parallel` feature's
    // rayon leaf sweep builds — byte-anchored to the same fixture.
    let mut sk_table = {
        let (sk, pk) = keygen_from_parts(&SEED, &IDENTIFIER);
        assert_eq!(pk, pk_cached, "node-table key must match the reused key");
        oxicrypt_lms::lms_sha256_m32_h10_w4::LmsSigningKey::from_private_key_internal(sk)
    };
    for (m, _) in &THROWAWAY {
        sk_table
            .sign_internal(m)
            .expect("node-table throwaway sign");
    }
    let sig_table = sk_table
        .sign_internal(TARGET_MSG)
        .expect("node-table target sign");
    assert_eq!(
        sig_table, golden,
        "LmsSigningKey node-table q = 3 signature drifted from the golden fixture"
    );

    // All paths must also agree with each other, and the pinned
    // signature must verify under the cached key's public key.
    assert_eq!(
        sig_free, sig_cached,
        "free and reused-key signing paths produced different q = 3 bytes"
    );
    assert!(
        verify_internal(&pk_cached, TARGET_MSG, &sig_cached),
        "the pinned q = 3 signature must verify"
    );
}
