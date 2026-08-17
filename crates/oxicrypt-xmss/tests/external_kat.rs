//! XMSS-SHA2_10_256 verification against externally produced vectors.
//!
//! The vectors in `tests/data/botan-xmss-sha2_10_256.vec` come from the
//! Botan project's test suite and trace back to the XMSS reference
//! implementation. Nothing in them was produced by this crate, which is
//! what makes them evidence: a verifier tested against signatures it
//! generated itself proves only that it agrees with itself.
//!
//! Reference: RFC 8391 Algorithm 14; SP 800-208 §5.1 Table 10, §8.2.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use oxicrypt_xmss::{PUBLIC_KEY_LEN, SIGNATURE_LEN, verify_internal};

struct Vector {
    valid: bool,
    msg: Vec<u8>,
    public_key: [u8; PUBLIC_KEY_LEN],
    /// Kept as a slice: part of Botan's negative set carries signatures of
    /// the wrong length, which `[u8; SIGNATURE_LEN]` cannot represent.
    signature: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    // Chunked rather than indexed: `&s[i..i + 2]` needs index arithmetic the
    // workspace lints deny, and `chunks_exact` expresses the same pairing
    // without it. The `assert!` above is what makes the discarded remainder
    // unreachable.
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hex = core::str::from_utf8(pair).expect("hex is ascii");
            u8::from_str_radix(hex, 16).expect("bad hex")
        })
        .collect()
}

const BOTAN: &str = include_str!("data/botan-xmss-sha2_10_256.vec");
const MULTI_LEAF: &str = include_str!("data/multi-leaf-xmss-sha2_10_256.vec");

fn load() -> Vec<Vector> {
    parse(BOTAN)
}

/// The multi-leaf corpus: six independent key pairs across 33 distinct leaf
/// indices. Botan's vectors all sign leaf 0, where the index contributes
/// nothing to any hash — so on that corpus alone the whole leaf-index
/// binding (the `idx` field, the authentication-path parity, the ADRS tree
/// index) can be deleted without a single test noticing.
fn load_multi_leaf() -> Vec<Vector> {
    parse(MULTI_LEAF)
}

fn leaf_index(v: &Vector) -> u32 {
    let head: [u8; 4] = v
        .signature
        .get(..4)
        .expect("a signature carries its leaf index in the first four bytes")
        .try_into()
        .expect("four bytes");
    u32::from_be_bytes(head)
}

fn parse(raw: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    let (mut valid, mut msg, mut pk) = (None, None, None);
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("malformed line");
        let value = value.trim();
        match key.trim() {
            "Valid" => valid = Some(value == "1"),
            "Msg" => msg = Some(unhex(value)),
            "PublicKey" => pk = Some(unhex(value)),
            "Signature" => out.push(Vector {
                valid: valid.take().expect("no Valid"),
                msg: msg.take().expect("no Msg"),
                public_key: pk
                    .take()
                    .expect("no PublicKey")
                    .try_into()
                    .expect("public key length"),
                signature: unhex(value),
            }),
            other => panic!("unknown key {other}"),
        }
    }
    out
}

fn sized(v: &Vector) -> Option<[u8; SIGNATURE_LEN]> {
    v.signature.clone().try_into().ok()
}

/// The file must carry both classes at the expected counts, or every test
/// below can pass vacuously by iterating nothing.
#[test]
fn vector_file_carries_both_classes() {
    let vectors = load();
    let valid = vectors.iter().filter(|v| v.valid).count();
    assert_eq!(valid, 3, "expected 3 valid vectors, found {valid}");
    assert_eq!(vectors.len() - valid, 28, "expected 28 invalid vectors");
}

#[test]
fn accepts_externally_produced_signatures() {
    let vectors = load();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.valid) {
        let sig = sized(v).expect("a valid vector must be SIGNATURE_LEN bytes");
        assert!(
            verify_internal(&v.public_key, &v.msg, &sig),
            "rejected a valid external signature over a {}-byte message",
            v.msg.len()
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "loop ran {checked} times, not 3");
}

#[test]
fn rejects_externally_produced_invalid_signatures() {
    let vectors = load();
    let mut checked = 0;
    for (i, v) in vectors.iter().filter(|v| !v.valid).enumerate() {
        // Wrong-length signatures are unrepresentable in the public API and
        // are counted by the test below rather than passed to the verifier.
        let Some(sig) = sized(v) else { continue };
        assert!(
            !verify_internal(&v.public_key, &v.msg, &sig),
            "accepted invalid external vector {i}"
        );
        checked += 1;
    }
    assert_eq!(checked, 16, "loop ran {checked} times, not 16");
}

/// Part of Botan's negative set is malformed by length. Those cases cannot
/// reach `verify` at all: it takes `&[u8; SIGNATURE_LEN]`, so a signature of
/// any other length is rejected by the type rather than at run time. This
/// test pins that as a property, and pins the split so a future vector
/// refresh cannot quietly move cases from one bucket to the other.
#[test]
fn wrong_length_signatures_are_unrepresentable() {
    let vectors = load();
    let malformed: Vec<usize> = vectors
        .iter()
        .filter(|v| !v.valid && sized(v).is_none())
        .map(|v| v.signature.len())
        .collect();
    assert_eq!(malformed.len(), 12, "expected 12 wrong-length negatives");
    // The `all(|n| n != SIGNATURE_LEN)` this replaced could not fail:
    // `malformed` is built by filtering on `sized(v).is_none()`, which is
    // defined as the length conversion failing. Partition sizes can fail,
    // so they are what is asserted.
    let representable = vectors.iter().filter(|v| sized(v).is_some()).count();
    assert_eq!(
        representable + malformed.len(),
        vectors.len(),
        "every vector belongs to exactly one of the two buckets"
    );
    assert_eq!(
        representable, 19,
        "expected 19 length-representable vectors"
    );
}

/// A valid vector with one flipped bit must fail. Guards against a verifier
/// that accepts everything, which would pass the acceptance test and fail
/// nothing.
#[test]
fn rejects_a_bit_flipped_valid_signature() {
    let vectors = load();
    let v = vectors.iter().find(|v| v.valid).expect("no valid vector");
    let mut tampered = sized(v).expect("valid vector length");
    tampered[64] ^= 0x01;
    assert!(!verify_internal(&v.public_key, &v.msg, &tampered));
}

/// A valid signature checked against a different public key must fail.
#[test]
fn rejects_a_signature_under_the_wrong_public_key() {
    let vectors = load();
    let valid: Vec<&Vector> = vectors.iter().filter(|v| v.valid).collect();
    let a = valid.first().expect("the file carries a valid vector");
    let other = valid
        .iter()
        .find(|v| v.public_key != a.public_key)
        .expect("all valid vectors share one public key");
    let sig = sized(a).expect("valid vector length");
    assert!(!verify_internal(&other.public_key, &a.msg, &sig));
}

// ── Multi-leaf corpus ───────────────────────────────────────────────────────
//
// Six independent key pairs, five of them with a non-zero public SEED, across
// 33 distinct leaf indices from 0 to 1023. Sources and licences are recorded
// in the vector file's own header; every record carries a `# source:` tag.

/// Counts first, because every test below iterates. A parse that silently
/// yielded nothing would let all of them pass having verified no signature.
#[test]
fn multi_leaf_corpus_spans_the_tree() {
    let vectors = load_multi_leaf();
    let valid: Vec<&Vector> = vectors.iter().filter(|v| v.valid).collect();
    assert_eq!(valid.len(), 30, "expected 30 valid vectors");
    assert_eq!(vectors.len() - valid.len(), 9, "expected 9 invalid vectors");

    let keys: std::collections::BTreeSet<_> = valid.iter().map(|v| v.public_key).collect();
    assert_eq!(keys.len(), 6, "expected 6 distinct public keys");

    let indices: std::collections::BTreeSet<u32> = valid.iter().map(|v| leaf_index(v)).collect();
    assert!(
        indices.len() >= 24,
        "expected at least 24 distinct leaf indices, found {}",
        indices.len()
    );
    let non_zero = indices.iter().filter(|&&i| i != 0).count();
    assert!(
        non_zero >= 23,
        "the point of this corpus is non-zero leaf indices; found {non_zero}"
    );
    assert!(
        indices.contains(&1023),
        "the last leaf of the tree must be covered"
    );
}

/// Every valid signature in the corpus must verify, at whatever leaf it was
/// produced. This is what pins the leaf-index binding: a verifier that
/// ignores the index, or that puts the authentication node on the wrong side
/// for odd leaves, still verifies leaf 0 and fails here.
#[test]
fn verifies_signatures_across_the_tree() {
    let vectors = load_multi_leaf();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.valid) {
        let sig = sized(v).expect("valid vector length");
        assert!(
            verify_internal(&v.public_key, &v.msg, &sig),
            "rejected a valid signature at leaf {}",
            leaf_index(v)
        );
        checked += 1;
    }
    assert_eq!(checked, 30, "expected to check 30 signatures");
}

/// The corpus's negative half must be rejected. These come from published
/// ACVP expected-results, so this also pins agreement with an external
/// authority on which signatures are bad, not merely on which are good.
#[test]
fn rejects_the_corpus_negatives() {
    let vectors = load_multi_leaf();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| !v.valid) {
        if let Some(sig) = sized(v) {
            assert!(
                !verify_internal(&v.public_key, &v.msg, &sig),
                "accepted an invalid signature at leaf {}",
                leaf_index(v)
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 9, "expected to check 9 invalid signatures");
}
