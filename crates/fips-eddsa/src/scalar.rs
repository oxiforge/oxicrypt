//! Scalars modulo the edwards25519 group order `L`.
//!
//! Ed25519 private scalars, signing nonces, and the signature
//! component `s` all live in the prime-order subgroup
//! `Z / LZ`, where
//!
//! ```text
//! L = 2^252 + 27742317777372353535851937790883648493
//!   = 0x1000000000000000 0000000000000000
//!       14def9dea2f79cd6 5812631a5cf5d3ed
//! ```
//!
//! This module lands the scalar type plus its encoding and
//! canonicalization check. The heavier modular-reduction and
//! multiply-add primitives (`reduce`, `muladd`) arrive in a
//! follow-up commit so they can be reviewed on their own.
//!
//! # Canonicalization and signature verification
//!
//! RFC 8032 §5.1.7 step 2 requires that signature verifiers reject
//! any signature whose `s` component, decoded from the low 32 bytes
//! of the signature, is not strictly less than `L`. Accepting
//! non-canonical `s` values opens the door to signature malleability
//! and, in some integrations, to replay. The
//! [`is_canonical_encoding`] helper performs exactly this check in
//! constant time relative to the byte values.
//!
//! # Representation
//!
//! A [`Scalar`] stores a value in `[0, 2^256)` as an eight-limb
//! little-endian `u32` array. The value is not automatically reduced
//! mod `L`; callers that need a canonical scalar must use the
//! reduction primitive added in the next commit, or construct the
//! scalar via an API that performs the reduction itself.

// The scalar module does native bignum arithmetic on u32 limbs and
// will grow constant-time modular reduction in the next commit.
// The pedantic lints that fire on every limbwise add / shift / mask
// don't add safety signal here; we opt out at module scope just
// like `field.rs` and the sha3 / sha512_t modules in `fips-sha`.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use
)]

/// The edwards25519 group order `L`, stored as eight little-endian
/// `u32` limbs so that `L = sum(L_LIMBS[i] * 2^(32*i))`.
///
/// Derived once from `L = 2^252 + 27742317777372353535851937790883648493`
/// and pinned here so the value is obvious to anyone reading this
/// module. Equivalent to the encoding used by ref10
/// (`crypto_sign/ed25519/ref10/sc_reduce.c`).
///
/// Currently only consumed by the unit-test cross-check against
/// [`L_BYTES`]; the reduction primitive landing in the follow-up
/// commit will use it directly.
#[allow(dead_code)]
pub(crate) const L_LIMBS: [u32; 8] = [
    0x5cf5_d3ed,
    0x5812_631a,
    0xa2f7_9cd6,
    0x14de_f9de,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x1000_0000,
];

/// Canonical little-endian byte encoding of `L`. Cross-checked
/// against the [`L_LIMBS`] constant by the module unit tests.
pub(crate) const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// An integer in `[0, 2^256)`, typically a scalar modulo the
/// edwards25519 group order.
///
/// This type is the raw 256-bit container. Values are **not**
/// guaranteed to be reduced modulo `L`. Helpers that produce
/// canonical reduced scalars will live alongside `reduce` and
/// `muladd` in the follow-up commit.
#[derive(Copy, Clone, Debug)]
pub struct Scalar {
    limbs: [u32; 8],
}

impl Scalar {
    /// The zero scalar.
    pub const ZERO: Scalar = Scalar { limbs: [0; 8] };

    /// The multiplicative identity.
    pub const ONE: Scalar = Scalar {
        limbs: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    /// Load a scalar from 32 little-endian bytes **without** reducing
    /// modulo `L`.
    ///
    /// Use this when you need the raw 256-bit value — for example
    /// when decoding the `s` component of a signature before running
    /// the canonical-form check (RFC 8032 §5.1.7 step 2). Callers
    /// that want a reduced scalar should use the reduction API that
    /// lands in a follow-up commit.
    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar {
        let mut limbs = [0u32; 8];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let off = i * 4;
            *limb = u32::from(bytes[off])
                | (u32::from(bytes[off + 1]) << 8)
                | (u32::from(bytes[off + 2]) << 16)
                | (u32::from(bytes[off + 3]) << 24);
        }
        Scalar { limbs }
    }

    /// Serialize a scalar to 32 little-endian bytes.
    ///
    /// No canonicalization is performed — the bytes reflect whatever
    /// value is currently stored in the limbs.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.limbs.iter().enumerate() {
            let off = i * 4;
            out[off] = *limb as u8;
            out[off + 1] = (*limb >> 8) as u8;
            out[off + 2] = (*limb >> 16) as u8;
            out[off + 3] = (*limb >> 24) as u8;
        }
        out
    }

    /// Access the underlying limb array. `pub(crate)` so the rest of
    /// the `fips-eddsa` crate can build reduction routines on top
    /// without exposing the representation publicly. Will be used by
    /// the reduction primitive landing in the follow-up commit.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn limbs(&self) -> &[u32; 8] {
        &self.limbs
    }

    /// Constant-time test for the zero scalar.
    ///
    /// Returns `1` if every limb is zero, `0` otherwise.
    pub fn is_zero_ct(&self) -> u8 {
        let mut acc: u32 = 0;
        for limb in &self.limbs {
            acc |= *limb;
        }
        // acc == 0  →  return 1
        // acc != 0  →  return 0
        (((acc | acc.wrapping_neg()) >> 31) ^ 1) as u8
    }
}

/// Test whether `bytes` is a canonical little-endian encoding of a
/// scalar in `[0, L)`.
///
/// This is the RFC 8032 §5.1.7 step 2 check for the `s` component of
/// an Ed25519 signature: verifiers MUST reject any signature whose
/// `s` decodes to a value greater than or equal to `L`.
///
/// Constant time with respect to the input bytes.
pub fn is_canonical_encoding(bytes: &[u8; 32]) -> bool {
    // Walk from most-significant byte down; propagate the first
    // non-equal comparison result in a constant-time accumulator.
    //
    // `lt` (0 or 1) becomes 1 exactly when bytes < L_BYTES in the
    // standard little-endian interpretation (compared from the top).
    // `gt` similarly.
    //
    // The comparisons use unsigned subtraction into u32 so we don't
    // need signed casts: `(a - b)` wraps around exactly when a < b,
    // and bit 31 of the wrapped result is the borrow flag.
    let mut lt: u32 = 0;
    let mut gt: u32 = 0;
    for (a, b) in bytes.iter().rev().zip(L_BYTES.iter().rev()) {
        let a = u32::from(*a);
        let b = u32::from(*b);
        // still_undecided == 1 iff lt == 0 and gt == 0 so far.
        let still_undecided = (!(lt | gt)) & 1;
        let this_lt = (a.wrapping_sub(b) >> 31) & 1; // 1 if a < b
        let this_gt = (b.wrapping_sub(a) >> 31) & 1; // 1 if a > b
        lt |= still_undecided & this_lt;
        gt |= still_undecided & this_gt;
    }
    // Canonical iff strictly less than L: lt == 1.
    lt == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_limbs_matches_l_bytes() {
        // Recompute the byte encoding from the u32 limbs and compare.
        let mut bytes = [0u8; 32];
        for (i, limb) in L_LIMBS.iter().enumerate() {
            let off = i * 4;
            bytes[off] = *limb as u8;
            bytes[off + 1] = (*limb >> 8) as u8;
            bytes[off + 2] = (*limb >> 16) as u8;
            bytes[off + 3] = (*limb >> 24) as u8;
        }
        assert_eq!(bytes, L_BYTES);
    }

    #[test]
    fn roundtrip_zero_and_one() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(Scalar::from_bytes(&zero).to_bytes(), zero);
        assert_eq!(Scalar::from_bytes(&one).to_bytes(), one);
        assert_eq!(Scalar::ZERO.to_bytes(), zero);
        assert_eq!(Scalar::ONE.to_bytes(), one);
    }

    #[test]
    fn roundtrip_arbitrary() {
        let bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9,
            0x87, 0x65, 0x43, 0x21,
        ];
        assert_eq!(Scalar::from_bytes(&bytes).to_bytes(), bytes);
    }

    #[test]
    fn is_zero_ct_detects_zero() {
        assert_eq!(Scalar::ZERO.is_zero_ct(), 1);
        assert_eq!(Scalar::ONE.is_zero_ct(), 0);
        let mut bytes = [0u8; 32];
        bytes[17] = 0x01;
        assert_eq!(Scalar::from_bytes(&bytes).is_zero_ct(), 0);
    }

    #[test]
    fn canonical_accepts_zero_one_and_l_minus_one() {
        assert!(is_canonical_encoding(&[0u8; 32]));

        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_canonical_encoding(&one));

        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        assert!(is_canonical_encoding(&l_minus_one));
    }

    #[test]
    fn canonical_rejects_l_and_above() {
        // L itself is not canonical.
        assert!(!is_canonical_encoding(&L_BYTES));

        // L + 1.
        let mut l_plus_one = L_BYTES;
        l_plus_one[0] += 1;
        assert!(!is_canonical_encoding(&l_plus_one));

        // 2^255 - 1, which is well above L.
        let all_high = {
            let mut b = [0xffu8; 32];
            b[31] = 0x7f;
            b
        };
        assert!(!is_canonical_encoding(&all_high));

        // 2^256 - 1, maximum 256-bit value.
        let max = [0xffu8; 32];
        assert!(!is_canonical_encoding(&max));
    }

    #[test]
    fn canonical_accepts_values_just_below_high_byte_boundary() {
        // A value whose top byte is 0x0f (below L's top byte 0x10):
        // must be canonical regardless of the lower bytes.
        let mut bytes = [0xffu8; 32];
        bytes[31] = 0x0f;
        assert!(is_canonical_encoding(&bytes));
    }
}
