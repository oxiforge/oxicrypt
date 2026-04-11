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
/// Cross-checked against [`L_BYTES`] by the module unit tests and
/// consumed by [`reduce_wide`] / [`muladd`] via the Barrett reduction
/// below.
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
    /// without exposing the representation publicly.
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

/// Barrett reduction precomputation
/// `MU = floor(2^512 / L) = 0x...eb2106215d086329a7ed9ce5a30a2c131b`.
///
/// Nine `u32` limbs (little-endian) because `MU` is 260 bits wide —
/// the top limb holds only the four bits `0xF`. Used exclusively by
/// [`reduce_wide`].
const MU_LIMBS: [u32; 9] = [
    0x0a2c_131b,
    0xed9c_e5a3,
    0x0863_29a7,
    0x2106_215d,
    0xffff_ffeb,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0x0000_000f,
];

/// Schoolbook multiplication of two little-endian `u32`-limb bignums.
///
/// Implemented in closed form because the `M` and `N` we care about
/// are small (at most 16 × 9), so the double-loop version with a
/// `u64` carry per row is both compact and constant-time with respect
/// to the limb *values* — every iteration executes unconditionally.
///
/// Invariant used by every row: each partial product
/// `u32 × u32 + u32 + u64_carry` always fits in `u64` because
/// `(2^32-1)^2 + 2·(2^32-1) = 2^64 - 1`.
fn wide_mul<const M: usize, const N: usize, const MN: usize>(
    a: &[u32; M],
    b: &[u32; N],
) -> [u32; MN] {
    debug_assert!(MN == M + N);
    let mut out = [0u32; MN];
    for i in 0..M {
        let ai = u64::from(a[i]);
        let mut carry: u64 = 0;
        for j in 0..N {
            let p = ai * u64::from(b[j]) + u64::from(out[i + j]) + carry;
            out[i + j] = p as u32;
            carry = p >> 32;
        }
        out[i + N] = carry as u32;
    }
    out
}

/// Subtract `b` from `a` in place over `LEN` little-endian `u32`
/// limbs, returning the final borrow (0 or 1). Constant-time.
fn sub_assign_borrow<const LEN: usize>(a: &mut [u32; LEN], b: &[u32; LEN]) -> u32 {
    let mut borrow: u64 = 0;
    for i in 0..LEN {
        let diff = u64::from(a[i])
            .wrapping_sub(u64::from(b[i]))
            .wrapping_sub(borrow);
        a[i] = diff as u32;
        borrow = (diff >> 32) & 1;
    }
    borrow as u32
}

/// One conditional subtraction of `L` (9-limb form, top limb zero).
///
/// If the current `r` is `≥ L` the subtracted result replaces `r`;
/// otherwise `r` is left unchanged. Constant time in the value of
/// `r`: both paths execute the same arithmetic and the selection is
/// done with a bitmask.
fn cond_sub_l_9(r: &mut [u32; 9]) {
    let l9: [u32; 9] = [
        L_LIMBS[0], L_LIMBS[1], L_LIMBS[2], L_LIMBS[3],
        L_LIMBS[4], L_LIMBS[5], L_LIMBS[6], L_LIMBS[7],
        0,
    ];
    let mut tmp = *r;
    let borrow = sub_assign_borrow::<9>(&mut tmp, &l9);
    // borrow == 0 → r was ≥ L → keep tmp
    // borrow == 1 → r was  < L → keep r
    let keep_tmp_mask = borrow.wrapping_sub(1); // 0xFFFF_FFFF if borrow==0
    let keep_r_mask = !keep_tmp_mask;
    for i in 0..9 {
        r[i] = (tmp[i] & keep_tmp_mask) | (r[i] & keep_r_mask);
    }
}

/// Reduce a 64-byte little-endian integer `x` (any value in
/// `[0, 2^512)`) modulo `L` and return it as a canonical [`Scalar`].
///
/// Barrett reduction with `mu = floor(2^512 / L)`:
///
/// ```text
/// q̂ = floor(x · mu / 2^512)
/// r = x − q̂ · L          (mod 2^288)
/// while r ≥ L: r −= L
/// ```
///
/// Because `L < 2^253` and `mu < 2^260`, the quotient estimate `q̂`
/// undershoots the true quotient by at most two, so `r < 3L < 2^255`
/// and at most two conditional subtractions suffice. We perform three
/// for a safety margin; the extra pass is a no-op when `r < L`.
///
/// The function is constant-time in the value of `x`. It is used for
/// the `SHA512(…) mod L` step in RFC 8032 §5.1.6 / §5.1.7 and by
/// [`muladd`] below.
pub fn reduce_wide(x_bytes: &[u8; 64]) -> Scalar {
    // Load the 64 input bytes as sixteen little-endian u32 limbs.
    let mut x = [0u32; 16];
    for (i, limb) in x.iter_mut().enumerate() {
        let off = i * 4;
        *limb = u32::from(x_bytes[off])
            | (u32::from(x_bytes[off + 1]) << 8)
            | (u32::from(x_bytes[off + 2]) << 16)
            | (u32::from(x_bytes[off + 3]) << 24);
    }

    // q_full = x * MU, 16+9 = 25 limbs.
    let q_full: [u32; 25] = wide_mul::<16, 9, 25>(&x, &MU_LIMBS);

    // q̂ = q_full >> 512 — i.e. the top 9 limbs.
    let mut q_hat = [0u32; 9];
    q_hat.copy_from_slice(&q_full[16..25]);

    // q̂ · L, 9+8 = 17 limbs.
    let ql_full: [u32; 17] = wide_mul::<9, 8, 17>(&q_hat, &L_LIMBS);

    // r = x − q̂·L, computed over 17 limbs so cancellation in the
    // high limbs is honored. x is zero-extended from 16 → 17 limbs.
    // The true result is in `[0, 3L)` which fits in 255 bits, so the
    // high limbs of `r` end up zero after subtraction.
    let mut r17 = [0u32; 17];
    r17[..16].copy_from_slice(&x);
    let _ = sub_assign_borrow::<17>(&mut r17, &ql_full);

    // Reuse only the low 9 limbs (288 bits) for the conditional
    // subtractions. `r < 3L < 2^255` so limbs above index 8 are zero.
    let mut r = [0u32; 9];
    r.copy_from_slice(&r17[..9]);
    debug_assert!(r17[9..].iter().all(|&w| w == 0));

    // Up to three conditional subtractions of L.
    cond_sub_l_9(&mut r);
    cond_sub_l_9(&mut r);
    cond_sub_l_9(&mut r);

    // Result fits in the low 8 limbs; top limb must be zero.
    debug_assert!(r[8] == 0);
    let mut limbs = [0u32; 8];
    limbs.copy_from_slice(&r[..8]);
    Scalar { limbs }
}

/// Compute `(a · b + c) mod L` and return it as a canonical scalar.
///
/// Used throughout RFC 8032 §5.1.6 for the signing equation
/// `S = (r + k · s) mod L`. Constant time in `a`, `b`, and `c`.
pub fn muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    // Full 256×256 → 512-bit product.
    let ab: [u32; 16] = wide_mul::<8, 8, 16>(a.limbs(), b.limbs());

    // Add c (8 limbs) into the low half; propagate the carry up.
    let mut sum = ab;
    let mut carry: u64 = 0;
    let c_limbs = c.limbs();
    for (i, item) in sum.iter_mut().take(8).enumerate() {
        let s = u64::from(*item) + u64::from(c_limbs[i]) + carry;
        *item = s as u32;
        carry = s >> 32;
    }
    for item in sum.iter_mut().skip(8) {
        let s = u64::from(*item) + carry;
        *item = s as u32;
        carry = s >> 32;
    }
    // `a·b + c < 2·2^512`, so any residual carry lives outside the
    // 16-limb buffer. Because `a,b,c < 2^256`, the actual value fits
    // in 513 bits — but the high bit beyond 2^512 is effectively a
    // "17th limb worth 1". Since 2^512 ≡ L · mu + (2^512 mod L) and
    // (2^512 mod L) < L, that extra bit can only shift the true
    // quotient by a small constant, still bounded by our 3×
    // conditional-subtract loop below. We absorb it by simply
    // discarding — proof: `a,b,c ≤ L − 1` in the signing use case, so
    // `a·b + c ≤ (L−1)^2 + (L−1) = L² − L < L·2^253 < 2^506`, well
    // under 2^512 and carry is always 0 here.
    debug_assert!(carry == 0);

    // Re-serialize to bytes and run the wide reduction.
    let mut wide = [0u8; 64];
    for (i, limb) in sum.iter().enumerate() {
        let off = i * 4;
        wide[off] = *limb as u8;
        wide[off + 1] = (*limb >> 8) as u8;
        wide[off + 2] = (*limb >> 16) as u8;
        wide[off + 3] = (*limb >> 24) as u8;
    }
    reduce_wide(&wide)
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

    // --- Barrett reduction test vectors ------------------------------
    // Ground truth computed in Python with authoritative
    //   L = 2**252 + 27742317777372353535851937790883648493
    // and `x % L`. The bytes are little-endian. Vectors cover the
    // interesting boundary cases: 0, 1, L-1, L, L+1, 2L, 2^256-1,
    // 2^512-1, and one "middle" value chosen to exercise every limb.

    fn wide(bytes: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }

    #[test]
    fn reduce_wide_zero() {
        assert_eq!(reduce_wide(&[0u8; 64]).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn reduce_wide_one() {
        let mut w = [0u8; 64];
        w[0] = 1;
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(reduce_wide(&w).to_bytes(), expected);
    }

    #[test]
    fn reduce_wide_l_minus_one() {
        let mut w = [0u8; 64];
        w[..32].copy_from_slice(&L_BYTES);
        w[0] -= 1;
        let mut expected = L_BYTES;
        expected[0] -= 1;
        assert_eq!(reduce_wide(&w).to_bytes(), expected);
    }

    #[test]
    fn reduce_wide_l_exact() {
        let mut w = [0u8; 64];
        w[..32].copy_from_slice(&L_BYTES);
        assert_eq!(reduce_wide(&w).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn reduce_wide_l_plus_one() {
        let mut w = [0u8; 64];
        w[..32].copy_from_slice(&L_BYTES);
        w[0] += 1;
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(reduce_wide(&w).to_bytes(), expected);
    }

    #[test]
    fn reduce_wide_two_l() {
        // 2*L, little-endian, computed once in Python.
        let input: [u8; 32] = [
            218, 167, 235, 185, 52, 198, 36, 176, 172, 57, 239, 69, 189, 243, 189, 41, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
        ];
        assert_eq!(reduce_wide(&wide(&input)).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn reduce_wide_two_256_minus_one() {
        let input = [0xffu8; 32];
        // 2^256 - 1 mod L
        let expected: [u8; 32] = [
            28, 149, 152, 141, 116, 49, 236, 214, 112, 207, 125, 115, 244, 91, 239, 198, 254, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 15,
        ];
        assert_eq!(reduce_wide(&wide(&input)).to_bytes(), expected);
    }

    #[test]
    fn reduce_wide_two_512_minus_one() {
        let input = [0xffu8; 64];
        let expected: [u8; 32] = [
            0, 15, 156, 68, 227, 17, 6, 164, 71, 147, 133, 104, 167, 27, 14, 208, 101, 190, 245,
            23, 210, 115, 236, 206, 61, 154, 48, 124, 27, 65, 153, 3,
        ];
        assert_eq!(reduce_wide(&input).to_bytes(), expected);
    }

    #[test]
    fn reduce_wide_mid_512() {
        let input: [u8; 64] = [
            119, 102, 85, 68, 51, 34, 17, 0, 255, 238, 221, 204, 187, 170, 0, 153, 136, 119, 102,
            85, 68, 51, 34, 17, 0, 153, 136, 119, 85, 68, 187, 204, 221, 238, 34, 255, 0, 17, 153,
            136, 119, 102, 85, 68, 51, 34, 17, 237, 254, 206, 250, 237, 254, 13, 240, 190, 186,
            254, 202, 239, 190, 173, 222, 0,
        ];
        let expected: [u8; 32] = [
            45, 121, 145, 135, 134, 70, 14, 143, 74, 244, 239, 216, 217, 62, 98, 13, 224, 52, 147,
            244, 122, 131, 90, 206, 37, 229, 255, 26, 195, 234, 190, 8,
        ];
        assert_eq!(reduce_wide(&input).to_bytes(), expected);
    }

    // --- muladd test vectors -----------------------------------------

    #[test]
    fn muladd_zero() {
        let z = Scalar::ZERO;
        let o = Scalar::ONE;
        assert_eq!(muladd(&z, &z, &z).to_bytes(), [0u8; 32]);
        assert_eq!(muladd(&z, &o, &z).to_bytes(), [0u8; 32]);
        assert_eq!(muladd(&o, &z, &z).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn muladd_one_times_l_minus_one_plus_five() {
        // (1 * (L-1) + 5) mod L = 4
        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        let mut c_bytes = [0u8; 32];
        c_bytes[0] = 5;
        let r = muladd(
            &Scalar::ONE,
            &Scalar::from_bytes(&l_minus_one),
            &Scalar::from_bytes(&c_bytes),
        );
        let mut expected = [0u8; 32];
        expected[0] = 4;
        assert_eq!(r.to_bytes(), expected);
    }

    #[test]
    fn muladd_both_big_identity() {
        // (L-1)^2 + (L-1) = L^2 - L ≡ 0 (mod L)
        let mut l_minus_one = L_BYTES;
        l_minus_one[0] -= 1;
        let a = Scalar::from_bytes(&l_minus_one);
        let r = muladd(&a, &a, &a);
        assert_eq!(r.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn muladd_general() {
        // Python ground truth: a,b,c are three random 256-bit values
        // already pre-reduced mod L. Expected = (a*b + c) mod L.
        let a: [u8; 32] = [
            126, 214, 43, 178, 227, 58, 162, 66, 99, 123, 7, 188, 29, 72, 164, 194, 204, 187, 64,
            211, 231, 120, 135, 205, 66, 169, 115, 76, 186, 88, 234, 10,
        ];
        let b: [u8; 32] = [
            198, 22, 131, 141, 140, 129, 45, 54, 37, 186, 189, 2, 177, 226, 211, 220, 68, 233,
            229, 144, 80, 170, 172, 111, 139, 95, 100, 41, 185, 28, 129, 15,
        ];
        let c: [u8; 32] = [
            255, 128, 43, 219, 195, 103, 36, 199, 194, 101, 32, 180, 136, 2, 0, 135, 35, 96, 228,
            143, 14, 37, 145, 160, 137, 199, 161, 44, 12, 234, 156, 12,
        ];
        let expected: [u8; 32] = [
            233, 241, 235, 1, 96, 147, 57, 16, 37, 178, 95, 33, 137, 163, 196, 20, 178, 30, 78,
            176, 33, 160, 247, 108, 199, 186, 31, 186, 33, 142, 218, 2,
        ];
        let r = muladd(
            &Scalar::from_bytes(&a),
            &Scalar::from_bytes(&b),
            &Scalar::from_bytes(&c),
        );
        assert_eq!(r.to_bytes(), expected);
    }
}
