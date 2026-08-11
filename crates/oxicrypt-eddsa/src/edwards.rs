//! Point arithmetic on edwards25519 in extended twisted-Edwards
//! coordinates.
//!
//! # Curve
//!
//! edwards25519 is the twisted Edwards curve
//!
//! ```text
//!     -x² + y² = 1 + d · x² · y²       over GF(2^255 - 19)
//! ```
//!
//! with the curve parameter
//!
//! ```text
//!     d = -121665 / 121666 (mod p)
//! ```
//!
//! The curve has order `8 · L`, where `L` is the prime group order
//! defined in [`crate::scalar`]. The generator `B` used by FIPS 186-5
//! and RFC 8032 lies in the prime-order subgroup of size `L`.
//!
//! # Coordinates
//!
//! Points are stored in the extended twisted-Edwards form
//! `(X : Y : Z : T)` from Hisil, Wong, Carter, and Dawson —
//! "Twisted Edwards Curves Revisited" — where
//!
//! ```text
//!     x = X / Z,     y = Y / Z,     x · y = T / Z.
//! ```
//!
//! This representation admits a dedicated addition formula without
//! any field inversions, which matters for constant-time scalar
//! multiplication.
//!
//! # Status
//!
//! The module holds the point type, the curve constants (`d2 = 2·d`,
//! base point `B`, identity), the complete add / double formulas,
//! fixed-window scalar multiplication, and point compression /
//! decompression. The RFC 8032 sign / verify wiring sits in
//! [`crate::ed25519`].

// The extended-coordinate add / double formulas hammer on field
// elements through the +/-/* operators; each of those ops internally
// uses wrapping arithmetic that clippy's `arithmetic_side_effects`
// lint flags. The allow-set mirrors the one in `field.rs` and
// `scalar.rs` for consistency across the eddsa crate.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::similar_names,
    clippy::return_self_not_must_use,
    clippy::many_single_char_names
)]

use crate::field::FieldElement;
use crate::scalar::Scalar;

/// `2 · d (mod p)`, where `d = -121665 · 121666⁻¹ (mod p)` is the
/// edwards25519 curve coefficient.
///
/// Used by the addition formula (see [`EdwardsPoint::add`]).
/// Five-limb radix-2⁵¹ encoding cross-checked against the byte
/// value in [`tests::d2_matches_python`].
const D2: FieldElement = FieldElement([
    0x0006_9b94_26b2_f159,
    0x0003_5050_762a_dd7a,
    0x0003_cf44_c003_8052,
    0x0006_738c_c740_7977,
    0x0002_406d_9dc5_6dff,
]);

/// The edwards25519 curve coefficient
/// `d = -121665 · 121666⁻¹ (mod p)`.
///
/// Used by the RFC 8032 §5.1.3 point decompression routine to recover
/// the x-coordinate from a compressed y-coordinate. Five-limb
/// radix-2⁵¹ encoding cross-checked in [`tests::d_matches_python`].
const D: FieldElement = FieldElement([
    0x0003_4dca_1359_78a3,
    0x0001_a828_3b15_6ebd,
    0x0005_e7a2_6001_c029,
    0x0007_39c6_63a0_3cbb,
    0x0005_2036_cee2_b6ff,
]);

/// The Ed25519 base point `B`, projected into extended
/// twisted-Edwards coordinates `(X : Y : Z : T)` with `Z = 1` and
/// `T = X · Y`.
///
/// Affine coordinates (from RFC 8032 §5.1):
///
/// ```text
/// Bx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
/// By = 4 / 5 (mod p) = 0x6666…58
/// ```
const BASE_X_LIMBS: [u64; 5] = [
    0x0006_2d60_8f25_d51a,
    0x0004_12a4_b4f6_592a,
    0x0007_5b71_71a4_b31d,
    0x0001_ff60_5271_18fe,
    0x0002_1693_6d3c_d6e5,
];
const BASE_Y_LIMBS: [u64; 5] = [
    0x0006_6666_6666_6658,
    0x0004_cccc_cccc_cccc,
    0x0001_9999_9999_9999,
    0x0003_3333_3333_3333,
    0x0006_6666_6666_6666,
];
const BASE_T_LIMBS: [u64; 5] = [
    0x0006_8ab3_a5b7_dda3,
    0x0000_0eea_2a5e_adbb,
    0x0002_af8d_f483_c27e,
    0x0003_32b3_7527_4732,
    0x0006_7875_f0fd_78b7,
];

/// A point on edwards25519 in extended twisted-Edwards coordinates.
///
/// Two representations `(X₁ : Y₁ : Z₁ : T₁)` and `(X₂ : Y₂ : Z₂ : T₂)`
/// denote the same affine point iff `X₁ · Z₂ == X₂ · Z₁` and
/// `Y₁ · Z₂ == Y₂ · Z₁`. See [`EdwardsPoint::ct_eq`] for a
/// constant-time equality test that performs exactly those two
/// cross-multiplications.
#[derive(Copy, Clone, Debug)]
pub struct EdwardsPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl EdwardsPoint {
    /// The neutral element `(0 : 1 : 1 : 0)`, which corresponds to
    /// the affine point `(0, 1)` — the identity of the edwards25519
    /// group.
    pub const IDENTITY: EdwardsPoint = EdwardsPoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// The Ed25519 base point `B`.
    pub const BASE: EdwardsPoint = EdwardsPoint {
        x: FieldElement(BASE_X_LIMBS),
        y: FieldElement(BASE_Y_LIMBS),
        z: FieldElement::ONE,
        t: FieldElement(BASE_T_LIMBS),
    };

    /// Projective point equality.
    ///
    /// Returns `1` if `self` and `other` represent the same affine
    /// point, `0` otherwise.
    pub fn ct_eq(&self, other: &EdwardsPoint) -> u8 {
        // (X1*Z2 == X2*Z1) AND (Y1*Z2 == Y2*Z1)
        let xz = self.x * other.z;
        let xzp = other.x * self.z;
        let yz = self.y * other.z;
        let yzp = other.y * self.z;
        xz.ct_eq(&xzp) & yz.ct_eq(&yzp)
    }

    /// Point addition on edwards25519 in extended twisted-Edwards
    /// coordinates.
    ///
    /// Implements formula (3.1) from Hisil et al. — the "unified"
    /// complete addition law that requires nine field multiplications
    /// and no inversions. The formula works uniformly for all pairs
    /// of input points, including doublings and the identity, so no
    /// branching on input structure is needed and the operation is
    /// fully constant time.
    ///
    /// ```text
    /// A = (Y1 - X1) · (Y2 - X2)
    /// B = (Y1 + X1) · (Y2 + X2)
    /// C = T1 · 2d · T2
    /// D = 2 · Z1 · Z2
    /// E = B - A
    /// F = D - C
    /// G = D + C
    /// H = B + A
    /// X3 = E · F,  Y3 = G · H,  T3 = E · H,  Z3 = F · G
    /// ```
    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = self.t * D2 * other.t;
        let d = (self.z * other.z) + (self.z * other.z); // 2·Z1·Z2
        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        EdwardsPoint {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// Constant-time conditional select on every coordinate.
    ///
    /// Returns `a` when `choice == 0` and `b` when `choice == 1`.
    /// Delegates to [`FieldElement::conditional_select`] per limb,
    /// so the running time is independent of both `choice` and the
    /// coordinate values.
    pub fn conditional_select(a: &EdwardsPoint, b: &EdwardsPoint, choice: u8) -> EdwardsPoint {
        EdwardsPoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
            t: FieldElement::conditional_select(&a.t, &b.t, choice),
        }
    }

    /// Variable-base scalar multiplication: `[k] · self`.
    ///
    /// Implemented as a constant-time MSB-first double-and-add
    /// (Montgomery-ladder–equivalent for Edwards points): for every
    /// bit of the 256-bit scalar `k`, the accumulator is doubled and
    /// then conditionally updated to `Q + self` if the bit is 1.
    /// The conditional is a branchless per-coordinate select so the
    /// control flow and memory access pattern are independent of the
    /// scalar value.
    ///
    /// Note: this ladder runs 256 doublings and 256 point additions
    /// unconditionally, which is ample for Ed25519 sign / verify and
    /// keeps the implementation simple and auditable. A windowed or
    /// fixed-base comb can be layered on later if performance needs
    /// it.
    pub fn mul(&self, scalar: &Scalar) -> EdwardsPoint {
        let mut q = EdwardsPoint::IDENTITY;
        for i in (0..256).rev() {
            q = q.double();
            let t = q.add(self);
            q = EdwardsPoint::conditional_select(&q, &t, scalar.bit(i));
        }
        q
    }

    /// Point doubling on edwards25519.
    ///
    /// Uses the dedicated doubling formula from Hisil et al.
    /// (section 3.3), which is faster than the general addition law
    /// because it exploits the fact that both inputs are the same
    /// point and so avoids one multiplication by `2d`. Constant time.
    ///
    /// ```text
    /// A = X1²,  B = Y1²,  C = 2 · Z1²
    /// H = A + B
    /// E = H - (X1 + Y1)²
    /// G = A - B
    /// F = C + G
    /// X3 = E · F,  Y3 = G · H,  T3 = E · H,  Z3 = F · G
    /// ```
    pub fn double(&self) -> EdwardsPoint {
        let a = self.x.square();
        let b = self.y.square();
        let z_sq = self.z.square();
        let c = z_sq + z_sq; // 2·Z1²
        let h = a + b;
        let xy = self.x + self.y;
        let e = h - xy.square();
        let g = a - b;
        let f = c + g;
        EdwardsPoint {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// Compress a point to 32 bytes per RFC 8032 §5.1.2.
    ///
    /// Converts from extended `(X : Y : Z : T)` coordinates to affine
    /// `(x, y)` by multiplying by `Z⁻¹`, encodes the y-coordinate as 32
    /// little-endian bytes, and overwrites the most significant bit of
    /// the last byte with the least significant bit of the canonical
    /// x-coordinate (the "sign" bit).
    pub fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;
        let mut out = y.to_bytes();
        // Fold x's parity into the high bit of the last byte.
        out[31] |= x.is_negative() << 7;
        out
    }

    /// Decompress 32 bytes back to a curve point per RFC 8032 §5.1.3.
    ///
    /// Returns `None` if the bytes do not encode a valid point. The
    /// checks performed, in order, are:
    ///
    ///   1. The y-coordinate is strictly less than `p` (non-canonical
    ///      encodings are rejected, matching RFC 8032's requirement
    ///      that decoding fails when the decoded integer is ≥ p).
    ///   2. The equation `x² = (y² − 1) / (d·y² + 1)` has a solution
    ///      in GF(p). The candidate square root is computed as
    ///      `(u·v³) · (u·v⁷)^((p−5)/8)`; if squaring gives `u` we
    ///      take it directly, if it gives `−u` we multiply by
    ///      `√(−1)`, otherwise the point is invalid.
    ///   3. If the recovered `x` is zero and the encoded sign bit is
    ///      1, decoding fails (there is no signed variant of zero).
    ///   4. Otherwise, the recovered `x` is negated when its parity
    ///      disagrees with the encoded sign bit.
    ///
    /// The returned point is in extended coordinates with `Z = 1` and
    /// `T = x · y`. This routine is **not** constant time with respect
    /// to the validity of its input — invalid encodings are rejected
    /// via early returns.
    pub fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        // Split off the sign bit and mask it out of the y bytes.
        let sign_bit = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;

        // Load y and reject non-canonical encodings: the value must be
        // strictly less than p, i.e. the 255-bit integer represented
        // by y_bytes must round-trip through the canonical encoder.
        let y = FieldElement::from_bytes(&y_bytes);
        if y.to_bytes() != y_bytes {
            return None;
        }

        // u = y² − 1, v = d·y² + 1.
        let y_sq = y.square();
        let u = y_sq - FieldElement::ONE;
        let v = D * y_sq + FieldElement::ONE;

        // Candidate x = (u · v³) · (u · v⁷)^((p−5)/8).
        let v3 = v.square() * v;
        let v7 = v3.square() * v;
        let uv7 = u * v7;
        let x_cand = u * v3 * uv7.pow_p_5_8();

        // Check v · x² against ±u.
        let vx2 = v * x_cand.square();
        let correct_sign = vx2.ct_eq(&u);
        let flipped_sign = vx2.ct_eq(&(-u));

        let x_flipped = x_cand * FieldElement::SQRT_M1;
        let mut x = FieldElement::conditional_select(&x_cand, &x_flipped, flipped_sign);

        if correct_sign == 0 && flipped_sign == 0 {
            // Neither root works; no square root exists.
            return None;
        }

        // If x == 0 and sign bit is 1, the point is invalid.
        if x.is_zero() == 1 && sign_bit == 1 {
            return None;
        }

        // Force x's parity to match the encoded sign bit.
        let needs_neg = u8::from(x.is_negative() != sign_bit);
        let neg_x = -x;
        x = FieldElement::conditional_select(&x, &neg_x, needs_neg);

        let t = x * y;
        Some(EdwardsPoint {
            x,
            y,
            z: FieldElement::ONE,
            t,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // D2 cross-check against the Python-computed byte value.
    // ---------------------------------------------------------------
    //
    // Python:
    //
    //   p  = 2**255 - 19
    //   d  = (-121665 * pow(121666, -1, p)) % p
    //   d2 = (2*d) % p
    //
    // and then the little-endian 32-byte encoding.
    const D2_BYTES: [u8; 32] = [
        0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0,
        0x00, 0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9,
        0x06, 0x24,
    ];
    // Base point byte encodings from RFC 8032 §5.1.
    const BASE_X_BYTES: [u8; 32] = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c,
        0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36,
        0x69, 0x21,
    ];
    const BASE_Y_BYTES: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    #[test]
    fn d2_matches_python() {
        assert_eq!(D2.to_bytes(), D2_BYTES);
    }

    #[test]
    fn base_point_coordinates_match_rfc_8032() {
        assert_eq!(EdwardsPoint::BASE.x.to_bytes(), BASE_X_BYTES);
        assert_eq!(EdwardsPoint::BASE.y.to_bytes(), BASE_Y_BYTES);
    }

    #[test]
    fn base_point_satisfies_curve_equation() {
        // -x² + y² = 1 + d · x² · y²
        // Compute D from D2/2: use D = (D2 + p)/2... simpler path:
        // check -x² + y² - 1 - d·x²·y² == 0 using D2 and halving
        // the right-hand side by multiplying both sides by 2:
        // -2·x² + 2·y² - 2 - 2d·x²·y² == 0.
        let x = EdwardsPoint::BASE.x;
        let y = EdwardsPoint::BASE.y;
        let two_xsq = x.square() + x.square();
        let two_ysq = y.square() + y.square();
        let two_one = FieldElement::ONE + FieldElement::ONE;
        let xsq_ysq = x.square() * y.square();
        let lhs = two_ysq - two_xsq;
        let rhs = two_one + D2 * xsq_ysq;
        assert_eq!(lhs.ct_eq(&rhs), 1);
    }

    #[test]
    fn add_identity_is_noop() {
        let p = EdwardsPoint::BASE;
        let s = p.add(&EdwardsPoint::IDENTITY);
        assert_eq!(p.ct_eq(&s), 1);
        let s2 = EdwardsPoint::IDENTITY.add(&p);
        assert_eq!(p.ct_eq(&s2), 1);
    }

    #[test]
    fn double_identity_is_identity() {
        let d = EdwardsPoint::IDENTITY.double();
        assert_eq!(d.ct_eq(&EdwardsPoint::IDENTITY), 1);
    }

    #[test]
    fn add_self_equals_double() {
        let b = EdwardsPoint::BASE;
        let sum = b.add(&b);
        let dbl = b.double();
        assert_eq!(sum.ct_eq(&dbl), 1);
    }

    // Convert an extended-coordinate point to affine bytes for
    // comparison against Python-computed fixtures.
    fn affine_bytes(p: &EdwardsPoint) -> ([u8; 32], [u8; 32]) {
        let z_inv = p.z.invert();
        let x = p.x * z_inv;
        let y = p.y * z_inv;
        (x.to_bytes(), y.to_bytes())
    }

    fn scalar_from_u64(k: u64) -> Scalar {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&k.to_le_bytes());
        Scalar::from_bytes(&b)
    }

    #[test]
    fn scalar_mul_zero_is_identity() {
        let q = EdwardsPoint::BASE.mul(&Scalar::ZERO);
        assert_eq!(q.ct_eq(&EdwardsPoint::IDENTITY), 1);
    }

    #[test]
    fn scalar_mul_one_is_input() {
        let q = EdwardsPoint::BASE.mul(&Scalar::ONE);
        assert_eq!(q.ct_eq(&EdwardsPoint::BASE), 1);
    }

    #[test]
    fn scalar_mul_two_equals_double() {
        let q = EdwardsPoint::BASE.mul(&scalar_from_u64(2));
        assert_eq!(q.ct_eq(&EdwardsPoint::BASE.double()), 1);
    }

    #[test]
    fn scalar_mul_small_multiples_match_python() {
        // Affine (x, y) of k·B for k ∈ {3, 5, 8, 16}, computed in
        // Python with the pure affine add-and-double reference.
        let cases: [(u64, [u8; 32], [u8; 32]); 4] = [
            (
                3,
                [
                    92, 226, 248, 211, 95, 72, 98, 172, 134, 72, 98, 129, 25, 152, 67, 99, 58, 200,
                    218, 62, 116, 174, 244, 31, 73, 143, 146, 34, 74, 156, 174, 103,
                ],
                [
                    212, 180, 245, 120, 72, 104, 195, 2, 4, 3, 36, 103, 23, 236, 22, 159, 247, 158,
                    38, 96, 142, 161, 38, 161, 171, 105, 238, 119, 209, 177, 103, 18,
                ],
            ),
            (
                5,
                [
                    51, 242, 46, 50, 192, 156, 64, 145, 165, 225, 27, 62, 249, 25, 40, 92, 222,
                    165, 45, 209, 247, 124, 239, 252, 123, 88, 227, 173, 62, 167, 253, 73,
                ],
                [
                    237, 200, 118, 214, 131, 31, 210, 16, 93, 11, 67, 137, 202, 46, 40, 49, 102,
                    70, 146, 137, 20, 110, 44, 224, 111, 174, 254, 152, 178, 37, 72, 95,
                ],
            ),
            (
                8,
                [
                    200, 132, 165, 8, 188, 253, 135, 59, 153, 139, 105, 128, 123, 198, 58, 235,
                    147, 207, 78, 248, 92, 45, 134, 66, 182, 113, 215, 151, 95, 225, 66, 103,
                ],
                [
                    180, 185, 55, 252, 169, 91, 47, 30, 147, 228, 30, 98, 252, 60, 120, 129, 143,
                    243, 138, 102, 9, 111, 173, 110, 121, 115, 229, 201, 0, 6, 211, 33,
                ],
            ),
            (
                16,
                [
                    248, 249, 40, 108, 109, 89, 178, 89, 116, 35, 191, 231, 51, 141, 87, 9, 145,
                    156, 36, 8, 21, 43, 226, 184, 238, 58, 229, 39, 6, 134, 164, 35,
                ],
                [
                    235, 39, 103, 193, 55, 171, 122, 216, 39, 156, 7, 142, 255, 17, 106, 176, 120,
                    110, 173, 58, 46, 15, 152, 159, 114, 195, 127, 130, 242, 150, 150, 112,
                ],
            ),
        ];
        for (k, xx, yy) in cases {
            let q = EdwardsPoint::BASE.mul(&scalar_from_u64(k));
            let (x, y) = affine_bytes(&q);
            assert_eq!(x, xx, "k = {k}");
            assert_eq!(y, yy, "k = {k}");
        }
    }

    #[test]
    fn scalar_mul_by_group_order_is_identity() {
        // [L]·B == O, since B has prime order L.
        let l = Scalar::from_bytes(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);
        let q = EdwardsPoint::BASE.mul(&l);
        assert_eq!(q.ct_eq(&EdwardsPoint::IDENTITY), 1);
    }

    #[test]
    fn double_base_matches_known_2b() {
        // 2·B, precomputed in Python with the pure-Python reference
        // point addition on edwards25519:
        //
        //   p = 2**255 - 19
        //   d = (-121665 * pow(121666, -1, p)) % p
        //   def add(P, Q):
        //       x1,y1 = P; x2,y2 = Q
        //       t = d*x1*x2*y1*y2 % p
        //       x3 = (x1*y2 + x2*y1) * pow(1 + t, -1, p) % p
        //       y3 = (y1*y2 + x1*x2) * pow(1 - t, -1, p) % p
        //       return (x3, y3)
        //   Bx,By = ...
        //   (x2, y2) = add((Bx,By),(Bx,By))
        //
        // gives the canonical 32-byte encodings below.
        const TWO_B_X: [u8; 32] = [
            14, 206, 67, 40, 78, 161, 197, 131, 95, 164, 215, 21, 69, 142, 13, 8, 172, 231, 51, 24,
            125, 59, 4, 61, 108, 4, 90, 159, 76, 56, 171, 54,
        ];
        const TWO_B_Y: [u8; 32] = [
            201, 163, 248, 106, 174, 70, 95, 14, 86, 81, 56, 100, 81, 15, 57, 151, 86, 31, 162,
            201, 232, 94, 162, 29, 194, 41, 35, 9, 243, 205, 96, 34,
        ];
        let two_b = EdwardsPoint::BASE.double();
        // Normalize: (x/z, y/z)
        let z_inv = two_b.z.invert();
        let x_aff = two_b.x * z_inv;
        let y_aff = two_b.y * z_inv;
        assert_eq!(x_aff.to_bytes(), TWO_B_X);
        assert_eq!(y_aff.to_bytes(), TWO_B_Y);
    }

    #[test]
    fn d_matches_python() {
        // Python: d = (-121665 * pow(121666, -1, p)) % p
        // little-endian 32-byte encoding:
        const D_BYTES: [u8; 32] = [
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52,
        ];
        assert_eq!(D.to_bytes(), D_BYTES);
    }

    #[test]
    fn compress_base_point() {
        // B has x-coordinate with LSB 0 (Bx[0] == 0x1a), so the
        // compressed encoding is just the little-endian encoding of
        // y = 4/5 with the high bit of the last byte cleared — which
        // is exactly BASE_Y_BYTES because 0x66 already has high bit 0.
        assert_eq!(EdwardsPoint::BASE.compress(), BASE_Y_BYTES);
    }

    #[test]
    fn compress_identity() {
        // Identity is (0, 1). y=1 encodes to 0x01 in byte 0, and
        // x=0 has LSB 0 so the high bit of byte 31 stays 0.
        let expected = {
            let mut e = [0u8; 32];
            e[0] = 1;
            e
        };
        assert_eq!(EdwardsPoint::IDENTITY.compress(), expected);
    }

    #[test]
    fn decompress_base_point_round_trip() {
        let compressed = EdwardsPoint::BASE.compress();
        let recovered =
            EdwardsPoint::decompress(&compressed).expect("base point should decompress");
        assert_eq!(recovered.ct_eq(&EdwardsPoint::BASE), 1);
    }

    #[test]
    fn decompress_identity_round_trip() {
        let compressed = EdwardsPoint::IDENTITY.compress();
        let recovered = EdwardsPoint::decompress(&compressed).expect("identity should decompress");
        assert_eq!(recovered.ct_eq(&EdwardsPoint::IDENTITY), 1);
    }

    #[test]
    fn compress_decompress_round_trip_multiples_of_base() {
        // Walk a handful of multiples of B through compress/decompress
        // and confirm we recover the same point.
        let mut p = EdwardsPoint::IDENTITY;
        for i in 0..16 {
            let bytes = p.compress();
            let Some(q) = EdwardsPoint::decompress(&bytes) else {
                panic!("iteration {i} failed: bytes={bytes:02x?}")
            };
            assert_eq!(q.ct_eq(&p), 1, "iteration {i} decoded wrong point");
            p = p.add(&EdwardsPoint::BASE);
        }
    }

    #[test]
    fn decompress_rejects_noncanonical_y() {
        // y = p is not canonical: from_bytes masks the high bit so y
        // decodes as 0 < p, but the round-trip check in decompress
        // sees the original bytes differ from the canonical encoding
        // of 0 and rejects them. Use y = p exactly.
        let mut y_p: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        // Ensure the sign bit is clear (it already is, 0x7f).
        y_p[31] &= 0x7f;
        assert!(EdwardsPoint::decompress(&y_p).is_none());
    }

    #[test]
    fn decompress_rejects_non_square() {
        // Choose y = 2. Then u = y²−1 = 3, v = d·y²+1 = 4d+1. u/v is
        // not a quadratic residue mod p (verified in Python below), so
        // decompression must fail:
        //
        //   p = 2**255 - 19
        //   d = (-121665 * pow(121666, -1, p)) % p
        //   u = (2*2 - 1) % p
        //   v = (d*4 + 1) % p
        //   legendre = pow(u * pow(v, -1, p), (p-1)//2, p)
        //   # legendre == p - 1, i.e. -1: non-square
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert!(EdwardsPoint::decompress(&bytes).is_none());
    }
}
