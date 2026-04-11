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
//! This commit lands the point type, the curve constants (`d2 = 2·d`,
//! base point `B`, identity), and the complete add / double formulas.
//! Scalar multiplication, compression / decompression, and the
//! RFC 8032 sign / verify wiring arrive in follow-up commits.

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
    /// point, `0` otherwise. Constant time in both inputs.
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
}

#[cfg(test)]
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
            14, 206, 67, 40, 78, 161, 197, 131, 95, 164, 215, 21, 69, 142, 13, 8, 172, 231, 51,
            24, 125, 59, 4, 61, 108, 4, 90, 159, 76, 56, 171, 54,
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
}
