//! Points on NIST P-384 in Jacobian coordinates.
//!
//! P-384 is the short-Weierstrass curve
//!
//! ```text
//! y^2 = x^3 + a·x + b   (mod p)
//! ```
//!
//! with `a = -3 mod p` and `b` the 384-bit constant from SP 800-186.
//! We use the `a = -3` optimized addition / doubling formulas from
//! the EFD.
//!
//! A point is stored as three [`Fp384`] coordinates `(X, Y, Z)`. The
//! affine representative is `(X · Z^-2, Y · Z^-3)`. The point at
//! infinity is `Z = 0`.
//!
//! # Constant-time contract
//!
//! Every operation that depends on a secret scalar (`mul`, the inner
//! `conditional_select`) is constant time in the scalar bits. Point
//! addition is implemented with the "complete" formula only at
//! compression time; during scalar multiplication we use the
//! Montgomery-ladder-style "always add" pattern with masked selects
//! so the branch structure is independent of the scalar.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use,
    clippy::unreadable_literal,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use crate::p384_field::Fp384;
use crate::p384_scalar::Scalar384;

/// The curve constant `b` for P-384, big-endian SEC1 encoding. Pinned
/// from SP 800-186.
pub(crate) const B_BYTES: [u8; 48] = [
    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
    0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
    0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
];

/// Generator `G.x` for P-384, big-endian SEC1 encoding.
const G_X_BYTES: [u8; 48] = [
    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
    0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
    0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
];

/// Generator `G.y` for P-384, big-endian SEC1 encoding.
const G_Y_BYTES: [u8; 48] = [
    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
    0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
    0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
];

/// A point on P-384 in Jacobian coordinates.
#[derive(Copy, Clone, Debug)]
pub struct Point384 {
    pub(crate) x: Fp384,
    pub(crate) y: Fp384,
    pub(crate) z: Fp384,
}

impl Point384 {
    /// The point at infinity.
    pub const fn identity() -> Point384 {
        Point384 {
            x: Fp384::ONE,
            y: Fp384::ONE,
            z: Fp384::ZERO,
        }
    }

    /// Construct the generator `G`.
    pub fn generator() -> Point384 {
        let x = Fp384::from_bytes(&G_X_BYTES).unwrap_or(Fp384::ZERO);
        let y = Fp384::from_bytes(&G_Y_BYTES).unwrap_or(Fp384::ZERO);
        Point384 {
            x,
            y,
            z: Fp384::ONE,
        }
    }

    /// Constant-time test for the point at infinity.
    pub fn is_identity(&self) -> u8 {
        self.z.is_zero()
    }

    /// Convert to affine coordinates via a single field inversion.
    /// Returns `None` if `self` is the identity.
    pub fn to_affine(&self) -> Option<(Fp384, Fp384)> {
        if self.is_identity() == 1 {
            return None;
        }
        let zinv = self.z.invert();
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        Some((self.x.mul(&zinv2), self.y.mul(&zinv3)))
    }

    /// Jacobian doubling with the `a = -3` optimization (EFD
    /// `dbl-2001-b`).
    pub fn double(&self) -> Point384 {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);

        let t0 = self.x.sub(&delta);
        let t1 = self.x.add(&delta);
        let t2 = t0.mul(&t1);
        let alpha = t2.add(&t2).add(&t2);

        let alpha2 = alpha.square();
        let eight_beta = {
            let two = beta.add(&beta);
            let four = two.add(&two);
            four.add(&four)
        };
        let x3 = alpha2.sub(&eight_beta);

        let yz = self.y.add(&self.z);
        let yz2 = yz.square();
        let z3 = yz2.sub(&gamma).sub(&delta);

        let four_beta = {
            let two = beta.add(&beta);
            two.add(&two)
        };
        let gamma2 = gamma.square();
        let eight_gamma2 = {
            let two = gamma2.add(&gamma2);
            let four = two.add(&two);
            four.add(&four)
        };
        let y3 = alpha.mul(&four_beta.sub(&x3)).sub(&eight_gamma2);

        Point384 {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Jacobian mixed addition `self + other` where `other` is in
    /// affine form (`Z2 = 1`). Uses the EFD `madd-2007-bl` formulas
    /// with explicit fallbacks for degenerate cases.
    pub fn add_mixed(&self, other_x: &Fp384, other_y: &Fp384) -> Point384 {
        if self.is_identity() == 1 {
            return Point384 {
                x: *other_x,
                y: *other_y,
                z: Fp384::ONE,
            };
        }

        let z1z1 = self.z.square();
        let u2 = other_x.mul(&z1z1);
        let s2 = other_y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let r_raw = s2.sub(&self.y);

        if h.is_zero() == 1 {
            if r_raw.is_zero() == 1 {
                return self.double();
            }
            return Point384::identity();
        }

        let hh = h.square();
        let i = {
            let two = hh.add(&hh);
            two.add(&two)
        };
        let j = h.mul(&i);
        let r = r_raw.add(&r_raw);
        let v = self.x.mul(&i);

        let x3 = {
            let r2 = r.square();
            let two_v = v.add(&v);
            r2.sub(&j).sub(&two_v)
        };
        let y3 = {
            let v_minus_x3 = v.sub(&x3);
            let rvx = r.mul(&v_minus_x3);
            let two_y1_j = {
                let y1j = self.y.mul(&j);
                y1j.add(&y1j)
            };
            rvx.sub(&two_y1_j)
        };
        let z3 = {
            let z1_plus_h = self.z.add(&h);
            z1_plus_h.square().sub(&z1z1).sub(&hh)
        };

        Point384 {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// CT mixed addition for the scalar-mul ladder — no early returns
    /// on identity. See `p256_point::Point::add_mixed_ct` for the
    /// full rationale.
    fn add_mixed_ct(&self, other_x: &Fp384, other_y: &Fp384) -> Point384 {
        let z1z1 = self.z.square();
        let u2 = other_x.mul(&z1z1);
        let s2 = other_y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let r_raw = s2.sub(&self.y);

        let hh = h.square();
        let i = {
            let two = hh.add(&hh);
            two.add(&two)
        };
        let j = h.mul(&i);
        let r = r_raw.add(&r_raw);
        let v = self.x.mul(&i);

        let x3 = {
            let r2 = r.square();
            let two_v = v.add(&v);
            r2.sub(&j).sub(&two_v)
        };
        let y3 = {
            let v_minus_x3 = v.sub(&x3);
            let rvx = r.mul(&v_minus_x3);
            let two_y1_j = {
                let y1j = self.y.mul(&j);
                y1j.add(&y1j)
            };
            rvx.sub(&two_y1_j)
        };
        let z3 = {
            let z1_plus_h = self.z.add(&h);
            z1_plus_h.square().sub(&z1z1).sub(&hh)
        };

        let normal = Point384 {
            x: x3,
            y: y3,
            z: z3,
        };
        let other_as_jac = Point384 {
            x: *other_x,
            y: *other_y,
            z: Fp384::ONE,
        };
        Point384::conditional_select(&normal, &other_as_jac, self.is_identity())
    }

    /// Constant-time scalar multiplication `[k] self` using the
    /// left-to-right binary ladder with masked add.
    pub fn mul(&self, k: &Scalar384) -> Point384 {
        let Some((ax, ay)) = self.to_affine() else {
            return Point384::identity();
        };

        let k_bytes = k.to_bytes();

        let mut acc = Point384::identity();
        for byte in k_bytes {
            for bit_idx in (0..8).rev() {
                acc = acc.double();
                let bit = (byte >> bit_idx) & 1;
                let candidate = acc.add_mixed_ct(&ax, &ay);
                acc = Point384::conditional_select(&acc, &candidate, bit);
            }
        }
        acc
    }

    /// Constant-time conditional select on three coordinates.
    #[inline]
    pub fn conditional_select(a: &Point384, b: &Point384, choice: u8) -> Point384 {
        Point384 {
            x: Fp384::conditional_select(&a.x, &b.x, choice),
            y: Fp384::conditional_select(&a.y, &b.y, choice),
            z: Fp384::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// The P-384 curve constant `b`, decoded.
    fn b_constant() -> Fp384 {
        Fp384::from_bytes(&B_BYTES).unwrap_or(Fp384::ZERO)
    }

    /// Constant-time on-curve check for an affine point `(x, y)`.
    /// Returns `1` iff `y^2 ≡ x^3 - 3·x + b (mod p)`.
    pub fn is_on_curve_affine(x: &Fp384, y: &Fp384) -> u8 {
        let lhs = y.square();
        let x2 = x.square();
        let three = Fp384::ONE.add(&Fp384::ONE).add(&Fp384::ONE);
        let x2_minus_3 = x2.sub(&three);
        let x_cubed_minus_3x = x.mul(&x2_minus_3);
        let rhs = x_cubed_minus_3x.add(&Self::b_constant());
        lhs.ct_eq(&rhs)
    }

    /// Decode an uncompressed SEC1 public key `0x04 || X || Y` and
    /// perform SP 800-56Ar3 §5.6.2.3.3 "full" public-key validation.
    pub fn from_sec1_uncompressed_validated(pk_bytes: &[u8; 97]) -> Option<Point384> {
        if pk_bytes[0] != 0x04 {
            return None;
        }
        let mut x_bytes = [0u8; 48];
        let mut y_bytes = [0u8; 48];
        x_bytes.copy_from_slice(&pk_bytes[1..49]);
        y_bytes.copy_from_slice(&pk_bytes[49..97]);
        let x = Fp384::from_bytes(&x_bytes)?;
        let y = Fp384::from_bytes(&y_bytes)?;
        if x.is_zero() == 1 && y.is_zero() == 1 {
            return None;
        }
        if Self::is_on_curve_affine(&x, &y) != 1 {
            return None;
        }
        Some(Point384 {
            x,
            y,
            z: Fp384::ONE,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn fp(bytes: [u8; 48]) -> Fp384 {
        Fp384::from_bytes(&bytes).unwrap()
    }

    fn sc(bytes: [u8; 48]) -> Scalar384 {
        Scalar384::from_bytes(&bytes).unwrap()
    }

    fn small(k: u64) -> Scalar384 {
        let mut b = [0u8; 48];
        b[40..48].copy_from_slice(&k.to_be_bytes());
        Scalar384::from_bytes(&b).unwrap()
    }

    const G1_X: [u8; 48] = G_X_BYTES;
    const G1_Y: [u8; 48] = G_Y_BYTES;

    const G2_X: [u8; 48] = [
        0x08, 0xd9, 0x99, 0x05, 0x7b, 0xa3, 0xd2, 0xd9, 0x69, 0x26, 0x00, 0x45, 0xc5, 0x5b, 0x97,
        0xf0, 0x89, 0x02, 0x59, 0x59, 0xa6, 0xf4, 0x34, 0xd6, 0x51, 0xd2, 0x07, 0xd1, 0x9f, 0xb9,
        0x6e, 0x9e, 0x4f, 0xe0, 0xe8, 0x6e, 0xbe, 0x0e, 0x64, 0xf8, 0x5b, 0x96, 0xa9, 0xc7, 0x52,
        0x95, 0xdf, 0x61,
    ];
    const G2_Y: [u8; 48] = [
        0x8e, 0x80, 0xf1, 0xfa, 0x5b, 0x1b, 0x3c, 0xed, 0xb7, 0xbf, 0xe8, 0xdf, 0xfd, 0x6d, 0xba,
        0x74, 0xb2, 0x75, 0xd8, 0x75, 0xbc, 0x6c, 0xc4, 0x3e, 0x90, 0x4e, 0x50, 0x5f, 0x25, 0x6a,
        0xb4, 0x25, 0x5f, 0xfd, 0x43, 0xe9, 0x4d, 0x39, 0xe2, 0x2d, 0x61, 0x50, 0x1e, 0x70, 0x0a,
        0x94, 0x0e, 0x80,
    ];

    const G3_X: [u8; 48] = [
        0x07, 0x7a, 0x41, 0xd4, 0x60, 0x6f, 0xfa, 0x14, 0x64, 0x79, 0x3c, 0x7e, 0x5f, 0xdc, 0x7d,
        0x98, 0xcb, 0x9d, 0x39, 0x10, 0x20, 0x2d, 0xcd, 0x06, 0xbe, 0xa4, 0xf2, 0x40, 0xd3, 0x56,
        0x6d, 0xa6, 0xb4, 0x08, 0xbb, 0xae, 0x50, 0x26, 0x58, 0x0d, 0x02, 0xd7, 0xe5, 0xc7, 0x05,
        0x00, 0xc8, 0x31,
    ];
    const G3_Y: [u8; 48] = [
        0xc9, 0x95, 0xf7, 0xca, 0x0b, 0x0c, 0x42, 0x83, 0x7d, 0x0b, 0xbe, 0x96, 0x02, 0xa9, 0xfc,
        0x99, 0x85, 0x20, 0xb4, 0x1c, 0x85, 0x11, 0x5a, 0xa5, 0xf7, 0x68, 0x4c, 0x0e, 0xdc, 0x11,
        0x1e, 0xac, 0xc2, 0x4a, 0xbd, 0x6b, 0xe4, 0xb5, 0xd2, 0x98, 0xb6, 0x5f, 0x28, 0x60, 0x0a,
        0x2f, 0x1d, 0xf1,
    ];

    const G4_X: [u8; 48] = [
        0x13, 0x82, 0x51, 0xcd, 0x52, 0xac, 0x92, 0x98, 0xc1, 0xc8, 0xaa, 0xd9, 0x77, 0x32, 0x1d,
        0xeb, 0x97, 0xe7, 0x09, 0xbd, 0x0b, 0x4c, 0xa0, 0xac, 0xa5, 0x5d, 0xc8, 0xad, 0x51, 0xdc,
        0xfc, 0x9d, 0x15, 0x89, 0xa1, 0x59, 0x7e, 0x3a, 0x51, 0x20, 0xe1, 0xef, 0xd6, 0x31, 0xc6,
        0x3e, 0x18, 0x35,
    ];
    const G4_Y: [u8; 48] = [
        0xca, 0xca, 0xe2, 0x98, 0x69, 0xa6, 0x2e, 0x16, 0x31, 0xe8, 0xa2, 0x81, 0x81, 0xab, 0x56,
        0x61, 0x6d, 0xc4, 0x5d, 0x91, 0x8a, 0xbc, 0x09, 0xf3, 0xab, 0x0e, 0x63, 0xcf, 0x79, 0x2a,
        0xa4, 0xdc, 0xed, 0x73, 0x87, 0xbe, 0x37, 0xbb, 0xa5, 0x69, 0x54, 0x9f, 0x1c, 0x02, 0xb2,
        0x70, 0xed, 0x67,
    ];

    const G5_X: [u8; 48] = [
        0x11, 0xde, 0x24, 0xa2, 0xc2, 0x51, 0xc7, 0x77, 0x57, 0x3c, 0xac, 0x5e, 0xa0, 0x25, 0xe4,
        0x67, 0xf2, 0x08, 0xe5, 0x1d, 0xbf, 0xf9, 0x8f, 0xc5, 0x4f, 0x66, 0x61, 0xcb, 0xe5, 0x65,
        0x83, 0xb0, 0x37, 0x88, 0x2f, 0x4a, 0x1c, 0xa2, 0x97, 0xe6, 0x0a, 0xbc, 0xdb, 0xc3, 0x83,
        0x6d, 0x84, 0xbc,
    ];
    const G5_Y: [u8; 48] = [
        0x8f, 0xa6, 0x96, 0xc7, 0x74, 0x40, 0xf9, 0x2d, 0x0f, 0x58, 0x37, 0xe9, 0x0a, 0x00, 0xe7,
        0xc5, 0x28, 0x4b, 0x44, 0x77, 0x54, 0xd5, 0xde, 0xe8, 0x8c, 0x98, 0x65, 0x33, 0xb6, 0x90,
        0x1a, 0xeb, 0x31, 0x77, 0x68, 0x6d, 0x0a, 0xe8, 0xfb, 0x33, 0x18, 0x44, 0x14, 0xab, 0xe6,
        0xc1, 0x71, 0x3a,
    ];

    const G10_X: [u8; 48] = [
        0xa6, 0x69, 0xc5, 0x56, 0x3b, 0xd6, 0x7e, 0xec, 0x67, 0x8d, 0x29, 0xd6, 0xef, 0x4f, 0xde,
        0x86, 0x4f, 0x37, 0x2d, 0x90, 0xb7, 0x9b, 0x9e, 0x88, 0x93, 0x1d, 0x5c, 0x29, 0x29, 0x12,
        0x38, 0xcc, 0xed, 0x8e, 0x85, 0xab, 0x50, 0x7b, 0xf9, 0x1a, 0xa9, 0xcb, 0x2d, 0x13, 0x18,
        0x66, 0x58, 0xfb,
    ];
    const G10_Y: [u8; 48] = [
        0xa9, 0x88, 0xb7, 0x2a, 0xe7, 0xc1, 0x27, 0x9f, 0x22, 0xd9, 0x08, 0x3d, 0xb5, 0xf0, 0xec,
        0xdd, 0xf7, 0x01, 0x19, 0x55, 0x0c, 0x18, 0x3c, 0x31, 0xc5, 0x02, 0xdf, 0x78, 0xc3, 0xb7,
        0x05, 0xa8, 0x29, 0x6d, 0x81, 0x95, 0x24, 0x82, 0x88, 0xd9, 0x97, 0x78, 0x4f, 0x6a, 0xb7,
        0x3a, 0x21, 0xdd,
    ];

    fn assert_affine_eq(p: &Point384, x: [u8; 48], y: [u8; 48]) {
        let (ax, ay) = p.to_affine().expect("point is not identity");
        assert_eq!(ax.to_bytes(), x);
        assert_eq!(ay.to_bytes(), y);
    }

    #[test]
    fn generator_is_on_curve() {
        let gx = fp(G1_X);
        let gy = fp(G1_Y);
        assert_eq!(Point384::is_on_curve_affine(&gx, &gy), 1);
    }

    #[test]
    fn generator_double_gives_2g() {
        let two_g = Point384::generator().double();
        assert_affine_eq(&two_g, G2_X, G2_Y);
    }

    #[test]
    fn generator_double_and_add_gives_3g() {
        let g = Point384::generator();
        let two_g = g.double();
        let gx = fp(G1_X);
        let gy = fp(G1_Y);
        let three_g = two_g.add_mixed(&gx, &gy);
        assert_affine_eq(&three_g, G3_X, G3_Y);
    }

    #[test]
    fn identity_plus_g_is_g() {
        let gx = fp(G1_X);
        let gy = fp(G1_Y);
        let result = Point384::identity().add_mixed(&gx, &gy);
        assert_affine_eq(&result, G1_X, G1_Y);
    }

    #[test]
    fn add_mixed_point_to_its_negation_is_identity() {
        let g = Point384::generator();
        let gx = fp(G1_X);
        let gy_neg = fp(G1_Y).neg();
        let result = g.add_mixed(&gx, &gy_neg);
        assert_eq!(result.is_identity(), 1);
    }

    #[test]
    fn add_mixed_point_to_itself_is_double() {
        let g = Point384::generator();
        let gx = fp(G1_X);
        let gy = fp(G1_Y);
        let via_add = g.add_mixed(&gx, &gy);
        let via_double = g.double();
        let (ax1, ay1) = via_add.to_affine().unwrap();
        let (ax2, ay2) = via_double.to_affine().unwrap();
        assert_eq!(ax1.to_bytes(), ax2.to_bytes());
        assert_eq!(ay1.to_bytes(), ay2.to_bytes());
    }

    #[test]
    fn scalar_mul_by_zero_is_identity() {
        let g = Point384::generator();
        assert_eq!(g.mul(&Scalar384::ZERO).is_identity(), 1);
    }

    #[test]
    fn scalar_mul_by_one_is_point() {
        let g = Point384::generator();
        let one_g = g.mul(&Scalar384::ONE);
        assert_affine_eq(&one_g, G1_X, G1_Y);
    }

    #[test]
    fn scalar_mul_matches_small_multiples() {
        let g = Point384::generator();
        assert_affine_eq(&g.mul(&small(1)), G1_X, G1_Y);
        assert_affine_eq(&g.mul(&small(2)), G2_X, G2_Y);
        assert_affine_eq(&g.mul(&small(3)), G3_X, G3_Y);
        assert_affine_eq(&g.mul(&small(4)), G4_X, G4_Y);
        assert_affine_eq(&g.mul(&small(5)), G5_X, G5_Y);
        assert_affine_eq(&g.mul(&small(10)), G10_X, G10_Y);
    }

    #[test]
    fn on_curve_accepts_small_multiples() {
        for (x_bytes, y_bytes) in [
            (G2_X, G2_Y),
            (G3_X, G3_Y),
            (G4_X, G4_Y),
            (G5_X, G5_Y),
            (G10_X, G10_Y),
        ] {
            let x = fp(x_bytes);
            let y = fp(y_bytes);
            assert_eq!(Point384::is_on_curve_affine(&x, &y), 1);
        }
    }

    #[test]
    fn on_curve_rejects_tampered_point() {
        let gx = fp(G1_X);
        let mut gy_bytes = G1_Y;
        gy_bytes[47] ^= 0x01;
        let gy = fp(gy_bytes);
        assert_eq!(Point384::is_on_curve_affine(&gx, &gy), 0);
    }

    #[test]
    fn validated_decoder_accepts_generator() {
        let mut pk = [0u8; 97];
        pk[0] = 0x04;
        pk[1..49].copy_from_slice(&G1_X);
        pk[49..97].copy_from_slice(&G1_Y);
        assert!(Point384::from_sec1_uncompressed_validated(&pk).is_some());
    }

    #[test]
    fn validated_decoder_rejects_off_curve() {
        let mut pk = [0u8; 97];
        pk[0] = 0x04;
        pk[1..49].copy_from_slice(&G1_X);
        let mut bad_y = G1_Y;
        bad_y[47] ^= 0x01;
        pk[49..97].copy_from_slice(&bad_y);
        assert!(Point384::from_sec1_uncompressed_validated(&pk).is_none());
    }

    #[test]
    fn scalar_mul_by_n_minus_one_is_minus_g() {
        let n_minus_one: [u8; 48] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
            0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
            0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x72,
        ];
        let r = Point384::generator().mul(&sc(n_minus_one));
        let (ax, ay) = r.to_affine().unwrap();
        assert_eq!(ax.to_bytes(), G1_X);
        let minus_gy = fp(G1_Y).neg();
        assert_eq!(ay.to_bytes(), minus_gy.to_bytes());
    }
}
