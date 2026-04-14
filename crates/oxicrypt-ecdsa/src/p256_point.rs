//! Points on NIST P-256 in Jacobian coordinates.
//!
//! P-256 is the short-Weierstrass curve
//!
//! ```text
//! y^2 = x^3 + a·x + b   (mod p)
//! ```
//!
//! with `a = -3 mod p` and `b` the 256-bit constant from SP 800-186.
//! We use the `a = -3` optimized addition / doubling formulas from
//! the EFD.
//!
//! A point is stored as three [`Fp`] coordinates `(X, Y, Z)`. The
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

use crate::p256_field::Fp;
use crate::p256_scalar::Scalar;

/// The curve constant `b` for P-256, big-endian SEC1 encoding. Pinned
/// from SP 800-186. Used by [`Point::is_on_curve_affine`] and
/// [`Point::from_sec1_uncompressed_validated`] to enforce membership
/// in the curve group during SP 800-56Ar3 public-key validation.
pub(crate) const B_BYTES: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// Generator `G.x` for P-256, big-endian SEC1 encoding.
const G_X_BYTES: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];

/// Generator `G.y` for P-256, big-endian SEC1 encoding.
const G_Y_BYTES: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// A point on P-256 in Jacobian coordinates.
#[derive(Copy, Clone, Debug)]
pub struct Point {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

impl Point {
    /// The point at infinity. `Z = 0` is the standard Jacobian
    /// encoding; we set `X = Y = 1` so that `is_identity` doesn't
    /// accidentally depend on the value of `X` / `Y`.
    pub const fn identity() -> Point {
        Point {
            x: Fp::ONE,
            y: Fp::ONE,
            z: Fp::ZERO,
        }
    }

    /// Construct the generator `G`. Rebuilt at call time from the
    /// SEC1 byte constants so the representation (Montgomery form)
    /// is consistent with `Fp::from_bytes`. The `from_bytes`
    /// decodes are infallible because `G_X_BYTES` and `G_Y_BYTES`
    /// are compile-time constants known to be less than `p`; the
    /// fallback to `Fp::ZERO` on `None` preserves clippy's
    /// no-`expect` stance without affecting correctness.
    pub fn generator() -> Point {
        let x = Fp::from_bytes(&G_X_BYTES).unwrap_or(Fp::ZERO);
        let y = Fp::from_bytes(&G_Y_BYTES).unwrap_or(Fp::ZERO);
        Point { x, y, z: Fp::ONE }
    }

    /// Constant-time test for the point at infinity. Returns `1` if
    /// `self` is the identity, `0` otherwise.
    pub fn is_identity(&self) -> u8 {
        self.z.is_zero()
    }

    /// Convert to affine coordinates `(x, y)` via a single field
    /// inversion. Returns `None` if `self` is the identity.
    ///
    /// Note: the inversion here uses [`Fp::invert`], which is
    /// constant time in the coordinate being inverted. The early
    /// return on the identity makes this routine **not** constant
    /// time with respect to whether the input is the point at
    /// infinity — callers that must keep that fact secret should
    /// branch on `is_identity` themselves.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        if self.is_identity() == 1 {
            return None;
        }
        let zinv = self.z.invert();
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        Some((self.x.mul(&zinv2), self.y.mul(&zinv3)))
    }

    /// Jacobian doubling with the `a = -3` optimization (EFD
    /// `dbl-2001-b`). Handles the identity correctly: doubling the
    /// identity returns the identity because every output is
    /// multiplied by `Z` (which is zero).
    pub fn double(&self) -> Point {
        //   delta = Z^2
        //   gamma = Y^2
        //   beta  = X * gamma
        //   alpha = 3 * (X - delta) * (X + delta)
        //   X3 = alpha^2 - 8*beta
        //   Z3 = (Y + Z)^2 - gamma - delta
        //   Y3 = alpha * (4*beta - X3) - 8*gamma^2
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);

        let t0 = self.x.sub(&delta);
        let t1 = self.x.add(&delta);
        let t2 = t0.mul(&t1);
        let alpha = t2.add(&t2).add(&t2); // 3 * t2

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

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Jacobian mixed addition `self + other` where `other` is in
    /// affine form (`Z2 = 1`). Uses the EFD `madd-2007-bl` formulas
    /// but with explicit fallbacks to `double` and `identity` in the
    /// degenerate cases (equal points, negation, operands that are
    /// themselves the identity).
    ///
    /// This routine is **not** constant time in the identity /
    /// equality branches. Our scalar multiplication never takes
    /// those branches on secret data: the ladder is initialized with
    /// the identity and always calls `add_mixed(G, ...)` where `G` is
    /// public, so the only branch dependence is on curve structure
    /// and the fixed-iteration loop bound.
    pub fn add_mixed(&self, other_x: &Fp, other_y: &Fp) -> Point {
        // Short-circuit on identities.
        if self.is_identity() == 1 {
            return Point {
                x: *other_x,
                y: *other_y,
                z: Fp::ONE,
            };
        }

        //   Z1Z1 = Z1^2
        //   U2   = X2 * Z1Z1
        //   S2   = Y2 * Z1 * Z1Z1
        //   H    = U2 - X1
        //   HH   = H^2
        //   I    = 4 * HH
        //   J    = H * I
        //   r    = 2 * (S2 - Y1)
        //   V    = X1 * I
        //   X3 = r^2 - J - 2*V
        //   Y3 = r*(V - X3) - 2*Y1*J
        //   Z3 = (Z1 + H)^2 - Z1Z1 - HH
        let z1z1 = self.z.square();
        let u2 = other_x.mul(&z1z1);
        let s2 = other_y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let r_raw = s2.sub(&self.y);

        // Exceptional cases: H == 0 means U2 == X1 (same affine x).
        // If r_raw is also zero, we're adding the point to itself →
        // double. Otherwise, we're adding the point to its negation →
        // identity.
        if h.is_zero() == 1 {
            if r_raw.is_zero() == 1 {
                return self.double();
            }
            return Point::identity();
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

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Jacobian mixed addition specialised for the scalar-mul ladder:
    /// always computes the full "normal" EFD `madd-2007-bl` formula
    /// with no early returns, and CT-selects against the degenerate
    /// `self == identity` result at the end.
    ///
    /// This exists because [`Point::add_mixed`] short-circuits with
    /// `if self.is_identity() == 1 { return ... }` on the identity —
    /// for external callers that's fine, but inside the ladder the
    /// accumulator *is* the identity for every iteration before the
    /// first set bit of the scalar, so the short-circuit makes the
    /// per-iteration cycle count depend on the number of leading
    /// zero bits. dudect catches that as a multi-sigma leak on
    /// `Point::mul` and therefore on `ecdh_p256_cdh`.
    ///
    /// The equal-points / point-plus-negation exceptional cases that
    /// [`add_mixed`](Self::add_mixed) handles with `h.is_zero()` are
    /// **not** handled here. In the ladder they can only fire if the
    /// running accumulator equals `±self`, which for a 256-bit scalar
    /// happens with probability ≈ `256 · 2⁻²⁵⁶` — not an
    /// observable timing artifact and not a correctness concern for
    /// the secret-scalar use cases (ECDSA sign, ECDH CDH). Callers
    /// that need those paths should use [`Point::add_mixed`].
    fn add_mixed_ct(&self, other_x: &Fp, other_y: &Fp) -> Point {
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

        let normal = Point {
            x: x3,
            y: y3,
            z: z3,
        };
        // "if self was the identity, the result is just (other, 1)".
        let other_as_jac = Point {
            x: *other_x,
            y: *other_y,
            z: Fp::ONE,
        };
        Point::conditional_select(&normal, &other_as_jac, self.is_identity())
    }

    /// Constant-time scalar multiplication `[k] self` using the
    /// left-to-right binary ladder with masked add.
    ///
    /// Each iteration does a double, then computes
    /// `candidate = current + self_affine`, and conditionally
    /// replaces `current` with `candidate` based on the scalar bit.
    /// Both the add and the select are performed unconditionally so
    /// the timing is independent of the scalar. The mixed-add uses
    /// the dedicated `add_mixed_ct` helper that does **not**
    /// short-circuit on the identity accumulator; that short-circuit
    /// used to make the per-iteration cycle count depend on the
    /// number of leading zero bits of the scalar, which dudect (see
    /// `tools/ct-validation` and §12.1) picked up as a multi-sigma
    /// leak on `ecdsa_p256_scalar_mul` and `ecdh_p256_cdh`.
    ///
    /// The input point is converted to affine once up front — that
    /// inversion depends on `self.z`, which is a public curve
    /// parameter for the generator case (`z = 1`). For ECDH `d · Q`
    /// it depends on the peer's public key `Q`, which is also public
    /// by definition.
    pub fn mul(&self, k: &Scalar) -> Point {
        // Precompute `self` in affine form so the inner loop uses
        // mixed addition.
        let Some((ax, ay)) = self.to_affine() else {
            return Point::identity();
        };

        // Read scalar in canonical (non-Montgomery) form, big-endian.
        let k_bytes = k.to_bytes();

        let mut acc = Point::identity();
        for byte in k_bytes {
            for bit_idx in (0..8).rev() {
                acc = acc.double();
                let bit = (byte >> bit_idx) & 1;
                let candidate = acc.add_mixed_ct(&ax, &ay);
                acc = Point::conditional_select(&acc, &candidate, bit);
            }
        }
        acc
    }

    /// Constant-time conditional select on three coordinates. Callers
    /// must pass `choice ∈ {0, 1}`.
    #[inline]
    pub fn conditional_select(a: &Point, b: &Point, choice: u8) -> Point {
        Point {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// The P-256 curve constant `b`, decoded into an [`Fp`]. The
    /// `unwrap_or` branch is unreachable because `B_BYTES` is a pinned
    /// constant strictly less than `p`; the fallback keeps this callable
    /// from a `const`-free context without `expect`.
    fn b_constant() -> Fp {
        Fp::from_bytes(&B_BYTES).unwrap_or(Fp::ZERO)
    }

    /// Constant-time on-curve check for an affine point `(x, y)`.
    /// Returns `1` iff `y^2 ≡ x^3 - 3·x + b (mod p)`, `0` otherwise.
    ///
    /// Independent of any secret scalar, this routine is intended for
    /// public-key validation per SP 800-56Ar3 §5.6.2.3.3 step 3, where
    /// the inputs are peer-supplied and therefore already public.
    pub fn is_on_curve_affine(x: &Fp, y: &Fp) -> u8 {
        // lhs = y^2
        let lhs = y.square();
        // rhs = x^3 - 3x + b = x*(x^2 - 3) + b
        let x2 = x.square();
        let three = Fp::ONE.add(&Fp::ONE).add(&Fp::ONE);
        let x2_minus_3 = x2.sub(&three);
        let x_cubed_minus_3x = x.mul(&x2_minus_3);
        let rhs = x_cubed_minus_3x.add(&Self::b_constant());
        lhs.ct_eq(&rhs)
    }

    /// Decode an uncompressed SEC1 public key `0x04 || X || Y` and
    /// perform SP 800-56Ar3 §5.6.2.3.3 "full" public-key validation:
    ///
    ///   1. Check that `Q != O` (the identity — enforced by rejecting
    ///      an all-zero encoding once both coordinates are parsed).
    ///   2. Check that `x_Q, y_Q ∈ [0, p-1]` (enforced by
    ///      [`Fp::from_bytes`], which rejects non-canonical encodings).
    ///   3. Check that `y^2 ≡ x^3 - 3·x + b (mod p)`.
    ///
    /// Step 4 ("`n·Q = O`") is vacuous for P-256 because its cofactor
    /// is 1 and the curve order `n` equals the group order.
    ///
    /// Returns the decoded [`Point`] in Jacobian coordinates with
    /// `Z = 1`, or `None` on any validation failure.
    pub fn from_sec1_uncompressed_validated(pk_bytes: &[u8; 65]) -> Option<Point> {
        if pk_bytes[0] != 0x04 {
            return None;
        }
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&pk_bytes[1..33]);
        y_bytes.copy_from_slice(&pk_bytes[33..65]);
        let x = Fp::from_bytes(&x_bytes)?;
        let y = Fp::from_bytes(&y_bytes)?;
        // Reject the encoding of the point at infinity as `(0, 0)`.
        // P-256 does not have (0, 0) on the curve so the on-curve
        // check below would also catch it, but being explicit here
        // keeps the intent obvious.
        if x.is_zero() == 1 && y.is_zero() == 1 {
            return None;
        }
        if Self::is_on_curve_affine(&x, &y) != 1 {
            return None;
        }
        Some(Point { x, y, z: Fp::ONE })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper: decode a big-endian hex-like byte array into an `Fp`.
    fn fp(bytes: [u8; 32]) -> Fp {
        Fp::from_bytes(&bytes).unwrap()
    }

    fn sc(bytes: [u8; 32]) -> Scalar {
        Scalar::from_bytes(&bytes).unwrap()
    }

    /// Small integer as a 32-byte big-endian scalar.
    fn small(k: u64) -> Scalar {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&k.to_be_bytes());
        Scalar::from_bytes(&b).unwrap()
    }

    /// Expected affine coordinates for small multiples of `G`,
    /// computed in Python via `(k * G)` on the reference curve.
    const G1_X: [u8; 32] = G_X_BYTES;
    const G1_Y: [u8; 32] = G_Y_BYTES;

    const G2_X: [u8; 32] = [
        0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
        0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66,
        0x99, 0x78,
    ];
    const G2_Y: [u8; 32] = [
        0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30,
        0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78,
        0x73, 0xd1,
    ];

    const G3_X: [u8; 32] = [
        0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a, 0x44, 0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1,
        0x65, 0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9, 0x85, 0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7,
        0xfd, 0x6c,
    ];
    const G3_Y: [u8; 32] = [
        0x87, 0x34, 0x64, 0x0c, 0x49, 0x98, 0xff, 0x7e, 0x37, 0x4b, 0x06, 0xce, 0x1a, 0x64, 0xa2,
        0xec, 0xd8, 0x2a, 0xb0, 0x36, 0x38, 0x4f, 0xb8, 0x3d, 0x9a, 0x79, 0xb1, 0x27, 0xa2, 0x7d,
        0x50, 0x32,
    ];

    const G4_X: [u8; 32] = [
        0xe2, 0x53, 0x4a, 0x35, 0x32, 0xd0, 0x8f, 0xbb, 0xa0, 0x2d, 0xde, 0x65, 0x9e, 0xe6, 0x2b,
        0xd0, 0x03, 0x1f, 0xe2, 0xdb, 0x78, 0x55, 0x96, 0xef, 0x50, 0x93, 0x02, 0x44, 0x6b, 0x03,
        0x08, 0x52,
    ];
    const G4_Y: [u8; 32] = [
        0xe0, 0xf1, 0x57, 0x5a, 0x4c, 0x63, 0x3c, 0xc7, 0x19, 0xdf, 0xee, 0x5f, 0xda, 0x86, 0x2d,
        0x76, 0x4e, 0xfc, 0x96, 0xc3, 0xf3, 0x0e, 0xe0, 0x05, 0x5c, 0x42, 0xc2, 0x3f, 0x18, 0x4e,
        0xd8, 0xc6,
    ];

    const G5_X: [u8; 32] = [
        0x51, 0x59, 0x0b, 0x7a, 0x51, 0x51, 0x40, 0xd2, 0xd7, 0x84, 0xc8, 0x56, 0x08, 0x66, 0x8f,
        0xdf, 0xef, 0x8c, 0x82, 0xfd, 0x1f, 0x5b, 0xe5, 0x24, 0x21, 0x55, 0x4a, 0x0d, 0xc3, 0xd0,
        0x33, 0xed,
    ];
    const G5_Y: [u8; 32] = [
        0xe0, 0xc1, 0x7d, 0xa8, 0x90, 0x4a, 0x72, 0x7d, 0x8a, 0xe1, 0xbf, 0x36, 0xbf, 0x8a, 0x79,
        0x26, 0x0d, 0x01, 0x2f, 0x00, 0xd4, 0xd8, 0x08, 0x88, 0xd1, 0xd0, 0xbb, 0x44, 0xfd, 0xa1,
        0x6d, 0xa4,
    ];

    const G10_X: [u8; 32] = [
        0xce, 0xf6, 0x6d, 0x6b, 0x2a, 0x3a, 0x99, 0x3e, 0x59, 0x12, 0x14, 0xd1, 0xea, 0x22, 0x3f,
        0xb5, 0x45, 0xca, 0x6c, 0x47, 0x1c, 0x48, 0x30, 0x6e, 0x4c, 0x36, 0x06, 0x94, 0x04, 0xc5,
        0x72, 0x3f,
    ];
    const G10_Y: [u8; 32] = [
        0x87, 0x86, 0x62, 0xa2, 0x29, 0xaa, 0xae, 0x90, 0x6e, 0x12, 0x3c, 0xdd, 0x9d, 0x3b, 0x4c,
        0x10, 0x59, 0x0d, 0xed, 0x29, 0xfe, 0x75, 0x1e, 0xee, 0xca, 0x34, 0xbb, 0xaa, 0x44, 0xaf,
        0x07, 0x73,
    ];

    fn assert_affine_eq(p: &Point, x: [u8; 32], y: [u8; 32]) {
        let (ax, ay) = p.to_affine().expect("point is not identity");
        assert_eq!(ax.to_bytes(), x);
        assert_eq!(ay.to_bytes(), y);
    }

    #[test]
    fn generator_is_on_curve_as_2g_via_double() {
        let two_g = Point::generator().double();
        assert_affine_eq(&two_g, G2_X, G2_Y);
    }

    #[test]
    fn generator_double_and_add_gives_3g() {
        let g = Point::generator();
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
        let result = Point::identity().add_mixed(&gx, &gy);
        assert_affine_eq(&result, G1_X, G1_Y);
    }

    #[test]
    fn add_mixed_point_to_its_negation_is_identity() {
        let g = Point::generator();
        // -G has x = G.x and y = -G.y.
        let gx = fp(G1_X);
        let gy_neg = fp(G1_Y).neg();
        let result = g.add_mixed(&gx, &gy_neg);
        assert_eq!(result.is_identity(), 1);
    }

    #[test]
    fn add_mixed_point_to_itself_is_double() {
        let g = Point::generator();
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
        let g = Point::generator();
        assert_eq!(g.mul(&Scalar::ZERO).is_identity(), 1);
    }

    #[test]
    fn scalar_mul_by_one_is_point() {
        let g = Point::generator();
        let one_g = g.mul(&Scalar::ONE);
        assert_affine_eq(&one_g, G1_X, G1_Y);
    }

    #[test]
    fn scalar_mul_matches_small_multiples() {
        let g = Point::generator();
        assert_affine_eq(&g.mul(&small(1)), G1_X, G1_Y);
        assert_affine_eq(&g.mul(&small(2)), G2_X, G2_Y);
        assert_affine_eq(&g.mul(&small(3)), G3_X, G3_Y);
        assert_affine_eq(&g.mul(&small(4)), G4_X, G4_Y);
        assert_affine_eq(&g.mul(&small(5)), G5_X, G5_Y);
        assert_affine_eq(&g.mul(&small(10)), G10_X, G10_Y);
    }

    #[test]
    fn on_curve_accepts_generator() {
        let gx = fp(G1_X);
        let gy = fp(G1_Y);
        assert_eq!(Point::is_on_curve_affine(&gx, &gy), 1);
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
            assert_eq!(Point::is_on_curve_affine(&x, &y), 1);
        }
    }

    #[test]
    fn on_curve_rejects_tampered_point() {
        let gx = fp(G1_X);
        let mut gy_bytes = G1_Y;
        gy_bytes[31] ^= 0x01;
        let gy = fp(gy_bytes);
        assert_eq!(Point::is_on_curve_affine(&gx, &gy), 0);
    }

    #[test]
    fn on_curve_rejects_zero_point() {
        // (0, 0) is not on the curve: 0 ≠ 0 + 0 + b.
        assert_eq!(Point::is_on_curve_affine(&Fp::ZERO, &Fp::ZERO), 0);
    }

    #[test]
    fn validated_decoder_accepts_generator() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        pk[1..33].copy_from_slice(&G1_X);
        pk[33..65].copy_from_slice(&G1_Y);
        assert!(Point::from_sec1_uncompressed_validated(&pk).is_some());
    }

    #[test]
    fn validated_decoder_rejects_off_curve() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        pk[1..33].copy_from_slice(&G1_X);
        let mut bad_y = G1_Y;
        bad_y[31] ^= 0x01;
        pk[33..65].copy_from_slice(&bad_y);
        assert!(Point::from_sec1_uncompressed_validated(&pk).is_none());
    }

    #[test]
    fn validated_decoder_rejects_wrong_header() {
        let mut pk = [0u8; 65];
        pk[0] = 0x02; // compressed — not supported
        pk[1..33].copy_from_slice(&G1_X);
        pk[33..65].copy_from_slice(&G1_Y);
        assert!(Point::from_sec1_uncompressed_validated(&pk).is_none());
    }

    #[test]
    fn validated_decoder_rejects_zero_zero() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        // x and y already zero.
        assert!(Point::from_sec1_uncompressed_validated(&pk).is_none());
    }

    #[test]
    fn validated_decoder_rejects_non_canonical_x() {
        // x = p is not canonical — Fp::from_bytes rejects it.
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        let p_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        pk[1..33].copy_from_slice(&p_bytes);
        pk[33..65].copy_from_slice(&G1_Y);
        assert!(Point::from_sec1_uncompressed_validated(&pk).is_none());
    }

    #[test]
    fn scalar_mul_by_n_minus_one_is_minus_g() {
        // (n - 1) * G = -G, which has (x, -y) in affine form.
        let n_minus_one: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x50,
        ];
        let r = Point::generator().mul(&sc(n_minus_one));
        let (ax, ay) = r.to_affine().unwrap();
        assert_eq!(ax.to_bytes(), G1_X);
        let minus_gy = fp(G1_Y).neg();
        assert_eq!(ay.to_bytes(), minus_gy.to_bytes());
    }
}
