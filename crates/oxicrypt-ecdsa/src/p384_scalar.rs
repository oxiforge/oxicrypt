//! Scalar field arithmetic for NIST P-384.
//!
//! The group order is
//!
//! ```text
//! n = 0xffffffffffffffffffffffffffffffff
//!     ffffffffffffffc7634d81f4372ddf
//!     581a0db248b0a77aecec196accc52973
//! ```
//!
//! Scalars are represented in **Montgomery form** as six little-endian
//! `u64` limbs. Constant time with respect to secret values; loop
//! bounds (limb count, bit length of `n - 2`) are public parameters.
//!
//! The structure mirrors [`crate::p384_field`] — the only differences
//! are the modulus `N`, the Montgomery multiplier `-n^(-1) mod 2^64`,
//! the precomputed `R mod n` and `R^2 mod n`, and the `n - 2` exponent
//! used by the Fermat inverse. Duplicating the arithmetic instead of
//! parameterizing it keeps the two modules independently auditable,
//! which is the stance FIPS 140-3 IG D.G effectively demands for
//! algorithm-specific constants.

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

// ------------------------------------------------------------------
// Curve constants
// ------------------------------------------------------------------

/// The P-384 group order `n`, stored as six little-endian `u64` limbs.
pub(crate) const N: [u64; 6] = [
    0xecec196accc52973,
    0x581a0db248b0a77a,
    0xc7634d81f4372ddf,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

/// `-n^(-1) mod 2^64`, the Montgomery multiplier constant.
const N_PRIME: u64 = 0x6ed46089e88fdc45;

/// `R mod n` where `R = 2^384`. The Montgomery form of the integer
/// `1`, used as the multiplicative identity.
const R_MOD_N: [u64; 6] = [
    0x1313e695333ad68d,
    0xa7e5f24db74f5885,
    0x389cb27e0bc8d220,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// `R^2 mod n` where `R = 2^384`. Used to convert an integer `a`
/// into Montgomery form: `mont_mul(a, R^2) = a · R mod n`.
const R2_MOD_N: [u64; 6] = [
    0x2d319b2419b409a9,
    0xff3d81e5df1aa419,
    0xbc3e483afcb82947,
    0xd40d49174aab1cc5,
    0x3fb05b7a28266895,
    0x0c84ee012b39bf21,
];

// ------------------------------------------------------------------
// Public type
// ------------------------------------------------------------------

/// An element of the P-384 scalar field `Z/nZ` in Montgomery form.
///
/// The internal representation is `value · R mod n` where `R = 2^384`.
/// Use [`Scalar384::from_bytes`] / [`Scalar384::to_bytes`] to move
/// between big-endian byte strings (the SEC1 scalar encoding) and
/// this type.
#[derive(Copy, Clone, Debug)]
pub struct Scalar384 {
    limbs: [u64; 6],
}

impl Scalar384 {
    /// The additive identity (`0`).
    pub const ZERO: Scalar384 = Scalar384 { limbs: [0; 6] };

    /// The multiplicative identity (`1`). Stored as `R mod n`.
    pub const ONE: Scalar384 = Scalar384 { limbs: R_MOD_N };

    /// Decode a big-endian 48-byte scalar encoding, rejecting values
    /// `>= n`.
    ///
    /// Per FIPS 186-5 §6.4 and SEC1 §2.3.8, an ECDSA scalar must be in
    /// `[1, n-1]`. This constructor only enforces the upper bound;
    /// callers that need to exclude zero (e.g. sign/verify) must do so
    /// themselves using [`Scalar384::is_zero`].
    pub fn from_bytes(bytes: &[u8; 48]) -> Option<Scalar384> {
        let mut raw = [0u64; 6];
        for i in 0..6 {
            let off = 40 - 8 * i;
            raw[i] = u64::from_be_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
        }
        // Reject raw >= n.
        let mut borrow: u128 = 0;
        for i in 0..6 {
            let diff = (raw[i] as u128)
                .wrapping_sub(N[i] as u128)
                .wrapping_sub(borrow);
            borrow = (diff >> 127) & 1;
        }
        if borrow == 0 {
            return None;
        }
        Some(Scalar384 {
            limbs: mont_mul(&raw, &R2_MOD_N),
        })
    }

    /// Reduce a 48-byte big-endian integer mod `n`, returning the
    /// resulting `Scalar384`.
    ///
    /// This is the "take whatever was in the hash, mod n" operation
    /// that FIPS 186-5 §6.4.1 calls for when deriving `e` from
    /// a hash digest. Unlike [`Scalar384::from_bytes`], it never
    /// rejects the input — the caller has already committed to
    /// reducing.
    pub fn from_bytes_reduced(bytes: &[u8; 48]) -> Scalar384 {
        let mut raw = [0u64; 6];
        for i in 0..6 {
            let off = 40 - 8 * i;
            raw[i] = u64::from_be_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
        }
        // Conditionally subtract n. `raw` is in [0, 2^384), which is
        // less than 2n since n > 2^383, so one subtraction suffices.
        let reduced = cond_sub_n(&raw, 0);
        Scalar384 {
            limbs: mont_mul(&reduced, &R2_MOD_N),
        }
    }

    /// Encode to a big-endian 48-byte string, the canonical SEC1
    /// scalar representation.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut one = [0u64; 6];
        one[0] = 1;
        let canonical = mont_mul(&self.limbs, &one);

        let mut out = [0u8; 48];
        for i in 0..6 {
            let off = 40 - 8 * i;
            out[off..off + 8].copy_from_slice(&canonical[i].to_be_bytes());
        }
        out
    }

    /// Scalar addition, `self + other mod n`.
    pub fn add(&self, other: &Scalar384) -> Scalar384 {
        let mut sum = [0u64; 6];
        let mut carry: u128 = 0;
        for i in 0..6 {
            let s = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        Scalar384 {
            limbs: cond_sub_n(&sum, carry as u64),
        }
    }

    /// Scalar subtraction, `self - other mod n`.
    pub fn sub(&self, other: &Scalar384) -> Scalar384 {
        let mut diff = [0u64; 6];
        let mut borrow: u128 = 0;
        for i in 0..6 {
            let d = (self.limbs[i] as u128)
                .wrapping_sub(other.limbs[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        let mask = 0u64.wrapping_sub(borrow as u64);
        let mut carry: u128 = 0;
        for i in 0..6 {
            let s = (diff[i] as u128) + ((N[i] & mask) as u128) + carry;
            diff[i] = s as u64;
            carry = s >> 64;
        }
        let _ = carry;
        Scalar384 { limbs: diff }
    }

    /// Scalar negation, `-self mod n`.
    pub fn neg(&self) -> Scalar384 {
        Scalar384::ZERO.sub(self)
    }

    /// Scalar multiplication via Montgomery multiplication.
    pub fn mul(&self, other: &Scalar384) -> Scalar384 {
        Scalar384 {
            limbs: mont_mul(&self.limbs, &other.limbs),
        }
    }

    /// Scalar squaring. Routes through [`Scalar384::mul`]; a dedicated
    /// squaring is a Phase 4 optimization.
    pub fn square(&self) -> Scalar384 {
        self.mul(self)
    }

    /// Multiplicative inverse via Fermat's little theorem:
    /// `self^(n-2) mod n`.
    ///
    /// Returns `Scalar384::ZERO` if `self == 0`. ECDSA sign/verify
    /// treat zero as an error condition separately.
    pub fn invert(&self) -> Scalar384 {
        // n - 2 as big-endian bytes.
        const N_MINUS_2: [u8; 48] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
            0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
            0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x71,
        ];

        let mut result = Scalar384::ONE;
        for byte in N_MINUS_2 {
            for bit_idx in (0..8).rev() {
                result = result.square();
                let bit = (byte >> bit_idx) & 1;
                let prod = result.mul(self);
                result = Scalar384::conditional_select(&result, &prod, bit);
            }
        }
        result
    }

    /// Constant-time equality test.
    pub fn ct_eq(&self, other: &Scalar384) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..6 {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        (((acc | acc.wrapping_neg()) >> 63) ^ 1) as u8
    }

    /// Constant-time test for the zero scalar.
    pub fn is_zero(&self) -> u8 {
        self.ct_eq(&Scalar384::ZERO)
    }

    /// Constant-time conditional select. Callers must pass
    /// `choice ∈ {0, 1}`.
    #[inline]
    pub fn conditional_select(a: &Scalar384, b: &Scalar384, choice: u8) -> Scalar384 {
        let mask = 0u64.wrapping_sub(choice as u64);
        let mut out = [0u64; 6];
        for i in 0..6 {
            out[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]));
        }
        Scalar384 { limbs: out }
    }

    /// Access the raw little-endian limbs.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn limbs(&self) -> &[u64; 6] {
        &self.limbs
    }
}

// ------------------------------------------------------------------
// Low-level primitives
// ------------------------------------------------------------------

/// Montgomery multiplication mod `n` (SOS variant).
fn mont_mul(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut t = [0u64; 13];
    for i in 0..6 {
        let bi = b[i] as u128;
        let mut carry: u128 = 0;
        for j in 0..6 {
            let prod = (a[j] as u128) * bi + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        t[i + 6] = carry as u64;
    }

    for i in 0..6 {
        let m = t[i].wrapping_mul(N_PRIME) as u128;
        let mut carry: u128 = 0;
        for j in 0..6 {
            let sum = m * (N[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = sum as u64;
            carry = sum >> 64;
        }
        let mut k = i + 6;
        while k < 13 {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
        debug_assert_eq!(carry, 0);
    }

    let r = [t[6], t[7], t[8], t[9], t[10], t[11]];
    let extra = t[12];
    cond_sub_n(&r, extra)
}

/// Conditional subtraction of `n`.
fn cond_sub_n(r: &[u64; 6], extra: u64) -> [u64; 6] {
    let mut diff = [0u64; 6];
    let mut borrow: u128 = 0;
    for i in 0..6 {
        let d = (r[i] as u128)
            .wrapping_sub(N[i] as u128)
            .wrapping_sub(borrow);
        diff[i] = d as u64;
        borrow = (d >> 127) & 1;
    }
    let take_diff = extra | ((borrow ^ 1) as u64);
    let mask = 0u64.wrapping_sub(take_diff);
    let mut out = [0u64; 6];
    for i in 0..6 {
        out[i] = r[i] ^ (mask & (r[i] ^ diff[i]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    /// Big-endian byte encoding of `n`.
    const N_BYTES: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ];

    /// Big-endian byte encoding of `n - 1`.
    const N_MINUS_ONE_BYTES: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x72,
    ];

    fn be(bytes: [u8; 48]) -> Scalar384 {
        Scalar384::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn n_constant_matches_byte_encoding() {
        let mut expected = [0u8; 48];
        for i in 0..6 {
            let off = 40 - 8 * i;
            expected[off..off + 8].copy_from_slice(&N[i].to_be_bytes());
        }
        assert_eq!(expected, N_BYTES);
    }

    #[test]
    fn from_bytes_rejects_n_and_above() {
        assert!(Scalar384::from_bytes(&N_BYTES).is_none());
        assert!(Scalar384::from_bytes(&[0xffu8; 48]).is_none());
    }

    #[test]
    fn from_bytes_accepts_zero_one_and_n_minus_one() {
        assert!(Scalar384::from_bytes(&[0u8; 48]).is_some());
        let mut one = [0u8; 48];
        one[47] = 1;
        assert!(Scalar384::from_bytes(&one).is_some());
        assert!(Scalar384::from_bytes(&N_MINUS_ONE_BYTES).is_some());
    }

    #[test]
    fn from_bytes_reduced_on_all_ones_equals_expected() {
        // Python: (2**384 - 1) % n
        let all_ones = [0xffu8; 48];
        let reduced = Scalar384::from_bytes_reduced(&all_ones);
        let expected_bytes: [u8; 48] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x9c, 0xb2, 0x7e,
            0x0b, 0xc8, 0xd2, 0x20, 0xa7, 0xe5, 0xf2, 0x4d, 0xb7, 0x4f, 0x58, 0x85, 0x13, 0x13,
            0xe6, 0x95, 0x33, 0x3a, 0xd6, 0x8c,
        ];
        assert_eq!(reduced.to_bytes(), expected_bytes);
    }

    #[test]
    fn roundtrip_bytes() {
        let vectors: &[[u8; 48]] = &[
            [0u8; 48],
            {
                let mut b = [0u8; 48];
                b[47] = 1;
                b
            },
            N_MINUS_ONE_BYTES,
            [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
                0x43, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce,
                0x13, 0x37, 0xc0, 0xde, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ],
        ];
        for v in vectors {
            let s = Scalar384::from_bytes(v).unwrap();
            assert_eq!(&s.to_bytes(), v);
        }
    }

    #[test]
    fn add_zero_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.add(&Scalar384::ZERO).to_bytes(), a.to_bytes());
    }

    #[test]
    fn add_n_minus_one_plus_one_is_zero() {
        let n_minus_one = be(N_MINUS_ONE_BYTES);
        let mut one_bytes = [0u8; 48];
        one_bytes[47] = 1;
        let one = be(one_bytes);
        assert_eq!(n_minus_one.add(&one).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn sub_one_from_zero_is_n_minus_one() {
        let mut one_bytes = [0u8; 48];
        one_bytes[47] = 1;
        let one = be(one_bytes);
        assert_eq!(Scalar384::ZERO.sub(&one).to_bytes(), N_MINUS_ONE_BYTES);
    }

    #[test]
    fn neg_roundtrip() {
        let a = be([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37,
            0xc0, 0xde, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed,
            0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
        ]);
        assert_eq!(a.neg().neg().to_bytes(), a.to_bytes());
        assert_eq!(a.add(&a.neg()).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn mul_zero_is_zero() {
        let a = be(N_MINUS_ONE_BYTES);
        assert_eq!(a.mul(&Scalar384::ZERO).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn mul_one_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.mul(&Scalar384::ONE).to_bytes(), a.to_bytes());
    }

    #[test]
    fn mul_n_minus_one_by_n_minus_one_is_one() {
        let n_minus_one = be(N_MINUS_ONE_BYTES);
        let result = n_minus_one.mul(&n_minus_one);
        let mut one = [0u8; 48];
        one[47] = 1;
        assert_eq!(result.to_bytes(), one);
    }

    #[test]
    fn square_matches_mul() {
        let a = be([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
            0x43, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce,
            0x13, 0x37, 0xc0, 0xde, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.square().to_bytes(), a.mul(&a).to_bytes());
    }

    #[test]
    fn invert_one_is_one() {
        assert_eq!(
            Scalar384::ONE.invert().to_bytes(),
            Scalar384::ONE.to_bytes()
        );
    }

    #[test]
    fn invert_roundtrip() {
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42, 0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48,
            0xa4, 0xc2, 0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd, 0x42, 0xa9, 0x73, 0x4c,
            0xba, 0x58, 0xea, 0x0a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        let a_inv = a.invert();
        let mut one = [0u8; 48];
        one[47] = 1;
        assert_eq!(a.mul(&a_inv).to_bytes(), one);
    }

    #[test]
    fn ct_eq_and_is_zero() {
        assert_eq!(Scalar384::ZERO.is_zero(), 1);
        assert_eq!(Scalar384::ONE.is_zero(), 0);
        assert_eq!(Scalar384::ONE.ct_eq(&Scalar384::ONE), 1);
        assert_eq!(Scalar384::ZERO.ct_eq(&Scalar384::ONE), 0);
    }
}
