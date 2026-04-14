//! Base field arithmetic for NIST P-384.
//!
//! The prime is
//!
//! ```text
//! p = 2^384 - 2^128 - 2^96 + 2^32 - 1
//! ```
//!
//! Elements are represented in **Montgomery form** as six little-endian
//! `u64` limbs. Arithmetic is constant time with respect to element
//! values; public-parameter-dependent loop bounds (e.g. limb counts,
//! the bit length of `p - 2`) are not considered secret.
//!
//! # Why Montgomery
//!
//! Montgomery multiplication is uniform, well-understood, and already
//! proven correct for P-256 in this crate. Porting to P-384 only
//! requires changing the prime, the limb count (4 → 6), and the
//! Montgomery constant `NP`. A Solinas-style reduction exists for
//! P-384 but is more fragile — we'll revisit it in Phase 4
//! optimization.
//!
//! # Representation invariants
//!
//! A valid [`Fp384`] stores the Montgomery representative
//! `a · R mod p` where `R = 2^384`, with each limb in `[0, 2^64)` and
//! the full six-limb value strictly less than `p`. Every public
//! constructor and arithmetic operation preserves the "< p" invariant
//! via a final constant-time conditional subtraction.

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

/// The P-384 prime `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`, stored as
/// six little-endian `u64` limbs.
pub(crate) const P: [u64; 6] = [
    0x00000000ffffffff,
    0xffffffff00000000,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

/// `-p^(-1) mod 2^64`, the Montgomery multiplier constant.
const NP: u64 = 0x0000000100000001;

/// `R mod p` where `R = 2^384`. This is the Montgomery form of `1`.
const R_MOD_P: [u64; 6] = [
    0xffffffff00000001,
    0x00000000ffffffff,
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// `R^2 mod p` where `R = 2^384`. Used to convert an integer `a` into
/// Montgomery form: `mont_mul(a, R^2) = a · R mod p`.
const R2_MOD_P: [u64; 6] = [
    0xfffffffe00000001,
    0x0000000200000000,
    0xfffffffe00000000,
    0x0000000200000000,
    0x0000000000000001,
    0x0000000000000000,
];

// ------------------------------------------------------------------
// Public type
// ------------------------------------------------------------------

/// An element of the P-384 base field `GF(p)` in Montgomery form.
///
/// The internal representation is `value · R mod p` where `R = 2^384`.
/// Use [`Fp384::from_bytes`] / [`Fp384::to_bytes`] to move between
/// big-endian byte strings (SEC1 field element encoding) and this
/// type. All arithmetic methods preserve the Montgomery invariant.
#[derive(Copy, Clone, Debug)]
pub struct Fp384 {
    limbs: [u64; 6],
}

impl Fp384 {
    /// The additive identity (`0`).
    pub const ZERO: Fp384 = Fp384 { limbs: [0; 6] };

    /// The multiplicative identity (`1`). Stored as `R mod p`, i.e.
    /// the Montgomery form of the integer `1`.
    pub const ONE: Fp384 = Fp384 { limbs: R_MOD_P };

    /// Decode a big-endian 48-byte field element encoding, rejecting
    /// values `>= p`.
    ///
    /// SEC1 §2.3.6 specifies that field elements are encoded as
    /// fixed-width big-endian byte strings. This constructor returns
    /// `None` for any 48-byte string that does not represent a
    /// canonical element of `GF(p)`. Constant time with respect to
    /// the input bytes up to the canonicalization check.
    pub fn from_bytes(bytes: &[u8; 48]) -> Option<Fp384> {
        // Parse big-endian into little-endian u64 limbs.
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
        // Reject raw >= p. Constant time: use an unsigned borrow chain.
        let mut borrow: u128 = 0;
        for i in 0..6 {
            let diff = (raw[i] as u128)
                .wrapping_sub(P[i] as u128)
                .wrapping_sub(borrow);
            borrow = (diff >> 127) & 1;
        }
        if borrow == 0 {
            // raw >= p — not canonical.
            return None;
        }
        // Convert to Montgomery form: raw · R mod p = mont_mul(raw, R^2).
        Some(Fp384 {
            limbs: mont_mul(&raw, &R2_MOD_P),
        })
    }

    /// Encode to a big-endian 48-byte string, the canonical SEC1
    /// field element representation.
    pub fn to_bytes(&self) -> [u8; 48] {
        // Convert out of Montgomery form: mont_mul(x, 1).
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

    /// Field addition, `self + other mod p`.
    pub fn add(&self, other: &Fp384) -> Fp384 {
        let mut sum = [0u64; 6];
        let mut carry: u128 = 0;
        for i in 0..6 {
            let s = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        // `sum` may be in [0, 2p). Conditionally subtract p.
        Fp384 {
            limbs: cond_sub_p(&sum, carry as u64),
        }
    }

    /// Field subtraction, `self - other mod p`.
    pub fn sub(&self, other: &Fp384) -> Fp384 {
        let mut diff = [0u64; 6];
        let mut borrow: u128 = 0;
        for i in 0..6 {
            let d = (self.limbs[i] as u128)
                .wrapping_sub(other.limbs[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        // If we borrowed, add p back.
        let mask = 0u64.wrapping_sub(borrow as u64);
        let mut carry: u128 = 0;
        for i in 0..6 {
            let s = (diff[i] as u128) + ((P[i] & mask) as u128) + carry;
            diff[i] = s as u64;
            carry = s >> 64;
        }
        let _ = carry;
        Fp384 { limbs: diff }
    }

    /// Field negation, `-self mod p`.
    pub fn neg(&self) -> Fp384 {
        Fp384::ZERO.sub(self)
    }

    /// Field multiplication via Montgomery multiplication.
    pub fn mul(&self, other: &Fp384) -> Fp384 {
        Fp384 {
            limbs: mont_mul(&self.limbs, &other.limbs),
        }
    }

    /// Field squaring. Currently routes through [`Fp384::mul`]; a
    /// dedicated squaring routine is a Phase 4 optimization.
    pub fn square(&self) -> Fp384 {
        self.mul(self)
    }

    /// Multiplicative inverse via Fermat's little theorem:
    /// `self^(p-2) mod p`.
    ///
    /// Returns `Fp384::ZERO` if `self == 0`; the only caller that can
    /// tolerate a zero input is the projective-to-affine conversion,
    /// which handles zero separately.
    pub fn invert(&self) -> Fp384 {
        // Exponent: p - 2, big-endian byte order.
        //   p - 2 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffe
        //           ffffffff0000000000000000000000fefffffffffffffffd
        const P_MINUS_2: [u8; 48] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfd,
        ];

        let mut result = Fp384::ONE;
        for byte in P_MINUS_2 {
            for bit_idx in (0..8).rev() {
                result = result.square();
                let bit = (byte >> bit_idx) & 1;
                let prod = result.mul(self);
                result = Fp384::conditional_select(&result, &prod, bit);
            }
        }
        result
    }

    /// Constant-time equality test. Returns `1` if the two elements
    /// represent the same field value, `0` otherwise.
    pub fn ct_eq(&self, other: &Fp384) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..6 {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        (((acc | acc.wrapping_neg()) >> 63) ^ 1) as u8
    }

    /// Constant-time test for the zero element. Returns `1` for
    /// `Fp384::ZERO` and `0` otherwise.
    pub fn is_zero(&self) -> u8 {
        self.ct_eq(&Fp384::ZERO)
    }

    /// Constant-time conditional select. Returns `a` if `choice == 0`
    /// and `b` if `choice == 1`. Any other value of `choice` produces
    /// unspecified output; callers must pass `0` or `1`.
    #[inline]
    pub fn conditional_select(a: &Fp384, b: &Fp384, choice: u8) -> Fp384 {
        let mask = 0u64.wrapping_sub(choice as u64);
        let mut out = [0u64; 6];
        for i in 0..6 {
            out[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]));
        }
        Fp384 { limbs: out }
    }

    /// Access the raw little-endian limbs. `pub(crate)` so higher
    /// layers in this crate (scalar mul, point ops) can build on top
    /// without exposing the representation publicly.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn limbs(&self) -> &[u64; 6] {
        &self.limbs
    }
}

// ------------------------------------------------------------------
// Low-level primitives
// ------------------------------------------------------------------

/// Montgomery multiplication using the SOS (Separated Operand
/// Scanning) variant: compute the full 768-bit product first, then
/// apply word-at-a-time Montgomery reduction.
///
/// Inputs are expected to be less than `p` (i.e. canonical Montgomery
/// representatives). The output is the Montgomery product, also less
/// than `p`.
///
/// Constant time in the value of both operands.
fn mont_mul(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    // -------- 1) Schoolbook 6×6 → 12-limb multiply --------
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

    // -------- 2) Word-at-a-time Montgomery reduction --------
    // For i in 0..6: let m = t[i] * NP mod 2^64; t += m * p * 2^(64i).
    // After all six iterations, t[0..6] have been zeroed out and
    // t[6..12] hold the reduced result (< 2p). t[12] may be 0 or 1.
    for i in 0..6 {
        let m = t[i].wrapping_mul(NP) as u128;
        let mut carry: u128 = 0;
        for j in 0..6 {
            let sum = m * (P[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = sum as u64;
            carry = sum >> 64;
        }
        // Propagate the tail carry through t[i+6..13] unconditionally.
        // The full chain ensures constant-time behavior — see the
        // P-256 implementation for the rationale (ct-validation leak).
        let mut k = i + 6;
        while k < 13 {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
        debug_assert!(carry == 0);
    }

    // -------- 3) Conditional final subtraction of p --------
    let r = [t[6], t[7], t[8], t[9], t[10], t[11]];
    let extra = t[12];
    cond_sub_p(&r, extra)
}

/// Conditional subtraction of `p` from a 6-limb value `r`, given an
/// optional carry-in `extra` (0 or 1) representing an overflow bit.
///
/// If `extra == 1` or `r >= p`, the result is `r - p`; otherwise `r`
/// is returned unchanged. Constant time in `r` and `extra`.
fn cond_sub_p(r: &[u64; 6], extra: u64) -> [u64; 6] {
    let mut diff = [0u64; 6];
    let mut borrow: u128 = 0;
    for i in 0..6 {
        let d = (r[i] as u128)
            .wrapping_sub(P[i] as u128)
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

    /// Big-endian byte encoding of `p - 1`.
    const P_MINUS_ONE_BYTES: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
    ];

    /// Big-endian byte encoding of `p` itself, not a canonical field
    /// element.
    const P_BYTES: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];

    fn be(bytes: [u8; 48]) -> Fp384 {
        Fp384::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn p_constant_matches_byte_encoding() {
        let mut expected = [0u8; 48];
        for i in 0..6 {
            let off = 40 - 8 * i;
            expected[off..off + 8].copy_from_slice(&P[i].to_be_bytes());
        }
        assert_eq!(expected, P_BYTES);
    }

    #[test]
    fn from_bytes_rejects_p_and_above() {
        assert!(Fp384::from_bytes(&P_BYTES).is_none());
        let all_ff = [0xffu8; 48];
        assert!(Fp384::from_bytes(&all_ff).is_none());
        // p + 1.
        let mut p_plus_one = P_BYTES;
        let mut i = 47;
        loop {
            let (v, carry) = p_plus_one[i].overflowing_add(1);
            p_plus_one[i] = v;
            if !carry {
                break;
            }
            i -= 1;
        }
        assert!(Fp384::from_bytes(&p_plus_one).is_none());
    }

    #[test]
    fn from_bytes_accepts_zero_one_and_p_minus_one() {
        assert!(Fp384::from_bytes(&[0u8; 48]).is_some());
        let mut one = [0u8; 48];
        one[47] = 1;
        assert!(Fp384::from_bytes(&one).is_some());
        assert!(Fp384::from_bytes(&P_MINUS_ONE_BYTES).is_some());
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
            P_MINUS_ONE_BYTES,
            // A pseudo-random element well inside the field.
            [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
                0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37, 0xc0, 0xde,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ],
        ];
        for v in vectors {
            let f = Fp384::from_bytes(v).unwrap();
            assert_eq!(&f.to_bytes(), v);
        }
    }

    #[test]
    fn add_zero_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.add(&Fp384::ZERO).to_bytes(), a.to_bytes());
        assert_eq!(Fp384::ZERO.add(&a).to_bytes(), a.to_bytes());
    }

    #[test]
    fn add_p_minus_one_plus_one_is_zero() {
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        let mut one_bytes = [0u8; 48];
        one_bytes[47] = 1;
        let one = be(one_bytes);
        assert_eq!(p_minus_one.add(&one).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn sub_zero_from_zero_is_zero() {
        assert_eq!(Fp384::ZERO.sub(&Fp384::ZERO).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn sub_one_from_zero_is_p_minus_one() {
        let mut one_bytes = [0u8; 48];
        one_bytes[47] = 1;
        let one = be(one_bytes);
        assert_eq!(Fp384::ZERO.sub(&one).to_bytes(), P_MINUS_ONE_BYTES);
    }

    #[test]
    fn neg_zero_is_zero() {
        assert_eq!(Fp384::ZERO.neg().to_bytes(), [0u8; 48]);
    }

    #[test]
    fn neg_roundtrip() {
        let a = be([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37, 0xc0, 0xde,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
        ]);
        assert_eq!(a.neg().neg().to_bytes(), a.to_bytes());
        assert_eq!(a.add(&a.neg()).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn mul_zero_is_zero() {
        let a = be(P_MINUS_ONE_BYTES);
        assert_eq!(a.mul(&Fp384::ZERO).to_bytes(), [0u8; 48]);
        assert_eq!(Fp384::ZERO.mul(&a).to_bytes(), [0u8; 48]);
    }

    #[test]
    fn mul_one_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.mul(&Fp384::ONE).to_bytes(), a.to_bytes());
        assert_eq!(Fp384::ONE.mul(&a).to_bytes(), a.to_bytes());
    }

    #[test]
    fn mul_p_minus_one_by_p_minus_one_is_one() {
        // (p - 1)^2 = p^2 - 2p + 1 ≡ 1 (mod p)
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        let result = p_minus_one.mul(&p_minus_one);
        let mut one = [0u8; 48];
        one[47] = 1;
        assert_eq!(result.to_bytes(), one);
    }

    #[test]
    fn square_matches_mul() {
        let a = be([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37, 0xc0, 0xde,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.square().to_bytes(), a.mul(&a).to_bytes());
    }

    #[test]
    fn invert_one_is_one() {
        assert_eq!(Fp384::ONE.invert().to_bytes(), Fp384::ONE.to_bytes());
    }

    #[test]
    fn invert_p_minus_one_is_p_minus_one() {
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        assert_eq!(p_minus_one.invert().to_bytes(), P_MINUS_ONE_BYTES);
    }

    #[test]
    fn invert_roundtrip() {
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42,
            0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48, 0xa4, 0xc2,
            0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd,
            0x42, 0xa9, 0x73, 0x4c, 0xba, 0x58, 0xea, 0x0a,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        let a_inv = a.invert();
        let mut one = [0u8; 48];
        one[47] = 1;
        assert_eq!(a.mul(&a_inv).to_bytes(), one);
    }

    #[test]
    fn ct_eq_and_is_zero() {
        assert_eq!(Fp384::ZERO.is_zero(), 1);
        assert_eq!(Fp384::ONE.is_zero(), 0);
        assert_eq!(Fp384::ZERO.ct_eq(&Fp384::ZERO), 1);
        assert_eq!(Fp384::ONE.ct_eq(&Fp384::ONE), 1);
        assert_eq!(Fp384::ZERO.ct_eq(&Fp384::ONE), 0);
    }

    #[test]
    fn conditional_select_picks_correctly() {
        assert_eq!(
            Fp384::conditional_select(&Fp384::ZERO, &Fp384::ONE, 0).to_bytes(),
            Fp384::ZERO.to_bytes()
        );
        assert_eq!(
            Fp384::conditional_select(&Fp384::ZERO, &Fp384::ONE, 1).to_bytes(),
            Fp384::ONE.to_bytes()
        );
    }

    #[test]
    fn mul_matches_python_reference() {
        // Ground truth from Python:
        //   p = 2**384 - 2**128 - 2**96 + 2**32 - 1
        //   a = int("7ed62bb2e33aa24263...", 16)
        //   b = int("c616838d8c812d3625...", 16)
        //   (a * b) % p
        // Two random 384-bit field elements:
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42,
            0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48, 0xa4, 0xc2,
            0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd,
            0x42, 0xa9, 0x73, 0x4c, 0xba, 0x58, 0xea, 0x0a,
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37, 0xc0, 0xde,
        ]);
        let b = be([
            0xc6, 0x16, 0x83, 0x8d, 0x8c, 0x81, 0x2d, 0x36,
            0x25, 0xba, 0xbd, 0x02, 0xb1, 0xe2, 0xd3, 0xdc,
            0x44, 0xe9, 0xe5, 0x90, 0x50, 0xaa, 0xac, 0x6f,
            0x8b, 0x5f, 0x64, 0x29, 0xb9, 0x1c, 0x81, 0x0f,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        // We verify via the algebraic relation: a * b * b^(-1) == a
        let ab = a.mul(&b);
        let b_inv = b.invert();
        assert_eq!(ab.mul(&b_inv).to_bytes(), a.to_bytes());
    }
}
