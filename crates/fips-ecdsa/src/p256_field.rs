//! Base field arithmetic for NIST P-256.
//!
//! The prime is
//!
//! ```text
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//! ```
//!
//! Elements are represented in **Montgomery form** as four little-endian
//! `u64` limbs. Arithmetic is constant time with respect to element
//! values; public-parameter-dependent loop bounds (e.g. limb counts,
//! the bit length of `p - 2`) are not considered secret.
//!
//! # Why Montgomery and not Solinas
//!
//! P-256 admits a fast Solinas-style reduction that exploits the
//! structure of the prime (`2^256 - 2^224 + 2^192 + 2^96 - 1` decomposes
//! into a handful of shifted copies of the top half of the input). It
//! is faster than Montgomery in absolute terms, but the reduction
//! itself is brittle — small sign/shift errors produce values that are
//! "almost right" and slip past coarse unit tests. Montgomery
//! multiplication is uniform, well-understood, easier to get correct
//! on the first try, and ports directly to P-384 and P-521 by changing
//! the prime constant and the `-p^(-1) mod 2^64` factor. We'll revisit
//! Solinas when Phase 4 optimization comes around.
//!
//! # Representation invariants
//!
//! A valid [`Fp`] stores the Montgomery representative
//! `a · R mod p` where `R = 2^256`, with each limb in `[0, 2^64)` and
//! the full four-limb value strictly less than `p`. Every public
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

/// The P-256 prime `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, stored as
/// four little-endian `u64` limbs. Cross-checked against the byte
/// encoding in the unit tests.
pub(crate) const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// `-p^(-1) mod 2^64`, the Montgomery multiplier constant. For P-256
/// the low limb of `p` is `2^64 - 1`, so `p^(-1) ≡ -1 (mod 2^64)` and
/// `-p^(-1) ≡ 1`. Pinned here so a reader doesn't have to re-derive it.
const NP: u64 = 0x0000_0000_0000_0001;

/// `R mod p` where `R = 2^256`. This is the Montgomery form of `1`
/// and is used to cheaply construct the multiplicative identity
/// without running a full `to_montgomery` conversion.
const R_MOD_P: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
];

/// `R^2 mod p` where `R = 2^256`. Used to convert an integer `a` into
/// Montgomery form: `mont_mul(a, R^2) = a · R mod p`.
const R2_MOD_P: [u64; 4] = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];

// ------------------------------------------------------------------
// Public type
// ------------------------------------------------------------------

/// An element of the P-256 base field `GF(p)` in Montgomery form.
///
/// The internal representation is `value · R mod p` where `R = 2^256`.
/// Use [`Fp::from_bytes`] / [`Fp::to_bytes`] to move between
/// big-endian byte strings (SEC1 field element encoding) and this
/// type. All arithmetic methods preserve the Montgomery invariant.
#[derive(Copy, Clone, Debug)]
pub struct Fp {
    limbs: [u64; 4],
}

impl Fp {
    /// The additive identity (`0`).
    pub const ZERO: Fp = Fp { limbs: [0; 4] };

    /// The multiplicative identity (`1`). Stored as `R mod p`, i.e.
    /// the Montgomery form of the integer `1`.
    pub const ONE: Fp = Fp { limbs: R_MOD_P };

    /// Decode a big-endian 32-byte field element encoding, rejecting
    /// values `>= p`.
    ///
    /// SEC1 §2.3.6 specifies that field elements are encoded as
    /// fixed-width big-endian byte strings. This constructor returns
    /// `None` for any 32-byte string that does not represent a
    /// canonical element of `GF(p)`. Constant time with respect to
    /// the input bytes up to the canonicalization check.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Fp> {
        // Parse big-endian into little-endian u64 limbs.
        let mut raw = [0u64; 4];
        for i in 0..4 {
            let off = 24 - 8 * i;
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
        for i in 0..4 {
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
        Some(Fp {
            limbs: mont_mul(&raw, &R2_MOD_P),
        })
    }

    /// Encode to a big-endian 32-byte string, the canonical SEC1
    /// field element representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Convert out of Montgomery form: mont_mul(x, 1).
        let mut one = [0u64; 4];
        one[0] = 1;
        let canonical = mont_mul(&self.limbs, &one);

        let mut out = [0u8; 32];
        for i in 0..4 {
            let off = 24 - 8 * i;
            out[off..off + 8].copy_from_slice(&canonical[i].to_be_bytes());
        }
        out
    }

    /// Field addition, `self + other mod p`.
    pub fn add(&self, other: &Fp) -> Fp {
        let mut sum = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let s = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        // `sum` may be in [0, 2p). Conditionally subtract p.
        Fp {
            limbs: cond_sub_p(&sum, carry as u64),
        }
    }

    /// Field subtraction, `self - other mod p`.
    pub fn sub(&self, other: &Fp) -> Fp {
        let mut diff = [0u64; 4];
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let d = (self.limbs[i] as u128)
                .wrapping_sub(other.limbs[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        // If we borrowed, add p back.
        let mask = 0u64.wrapping_sub(borrow as u64);
        let mut carry: u128 = 0;
        for i in 0..4 {
            let s = (diff[i] as u128) + ((P[i] & mask) as u128) + carry;
            diff[i] = s as u64;
            carry = s >> 64;
        }
        let _ = carry;
        Fp { limbs: diff }
    }

    /// Field negation, `-self mod p`.
    pub fn neg(&self) -> Fp {
        Fp::ZERO.sub(self)
    }

    /// Field multiplication via Montgomery multiplication.
    pub fn mul(&self, other: &Fp) -> Fp {
        Fp {
            limbs: mont_mul(&self.limbs, &other.limbs),
        }
    }

    /// Field squaring. Currently routes through [`Fp::mul`]; a
    /// dedicated squaring routine is a Phase 4 optimization.
    pub fn square(&self) -> Fp {
        self.mul(self)
    }

    /// Multiplicative inverse via Fermat's little theorem:
    /// `self^(p-2) mod p`.
    ///
    /// Returns `Fp::ZERO` if `self == 0`; the only caller that can
    /// tolerate a zero input is the projective-to-affine conversion,
    /// which handles zero separately.
    pub fn invert(&self) -> Fp {
        // Exponent: p - 2, big-endian byte order. Pinned here as a
        // constant so the square-and-multiply loop below is constant
        // time in the input. Computed once from the curve parameter:
        //     p - 2 = 0xffffffff 00000001 00000000 00000000
        //             00000000 ffffffff ffffffff fffffffd
        const P_MINUS_2: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, //
        ];

        let mut result = Fp::ONE;
        for byte in P_MINUS_2 {
            for bit_idx in (0..8).rev() {
                result = result.square();
                let bit = (byte >> bit_idx) & 1;
                // Constant-time conditional multiply: select between
                // `result` and `result * self` based on the public
                // exponent bit.
                let prod = result.mul(self);
                result = Fp::conditional_select(&result, &prod, bit);
            }
        }
        result
    }

    /// Constant-time equality test. Returns `1` if the two elements
    /// represent the same field value, `0` otherwise.
    pub fn ct_eq(&self, other: &Fp) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..4 {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        // acc == 0 → return 1; acc != 0 → return 0.
        (((acc | acc.wrapping_neg()) >> 63) ^ 1) as u8
    }

    /// Constant-time test for the zero element. Returns `1` for
    /// `Fp::ZERO` and `0` otherwise.
    pub fn is_zero(&self) -> u8 {
        self.ct_eq(&Fp::ZERO)
    }

    /// Constant-time conditional select. Returns `a` if `choice == 0`
    /// and `b` if `choice == 1`. Any other value of `choice` produces
    /// unspecified output; callers must pass `0` or `1`.
    #[inline]
    pub fn conditional_select(a: &Fp, b: &Fp, choice: u8) -> Fp {
        let mask = 0u64.wrapping_sub(choice as u64);
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]));
        }
        Fp { limbs: out }
    }

    /// Access the raw little-endian limbs. `pub(crate)` so higher
    /// layers in this crate (scalar mul, point ops) can build on top
    /// without exposing the representation publicly.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn limbs(&self) -> &[u64; 4] {
        &self.limbs
    }
}

// ------------------------------------------------------------------
// Low-level primitives
// ------------------------------------------------------------------

/// Montgomery multiplication using the SOS (Separated Operand
/// Scanning) variant: compute the full 512-bit product first, then
/// apply word-at-a-time Montgomery reduction.
///
/// Inputs are expected to be less than `p` (i.e. canonical Montgomery
/// representatives). The output is the Montgomery product, also less
/// than `p`.
///
/// Constant time in the value of both operands.
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // -------- 1) Schoolbook 4x4 → 8 limb multiply --------
    let mut t = [0u64; 9];
    for i in 0..4 {
        let bi = b[i] as u128;
        let mut carry: u128 = 0;
        for j in 0..4 {
            let prod = (a[j] as u128) * bi + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        t[i + 4] = carry as u64;
    }
    // t[8] is zero after the multiply; it exists so the reduction
    // below has headroom for its carry chain.

    // -------- 2) Word-at-a-time Montgomery reduction --------
    // For i in 0..4: let m = t[i] * NP mod 2^64; t += m * p * 2^(64i).
    // After all four iterations, t[0..4] have been zeroed out and
    // t[4..8] hold the reduced result (< 2p). t[8] may be 0 or 1.
    for i in 0..4 {
        let m = t[i].wrapping_mul(NP) as u128;
        let mut carry: u128 = 0;
        for j in 0..4 {
            let sum = m * (P[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = sum as u64;
            carry = sum >> 64;
        }
        // Propagate the tail carry through t[i+4..9]. Loop bounds are
        // a public parameter (limb count), not secret.
        let mut k = i + 4;
        while k < 9 {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            if carry == 0 {
                break;
            }
            k += 1;
        }
        // Any residual carry beyond t[8] would indicate
        // `t > 2^(64*9)`, which is impossible since the running value
        // is bounded by `p^2 + p · 2^256 < 2^513 < 2^576 = 2^(64·9)`.
        debug_assert!(carry == 0);
    }

    // -------- 3) Conditional final subtraction of p --------
    // The result in t[4..8] is less than 2p. t[8] is 0 or 1 and
    // represents the "overflow" bit. If t[8] == 1 OR t[4..8] >= p,
    // subtract p once.
    let r = [t[4], t[5], t[6], t[7]];
    let extra = t[8];
    cond_sub_p(&r, extra)
}

/// Conditional subtraction of `p` from a 4-limb value `r`, given an
/// optional carry-in `extra` (0 or 1) representing an overflow bit.
///
/// If `extra == 1` or `r >= p`, the result is `r - p`; otherwise `r`
/// is returned unchanged. Constant time in `r` and `extra`.
fn cond_sub_p(r: &[u64; 4], extra: u64) -> [u64; 4] {
    // Compute `r - p` and track the borrow.
    let mut diff = [0u64; 4];
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let d = (r[i] as u128)
            .wrapping_sub(P[i] as u128)
            .wrapping_sub(borrow);
        diff[i] = d as u64;
        borrow = (d >> 127) & 1;
    }
    // If there was no borrow (r >= p) OR the high overflow bit was
    // set, we want the subtracted result. `extra == 1` forces the
    // selection of `diff` regardless of the borrow, because the true
    // value `(extra << 256) + r` is always >= p in that case.
    //
    //   take_diff = extra | !borrow
    //
    // which is 1 iff we should keep `diff`, 0 iff we should keep `r`.
    let take_diff = extra | ((borrow ^ 1) as u64);
    let mask = 0u64.wrapping_sub(take_diff);
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = r[i] ^ (mask & (r[i] ^ diff[i]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    /// Big-endian byte encoding of `p - 1`, used in canonical-form
    /// boundary tests.
    const P_MINUS_ONE_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, //
    ];

    /// Big-endian byte encoding of `p` itself, not a canonical field
    /// element.
    const P_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    ];

    fn be(bytes: [u8; 32]) -> Fp {
        Fp::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn p_constant_matches_byte_encoding() {
        // Recompute P as bytes and compare to the expected
        // big-endian byte string.
        let mut expected = [0u8; 32];
        for i in 0..4 {
            let off = 24 - 8 * i;
            expected[off..off + 8].copy_from_slice(&P[i].to_be_bytes());
        }
        assert_eq!(expected, P_BYTES);
    }

    #[test]
    fn from_bytes_rejects_p_and_above() {
        assert!(Fp::from_bytes(&P_BYTES).is_none());
        // 2^256 - 1, definitely above p.
        let all_ff = [0xffu8; 32];
        assert!(Fp::from_bytes(&all_ff).is_none());
        // p + 1 — smallest invalid value above p.
        let mut p_plus_one = P_BYTES;
        let mut i = 31;
        loop {
            let (v, carry) = p_plus_one[i].overflowing_add(1);
            p_plus_one[i] = v;
            if !carry {
                break;
            }
            i -= 1;
        }
        assert!(Fp::from_bytes(&p_plus_one).is_none());
    }

    #[test]
    fn from_bytes_accepts_zero_one_and_p_minus_one() {
        assert!(Fp::from_bytes(&[0u8; 32]).is_some());
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(Fp::from_bytes(&one).is_some());
        assert!(Fp::from_bytes(&P_MINUS_ONE_BYTES).is_some());
    }

    #[test]
    fn roundtrip_bytes() {
        let vectors: &[[u8; 32]] = &[
            [0u8; 32],
            {
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            },
            P_MINUS_ONE_BYTES,
            // A pseudo-random element well inside the field.
            [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
                0x43, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce,
                0x13, 0x37, 0xc0, 0xde,
            ],
        ];
        for v in vectors {
            let f = Fp::from_bytes(v).unwrap();
            assert_eq!(&f.to_bytes(), v);
        }
    }

    #[test]
    fn add_zero_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ]);
        assert_eq!(a.add(&Fp::ZERO).to_bytes(), a.to_bytes());
        assert_eq!(Fp::ZERO.add(&a).to_bytes(), a.to_bytes());
    }

    #[test]
    fn add_p_minus_one_plus_one_is_zero() {
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = be(one_bytes);
        assert_eq!(p_minus_one.add(&one).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn sub_zero_from_zero_is_zero() {
        assert_eq!(Fp::ZERO.sub(&Fp::ZERO).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn sub_one_from_zero_is_p_minus_one() {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = be(one_bytes);
        assert_eq!(Fp::ZERO.sub(&one).to_bytes(), P_MINUS_ONE_BYTES);
    }

    #[test]
    fn neg_zero_is_zero() {
        assert_eq!(Fp::ZERO.neg().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn neg_roundtrip() {
        let a = be([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce, 0x13, 0x37,
            0xc0, 0xde, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ]);
        assert_eq!(a.neg().neg().to_bytes(), a.to_bytes());
        assert_eq!(a.add(&a.neg()).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn mul_zero_is_zero() {
        let a = be(P_MINUS_ONE_BYTES);
        assert_eq!(a.mul(&Fp::ZERO).to_bytes(), [0u8; 32]);
        assert_eq!(Fp::ZERO.mul(&a).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn mul_one_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ]);
        assert_eq!(a.mul(&Fp::ONE).to_bytes(), a.to_bytes());
        assert_eq!(Fp::ONE.mul(&a).to_bytes(), a.to_bytes());
    }

    #[test]
    fn mul_p_minus_one_by_p_minus_one_is_one() {
        // (p - 1)^2 = p^2 - 2p + 1 ≡ 1 (mod p)
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        let result = p_minus_one.mul(&p_minus_one);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(result.to_bytes(), one);
    }

    #[test]
    fn mul_matches_python_reference() {
        // Ground truth from Python: (a * b) mod p for two random field
        // elements pre-reduced. Values chosen so every limb is exercised.
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42, 0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48,
            0xa4, 0xc2, 0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd, 0x42, 0xa9, 0x73, 0x4c,
            0xba, 0x58, 0xea, 0x0a,
        ]);
        let b = be([
            0xc6, 0x16, 0x83, 0x8d, 0x8c, 0x81, 0x2d, 0x36, 0x25, 0xba, 0xbd, 0x02, 0xb1, 0xe2,
            0xd3, 0xdc, 0x44, 0xe9, 0xe5, 0x90, 0x50, 0xaa, 0xac, 0x6f, 0x8b, 0x5f, 0x64, 0x29,
            0xb9, 0x1c, 0x81, 0x0f,
        ]);
        // Computed in Python:
        //   p = 2**256 - 2**224 + 2**192 + 2**96 - 1
        //   (a * b) % p
        // = 0x282a23c89ecd4b28819a50aa9c188c15215ad249f3a562cc730df20158e41e65
        let expected_bytes: [u8; 32] = [
            0x28, 0x2a, 0x23, 0xc8, 0x9e, 0xcd, 0x4b, 0x28, 0x81, 0x9a, 0x50, 0xaa, 0x9c, 0x18,
            0x8c, 0x15, 0x21, 0x5a, 0xd2, 0x49, 0xf3, 0xa5, 0x62, 0xcc, 0x73, 0x0d, 0xf2, 0x01,
            0x58, 0xe4, 0x1e, 0x65,
        ];
        let expected = be(expected_bytes);
        assert_eq!(a.mul(&b).to_bytes(), expected.to_bytes());
    }

    #[test]
    fn square_matches_mul() {
        let a = be([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
            0x43, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce,
            0x13, 0x37, 0xc0, 0xde,
        ]);
        assert_eq!(a.square().to_bytes(), a.mul(&a).to_bytes());
    }

    #[test]
    fn invert_one_is_one() {
        assert_eq!(Fp::ONE.invert().to_bytes(), Fp::ONE.to_bytes());
    }

    #[test]
    fn invert_p_minus_one_is_p_minus_one() {
        // (p - 1)^(-1) = (p - 1) since (p - 1)^2 ≡ 1 (mod p).
        let p_minus_one = be(P_MINUS_ONE_BYTES);
        assert_eq!(p_minus_one.invert().to_bytes(), P_MINUS_ONE_BYTES);
    }

    #[test]
    fn invert_roundtrip() {
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42, 0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48,
            0xa4, 0xc2, 0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd, 0x42, 0xa9, 0x73, 0x4c,
            0xba, 0x58, 0xea, 0x0a,
        ]);
        let a_inv = a.invert();
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(a.mul(&a_inv).to_bytes(), one);
    }

    #[test]
    fn ct_eq_and_is_zero() {
        assert_eq!(Fp::ZERO.is_zero(), 1);
        assert_eq!(Fp::ONE.is_zero(), 0);
        assert_eq!(Fp::ZERO.ct_eq(&Fp::ZERO), 1);
        assert_eq!(Fp::ONE.ct_eq(&Fp::ONE), 1);
        assert_eq!(Fp::ZERO.ct_eq(&Fp::ONE), 0);
    }

    #[test]
    fn conditional_select_picks_correctly() {
        assert_eq!(
            Fp::conditional_select(&Fp::ZERO, &Fp::ONE, 0).to_bytes(),
            Fp::ZERO.to_bytes()
        );
        assert_eq!(
            Fp::conditional_select(&Fp::ZERO, &Fp::ONE, 1).to_bytes(),
            Fp::ONE.to_bytes()
        );
    }
}
