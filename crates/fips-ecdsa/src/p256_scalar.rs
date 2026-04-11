//! Scalar field arithmetic for NIST P-256.
//!
//! The group order is
//!
//! ```text
//! n = 0xffffffff 00000000 ffffffff ffffffff
//!     bce6faad a7179e84 f3b9cac2 fc632551
//! ```
//!
//! Scalars are represented in **Montgomery form** as four little-endian
//! `u64` limbs. Constant time with respect to secret values; loop
//! bounds (limb count, bit length of `n - 2`) are public parameters.
//!
//! The structure mirrors [`crate::p256_field`] — the only differences
//! are the modulus `N`, the Montgomery multiplier `-n^(-1) mod 2^64`,
//! the precomputed `R mod n` and `R^2 mod n`, and the `n - 2` exponent
//! used by the Fermat inverse. Duplicating the arithmetic instead of
//! parameterizing it keeps the two modules independently auditable,
//! which is the stance FIPS 140-3 IG D.G effectively demands for
//! algorithm-specific constants. A Phase 4 refactor can revisit this
//! once P-384 / P-521 are on the roadmap.

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

/// The P-256 group order `n`, stored as four little-endian `u64`
/// limbs. Cross-checked against the byte encoding in the unit tests.
pub(crate) const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// `-n^(-1) mod 2^64`, the Montgomery multiplier constant. Computed
/// once by the Python helper and pinned here.
const N_PRIME: u64 = 0xccd1_c8aa_ee00_bc4f;

/// `R mod n` where `R = 2^256`. The Montgomery form of the integer
/// `1`, used as the multiplicative identity without running a full
/// Montgomery conversion.
const R_MOD_N: [u64; 4] = [
    0x0c46_353d_039c_daaf,
    0x4319_0552_58e8_617b,
    0x0000_0000_0000_0000,
    0x0000_0000_ffff_ffff,
];

/// `R^2 mod n` where `R = 2^256`. Used to convert an integer `a`
/// into Montgomery form: `mont_mul(a, R^2) = a · R mod n`.
const R2_MOD_N: [u64; 4] = [
    0x8324_4c95_be79_eea2,
    0x4699_799c_49bd_6fa6,
    0x2845_b239_2b6b_ec59,
    0x66e1_2d94_f3d9_5620,
];

// ------------------------------------------------------------------
// Public type
// ------------------------------------------------------------------

/// An element of the P-256 scalar field `Z/nZ` in Montgomery form.
///
/// The internal representation is `value · R mod n` where `R = 2^256`.
/// Use [`Scalar::from_bytes`] / [`Scalar::to_bytes`] to move between
/// big-endian byte strings (the SEC1 scalar encoding) and this type.
#[derive(Copy, Clone, Debug)]
pub struct Scalar {
    limbs: [u64; 4],
}

impl Scalar {
    /// The additive identity (`0`).
    pub const ZERO: Scalar = Scalar { limbs: [0; 4] };

    /// The multiplicative identity (`1`). Stored as `R mod n`.
    pub const ONE: Scalar = Scalar { limbs: R_MOD_N };

    /// Decode a big-endian 32-byte scalar encoding, rejecting values
    /// `>= n`.
    ///
    /// Per FIPS 186-5 §6.4 and SEC1 §2.3.8, an ECDSA scalar must be in
    /// `[1, n-1]`. This constructor only enforces the upper bound;
    /// callers that need to exclude zero (e.g. sign/verify) must do so
    /// themselves using [`Scalar::is_zero`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
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
        // Reject raw >= n. Unsigned borrow chain; constant time in the
        // input bytes up to the canonicalization check.
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let diff = (raw[i] as u128)
                .wrapping_sub(N[i] as u128)
                .wrapping_sub(borrow);
            borrow = (diff >> 127) & 1;
        }
        if borrow == 0 {
            return None;
        }
        Some(Scalar {
            limbs: mont_mul(&raw, &R2_MOD_N),
        })
    }

    /// Reduce a 32-byte big-endian integer mod `n`, returning the
    /// resulting `Scalar`.
    ///
    /// This is the "take whatever was in the hash, mod n" operation
    /// that FIPS 186-5 §6.4.1 calls for when deriving `e` from
    /// `SHA-256(M)`. Unlike [`Scalar::from_bytes`], it never rejects
    /// the input — the caller has already committed to reducing.
    pub fn from_bytes_reduced(bytes: &[u8; 32]) -> Scalar {
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
        // Conditionally subtract n up to twice. `raw` starts in
        // [0, 2^256), which is less than 2n since n > 2^255, so a
        // single subtraction is sufficient.
        let reduced = cond_sub_n(&raw, 0);
        Scalar {
            limbs: mont_mul(&reduced, &R2_MOD_N),
        }
    }

    /// Encode to a big-endian 32-byte string, the canonical SEC1
    /// scalar representation.
    pub fn to_bytes(&self) -> [u8; 32] {
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

    /// Scalar addition, `self + other mod n`.
    pub fn add(&self, other: &Scalar) -> Scalar {
        let mut sum = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let s = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        Scalar {
            limbs: cond_sub_n(&sum, carry as u64),
        }
    }

    /// Scalar subtraction, `self - other mod n`.
    pub fn sub(&self, other: &Scalar) -> Scalar {
        let mut diff = [0u64; 4];
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let d = (self.limbs[i] as u128)
                .wrapping_sub(other.limbs[i] as u128)
                .wrapping_sub(borrow);
            diff[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        let mask = 0u64.wrapping_sub(borrow as u64);
        let mut carry: u128 = 0;
        for i in 0..4 {
            let s = (diff[i] as u128) + ((N[i] & mask) as u128) + carry;
            diff[i] = s as u64;
            carry = s >> 64;
        }
        let _ = carry;
        Scalar { limbs: diff }
    }

    /// Scalar negation, `-self mod n`.
    pub fn neg(&self) -> Scalar {
        Scalar::ZERO.sub(self)
    }

    /// Scalar multiplication via Montgomery multiplication.
    pub fn mul(&self, other: &Scalar) -> Scalar {
        Scalar {
            limbs: mont_mul(&self.limbs, &other.limbs),
        }
    }

    /// Scalar squaring. Routes through [`Scalar::mul`]; a dedicated
    /// squaring is a Phase 4 optimization.
    pub fn square(&self) -> Scalar {
        self.mul(self)
    }

    /// Multiplicative inverse via Fermat's little theorem:
    /// `self^(n-2) mod n`.
    ///
    /// Returns `Scalar::ZERO` if `self == 0`. ECDSA sign/verify treat
    /// zero as an error condition separately.
    pub fn invert(&self) -> Scalar {
        // n - 2 as big-endian bytes, pinned:
        //   n - 2 = 0xffffffff00000000ffffffffffffffff
        //           bce6faada7179e84f3b9cac2fc63254f
        const N_MINUS_2: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, //
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, //
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f, //
        ];

        let mut result = Scalar::ONE;
        for byte in N_MINUS_2 {
            for bit_idx in (0..8).rev() {
                result = result.square();
                let bit = (byte >> bit_idx) & 1;
                let prod = result.mul(self);
                result = Scalar::conditional_select(&result, &prod, bit);
            }
        }
        result
    }

    /// Constant-time equality test. Returns `1` if the two scalars
    /// represent the same value, `0` otherwise.
    pub fn ct_eq(&self, other: &Scalar) -> u8 {
        let mut acc: u64 = 0;
        for i in 0..4 {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        (((acc | acc.wrapping_neg()) >> 63) ^ 1) as u8
    }

    /// Constant-time test for the zero scalar.
    pub fn is_zero(&self) -> u8 {
        self.ct_eq(&Scalar::ZERO)
    }

    /// Constant-time conditional select. Callers must pass
    /// `choice ∈ {0, 1}`.
    #[inline]
    pub fn conditional_select(a: &Scalar, b: &Scalar, choice: u8) -> Scalar {
        let mask = 0u64.wrapping_sub(choice as u64);
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = a.limbs[i] ^ (mask & (a.limbs[i] ^ b.limbs[i]));
        }
        Scalar { limbs: out }
    }

    /// Access the raw little-endian limbs. `pub(crate)` so the
    /// scalar-multiplication routine can read bits without exposing
    /// the representation publicly.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn limbs(&self) -> &[u64; 4] {
        &self.limbs
    }
}

// ------------------------------------------------------------------
// Low-level primitives
// ------------------------------------------------------------------

/// Montgomery multiplication mod `n` (SOS variant).
///
/// Inputs and outputs are canonical Montgomery representatives
/// (`< n`). Constant time in both operands.
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // Schoolbook 4x4 → 8 limb multiply.
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

    // Word-at-a-time Montgomery reduction.
    for i in 0..4 {
        let m = t[i].wrapping_mul(N_PRIME) as u128;
        let mut carry: u128 = 0;
        for j in 0..4 {
            let sum = m * (N[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = sum as u64;
            carry = sum >> 64;
        }
        // Propagate the tail carry through t[i+4..9] unconditionally.
        // An earlier draft had an `if carry == 0 { break; }` here,
        // which made the iteration count depend on whether the
        // intermediate carry happened to be zero — that is a secret-
        // dependent branch and the ct-validation harness picked it up
        // as a multi-thousand-sigma leak on `Scalar::mul` / `invert`.
        // Iterating the fixed upper bound is cheap (at most five
        // add-with-carry steps) and restores constant time.
        let mut k = i + 4;
        while k < 9 {
            let sum = (t[k] as u128) + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
        debug_assert!(carry == 0);
    }

    let r = [t[4], t[5], t[6], t[7]];
    let extra = t[8];
    cond_sub_n(&r, extra)
}

/// Conditional subtraction of `n` from a 4-limb value `r`, given an
/// optional carry-in `extra` (0 or 1). If `extra == 1` or `r >= n`,
/// returns `r - n`; otherwise returns `r`. Constant time.
fn cond_sub_n(r: &[u64; 4], extra: u64) -> [u64; 4] {
    let mut diff = [0u64; 4];
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let d = (r[i] as u128)
            .wrapping_sub(N[i] as u128)
            .wrapping_sub(borrow);
        diff[i] = d as u64;
        borrow = (d >> 127) & 1;
    }
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

    /// Big-endian byte encoding of `n`.
    const N_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, //
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51, //
    ];

    /// Big-endian byte encoding of `n - 1`.
    const N_MINUS_ONE_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, //
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, //
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50, //
    ];

    fn be(bytes: [u8; 32]) -> Scalar {
        Scalar::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn n_constant_matches_byte_encoding() {
        let mut expected = [0u8; 32];
        for i in 0..4 {
            let off = 24 - 8 * i;
            expected[off..off + 8].copy_from_slice(&N[i].to_be_bytes());
        }
        assert_eq!(expected, N_BYTES);
    }

    #[test]
    fn from_bytes_rejects_n_and_above() {
        assert!(Scalar::from_bytes(&N_BYTES).is_none());
        assert!(Scalar::from_bytes(&[0xffu8; 32]).is_none());
    }

    #[test]
    fn from_bytes_accepts_zero_one_and_n_minus_one() {
        assert!(Scalar::from_bytes(&[0u8; 32]).is_some());
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(Scalar::from_bytes(&one).is_some());
        assert!(Scalar::from_bytes(&N_MINUS_ONE_BYTES).is_some());
    }

    #[test]
    fn from_bytes_reduced_on_all_ones_equals_two_power_256_minus_1_mod_n() {
        // Python: (2**256 - 1) % n
        //   = 0x00000000ffffffff0000000000000000
        //     4319055258e8617b0c46353d039cdaae
        let all_ones = [0xffu8; 32];
        let reduced = Scalar::from_bytes_reduced(&all_ones);
        let expected_bytes: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x43, 0x19, 0x05, 0x52, 0x58, 0xe8, 0x61, 0x7b, //
            0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xae, //
        ];
        assert_eq!(reduced.to_bytes(), expected_bytes);
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
            N_MINUS_ONE_BYTES,
            [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
                0x43, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce,
                0x13, 0x37, 0xc0, 0xde,
            ],
        ];
        for v in vectors {
            let s = Scalar::from_bytes(v).unwrap();
            assert_eq!(&s.to_bytes(), v);
        }
    }

    #[test]
    fn add_zero_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ]);
        assert_eq!(a.add(&Scalar::ZERO).to_bytes(), a.to_bytes());
    }

    #[test]
    fn add_n_minus_one_plus_one_is_zero() {
        let n_minus_one = be(N_MINUS_ONE_BYTES);
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = be(one_bytes);
        assert_eq!(n_minus_one.add(&one).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn sub_one_from_zero_is_n_minus_one() {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = be(one_bytes);
        assert_eq!(Scalar::ZERO.sub(&one).to_bytes(), N_MINUS_ONE_BYTES);
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
        let a = be(N_MINUS_ONE_BYTES);
        assert_eq!(a.mul(&Scalar::ZERO).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn mul_one_is_identity() {
        let a = be([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ]);
        assert_eq!(a.mul(&Scalar::ONE).to_bytes(), a.to_bytes());
    }

    #[test]
    fn mul_n_minus_one_by_n_minus_one_is_one() {
        let n_minus_one = be(N_MINUS_ONE_BYTES);
        let result = n_minus_one.mul(&n_minus_one);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(result.to_bytes(), one);
    }

    #[test]
    fn mul_matches_python_reference() {
        // Python ground truth:
        //   n = 2^256 group order
        //   (a*b) mod n = 0xb4d6d9438844d836c6cb5b6b44225fc8
        //                 5e6a9a09c7fd8c58b0b3fa76e27bd682
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
        let expected: [u8; 32] = [
            0xb4, 0xd6, 0xd9, 0x43, 0x88, 0x44, 0xd8, 0x36, 0xc6, 0xcb, 0x5b, 0x6b, 0x44, 0x22,
            0x5f, 0xc8, 0x5e, 0x6a, 0x9a, 0x09, 0xc7, 0xfd, 0x8c, 0x58, 0xb0, 0xb3, 0xfa, 0x76,
            0xe2, 0x7b, 0xd6, 0x82,
        ];
        assert_eq!(a.mul(&b).to_bytes(), expected);
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
        assert_eq!(Scalar::ONE.invert().to_bytes(), Scalar::ONE.to_bytes());
    }

    #[test]
    fn invert_matches_python_reference() {
        // Python: a^-1 mod n
        //   = 0xf94f5713cb3fbcc25a0972457a5174cc
        //     23edda9d0d8c20c7665b45358f5111db
        let a = be([
            0x7e, 0xd6, 0x2b, 0xb2, 0xe3, 0x3a, 0xa2, 0x42, 0x63, 0x7b, 0x07, 0xbc, 0x1d, 0x48,
            0xa4, 0xc2, 0xcc, 0xbb, 0x40, 0xd3, 0xe7, 0x78, 0x87, 0xcd, 0x42, 0xa9, 0x73, 0x4c,
            0xba, 0x58, 0xea, 0x0a,
        ]);
        let expected: [u8; 32] = [
            0xf9, 0x4f, 0x57, 0x13, 0xcb, 0x3f, 0xbc, 0xc2, 0x5a, 0x09, 0x72, 0x45, 0x7a, 0x51,
            0x74, 0xcc, 0x23, 0xed, 0xda, 0x9d, 0x0d, 0x8c, 0x20, 0xc7, 0x66, 0x5b, 0x45, 0x35,
            0x8f, 0x51, 0x11, 0xdb,
        ];
        assert_eq!(a.invert().to_bytes(), expected);
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
        assert_eq!(Scalar::ZERO.is_zero(), 1);
        assert_eq!(Scalar::ONE.is_zero(), 0);
        assert_eq!(Scalar::ONE.ct_eq(&Scalar::ONE), 1);
        assert_eq!(Scalar::ZERO.ct_eq(&Scalar::ONE), 0);
    }
}
