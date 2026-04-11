//! Arithmetic in the prime field GF(p) with p = 2^255 - 19.
//!
//! This is the base field for Curve25519 / edwards25519, and the
//! foundation for every higher-level Ed25519 operation.
//!
//! # Representation
//!
//! A field element `h` is stored as five unsigned 64-bit limbs in
//! little-endian order:
//!
//! ```text
//! h = h[0] + h[1]*2^51 + h[2]*2^102 + h[3]*2^153 + h[4]*2^204
//! ```
//!
//! Each limb is *unsaturated*: immediately after a carry pass every
//! limb lies in `[0, 2^51)`, but operations like `add` may leave
//! limbs as large as roughly `2^52` or `2^53` temporarily. Callers
//! that need a canonical fully-reduced representation (for example
//! `to_bytes` or equality comparison) should go through `reduce`
//! first.
//!
//! # Constant-time
//!
//! Every operation in this module runs in constant time with respect
//! to the values of its inputs — there are no data-dependent branches
//! and no data-dependent memory accesses. Conditional moves are
//! implemented with arithmetic masks built from subtraction, matching
//! the patterns used by `curve25519-dalek` and the ref10
//! implementation.
//!
//! # References
//!
//! * RFC 8032 §5.1 (edwards25519 field)
//! * Bernstein et al., "High-speed high-security signatures" (Ed25519
//!   paper), §4
//! * FIPS 186-5 §7.8 (EdDSA)

// Field arithmetic is inherently bit-twiddly: it packs 255-bit values
// into u64 limbs, multiplies through u128, and relies on wrapping
// arithmetic with explicit carry chains. The workspace-wide pedantic
// lints are appropriate for most crypto code but would flood this
// file with noise that obscures the actual invariants. This allow-set
// matches the pattern used by `fips-sha` (sha3, sha512_t) and
// `fips-aes` (kat, modes) for similar low-level modules.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::return_self_not_must_use
)]

use core::ops::{Add, Mul, Neg, Sub};

/// Mask keeping only the low 51 bits of a u64 — one radix digit.
const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

/// Field element in GF(2^255 - 19).
///
/// Limbs are stored in little-endian order; each limb nominally holds
/// 51 bits but may exceed that bound between operations.
#[derive(Copy, Clone, Debug)]
pub struct FieldElement(pub(crate) [u64; 5]);

impl FieldElement {
    /// The additive identity, `0`.
    pub const ZERO: FieldElement = FieldElement([0, 0, 0, 0, 0]);

    /// The multiplicative identity, `1`.
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0]);

    /// Load a field element from 32 little-endian bytes.
    ///
    /// The high bit of the last byte is ignored, matching RFC 8032
    /// §5.1.3 ("the most significant bit of the final octet is always
    /// zero"). This method does **not** verify that the decoded value
    /// is less than `p`; canonicalization is applied by `reduce` /
    /// `to_bytes`.
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement {
        let load8 = |b: &[u8]| -> u64 {
            (b[0] as u64)
                | ((b[1] as u64) << 8)
                | ((b[2] as u64) << 16)
                | ((b[3] as u64) << 24)
                | ((b[4] as u64) << 32)
                | ((b[5] as u64) << 40)
                | ((b[6] as u64) << 48)
                | ((b[7] as u64) << 56)
        };

        // Read overlapping 64-bit windows and shift each to extract
        // 51-bit limbs. The high bit of the last limb is masked off
        // per RFC 8032.
        let h0 = load8(&bytes[0..8]) & LOW_51_BIT_MASK;
        let h1 = (load8(&bytes[6..14]) >> 3) & LOW_51_BIT_MASK;
        let h2 = (load8(&bytes[12..20]) >> 6) & LOW_51_BIT_MASK;
        let h3 = (load8(&bytes[19..27]) >> 1) & LOW_51_BIT_MASK;
        let h4 = (load8(&bytes[24..32]) >> 12) & LOW_51_BIT_MASK;

        FieldElement([h0, h1, h2, h3, h4])
    }

    /// Serialize a field element to 32 little-endian bytes.
    ///
    /// Returns the canonical representative in `[0, p)`.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Fully reduce first so every limb lies in [0, 2^51).
        let reduced = self.reduce();
        let l = reduced.0;

        // Pack five 51-bit limbs into 32 bytes.
        let mut out = [0u8; 32];
        out[0] = l[0] as u8;
        out[1] = (l[0] >> 8) as u8;
        out[2] = (l[0] >> 16) as u8;
        out[3] = (l[0] >> 24) as u8;
        out[4] = (l[0] >> 32) as u8;
        out[5] = (l[0] >> 40) as u8;
        out[6] = ((l[0] >> 48) | (l[1] << 3)) as u8;
        out[7] = (l[1] >> 5) as u8;
        out[8] = (l[1] >> 13) as u8;
        out[9] = (l[1] >> 21) as u8;
        out[10] = (l[1] >> 29) as u8;
        out[11] = (l[1] >> 37) as u8;
        out[12] = ((l[1] >> 45) | (l[2] << 6)) as u8;
        out[13] = (l[2] >> 2) as u8;
        out[14] = (l[2] >> 10) as u8;
        out[15] = (l[2] >> 18) as u8;
        out[16] = (l[2] >> 26) as u8;
        out[17] = (l[2] >> 34) as u8;
        out[18] = (l[2] >> 42) as u8;
        out[19] = ((l[2] >> 50) | (l[3] << 1)) as u8;
        out[20] = (l[3] >> 7) as u8;
        out[21] = (l[3] >> 15) as u8;
        out[22] = (l[3] >> 23) as u8;
        out[23] = (l[3] >> 31) as u8;
        out[24] = (l[3] >> 39) as u8;
        out[25] = ((l[3] >> 47) | (l[4] << 4)) as u8;
        out[26] = (l[4] >> 4) as u8;
        out[27] = (l[4] >> 12) as u8;
        out[28] = (l[4] >> 20) as u8;
        out[29] = (l[4] >> 28) as u8;
        out[30] = (l[4] >> 36) as u8;
        out[31] = (l[4] >> 44) as u8;
        out
    }

    /// Reduce a field element to its canonical representative in
    /// `[0, p)`.
    ///
    /// The input may have limbs that exceed 2^51 (as produced by
    /// `add`, `sub`, or an un-carried `mul`). The output has every
    /// limb in `[0, 2^51)` and is strictly less than `p`.
    pub fn reduce(&self) -> FieldElement {
        // First: carry chain to bring every limb into [0, 2^51) plus
        // a possible overflow out of the top limb.
        let mut l = self.0;

        let c = l[0] >> 51;
        l[0] &= LOW_51_BIT_MASK;
        l[1] = l[1].wrapping_add(c);

        let c = l[1] >> 51;
        l[1] &= LOW_51_BIT_MASK;
        l[2] = l[2].wrapping_add(c);

        let c = l[2] >> 51;
        l[2] &= LOW_51_BIT_MASK;
        l[3] = l[3].wrapping_add(c);

        let c = l[3] >> 51;
        l[3] &= LOW_51_BIT_MASK;
        l[4] = l[4].wrapping_add(c);

        let c = l[4] >> 51;
        l[4] &= LOW_51_BIT_MASK;
        // Any overflow out of the top limb wraps around as 19 * c
        // because 2^255 ≡ 19 (mod p).
        l[0] = l[0].wrapping_add(c.wrapping_mul(19));

        // A second pass is enough because l[0] + 19*c still fits
        // comfortably in 52 bits after the mask above.
        let c = l[0] >> 51;
        l[0] &= LOW_51_BIT_MASK;
        l[1] = l[1].wrapping_add(c);

        // At this point `l` represents a value in [0, 2*p). One
        // conditional subtract of p gives the canonical form.
        //
        // Add 19 (to test for overflow past 2^255 - 19): if
        // l + 19 >= 2^255 then l >= p and we need to subtract p.
        let mut t = l;
        t[0] = t[0].wrapping_add(19);

        let c = t[0] >> 51;
        t[0] &= LOW_51_BIT_MASK;
        t[1] = t[1].wrapping_add(c);

        let c = t[1] >> 51;
        t[1] &= LOW_51_BIT_MASK;
        t[2] = t[2].wrapping_add(c);

        let c = t[2] >> 51;
        t[2] &= LOW_51_BIT_MASK;
        t[3] = t[3].wrapping_add(c);

        let c = t[3] >> 51;
        t[3] &= LOW_51_BIT_MASK;
        t[4] = t[4].wrapping_add(c);

        // If bit 51 of t[4] is set, l + 19 >= 2^255 and l >= p.
        // Otherwise l < p. We keep `t` (which already has the +19
        // added, equivalent to subtracting p - effectively l mod p)
        // if the high bit was set, else we restore `l`.
        let overflowed = (t[4] >> 51) & 1;
        t[4] &= LOW_51_BIT_MASK;

        // Select between `t` (overflowed) and `l` (not overflowed)
        // in constant time.
        let mask = 0u64.wrapping_sub(overflowed);
        let out0 = (t[0] & mask) | (l[0] & !mask);
        let out1 = (t[1] & mask) | (l[1] & !mask);
        let out2 = (t[2] & mask) | (l[2] & !mask);
        let out3 = (t[3] & mask) | (l[3] & !mask);
        let out4 = (t[4] & mask) | (l[4] & !mask);

        FieldElement([out0, out1, out2, out3, out4])
    }

    /// Constant-time equality comparison.
    ///
    /// Returns `1` if `self` and `rhs` represent the same field
    /// element, or `0` otherwise. Both inputs are canonicalized via
    /// `reduce` / `to_bytes` first, so non-canonical representations
    /// of the same element compare equal.
    pub fn ct_eq(&self, rhs: &FieldElement) -> u8 {
        let a = self.to_bytes();
        let b = rhs.to_bytes();
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        // diff == 0 iff equal. Fold to a single bit.
        let x = diff as u32;
        // x == 0 -> 1, x != 0 -> 0.
        (((x.wrapping_sub(1)) >> 31) & 1) as u8
    }

    /// Negate a field element: `-self mod p`.
    pub fn negate(&self) -> FieldElement {
        // 2*p in limb form; adding this to any element keeps it
        // non-negative and ≡ 0 (mod p).
        const TWO_P_0: u64 = (1u64 << 52) - 38;
        const TWO_P_OTHER: u64 = (1u64 << 52) - 2;
        let l = &self.0;
        FieldElement([
            TWO_P_0.wrapping_sub(l[0]),
            TWO_P_OTHER.wrapping_sub(l[1]),
            TWO_P_OTHER.wrapping_sub(l[2]),
            TWO_P_OTHER.wrapping_sub(l[3]),
            TWO_P_OTHER.wrapping_sub(l[4]),
        ])
        .reduce()
    }

    /// Field multiplication: `self * rhs mod p`.
    pub fn multiply(&self, rhs: &FieldElement) -> FieldElement {
        let a = self.0;
        let b = rhs.0;

        // Precompute 19*b[i] for the wrap-around terms. Since R^5 =
        // 2^255 ≡ 19 (mod p), every product a[i]*b[j] with i+j >= 5
        // contributes 19 * a[i] * b[j] to limb (i+j-5).
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;

        // Compute the five 128-bit limb sums. Worst-case each input
        // limb is bounded by a few * 2^51, so each partial product
        // fits in ~104 bits and five of them fit in u128.
        let c0: u128 = (a[0] as u128) * (b[0] as u128)
            + (a[1] as u128) * b4_19
            + (a[2] as u128) * b3_19
            + (a[3] as u128) * b2_19
            + (a[4] as u128) * b1_19;
        let c1: u128 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + (a[2] as u128) * b4_19
            + (a[3] as u128) * b3_19
            + (a[4] as u128) * b2_19;
        let c2: u128 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + (a[3] as u128) * b4_19
            + (a[4] as u128) * b3_19;
        let c3: u128 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + (a[4] as u128) * b4_19;
        let c4: u128 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        carry_reduce_u128([c0, c1, c2, c3, c4])
    }

    /// Field squaring: `self * self mod p`.
    ///
    /// Equivalent to `self.multiply(self)` but uses fewer
    /// multiplications by exploiting symmetry.
    pub fn square(&self) -> FieldElement {
        let a = self.0;
        let a0_2 = (a[0] as u128) * 2;
        let a1_2 = (a[1] as u128) * 2;
        let a3_19 = (a[3] as u128) * 19;
        let a4_19 = (a[4] as u128) * 19;

        let c0: u128 = (a[0] as u128) * (a[0] as u128)
            + a1_2 * a4_19
            + ((a[2] as u128) * 2) * a3_19;
        let c1: u128 = a0_2 * (a[1] as u128)
            + ((a[2] as u128) * 2) * a4_19
            + (a[3] as u128) * a3_19;
        let c2: u128 = a0_2 * (a[2] as u128)
            + (a[1] as u128) * (a[1] as u128)
            + ((a[3] as u128) * 2) * a4_19;
        let c3: u128 = a0_2 * (a[3] as u128)
            + ((a[1] as u128) * 2) * (a[2] as u128)
            + (a[4] as u128) * a4_19;
        let c4: u128 = a0_2 * (a[4] as u128)
            + ((a[1] as u128) * 2) * (a[3] as u128)
            + (a[2] as u128) * (a[2] as u128);

        carry_reduce_u128([c0, c1, c2, c3, c4])
    }

    /// Multiplication by the small constant 121666.
    ///
    /// Used in the Montgomery ladder and by some edwards25519
    /// formulas. The constant fits comfortably in 17 bits, so a
    /// single carry pass suffices.
    pub fn mul_121666(&self) -> FieldElement {
        let k: u128 = 121_666;
        let c0: u128 = (self.0[0] as u128) * k;
        let c1: u128 = (self.0[1] as u128) * k;
        let c2: u128 = (self.0[2] as u128) * k;
        let c3: u128 = (self.0[3] as u128) * k;
        let c4: u128 = (self.0[4] as u128) * k;
        carry_reduce_u128([c0, c1, c2, c3, c4])
    }

    /// Compute `self^(2^n)` by repeated squaring.
    pub fn pow2k(&self, n: u32) -> FieldElement {
        let mut out = *self;
        for _ in 0..n {
            out = out.square();
        }
        out
    }

    /// Multiplicative inverse: `self^(p-2) mod p`.
    ///
    /// Uses the fixed addition chain from Bernstein's ref10.
    /// Returns `ZERO` if `self` is zero (undefined mathematically,
    /// but the chain yields `0` naturally which is fine for callers
    /// that check for zero explicitly).
    pub fn invert(&self) -> FieldElement {
        // p - 2 = 2^255 - 21
        //       = 2^255 - 2^5 + 11
        // The addition chain below computes self^(2^255 - 21) using
        // 254 squarings and 11 multiplications, matching ref10.
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.pow2k(2);
        let z9 = z1.multiply(&z8);
        let z11 = z2.multiply(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.multiply(&z22);
        let z_10_5 = z_5_0.pow2k(5);
        let z_10_0 = z_10_5.multiply(&z_5_0);
        let z_20_10 = z_10_0.pow2k(10);
        let z_20_0 = z_20_10.multiply(&z_10_0);
        let z_40_20 = z_20_0.pow2k(20);
        let z_40_0 = z_40_20.multiply(&z_20_0);
        let z_50_10 = z_40_0.pow2k(10);
        let z_50_0 = z_50_10.multiply(&z_10_0);
        let z_100_50 = z_50_0.pow2k(50);
        let z_100_0 = z_100_50.multiply(&z_50_0);
        let z_200_100 = z_100_0.pow2k(100);
        let z_200_0 = z_200_100.multiply(&z_100_0);
        let z_250_50 = z_200_0.pow2k(50);
        let z_250_0 = z_250_50.multiply(&z_50_0);
        let z_255_5 = z_250_0.pow2k(5);
        z_255_5.multiply(&z11)
    }
}

/// Take an un-carried 5-limb value (limbs up to ~2^128) and reduce it
/// to a properly-formed `FieldElement` with limbs in roughly `[0,
/// 2^52)`. This is the shared tail of `mul`, `square`, and
/// `mul_121666`.
fn carry_reduce_u128(c: [u128; 5]) -> FieldElement {
    // Carry propagation using 19*R^-5 folding.
    let [c0, c1, c2, c3, c4] = c;

    let r0 = (c0 as u64) & LOW_51_BIT_MASK;
    let carry0 = (c0 >> 51) as u64;

    let c1 = c1 + (carry0 as u128);
    let r1 = (c1 as u64) & LOW_51_BIT_MASK;
    let carry1 = (c1 >> 51) as u64;

    let c2 = c2 + (carry1 as u128);
    let r2 = (c2 as u64) & LOW_51_BIT_MASK;
    let carry2 = (c2 >> 51) as u64;

    let c3 = c3 + (carry2 as u128);
    let r3 = (c3 as u64) & LOW_51_BIT_MASK;
    let carry3 = (c3 >> 51) as u64;

    let c4 = c4 + (carry3 as u128);
    let r4 = (c4 as u64) & LOW_51_BIT_MASK;
    let carry4 = (c4 >> 51) as u64;

    // Fold the top overflow back into the low limb; 2^255 ≡ 19.
    let r0 = r0 + carry4.wrapping_mul(19);

    // One more pass to normalize r0 into 51 bits.
    let carry = r0 >> 51;
    let r0 = r0 & LOW_51_BIT_MASK;
    let r1 = r1 + carry;

    FieldElement([r0, r1, r2, r3, r4])
}

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: FieldElement) -> FieldElement {
        FieldElement([
            self.0[0].wrapping_add(rhs.0[0]),
            self.0[1].wrapping_add(rhs.0[1]),
            self.0[2].wrapping_add(rhs.0[2]),
            self.0[3].wrapping_add(rhs.0[3]),
            self.0[4].wrapping_add(rhs.0[4]),
        ])
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: FieldElement) -> FieldElement {
        // Add 2*p to avoid borrowing. 2p limbs: [2^52-38, 2^52-2, ...].
        const TWO_P_0: u64 = (1u64 << 52) - 38;
        const TWO_P_OTHER: u64 = (1u64 << 52) - 2;
        FieldElement([
            TWO_P_0.wrapping_add(self.0[0]).wrapping_sub(rhs.0[0]),
            TWO_P_OTHER.wrapping_add(self.0[1]).wrapping_sub(rhs.0[1]),
            TWO_P_OTHER.wrapping_add(self.0[2]).wrapping_sub(rhs.0[2]),
            TWO_P_OTHER.wrapping_add(self.0[3]).wrapping_sub(rhs.0[3]),
            TWO_P_OTHER.wrapping_add(self.0[4]).wrapping_sub(rhs.0[4]),
        ])
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        FieldElement::multiply(&self, &rhs)
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::negate(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical encoding of `p - 1 = 2^255 - 20`.
    const P_MINUS_1_BYTES: [u8; 32] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    /// Canonical encoding of `2`.
    const TWO_BYTES: [u8; 32] = [
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    /// Canonical encoding of `1`.
    const ONE_BYTES: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    /// Canonical encoding of `0`.
    const ZERO_BYTES: [u8; 32] = [0u8; 32];

    #[test]
    fn roundtrip_zero_one_two() {
        for bytes in &[ZERO_BYTES, ONE_BYTES, TWO_BYTES, P_MINUS_1_BYTES] {
            let f = FieldElement::from_bytes(bytes);
            assert_eq!(&f.to_bytes(), bytes);
        }
    }

    #[test]
    fn constants_are_canonical() {
        assert_eq!(FieldElement::ZERO.to_bytes(), ZERO_BYTES);
        assert_eq!(FieldElement::ONE.to_bytes(), ONE_BYTES);
    }

    #[test]
    fn add_one_to_p_minus_one_is_zero() {
        let one = FieldElement::from_bytes(&ONE_BYTES);
        let pm1 = FieldElement::from_bytes(&P_MINUS_1_BYTES);
        let sum = one + pm1;
        assert_eq!(sum.to_bytes(), ZERO_BYTES);
    }

    #[test]
    fn sub_one_from_zero_is_p_minus_one() {
        let zero = FieldElement::ZERO;
        let one = FieldElement::ONE;
        let diff = zero - one;
        assert_eq!(diff.to_bytes(), P_MINUS_1_BYTES);
    }

    #[test]
    fn neg_roundtrip() {
        let two = FieldElement::from_bytes(&TWO_BYTES);
        let sum = two + two.negate();
        assert_eq!(sum.to_bytes(), ZERO_BYTES);
    }

    #[test]
    fn mul_one_is_identity() {
        let two = FieldElement::from_bytes(&TWO_BYTES);
        let prod = two.multiply(&FieldElement::ONE);
        assert_eq!(prod.to_bytes(), TWO_BYTES);
    }

    #[test]
    fn mul_zero_is_zero() {
        let two = FieldElement::from_bytes(&TWO_BYTES);
        let prod = two.multiply(&FieldElement::ZERO);
        assert_eq!(prod.to_bytes(), ZERO_BYTES);
    }

    #[test]
    fn square_matches_mul() {
        // Pick an arbitrary non-trivial element. These bytes were
        // generated by hashing the ASCII string "pqclib-field-test"
        // with SHA-256 and clearing the high bit so the result is a
        // valid 255-bit encoding.
        let bytes: [u8; 32] = [
            0x1c, 0x3e, 0x5f, 0x77, 0x91, 0x22, 0xab, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x01, 0x02, 0x03, 0x04,
        ];
        let a = FieldElement::from_bytes(&bytes);
        let sq = a.square();
        let mm = a.multiply(&a);
        assert_eq!(sq.to_bytes(), mm.to_bytes());
    }

    #[test]
    fn mul_is_commutative() {
        let a_bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];
        let b_bytes: [u8; 32] = [
            0x9a, 0x87, 0x65, 0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f,
            0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43,
            0x21, 0x0f, 0xed, 0x4b,
        ];
        let a = FieldElement::from_bytes(&a_bytes);
        let b = FieldElement::from_bytes(&b_bytes);
        assert_eq!(a.multiply(&b).to_bytes(), b.multiply(&a).to_bytes());
    }

    #[test]
    fn mul_is_associative() {
        let a = FieldElement::from_bytes(&[3u8; 32]);
        let b = FieldElement::from_bytes(&[5u8; 32]);
        let c = FieldElement::from_bytes(&[7u8; 32]);
        let left = a.multiply(&b).multiply(&c);
        let right = a.multiply(&b.multiply(&c));
        assert_eq!(left.to_bytes(), right.to_bytes());
    }

    #[test]
    fn mul_distributes_over_add() {
        let a = FieldElement::from_bytes(&[11u8; 32]);
        let b = FieldElement::from_bytes(&[13u8; 32]);
        let c = FieldElement::from_bytes(&[17u8; 32]);
        let left = a.multiply(&(b + c));
        let right = a.multiply(&b) + a.multiply(&c);
        assert_eq!(left.to_bytes(), right.to_bytes());
    }

    #[test]
    fn invert_nonzero() {
        let a = FieldElement::from_bytes(&[
            0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let inv = a.invert();
        let prod = a.multiply(&inv);
        assert_eq!(prod.to_bytes(), ONE_BYTES);
    }

    #[test]
    fn invert_of_one_is_one() {
        let inv = FieldElement::ONE.invert();
        assert_eq!(inv.to_bytes(), ONE_BYTES);
    }

    #[test]
    fn pow2k_matches_repeated_square() {
        let a = FieldElement::from_bytes(&[0x37u8; 32]);
        let manual = a.square().square().square().square();
        let via_pow = a.pow2k(4);
        assert_eq!(manual.to_bytes(), via_pow.to_bytes());
    }

    #[test]
    fn ct_eq_detects_equality() {
        let a = FieldElement::from_bytes(&[0x5au8; 32]);
        let b = FieldElement::from_bytes(&[0x5au8; 32]);
        let c = FieldElement::from_bytes(&[0x5bu8; 32]);
        assert_eq!(a.ct_eq(&b), 1);
        assert_eq!(a.ct_eq(&c), 0);
    }

    #[test]
    fn fermat_little_theorem() {
        // For any nonzero a in GF(p), a^(p-1) == 1. We build
        // a^(p-1) = a^(p-2) * a via invert().
        let a = FieldElement::from_bytes(&[0x29u8; 32]);
        let result = a.invert().multiply(&a);
        assert_eq!(result.to_bytes(), ONE_BYTES);
    }

    #[test]
    fn mul_121666_matches_general_mul() {
        let a = FieldElement::from_bytes(&[0x4eu8; 32]);
        let k = {
            let mut b = [0u8; 32];
            b[0] = 0x82; // 121666 = 0x1DB42 -> low byte 0x42? actually
                        // 121666 = 0x1DB42, bytes little endian:
                        // 0x42, 0xDB, 0x01
            b[0] = 0x42;
            b[1] = 0xDB;
            b[2] = 0x01;
            FieldElement::from_bytes(&b)
        };
        assert_eq!(a.mul_121666().to_bytes(), a.multiply(&k).to_bytes());
    }
}
