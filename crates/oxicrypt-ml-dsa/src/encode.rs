//! Byte encoding/decoding for ML-DSA-87 key material and signatures.
//!
//! Bit-packing routines for polynomials at various bit widths:
//! - η packing (3 bits for η=2): secret key coefficients
//! - t₁ packing (10 bits): public key high part
//! - t₀ packing (13 bits): secret key low part
//! - z packing (20 bits): signature response vector
//! - Hint encoding/decoding: sparse ω+k format
//!
//! All packers use little-endian bit ordering.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::integer_division
)]

use crate::params::{
    CTILDE_LEN, D, ETA, ETA_PACKED, GAMMA1, H_PACKED, K, L, N, OMEGA, PK_LEN, Q, SIG_LEN, SK_LEN,
    T0_PACKED, T1_PACKED, Z_PACKED,
};
use crate::poly::{Poly, PolyVecK, PolyVecL};

// ========================================================================
// η-packing (η = 2 → coefficients in [-2, 2], stored as [0, 4])
// ========================================================================

/// Pack a polynomial with coefficients in [-η, η] into bytes.
///
/// For η = 2: each coefficient maps to [0, 4] (add η), and we pack
/// using 3 bits per coefficient → 96 bytes per polynomial.
pub(crate) fn pack_eta(poly: &Poly, buf: &mut [u8]) {
    debug_assert!(buf.len() >= ETA_PACKED);
    // 8 coefficients → 3 bytes
    for i in 0..N / 8 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            // Map from [-2, 2] to [0, 4]
            t[j] = (ETA - poly.coeffs[8 * i + j]) as u8;
        }
        // Pack 8 3-bit values into 3 bytes (24 bits)
        buf[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
        buf[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        buf[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

/// Unpack a polynomial with coefficients in [-η, η] from bytes.
pub(crate) fn unpack_eta(buf: &[u8], poly: &mut Poly) {
    debug_assert!(buf.len() >= ETA_PACKED);
    for i in 0..N / 8 {
        let b0 = buf[3 * i] as u32;
        let b1 = buf[3 * i + 1] as u32;
        let b2 = buf[3 * i + 2] as u32;

        poly.coeffs[8 * i] = ETA - (b0 & 7) as i32;
        poly.coeffs[8 * i + 1] = ETA - ((b0 >> 3) & 7) as i32;
        poly.coeffs[8 * i + 2] = ETA - (((b0 >> 6) | (b1 << 2)) & 7) as i32;
        poly.coeffs[8 * i + 3] = ETA - ((b1 >> 1) & 7) as i32;
        poly.coeffs[8 * i + 4] = ETA - ((b1 >> 4) & 7) as i32;
        poly.coeffs[8 * i + 5] = ETA - (((b1 >> 7) | (b2 << 1)) & 7) as i32;
        poly.coeffs[8 * i + 6] = ETA - ((b2 >> 2) & 7) as i32;
        poly.coeffs[8 * i + 7] = ETA - ((b2 >> 5) & 7) as i32;
    }
}

// ========================================================================
// t₁ packing (10 bits per coefficient)
// ========================================================================

/// Pack t₁ polynomial (coefficients in [0, 2^10)) into bytes.
/// 4 coefficients → 5 bytes.
pub(crate) fn pack_t1(poly: &Poly, buf: &mut [u8]) {
    debug_assert!(buf.len() >= T1_PACKED);
    for i in 0..N / 4 {
        let c0 = poly.coeffs[4 * i] as u32;
        let c1 = poly.coeffs[4 * i + 1] as u32;
        let c2 = poly.coeffs[4 * i + 2] as u32;
        let c3 = poly.coeffs[4 * i + 3] as u32;

        buf[5 * i] = c0 as u8;
        buf[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
        buf[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
        buf[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
        buf[5 * i + 4] = (c3 >> 2) as u8;
    }
}

/// Unpack t₁ polynomial from bytes.
pub(crate) fn unpack_t1(buf: &[u8], poly: &mut Poly) {
    debug_assert!(buf.len() >= T1_PACKED);
    for i in 0..N / 4 {
        let b0 = buf[5 * i] as u32;
        let b1 = buf[5 * i + 1] as u32;
        let b2 = buf[5 * i + 2] as u32;
        let b3 = buf[5 * i + 3] as u32;
        let b4 = buf[5 * i + 4] as u32;

        poly.coeffs[4 * i] = (b0 | (b1 << 8)) as i32 & 0x3FF;
        poly.coeffs[4 * i + 1] = ((b1 >> 2) | (b2 << 6)) as i32 & 0x3FF;
        poly.coeffs[4 * i + 2] = ((b2 >> 4) | (b3 << 4)) as i32 & 0x3FF;
        poly.coeffs[4 * i + 3] = ((b3 >> 6) | (b4 << 2)) as i32 & 0x3FF;
    }
}

// ========================================================================
// t₀ packing (13 bits per coefficient, signed: centered in [-2^(d-1), 2^(d-1)])
// ========================================================================

/// Pack t₀ polynomial (coefficients in (−2^(d−1), 2^(d−1)]) into bytes.
/// Each coefficient is mapped to [0, 2^d) first.
/// 8 coefficients → 13 bytes.
pub(crate) fn pack_t0(poly: &Poly, buf: &mut [u8]) {
    debug_assert!(buf.len() >= T0_PACKED);
    let half = 1i32 << (D - 1); // 4096
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for j in 0..8 {
            // Map from (−4096, 4096] to [0, 8192)
            // t₀ ∈ (−2^12, 2^12], we store (2^12 − t₀) which is in [0, 2^13)
            t[j] = (half - poly.coeffs[8 * i + j]) as u32;
        }
        buf[13 * i] = t[0] as u8;
        buf[13 * i + 1] = (t[0] >> 8) as u8 | (t[1] << 5) as u8;
        buf[13 * i + 2] = (t[1] >> 3) as u8;
        buf[13 * i + 3] = (t[1] >> 11) as u8 | (t[2] << 2) as u8;
        buf[13 * i + 4] = (t[2] >> 6) as u8 | (t[3] << 7) as u8;
        buf[13 * i + 5] = (t[3] >> 1) as u8;
        buf[13 * i + 6] = (t[3] >> 9) as u8 | (t[4] << 4) as u8;
        buf[13 * i + 7] = (t[4] >> 4) as u8;
        buf[13 * i + 8] = (t[4] >> 12) as u8 | (t[5] << 1) as u8;
        buf[13 * i + 9] = (t[5] >> 7) as u8 | (t[6] << 6) as u8;
        buf[13 * i + 10] = (t[6] >> 2) as u8;
        buf[13 * i + 11] = (t[6] >> 10) as u8 | (t[7] << 3) as u8;
        buf[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack t₀ polynomial from bytes.
pub(crate) fn unpack_t0(buf: &[u8], poly: &mut Poly) {
    debug_assert!(buf.len() >= T0_PACKED);
    let half = 1i32 << (D - 1);
    for i in 0..N / 8 {
        let b = |idx: usize| buf[13 * i + idx] as u32;

        let t0 = b(0) | (b(1) << 8);
        let t1 = (b(1) >> 5) | (b(2) << 3) | (b(3) << 11);
        let t2 = (b(3) >> 2) | (b(4) << 6);
        let t3 = (b(4) >> 7) | (b(5) << 1) | (b(6) << 9);
        let t4 = (b(6) >> 4) | (b(7) << 4) | (b(8) << 12);
        let t5 = (b(8) >> 1) | (b(9) << 7);
        let t6 = (b(9) >> 6) | (b(10) << 2) | (b(11) << 10);
        let t7 = (b(11) >> 3) | (b(12) << 5);

        poly.coeffs[8 * i] = half - (t0 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 1] = half - (t1 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 2] = half - (t2 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 3] = half - (t3 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 4] = half - (t4 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 5] = half - (t5 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 6] = half - (t6 & 0x1FFF) as i32;
        poly.coeffs[8 * i + 7] = half - (t7 & 0x1FFF) as i32;
    }
}

// ========================================================================
// z packing (20 bits per coefficient, signed: γ₁ − coefficient)
// ========================================================================

/// Pack z polynomial (coefficients in [0, q), representing centered
/// values in [−γ₁+β+1, γ₁−β−1]) into bytes.
/// Each coefficient is mapped to [0, 2γ₁) = [0, 2^20).
/// 4 coefficients → 10 bytes.
pub(crate) fn pack_z(poly: &Poly, buf: &mut [u8]) {
    debug_assert!(buf.len() >= Z_PACKED);
    for i in 0..N / 4 {
        let mut t = [0u32; 4];
        for j in 0..4 {
            // Center coefficient: if > (q-1)/2, interpret as negative
            let mut c = poly.coeffs[4 * i + j];
            if c > (Q - 1) / 2 {
                c -= Q;
            }
            t[j] = (GAMMA1 - c) as u32;
        }
        buf[10 * i] = t[0] as u8;
        buf[10 * i + 1] = (t[0] >> 8) as u8;
        buf[10 * i + 2] = (t[0] >> 16) as u8 | (t[1] << 4) as u8;
        buf[10 * i + 3] = (t[1] >> 4) as u8;
        buf[10 * i + 4] = (t[1] >> 12) as u8;
        buf[10 * i + 5] = t[2] as u8;
        buf[10 * i + 6] = (t[2] >> 8) as u8;
        buf[10 * i + 7] = (t[2] >> 16) as u8 | (t[3] << 4) as u8;
        buf[10 * i + 8] = (t[3] >> 4) as u8;
        buf[10 * i + 9] = (t[3] >> 12) as u8;
    }
}

/// Unpack z polynomial from bytes.
pub(crate) fn unpack_z(buf: &[u8], poly: &mut Poly) {
    debug_assert!(buf.len() >= Z_PACKED);
    for i in 0..N / 4 {
        let b = |idx: usize| buf[10 * i + idx] as u32;

        let t0 = b(0) | (b(1) << 8) | ((b(2) & 0x0F) << 16);
        let t1 = (b(2) >> 4) | (b(3) << 4) | (b(4) << 12);
        let t2 = b(5) | (b(6) << 8) | ((b(7) & 0x0F) << 16);
        let t3 = (b(7) >> 4) | (b(8) << 4) | (b(9) << 12);

        poly.coeffs[4 * i] = GAMMA1 - (t0 & 0xFFFFF) as i32;
        poly.coeffs[4 * i + 1] = GAMMA1 - (t1 & 0xFFFFF) as i32;
        poly.coeffs[4 * i + 2] = GAMMA1 - (t2 & 0xFFFFF) as i32;
        poly.coeffs[4 * i + 3] = GAMMA1 - (t3 & 0xFFFFF) as i32;
    }
}

// ========================================================================
// Hint encoding — FIPS 204 §7.2 (sorted index list)
// ========================================================================

/// Pack the hint vector h into the signature's hint encoding.
///
/// Format: for each of the k polynomials, write the indices of nonzero
/// coefficients (sorted), then a terminator byte giving the running
/// count. Total: ω + k bytes.
///
/// Returns `true` on success, `false` if the total hint weight exceeds ω.
pub(crate) fn pack_hint(h: &PolyVecK, buf: &mut [u8]) -> bool {
    debug_assert!(buf.len() >= H_PACKED);
    for b in buf.iter_mut().take(H_PACKED) {
        *b = 0;
    }

    let mut offset = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h.polys[i].coeffs[j] != 0 {
                if offset >= OMEGA {
                    return false;
                }
                buf[offset] = j as u8;
                offset += 1;
            }
        }
        buf[OMEGA + i] = offset as u8;
    }
    true
}

/// Unpack the hint vector from the signature.
///
/// Returns `true` on success, `false` if the encoding is malformed.
pub(crate) fn unpack_hint(buf: &[u8], h: &mut PolyVecK) -> bool {
    debug_assert!(buf.len() >= H_PACKED);

    // Clear h
    for p in &mut h.polys {
        for c in &mut p.coeffs {
            *c = 0;
        }
    }

    let mut prev_offset = 0u8;
    for i in 0..K {
        let cur_offset = buf[OMEGA + i];

        // Offsets must be non-decreasing and ≤ ω
        if cur_offset < prev_offset || cur_offset as usize > OMEGA {
            return false;
        }

        // Indices must be strictly increasing within each polynomial
        let mut prev_idx: Option<u8> = None;
        for k in (prev_offset as usize)..(cur_offset as usize) {
            let idx = buf[k];
            if idx as usize >= N {
                return false;
            }
            if let Some(p) = prev_idx {
                if idx <= p {
                    return false;
                }
            }
            h.polys[i].coeffs[idx as usize] = 1;
            prev_idx = Some(idx);
        }

        prev_offset = cur_offset;
    }

    // Remaining bytes (from offset to ω-1) must be zero
    for k in (prev_offset as usize)..OMEGA {
        if buf[k] != 0 {
            return false;
        }
    }

    true
}

// ========================================================================
// Full key/signature packing
// ========================================================================

/// Pack a public key: pk = ρ ‖ t₁_packed.
pub(crate) fn pack_pk(rho: &[u8; 32], t1: &PolyVecK, pk: &mut [u8]) {
    debug_assert!(pk.len() >= PK_LEN);
    pk[..32].copy_from_slice(rho);
    for i in 0..K {
        let off = 32 + i * T1_PACKED;
        pack_t1(&t1.polys[i], &mut pk[off..off + T1_PACKED]);
    }
}

/// Unpack a public key.
pub(crate) fn unpack_pk(pk: &[u8], rho: &mut [u8; 32], t1: &mut PolyVecK) {
    debug_assert!(pk.len() >= PK_LEN);
    rho.copy_from_slice(&pk[..32]);
    for i in 0..K {
        let off = 32 + i * T1_PACKED;
        unpack_t1(&pk[off..off + T1_PACKED], &mut t1.polys[i]);
    }
}

/// Pack a secret key: sk = ρ ‖ K ‖ tr ‖ s₁ ‖ s₂ ‖ t₀.
pub(crate) fn pack_sk(
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8; 64],
    s1: &PolyVecL,
    s2: &PolyVecK,
    t0: &PolyVecK,
    sk: &mut [u8],
) {
    debug_assert!(sk.len() >= SK_LEN);
    let mut off = 0;

    sk[off..off + 32].copy_from_slice(rho);
    off += 32;
    sk[off..off + 32].copy_from_slice(key);
    off += 32;
    sk[off..off + 64].copy_from_slice(tr);
    off += 64;

    for i in 0..L {
        pack_eta(&s1.polys[i], &mut sk[off..off + ETA_PACKED]);
        off += ETA_PACKED;
    }
    for i in 0..K {
        pack_eta(&s2.polys[i], &mut sk[off..off + ETA_PACKED]);
        off += ETA_PACKED;
    }
    for i in 0..K {
        pack_t0(&t0.polys[i], &mut sk[off..off + T0_PACKED]);
        off += T0_PACKED;
    }
}

/// Unpack a secret key.
pub(crate) fn unpack_sk(
    sk: &[u8],
    rho: &mut [u8; 32],
    key: &mut [u8; 32],
    tr: &mut [u8; 64],
    s1: &mut PolyVecL,
    s2: &mut PolyVecK,
    t0: &mut PolyVecK,
) {
    debug_assert!(sk.len() >= SK_LEN);
    let mut off = 0;

    rho.copy_from_slice(&sk[off..off + 32]);
    off += 32;
    key.copy_from_slice(&sk[off..off + 32]);
    off += 32;
    tr.copy_from_slice(&sk[off..off + 64]);
    off += 64;

    for i in 0..L {
        unpack_eta(&sk[off..off + ETA_PACKED], &mut s1.polys[i]);
        off += ETA_PACKED;
    }
    for i in 0..K {
        unpack_eta(&sk[off..off + ETA_PACKED], &mut s2.polys[i]);
        off += ETA_PACKED;
    }
    for i in 0..K {
        unpack_t0(&sk[off..off + T0_PACKED], &mut t0.polys[i]);
        off += T0_PACKED;
    }
}

/// Pack a signature: sig = c̃ ‖ z ‖ h.
pub(crate) fn pack_sig(ctilde: &[u8], z: &PolyVecL, h: &PolyVecK, sig: &mut [u8]) -> bool {
    debug_assert!(sig.len() >= SIG_LEN);
    debug_assert!(ctilde.len() == CTILDE_LEN);

    sig[..CTILDE_LEN].copy_from_slice(ctilde);
    let mut off = CTILDE_LEN;
    for i in 0..L {
        pack_z(&z.polys[i], &mut sig[off..off + Z_PACKED]);
        off += Z_PACKED;
    }
    pack_hint(h, &mut sig[off..off + H_PACKED])
}

/// Unpack a signature.
///
/// Returns `false` if the hint encoding is malformed.
pub(crate) fn unpack_sig(
    sig: &[u8],
    ctilde: &mut [u8],
    z: &mut PolyVecL,
    h: &mut PolyVecK,
) -> bool {
    if sig.len() < SIG_LEN {
        return false;
    }
    debug_assert!(ctilde.len() == CTILDE_LEN);

    ctilde.copy_from_slice(&sig[..CTILDE_LEN]);
    let mut off = CTILDE_LEN;
    for i in 0..L {
        unpack_z(&sig[off..off + Z_PACKED], &mut z.polys[i]);
        off += Z_PACKED;
    }
    unpack_hint(&sig[off..off + H_PACKED], h)
}
