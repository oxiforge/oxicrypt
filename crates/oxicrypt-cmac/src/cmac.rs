//! AES-CMAC per NIST SP 800-38B.
//!
//! # Scope
//!
//! Implements CMAC with AES-128 / AES-192 / AES-256 as the underlying
//! block cipher. This is the MAC-only construction defined in
//! SP 800-38B; the CBC-MAC variants referenced from other NIST
//! documents are not in scope here.
//!
//! The implementation is a direct transcription of the algorithms in
//! SP 800-38B:
//!
//!   * **Subkey generation** (§6.1 "Subkey Generation Algorithm"):
//!     L = CIPH_K(0^128); K1 = L · x; K2 = L · x^2, with the left
//!     shift and conditional XOR of the block-size-specific constant
//!     R_b = 0x87 for 128-bit blocks.
//!   * **MAC generation** (§6.2 "MAC Generation Algorithm"):
//!     split the message into n 128-bit blocks (with zero-padding of
//!     the final block if needed, including for the empty message),
//!     XOR the final block with K1 (if the last block was complete)
//!     or K2 (if it was padded), and CBC-MAC with IV = 0^128. The
//!     tag is the final CBC output truncated to Tlen.
//!
//! Per SP 800-38B the minimum Tlen is 32 bits. This crate exposes
//! fixed full-length 128-bit tags via [`cmac_tag`]. Callers that need
//! a shorter approved tag (Tlen ≥ 32) can truncate the returned tag.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop
)]

use oxicrypt_aes::{Aes128Key, Aes192Key, Aes256Key, BlockCipher};

/// AES block size in bytes. Always 16 for AES.
pub const BLOCK_SIZE: usize = 16;

/// Rb constant for 128-bit blocks, SP 800-38B §5.3 Table 1.
const RB_128: u8 = 0x87;

/// Derive the CMAC subkeys K1 and K2 from a block cipher.
///
/// Follows SP 800-38B §6.1 exactly: L = CIPH_K(0^128), then
/// K1 = L · x and K2 = L · x^2 in GF(2^128) with the polynomial
/// x^128 + x^7 + x^2 + x + 1 (so multiplication by x is a 1-bit left
/// shift, conditionally XOR'd with R_b = 0x87 if the high bit was
/// set).
fn derive_subkeys<B: BlockCipher>(cipher: &B) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    let mut l = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut l);
    let k1 = shift_with_rb(&l);
    let k2 = shift_with_rb(&k1);
    (k1, k2)
}

/// Multiply a 128-bit block by `x` in GF(2^128) with the GCM/CMAC
/// polynomial (big-endian bit order per SP 800-38B §5.3). Equivalent
/// to `(b << 1) ^ (msb(b) ? Rb : 0)`.
fn shift_with_rb(b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let msb = b[0] >> 7;
    let mut out = [0u8; BLOCK_SIZE];
    let mut carry: u8 = 0;
    let mut i = BLOCK_SIZE;
    while i > 0 {
        i -= 1;
        out[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    if msb == 1 {
        out[BLOCK_SIZE - 1] ^= RB_128;
    }
    out
}

/// Compute a full 128-bit AES-CMAC tag over `msg` using `cipher`.
///
/// Returns the tag `T = CIPH_K(C_{n-1} XOR M_n*)` from SP 800-38B
/// §6.2. The empty message is handled by the `if msg.is_empty()`
/// branch (n = 1, M_1* = 10^{b-1}).
pub fn cmac_tag<B: BlockCipher>(cipher: &B, msg: &[u8]) -> [u8; BLOCK_SIZE] {
    let (k1, k2) = derive_subkeys(cipher);

    // Partition into n 128-bit blocks; track whether the last block
    // is complete or needs padding.
    let complete_last = !msg.is_empty() && msg.len() % BLOCK_SIZE == 0;
    let n = if msg.is_empty() {
        1
    } else {
        msg.len().div_ceil(BLOCK_SIZE)
    };

    // CBC-MAC with IV = 0.
    let mut c = [0u8; BLOCK_SIZE];
    for i in 0..n - 1 {
        let start = i * BLOCK_SIZE;
        for k in 0..BLOCK_SIZE {
            c[k] ^= msg[start + k];
        }
        cipher.encrypt_block(&mut c);
    }

    // Final block M_n*: last 16 bytes of msg if complete_last, else
    // the trailing bytes padded with 0x80 0x00* to 16 bytes.
    let mut m_n = [0u8; BLOCK_SIZE];
    if complete_last {
        let start = (n - 1) * BLOCK_SIZE;
        m_n.copy_from_slice(&msg[start..start + BLOCK_SIZE]);
        for k in 0..BLOCK_SIZE {
            m_n[k] ^= k1[k];
        }
    } else {
        let start = (n - 1) * BLOCK_SIZE;
        let rem = msg.len() - start;
        m_n[..rem].copy_from_slice(&msg[start..]);
        m_n[rem] = 0x80;
        for k in 0..BLOCK_SIZE {
            m_n[k] ^= k2[k];
        }
    }

    for k in 0..BLOCK_SIZE {
        c[k] ^= m_n[k];
    }
    cipher.encrypt_block(&mut c);
    c
}

/// Compute an AES-128 CMAC tag.
pub fn cmac_aes128(key: &[u8; 16], msg: &[u8]) -> [u8; BLOCK_SIZE] {
    let k = Aes128Key::new(key);
    cmac_tag(&k, msg)
}

/// Compute an AES-192 CMAC tag.
pub fn cmac_aes192(key: &[u8; 24], msg: &[u8]) -> [u8; BLOCK_SIZE] {
    let k = Aes192Key::new(key);
    cmac_tag(&k, msg)
}

/// Compute an AES-256 CMAC tag.
pub fn cmac_aes256(key: &[u8; 32], msg: &[u8]) -> [u8; BLOCK_SIZE] {
    let k = Aes256Key::new(key);
    cmac_tag(&k, msg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{cmac_aes128, cmac_aes192, cmac_aes256};

    // SP 800-38B Appendix D.1 Example 1 — Mlen = 0, AES-128
    #[test]
    fn sp38b_d1_example1_aes128_empty() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expected: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        assert_eq!(cmac_aes128(&key, &[]), expected);
    }

    // SP 800-38B Appendix D.1 Example 2 — Mlen = 128, AES-128
    #[test]
    fn sp38b_d1_example2_aes128_one_block() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        assert_eq!(cmac_aes128(&key, &msg), expected);
    }

    // SP 800-38B Appendix D.2 Example 4 — Mlen = 512, AES-192
    #[test]
    fn sp38b_d2_example4_aes192_four_blocks() {
        let key: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let msg: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected: [u8; 16] = [
            0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79, 0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3,
            0x9a, 0x11,
        ];
        assert_eq!(cmac_aes192(&key, &msg), expected);
    }

    // SP 800-38B Appendix D.3 Example 3 — Mlen = 320, AES-256
    // (Partial final block — exercises the K2 subkey path.)
    #[test]
    fn sp38b_d3_example3_aes256_partial_block() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let msg: [u8; 40] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected: [u8; 16] = [
            0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9,
            0x11, 0xe6,
        ];
        assert_eq!(cmac_aes256(&key, &msg), expected);
    }
}
