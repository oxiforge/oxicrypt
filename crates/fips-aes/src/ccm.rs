//! AES Counter with CBC-MAC (CCM) per NIST SP 800-38C.
//!
//! # Scope
//!
//! Implements the full SP 800-38C authenticated encryption construction
//! (CCM-AE / CCM-AD) over the `BlockCipher` trait so the same code runs
//! across AES-128 / AES-192 / AES-256. The formatting and counter
//! generation functions follow Appendix A verbatim:
//!
//!   * **Formatting (`format_b0` + `format_associated_data`)** —
//!     Appendix A.2. The first formatting block `B0` packs the
//!     `Adata`/`Tlen`/`L` flags, the nonce `N`, and the plaintext
//!     length `Q = [Plen]_{8L}`. Associated data is prefixed with a
//!     length encoding that is 2 bytes, 6 bytes (`0xFFFE` prefix), or
//!     10 bytes (`0xFFFF` prefix) depending on its length.
//!   * **Counter block (`format_ctr`)** — Appendix A.3. The counter
//!     block has the same L/Nlen layout as `B0`, with the low L bytes
//!     holding the counter value i (starting at 0).
//!
//! Encryption proceeds in two passes per SP 800-38C §6.1 "CCM
//! Generation-Encryption Process":
//!
//!   1. Format the CBC-MAC input as
//!      `B0 || format(A) || zeropad(P)` and CBC-MAC it with IV = 0
//!      to obtain the raw tag `Y_r`.
//!   2. Derive the CTR keystream starting from block index 1 and XOR
//!      it with the plaintext. The tag output is
//!      `T = MSB_Tlen(Y_r XOR S_0)`, where `S_0 = CIPH_K(Ctr_0)`.
//!
//! Decryption (§6.2 "CCM Decryption-Verification Process") runs the
//! CTR keystream in reverse to recover the plaintext, then recomputes
//! the CBC-MAC over the same formatted input and verifies the
//! resulting tag against the transmitted tag in **constant time**. A
//! mismatch returns [`ModeError::TagMismatch`] and the recovered
//! plaintext is zeroised in the output buffer.
//!
//! # Parameter validation
//!
//! The call sites enforce the full SP 800-38C §5.3 parameter matrix:
//!
//!   * Nonce length `Nlen` ∈ {7, 8, 9, 10, 11, 12, 13}.
//!   * Tag length `Tlen` ∈ {4, 6, 8, 10, 12, 14, 16}.
//!   * Plaintext length `Plen` < `2^(8*(15 - Nlen))` (equivalently, `P`
//!     must be representable in the L-byte length field `Q`).
//!   * Associated-data length `Alen` < `2^64 - 2^16` (the §A.2.2 hard
//!     upper bound for the 10-byte `0xFFFF`-prefixed encoding).
//!
//! Out-of-range values return dedicated [`ModeError`] variants rather
//! than panicking.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop
)]

use crate::modes::{BlockCipher, ModeError};

/// AES block size in bytes. Always 16 for AES.
const B: usize = 16;

/// Valid nonce-length interval per SP 800-38C §5.3.
const NLEN_MIN: usize = 7;
const NLEN_MAX: usize = 13;

/// Valid tag-length set per SP 800-38C §5.3 (bytes, not bits).
const fn tlen_valid(tlen: usize) -> bool {
    matches!(tlen, 4 | 6 | 8 | 10 | 12 | 14 | 16)
}

/// Build the `B0` formatting block per SP 800-38C Appendix A.2.1.
///
/// Layout:
///
/// ```text
/// B0[0]   = flags
///         = (Adata?64:0)                // bit 6
///         | (((Tlen-2)/2) << 3)         // bits 3..5: (t-2)/2
///         | (L-1)                       // bits 0..2
/// B0[1..1+Nlen] = N
/// B0[1+Nlen..16] = Q  // Plen as L-byte big-endian
/// ```
fn format_b0(nonce: &[u8], adata_present: bool, tlen: usize, plen: u64) -> [u8; B] {
    let nlen = nonce.len();
    let l = B - 1 - nlen;
    let mut b0 = [0u8; B];
    let a_flag: u8 = if adata_present { 0x40 } else { 0 };
    let t_flag: u8 = (((tlen as u8) - 2) / 2) << 3;
    let l_flag: u8 = (l as u8) - 1;
    b0[0] = a_flag | t_flag | l_flag;
    b0[1..=nlen].copy_from_slice(nonce);
    // Encode plen into the trailing L bytes as big-endian. L ≤ 8 so
    // the length always fits in a u64.
    let mut q = plen;
    for i in 0..l {
        b0[B - 1 - i] = (q & 0xff) as u8;
        q >>= 8;
    }
    b0
}

/// Build the CTR_i counter block per SP 800-38C Appendix A.3.
///
/// ```text
/// Ctr_i[0]    = (L-1)        // bits 0..2 only; upper bits reserved=0
/// Ctr_i[1..1+Nlen] = N
/// Ctr_i[1+Nlen..16] = [i]_{8L}
/// ```
fn format_ctr(nonce: &[u8], i: u64) -> [u8; B] {
    let nlen = nonce.len();
    let l = B - 1 - nlen;
    let mut c = [0u8; B];
    c[0] = (l as u8) - 1;
    c[1..=nlen].copy_from_slice(nonce);
    let mut v = i;
    for k in 0..l {
        c[B - 1 - k] = (v & 0xff) as u8;
        v >>= 8;
    }
    c
}

/// XOR a single block into `acc` in place: `acc ^= other`.
fn xor_block(acc: &mut [u8; B], other: &[u8; B]) {
    for k in 0..B {
        acc[k] ^= other[k];
    }
}

/// Constant-time equality compare for two byte slices of identical
/// length. Returns `true` iff every byte matches.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Absorb a single partial-or-full block (already zero-padded) into
/// the running CBC-MAC state.
fn cbc_mac_block<B2: BlockCipher>(cipher: &B2, y: &mut [u8; B], block: &[u8; B]) {
    xor_block(y, block);
    cipher.encrypt_block(y);
}

/// Compute the raw CBC-MAC tag `Y_r` over `B0 || format(A) ||
/// zeropad(P)` per SP 800-38C §6.1 steps 2 and 3.
///
/// This helper centralises the formatting logic so both encryption and
/// decryption use byte-for-byte identical CBC-MAC inputs.
fn ccm_mac<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tlen: usize,
) -> [u8; B] {
    // Y0 = B0
    let mut y = format_b0(nonce, !aad.is_empty(), tlen, plaintext.len() as u64);
    cipher.encrypt_block(&mut y);

    // Absorb associated data per §A.2.2.
    if !aad.is_empty() {
        // Length prefix: 2 bytes if Alen < 2^16 - 2^8, otherwise 6
        // bytes (0xFFFE||a_be32) if Alen < 2^32, otherwise 10 bytes
        // (0xFFFF||a_be64).
        let alen = aad.len() as u64;
        // First partial block: [length_prefix || leading AAD bytes].
        let mut first = [0u8; B];
        let prefix_len: usize;
        if alen < (1u64 << 16) - (1u64 << 8) {
            first[0] = ((alen >> 8) & 0xff) as u8;
            first[1] = (alen & 0xff) as u8;
            prefix_len = 2;
        } else if alen < (1u64 << 32) {
            first[0] = 0xff;
            first[1] = 0xfe;
            let a32 = (alen as u32).to_be_bytes();
            first[2..6].copy_from_slice(&a32);
            prefix_len = 6;
        } else {
            first[0] = 0xff;
            first[1] = 0xff;
            first[2..10].copy_from_slice(&alen.to_be_bytes());
            prefix_len = 10;
        }
        // Copy the leading AAD bytes into the remaining space.
        let take = core::cmp::min(B - prefix_len, aad.len());
        first[prefix_len..prefix_len + take].copy_from_slice(&aad[..take]);
        cbc_mac_block(cipher, &mut y, &first);

        // Absorb full middle blocks then the final zero-padded tail.
        let mut off = take;
        while aad.len() - off >= B {
            let mut blk = [0u8; B];
            blk.copy_from_slice(&aad[off..off + B]);
            cbc_mac_block(cipher, &mut y, &blk);
            off += B;
        }
        let rem = aad.len() - off;
        if rem > 0 {
            let mut blk = [0u8; B];
            blk[..rem].copy_from_slice(&aad[off..]);
            cbc_mac_block(cipher, &mut y, &blk);
        }
    }

    // Absorb the plaintext, zero-padded to a block boundary.
    let mut off = 0;
    while plaintext.len() - off >= B {
        let mut blk = [0u8; B];
        blk.copy_from_slice(&plaintext[off..off + B]);
        cbc_mac_block(cipher, &mut y, &blk);
        off += B;
    }
    let rem = plaintext.len() - off;
    if rem > 0 {
        let mut blk = [0u8; B];
        blk[..rem].copy_from_slice(&plaintext[off..]);
        cbc_mac_block(cipher, &mut y, &blk);
    }
    y
}

/// Validate the parameter matrix from SP 800-38C §5.3 and return the
/// corresponding `ModeError` variant on any failure.
fn validate_params(
    nonce_len: usize,
    aad_len: usize,
    plaintext_len: usize,
    tlen: usize,
) -> Result<(), ModeError> {
    if !(NLEN_MIN..=NLEN_MAX).contains(&nonce_len) {
        return Err(ModeError::InvalidNonceLength);
    }
    if !tlen_valid(tlen) {
        return Err(ModeError::InvalidTagLength);
    }
    // L = 15 - Nlen, Plen must be < 2^(8L).
    let l = B - 1 - nonce_len;
    if l < 8 {
        let max_plen: u64 = 1u64 << (8 * l as u32);
        if (plaintext_len as u64) >= max_plen {
            return Err(ModeError::InvalidPayloadLength);
        }
    }
    // Alen < 2^64 - 2^16 per §A.2.2. On 64-bit targets any `usize` is
    // automatically < 2^64, so we only need to reject the final 2^16
    // bytes.
    if (aad_len as u64) > u64::MAX - (1u64 << 16) {
        return Err(ModeError::InvalidAadLength);
    }
    Ok(())
}

/// Encrypt and authenticate `plaintext` under CCM.
///
/// Writes `plaintext.len() + tlen` bytes into `out`, laid out as
/// `ciphertext || tag`. Returns `ModeError` on any parameter violation
/// or output-buffer length mismatch.
pub fn ccm_encrypt<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tlen: usize,
    out: &mut [u8],
) -> Result<(), ModeError> {
    validate_params(nonce.len(), aad.len(), plaintext.len(), tlen)?;
    if out.len() != plaintext.len() + tlen {
        return Err(ModeError::LengthMismatch);
    }

    // Raw CBC-MAC tag.
    let y = ccm_mac(cipher, nonce, aad, plaintext, tlen);

    // Keystream block 0 is used to mask the tag.
    let mut s0 = format_ctr(nonce, 0);
    cipher.encrypt_block(&mut s0);

    // CTR-encrypt plaintext into out[..plen] starting from block 1.
    let mut off = 0usize;
    let mut i: u64 = 1;
    while off < plaintext.len() {
        let mut s = format_ctr(nonce, i);
        cipher.encrypt_block(&mut s);
        let take = core::cmp::min(B, plaintext.len() - off);
        for k in 0..take {
            out[off + k] = plaintext[off + k] ^ s[k];
        }
        off += take;
        i += 1;
    }

    // Append T = MSB_Tlen(Y XOR S0).
    for k in 0..tlen {
        out[plaintext.len() + k] = y[k] ^ s0[k];
    }
    Ok(())
}

/// Decrypt and verify a CCM ciphertext.
///
/// `ciphertext` is the full `C || T` buffer from the sender. On
/// success writes the recovered plaintext (which has length
/// `ciphertext.len() - tlen`) into `out`. On tag-verification failure
/// returns `ModeError::TagMismatch` and zeroises `out` so that unverified
/// plaintext is never exposed.
pub fn ccm_decrypt<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tlen: usize,
    out: &mut [u8],
) -> Result<(), ModeError> {
    if ciphertext.len() < tlen {
        return Err(ModeError::LengthMismatch);
    }
    let plen = ciphertext.len() - tlen;
    validate_params(nonce.len(), aad.len(), plen, tlen)?;
    if out.len() != plen {
        return Err(ModeError::LengthMismatch);
    }

    // CTR-decrypt ciphertext into out.
    let mut off = 0usize;
    let mut i: u64 = 1;
    while off < plen {
        let mut s = format_ctr(nonce, i);
        cipher.encrypt_block(&mut s);
        let take = core::cmp::min(B, plen - off);
        for k in 0..take {
            out[off + k] = ciphertext[off + k] ^ s[k];
        }
        off += take;
        i += 1;
    }

    // Recompute raw CBC-MAC over the recovered plaintext and the
    // same formatted AAD, then mask with S0 to compare against the
    // transmitted tag in constant time.
    let y = ccm_mac(cipher, nonce, aad, &out[..plen], tlen);
    let mut s0 = format_ctr(nonce, 0);
    cipher.encrypt_block(&mut s0);
    let mut expected_tag = [0u8; B];
    for k in 0..tlen {
        expected_tag[k] = y[k] ^ s0[k];
    }
    let received_tag = &ciphertext[plen..plen + tlen];
    if !ct_eq(&expected_tag[..tlen], received_tag) {
        // Zeroise on failure so the caller never sees unverified
        // plaintext.
        for b in out.iter_mut() {
            *b = 0;
        }
        return Err(ModeError::TagMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{ccm_decrypt, ccm_encrypt};
    use crate::block::{Aes128Key, Aes192Key, Aes256Key};

    // Shared CAVP parameters for all three keysize tests.
    // [Alen=32, Nlen=13, Tlen=16, Plen=16], Count=160.

    // CAVP CCMVS CCM-VPT, AES-128. Source: VPT128.rsp Count=160.
    #[test]
    fn cavp_vpt128_plen16_count160() {
        let key: [u8; 16] = [
            0x70, 0x01, 0x0e, 0xd9, 0x0e, 0x61, 0x86, 0xec, 0xad, 0x41, 0xf0, 0xd3, 0xc7, 0xc4,
            0x2f, 0xf8,
        ];
        let nonce: [u8; 13] = [
            0xa5, 0xf4, 0xf4, 0x98, 0x6e, 0x98, 0x47, 0x29, 0x65, 0xf5, 0xab, 0xcc, 0x4b,
        ];
        let aad: [u8; 32] = [
            0x3f, 0xec, 0x0e, 0x5c, 0xc2, 0x4d, 0x67, 0x13, 0x94, 0x37, 0xcb, 0xc8, 0x11, 0x24,
            0x14, 0xfc, 0x8d, 0xac, 0xcd, 0x1a, 0x94, 0xb4, 0x9a, 0x4c, 0x76, 0xe2, 0xd3, 0x93,
            0x03, 0x54, 0x73, 0x17,
        ];
        let pt: [u8; 16] = [
            0xbe, 0x32, 0x2f, 0x58, 0xef, 0xa7, 0xf8, 0xc6, 0x8a, 0x63, 0x5e, 0x0b, 0x9c, 0xce,
            0x77, 0xf2,
        ];
        let expected_ct: [u8; 32] = [
            0x8e, 0x44, 0x25, 0xae, 0x57, 0x39, 0x74, 0xf0, 0xf0, 0x69, 0x3a, 0x18, 0x8b, 0x52,
            0x58, 0x12, 0xee, 0xf0, 0x8e, 0x3f, 0xb1, 0x5f, 0x42, 0x27, 0xe0, 0xd9, 0x89, 0xa4,
            0xd5, 0x87, 0xa8, 0xcf,
        ];
        let k = Aes128Key::new(&key);
        let mut out = [0u8; 32];
        ccm_encrypt(&k, &nonce, &aad, &pt, 16, &mut out).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        ccm_decrypt(&k, &nonce, &aad, &expected_ct, 16, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // CAVP CCMVS CCM-VPT, AES-192. Source: VPT192.rsp Count=160.
    #[test]
    fn cavp_vpt192_plen16_count160() {
        let key: [u8; 24] = [
            0x68, 0x73, 0xf1, 0xc6, 0xc3, 0x09, 0x75, 0xaf, 0xf6, 0xf0, 0x84, 0x70, 0x26, 0x43,
            0x21, 0x13, 0x0a, 0x6e, 0x59, 0x84, 0xad, 0xe3, 0x24, 0xe9,
        ];
        let nonce: [u8; 13] = [
            0x7c, 0x4d, 0x2f, 0x7c, 0xec, 0x04, 0x36, 0x1f, 0x18, 0x7f, 0x07, 0x26, 0xd5,
        ];
        let aad: [u8; 32] = [
            0x77, 0x74, 0x3b, 0x5d, 0x83, 0xa0, 0x0d, 0x2c, 0x8d, 0x5f, 0x7e, 0x10, 0x78, 0x15,
            0x31, 0xb4, 0x96, 0xe0, 0x9f, 0x3b, 0xc9, 0x29, 0x5d, 0x7a, 0xe9, 0x79, 0x9e, 0x64,
            0x66, 0x8e, 0xf8, 0xc5,
        ];
        let pt: [u8; 16] = [
            0x50, 0x51, 0xa0, 0xb0, 0xb6, 0x76, 0x6c, 0xd6, 0xea, 0x29, 0xa6, 0x72, 0x76, 0x9d,
            0x40, 0xfe,
        ];
        let expected_ct: [u8; 32] = [
            0x0c, 0xe5, 0xac, 0x8d, 0x6b, 0x25, 0x6f, 0xb7, 0x58, 0x0b, 0xf6, 0xac, 0xc7, 0x64,
            0x26, 0xaf, 0x40, 0xbc, 0xe5, 0x8f, 0xd4, 0xcd, 0x65, 0x48, 0xdf, 0x90, 0xa0, 0x33,
            0x7c, 0x84, 0x20, 0x04,
        ];
        let k = Aes192Key::new(&key);
        let mut out = [0u8; 32];
        ccm_encrypt(&k, &nonce, &aad, &pt, 16, &mut out).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        ccm_decrypt(&k, &nonce, &aad, &expected_ct, 16, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // CAVP CCMVS CCM-VPT, AES-256. Source: VPT256.rsp Count=160.
    #[test]
    fn cavp_vpt256_plen16_count160() {
        let key: [u8; 32] = [
            0xee, 0x8c, 0xe1, 0x87, 0x16, 0x97, 0x79, 0xd1, 0x3e, 0x44, 0x3d, 0x64, 0x28, 0xe3,
            0x8b, 0x38, 0xb5, 0x5d, 0xfb, 0x90, 0xf0, 0x22, 0x8a, 0x8a, 0x4e, 0x62, 0xf8, 0xf5,
            0x35, 0x80, 0x6e, 0x62,
        ];
        let nonce: [u8; 13] = [
            0x12, 0x16, 0x42, 0xc4, 0x21, 0x8b, 0x39, 0x1c, 0x98, 0xe6, 0x26, 0x9c, 0x8a,
        ];
        let aad: [u8; 32] = [
            0x71, 0x8d, 0x13, 0xe4, 0x75, 0x22, 0xac, 0x4c, 0xdf, 0x3f, 0x82, 0x80, 0x63, 0x98,
            0x0b, 0x6d, 0x45, 0x2f, 0xcd, 0xcd, 0x6e, 0x1a, 0x19, 0x04, 0xbf, 0x87, 0xf5, 0x48,
            0xa5, 0xfd, 0x5a, 0x05,
        ];
        let pt: [u8; 16] = [
            0xd1, 0x5f, 0x98, 0xf2, 0xc6, 0xd6, 0x70, 0xf5, 0x5c, 0x78, 0xa0, 0x66, 0x48, 0x33,
            0x2b, 0xc9,
        ];
        let expected_ct: [u8; 32] = [
            0xcc, 0x17, 0xbf, 0x87, 0x94, 0xc8, 0x43, 0x45, 0x7d, 0x89, 0x93, 0x91, 0x89, 0x8e,
            0xd2, 0x2a, 0x6f, 0x9d, 0x28, 0xfc, 0xb6, 0x42, 0x34, 0xe1, 0xcd, 0x79, 0x3c, 0x41,
            0x44, 0xf1, 0xda, 0x50,
        ];
        let k = Aes256Key::new(&key);
        let mut out = [0u8; 32];
        ccm_encrypt(&k, &nonce, &aad, &pt, 16, &mut out).unwrap();
        assert_eq!(out, expected_ct);
        let mut dec = [0u8; 16];
        ccm_decrypt(&k, &nonce, &aad, &expected_ct, 16, &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    // Tamper rejection: flipping a ciphertext bit must return
    // TagMismatch and leave the output buffer zeroised.
    #[test]
    fn ccm_rejects_bit_flip() {
        use crate::modes::ModeError;
        let key: [u8; 16] = [
            0x70, 0x01, 0x0e, 0xd9, 0x0e, 0x61, 0x86, 0xec, 0xad, 0x41, 0xf0, 0xd3, 0xc7, 0xc4,
            0x2f, 0xf8,
        ];
        let nonce: [u8; 13] = [
            0xa5, 0xf4, 0xf4, 0x98, 0x6e, 0x98, 0x47, 0x29, 0x65, 0xf5, 0xab, 0xcc, 0x4b,
        ];
        let aad: [u8; 32] = [
            0x3f, 0xec, 0x0e, 0x5c, 0xc2, 0x4d, 0x67, 0x13, 0x94, 0x37, 0xcb, 0xc8, 0x11, 0x24,
            0x14, 0xfc, 0x8d, 0xac, 0xcd, 0x1a, 0x94, 0xb4, 0x9a, 0x4c, 0x76, 0xe2, 0xd3, 0x93,
            0x03, 0x54, 0x73, 0x17,
        ];
        let mut ct: [u8; 32] = [
            0x8e, 0x44, 0x25, 0xae, 0x57, 0x39, 0x74, 0xf0, 0xf0, 0x69, 0x3a, 0x18, 0x8b, 0x52,
            0x58, 0x12, 0xee, 0xf0, 0x8e, 0x3f, 0xb1, 0x5f, 0x42, 0x27, 0xe0, 0xd9, 0x89, 0xa4,
            0xd5, 0x87, 0xa8, 0xcf,
        ];
        ct[0] ^= 0x01;
        let k = Aes128Key::new(&key);
        let mut dec = [0u8; 16];
        let err = ccm_decrypt(&k, &nonce, &aad, &ct, 16, &mut dec).unwrap_err();
        assert_eq!(err, ModeError::TagMismatch);
        assert!(dec.iter().all(|&b| b == 0));
    }
}
