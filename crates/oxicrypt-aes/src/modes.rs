//! AES modes of operation: ECB, CBC, CTR, GCM.
//!
//! # Scope
//!
//! Implements the four Phase-1 modes over the raw AES block cipher
//! from [`crate::block`]:
//!
//!   * **ECB** — SP 800-38A §6.1. Encrypt / decrypt whole-block
//!     messages with no chaining. Primarily exposed to support the
//!     per-block CAVP KATs; not recommended for general use.
//!   * **CBC** — SP 800-38A §6.2. Requires a 16-byte IV and a
//!     block-aligned plaintext (no padding mode baked in here).
//!   * **CTR** — SP 800-38A §6.5. Uses a 16-byte initial counter
//!     block (`icb`) and increments the low 32 bits as a big-endian
//!     counter, matching the convention used by GCM.
//!   * **GCM** — SP 800-38D. 96-bit IV and 128-bit tag only; longer
//!     IV forms and shorter tags are deliberately not wired in the
//!     Phase-1 scope.
//!
//! Each mode is parameterised over a trait [`BlockCipher`] so the
//! same mode code runs unchanged over AES-128, AES-192 and AES-256.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use crate::block::{Aes128Key, Aes192Key, Aes256Key, BLOCK_SIZE};

// ----------------------------------------------------------------------
// Generic block-cipher trait used internally by mode code.
// ----------------------------------------------------------------------

/// Minimal block-cipher primitive used by mode code.
pub trait BlockCipher {
    /// Block size in bytes. Always 16 for AES.
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    /// Encrypt a 16-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);
    /// Decrypt a 16-byte block in place.
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

impl BlockCipher for Aes128Key {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        Aes128Key::encrypt_block(self, block);
    }
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        Aes128Key::decrypt_block(self, block);
    }
}
impl BlockCipher for Aes192Key {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        Aes192Key::encrypt_block(self, block);
    }
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        Aes192Key::decrypt_block(self, block);
    }
}
impl BlockCipher for Aes256Key {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        Aes256Key::encrypt_block(self, block);
    }
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        Aes256Key::decrypt_block(self, block);
    }
}

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

/// Errors returned by mode APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeError {
    /// Input length is not a multiple of the block size (ECB/CBC).
    NotBlockAligned,
    /// GCM: IV length is not 12 bytes (Phase 1 only supports the
    /// common 96-bit IV form).
    InvalidIvLength,
    /// GCM/CCM: authentication tag did not verify.
    TagMismatch,
    /// GCM/CCM: buffer length mismatch between `ciphertext` and `out`.
    LengthMismatch,
    /// CCM: nonce length is outside the SP 800-38C range (7..=13).
    InvalidNonceLength,
    /// CCM: tag length is not in {4, 6, 8, 10, 12, 14, 16}.
    InvalidTagLength,
    /// CCM: plaintext is too long for the chosen nonce length
    /// (`Plen >= 2^(8*(15 - Nlen))`).
    InvalidPayloadLength,
    /// CCM: associated data exceeds the SP 800-38C §A.2.2 cap.
    InvalidAadLength,
}

impl core::fmt::Display for ModeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotBlockAligned => write!(
                f,
                "input length is not a multiple of 16 bytes (AES block size); \
                 pad or use a streaming mode (CTR/GCM/CCM)"
            ),
            Self::InvalidIvLength => write!(
                f,
                "GCM IV must be exactly 12 bytes (96 bits); \
                 pass a 12-byte nonce"
            ),
            Self::TagMismatch => write!(
                f,
                "authentication tag did not verify; \
                 the ciphertext or AAD was modified, or the key/nonce is wrong"
            ),
            Self::LengthMismatch => write!(
                f,
                "output buffer length does not match ciphertext length; \
                 allocate an output buffer of the same size as the ciphertext"
            ),
            Self::InvalidNonceLength => write!(
                f,
                "CCM nonce must be 7..=13 bytes (SP 800-38C §A.2.1); \
                 pass a nonce in that range"
            ),
            Self::InvalidTagLength => write!(
                f,
                "CCM tag length must be one of {{4, 6, 8, 10, 12, 14, 16}} bytes; \
                 choose a valid tag size"
            ),
            Self::InvalidPayloadLength => write!(
                f,
                "CCM plaintext too long for the chosen nonce length; \
                 use a shorter nonce (fewer bytes = larger max payload) \
                 or split the data"
            ),
            Self::InvalidAadLength => write!(
                f,
                "CCM associated data exceeds the SP 800-38C §A.2.2 maximum; \
                 reduce the AAD length"
            ),
        }
    }
}

// ----------------------------------------------------------------------
// ECB — SP 800-38A §6.1
// ----------------------------------------------------------------------

/// ECB-encrypt `input` into `output`. Both buffers must have the
/// same length and that length must be a multiple of 16.
pub fn ecb_encrypt<B: BlockCipher>(
    cipher: &B,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut i = 0;
    while i < input.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&input[i..i + 16]);
        cipher.encrypt_block(&mut blk);
        output[i..i + 16].copy_from_slice(&blk);
        i += 16;
    }
    Ok(())
}

/// ECB-decrypt `input` into `output`.
pub fn ecb_decrypt<B: BlockCipher>(
    cipher: &B,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut i = 0;
    while i < input.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&input[i..i + 16]);
        cipher.decrypt_block(&mut blk);
        output[i..i + 16].copy_from_slice(&blk);
        i += 16;
    }
    Ok(())
}

// ----------------------------------------------------------------------
// CBC — SP 800-38A §6.2
// ----------------------------------------------------------------------

/// CBC-encrypt `input` into `output` with 16-byte IV. Lengths must
/// match and be a multiple of 16. No padding is applied.
pub fn cbc_encrypt<B: BlockCipher>(
    cipher: &B,
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut prev = *iv;
    let mut i = 0;
    while i < input.len() {
        let mut blk = [0u8; 16];
        for j in 0..16 {
            blk[j] = input[i + j] ^ prev[j];
        }
        cipher.encrypt_block(&mut blk);
        output[i..i + 16].copy_from_slice(&blk);
        prev = blk;
        i += 16;
    }
    Ok(())
}

/// CBC-decrypt `input` into `output`.
pub fn cbc_decrypt<B: BlockCipher>(
    cipher: &B,
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ModeError> {
    if input.len() != output.len() || input.len() % BLOCK_SIZE != 0 {
        return Err(ModeError::NotBlockAligned);
    }
    let mut prev = *iv;
    let mut i = 0;
    while i < input.len() {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&input[i..i + 16]);
        let cipher_in = blk;
        cipher.decrypt_block(&mut blk);
        for j in 0..16 {
            blk[j] ^= prev[j];
        }
        output[i..i + 16].copy_from_slice(&blk);
        prev = cipher_in;
        i += 16;
    }
    Ok(())
}

// ----------------------------------------------------------------------
// CTR — SP 800-38A §6.5
// ----------------------------------------------------------------------

/// Increment a 16-byte counter block by treating the final 4 bytes
/// as a big-endian counter. Matches the GCM convention.
#[inline]
fn inc32(ctr: &mut [u8; 16]) {
    let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    c = c.wrapping_add(1);
    let b = c.to_be_bytes();
    ctr[12] = b[0];
    ctr[13] = b[1];
    ctr[14] = b[2];
    ctr[15] = b[3];
}

/// CTR encrypt/decrypt (the same operation) using `icb` as the
/// initial counter block. The low 32 bits of the counter are
/// incremented per SP 800-38A §6.5 with the convention that the
/// counter occupies the last 4 bytes of the 16-byte block — this
/// matches the convention used by GCM.
///
/// Note: SP 800-38A defines CTR with an application-selected
/// standard incrementing function. For the FIPS 140-3 power-up KAT
/// we follow the test-vector convention in SP 800-38A Appendix F.5,
/// which treats the full 128-bit block as a big-endian counter —
/// but because the Appendix F.5 test counters only span the low 32
/// bits, [`ctr_xor`] and the Appendix F.5 vectors agree.
pub fn ctr_xor<B: BlockCipher>(cipher: &B, icb: &[u8; 16], input: &[u8], output: &mut [u8]) {
    let mut ctr = *icb;
    let mut i = 0;
    while i < input.len() {
        let mut ks = ctr;
        cipher.encrypt_block(&mut ks);
        let take = core::cmp::min(16, input.len() - i);
        for j in 0..take {
            output[i + j] = input[i + j] ^ ks[j];
        }
        inc128_for_ctr(&mut ctr);
        i += 16;
    }
}

/// Full 128-bit big-endian increment, used by CTR mode to follow the
/// SP 800-38A Appendix F.5 test-vector convention. The vectors only
/// wrap the low 32 bits within the length of the sample message, so
/// this agrees with [`inc32`] for every Appendix F.5 KAT but is the
/// documented Appendix F.5 increment. GCM uses [`inc32`] instead.
fn inc128_for_ctr(ctr: &mut [u8; 16]) {
    let mut carry: u16 = 1;
    let mut i = 16;
    while i > 0 {
        i -= 1;
        let s = u16::from(ctr[i]) + carry;
        ctr[i] = (s & 0xff) as u8;
        carry = s >> 8;
        if carry == 0 {
            break;
        }
    }
}

// ----------------------------------------------------------------------
// GCM — SP 800-38D
// ----------------------------------------------------------------------

/// GHASH multiplication in GF(2^128) with polynomial
/// `x^128 + x^7 + x^2 + x + 1` (SP 800-38D §6.3).
///
/// Operates on 128-bit blocks interpreted big-endian-bit-reversed
/// per the GCM spec: bit 0 of byte 0 is the coefficient of `1`.
/// The implementation is the standard bit-by-bit schoolbook
/// algorithm ("Algorithm 1" in McGrew & Viega), which is slow but
/// simple and avoids cache-timing risk from table-based variants.
///
/// This is the **validated baseline** and the correctness oracle for
/// the optional PCLMULQDQ-accelerated path: [`gf_mul`] dispatches to
/// `oxicrypt-aes-accel` when the `accel-aes` feature is on and PCLMULQDQ
/// is present, and falls back here otherwise. Keep this function
/// byte-for-byte unchanged.
fn gf_mul_portable(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        if (x[byte] >> bit) & 1 == 1 {
            for k in 0..16 {
                z[k] ^= v[k];
            }
        }
        // v = v >> 1 ; if (lsb) v ^= R where R = 0xe1 || 0^120.
        let lsb = v[15] & 1;
        let mut carry: u8 = 0;
        for k in 0..16 {
            let b = v[k];
            v[k] = (b >> 1) | carry;
            carry = (b & 1) << 7;
        }
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}

/// GHASH multiply dispatcher: the CPU-accelerated PCLMULQDQ path when
/// the `accel-aes` feature is on and the running CPU supports it, else
/// the validated portable [`gf_mul_portable`]. The result is
/// byte-for-byte identical either way — the accel path is proven
/// equivalent by the `accel-aes`-gated differential oracle in this
/// module's tests. All GCM callers use this dispatcher unchanged.
fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    #[cfg(feature = "accel-aes")]
    {
        let mut out = [0u8; 16];
        if oxicrypt_aes_accel::ghash_mul(x, y, &mut out) {
            return out;
        }
    }
    gf_mul_portable(x, y)
}

/// Accumulate `data` into `y` by XOR-then-multiply-by-H, padding the
/// final partial block with zero bytes on the right (SP 800-38D §6.4).
fn ghash_update(y: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut i = 0;
    while i < data.len() {
        let take = core::cmp::min(16, data.len() - i);
        let mut blk = [0u8; 16];
        blk[..take].copy_from_slice(&data[i..i + take]);
        for k in 0..16 {
            y[k] ^= blk[k];
        }
        *y = gf_mul(y, h);
        i += 16;
    }
}

/// AES-GCM authenticated encryption (SP 800-38D §7.1).
///
/// Phase 1 constraints: `iv` must be exactly 12 bytes and the
/// authentication tag is always 16 bytes.
pub fn gcm_encrypt<B: BlockCipher>(
    cipher: &B,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; 16],
) -> Result<(), ModeError> {
    if iv.len() != 12 {
        return Err(ModeError::InvalidIvLength);
    }
    if plaintext.len() != ciphertext_out.len() {
        return Err(ModeError::LengthMismatch);
    }

    // H = AES_K(0^128)
    let mut h = [0u8; 16];
    cipher.encrypt_block(&mut h);

    // J0 = IV || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 0x01;

    // Encrypt plaintext with CTR starting at inc32(J0).
    let mut counter = j0;
    inc32(&mut counter);
    let mut i = 0;
    while i < plaintext.len() {
        let mut ks = counter;
        cipher.encrypt_block(&mut ks);
        let take = core::cmp::min(16, plaintext.len() - i);
        for j in 0..take {
            ciphertext_out[i + j] = plaintext[i + j] ^ ks[j];
        }
        inc32(&mut counter);
        i += 16;
    }

    // S = GHASH_H(AAD || 0^v || C || 0^u || len(AAD)64 || len(C)64)
    let mut y = [0u8; 16];
    ghash_update(&mut y, &h, aad);
    ghash_update(&mut y, &h, ciphertext_out);
    let mut lenblk = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext_out.len() as u64).wrapping_mul(8);
    lenblk[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lenblk[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    for k in 0..16 {
        y[k] ^= lenblk[k];
    }
    y = gf_mul(&y, &h);

    // T = GCTR_K(J0, S) = AES_K(J0) XOR S (single-block).
    let mut ej0 = j0;
    cipher.encrypt_block(&mut ej0);
    for k in 0..16 {
        tag_out[k] = ej0[k] ^ y[k];
    }
    Ok(())
}

/// AES-GCM authenticated decryption with constant-time tag check
/// (SP 800-38D §7.2). Returns `Ok(())` only if the tag verifies.
pub fn gcm_decrypt<B: BlockCipher>(
    cipher: &B,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext_out: &mut [u8],
) -> Result<(), ModeError> {
    if iv.len() != 12 {
        return Err(ModeError::InvalidIvLength);
    }
    if ciphertext.len() != plaintext_out.len() {
        return Err(ModeError::LengthMismatch);
    }

    let mut h = [0u8; 16];
    cipher.encrypt_block(&mut h);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 0x01;

    // Verify tag first over the original ciphertext.
    let mut y = [0u8; 16];
    ghash_update(&mut y, &h, aad);
    ghash_update(&mut y, &h, ciphertext);
    let mut lenblk = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    lenblk[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lenblk[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    for k in 0..16 {
        y[k] ^= lenblk[k];
    }
    y = gf_mul(&y, &h);

    let mut ej0 = j0;
    cipher.encrypt_block(&mut ej0);
    let mut computed_tag = [0u8; 16];
    for k in 0..16 {
        computed_tag[k] = ej0[k] ^ y[k];
    }

    // Constant-time compare.
    let mut diff: u8 = 0;
    for k in 0..16 {
        diff |= computed_tag[k] ^ tag[k];
    }
    if diff != 0 {
        return Err(ModeError::TagMismatch);
    }

    // Decrypt by CTR starting at inc32(J0).
    let mut counter = j0;
    inc32(&mut counter);
    let mut i = 0;
    while i < ciphertext.len() {
        let mut ks = counter;
        cipher.encrypt_block(&mut ks);
        let take = core::cmp::min(16, ciphertext.len() - i);
        for j in 0..take {
            plaintext_out[i + j] = ciphertext[i + j] ^ ks[j];
        }
        inc32(&mut counter);
        i += 16;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{
        cbc_decrypt, cbc_encrypt, ctr_xor, ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt,
    };
    use crate::block::Aes128Key;

    // Minimal AES-128 round-trip test for each mode using the
    // FIPS 197 single-block key. Fuller NIST-vector KATs live in the
    // `kat` module.
    #[test]
    fn ecb_roundtrip_aes128_single_block() {
        let key = [0u8; 16];
        let k = Aes128Key::new_internal(&key);
        let pt = [0x00; 16];
        let mut ct = [0u8; 16];
        let mut back = [0u8; 16];
        ecb_encrypt(&k, &pt, &mut ct).unwrap();
        ecb_decrypt(&k, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn cbc_roundtrip_aes128() {
        let key = [0x11u8; 16];
        let k = Aes128Key::new_internal(&key);
        let iv = [0x22u8; 16];
        let pt = [0xaau8; 32];
        let mut ct = [0u8; 32];
        let mut back = [0u8; 32];
        cbc_encrypt(&k, &iv, &pt, &mut ct).unwrap();
        cbc_decrypt(&k, &iv, &ct, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ctr_roundtrip_aes128() {
        let key = [0x33u8; 16];
        let k = Aes128Key::new_internal(&key);
        let icb = [0x44u8; 16];
        let pt = [0x55u8; 37];
        let mut ct = [0u8; 37];
        let mut back = [0u8; 37];
        ctr_xor(&k, &icb, &pt, &mut ct);
        ctr_xor(&k, &icb, &ct, &mut back);
        assert_eq!(back, pt);
    }

    #[test]
    fn gcm_roundtrip_aes128() {
        let key = [0x66u8; 16];
        let k = Aes128Key::new_internal(&key);
        let iv = [0x77u8; 12];
        let aad = [0x88u8; 13];
        let pt = [0x99u8; 37];
        let mut ct = [0u8; 37];
        let mut tag = [0u8; 16];
        let mut back = [0u8; 37];
        gcm_encrypt(&k, &iv, &aad, &pt, &mut ct, &mut tag).unwrap();
        gcm_decrypt(&k, &iv, &aad, &ct, &tag, &mut back).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn gcm_detects_tag_tamper() {
        let key = [0u8; 16];
        let k = Aes128Key::new_internal(&key);
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        let mut back = [0u8; 16];
        gcm_encrypt(&k, &iv, &[], &pt, &mut ct, &mut tag).unwrap();
        tag[0] ^= 1;
        assert!(gcm_decrypt(&k, &iv, &[], &ct, &tag, &mut back).is_err());
    }
}

// ── GHASH cross-path differential oracle (accel-aes) ────────────────
//
// The UNFORGEABLE gate for the PCLMULQDQ GHASH multiply: for many
// thousands of pseudo-random (x, y) pairs, the accelerated product
// must equal the validated portable `gf_mul_portable` byte-for-byte.
// The accelerated value is obtained through the public dispatcher
// `gf_mul` (which, under `accel-aes` with PCLMULQDQ present, runs the
// hardware path). Skips gracefully on non-PCLMUL hosts so the suite is
// a no-op there; on PCLMUL hosts (CI + dev) it WILL run.
#[cfg(all(test, feature = "accel-aes"))]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod ghash_accel_oracle {
    use super::{gf_mul, gf_mul_portable};

    /// Tiny self-contained xorshift128+ PRNG — deterministic, no extra
    /// dependency, reproducible from a fixed seed. Good enough to spray
    /// the GF(2^128) input space for the oracle.
    struct XorShift128p {
        s0: u64,
        s1: u64,
    }

    impl XorShift128p {
        fn new(seed: u64) -> Self {
            // SplitMix64-style seeding so a single u64 seed yields a
            // well-mixed 128-bit state (avoids the all-zero fixed point).
            let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut next = || {
                z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut x = z;
                x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                x ^ (x >> 31)
            };
            Self {
                s0: next(),
                s1: next(),
            }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.s0;
            let y = self.s1;
            self.s0 = y;
            x ^= x << 23;
            self.s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
            self.s1.wrapping_add(y)
        }

        fn fill_block(&mut self) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&self.next_u64().to_le_bytes());
            b[8..].copy_from_slice(&self.next_u64().to_le_bytes());
            b
        }
    }

    const CASES: usize = 50_000;

    #[test]
    fn accel_ghash_matches_portable_byte_exact() {
        // No-op on CPUs without PCLMULQDQ (gf_mul falls back to portable
        // there, so the comparison would be trivially equal anyway, but
        // we skip to keep intent honest).
        if !oxicrypt_aes_accel::ghash_available() {
            return;
        }

        let mut rng = XorShift128p::new(0x0C1C_8A54_6A45_5701);

        // A handful of structured edge cases up front, then the random
        // spray. Edge cases stress the reduction's lane-crossing and
        // high-bit handling.
        let edge: &[([u8; 16], [u8; 16])] = &[
            ([0u8; 16], [0u8; 16]),
            ([0xFFu8; 16], [0xFFu8; 16]),
            (
                [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            (
                [0xFFu8; 16],
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
        ];
        for (x, y) in edge {
            let want = gf_mul_portable(x, y);
            let got = gf_mul(x, y);
            assert_eq!(
                got, want,
                "GHASH accel != portable on edge case x={x:02x?} y={y:02x?}"
            );
        }

        for i in 0..CASES {
            let x = rng.fill_block();
            let y = rng.fill_block();
            let want = gf_mul_portable(&x, &y);
            let got = gf_mul(&x, &y);
            assert_eq!(
                got, want,
                "GHASH accel != portable at random case {i}: x={x:02x?} y={y:02x?}"
            );
        }
    }
}
