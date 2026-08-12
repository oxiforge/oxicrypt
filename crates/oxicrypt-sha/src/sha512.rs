//! SHA-512 per FIPS 180-4 §6.4.
//!
//! Pure-Rust and `no_std`. This module hosts the
//! 64-bit compression function used by SHA-384, SHA-512, SHA-512/224,
//! and SHA-512/256. The differences between those four variants are:
//!
//! * a different initial hash value H(0), and
//! * a different output truncation.
//!
//! The compression function, message schedule, K constants, padding
//! (128-bit length field), and block size (128 bytes) are identical.
//! `compress512` is exposed at the crate level so the three SHA-384
//! / SHA-512-t wrappers can share it.
//!
//! See `sha256.rs` for a full commentary on the `indexing_slicing`,
//! `arithmetic_side_effects`, `many_single_char_names`, and
//! `needless_range_loop` allows; the same rationale applies here.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]

use oxicrypt_module::{Error, SelfTestFailure, Service, require_allowed, require_operational};

/// Output length of SHA-512 in bytes.
pub const DIGEST_SIZE: usize = 64;

/// Input block length of SHA-512 in bytes (1024 bits).
pub const BLOCK_SIZE: usize = 128;

/// Length-field size in bytes. SHA-512 uses a 128-bit big-endian
/// length field at the end of the final block. Our `total_len`
/// counter is a `u64` of bytes, so the upper 64 bits are always
/// zero in practice; we still pad them out per the spec.
pub(crate) const LEN_FIELD: usize = 16;

/// SHA-512 initial hash value H(0) from FIPS 180-4 §5.3.5.
const H0: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Round constants K from FIPS 180-4 §4.2.3.
#[rustfmt::skip]
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
];

// ------------------------------------------------------------------------
// SHA-512 logical functions (FIPS 180-4 §4.1.3)
// ------------------------------------------------------------------------

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// SHA-512 compression function — one 1024-bit block.
///
/// Shared by SHA-512, SHA-384, SHA-512/224, and SHA-512/256.
pub(crate) fn compress512(state: &mut [u64; 8], block: &[u8; BLOCK_SIZE]) {
    // 1. Prepare the message schedule W[0..80].
    let mut w = [0u64; 80];
    for i in 0..16 {
        let off = i * 8;
        w[i] = u64::from_be_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]);
    }
    for i in 16..80 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..80 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ------------------------------------------------------------------------
// Shared streaming buffer (used by all four 64-bit variants)
// ------------------------------------------------------------------------

/// Streaming state shared by SHA-384, SHA-512, and the truncated
/// SHA-512/t variants. Only the initial `state` and the final
/// truncation differ between them.
#[derive(Clone)]
pub(crate) struct Sha512State {
    pub(crate) state: [u64; 8],
    pub(crate) buffer: [u8; BLOCK_SIZE],
    pub(crate) buffer_len: usize,
    pub(crate) total_len: u64,
}

impl Sha512State {
    pub(crate) const fn with_iv(iv: [u64; 8]) -> Self {
        Self {
            state: iv,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            if data.len() < need {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            let (head, tail) = data.split_at(need);
            self.buffer[self.buffer_len..BLOCK_SIZE].copy_from_slice(head);
            let block = self.buffer;
            compress512(&mut self.state, &block);
            self.buffer_len = 0;
            data = tail;
        }

        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            let mut fixed = [0u8; BLOCK_SIZE];
            fixed.copy_from_slice(block);
            compress512(&mut self.state, &fixed);
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Pads and compresses the final block(s), leaving `state` as the
    /// final H. Callers then serialize / truncate as needed.
    pub(crate) fn finalize_state(&mut self) {
        let bit_len: u64 = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > BLOCK_SIZE - LEN_FIELD {
            for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            compress512(&mut self.state, &block);
            self.buffer_len = 0;
        }
        for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE - LEN_FIELD] {
            *b = 0;
        }

        // 128-bit big-endian length: upper 64 bits are zero because we
        // count bytes in a u64. The lower 64 bits are the bit length.
        self.buffer[BLOCK_SIZE - LEN_FIELD..BLOCK_SIZE - 8].copy_from_slice(&[0u8; 8]);
        self.buffer[BLOCK_SIZE - 8..BLOCK_SIZE].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buffer;
        compress512(&mut self.state, &block);
    }
}

impl Drop for Sha512State {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize_u64(&mut self.state);
        oxicrypt_zeroize::zeroize(&mut self.buffer);
    }
}

// ------------------------------------------------------------------------
// SHA-512 public type
// ------------------------------------------------------------------------

/// SHA-512 streaming hasher.
#[derive(Clone)]
pub struct Sha512 {
    inner: Sha512State,
}

impl Sha512 {
    /// Creates a new SHA-512 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha512)?;
        Ok(Self::new_internal())
    }

    /// Constructor that bypasses the module state machine.
    ///
    /// Used by this crate's power-up KAT and by downstream crates
    /// (oxicrypt-hmac, oxicrypt-kdf) that need to instantiate a hash while
    /// the module is still in `SelfTest`. Public callers must use
    /// [`Sha512::new`] instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            inner: Sha512State::with_iv(H0),
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes and returns the 64-byte digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        self.inner.finalize_state();
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.inner.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One-shot SHA-512.
pub fn sha512(data: &[u8]) -> Result<[u8; DIGEST_SIZE], Error> {
    let mut h = Sha512::new()?;
    h.update(data);
    Ok(h.finalize())
}

// ------------------------------------------------------------------------
// Power-up self-test
// ------------------------------------------------------------------------

/// Expected digest for the NIST SHA-512 example:
/// SHA-512("abc"). Retained for the cross-check tests below; the
/// power-up KAT uses a NIST CAVP SHS vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_ABC_DIGEST: [u8; DIGEST_SIZE] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, //
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, //
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, //
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, //
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, //
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, //
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, //
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f, //
];

/// Power-up KAT for SHA-512.
///
/// Sourced from NIST CAVP SHS (`SHA512ShortMsg.rsp`, Len=8) via
/// `oxicrypt-test-vectors`.
pub fn self_test() -> Result<(), SelfTestFailure> {
    let mut h = Sha512::new_internal();
    h.update(&oxicrypt_test_vectors::SHA_512_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA_512_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ------------------------------------------------------------------------
// Unit tests
// ------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{DIGEST_SIZE, KAT_ABC_DIGEST, Sha512, self_test, sha512};
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    fn hex64(s: &str) -> [u8; DIGEST_SIZE] {
        assert_eq!(s.len(), DIGEST_SIZE * 2);
        let mut out = [0u8; DIGEST_SIZE];
        let bytes = s.as_bytes();
        for i in 0..DIGEST_SIZE {
            out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        }
        out
    }

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex char: {c}"),
        }
    }

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "sha512-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn kat_abc_appendix_c1() {
        let mut h = Sha512::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST);
    }

    #[test]
    fn kat_two_block_appendix_c2() {
        // NIST SHA-512 two-block example: "abcdefgh...stu" (112 bytes)
        let msg: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex64(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
        let mut h = Sha512::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_empty_string() {
        // NIST CAVP: SHA-512("")
        let expected = hex64(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        let mut h = Sha512::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog, \
                          and we are feeding this in three uneven chunks \
                          to make sure the block boundary handling works.";
        ensure_initialized();
        let one_shot = sha512(msg).unwrap();

        let mut h = Sha512::new().unwrap();
        h.update(&msg[..11]);
        h.update(&msg[11..73]);
        h.update(&msg[73..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn digest_size_is_64() {
        assert_eq!(DIGEST_SIZE, 64);
    }
}
