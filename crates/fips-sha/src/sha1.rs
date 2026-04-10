//! SHA-1 per FIPS 180-4 §6.1.
//!
//! # Cryptographic use
//!
//! Per FIPS 140-3 IG D.G and SP 800-131A Rev. 2, SHA-1 is disallowed
//! for generating digital signatures but remains approved for
//! HMAC, KDF, and non-digital-signature applications. This module
//! provides the primitive; restrictions on *how* it may be used are
//! enforced by the higher-level algorithm crates (`fips-hmac`, etc.)
//! and by the ACVP harness.
//!
//! # Implementation
//!
//! Pure-Rust transcription of FIPS 180-4 §6.1.2. The block size is
//! 512 bits (64 bytes) and the word size is 32 bits, identical to
//! SHA-256, but the compression function is different: it uses 80
//! rounds with four distinct round functions (f0..f79) and four
//! round constants. The padding scheme is the same as SHA-256
//! (0x80 terminator + zero fill + 64-bit big-endian bit length).
//!
//! See `sha256.rs` for the rationale behind the module-level lint
//! allows.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]

use fips_module::{require_operational, Error, SelfTestFailure};

/// Output length of SHA-1 in bytes.
pub const DIGEST_SIZE: usize = 20;

/// Input block length of SHA-1 in bytes.
pub const BLOCK_SIZE: usize = 64;

/// Initial hash value H(0) from FIPS 180-4 §5.3.1.
const H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Round constants K(t) from FIPS 180-4 §4.2.1.
const K0: u32 = 0x5a82_7999; // rounds  0..19
const K1: u32 = 0x6ed9_eba1; // rounds 20..39
const K2: u32 = 0x8f1b_bcdc; // rounds 40..59
const K3: u32 = 0xca62_c1d6; // rounds 60..79

// FIPS 180-4 §4.1.1 round functions.
#[inline]
fn f0(b: u32, c: u32, d: u32) -> u32 {
    (b & c) ^ (!b & d)
}

#[inline]
fn f1(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn f2(b: u32, c: u32, d: u32) -> u32 {
    (b & c) ^ (b & d) ^ (c & d)
}

/// SHA-1 streaming hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    /// Creates a new SHA-1 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal())
    }

    /// Construct without consulting the module state machine.
    ///
    /// Used by this crate's power-up KAT and by downstream crates
    /// (fips-hmac, fips-kdf) that need to instantiate a hash while
    /// the module is still in `SelfTest`. Public callers must use
    /// [`Sha1::new`] instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            state: H0,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
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
            compress(&mut self.state, &block);
            self.buffer_len = 0;
            data = tail;
        }

        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            let mut fixed = [0u8; BLOCK_SIZE];
            fixed.copy_from_slice(block);
            compress(&mut self.state, &fixed);
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalizes and returns the 20-byte digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bit_len: u64 = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > BLOCK_SIZE - 8 {
            for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffer_len = 0;
        }
        for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE - 8] {
            *b = 0;
        }
        self.buffer[BLOCK_SIZE - 8..BLOCK_SIZE].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        compress(&mut self.state, &block);

        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-1 compression function — one 512-bit block.
fn compress(state: &mut [u32; 5], block: &[u8; BLOCK_SIZE]) {
    // 1. Prepare the message schedule W[0..80].
    let mut w = [0u32; 80];
    for i in 0..16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    // Four 20-round blocks, each with its own f and K.
    for i in 0..20 {
        let t = a
            .rotate_left(5)
            .wrapping_add(f0(b, c, d))
            .wrapping_add(e)
            .wrapping_add(K0)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 20..40 {
        let t = a
            .rotate_left(5)
            .wrapping_add(f1(b, c, d))
            .wrapping_add(e)
            .wrapping_add(K1)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 40..60 {
        let t = a
            .rotate_left(5)
            .wrapping_add(f2(b, c, d))
            .wrapping_add(e)
            .wrapping_add(K2)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for i in 60..80 {
        let t = a
            .rotate_left(5)
            .wrapping_add(f1(b, c, d))
            .wrapping_add(e)
            .wrapping_add(K3)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// One-shot SHA-1.
pub fn sha1(data: &[u8]) -> Result<[u8; DIGEST_SIZE], Error> {
    let mut h = Sha1::new()?;
    h.update(data);
    Ok(h.finalize())
}

// ------------------------------------------------------------------------
// Power-up self-test
// ------------------------------------------------------------------------

/// SHA-1("abc") — FIPS 180-4 §A.1 example.
const KAT_ABC_DIGEST: [u8; DIGEST_SIZE] = [
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, //
    0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d, //
];

/// Power-up KAT for SHA-1.
pub fn self_test() -> Result<(), SelfTestFailure> {
    let mut h = Sha1::new_internal();
    h.update(b"abc");
    if h.finalize() == KAT_ABC_DIGEST {
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
    use super::{self_test, sha1, Sha1, DIGEST_SIZE, KAT_ABC_DIGEST};
    use fips_module::{initialize_with_tests, KatEntry};

    fn hex(s: &str) -> [u8; DIGEST_SIZE] {
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
            name: "sha1-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn kat_abc_appendix_a1() {
        let mut h = Sha1::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST);
    }

    #[test]
    fn kat_empty_string() {
        // SHA-1("") — NIST CAVP
        let expected = hex("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let mut h = Sha1::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_two_block_appendix_a2() {
        // FIPS 180-4 §A.2: "abcdbcde...nopq"
        let msg: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        let mut h = Sha1::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_one_million_a() {
        // SHA-1 of 1,000,000 'a' bytes — FIPS 180-4 §A.3.
        let expected = hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        let mut h = Sha1::new_internal();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        ensure_initialized();
        let one_shot = sha1(msg).unwrap();
        let mut h = Sha1::new().unwrap();
        h.update(&msg[..13]);
        h.update(&msg[13..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn digest_size_is_20() {
        assert_eq!(DIGEST_SIZE, 20);
    }
}
