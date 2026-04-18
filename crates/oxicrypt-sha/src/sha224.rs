//! SHA-224 per FIPS 180-4 §6.3.
//!
//! SHA-224 shares its entire compression function, message schedule,
//! and padding with SHA-256. The only differences are:
//!
//! 1. A different initial hash value H(0), from FIPS 180-4 §5.3.2.
//! 2. The digest is truncated from 32 to 28 bytes (the leftmost 224
//!    bits of the final H).
//!
//! The KAT is the FIPS 180-4 Appendix A example, SHA-224("abc").
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::sha256::{compress256, BLOCK_SIZE as SHA256_BLOCK};
use oxicrypt_module::{require_allowed, require_operational, Error, SelfTestFailure, Service};

/// Output length of SHA-224 in bytes (28 = 224/8).
pub const DIGEST_SIZE: usize = 28;

/// Input block length of SHA-224 in bytes — same as SHA-256.
pub const BLOCK_SIZE: usize = SHA256_BLOCK;

/// SHA-224 initial hash value H(0) from FIPS 180-4 §5.3.2.
const H0: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// SHA-224 streaming hasher.
///
/// Identical internal state layout to SHA-256. [`Sha224::finalize`]
/// truncates the 32-byte SHA-256 output to 28 bytes.
#[derive(Clone)]
pub struct Sha224 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha224 {
    /// Creates a new SHA-224 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha224)?;
        Ok(Self::new_internal())
    }

    /// Constructor that bypasses the module state machine.
    ///
    /// Used by this crate's power-up KAT and by downstream crates
    /// (fips-hmac, fips-kdf) that need to instantiate a hash while
    /// the module is still in `SelfTest`. Public callers must use
    /// [`Sha224::new`] instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            state: H0,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feeds `data` into the hasher. Identical control flow to
    /// `Sha256::update`; differs only in the compression IV.
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
            compress256(&mut self.state, &block);
            self.buffer_len = 0;
            data = tail;
        }

        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            let mut fixed = [0u8; BLOCK_SIZE];
            fixed.copy_from_slice(block);
            compress256(&mut self.state, &fixed);
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalizes and returns the 28-byte digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bit_len: u64 = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > BLOCK_SIZE - 8 {
            for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            compress256(&mut self.state, &block);
            self.buffer_len = 0;
        }
        for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE - 8] {
            *b = 0;
        }

        self.buffer[BLOCK_SIZE - 8..BLOCK_SIZE].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        compress256(&mut self.state, &block);

        // Truncate to 28 bytes: the leftmost 7 32-bit words of H.
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter().take(7)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Drop for Sha224 {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize_u32(&mut self.state);
        oxicrypt_zeroize::zeroize(&mut self.buffer);
    }
}

/// One-shot SHA-224: hash `data` and return the digest.
pub fn sha224(data: &[u8]) -> Result<[u8; DIGEST_SIZE], Error> {
    let mut h = Sha224::new()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for the FIPS 180-4 Appendix A example:
/// SHA-224("abc"). Retained for the cross-check tests below; the
/// power-up KAT uses a NIST CAVP SHS vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_ABC_DIGEST: [u8; DIGEST_SIZE] = [
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, //
    0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, //
    0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, //
    0xe3, 0x6c, 0x9d, 0xa7, //
];

/// Power-up KAT for SHA-224.
///
/// Sourced from the NIST CAVP Secure Hash Standard (SHS) byte-oriented
/// short-message test vectors (`SHA224ShortMsg.rsp`, Len=8). Constants
/// are re-exported from `fips-test-vectors`, which pins the vendored
/// file's SHA-256 in `vendor/nist/MANIFEST.toml`.
pub fn self_test() -> Result<(), SelfTestFailure> {
    let mut h = Sha224::new_internal();
    h.update(&oxicrypt_test_vectors::SHA_224_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA_224_MD {
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
    use super::{self_test, sha224, Sha224, DIGEST_SIZE, KAT_ABC_DIGEST};
    use oxicrypt_module::{initialize_with_tests, KatEntry};

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
            name: "sha224-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn kat_abc_appendix_a() {
        let mut h = Sha224::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST);
    }

    #[test]
    fn kat_two_block_appendix_a() {
        // FIPS 180-4 Appendix A example 2.
        let msg: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
        let mut h = Sha224::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_empty_string() {
        // NIST CAVP example: SHA-224("")
        let expected = hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        let mut h = Sha224::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        ensure_initialized();
        let one_shot = sha224(msg).unwrap();

        let mut h = Sha224::new().unwrap();
        h.update(&msg[..10]);
        h.update(&msg[10..25]);
        h.update(&msg[25..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn digest_size_is_28() {
        assert_eq!(DIGEST_SIZE, 28);
    }
}
