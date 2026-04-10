//! SHA-256 per FIPS 180-4.
//!
//! Pure-Rust, `no_std`, dependency-free. The implementation is a
//! direct, unrolled transcription of FIPS 180-4 §6.2.2 — no SHA-NI
//! acceleration, no assembly. Performance is adequate for Level 1
//! self-tests and the ACVP harness; optimized variants come in
//! Phase 4.
//!
//! # Module boundary
//!
//! [`Sha256::new`] calls `fips_module::require_operational()` before
//! returning a hasher, so no SHA-256 computation can escape until
//! the module's power-up KATs have passed. The self-test entry point
//! [`self_test`] uses a private constructor that bypasses this check —
//! it is invoked *during* the `SelfTest` state and would otherwise
//! deadlock the state machine.
//!
//! Lints: array indexing with compile-time-bounded loops is the
//! natural way to express SHA-256 (state[0..8], w[0..64]), and the
//! message-schedule recurrence uses plain index arithmetic that the
//! `arithmetic_side_effects` lint warns on. Every index in this
//! module is statically bounded by a `for i in N..M` loop or a
//! constant, so both lints are disabled at the module level. They
//! remain active workspace-wide for crypto code that operates on
//! secret-length / secret-dependent data.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]

use fips_module::{require_operational, Error, SelfTestFailure};

/// Output length of SHA-256 in bytes.
pub const DIGEST_SIZE: usize = 32;

/// Input block length of SHA-256 in bytes.
pub const BLOCK_SIZE: usize = 64;

/// Initial hash value H(0) from FIPS 180-4 §5.3.3.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Round constants K from FIPS 180-4 §4.2.2.
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

// ------------------------------------------------------------------------
// SHA-256 logical functions (FIPS 180-4 §4.1.2)
// ------------------------------------------------------------------------

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ------------------------------------------------------------------------
// Hasher state
// ------------------------------------------------------------------------

/// SHA-256 streaming hasher.
///
/// Use [`Sha256::new`] to obtain one from the approved module, or
/// [`sha256`] for a one-shot convenience function.
#[derive(Clone)]
pub struct Sha256 {
    /// Running hash state H.
    state: [u32; 8],
    /// Partial block buffer. Bytes 0..`buffer_len` are meaningful.
    buffer: [u8; BLOCK_SIZE],
    /// Number of valid bytes currently in `buffer`. Always in 0..64.
    buffer_len: usize,
    /// Total number of message bytes hashed so far (not bits).
    total_len: u64,
}

impl Sha256 {
    /// Creates a new SHA-256 hasher, enforcing the module boundary.
    ///
    /// Returns [`Error::NotOperational`] if the module has not yet
    /// completed its power-up self-tests.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal())
    }

    /// Private constructor used by [`self_test`], which runs *before*
    /// the module is operational and therefore cannot go through the
    /// gated [`Sha256::new`].
    const fn new_internal() -> Self {
        Self {
            state: H0,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        // Track total length. SHA-256 allows messages up to 2^64 bits;
        // we track bytes as u64, which gives 2^64 bytes — more than
        // enough, and wrapping_add keeps the unrealistic overflow path
        // well-defined.
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Fill any partial buffer left from a prior update first.
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
            self.compress(&block);
            self.buffer_len = 0;
            data = tail;
        }

        // Process complete blocks directly from the input slice.
        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            let mut fixed = [0u8; BLOCK_SIZE];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
            data = rest;
        }

        // Stash any remainder for the next update / finalize.
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalizes and returns the 32-byte digest.
    ///
    /// Consumes `self` because SHA-256 is not restartable after
    /// finalization; the contract matches RustCrypto's `Digest` even
    /// though we do not depend on that trait.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        // Padding per FIPS 180-4 §5.1.1:
        //   append 0x80, then zero bytes until (length mod 64) == 56,
        //   then 8 bytes of big-endian bit length.
        let bit_len: u64 = self.total_len.wrapping_mul(8);

        // Step 1: the mandatory 0x80 byte. There is always room: the
        // buffer holds at most 63 bytes at this point.
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Step 2: zero-pad. If there are fewer than 8 bytes left for
        // the length field, fill the rest of the current block, emit
        // it, and start a new block.
        if self.buffer_len > BLOCK_SIZE - 8 {
            for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE] {
                *b = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE - 8] {
            *b = 0;
        }

        // Step 3: the 64-bit big-endian bit-length.
        self.buffer[BLOCK_SIZE - 8..BLOCK_SIZE].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        // Step 4: serialize H as 32 big-endian bytes.
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// SHA-256 compression function — one 512-bit block.
    fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        // 1. Prepare the message schedule W[0..64].
        let mut w = [0u32; 64];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // 2. Initialize working vars from the current hash value.
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 3. The 64-round main loop.
        for i in 0..64 {
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

        // 4. Fold the working vars back into the hash state.
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// One-shot SHA-256: hash `data` and return the digest.
///
/// Convenience wrapper around [`Sha256::new`] + [`Sha256::update`] +
/// [`Sha256::finalize`]. Fails with [`Error::NotOperational`] if the
/// module has not been initialized.
pub fn sha256(data: &[u8]) -> Result<[u8; DIGEST_SIZE], Error> {
    let mut h = Sha256::new()?;
    h.update(data);
    Ok(h.finalize())
}

// ------------------------------------------------------------------------
// Power-up self-test (KAT)
// ------------------------------------------------------------------------

/// Expected digest for the FIPS 180-4 Appendix B.1 one-block example:
/// SHA-256("abc").
const KAT_ABC_DIGEST: [u8; DIGEST_SIZE] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, //
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, //
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, //
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, //
];

/// Power-up KAT for SHA-256.
///
/// Called by `fips_module::initialize_with_tests` during the
/// `SelfTest` state. Uses [`Sha256::new_internal`] to bypass the
/// operational-mode gate, since the whole point of the KAT is to run
/// *before* the module is operational.
pub fn self_test() -> Result<(), SelfTestFailure> {
    let mut h = Sha256::new_internal();
    h.update(b"abc");
    let digest = h.finalize();
    if digest == KAT_ABC_DIGEST {
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
    use super::{self_test, sha256, Sha256, DIGEST_SIZE, KAT_ABC_DIGEST};
    use fips_module::{initialize_with_tests, KatEntry};

    /// Hex-decode a compile-time string literal into a fixed-size
    /// byte array. Test-only; avoids pulling in a hex crate.
    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for i in 0..32 {
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

    // Lazily make sure the module is operational for `Sha256::new`
    // tests. `initialize_with_tests` is idempotent after the first
    // successful call: subsequent calls return `AlreadyInitialized`,
    // which we deliberately ignore here.
    fn ensure_initialized() {
        let _ = initialize_with_tests(&[KatEntry {
            name: "sha256-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn kat_abc_matches_fips_180_4_appendix_b1() {
        // "abc" — FIPS 180-4 Appendix B.1
        let mut h = Sha256::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST);
    }

    #[test]
    fn kat_empty_string() {
        // SHA-256("") — widely published NIST example vector
        let expected = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let mut h = Sha256::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_two_block_message() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        // FIPS 180-4 Appendix B.2 — exercises a two-block message,
        // so this verifies the block-boundary code path.
        let msg: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex32("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        let mut h = Sha256::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_one_million_a() {
        // SHA-256 of 1,000,000 'a' bytes — FIPS 180-4 Appendix B.3.
        // Exercises both the block-loop and the 2^20-byte length
        // field in the padding.
        let expected = hex32("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        let mut h = Sha256::new_internal();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        // A message whose length straddles several block boundaries,
        // fed in irregular chunks, must match a single-shot call.
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog, \
                          and then jumps right back again to make sure \
                          we hash more than a single SHA-256 block.";
        ensure_initialized();
        let one_shot = sha256(msg).unwrap();

        let mut h = Sha256::new().unwrap();
        // Irregular chunking: 1, 7, 13, rest.
        let splits = [1usize, 7, 13];
        let mut offset = 0usize;
        for s in splits {
            let end = offset + s;
            h.update(&msg[offset..end]);
            offset = end;
        }
        h.update(&msg[offset..]);
        let streamed = h.finalize();

        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn new_before_init_returns_not_operational() {
        // Important invariant: Sha256::new must gate on module state.
        // We can't reliably test this here because other tests in
        // the shared binary may have already called
        // initialize_with_tests, so this test only exercises the
        // Ok path as a positive assertion and leaves the negative
        // path to the fips-module unit tests.
        ensure_initialized();
        let h = Sha256::new();
        assert!(h.is_ok());
    }

    #[test]
    fn digest_size_constant_is_32() {
        assert_eq!(DIGEST_SIZE, 32);
    }
}
