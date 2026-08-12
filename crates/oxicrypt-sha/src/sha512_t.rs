//! SHA-512/224 and SHA-512/256 per FIPS 180-4 §5.3.6 and §6.6/§6.7.
//!
//! Both variants reuse the SHA-512 compression function and padding;
//! they differ from SHA-512 only in the initial hash value and in the
//! output truncation. The initial hash values are the pre-computed
//! SHA-512/t IVs from FIPS 180-4 §5.3.6.1 and §5.3.6.2 respectively
//! — these are *not* the same as SHA-512's IV with a different mask;
//! they are the result of running a modified SHA-512 over the ASCII
//! string "SHA-512/224" / "SHA-512/256", as described in the spec.
//!
//! SHA-512/224 and SHA-512/256 are approved digest algorithms per
//! FIPS 180-4. Each ships its own power-up KAT; a KAT over SHA-256 or
//! SHA-512 does not cover them.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::sha512::{BLOCK_SIZE as SHA512_BLOCK, Sha512State};
use oxicrypt_module::{Error, SelfTestFailure, Service, require_allowed, require_operational};

// ========================================================================
// SHA-512/224
// ========================================================================

/// Output length of SHA-512/224 in bytes.
pub const DIGEST_SIZE_224: usize = 28;

/// Input block length of SHA-512/224 in bytes — same as SHA-512.
pub const BLOCK_SIZE_224: usize = SHA512_BLOCK;

/// SHA-512/224 initial hash value (FIPS 180-4 §5.3.6.1).
const H0_224: [u64; 8] = [
    0x8c3d_37c8_1954_4da2,
    0x73e1_9966_89dc_d4d6,
    0x1dfa_b7ae_32ff_9c82,
    0x679d_d514_582f_9fcf,
    0x0f6d_2b69_7bd4_4da8,
    0x77e3_6f73_04c4_8942,
    0x3f9d_85a8_6a1d_36c8,
    0x1112_e6ad_91d6_92a1,
];

/// SHA-512/224 streaming hasher.
#[derive(Clone)]
pub struct Sha512_224 {
    inner: Sha512State,
}

impl Sha512_224 {
    /// Creates a new SHA-512/224 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha512_224)?;
        Ok(Self::new_internal())
    }

    /// Constructor that bypasses the module state machine.
    ///
    /// Used by this crate's power-up KAT and by downstream crates
    /// (oxicrypt-hmac, oxicrypt-kdf) that need to instantiate a hash while
    /// the module is still in `SelfTest`. Public callers must use
    /// [`Sha512_224::new`] instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            inner: Sha512State::with_iv(H0_224),
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes and returns the 28-byte digest (leftmost 224 bits).
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE_224] {
        self.inner.finalize_state();
        // Leftmost 224 bits = 28 bytes = 3 full u64 words (24 bytes)
        // followed by the top 4 bytes of word 3.
        let mut out = [0u8; DIGEST_SIZE_224];
        for (chunk, word) in out[..24]
            .chunks_exact_mut(8)
            .zip(self.inner.state.iter().take(3))
        {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        let w3_be = self.inner.state[3].to_be_bytes();
        out[24..28].copy_from_slice(&w3_be[..4]);
        out
    }
}

/// One-shot SHA-512/224.
pub fn sha512_224(data: &[u8]) -> Result<[u8; DIGEST_SIZE_224], Error> {
    let mut h = Sha512_224::new()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA-512/224("abc"), NIST CAVP example.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST CAVP SHS vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_ABC_DIGEST_224: [u8; DIGEST_SIZE_224] = [
    0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, //
    0xda, 0xae, 0x75, 0x30, 0x46, 0x08, 0x42, 0xe2, //
    0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4, //
    0x3e, 0x89, 0x24, 0xaa, //
];

/// Power-up KAT for SHA-512/224.
///
/// Sourced from NIST CAVP SHS (`SHA512_224ShortMsg.rsp`, Len=8) via
/// `oxicrypt-test-vectors`.
pub fn self_test_224() -> Result<(), SelfTestFailure> {
    let mut h = Sha512_224::new_internal();
    h.update(&oxicrypt_test_vectors::SHA_512_224_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA_512_224_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// SHA-512/256
// ========================================================================

/// Output length of SHA-512/256 in bytes.
pub const DIGEST_SIZE_256: usize = 32;

/// Input block length of SHA-512/256 in bytes — same as SHA-512.
pub const BLOCK_SIZE_256: usize = SHA512_BLOCK;

/// SHA-512/256 initial hash value (FIPS 180-4 §5.3.6.2).
const H0_256: [u64; 8] = [
    0x2231_2194_fc2b_f72c,
    0x9f55_5fa3_c84c_64c2,
    0x2393_b86b_6f53_b151,
    0x9638_7719_5940_eabd,
    0x9628_3ee2_a88e_ffe3,
    0xbe5e_1e25_5386_3992,
    0x2b01_99fc_2c85_b8aa,
    0x0eb7_2ddc_81c5_2ca2,
];

/// SHA-512/256 streaming hasher.
#[derive(Clone)]
pub struct Sha512_256 {
    inner: Sha512State,
}

impl Sha512_256 {
    /// Creates a new SHA-512/256 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha512_256)?;
        Ok(Self::new_internal())
    }

    /// Constructor that bypasses the module state machine.
    ///
    /// Used by this crate's power-up KAT and by downstream crates
    /// (oxicrypt-hmac, oxicrypt-kdf) that need to instantiate a hash while
    /// the module is still in `SelfTest`. Public callers must use
    /// [`Sha512_256::new`] instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            inner: Sha512State::with_iv(H0_256),
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes and returns the 32-byte digest (leftmost 256 bits).
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE_256] {
        self.inner.finalize_state();
        let mut out = [0u8; DIGEST_SIZE_256];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.inner.state.iter().take(4)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One-shot SHA-512/256.
pub fn sha512_256(data: &[u8]) -> Result<[u8; DIGEST_SIZE_256], Error> {
    let mut h = Sha512_256::new()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA-512/256("abc"), NIST CAVP example.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST CAVP SHS vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_ABC_DIGEST_256: [u8; DIGEST_SIZE_256] = [
    0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, //
    0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab, //
    0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, //
    0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23, //
];

/// Power-up KAT for SHA-512/256.
///
/// Sourced from NIST CAVP SHS (`SHA512_256ShortMsg.rsp`, Len=8) via
/// `oxicrypt-test-vectors`.
pub fn self_test_256() -> Result<(), SelfTestFailure> {
    let mut h = Sha512_256::new_internal();
    h.update(&oxicrypt_test_vectors::SHA_512_256_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA_512_256_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// Unit tests
// ========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        DIGEST_SIZE_224, DIGEST_SIZE_256, KAT_ABC_DIGEST_224, KAT_ABC_DIGEST_256, Sha512_224,
        Sha512_256, self_test_224, self_test_256, sha512_224, sha512_256,
    };
    use oxicrypt_module::{KatEntry, initialize_with_tests};

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex char: {c}"),
        }
    }

    fn hex28(s: &str) -> [u8; DIGEST_SIZE_224] {
        assert_eq!(s.len(), DIGEST_SIZE_224 * 2);
        let mut out = [0u8; DIGEST_SIZE_224];
        let bytes = s.as_bytes();
        for i in 0..DIGEST_SIZE_224 {
            out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        }
        out
    }

    fn hex32(s: &str) -> [u8; DIGEST_SIZE_256] {
        assert_eq!(s.len(), DIGEST_SIZE_256 * 2);
        let mut out = [0u8; DIGEST_SIZE_256];
        let bytes = s.as_bytes();
        for i in 0..DIGEST_SIZE_256 {
            out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        }
        out
    }

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[
            KatEntry {
                name: "sha512-224-unit-test-bootstrap",
                run: self_test_224,
            },
            KatEntry {
                name: "sha512-256-unit-test-bootstrap",
                run: self_test_256,
            },
        ]);
    }

    #[test]
    fn sha512_224_self_test_passes() {
        self_test_224().unwrap();
    }

    #[test]
    fn sha512_256_self_test_passes() {
        self_test_256().unwrap();
    }

    #[test]
    fn sha512_224_kat_abc() {
        let mut h = Sha512_224::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST_224);
    }

    #[test]
    fn sha512_256_kat_abc() {
        let mut h = Sha512_256::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST_256);
    }

    #[test]
    fn sha512_224_empty_string() {
        // NIST CAVP: SHA-512/224("")
        let expected = hex28("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
        let mut h = Sha512_224::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha512_256_empty_string() {
        // NIST CAVP: SHA-512/256("")
        let expected = hex32("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
        let mut h = Sha512_256::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha512_224_two_block() {
        // NIST CAVP SHA-512/224 two-block example.
        let msg: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex28("23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
        let mut h = Sha512_224::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha512_256_two_block() {
        // NIST CAVP SHA-512/256 two-block example.
        let msg: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex32("3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
        let mut h = Sha512_256::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha512_224_streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        ensure_initialized();
        let one_shot = sha512_224(msg).unwrap();
        let mut h = Sha512_224::new().unwrap();
        h.update(&msg[..17]);
        h.update(&msg[17..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn sha512_256_streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        ensure_initialized();
        let one_shot = sha512_256(msg).unwrap();
        let mut h = Sha512_256::new().unwrap();
        h.update(&msg[..5]);
        h.update(&msg[5..]);
        assert_eq!(h.finalize(), one_shot);
    }
}
