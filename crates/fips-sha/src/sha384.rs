//! SHA-384 per FIPS 180-4 §6.5.
//!
//! SHA-384 uses the SHA-512 compression function with a different
//! initial hash value and truncates the output to the leftmost 384
//! bits (48 bytes / 6 64-bit words).
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::sha512::{Sha512State, BLOCK_SIZE as SHA512_BLOCK};
use fips_module::{require_operational, Error, SelfTestFailure};

/// Output length of SHA-384 in bytes.
pub const DIGEST_SIZE: usize = 48;

/// Input block length of SHA-384 in bytes — same as SHA-512.
pub const BLOCK_SIZE: usize = SHA512_BLOCK;

/// SHA-384 initial hash value H(0) from FIPS 180-4 §5.3.4.
const H0: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// SHA-384 streaming hasher.
#[derive(Clone)]
pub struct Sha384 {
    inner: Sha512State,
}

impl Sha384 {
    /// Creates a new SHA-384 hasher, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal())
    }

    const fn new_internal() -> Self {
        Self {
            inner: Sha512State::with_iv(H0),
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes and returns the 48-byte digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        self.inner.finalize_state();
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.inner.state.iter().take(6)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One-shot SHA-384.
pub fn sha384(data: &[u8]) -> Result<[u8; DIGEST_SIZE], Error> {
    let mut h = Sha384::new()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for the FIPS 180-4 Appendix D.1 example:
/// SHA-384("abc").
const KAT_ABC_DIGEST: [u8; DIGEST_SIZE] = [
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, //
    0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, //
    0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, //
    0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, //
    0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, //
    0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7, //
];

/// Power-up KAT for SHA-384.
pub fn self_test() -> Result<(), SelfTestFailure> {
    let mut h = Sha384::new_internal();
    h.update(b"abc");
    if h.finalize() == KAT_ABC_DIGEST {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{self_test, sha384, Sha384, DIGEST_SIZE, KAT_ABC_DIGEST};
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
            name: "sha384-unit-test-bootstrap",
            run: self_test,
        }]);
    }

    #[test]
    fn self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn kat_abc_appendix_d1() {
        let mut h = Sha384::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_ABC_DIGEST);
    }

    #[test]
    fn kat_empty_string() {
        // NIST CAVP: SHA-384("")
        let expected = hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        );
        let mut h = Sha384::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn kat_two_block_appendix_d2() {
        // FIPS 180-4 Appendix D.2
        let msg: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex(
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039",
        );
        let mut h = Sha384::new_internal();
        h.update(msg);
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        ensure_initialized();
        let one_shot = sha384(msg).unwrap();
        let mut h = Sha384::new().unwrap();
        h.update(&msg[..20]);
        h.update(&msg[20..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn digest_size_is_48() {
        assert_eq!(DIGEST_SIZE, 48);
    }
}
