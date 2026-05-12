//! SHA-3 fixed-length hash functions per FIPS 202 §6.1.
//!
//! Provides SHA3-224, SHA3-256, SHA3-384, and SHA3-512 as
//! `Sponge`-based streaming hashers. The rate for each variant is
//! derived from FIPS 202 Table 3:
//!
//!   SHA3-224: rate = (1600 − 448)  = 1152 bits = 144 bytes
//!   SHA3-256: rate = (1600 − 512)  = 1088 bits = 136 bytes
//!   SHA3-384: rate = (1600 − 768)  =  832 bits = 104 bytes
//!   SHA3-512: rate = (1600 − 1024) =  576 bits =  72 bytes
//!
//! Domain separation byte: 0x06 for all SHA-3 fixed-length hashes
//! (FIPS 202 §B.2).
//!
//! Each variant ships its own power-up KAT over SHA3-n("abc").
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::keccak::Sponge;
use oxicrypt_module::{Error, SelfTestFailure, Service, require_allowed, require_operational};

/// Domain-separation byte for SHA-3 fixed-length variants.
const SHA3_DOMAIN: u8 = 0x06;

// ========================================================================
// Shared streaming wrapper
// ========================================================================

/// A SHA-3 hasher, parameterized by rate and output size.
///
/// All four SHA-3 variants share this type; the concrete variants
/// below are type aliases.
#[derive(Clone)]
pub struct Sha3<const RATE: usize, const OUT: usize> {
    sponge: Sponge<RATE>,
    finalized: bool,
}

impl<const RATE: usize, const OUT: usize> Sha3<RATE, OUT> {
    /// Constructor that bypasses the module state machine.
    ///
    /// Used by this crate's power-up KATs and by downstream crates
    /// (fips-hmac) that need to instantiate a hash while the module
    /// is still in `SelfTest`. Public callers must use the typed
    /// constructors like `Sha3_256::new_256` instead.
    #[doc(hidden)]
    pub const fn new_internal() -> Self {
        Self {
            sponge: Sponge::new(),
            finalized: false,
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.sponge.absorb(data);
    }

    /// Finalizes and returns the fixed-length digest.
    pub fn finalize(mut self) -> [u8; OUT] {
        self.sponge.finalize(SHA3_DOMAIN);
        self.finalized = true;
        let mut out = [0u8; OUT];
        self.sponge.squeeze(&mut out);
        out
    }
}

// ========================================================================
// SHA3-224
// ========================================================================

/// Output length of SHA3-224 in bytes.
pub const SHA3_224_DIGEST_SIZE: usize = 28;

/// Rate (bitrate in bytes) of SHA3-224.
pub const SHA3_224_RATE: usize = 144;

/// SHA3-224 streaming hasher.
pub type Sha3_224 = Sha3<SHA3_224_RATE, SHA3_224_DIGEST_SIZE>;

impl Sha3_224 {
    /// Creates a new SHA3-224 hasher, enforcing the module boundary.
    pub fn new_224() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha3_224)?;
        Ok(Self::new_internal())
    }
}

/// One-shot SHA3-224.
pub fn sha3_224(data: &[u8]) -> Result<[u8; SHA3_224_DIGEST_SIZE], Error> {
    let mut h = Sha3_224::new_224()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA3-224("abc") from FIPS 202 Appendix A.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST ACVP-Server vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_SHA3_224_ABC: [u8; SHA3_224_DIGEST_SIZE] = [
    0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a, //
    0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f, //
    0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad, //
    0x73, 0xb4, 0x6f, 0xdf, //
];

/// Power-up KAT for SHA3-224.
///
/// Sourced from NIST ACVP-Server `SHA3-224-2.0/internalProjection.json`
/// via `fips-test-vectors`; the selected tgId/tcId and the vendored
/// slice file's SHA-256 are recorded in `vendor/nist/MANIFEST.toml`.
pub fn self_test_224() -> Result<(), SelfTestFailure> {
    let mut h = <Sha3_224>::new_internal();
    h.update(&oxicrypt_test_vectors::SHA3_224_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA3_224_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// SHA3-256
// ========================================================================

/// Output length of SHA3-256 in bytes.
pub const SHA3_256_DIGEST_SIZE: usize = 32;

/// Rate of SHA3-256 in bytes.
pub const SHA3_256_RATE: usize = 136;

/// SHA3-256 streaming hasher.
pub type Sha3_256 = Sha3<SHA3_256_RATE, SHA3_256_DIGEST_SIZE>;

impl Sha3_256 {
    /// Creates a new SHA3-256 hasher, enforcing the module boundary.
    pub fn new_256() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha3_256)?;
        Ok(Self::new_internal())
    }
}

/// One-shot SHA3-256.
pub fn sha3_256(data: &[u8]) -> Result<[u8; SHA3_256_DIGEST_SIZE], Error> {
    let mut h = Sha3_256::new_256()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA3-256("abc") from FIPS 202 Appendix A.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST ACVP-Server vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_SHA3_256_ABC: [u8; SHA3_256_DIGEST_SIZE] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, //
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd, //
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, //
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32, //
];

/// Power-up KAT for SHA3-256.
///
/// Sourced from NIST ACVP-Server `SHA3-256-2.0/internalProjection.json`
/// via `fips-test-vectors`.
pub fn self_test_256() -> Result<(), SelfTestFailure> {
    let mut h = <Sha3_256>::new_internal();
    h.update(&oxicrypt_test_vectors::SHA3_256_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA3_256_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// SHA3-384
// ========================================================================

/// Output length of SHA3-384 in bytes.
pub const SHA3_384_DIGEST_SIZE: usize = 48;

/// Rate of SHA3-384 in bytes.
pub const SHA3_384_RATE: usize = 104;

/// SHA3-384 streaming hasher.
pub type Sha3_384 = Sha3<SHA3_384_RATE, SHA3_384_DIGEST_SIZE>;

impl Sha3_384 {
    /// Creates a new SHA3-384 hasher, enforcing the module boundary.
    pub fn new_384() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha3_384)?;
        Ok(Self::new_internal())
    }
}

/// One-shot SHA3-384.
pub fn sha3_384(data: &[u8]) -> Result<[u8; SHA3_384_DIGEST_SIZE], Error> {
    let mut h = Sha3_384::new_384()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA3-384("abc") from FIPS 202 Appendix A.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST ACVP-Server vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_SHA3_384_ABC: [u8; SHA3_384_DIGEST_SIZE] = [
    0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, //
    0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d, //
    0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, //
    0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2, //
    0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, //
    0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25, //
];

/// Power-up KAT for SHA3-384.
///
/// Sourced from NIST ACVP-Server `SHA3-384-2.0/internalProjection.json`
/// via `fips-test-vectors`.
pub fn self_test_384() -> Result<(), SelfTestFailure> {
    let mut h = <Sha3_384>::new_internal();
    h.update(&oxicrypt_test_vectors::SHA3_384_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA3_384_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// SHA3-512
// ========================================================================

/// Output length of SHA3-512 in bytes.
pub const SHA3_512_DIGEST_SIZE: usize = 64;

/// Rate of SHA3-512 in bytes.
pub const SHA3_512_RATE: usize = 72;

/// SHA3-512 streaming hasher.
pub type Sha3_512 = Sha3<SHA3_512_RATE, SHA3_512_DIGEST_SIZE>;

impl Sha3_512 {
    /// Creates a new SHA3-512 hasher, enforcing the module boundary.
    pub fn new_512() -> Result<Self, Error> {
        require_operational()?;
        require_allowed(Service::Sha3_512)?;
        Ok(Self::new_internal())
    }
}

/// One-shot SHA3-512.
pub fn sha3_512(data: &[u8]) -> Result<[u8; SHA3_512_DIGEST_SIZE], Error> {
    let mut h = Sha3_512::new_512()?;
    h.update(data);
    Ok(h.finalize())
}

/// Expected digest for SHA3-512("abc") from FIPS 202 Appendix A.
/// Retained for the cross-check tests below; the power-up KAT uses
/// a NIST ACVP-Server vector via `oxicrypt_test_vectors`.
#[cfg(test)]
const KAT_SHA3_512_ABC: [u8; SHA3_512_DIGEST_SIZE] = [
    0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, //
    0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, //
    0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, //
    0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e, //
    0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, //
    0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, //
    0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, //
    0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0, //
];

/// Power-up KAT for SHA3-512.
///
/// Sourced from NIST ACVP-Server `SHA3-512-2.0/internalProjection.json`
/// via `fips-test-vectors`.
pub fn self_test_512() -> Result<(), SelfTestFailure> {
    let mut h = <Sha3_512>::new_internal();
    h.update(&oxicrypt_test_vectors::SHA3_512_MSG);
    if h.finalize() == oxicrypt_test_vectors::SHA3_512_MD {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ========================================================================
// Unit tests
// ========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{
        KAT_SHA3_224_ABC, KAT_SHA3_256_ABC, KAT_SHA3_384_ABC, KAT_SHA3_512_ABC,
        SHA3_224_DIGEST_SIZE, SHA3_256_DIGEST_SIZE, SHA3_384_DIGEST_SIZE, SHA3_512_DIGEST_SIZE,
        Sha3_224, Sha3_256, Sha3_384, Sha3_512, self_test_224, self_test_256, self_test_384,
        self_test_512, sha3_256, sha3_512,
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

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        let bytes = s.as_bytes();
        for i in 0..N {
            out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        }
        out
    }

    fn ensure_initialized() {
        let _ = initialize_with_tests(&[
            KatEntry {
                name: "sha3-224-bootstrap",
                run: self_test_224,
            },
            KatEntry {
                name: "sha3-256-bootstrap",
                run: self_test_256,
            },
            KatEntry {
                name: "sha3-384-bootstrap",
                run: self_test_384,
            },
            KatEntry {
                name: "sha3-512-bootstrap",
                run: self_test_512,
            },
        ]);
    }

    #[test]
    fn sha3_224_self_test() {
        self_test_224().unwrap();
    }

    #[test]
    fn sha3_256_self_test() {
        self_test_256().unwrap();
    }

    #[test]
    fn sha3_384_self_test() {
        self_test_384().unwrap();
    }

    #[test]
    fn sha3_512_self_test() {
        self_test_512().unwrap();
    }

    #[test]
    fn sha3_224_kat_abc_matches_appendix_a() {
        let mut h = <Sha3_224>::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_SHA3_224_ABC);
    }

    #[test]
    fn sha3_256_kat_abc_matches_appendix_a() {
        let mut h = <Sha3_256>::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_SHA3_256_ABC);
    }

    #[test]
    fn sha3_384_kat_abc_matches_appendix_a() {
        let mut h = <Sha3_384>::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_SHA3_384_ABC);
    }

    #[test]
    fn sha3_512_kat_abc_matches_appendix_a() {
        let mut h = <Sha3_512>::new_internal();
        h.update(b"abc");
        assert_eq!(h.finalize(), KAT_SHA3_512_ABC);
    }

    #[test]
    fn sha3_224_empty_string() {
        let expected: [u8; SHA3_224_DIGEST_SIZE] =
            hex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        let mut h = <Sha3_224>::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha3_256_empty_string() {
        let expected: [u8; SHA3_256_DIGEST_SIZE] =
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        let mut h = <Sha3_256>::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha3_384_empty_string() {
        let expected: [u8; SHA3_384_DIGEST_SIZE] = hex(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
             c3713831264adb47fb6bd1e058d5f004",
        );
        let mut h = <Sha3_384>::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha3_512_empty_string() {
        let expected: [u8; SHA3_512_DIGEST_SIZE] = hex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        );
        let mut h = <Sha3_512>::new_internal();
        h.update(b"");
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn sha3_256_streaming_matches_one_shot() {
        // SHA3-256 rate is 136 bytes, so use a message that straddles
        // several rate-block boundaries to exercise the absorb loop.
        let msg: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        ensure_initialized();
        let one_shot = sha3_256(&msg).unwrap();
        let mut h = Sha3_256::new_256().unwrap();
        h.update(&msg[..50]);
        h.update(&msg[50..200]);
        h.update(&msg[200..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn sha3_512_streaming_matches_one_shot() {
        // SHA3-512 rate is 72 bytes — smallest SHA-3 rate, so a
        // 200-byte message crosses several block boundaries.
        let msg: [u8; 200] = core::array::from_fn(|i| (i as u8).wrapping_add(3));
        ensure_initialized();
        let one_shot = sha3_512(&msg).unwrap();
        let mut h = Sha3_512::new_512().unwrap();
        h.update(&msg[..71]);
        h.update(&msg[71..145]);
        h.update(&msg[145..]);
        assert_eq!(h.finalize(), one_shot);
    }
}
