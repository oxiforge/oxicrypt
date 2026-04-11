//! SHAKE128 / SHAKE256 extendable-output functions per FIPS 202 §6.2.
//!
//! # Approved algorithms
//!
//! | Algorithm | Standard | Rate (bytes) | Capacity (bits) |
//! |-----------|----------|--------------|-----------------|
//! | SHAKE128 | FIPS 202 §6.2 | 168 | 256 |
//! | SHAKE256 | FIPS 202 §6.2 | 136 | 512 |
//!
//! Both use the SHAKE domain-separation byte `0x1f`
//! (FIPS 202 §B.2) and share the Keccak-f\[1600\] permutation
//! and sponge exposed by `fips_sha::keccak`. cSHAKE, KMAC, and
//! the rest of the SP 800-185 family are not yet in scope.
//!
//! # API shape
//!
//! SHAKE is an XOF, not a hash: the output length is chosen by
//! the caller at squeeze time, not fixed at construction. The
//! streaming API is `new → update* → finalize → squeeze*`.
//! `squeeze` may be called repeatedly for arbitrarily long
//! output.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one pinned SHAKE128 and one pinned SHAKE256
//! vector, with the squeeze length matched to the NIST ACVP
//! reference output.
//!
//! # Sensitive security parameters
//!
//! None. SHAKE is a keyless public primitive; all inputs and
//! outputs are public.
//!
//! # FIPS module gating
//!
//! Public SHAKE entry points gate on
//! [`fips_module::require_operational`] and expose a hidden
//! `*_internal` surface for in-module consumers (e.g. a future
//! SP 800-185 KMAC) that need to run during `SelfTest`.

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fips_module::{require_operational, Error, KatEntry, SelfTestFailure};
use fips_sha::keccak::Sponge;

/// SHAKE domain-separation byte (FIPS 202 §B.2).
const SHAKE_DOMAIN: u8 = 0x1f;

/// SHAKE128 rate in bytes.
pub const SHAKE128_RATE: usize = 168;

/// SHAKE256 rate in bytes.
pub const SHAKE256_RATE: usize = 136;

/// Internal XOF state, parameterized by rate.
#[derive(Clone)]
struct ShakeCore<const RATE: usize> {
    sponge: Sponge<RATE>,
    finalized: bool,
}

impl<const RATE: usize> ShakeCore<RATE> {
    const fn new_internal() -> Self {
        Self {
            sponge: Sponge::new(),
            finalized: false,
        }
    }

    fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.sponge.absorb(data);
    }

    fn finalize(&mut self) {
        debug_assert!(!self.finalized);
        self.sponge.finalize(SHAKE_DOMAIN);
        self.finalized = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.finalized);
        self.sponge.squeeze(out);
    }
}

// ========================================================================
// SHAKE128
// ========================================================================

/// SHAKE128 extendable-output hasher.
#[derive(Clone)]
pub struct Shake128 {
    core: ShakeCore<SHAKE128_RATE>,
}

impl Shake128 {
    /// Creates a new SHAKE128 XOF, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal())
    }

    const fn new_internal() -> Self {
        Self {
            core: ShakeCore::new_internal(),
        }
    }

    /// Feeds `data` into the XOF. Legal only before `finalize`.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes the absorb phase. After this call, no more `update`s
    /// are legal; `squeeze` may be called one or more times to read
    /// output.
    pub fn finalize(&mut self) {
        self.core.finalize();
    }

    /// Squeezes `out.len()` bytes of output. May be called repeatedly
    /// after `finalize`.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.core.squeeze(out);
    }
}

/// One-shot SHAKE128: absorb `data`, finalize, squeeze `OUT_LEN`
/// bytes.
pub fn shake128<const OUT_LEN: usize>(data: &[u8]) -> Result<[u8; OUT_LEN], Error> {
    let mut x = Shake128::new()?;
    x.update(data);
    x.finalize();
    let mut out = [0u8; OUT_LEN];
    x.squeeze(&mut out);
    Ok(out)
}

// ========================================================================
// SHAKE256
// ========================================================================

/// SHAKE256 extendable-output hasher.
#[derive(Clone)]
pub struct Shake256 {
    core: ShakeCore<SHAKE256_RATE>,
}

impl Shake256 {
    /// Creates a new SHAKE256 XOF, enforcing the module boundary.
    pub fn new() -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal())
    }

    const fn new_internal() -> Self {
        Self {
            core: ShakeCore::new_internal(),
        }
    }

    /// Feeds `data` into the XOF. Legal only before `finalize`.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes the absorb phase.
    pub fn finalize(&mut self) {
        self.core.finalize();
    }

    /// Squeezes `out.len()` bytes of output.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.core.squeeze(out);
    }
}

/// One-shot SHAKE256.
pub fn shake256<const OUT_LEN: usize>(data: &[u8]) -> Result<[u8; OUT_LEN], Error> {
    let mut x = Shake256::new()?;
    x.update(data);
    x.finalize();
    let mut out = [0u8; OUT_LEN];
    x.squeeze(&mut out);
    Ok(out)
}

// ========================================================================
// Power-up self-tests
// ========================================================================

/// SHAKE128("") squeezed to 32 bytes — FIPS 202 example, retained
/// for the cross-check tests below. The power-up KAT uses a NIST
/// ACVP-Server vector via `fips_test_vectors`.
#[cfg(test)]
const KAT_SHAKE128_EMPTY_32: [u8; 32] = [
    0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, //
    0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e, //
    0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, //
    0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26, //
];

/// SHAKE256("") squeezed to 64 bytes — FIPS 202 example, retained
/// for the cross-check tests below. The power-up KAT uses a NIST
/// ACVP-Server vector via `fips_test_vectors`.
#[cfg(test)]
const KAT_SHAKE256_EMPTY_64: [u8; 64] = [
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, //
    0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24, //
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, //
    0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f, //
    0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, //
    0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6, //
    0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86, //
    0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe, //
];

/// Power-up KAT for SHAKE128.
///
/// Sourced from NIST ACVP-Server `SHAKE-128-FIPS202/internalProjection.json`
/// via `fips-test-vectors`; the selected tgId/tcId and the vendored
/// slice file's SHA-256 are recorded in `vendor/nist/MANIFEST.toml`.
pub fn self_test_128() -> Result<(), SelfTestFailure> {
    let mut x = Shake128::new_internal();
    x.update(&fips_test_vectors::SHAKE128_MSG);
    x.finalize();
    let mut out = [0u8; fips_test_vectors::SHAKE128_OUT.len()];
    x.squeeze(&mut out);
    if out == fips_test_vectors::SHAKE128_OUT {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// Power-up KAT for SHAKE256.
///
/// Sourced from NIST ACVP-Server `SHAKE-256-FIPS202/internalProjection.json`
/// via `fips-test-vectors`.
pub fn self_test_256() -> Result<(), SelfTestFailure> {
    let mut x = Shake256::new_internal();
    x.update(&fips_test_vectors::SHAKE256_MSG);
    x.finalize();
    let mut out = [0u8; fips_test_vectors::SHAKE256_OUT.len()];
    x.squeeze(&mut out);
    if out == fips_test_vectors::SHAKE256_OUT {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// Power-up KATs exported by this crate.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "SHAKE128 KAT (NIST ACVP-Server SHAKE-128-FIPS202)",
        run: self_test_128,
    },
    KatEntry {
        name: "SHAKE256 KAT (NIST ACVP-Server SHAKE-256-FIPS202)",
        run: self_test_256,
    },
];

// ========================================================================
// Unit tests
// ========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{
        self_test_128, self_test_256, shake128, shake256, Shake128, Shake256,
        KAT_SHAKE128_EMPTY_32, KAT_SHAKE256_EMPTY_64,
    };
    use fips_module::{initialize_with_tests, KatEntry};

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
                name: "shake128-bootstrap",
                run: self_test_128,
            },
            KatEntry {
                name: "shake256-bootstrap",
                run: self_test_256,
            },
        ]);
    }

    #[test]
    fn shake128_self_test_passes() {
        self_test_128().unwrap();
    }

    #[test]
    fn shake256_self_test_passes() {
        self_test_256().unwrap();
    }

    #[test]
    fn shake128_empty_32_matches_fips202() {
        let mut x = Shake128::new_internal();
        x.update(b"");
        x.finalize();
        let mut out = [0u8; 32];
        x.squeeze(&mut out);
        assert_eq!(out, KAT_SHAKE128_EMPTY_32);
    }

    #[test]
    fn shake256_empty_64_matches_fips202() {
        let mut x = Shake256::new_internal();
        x.update(b"");
        x.finalize();
        let mut out = [0u8; 64];
        x.squeeze(&mut out);
        assert_eq!(out, KAT_SHAKE256_EMPTY_64);
    }

    #[test]
    fn shake128_abc_32() {
        // SHAKE128("abc") truncated to 32 bytes — NIST CAVP
        let expected: [u8; 32] =
            hex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
        ensure_initialized();
        let out: [u8; 32] = shake128(b"abc").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn shake256_abc_64() {
        // SHAKE256("abc") truncated to 64 bytes — NIST CAVP
        let expected: [u8; 64] = hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        );
        ensure_initialized();
        let out: [u8; 64] = shake256(b"abc").unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn shake128_incremental_squeeze_matches_oneshot() {
        // Squeezing in multiple calls must yield the same bytes as
        // a single squeeze call of the total length.
        ensure_initialized();
        let mut a = Shake128::new().unwrap();
        a.update(b"incremental squeeze test");
        a.finalize();
        let mut full = [0u8; 400];
        a.squeeze(&mut full);

        let mut b = Shake128::new().unwrap();
        b.update(b"incremental squeeze test");
        b.finalize();
        let mut piecewise = [0u8; 400];
        // Squeezes across rate boundaries: SHAKE128 rate is 168.
        b.squeeze(&mut piecewise[..50]);
        b.squeeze(&mut piecewise[50..168]);
        b.squeeze(&mut piecewise[168..200]);
        b.squeeze(&mut piecewise[200..400]);

        assert_eq!(full, piecewise);
    }

    #[test]
    fn shake256_streaming_absorb_matches_oneshot() {
        ensure_initialized();
        let msg: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));

        let mut a = Shake256::new().unwrap();
        a.update(&msg);
        a.finalize();
        let mut one_shot = [0u8; 128];
        a.squeeze(&mut one_shot);

        let mut b = Shake256::new().unwrap();
        b.update(&msg[..7]);
        b.update(&msg[7..136]);
        b.update(&msg[136..]);
        b.finalize();
        let mut streamed = [0u8; 128];
        b.squeeze(&mut streamed);

        assert_eq!(one_shot, streamed);
    }
}
