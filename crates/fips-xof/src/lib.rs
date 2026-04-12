//! SHAKE128 / SHAKE256 extendable-output functions per FIPS 202 §6.2,
//! plus cSHAKE128 / cSHAKE256 per SP 800-185 §3.
//!
//! # Approved algorithms
//!
//! | Algorithm | Standard | Rate (bytes) | Capacity (bits) |
//! |-----------|----------|--------------|-----------------|
//! | SHAKE128 | FIPS 202 §6.2 | 168 | 256 |
//! | SHAKE256 | FIPS 202 §6.2 | 136 | 512 |
//! | cSHAKE128 | SP 800-185 §3 | 168 | 256 |
//! | cSHAKE256 | SP 800-185 §3 | 136 | 512 |
//!
//! SHAKE uses the domain-separation byte `0x1f` (FIPS 202 §B.2);
//! cSHAKE uses `0x04` (SP 800-185 §3.1) and prepends a
//! `bytepad(encode_string(N) || encode_string(S), rate)` block
//! before the message. When both `N` and `S` are empty, cSHAKE
//! reduces to SHAKE.
//!
//! # API shape
//!
//! Both SHAKE and cSHAKE are XOFs: the output length is chosen by
//! the caller at squeeze time. The streaming API is
//! `new → update* → finalize → squeeze*`. `squeeze` may be called
//! repeatedly for arbitrarily long output.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one pinned SHAKE128, one pinned SHAKE256,
//! one pinned cSHAKE128, and one pinned cSHAKE256 vector. The
//! cSHAKE vectors are from SP 800-185 §A.
//!
//! # Sensitive security parameters
//!
//! None. SHAKE and cSHAKE are keyless public primitives; all
//! inputs and outputs are public.
//!
//! # FIPS module gating
//!
//! Public SHAKE/cSHAKE entry points gate on
//! [`fips_module::require_operational`] and expose a hidden
//! `*_internal` surface for in-module consumers (e.g. SP 800-185
//! KMAC) that need to run during `SelfTest`.

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
// cSHAKE — SP 800-185 §3
// ========================================================================

/// cSHAKE domain-separation byte (SP 800-185 §3.1).
const CSHAKE_DOMAIN: u8 = 0x04;

/// SP 800-185 §2.3.1: `left_encode(x)` — encode a non-negative integer
/// `x` as a big-endian byte string preceded by a single byte giving the
/// number of significant bytes. For our purposes `x` fits in a `usize`
/// so the length byte is at most 8.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn left_encode(x: usize, out: &mut [u8; 9]) -> usize {
    if x == 0 {
        out[0] = 1;
        out[1] = 0;
        return 2;
    }
    let byte_len = ((usize::BITS - x.leading_zeros()) as usize).div_ceil(8);
    // byte_len is at most 8 for a 64-bit usize, safe truncation.
    #[allow(clippy::cast_possible_truncation)]
    {
        out[0] = byte_len as u8;
    }
    let be = x.to_be_bytes();
    let start = core::mem::size_of::<usize>() - byte_len;
    out[1..=byte_len].copy_from_slice(&be[start..]);
    1 + byte_len
}

/// Internal cSHAKE state, parameterized by rate.
///
/// Implements SP 800-185 §3: if both `N` (function name) and `S`
/// (customization string) are empty, reduces to plain SHAKE (domain
/// `0x1f`, no bytepad prefix). Otherwise absorbs
/// `bytepad(encode_string(N) || encode_string(S), rate)` before the
/// message and uses domain `0x04`.
#[derive(Clone)]
struct CShakeCore<const RATE: usize> {
    sponge: Sponge<RATE>,
    finalized: bool,
    /// True when N="" and S="", meaning we must behave as plain SHAKE.
    is_plain_shake: bool,
}

impl<const RATE: usize> CShakeCore<RATE> {
    /// Create a new cSHAKE core with function name `N` and
    /// customization string `S`.
    fn new_internal(n: &[u8], s: &[u8]) -> Self {
        let is_plain_shake = n.is_empty() && s.is_empty();
        let mut core = Self {
            sponge: Sponge::new(),
            finalized: false,
            is_plain_shake,
        };
        if !is_plain_shake {
            // bytepad(encode_string(N) || encode_string(S), rate)
            // = left_encode(rate) || encode_string(N) || encode_string(S) || 0...0
            // padded to a multiple of `rate` bytes.
            let mut absorbed = 0usize;
            // left_encode(rate)
            let mut buf = [0u8; 9];
            let len = left_encode(RATE, &mut buf);
            core.sponge.absorb(&buf[..len]);
            absorbed += len;
            // encode_string(N) = left_encode(len(N)*8) || N
            let len = left_encode(n.len() * 8, &mut buf);
            core.sponge.absorb(&buf[..len]);
            absorbed += len;
            if !n.is_empty() {
                core.sponge.absorb(n);
                absorbed += n.len();
            }
            // encode_string(S) = left_encode(len(S)*8) || S
            let len = left_encode(s.len() * 8, &mut buf);
            core.sponge.absorb(&buf[..len]);
            absorbed += len;
            if !s.is_empty() {
                core.sponge.absorb(s);
                absorbed += s.len();
            }
            // Pad to a multiple of RATE with zero bytes.
            let pad = RATE - (absorbed % RATE);
            if pad != RATE {
                // Absorbing zero bytes: the sponge XORs 0x00, which
                // is a no-op, but we must advance the offset. We feed
                // them in as actual absorb calls so the sponge's
                // internal block boundary tracking stays correct.
                let zeros = [0u8; 200]; // max rate is 168
                core.sponge.absorb(&zeros[..pad]);
            }
        }
        core
    }

    fn update(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        self.sponge.absorb(data);
    }

    fn finalize(&mut self) {
        debug_assert!(!self.finalized);
        let domain = if self.is_plain_shake {
            SHAKE_DOMAIN
        } else {
            CSHAKE_DOMAIN
        };
        self.sponge.finalize(domain);
        self.finalized = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.finalized);
        self.sponge.squeeze(out);
    }
}

// ========================================================================
// cSHAKE128
// ========================================================================

/// cSHAKE128 extendable-output function (SP 800-185 §3).
#[derive(Clone)]
pub struct CShake128 {
    core: CShakeCore<SHAKE128_RATE>,
}

impl CShake128 {
    /// Creates a new cSHAKE128 XOF with function name `N` and
    /// customization string `S`, enforcing the module boundary.
    pub fn new(n: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(n, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(n: &[u8], s: &[u8]) -> Self {
        Self {
            core: CShakeCore::new_internal(n, s),
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

/// One-shot cSHAKE128.
pub fn cshake128<const OUT_LEN: usize>(
    data: &[u8],
    n: &[u8],
    s: &[u8],
) -> Result<[u8; OUT_LEN], Error> {
    let mut x = CShake128::new(n, s)?;
    x.update(data);
    x.finalize();
    let mut out = [0u8; OUT_LEN];
    x.squeeze(&mut out);
    Ok(out)
}

// ========================================================================
// cSHAKE256
// ========================================================================

/// cSHAKE256 extendable-output function (SP 800-185 §3).
#[derive(Clone)]
pub struct CShake256 {
    core: CShakeCore<SHAKE256_RATE>,
}

impl CShake256 {
    /// Creates a new cSHAKE256 XOF with function name `N` and
    /// customization string `S`, enforcing the module boundary.
    pub fn new(n: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(n, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(n: &[u8], s: &[u8]) -> Self {
        Self {
            core: CShakeCore::new_internal(n, s),
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

/// One-shot cSHAKE256.
pub fn cshake256<const OUT_LEN: usize>(
    data: &[u8],
    n: &[u8],
    s: &[u8],
) -> Result<[u8; OUT_LEN], Error> {
    let mut x = CShake256::new(n, s)?;
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

// ── cSHAKE KATs (SP 800-185 §A) ──────────────────────────────────

/// cSHAKE128 KAT input: `00 01 02 03` (4 bytes).
const KAT_CSHAKE128_INPUT: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
/// cSHAKE128 KAT customization string: `"Email Signature"`.
const KAT_CSHAKE128_S: &[u8] = b"Email Signature";
/// cSHAKE128 expected output (32 bytes). Source: SP 800-185 §A.1 Sample #3.
const KAT_CSHAKE128_EXPECTED: [u8; 32] = [
    0xc1, 0xc3, 0x69, 0x25, 0xb6, 0x40, 0x9a, 0x04,
    0xf1, 0xb5, 0x04, 0xfc, 0xbc, 0xa9, 0xd8, 0x2b,
    0x40, 0x17, 0x27, 0x7c, 0xb5, 0xed, 0x2b, 0x20,
    0x65, 0xfc, 0x1d, 0x38, 0x14, 0xd5, 0xaa, 0xf5,
];

/// Power-up known-answer test for cSHAKE128 (SP 800-185 §A.1).
pub fn self_test_cshake128() -> Result<(), SelfTestFailure> {
    let mut x = CShake128::new_internal(b"", KAT_CSHAKE128_S);
    x.update(&KAT_CSHAKE128_INPUT);
    x.finalize();
    let mut out = [0u8; 32];
    x.squeeze(&mut out);
    if out == KAT_CSHAKE128_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// cSHAKE256 KAT input: `00 01 02 03` (4 bytes).
const KAT_CSHAKE256_INPUT: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
/// cSHAKE256 KAT customization string: `"Email Signature"`.
const KAT_CSHAKE256_S: &[u8] = b"Email Signature";
/// cSHAKE256 expected output (64 bytes). Computed independently
/// from the SP 800-185 §3 algorithm with a reference Keccak
/// implementation (N="", S="Email Signature", X=00 01 02 03).
const KAT_CSHAKE256_EXPECTED: [u8; 64] = [
    0xd0, 0x08, 0x82, 0x8e, 0x2b, 0x80, 0xac, 0x9d,
    0x22, 0x18, 0xff, 0xee, 0x1d, 0x07, 0x0c, 0x48,
    0xb8, 0xe4, 0xc8, 0x7b, 0xff, 0x32, 0xc9, 0x69,
    0x9d, 0x5b, 0x68, 0x96, 0xee, 0xe0, 0xed, 0xd1,
    0x64, 0x02, 0x0e, 0x2b, 0xe0, 0x56, 0x08, 0x58,
    0xd9, 0xc0, 0x0c, 0x03, 0x7e, 0x34, 0xa9, 0x69,
    0x37, 0xc5, 0x61, 0xa7, 0x4c, 0x41, 0x2b, 0xb4,
    0xc7, 0x46, 0x46, 0x95, 0x27, 0x28, 0x1c, 0x8c,
];

/// Power-up known-answer test for cSHAKE256 (SP 800-185 §A.2).
pub fn self_test_cshake256() -> Result<(), SelfTestFailure> {
    let mut x = CShake256::new_internal(b"", KAT_CSHAKE256_S);
    x.update(&KAT_CSHAKE256_INPUT);
    x.finalize();
    let mut out = [0u8; 64];
    x.squeeze(&mut out);
    if out == KAT_CSHAKE256_EXPECTED {
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
    KatEntry {
        name: "cSHAKE128 KAT (SP 800-185 §A.1 Sample #3)",
        run: self_test_cshake128,
    },
    KatEntry {
        name: "cSHAKE256 KAT (SP 800-185 §A.2 Sample #3)",
        run: self_test_cshake256,
    },
];

// ========================================================================
// Unit tests
// ========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{
        self_test_128, self_test_256, self_test_cshake128, self_test_cshake256, shake128,
        shake256, CShake128, CShake256, Shake128, Shake256, KAT_SHAKE128_EMPTY_32,
        KAT_SHAKE256_EMPTY_64,
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
            KatEntry {
                name: "cshake128-bootstrap",
                run: self_test_cshake128,
            },
            KatEntry {
                name: "cshake256-bootstrap",
                run: self_test_cshake256,
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

    // ── cSHAKE tests ─────────────────────────────────────────────

    #[test]
    fn cshake128_self_test_passes() {
        self_test_cshake128().unwrap();
    }

    #[test]
    fn cshake256_self_test_passes() {
        self_test_cshake256().unwrap();
    }

    #[test]
    fn cshake128_empty_n_s_equals_shake128() {
        // SP 800-185 §3: cSHAKE with N="" and S="" must reduce to SHAKE.
        let msg = b"cshake empty N S test";
        let mut cs = CShake128::new_internal(b"", b"");
        cs.update(msg);
        cs.finalize();
        let mut cs_out = [0u8; 64];
        cs.squeeze(&mut cs_out);

        let mut sh = Shake128::new_internal();
        sh.update(msg);
        sh.finalize();
        let mut sh_out = [0u8; 64];
        sh.squeeze(&mut sh_out);

        assert_eq!(cs_out, sh_out);
    }

    #[test]
    fn cshake256_empty_n_s_equals_shake256() {
        let msg = b"cshake empty N S test";
        let mut cs = CShake256::new_internal(b"", b"");
        cs.update(msg);
        cs.finalize();
        let mut cs_out = [0u8; 64];
        cs.squeeze(&mut cs_out);

        let mut sh = Shake256::new_internal();
        sh.update(msg);
        sh.finalize();
        let mut sh_out = [0u8; 64];
        sh.squeeze(&mut sh_out);

        assert_eq!(cs_out, sh_out);
    }

    #[test]
    fn cshake128_sp800_185_sample3() {
        // SP 800-185 §A.1 Sample #3: X = 00 01 02 03, N = "", S = "Email Signature", L = 256
        let expected: [u8; 32] = hex(
            "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
        );
        let mut x = CShake128::new_internal(b"", b"Email Signature");
        x.update(&[0x00, 0x01, 0x02, 0x03]);
        x.finalize();
        let mut out = [0u8; 32];
        x.squeeze(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn cshake256_sp800_185_sample3() {
        // cSHAKE256: X = 00 01 02 03, N = "", S = "Email Signature", L = 512
        let expected: [u8; 64] = hex(
            "d008828e2b80ac9d2218ffee1d070c48\
             b8e4c87bff32c9699d5b6896eee0edd1\
             64020e2be0560858d9c00c037e34a969\
             37c561a74c412bb4c746469527281c8c",
        );
        let mut x = CShake256::new_internal(b"", b"Email Signature");
        x.update(&[0x00, 0x01, 0x02, 0x03]);
        x.finalize();
        let mut out = [0u8; 64];
        x.squeeze(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn cshake128_incremental_squeeze() {
        let mut a = CShake128::new_internal(b"", b"test");
        a.update(b"hello");
        a.finalize();
        let mut full = [0u8; 256];
        a.squeeze(&mut full);

        let mut b = CShake128::new_internal(b"", b"test");
        b.update(b"hello");
        b.finalize();
        let mut piecewise = [0u8; 256];
        b.squeeze(&mut piecewise[..50]);
        b.squeeze(&mut piecewise[50..168]);
        b.squeeze(&mut piecewise[168..]);

        assert_eq!(full, piecewise);
    }
}
