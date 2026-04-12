//! SHAKE128 / SHAKE256 extendable-output functions per FIPS 202 §6.2,
//! cSHAKE128 / cSHAKE256 per SP 800-185 §3, KMAC128 / KMAC256
//! keyed message authentication codes per SP 800-185 §4, and
//! KMACXOF128 / KMACXOF256 XOF variants per SP 800-185 §4.3.1.
//!
//! # Approved algorithms
//!
//! | Algorithm | Standard | Rate (bytes) | Capacity (bits) |
//! |-----------|----------|--------------|-----------------|
//! | SHAKE128 | FIPS 202 §6.2 | 168 | 256 |
//! | SHAKE256 | FIPS 202 §6.2 | 136 | 512 |
//! | cSHAKE128 | SP 800-185 §3 | 168 | 256 |
//! | cSHAKE256 | SP 800-185 §3 | 136 | 512 |
//! | KMAC128    | SP 800-185 §4   | 168 | 256 |
//! | KMAC256    | SP 800-185 §4   | 136 | 512 |
//! | KMACXOF128 | SP 800-185 §4.3.1 | 168 | 256 |
//! | KMACXOF256 | SP 800-185 §4.3.1 | 136 | 512 |
//!
//! SHAKE uses the domain-separation byte `0x1f` (FIPS 202 §B.2);
//! cSHAKE uses `0x04` (SP 800-185 §3.1) and prepends a
//! `bytepad(encode_string(N) || encode_string(S), rate)` block
//! before the message. When both `N` and `S` are empty, cSHAKE
//! reduces to SHAKE. KMAC builds on cSHAKE with N = `"KMAC"`,
//! absorbing `bytepad(encode_string(K), rate) || X || right_encode(L)`
//! as the cSHAKE message. KMACXOF is identical except it appends
//! `right_encode(0)` instead of `right_encode(L)`, enabling XOF-mode
//! output of arbitrary length.
//!
//! # API shape
//!
//! SHAKE and cSHAKE are XOFs: the output length is chosen by the
//! caller at squeeze time. The streaming API is
//! `new → update* → finalize → squeeze*`. `squeeze` may be called
//! repeatedly for arbitrarily long output. KMAC uses
//! `new → update* → finalize_into` for fixed-length tags. KMACXOF
//! uses `new → update* → finalize → squeeze*` like SHAKE/cSHAKE.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes one pinned SHAKE128, one pinned SHAKE256,
//! one pinned cSHAKE128, one pinned cSHAKE256, one pinned KMAC128,
//! one pinned KMAC256, one pinned KMACXOF128, and one pinned
//! KMACXOF256 vector.
//!
//! # Sensitive security parameters
//!
//! None. SHAKE and cSHAKE are keyless public primitives; all
//! inputs and outputs are public. KMAC and KMACXOF keys are
//! sensitive security parameters managed by the caller.
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
// KMAC — SP 800-185 §4
// ========================================================================

/// SP 800-185 §2.3.1: `right_encode(x)` — encode a non-negative integer
/// `x` as a big-endian byte string followed by a single byte giving the
/// number of significant bytes. Returns the number of bytes written to
/// `out`.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn right_encode(x: usize, out: &mut [u8; 9]) -> usize {
    if x == 0 {
        out[0] = 0;
        out[1] = 1;
        return 2;
    }
    let byte_len = ((usize::BITS - x.leading_zeros()) as usize).div_ceil(8);
    let be = x.to_be_bytes();
    let start = core::mem::size_of::<usize>() - byte_len;
    out[..byte_len].copy_from_slice(&be[start..]);
    // byte_len is at most 8 for a 64-bit usize, safe truncation.
    #[allow(clippy::cast_possible_truncation)]
    {
        out[byte_len] = byte_len as u8;
    }
    byte_len + 1
}

/// Internal KMAC state, parameterized by sponge rate.
///
/// Implements SP 800-185 §4:
///
/// ```text
/// KMAC(K, X, L, S) = cSHAKE(newX, L, "KMAC", S)
/// newX = bytepad(encode_string(K), rate) || X || right_encode(L)
/// ```
///
/// The caller feeds `X` incrementally via [`update`](KmacCore::update),
/// then calls [`finalize`](KmacCore::finalize) which appends
/// `right_encode(L)` and squeezes the tag.
#[derive(Clone)]
struct KmacCore<const RATE: usize> {
    cshake: CShakeCore<RATE>,
}

impl<const RATE: usize> KmacCore<RATE> {
    /// Create a new KMAC core with key `K` and customization string `S`.
    ///
    /// # Safety invariant
    ///
    /// `absorbed` tracks the bytepad offset; all slice accesses are
    /// bounded by `RATE` which is at most 168.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn new_internal(key: &[u8], s: &[u8]) -> Self {
        let mut cshake = CShakeCore::<RATE>::new_internal(b"KMAC", s);

        // Absorb bytepad(encode_string(K), RATE):
        // = left_encode(RATE) || encode_string(K) || zero-pad to RATE
        let mut absorbed = 0usize;
        let mut buf = [0u8; 9];

        // left_encode(RATE)
        let len = left_encode(RATE, &mut buf);
        cshake.update(&buf[..len]);
        absorbed += len;

        // encode_string(K) = left_encode(len(K)*8) || K
        let len = left_encode(key.len() * 8, &mut buf);
        cshake.update(&buf[..len]);
        absorbed += len;
        if !key.is_empty() {
            cshake.update(key);
            absorbed += key.len();
        }

        // Zero-pad to multiple of RATE.
        let pad = RATE - (absorbed % RATE);
        if pad != RATE {
            let zeros = [0u8; 200];
            cshake.update(&zeros[..pad]);
        }

        Self { cshake }
    }

    /// Feed more message data (`X`).
    fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }

    /// Finalize: append `right_encode(tag_len_bits)`, then finalize the
    /// underlying cSHAKE and squeeze `tag.len()` bytes.
    fn finalize_into(&mut self, tag: &mut [u8]) {
        let mut buf = [0u8; 9];
        #[allow(clippy::arithmetic_side_effects)]
        let len = right_encode(tag.len() * 8, &mut buf);
        self.cshake.update(&buf[..len]);
        self.cshake.finalize();
        self.cshake.squeeze(tag);
    }

    /// Finalize in XOF mode: append `right_encode(0)`, then finalize
    /// the underlying cSHAKE. Call [`squeeze`](KmacCore::squeeze)
    /// afterwards.
    fn finalize_xof(&mut self) {
        // right_encode(0) = 0x00 0x01
        self.cshake.update(&[0x00, 0x01]);
        self.cshake.finalize();
    }

    /// Squeeze output bytes (XOF mode only, after `finalize_xof`).
    fn squeeze(&mut self, out: &mut [u8]) {
        self.cshake.squeeze(out);
    }
}

/// KMAC128 message authentication code (SP 800-185 §4).
///
/// Built on cSHAKE128 with N = `"KMAC"`.
#[derive(Clone)]
pub struct Kmac128 {
    core: KmacCore<SHAKE128_RATE>,
}

impl Kmac128 {
    /// Creates a new KMAC128 instance, gated on module state.
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(key, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(key: &[u8], s: &[u8]) -> Self {
        Self {
            core: KmacCore::new_internal(key, s),
        }
    }

    /// Feeds `data` into the message.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes and writes the tag into `tag`.
    pub fn finalize_into(&mut self, tag: &mut [u8]) {
        self.core.finalize_into(tag);
    }
}

/// One-shot KMAC128.
pub fn kmac128<const TAG_LEN: usize>(
    key: &[u8],
    data: &[u8],
    s: &[u8],
) -> Result<[u8; TAG_LEN], Error> {
    let mut m = Kmac128::new(key, s)?;
    m.update(data);
    let mut tag = [0u8; TAG_LEN];
    m.finalize_into(&mut tag);
    Ok(tag)
}

/// KMAC256 message authentication code (SP 800-185 §4).
///
/// Built on cSHAKE256 with N = `"KMAC"`.
#[derive(Clone)]
pub struct Kmac256 {
    core: KmacCore<SHAKE256_RATE>,
}

impl Kmac256 {
    /// Creates a new KMAC256 instance, gated on module state.
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(key, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(key: &[u8], s: &[u8]) -> Self {
        Self {
            core: KmacCore::new_internal(key, s),
        }
    }

    /// Feeds `data` into the message.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes and writes the tag into `tag`.
    pub fn finalize_into(&mut self, tag: &mut [u8]) {
        self.core.finalize_into(tag);
    }
}

/// One-shot KMAC256.
pub fn kmac256<const TAG_LEN: usize>(
    key: &[u8],
    data: &[u8],
    s: &[u8],
) -> Result<[u8; TAG_LEN], Error> {
    let mut m = Kmac256::new(key, s)?;
    m.update(data);
    let mut tag = [0u8; TAG_LEN];
    m.finalize_into(&mut tag);
    Ok(tag)
}

// ========================================================================
// KMACXOF — SP 800-185 §4.3.1
// ========================================================================

/// KMACXOF128 extendable-output function (SP 800-185 §4.3.1).
///
/// Identical to KMAC128 except `right_encode(0)` is appended instead
/// of `right_encode(L)`, enabling arbitrary-length output via
/// repeated squeezing.
#[derive(Clone)]
pub struct KmacXof128 {
    core: KmacCore<SHAKE128_RATE>,
}

impl KmacXof128 {
    /// Creates a new KMACXOF128 instance, gated on module state.
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(key, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(key: &[u8], s: &[u8]) -> Self {
        Self {
            core: KmacCore::new_internal(key, s),
        }
    }

    /// Feeds `data` into the message.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes the XOF. Call [`squeeze`](KmacXof128::squeeze)
    /// afterwards to extract output.
    pub fn finalize(&mut self) {
        self.core.finalize_xof();
    }

    /// Squeezes `out.len()` bytes from the XOF. May be called
    /// repeatedly for streaming output.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.core.squeeze(out);
    }
}

/// One-shot KMACXOF128: squeeze `OUT_LEN` bytes.
pub fn kmacxof128<const OUT_LEN: usize>(
    key: &[u8],
    data: &[u8],
    s: &[u8],
) -> Result<[u8; OUT_LEN], Error> {
    let mut m = KmacXof128::new(key, s)?;
    m.update(data);
    m.finalize();
    let mut out = [0u8; OUT_LEN];
    m.squeeze(&mut out);
    Ok(out)
}

/// KMACXOF256 extendable-output function (SP 800-185 §4.3.1).
///
/// Identical to KMAC256 except `right_encode(0)` is appended instead
/// of `right_encode(L)`, enabling arbitrary-length output via
/// repeated squeezing.
#[derive(Clone)]
pub struct KmacXof256 {
    core: KmacCore<SHAKE256_RATE>,
}

impl KmacXof256 {
    /// Creates a new KMACXOF256 instance, gated on module state.
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error> {
        require_operational()?;
        Ok(Self::new_internal(key, s))
    }

    /// Internal constructor (no module-state gate).
    fn new_internal(key: &[u8], s: &[u8]) -> Self {
        Self {
            core: KmacCore::new_internal(key, s),
        }
    }

    /// Feeds `data` into the message.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Finalizes the XOF. Call [`squeeze`](KmacXof256::squeeze)
    /// afterwards to extract output.
    pub fn finalize(&mut self) {
        self.core.finalize_xof();
    }

    /// Squeezes `out.len()` bytes from the XOF. May be called
    /// repeatedly for streaming output.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.core.squeeze(out);
    }
}

/// One-shot KMACXOF256: squeeze `OUT_LEN` bytes.
pub fn kmacxof256<const OUT_LEN: usize>(
    key: &[u8],
    data: &[u8],
    s: &[u8],
) -> Result<[u8; OUT_LEN], Error> {
    let mut m = KmacXof256::new(key, s)?;
    m.update(data);
    m.finalize();
    let mut out = [0u8; OUT_LEN];
    m.squeeze(&mut out);
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

// ── KMAC KATs (NIST KMAC_samples.pdf) ─────────────────────────────

/// KMAC128 KAT key: 32 bytes `40 41 42 … 5F` (NIST Sample #1).
const KAT_KMAC128_KEY: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
/// KMAC128 KAT input: `00 01 02 03` (4 bytes).
const KAT_KMAC128_INPUT: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
/// KMAC128 expected tag (32 bytes, S="", L=256). Source: NIST
/// `KMAC_samples.pdf` Sample #1 (Security Strength 128-bits).
const KAT_KMAC128_EXPECTED: [u8; 32] = [
    0xe5, 0x78, 0x0b, 0x0d, 0x3e, 0xa6, 0xf7, 0xd3,
    0xa4, 0x29, 0xc5, 0x70, 0x6a, 0xa4, 0x3a, 0x00,
    0xfa, 0xdb, 0xd7, 0xd4, 0x96, 0x28, 0x83, 0x9e,
    0x31, 0x87, 0x24, 0x3f, 0x45, 0x6e, 0xe1, 0x4e,
];

/// Power-up known-answer test for KMAC128 (NIST Sample #1).
pub fn self_test_kmac128() -> Result<(), SelfTestFailure> {
    let mut m = Kmac128::new_internal(&KAT_KMAC128_KEY, b"");
    m.update(&KAT_KMAC128_INPUT);
    let mut tag = [0u8; 32];
    m.finalize_into(&mut tag);
    if tag == KAT_KMAC128_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// KMAC256 KAT expected tag (64 bytes, S="", L=512). Source: NIST
/// `KMAC_samples.pdf` Sample #5 (Security Strength 256-bits,
/// K=40..5F, X=00..C7 200 bytes, S="").
const KAT_KMAC256_EXPECTED: [u8; 64] = [
    0x75, 0x35, 0x8c, 0xf3, 0x9e, 0x41, 0x49, 0x4e,
    0x94, 0x97, 0x07, 0x92, 0x7c, 0xee, 0x0a, 0xf2,
    0x0a, 0x3f, 0xf5, 0x53, 0x90, 0x4c, 0x86, 0xb0,
    0x8f, 0x21, 0xcc, 0x41, 0x4b, 0xcf, 0xd6, 0x91,
    0x58, 0x9d, 0x27, 0xcf, 0x5e, 0x15, 0x36, 0x9c,
    0xbb, 0xff, 0x8b, 0x9a, 0x4c, 0x2e, 0xb1, 0x78,
    0x00, 0x85, 0x5d, 0x02, 0x35, 0xff, 0x63, 0x5d,
    0xa8, 0x25, 0x33, 0xec, 0x6b, 0x75, 0x9b, 0x69,
];

/// Power-up known-answer test for KMAC256 (NIST Sample #5).
pub fn self_test_kmac256() -> Result<(), SelfTestFailure> {
    // X = 00 01 02 … C7 (200 bytes)
    let x: [u8; 200] = core::array::from_fn(|i| {
        #[allow(clippy::cast_possible_truncation)]
        { i as u8 }
    });
    let mut m = Kmac256::new_internal(&KAT_KMAC128_KEY, b"");
    m.update(&x);
    let mut tag = [0u8; 64];
    m.finalize_into(&mut tag);
    if tag == KAT_KMAC256_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ── KMACXOF KATs ─────────────────────────────────────────────────

/// KMACXOF128 expected output (32 bytes, S="", K=40..5F, X=00 01 02 03).
/// Computed via pycryptodome's `cSHAKE_XOF` with N="KMAC" and
/// `right_encode(0)` appended per SP 800-185 §4.3.1.
const KAT_KMACXOF128_EXPECTED: [u8; 32] = [
    0xcd, 0x83, 0x74, 0x0b, 0xbd, 0x92, 0xcc, 0xc8,
    0xcf, 0x03, 0x2b, 0x14, 0x81, 0xa0, 0xf4, 0x46,
    0x0e, 0x7c, 0xa9, 0xdd, 0x12, 0xb0, 0x8a, 0x0c,
    0x40, 0x31, 0x17, 0x8b, 0xac, 0xd6, 0xec, 0x35,
];

/// Power-up known-answer test for KMACXOF128.
///
/// Exercises `KmacXof128` with K=40..5F (32 bytes), X=00 01 02 03
/// (4 bytes), S="", squeezed to 32 bytes. Reference computed
/// independently via pycryptodome cSHAKE_XOF with N="KMAC" and
/// `right_encode(0)`.
pub fn self_test_kmacxof128() -> Result<(), SelfTestFailure> {
    let mut m = KmacXof128::new_internal(&KAT_KMAC128_KEY, b"");
    m.update(&KAT_KMAC128_INPUT);
    m.finalize();
    let mut out = [0u8; 32];
    m.squeeze(&mut out);
    if out == KAT_KMACXOF128_EXPECTED {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

/// KMACXOF256 expected output (64 bytes, S="", K=40..5F, X=00..C7).
/// Computed via pycryptodome's `cSHAKE_XOF` with N="KMAC",
/// capacity=512, and `right_encode(0)`.
const KAT_KMACXOF256_EXPECTED: [u8; 64] = [
    0xff, 0x7b, 0x17, 0x1f, 0x1e, 0x8a, 0x2b, 0x24,
    0x68, 0x3e, 0xed, 0x37, 0x83, 0x0e, 0xe7, 0x97,
    0x53, 0x8b, 0xa8, 0xdc, 0x56, 0x3f, 0x6d, 0xa1,
    0xe6, 0x67, 0x39, 0x1a, 0x75, 0xed, 0xc0, 0x2c,
    0xa6, 0x33, 0x07, 0x9f, 0x81, 0xce, 0x12, 0xa2,
    0x5f, 0x45, 0x61, 0x5e, 0xc8, 0x99, 0x72, 0x03,
    0x1d, 0x18, 0x33, 0x73, 0x31, 0xd2, 0x4c, 0xeb,
    0x8f, 0x8c, 0xa8, 0xe6, 0xa1, 0x9f, 0xd9, 0x8b,
];

/// Power-up known-answer test for KMACXOF256.
///
/// Exercises `KmacXof256` with K=40..5F (32 bytes), X=00..C7
/// (200 bytes), S="", squeezed to 64 bytes.
pub fn self_test_kmacxof256() -> Result<(), SelfTestFailure> {
    let x: [u8; 200] = core::array::from_fn(|i| {
        #[allow(clippy::cast_possible_truncation)]
        { i as u8 }
    });
    let mut m = KmacXof256::new_internal(&KAT_KMAC128_KEY, b"");
    m.update(&x);
    m.finalize();
    let mut out = [0u8; 64];
    m.squeeze(&mut out);
    if out == KAT_KMACXOF256_EXPECTED {
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
    KatEntry {
        name: "KMAC128 KAT (NIST KMAC_samples #1, SP 800-185 §4)",
        run: self_test_kmac128,
    },
    KatEntry {
        name: "KMAC256 KAT (NIST KMAC_samples #5, SP 800-185 §4)",
        run: self_test_kmac256,
    },
    KatEntry {
        name: "KMACXOF128 KAT (SP 800-185 §4.3.1, pycryptodome cross-check)",
        run: self_test_kmacxof128,
    },
    KatEntry {
        name: "KMACXOF256 KAT (SP 800-185 §4.3.1, pycryptodome cross-check)",
        run: self_test_kmacxof256,
    },
];

// ========================================================================
// Unit tests
// ========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{
        self_test_128, self_test_256, self_test_cshake128, self_test_cshake256,
        self_test_kmac128, self_test_kmac256, self_test_kmacxof128,
        self_test_kmacxof256, shake128, shake256, CShake128, CShake256,
        Kmac128, Kmac256, KmacXof128, KmacXof256, Shake128, Shake256,
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
            KatEntry {
                name: "cshake128-bootstrap",
                run: self_test_cshake128,
            },
            KatEntry {
                name: "cshake256-bootstrap",
                run: self_test_cshake256,
            },
            KatEntry {
                name: "kmac128-bootstrap",
                run: self_test_kmac128,
            },
            KatEntry {
                name: "kmac256-bootstrap",
                run: self_test_kmac256,
            },
            KatEntry {
                name: "kmacxof128-bootstrap",
                run: self_test_kmacxof128,
            },
            KatEntry {
                name: "kmacxof256-bootstrap",
                run: self_test_kmacxof256,
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

    // ── KMAC tests ──────────────────────────────────────────────

    #[test]
    fn kmac128_self_test_passes() {
        self_test_kmac128().unwrap();
    }

    #[test]
    fn kmac256_self_test_passes() {
        self_test_kmac256().unwrap();
    }

    #[test]
    fn kmac128_nist_sample2() {
        // NIST KMAC_samples.pdf Sample #2: K=40..5F, X=00 01 02 03,
        // S="My Tagged Application", L=256
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x = [0x00u8, 0x01, 0x02, 0x03];
        let expected: [u8; 32] = hex(
            "3b1fba963cd8b0b59e8c1a6d71888b714365\
             1af8ba0a7070c0979e2811324aa5",
        );
        let mut m = Kmac128::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        let mut tag = [0u8; 32];
        m.finalize_into(&mut tag);
        assert_eq!(tag, expected);
    }

    #[test]
    fn kmac128_nist_sample3() {
        // NIST KMAC_samples.pdf Sample #3: K=40..5F, X=00..C7 (200 bytes),
        // S="My Tagged Application", L=256
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x: [u8; 200] = core::array::from_fn(|i| i as u8);
        let expected: [u8; 32] = hex(
            "1f5b4e6cca02209e0dcb5ca635b89a15e271\
             ecc760071dfd805faa38f9729230",
        );
        let mut m = Kmac128::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        let mut tag = [0u8; 32];
        m.finalize_into(&mut tag);
        assert_eq!(tag, expected);
    }

    #[test]
    fn kmac256_nist_sample4() {
        // NIST KMAC_samples.pdf Sample #4: K=40..5F, X=00 01 02 03,
        // S="My Tagged Application", L=512
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x = [0x00u8, 0x01, 0x02, 0x03];
        let expected: [u8; 64] = hex(
            "20c570c31346f703c9ac36c61c03cb64\
             c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f595\
             1f0103f33f4f24871024d9c27773a8dd",
        );
        let mut m = Kmac256::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        let mut tag = [0u8; 64];
        m.finalize_into(&mut tag);
        assert_eq!(tag, expected);
    }

    #[test]
    fn kmac256_nist_sample6() {
        // NIST KMAC_samples.pdf Sample #6: K=40..5F, X=00..C7,
        // S="My Tagged Application", L=512
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x: [u8; 200] = core::array::from_fn(|i| i as u8);
        let expected: [u8; 64] = hex(
            "b58618f71f92e1d56c1b8c55ddd7cd18\
             8b97b4ca4d99831eb2699a837da2e4d9\
             70fbacfde50033aea585f1a2708510c3\
             2d07880801bd182898fe476876fc8965",
        );
        let mut m = Kmac256::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        let mut tag = [0u8; 64];
        m.finalize_into(&mut tag);
        assert_eq!(tag, expected);
    }

    #[test]
    fn kmac128_streaming_matches_oneshot() {
        // Feeding data in pieces must match feeding it all at once.
        let key = b"streaming-test-key-128";
        let msg: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));

        let mut one = Kmac128::new_internal(key, b"stream");
        one.update(&msg);
        let mut tag1 = [0u8; 32];
        one.finalize_into(&mut tag1);

        let mut two = Kmac128::new_internal(key, b"stream");
        two.update(&msg[..50]);
        two.update(&msg[50..200]);
        two.update(&msg[200..]);
        let mut tag2 = [0u8; 32];
        two.finalize_into(&mut tag2);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn kmac128_different_keys_produce_different_tags() {
        let msg = b"same message";
        let mut m1 = Kmac128::new_internal(b"key-a", b"");
        m1.update(msg);
        let mut tag1 = [0u8; 32];
        m1.finalize_into(&mut tag1);

        let mut m2 = Kmac128::new_internal(b"key-b", b"");
        m2.update(msg);
        let mut tag2 = [0u8; 32];
        m2.finalize_into(&mut tag2);

        assert_ne!(tag1, tag2);
    }

    // ── KMACXOF tests ───────────────────────────────────────────

    #[test]
    fn kmacxof128_self_test_passes() {
        self_test_kmacxof128().unwrap();
    }

    #[test]
    fn kmacxof256_self_test_passes() {
        self_test_kmacxof256().unwrap();
    }

    #[test]
    fn kmacxof128_differs_from_kmac128() {
        // KMACXOF and KMAC with the same inputs must produce different output
        // because right_encode(0) ≠ right_encode(256).
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x = [0x00u8, 0x01, 0x02, 0x03];

        let mut kmac = Kmac128::new_internal(&key, b"");
        kmac.update(&x);
        let mut tag = [0u8; 32];
        kmac.finalize_into(&mut tag);

        let mut xof = KmacXof128::new_internal(&key, b"");
        xof.update(&x);
        xof.finalize();
        let mut out = [0u8; 32];
        xof.squeeze(&mut out);

        assert_ne!(tag, out, "KMAC and KMACXOF must differ");
    }

    #[test]
    fn kmacxof128_with_custom_string() {
        // KMACXOF128: K=40..5F, X=00 01 02 03, S="My Tagged Application", out=32
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x = [0x00u8, 0x01, 0x02, 0x03];
        let expected: [u8; 32] = hex(
            "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c",
        );
        let mut m = KmacXof128::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        m.finalize();
        let mut out = [0u8; 32];
        m.squeeze(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn kmacxof256_with_custom_string() {
        // KMACXOF256: K=40..5F, X=00 01 02 03, S="My Tagged Application", out=64
        let key: [u8; 32] = core::array::from_fn(|i| (0x40 + i) as u8);
        let x = [0x00u8, 0x01, 0x02, 0x03];
        let expected: [u8; 64] = hex(
            "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa9\
             6faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b",
        );
        let mut m = KmacXof256::new_internal(&key, b"My Tagged Application");
        m.update(&x);
        m.finalize();
        let mut out = [0u8; 64];
        m.squeeze(&mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn kmacxof128_incremental_squeeze() {
        // Squeezing in pieces must match squeezing all at once.
        let key = b"xof-squeeze-test";
        let msg = b"test data for incremental squeeze";

        let mut a = KmacXof128::new_internal(key, b"");
        a.update(msg);
        a.finalize();
        let mut full = [0u8; 256];
        a.squeeze(&mut full);

        let mut b = KmacXof128::new_internal(key, b"");
        b.update(msg);
        b.finalize();
        let mut piecewise = [0u8; 256];
        b.squeeze(&mut piecewise[..50]);
        b.squeeze(&mut piecewise[50..168]);
        b.squeeze(&mut piecewise[168..]);

        assert_eq!(full, piecewise);
    }

    #[test]
    fn kmacxof128_streaming_matches_oneshot() {
        let key = b"streaming-xof-key";
        let msg: [u8; 300] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));

        let mut one = KmacXof128::new_internal(key, b"s");
        one.update(&msg);
        one.finalize();
        let mut out1 = [0u8; 64];
        one.squeeze(&mut out1);

        let mut two = KmacXof128::new_internal(key, b"s");
        two.update(&msg[..100]);
        two.update(&msg[100..]);
        two.finalize();
        let mut out2 = [0u8; 64];
        two.squeeze(&mut out2);

        assert_eq!(out1, out2);
    }
}
