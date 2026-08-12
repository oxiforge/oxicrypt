//! Hash_DRBG — NIST SP 800-90A Rev. 1 §10.1.1.
//!
//! Implements Hash_DRBG over the approved SHA-2 digests covered by
//! this module: SHA-256 (`seedlen = 440`), SHA-384 (`seedlen = 888`),
//! and SHA-512 (`seedlen = 888`). Prediction resistance is supported
//! via the `reseed` + `generate` pattern; the implementation is pure
//! state — it does not talk to any entropy source.
//!
//! The derivation function `Hash_df` from §10.3.1 is implemented
//! internally; no external KDF is used.
//!
//! # Implementation notes
//!
//! * Working state is held in fixed-size buffers sized to the
//!   largest supported seedlen (111 bytes). Each variant only uses
//!   the leftmost `SEEDLEN` bytes.
//! * Integer arithmetic modulo `2^(8 * SEEDLEN)` is performed
//!   byte-at-a-time with explicit carry, matching the big-endian
//!   representation SP 800-90A specifies.
//! * The reseed interval is hardcoded at `2^48`, the value SP 800-90A
//!   Table 2 gives for every hash variant.
//! * Hash algorithm hand-off uses the `_internal` constructors
//!   exported by `oxicrypt-sha`, which bypass the module state machine
//!   so that DRBG self-tests can run during Init.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::range_plus_one
)]

use core::marker::PhantomData;

use oxicrypt_module::{Error, Service, require_allowed, require_operational};
use oxicrypt_sha::sha256::Sha256;
use oxicrypt_sha::sha384::Sha384;
use oxicrypt_sha::sha512::Sha512;

use crate::ctr::DrbgError;

/// Maximum digest length across all supported algorithms (SHA-512).
const MAX_OUTLEN: usize = 64;
/// Maximum seedlen across all supported algorithms (SHA-384/512 = 111).
const MAX_SEEDLEN: usize = 111;
/// Upper bound on the total length of `entropy || nonce || personalization`
/// (or `V || entropy || additional_input`) buffered for a single
/// `Hash_df` call. Sized to accommodate the largest ACVP payload:
/// SHA2-512 with `entropy(320) + nonce(64) + perso(256)` bits = 80
/// bytes, plus room for the `V || entropy || additional_input` reseed
/// path, where `V` alone is 111 bytes.
pub const HASH_DRBG_MAX_DF_INPUT: usize = 768;
/// Maximum output bytes per `generate` call (2^19 bits ≈ 64 KiB).
const HASH_DRBG_MAX_BITS_PER_REQ: usize = 1 << 16;
/// SP 800-90A Table 2 reseed interval.
const HASH_DRBG_RESEED_INTERVAL: u64 = 1u64 << 48;

/// Trait describing a concrete SHA-2 flavour used by Hash_DRBG.
pub trait HashAlg {
    /// Digest length in bytes (`outlen` in SP 800-90A).
    const OUTLEN: usize;
    /// Seed length in bytes (SP 800-90A Table 2: 440 bits for SHA-1
    /// through SHA-256, 888 bits for SHA-384 / SHA-512).
    const SEEDLEN: usize;
    /// The FIPS module service gate associated with this hash algorithm.
    const DRBG_SERVICE: Service;
    /// Hash the concatenation of `parts` and write exactly `OUTLEN`
    /// bytes into `out`.
    ///
    /// `out.len()` must be `>= OUTLEN`.
    fn digest_parts(parts: &[&[u8]], out: &mut [u8]);
}

/// `HashAlg` implementation for SHA-256.
pub struct Sha256Alg;
/// `HashAlg` implementation for SHA-384.
pub struct Sha384Alg;
/// `HashAlg` implementation for SHA-512.
pub struct Sha512Alg;

impl HashAlg for Sha256Alg {
    const OUTLEN: usize = 32;
    const SEEDLEN: usize = 55; // 440 bits
    const DRBG_SERVICE: Service = Service::HashDrbgSha256;
    fn digest_parts(parts: &[&[u8]], out: &mut [u8]) {
        let mut ctx = Sha256::new_internal();
        for p in parts {
            ctx.update(p);
        }
        let digest = ctx.finalize();
        out[..32].copy_from_slice(&digest);
    }
}

impl HashAlg for Sha384Alg {
    const OUTLEN: usize = 48;
    const SEEDLEN: usize = 111; // 888 bits
    const DRBG_SERVICE: Service = Service::HashDrbgSha384;
    fn digest_parts(parts: &[&[u8]], out: &mut [u8]) {
        let mut ctx = Sha384::new_internal();
        for p in parts {
            ctx.update(p);
        }
        let digest = ctx.finalize();
        out[..48].copy_from_slice(&digest);
    }
}

impl HashAlg for Sha512Alg {
    const OUTLEN: usize = 64;
    const SEEDLEN: usize = 111; // 888 bits
    const DRBG_SERVICE: Service = Service::HashDrbgSha512;
    fn digest_parts(parts: &[&[u8]], out: &mut [u8]) {
        let mut ctx = Sha512::new_internal();
        for p in parts {
            ctx.update(p);
        }
        let digest = ctx.finalize();
        out[..64].copy_from_slice(&digest);
    }
}

/// Hash_DRBG instance parameterised by a [`HashAlg`].
pub struct HashDrbg<H: HashAlg> {
    /// Working state `V`, big-endian `SEEDLEN`-byte integer.
    v: [u8; MAX_SEEDLEN],
    /// Working state `C`, big-endian `SEEDLEN`-byte integer.
    c: [u8; MAX_SEEDLEN],
    reseed_counter: u64,
    instantiated: bool,
    _marker: PhantomData<H>,
}

/// Hash_DRBG over SHA-256.
pub type HashDrbgSha256 = HashDrbg<Sha256Alg>;
/// Hash_DRBG over SHA-384.
pub type HashDrbgSha384 = HashDrbg<Sha384Alg>;
/// Hash_DRBG over SHA-512.
pub type HashDrbgSha512 = HashDrbg<Sha512Alg>;

impl<H: HashAlg> HashDrbg<H> {
    /// Create an empty, uninstantiated Hash_DRBG slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            v: [0u8; MAX_SEEDLEN],
            c: [0u8; MAX_SEEDLEN],
            reseed_counter: 0,
            instantiated: false,
            _marker: PhantomData,
        }
    }

    /// Hash_DRBG Instantiate — SP 800-90A §10.1.1.2.
    pub fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        require_operational()?;
        require_allowed(H::DRBG_SERVICE)?;
        self.instantiate_internal(entropy, nonce, personalization)
    }

    /// Internal instantiate function used by KAT runners.
    pub(crate) fn instantiate_internal(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<(), Error> {
        let total = entropy
            .len()
            .checked_add(nonce.len())
            .and_then(|n| n.checked_add(personalization.len()))
            .ok_or(Error::InvalidInput)?;
        if total > HASH_DRBG_MAX_DF_INPUT {
            return Err(Error::InvalidInput);
        }
        let mut seed_material = [0u8; HASH_DRBG_MAX_DF_INPUT];
        seed_material[..entropy.len()].copy_from_slice(entropy);
        seed_material[entropy.len()..entropy.len() + nonce.len()].copy_from_slice(nonce);
        let off = entropy.len() + nonce.len();
        seed_material[off..off + personalization.len()].copy_from_slice(personalization);

        // seed = Hash_df(seed_material, seedlen)
        hash_df::<H>(&seed_material[..total], &mut self.v[..H::SEEDLEN]);
        // C = Hash_df(0x00 || V, seedlen)
        let mut prefixed = [0u8; 1 + MAX_SEEDLEN];
        prefixed[0] = 0x00;
        prefixed[1..1 + H::SEEDLEN].copy_from_slice(&self.v[..H::SEEDLEN]);
        hash_df::<H>(&prefixed[..1 + H::SEEDLEN], &mut self.c[..H::SEEDLEN]);
        self.reseed_counter = 1;
        self.instantiated = true;
        Ok(())
    }

    /// Hash_DRBG Reseed — SP 800-90A §10.1.1.3.
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        let total = 1usize
            .checked_add(H::SEEDLEN)
            .and_then(|n| n.checked_add(entropy.len()))
            .and_then(|n| n.checked_add(additional_input.len()))
            .ok_or(DrbgError::InputTooLong)?;
        if total > HASH_DRBG_MAX_DF_INPUT {
            return Err(DrbgError::InputTooLong);
        }
        let mut seed_material = [0u8; HASH_DRBG_MAX_DF_INPUT];
        seed_material[0] = 0x01;
        seed_material[1..1 + H::SEEDLEN].copy_from_slice(&self.v[..H::SEEDLEN]);
        let mut off = 1 + H::SEEDLEN;
        seed_material[off..off + entropy.len()].copy_from_slice(entropy);
        off += entropy.len();
        seed_material[off..off + additional_input.len()].copy_from_slice(additional_input);

        hash_df::<H>(&seed_material[..total], &mut self.v[..H::SEEDLEN]);
        let mut prefixed = [0u8; 1 + MAX_SEEDLEN];
        prefixed[0] = 0x00;
        prefixed[1..1 + H::SEEDLEN].copy_from_slice(&self.v[..H::SEEDLEN]);
        hash_df::<H>(&prefixed[..1 + H::SEEDLEN], &mut self.c[..H::SEEDLEN]);
        self.reseed_counter = 1;
        Ok(())
    }

    /// Hash_DRBG Generate — SP 800-90A §10.1.1.4.
    ///
    /// If `additional_input` is present its length must fit within
    /// `HASH_DRBG_MAX_DF_INPUT - 1 - SEEDLEN`.
    pub fn generate(
        &mut self,
        additional_input: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        if !self.instantiated {
            return Err(DrbgError::Uninstantiated);
        }
        if out.len() > HASH_DRBG_MAX_BITS_PER_REQ {
            return Err(DrbgError::RequestTooLong);
        }
        if self.reseed_counter > HASH_DRBG_RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }

        // Step 2: if additional_input != Null: w = Hash(0x02 || V || ai)
        if let Some(ai) = additional_input {
            if ai
                .len()
                .checked_add(1 + H::SEEDLEN)
                .is_none_or(|t| t > HASH_DRBG_MAX_DF_INPUT)
            {
                return Err(DrbgError::InputTooLong);
            }
            let mut w = [0u8; MAX_OUTLEN];
            let prefix = [0x02u8];
            H::digest_parts(&[&prefix, &self.v[..H::SEEDLEN], ai], &mut w[..H::OUTLEN]);
            // V = (V + w) mod 2^(8*SEEDLEN)
            add_into_be(&mut self.v[..H::SEEDLEN], &w[..H::OUTLEN]);
        }

        // Step 3: returned_bits = Hashgen(requested, V)
        self.hashgen(out);

        // Step 4: H = Hash(0x03 || V)
        let mut h = [0u8; MAX_OUTLEN];
        let prefix = [0x03u8];
        H::digest_parts(&[&prefix, &self.v[..H::SEEDLEN]], &mut h[..H::OUTLEN]);

        // Step 5: V = (V + H + C + reseed_counter) mod 2^(8*SEEDLEN)
        add_into_be(&mut self.v[..H::SEEDLEN], &h[..H::OUTLEN]);
        let c_copy_len = H::SEEDLEN;
        // Borrow gymnastics: copy C into a temp to avoid aliased borrow
        // of &self in add_into_be.
        let mut c_tmp = [0u8; MAX_SEEDLEN];
        c_tmp[..c_copy_len].copy_from_slice(&self.c[..c_copy_len]);
        add_into_be(&mut self.v[..H::SEEDLEN], &c_tmp[..c_copy_len]);
        let rc_be = self.reseed_counter.to_be_bytes();
        add_into_be(&mut self.v[..H::SEEDLEN], &rc_be);

        self.reseed_counter += 1;
        Ok(())
    }

    /// Hash_DRBG Generate with prediction resistance —
    /// SP 800-90A §9.3.1 step 7.
    ///
    /// Equivalent to `reseed(entropy, additional_input)` followed by
    /// `generate(None, out)`, matching the §9.3.1 step 7.1/7.2
    /// sequence where the additional input is consumed by the reseed
    /// and the subsequent generate is invoked with a Null additional
    /// input.
    pub fn generate_pr(
        &mut self,
        entropy: &[u8],
        additional_input: &[u8],
        out: &mut [u8],
    ) -> Result<(), DrbgError> {
        self.reseed(entropy, additional_input)?;
        self.generate(None, out)
    }

    /// Zeroise and mark the instance uninstantiated.
    pub fn uninstantiate(&mut self) {
        self.v = [0u8; MAX_SEEDLEN];
        self.c = [0u8; MAX_SEEDLEN];
        self.reseed_counter = 0;
        self.instantiated = false;
    }

    /// Health-test helper: force the reseed counter above the
    /// SP 800-90A §10.1.1 ceiling so the next `generate` call
    /// returns [`DrbgError::ReseedRequired`]. Used only by the
    /// §11.3 power-up health tests.
    #[doc(hidden)]
    pub fn debug_force_reseed_ceiling(&mut self) {
        self.reseed_counter = HASH_DRBG_RESEED_INTERVAL + 1;
    }

    /// `Hashgen(requested_bytes, V)` — SP 800-90A §10.1.1.4 step 3.
    fn hashgen(&mut self, out: &mut [u8]) {
        let mut data = [0u8; MAX_SEEDLEN];
        data[..H::SEEDLEN].copy_from_slice(&self.v[..H::SEEDLEN]);
        let mut produced = 0usize;
        let mut block = [0u8; MAX_OUTLEN];
        while produced < out.len() {
            H::digest_parts(&[&data[..H::SEEDLEN]], &mut block[..H::OUTLEN]);
            let take = core::cmp::min(H::OUTLEN, out.len() - produced);
            out[produced..produced + take].copy_from_slice(&block[..take]);
            produced += take;
            // data = (data + 1) mod 2^(8*SEEDLEN)
            increment_be(&mut data[..H::SEEDLEN]);
        }
    }
}

impl<H: HashAlg> Default for HashDrbg<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HashAlg> Drop for HashDrbg<H> {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.v);
        oxicrypt_zeroize::zeroize(&mut self.c);
    }
}

/// `Hash_df(input_string, no_of_bits_to_return)` — SP 800-90A §10.3.1.
///
/// Writes exactly `out.len()` derived bytes. `out.len()` must be at
/// most 255 × `OUTLEN` (the counter in Hash_df is a single byte).
pub(crate) fn hash_df<H: HashAlg>(input: &[u8], out: &mut [u8]) {
    let no_bytes = out.len();
    let no_bits_be = ((no_bytes as u32) * 8).to_be_bytes();
    let mut counter: u8 = 1;
    let mut produced = 0usize;
    let mut block = [0u8; MAX_OUTLEN];
    while produced < no_bytes {
        let counter_byte = [counter];
        H::digest_parts(
            &[&counter_byte, &no_bits_be, input],
            &mut block[..H::OUTLEN],
        );
        let take = core::cmp::min(H::OUTLEN, no_bytes - produced);
        out[produced..produced + take].copy_from_slice(&block[..take]);
        produced += take;
        counter = counter.wrapping_add(1);
    }
}

/// `dst = (dst + src) mod 2^(8*dst.len())` interpreted as big-endian.
///
/// `src` may be shorter than `dst`; it is right-aligned (most
/// significant bytes of the sum are taken from `dst` untouched plus
/// any carry).
fn add_into_be(dst: &mut [u8], src: &[u8]) {
    let dst_len = dst.len();
    let src_len = src.len();
    let mut carry: u16 = 0;
    // Walk from least significant (end) toward most significant (start).
    let common = core::cmp::min(dst_len, src_len);
    for i in 0..common {
        let di = dst_len - 1 - i;
        let si = src_len - 1 - i;
        let sum = u16::from(dst[di]) + u16::from(src[si]) + carry;
        dst[di] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // Propagate carry into the remaining MSBs of dst.
    if dst_len > src_len {
        let mut i = dst_len - common;
        while carry != 0 && i > 0 {
            i -= 1;
            let sum = u16::from(dst[i]) + carry;
            dst[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }
    // Any remaining carry is silently dropped, implementing the
    // `mod 2^(8*dst_len)` reduction.
}

/// Increment a big-endian integer in place, wrapping at 2^(8*len).
fn increment_be(buf: &mut [u8]) {
    let mut i = buf.len();
    while i > 0 {
        i -= 1;
        let (next, carry) = buf[i].overflowing_add(1);
        buf[i] = next;
        if !carry {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), N * 2, "hex length mismatch");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            let hi = hex_nib(bytes[2 * i]);
            let lo = hex_nib(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    const fn hex_nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0xff,
        }
    }

    // CAVP Hash_DRBG no-reseed SHA-256 [EntropyInputLen=256 NonceLen=128
    // PersonalizationStringLen=0 AdditionalInputLen=0 ReturnedBitsLen=1024]
    // COUNT = 0
    #[test]
    fn cavp_hash_drbg_sha256_count0() {
        let entropy: [u8; 32] =
            hex_to_bytes("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb");
        let nonce: [u8; 16] = hex_to_bytes("8581f9317517276e06e9607ddbcbcc2e");
        let expected: [u8; 128] = hex_to_bytes(
            "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
        );
        let mut drbg = HashDrbgSha256::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 128];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn cavp_hash_drbg_sha384_count0() {
        let entropy: [u8; 32] =
            hex_to_bytes("9ef0b00381d6c8c54d08fcadc6f5ef331134bb986373f65c6a14f553bcb6c55d");
        let nonce: [u8; 16] = hex_to_bytes("9fce26ada7b1de39590312bd9d81c4f5");
        let expected: [u8; 192] = hex_to_bytes(
            "663ffb625e62c4eb67d7177a6abb808a9f68c2d5840f19992c11ea3a635d05b537fae1f1746c1314e1a75e141c2e094187d17b9daae1442e41d3a0d1fea94d8ef9d840111379a52e6c7ffafa7ee83b244ced129613d5b8bb089e7ea25de1c29897735cf95695043a648a2ef6fd4aa74ce8328a5550da8ddb51f98adcdc108e455603f6f18f5a50016f3e8ebcb244a16bc6b6e554a7546153c12f522c75ca5f1017e01da36650e6203f30ed5c3da3b6078736465eecb400eeaaa2c876e37564d8",
        );
        let mut drbg = HashDrbgSha384::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 192];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn cavp_hash_drbg_sha512_count0() {
        let entropy: [u8; 32] =
            hex_to_bytes("6b50a7d8f8a55d7a3df8bb40bcc3b722d8708de67fda010b03c4c84d72096f8c");
        let nonce: [u8; 16] = hex_to_bytes("3ec649cc6256d9fa31db7a2904aaf025");
        let expected: [u8; 256] = hex_to_bytes(
            "95b7f17e9802d3577392c6a9c08083b67dd1292265b5f42d237f1c55bb9b10bfcfd82c77a378b8266a0099143b3c2d64611eeeb69acdc055957c139e8b190c7a06955f2c797c2778de940396a501f40e91396acf8d7e45ebdbb53bbf8c975230d2f0ff9106c76119ae498e7fbc03d90f8e4c51627aed5c8d4263d5d2b978873a0de596ee6dc7f7c29e37eee8b34c90dd1cf6a9ddb22b4cbd086b14b35de93da2d5cb1806698cbd7bbb67bfe3d31fd2d1dbd2a1e058a3eb99d7e51f1a938eed5e1c1de23a6b4345d3191409f92f39b3670d8dbfb635d8e6a36932d81033d1448d63b403ddf88e121b6e819ac381226c1321e4b08644f6727c368c5a9f7a4b3ee2",
        );
        let mut drbg = HashDrbgSha512::new();
        drbg.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out = [0u8; 256];
        drbg.generate(None, &mut out).unwrap();
        drbg.generate(None, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    // Consistency check for §9.3.1 prediction-resistance generate.
    #[test]
    fn generate_pr_matches_reseed_then_generate() {
        let entropy: [u8; 32] = [0x11u8; 32];
        let nonce: [u8; 16] = [0x22u8; 16];
        let reseed_e: [u8; 32] = [0x33u8; 32];
        let reseed_ai: [u8; 12] = [0x44u8; 12];

        let mut a = HashDrbgSha256::new();
        a.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        let mut out_a = [0u8; 80];
        a.generate_pr(&reseed_e, &reseed_ai, &mut out_a).unwrap();

        let mut b = HashDrbgSha256::new();
        b.instantiate_internal(&entropy, &nonce, &[]).unwrap();
        b.reseed(&reseed_e, &reseed_ai).unwrap();
        let mut out_b = [0u8; 80];
        b.generate(None, &mut out_b).unwrap();

        assert_eq!(out_a, out_b);
    }

    #[test]
    fn add_into_be_basic() {
        let mut dst = [0x00u8, 0x00, 0xff];
        let src = [0x02u8];
        add_into_be(&mut dst, &src);
        assert_eq!(dst, [0x00, 0x01, 0x01]);
    }

    #[test]
    fn add_into_be_wraps() {
        let mut dst = [0xffu8, 0xff, 0xff];
        let src = [0x01u8];
        add_into_be(&mut dst, &src);
        assert_eq!(dst, [0x00, 0x00, 0x00]);
    }
}
