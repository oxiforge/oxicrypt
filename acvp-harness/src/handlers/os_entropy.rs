//! OS-entropy and DRBG bootstrap shared by every handler that
//! samples fresh randomness for FIPS 186-5 §A.2.2 generative paths
//! (ECDSA sigGen/keyGen, KAS-ECC-SSC live AFT, future EdDSA keyGen,
//! ML-DSA/ML-KEM/SLH-DSA keyGen, etc).
//!
//! The harness is Linux-only — its mTLS transport relies on the
//! `s_client(1)` subprocess for PIV-key-bound TLS — so `/dev/urandom`
//! is the canonical entropy source. SP 800-90A §10.1 specifies a
//! 256-bit minimum entropy + 128-bit minimum nonce for the SHA-256
//! HMAC_DRBG instantiation; this module reads 32 + 16 = 48 bytes and
//! splits them accordingly.

use crate::dispatch::DispatchError;

/// Build a freshly instantiated [`oxicrypt_drbg::HmacDrbgSha256`]
/// seeded from `/dev/urandom`. The 48-byte read is split into
/// 32 bytes of entropy and 16 bytes of nonce, satisfying SP 800-90A
/// §10.1's minimums for the SHA-256 instantiation.
pub fn build_seeded_drbg() -> Result<oxicrypt_drbg::HmacDrbgSha256, DispatchError> {
    let mut buf = [0u8; 48];
    read_os_entropy(&mut buf)?;
    let mut drbg = oxicrypt_drbg::HmacDrbgSha256::new();
    drbg.instantiate(&buf[..32], &buf[32..], &[])
        .map_err(|_| DispatchError::Crypto("HmacDrbgSha256::instantiate failed"))?;
    Ok(drbg)
}

/// Read OS entropy from `/dev/urandom`. Failure surfaces as
/// [`DispatchError::Crypto`] rather than a panic.
pub fn read_os_entropy(buf: &mut [u8]) -> Result<(), DispatchError> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|_| DispatchError::Crypto("open /dev/urandom failed"))?;
    f.read_exact(buf)
        .map_err(|_| DispatchError::Crypto("read /dev/urandom failed"))?;
    Ok(())
}
