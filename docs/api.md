# oxicrypt API reference

This document provides a quick-reference overview of the public API across
all oxicrypt crates. For detailed function signatures and type definitions,
build the rustdoc with `cargo doc --workspace --no-deps`.

## Crate map

| Crate | Purpose | `no_std` |
|-------|---------|----------|
| `oxicrypt-module` | Module state machine, self-test runner | No (`std`) |
| `oxicrypt-integrity` | Software integrity check (IG 10.3.A) | No (`std`) |
| `oxicrypt-sha` | SHA-1, SHA-2, SHA-3 hash families | Yes |
| `oxicrypt-xof` | SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash | Yes |
| `oxicrypt-hmac` | HMAC over all 11 approved hashes | Yes |
| `oxicrypt-cmac` | AES-CMAC (SP 800-38B) | Yes |
| `oxicrypt-aes` | AES block cipher and modes | Yes |
| `oxicrypt-drbg` | CTR_DRBG, Hash_DRBG, HMAC_DRBG | Yes |
| `oxicrypt-kdf` | SP 800-108 KBKDF, HKDF, PBKDF2 | Yes |
| `oxicrypt-tls-kdf` | TLS 1.2 PRF | Yes |
| `oxicrypt-rsa` | RSA-2048 sign/verify/encrypt/decrypt/keygen | Yes |
| `oxicrypt-ecdsa` | ECDSA P-256 sign/verify/keygen | Yes |
| `oxicrypt-ecdh` | ECDH P-256 shared secret | Yes |
| `oxicrypt-eddsa` | Ed25519 sign/verify/keygen | Yes |
| `oxicrypt-test-vectors` | Generated KAT constants | Yes |

## Module lifecycle

```
PowerOff ──initialize_with_tests()──> SelfTest ──(all KATs pass)──> Operational
                                         │
                                    (any KAT fails)
                                         │
                                         v
                                       Error (terminal)
```

### `oxicrypt_module`

| Function | Signature | Description |
|----------|-----------|-------------|
| `initialize_with_tests` | `(tests: &[KatEntry]) -> Result<(), Error>` | Run power-up KATs, transition to Operational |
| `require_operational` | `() -> Result<(), Error>` | Guard — returns error if not Operational |
| `state` | `() -> State` | Current module state |
| `is_operational` | `() -> bool` | Convenience check |
| `enter_error_state` | `(reason: &'static str)` | Force terminal error state |

## Hash functions — `oxicrypt_sha`

### One-shot functions

| Function | Output | Standard |
|----------|--------|----------|
| `sha1(data)` | `[u8; 20]` | FIPS 180-4 |
| `sha224(data)` | `[u8; 28]` | FIPS 180-4 |
| `sha256(data)` | `[u8; 32]` | FIPS 180-4 |
| `sha384(data)` | `[u8; 48]` | FIPS 180-4 |
| `sha512(data)` | `[u8; 64]` | FIPS 180-4 |
| `sha3_224(data)` | `[u8; 28]` | FIPS 202 |
| `sha3_256(data)` | `[u8; 32]` | FIPS 202 |
| `sha3_384(data)` | `[u8; 48]` | FIPS 202 |
| `sha3_512(data)` | `[u8; 64]` | FIPS 202 |

### Streaming hashers

All hashers share the same interface: `new() -> Result<Self, Error>`,
`update(&mut self, data: &[u8])`, `finalize(self) -> [u8; N]`.

Types: `Sha1`, `Sha224`, `Sha256`, `Sha384`, `Sha512`,
`sha512_t::Sha512_224`, `sha512_t::Sha512_256`,
`Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`.

## HMAC — `oxicrypt_hmac`

All 11 types share: `new(key: &[u8]) -> Result<Self, Error>`,
`update(&mut self, data: &[u8])`, `finalize(self) -> [u8; L]`.

| Type | Output | Hash |
|------|--------|------|
| `HmacSha1` | 20 bytes | SHA-1 |
| `HmacSha224` | 28 bytes | SHA-224 |
| `HmacSha256` | 32 bytes | SHA-256 |
| `HmacSha384` | 48 bytes | SHA-384 |
| `HmacSha512` | 64 bytes | SHA-512 |
| `HmacSha512_224` | 28 bytes | SHA-512/224 |
| `HmacSha512_256` | 32 bytes | SHA-512/256 |
| `HmacSha3_224` | 28 bytes | SHA3-224 |
| `HmacSha3_256` | 32 bytes | SHA3-256 |
| `HmacSha3_384` | 48 bytes | SHA3-384 |
| `HmacSha3_512` | 64 bytes | SHA3-512 |

## AES — `oxicrypt_aes`

### Key types

`Aes128Key::new(&[u8; 16]) -> Result<Self, Error>`, `Aes192Key::new(&[u8; 24]) -> Result<Self, Error>`,
`Aes256Key::new(&[u8; 32]) -> Result<Self, Error>`.

### Mode operations

| Function | Mode | Notes |
|----------|------|-------|
| `ecb_encrypt`, `ecb_decrypt` | ECB | Block-aligned input |
| `cbc_encrypt`, `cbc_decrypt` | CBC | 16-byte IV, block-aligned |
| `ctr_xor` | CTR | 16-byte ICB, any length |
| `gcm_encrypt`, `gcm_decrypt` | GCM | 12-byte IV, 16-byte tag |
| `ccm_encrypt`, `ccm_decrypt` | CCM | Variable nonce/tag lengths |
| `kw_wrap`, `kw_unwrap` | KW | SP 800-38F key wrap |
| `kwp_wrap`, `kwp_unwrap` | KWP | Key wrap with padding |

All mode functions are generic over `BlockCipher`, accepting any AES key size.

### Error type

`ModeError`: `NotBlockAligned`, `InvalidIvLength`, `TagMismatch`,
`LengthMismatch`, `InvalidNonceLength`, `InvalidTagLength`,
`InvalidPayloadLength`, `InvalidAadLength`.

## DRBG — `oxicrypt_drbg`

### Types

CTR_DRBG: `CtrDrbgAes128`, `CtrDrbgAes192`, `CtrDrbgAes256`.
Hash_DRBG: `HashDrbgSha256`, `HashDrbgSha384`, `HashDrbgSha512`.
HMAC_DRBG: `HmacDrbgSha256`, `HmacDrbgSha384`, `HmacDrbgSha512`.

### Common operations

| Method | Description |
|--------|-------------|
| `new()` | Create uninstantiated DRBG |
| `instantiate_df(entropy, nonce, personalization)` | Instantiate with derivation function |
| `instantiate_no_df(seed_material)` | Instantiate without DF (fixed-length seed) |
| `reseed_df(entropy, additional)` | Reseed with DF |
| `generate_df(output, additional)` | Generate random bytes |
| `generate_df_pr(entropy, output, additional)` | Generate with prediction resistance |
| `uninstantiate()` | Zeroize and reset |

### Error type

`DrbgError`: `Uninstantiated`, `ReseedRequired`, `InputTooLong`,
`InvalidSeedLength`, `RequestTooLong`.

## RSA-2048 — `oxicrypt_rsa`

### Key construction

| Method | Description |
|--------|-------------|
| `RsaPrivateKey2048::from_components(n, e, d)` | Import key (runs PCT) |
| `RsaPrivateKey2048::from_components_crt(n, e, d, p, q, dp, dq, qinv)` | Import CRT form |
| `RsaPrivateKey2048::generate(drbg)` | FIPS 186-5 keygen |

### Signing

| Method | Standard |
|--------|----------|
| `sign_pkcs1_v15_sha256(msg)` | RSASSA-PKCS1-v1_5 + SHA-256 |
| `sign_pss_sha256(drbg, msg)` | RSASSA-PSS + SHA-256 (DRBG salt) |
| `sign_pss_sha256_with_salt(msg, salt)` | RSASSA-PSS + SHA-256 (explicit salt) |

### Verification (free functions)

| Function | Standard |
|----------|----------|
| `rsa_pkcs1_v15_verify_2048_sha256(n, e, msg, sig)` | RSASSA-PKCS1-v1_5 |
| `rsa_pss_verify_2048_sha256(n, e, msg, sig)` | RSASSA-PSS |

### OAEP encryption

| Function | Standard |
|----------|----------|
| `rsa_oaep_encrypt_2048_sha256(n, e, plaintext, ciphertext)` | RSAES-OAEP + SHA-256 |

## ECDSA P-256 — `oxicrypt_ecdsa`

### Key handle

| Method | Description |
|--------|-------------|
| `EcdsaP256PrivateKey::generate(drbg)` | Keygen with rejection sampling + PCT |
| `EcdsaP256PrivateKey::from_bytes(drbg, d)` | Import scalar + PCT |
| `sign_sha256(drbg, msg)` | Sign with DRBG-sampled k |
| `public_key()` | 65-byte SEC1 uncompressed public key |

### Free functions

| Function | Description |
|----------|-------------|
| `verify(pk, msg, sig)` | Verify ECDSA-P256-SHA256 signature |
| `derive_public_key(d)` | Compute Q = d * G |
| `sign_with_k(d, msg, k)` | Sign with explicit k (KAT use) |

## Ed25519 — `oxicrypt_eddsa`

### Key handle

| Method | Description |
|--------|-------------|
| `Ed25519PrivateKey::generate(drbg)` | Keygen + PCT |
| `Ed25519PrivateKey::from_seed(drbg, seed)` | Import 32-byte seed + PCT |
| `sign(msg)` | Deterministic sign (RFC 8032) |
| `public_key()` | 32-byte compressed Edwards point |

### Free function

| Function | Description |
|----------|-------------|
| `verify(pk, msg, sig)` | Verify Ed25519 signature |

## ECDH P-256 — `oxicrypt_ecdh`

| Function | Description |
|----------|-------------|
| `compute_shared_secret_p256(d, peer_pk)` | SP 800-56Ar3 CDH: x-coordinate of d * Q |

## KDF — `oxicrypt_kdf`

### PBKDF2

| Method | Description |
|--------|-------------|
| `Pbkdf2::derive(hmac_alg, password, salt, iterations, output)` | SP 800-132 / RFC 8018 |

### KBKDF (SP 800-108)

Counter, feedback, and double-pipeline iteration modes over all 11 HMAC
instantiations.

### HKDF

Extract-then-expand over all 11 HMAC instantiations, with convenience
one-shot functions.

## Module-gate pattern

Every public API function calls `require_operational()` internally.
If the module is not in the `Operational` state, the function returns
`Err(Error::NotOperational { current })` without performing any
cryptographic computation.

```rust
// This pattern is enforced by the library — you don't need to check manually:
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    require_operational()?;  // <-- automatic gate
    // ... compute hash ...
}
```
