# oxicrypt API reference

This document provides a quick-reference overview of the public API across
all oxicrypt crates. For detailed function signatures and type definitions,
build the rustdoc with `cargo doc --workspace --no-deps`.

## Crate map

| Crate | Purpose | `no_std` |
|-------|---------|----------|
| `oxicrypt-module` | Module state machine, self-test runner | No (`std`) |
| `oxicrypt-integrity` | Pre-operational software integrity check (§7.10.2.2) | No (`std`) |
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
| `oxicrypt-dh` | Finite-field DH-3072 (RFC 3526 Group 15) | Yes |
| `oxicrypt-ml-kem` | ML-KEM-512/768/1024 (FIPS 203) | Yes |
| `oxicrypt-ml-dsa` | ML-DSA-44/65/87 (FIPS 204) | Yes |
| `oxicrypt-slh-dsa` | SLH-DSA 12 param sets (FIPS 205) | Yes¹ |
| `oxicrypt-lms` | LMS / LM-OTS stateful HBS (SP 800-208) | Yes¹ |
| `oxicrypt-xmss` | XMSS-SHA2_10_256 stateful HBS (SP 800-208) | Yes |
| `oxicrypt-test-vectors` | Generated KAT constants | Yes |

¹ `oxicrypt-slh-dsa` and `oxicrypt-lms` are `no_std` by default; the
optional `parallel` feature pulls in `rayon` (hence `std`).

### Out-of-boundary / tooling crates

These crates are not part of the module's public cryptographic
API. They are internal infrastructure or out-of-boundary tooling and are
documented here only for completeness:

| Crate | Purpose |
|-------|---------|
| `oxicrypt-zeroize` | Out-of-boundary tooling / internal — volatile memory zeroization primitive |
| `oxicrypt-sha-accel` | Out-of-boundary tooling / internal — SHA hardware-acceleration backend |
| `oxicrypt-aes-accel` | Out-of-boundary tooling / internal — AES hardware-acceleration backend |
| `oxicrypt-timer` | Out-of-boundary tooling / internal — jitter-source timing primitive |
| `oxicrypt-entropy` | Out-of-boundary tooling / internal — entropy-source assessment support |
| `oxicrypt-maxwell` | Out-of-boundary tooling / internal — SP 800-90B entropy-estimation tooling |
| `oxicrypt-ffi` | Out-of-boundary tooling / internal — C ABI foreign-function interface |

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
| `initialize_with_tests` | `(integrity: &[KatEntry], tests: &[KatEntry]) -> Result<(), Error>` | Run the integrity test then power-up KATs, transition to Operational |
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

## XOF / SP 800-185 — `oxicrypt_xof`

SHAKE extendable-output functions (FIPS 202 §6.2) plus the SP 800-185
derived functions: cSHAKE, KMAC, KMACXOF, TupleHash, and ParallelHash.

### Rate constants

```rust
pub const SHAKE128_RATE: usize = 168;  // 256-bit capacity
pub const SHAKE256_RATE: usize = 136;  // 512-bit capacity
```

### SHAKE — one-shot

```rust
pub fn shake128<const OUT_LEN: usize>(data: &[u8]) -> Result<[u8; OUT_LEN], Error>;
pub fn shake256<const OUT_LEN: usize>(data: &[u8]) -> Result<[u8; OUT_LEN], Error>;
```

### SHAKE — streaming

`Shake128` and `Shake256` share the same XOF interface:

```rust
impl Shake128 {
    pub fn new() -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(&mut self);              // ends absorb phase
    pub fn squeeze(&mut self, out: &mut [u8]); // may be called repeatedly
}
```

### cSHAKE (SP 800-185 §3)

```rust
// One-shot: n = function name, s = customization string.
pub fn cshake128<const OUT_LEN: usize>(data: &[u8], n: &[u8], s: &[u8]) -> Result<[u8; OUT_LEN], Error>;
pub fn cshake256<const OUT_LEN: usize>(data: &[u8], n: &[u8], s: &[u8]) -> Result<[u8; OUT_LEN], Error>;

// Streaming: CShake128 / CShake256.
impl CShake128 {
    pub fn new(n: &[u8], s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(&mut self);
    pub fn squeeze(&mut self, out: &mut [u8]);
}
```

### KMAC (SP 800-185 §4)

```rust
// One-shot: key, message, s = customization string.
pub fn kmac128<const TAG_LEN: usize>(key: &[u8], data: &[u8], s: &[u8]) -> Result<[u8; TAG_LEN], Error>;
pub fn kmac256<const TAG_LEN: usize>(key: &[u8], data: &[u8], s: &[u8]) -> Result<[u8; TAG_LEN], Error>;

// Streaming: Kmac128 / Kmac256 (fixed-length tag).
impl Kmac128 {
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize_into(&mut self, tag: &mut [u8]);
}
```

### KMACXOF (SP 800-185 §4.3.1)

Arbitrary-length output variant of KMAC.

```rust
pub fn kmacxof128<const OUT_LEN: usize>(key: &[u8], data: &[u8], s: &[u8]) -> Result<[u8; OUT_LEN], Error>;
pub fn kmacxof256<const OUT_LEN: usize>(key: &[u8], data: &[u8], s: &[u8]) -> Result<[u8; OUT_LEN], Error>;

// Streaming: KmacXof128 / KmacXof256.
impl KmacXof128 {
    pub fn new(key: &[u8], s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(&mut self);
    pub fn squeeze(&mut self, out: &mut [u8]);
}
```

### TupleHash (SP 800-185 §5)

Hashes a sequence of byte strings with unambiguous separation; each
`update` call adds one tuple element.

```rust
// TupleHash128 / TupleHash256 — fixed-length output.
impl TupleHash128 {
    pub fn new(s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, element: &[u8]);   // one tuple element per call
    pub fn finalize_into(&mut self, out: &mut [u8]);
}

// TupleHashXof128 / TupleHashXof256 — arbitrary-length output (§5.3.1).
impl TupleHashXof128 {
    pub fn new(s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, element: &[u8]);
    pub fn finalize(&mut self);
    pub fn squeeze(&mut self, out: &mut [u8]);
}
```

### ParallelHash (SP 800-185 §6)

`block_size` is the per-block byte length `B`.

```rust
// ParallelHash128 / ParallelHash256 — fixed-length output.
impl ParallelHash128 {
    pub fn new(block_size: usize, s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize_into(&mut self, out: &mut [u8]);
}

// ParallelHashXof128 / ParallelHashXof256 — arbitrary-length output (§6.3.1).
impl ParallelHashXof128 {
    pub fn new(block_size: usize, s: &[u8]) -> Result<Self, Error>;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(&mut self);
    pub fn squeeze(&mut self, out: &mut [u8]);
}
```

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

## ML-KEM — `oxicrypt_ml_kem`

Lattice-based key encapsulation (FIPS 203). Three parameter sets, each in
its own module: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`. The crate root
re-exports the `ml_kem_1024` surface for backward compatibility.

### Free functions (per variant module)

| Function | Signature |
|----------|-----------|
| `keygen` | `(d: &[u8; SEED_LEN], z: &[u8; SEED_LEN]) -> Result<([u8; EK_LEN], [u8; DK_LEN]), Error>` |
| `encapsulate` | `(ek: &[u8; EK_LEN], m: &[u8; SEED_LEN]) -> Result<([u8; SHARED_SECRET_LEN], [u8; CT_LEN]), Error>` |
| `decapsulate` | `(dk: &[u8; DK_LEN], ct: &[u8; CT_LEN]) -> Result<[u8; SHARED_SECRET_LEN], Error>` |

`keygen` returns `(ek, dk)` — the encapsulation (public) key first, then
the decapsulation (private) key. `encapsulate` returns
`(shared_secret, ciphertext)`. `m`, `d`, and `z` are each 32 bytes of
fresh DRBG output.

### Constants (per variant module)

```rust
pub const SEED_LEN: usize = 32;            // d, z, m randomness length
pub const SHARED_SECRET_LEN: usize = 32;
// Variant-dependent (ML-KEM-512 / 768 / 1024):
pub const EK_LEN: usize;   // 800  / 1184 / 1568
pub const DK_LEN: usize;   // 1632 / 2400 / 3168
pub const CT_LEN: usize;   // 768  / 1088 / 1568
```

## ML-DSA — `oxicrypt_ml_dsa`

Lattice-based digital signatures (FIPS 204). Modules `ml_dsa_44`,
`ml_dsa_65`, `ml_dsa_87`; the crate root re-exports `ml_dsa_87`.

### Free functions (per variant module)

| Function | Signature |
|----------|-----------|
| `keygen` | `(xi: &[u8; SEED_LEN]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error>` |
| `sign` | `(sk: &[u8; SK_LEN], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error>` |
| `verify` | `(pk: &[u8; PK_LEN], message: &[u8], ctx: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), Error>` |

`keygen` returns `(pk, sk)` — public key first. `sign` / `verify`
implement the external FIPS 204 §5.2 API and frame the message as
`M' = 0x00 || |ctx| || ctx || M`; pass `ctx = b""` for the spec-default
(X.509 / CMS / OpenSSL 3.5) shape.

### Constants (per variant module)

```rust
pub const SEED_LEN: usize = 32;
// Variant-dependent (ML-DSA-44 / 65 / 87):
pub const PK_LEN: usize;   // 1312 / 1952 / 2592
pub const SK_LEN: usize;   // 2560 / 4032 / 4896
pub const SIG_LEN: usize;  // 2420 / 3309 / 4627
```

## SLH-DSA — `oxicrypt_slh_dsa`

Stateless hash-based signatures (FIPS 205). Twelve parameter-set modules:
`slh_dsa_{sha2,shake}_{128,192,256}{s,f}`. The crate root re-exports
`slh_dsa_sha2_256s`. CNSSP-15 lists no SLH-DSA parameter set, so all twelve
are permitted under the Unrestricted profile only.

### Free functions (per variant module)

| Function | Signature |
|----------|-----------|
| `keygen` | `(xi: &[u8]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error>` |
| `sign` | `(sk: &[u8], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error>` |
| `verify` | `(pk: &[u8], message: &[u8], ctx: &[u8], signature: &[u8]) -> Result<(), Error>` |

`keygen` returns `(pk, sk)` — public key first; `xi` must be exactly
`3 * N` bytes (`SK_SEED || SK_PRF || PK_SEED`). `sign` / `verify`
implement the external FIPS 205 §9.2 / §9.3 API with the same
`M' = 0x00 || |ctx| || ctx || M` framing as ML-DSA (`ctx = b""` for the
spec default).

### Constants (per variant module)

```rust
pub const N: usize;        // 16 (128*) / 24 (192*) / 32 (256*)
pub const PK_LEN: usize;   // = 2 * N
pub const SK_LEN: usize;   // = 4 * N
pub const SIG_LEN: usize;  // param-set dependent (e.g. 29 792 for SHA2-256s)
```

## LMS — `oxicrypt_lms`

Leighton-Micali stateful hash-based signatures (SP 800-208 / RFC 8554 /
RFC 8708). **Stateful**: each Merkle-tree leaf signs exactly one message;
the signer must persist the private key's leaf index after every
signature to avoid catastrophic one-time-key reuse.

Each (LMS, LM-OTS) parameter pair lives in its own module
`lms_<family>_m<N>_h<H>_w<W>` over family ∈ {`sha256`, `shake`},
N ∈ {24, 32}, H ∈ {5, 10, 15, 20, 25}, W ∈ {1, 2, 4, 8} (80 pairs). The
crate root re-exports the `lms_sha256_m32_h10_w4` baseline pair.

### Key types

`LmsPrivateKey` — zeroize-on-Drop private key with a stateful leaf
counter; `leaf_index() -> u32`, `is_exhausted() -> bool`,
`to_bytes() -> [u8; PRIVATE_KEY_LEN]`, `from_bytes(&[u8]) -> Option<Self>`.

### Free functions (per pair module)

| Function | Signature |
|----------|-----------|
| `keygen` | `(xi: &[u8; 32]) -> Result<(LmsPrivateKey, [u8; PUBLIC_KEY_LEN]), Error>` |
| `sign` | `(key: &mut LmsPrivateKey, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error>` |
| `verify` | `(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), Error>` |

`keygen` returns `(sk, pk)` — the private key first, then the public key.
`sign` advances the leaf index; it returns `Err(Error::InvalidInput)`
once the tree is exhausted.

### Cached signing — `LmsSigningKey` (feature `alloc`)

Precomputes the full Merkle node table once (cost ≈ one keygen), taking
per-signature tree cost from O(2^H) to O(H). Signatures are
byte-identical to the uncached path.

```rust
impl LmsSigningKey {
    pub fn new(xi: &[u8; 32]) -> Result<(Self, [u8; PUBLIC_KEY_LEN]), Error>;
    pub fn from_private_key(key: LmsPrivateKey) -> Result<Self, Error>;
    pub fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error>;
    pub fn leaf_index(&self) -> u32;
    pub fn is_exhausted(&self) -> bool;
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN];
    pub fn private_key(&self) -> &LmsPrivateKey;   // borrow to persist state
    pub fn into_private_key(self) -> LmsPrivateKey;
}
```

### Constants (per pair module)

```rust
pub const MAX_SIGNATURES: u32;   // 2^H
pub const SIGNATURE_LEN: usize;
pub const PUBLIC_KEY_LEN: usize;
pub const PRIVATE_KEY_LEN: usize;
```

## XMSS — `oxicrypt_xmss`

eXtended Merkle Signature Scheme (SP 800-208 / RFC 8391), parameter set
XMSS-SHA2_10_256 (SHA-256, tree height 10 = 1024 signatures). Like LMS,
**stateful** — each leaf signs once; persist the leaf index after every
signature.

### Key type

`XmssPrivateKey` — zeroize-on-Drop private key with a stateful leaf
counter; `leaf_index() -> u32`, `is_exhausted() -> bool`,
`to_bytes() -> [u8; 132]`, `from_bytes(&[u8]) -> Option<Self>`.

### Free functions

| Function | Signature |
|----------|-----------|
| `keygen` | `(xi: &[u8; 32]) -> Result<(XmssPrivateKey, [u8; PUBLIC_KEY_LEN]), Error>` |
| `sign` | `(key: &mut XmssPrivateKey, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error>` |
| `verify` | `(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<(), Error>` |

`keygen` returns `(sk, pk)` — the private key first. `sign` advances the
leaf index and returns `Err(Error::InvalidInput)` once exhausted.

### Constants

```rust
pub const SIGNATURE_LEN: usize = 2500;   // idx(4) + r(32) + wots(67*32) + auth(10*32)
pub const PUBLIC_KEY_LEN: usize = 68;    // OID(4) + root(32) + PUB_SEED(32)
pub const MAX_SIGNATURES: u32 = 1024;
```

## DH-3072 — `oxicrypt_dh`

Finite-field Diffie-Hellman key agreement over RFC 3526 Group 15
(3072-bit MODP group, generator `g = 2`), per SP 800-56Ar3. Keys and the
shared secret are all 384-byte big-endian values.

### Free functions

| Function | Signature |
|----------|-----------|
| `generate_keypair_3072` | `(drbg: &mut HmacDrbgSha256) -> Result<([u8; KEY_BYTES], [u8; KEY_BYTES]), Error>` |
| `compute_shared_secret_3072` | `(x_bytes: &[u8; KEY_BYTES], y_bytes: &[u8; KEY_BYTES]) -> Result<[u8; KEY_BYTES], Error>` |

`generate_keypair_3072` returns `(private_key, public_key)` = `(x, y)`
where `y = g^x mod p`. `compute_shared_secret_3072` computes
`Z = y_B^{x_A} mod p` (the caller's private key `x`, the peer's public
key `y`); the returned `Z` is raw and must be fed into an SP 800-56Cr2
extractor / KDF before use as keying material. `drbg` is an
`oxicrypt_drbg::hmac::HmacDrbgSha256`.

### Constant

```rust
pub const KEY_BYTES: usize = 384;   // private key, public key, and shared secret
```

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
