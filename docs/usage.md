# Using oxicrypt

This guide walks through the oxicrypt API, from module initialization through
algorithm usage. All public APIs enforce the FIPS 140-3 module state machine:
you must initialize the module before calling any cryptographic operation.

## Module initialization

Every program using oxicrypt must initialize the module once at startup.
This runs all power-up known-answer tests and the software integrity check
before any cryptographic service becomes available.

```rust
use oxicrypt_module::{initialize_with_tests, require_operational, KatEntry};

fn main() -> Result<(), oxicrypt_module::Error> {
    // Collect KATs from every algorithm crate you use.
    // Each crate exposes a KATS constant with its test entries.
    let mut all_kats = Vec::new();
    all_kats.extend_from_slice(oxicrypt_sha::KATS);
    all_kats.extend_from_slice(oxicrypt_hmac::KATS);
    all_kats.extend_from_slice(oxicrypt_aes::KATS);
    all_kats.extend_from_slice(oxicrypt_drbg::KATS);

    // Initialize the module. This runs every KAT sequentially.
    // If any test fails, the module enters an error state and
    // all subsequent require_operational() calls will fail.
    initialize_with_tests(&all_kats)?;

    // From this point, all approved services are available.
    require_operational()?;
    Ok(())
}
```

The module has four states: `PowerOff`, `SelfTest`, `Operational`, and
`Error`. Once in `Error`, the module cannot recover — the process must
be restarted. Every public API function calls `require_operational()`
internally, so you get a clear error rather than silent misbehavior if
initialization fails.

## Hashing (SHA-1, SHA-2, SHA-3)

oxicrypt provides both one-shot functions and streaming hashers for all
approved hash algorithms.

### One-shot hashing

```rust
use oxicrypt_sha::{sha256, sha3_256};

let digest = sha256(b"hello world")?;    // [u8; 32]
let digest = sha3_256(b"hello world")?;  // [u8; 32]
```

### Streaming (multi-part) hashing

```rust
use oxicrypt_sha::Sha256;

let mut hasher = Sha256::new()?;
hasher.update(b"hello ");
hasher.update(b"world");
let digest = hasher.finalize();  // [u8; 32]
```

All SHA-2 and SHA-3 variants follow the same pattern: `Sha1`, `Sha224`,
`Sha256`, `Sha384`, `Sha512`, `Sha3_224`, `Sha3_256`, `Sha3_384`,
`Sha3_512`. Truncated SHA-512 variants are available as
`sha512_t::Sha512_224` and `sha512_t::Sha512_256`.

## HMAC

```rust
use oxicrypt_hmac::HmacSha256;

let mut mac = HmacSha256::new(b"my-secret-key")?;
mac.update(b"message to authenticate");
let tag = mac.finalize();  // [u8; 32]
```

All eleven HMAC instantiations are available: `HmacSha1`, `HmacSha224`,
`HmacSha256`, `HmacSha384`, `HmacSha512`, `HmacSha512_224`,
`HmacSha512_256`, `HmacSha3_224`, `HmacSha3_256`, `HmacSha3_384`,
`HmacSha3_512`.

## AES

### AES-GCM (authenticated encryption)

```rust
use oxicrypt_aes::{Aes256Key, gcm_encrypt, gcm_decrypt};

let key = Aes256Key::new(&key_bytes);
let iv = [0u8; 12];  // 96-bit IV (use a unique IV for each message)
let aad = b"additional authenticated data";
let plaintext = b"secret message";

// Encrypt
let mut ciphertext = vec![0u8; plaintext.len()];
let mut tag = [0u8; 16];
gcm_encrypt(&key, &iv, aad, plaintext, &mut ciphertext, &mut tag)?;

// Decrypt
let mut recovered = vec![0u8; ciphertext.len()];
gcm_decrypt(&key, &iv, aad, &ciphertext, &mut recovered, &tag)?;
```

### AES-CTR (streaming cipher)

```rust
use oxicrypt_aes::{Aes256Key, ctr_xor};

let key = Aes256Key::new(&key_bytes);
let icb = [0u8; 16];  // Initial counter block
let mut output = vec![0u8; plaintext.len()];
ctr_xor(&key, &icb, &plaintext, &mut output);
// Decrypt is the same operation (XOR is its own inverse)
```

### AES-CBC

```rust
use oxicrypt_aes::{Aes256Key, cbc_encrypt, cbc_decrypt};

let key = Aes256Key::new(&key_bytes);
let iv = [0u8; 16];
let mut ct = vec![0u8; plaintext.len()];  // Must be block-aligned
cbc_encrypt(&key, &iv, &plaintext, &mut ct)?;
```

### Key wrapping (SP 800-38F)

```rust
use oxicrypt_aes::{Aes256Key, kw_wrap, kw_unwrap};

let kek = Aes256Key::new(&kek_bytes);
let mut wrapped = vec![0u8; key_to_wrap.len() + 8];  // +8 for integrity check value
kw_wrap(&kek, &key_to_wrap, &mut wrapped)?;
```

## DRBG (random number generation)

```rust
use oxicrypt_drbg::CtrDrbgAes256;

let mut drbg = CtrDrbgAes256::new();

// Instantiate with entropy, nonce, and optional personalization
drbg.instantiate_df(&entropy, &nonce, b"my-application")?;

// Generate random bytes
let mut random_bytes = [0u8; 32];
drbg.generate_df(&mut random_bytes, &[])?;

// Reseed when needed
drbg.reseed_df(&fresh_entropy, &[])?;

// Generate with prediction resistance (fresh entropy per call)
drbg.generate_df_pr(&fresh_entropy, &mut random_bytes, &[])?;
```

Three DRBG families are available: `CtrDrbgAes128` / `CtrDrbgAes192` /
`CtrDrbgAes256`, `HashDrbgSha256` / `HashDrbgSha384` / `HashDrbgSha512`,
and `HmacDrbgSha256` / `HmacDrbgSha384` / `HmacDrbgSha512`.

## RSA-2048

### Sign and verify

```rust
use oxicrypt_rsa::{RsaPrivateKey2048, rsa_pkcs1_v15_verify_2048_sha256};

// Import a key (runs pairwise consistency test on construction)
let key = RsaPrivateKey2048::from_components(&n_bytes, 65537, &d_bytes)?;

// Sign with PKCS#1 v1.5
let signature = key.sign_pkcs1_v15_sha256(b"message to sign")?;  // [u8; 256]

// Verify (standalone function, only needs public key)
let valid = rsa_pkcs1_v15_verify_2048_sha256(
    key.modulus_bytes(), key.public_exponent(), b"message to sign", &signature
);
```

### PSS signatures

```rust
use oxicrypt_rsa::RsaPrivateKey2048;

// Sign with PSS and DRBG-sampled salt
let signature = key.sign_pss_sha256(&mut drbg, b"message")?;
```

### Key generation

```rust
use oxicrypt_rsa::RsaPrivateKey2048;
use oxicrypt_drbg::HmacDrbgSha256;

let mut drbg = HmacDrbgSha256::new();
drbg.instantiate_no_df(&seed)?;
let key = RsaPrivateKey2048::generate(&mut drbg)?;
```

## ECDSA P-256

### Key generation and signing

```rust
use oxicrypt_ecdsa::EcdsaP256PrivateKey;
use oxicrypt_drbg::HmacDrbgSha256;

let mut drbg = HmacDrbgSha256::new();
drbg.instantiate_no_df(&seed)?;

// Generate a key (includes pairwise consistency test)
let key = EcdsaP256PrivateKey::generate(&mut drbg)?;

// Sign (DRBG-sampled k, rejection-sampled per FIPS 186-5 Section A.2.2)
let sig = key.sign_sha256(&mut drbg, b"message")?;  // [u8; 64] = r || s

// Get the public key for verification
let pk = key.public_key();  // [u8; 65] = 0x04 || X || Y
```

### Verification

```rust
use oxicrypt_ecdsa::verify;

let valid = verify(&public_key, b"message", &signature)?;
```

## Ed25519

```rust
use oxicrypt_eddsa::Ed25519PrivateKey;
use oxicrypt_drbg::HmacDrbgSha256;

let mut drbg = HmacDrbgSha256::new();
drbg.instantiate_no_df(&seed)?;

// Generate a key (includes pairwise consistency test)
let key = Ed25519PrivateKey::generate(&mut drbg)?;

// Sign (deterministic per RFC 8032 — no per-signature DRBG draw)
let sig = key.sign(b"message")?;  // [u8; 64]

// Verify
let pk = key.public_key();
let valid = oxicrypt_eddsa::verify(&pk, b"message", &sig)?;
```

## ECDH P-256

```rust
use oxicrypt_ecdh::compute_shared_secret_p256;

// Given our private scalar and the peer's public key (SEC1 uncompressed)
let shared_secret = compute_shared_secret_p256(&our_d, &peer_pk)?;  // [u8; 32]
```

The shared secret is the x-coordinate of the resulting point, suitable
for input to a KDF (SP 800-56Cr2 two-step or HKDF).

## Error handling

All approved-service functions return `Result<T, oxicrypt_module::Error>`.
The error type covers module-state violations, self-test failures, and
algorithm-specific invalid inputs:

```rust
match oxicrypt_sha::sha256(data) {
    Ok(digest) => { /* use digest */ }
    Err(oxicrypt_module::Error::NotOperational { current }) => {
        // Module not initialized or in error state
    }
    Err(e) => { /* other error */ }
}
```

Algorithm-specific crates may also return their own error types (e.g.,
`oxicrypt_aes::ModeError` for invalid IV lengths or tag mismatches,
`oxicrypt_drbg::DrbgError` for uninstantiated generators).

## FIPS mode gating

Every public function in the algorithm crates calls
`oxicrypt_module::require_operational()` before performing any
cryptographic operation. This means:

1. If you forget to initialize, you get a clear error on the first call.
2. If a power-up KAT fails, the module locks out all services.
3. There is no "non-FIPS" mode — the module is either operational or not.

Internal `*_internal()` variants exist for use during self-tests (where the
module is in `SelfTest` state and `require_operational()` would fail). These
are marked `#[doc(hidden)]` and are not part of the public API.
