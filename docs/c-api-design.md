# oxicrypt C API Design Document

**Status:** Design intent — not yet implemented. This document defines the
planned C ABI surface for oxicrypt. The implementation will follow after the
ACVP dry run validates the underlying Rust cryptographic core.

**Boundary note:** The C FFI shim resides *inside* the FIPS 140-3 module
boundary. It is thin glue that calls the same Rust functions exercised by
the ACVP harness. Language bindings built on top of this C API (Python,
Go, Node) reside *outside* the boundary.

## Design principles

1. **Flat C ABI.** No C++ name mangling, no templates, no exceptions.
   Every function is `extern "C"` with `#[no_mangle]`.

2. **Opaque handles.** Complex types (keys, DRBG state, hashers) are
   exposed as opaque pointers. The caller never sees the struct layout.
   This lets the Rust side evolve internals without breaking ABI.

3. **Explicit ownership.** Every `_new` / `_create` / `_generate` function
   has a corresponding `_free`. The caller owns the handle and must free it.

4. **Error codes, not exceptions.** Every function returns an `OxiResult`
   enum. On error, output parameters are untouched.

5. **No global state leaks.** Module initialization is explicit.
   The caller controls when KATs run.

6. **Buffer conventions.** Output buffers are caller-allocated with
   explicit length parameters. The API never allocates on behalf of
   the caller (no `malloc` inside the library).

## Header: `oxicrypt.h`

```c
#ifndef OXICRYPT_H
#define OXICRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ──────────────────────────────────────────────────── */

typedef enum {
    OXI_OK                    = 0,
    OXI_ERR_NOT_OPERATIONAL   = 1,
    OXI_ERR_SELF_TEST_FAILED  = 2,
    OXI_ERR_ALREADY_INIT      = 3,
    OXI_ERR_INVALID_INPUT     = 4,
    OXI_ERR_BUFFER_TOO_SMALL  = 5,
    OXI_ERR_TAG_MISMATCH      = 6,
    OXI_ERR_NOT_BLOCK_ALIGNED = 7,
    OXI_ERR_UNINSTANTIATED    = 8,
    OXI_ERR_RESEED_REQUIRED   = 9,
    OXI_ERR_PCT_FAILED        = 10,
    OXI_ERR_INTERNAL          = 255,
} OxiResult;

/* ── Module lifecycle ─────────────────────────────────────────────── */

/**
 * Initialize the module. Runs all power-up KATs and the software
 * integrity check. Must be called exactly once before any other
 * oxicrypt function.
 *
 * Returns OXI_OK on success, OXI_ERR_SELF_TEST_FAILED if any KAT
 * fails (module enters terminal error state), or
 * OXI_ERR_ALREADY_INIT if called more than once.
 */
OxiResult oxi_init(void);

/**
 * Query the module state.
 * Returns 1 if the module is operational, 0 otherwise.
 */
int oxi_is_operational(void);

/* ── Hashing ──────────────────────────────────────────────────────── */

/**
 * One-shot SHA-256.
 *
 * @param data      Input data.
 * @param data_len  Length of input data in bytes.
 * @param out       Output buffer, must be at least 32 bytes.
 * @return          OXI_OK or OXI_ERR_NOT_OPERATIONAL.
 */
OxiResult oxi_sha256(const uint8_t *data, size_t data_len,
                     uint8_t out[32]);

OxiResult oxi_sha384(const uint8_t *data, size_t data_len,
                     uint8_t out[48]);

OxiResult oxi_sha512(const uint8_t *data, size_t data_len,
                     uint8_t out[64]);

OxiResult oxi_sha3_256(const uint8_t *data, size_t data_len,
                       uint8_t out[32]);

/* Streaming hasher */
typedef struct OxiSha256Ctx OxiSha256Ctx;

OxiResult oxi_sha256_new(OxiSha256Ctx **ctx);
void      oxi_sha256_update(OxiSha256Ctx *ctx,
                            const uint8_t *data, size_t data_len);
OxiResult oxi_sha256_finalize(OxiSha256Ctx *ctx, uint8_t out[32]);
/* finalize consumes the context; do not call free after finalize */
void      oxi_sha256_free(OxiSha256Ctx *ctx);

/* ── HMAC ─────────────────────────────────────────────────────────── */

typedef struct OxiHmacSha256Ctx OxiHmacSha256Ctx;

/**
 * Create an HMAC-SHA-256 context.
 *
 * @param ctx       Receives the new context pointer.
 * @param key       HMAC key (any length).
 * @param key_len   Key length in bytes.
 * @return          OXI_OK or OXI_ERR_NOT_OPERATIONAL.
 */
OxiResult oxi_hmac_sha256_new(OxiHmacSha256Ctx **ctx,
                              const uint8_t *key, size_t key_len);

void      oxi_hmac_sha256_update(OxiHmacSha256Ctx *ctx,
                                 const uint8_t *data, size_t data_len);

OxiResult oxi_hmac_sha256_finalize(OxiHmacSha256Ctx *ctx,
                                   uint8_t out[32]);
/* finalize consumes the context */
void      oxi_hmac_sha256_free(OxiHmacSha256Ctx *ctx);

/* ── AES ──────────────────────────────────────────────────────────── */

typedef struct OxiAes128Key OxiAes128Key;
typedef struct OxiAes256Key OxiAes256Key;

OxiResult oxi_aes128_new(OxiAes128Key **key,
                         const uint8_t raw_key[16]);
OxiResult oxi_aes256_new(OxiAes256Key **key,
                         const uint8_t raw_key[32]);
void      oxi_aes128_free(OxiAes128Key *key);
void      oxi_aes256_free(OxiAes256Key *key);

/**
 * AES-256-GCM authenticated encryption.
 *
 * @param key        AES-256 key (from oxi_aes256_new).
 * @param iv         12-byte initialization vector (MUST be unique per key).
 * @param aad        Additional authenticated data (may be NULL if aad_len==0).
 * @param aad_len    Length of AAD in bytes.
 * @param plaintext  Input plaintext.
 * @param pt_len     Length of plaintext in bytes.
 * @param ciphertext Output buffer, must be at least pt_len bytes.
 * @param tag        Output buffer for 16-byte authentication tag.
 * @return           OXI_OK or error.
 */
OxiResult oxi_aes256_gcm_encrypt(const OxiAes256Key *key,
                                 const uint8_t iv[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *plaintext, size_t pt_len,
                                 uint8_t *ciphertext,
                                 uint8_t tag[16]);

/**
 * AES-256-GCM authenticated decryption.
 *
 * Returns OXI_ERR_TAG_MISMATCH if authentication fails.
 * On tag mismatch, the plaintext buffer contents are UNDEFINED —
 * the caller MUST NOT use them.
 */
OxiResult oxi_aes256_gcm_decrypt(const OxiAes256Key *key,
                                 const uint8_t iv[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ciphertext, size_t ct_len,
                                 uint8_t *plaintext,
                                 const uint8_t tag[16]);

OxiResult oxi_aes256_ctr(const OxiAes256Key *key,
                         const uint8_t icb[16],
                         const uint8_t *input, size_t len,
                         uint8_t *output);

/* ── DRBG ─────────────────────────────────────────────────────────── */

typedef struct OxiCtrDrbgAes256 OxiCtrDrbgAes256;

OxiResult oxi_ctr_drbg_aes256_new(OxiCtrDrbgAes256 **drbg);

OxiResult oxi_ctr_drbg_aes256_instantiate(
    OxiCtrDrbgAes256 *drbg,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t pers_len);

OxiResult oxi_ctr_drbg_aes256_generate(
    OxiCtrDrbgAes256 *drbg,
    uint8_t *output, size_t output_len,
    const uint8_t *additional, size_t additional_len);

OxiResult oxi_ctr_drbg_aes256_reseed(
    OxiCtrDrbgAes256 *drbg,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional, size_t additional_len);

void oxi_ctr_drbg_aes256_free(OxiCtrDrbgAes256 *drbg);

/* ── RSA-2048 ─────────────────────────────────────────────────────── */

typedef struct OxiRsa2048PrivateKey OxiRsa2048PrivateKey;

/**
 * Import an RSA-2048 private key.
 * Runs a pairwise consistency test on construction.
 *
 * @param key   Receives the new key handle.
 * @param n     256-byte modulus (big-endian).
 * @param e     Public exponent (typically 65537).
 * @param d     256-byte private exponent (big-endian).
 * @return      OXI_OK, OXI_ERR_PCT_FAILED, or OXI_ERR_NOT_OPERATIONAL.
 */
OxiResult oxi_rsa2048_from_components(
    OxiRsa2048PrivateKey **key,
    const uint8_t n[256], uint64_t e, const uint8_t d[256]);

OxiResult oxi_rsa2048_sign_pkcs1_sha256(
    const OxiRsa2048PrivateKey *key,
    const uint8_t *msg, size_t msg_len,
    uint8_t sig[256]);

/**
 * Verify RSA-2048 PKCS#1 v1.5 SHA-256 signature.
 *
 * @param n     256-byte modulus (big-endian).
 * @param e     Public exponent.
 * @param msg   Original message.
 * @param sig   256-byte signature.
 * @param valid Receives 1 if valid, 0 if invalid.
 * @return      OXI_OK or OXI_ERR_NOT_OPERATIONAL.
 */
OxiResult oxi_rsa2048_verify_pkcs1_sha256(
    const uint8_t n[256], uint64_t e,
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[256],
    int *valid);

void oxi_rsa2048_free(OxiRsa2048PrivateKey *key);

/* ── ECDSA P-256 ──────────────────────────────────────────────────── */

typedef struct OxiEcdsaP256Key OxiEcdsaP256Key;

/**
 * Generate an ECDSA P-256 key pair.
 *
 * @param key   Receives the new key handle.
 * @param drbg  Instantiated DRBG for randomness.
 * @return      OXI_OK, OXI_ERR_PCT_FAILED, or OXI_ERR_NOT_OPERATIONAL.
 */
OxiResult oxi_ecdsa_p256_generate(OxiEcdsaP256Key **key,
                                  OxiCtrDrbgAes256 *drbg);

OxiResult oxi_ecdsa_p256_sign_sha256(
    const OxiEcdsaP256Key *key,
    OxiCtrDrbgAes256 *drbg,
    const uint8_t *msg, size_t msg_len,
    uint8_t sig[64]);

/**
 * Get the public key from a key handle.
 *
 * @param key   Key handle.
 * @param pk    Output: 65-byte SEC1 uncompressed public key.
 */
OxiResult oxi_ecdsa_p256_public_key(const OxiEcdsaP256Key *key,
                                    uint8_t pk[65]);

/**
 * Verify an ECDSA P-256 SHA-256 signature.
 *
 * @param pk    65-byte SEC1 uncompressed public key.
 * @param msg   Message to verify.
 * @param sig   64-byte signature (r || s).
 * @param valid Receives 1 if valid, 0 if invalid.
 */
OxiResult oxi_ecdsa_p256_verify(
    const uint8_t pk[65],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[64],
    int *valid);

void oxi_ecdsa_p256_free(OxiEcdsaP256Key *key);

/* ── Ed25519 ──────────────────────────────────────────────────────── */

typedef struct OxiEd25519Key OxiEd25519Key;

OxiResult oxi_ed25519_generate(OxiEd25519Key **key,
                               OxiCtrDrbgAes256 *drbg);

OxiResult oxi_ed25519_sign(const OxiEd25519Key *key,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t sig[64]);

OxiResult oxi_ed25519_public_key(const OxiEd25519Key *key,
                                 uint8_t pk[32]);

OxiResult oxi_ed25519_verify(const uint8_t pk[32],
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t sig[64],
                             int *valid);

void oxi_ed25519_free(OxiEd25519Key *key);

/* ── ECDH P-256 ───────────────────────────────────────────────────── */

/**
 * Compute ECDH P-256 shared secret.
 *
 * @param d             32-byte private scalar (big-endian).
 * @param peer_pk       65-byte SEC1 uncompressed peer public key.
 * @param shared_secret Output: 32-byte x-coordinate. MUST be passed
 *                      through a KDF before use as keying material.
 */
OxiResult oxi_ecdh_p256(const uint8_t d[32],
                        const uint8_t peer_pk[65],
                        uint8_t shared_secret[32]);

/* ── Version ──────────────────────────────────────────────────────── */

/**
 * Returns a null-terminated version string, e.g. "0.1.0".
 * The returned pointer is valid for the lifetime of the process.
 */
const char *oxi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* OXICRYPT_H */
```

## Naming conventions

| Pattern | Meaning |
|---------|---------|
| `oxi_` | All public symbols are prefixed to avoid collisions. |
| `_new` / `_generate` | Allocates and returns a handle via double pointer. |
| `_free` | Deallocates a handle. Safe to call with NULL. |
| `_finalize` | Consumes the context (do not call `_free` after). |
| Output-last | Output parameters come after all input parameters. |
| `*valid` | Verification functions write 1/0 to an int pointer. |

## Memory model

- The library never calls `malloc` or `free`. All allocations use
  Rust's global allocator, exposed through opaque handles.
- Output buffers are always caller-allocated with known sizes.
- Handles must be freed with the corresponding `_free` function.
- After `_finalize`, the handle is consumed — calling `_free` on it
  is undefined behavior.
- Passing NULL to `_free` is a no-op (safe).

## Thread safety

- `oxi_init()` is not thread-safe. Call it once from the main thread.
- After initialization, all functions that take only `const` handles
  are thread-safe.
- Functions that take `*mut` handles (DRBG generate, hasher update)
  are not thread-safe on the same handle. Use one handle per thread.

## Implementation plan

1. Create `crates/oxicrypt-ffi/` as a `cdylib` + `staticlib` crate.
2. Implement the `extern "C"` functions as thin wrappers over the
   existing Rust API.
3. Generate `oxicrypt.h` from the Rust source via `cbindgen`.
4. Add C integration tests using a vendored test harness.
5. The FFI crate ships inside the FIPS boundary alongside the
   algorithm crates.

## What this document is NOT

This is a design document, not a commitment to API stability. The
function signatures may change during implementation. The intent is
to signal the API shape so that potential users and binding authors
can plan against it.
