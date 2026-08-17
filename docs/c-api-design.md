# oxicrypt C API Design Document

**Status:** Foundation implemented (2026-04-29). The C ABI shim is live in
`crates/oxicrypt-ffi/` with the design described below realised through
two staged PRs:

- **Phase 1** (PR #6, merged 2026-04-29) — build infrastructure (`cdylib` +
  `staticlib` targets, `cbindgen` build-dep, generated header committed),
  `OxiResult` discriminant-banded error enum with exhaustive
  `From<oxicrypt_module::Error>` and `From<oxicrypt_aes::ModeError>` mappings.
- **Phase 2** (PR #7, this chunk) — `OxiHandle<T>` consumed-sentinel for
  safe-no-op-after-finalize lifecycle, symbol rename `oxicrypt_*` → `oxi_*`,
  single-function `oxi_init(int profile)` (F3) with distinct
  `OxiResult::InvalidInput` for unknown profile codes (F4),
  `oxi_is_operational` state query, AES-256-GCM canonical exposure with
  opaque `OxiAes256Key` handle (F4 distinct `OxiResult::TagMismatch`,
  F5 NULL-safe `_free`, F9 NULL-AAD-with-len-0 allowed),
  `oxicrypt-integrity-sign` extended for multi-target signing (F8 per-binary
  integrity slots in cdylib + staticlib), C integration test harness
  (McGrew/Viega Case 15 + tag-tamper + handle lifecycle, 6 test runs
  spanning both link modes).

The implementation tracks the design below; deltas during implementation
are recorded inline in the Implementation Plan section.

**Boundary note:** The C FFI shim resides *outside* the FIPS 140-3 module
boundary, as does everything built on top of it. It is thin glue that calls
the same Rust functions exercised by the ACVP harness, which are the ones
inside the boundary. Security Policy §1 states the boundary membership;
`doc-guard` asserts the crate set against it.

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

1. ✅ **Complete** (PR #6) — `crates/oxicrypt-ffi/` builds as `cdylib` +
   `staticlib` (`rlib` deliberately omitted; the crate is FFI-only).
2. ✅ **Complete** (PR #7) — `extern "C"` functions implemented as thin
   wrappers over the Rust API: `oxi_init`, `oxi_active_profile`,
   `oxi_is_operational`, `oxi_sha256`, `oxi_sha512`, `oxi_hmac_sha256`,
   `oxi_aes256_new`, `oxi_aes256_free`, `oxi_aes256_gcm_encrypt`,
   `oxi_aes256_gcm_decrypt`. Streaming AES-GCM exposure deferred —
   the underlying `oxicrypt-aes` public API does not expose streaming
   GCM yet; exposing a caller-managed streaming surface ahead of the
   Rust API would invert the dependency direction.
3. ✅ **Complete** (PR #6) — `oxicrypt.h` is cbindgen-generated and
   committed under version control. Deterministic regeneration is
   verified by build (force-delete + rebuild yields empty diff).
4. ✅ **Complete** (PR #7) — C integration test harness lives at
   `crates/oxicrypt-ffi/tests/c-integration/`, with `make test-cdylib`
   and `make test-staticlib` independent targets. Tests cover the
   McGrew/Viega Case 15 vector (AES-256, no AAD), decrypt round-trip,
   tag tamper rejection (`OxiResult::TagMismatch=22`), and handle
   lifecycle (NULL-free safe no-op, NULL-arg rejection).
5. ✅ **Complete** (PR #6) — The FFI crate sits outside the FIPS
   boundary and translates for the in-boundary algorithm crates. Both
   the cdylib and staticlib outputs embed the integrity slot per F8.
   `oxicrypt-integrity-sign --cdylib-target …` signs the shared library; a
   consumer linking the static archive signs the binary they produce,
   since an archive is a build input with no loadable image to verify.

**Future work** (tracked separately):

- Streaming AES-GCM exposure once `oxicrypt-aes` adds streaming Rust API.
- SHA-3 / KMAC / SLH-DSA / ML-DSA / ML-KEM / ECDSA / ECDH / EdDSA / RSA
  / DRBG / KDF C ABI exposures (per-algorithm chunks, each adding
  `oxi_<alg>_*` symbols + handle types as needed).
- Runtime integrity verification of the cdylib slot under host-process
  loading. The current `integrity_self_test` resolves
  `env::current_exe()` which for a cdylib returns the host's path,
  not the .so's. A `dladdr`-based "find this .so's own path" helper
  is the proper fix; tracked in security policy §4.7.1.
- Language bindings (Python, Go, Java, Node, .NET) — separate
  adoption-accessories chunks, each consuming the C ABI.

## What this document is NOT

This is a design document, not a commitment to API stability. The
function signatures may change during implementation. The intent is
to signal the API shape so that potential users and binding authors
can plan against it.
