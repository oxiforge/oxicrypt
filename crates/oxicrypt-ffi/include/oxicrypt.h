/* oxicrypt — C ABI for the oxicrypt FIPS 140-3 module.
 *
 * Link against liboxicrypt_ffi.a (static) or liboxicrypt_ffi.so/dylib
 * (shared), built by `cargo build -p oxicrypt-ffi --release`.
 *
 * Status codes:
 *   0  success
 *  -1  module not operational (call oxicrypt_init first)
 *  -2  invalid input (null pointer, wrong length, etc.)
 *  -3  cryptographic operation failed (e.g. GCM tag mismatch)
 */

#ifndef OXICRYPT_H
#define OXICRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Module lifecycle ────────────────────────────────────────── */

/* Initialise the FIPS module (runs all power-up KATs).
 * Must be called once before any crypto function. */
int32_t oxicrypt_init(void);

/* ── Hashing ─────────────────────────────────────────────────── */

/* SHA-256.  out must be >= 32 bytes. */
int32_t oxicrypt_sha256(const uint8_t *data, size_t data_len,
                        uint8_t *out);

/* SHA-512.  out must be >= 64 bytes. */
int32_t oxicrypt_sha512(const uint8_t *data, size_t data_len,
                        uint8_t *out);

/* ── MAC ─────────────────────────────────────────────────────── */

/* HMAC-SHA-256.  out must be >= 32 bytes. */
int32_t oxicrypt_hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *out);

/* ── AES-256-GCM ─────────────────────────────────────────────── */

/* Encrypt.  key=32B, iv=12B, ct_out>=pt_len, tag_out=16B. */
int32_t oxicrypt_aes256_gcm_encrypt(
    const uint8_t *key,          /* 32 bytes */
    const uint8_t *iv,           /* 12 bytes */
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt,  size_t pt_len,
    uint8_t *ct_out,             /* pt_len bytes */
    uint8_t *tag_out);           /* 16 bytes */

/* Decrypt.  Returns -3 on tag mismatch. */
int32_t oxicrypt_aes256_gcm_decrypt(
    const uint8_t *key,          /* 32 bytes */
    const uint8_t *iv,           /* 12 bytes */
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct,  size_t ct_len,
    const uint8_t *tag,          /* 16 bytes */
    uint8_t *pt_out);            /* ct_len bytes */

#ifdef __cplusplus
}
#endif

#endif /* OXICRYPT_H */
