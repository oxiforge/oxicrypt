/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * oxicrypt — pure-Rust FIPS 140-3 cryptographic module
 *
 * This header is GENERATED from the Rust source by cbindgen.
 * Do not edit by hand — edit the Rust signatures and rerun the build.
 *
 * The C ABI shim resides INSIDE the FIPS 140-3 module boundary.
 * See docs/security-policy/ for the formal CMVP Security Policy.
 *
 * Generated headers are committed under version control and verified
 * by CI to match cbindgen's deterministic output.
 */


#ifndef OXICRYPT_H
#define OXICRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 Initialise the FIPS module with the `Unrestricted` profile,
 running all power-up KATs.

 Equivalent to `oxicrypt_init_with_profile(0)`.

 Must be called exactly once before any other `oxicrypt_*`
 function. Returns `0` on success or a negative error code.

 # Safety

 No pointers; always safe to call.
 */
int32_t oxicrypt_init(void);

/*
 Initialise the FIPS module with the given algorithm profile,
 running all power-up KATs.

 `profile` selects the algorithm-restriction level:

 - `0` — Unrestricted (all approved algorithms available)
 - `1` — CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
   LMS, XMSS)
 - `2` — CNSA 1.0 (AES-256, SHA-256+, P-384, RSA ≥ 3072, DH ≥ 3072)

 Any other value is treated as `1` (CNSA 2.0) as a defence-in-depth
 default — the most restrictive standard profile.

 Returns `0` on success, or a negative error code.

 # Safety

 No pointers; always safe to call.
 */
int32_t oxicrypt_init_with_profile(int32_t profile);

/*
 Query the active algorithm profile.

 Returns:
 - `0` — Unrestricted
 - `1` — CNSA 2.0
 - `2` — CNSA 1.0

 # Safety

 No pointers; always safe to call.
 */
int32_t oxicrypt_active_profile(void);

/*
 Compute SHA-256 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 32 bytes.
 */
int32_t oxicrypt_sha256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-512 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 64 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 64 bytes.
 */
int32_t oxicrypt_sha512(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute HMAC-SHA-256 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int32_t oxicrypt_hmac_sha256(const uint8_t *key_ptr,
                             uintptr_t key_len,
                             const uint8_t *data_ptr,
                             uintptr_t data_len,
                             uint8_t *out);

/*
 Encrypt with AES-256-GCM (96-bit IV, 128-bit tag).

 `ct_out` must be at least `pt_len` bytes; `tag_out` at least 16.

 # Safety

 All pointer/length pairs must be valid.
 */
int32_t oxicrypt_aes256_gcm_encrypt(const uint8_t *key_ptr,
                                    const uint8_t *iv_ptr,
                                    const uint8_t *aad_ptr,
                                    uintptr_t aad_len,
                                    const uint8_t *pt_ptr,
                                    uintptr_t pt_len,
                                    uint8_t *ct_out,
                                    uint8_t *tag_out);

/*
 Decrypt with AES-256-GCM (96-bit IV, 128-bit tag).

 Returns `0` on success (tag valid) or `-3` on tag mismatch.
 `pt_out` must be at least `ct_len` bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int32_t oxicrypt_aes256_gcm_decrypt(const uint8_t *key_ptr,
                                    const uint8_t *iv_ptr,
                                    const uint8_t *aad_ptr,
                                    uintptr_t aad_len,
                                    const uint8_t *ct_ptr,
                                    uintptr_t ct_len,
                                    const uint8_t *tag_ptr,
                                    uint8_t *pt_out);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* OXICRYPT_H */
