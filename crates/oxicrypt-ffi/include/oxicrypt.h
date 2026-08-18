/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/*
 * oxicrypt — pure-Rust cryptographic module targeting FIPS 140-3 Level 1
 *
 * This header is GENERATED from the Rust source by cbindgen.
 * Do not edit by hand — edit the Rust signatures and rerun the build.
 *
 * The C ABI shim resides OUTSIDE the FIPS 140-3 module boundary.
 * See docs/security-policy/ for the formal CMVP Security Policy.
 *
 * Generated headers are committed under version control and verified
 * by CI to match cbindgen's deterministic output.
 */


#ifndef OXICRYPT_H
#define OXICRYPT_H

#include <stddef.h>
#include <stdint.h>

/*
 Opaque AES-256 key handle. The internal layout
 (`OxiHandle<Aes256Key>`) is implementation detail and not part
 of the C ABI; cbindgen renders this as an opaque struct.

 */
typedef struct OxiAes256Key OxiAes256Key;

/*
 Opaque CTR_DRBG-AES-128 handle. See `OxiHmacDrbgSha256` for the
 per-call-mutating thread-safety and Drop-zeroize contract.

 */
typedef struct OxiCtrDrbgAes128 OxiCtrDrbgAes128;

/*
 Opaque CTR_DRBG-AES-192 handle. See `OxiCtrDrbgAes128`.

 */
typedef struct OxiCtrDrbgAes192 OxiCtrDrbgAes192;

/*
 Opaque CTR_DRBG-AES-256 handle. See `OxiCtrDrbgAes128`.

 */
typedef struct OxiCtrDrbgAes256 OxiCtrDrbgAes256;

/*
 Opaque ECDSA P-256 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time.

 The internal layout (`OxiHandle<EcdsaP256PrivateKey>`) is
 implementation detail and not part of the C ABI; cbindgen renders
 this as an opaque struct.

 */
typedef struct OxiEcdsaP256PrivateKey OxiEcdsaP256PrivateKey;

/*
 Opaque ECDSA P-384 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time.

 */
typedef struct OxiEcdsaP384PrivateKey OxiEcdsaP384PrivateKey;

/*
 Opaque Hash_DRBG-SHA-256 handle. See `OxiHmacDrbgSha256`.

 */
typedef struct OxiHashDrbgSha256 OxiHashDrbgSha256;

/*
 Opaque Hash_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.

 */
typedef struct OxiHashDrbgSha384 OxiHashDrbgSha384;

/*
 Opaque Hash_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.

 */
typedef struct OxiHashDrbgSha512 OxiHashDrbgSha512;

/*
 Opaque HMAC_DRBG-SHA-256 handle. The internal layout
 (`OxiHandle<HmacDrbgSha256>`) is implementation detail and not
 part of the C ABI; cbindgen renders this as an opaque struct.

 */
typedef struct OxiHmacDrbgSha256 OxiHmacDrbgSha256;

/*
 Opaque HMAC_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.

 */
typedef struct OxiHmacDrbgSha384 OxiHmacDrbgSha384;

/*
 Opaque HMAC_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.

 */
typedef struct OxiHmacDrbgSha512 OxiHmacDrbgSha512;

/*
 Opaque RSA-2048 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time. Mirrors the
 `OxiEcdsaP256PrivateKey` pattern and inherits the same PCT-at-
 construction structural argument from security-policy §4.8.

 */
typedef struct OxiRsaPrivateKey2048 OxiRsaPrivateKey2048;

/*
 Opaque RSA-3072 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time.

 */
typedef struct OxiRsaPrivateKey3072 OxiRsaPrivateKey3072;

/*
 Opaque RSA-4096 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time.

 */
typedef struct OxiRsaPrivateKey4096 OxiRsaPrivateKey4096;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 Return the LAMA API manifest as a NUL-terminated UTF-8 string with
 static lifetime.

 This is the shared-library half of LAMA discovery: an agent that has
 loaded the `.so` / `.dylib` / `.dll` resolves this symbol and reads the
 manifest describing every `oxi_*` entry point, rather than inferring
 the API from the header. The specification fixes both the name and the
 signature — `const char *lama_manifest(void)` — so this is the one
 exported symbol in this crate that does **not** carry the `oxi_`
 prefix: a name an agent has to guess would defeat the purpose.

 See <https://github.com/lamaspec/lama/blob/main/SPEC.md> §"Discovery".

 The returned pointer is valid for the lifetime of the loaded library
 and must not be freed. The manifest is metadata about the binary, not
 a service it provides, so this requires no initialisation and is
 callable before [`oxi_init`] and regardless of module state.

 # Safety

 No pointers in; always safe to call. The caller must treat the result
 as read-only and must not free it.
 */
const char *lama_manifest(void);

/*
 Initialise the FIPS module with the given algorithm profile,
 running all power-up KATs.

 `profile` selects the algorithm-restriction level:

 - `0` — Unrestricted (all approved algorithms available)
 - `1` — CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
   LMS, XMSS)
 - `2` — CNSA 1.0 (AES-256, SHA-384, P-384, RSA ≥ 3072, DH ≥ 3072)
 - `3` — Migration (both suites at once; not a CNSA profile)

 Any other value returns [`OxiResult::InvalidInput`] without
 performing initialisation. This is per F4 reviewer-framing —
 distinct error variants per failure mode rather than silently
 defaulting unknown codes to a profile.

 Idempotent: calling `oxi_init` more than once returns
 [`OxiResult::Ok`] on the second call. **The first init's outcome
 is authoritative** — both the success/failure state AND the
 active profile are determined by the first successful call. A
 second call passing a *different* profile selector is silently
 accepted and the *original* profile remains active. Callers that
 need to verify which profile is in effect must call
 [`oxi_active_profile`] after `oxi_init` returns.

 Must be called exactly once before any other `oxi_*` function.
 Returns `0` on success or a non-zero `OxiResult` discriminant.

 # Safety

 No pointers; always safe to call.
 */
int oxi_init(int profile);

/*
 Query the active algorithm profile.

 Returns:
 - `0` — Unrestricted
 - `1` — CNSA 2.0
 - `2` — CNSA 1.0
 - `3` — Migration (CNSA 1.0 + CNSA 2.0)

 # Safety

 No pointers; always safe to call.
 */
int oxi_active_profile(void);

/*
 Query whether the module is in the `Operational` state.

 Returns `1` if the module has completed power-up self-tests
 without failure and is currently servicing approved cryptographic
 requests, `0` otherwise (any other state: `PowerOff`, `SelfTest`,
 `Error`).

 This is a query, not a gate — operational-only entry points
 already gate themselves via `oxicrypt_module::require_operational`
 and return [`OxiResult::NotOperational`] when called outside the
 operational state. The query exists so C callers can present a
 clear "module ready" signal without needing to make a
 cryptographic call to discover the state.

 # Safety

 No pointers; always safe to call.
 */
int oxi_is_operational(void);

/*
 Returns the pre-operational integrity test's status indicator.

 | Value | Meaning |
 |---|---|
 | 0 | `NotRun` — the test has not run in this process |
 | 1 | `Passed` — the image matched its reference MAC |
 | 2 | `Mismatch` — the image does not match its reference MAC |
 | 3 | `SlotInvalid` — the slot is absent, malformed, or impossible |
 | 4 | `Unreadable` — the test was **not performed** |
 | 5 | `CastNotRun` — the test was reached before its CAST |
 | 6 | `Unknown` — the record held a value this module never writes |

 This exists because `oxi_init` cannot carry the distinction: a
 failing self-test returns [`OxiResult::SelfTestFailed`] whatever the
 cause, so `Mismatch` and `Unreadable` are indistinguishable from its
 return value alone. Security Policy §5.2 requires an operator and a
 test laboratory to be able to tell those two apart — a corrupt module
 from an environment that could not supply the module's own bytes —
 and this query is how that is retrieved.

 The value latches on the first run and nothing is re-run here, so a
 later call cannot revise it and this is safe to call from the error
 state. A value of 6 means the record held something this module never
 writes.

 # Safety

 No pointers; always safe to call.
 */
int oxi_integrity_status(void);

/*
 Compute SHA-256 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 32 bytes.
 */
int oxi_sha256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-512 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 64 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 64 bytes.
 */
int oxi_sha512(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-224 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 28 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 28 bytes.
 */
int oxi_sha224(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-384 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 48 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 48 bytes.
 */
int oxi_sha384(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-512/224 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 28 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 28 bytes.
 */
int oxi_sha512_224(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA-512/256 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 32 bytes.
 */
int oxi_sha512_256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA3-224 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 28 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 28 bytes.
 */
int oxi_sha3_224(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA3-256 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 32 bytes.
 */
int oxi_sha3_256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA3-384 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 48 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 48 bytes.
 */
int oxi_sha3_384(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute SHA3-512 over `data_len` bytes at `data_ptr`.

 `out` must point to a buffer of at least 64 bytes.

 # Safety

 Caller must ensure `data_ptr` is valid for `data_len` bytes
 and `out` is valid for 64 bytes.
 */
int oxi_sha3_512(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out);

/*
 Compute HMAC-SHA-256 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha256(const uint8_t *key_ptr,
                    uintptr_t key_len,
                    const uint8_t *data_ptr,
                    uintptr_t data_len,
                    uint8_t *out);

/*
 Compute HMAC-SHA-384 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 48 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha384(const uint8_t *key_ptr,
                    uintptr_t key_len,
                    const uint8_t *data_ptr,
                    uintptr_t data_len,
                    uint8_t *out);

/*
 Compute HMAC-SHA-512 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 64 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha512(const uint8_t *key_ptr,
                    uintptr_t key_len,
                    const uint8_t *data_ptr,
                    uintptr_t data_len,
                    uint8_t *out);

/*
 Compute HMAC-SHA3-224 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 28 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha3_224(const uint8_t *key_ptr,
                      uintptr_t key_len,
                      const uint8_t *data_ptr,
                      uintptr_t data_len,
                      uint8_t *out);

/*
 Compute HMAC-SHA3-256 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 32 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha3_256(const uint8_t *key_ptr,
                      uintptr_t key_len,
                      const uint8_t *data_ptr,
                      uintptr_t data_len,
                      uint8_t *out);

/*
 Compute HMAC-SHA3-384 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 48 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha3_384(const uint8_t *key_ptr,
                      uintptr_t key_len,
                      const uint8_t *data_ptr,
                      uintptr_t data_len,
                      uint8_t *out);

/*
 Compute HMAC-SHA3-512 over `data_len` bytes with the given key.

 `out` must point to a buffer of at least 64 bytes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_hmac_sha3_512(const uint8_t *key_ptr,
                      uintptr_t key_len,
                      const uint8_t *data_ptr,
                      uintptr_t data_len,
                      uint8_t *out);

/*
 Derive the uncompressed SEC1 public key for an ECDSA P-256 private
 scalar (FIPS 186-5 §6.2.1).

 `d_ptr` must point to exactly 32 bytes (the private scalar). On
 success, writes 65 bytes (`0x04 || X(32) || Y(32)`) into
 `public_key_out`.

 # Safety

 All pointer/length pairs must be valid. `public_key_out` must be a
 non-NULL writable pointer to ≥65 bytes.
 */
int oxi_ecdsa_p256_derive_public_key(const uint8_t *d_ptr, uint8_t *public_key_out);

/*
 Sign `msg` with ECDSA P-256 using a caller-supplied per-message
 secret `k` (FIPS 186-5 §6.4.1).

 `d_ptr` and `k_ptr` must each point to exactly 32 bytes; `k` must
 be uniformly random in `[1, n-1]` per FIPS 186-5 §A.2.2 — the FFI
 cannot enforce uniformity, only document the requirement. On
 success, writes 64 bytes (`r(32) || s(32)`) into `sig_out`.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥64 bytes.
 */
int oxi_ecdsa_p256_sign_with_k(const uint8_t *d_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *k_ptr,
                               uint8_t *sig_out);

/*
 Verify an ECDSA P-256 signature over `msg` against the public key
 `pk` (FIPS 186-5 §6.4.2).

 `public_key_ptr` must point to exactly 65 bytes (uncompressed SEC1)
 and `sig_ptr` to exactly 64 bytes (`r || s`).

 Returns `OxiResult::Ok = 0` for valid, `OxiResult::TagMismatch = 22`
 for well-formed-but-invalid (the upstream `Ok(false)`), or a module
 error variant on `Err`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ecdsa_p256_verify(const uint8_t *public_key_ptr,
                          const uint8_t *msg_ptr,
                          uintptr_t msg_len,
                          const uint8_t *sig_ptr);

/*
 Derive the uncompressed SEC1 public key for an ECDSA P-384 private
 scalar (FIPS 186-5 §6.2.1).

 `d_ptr` must point to exactly 48 bytes. On success, writes 97
 bytes (`0x04 || X(48) || Y(48)`) into `public_key_out`.

 # Safety

 All pointer/length pairs must be valid. `public_key_out` must be a
 non-NULL writable pointer to ≥97 bytes.
 */
int oxi_ecdsa_p384_derive_public_key(const uint8_t *d_ptr, uint8_t *public_key_out);

/*
 Sign `msg` with ECDSA P-384 using a caller-supplied per-message
 secret `k` (FIPS 186-5 §6.4.1).

 `d_ptr` and `k_ptr` must each point to exactly 48 bytes; `k` must
 be uniformly random in `[1, n-1]` per FIPS 186-5 §A.2.2. On
 success, writes 96 bytes (`r(48) || s(48)`) into `sig_out`.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥96 bytes.
 */
int oxi_ecdsa_p384_sign_with_k(const uint8_t *d_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *k_ptr,
                               uint8_t *sig_out);

/*
 Verify an ECDSA P-384 signature over `msg` against the public key
 `pk` (FIPS 186-5 §6.4.2).

 `public_key_ptr` must point to exactly 97 bytes (uncompressed SEC1)
 and `sig_ptr` to exactly 96 bytes (`r || s`).

 Returns `OxiResult::Ok = 0` for valid, `OxiResult::TagMismatch = 22`
 for well-formed-but-invalid, or a module error on `Err`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ecdsa_p384_verify(const uint8_t *public_key_ptr,
                          const uint8_t *msg_ptr,
                          uintptr_t msg_len,
                          const uint8_t *sig_ptr);

/*
 Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-256.

 Computes `PRK = HMAC-SHA-256(salt, IKM)` and writes the 32-byte
 PRK into `prk_out`. A NULL or zero-length salt is interpreted as
 32 zero bytes per RFC 5869 §2.2.

 `prk_out` must point to a buffer of at least 32 bytes.

 # Safety

 All pointer/length pairs must be valid. `prk_out` must be a
 non-NULL writable pointer to ≥32 bytes.
 */
int oxi_hkdf_sha256_extract(const uint8_t *salt_ptr,
                            uintptr_t salt_len,
                            const uint8_t *ikm_ptr,
                            uintptr_t ikm_len,
                            uint8_t *prk_out);

/*
 Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-256.

 Reconstructs HKDF state from a 32-byte PRK and fills `okm_out`
 with `okm_len` bytes of derived key material. Returns
 `OxiResult::OutputTooLong` when `okm_len > 255 * 32 = 8160`.

 `prk_ptr` must point to exactly 32 bytes.

 # Safety

 All pointer/length pairs must be valid. `okm_out` must be a
 writable pointer to at least `okm_len` bytes.
 */
int oxi_hkdf_sha256_expand(const uint8_t *prk_ptr,
                           const uint8_t *info_ptr,
                           uintptr_t info_len,
                           uint8_t *okm_out,
                           uintptr_t okm_len);

/*
 Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-384.

 Computes `PRK = HMAC-SHA-384(salt, IKM)` and writes the 48-byte
 PRK into `prk_out`. A NULL or zero-length salt is interpreted as
 48 zero bytes per RFC 5869 §2.2.

 `prk_out` must point to a buffer of at least 48 bytes.

 # Safety

 All pointer/length pairs must be valid. `prk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_hkdf_sha384_extract(const uint8_t *salt_ptr,
                            uintptr_t salt_len,
                            const uint8_t *ikm_ptr,
                            uintptr_t ikm_len,
                            uint8_t *prk_out);

/*
 Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-384.

 Reconstructs HKDF state from a 48-byte PRK and fills `okm_out`
 with `okm_len` bytes of derived key material. Returns
 `OxiResult::OutputTooLong` when `okm_len > 255 * 48 = 12240`.

 `prk_ptr` must point to exactly 48 bytes.

 # Safety

 All pointer/length pairs must be valid. `okm_out` must be a
 writable pointer to at least `okm_len` bytes.
 */
int oxi_hkdf_sha384_expand(const uint8_t *prk_ptr,
                           const uint8_t *info_ptr,
                           uintptr_t info_len,
                           uint8_t *okm_out,
                           uintptr_t okm_len);

/*
 Run HKDF-Extract per RFC 5869 §2.2 with HMAC-SHA-512.

 Computes `PRK = HMAC-SHA-512(salt, IKM)` and writes the 64-byte
 PRK into `prk_out`. A NULL or zero-length salt is interpreted as
 64 zero bytes per RFC 5869 §2.2.

 `prk_out` must point to a buffer of at least 64 bytes.

 # Safety

 All pointer/length pairs must be valid. `prk_out` must be a
 non-NULL writable pointer to ≥64 bytes.
 */
int oxi_hkdf_sha512_extract(const uint8_t *salt_ptr,
                            uintptr_t salt_len,
                            const uint8_t *ikm_ptr,
                            uintptr_t ikm_len,
                            uint8_t *prk_out);

/*
 Run HKDF-Expand per RFC 5869 §2.3 with HMAC-SHA-512.

 Reconstructs HKDF state from a 64-byte PRK and fills `okm_out`
 with `okm_len` bytes of derived key material. Returns
 `OxiResult::OutputTooLong` when `okm_len > 255 * 64 = 16320`.

 `prk_ptr` must point to exactly 64 bytes.

 # Safety

 All pointer/length pairs must be valid. `okm_out` must be a
 writable pointer to at least `okm_len` bytes.
 */
int oxi_hkdf_sha512_expand(const uint8_t *prk_ptr,
                           const uint8_t *info_ptr,
                           uintptr_t info_len,
                           uint8_t *okm_out,
                           uintptr_t okm_len);

/*
 Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-256.

 Builds the HkdfLabel wire structure
 `length || "tls13 " + label || context` and runs HKDF-Expand
 (RFC 5869 §2.3) to fill `out` with `out_len` bytes.

 # Safety

 All pointer/length pairs must be valid. `out` must be a writable
 pointer to at least `out_len` bytes.
 */
int oxi_tls13_hkdf_expand_label_sha256(const uint8_t *secret_ptr,
                                       uintptr_t secret_len,
                                       const uint8_t *label_ptr,
                                       uintptr_t label_len,
                                       const uint8_t *context_ptr,
                                       uintptr_t context_len,
                                       uint8_t *out,
                                       uintptr_t out_len);

/*
 Run HKDF-Expand-Label per RFC 8446 §7.1 with HMAC-SHA-384.

 Builds the HkdfLabel wire structure
 `length || "tls13 " + label || context` and runs HKDF-Expand
 (RFC 5869 §2.3) to fill `out` with `out_len` bytes.

 # Safety

 All pointer/length pairs must be valid. `out` must be a writable
 pointer to at least `out_len` bytes.
 */
int oxi_tls13_hkdf_expand_label_sha384(const uint8_t *secret_ptr,
                                       uintptr_t secret_len,
                                       const uint8_t *label_ptr,
                                       uintptr_t label_len,
                                       const uint8_t *context_ptr,
                                       uintptr_t context_len,
                                       uint8_t *out,
                                       uintptr_t out_len);

/*
 Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-256.

 Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
 out_len)`. The caller computes `Hash(messages)` (the running
 transcript hash) and passes it as `transcript_hash`.

 # Safety

 All pointer/length pairs must be valid. `out` must be a writable
 pointer to at least `out_len` bytes.
 */
int oxi_tls13_derive_secret_sha256(const uint8_t *secret_ptr,
                                   uintptr_t secret_len,
                                   const uint8_t *label_ptr,
                                   uintptr_t label_len,
                                   const uint8_t *transcript_hash_ptr,
                                   uintptr_t transcript_hash_len,
                                   uint8_t *out,
                                   uintptr_t out_len);

/*
 Run Derive-Secret per RFC 8446 §7.1 with HMAC-SHA-384.

 Equivalent to `HKDF-Expand-Label(secret, label, transcript_hash,
 out_len)`. The caller computes `Hash(messages)` (the running
 transcript hash) and passes it as `transcript_hash`.

 # Safety

 All pointer/length pairs must be valid. `out` must be a writable
 pointer to at least `out_len` bytes.
 */
int oxi_tls13_derive_secret_sha384(const uint8_t *secret_ptr,
                                   uintptr_t secret_len,
                                   const uint8_t *label_ptr,
                                   uintptr_t label_len,
                                   const uint8_t *transcript_hash_ptr,
                                   uintptr_t transcript_hash_len,
                                   uint8_t *out,
                                   uintptr_t out_len);

/*
 Derive the Ed25519 public key from a 32-byte seed (RFC 8032 §5.1.5).

 Reads exactly 32 bytes from `seed_ptr`. Writes the 32-byte
 compressed-Edwards-point public key into `public_key_out`. This
 operation is **deterministic**: given the same seed, the same
 public key. Distinct from ECDSA's DRBG-sampled key generation —
 the `Service::Ed25519Keygen` gate fires for profile-restriction
 purposes, NOT because randomness is consumed.

 # Safety

 All pointer/length pairs must be valid. `public_key_out` must be a
 non-NULL writable pointer to ≥32 bytes.
 */
int oxi_ed25519_keygen(const uint8_t *seed_ptr, uint8_t *public_key_out);

/*
 Sign `msg` with Ed25519 using the 32-byte seed (RFC 8032 §5.1.6).

 Reads exactly 32 bytes from `seed_ptr`. Writes 64 bytes
 (`R(32) || S(32)`) into `sig_out`. Signing is **deterministic** —
 the per-message nonce is derived via HMAC-SHA512 over a prefix of
 the secret and the message, so signatures are bit-identical for
 the same `(seed, msg)` pair. There is NO `sign_with_k` variant
 because RFC 8032 supplies the `k` internally.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥64 bytes.
 */
int oxi_ed25519_sign(const uint8_t *seed_ptr,
                     const uint8_t *msg_ptr,
                     uintptr_t msg_len,
                     uint8_t *sig_out);

/*
 Verify an Ed25519 signature over `msg` (RFC 8032 §5.1.7).

 Reads exactly 32 bytes from `public_key_ptr` and exactly 64 bytes
 from `sig_ptr`. Returns `OxiResult::Ok = 0` for valid,
 `OxiResult::TagMismatch = 22` for well-formed-but-invalid (the
 upstream `Ok(false)` — same cross-family verify-mismatch code as
 AEAD AES-GCM/CCM/KW/KWP and ECDSA verify), or a module error
 variant on `Err`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ed25519_verify(const uint8_t *public_key_ptr,
                       const uint8_t *msg_ptr,
                       uintptr_t msg_len,
                       const uint8_t *sig_ptr);

/*
 Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH shared secret for
 P-256: `Z = x(d * Q)`.

 Reads exactly 32 bytes from `d_ptr` (the caller's private scalar)
 and exactly 65 bytes from `peer_public_key_ptr` (the peer's
 uncompressed SEC1 public key, `0x04 || X(32) || Y(32)`). Writes
 32 bytes (the raw big-endian x-coordinate of `d * Q`) into
 `shared_secret_out`. The shared secret is the **raw** ECDH output
 per SP 800-56Ar3; the caller MUST run an SP 800-56C Rev. 2
 extractor (HKDF, KBKDF) over `Z` before using it as keying
 material.

 Peer public key undergoes full SP 800-56Ar3 §5.6.2.3.3 validation
 (canonical encoding, coordinate canonicality, non-identity,
 on-curve) before any scalar multiplication; a peer key failing
 any check causes the call to return `OxiResult::InvalidInput = 5`
 without performing the scalar-mul.

 # Safety

 All pointer/length pairs must be valid. `shared_secret_out` must
 be a non-NULL writable pointer to ≥32 bytes.
 */
int oxi_ecdh_p256_compute_shared_secret(const uint8_t *d_ptr,
                                        const uint8_t *peer_public_key_ptr,
                                        uint8_t *shared_secret_out);

/*
 Compute the SP 800-56Ar3 §5.7.1.2 ECC CDH shared secret for
 P-384: `Z = x(d * Q)`.

 Reads exactly 48 bytes from `d_ptr` and exactly 97 bytes from
 `peer_public_key_ptr` (uncompressed SEC1, `0x04 || X(48) || Y(48)`).
 Writes 48 bytes (raw big-endian x-coordinate) into
 `shared_secret_out`. The shared secret is the raw ECDH output;
 the caller MUST run an SP 800-56C Rev. 2 extractor before use as
 keying material.

 Peer public key undergoes full SP 800-56Ar3 §5.6.2.3.3 validation
 before scalar multiplication.

 # Safety

 All pointer/length pairs must be valid. `shared_secret_out` must
 be a non-NULL writable pointer to ≥48 bytes.
 */
int oxi_ecdh_p384_compute_shared_secret(const uint8_t *d_ptr,
                                        const uint8_t *peer_public_key_ptr,
                                        uint8_t *shared_secret_out);

/*
 Generate a fresh ECDH P-256 key pair via the FIPS 186-5 §A.2.2
 rejection sampler driven by `drbg`, run the IG 10.3.A pairwise
 consistency test, and write the private/public key bytes to the
 caller-provided buffers.

 On success, writes 32 bytes (the private scalar `d` in canonical
 big-endian encoding, in `[1, n − 1]`) into `private_out` and
 65 bytes (the SEC1 uncompressed public key `0x04 || X(32) || Y(32)`
 of `Q = d · G`) into `public_out`. The IG 10.3.A PCT runs as an
 ECDH roundtrip against the RFC 5903 §8.1 responder keypair: a
 faulted scalar-mul during keygen produces a `Q` that fails the
 roundtrip equality and the call returns
 `OxiResult::InvalidInput = 5` without writing the buffers.

 Applies the per-call-mutating-handle thread-safety contract:
 callers MUST serialise concurrent calls on the same `drbg`
 pointer (the FFI projects `*mut OxiHmacDrbgSha256` to
 `&mut HmacDrbgSha256` for the duration of this call, which
 Rust's exclusivity rule enforces internally but cannot enforce
 across the C boundary). See the per-call-mutating-handle
 paragraph in `docs/security-policy/security-policy.md` §4.8.

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::NullPointer = 10` if any pointer is NULL;
 `OxiResult::NotOperational = 1` if the FIPS module is not in
 the `Operational` state OR the DRBG handle has been finalised;
 `OxiResult::AlgorithmRestricted = 6` if the active profile does
 not allow ECDH-P-256;
 `OxiResult::InvalidInput = 5` if the DRBG faults during sampling,
 rejection-sampling exhausts without an in-range scalar (in
 practice only a broken DRBG), or the IG 10.3.A PCT mismatches.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate`]. `private_out` must be a
 non-NULL writable pointer to ≥32 bytes. `public_out` must be a
 non-NULL writable pointer to ≥65 bytes. The caller MUST
 serialise concurrent calls on the same `drbg` pointer.
 */
int oxi_ecdh_p256_generate_keypair(OxiHmacDrbgSha256 *drbg,
                                   uint8_t *private_out,
                                   uint8_t *public_out);

/*
 Generate a fresh ECDH P-384 key pair via the FIPS 186-5 §A.2.2
 rejection sampler driven by `drbg`, run the IG 10.3.A pairwise
 consistency test, and write the private/public key bytes to the
 caller-provided buffers.

 Mirrors [`oxi_ecdh_p256_generate_keypair`] for the P-384 curve:
 48-byte private scalar, 97-byte SEC1 uncompressed public key,
 RFC 5903 §8.2 responder keypair drives the IG 10.3.A PCT.
 Same error mapping and thread-safety contract.

 # Safety

 `drbg` must be a live, instantiated handle. `private_out` must be
 a non-NULL writable pointer to ≥48 bytes. `public_out` must be a
 non-NULL writable pointer to ≥97 bytes. Callers MUST serialise
 concurrent calls on the same `drbg` pointer.
 */
int oxi_ecdh_p384_generate_keypair(OxiHmacDrbgSha256 *drbg,
                                   uint8_t *private_out,
                                   uint8_t *public_out);

/*
 Compute the SP 800-56Ar3 §5.7.1.1 finite-field DH shared secret
 over RFC 3526 Group 15 (3072-bit safe prime): `Z = y^x mod p`.

 Reads exactly 384 bytes from `x_ptr` (the caller's private key,
 big-endian, in `[1, q − 1]` where `q = (p − 1) / 2`) and exactly
 384 bytes from `peer_public_key_ptr` (the peer's public key, big-
 endian, in `[2, p − 2]`). Writes 384 bytes (the raw shared
 secret `Z`) into `shared_secret_out`.

 The shared secret is the **raw** FFC-DH output; the caller MUST
 run an SP 800-56C Rev. 2 extractor over `Z` before using it as
 keying material — same discipline as ECDH (see security-policy
 §4.8 ECDH raw-Z paragraph).

 Peer public key undergoes SP 800-56Ar3 §5.6.2.3.1 partial
 validation (`2 ≤ y ≤ p − 2`) before any modular exponentiation;
 a peer key failing the bound check causes the call to return
 `OxiResult::InvalidInput = 5` without performing the exponent.
 The post-exponent `Z != 1` check guards against the degenerate
 SP 800-56Ar3 §5.7.1.1 "shall fail" outcome.

 # Safety

 All pointer/length pairs must be valid. `shared_secret_out` must
 be a non-NULL writable pointer to ≥384 bytes.
 */
int oxi_dh3072_compute_shared_secret(const uint8_t *x_ptr,
                                     const uint8_t *peer_public_key_ptr,
                                     uint8_t *shared_secret_out);

/*
 Generate a DH-3072 key pair `(private_key, public_key)` from the
 caller-supplied DRBG handle (RFC 3526 Group 15, SP 800-56Ar3
 §5.7.1.1).

 The private key `x` is sampled from `[1, q − 1]` via HMAC-DRBG-
 SHA-256 rejection sampling. The public key is `y = 2^x mod p`. On
 success, writes the 384-byte big-endian `x` into `private_out` and
 the 384-byte big-endian `y` into `public_out`. The DRBG handle is
 advanced (its `(K, V, reseed_counter)` state mutates) by the
 rejection-sampling loop.

 **First C ABI surface to consume an opaque DRBG handle.** The
 caller is responsible for: (a) allocating the handle via
 [`oxi_hmac_drbg_sha256_new`]; (b) instantiating it via
 [`oxi_hmac_drbg_sha256_instantiate`] with caller-sourced entropy
 before this call; (c) freeing it via [`oxi_hmac_drbg_sha256_free`]
 after use; and (d) serializing all calls on the same handle
 pointer per the per-call-mutating-handle thread-safety contract.

 Returns `OxiResult::Ok = 0` on success; `OxiResult::InvalidInput
 = 5` if the DRBG is uninstantiated, exhausts its rejection-
 sampling attempts, or fails to produce output (the upstream
 `Option` is collapsed to `Err(InvalidInput)` by the gated public
 API); `OxiResult::NotOperational = 1` if the FIPS module is not
 operational; or `OxiResult::AlgorithmRestricted = 6` if the
 active profile blocks DH-3072.

 # Safety

 `drbg` must be a live handle from [`oxi_hmac_drbg_sha256_new`]
 that has been instantiated. `private_out` must be a non-NULL
 writable pointer to ≥384 bytes. `public_out` must be a non-NULL
 writable pointer to ≥384 bytes.
 */
int oxi_dh3072_generate_keypair(OxiHmacDrbgSha256 *drbg, uint8_t *private_out, uint8_t *public_out);

/*
 Verify an RSASSA-PKCS#1-v1.5 signature with a 2048-bit RSA public
 key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).

 Reads exactly 256 bytes from `n_ptr` (modulus, big-endian), takes
 the public exponent `e` as a `uint64_t`, reads `msg_len` bytes
 from `msg_ptr`, and reads exactly 256 bytes from `sig_ptr`.

 Returns `OxiResult::Ok = 0` on a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (invalid modulus, malformed signature, digest mismatch — upstream
 collapses these into a single Err), or a module error variant on
 `NotOperational` / `AlgorithmRestricted`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pkcs1_v15_verify_2048_sha256(const uint8_t *n_ptr,
                                         uint64_t e,
                                         const uint8_t *msg_ptr,
                                         uintptr_t msg_len,
                                         const uint8_t *sig_ptr);

/*
 Verify an RSASSA-PSS signature with a 2048-bit RSA public key,
 SHA-256 as both message hash and MGF1 hash, salt length 32 bytes
 (FIPS 186-5 §5.4 / RFC 8017 §8.1).

 Reads exactly 256 bytes from `n_ptr`, takes `e` as `uint64_t`,
 reads `msg_len` bytes from `msg_ptr`, and reads exactly 256 bytes
 from `sig_ptr`. Returns `Ok = 0` on a valid signature,
 `TagMismatch = 22` on any verification failure (see TagMismatch
 paragraph in security-policy §4.8 for upstream-Err mapping
 rationale), or a module error variant.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pss_verify_2048_sha256(const uint8_t *n_ptr,
                                   uint64_t e,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Verify an RSASSA-PKCS#1-v1.5 signature with a 3072-bit RSA public
 key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).

 Reads exactly 384 bytes from `n_ptr` and 384 bytes from `sig_ptr`.
 See the `oxi_rsa_pkcs1_v15_verify_2048_sha256` rustdoc for return
 semantics — identical except for byte sizes.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pkcs1_v15_verify_3072_sha256(const uint8_t *n_ptr,
                                         uint64_t e,
                                         const uint8_t *msg_ptr,
                                         uintptr_t msg_len,
                                         const uint8_t *sig_ptr);

/*
 Verify an RSASSA-PSS signature with a 3072-bit RSA public key,
 SHA-256 as both message hash and MGF1 hash (FIPS 186-5 §5.4 /
 RFC 8017 §8.1).

 Reads exactly 384 bytes from `n_ptr` and 384 bytes from `sig_ptr`.
 PSS parameters per `oxicrypt_rsa::rsa3072` rustdoc:
 `emBits = 3071`, `emLen = 384`, `sLen = hLen = 32`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pss_verify_3072_sha256(const uint8_t *n_ptr,
                                   uint64_t e,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Verify an RSASSA-PKCS#1-v1.5 signature with a 4096-bit RSA public
 key, SHA-256 hash (FIPS 186-5 §5.4 / RFC 8017 §8.2).

 Reads exactly 512 bytes from `n_ptr` and 512 bytes from `sig_ptr`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pkcs1_v15_verify_4096_sha256(const uint8_t *n_ptr,
                                         uint64_t e,
                                         const uint8_t *msg_ptr,
                                         uintptr_t msg_len,
                                         const uint8_t *sig_ptr);

/*
 Verify an RSASSA-PSS signature with a 4096-bit RSA public key,
 SHA-256 as both message hash and MGF1 hash (FIPS 186-5 §5.4 /
 RFC 8017 §8.1).

 Reads exactly 512 bytes from `n_ptr` and 512 bytes from `sig_ptr`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_rsa_pss_verify_4096_sha256(const uint8_t *n_ptr,
                                   uint64_t e,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an ML-DSA-87 key pair from a 32-byte seed (FIPS 204 §6.1).

 Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
 `xi`). Writes the 2592-byte public key into `pk_out` and the
 4896-byte secret key into `sk_out`. The caller is responsible for
 sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
 performs no entropy generation.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `pk_out` and `sk_out` must
 each be non-NULL writable pointers to ≥2592 and ≥4896 bytes
 respectively.
 */
int oxi_ml_dsa_87_keygen(const uint8_t *seed_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with ML-DSA-87 (FIPS 204 §5.2 Algorithm 2).

 Reads exactly 4896 bytes from `sk_ptr`, `msg_len` bytes from
 `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
 4627-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
 `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.

 Signing is deterministic: bit-identical signature across calls
 for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
 is exposed.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
 `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
 after the upstream bound, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥4627 bytes.
 */
int oxi_ml_dsa_87_sign(const uint8_t *sk_ptr,
                       const uint8_t *msg_ptr,
                       uintptr_t msg_len,
                       const uint8_t *ctx_ptr,
                       uintptr_t ctx_len,
                       uint8_t *sig_out);

/*
 Verify an ML-DSA-87 signature (FIPS 204 §5.2 Algorithm 3).

 Reads exactly 2592 bytes from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 4627 bytes from
 `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
 X.509 / CMS / LAMPS.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (decode-fail OR signature-invalid — upstream collapses these into
 a single `Err(InvalidInput)`; same shape as RSA verify), or a
 module error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ml_dsa_87_verify(const uint8_t *pk_ptr,
                         const uint8_t *msg_ptr,
                         uintptr_t msg_len,
                         const uint8_t *ctx_ptr,
                         uintptr_t ctx_len,
                         const uint8_t *sig_ptr);

/*
 Generate an ML-DSA-44 key pair from a 32-byte seed (FIPS 204 §6.1).

 Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
 `xi`). Writes the 1312-byte public key into `pk_out` and the
 2560-byte secret key into `sk_out`. The caller is responsible for
 sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
 performs no entropy generation.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `pk_out` and `sk_out` must
 each be non-NULL writable pointers to ≥1312 and ≥2560 bytes
 respectively.
 */
int oxi_ml_dsa_44_keygen(const uint8_t *seed_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with ML-DSA-44 (FIPS 204 §5.2 Algorithm 2).

 Reads exactly 2560 bytes from `sk_ptr`, `msg_len` bytes from
 `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
 2420-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
 `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.

 Signing is deterministic: bit-identical signature across calls
 for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
 is exposed.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
 `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
 after the upstream bound, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥2420 bytes.
 */
int oxi_ml_dsa_44_sign(const uint8_t *sk_ptr,
                       const uint8_t *msg_ptr,
                       uintptr_t msg_len,
                       const uint8_t *ctx_ptr,
                       uintptr_t ctx_len,
                       uint8_t *sig_out);

/*
 Verify an ML-DSA-44 signature (FIPS 204 §5.2 Algorithm 3).

 Reads exactly 1312 bytes from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 2420 bytes from
 `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
 X.509 / CMS / LAMPS.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (decode-fail OR signature-invalid — upstream collapses these into
 a single `Err(InvalidInput)`; same shape as RSA verify), or a
 module error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ml_dsa_44_verify(const uint8_t *pk_ptr,
                         const uint8_t *msg_ptr,
                         uintptr_t msg_len,
                         const uint8_t *ctx_ptr,
                         uintptr_t ctx_len,
                         const uint8_t *sig_ptr);

/*
 Generate an ML-DSA-65 key pair from a 32-byte seed (FIPS 204 §6.1).

 Reads exactly 32 bytes from `seed_ptr` (the keygen randomness
 `xi`). Writes the 1952-byte public key into `pk_out` and the
 4032-byte secret key into `sk_out`. The caller is responsible for
 sourcing `seed_ptr` from an approved DRBG (SP 800-90A); the FFI
 performs no entropy generation.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `pk_out` and `sk_out` must
 each be non-NULL writable pointers to ≥1952 and ≥4032 bytes
 respectively.
 */
int oxi_ml_dsa_65_keygen(const uint8_t *seed_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with ML-DSA-65 (FIPS 204 §5.2 Algorithm 2).

 Reads exactly 4032 bytes from `sk_ptr`, `msg_len` bytes from
 `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
 3309-byte signature into `sig_out`. Pass `ctx_len = 0` (with any
 `ctx_ptr`) for the empty context used by X.509 / CMS / LAMPS.

 Signing is deterministic: bit-identical signature across calls
 for the same `(sk, msg, ctx)` triple. NO randomized-mode variant
 is exposed.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
 `ctx_len > 255` (FIPS 204 §5.2 limit) or rejection sampling fails
 after the upstream bound, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥3309 bytes.
 */
int oxi_ml_dsa_65_sign(const uint8_t *sk_ptr,
                       const uint8_t *msg_ptr,
                       uintptr_t msg_len,
                       const uint8_t *ctx_ptr,
                       uintptr_t ctx_len,
                       uint8_t *sig_out);

/*
 Verify an ML-DSA-65 signature (FIPS 204 §5.2 Algorithm 3).

 Reads exactly 1952 bytes from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 3309 bytes from
 `sig_ptr`. Pass `ctx_len = 0` for the empty context used by
 X.509 / CMS / LAMPS.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (decode-fail OR signature-invalid — upstream collapses these into
 a single `Err(InvalidInput)`; same shape as RSA verify), or a
 module error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_ml_dsa_65_verify(const uint8_t *pk_ptr,
                         const uint8_t *msg_ptr,
                         uintptr_t msg_len,
                         const uint8_t *ctx_ptr,
                         uintptr_t ctx_len,
                         const uint8_t *sig_ptr);

/*
 Generate an ML-KEM-1024 key pair from two 32-byte caller-supplied
 seeds (FIPS 203 §6.1 ML-KEM.KeyGen).

 Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
 exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
 the 1568-byte encapsulation key into `ek_out` and the 3168-byte
 decapsulation key into `dk_out`. Both seeds are caller-supplied;
 the caller MUST source each independently from an approved DRBG
 (SP 800-90A). `d` and `z` are NOT interchangeable — see the
 section comment above for the semantic distinction.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
 rare K-PKE NTT decode failure occurs during keygen, or a module
 error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ek_out` and `dk_out`
 must each be non-NULL writable pointers to ≥1568 and ≥3168 bytes
 respectively.
 */
int oxi_ml_kem_1024_keygen(const uint8_t *d_ptr,
                           const uint8_t *z_ptr,
                           uint8_t *ek_out,
                           uint8_t *dk_out);

/*
 Encapsulate a shared secret against an ML-KEM-1024 encapsulation
 key (FIPS 203 §6.2 ML-KEM.Encaps).

 Reads exactly 1568 bytes from `ek_ptr` and exactly 32 bytes from
 `m_ptr` (encapsulation randomness, caller-supplied from an
 SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
 and the 1568-byte ciphertext into `ct_out`.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` and `ct_out`
 must each be non-NULL writable pointers to ≥32 and ≥1568 bytes
 respectively.
 */
int oxi_ml_kem_1024_encapsulate(const uint8_t *ek_ptr,
                                const uint8_t *m_ptr,
                                uint8_t *ss_out,
                                uint8_t *ct_out);

/*
 Decapsulate a shared secret from an ML-KEM-1024 ciphertext
 (FIPS 203 §6.3 ML-KEM.Decaps).

 Reads exactly 3168 bytes from `dk_ptr` and exactly 1568 bytes
 from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
 **Fully deterministic** — no caller randomness, no `Ok(false)`
 shape, no `TagMismatch = 22` mapping. The FO transform's
 implicit-rejection branch absorbs tampered ciphertext into a
 deterministic-but-pseudorandom shared secret in constant time;
 tamper does NOT surface as a discriminant. See the
 decapsulate-implicit-rejection paragraph in security-policy §4.9.

 Returns `OxiResult::Ok = 0` on success, or a module error
 variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` must be a
 non-NULL writable pointer to ≥32 bytes.
 */
int oxi_ml_kem_1024_decapsulate(const uint8_t *dk_ptr, const uint8_t *ct_ptr, uint8_t *ss_out);

/*
 Generate an ML-KEM-512 key pair from two 32-byte caller-supplied
 seeds (FIPS 203 §6.1 ML-KEM.KeyGen, k=2 parameter set).

 Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
 exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
 the 800-byte encapsulation key into `ek_out` and the 1632-byte
 decapsulation key into `dk_out`. Both seeds are caller-supplied;
 the caller MUST source each independently from an approved DRBG
 (SP 800-90A). `d` and `z` are NOT interchangeable — see the
 ML-KEM-1024 section comment above for the semantic distinction
 (identical across all three parameter sets).

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
 rare K-PKE NTT decode failure occurs during keygen, or a module
 error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ek_out` and `dk_out`
 must each be non-NULL writable pointers to ≥800 and ≥1632 bytes
 respectively.
 */
int oxi_ml_kem_512_keygen(const uint8_t *d_ptr,
                          const uint8_t *z_ptr,
                          uint8_t *ek_out,
                          uint8_t *dk_out);

/*
 Encapsulate a shared secret against an ML-KEM-512 encapsulation
 key (FIPS 203 §6.2 ML-KEM.Encaps, k=2 parameter set).

 Reads exactly 800 bytes from `ek_ptr` and exactly 32 bytes from
 `m_ptr` (encapsulation randomness, caller-supplied from an
 SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
 and the 768-byte ciphertext into `ct_out`.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` and `ct_out`
 must each be non-NULL writable pointers to ≥32 and ≥768 bytes
 respectively.
 */
int oxi_ml_kem_512_encapsulate(const uint8_t *ek_ptr,
                               const uint8_t *m_ptr,
                               uint8_t *ss_out,
                               uint8_t *ct_out);

/*
 Decapsulate a shared secret from an ML-KEM-512 ciphertext
 (FIPS 203 §6.3 ML-KEM.Decaps, k=2 parameter set).

 Reads exactly 1632 bytes from `dk_ptr` and exactly 768 bytes
 from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
 **Fully deterministic** — no caller randomness, no `Ok(false)`
 shape, no `TagMismatch = 22` mapping. The FO transform's
 implicit-rejection branch absorbs tampered ciphertext into a
 deterministic-but-pseudorandom shared secret in constant time;
 tamper does NOT surface as a discriminant. See the
 decapsulate-implicit-rejection paragraph in security-policy §4.9.

 Returns `OxiResult::Ok = 0` on success, or a module error
 variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` must be a
 non-NULL writable pointer to ≥32 bytes.
 */
int oxi_ml_kem_512_decapsulate(const uint8_t *dk_ptr, const uint8_t *ct_ptr, uint8_t *ss_out);

/*
 Generate an ML-KEM-768 key pair from two 32-byte caller-supplied
 seeds (FIPS 203 §6.1 ML-KEM.KeyGen, k=3 parameter set).

 Reads exactly 32 bytes from `d_ptr` (K-PKE keygen randomness) and
 exactly 32 bytes from `z_ptr` (implicit-rejection seed). Writes
 the 1184-byte encapsulation key into `ek_out` and the 2400-byte
 decapsulation key into `dk_out`. Both seeds are caller-supplied;
 the caller MUST source each independently from an approved DRBG
 (SP 800-90A). `d` and `z` are NOT interchangeable — see the
 ML-KEM-1024 section comment above for the semantic distinction
 (identical across all three parameter sets).

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if a
 rare K-PKE NTT decode failure occurs during keygen, or a module
 error variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ek_out` and `dk_out`
 must each be non-NULL writable pointers to ≥1184 and ≥2400 bytes
 respectively.
 */
int oxi_ml_kem_768_keygen(const uint8_t *d_ptr,
                          const uint8_t *z_ptr,
                          uint8_t *ek_out,
                          uint8_t *dk_out);

/*
 Encapsulate a shared secret against an ML-KEM-768 encapsulation
 key (FIPS 203 §6.2 ML-KEM.Encaps, k=3 parameter set).

 Reads exactly 1184 bytes from `ek_ptr` and exactly 32 bytes from
 `m_ptr` (encapsulation randomness, caller-supplied from an
 SP 800-90A DRBG). Writes the 32-byte shared secret into `ss_out`
 and the 1088-byte ciphertext into `ct_out`.

 Returns `OxiResult::Ok = 0` on success, or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` and `ct_out`
 must each be non-NULL writable pointers to ≥32 and ≥1088 bytes
 respectively.
 */
int oxi_ml_kem_768_encapsulate(const uint8_t *ek_ptr,
                               const uint8_t *m_ptr,
                               uint8_t *ss_out,
                               uint8_t *ct_out);

/*
 Decapsulate a shared secret from an ML-KEM-768 ciphertext
 (FIPS 203 §6.3 ML-KEM.Decaps, k=3 parameter set).

 Reads exactly 2400 bytes from `dk_ptr` and exactly 1088 bytes
 from `ct_ptr`. Writes the 32-byte shared secret into `ss_out`.
 **Fully deterministic** — no caller randomness, no `Ok(false)`
 shape, no `TagMismatch = 22` mapping. The FO transform's
 implicit-rejection branch absorbs tampered ciphertext into a
 deterministic-but-pseudorandom shared secret in constant time;
 tamper does NOT surface as a discriminant. See the
 decapsulate-implicit-rejection paragraph in security-policy §4.9.

 Returns `OxiResult::Ok = 0` on success, or a module error
 variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `ss_out` must be a
 non-NULL writable pointer to ≥32 bytes.
 */
int oxi_ml_kem_768_decapsulate(const uint8_t *dk_ptr, const uint8_t *ct_ptr, uint8_t *ss_out);

/*
 Generate an SLH-DSA-SHA2-256s key pair from a 96-byte
 caller-supplied seed (FIPS 205 §9.1 Algorithm 17).

 Reads exactly 96 bytes from `xi_ptr`, internally framed as
 `SK.seed ‖ SK.prf ‖ PK.seed`. Writes the 64-byte public key
 into `pk_out` and the 128-byte secret key into `sk_out`. The
 caller MUST source the 96 bytes from an approved DRBG
 (SP 800-90A); the FFI performs no entropy generation. The three
 32-byte components are NOT interchangeable — see the section
 comment above for the semantic distinction.

 Returns `OxiResult::Ok = 0` on success, or a module error
 variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `pk_out` and `sk_out`
 must each be non-NULL writable pointers to ≥64 and ≥128 bytes
 respectively.
 */
int oxi_slh_dsa_sha2_256s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-256s (FIPS 205 §9.2
 Algorithm 22, external `slh_sign`).

 Reads exactly 128 bytes from `sk_ptr`, `msg_len` bytes from
 `msg_ptr`, and `ctx_len` bytes from `ctx_ptr`. Writes the
 29 792-byte signature into `sig_out`. Pass `ctx_len = 0` (with
 any `ctx_ptr`) for the empty context used by X.509 / CMS /
 LAMPS.

 Signing is **deterministic** (opt_rand = PK.seed): bit-identical
 signature across calls for the same `(sk, msg, ctx)` triple.
 NO randomized-mode variant is exposed.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if
 `ctx_len > 255` (FIPS 205 §9.2 limit), or a module error
 variant (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid. `sig_out` must be a
 non-NULL writable pointer to ≥29 792 bytes.
 */
int oxi_slh_dsa_sha2_256s_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-256s signature (FIPS 205 §9.3
 Algorithm 24, external `slh_verify`).

 Reads exactly 64 bytes from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, `ctx_len` bytes from `ctx_ptr`, and 29 792 bytes
 from `sig_ptr`. Pass `ctx_len = 0` for the empty context used
 by X.509 / CMS / LAMPS.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (decode-fail OR signature-invalid — upstream collapses these
 into a single `Err(InvalidInput)`; same shape as RSA verify and
 ML-DSA verify), or a module error variant (`NotOperational`,
 `AlgorithmRestricted`).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_256s_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHA2-128s key pair from a 48-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=16; xi=48, pk=32, sk=64).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-128s (FIPS 205 §9.2 Algorithm
 22). Deterministic. Reads 64-byte sk, writes 7 856-byte
 signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128s_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-128s signature (FIPS 205 §9.3 Algorithm
 24). Reads 32-byte pk + 7 856-byte sig. `Err(InvalidInput) →
 TagMismatch = 22` collapse.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128s_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHA2-128f key pair from a 48-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=16, fast variant; xi=48, pk=32,
 sk=64).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-128f (FIPS 205 §9.2 Algorithm
 22). Deterministic. Reads 64-byte sk, writes 17 088-byte
 signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128f_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-128f signature (FIPS 205 §9.3 Algorithm
 24). Reads 32-byte pk + 17 088-byte sig. `Err(InvalidInput) →
 TagMismatch = 22` collapse.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_128f_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHA2-192s key pair from a 72-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=24).

 Reads 72 bytes from `xi_ptr` (`SK.seed ‖ SK.prf ‖ PK.seed`,
 3 × 24 bytes). Writes the 48-byte pk into `pk_out` and the
 96-byte sk into `sk_out`.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_192s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-192s (FIPS 205 §9.2 Algorithm
 22). Reads 96-byte sk, writes 16 224-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must point to
 ≥16 224 writable bytes.
 */
int oxi_slh_dsa_sha2_192s_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-192s signature (FIPS 205 §9.3 Algorithm
 24). Reads 48-byte pk, 16 224-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_192s_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHA2-192f key pair from a 72-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=24, fast variant).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_192f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-192f (FIPS 205 §9.2 Algorithm
 22). Reads 96-byte sk, writes 35 664-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must point to
 ≥35 664 writable bytes.
 */
int oxi_slh_dsa_sha2_192f_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-192f signature (FIPS 205 §9.3 Algorithm
 24). Reads 48-byte pk, 35 664-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_192f_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHA2-256f key pair from a 96-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=32, fast variant).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_256f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHA2-256f (FIPS 205 §9.2 Algorithm
 22). Reads 128-byte sk, writes 49 856-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid. `sig_out` must point to
 ≥49 856 writable bytes.
 */
int oxi_slh_dsa_sha2_256f_sign(const uint8_t *sk_ptr,
                               const uint8_t *msg_ptr,
                               uintptr_t msg_len,
                               const uint8_t *ctx_ptr,
                               uintptr_t ctx_len,
                               uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHA2-256f signature (FIPS 205 §9.3 Algorithm
 24). Reads 64-byte pk, 49 856-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_sha2_256f_verify(const uint8_t *pk_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 const uint8_t *ctx_ptr,
                                 uintptr_t ctx_len,
                                 const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-128s key pair from a 48-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=16).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-128s (FIPS 205 §9.2 Algorithm
 22). Reads 64-byte sk, writes 7 856-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128s_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-128s signature (FIPS 205 §9.3 Algorithm
 24). Reads 32-byte pk, 7 856-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128s_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-128f key pair from a 48-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=16, fast variant).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-128f (FIPS 205 §9.2 Algorithm
 22). Reads 64-byte sk, writes 17 088-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128f_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-128f signature (FIPS 205 §9.3 Algorithm
 24). Reads 32-byte pk, 17 088-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_128f_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-192s key pair from a 72-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=24).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-192s (FIPS 205 §9.2 Algorithm
 22). Reads 96-byte sk, writes 16 224-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192s_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-192s signature (FIPS 205 §9.3 Algorithm
 24). Reads 48-byte pk, 16 224-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192s_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-192f key pair from a 72-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=24, fast variant).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-192f (FIPS 205 §9.2 Algorithm
 22). Reads 96-byte sk, writes 35 664-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192f_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-192f signature (FIPS 205 §9.3 Algorithm
 24). Reads 48-byte pk, 35 664-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_192f_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-256s key pair from a 96-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=32).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256s_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-256s (FIPS 205 §9.2 Algorithm
 22). Reads 128-byte sk, writes 29 792-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256s_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-256s signature (FIPS 205 §9.3 Algorithm
 24). Reads 64-byte pk, 29 792-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256s_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an SLH-DSA-SHAKE-256f key pair from a 96-byte seed
 (FIPS 205 §9.1 Algorithm 17; n=32, fast variant).

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256f_keygen(const uint8_t *xi_ptr, uint8_t *pk_out, uint8_t *sk_out);

/*
 Sign a message with SLH-DSA-SHAKE-256f (FIPS 205 §9.2 Algorithm
 22). Reads 128-byte sk, writes 49 856-byte signature.
 Deterministic.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256f_sign(const uint8_t *sk_ptr,
                                const uint8_t *msg_ptr,
                                uintptr_t msg_len,
                                const uint8_t *ctx_ptr,
                                uintptr_t ctx_len,
                                uint8_t *sig_out);

/*
 Verify an SLH-DSA-SHAKE-256f signature (FIPS 205 §9.3 Algorithm
 24). Reads 64-byte pk, 49 856-byte signature.

 # Safety

 All pointer/length pairs must be valid.
 */
int oxi_slh_dsa_shake_256f_verify(const uint8_t *pk_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  const uint8_t *ctx_ptr,
                                  uintptr_t ctx_len,
                                  const uint8_t *sig_ptr);

/*
 Generate an LMS key pair from a 32-byte caller-supplied seed.

 Reads exactly 32 bytes from `xi_ptr`, deterministically derives
 the tree seed and 16-byte identifier `I` via SHA-256, and writes
 the 52-byte opaque private-key blob into `sk_out` and the
 56-byte public key into `pk_out`. The caller MUST source the 32
 seed bytes from an approved DRBG (SP 800-90A); the FFI performs
 no entropy generation.

 `sk_out` is the persistence-of-record format. Treat it as an
 opaque blob and pass it back unchanged to [`oxi_lms_sign`].

 Returns `OxiResult::Ok = 0` on success or a module error variant
 (`NotOperational`, `AlgorithmRestricted`).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a non-NULL
 writable pointer to ≥56 bytes.
 */
int oxi_lms_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with an LMS private key.

 Reads the 52-byte opaque private-key blob from `sk_in_ptr`,
 `msg_len` bytes from `msg_ptr`, signs the message, advances the
 internal leaf index by one, writes the **updated** 52-byte blob
 into `sk_out`, and writes the 2508-byte signature into `sig_out`.

 **Persistence contract:** the caller MUST persist `sk_out` (the
 post-state) before using `sig_out`. Failure to persist before a
 crash, followed by a restart that re-signs from the pre-state,
 reuses the same one-time key — a catastrophic break of LMS.

 Returns `OxiResult::Ok = 0` on success, `InvalidInput = 5` if the
 key is exhausted (1024 signatures already issued), or a module
 error variant.

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr` must be valid
 for `msg_len` bytes (NULL with len=0 is permitted). `sk_out`
 must be a non-NULL writable pointer to ≥52 bytes. `sig_out`
 must be a non-NULL writable pointer to ≥2508 bytes. `sk_in_ptr`
 and `sk_out` may alias (in-place advance is supported).
 */
int oxi_lms_sign(const uint8_t *sk_in_ptr,
                 const uint8_t *msg_ptr,
                 uintptr_t msg_len,
                 uint8_t *sk_out,
                 uint8_t *sig_out);

/*
 Verify an LMS signature.

 Reads the 56-byte public key from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, and the 2508-byte signature from `sig_ptr`.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (parse, structural mismatch, or cryptographic mismatch — upstream
 collapses these into a single `Err(InvalidInput)`; same shape
 as RSA verify, ML-DSA verify, SLH-DSA verify), or a module error
 variant.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must be valid for
 `msg_len` bytes (NULL with len=0 is permitted). `sig_ptr` must
 be valid for 2508 bytes.
 */
int oxi_lms_verify(const uint8_t *pk_ptr,
                   const uint8_t *msg_ptr,
                   uintptr_t msg_len,
                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=5 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h5_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=5 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 8684-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥8684 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h5_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=5 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8684-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 8684 bytes.
 */
int oxi_lms_sha256_m32_h5_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=5 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h5_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=5 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4460-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4460 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h5_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=5 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4460-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4460 bytes.
 */
int oxi_lms_sha256_m32_h5_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=5 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h5_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=5 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2348-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2348 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h5_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=5 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2348-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2348 bytes.
 */
int oxi_lms_sha256_m32_h5_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=5 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h5_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=5 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1292-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1292 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h5_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=5 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1292-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1292 bytes.
 */
int oxi_lms_sha256_m32_h5_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=10 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h10_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=10 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 8844-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥8844 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h10_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=10 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8844-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 8844 bytes.
 */
int oxi_lms_sha256_m32_h10_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=10 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h10_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=10 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4620-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4620 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h10_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=10 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4620 bytes.
 */
int oxi_lms_sha256_m32_h10_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=10 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h10_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=10 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2508-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2508 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h10_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=10 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2508-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2508 bytes.
 */
int oxi_lms_sha256_m32_h10_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=10 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h10_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=10 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1452-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1452 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h10_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=10 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1452-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1452 bytes.
 */
int oxi_lms_sha256_m32_h10_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=15 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h15_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=15 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9004-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9004 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h15_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=15 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9004-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9004 bytes.
 */
int oxi_lms_sha256_m32_h15_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=15 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h15_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=15 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4780-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4780 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h15_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=15 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4780 bytes.
 */
int oxi_lms_sha256_m32_h15_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=15 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h15_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=15 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2668-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2668 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h15_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=15 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2668-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2668 bytes.
 */
int oxi_lms_sha256_m32_h15_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=15 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h15_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=15 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1612-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1612 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h15_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=15 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1612-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1612 bytes.
 */
int oxi_lms_sha256_m32_h15_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=20 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h20_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=20 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9164-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9164 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h20_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=20 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9164-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9164 bytes.
 */
int oxi_lms_sha256_m32_h20_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=20 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h20_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=20 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4940-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4940 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h20_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=20 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4940 bytes.
 */
int oxi_lms_sha256_m32_h20_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=20 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h20_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=20 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2828-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2828 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h20_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=20 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2828-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2828 bytes.
 */
int oxi_lms_sha256_m32_h20_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=20 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h20_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=20 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1772-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1772 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h20_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=20 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1772-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1772 bytes.
 */
int oxi_lms_sha256_m32_h20_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=25 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h25_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=25 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9324-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9324 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h25_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=25 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9324-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9324 bytes.
 */
int oxi_lms_sha256_m32_h25_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=25 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h25_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=25 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5100-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥5100 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h25_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=25 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 5100-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5100 bytes.
 */
int oxi_lms_sha256_m32_h25_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=25 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h25_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=25 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2988-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2988 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h25_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=25 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2988-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2988 bytes.
 */
int oxi_lms_sha256_m32_h25_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=32 H=25 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8554 §A.1+§A.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_sha256_m32_h25_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=32 H=25 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1932-byte signature into `sig_out`. Spec: RFC 8554 §A.1+§A.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1932 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m32_h25_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=32 H=25 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1932-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8554 §A.1+§A.2.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1932 bytes.
 */
int oxi_lms_sha256_m32_h25_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=5 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h5_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=5 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4956-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥4956 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h5_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=5 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 4956-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4956 bytes.
 */
int oxi_lms_sha256_m24_h5_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=5 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h5_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=5 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2580-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2580 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h5_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=5 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2580-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2580 bytes.
 */
int oxi_lms_sha256_m24_h5_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=5 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h5_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=5 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1380-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1380 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h5_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=5 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1380-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1380 bytes.
 */
int oxi_lms_sha256_m24_h5_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=5 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h5_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=5 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 780-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥780 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h5_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=5 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 780 bytes.
 */
int oxi_lms_sha256_m24_h5_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=10 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h10_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=10 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5076-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5076 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h10_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=10 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5076-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5076 bytes.
 */
int oxi_lms_sha256_m24_h10_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=10 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h10_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=10 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2700-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2700 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h10_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=10 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2700-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2700 bytes.
 */
int oxi_lms_sha256_m24_h10_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=10 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h10_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=10 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1500-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1500 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h10_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=10 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1500-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1500 bytes.
 */
int oxi_lms_sha256_m24_h10_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=10 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h10_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=10 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 900-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥900 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h10_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=10 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 900-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 900 bytes.
 */
int oxi_lms_sha256_m24_h10_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=15 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h15_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=15 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5196-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5196 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h15_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=15 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5196-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5196 bytes.
 */
int oxi_lms_sha256_m24_h15_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=15 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h15_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=15 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2820-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2820 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h15_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=15 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2820-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2820 bytes.
 */
int oxi_lms_sha256_m24_h15_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=15 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h15_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=15 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1620-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1620 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h15_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=15 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1620 bytes.
 */
int oxi_lms_sha256_m24_h15_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=15 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h15_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=15 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1020-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1020 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h15_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=15 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1020-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1020 bytes.
 */
int oxi_lms_sha256_m24_h15_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=20 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h20_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=20 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5316-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5316 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h20_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=20 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5316-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5316 bytes.
 */
int oxi_lms_sha256_m24_h20_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=20 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h20_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=20 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2940-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2940 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h20_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=20 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2940 bytes.
 */
int oxi_lms_sha256_m24_h20_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=20 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h20_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=20 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1740-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1740 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h20_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=20 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1740-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1740 bytes.
 */
int oxi_lms_sha256_m24_h20_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=20 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h20_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=20 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1140-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1140 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h20_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=20 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1140-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1140 bytes.
 */
int oxi_lms_sha256_m24_h20_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=25 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h25_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=25 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5436-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5436 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h25_w1_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=25 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5436-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5436 bytes.
 */
int oxi_lms_sha256_m24_h25_w1_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=25 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h25_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=25 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 3060-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥3060 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h25_w2_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=25 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 3060-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 3060 bytes.
 */
int oxi_lms_sha256_m24_h25_w2_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=25 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h25_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=25 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1860-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1860 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h25_w4_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=25 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1860-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1860 bytes.
 */
int oxi_lms_sha256_m24_h25_w4_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHA-256 M=24 H=25 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_sha256_m24_h25_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHA-256 M=24 H=25 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1260-byte signature into `sig_out`. Spec: RFC 8708 §4.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1260 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_sha256_m24_h25_w8_sign(const uint8_t *sk_in_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   uint8_t *sk_out,
                                   uint8_t *sig_out);

/*
 Verify an LMS signature for the SHA-256 M=24 H=25 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1260-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.1.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1260 bytes.
 */
int oxi_lms_sha256_m24_h25_w8_verify(const uint8_t *pk_ptr,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=5 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h5_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=5 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 8684-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥8684 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h5_w1_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8684-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 8684 bytes.
 */
int oxi_lms_shake_m32_h5_w1_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=5 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h5_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=5 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4460-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4460 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h5_w2_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4460-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4460 bytes.
 */
int oxi_lms_shake_m32_h5_w2_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=5 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h5_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=5 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2348-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2348 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h5_w4_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2348-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2348 bytes.
 */
int oxi_lms_shake_m32_h5_w4_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=5 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h5_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=5 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1292-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1292 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h5_w8_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1292-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1292 bytes.
 */
int oxi_lms_shake_m32_h5_w8_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=10 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h10_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=10 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 8844-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥8844 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h10_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8844-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 8844 bytes.
 */
int oxi_lms_shake_m32_h10_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=10 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h10_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=10 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4620-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4620 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h10_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4620 bytes.
 */
int oxi_lms_shake_m32_h10_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=10 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h10_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=10 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2508-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2508 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h10_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2508-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2508 bytes.
 */
int oxi_lms_shake_m32_h10_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=10 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h10_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=10 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1452-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1452 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h10_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1452-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1452 bytes.
 */
int oxi_lms_shake_m32_h10_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=15 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h15_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=15 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9004-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9004 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h15_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9004-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9004 bytes.
 */
int oxi_lms_shake_m32_h15_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=15 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h15_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=15 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4780-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4780 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h15_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4780 bytes.
 */
int oxi_lms_shake_m32_h15_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=15 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h15_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=15 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2668-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2668 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h15_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2668-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2668 bytes.
 */
int oxi_lms_shake_m32_h15_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=15 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h15_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=15 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1612-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1612 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h15_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1612-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1612 bytes.
 */
int oxi_lms_shake_m32_h15_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=20 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h20_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=20 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9164-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9164 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h20_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9164-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9164 bytes.
 */
int oxi_lms_shake_m32_h20_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=20 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h20_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=20 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4940-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥4940 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h20_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4940 bytes.
 */
int oxi_lms_shake_m32_h20_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=20 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h20_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=20 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2828-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2828 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h20_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2828-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2828 bytes.
 */
int oxi_lms_shake_m32_h20_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=20 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h20_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=20 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1772-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1772 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h20_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1772-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1772 bytes.
 */
int oxi_lms_shake_m32_h20_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=25 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h25_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=25 W=1 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 9324-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥9324 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h25_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9324-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 9324 bytes.
 */
int oxi_lms_shake_m32_h25_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=25 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h25_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=25 W=2 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5100-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥5100 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h25_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 5100-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5100 bytes.
 */
int oxi_lms_shake_m32_h25_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=25 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h25_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=25 W=4 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2988-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥2988 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h25_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2988-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2988 bytes.
 */
int oxi_lms_shake_m32_h25_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=32 H=25 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 52-byte opaque
 private-key blob into `sk_out` and a 56-byte public key
 into `pk_out`. Spec: RFC 8708 §3.1. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥52 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥56 bytes.
 */
int oxi_lms_shake_m32_h25_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=32 H=25 W=8 variant.

 Reads the 52-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1932-byte signature into `sig_out`. Spec: RFC 8708 §3.1.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 52 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥52 bytes, `sig_out` ≥1932 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m32_h25_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1932-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §3.1.

 # Safety

 `pk_ptr` must be valid for 56 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1932 bytes.
 */
int oxi_lms_shake_m32_h25_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=5 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h5_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=5 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 4956-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥4956 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h5_w1_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 4956-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 4956 bytes.
 */
int oxi_lms_shake_m24_h5_w1_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=5 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h5_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=5 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2580-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2580 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h5_w2_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2580-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2580 bytes.
 */
int oxi_lms_shake_m24_h5_w2_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=5 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h5_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=5 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1380-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1380 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h5_w4_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1380-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1380 bytes.
 */
int oxi_lms_shake_m24_h5_w4_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=5 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h5_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=5 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 780-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥780 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h5_w8_sign(const uint8_t *sk_in_ptr,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sk_out,
                                 uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 780 bytes.
 */
int oxi_lms_shake_m24_h5_w8_verify(const uint8_t *pk_ptr,
                                   const uint8_t *msg_ptr,
                                   uintptr_t msg_len,
                                   const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=10 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h10_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=10 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5076-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5076 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h10_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5076-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5076 bytes.
 */
int oxi_lms_shake_m24_h10_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=10 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h10_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=10 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2700-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2700 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h10_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2700-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2700 bytes.
 */
int oxi_lms_shake_m24_h10_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=10 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h10_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=10 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1500-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1500 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h10_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1500-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1500 bytes.
 */
int oxi_lms_shake_m24_h10_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=10 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h10_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=10 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 900-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥900 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h10_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 900-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 900 bytes.
 */
int oxi_lms_shake_m24_h10_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=15 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h15_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=15 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5196-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5196 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h15_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5196-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5196 bytes.
 */
int oxi_lms_shake_m24_h15_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=15 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h15_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=15 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2820-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2820 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h15_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2820-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2820 bytes.
 */
int oxi_lms_shake_m24_h15_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=15 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h15_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=15 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1620-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1620 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h15_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1620 bytes.
 */
int oxi_lms_shake_m24_h15_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=15 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h15_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=15 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1020-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1020 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h15_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1020-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1020 bytes.
 */
int oxi_lms_shake_m24_h15_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=20 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h20_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=20 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5316-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5316 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h20_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5316-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5316 bytes.
 */
int oxi_lms_shake_m24_h20_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=20 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h20_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=20 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 2940-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥2940 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h20_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 2940 bytes.
 */
int oxi_lms_shake_m24_h20_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=20 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h20_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=20 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1740-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1740 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h20_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1740-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1740 bytes.
 */
int oxi_lms_shake_m24_h20_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=20 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h20_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=20 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1140-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1140 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h20_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1140-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1140 bytes.
 */
int oxi_lms_shake_m24_h20_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=25 W=1.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h25_w1_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=25 W=1 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 5436-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥5436 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h25_w1_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5436-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 5436 bytes.
 */
int oxi_lms_shake_m24_h25_w1_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=25 W=2.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h25_w2_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=25 W=2 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 3060-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥3060 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h25_w2_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 3060-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 3060 bytes.
 */
int oxi_lms_shake_m24_h25_w2_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=25 W=4.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h25_w4_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=25 W=4 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1860-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1860 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h25_w4_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1860-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1860 bytes.
 */
int oxi_lms_shake_m24_h25_w4_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Generate an LMS key pair for SHAKE-256 M=24 H=25 W=8.

 Reads 32 bytes from `xi_ptr`, writes a 44-byte opaque
 private-key blob into `sk_out` and a 48-byte public key
 into `pk_out`. Spec: RFC 8708 §4.2. See [`oxi_lms_keygen`] for the
 LMS-family contract (deterministic derivation from `xi`,
 persistence-of-record format, profile gating).

 # Safety

 `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
 writable pointer to ≥44 bytes. `pk_out` must be a
 non-NULL writable pointer to ≥48 bytes.
 */
int oxi_lms_shake_m24_h25_w8_keygen(const uint8_t *xi_ptr, uint8_t *sk_out, uint8_t *pk_out);

/*
 Sign a message with the LMS SHAKE-256 M=24 H=25 W=8 variant.

 Reads the 44-byte opaque private-key blob from
 `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
 leaf index, writes the updated blob to `sk_out`, and writes the
 1260-byte signature into `sig_out`. Spec: RFC 8708 §4.2.
 See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
 be persisted before using `sig_out`).

 # Safety

 `sk_in_ptr` must be valid for 44 bytes. `msg_ptr`
 must be valid for `msg_len` bytes (NULL with len=0 permitted).
 `sk_out` ≥44 bytes, `sig_out` ≥1260 bytes.
 `sk_in_ptr` and `sk_out` may alias.
 */
int oxi_lms_shake_m24_h25_w8_sign(const uint8_t *sk_in_ptr,
                                  const uint8_t *msg_ptr,
                                  uintptr_t msg_len,
                                  uint8_t *sk_out,
                                  uint8_t *sig_out);

/*
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1260-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: RFC 8708 §4.2.

 # Safety

 `pk_ptr` must be valid for 48 bytes. `msg_ptr` must
 be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
 must be valid for 1260 bytes.
 */
int oxi_lms_shake_m24_h25_w8_verify(const uint8_t *pk_ptr,
                                    const uint8_t *msg_ptr,
                                    uintptr_t msg_len,
                                    const uint8_t *sig_ptr);

/*
 Verify an XMSS signature.

 Reads the 68-byte public key from `pk_ptr`, `msg_len` bytes from
 `msg_ptr`, and the 2500-byte signature from `sig_ptr`.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::TagMismatch = 22` for any verification failure
 (parse / structural / cryptographic), or a module error variant.

 # Safety

 `pk_ptr` must be valid for 68 bytes. `msg_ptr` must be valid for
 `msg_len` bytes. `sig_ptr` must be valid for 2500 bytes.
 */
int oxi_xmss_verify(const uint8_t *pk_ptr,
                    const uint8_t *msg_ptr,
                    uintptr_t msg_len,
                    const uint8_t *sig_ptr);

/*
 Allocate a new ECDSA P-256 private-key handle, generating its
 private scalar via the FIPS 186-5 §A.2.2 rejection sampler on
 `drbg`, deriving its public key, and running the IG 10.3.A
 pairwise consistency test against a fixed probe message before
 returning.

 On success, writes a heap-allocated handle pointer through
 `out_key` and returns `OxiResult::Ok = 0`. The caller owns the
 handle and MUST release it with
 [`oxi_ecdsa_p256_private_key_free`].

 Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
 scalar / nonce sampling, or if the IG 10.3.A PCT sign-and-verify
 round-trip on the freshly-generated key fails (the latter would
 indicate a faulted sign or verify primitive). Returns
 `OxiResult::NotOperational = 1` if the FIPS module is not in the
 `Operational` state. Returns `OxiResult::AlgorithmRestricted = 6`
 if the active algorithm profile blocks ECDSA-P256 keygen.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate`]. `out_key` must be a non-NULL
 writable pointer to a `*mut OxiEcdsaP256PrivateKey`.
 */
int oxi_ecdsa_p256_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                            OxiEcdsaP256PrivateKey **out_key);

/*
 Free an ECDSA P-256 private-key handle. NULL-safe.

 After this call the caller's pointer is dangling; the caller
 SHOULD set their pointer to NULL to avoid use-after-free. Drop
 on the upstream `EcdsaP256PrivateKey` zeroises the private
 scalar `d` via the workspace-wide `oxicrypt-zeroize` volatile-
 write convention; no caller-side scrubbing is required.

 # Safety

 `key` must be either NULL or a pointer previously returned by
 [`oxi_ecdsa_p256_private_key_new_generate`] that has not yet
 been freed.
 */
void oxi_ecdsa_p256_private_key_free(OxiEcdsaP256PrivateKey *key);

/*
 Copy the uncompressed SEC1 public key (`0x04 || X(32) || Y(32)`,
 65 bytes) from an ECDSA P-256 private-key handle into the caller
 buffer.

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::NullPointer = 10` if either pointer is NULL;
 `OxiResult::NotOperational = 1` if the handle has been
 finalised (today: never — no `_finalize` exists for this handle).

 # Safety

 `key` must be a live handle from
 [`oxi_ecdsa_p256_private_key_new_generate`]. `public_key_out`
 must be a non-NULL writable pointer to ≥65 bytes.
 */
int oxi_ecdsa_p256_private_key_public_key(const OxiEcdsaP256PrivateKey *key,
                                          uint8_t *public_key_out);

/*
 Sign `msg` with ECDSA P-256 + SHA-256 under the private-key
 handle, sampling a fresh per-signature nonce `k` from `drbg` via
 the FIPS 186-5 §A.2.2 rejection sampler. If the sampled `k`
 produces `r == 0` or `s == 0` (mathematically possible but
 astronomically unlikely; on the order of `2^(-256)` per draw),
 the call retries with a fresh draw up to 8 times before returning
 `OxiResult::InvalidInput = 5`.

 On success, writes 64 bytes (`r(32) || s(32)`) into `sig_out`.

 Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
 nonce sampling or the bounded retry chain exhausts without a
 non-zero `(r, s)` (a faulted primitive, not bad input). Returns
 `OxiResult::NotOperational = 1` if the FIPS module is not in the
 `Operational` state. Returns `OxiResult::AlgorithmRestricted = 6`
 if the active algorithm profile blocks ECDSA-P256 sign (a profile
 MAY allow `EcdsaP256Keygen` but block `EcdsaP256Sign`, in which
 case `_new_generate` succeeds but this fn returns 6).

 # Safety

 `key` must be a live handle from
 [`oxi_ecdsa_p256_private_key_new_generate`]. `drbg` must be a
 live, instantiated handle from [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate`]; the caller MUST serialise
 concurrent calls on the same `drbg` pointer per the
 per-call-mutating-handle thread-safety contract documented in
 security-policy §4.8. `msg_ptr` must be valid for `msg_len` bytes.
 `sig_out` must be a non-NULL writable pointer to ≥64 bytes.
 */
int oxi_ecdsa_p256_private_key_sign_sha256(const OxiEcdsaP256PrivateKey *key,
                                           OxiHmacDrbgSha256 *drbg,
                                           const uint8_t *msg_ptr,
                                           uintptr_t msg_len,
                                           uint8_t *sig_out);

/*
 Allocate a new ECDSA P-384 private-key handle, generating its
 private scalar via the FIPS 186-5 §A.2.2 rejection sampler on
 `drbg`, deriving its public key, and running the IG 10.3.A
 pairwise consistency test before returning. Mirrors
 [`oxi_ecdsa_p256_private_key_new_generate`].

 # Safety

 `drbg` must be a live, instantiated DRBG handle. `out_key` must
 be a non-NULL writable pointer to a `*mut OxiEcdsaP384PrivateKey`.
 */
int oxi_ecdsa_p384_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                            OxiEcdsaP384PrivateKey **out_key);

/*
 Free an ECDSA P-384 private-key handle. NULL-safe. Mirrors
 [`oxi_ecdsa_p256_private_key_free`].

 # Safety

 `key` must be either NULL or a pointer previously returned by
 [`oxi_ecdsa_p384_private_key_new_generate`] that has not yet
 been freed.
 */
void oxi_ecdsa_p384_private_key_free(OxiEcdsaP384PrivateKey *key);

/*
 Copy the uncompressed SEC1 public key (`0x04 || X(48) || Y(48)`,
 97 bytes) from an ECDSA P-384 private-key handle into the caller
 buffer.

 # Safety

 `key` must be a live handle from
 [`oxi_ecdsa_p384_private_key_new_generate`]. `public_key_out`
 must be a non-NULL writable pointer to ≥97 bytes.
 */
int oxi_ecdsa_p384_private_key_public_key(const OxiEcdsaP384PrivateKey *key,
                                          uint8_t *public_key_out);

/*
 Sign `msg` with ECDSA P-384 + SHA-384 under the private-key
 handle, sampling a fresh per-signature nonce `k` from `drbg` via
 the FIPS 186-5 §A.2.2 rejection sampler. Mirrors
 [`oxi_ecdsa_p256_private_key_sign_sha256`] with `[u8; 96]`
 signature output.

 Returns `OxiResult::InvalidInput = 5` if the DRBG faults or the
 bounded retry chain exhausts. Returns `OxiResult::NotOperational
 = 1` if the FIPS module is not in the `Operational` state.
 Returns `OxiResult::AlgorithmRestricted = 6` if the active
 algorithm profile blocks ECDSA-P384 sign (a profile MAY allow
 `EcdsaP384Keygen` but block `EcdsaP384Sign`, in which case
 `_new_generate` succeeds but this fn returns 6).

 # Safety

 `key` must be a live handle from
 [`oxi_ecdsa_p384_private_key_new_generate`]. `drbg` must be a
 live, instantiated DRBG handle; serialise concurrent calls per
 the per-call-mutating-handle thread-safety contract.
 `msg_ptr` must be valid for `msg_len` bytes. `sig_out` must be a
 non-NULL writable pointer to ≥96 bytes.
 */
int oxi_ecdsa_p384_private_key_sign_sha384(const OxiEcdsaP384PrivateKey *key,
                                           OxiHmacDrbgSha256 *drbg,
                                           const uint8_t *msg_ptr,
                                           uintptr_t msg_len,
                                           uint8_t *sig_out);

/*
 Allocate a new RSA-2048 private-key handle, generating a fresh
 keypair via FIPS 186-5 §A.1.1 / §B.3.1 prime sampling on `drbg`,
 then running the IG 10.3.A pairwise consistency test on the CRT
 path (sign a fixed probe, verify with the public exponent) before
 returning. `e` must be an odd prime in `[65537, 2^64)` — in
 practice, pass `65537` (F4).

 On success, writes a heap-allocated handle pointer through
 `out_key` and returns `OxiResult::Ok = 0`. The caller owns the
 handle and MUST release it with [`oxi_rsa_2048_private_key_free`].

 Returns `OxiResult::InvalidInput = 5` if the DRBG faults during
 prime sampling, the prime-candidate retry budget is exceeded,
 `e` fails the structural check, or the resulting keypair fails
 the pairwise consistency test (the latter would indicate internal
 corruption). Returns `OxiResult::NotOperational = 1` if the FIPS
 module is not in the `Operational` state. Returns
 `OxiResult::AlgorithmRestricted = 6` if the active algorithm
 profile blocks RSA-2048 keygen.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate`]. `out_key` must be a non-NULL
 writable pointer to a `*mut OxiRsaPrivateKey2048`.
 */
int oxi_rsa_2048_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                          uint64_t e,
                                          OxiRsaPrivateKey2048 **out_key);

/*
 Free an RSA-2048 private-key handle. NULL-safe.

 After this call the caller's pointer is dangling. Drop on the
 upstream `RsaPrivateKey2048` zeroises the private exponent `d`
 and (when present) the CRT components `p, q, dP, dQ, qInv` via
 the workspace-wide `oxicrypt-zeroize` volatile-write convention.

 # Safety

 `key` must be either NULL or a pointer previously returned by
 [`oxi_rsa_2048_private_key_new_generate`] that has not yet been
 freed.
 */
void oxi_rsa_2048_private_key_free(OxiRsaPrivateKey2048 *key);

/*
 Copy the public modulus `n` (256 bytes, big-endian) from an
 RSA-2048 private-key handle into the caller buffer.

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::NullPointer = 10` if either pointer is NULL.

 # Safety

 `key` must be a live handle. `modulus_out` must be a non-NULL
 writable pointer to ≥256 bytes.
 */
int oxi_rsa_2048_modulus(const OxiRsaPrivateKey2048 *key, uint8_t *modulus_out);

/*
 Copy the public exponent `e` from an RSA-2048 private-key handle
 into the caller-supplied `uint64_t*`.

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::NullPointer = 10` if either pointer is NULL.

 # Safety

 `key` must be a live handle. `e_out` must be a non-NULL writable
 pointer to a `uint64_t`.
 */
int oxi_rsa_2048_public_exponent(const OxiRsaPrivateKey2048 *key, uint64_t *e_out);

/*
 Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-2048
 private-key handle (FIPS 186-5 §5.4 / RFC 8017 §8.2).
 Deterministic — signing the same `(key, msg)` twice produces
 byte-identical signatures.

 On success, writes 256 bytes into `sig_out` and returns `Ok = 0`.

 # Safety

 `key` must be a live handle. `msg_ptr` must be valid for
 `msg_len` bytes. `sig_out` must be a non-NULL writable pointer
 to ≥256 bytes.
 */
int oxi_rsa_2048_sign_pkcs1_v15_sha256(const OxiRsaPrivateKey2048 *key,
                                       const uint8_t *msg_ptr,
                                       uintptr_t msg_len,
                                       uint8_t *sig_out);

/*
 Sign `msg` with RSASSA-PSS SHA-256 under the RSA-2048 private-
 key handle, sampling a fresh 32-byte salt from `drbg` per call
 (FIPS 186-5 §5.4 / RFC 8017 §8.1). Signing the same `(key, msg)`
 twice produces two distinct signatures.

 On success, writes 256 bytes into `sig_out` and returns `Ok = 0`.

 # Safety

 `key` must be a live handle. `drbg` must be a live, instantiated
 DRBG handle; the caller MUST serialise concurrent calls on the
 same `drbg` pointer per the per-call-mutating-handle thread-
 safety contract documented in security-policy.md. `msg_ptr` must
 be valid for `msg_len` bytes. `sig_out` must be a non-NULL
 writable pointer to ≥256 bytes.
 */
int oxi_rsa_2048_sign_pss_sha256(const OxiRsaPrivateKey2048 *key,
                                 OxiHmacDrbgSha256 *drbg,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sig_out);

/*
 Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-2048
 public key `(n, e)`, sampling a fresh 32-byte seed from `drbg`
 per call (RFC 8017 §7.1). The ciphertext is fixed at 256 bytes
 regardless of message length. Maximum plaintext length is 190
 bytes (`k − 2·hLen − 2` with `k = 256`, `hLen = 32`).

 On success, writes 256 bytes into `ct_out` and returns `Ok = 0`.

 # Safety

 `drbg` must be a live, instantiated DRBG handle. `n_ptr` must
 point to a 256-byte big-endian modulus. `label_ptr` must be valid
 for `label_len` bytes (use `NULL`/`0` for the empty label).
 `msg_ptr` must be valid for `msg_len` bytes; `msg_len` must be
 ≤ 190. `ct_out` must be a non-NULL writable pointer to ≥256 bytes.
 */
int oxi_rsa_2048_oaep_encrypt_sha256(OxiHmacDrbgSha256 *drbg,
                                     const uint8_t *n_ptr,
                                     uint64_t e,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     uint8_t *ct_out);

/*
 Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-2048
 private-key handle (RFC 8017 §7.1). The ciphertext is fixed at
 256 bytes; the recovered plaintext length is variable in
 `[0, 190]` and reported through `out_actual_len`.

 `out_max_len` must be ≥ 190 (the maximum possible plaintext for
 RSA-2048 OAEP-SHA-256). On success, the recovered plaintext is
 written into `out_ptr[0..*out_actual_len]`.

 All OAEP decode failures (bad `Y` byte, `lHash'` mismatch,
 malformed `PS`, missing `0x01` delimiter, wrong label) collapse
 to `OxiResult::InvalidInput = 5` without revealing which check
 failed (Manger-resistance contract). When the handle was built
 with CRT material (the only path exposed via `_new_generate`), a
 single CRT-half fault is caught by the Bellcore verify-after-
 decrypt step in the upstream primitive.

 # Safety

 `key` must be a live handle. `label_ptr` must be valid for
 `label_len` bytes. `ct_ptr` must point to exactly 256 bytes.
 `out_ptr` must be a non-NULL writable pointer to ≥`out_max_len`
 bytes; `out_max_len` must be ≥ 190. `out_actual_len` must be a
 non-NULL writable pointer to a `size_t`.
 */
int oxi_rsa_2048_oaep_decrypt_sha256(const OxiRsaPrivateKey2048 *key,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *ct_ptr,
                                     uint8_t *out_ptr,
                                     uintptr_t out_max_len,
                                     uintptr_t *out_actual_len);

/*
 Allocate a new RSA-3072 private-key handle. Mirrors
 [`oxi_rsa_2048_private_key_new_generate`] for the 3072-bit
 modulus; PCT-at-construction runs on the CRT path with Bellcore
 verify-after-sign.

 # Safety

 See [`oxi_rsa_2048_private_key_new_generate`].
 */
int oxi_rsa_3072_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                          uint64_t e,
                                          OxiRsaPrivateKey3072 **out_key);

/*
 Free an RSA-3072 private-key handle. NULL-safe. See
 [`oxi_rsa_2048_private_key_free`] for zeroization semantics.

 # Safety

 See [`oxi_rsa_2048_private_key_free`].
 */
void oxi_rsa_3072_private_key_free(OxiRsaPrivateKey3072 *key);

/*
 Copy the 384-byte big-endian public modulus `n` from an RSA-3072
 handle. See [`oxi_rsa_2048_modulus`].

 # Safety

 `key` must be a live handle. `modulus_out` must be a non-NULL
 writable pointer to ≥384 bytes.
 */
int oxi_rsa_3072_modulus(const OxiRsaPrivateKey3072 *key, uint8_t *modulus_out);

/*
 Copy the public exponent `e` from an RSA-3072 handle. See
 [`oxi_rsa_2048_public_exponent`].

 # Safety

 `key` must be a live handle. `e_out` must be a non-NULL writable
 pointer to a `uint64_t`.
 */
int oxi_rsa_3072_public_exponent(const OxiRsaPrivateKey3072 *key, uint64_t *e_out);

/*
 Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-3072
 handle. Deterministic; produces a 384-byte signature.

 # Safety

 See [`oxi_rsa_2048_sign_pkcs1_v15_sha256`]. `sig_out` must be a
 non-NULL writable pointer to ≥384 bytes.
 */
int oxi_rsa_3072_sign_pkcs1_v15_sha256(const OxiRsaPrivateKey3072 *key,
                                       const uint8_t *msg_ptr,
                                       uintptr_t msg_len,
                                       uint8_t *sig_out);

/*
 Sign `msg` with RSASSA-PSS SHA-256 under the RSA-3072 handle,
 DRBG-sampled salt. Produces a 384-byte signature.

 # Safety

 See [`oxi_rsa_2048_sign_pss_sha256`]. `sig_out` must be a
 non-NULL writable pointer to ≥384 bytes.
 */
int oxi_rsa_3072_sign_pss_sha256(const OxiRsaPrivateKey3072 *key,
                                 OxiHmacDrbgSha256 *drbg,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sig_out);

/*
 Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-3072
 public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
 is 318 bytes (`k − 2·hLen − 2` with `k = 384`, `hLen = 32`).
 Ciphertext is fixed at 384 bytes.

 # Safety

 See [`oxi_rsa_2048_oaep_encrypt_sha256`]. `n_ptr` must point to
 384 bytes; `msg_len` must be ≤ 318; `ct_out` must be a non-NULL
 writable pointer to ≥384 bytes.
 */
int oxi_rsa_3072_oaep_encrypt_sha256(OxiHmacDrbgSha256 *drbg,
                                     const uint8_t *n_ptr,
                                     uint64_t e,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     uint8_t *ct_out);

/*
 Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-3072
 handle. `out_max_len` must be ≥ 318. Mirrors the Manger-
 resistance and Bellcore-on-CRT contracts of
 [`oxi_rsa_2048_oaep_decrypt_sha256`].

 # Safety

 See [`oxi_rsa_2048_oaep_decrypt_sha256`]. `ct_ptr` must point to
 exactly 384 bytes; `out_max_len` must be ≥ 318.
 */
int oxi_rsa_3072_oaep_decrypt_sha256(const OxiRsaPrivateKey3072 *key,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *ct_ptr,
                                     uint8_t *out_ptr,
                                     uintptr_t out_max_len,
                                     uintptr_t *out_actual_len);

/*
 Allocate a new RSA-4096 private-key handle. Mirrors
 [`oxi_rsa_2048_private_key_new_generate`] for the 4096-bit
 modulus.

 # Safety

 See [`oxi_rsa_2048_private_key_new_generate`].
 */
int oxi_rsa_4096_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                          uint64_t e,
                                          OxiRsaPrivateKey4096 **out_key);

/*
 Free an RSA-4096 private-key handle. NULL-safe.

 # Safety

 See [`oxi_rsa_2048_private_key_free`].
 */
void oxi_rsa_4096_private_key_free(OxiRsaPrivateKey4096 *key);

/*
 Copy the 512-byte big-endian public modulus `n` from an RSA-4096
 handle.

 # Safety

 `key` must be a live handle. `modulus_out` must be a non-NULL
 writable pointer to ≥512 bytes.
 */
int oxi_rsa_4096_modulus(const OxiRsaPrivateKey4096 *key, uint8_t *modulus_out);

/*
 Copy the public exponent `e` from an RSA-4096 handle.

 # Safety

 `key` must be a live handle. `e_out` must be a non-NULL writable
 pointer to a `uint64_t`.
 */
int oxi_rsa_4096_public_exponent(const OxiRsaPrivateKey4096 *key, uint64_t *e_out);

/*
 Sign `msg` with RSASSA-PKCS#1-v1.5 SHA-256 under the RSA-4096
 handle. Deterministic; produces a 512-byte signature.

 # Safety

 See [`oxi_rsa_2048_sign_pkcs1_v15_sha256`]. `sig_out` must be a
 non-NULL writable pointer to ≥512 bytes.
 */
int oxi_rsa_4096_sign_pkcs1_v15_sha256(const OxiRsaPrivateKey4096 *key,
                                       const uint8_t *msg_ptr,
                                       uintptr_t msg_len,
                                       uint8_t *sig_out);

/*
 Sign `msg` with RSASSA-PSS SHA-256 under the RSA-4096 handle,
 DRBG-sampled salt. Produces a 512-byte signature.

 # Safety

 See [`oxi_rsa_2048_sign_pss_sha256`]. `sig_out` must be a
 non-NULL writable pointer to ≥512 bytes.
 */
int oxi_rsa_4096_sign_pss_sha256(const OxiRsaPrivateKey4096 *key,
                                 OxiHmacDrbgSha256 *drbg,
                                 const uint8_t *msg_ptr,
                                 uintptr_t msg_len,
                                 uint8_t *sig_out);

/*
 Encrypt `msg` with RSAES-OAEP SHA-256 against the RSA-4096
 public key `(n, e)`, DRBG-sampled seed. Maximum plaintext length
 is 446 bytes; ciphertext is 512 bytes.

 # Safety

 See [`oxi_rsa_2048_oaep_encrypt_sha256`]. `n_ptr` must point to
 512 bytes; `msg_len` must be ≤ 446; `ct_out` must be a non-NULL
 writable pointer to ≥512 bytes.
 */
int oxi_rsa_4096_oaep_encrypt_sha256(OxiHmacDrbgSha256 *drbg,
                                     const uint8_t *n_ptr,
                                     uint64_t e,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *msg_ptr,
                                     uintptr_t msg_len,
                                     uint8_t *ct_out);

/*
 Decrypt an RSAES-OAEP SHA-256 ciphertext under the RSA-4096
 handle. `out_max_len` must be ≥ 446. Manger-resistant and
 Bellcore-protected on the CRT path.

 # Safety

 See [`oxi_rsa_2048_oaep_decrypt_sha256`]. `ct_ptr` must point to
 exactly 512 bytes; `out_max_len` must be ≥ 446.
 */
int oxi_rsa_4096_oaep_decrypt_sha256(const OxiRsaPrivateKey4096 *key,
                                     const uint8_t *label_ptr,
                                     uintptr_t label_len,
                                     const uint8_t *ct_ptr,
                                     uint8_t *out_ptr,
                                     uintptr_t out_max_len,
                                     uintptr_t *out_actual_len);

/*
 Allocate a new AES-256 key handle from raw 32-byte key material.

 On success, writes a heap-allocated handle pointer through
 `out_handle` and returns `OxiResult::Ok = 0`. The caller owns the
 handle and MUST release it with [`oxi_aes256_free`].

 # Safety

 - `out_handle` must be a valid pointer to a writable
   `*mut OxiAes256Key`.
 - `key` must point to at least 32 readable bytes.
 */
int oxi_aes256_new(OxiAes256Key **out_handle, const uint8_t *key);

/*
 Free an AES-256 key handle. NULL-safe.

 After this call the caller's pointer is dangling; the caller
 SHOULD set their pointer to NULL to avoid use-after-free. A
 double-free of the same non-NULL pointer is undefined behaviour
 (matches malloc/free semantics — the shim cannot detect it).

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_aes256_new`] that has not yet been freed.
 */
void oxi_aes256_free(OxiAes256Key *handle);

/*
 AES-256-GCM authenticated encryption (one-shot).

 Buffer requirements:
 - `iv` — exactly 12 readable bytes (96-bit nonce).
 - `aad` — `aad_len` readable bytes if `aad_len > 0`; may be NULL
   when `aad_len == 0` (per F9).
 - `plaintext` — `pt_len` readable bytes; may be NULL when
   `pt_len == 0`.
 - `ciphertext` — `pt_len` writable bytes.
 - `tag` — exactly 16 writable bytes (128-bit authentication tag).

 Returns `OxiResult::Ok = 0` on success or a non-zero discriminant
 per the [`crate::OxiResult`] mapping. `OxiResult::AlgorithmRestricted = 6`
 is returned when AES-256-GCM is blocked by the active profile.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_gcm_encrypt(const OxiAes256Key *key,
                           const uint8_t *iv,
                           const uint8_t *aad,
                           uintptr_t aad_len,
                           const uint8_t *plaintext,
                           uintptr_t pt_len,
                           uint8_t *ciphertext,
                           uint8_t *tag);

/*
 AES-256-GCM authenticated decryption (one-shot).

 Returns `OxiResult::TagMismatch = 22` on authentication failure.
 On tag mismatch the `plaintext` buffer contents are UNDEFINED —
 the caller MUST NOT use them. (FIPS 140-3 expects the
 implementation to release the plaintext only after successful
 tag verification, but operating-system buffers may have been
 touched during the constant-time tag check; treat the buffer as
 untrusted on any non-Ok return.)

 Buffer requirements identical to [`oxi_aes256_gcm_encrypt`] with
 `ciphertext`/`plaintext` directions swapped and `tag` as input.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_gcm_decrypt(const OxiAes256Key *key,
                           const uint8_t *iv,
                           const uint8_t *aad,
                           uintptr_t aad_len,
                           const uint8_t *ciphertext,
                           uintptr_t ct_len,
                           uint8_t *plaintext,
                           const uint8_t *tag);

/*
 AES-256-CBC encryption (one-shot).

 Buffer requirements:
 - `iv` — exactly 16 readable bytes.
 - `input` — `input_len` readable bytes; must be a positive multiple of 16.
 - `output` — `input_len` writable bytes.

 Returns `OxiResult::NotBlockAligned = 20` when `input_len` is not
 a multiple of 16, `OxiResult::LengthMismatch = 23` when the output
 buffer length doesn't match.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_cbc_encrypt(const OxiAes256Key *key,
                           const uint8_t *iv,
                           const uint8_t *input,
                           uintptr_t input_len,
                           uint8_t *output);

/*
 AES-256-CBC decryption (one-shot).

 Buffer requirements identical to [`oxi_aes256_cbc_encrypt`] with
 input/output directions reversed.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_cbc_decrypt(const OxiAes256Key *key,
                           const uint8_t *iv,
                           const uint8_t *input,
                           uintptr_t input_len,
                           uint8_t *output);

/*
 AES-256-CTR XOR (one-shot).

 Buffer requirements:
 - `icb` — exactly 16 readable bytes (initial counter block).
 - `input` — `len` readable bytes (any length).
 - `output` — `len` writable bytes.

 CTR is symmetric: encrypt and decrypt are the same operation.
 Same `(key, icb)` pair MUST NOT be reused — the caller is
 responsible for nonce uniqueness within a key (SP 800-38A
 Appendix B).

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_ctr(const OxiAes256Key *key,
                   const uint8_t *icb,
                   const uint8_t *input,
                   uintptr_t len,
                   uint8_t *output);

/*
 AES-256-CCM authenticated encryption (one-shot).

 Buffer requirements:
 - `nonce` — `nonce_len` readable bytes; valid range 7..=13 per SP 800-38C.
 - `aad` — `aad_len` readable bytes if `aad_len > 0`; may be NULL
   when `aad_len == 0` (per F9, AAD logically defined by length).
 - `plaintext` — `pt_len` readable bytes; may be NULL when `pt_len == 0`.
 - `tlen` — tag length in bytes; valid set {4, 6, 8, 10, 12, 14, 16}.
 - `out` — exactly `pt_len + tlen` writable bytes; layout `C || T`.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_ccm_encrypt(const OxiAes256Key *key,
                           const uint8_t *nonce,
                           uintptr_t nonce_len,
                           const uint8_t *aad,
                           uintptr_t aad_len,
                           const uint8_t *plaintext,
                           uintptr_t pt_len,
                           uintptr_t tlen,
                           uint8_t *out);

/*
 AES-256-CCM authenticated decryption (one-shot).

 `ciphertext` is the full `C || T` buffer of length
 `ct_len = pt_len + tlen`. On success writes the recovered plaintext
 (length `ct_len - tlen`) into `out`.

 On tag-verification failure returns `OxiResult::TagMismatch = 22`
 and the upstream zeroises the output buffer so unverified plaintext
 is never exposed.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_ccm_decrypt(const OxiAes256Key *key,
                           const uint8_t *nonce,
                           uintptr_t nonce_len,
                           const uint8_t *aad,
                           uintptr_t aad_len,
                           const uint8_t *ciphertext,
                           uintptr_t ct_len,
                           uintptr_t tlen,
                           uint8_t *out);

/*
 CMAC-AES-256 (one-shot).

 Buffer requirements:
 - `msg` — `msg_len` readable bytes; may be NULL when `msg_len == 0`.
 - `tag` — exactly 16 writable bytes.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_cmac(const OxiAes256Key *key, const uint8_t *msg, uintptr_t msg_len, uint8_t *tag);

/*
 AES-256-KW wrap (SP 800-38F §6.2 KW-AE).

 Buffer requirements:
 - `plaintext` — `pt_len` readable bytes; must be a positive
   multiple of 8 and at least 16.
 - `out` — exactly `pt_len + 8` writable bytes.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_kw_wrap(const OxiAes256Key *key,
                       const uint8_t *plaintext,
                       uintptr_t pt_len,
                       uint8_t *out);

/*
 AES-256-KW unwrap (SP 800-38F §6.2 KW-AD).

 Buffer requirements:
 - `ciphertext` — `ct_len` readable bytes; must be a positive
   multiple of 8 and at least 24.
 - `out` — exactly `ct_len - 8` writable bytes.

 Returns `OxiResult::TagMismatch = 22` if the integrity check
 value did not verify.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_kw_unwrap(const OxiAes256Key *key,
                         const uint8_t *ciphertext,
                         uintptr_t ct_len,
                         uint8_t *out);

/*
 AES-256-KWP wrap (SP 800-38F §6.3 KWP-AE / RFC 5649).

 Buffer requirements:
 - `plaintext` — `pt_len` readable bytes; must be `1..=2^32-1`.
 - `out` — exactly `((pt_len + 7) / 8) * 8 + 8` writable bytes
   (padded plaintext + 8-byte AIV).

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_kwp_wrap(const OxiAes256Key *key,
                        const uint8_t *plaintext,
                        uintptr_t pt_len,
                        uint8_t *out);

/*
 AES-256-KWP unwrap (SP 800-38F §6.3 KWP-AD / RFC 5649).

 Buffer requirements:
 - `ciphertext` — `ct_len` readable bytes; must be a positive
   multiple of 8 and at least 16.
 - `out_scratch` — exactly `ct_len - 8` writable bytes (padded
   plaintext buffer; only the first `*out_len` bytes are the
   recovered message after success).
 - `out_len` — pointer to a `size_t` that receives the recovered
   plaintext length (≤ `ct_len - 8`) on success.

 Returns `OxiResult::TagMismatch = 22` on AIV / padding mismatch.
 `*out_len` is unmodified on any non-Ok return.

 # Safety

 All pointer/length pairs must be valid as documented above.
 `key` must be a live handle from [`oxi_aes256_new`].
 */
int oxi_aes256_kwp_unwrap(const OxiAes256Key *key,
                          const uint8_t *ciphertext,
                          uintptr_t ct_len,
                          uint8_t *out_scratch,
                          uintptr_t *out_len);

/*
 Allocate a new, **uninstantiated** HMAC_DRBG-SHA-256 handle.

 On success, writes a heap-allocated handle pointer through
 `out_handle` and returns `OxiResult::Ok = 0`. The caller owns
 the handle and MUST release it with [`oxi_hmac_drbg_sha256_free`].

 The newly-allocated handle is uninstantiated — calling
 [`oxi_hmac_drbg_sha256_generate`] or
 [`oxi_hmac_drbg_sha256_reseed`] before
 [`oxi_hmac_drbg_sha256_instantiate`] returns
 `OxiResult::Uninstantiated = 8`.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHmacDrbgSha256`.
 */
int oxi_hmac_drbg_sha256_new(OxiHmacDrbgSha256 **out_handle);

/*
 Free an HMAC_DRBG-SHA-256 handle. NULL-safe.

 After this call the caller's pointer is dangling; the caller
 SHOULD set their pointer to NULL to avoid use-after-free. A
 double-free of the same non-NULL pointer is undefined behaviour
 (matches malloc/free semantics — the shim cannot detect it).

 Drop on the upstream `HmacDrbgSha256` zeroizes the internal
 `(K, V)` state via the workspace-wide `oxicrypt-zeroize`
 volatile-write convention; no caller-side scrubbing is required.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hmac_drbg_sha256_new`] that has not yet been freed.
 */
void oxi_hmac_drbg_sha256_free(OxiHmacDrbgSha256 *handle);

/*
 HMAC_DRBG-SHA-256 Instantiate (SP 800-90A §10.1.2.3).

 Seeds the DRBG with caller-supplied entropy, nonce, and
 personalization. The combined length
 `entropy_len + nonce_len + perso_len` MUST NOT exceed
 `HMAC_DRBG_MAX_PROVIDED = 768` bytes; over-length returns
 `OxiResult::InvalidInput = 5`.

 Each input may be NULL when its corresponding length is 0.
 Personalization length 0 is the typical path for FIPS-conformant
 callers that don't have a personalization string; entropy and
 nonce SHOULD be sized per SP 800-90A Table 2 (security strength
 256 → entropy ≥ 256 bits, nonce ≥ 128 bits).

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha256_new`].
 */
int oxi_hmac_drbg_sha256_instantiate(OxiHmacDrbgSha256 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 HMAC_DRBG-SHA-256 Reseed (SP 800-90A §10.1.2.4).

 Re-seeds the DRBG with fresh entropy and (optionally) additional
 input. After successful reseed, `reseed_counter` is reset to 1
 and the handle is ready to serve new `generate` calls.

 `additional_input` may be NULL when `additional_input_len` is 0.
 `entropy` MUST point to ≥ `entropy_len` readable bytes.

 Returns `OxiResult::Uninstantiated = 8` if the handle has not yet
 been instantiated. Returns `OxiResult::InvalidInput = 5` if the
 combined `entropy_len + additional_input_len` exceeds
 `HMAC_DRBG_MAX_PROVIDED = 768` bytes.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha256_new`].
 */
int oxi_hmac_drbg_sha256_reseed(OxiHmacDrbgSha256 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 HMAC_DRBG-SHA-256 Generate (SP 800-90A §10.1.2.5).

 Produces `out_len` pseudorandom bytes into `out`, advancing the
 internal `(K, V)` state and incrementing `reseed_counter`.

 `additional_input` may be NULL when `additional_input_len` is 0
 (mapped to upstream `additional_input = None`); a NULL with
 non-zero length returns `OxiResult::NullPointer = 10`.

 Returns `OxiResult::Uninstantiated = 8` if `instantiate` has not
 yet succeeded on this handle. Returns `OxiResult::ReseedRequired = 9`
 if `reseed_counter` has reached the SP 800-90A Table 3 bound; the
 caller MUST call [`oxi_hmac_drbg_sha256_reseed`] before retrying.
 Returns `OxiResult::OutputTooLong = 12` if `out_len` exceeds the
 SP 800-90A Table 3 `max_number_of_bits_per_request` ceiling
 (`2^19` bits = 65 536 bytes).

 # Safety

 `handle` must be a live handle from [`oxi_hmac_drbg_sha256_new`].
 `out` must point to ≥ `out_len` writable bytes (or `out_len == 0`,
 in which case the call is a no-op state advance — useful only as
 part of a `reseed`-then-`generate(None, [])` PR equivalence).
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hmac_drbg_sha256_generate(OxiHmacDrbgSha256 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated HMAC_DRBG-SHA-384 handle. See
 [`oxi_hmac_drbg_sha256_new`] for full contract.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHmacDrbgSha384`.
 */
int oxi_hmac_drbg_sha384_new(OxiHmacDrbgSha384 **out_handle);

/*
 Free an HMAC_DRBG-SHA-384 handle. NULL-safe. See
 [`oxi_hmac_drbg_sha256_free`] for zeroization semantics.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hmac_drbg_sha384_new`] that has not yet been freed.
 */
void oxi_hmac_drbg_sha384_free(OxiHmacDrbgSha384 *handle);

/*
 HMAC_DRBG-SHA-384 Instantiate (SP 800-90A §10.1.2.3). See
 [`oxi_hmac_drbg_sha256_instantiate`] for full contract; the
 `entropy_len + nonce_len + perso_len` ceiling is the same upstream
 `HMAC_DRBG_MAX_PROVIDED = 768` bytes (alg-independent constant).
 Per SP 800-90A Table 2, security strength 192 → entropy ≥ 192
 bits, nonce ≥ 96 bits.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha384_new`].
 */
int oxi_hmac_drbg_sha384_instantiate(OxiHmacDrbgSha384 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 HMAC_DRBG-SHA-384 Reseed (SP 800-90A §10.1.2.4). See
 [`oxi_hmac_drbg_sha256_reseed`] for full contract.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha384_new`].
 */
int oxi_hmac_drbg_sha384_reseed(OxiHmacDrbgSha384 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 HMAC_DRBG-SHA-384 Generate (SP 800-90A §10.1.2.5). See
 [`oxi_hmac_drbg_sha256_generate`] for full contract; the
 `out_len` ceiling is the alg-independent
 `max_number_of_bits_per_request` = `2^19` bits = 65 536 bytes.

 # Safety

 `handle` must be a live handle from [`oxi_hmac_drbg_sha384_new`].
 `out` must point to ≥ `out_len` writable bytes.
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hmac_drbg_sha384_generate(OxiHmacDrbgSha384 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated HMAC_DRBG-SHA-512 handle. See
 [`oxi_hmac_drbg_sha256_new`] for full contract.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHmacDrbgSha512`.
 */
int oxi_hmac_drbg_sha512_new(OxiHmacDrbgSha512 **out_handle);

/*
 Free an HMAC_DRBG-SHA-512 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hmac_drbg_sha512_new`] that has not yet been freed.
 */
void oxi_hmac_drbg_sha512_free(OxiHmacDrbgSha512 *handle);

/*
 HMAC_DRBG-SHA-512 Instantiate (SP 800-90A §10.1.2.3). See
 [`oxi_hmac_drbg_sha256_instantiate`] for full contract. Per
 SP 800-90A Table 2, security strength 256 → entropy ≥ 256 bits,
 nonce ≥ 128 bits — same as SHA-256 but with a wider internal
 `(K, V)` of 64 bytes each.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha512_new`].
 */
int oxi_hmac_drbg_sha512_instantiate(OxiHmacDrbgSha512 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 HMAC_DRBG-SHA-512 Reseed (SP 800-90A §10.1.2.4). See
 [`oxi_hmac_drbg_sha256_reseed`].

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hmac_drbg_sha512_new`].
 */
int oxi_hmac_drbg_sha512_reseed(OxiHmacDrbgSha512 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 HMAC_DRBG-SHA-512 Generate (SP 800-90A §10.1.2.5). See
 [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be a live handle from [`oxi_hmac_drbg_sha512_new`].
 `out` must point to ≥ `out_len` writable bytes.
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hmac_drbg_sha512_generate(OxiHmacDrbgSha512 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated Hash_DRBG-SHA-256 handle. See
 [`oxi_hmac_drbg_sha256_new`] for full contract.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHashDrbgSha256`.
 */
int oxi_hash_drbg_sha256_new(OxiHashDrbgSha256 **out_handle);

/*
 Free a Hash_DRBG-SHA-256 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hash_drbg_sha256_new`] that has not yet been freed.
 */
void oxi_hash_drbg_sha256_free(OxiHashDrbgSha256 *handle);

/*
 Hash_DRBG-SHA-256 Instantiate (SP 800-90A §10.1.1.2). See
 [`oxi_hmac_drbg_sha256_instantiate`] for full contract; per
 SP 800-90A Table 2, security strength 256 → entropy ≥ 256 bits,
 nonce ≥ 128 bits. Combined-input ceiling is the alg-independent
 `HASH_DRBG_MAX_DF_INPUT` upstream constant.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha256_new`].
 */
int oxi_hash_drbg_sha256_instantiate(OxiHashDrbgSha256 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 Hash_DRBG-SHA-256 Reseed (SP 800-90A §10.1.1.3). See
 [`oxi_hmac_drbg_sha256_reseed`].

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha256_new`].
 */
int oxi_hash_drbg_sha256_reseed(OxiHashDrbgSha256 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 Hash_DRBG-SHA-256 Generate (SP 800-90A §10.1.1.4). See
 [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be a live handle from [`oxi_hash_drbg_sha256_new`].
 `out` must point to ≥ `out_len` writable bytes.
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hash_drbg_sha256_generate(OxiHashDrbgSha256 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated Hash_DRBG-SHA-384 handle.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHashDrbgSha384`.
 */
int oxi_hash_drbg_sha384_new(OxiHashDrbgSha384 **out_handle);

/*
 Free a Hash_DRBG-SHA-384 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hash_drbg_sha384_new`] that has not yet been freed.
 */
void oxi_hash_drbg_sha384_free(OxiHashDrbgSha384 *handle);

/*
 Hash_DRBG-SHA-384 Instantiate. Per SP 800-90A Table 2, security
 strength 192 → entropy ≥ 192 bits, nonce ≥ 96 bits.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha384_new`].
 */
int oxi_hash_drbg_sha384_instantiate(OxiHashDrbgSha384 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 Hash_DRBG-SHA-384 Reseed.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha384_new`].
 */
int oxi_hash_drbg_sha384_reseed(OxiHashDrbgSha384 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 Hash_DRBG-SHA-384 Generate.

 # Safety

 `handle` must be a live handle from [`oxi_hash_drbg_sha384_new`].
 `out` must point to ≥ `out_len` writable bytes.
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hash_drbg_sha384_generate(OxiHashDrbgSha384 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated Hash_DRBG-SHA-512 handle.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiHashDrbgSha512`.
 */
int oxi_hash_drbg_sha512_new(OxiHashDrbgSha512 **out_handle);

/*
 Free a Hash_DRBG-SHA-512 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hash_drbg_sha512_new`] that has not yet been freed.
 */
void oxi_hash_drbg_sha512_free(OxiHashDrbgSha512 *handle);

/*
 Hash_DRBG-SHA-512 Instantiate. Per SP 800-90A Table 2, security
 strength 256 → entropy ≥ 256 bits, nonce ≥ 128 bits.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha512_new`].
 */
int oxi_hash_drbg_sha512_instantiate(OxiHashDrbgSha512 *handle,
                                     const uint8_t *entropy,
                                     uintptr_t entropy_len,
                                     const uint8_t *nonce,
                                     uintptr_t nonce_len,
                                     const uint8_t *personalization,
                                     uintptr_t personalization_len);

/*
 Hash_DRBG-SHA-512 Reseed.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_hash_drbg_sha512_new`].
 */
int oxi_hash_drbg_sha512_reseed(OxiHashDrbgSha512 *handle,
                                const uint8_t *entropy,
                                uintptr_t entropy_len,
                                const uint8_t *additional_input,
                                uintptr_t additional_input_len);

/*
 Hash_DRBG-SHA-512 Generate.

 # Safety

 `handle` must be a live handle from [`oxi_hash_drbg_sha512_new`].
 `out` must point to ≥ `out_len` writable bytes.
 `additional_input` must point to ≥ `additional_input_len`
 readable bytes when `additional_input_len > 0`.
 */
int oxi_hash_drbg_sha512_generate(OxiHashDrbgSha512 *handle,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len,
                                  uint8_t *out,
                                  uintptr_t out_len);

/*
 Allocate a new, uninstantiated CTR_DRBG-AES-128 handle. Caller
 must subsequently call exactly one of
 [`oxi_ctr_drbg_aes128_instantiate_no_df`] or
 [`oxi_ctr_drbg_aes128_instantiate_df`] before generate / reseed
 becomes operational.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiCtrDrbgAes128`.
 */
int oxi_ctr_drbg_aes128_new(OxiCtrDrbgAes128 **out_handle);

/*
 Free a CTR_DRBG-AES-128 handle. NULL-safe. Drop on the upstream
 `CtrDrbgAes128` zeroizes the internal `(Key, V, reseed_counter)`
 state via `oxicrypt-zeroize`.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_ctr_drbg_aes128_new`] that has not yet been freed.
 */
void oxi_ctr_drbg_aes128_free(OxiCtrDrbgAes128 *handle);

/*
 CTR_DRBG-AES-128 Instantiate, **no-df** variant (SP 800-90A
 §10.2.1.3.1). `seed_material` MUST be exactly `SEED_LEN` = 32
 bytes (= AES-128 key length 16 + AES block size 16) and MUST
 equal `entropy_input || personalization_string` per the spec's
 no-df construction. Seed-length mismatch returns
 `OxiResult::InvalidInput = 5` — there is no auto-extend or
 auto-truncate at the FFI boundary.

 # Safety

 `handle` must be a live handle from
 [`oxi_ctr_drbg_aes128_new`]. `seed_material` must point to ≥
 `seed_material_len` readable bytes.
 */
int oxi_ctr_drbg_aes128_instantiate_no_df(OxiCtrDrbgAes128 *handle,
                                          const uint8_t *seed_material,
                                          uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-128 Instantiate, **df** variant (SP 800-90A
 §10.2.1.3.2). Runs `Block_Cipher_df(entropy || nonce ||
 personalization, seedlen)` to derive the initial seed material.
 Combined-length ceiling is `MAX_DF_INPUT` (alg-independent).
 Each input may be NULL when its length is 0. Per SP 800-90A
 Table 3, security strength 128 → entropy ≥ 128 bits, nonce ≥
 64 bits.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_ctr_drbg_aes128_new`].
 */
int oxi_ctr_drbg_aes128_instantiate_df(OxiCtrDrbgAes128 *handle,
                                       const uint8_t *entropy,
                                       uintptr_t entropy_len,
                                       const uint8_t *nonce,
                                       uintptr_t nonce_len,
                                       const uint8_t *personalization,
                                       uintptr_t personalization_len);

/*
 CTR_DRBG-AES-128 Reseed, **no-df** variant (SP 800-90A
 §10.2.1.4.1). `seed_material` MUST be exactly `SEED_LEN` = 32
 bytes; mismatch returns `OxiResult::InvalidInput = 5`.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes128_new`].
 */
int oxi_ctr_drbg_aes128_reseed_no_df(OxiCtrDrbgAes128 *handle,
                                     const uint8_t *seed_material,
                                     uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-128 Reseed, **df** variant (SP 800-90A §10.2.1.4.2).
 Runs `Block_Cipher_df(entropy || additional_input, seedlen)` to
 derive the new seed. Combined-length ceiling is `MAX_DF_INPUT`.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes128_new`].
 */
int oxi_ctr_drbg_aes128_reseed_df(OxiCtrDrbgAes128 *handle,
                                  const uint8_t *entropy,
                                  uintptr_t entropy_len,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len);

/*
 CTR_DRBG-AES-128 Generate, **no-df** variant (SP 800-90A
 §10.2.1.5.1). When `additional_input` is supplied (non-NULL +
 non-zero len), it MUST be exactly `SEED_LEN` = 32 bytes — this
 constraint is what makes this the no-df path; `additional_input
 = NULL, len = 0` is the typical no-AI call. `out_len` is bounded
 by `2^16` bytes (SP 800-90A §10.2.1.5.1 step 5).

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes128_new`]. `out` must point to ≥ `out_len`
 writable bytes (or `out_len == 0`).
 */
int oxi_ctr_drbg_aes128_generate_no_df(OxiCtrDrbgAes128 *handle,
                                       const uint8_t *additional_input,
                                       uintptr_t additional_input_len,
                                       uint8_t *out,
                                       uintptr_t out_len);

/*
 CTR_DRBG-AES-128 Generate, **df** variant (SP 800-90A
 §10.2.1.5.2). `additional_input` is variable length up to
 `MAX_DF_INPUT` and is passed through `Block_Cipher_df` before
 being mixed in. NULL+0 is the no-AI call; NULL with non-zero
 length returns `OxiResult::NullPointer = 10`. `out_len` is
 bounded by `2^16` bytes.

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes128_new`]. `out` must point to ≥ `out_len`
 writable bytes. `additional_input` must point to ≥
 `additional_input_len` readable bytes when
 `additional_input_len > 0`.
 */
int oxi_ctr_drbg_aes128_generate_df(OxiCtrDrbgAes128 *handle,
                                    const uint8_t *additional_input,
                                    uintptr_t additional_input_len,
                                    uint8_t *out,
                                    uintptr_t out_len);

/*
 Allocate a new, uninstantiated CTR_DRBG-AES-192 handle. See
 [`oxi_ctr_drbg_aes128_new`].

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiCtrDrbgAes192`.
 */
int oxi_ctr_drbg_aes192_new(OxiCtrDrbgAes192 **out_handle);

/*
 Free a CTR_DRBG-AES-192 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_ctr_drbg_aes192_new`] that has not yet been freed.
 */
void oxi_ctr_drbg_aes192_free(OxiCtrDrbgAes192 *handle);

/*
 CTR_DRBG-AES-192 Instantiate, no-df variant. `seed_material` must
 be exactly `SEED_LEN` = 40 bytes (AES-192 key 24 + AES block 16).
 See [`oxi_ctr_drbg_aes128_instantiate_no_df`].

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_ctr_drbg_aes192_new`].
 */
int oxi_ctr_drbg_aes192_instantiate_no_df(OxiCtrDrbgAes192 *handle,
                                          const uint8_t *seed_material,
                                          uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-192 Instantiate, df variant. Per SP 800-90A Table 3,
 security strength 192 → entropy ≥ 192 bits, nonce ≥ 96 bits. See
 [`oxi_ctr_drbg_aes128_instantiate_df`].

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_ctr_drbg_aes192_new`].
 */
int oxi_ctr_drbg_aes192_instantiate_df(OxiCtrDrbgAes192 *handle,
                                       const uint8_t *entropy,
                                       uintptr_t entropy_len,
                                       const uint8_t *nonce,
                                       uintptr_t nonce_len,
                                       const uint8_t *personalization,
                                       uintptr_t personalization_len);

/*
 CTR_DRBG-AES-192 Reseed, no-df. `seed_material` must be exactly
 40 bytes.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes192_new`].
 */
int oxi_ctr_drbg_aes192_reseed_no_df(OxiCtrDrbgAes192 *handle,
                                     const uint8_t *seed_material,
                                     uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-192 Reseed, df.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes192_new`].
 */
int oxi_ctr_drbg_aes192_reseed_df(OxiCtrDrbgAes192 *handle,
                                  const uint8_t *entropy,
                                  uintptr_t entropy_len,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len);

/*
 CTR_DRBG-AES-192 Generate, no-df. When `additional_input` is
 supplied it MUST be exactly 40 bytes.

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes192_new`]. `out` must point to ≥ `out_len`
 writable bytes.
 */
int oxi_ctr_drbg_aes192_generate_no_df(OxiCtrDrbgAes192 *handle,
                                       const uint8_t *additional_input,
                                       uintptr_t additional_input_len,
                                       uint8_t *out,
                                       uintptr_t out_len);

/*
 CTR_DRBG-AES-192 Generate, df. `additional_input` is variable up
 to `MAX_DF_INPUT`.

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes192_new`]. `out` must point to ≥ `out_len`
 writable bytes. `additional_input` must point to ≥
 `additional_input_len` readable bytes when
 `additional_input_len > 0`.
 */
int oxi_ctr_drbg_aes192_generate_df(OxiCtrDrbgAes192 *handle,
                                    const uint8_t *additional_input,
                                    uintptr_t additional_input_len,
                                    uint8_t *out,
                                    uintptr_t out_len);

/*
 Allocate a new, uninstantiated CTR_DRBG-AES-256 handle.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiCtrDrbgAes256`.
 */
int oxi_ctr_drbg_aes256_new(OxiCtrDrbgAes256 **out_handle);

/*
 Free a CTR_DRBG-AES-256 handle. NULL-safe.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_ctr_drbg_aes256_new`] that has not yet been freed.
 */
void oxi_ctr_drbg_aes256_free(OxiCtrDrbgAes256 *handle);

/*
 CTR_DRBG-AES-256 Instantiate, no-df. `seed_material` must be
 exactly `SEED_LEN` = 48 bytes (AES-256 key 32 + AES block 16).

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_ctr_drbg_aes256_new`].
 */
int oxi_ctr_drbg_aes256_instantiate_no_df(OxiCtrDrbgAes256 *handle,
                                          const uint8_t *seed_material,
                                          uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-256 Instantiate, df. Per SP 800-90A Table 3,
 security strength 256 → entropy ≥ 256 bits, nonce ≥ 128 bits.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live
 handle from [`oxi_ctr_drbg_aes256_new`].
 */
int oxi_ctr_drbg_aes256_instantiate_df(OxiCtrDrbgAes256 *handle,
                                       const uint8_t *entropy,
                                       uintptr_t entropy_len,
                                       const uint8_t *nonce,
                                       uintptr_t nonce_len,
                                       const uint8_t *personalization,
                                       uintptr_t personalization_len);

/*
 CTR_DRBG-AES-256 Reseed, no-df. `seed_material` must be exactly
 48 bytes.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes256_new`].
 */
int oxi_ctr_drbg_aes256_reseed_no_df(OxiCtrDrbgAes256 *handle,
                                     const uint8_t *seed_material,
                                     uintptr_t seed_material_len);

/*
 CTR_DRBG-AES-256 Reseed, df.

 # Safety

 All pointer/length pairs must be valid. `handle` must be a live,
 instantiated handle from [`oxi_ctr_drbg_aes256_new`].
 */
int oxi_ctr_drbg_aes256_reseed_df(OxiCtrDrbgAes256 *handle,
                                  const uint8_t *entropy,
                                  uintptr_t entropy_len,
                                  const uint8_t *additional_input,
                                  uintptr_t additional_input_len);

/*
 CTR_DRBG-AES-256 Generate, no-df. When `additional_input` is
 supplied it MUST be exactly 48 bytes.

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes256_new`]. `out` must point to ≥ `out_len`
 writable bytes.
 */
int oxi_ctr_drbg_aes256_generate_no_df(OxiCtrDrbgAes256 *handle,
                                       const uint8_t *additional_input,
                                       uintptr_t additional_input_len,
                                       uint8_t *out,
                                       uintptr_t out_len);

/*
 CTR_DRBG-AES-256 Generate, df. `additional_input` is variable up
 to `MAX_DF_INPUT`.

 # Safety

 `handle` must be a live, instantiated handle from
 [`oxi_ctr_drbg_aes256_new`]. `out` must point to ≥ `out_len`
 writable bytes. `additional_input` must point to ≥
 `additional_input_len` readable bytes when
 `additional_input_len > 0`.
 */
int oxi_ctr_drbg_aes256_generate_df(OxiCtrDrbgAes256 *handle,
                                    const uint8_t *additional_input,
                                    uintptr_t additional_input_len,
                                    uint8_t *out,
                                    uintptr_t out_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* OXICRYPT_H */
