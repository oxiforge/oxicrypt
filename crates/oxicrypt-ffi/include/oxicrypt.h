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

/*
 Opaque AES-256 key handle. The internal layout
 (`OxiHandle<Aes256Key>`) is implementation detail and not part
 of the C ABI; cbindgen renders this as an opaque struct.

 */
typedef struct OxiAes256Key OxiAes256Key;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 Initialise the FIPS module with the given algorithm profile,
 running all power-up KATs.

 `profile` selects the algorithm-restriction level:

 - `0` — Unrestricted (all approved algorithms available)
 - `1` — CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87,
   LMS, XMSS)
 - `2` — CNSA 1.0 (AES-256, SHA-256+, P-384, RSA ≥ 3072, DH ≥ 3072)

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
 per the [`OxiResult`] mapping. `OxiResult::AlgorithmRestricted = 6`
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

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* OXICRYPT_H */
