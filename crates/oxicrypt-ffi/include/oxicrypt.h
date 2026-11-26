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
 * Buffer contract of every oxi_aes_* function.
 *
 * In an operational module, every oxi_aes_* function that returns int
 * refuses its pointer and length arguments as follows, before any work:
 *
 * - a NULL key handle, a NULL pointer with a non-zero length, or a NULL
 *   fixed-size pointer (an IV, counter, tag, MAC, `written`, the DRBG
 *   handle, or the `out` of a `_key_new` or `_key_invocations`) returns
 *   OXI_RESULT_NULL_POINTER (10);
 * - a length above SIZE_MAX / 2, or a range that runs past the top of the
 *   address space, returns OXI_RESULT_INVALID_INPUT (5);
 * - an output range that shares a byte with an input, with another output
 *   or with a handle, and an input that shares a byte with a handle,
 *   return OXI_RESULT_INVALID_INPUT (5), so in-place operation is refused;
 * - a key handle of another mode returns OXI_RESULT_INVALID_INPUT (5).
 *
 * A module not in the operational state returns OXI_RESULT_NOT_OPERATIONAL
 * (1) after the NULL key handle and NULL output-pointer checks and before
 * the other pointer checks.
 *
 * On any refusal every output buffer is left unwritten, except that when a
 * function has several outputs and a later copy is refused, the outputs
 * already copied are zeroed. On a KW or KWP
 * unwrap failure, in either cipher direction, `out` and `written` are left
 * unwritten.
 */


/*
 C ABI status code returned by every `oxi_*` function that returns an `int`
 status: `Ok = 0` is success, and non-zero values are distinct failure
 modes.

 Four functions return a value of their own instead, never an `OxiResult`:
 `oxi_abi_version` (the ABI number), `oxi_active_profile` (a profile code),
 `oxi_is_operational` (1 or 0) and `oxi_integrity_status` (the integrity
 indicator). `lama_manifest` returns a string, and the `_free` functions
 return nothing.
 Layout is fixed (`#[repr(C)]`) so the C-side typedef has stable
 discriminants across cbindgen regenerations.
 */
typedef enum {
  /*
   Operation succeeded.
   */
  OXI_RESULT_OK = 0,
  /*
   Module not in `Operational` state — call `oxi_init` first.
   */
  OXI_RESULT_NOT_OPERATIONAL = 1,
  /*
   Power-up self-test failed during init. Module is in terminal `Error` state.
   */
  OXI_RESULT_SELF_TEST_FAILED = 2,
  /*
   Conditional self-test failed during operation (e.g. DRBG CRNGT, pairwise consistency).
   */
  OXI_RESULT_CONDITIONAL_TEST_FAILED = 3,
  /*
   `oxi_init` called more than once. The first init's outcome is authoritative.
   */
  OXI_RESULT_ALREADY_INITIALIZED = 4,
  /*
   Cryptographic input was not a valid domain element (invalid scalar, point not on curve, etc.).
   */
  OXI_RESULT_INVALID_INPUT = 5,
  /*
   Service blocked by the active algorithm profile. Requires process restart with different profile.
   */
  OXI_RESULT_ALGORITHM_RESTRICTED = 6,
  /*
   Service exists in the `Service` enum but its implementation is not yet built (stub crate).
   */
  OXI_RESULT_NOT_IMPLEMENTED = 7,
  /*
   `generate` (or `reseed`) called before `instantiate` succeeded on this DRBG handle.
   */
  OXI_RESULT_UNINSTANTIATED = 8,
  /*
   The DRBG's reseed counter passed the SP 800-90A Table 3 reseed
   interval and the DRBG cannot reseed itself. No exported function
   returns it at ABI 3: every C DRBG handle is seeded by the module and
   reseeds itself at the interval. It is returned by `generate` on an
   `oxicrypt_drbg` instance instantiated through the testing interface
   with a caller-supplied entropy input, which does not reseed itself at
   the interval.
   */
  OXI_RESULT_RESEED_REQUIRED = 9,
  /*
   Caller passed a NULL pointer where one is required.
   */
  OXI_RESULT_NULL_POINTER = 10,
  /*
   Caller-allocated output buffer is smaller than the documented minimum.
   */
  OXI_RESULT_BUFFER_TOO_SMALL = 11,
  /*
   Output bound exceeded. Reused across families: HKDF-Expand requested more than
   `255 * HashLen` bytes (RFC 5869 §2.3); HMAC_DRBG `generate` requested more than
   `2^19` bits (SP 800-90A Table 3 `max_number_of_bits_per_request`). Same
   cross-family-discriminant-reuse pattern as `TagMismatch = 22`: one code, multiple
   upstream sources, all sharing the same caller-recovery semantic ("ask for less").
   */
  OXI_RESULT_OUTPUT_TOO_LONG = 12,
  /*
   Input length is not aligned to the cipher block size (where required).
   */
  OXI_RESULT_NOT_BLOCK_ALIGNED = 20,
  /*
   IV length doesn't match the mode's specification (e.g. GCM requires exactly 12 bytes).
   */
  OXI_RESULT_INVALID_IV_LENGTH = 21,
  /*
   Cryptographic verification mismatched.

   Covers BOTH AEAD tag verification (AES-GCM, AES-CCM, AES-KW, AES-KWP)
   AND signature verification (ECDSA `Ok(false)` from FIPS 186-5 §6.4.2,
   and the other `_verify` functions). The semantic is uniform: "the
   cryptographic verification primitive ran cleanly but the result
   disagrees with the claimed value." Distinct from
   [`OxiResult::InvalidInput`] (= 5), which signals input that failed
   to decode BEFORE any cryptographic comparison. The AES mode
   symbols write no output when they return this code.
   */
  OXI_RESULT_TAG_MISMATCH = 22,
  /*
   Input/output buffer length pair is mismatched (e.g. plaintext.len() != ciphertext.len()).
   */
  OXI_RESULT_LENGTH_MISMATCH = 23,
  /*
   Nonce length doesn't match the mode's specification.
   */
  OXI_RESULT_INVALID_NONCE_LENGTH = 24,
  /*
   Tag length doesn't match the mode's specification.
   */
  OXI_RESULT_INVALID_TAG_LENGTH = 25,
  /*
   Payload length exceeds the mode's allowed maximum.
   */
  OXI_RESULT_INVALID_PAYLOAD_LENGTH = 26,
  /*
   AAD length exceeds the mode's allowed maximum.
   */
  OXI_RESULT_INVALID_AAD_LENGTH = 27,
  /*
   The module was initialised without the pre-operational software
   integrity test, so it was never verified against its integrity
   signature. Distinct from `SelfTestFailed`: no test failed, none ran.
   */
  OXI_RESULT_INTEGRITY_UNVERIFIED = 28,
  /*
   A DRBG instantiate or reseed was given an entropy input shorter than
   the minimum for the instantiated security strength (SP 800-90A Rev. 1
   Tables 2 and 3). No exported function returns it at ABI 3: the C
   interface takes no entropy input, and the module's seed path supplies
   a full-length one. It is returned by the `oxicrypt_drbg` testing
   interface's caller-entropy forms: HMAC_DRBG and Hash_DRBG
   `instantiate` and `reseed`, and CTR_DRBG `instantiate_df` and
   `reseed_df`. Distinct from `InvalidInput = 5`, which an over-long
   input returns, as does CTR_DRBG `instantiate_no_df` or `reseed_no_df`
   seed material that is not exactly `seedlen` bytes.
   */
  OXI_RESULT_ENTROPY_INPUT_TOO_SHORT = 29,
  /*
   A DRBG instantiate was given a nonce shorter than half the
   instantiated security strength, the module's nonce floor
   (permitted by SP 800-90A Rev. 1 §9.1 step 8; a shorter nonce that
   would meet only the uniqueness condition of §8.6.7 is refused). No
   exported function returns it at ABI 3: the C interface takes no
   nonce, and the module's seed path supplies a full-length one. It is
   returned by the `oxicrypt_drbg` testing interface's caller-nonce
   forms: HMAC_DRBG and Hash_DRBG `instantiate`, and CTR_DRBG
   `instantiate_df`.
   */
  OXI_RESULT_NONCE_TOO_SHORT = 30,
  /*
   The random bit generator handed to a service has a security strength
   below what that service requires. Pass a DRBG of a higher strength.
   */
  OXI_RESULT_RBG_TOO_WEAK = 31,
  /*
   The DRBG handle is in use by another call, or the module's seed path
   was held by another thread for longer than its wait bound. Nothing
   was changed; retry after a pause.
   */
  OXI_RESULT_BUSY = 32,
  /*
   The entropy source failed while seeding or testing. The module has
   entered its error state, and every later service returns
   `NotOperational = 1` until the process restarts.
   */
  OXI_RESULT_ENTROPY_UNAVAILABLE = 33,
  /*
   The key has reached the number of invocations its mode permits under
   one key (2^32 AES-GCM encryptions, SP 800-38D §8.3; 2^61 AES-CCM
   block-cipher invocations, SP 800-38C §5.1). Nothing was written and
   no IV was generated; the key stays exhausted, so establish a new key.
   */
  OXI_RESULT_KEY_EXHAUSTED = 34,
  /*
   Catch-all for "should-never-happen" cases, including an error variant
   this mapping does not name.
   */
  OXI_RESULT_INTERNAL = 255,
} OxiResult;

/*
 Opaque AES-CBC key handle: a key of 16, 24 or 32 bytes. Built by
 [`oxi_aes_cbc_key_new`], released by [`oxi_aes_cbc_key_free`], and
 refused with `InvalidInput = 5` by the symbols of every other mode,
 which read the allocation's leading `OxiKeyHeader` (a mode kind and a
 magic the module writes at construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and no call
 changes any state through it. [`oxi_aes_cbc_key_free`] alone requires
 that no other thread is using the handle.
 */
typedef struct OxiAesCbcKey OxiAesCbcKey;

/*
 Opaque AES-CCM key handle: a key of 16, 24 or 32 bytes, its tag length
 and its count of block-cipher invocations. Built by the
 `oxi_aes_ccm_key_new` functions, released by [`oxi_aes_ccm_key_free`],
 and refused with `InvalidInput = 5` by the symbols of every other mode,
 which read the allocation's leading `OxiKeyHeader` (a mode kind and a
 magic the module writes at construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and the only
 state a call changes through it is the CCM invocation count, which is
 atomic. [`oxi_aes_ccm_key_free`] alone requires that no other thread is
 using the handle.
 */
typedef struct OxiAesCcmKey OxiAesCcmKey;

/*
 Opaque CMAC key handle: a key of 16, 24 or 32 bytes and its MAC length.
 Built by [`oxi_aes_cmac_key_new`], released by [`oxi_aes_cmac_key_free`],
 and refused with `InvalidInput = 5` by the symbols of every other mode,
 which read the allocation's leading `OxiKeyHeader` (a mode kind and a
 magic the module writes at construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and no call
 changes any state through it. [`oxi_aes_cmac_key_free`] alone requires
 that no other thread is using the handle.
 */
typedef struct OxiAesCmacKey OxiAesCmacKey;

/*
 Opaque AES-CTR key handle: a key of 16, 24 or 32 bytes. Built by
 [`oxi_aes_ctr_key_new`], released by [`oxi_aes_ctr_key_free`], and
 refused with `InvalidInput = 5` by the symbols of every other mode,
 which read the allocation's leading `OxiKeyHeader` (a mode kind and a
 magic the module writes at construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and no call
 changes any state through it. [`oxi_aes_ctr_key_free`] alone requires
 that no other thread is using the handle.
 */
typedef struct OxiAesCtrKey OxiAesCtrKey;

/*
 Opaque AES-GCM key handle: a key of 16, 24 or 32 bytes and its count of
 encryptions. Built by the `oxi_aes_gcm_key_new` functions, released by
 [`oxi_aes_gcm_key_free`], and refused with `InvalidInput = 5` by the
 symbols of every other mode, which read the allocation's leading
 `OxiKeyHeader` (a mode kind and a magic the module writes at
 construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and the only
 state a call changes through it is the GCM invocation count, which is
 atomic. [`oxi_aes_gcm_key_free`] alone requires that no other thread is
 using the handle.
 */
typedef struct OxiAesGcmKey OxiAesGcmKey;

/*
 Opaque AES key-wrap key handle: a key of 16, 24 or 32 bytes for KW and
 KWP, in both the forward and the inverse-cipher variants. Built by
 [`oxi_aes_kw_key_new`], released by [`oxi_aes_kw_key_free`], and refused
 with `InvalidInput = 5` by the symbols of every other mode, which read
 the allocation's leading `OxiKeyHeader` (a mode kind and a magic the
 module writes at construction) before any typed access.

 Any number of threads may call the mode's functions with the same handle
 at the same time: every function takes the handle shared, and no call
 changes any state through it. [`oxi_aes_kw_key_free`] alone requires
 that no other thread is using the handle.
 */
typedef struct OxiAesKwKey OxiAesKwKey;

/*
 Opaque CTR_DRBG-AES-128 handle. See `OxiHmacDrbgSha256` for the
 per-call-mutating thread-safety and Drop-zeroize contract.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiCtrDrbgAes128 OxiCtrDrbgAes128;

/*
 Opaque CTR_DRBG-AES-192 handle. See `OxiCtrDrbgAes128`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiCtrDrbgAes192 OxiCtrDrbgAes192;

/*
 Opaque CTR_DRBG-AES-256 handle. See `OxiCtrDrbgAes128`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiCtrDrbgAes256 OxiCtrDrbgAes256;

/*
 Opaque handle to one of the nine SP 800-90A DRBGs, seeded by the module.

 After fork, the child inherits a copy of every handle. The copy is refused in the child with
 `InvalidInput = 5` until the child either constructs a new handle or re-instantiates the
 inherited one with `oxi_drbg_instantiate`, so parent and child never produce the same output.
 One thread of the child takes the inherited handle over; another thread calling on it
 meanwhile receives `Busy = 32`. If the re-instantiation fails, the handle holds no state
 from the parent and returns `Uninstantiated = 8` until it is instantiated. The check
 compares the caller's process id with the one recorded at instantiation and with the one
 recorded by the call holding the handle, so a handle a parent thread was instantiating
 for the first time at the fork is inherited too. A process id reused after the parent
 exits is not detected.

 A call that finds the handle in use by another call of this process returns `Busy = 32` and
 changes nothing: retry after a pause. A hold inherited from a thread of the parent is not
 `Busy`: `oxi_drbg_instantiate` takes the handle over in every case. Calls on one handle from
 several threads are otherwise safe.

 Calling `oxi_drbg_free` on a handle another thread is using is undefined behaviour, as for
 every handle.

 */
typedef struct OxiDrbg OxiDrbg;

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

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHashDrbgSha256 OxiHashDrbgSha256;

/*
 Opaque Hash_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHashDrbgSha384 OxiHashDrbgSha384;

/*
 Opaque Hash_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHashDrbgSha512 OxiHashDrbgSha512;

/*
 Opaque HMAC_DRBG-SHA-256 handle. The internal layout
 (`OxiHandle<HmacDrbgSha256>`) is implementation detail and not
 part of the C ABI; cbindgen renders this as an opaque struct.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHmacDrbgSha256 OxiHmacDrbgSha256;

/*
 Opaque HMAC_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHmacDrbgSha384 OxiHmacDrbgSha384;

/*
 Opaque HMAC_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.

 The handle is seeded by the module: `_instantiate_from_module` draws its
 entropy input and nonce from the module's seed path, and the DRBG reseeds
 itself from the same path at the SP 800-90A reseed interval. A forked
 child inherits a copy that returns `InvalidInput = 5` until the child
 re-instantiates it with `_instantiate_from_module`. The handle has no
 busy flag: callers serialise all calls on one handle.

 */
typedef struct OxiHmacDrbgSha512 OxiHmacDrbgSha512;

/*
 Opaque RSA-2048 private-key handle that has passed an IG 10.3.A
 pairwise consistency test at construction time. Mirrors the
 `OxiEcdsaP256PrivateKey` pattern: its only constructor runs the
 PCT, so no handle exists that has not passed it.

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
 Return the ABI number of this C interface.

 The number is independent of the release version. It changes only when
 the interface breaks compatibility (a function removed, a parameter or
 return type changed, or an output size changed) and never when functions
 are added. Compatibility within a number runs one way: a library returning
 N serves a caller built against an earlier release of ABI N, but a caller
 that uses a function added later in ABI N cannot load an older library of
 the same number, which lacks it. The library's `SONAME` on Linux
 (`liboxicrypt_ffi.so.<N>`) and its macOS install name follow the number;
 Android keeps the plain `liboxicrypt_ffi.so`.

 A query about the interface, not a service: it requires no
 initialisation and is callable before [`oxi_init`] and in any module
 state. A library that predates this function does not export it.

 # Safety

 No pointers; always safe to call.
 */
int oxi_abi_version(void);

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
 performing initialisation, rather than silently defaulting an unknown
 code to a profile.

 Initialisation happens once per process, and **the first init's
 outcome is authoritative**. A later call runs no self-test and
 returns that outcome: [`OxiResult::Ok`] if the first call succeeded,
 and [`OxiResult::NotOperational`] if it failed, because a failed
 initialisation is terminal until the process restarts. The active
 profile is the one the first successful call selected; a later call
 passing a *different* profile selector is accepted and the
 *original* profile remains active. Callers that need to verify which
 profile is in effect must call [`oxi_active_profile`] after
 `oxi_init` returns.

 Must be called before any other `oxi_*` function.
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
 | 1 | `Passed` — the signature over the image verified |
 | 2 | `SignatureInvalid` — the image does not match its signature |
 | 3 | `SlotInvalid` — the slot is the unsigned template, as in an unsigned build or a signed one whose slot was overwritten; not on its own a reason to sign (see the remedies below) |
 | 4 | `Unreadable` — the test was **not performed**; do not sign, and obtain a fresh copy if it persists |
 | 5 | `CastNotRun` — the test was reached before its CASTs passed |
 | 6 | `Unknown` — the record held a value this module never writes |
 | 7 | `Refused` — the module refused a primitive, so the test was **not performed** |
 | 8 | `NoVerifyKey` — the library carries no verifying key, as in a key-less build or a signed one whose key was zeroed; as for 3 |
 | 9 | `KeyMismatch` — the slot was signed for a different key than the library embeds |
 | 10 | `SlotDamaged` — the slot, the key record or a bound import is damaged; do not re-sign |

 Remedies: no value is on its own a reason to sign the library. If you
 built it from source yourself and have not signed it yet, sign it with
 your own key; if you received it from anyone else, do not sign it and
 obtain a fresh copy from its publisher. For 2, 9 and 10, never sign it
 again.

 This exists because `oxi_init` cannot carry the distinction: a
 failing self-test returns [`OxiResult::SelfTestFailed`] whatever the
 cause, so `SignatureInvalid` and `Unreadable` are indistinguishable from
 its return value alone. An operator and a test laboratory must be able
 to tell those apart — a corrupt module from
 one signed for another key, one built without a key, and an environment
 that could not supply the module's own bytes — and this query is how
 that is retrieved.

 The value latches on the first run and nothing is re-run here, so a
 later call cannot revise it and this is safe to call from the error
 state.

 # Safety

 No pointers; always safe to call.
 */
int oxi_integrity_status(void);

/*
 Writes the fingerprint of the verifying key this library embeds: the
 SHA-256 of the encoded ML-DSA-87 public key, 32 bytes, to `out`.

 The fingerprint names the signer this build trusts: a project release
 embeds the project key, a source build the builder's own. It is recorded
 when the integrity test reads the key, so it is available after
 [`oxi_init`] whether or not the test passed, and it equals the
 fingerprint `oxicrypt-integrity-sign --show` prints for the file.

 Returns:
 - [`OxiResult::Ok`] — the fingerprint was written to `out[0..32]`.
 - [`OxiResult::NullPointer`] — `out` is null.
 - [`OxiResult::BufferTooSmall`] — `out_len` is less than 32. Nothing is
   written.
 - [`OxiResult::NotOperational`] — no fingerprint is known, and nothing
   is written. The integrity test has not read a key: `oxi_init` has not
   run it, its CAST failed first, the key record could not be read or
   is malformed, or the library embeds no key. `oxi_integrity_status`
   tells these apart (`NotRun`, `CastNotRun`, `Unreadable`,
   `SlotDamaged`, `NoVerifyKey`).

 # Safety

 `out` must be valid for writes of `out_len` bytes.
 */
int oxi_integrity_key_fingerprint(uint8_t *out, uintptr_t out_len);

/*
 Writes the integrity test's failure in words, NUL-terminated UTF-8, to
 `out`: the cause the status value cannot carry, such as which slot
 defect, which memory route's error, or which lengths disagreed.

 `*written` always receives the number of bytes the text needs including
 its NUL, or 0 when there is none, so a caller can pass `out_len` 0 to
 size the buffer first.

 Returns:
 - [`OxiResult::Ok`] — the text and its NUL were written.
 - [`OxiResult::NullPointer`] — `written` is null, or `out` is null with a
   non-zero `out_len`; in the second case `*written` still receives the
   size.
 - [`OxiResult::BufferTooSmall`] — `out_len` is less than `*written`.
   Nothing is written to `out`.
 - [`OxiResult::NotOperational`] — the boot sequence's integrity test has
   not failed in this process, so there is no text; `*written` is 0.

 # Safety

 `out` must be valid for writes of `out_len` bytes and `written` for one
 `usize`.
 */
int oxi_integrity_status_detail(uint8_t *out, uintptr_t out_len, uintptr_t *written);

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

 Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
 hash blocks, if the label is empty or longer than 249 bytes, or if the
 context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
 255 hash blocks is refused for its length and writes nothing to `out`.
 Otherwise a failure once the derivation has started, a refused label or
 context or a refused write, leaves `out` zeroized for `out_len` bytes.

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

 Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
 hash blocks, if the label is empty or longer than 249 bytes, or if the
 context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
 255 hash blocks is refused for its length and writes nothing to `out`.
 Otherwise a failure once the derivation has started, a refused label or
 context or a refused write, leaves `out` zeroized for `out_len` bytes.

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

 Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
 hash blocks, if the label is empty or longer than 249 bytes, or if the
 context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
 255 hash blocks is refused for its length and writes nothing to `out`.
 Otherwise a failure once the derivation has started, a refused label or
 context or a refused write, leaves `out` zeroized for `out_len` bytes.

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

 Returns `OxiResult::InvalidInput = 5` if `out_len` exceeds 65535 or 255
 hash blocks, if the label is empty or longer than 249 bytes, or if the
 context is longer than 255 bytes (RFC 8446 §7.1). An `out_len` above
 255 hash blocks is refused for its length and writes nothing to `out`.
 Otherwise a failure once the derivation has started, a refused label or
 context or a refused write, leaves `out` zeroized for `out_len` bytes.

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
 across the C boundary).

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::NullPointer = 10` if any pointer is NULL;
 `OxiResult::NotOperational = 1` if the FIPS module is not in
 the `Operational` state;
 `OxiResult::AlgorithmRestricted = 6` if the active profile does
 not allow ECDH-P-256;
 `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was
 instantiated by another process, if the DRBG faults during
 sampling, if rejection sampling exhausts without an in-range scalar
 (in practice only a broken DRBG), or if the IG 10.3.A PCT mismatches.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `private_out` must be a
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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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
 keying material — same discipline as ECDH.

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

 The caller is responsible for: (a) allocating the handle via
 [`oxi_hmac_drbg_sha256_new`]; (b) having the handle instantiated
 with [`oxi_hmac_drbg_sha256_instantiate_from_module`], which seeds
 it from the module's seed path, before this call; (c) freeing it via
 [`oxi_hmac_drbg_sha256_free`] after use; and (d) serializing all
 calls on the same handle pointer per the per-call-mutating-handle
 thread-safety contract.

 Returns `OxiResult::Ok = 0` on success;
 `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated with `_instantiate_from_module`;
 `OxiResult::InvalidInput = 5` if the handle was instantiated by
 another process, or the DRBG exhausts its rejection-sampling
 attempts or fails to produce output (the upstream `Option` is
 collapsed to `Err(InvalidInput)` by the gated public API);
 `OxiResult::NotOperational = 1` if the FIPS module is not
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
 `TagMismatch = 22` on any verification failure (the upstream
 verifier reports a malformed input and a bad signature as the same
 error), or a module error variant.

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
 deterministic-but-pseudorandom shared secret; tamper does NOT
 surface as a discriminant. That this branch runs in constant time
 is unproven: no timing probe covers it.

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
 deterministic-but-pseudorandom shared secret; tamper does NOT
 surface as a discriminant. That this branch runs in constant time
 is unproven: no timing probe covers it.

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
 deterministic-but-pseudorandom shared secret; tamper does NOT
 surface as a discriminant. That this branch runs in constant time
 is unproven: no timing probe covers it.

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
 Verify an LMS signature under whichever of the 80 SP 800-208
 §4.1–§4.4 parameter pairs its public key names.

 Reads the LMS and LM-OTS typecodes from the first 8 bytes of the
 `pk_len`-byte public key and verifies through that pair's gated
 `verify`, as `oxicrypt_lms::verify_any` does.

 Returns `OxiResult::Ok = 0` for a valid signature,
 `OxiResult::InvalidInput = 5` when the input names no pair (fewer than
 8 public-key bytes, a typecode pair outside the 80, or a `pk_len` or
 `sig_len` that is not the named pair's), `OxiResult::TagMismatch = 22`
 when the named pair's verifier rejects the signature, or a module
 error variant from the named pair's gate.

 # Safety

 `pk_ptr` must be valid for `pk_len` bytes, `msg_ptr` for `msg_len`
 bytes and `sig_ptr` for `sig_len` bytes. Each may be NULL only when
 its length is 0.
 */
int oxi_lms_verify_any(const uint8_t *pk_ptr,
                       uintptr_t pk_len,
                       const uint8_t *msg_ptr,
                       uintptr_t msg_len,
                       const uint8_t *sig_ptr,
                       uintptr_t sig_len);

/*
 Verify an LMS signature for the SHA-256 M=32 H=5 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8684-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=5 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4460-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=5 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2348-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=5 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1292-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=10 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8844-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=10 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=10 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2508-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=10 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1452-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=15 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9004-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=15 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=15 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2668-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=15 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1612-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=20 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9164-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=20 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=20 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2828-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=20 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1772-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=25 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9324-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=25 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 5100-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=25 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2988-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=32 H=25 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1932-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.1.

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
 Verify an LMS signature for the SHA-256 M=24 H=5 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 4956-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=5 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2580-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=5 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1380-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=5 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=10 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5076-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=10 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2700-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=10 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1500-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=10 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 900-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=15 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5196-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=15 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2820-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=15 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=15 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1020-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=20 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5316-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=20 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=20 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1740-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=20 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1140-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=25 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5436-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=25 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 3060-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=25 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1860-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHA-256 M=24 H=25 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1260-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.2.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8684-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4460-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2348-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=5 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1292-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 8844-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2508-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=10 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1452-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9004-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2668-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=15 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1612-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9164-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 4940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2828-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=20 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1772-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=1 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 9324-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=2 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 5100-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=4 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 2988-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=32 H=25 W=8 variant.

 Reads 56-byte pk, `msg_len`-byte message, and
 1932-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.3.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 4956-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2580-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1380-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=5 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 780-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5076-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2700-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1500-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=10 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 900-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5196-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2820-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1620-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=15 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1020-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5316-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 2940-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1740-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=20 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1140-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=1 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 5436-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=2 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 3060-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=4 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1860-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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
 Verify an LMS signature for the SHAKE-256 M=24 H=25 W=8 variant.

 Reads 48-byte pk, `msg_len`-byte message, and
 1260-byte signature. Returns `TagMismatch=22` on any
 verification failure (parse / structural / cryptographic — upstream
 collapses into a single `Err(InvalidInput)`; same convention as
 every other oxicrypt verify FFI). Spec: SP 800-208 §4.4.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `out_key` must be a non-NULL
 writable pointer to a `*mut OxiEcdsaP256PrivateKey`.
 */
int oxi_ecdsa_p256_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                            OxiEcdsaP256PrivateKey **out_key);

/*
 Free an ECDSA P-256 private-key handle. NULL-safe.

 After this call the caller's pointer is dangling; the caller
 SHOULD set their pointer to NULL to avoid use-after-free. Drop
 on the upstream `EcdsaP256PrivateKey` calls `oxicrypt-zeroize` on
 the private scalar `d`; no caller-side scrubbing is required. That
 the freed memory reads zero is unproven: no test inspects it.

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
 finalised, which cannot happen: this handle has no `_finalize`.

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

 # Safety

 `key` must be a live handle from
 [`oxi_ecdsa_p256_private_key_new_generate`]. `drbg` must be a
 live, instantiated handle from [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate_from_module`]; the caller MUST serialise
 concurrent calls on the same `drbg` pointer, because every call
 mutates the DRBG's state. `msg_ptr` must be valid for `msg_len` bytes.
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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

 # Safety

 `drbg` must be a live, instantiated handle from
 [`oxi_hmac_drbg_sha256_new`] +
 [`oxi_hmac_drbg_sha256_instantiate_from_module`]. `out_key` must be a non-NULL
 writable pointer to a `*mut OxiRsaPrivateKey2048`.
 */
int oxi_rsa_2048_private_key_new_generate(OxiHmacDrbgSha256 *drbg,
                                          uint64_t e,
                                          OxiRsaPrivateKey2048 **out_key);

/*
 Free an RSA-2048 private-key handle. NULL-safe.

 After this call the caller's pointer is dangling. Drop on the
 upstream `RsaPrivateKey2048` calls `oxicrypt-zeroize` on the
 private exponent `d` and (when present) the CRT components
 `p, q, dP, dQ, qInv`. That the freed memory reads zero is unproven:
 no test inspects it.

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

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

 # Safety

 `key` must be a live handle. `drbg` must be a live, instantiated
 DRBG handle; the caller MUST serialise concurrent calls on the
 same `drbg` pointer, because every call mutates the DRBG's
 state. `msg_ptr` must
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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

 # Safety

 `key` must be a live handle. `modulus_out` must be a non-NULL
 writable pointer to ≥384 bytes.
 */
int oxi_rsa_3072_modulus(const OxiRsaPrivateKey3072 *key, uint8_t *modulus_out);

/*
 Copy the public exponent `e` from an RSA-3072 handle. See
 [`oxi_rsa_2048_public_exponent`].

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

 # Safety

 `key` must be a live handle. `modulus_out` must be a non-NULL
 writable pointer to ≥512 bytes.
 */
int oxi_rsa_4096_modulus(const OxiRsaPrivateKey4096 *key, uint8_t *modulus_out);

/*
 Copy the public exponent `e` from an RSA-4096 handle.

 Returns `OxiResult::NotOperational = 1` outside the `SelfTest` and
 `Operational` states, including for a handle created before the module
 entered `Error`.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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

 Returns `OxiResult::Uninstantiated = 8` if the DRBG handle was never
 instantiated, and `OxiResult::InvalidInput = 5` if it was instantiated
 by another process; both are checked before the module state.

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
 Construct an AES-GCM key handle from `key_len` bytes of key material,
 with a count of 0 and a limit of 2^32 encryptions (SP 800-38D §8.3).

 `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
 success the handle is written to `*out`; release it with
 [`oxi_aes_gcm_key_free`]. `out` must not overlap `key`. A NULL `out`, or
 a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
 operational returns 1. A failed allocation returns `Internal = 255`. On
 any failure `*out` is unchanged. The buffer contract of every
 `oxi_aes_*` function, this one included, is stated at the top of this
 header.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_gcm_key_new(const uint8_t *key, uintptr_t key_len, OxiAesGcmKey **out);

/*
 Construct an AES-GCM key handle as [`oxi_aes_gcm_key_new`] does, with
 its count preloaded to `used`: the encryptions earlier instances of the
 same key bytes performed, as read from [`oxi_aes_gcm_key_invocations`].

 A `used` above 2^32 returns `InvalidInput = 5`; a `used` of 2^32 builds
 a key that is already exhausted. The operator sums the counts of every
 instance of one key and establishes a new key before the sum reaches
 2^32; the module sees one instance only. A NULL `out`, or a NULL `key`
 with a non-zero `key_len`, returns 10; a module that is not operational
 returns 1. A failed allocation returns `Internal = 255`. On any failure
 `*out` is unchanged.

 # Safety

 As for [`oxi_aes_gcm_key_new`].
 */
int oxi_aes_gcm_key_new_with_count(const uint8_t *key,
                                   uintptr_t key_len,
                                   uint64_t used,
                                   OxiAesGcmKey **out);

/*
 Construct an AES-GCM key handle as [`oxi_aes_gcm_key_new`] does, with
 a count of 0 and a limit of `limit` encryptions: this instance's share
 of the 2^32 permitted under the key bytes.

 A `limit` of 0 or above 2^32 returns `InvalidInput = 5`. The operator
 keeps the sum of the shares of one key at or below 2^32; the module does
 not see the other instances. A NULL `out`, or a NULL `key` with a
 non-zero `key_len`, returns 10; a module that is not operational
 returns 1. A failed allocation returns `Internal = 255`. On any failure
 `*out` is unchanged.

 # Safety

 As for [`oxi_aes_gcm_key_new`].
 */
int oxi_aes_gcm_key_new_with_limit(const uint8_t *key,
                                   uintptr_t key_len,
                                   uint64_t limit,
                                   OxiAesGcmKey **out);

/*
 Write to `*out` the number of encryptions reserved under the handle,
 including any preloaded by [`oxi_aes_gcm_key_new_with_count`].

 A handle of another mode returns `InvalidInput = 5`. `out` must not
 overlap the handle. A NULL `key` returns 10; a module that is not
 operational returns 1.

 # Safety

 `key` must be NULL or a live key handle; `out` must be NULL or valid for
 a write of one `uint64_t`.
 */
int oxi_aes_gcm_key_invocations(const OxiAesGcmKey *key, uint64_t *out);

/*
 Free an AES-GCM key handle, zeroizing its key schedule. NULL frees
 nothing. A handle of another mode frees nothing and stays live, to be
 freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 An AES-GCM handle is dangling once the call returns.
 */
void oxi_aes_gcm_key_free(OxiAesGcmKey *key);

/*
 AES-GCM authenticated encryption (SP 800-38D §7.1) under a 96-bit IV the
 module draws from the caller's DRBG handle (SP 800-38D §8.2.2).

 Buffers: `aad`, `aad_len` bytes; `plaintext`, `pt_len` bytes;
 `ciphertext`, `pt_len` writable bytes; `iv_out`, 12 writable bytes;
 `tag_out`, 16 writable bytes. `aad` and `plaintext` may be NULL with a
 length of 0. No range may overlap a writable range or either handle,
 and the DRBG handle may not be the key handle: an overlap, in-place
 encryption included, returns `InvalidInput = 5`. A handle of another
 mode returns `InvalidInput = 5`. A NULL `key` returns 10; a module that
 is not operational returns 1.

 The DRBG handle is taken as `oxi_drbg_generate` takes it, with its codes:
 `Uninstantiated = 8` for a handle never instantiated, `Busy = 32` for one
 in use, `InvalidInput = 5` for one inherited from another process.
 Plaintext longer than 2^36 − 32 bytes returns
 `InvalidPayloadLength = 26`, AAD longer than 2^61 − 1 bytes
 `InvalidAadLength = 27`. A key that has reached its limit returns
 `KeyExhausted = 34` before any IV is drawn, and stays exhausted; an
 encryption whose IV draw fails still spends one invocation. On success
 the ciphertext, the IV and the tag are written. On any failure nothing
 of them survives in the caller's buffers: an output copied before a
 later copy is refused is zeroed.

 # Safety

 `key` must be NULL or a live key handle, `drbg` NULL or a live handle
 from a `_new_rbg` function, and every non-NULL buffer valid for its
 stated length.
 */
int oxi_aes_gcm_seal(const OxiAesGcmKey *key,
                     OxiDrbg *drbg,
                     const uint8_t *aad,
                     uintptr_t aad_len,
                     const uint8_t *plaintext,
                     uintptr_t pt_len,
                     uint8_t *ciphertext,
                     uint8_t *iv_out,
                     uint8_t *tag_out);

/*
 AES-GCM authenticated decryption (SP 800-38D §7.2).

 Buffers: `iv`, 12 bytes; `aad`, `aad_len` bytes; `ciphertext`, `ct_len`
 bytes; `tag`, 16 bytes; `plaintext`, `ct_len` writable bytes. `aad` and
 `ciphertext` may be NULL with a length of 0. No range may overlap
 `plaintext` or the handle: an overlap returns `InvalidInput = 5`. A
 handle of another mode returns `InvalidInput = 5`. A NULL `key` returns
 10; a module that is not operational returns 1.

 A tag that does not verify returns `TagMismatch = 22`. The length bounds
 of [`oxi_aes_gcm_seal`] apply to `ct_len` and `aad_len`. Decryption
 does not count against the key's limit. The plaintext is written only on
 success; on any failure nothing is.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_gcm_open(const OxiAesGcmKey *key,
                     const uint8_t *iv,
                     const uint8_t *aad,
                     uintptr_t aad_len,
                     const uint8_t *ciphertext,
                     uintptr_t ct_len,
                     const uint8_t *tag,
                     uint8_t *plaintext);

/*
 Construct an AES-CCM key handle from `key_len` bytes of key material
 with a tag length of `tag_len` bytes, fixed for the key (SP 800-38C
 §5.3), and an invocation count of 0.

 `key_len` is 16, 24 or 32 and `tag_len` one of 8, 10, 12, 14 or 16; any
 other returns `InvalidInput = 5`. On success the handle is written to
 `*out`; release it with [`oxi_aes_ccm_key_free`]. `out` must not overlap
 `key`. A NULL `out`, or a NULL `key` with a non-zero `key_len`, returns
 10; a module that is not operational returns 1. A failed allocation
 returns `Internal = 255`. On any failure `*out` is unchanged.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_ccm_key_new(const uint8_t *key,
                        uintptr_t key_len,
                        uintptr_t tag_len,
                        OxiAesCcmKey **out);

/*
 Construct an AES-CCM key handle as [`oxi_aes_ccm_key_new`] does, with
 its count preloaded to `used`: the block-cipher invocations earlier
 instances of the same key bytes performed, as read from
 [`oxi_aes_ccm_key_invocations`].

 A `used` above 2^61 returns `InvalidInput = 5`. A NULL `out`, or a NULL
 `key` with a non-zero `key_len`, returns 10; a module that is not
 operational returns 1. A failed allocation returns `Internal = 255`. On
 any failure `*out` is unchanged.

 # Safety

 As for [`oxi_aes_ccm_key_new`].
 */
int oxi_aes_ccm_key_new_with_count(const uint8_t *key,
                                   uintptr_t key_len,
                                   uintptr_t tag_len,
                                   uint64_t used,
                                   OxiAesCcmKey **out);

/*
 Write to `*out` the number of block-cipher invocations reserved under the
 handle, including any preloaded by [`oxi_aes_ccm_key_new_with_count`].

 A handle of another mode returns `InvalidInput = 5`. `out` must not
 overlap the handle. A NULL `key` returns 10; a module that is not
 operational returns 1.

 # Safety

 `key` must be NULL or a live key handle; `out` must be NULL or valid for
 a write of one `uint64_t`.
 */
int oxi_aes_ccm_key_invocations(const OxiAesCcmKey *key, uint64_t *out);

/*
 Free an AES-CCM key handle, zeroizing its key schedule. NULL frees
 nothing. A handle of another mode frees nothing and stays live, to be
 freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 An AES-CCM handle is dangling once the call returns.
 */
void oxi_aes_ccm_key_free(OxiAesCcmKey *key);

/*
 AES-CCM authenticated encryption (SP 800-38C §6.1) under a caller's
 nonce, which must be unique under the key.

 Buffers: `nonce`, `nonce_len` bytes, 7 to 13; `aad`, `aad_len` bytes;
 `pt`, `pt_len` bytes; `ct`, `pt_len` writable bytes; `tag`, the key's
 tag length in writable bytes. `aad` and `pt` may be NULL with a length
 of 0. No range may overlap a writable range or the handle: an overlap,
 in-place encryption included, returns `InvalidInput = 5`. A handle of
 another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
 module that is not operational returns 1.

 A nonce length outside 7 to 13 returns `InvalidNonceLength = 24`, a
 payload the nonce's length field cannot represent
 `InvalidPayloadLength = 26`, AAD above the SP 800-38C bound
 `InvalidAadLength = 27`, and an encryption that would take the key's
 count past 2^61 block-cipher invocations `KeyExhausted = 34`. A payload
 the length field cannot represent is refused before the key's count is
 charged. The ciphertext and tag are written only on success. On any
 failure nothing of them survives in the caller's buffers: a ciphertext
 copied before the tag's copy is refused is zeroed.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_ccm_seal(const OxiAesCcmKey *key,
                     const uint8_t *nonce,
                     uintptr_t nonce_len,
                     const uint8_t *aad,
                     uintptr_t aad_len,
                     const uint8_t *pt,
                     uintptr_t pt_len,
                     uint8_t *ct,
                     uint8_t *tag);

/*
 AES-CCM authenticated decryption (SP 800-38C §6.2).

 Buffers: `nonce`, `nonce_len` bytes; `aad`, `aad_len` bytes; `ct`,
 `ct_len` bytes, the ciphertext without its tag; `tag`, the key's tag
 length in bytes; `pt`, `ct_len` writable bytes. `nonce`, `aad` and `ct`
 may be NULL with a length of 0. No range may overlap `pt` or the
 handle: an overlap returns `InvalidInput = 5`. A handle of another mode
 returns `InvalidInput = 5`. A NULL `key` returns 10; a module that is
 not operational returns 1.

 Every invalid input returns `TagMismatch = 22`: a nonce length outside 7
 to 13, a payload length the nonce's length field cannot represent, and a
 tag that does not verify. The tag is verified before any plaintext
 exists outside the module, and `pt` is written only on success. A
 decryption that would take the key's count past 2^61 returns
 `KeyExhausted = 34`. A failed decryption is counted in full, except a
 `ct_len` the nonce's length field cannot represent, which is refused
 before the count is charged.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_ccm_open(const OxiAesCcmKey *key,
                     const uint8_t *nonce,
                     uintptr_t nonce_len,
                     const uint8_t *aad,
                     uintptr_t aad_len,
                     const uint8_t *ct,
                     uintptr_t ct_len,
                     const uint8_t *tag,
                     uint8_t *pt);

/*
 Construct an AES-CBC key handle from `key_len` bytes of key material.

 `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
 success the handle is written to `*out`; release it with
 [`oxi_aes_cbc_key_free`]. `out` must not overlap `key`. A NULL `out`, or
 a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
 operational returns 1. A failed allocation returns `Internal = 255`. On
 any failure `*out` is unchanged.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_cbc_key_new(const uint8_t *key, uintptr_t key_len, OxiAesCbcKey **out);

/*
 Free an AES-CBC key handle, zeroizing its key schedule. NULL frees
 nothing. A handle of another mode frees nothing and stays live, to be
 freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 An AES-CBC handle is dangling once the call returns.
 */
void oxi_aes_cbc_key_free(OxiAesCbcKey *key);

/*
 AES-CBC encryption (SP 800-38A §6.2), confidentiality only.

 Buffers: `iv`, 16 bytes, which must be unpredictable (SP 800-38A
 Appendix C); `in`, `len` bytes, a positive multiple of 16; `out`, `len`
 writable bytes. No range may overlap `out` or the handle: an overlap,
 in-place encryption included, returns `InvalidInput = 5`. A handle of
 another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
 module that is not operational returns 1.

 A `len` that is not a multiple of 16 returns `NotBlockAligned = 20`, a
 `len` of 0 `InvalidPayloadLength = 26`. `out` is written only on success.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_cbc_encrypt(const OxiAesCbcKey *key,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uintptr_t len,
                        uint8_t *out);

/*
 AES-CBC decryption (SP 800-38A §6.2).

 The buffers and codes of [`oxi_aes_cbc_encrypt`], with `in` the
 ciphertext and `out` the plaintext. A NULL `key` returns 10; a module
 that is not operational returns 1.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_cbc_decrypt(const OxiAesCbcKey *key,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uintptr_t len,
                        uint8_t *out);

/*
 Construct an AES-CTR key handle from `key_len` bytes of key material.

 `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
 success the handle is written to `*out`; release it with
 [`oxi_aes_ctr_key_free`]. `out` must not overlap `key`. A NULL `out`, or
 a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
 operational returns 1. A failed allocation returns `Internal = 255`. On
 any failure `*out` is unchanged.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_ctr_key_new(const uint8_t *key, uintptr_t key_len, OxiAesCtrKey **out);

/*
 Free an AES-CTR key handle, zeroizing its key schedule. NULL frees
 nothing. A handle of another mode frees nothing and stays live, to be
 freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 An AES-CTR handle is dangling once the call returns.
 */
void oxi_aes_ctr_key_free(OxiAesCtrKey *key);

/*
 AES-CTR (SP 800-38A §6.5): XORs `in` with the keystream from the
 16-byte initial counter block `counter`, which the module increments as
 one 128-bit big-endian integer. Encryption and decryption are the same
 operation.

 Buffers: `counter`, 16 bytes; `in`, `len` bytes, any length; `out`, `len`
 writable bytes. No range may overlap `out` or the handle: an overlap,
 in-place operation included, returns `InvalidInput = 5`. A handle of
 another mode returns `InvalidInput = 5`. A NULL `key` returns 10; a
 module that is not operational returns 1. No counter block may repeat
 under one key (SP 800-38A Appendix B); that is the caller's duty. `out`
 is written only on success.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_ctr(const OxiAesCtrKey *key,
                const uint8_t *counter,
                const uint8_t *in,
                uintptr_t len,
                uint8_t *out);

/*
 Construct an AES key-wrap key handle from `key_len` bytes of key
 material, for KW and KWP (SP 800-38F) in both the forward and the
 inverse-cipher variants.

 `key_len` is 16, 24 or 32; any other returns `InvalidInput = 5`. On
 success the handle is written to `*out`; release it with
 [`oxi_aes_kw_key_free`]. `out` must not overlap `key`. A NULL `out`, or
 a NULL `key` with a non-zero `key_len`, returns 10; a module that is not
 operational returns 1. A failed allocation returns `Internal = 255`. On
 any failure `*out` is unchanged.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_kw_key_new(const uint8_t *key, uintptr_t key_len, OxiAesKwKey **out);

/*
 Free an AES key-wrap key handle, zeroizing its key schedule. NULL frees
 nothing. A handle of another mode frees nothing and stays live, to be
 freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 An AES key-wrap handle is dangling once the call returns.
 */
void oxi_aes_kw_key_free(OxiAesKwKey *key);

/*
 AES-KW wrap (SP 800-38F §6.2 Algorithm 3, KW-AE).

 Buffers: `pt`, `pt_len` bytes, a multiple of 8 of at least 16 and fewer
 than 2^54 semiblocks; `out`, `pt_len + 8` writable bytes. No range may
 overlap `out` or the handle: an overlap, in-place wrapping included,
 returns `InvalidInput = 5`. A handle of another mode returns
 `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
 operational returns 1. A length KW does not accept returns
 `LengthMismatch = 23` or `InvalidPayloadLength = 26`. `out` is written
 only on success.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_kw_wrap(const OxiAesKwKey *key, const uint8_t *pt, uintptr_t pt_len, uint8_t *out);

/*
 AES-KW unwrap (SP 800-38F §6.2 Algorithm 4, KW-AD).

 Buffers: `ct`, `ct_len` bytes, a multiple of 8 of at least 24; `out`,
 `ct_len - 8` writable bytes. No range may overlap `out` or the handle:
 an overlap returns `InvalidInput = 5`. A handle of another mode returns
 `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
 operational returns 1. An integrity check value that does not verify
 returns `TagMismatch = 22`, a length KW does not accept
 `LengthMismatch = 23` or `InvalidPayloadLength = 26`. On any failure
 nothing is written to `out`: the unwrapped key is copied out only once
 it has verified.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_kw_unwrap(const OxiAesKwKey *key, const uint8_t *ct, uintptr_t ct_len, uint8_t *out);

/*
 AES-KWP wrap (SP 800-38F §6.3 Algorithm 5, KWP-AE).

 Buffers: `pt`, `pt_len` bytes, 1 to 2^32 − 1; `out`, `out_cap` writable
 bytes, at least the wrapped length `((pt_len + 7) / 8) * 8 + 8`;
 `written`, one writable `uintptr_t`, set to the wrapped length on
 success. No range may overlap `out`, `written` or the handle: an
 overlap returns `InvalidInput = 5`. A handle of another mode returns
 `InvalidInput = 5`. A NULL `key` or `written` returns 10; a module that
 is not operational returns 1. An `out_cap` below the wrapped length
 returns `BufferTooSmall = 11`, and a `pt_len` KWP does not accept
 `LengthMismatch = 23`. `out` and `written` are written only on success.
 On any failure nothing of them survives in the caller's buffers: an
 `out` copied before the copy of `written` is refused is zeroed.

 # Safety

 `key` must be NULL or a live key handle, every non-NULL buffer valid for
 its stated length, and `written` NULL or valid for a write of one
 `uintptr_t`.
 */
int oxi_aes_kwp_wrap(const OxiAesKwKey *key,
                     const uint8_t *pt,
                     uintptr_t pt_len,
                     uint8_t *out,
                     uintptr_t out_cap,
                     uintptr_t *written);

/*
 AES-KWP unwrap (SP 800-38F §6.3 Algorithm 6, KWP-AD).

 Buffers: `ct`, `ct_len` bytes, a multiple of 8 of at least 16; `out`,
 `out_cap` writable bytes, at least the unwrapped length; `written`, one
 writable `uintptr_t`, set to the unwrapped length on success. No range
 may overlap `out`, `written` or the handle: an overlap returns
 `InvalidInput = 5`. A handle of another mode returns
 `InvalidInput = 5`. A NULL `key` or `written` returns 10; a module that
 is not operational returns 1. An integrity check value or padding that
 does not verify returns `TagMismatch = 22`, a length KWP does not
 accept `LengthMismatch = 23`, and an `out_cap` below the unwrapped
 length `BufferTooSmall = 11`. `out_cap` is compared with the unwrapped
 length only after verification, so `TagMismatch = 22` takes precedence
 over `BufferTooSmall = 11`. The unwrapped key is copied out only once it
 has verified, and on any failure nothing of `out` or `written` survives
 in the caller's buffers: an `out` copied before the copy of `written`
 is refused is zeroed.

 # Safety

 `key` must be NULL or a live key handle, every non-NULL buffer valid for
 its stated length, and `written` NULL or valid for a write of one
 `uintptr_t`.
 */
int oxi_aes_kwp_unwrap(const OxiAesKwKey *key,
                       const uint8_t *ct,
                       uintptr_t ct_len,
                       uint8_t *out,
                       uintptr_t out_cap,
                       uintptr_t *written);

/*
 AES-KW wrap with the inverse cipher (SP 800-38F §6.4, KW-AE with
 CIPH⁻¹). The buffers and codes of [`oxi_aes_kw_wrap`]. A NULL `key`
 returns 10; a module that is not operational returns 1.

 # Safety

 As for [`oxi_aes_kw_wrap`].
 */
int oxi_aes_kw_wrap_inverse(const OxiAesKwKey *key,
                            const uint8_t *pt,
                            uintptr_t pt_len,
                            uint8_t *out);

/*
 AES-KW unwrap with the forward cipher (SP 800-38F §6.4, the inverse of
 [`oxi_aes_kw_wrap_inverse`]). The buffers and codes of
 [`oxi_aes_kw_unwrap`]; on any failure nothing is written to `out`. A
 NULL `key` returns 10; a module that is not operational returns 1.

 # Safety

 As for [`oxi_aes_kw_unwrap`].
 */
int oxi_aes_kw_unwrap_inverse(const OxiAesKwKey *key,
                              const uint8_t *ct,
                              uintptr_t ct_len,
                              uint8_t *out);

/*
 AES-KWP wrap with the inverse cipher (SP 800-38F §6.4, KWP-AE with
 CIPH⁻¹). The buffers and codes of [`oxi_aes_kwp_wrap`]. A NULL `key`
 returns 10; a module that is not operational returns 1.

 # Safety

 As for [`oxi_aes_kwp_wrap`].
 */
int oxi_aes_kwp_wrap_inverse(const OxiAesKwKey *key,
                             const uint8_t *pt,
                             uintptr_t pt_len,
                             uint8_t *out,
                             uintptr_t out_cap,
                             uintptr_t *written);

/*
 AES-KWP unwrap with the forward cipher (SP 800-38F §6.4, the inverse of
 [`oxi_aes_kwp_wrap_inverse`]). The buffers and codes of
 [`oxi_aes_kwp_unwrap`], including its precedence of `TagMismatch = 22`
 over `BufferTooSmall = 11`; on any failure nothing of `out` or `written`
 survives in the caller's buffers. A NULL `key` returns 10; a module that
 is not operational returns 1.

 # Safety

 As for [`oxi_aes_kwp_unwrap`].
 */
int oxi_aes_kwp_unwrap_inverse(const OxiAesKwKey *key,
                               const uint8_t *ct,
                               uintptr_t ct_len,
                               uint8_t *out,
                               uintptr_t out_cap,
                               uintptr_t *written);

/*
 Construct a CMAC key handle (SP 800-38B) from `key_len` bytes of key
 material with a MAC length of `mac_len` bytes, fixed for the key.

 `key_len` is 16, 24 or 32 and `mac_len` 8 to 16; any other returns
 `InvalidInput = 5`. On success the handle is written to `*out`; release
 it with [`oxi_aes_cmac_key_free`]. `out` must not overlap `key`. A NULL
 `out`, or a NULL `key` with a non-zero `key_len`, returns 10; a module
 that is not operational returns 1. A failed allocation returns
 `Internal = 255`. On any failure `*out` is unchanged. SP 800-38B
 Appendix B recommends at most 2^48 messages under one key.

 # Safety

 `key` must be NULL or valid for reads of `key_len` bytes; `out` must be
 NULL or valid for a write of one pointer.
 */
int oxi_aes_cmac_key_new(const uint8_t *key,
                         uintptr_t key_len,
                         uintptr_t mac_len,
                         OxiAesCmacKey **out);

/*
 Free a CMAC key handle, zeroizing its key schedule and subkeys. NULL
 frees nothing. A handle of another mode frees nothing and stays live, to
 be freed by its own mode's `_key_free`.

 # Safety

 `key` must be NULL or a live key handle that no other thread is using.
 A CMAC handle is dangling once the call returns.
 */
void oxi_aes_cmac_key_free(OxiAesCmacKey *key);

/*
 Compute the CMAC (SP 800-38B §6.2) of `msg` into `mac`.

 Buffers: `msg`, `msg_len` bytes, NULL with a length of 0 allowed; `mac`,
 the key's MAC length in writable bytes. No range may overlap `mac` or
 the handle: an overlap returns `InvalidInput = 5`. A handle of another
 mode returns `InvalidInput = 5`. A NULL `key` returns 10; a module that
 is not operational returns 1. `mac` is written only on success.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_cmac(const OxiAesCmacKey *key, const uint8_t *msg, uintptr_t msg_len, uint8_t *mac);

/*
 Verify `mac` as the CMAC of `msg` (SP 800-38B §6.3), comparing every
 byte of the key's MAC length without an early exit.

 Buffers: `msg`, `msg_len` bytes, NULL with a length of 0 allowed; `mac`,
 the key's MAC length in bytes. No range may overlap the handle: an
 overlap returns `InvalidInput = 5`. A handle of another mode returns
 `InvalidInput = 5`. A NULL `key` returns 10; a module that is not
 operational returns 1. A MAC that does not verify returns
 `TagMismatch = 22`. Nothing is written.

 # Safety

 `key` must be NULL or a live key handle, and every non-NULL buffer valid
 for its stated length.
 */
int oxi_aes_cmac_verify(const OxiAesCmacKey *key,
                        const uint8_t *msg,
                        uintptr_t msg_len,
                        const uint8_t *mac);

/*
 Allocate a new, **uninstantiated** HMAC_DRBG-SHA-256 handle.

 On success, writes a heap-allocated handle pointer through
 `out_handle` and returns `OxiResult::Ok = 0`. The caller owns
 the handle and MUST release it with [`oxi_hmac_drbg_sha256_free`].

 The newly-allocated handle is uninstantiated — calling
 [`oxi_hmac_drbg_sha256_generate`] or
 [`oxi_hmac_drbg_sha256_reseed_from_module`] before
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] returns
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
 volatile-write convention, and every byte of the handle is then wiped
 before its memory is released; no caller-side scrubbing is required.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_hmac_drbg_sha256_new`] that has not yet been freed.
 */
void oxi_hmac_drbg_sha256_free(OxiHmacDrbgSha256 *handle);

/*
 HMAC_DRBG-SHA-256 Instantiate from the module's seed path
 (SP 800-90A §10.1.2.3), with an optional personalization string.

 Draws the entropy input and nonce from the module's seed path,
 replaces any earlier instantiation of the handle and records the
 calling process's id. In a forked child this is the call that makes
 an inherited handle usable again.

 `perso` may be NULL when `perso_len` is 0; NULL with a non-zero length
 returns `OxiResult::InvalidInput = 5`. A personalization string longer
 than the DRBG accepts returns `InvalidInput = 5` before any draw. A
 failed draw returns `OxiResult::Busy = 32` (retry after a pause) or
 `OxiResult::EntropyUnavailable = 33`. Every refusal leaves the handle
 as it was.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha256_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hmac_drbg_sha256_instantiate_from_module(OxiHmacDrbgSha256 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 HMAC_DRBG-SHA-256 Reseed from the module's seed path
 (SP 800-90A §10.1.2.4), with optional additional input.

 `additional` may be NULL when `additional_len` is 0; NULL with a
 non-zero length returns `OxiResult::InvalidInput = 5`. A handle never
 instantiated with [`oxi_hmac_drbg_sha256_instantiate_from_module`]
 returns `OxiResult::Uninstantiated = 8`, and a handle instantiated by
 another process returns `InvalidInput = 5`. Additional input longer
 than the DRBG accepts returns `InvalidInput = 5` before any draw. A
 failed draw returns `OxiResult::Busy = 32` or
 `OxiResult::EntropyUnavailable = 33`.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha256_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hmac_drbg_sha256_reseed_from_module(OxiHmacDrbgSha256 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 HMAC_DRBG-SHA-256 Generate (SP 800-90A §10.1.2.5).

 Produces `out_len` pseudorandom bytes into `out`. The DRBG reseeds
 itself from the module's seed path when it reaches the SP 800-90A
 reseed interval, so `OxiResult::ReseedRequired = 9` never occurs.

 `additional_input` may be NULL when `additional_input_len` is 0
 (mapped to upstream `additional_input = None`); a NULL with
 non-zero length returns `OxiResult::NullPointer = 10`.

 Returns `OxiResult::Uninstantiated = 8` if the handle was never
 instantiated with [`oxi_hmac_drbg_sha256_instantiate_from_module`],
 and `OxiResult::InvalidInput = 5` if it was instantiated by another
 process or `additional_input_len` exceeds the additional input the
 DRBG accepts from a module reseed. Returns
 `OxiResult::OutputTooLong = 12` if `out_len` exceeds the
 SP 800-90A Table 3 `max_number_of_bits_per_request` ceiling
 (`2^19` bits = 65 536 bytes). `out` is written only on success.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha256_new`], not in use by another call.
 `out` must point to ≥ `out_len` writable bytes (or `out_len == 0`).
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
 HMAC_DRBG-SHA-384 Instantiate from the module's seed path
 (SP 800-90A §10.1.2.3). See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
 The instantiated security strength is 256 bits (SP 800-57 Part 1).

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha384_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hmac_drbg_sha384_instantiate_from_module(OxiHmacDrbgSha384 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 HMAC_DRBG-SHA-384 Reseed from the module's seed path
 (SP 800-90A §10.1.2.4). See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha384_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hmac_drbg_sha384_reseed_from_module(OxiHmacDrbgSha384 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 HMAC_DRBG-SHA-384 Generate (SP 800-90A §10.1.2.5). See
 [`oxi_hmac_drbg_sha256_generate`] for full contract; the
 `out_len` ceiling is the alg-independent
 `max_number_of_bits_per_request` = `2^19` bits = 65 536 bytes.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha384_new`], not in use by another call.
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
 HMAC_DRBG-SHA-512 Instantiate from the module's seed path
 (SP 800-90A §10.1.2.3). See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.
 The instantiated security strength is 256 bits, with a wider internal
 `(K, V)` of 64 bytes each.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha512_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hmac_drbg_sha512_instantiate_from_module(OxiHmacDrbgSha512 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 HMAC_DRBG-SHA-512 Reseed from the module's seed path
 (SP 800-90A §10.1.2.4). See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha512_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hmac_drbg_sha512_reseed_from_module(OxiHmacDrbgSha512 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 HMAC_DRBG-SHA-512 Generate (SP 800-90A §10.1.2.5). See
 [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hmac_drbg_sha512_new`], not in use by another call.
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
 Hash_DRBG-SHA-256 Instantiate from the module's seed path
 (SP 800-90A §10.1.1.2). See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha256_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hash_drbg_sha256_instantiate_from_module(OxiHashDrbgSha256 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 Hash_DRBG-SHA-256 Reseed from the module's seed path
 (SP 800-90A §10.1.1.3). See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha256_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hash_drbg_sha256_reseed_from_module(OxiHashDrbgSha256 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 Hash_DRBG-SHA-256 Generate (SP 800-90A §10.1.1.4). See
 [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha256_new`], not in use by another call.
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
 Hash_DRBG-SHA-384 Instantiate from the module's seed path. The
 instantiated security strength is 256 bits (SP 800-57 Part 1). See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha384_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hash_drbg_sha384_instantiate_from_module(OxiHashDrbgSha384 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 Hash_DRBG-SHA-384 Reseed from the module's seed path. See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha384_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hash_drbg_sha384_reseed_from_module(OxiHashDrbgSha384 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 Hash_DRBG-SHA-384 Generate. See [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha384_new`], not in use by another call.
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
 Hash_DRBG-SHA-512 Instantiate from the module's seed path. The
 instantiated security strength is 256 bits. See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha512_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_hash_drbg_sha512_instantiate_from_module(OxiHashDrbgSha512 *handle,
                                                 const uint8_t *perso,
                                                 uintptr_t perso_len);

/*
 Hash_DRBG-SHA-512 Reseed from the module's seed path. See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha512_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_hash_drbg_sha512_reseed_from_module(OxiHashDrbgSha512 *handle,
                                            const uint8_t *additional,
                                            uintptr_t additional_len);

/*
 Hash_DRBG-SHA-512 Generate. See [`oxi_hmac_drbg_sha256_generate`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_hash_drbg_sha512_new`], not in use by another call.
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
 must subsequently call
 [`oxi_ctr_drbg_aes128_instantiate_from_module`] before generate /
 reseed becomes operational.

 # Safety

 `out_handle` must be a valid pointer to a writable
 `*mut OxiCtrDrbgAes128`.
 */
int oxi_ctr_drbg_aes128_new(OxiCtrDrbgAes128 **out_handle);

/*
 Free a CTR_DRBG-AES-128 handle. NULL-safe. Drop on the upstream
 `CtrDrbgAes128` zeroizes the internal `(Key, V, reseed_counter)`
 state via `oxicrypt-zeroize`, and every byte of the handle is then wiped
 before its memory is released.

 # Safety

 `handle` must be either NULL or a pointer previously returned by
 [`oxi_ctr_drbg_aes128_new`] that has not yet been freed.
 */
void oxi_ctr_drbg_aes128_free(OxiCtrDrbgAes128 *handle);

/*
 CTR_DRBG-AES-128 Instantiate from the module's seed path, through the
 derivation function (SP 800-90A §10.2.1.3.2). The instantiated security
 strength is 128 bits. See
 [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes128_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_ctr_drbg_aes128_instantiate_from_module(OxiCtrDrbgAes128 *handle,
                                                const uint8_t *perso,
                                                uintptr_t perso_len);

/*
 CTR_DRBG-AES-128 Reseed from the module's seed path, through the
 derivation function (SP 800-90A §10.2.1.4.2). See
 [`oxi_hmac_drbg_sha256_reseed_from_module`] for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes128_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_ctr_drbg_aes128_reseed_from_module(OxiCtrDrbgAes128 *handle,
                                           const uint8_t *additional,
                                           uintptr_t additional_len);

/*
 CTR_DRBG-AES-128 Generate, **df** variant (SP 800-90A
 §10.2.1.5.2). `additional_input` is passed through
 `Block_Cipher_df` before being mixed in, and is bounded by the
 additional input the DRBG accepts from a module reseed; longer
 returns `OxiResult::InvalidInput = 5`. NULL+0 is the no-AI call;
 NULL with non-zero length returns `OxiResult::NullPointer = 10`.
 `out_len` is bounded by `2^16` bytes. See
 [`oxi_hmac_drbg_sha256_generate`] for the rest of the contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes128_new`], not in use by another call. `out` must
 point to ≥ `out_len` writable bytes. `additional_input` must point
 to ≥ `additional_input_len` readable bytes when
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
 CTR_DRBG-AES-192 Instantiate from the module's seed path, through the
 derivation function. The instantiated security strength is 192 bits.
 See [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full
 contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes192_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_ctr_drbg_aes192_instantiate_from_module(OxiCtrDrbgAes192 *handle,
                                                const uint8_t *perso,
                                                uintptr_t perso_len);

/*
 CTR_DRBG-AES-192 Reseed from the module's seed path, through the
 derivation function. See [`oxi_hmac_drbg_sha256_reseed_from_module`]
 for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes192_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_ctr_drbg_aes192_reseed_from_module(OxiCtrDrbgAes192 *handle,
                                           const uint8_t *additional,
                                           uintptr_t additional_len);

/*
 CTR_DRBG-AES-192 Generate, df. See [`oxi_ctr_drbg_aes128_generate_df`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes192_new`], not in use by another call. `out` must
 point to ≥ `out_len` writable bytes. `additional_input` must point
 to ≥ `additional_input_len` readable bytes when
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
 CTR_DRBG-AES-256 Instantiate from the module's seed path, through the
 derivation function. The instantiated security strength is 256 bits.
 See [`oxi_hmac_drbg_sha256_instantiate_from_module`] for the full
 contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes256_new`], not in use by another call. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_ctr_drbg_aes256_instantiate_from_module(OxiCtrDrbgAes256 *handle,
                                                const uint8_t *perso,
                                                uintptr_t perso_len);

/*
 CTR_DRBG-AES-256 Reseed from the module's seed path, through the
 derivation function. See [`oxi_hmac_drbg_sha256_reseed_from_module`]
 for the full contract.

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes256_new`], not in use by another call. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_ctr_drbg_aes256_reseed_from_module(OxiCtrDrbgAes256 *handle,
                                           const uint8_t *additional,
                                           uintptr_t additional_len);

/*
 CTR_DRBG-AES-256 Generate, df. See [`oxi_ctr_drbg_aes128_generate_df`].

 # Safety

 `handle` must be NULL or a live handle from
 [`oxi_ctr_drbg_aes256_new`], not in use by another call. `out` must
 point to ≥ `out_len` writable bytes. `additional_input` must point
 to ≥ `additional_input_len` readable bytes when
 `additional_input_len > 0`.
 */
int oxi_ctr_drbg_aes256_generate_df(OxiCtrDrbgAes256 *handle,
                                    const uint8_t *additional_input,
                                    uintptr_t additional_input_len,
                                    uint8_t *out,
                                    uintptr_t out_len);

/*
 Construct an uninstantiated handle holding HMAC_DRBG with SHA-256.

 Writes the handle to `*out` and returns `Ok = 0`. The caller owns it and
 releases it with `oxi_drbg_free`. Instantiate it with
 `oxi_drbg_instantiate` before generating: until then `oxi_drbg_generate`,
 `oxi_drbg_reseed` and `oxi_drbg_strength_bits` return
 `Uninstantiated = 8`.

 Returns `NullPointer = 10` when `out` is NULL, and `Internal = 255`
 when the allocation fails, leaving `*out` unchanged in both cases.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hmac_drbg_sha256_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding HMAC_DRBG with SHA-384.
 Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hmac_drbg_sha384_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding HMAC_DRBG with SHA-512.
 Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hmac_drbg_sha512_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding Hash_DRBG with SHA-256.
 Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hash_drbg_sha256_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding Hash_DRBG with SHA-384.
 Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hash_drbg_sha384_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding Hash_DRBG with SHA-512.
 Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_hash_drbg_sha512_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding CTR_DRBG with AES-128 and the
 derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_ctr_drbg_aes128_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding CTR_DRBG with AES-192 and the
 derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_ctr_drbg_aes192_new_rbg(OxiDrbg **out);

/*
 Construct an uninstantiated handle holding CTR_DRBG with AES-256 and the
 derivation function. Otherwise as `oxi_hmac_drbg_sha256_new_rbg`.

 # Safety

 `out` must be NULL or valid for a write of one pointer.
 */
int oxi_ctr_drbg_aes256_new_rbg(OxiDrbg **out);

/*
 Instantiate the handle's DRBG from the module's seed path, with an
 optional personalization string, replacing any earlier instantiation.

 `perso` may be NULL when `perso_len` is 0. A personalization string
 longer than the DRBG accepts returns `InvalidInput = 5` before any draw.
 A failed draw returns `Busy = 32` (retry after a pause) or
 `EntropyUnavailable = 33`; the handle keeps its earlier instantiation,
 except on a take-over (below), where the parent's instance is already
 reset and the handle is uninstantiated.

 On a handle inherited across fork, this is the call that makes it usable
 in the child, including a handle a thread of the parent was instantiating
 for the first time at the fork. Exactly one thread of the child takes the
 handle over: it takes the hold, which a thread of the parent may have
 held at the fork, resets the parent's DRBG instance, instantiates afresh
 and records the child's process id. Every other thread calling on the handle meanwhile
 returns `Busy = 32`. If that instantiation fails, the handle holds no
 state from the parent and returns `Uninstantiated = 8` until it is
 instantiated.

 # Safety

 `h` must be NULL or a live handle from a `_new_rbg` function. A non-NULL
 `perso` must be valid for reads of `perso_len` bytes.
 */
int oxi_drbg_instantiate(OxiDrbg *h, const uint8_t *perso, uintptr_t perso_len);

/*
 Reseed the handle's DRBG from the module's seed path, with optional
 additional input.

 `additional` may be NULL when `additional_len` is 0. Additional input
 longer than the DRBG accepts returns `InvalidInput = 5` before any draw.
 A failed draw returns `Busy = 32` (retry after a pause) or
 `EntropyUnavailable = 33`.

 # Safety

 `h` must be NULL or a live handle from a `_new_rbg` function. A non-NULL
 `additional` must be valid for reads of `additional_len` bytes.
 */
int oxi_drbg_reseed(OxiDrbg *h, const uint8_t *additional, uintptr_t additional_len);

/*
 Fill `out` with `out_len` bytes from the handle's DRBG, with optional
 additional input.

 `additional` may be NULL when `additional_len` is 0; additional input
 longer than the DRBG accepts from a reseed returns `InvalidInput = 5`.
 A request above 65536 bytes returns `OutputTooLong = 12`. A handle that
 reaches its reseed interval reseeds itself from the seed path first, and
 a failed draw then returns `Busy = 32` or `EntropyUnavailable = 33`.
 `out` is written only on success, and must not overlap `additional`.

 # Safety

 `h` must be NULL or a live handle from a `_new_rbg` function. `out` must
 be valid for writes of `out_len` bytes. A non-NULL `additional` must be
 valid for reads of `additional_len` bytes.
 */
int oxi_drbg_generate(OxiDrbg *h,
                      const uint8_t *additional,
                      uintptr_t additional_len,
                      uint8_t *out,
                      uintptr_t out_len);

/*
 Write the security strength, in bits, of the handle's DRBG to `*out`.

 Returns `Uninstantiated = 8` for a handle never instantiated.

 # Safety

 `h` must be NULL or a live handle from a `_new_rbg` function. `out` must
 be NULL or valid for a write of one `uint32_t`.
 */
int oxi_drbg_strength_bits(const OxiDrbg *h, uint32_t *out);

/*
 Free a handle. NULL is a no-op.

 The held DRBG's key material is wiped, then every byte of the handle,
 before its memory is released. Freeing a handle another thread is using,
 or freeing one twice, is undefined behaviour.

 # Safety

 `h` must be NULL or a live handle from a `_new_rbg` function that no
 other thread is using.
 */
void oxi_drbg_free(OxiDrbg *h);

/*
 Run the entropy source's on-demand test on the module's seed path.

 On the jitter path this runs the source's SP 800-90B on-demand health
 tests; on the operating-system path it performs one fill. The first call
 in a process decides the seed path, as the first draw does.

 Returns `Ok = 0`, `NotOperational = 1`, `Busy = 32` (retry after a
 pause) or `EntropyUnavailable = 33` (the test failed and the module has
 entered its error state). When `label_out` is not NULL, on `0` and `33`
 it is set to a static NUL-terminated label naming the seed path: on `0`
 the path just tested; on `33` the path the process has decided, or
 `undecided` when no draw has decided it. The string must not be freed.

 # Safety

 `label_out` must be NULL or valid for a write of one pointer.
 */
int oxi_entropy_on_demand_test(const char **label_out);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* OXICRYPT_H */
