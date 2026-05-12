//! C ABI for SP 800-90A DRBGs.
//!
//! This round wires the **HMAC-SHA-256** variant of HMAC_DRBG —
//! the workhorse PRNG used to satisfy the deferred follow-ups
//! across the C ABI backfill arc (ECDSA `generate` / `sign_sha*`,
//! ECDH `generate`, RSA sign / OAEP / keygen, DH-3072 keygen),
//! all of which need *some* DRBG. The other 8 variants
//! (HMAC-SHA-384/512, Hash-SHA-256/384/512, CTR-AES-128/192/256
//! with `_df` and `_no_df`) ship additively per stabilized arc
//! pattern #8 (per-variant naming, no enum dispatch).
//!
//! # Lifecycle
//!
//! ```text
//!   oxi_hmac_drbg_sha256_new(out_handle)
//!     → returns OxiResult::Ok and *out_handle = <heap handle>
//!
//!   oxi_hmac_drbg_sha256_instantiate(handle, entropy, nonce, perso)
//!     → seeds (K, V), sets reseed_counter = 1, transitions to instantiated
//!
//!   oxi_hmac_drbg_sha256_generate(handle, additional_input, out)
//!     → produces bytes, advances (K, V), increments reseed_counter
//!     → if reseed_counter > SP 800-90A Table 3 reseed_interval,
//!       returns OxiResult::ReseedRequired = 9 (caller must reseed
//!       and retry)
//!
//!   oxi_hmac_drbg_sha256_reseed(handle, entropy, additional_input)
//!     → re-seeds (K, V), resets reseed_counter to 1
//!
//!   oxi_hmac_drbg_sha256_free(handle)
//!     → NULL-safe; reclaims the heap handle. Drop fires Zeroize on
//!       the upstream HmacDrbgSha256 so (K, V) are zeroed.
//! ```
//!
//! # Entropy plumbing
//!
//! The module does NOT bundle an entropy source. Per
//! `oxicrypt_drbg::lib.rs` upstream design: every entropy-consuming
//! call (`instantiate`, `reseed`, `generate_pr`) takes the entropy
//! input as a caller-supplied byte buffer; the C ABI faithfully
//! mirrors this. Callers source entropy from an SP 800-90A-conformant
//! source (`/dev/urandom` on Linux, BCryptGenRandom on Windows,
//! `Security.framework` on macOS, or a hardware TRNG). This is the
//! same convention as every other PQ / classical caller-seeded
//! surface in the FFI (Ed25519, ML-DSA-87, ML-KEM-1024,
//! SLH-DSA-256s, LMS, XMSS).
//!
//! Prediction-resistance (`generate_pr`) is NOT exposed this round
//! because SP 800-90A §9.3.1 step 7 specifies it as
//! `reseed(entropy, ai)` followed by `generate(None, out)` — callers
//! can compose this trivially. Skipping reduces the surface from 5
//! to 4 method types per variant.
//!
//! # Error codes
//!
//! Only `_instantiate` can surface module-level errors
//! (`NotOperational`, `AlgorithmRestricted`); upstream gates only
//! fire on instantiate. `_reseed` and `_generate` inherit
//! operational state via the upstream `instantiated` flag and
//! therefore return DRBG-specific errors only.
//!
//! | Upstream | OxiResult | Surfaceable from |
//! |---|---|---|
//! | `Err(Module(NotOperational))` | `NotOperational = 1` | `_instantiate` only |
//! | `Err(Module(AlgorithmRestricted))` | `AlgorithmRestricted = 6` | `_instantiate` only |
//! | `Err(Module(InvalidInput))` | `InvalidInput = 5` | `_instantiate` only (total seed > 768 bytes) |
//! | `Err(DrbgError::Uninstantiated)` | `Uninstantiated = 8` | `_reseed`, `_generate` |
//! | `Err(DrbgError::ReseedRequired)` | `ReseedRequired = 9` | `_generate` only |
//! | `Err(DrbgError::InputTooLong)` | `InvalidInput = 5` | `_reseed`, `_generate` |
//! | `Err(DrbgError::RequestTooLong)` | `OutputTooLong = 12` | `_generate` only (out_len > 2^19 bits) |
//! | NULL handle / NULL output | `NullPointer = 10` | all three (FFI-layer guard) |
//!
//! Slots `8` and `9` are new this round; they were added to the
//! `OxiResult` enum in `error.rs` because collapsing them to
//! `InvalidInput = 5` would have prevented callers from
//! distinguishing "I need to call instantiate" from "I need to
//! reseed" from "my input is malformed" — three distinct recovery
//! paths per SP 800-90A.
//!
//! # Thread-safety contract
//!
//! `OxiHmacDrbgSha256` is a per-call-mutating handle: every
//! `_instantiate`, `_reseed`, and `_generate` call advances the
//! internal `(K, V, reseed_counter)` state. Rust enforces
//! exclusive access at the call site via the `&mut self`
//! projection in `OxiHandle::as_mut`, but the C ABI cannot
//! enforce this across threads: two C threads racing on the same
//! `*mut OxiHmacDrbgSha256` pointer would create a data race and
//! is undefined behaviour. **Caller MUST serialize all
//! `oxi_hmac_drbg_sha256_*` calls on a given handle pointer
//! externally** (mutex, single-threaded ownership, or equivalent
//! discipline). This is the first per-call-mutating handle in the
//! C ABI — AES handles are read-only-from-C and the HBS
//! byte-buffer surface side-steps the issue by passing state
//! through the function signature. The same serialization
//! contract will apply to every future per-call-mutating handle
//! (additional DRBG variants, future streaming SHA contexts,
//! etc.).
//!
//! # Handle lifecycle invariant
//!
//! `OxiHmacDrbgSha256` follows the same opaque-handle pattern as
//! `OxiAes256Key` (see `aes.rs`). The internal state lives on the
//! heap; the caller holds a `*mut OxiHmacDrbgSha256` and MUST pair
//! every `_new` with a `_free`. Distinct from the LMS / XMSS
//! byte-buffer pass-through: DRBG state is process-local (not
//! durably persisted across reboots), so the handle pattern is the
//! right shape; HBS keys carried a different one-write-per-leaf
//! invariant that the byte-buffer surface enforced structurally.

use crate::error::{OxiResult as R, status_drbg, status_module};
use crate::handle::OxiHandle;
use core::ffi::c_int;
use oxicrypt_drbg::{
    CtrDrbgAes128, CtrDrbgAes192, CtrDrbgAes256, HashDrbgSha256, HashDrbgSha384, HashDrbgSha512,
    HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512,
};

/// Opaque HMAC_DRBG-SHA-256 handle. The internal layout
/// (`OxiHandle<HmacDrbgSha256>`) is implementation detail and not
/// part of the C ABI; cbindgen renders this as an opaque struct.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha256 {
    inner: OxiHandle<HmacDrbgSha256>,
}

impl OxiHmacDrbgSha256 {
    /// Crate-internal accessor for the underlying mutable
    /// `HmacDrbgSha256`. Used by other FFI surfaces in this crate
    /// that consume a DRBG handle as a parameter (e.g.
    /// `oxi_dh3072_generate_keypair`). Keeps the `inner` field
    /// private while exposing the projection needed for
    /// DRBG-handle-as-parameter surfaces.
    ///
    /// Returns `None` if the handle has been finalized (today: never,
    /// because DRBG handles do not have a finalize-bearing lifecycle —
    /// the consumed-sentinel field is unused for DRBG, same as AES).
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HmacDrbgSha256> {
        self.inner.as_mut()
    }
}

/// Allocate a new, **uninstantiated** HMAC_DRBG-SHA-256 handle.
///
/// On success, writes a heap-allocated handle pointer through
/// `out_handle` and returns `OxiResult::Ok = 0`. The caller owns
/// the handle and MUST release it with [`oxi_hmac_drbg_sha256_free`].
///
/// The newly-allocated handle is uninstantiated — calling
/// [`oxi_hmac_drbg_sha256_generate`] or
/// [`oxi_hmac_drbg_sha256_reseed`] before
/// [`oxi_hmac_drbg_sha256_instantiate`] returns
/// `OxiResult::Uninstantiated = 8`.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_new(
    out_handle: *mut *mut OxiHmacDrbgSha256,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha256 {
        inner: OxiHandle::new(HmacDrbgSha256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-256 handle. NULL-safe.
///
/// After this call the caller's pointer is dangling; the caller
/// SHOULD set their pointer to NULL to avoid use-after-free. A
/// double-free of the same non-NULL pointer is undefined behaviour
/// (matches malloc/free semantics — the shim cannot detect it).
///
/// Drop on the upstream `HmacDrbgSha256` zeroizes the internal
/// `(K, V)` state via the workspace-wide `oxicrypt-zeroize`
/// volatile-write convention; no caller-side scrubbing is required.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_free(handle: *mut OxiHmacDrbgSha256) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// HMAC_DRBG-SHA-256 Instantiate (SP 800-90A §10.1.2.3).
///
/// Seeds the DRBG with caller-supplied entropy, nonce, and
/// personalization. The combined length
/// `entropy_len + nonce_len + perso_len` MUST NOT exceed
/// `HMAC_DRBG_MAX_PROVIDED = 768` bytes; over-length returns
/// `OxiResult::InvalidInput = 5`.
///
/// Each input may be NULL when its corresponding length is 0.
/// Personalization length 0 is the typical path for FIPS-conformant
/// callers that don't have a personalization string; entropy and
/// nonce SHOULD be sized per SP 800-90A Table 2 (security strength
/// 256 → entropy ≥ 256 bits, nonce ≥ 128 bits).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_instantiate(
    handle: *mut OxiHmacDrbgSha256,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    // SAFETY: per the handle lifecycle contract documented in security
    // policy §4.8, the caller MUST not race `_free` against an in-flight
    // call on the same handle. DRBG mutates per call, so we use `as_mut`
    // (added to OxiHandle this round) — the `&mut self` projection
    // upholds Rust's exclusivity rule for the duration of the call.
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// HMAC_DRBG-SHA-256 Reseed (SP 800-90A §10.1.2.4).
///
/// Re-seeds the DRBG with fresh entropy and (optionally) additional
/// input. After successful reseed, `reseed_counter` is reset to 1
/// and the handle is ready to serve new `generate` calls.
///
/// `additional_input` may be NULL when `additional_input_len` is 0.
/// `entropy` MUST point to ≥ `entropy_len` readable bytes.
///
/// Returns `OxiResult::Uninstantiated = 8` if the handle has not yet
/// been instantiated. Returns `OxiResult::InvalidInput = 5` if the
/// combined `entropy_len + additional_input_len` exceeds
/// `HMAC_DRBG_MAX_PROVIDED = 768` bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_reseed(
    handle: *mut OxiHmacDrbgSha256,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// HMAC_DRBG-SHA-256 Generate (SP 800-90A §10.1.2.5).
///
/// Produces `out_len` pseudorandom bytes into `out`, advancing the
/// internal `(K, V)` state and incrementing `reseed_counter`.
///
/// `additional_input` may be NULL when `additional_input_len` is 0
/// (mapped to upstream `additional_input = None`); a NULL with
/// non-zero length returns `OxiResult::NullPointer = 10`.
///
/// Returns `OxiResult::Uninstantiated = 8` if `instantiate` has not
/// yet succeeded on this handle. Returns `OxiResult::ReseedRequired = 9`
/// if `reseed_counter` has reached the SP 800-90A Table 3 bound; the
/// caller MUST call [`oxi_hmac_drbg_sha256_reseed`] before retrying.
/// Returns `OxiResult::OutputTooLong = 12` if `out_len` exceeds the
/// SP 800-90A Table 3 `max_number_of_bits_per_request` ceiling
/// (`2^19` bits = 65 536 bytes).
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hmac_drbg_sha256_new`].
/// `out` must point to ≥ `out_len` writable bytes (or `out_len == 0`,
/// in which case the call is a no-op state advance — useful only as
/// part of a `reseed`-then-`generate(None, [])` PR equivalence).
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha256_generate(
    handle: *mut OxiHmacDrbgSha256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    // additional_input: NULL+0 → None; non-NULL+>0 → Some(slice).
    // (NULL+>0 is rejected by slice_from_raw with NullPointer.)
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

// ── HMAC-DRBG-SHA-384 / -SHA-512 — additive variants ─────────────
//
// Pure stencil mirror of `OxiHmacDrbgSha256` for the wider HMAC-DRBG
// hashes (SP 800-90A §10.1.2). The upstream `HmacDrbg<H: HmacAlg>`
// is parametric over the hash alg, with `HmacDrbgSha384` and
// `HmacDrbgSha512` already shipped as type aliases at
// `crates/oxicrypt-drbg/src/hmac.rs:122`/`:124` — wider security
// strengths (256-bit vs SHA-384's instantiate-time 192-bit floor and
// SHA-512's 256-bit; per SP 800-90A Table 2 / Table 3) but identical
// `instantiate / reseed / generate` shape. Same per-call-mutating
// thread-safety contract, same `(K, V, reseed_counter)` Drop-zeroize,
// same `OxiResult` discriminant set (Ok / NotOperational /
// InvalidInput / AlgorithmRestricted / Uninstantiated /
// ReseedRequired / OutputTooLong / NullPointer); see the SHA-256
// rustdocs above for the full contract — comments here cite only
// hash-specific deltas.

/// Opaque HMAC_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha384 {
    inner: OxiHandle<HmacDrbgSha384>,
}

impl OxiHmacDrbgSha384 {
    /// Crate-internal mutable accessor; mirrors
    /// `OxiHmacDrbgSha256::inner_mut`. Future DRBG-handle-as-parameter
    /// surfaces wired to SHA-384 will use this projection.
    #[allow(dead_code)] // first call site lands when a SHA-384-DRBG-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HmacDrbgSha384> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated HMAC_DRBG-SHA-384 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha384`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_new(
    out_handle: *mut *mut OxiHmacDrbgSha384,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha384 {
        inner: OxiHandle::new(HmacDrbgSha384::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-384 handle. NULL-safe. See
/// [`oxi_hmac_drbg_sha256_free`] for zeroization semantics.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha384_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_free(handle: *mut OxiHmacDrbgSha384) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// HMAC_DRBG-SHA-384 Instantiate (SP 800-90A §10.1.2.3). See
/// [`oxi_hmac_drbg_sha256_instantiate`] for full contract; the
/// `entropy_len + nonce_len + perso_len` ceiling is the same upstream
/// `HMAC_DRBG_MAX_PROVIDED = 768` bytes (alg-independent constant).
/// Per SP 800-90A Table 2, security strength 192 → entropy ≥ 192
/// bits, nonce ≥ 96 bits.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha384_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_instantiate(
    handle: *mut OxiHmacDrbgSha384,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// HMAC_DRBG-SHA-384 Reseed (SP 800-90A §10.1.2.4). See
/// [`oxi_hmac_drbg_sha256_reseed`] for full contract.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha384_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_reseed(
    handle: *mut OxiHmacDrbgSha384,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// HMAC_DRBG-SHA-384 Generate (SP 800-90A §10.1.2.5). See
/// [`oxi_hmac_drbg_sha256_generate`] for full contract; the
/// `out_len` ceiling is the alg-independent
/// `max_number_of_bits_per_request` = `2^19` bits = 65 536 bytes.
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hmac_drbg_sha384_new`].
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha384_generate(
    handle: *mut OxiHmacDrbgSha384,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

/// Opaque HMAC_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.
///
/// cbindgen:opaque
pub struct OxiHmacDrbgSha512 {
    inner: OxiHandle<HmacDrbgSha512>,
}

impl OxiHmacDrbgSha512 {
    #[allow(dead_code)] // first call site lands when a SHA-512-DRBG-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HmacDrbgSha512> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated HMAC_DRBG-SHA-512 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHmacDrbgSha512`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_new(
    out_handle: *mut *mut OxiHmacDrbgSha512,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHmacDrbgSha512 {
        inner: OxiHandle::new(HmacDrbgSha512::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free an HMAC_DRBG-SHA-512 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hmac_drbg_sha512_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_free(handle: *mut OxiHmacDrbgSha512) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// HMAC_DRBG-SHA-512 Instantiate (SP 800-90A §10.1.2.3). See
/// [`oxi_hmac_drbg_sha256_instantiate`] for full contract. Per
/// SP 800-90A Table 2, security strength 256 → entropy ≥ 256 bits,
/// nonce ≥ 128 bits — same as SHA-256 but with a wider internal
/// `(K, V)` of 64 bytes each.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha512_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_instantiate(
    handle: *mut OxiHmacDrbgSha512,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// HMAC_DRBG-SHA-512 Reseed (SP 800-90A §10.1.2.4). See
/// [`oxi_hmac_drbg_sha256_reseed`].
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hmac_drbg_sha512_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_reseed(
    handle: *mut OxiHmacDrbgSha512,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// HMAC_DRBG-SHA-512 Generate (SP 800-90A §10.1.2.5). See
/// [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hmac_drbg_sha512_new`].
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hmac_drbg_sha512_generate(
    handle: *mut OxiHmacDrbgSha512,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

// ── Hash-DRBG-SHA-256 / -SHA-384 / -SHA-512 — additive variants ──
//
// SP 800-90A §10.1.1 Hash_DRBG family. Pure stencil mirror of
// `OxiHmacDrbgSha{256,384,512}` above; upstream `HashDrbg<H: HashAlg>`
// is parametric over the hash with `HashDrbgSha{256,384,512}` shipping
// as type aliases at `crates/oxicrypt-drbg/src/hash.rs:139-143`. The
// `instantiate / reseed / generate` signatures are byte-identical to
// the HMAC-DRBG family (same `Result<(), Error>` for instantiate,
// `Result<(), DrbgError>` for reseed and generate, same `Option<&[u8]>`
// for generate's `additional_input`). Combined-input ceiling is
// `HASH_DRBG_MAX_DF_INPUT` (alg-independent). Per SP 800-90A Table 2,
// security strengths match HMAC: SHA-256 = 256, SHA-384 = 192,
// SHA-512 = 256 bits. No new `OxiResult` discriminants.

/// Opaque Hash_DRBG-SHA-256 handle. See `OxiHmacDrbgSha256`.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha256 {
    inner: OxiHandle<HashDrbgSha256>,
}

impl OxiHashDrbgSha256 {
    #[allow(dead_code)] // first call site lands when a Hash-DRBG-SHA-256-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HashDrbgSha256> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-256 handle. See
/// [`oxi_hmac_drbg_sha256_new`] for full contract.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_new(
    out_handle: *mut *mut OxiHashDrbgSha256,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha256 {
        inner: OxiHandle::new(HashDrbgSha256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-256 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_free(handle: *mut OxiHashDrbgSha256) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// Hash_DRBG-SHA-256 Instantiate (SP 800-90A §10.1.1.2). See
/// [`oxi_hmac_drbg_sha256_instantiate`] for full contract; per
/// SP 800-90A Table 2, security strength 256 → entropy ≥ 256 bits,
/// nonce ≥ 128 bits. Combined-input ceiling is the alg-independent
/// `HASH_DRBG_MAX_DF_INPUT` upstream constant.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_instantiate(
    handle: *mut OxiHashDrbgSha256,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// Hash_DRBG-SHA-256 Reseed (SP 800-90A §10.1.1.3). See
/// [`oxi_hmac_drbg_sha256_reseed`].
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_reseed(
    handle: *mut OxiHashDrbgSha256,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// Hash_DRBG-SHA-256 Generate (SP 800-90A §10.1.1.4). See
/// [`oxi_hmac_drbg_sha256_generate`].
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hash_drbg_sha256_new`].
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha256_generate(
    handle: *mut OxiHashDrbgSha256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

/// Opaque Hash_DRBG-SHA-384 handle. See `OxiHmacDrbgSha256`.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha384 {
    inner: OxiHandle<HashDrbgSha384>,
}

impl OxiHashDrbgSha384 {
    #[allow(dead_code)] // first call site lands when a Hash-DRBG-SHA-384-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HashDrbgSha384> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-384 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha384`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_new(
    out_handle: *mut *mut OxiHashDrbgSha384,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha384 {
        inner: OxiHandle::new(HashDrbgSha384::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-384 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha384_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_free(handle: *mut OxiHashDrbgSha384) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// Hash_DRBG-SHA-384 Instantiate. Per SP 800-90A Table 2, security
/// strength 192 → entropy ≥ 192 bits, nonce ≥ 96 bits.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha384_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_instantiate(
    handle: *mut OxiHashDrbgSha384,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// Hash_DRBG-SHA-384 Reseed.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha384_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_reseed(
    handle: *mut OxiHashDrbgSha384,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// Hash_DRBG-SHA-384 Generate.
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hash_drbg_sha384_new`].
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha384_generate(
    handle: *mut OxiHashDrbgSha384,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

/// Opaque Hash_DRBG-SHA-512 handle. See `OxiHmacDrbgSha256`.
///
/// cbindgen:opaque
pub struct OxiHashDrbgSha512 {
    inner: OxiHandle<HashDrbgSha512>,
}

impl OxiHashDrbgSha512 {
    #[allow(dead_code)] // first call site lands when a Hash-DRBG-SHA-512-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut HashDrbgSha512> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated Hash_DRBG-SHA-512 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiHashDrbgSha512`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_new(
    out_handle: *mut *mut OxiHashDrbgSha512,
) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiHashDrbgSha512 {
        inner: OxiHandle::new(HashDrbgSha512::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a Hash_DRBG-SHA-512 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_hash_drbg_sha512_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_free(handle: *mut OxiHashDrbgSha512) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// Hash_DRBG-SHA-512 Instantiate. Per SP 800-90A Table 2, security
/// strength 256 → entropy ≥ 256 bits, nonce ≥ 128 bits.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha512_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_instantiate(
    handle: *mut OxiHashDrbgSha512,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate(entropy_slice, nonce_slice, perso_slice))
}

/// Hash_DRBG-SHA-512 Reseed.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_hash_drbg_sha512_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_reseed(
    handle: *mut OxiHashDrbgSha512,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed(entropy_slice, ai_slice))
}

/// Hash_DRBG-SHA-512 Generate.
///
/// # Safety
///
/// `handle` must be a live handle from [`oxi_hash_drbg_sha512_new`].
/// `out` must point to ≥ `out_len` writable bytes.
/// `additional_input` must point to ≥ `additional_input_len`
/// readable bytes when `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_hash_drbg_sha512_generate(
    handle: *mut OxiHashDrbgSha512,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate(ai_opt, out_slice))
}

// ── CTR-DRBG-AES-128 / -192 / -256 — additive variants ──────────
//
// SP 800-90A §10.2 CTR_DRBG family. Same opaque-handle / `OxiHandle<T>`
// / Drop-zeroize / per-call-mutating contract as the HMAC-DRBG and
// Hash-DRBG families above; differs in upstream construction (block
// cipher CTR mode per §10.2 vs hash-based per §10.1.1/§10.1.2) AND
// — uniquely among the three DRBG families — exposes BOTH `_no_df`
// and `_df` derivation modes through DISTINCT entry points per
// lifecycle stage rather than a runtime flag.
//
// **df vs no-df (SP 800-90A §10.2.1):** the `no_df` variant requires
// the caller to supply seed material that is already a full-entropy
// string of exactly `SEED_LEN` bytes (= `KEY_LEN + OUTLEN` per the
// underlying block cipher). The `df` variant runs `Block_Cipher_df`
// over arbitrary-length entropy + nonce + personalization input
// (capped at `MAX_DF_INPUT`) to derive the seed. SP 800-90A allows
// either; the choice is a deployment-environment decision (the no_df
// path is for callers with a hardware RNG that outputs full-entropy
// blocks; the df path is for callers with a non-full-entropy source
// or who want personalization). We surface BOTH because lab-grade
// callers exercise both — collapsing them into a runtime `use_df`
// flag would force conditional FFI-side validation that obscures the
// upstream's distinct preconditions (no_df: exact length; df:
// variable length up to MAX_DF_INPUT). One-to-one upstream-to-FFI
// mapping is the reviewer-legible default.
//
// Per SP 800-90A Table 3, security strength is 128 / 192 / 256 bits
// for CTR-AES-128 / -192 / -256 (matches the underlying block-cipher
// key length). `SEED_LEN` is `KEY_LEN + OUTLEN` = 32 / 40 / 48 bytes.
// `RESEED_INTERVAL` is `2^48` per Table 3. `max_number_of_bits_per_request`
// is `2^19` bits — alg-independent across all DRBG families. No new
// `OxiResult` discriminants this round; the discriminant set is
// already covered by `From<oxicrypt_module::Error>` +
// `From<DrbgError>` (DrbgError::InvalidSeedLength → InvalidInput,
// DrbgError::InputTooLong → InvalidInput, DrbgError::RequestTooLong
// → OutputTooLong; verified at error.rs:185-188).

/// Opaque CTR_DRBG-AES-128 handle. See `OxiHmacDrbgSha256` for the
/// per-call-mutating thread-safety and Drop-zeroize contract.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes128 {
    inner: OxiHandle<CtrDrbgAes128>,
}

impl OxiCtrDrbgAes128 {
    #[allow(dead_code)] // first call site lands when a CTR-AES-128-DRBG-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut CtrDrbgAes128> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-128 handle. Caller
/// must subsequently call exactly one of
/// [`oxi_ctr_drbg_aes128_instantiate_no_df`] or
/// [`oxi_ctr_drbg_aes128_instantiate_df`] before generate / reseed
/// becomes operational.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes128`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_new(out_handle: *mut *mut OxiCtrDrbgAes128) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes128 {
        inner: OxiHandle::new(CtrDrbgAes128::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-128 handle. NULL-safe. Drop on the upstream
/// `CtrDrbgAes128` zeroizes the internal `(Key, V, reseed_counter)`
/// state via `oxicrypt-zeroize`.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes128_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_free(handle: *mut OxiCtrDrbgAes128) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// CTR_DRBG-AES-128 Instantiate, **no-df** variant (SP 800-90A
/// §10.2.1.3.1). `seed_material` MUST be exactly `SEED_LEN` = 32
/// bytes (= AES-128 key length 16 + AES block size 16) and MUST
/// equal `entropy_input || personalization_string` per the spec's
/// no-df construction. Seed-length mismatch returns
/// `OxiResult::InvalidInput = 5` — there is no auto-extend or
/// auto-truncate at the FFI boundary.
///
/// # Safety
///
/// `handle` must be a live handle from
/// [`oxi_ctr_drbg_aes128_new`]. `seed_material` must point to ≥
/// `seed_material_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_instantiate_no_df(
    handle: *mut OxiCtrDrbgAes128,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_no_df(seed_slice))
}

/// CTR_DRBG-AES-128 Instantiate, **df** variant (SP 800-90A
/// §10.2.1.3.2). Runs `Block_Cipher_df(entropy || nonce ||
/// personalization, seedlen)` to derive the initial seed material.
/// Combined-length ceiling is `MAX_DF_INPUT` (alg-independent).
/// Each input may be NULL when its length is 0. Per SP 800-90A
/// Table 3, security strength 128 → entropy ≥ 128 bits, nonce ≥
/// 64 bits.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_ctr_drbg_aes128_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_instantiate_df(
    handle: *mut OxiCtrDrbgAes128,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_df(entropy_slice, nonce_slice, perso_slice))
}

/// CTR_DRBG-AES-128 Reseed, **no-df** variant (SP 800-90A
/// §10.2.1.4.1). `seed_material` MUST be exactly `SEED_LEN` = 32
/// bytes; mismatch returns `OxiResult::InvalidInput = 5`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes128_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_reseed_no_df(
    handle: *mut OxiCtrDrbgAes128,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_no_df(seed_slice))
}

/// CTR_DRBG-AES-128 Reseed, **df** variant (SP 800-90A §10.2.1.4.2).
/// Runs `Block_Cipher_df(entropy || additional_input, seedlen)` to
/// derive the new seed. Combined-length ceiling is `MAX_DF_INPUT`.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes128_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_reseed_df(
    handle: *mut OxiCtrDrbgAes128,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_df(entropy_slice, ai_slice))
}

/// CTR_DRBG-AES-128 Generate, **no-df** variant (SP 800-90A
/// §10.2.1.5.1). When `additional_input` is supplied (non-NULL +
/// non-zero len), it MUST be exactly `SEED_LEN` = 32 bytes — this
/// constraint is what makes this the no-df path; `additional_input
/// = NULL, len = 0` is the typical no-AI call. `out_len` is bounded
/// by `2^16` bytes (SP 800-90A §10.2.1.5.1 step 5).
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes128_new`]. `out` must point to ≥ `out_len`
/// writable bytes (or `out_len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_generate_no_df(
    handle: *mut OxiCtrDrbgAes128,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_no_df(ai_opt, out_slice))
}

/// CTR_DRBG-AES-128 Generate, **df** variant (SP 800-90A
/// §10.2.1.5.2). `additional_input` is variable length up to
/// `MAX_DF_INPUT` and is passed through `Block_Cipher_df` before
/// being mixed in. NULL+0 is the no-AI call; NULL with non-zero
/// length returns `OxiResult::NullPointer = 10`. `out_len` is
/// bounded by `2^16` bytes.
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes128_new`]. `out` must point to ≥ `out_len`
/// writable bytes. `additional_input` must point to ≥
/// `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes128_generate_df(
    handle: *mut OxiCtrDrbgAes128,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_df(ai_opt, out_slice))
}

/// Opaque CTR_DRBG-AES-192 handle. See `OxiCtrDrbgAes128`.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes192 {
    inner: OxiHandle<CtrDrbgAes192>,
}

impl OxiCtrDrbgAes192 {
    #[allow(dead_code)] // first call site lands when a CTR-AES-192-DRBG-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut CtrDrbgAes192> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-192 handle. See
/// [`oxi_ctr_drbg_aes128_new`].
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes192`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_new(out_handle: *mut *mut OxiCtrDrbgAes192) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes192 {
        inner: OxiHandle::new(CtrDrbgAes192::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-192 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes192_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_free(handle: *mut OxiCtrDrbgAes192) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// CTR_DRBG-AES-192 Instantiate, no-df variant. `seed_material` must
/// be exactly `SEED_LEN` = 40 bytes (AES-192 key 24 + AES block 16).
/// See [`oxi_ctr_drbg_aes128_instantiate_no_df`].
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_ctr_drbg_aes192_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_instantiate_no_df(
    handle: *mut OxiCtrDrbgAes192,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_no_df(seed_slice))
}

/// CTR_DRBG-AES-192 Instantiate, df variant. Per SP 800-90A Table 3,
/// security strength 192 → entropy ≥ 192 bits, nonce ≥ 96 bits. See
/// [`oxi_ctr_drbg_aes128_instantiate_df`].
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_ctr_drbg_aes192_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_instantiate_df(
    handle: *mut OxiCtrDrbgAes192,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_df(entropy_slice, nonce_slice, perso_slice))
}

/// CTR_DRBG-AES-192 Reseed, no-df. `seed_material` must be exactly
/// 40 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes192_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_reseed_no_df(
    handle: *mut OxiCtrDrbgAes192,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_no_df(seed_slice))
}

/// CTR_DRBG-AES-192 Reseed, df.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes192_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_reseed_df(
    handle: *mut OxiCtrDrbgAes192,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_df(entropy_slice, ai_slice))
}

/// CTR_DRBG-AES-192 Generate, no-df. When `additional_input` is
/// supplied it MUST be exactly 40 bytes.
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes192_new`]. `out` must point to ≥ `out_len`
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_generate_no_df(
    handle: *mut OxiCtrDrbgAes192,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_no_df(ai_opt, out_slice))
}

/// CTR_DRBG-AES-192 Generate, df. `additional_input` is variable up
/// to `MAX_DF_INPUT`.
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes192_new`]. `out` must point to ≥ `out_len`
/// writable bytes. `additional_input` must point to ≥
/// `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes192_generate_df(
    handle: *mut OxiCtrDrbgAes192,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_df(ai_opt, out_slice))
}

/// Opaque CTR_DRBG-AES-256 handle. See `OxiCtrDrbgAes128`.
///
/// cbindgen:opaque
pub struct OxiCtrDrbgAes256 {
    inner: OxiHandle<CtrDrbgAes256>,
}

impl OxiCtrDrbgAes256 {
    #[allow(dead_code)] // first call site lands when a CTR-AES-256-DRBG-driven primitive surfaces
    pub(crate) fn inner_mut(&mut self) -> Option<&mut CtrDrbgAes256> {
        self.inner.as_mut()
    }
}

/// Allocate a new, uninstantiated CTR_DRBG-AES-256 handle.
///
/// # Safety
///
/// `out_handle` must be a valid pointer to a writable
/// `*mut OxiCtrDrbgAes256`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_new(out_handle: *mut *mut OxiCtrDrbgAes256) -> c_int {
    if out_handle.is_null() {
        return R::NullPointer as c_int;
    }
    let boxed = Box::new(OxiCtrDrbgAes256 {
        inner: OxiHandle::new(CtrDrbgAes256::new()),
    });
    unsafe { *out_handle = Box::into_raw(boxed) };
    R::Ok as c_int
}

/// Free a CTR_DRBG-AES-256 handle. NULL-safe.
///
/// # Safety
///
/// `handle` must be either NULL or a pointer previously returned by
/// [`oxi_ctr_drbg_aes256_new`] that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_free(handle: *mut OxiCtrDrbgAes256) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// CTR_DRBG-AES-256 Instantiate, no-df. `seed_material` must be
/// exactly `SEED_LEN` = 48 bytes (AES-256 key 32 + AES block 16).
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_ctr_drbg_aes256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_instantiate_no_df(
    handle: *mut OxiCtrDrbgAes256,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_no_df(seed_slice))
}

/// CTR_DRBG-AES-256 Instantiate, df. Per SP 800-90A Table 3,
/// security strength 256 → entropy ≥ 256 bits, nonce ≥ 128 bits.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live
/// handle from [`oxi_ctr_drbg_aes256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_instantiate_df(
    handle: *mut OxiCtrDrbgAes256,
    entropy: *const u8,
    entropy_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    personalization: *const u8,
    personalization_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let nonce_slice = match unsafe { crate::slice_from_raw(nonce, nonce_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let perso_slice = match unsafe { crate::slice_from_raw(personalization, personalization_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_module(drbg.instantiate_df(entropy_slice, nonce_slice, perso_slice))
}

/// CTR_DRBG-AES-256 Reseed, no-df. `seed_material` must be exactly
/// 48 bytes.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_reseed_no_df(
    handle: *mut OxiCtrDrbgAes256,
    seed_material: *const u8,
    seed_material_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let seed_slice = match unsafe { crate::slice_from_raw(seed_material, seed_material_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_no_df(seed_slice))
}

/// CTR_DRBG-AES-256 Reseed, df.
///
/// # Safety
///
/// All pointer/length pairs must be valid. `handle` must be a live,
/// instantiated handle from [`oxi_ctr_drbg_aes256_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_reseed_df(
    handle: *mut OxiCtrDrbgAes256,
    entropy: *const u8,
    entropy_len: usize,
    additional_input: *const u8,
    additional_input_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    let entropy_slice = match unsafe { crate::slice_from_raw(entropy, entropy_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ai_slice = match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.reseed_df(entropy_slice, ai_slice))
}

/// CTR_DRBG-AES-256 Generate, no-df. When `additional_input` is
/// supplied it MUST be exactly 48 bytes.
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes256_new`]. `out` must point to ≥ `out_len`
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_generate_no_df(
    handle: *mut OxiCtrDrbgAes256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_no_df(ai_opt, out_slice))
}

/// CTR_DRBG-AES-256 Generate, df. `additional_input` is variable up
/// to `MAX_DF_INPUT`.
///
/// # Safety
///
/// `handle` must be a live, instantiated handle from
/// [`oxi_ctr_drbg_aes256_new`]. `out` must point to ≥ `out_len`
/// writable bytes. `additional_input` must point to ≥
/// `additional_input_len` readable bytes when
/// `additional_input_len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_ctr_drbg_aes256_generate_df(
    handle: *mut OxiCtrDrbgAes256,
    additional_input: *const u8,
    additional_input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return R::NullPointer as c_int;
    }
    if out.is_null() && out_len > 0 {
        return R::NullPointer as c_int;
    }
    let ai_opt: Option<&[u8]> = if additional_input.is_null() && additional_input_len == 0 {
        None
    } else {
        match unsafe { crate::slice_from_raw(additional_input, additional_input_len) } {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };
    let out_slice = match unsafe { crate::slice_from_raw_mut(out, out_len) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(drbg) = (unsafe { (*handle).inner.as_mut() }) else {
        return R::NotOperational as c_int;
    };
    status_drbg(drbg.generate_df(ai_opt, out_slice))
}
