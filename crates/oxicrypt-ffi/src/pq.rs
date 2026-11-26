//! The bodies of the ML-DSA and ML-KEM key generation, key expansion,
//! encapsulation and decapsulation symbols, shared by every parameter set.
//! Each applies the check order of the shared DRBG handle:
//!
//! 1. Each pointer and length pair, in parameter order: a NULL required
//!    pointer returns `NullPointer = 10`, and a range that runs past the top
//!    of the address space returns `InvalidInput = 5`. Then an output that
//!    shares a byte with any other range, the DRBG handle included, returns
//!    `InvalidInput = 5`.
//! 2. A module that is not operational returns `NotOperational = 1`.
//! 3. A service the active profile does not admit returns
//!    `AlgorithmRestricted = 6`, checked for the algorithm and then, on a
//!    symbol that takes a handle, for the DRBG.
//! 4. A handle inherited from another process returns `InvalidInput = 5`.
//! 5. A handle in use returns `Busy = 32`.
//! 6. The FIPS 203 §7.2 check of an encapsulation key returns
//!    `InvalidInput = 5`, then a DRBG weaker than the parameter set
//!    requires returns `RbgTooWeak = 31` (FIPS 203 §3.3, FIPS 204 §3.6.1).
//! 7. The operation, with the DRBG's codes and `ConditionalTestFailed = 3`
//!    when the pairwise consistency test fails (FIPS 140-3 IG 10.3.A).
//!
//! Outputs are copied to the caller only on success, each after the module
//! state is checked again; a refused copy zeroes the outputs already
//! copied.

use crate::aes::{disjoint, input, span, write_all};
use crate::error::OxiResult as R;
use crate::rbg::{DrbgKind, OxiDrbg, with_held};
use oxicrypt_module::{Error, Service};
use oxicrypt_zeroize::Zeroizing;

/// A key pair as the Rust key generation functions return it.
pub(crate) type Pair<const P: usize, const S: usize> = ([u8; P], [u8; S]);

/// A seed and a key pair as the `keygen_with_seed` functions return it.
pub(crate) type SeededPair<const N: usize, const P: usize, const S: usize> =
    (Zeroizing<[u8; N]>, [u8; P], [u8; S]);

/// A shared secret and ciphertext as the Rust encapsulation functions
/// return them.
pub(crate) type Encapsulated<const C: usize> = ([u8; 32], [u8; C]);

/// A Rust decapsulation function of a parameter set.
pub(crate) type Decapsulate<const K: usize, const C: usize> =
    fn(&[u8; K], &[u8; C]) -> Result<[u8; 32], Error>;

/// The fixed-size array a caller range of exactly `N` bytes is. Every range
/// passed here was taken at length `N`, so the mismatch is unreachable and
/// reports `Internal`.
fn array<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], R> {
    bytes.try_into().map_err(|_| R::Internal)
}

/// Steps 2 and 3 for the algorithm's own service.
fn admit(service: Service) -> Result<(), R> {
    oxicrypt_module::require_operational().map_err(R::from)?;
    oxicrypt_module::require_allowed(service).map_err(R::from)
}

/// Key generation from the caller's DRBG handle: writes the public key to
/// `pk_out`, the secret key to `sk_out` and, when `seed_out` is not NULL,
/// the seed to `seed_out`.
///
/// # Safety
///
/// `rbg` must be NULL or a live handle from a `_new_rbg` function; `pk_out`
/// and `sk_out` NULL or valid for writes of `P` and `S` bytes; `seed_out`
/// NULL or valid for writes of `N` bytes.
pub(crate) unsafe fn keygen_rbg<const P: usize, const S: usize, const N: usize>(
    rbg: *mut OxiDrbg,
    pk_out: *mut u8,
    sk_out: *mut u8,
    seed_out: *mut u8,
    service: Service,
    keygen: fn(&mut DrbgKind) -> Result<Pair<P, S>, Error>,
    keygen_with_seed: fn(&mut DrbgKind) -> Result<SeededPair<N, P, S>, Error>,
) -> Result<(), R> {
    let seed_len = if seed_out.is_null() { 0 } else { N };
    disjoint(&[
        span(rbg, size_of::<OxiDrbg>(), true)?,
        span(pk_out, P, true)?,
        span(sk_out, S, true)?,
        span(seed_out, seed_len, true)?,
    ])?;
    admit(service)?;
    // SAFETY: `rbg` was checked non-NULL by `span` and shares no byte with
    // an output, by `disjoint` above, and is a live handle by contract.
    let (seed, pk, sk) = unsafe {
        with_held(rbg, |kind| {
            if seed_len == 0 {
                keygen(kind).map(|(pk, sk)| (None, pk, Zeroizing::new(sk)))
            } else {
                keygen_with_seed(kind).map(|(seed, pk, sk)| (Some(seed), pk, Zeroizing::new(sk)))
            }
        })
    }?
    .map_err(R::from)?;
    // SAFETY: each destination was checked by `span` and `disjoint` above,
    // is valid for its source's length by contract, and overlaps none of
    // this function's buffers.
    unsafe {
        match seed.as_ref() {
            Some(seed) => write_all(&[
                (pk_out, &pk),
                (sk_out, sk.as_slice()),
                (seed_out, seed.as_slice()),
            ]),
            None => write_all(&[(pk_out, &pk), (sk_out, sk.as_slice())]),
        }
    }
}

/// Key expansion from a caller's seed: reads `D` bytes at `d` and `Z` at
/// `z`, passes them to `expand` and writes the public key to `pk_out` and
/// the secret key to `sk_out`. ML-DSA passes its seed ξ as `d`, with `z`
/// NULL and `Z` 0.
///
/// # Safety
///
/// `d` and `z` must be NULL or valid for reads of `D` and `Z` bytes;
/// `pk_out` and `sk_out` NULL or valid for writes of `P` and `S` bytes.
pub(crate) unsafe fn expand_key<const D: usize, const Z: usize, const P: usize, const S: usize>(
    d: *const u8,
    z: *const u8,
    pk_out: *mut u8,
    sk_out: *mut u8,
    service: Service,
    expand: impl FnOnce(&[u8; D], &[u8; Z]) -> Result<Pair<P, S>, Error>,
) -> Result<(), R> {
    disjoint(&[
        span(d, D, false)?,
        span(z, Z, false)?,
        span(pk_out, P, true)?,
        span(sk_out, S, true)?,
    ])?;
    admit(service)?;
    // SAFETY: both seeds passed `span` and `disjoint` above, so each is
    // non-NULL or empty and shares no byte with an output; each is valid
    // for its length by contract.
    let (d, z) = unsafe { (array::<D>(input(d, D))?, array::<Z>(input(z, Z))?) };
    let (pk, sk) = expand(d, z).map_err(R::from)?;
    let sk = Zeroizing::new(sk);
    // SAFETY: `pk_out` and `sk_out` were checked by `span` and `disjoint`
    // above, are valid for `P` and `S` bytes by contract, and overlap none of
    // this function's buffers.
    unsafe { write_all(&[(pk_out, &pk), (sk_out, sk.as_slice())]) }
}

/// Encapsulation against the caller's key with `m` drawn from the caller's
/// DRBG handle: writes the shared secret to `ss_out` and the ciphertext to
/// `ct_out`.
///
/// # Safety
///
/// `ek` must be NULL or valid for reads of `E` bytes, `rbg` NULL or a live
/// handle from a `_new_rbg` function, `ss_out` and `ct_out` NULL or valid
/// for writes of 32 and `C` bytes.
pub(crate) unsafe fn encapsulate_rbg<const E: usize, const C: usize>(
    ek: *const u8,
    rbg: *mut OxiDrbg,
    ss_out: *mut u8,
    ct_out: *mut u8,
    service: Service,
    encapsulate: fn(&[u8; E], &mut DrbgKind) -> Result<Encapsulated<C>, Error>,
) -> Result<(), R> {
    disjoint(&[
        span(ek, E, false)?,
        span(rbg, size_of::<OxiDrbg>(), true)?,
        span(ss_out, 32, true)?,
        span(ct_out, C, true)?,
    ])?;
    admit(service)?;
    // SAFETY: `ek` passed `span` and `disjoint` above, so it is non-NULL
    // and shares no byte with an output or the handle; it is valid for `E`
    // bytes by contract.
    let ek = array::<E>(unsafe { input(ek, E) })?;
    // SAFETY: `rbg` was checked non-NULL by `span` and shares no byte with
    // any range, by `disjoint` above, and is a live handle by contract.
    let (ss, ct) = unsafe { with_held(rbg, |kind| encapsulate(ek, kind)) }?.map_err(R::from)?;
    let ss = Zeroizing::new(ss);
    // SAFETY: `ss_out` and `ct_out` were checked by `span` and `disjoint`
    // above, are valid for 32 and `C` bytes by contract, and overlap none of
    // this function's buffers.
    unsafe { write_all(&[(ss_out, ss.as_slice()), (ct_out, &ct)]) }
}

/// Decapsulation of `ct` under the caller's `dk`: writes the shared secret
/// to `ss_out`.
///
/// # Safety
///
/// `dk` and `ct` must be NULL or valid for reads of `K` and `C` bytes,
/// `ss_out` NULL or valid for writes of 32 bytes.
pub(crate) unsafe fn decapsulate<const K: usize, const C: usize>(
    dk: *const u8,
    ct: *const u8,
    ss_out: *mut u8,
    service: Service,
    decapsulate: Decapsulate<K, C>,
) -> Result<(), R> {
    disjoint(&[
        span(dk, K, false)?,
        span(ct, C, false)?,
        span(ss_out, 32, true)?,
    ])?;
    admit(service)?;
    // SAFETY: `dk` and `ct` passed `span` and `disjoint` above, so each is
    // non-NULL and shares no byte with `ss_out`; each is valid for its
    // length by contract.
    let (dk, ct) = unsafe { (array::<K>(input(dk, K))?, array::<C>(input(ct, C))?) };
    let ss = Zeroizing::new(decapsulate(dk, ct).map_err(R::from)?);
    // SAFETY: `ss_out` was checked by `span` and `disjoint` above, is valid
    // for 32 bytes by contract, and does not overlap `ss`.
    unsafe { write_all(&[(ss_out, ss.as_slice())]) }
}
