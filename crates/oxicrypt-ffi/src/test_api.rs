//! Test symbols for simulating failures from C, exported only by a library
//! built with the `fault-injection` feature and declared in
//! `include/oxicrypt-test.h`. They are absent from `include/oxicrypt.h` and
//! from the ABI inventory, and a release build never contains them.

use core::ffi::c_int;
use core::fmt::Write as _;

use crate::rbg::OxiDrbg;

/// Replace the seed path's draw with a fixed stream: every later draw is
/// served from `seed`, in order, and fails once the stream is exhausted.
///
/// A NULL `seed` with a non-zero length, or a stream longer than the seam
/// can hold, installs nothing.
///
/// # Safety
///
/// A non-NULL `seed` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_test_set_seed_stream(seed: *const u8, len: usize) {
    if (seed.is_null() && len > 0) || len > isize::MAX.unsigned_abs() {
        return;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: `seed` is non-NULL and valid for `len` bytes by contract.
        unsafe { core::slice::from_raw_parts(seed, len) }
    };
    let mut value = String::from("seed-stream=");
    for b in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(value, "{b:02x}");
    }
    // A refused stream installs nothing, which is the documented result.
    let _ = oxicrypt_drbg::seam::arm_from_env(Some(&value));
}

/// Take (`on` non-zero) or release the hold on the handle, as a call in
/// progress on another thread of this process would: taking it records this
/// process as the holder, and releasing it records 0. A handle held this way
/// across a fork is one a thread of the parent held at the fork. NULL is a
/// no-op.
///
/// # Safety
///
/// `h` must be NULL or a live handle from a `_new_rbg` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oxi_test_hold_busy(h: *mut OxiDrbg, on: c_int) {
    use core::sync::atomic::Ordering::SeqCst;
    if h.is_null() {
        return;
    }
    // SAFETY: `h` is a live handle by contract; only its atomics are touched.
    let drbg = unsafe { &*h };
    let holder = if on != 0 {
        crate::rbg::current_process()
    } else {
        0
    };
    drbg.holder.store(holder, SeqCst);
}

/// Arm (`on` non-zero) or disarm a pairwise consistency test failure in the
/// next key generation of each of ML-DSA, ML-KEM, ECDSA, ECDH and RSA, as
/// the five `oxi_test_corrupt_next_*_<family>` functions do one family at a
/// time: the next key generation or key expansion of each armed family
/// returns `ConditionalTestFailed = 3` and puts the module in its error
/// state. Ed25519 is not armed: no C function runs the Ed25519 pairwise
/// consistency test.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_key(on: c_int) {
    if on != 0 {
        oxicrypt_ml_dsa::seam::corrupt_next_pk();
        oxicrypt_ml_kem::seam::corrupt_next_dk();
        oxicrypt_ecdsa::seam::corrupt_next_pk();
        oxicrypt_ecdh::seam::corrupt_next_pk();
        oxicrypt_rsa::seam::corrupt_next_pk();
    } else {
        oxicrypt_ml_dsa::seam::disarm();
        oxicrypt_ml_kem::seam::disarm();
        oxicrypt_ecdsa::seam::reset();
        oxicrypt_ecdh::seam::reset();
        oxicrypt_rsa::seam::reset();
    }
}

/// Make the next ML-DSA key generation or key expansion in the process, of
/// any parameter set, fail its pairwise consistency test: it returns
/// `ConditionalTestFailed = 3` and the module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_pk_ml_dsa() {
    oxicrypt_ml_dsa::seam::corrupt_next_pk();
}

/// Make the next ML-KEM key generation or key expansion in the process, of
/// any parameter set, fail its pairwise consistency test: it returns
/// `ConditionalTestFailed = 3` and the module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_dk_ml_kem() {
    oxicrypt_ml_kem::seam::corrupt_next_dk();
}

/// Make the next ECDSA key generation in the process, of either curve, fail
/// its pairwise consistency test: it returns `ConditionalTestFailed = 3`
/// and the module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_pk_ecdsa() {
    oxicrypt_ecdsa::seam::corrupt_next_pk();
}

/// Make the next ECDH key generation in the process, of either curve, fail
/// its pairwise consistency test: it returns `ConditionalTestFailed = 3`
/// and the module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_pk_ecdh() {
    oxicrypt_ecdh::seam::corrupt_next_pk();
}

/// Make the next RSA key generation in the process, of any modulus size,
/// fail its pairwise consistency test: it returns
/// `ConditionalTestFailed = 3` and the module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_corrupt_next_pk_rsa() {
    oxicrypt_rsa::seam::corrupt_next_pk();
}

/// Make the entropy source fail its start-up health tests, which puts the
/// module into its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_poison_entropy() {
    // The draw's failure is the intended effect.
    let _ = oxicrypt_drbg::seam::poison_pipeline();
}

/// Make the next `oxi_entropy_on_demand_test` call fail as a failed
/// on-demand health test does: it returns `EntropyUnavailable = 33` and the
/// module enters its error state.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_fail_next_on_demand() {
    oxicrypt_drbg::seam::fail_next(oxicrypt_drbg::seam::FaultClass::OnDemand);
}

/// `1` when the last allocation `wipe_and_free` released, a DRBG handle
/// from `oxi_drbg_free` or a typed DRBG `_free` or an AES key handle, read
/// as all zero after its wipe and before its memory was released, `0` when
/// it did not, `-1` when none has been released since the last call. Each
/// call clears the record.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_last_freed_bytes_zero() -> c_int {
    crate::rbg::last_freed_bytes_zero()
}

/// Make the next `_new_rbg` call fail as an allocation failure does,
/// returning `Internal = 255` without allocating.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_fail_next_alloc() {
    crate::rbg::fail_next_alloc();
}

/// Arm (`on` non-zero) or disarm a hold at the output check: the next DRBG
/// generate to reach the DRBG's re-check of the module state, made before it
/// produces any output bytes, waits there until `oxi_test_release_parked` or
/// until it has spun 2^32 times, whichever comes first. The hold is not at
/// the later re-check made before the result is copied to the caller.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_park_before_output(on: c_int) {
    oxicrypt_drbg::seam::park_before_output(on != 0);
}

/// Release a generate waiting at its output check, and disarm the hold.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_release_parked() {
    oxicrypt_drbg::seam::release_parked();
}

/// `1` while a generate is waiting at its output check, `0` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn oxi_test_is_parked() -> c_int {
    c_int::from(oxicrypt_drbg::seam::is_parked())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    /// The names of the functions `source` exports: each line that is
    /// exactly the `no_mangle` attribute, followed by an `extern "C" fn`.
    fn exported_names(source: &str) -> BTreeSet<String> {
        let attribute = concat!("#[unsafe(", "no_mangle)]");
        let lines: Vec<&str> = source.lines().map(str::trim).collect();
        lines
            .windows(2)
            .filter(|pair| pair.first() == Some(&attribute))
            .filter_map(|pair| {
                let decl = pair.get(1)?;
                let after = decl.split_once("extern \"C\" fn ")?.1;
                Some(after.split('(').next()?.to_owned())
            })
            .collect()
    }

    /// The `oxi_test_*` names declared as functions in a C header.
    fn declared_names(header: &str) -> BTreeSet<String> {
        header
            .match_indices("oxi_test_")
            .filter_map(|(at, _)| {
                let rest = header.get(at..)?;
                let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
                let name = rest.get(..end)?;
                rest.get(end..)?.starts_with('(').then(|| name.to_owned())
            })
            .collect()
    }

    #[test]
    fn test_header_matches_exports() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let read = |rel: &str| {
            let path = format!("{dir}/{rel}");
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
        };
        let exported = exported_names(&read("src/test_api.rs"));
        let declared = declared_names(&read("include/oxicrypt-test.h"));
        assert_eq!(exported.len(), 15, "{exported:?}");
        assert_eq!(declared, exported);
        assert!(!read("include/oxicrypt.h").contains("oxi_test_"));

        // Positive controls: each parser finds a name and misses a non-match.
        let source = concat!(
            "#[unsafe(",
            "no_mangle)]\npub extern \"C\" fn oxi_test_x(a: i32) {}\nfn oxi_test_y() {}\n"
        );
        assert_eq!(
            exported_names(source),
            BTreeSet::from(["oxi_test_x".to_owned()])
        );
        let header = "void oxi_test_x(int on);\n/* oxi_test_y */\nint oxi_other(void);\n";
        assert_eq!(
            declared_names(header),
            BTreeSet::from(["oxi_test_x".to_owned()])
        );
    }
}
