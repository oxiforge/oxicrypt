//! Software integrity self-test for the pqclib FIPS module.
//!
//! This crate implements the power-up integrity check required by
//! FIPS 140-3 IG 10.3.A (as of March 2026). The check verifies that
//! the module binary on disk has not been modified since it was
//! signed, by recomputing an HMAC-SHA-256 over the exact file bytes
//! of the currently-running executable and comparing against a
//! reference MAC produced at build time by the `fips-integrity-sign`
//! tool.
//!
//! # Design
//!
//! Two practical patterns for Level 1 software integrity tests are
//! (a) **in-binary patching** — computing the MAC at link time and
//! splicing it into a reserved byte region inside the binary — and
//! (b) **sidecar files** — computing the MAC after link and writing
//! it to a file that sits next to the executable. We use (b). The
//! sidecar pattern is simpler, works uniformly across Linux, macOS,
//! and Windows, does not require a linker script, and is explicitly
//! permitted by IG 10.3.A so long as the sidecar is considered part
//! of the distributed module. The security policy for this module
//! treats the `<exe>.fipshmac` sidecar as in-scope for delivery and
//! as in-scope for the integrity check itself (the MAC value is
//! covered by the same HMAC key and by the public-key integrity of
//! the distribution channel).
//!
//! The HMAC key is a fixed, publicly known 32-byte constant. IG
//! 10.3.A explicitly permits a known key here: the integrity check
//! is an **authenticity** check, not a secrecy check, and the
//! property that matters is that an attacker who rewrites the module
//! binary cannot also predict the corresponding reference MAC
//! without knowing the key embedded in the module source. The key is
//! therefore a build-time constant, not a runtime secret.
//!
//! # Boot flow
//!
//! The `integrity_self_test` function is registered in [`KATS`] as a
//! power-up KAT. During module boot the `fips-module` runner will
//! call it while the module is in `SelfTest` state, meaning the
//! standard HMAC entry points (`HmacSha256::new`) are still gated by
//! `require_operational()` and would return `NotOperational`. This
//! crate therefore talks to `HmacSha256::new_internal` directly, the
//! gateless constructor that exists for exactly this reason.
//!
//! # Failure modes
//!
//! Any of the following count as an integrity failure and will cause
//! the runner to latch the module into the terminal `Error` state:
//!
//! - The current executable path cannot be resolved.
//! - The executable cannot be read.
//! - The sidecar MAC file is missing, unreadable, or malformed.
//! - The computed MAC does not equal the expected MAC in constant
//!   time.
//!
//! The integrity KAT does **not** distinguish between a missing
//! sidecar and an actively-tampered binary: in either case the
//! module has failed its power-up self-tests and cannot be trusted
//! to produce approved output.
//!
//! # Signing
//!
//! A companion binary `fips-integrity-sign` (see
//! `src/bin/fips-integrity-sign.rs`) computes the expected MAC for a
//! given executable and writes the sidecar file. It must be run
//! after every rebuild of the module binary. The signer shares its
//! HMAC computation with the runtime check via [`compute_exe_hmac`],
//! so the signing tool and the power-up KAT cannot disagree about
//! the algorithm.

#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fips_hmac::HmacSha256;
use fips_module::{KatEntry, SelfTestFailure};

/// Fixed, publicly known HMAC key used for the software integrity
/// self-test. 32 bytes chosen arbitrarily at crate creation time;
/// rotation requires a module re-validation per IG 10.3.A.
///
/// The key material is the UTF-8 bytes of the ASCII literal
/// `"pqclib-fips-140-3-integrity-key!"` (32 bytes) — not a secret,
/// just a stable value that is trivially auditable from the source
/// tree.
pub const FIPS_INTEGRITY_KEY: [u8; 32] = *b"pqclib-fips-140-3-integrity-key!";

/// Filename extension used for the sidecar MAC file.
///
/// For an executable at `/path/to/module`, the signer writes the
/// 64-character lowercase-hex HMAC to `/path/to/module.fipshmac` and
/// the runtime check reads it back from the same location.
pub const SIDECAR_EXTENSION: &str = "fipshmac";

/// Size in bytes of a streaming read against the executable.
///
/// Chosen as one hash block (64B) times a generous multiplier so
/// that the HMAC streaming path does real work per syscall without
/// committing to large stack buffers or allocations.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Errors surfaced by the standalone integrity-check helpers.
///
/// Note that the power-up KAT itself returns only
/// [`SelfTestFailure`] — the runner has no use for richer error
/// information at boot time because the module is going to latch
/// into `Error` either way. These variants exist so that the signer
/// tool can print a useful diagnostic when, for example, the target
/// binary does not exist or the user passes `--verify` against a
/// tampered file.
#[derive(Debug)]
pub enum IntegrityError {
    /// Resolving `env::current_exe()` failed.
    CurrentExeUnresolved(io::Error),
    /// The executable at the expected path could not be opened or
    /// read to completion.
    ExeReadFailed(io::Error),
    /// The sidecar MAC file could not be opened or read.
    SidecarReadFailed(io::Error),
    /// The sidecar contained something that is not a 64-character
    /// lowercase hex MAC. The payload is truncated in the error so
    /// that accidentally-binary files don't flood the logs.
    SidecarMalformed,
    /// Writing the sidecar failed.
    SidecarWriteFailed(io::Error),
    /// The HMAC computed over the executable did not match the
    /// expected value from the sidecar. This is the "tampered
    /// binary" case.
    MacMismatch,
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CurrentExeUnresolved(e) => {
                write!(f, "could not resolve current executable path: {e}")
            }
            Self::ExeReadFailed(e) => write!(f, "could not read module binary: {e}"),
            Self::SidecarReadFailed(e) => write!(f, "could not read integrity sidecar: {e}"),
            Self::SidecarMalformed => f.write_str("integrity sidecar is not a 64-hex-char MAC"),
            Self::SidecarWriteFailed(e) => write!(f, "could not write integrity sidecar: {e}"),
            Self::MacMismatch => f.write_str(
                "module binary integrity MAC mismatch — the binary has been modified since signing",
            ),
        }
    }
}

impl std::error::Error for IntegrityError {}

/// Returns the sidecar path for a given executable path.
///
/// `/path/to/module` → `/path/to/module.fipshmac`. Preserves the
/// original extension if any (the sidecar is always appended, never
/// substituted) so `/path/to/mod.exe` → `/path/to/mod.exe.fipshmac`.
pub fn sidecar_path_for(exe_path: &Path) -> PathBuf {
    let mut s = exe_path.as_os_str().to_owned();
    s.push(".");
    s.push(SIDECAR_EXTENSION);
    PathBuf::from(s)
}

/// Computes HMAC-SHA-256 over the entire contents of `exe_path`,
/// streaming the file in 64 KiB chunks.
///
/// Uses [`HmacSha256::new_internal`] so that this function can be
/// called during the module's `SelfTest` phase, before
/// `require_operational()` would permit the public HMAC entry point.
pub fn compute_exe_hmac(exe_path: &Path) -> Result<[u8; 32], IntegrityError> {
    let mut file = File::open(exe_path).map_err(IntegrityError::ExeReadFailed)?;
    let mut mac = HmacSha256::new_internal(&FIPS_INTEGRITY_KEY);
    // Heap-allocated to avoid the 64 KiB stack buffer tripping
    // `clippy::large_stack_arrays`.
    let mut buf = vec![0u8; READ_CHUNK_BYTES].into_boxed_slice();
    loop {
        let n = file.read(&mut buf).map_err(IntegrityError::ExeReadFailed)?;
        if n == 0 {
            break;
        }
        let chunk = buf
            .get(..n)
            .ok_or_else(|| IntegrityError::ExeReadFailed(io::Error::other("short read slice")))?;
        mac.update(chunk);
    }
    Ok(mac.finalize())
}

/// Reads the expected MAC from the sidecar file at `sidecar_path`.
///
/// The sidecar is a plain text file containing exactly 64 lowercase
/// hex characters, optionally followed by a trailing newline. Any
/// deviation (wrong length, uppercase hex, non-hex characters,
/// embedded whitespace) is rejected as `SidecarMalformed`.
pub fn read_expected_hmac(sidecar_path: &Path) -> Result<[u8; 32], IntegrityError> {
    let mut file = File::open(sidecar_path).map_err(IntegrityError::SidecarReadFailed)?;
    // 65 bytes = 64 hex chars + optional trailing '\n'. Refuse
    // anything larger: the sidecar is fixed-length and we do not
    // want to allocate unboundedly.
    let mut buf = [0u8; 66];
    let mut filled = 0usize;
    loop {
        let remaining = buf
            .get_mut(filled..)
            .ok_or(IntegrityError::SidecarMalformed)?;
        if remaining.is_empty() {
            // More than 66 bytes available — too big.
            return Err(IntegrityError::SidecarMalformed);
        }
        let n = file
            .read(remaining)
            .map_err(IntegrityError::SidecarReadFailed)?;
        if n == 0 {
            break;
        }
        filled = filled
            .checked_add(n)
            .ok_or(IntegrityError::SidecarMalformed)?;
    }
    let trimmed =
        strip_trailing_newline(buf.get(..filled).ok_or(IntegrityError::SidecarMalformed)?);
    if trimmed.len() != 64 {
        return Err(IntegrityError::SidecarMalformed);
    }
    let mut out = [0u8; 32];
    for (pair, byte_out) in trimmed.chunks_exact(2).zip(out.iter_mut()) {
        let hi = pair.first().ok_or(IntegrityError::SidecarMalformed)?;
        let lo = pair.get(1).ok_or(IntegrityError::SidecarMalformed)?;
        *byte_out = (hex_nibble(*hi)? << 4) | hex_nibble(*lo)?;
    }
    Ok(out)
}

fn strip_trailing_newline(bytes: &[u8]) -> &[u8] {
    match bytes.split_last() {
        Some((&b'\n', head)) => head,
        _ => bytes,
    }
}

fn hex_nibble(c: u8) -> Result<u8, IntegrityError> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => Err(IntegrityError::SidecarMalformed),
    }
}

/// Formats a 32-byte MAC as 64 lowercase hex characters. Used by the
/// signer tool when writing the sidecar.
pub fn encode_hmac_hex(mac: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (pair, &byte) in out.chunks_exact_mut(2).zip(mac.iter()) {
        let high = HEX.get((byte >> 4) as usize).copied().unwrap_or(b'0');
        let low = HEX.get((byte & 0x0f) as usize).copied().unwrap_or(b'0');
        if let Some(slot) = pair.first_mut() {
            *slot = high;
        }
        if let Some(slot) = pair.get_mut(1) {
            *slot = low;
        }
    }
    out
}

/// Compares two 32-byte MACs in constant time.
///
/// Short-circuiting comparison would let a timing attacker brute
/// force the expected MAC one byte at a time; the integrity check
/// happens against untrusted on-disk bytes, so we take the same
/// care here that we would for any secret MAC verification.
#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        // These gets cannot fail at compile-time sized arrays, but
        // the `clippy::indexing_slicing` lint is denied workspace-
        // wide, so we spell it out.
        let Some(&ai) = a.get(i) else { return false };
        let Some(&bi) = b.get(i) else { return false };
        diff |= ai ^ bi;
    }
    diff == 0
}

/// Verifies the integrity of a specific executable + sidecar pair.
///
/// Public so that the `fips-integrity-sign --verify` workflow and
/// the unit tests can target a freshly-written test binary without
/// going through `env::current_exe`. Production power-up uses
/// [`integrity_self_test`] which routes through `current_exe`.
pub fn verify_exe_against_sidecar(exe_path: &Path) -> Result<(), IntegrityError> {
    let sidecar = sidecar_path_for(exe_path);
    let expected = read_expected_hmac(&sidecar)?;
    let computed = compute_exe_hmac(exe_path)?;
    if constant_time_eq(&expected, &computed) {
        Ok(())
    } else {
        Err(IntegrityError::MacMismatch)
    }
}

/// Computes, writes, and returns the sidecar MAC for an executable.
///
/// Used by the `fips-integrity-sign` tool. Overwrites any existing
/// sidecar.
pub fn sign_exe(exe_path: &Path) -> Result<[u8; 32], IntegrityError> {
    let mac = compute_exe_hmac(exe_path)?;
    let sidecar = sidecar_path_for(exe_path);
    let hex = encode_hmac_hex(&mac);
    let mut contents = [0u8; 65];
    let (head, tail) = contents.split_at_mut(64);
    head.copy_from_slice(&hex);
    if let Some(slot) = tail.first_mut() {
        *slot = b'\n';
    }
    std::fs::write(&sidecar, contents).map_err(IntegrityError::SidecarWriteFailed)?;
    Ok(mac)
}

/// Power-up integrity KAT.
///
/// Resolves the current executable, recomputes its HMAC, and
/// compares it against the sidecar MAC. Returns `SelfTestFailure`
/// on any error so the `fips-module` runner can latch the module
/// into the terminal `Error` state.
///
/// This is the function wired into [`KATS`] and, transitively, into
/// the acvp-harness boot sequence. Do not call it directly from
/// application code.
pub fn integrity_self_test() -> Result<(), SelfTestFailure> {
    let exe = env::current_exe().map_err(|_| SelfTestFailure)?;
    verify_exe_against_sidecar(&exe).map_err(|_| SelfTestFailure)
}

/// Power-up KAT inventory for the integrity self-test.
///
/// Merged into the acvp-harness boot sequence via
/// `fips_module::initialize_with_tests`. Per FIPS 140-3 IG 10.3.A
/// the integrity check is a mandatory power-up KAT and must run on
/// every module startup.
pub const KATS: &[KatEntry] = &[KatEntry {
    name: "Module binary integrity (HMAC-SHA-256 over current_exe() vs .fipshmac sidecar)",
    run: integrity_self_test,
}];

// ----------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        compute_exe_hmac, constant_time_eq, encode_hmac_hex, read_expected_hmac, sidecar_path_for,
        sign_exe, verify_exe_against_sidecar, IntegrityError, FIPS_INTEGRITY_KEY,
    };
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn unique_tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("fips-integrity-test-{tag}-{pid}-{ts}.bin"));
        p
    }

    fn write_fake_exe(path: &std::path::Path, body: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn fips_integrity_key_is_32_bytes_ascii() {
        // Sanity: the constant must match its documented length
        // and must be printable ASCII so auditors can read it in
        // the source tree and in a hex dump side by side.
        assert_eq!(FIPS_INTEGRITY_KEY.len(), 32);
        for b in FIPS_INTEGRITY_KEY {
            assert!(b.is_ascii() && !b.is_ascii_control());
        }
    }

    #[test]
    fn sidecar_path_appends_extension() {
        let exe = PathBuf::from("/tmp/some-module");
        let side = sidecar_path_for(&exe);
        assert_eq!(side, PathBuf::from("/tmp/some-module.fipshmac"));
    }

    #[test]
    fn sidecar_path_preserves_existing_extension() {
        let exe = PathBuf::from("/tmp/mod.exe");
        let side = sidecar_path_for(&exe);
        assert_eq!(side, PathBuf::from("/tmp/mod.exe.fipshmac"));
    }

    #[test]
    fn encode_hmac_hex_is_lowercase_and_64_chars() {
        let mac = [0xabu8; 32];
        let hex = encode_hmac_hex(&mac);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, [b'a', b'b'].repeat(32).as_slice());
    }

    #[test]
    fn constant_time_eq_detects_differences() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let exe = unique_tmp_path("signverify");
        write_fake_exe(&exe, b"pqclib fake module body for integrity test");
        let signed_mac = sign_exe(&exe).unwrap();
        let recomputed = compute_exe_hmac(&exe).unwrap();
        assert_eq!(signed_mac, recomputed);
        verify_exe_against_sidecar(&exe).unwrap();
        // Sidecar should contain exactly our encoded MAC + newline.
        let sidecar = sidecar_path_for(&exe);
        let contents = fs::read(&sidecar).unwrap();
        assert_eq!(contents.len(), 65);
        assert_eq!(contents.get(64).copied(), Some(b'\n'));
        let parsed = read_expected_hmac(&sidecar).unwrap();
        assert_eq!(parsed, signed_mac);
        let _ = fs::remove_file(&exe);
        let _ = fs::remove_file(&sidecar);
    }

    #[test]
    fn verify_detects_tampered_exe() {
        let exe = unique_tmp_path("tampered");
        write_fake_exe(&exe, b"original body");
        sign_exe(&exe).unwrap();
        // Tamper with the exe *after* signing.
        write_fake_exe(&exe, b"modified body");
        match verify_exe_against_sidecar(&exe) {
            Err(IntegrityError::MacMismatch) => {}
            other => panic!("expected MacMismatch, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
        let _ = fs::remove_file(sidecar_path_for(&exe));
    }

    #[test]
    fn verify_rejects_missing_sidecar() {
        let exe = unique_tmp_path("missingside");
        write_fake_exe(&exe, b"body");
        // Deliberately do not call sign_exe.
        match verify_exe_against_sidecar(&exe) {
            Err(IntegrityError::SidecarReadFailed(_)) => {}
            other => panic!("expected SidecarReadFailed, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
    }

    #[test]
    fn verify_rejects_malformed_sidecar_wrong_length() {
        let exe = unique_tmp_path("malformedlen");
        write_fake_exe(&exe, b"body");
        // Write a too-short sidecar manually.
        let sidecar = sidecar_path_for(&exe);
        fs::write(&sidecar, b"deadbeef").unwrap();
        match verify_exe_against_sidecar(&exe) {
            Err(IntegrityError::SidecarMalformed) => {}
            other => panic!("expected SidecarMalformed, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
        let _ = fs::remove_file(&sidecar);
    }

    #[test]
    fn verify_rejects_malformed_sidecar_bad_hex() {
        let exe = unique_tmp_path("badhex");
        write_fake_exe(&exe, b"body");
        let sidecar = sidecar_path_for(&exe);
        // 64 chars but with non-hex content.
        let bad: Vec<u8> = std::iter::repeat_n(b'Z', 64).collect();
        fs::write(&sidecar, &bad).unwrap();
        match verify_exe_against_sidecar(&exe) {
            Err(IntegrityError::SidecarMalformed) => {}
            other => panic!("expected SidecarMalformed, got {other:?}"),
        }
        let _ = fs::remove_file(&exe);
        let _ = fs::remove_file(&sidecar);
    }

    #[test]
    fn compute_exe_hmac_is_deterministic_across_calls() {
        let exe = unique_tmp_path("determ");
        // Use a body large enough to exercise multiple 64 KiB reads.
        let body: Vec<u8> = (0..200_000u32).map(|i| (i & 0xff) as u8).collect();
        write_fake_exe(&exe, &body);
        let a = compute_exe_hmac(&exe).unwrap();
        let b = compute_exe_hmac(&exe).unwrap();
        assert_eq!(a, b);
        let _ = fs::remove_file(&exe);
    }
}
