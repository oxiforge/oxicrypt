//! Initialisation of the library and the `Module` token.

use core::ffi::{CStr, c_int};
use core::fmt;
use std::sync::OnceLock;

use crate::error::{DetailError, Error, InitError, Site, status};
use crate::sys;

/// An algorithm profile of the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Code 0: every approved algorithm.
    Unrestricted,
    /// Code 1: the CNSA 2.0 suite.
    Cnsa2,
    /// Code 2: the CNSA 1.0 suite.
    Cnsa1,
    /// Code 3: CNSA 1.0 and CNSA 2.0 together; not a CNSA profile.
    Migration,
    /// A code this crate does not know. The library refuses it as an
    /// initialisation request with [`Error::InvalidInput`]; it appears when a
    /// newer library reports a profile this crate predates. `Unknown` of a
    /// code this crate does know is that profile: [`Module::init`] treats
    /// `Unknown(1)` as [`Profile::Cnsa2`].
    Unknown(i32),
}

impl Profile {
    /// The code the C ABI uses for this profile.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Unrestricted => 0,
            Self::Cnsa2 => 1,
            Self::Cnsa1 => 2,
            Self::Migration => 3,
            Self::Unknown(code) => code,
        }
    }

    /// The profile a C ABI code names.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Unrestricted,
            1 => Self::Cnsa2,
            2 => Self::Cnsa1,
            3 => Self::Migration,
            other => Self::Unknown(other),
        }
    }
}

/// The pre-operational integrity test's indicator, as `oxi_integrity_status`
/// reports it. The library latches it on the first run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IntegrityStatus {
    /// 0: the test has not run in this process.
    NotRun,
    /// 1: the signature over the image verified.
    Passed,
    /// 2: the image does not match its signature.
    SignatureInvalid,
    /// 3: the slot is the unsigned template.
    SlotInvalid,
    /// 4: the test was not performed: the image could not be read.
    Unreadable,
    /// 5: the test was reached before its self-tests passed.
    CastNotRun,
    /// 6: the record held a value the library never writes (the header's
    /// `Unknown`).
    UnknownRecord,
    /// 7: the module refused a primitive, so the test was not performed.
    Refused,
    /// 8: the library carries no verifying key.
    NoVerifyKey,
    /// 9: the slot was signed for a different key than the library embeds.
    KeyMismatch,
    /// 10: the slot, the key record or a bound import is damaged.
    SlotDamaged,
    /// A value this crate does not know.
    Unknown(i32),
}

impl IntegrityStatus {
    /// The indicator a C ABI value names.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::NotRun,
            1 => Self::Passed,
            2 => Self::SignatureInvalid,
            3 => Self::SlotInvalid,
            4 => Self::Unreadable,
            5 => Self::CastNotRun,
            6 => Self::UnknownRecord,
            7 => Self::Refused,
            8 => Self::NoVerifyKey,
            9 => Self::KeyMismatch,
            10 => Self::SlotDamaged,
            other => Self::Unknown(other),
        }
    }
}

/// The SHA-256 fingerprint of the verifying key a library embeds. Public
/// data: it names a signer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The 32 bytes of the fingerprint.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses exactly 64 hex digits, with or without the `sha256:` prefix.
    /// Anything else, a sign or whitespace included, is `None`.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let hex = text.strip_prefix("sha256:").unwrap_or(text).as_bytes();
        if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
            let digits = core::str::from_utf8(pair).ok()?;
            *byte = u8::from_str_radix(digits, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Proof that the library this program loaded is initialised.
///
/// Returned only by a successful [`Module::init`] (or
/// [`Module::init_unpinned`]); every service is a method on it, so a call
/// before initialisation does not compile. It does not make a service
/// infallible: a conditional self-test can move the library to its error
/// state between calls, after which every service returns
/// [`Error::NotOperational`].
#[derive(Debug, Clone, Copy)]
pub struct Module {
    _private: (),
}

/// Which verifying key `init_with` accepts.
#[derive(Clone, Copy)]
enum Pin {
    /// Only the key whose fingerprint is these 64 hex digits.
    #[cfg_attr(not(any(oxicrypt_pinned, doc)), allow(dead_code))]
    Required(&'static str),
    /// Any key.
    #[cfg_attr(not(oxicrypt_unpinned), allow(dead_code))]
    Unpinned,
}

/// The fingerprint `OXICRYPT_LIB_FINGERPRINT` pinned at build time, as 64
/// lower-case hex digits.
#[cfg(oxicrypt_pinned)]
const PIN: &str = env!("OXICRYPT_BINDINGS_PIN");

impl Module {
    /// Initialises the library with `profile` and checks that it is the
    /// library this crate was built for.
    ///
    /// In order: the library's version must equal this crate's (checked once
    /// per process, before anything but `lama_manifest` is called);
    /// `oxi_init(profile)` must return 0, else the code it returned is
    /// reported with the integrity indicator and detail as the library
    /// reports them after this call; the library must report itself
    /// operational; the verifying key it embeds must have the fingerprint
    /// pinned at build time; and its active profile must be `profile`.
    /// Operational state and the active profile are read on every call,
    /// never cached.
    ///
    /// The first call runs the library's power-up self-tests and blocks for
    /// their duration. Later calls are cheap, and every caller in a process
    /// shares the one initialised library: a later call with another profile
    /// is refused with [`Error::ProfileMismatch`]. A failed initialisation is
    /// terminal for the process; this function never retries it.
    ///
    /// Present when the crate was built with `OXICRYPT_LIB_FINGERPRINT`.
    #[cfg(any(oxicrypt_pinned, doc))]
    #[allow(clippy::result_large_err)] // not a hot path; the size is immaterial
    pub fn init(profile: Profile) -> Result<Self, InitError> {
        #[cfg(oxicrypt_pinned)]
        let pin = Pin::Required(PIN);
        // A documentation build without a pin compiles a body that accepts
        // no library.
        #[cfg(not(oxicrypt_pinned))]
        let pin = Pin::Required("");
        Self::init_with(profile, pin)
    }

    /// As [`Module::init`], accepting a library that embeds any verifying key.
    ///
    /// Present only when the crate was built with `OXICRYPT_LIB_UNPINNED=1`.
    #[cfg(any(oxicrypt_unpinned, doc))]
    #[allow(clippy::result_large_err)] // not a hot path; the size is immaterial
    pub fn init_unpinned(profile: Profile) -> Result<Self, InitError> {
        Self::init_with(profile, Pin::Unpinned)
    }

    #[cfg_attr(not(any(oxicrypt_pinned, oxicrypt_unpinned)), allow(dead_code))]
    #[allow(clippy::result_large_err)] // not a hot path; the size is immaterial
    fn init_with(profile: Profile, pin: Pin) -> Result<Self, InitError> {
        // `Unknown(1)` and `Cnsa2` send the same code, so they must be the
        // same request.
        let profile = Profile::from_code(profile.code());
        let refused = |code| InitError {
            code,
            integrity: Some(integrity_status()),
            detail: integrity_detail(),
        };
        // A library of another version is not called beyond its manifest,
        // so its indicator is not read.
        library_compatible().map_err(|code| InitError {
            code,
            integrity: None,
            detail: Ok(None),
        })?;
        // SAFETY: U1; no pointers.
        let code = unsafe { sys::oxi_init(profile.code()) };
        status(code, Site::Other).map_err(refused)?;
        // A correct library returns 0 from `oxi_init` only when it is
        // operational; this refusal holds if it is not, which the control
        // tests provoke with an overriding shared object.
        // SAFETY: U1; no pointers.
        if unsafe { sys::oxi_is_operational() } != 1 {
            return Err(refused(Error::NotOperational));
        }
        if let Pin::Required(hex) = pin {
            let found = key_fingerprint().map_err(refused)?;
            if found.to_string() != format!("sha256:{hex}") {
                let expected = Fingerprint::from_hex(hex).unwrap_or(Fingerprint([0; 32]));
                return Err(refused(Error::KeyFingerprint { found, expected }));
            }
        }
        // SAFETY: U1; no pointers.
        let active = Profile::from_code(unsafe { sys::oxi_active_profile() });
        if active != profile {
            return Err(refused(Error::ProfileMismatch {
                active,
                requested: profile,
            }));
        }
        Ok(Self { _private: () })
    }

    /// Whether the library is in its operational state now, read live.
    #[must_use]
    pub fn is_operational(self) -> bool {
        // SAFETY: U1; no pointers.
        unsafe { sys::oxi_is_operational() == 1 }
    }

    /// The integrity test's latched indicator.
    #[must_use]
    pub fn integrity_status(self) -> IntegrityStatus {
        integrity_status()
    }

    /// The fingerprint of the verifying key the library reports embedding,
    /// for a log line. Self-reported: it cannot authenticate the library.
    pub fn key_fingerprint(self) -> Result<Fingerprint, Error> {
        key_fingerprint()
    }

    /// The file the loader bound this program's `oxi_*` references to, for a
    /// log line. Never a check. `None` when the platform does not say.
    #[must_use]
    pub fn library_path() -> Option<std::path::PathBuf> {
        crate::platform::library_path()
    }
}

fn integrity_status() -> IntegrityStatus {
    // SAFETY: U1; no pointers.
    IntegrityStatus::from_code(unsafe { sys::oxi_integrity_status() })
}

fn key_fingerprint() -> Result<Fingerprint, Error> {
    let mut out = [0u8; 32];
    // SAFETY: U1; U3, `out` is 32 writable bytes and `out_len` says so.
    let code = unsafe { sys::oxi_integrity_key_fingerprint(out.as_mut_ptr(), out.len()) };
    status(code, Site::Other)?;
    Ok(Fingerprint(out))
}

/// The longest detail text the crate reads.
pub(crate) const DETAIL_MAX: usize = 64 * 1024;

fn integrity_detail() -> Result<Option<String>, DetailError> {
    let mut needed: usize = 0;
    // SAFETY: U1; U6, the sizing call: `out` null with `out_len` 0, which the
    // header permits, and `written` points to a live usize.
    let code =
        unsafe { sys::oxi_integrity_status_detail(core::ptr::null_mut(), 0, &raw mut needed) };
    detail_from((code, needed), |buf| {
        let mut written: usize = 0;
        // SAFETY: U1; U6, `buf` has the `needed` bytes the sizing call
        // reported, and `out_len` says so.
        let code = unsafe {
            sys::oxi_integrity_status_detail(buf.as_mut_ptr(), buf.len(), &raw mut written)
        };
        (code, written)
    })
}

/// The detail text from the sizing call's `(status, needed)` and a `read`
/// that fills a buffer of `needed` bytes and returns `(status, written)`.
pub(crate) fn detail_from(
    sizing: (c_int, usize),
    read: impl FnOnce(&mut [u8]) -> (c_int, usize),
) -> Result<Option<String>, DetailError> {
    let (code, needed) = sizing;
    // Status 1 with nothing needed: the integrity test has not failed, so
    // there is no text. Status 11 is the sizing call's normal answer.
    if needed == 0 && matches!(code, 0 | 1) {
        return Ok(None);
    }
    if !matches!(code, 0 | 11) {
        return Err(DetailError::Sizing(Error::from_code(code, Site::Other)));
    }
    if needed > DETAIL_MAX {
        return Err(DetailError::TooLong { needed });
    }
    let mut buf = vec![0u8; needed];
    let (code, written) = read(&mut buf);
    status(code, Site::Other).map_err(DetailError::Read)?;
    if written > buf.len() {
        return Err(DetailError::Overrun {
            written,
            capacity: buf.len(),
        });
    }
    buf.truncate(written);
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Ok((!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned()))
}

/// The library's API manifest, copied. `None` when the library returns null.
fn manifest() -> Option<String> {
    // SAFETY: U1; no pointers in.
    let ptr = unsafe { sys::lama_manifest() };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: U5, the header states the string is NUL-terminated and valid
    // for the library's lifetime; it is copied before use.
    let text = unsafe { CStr::from_ptr(ptr) };
    Some(text.to_string_lossy().into_owned())
}

/// The value of `version:` directly under the top-level `library:` mapping
/// of a manifest, unquoted. No other `version:` key is read.
pub(crate) fn manifest_library_version(manifest: &str) -> Option<&str> {
    let mut in_library = false;
    let mut child_indent: Option<usize> = None;
    for line in manifest.lines() {
        let content = line.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = line.len().saturating_sub(content.len());
        if indent == 0 {
            if in_library {
                return None;
            }
            in_library = content.trim_end() == "library:";
            continue;
        }
        if !in_library {
            continue;
        }
        let expected = *child_indent.get_or_insert(indent);
        if indent != expected {
            continue;
        }
        if let Some(value) = content.strip_prefix("version:") {
            let value = value.split(" #").next().unwrap_or("").trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

/// Whether the loaded library is one this crate may call: today, that its
/// manifest states exactly this crate's version. Checked once per process.
fn library_compatible() -> Result<(), Error> {
    static CHECKED: OnceLock<Result<(), Error>> = OnceLock::new();
    CHECKED
        .get_or_init(|| {
            let crate_ = env!("CARGO_PKG_VERSION");
            let text = manifest();
            let library = text.as_deref().and_then(manifest_library_version);
            if library == Some(crate_) {
                Ok(())
            } else {
                Err(Error::LibraryVersion {
                    library: library.map(str::to_owned),
                    crate_,
                })
            }
        })
        .clone()
}

/// Shared by the safe layer: status 0 or the mapped error for `Site::Other`.
pub(crate) fn check(code: c_int) -> Result<(), Error> {
    status(code, Site::Other)
}
