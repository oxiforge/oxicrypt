//! The signing key: reading it, generating a pair, and signing with it.
//!
//! A signing key is the 32-byte ML-DSA-87 key-generation seed ξ, in a file
//! the signer reads; `ML-DSA.KeyGen_internal(ξ)` (FIPS 204 Algorithm 6)
//! derives the pair from it. The public half, the 2,592-byte encoded public
//! key, is what a build embeds through `OXICRYPT_INTEGRITY_VERIFY_KEY`. The
//! private key never belongs in a source tree: [`keygen`] refuses a
//! directory inside a git work tree, and the signer never generates a key
//! implicitly or carries a default.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use oxicrypt_drbg::HmacDrbgSha256;
use oxicrypt_integrity::key::VERIFY_KEY_LEN;
use oxicrypt_integrity::slot::SIG_LEN;
use oxicrypt_ml_dsa::ml_dsa_87;

/// File name [`keygen`] gives the private key.
pub const SIGNING_KEY_FILE: &str = "integrity-signing.key";
/// File name [`keygen`] gives the public key.
pub const VERIFY_KEY_FILE: &str = "integrity-verify.pub";

/// Length of an ML-DSA-87 key-generation seed ξ.
pub const SEED_LEN: usize = ml_dsa_87::SEED_LEN;

/// The verification the pairwise consistency test runs: the gated external
/// `ML-DSA.Verify`, with the context string.
type Verify =
    fn(&[u8; VERIFY_KEY_LEN], &[u8], &[u8], &[u8; SIG_LEN]) -> Result<(), oxicrypt_module::Error>;

/// The message the pairwise consistency test signs and verifies.
const CONSISTENCY_MESSAGE: &[u8] = b"oxicrypt-integrity-sign pairwise consistency test";

/// An ML-DSA-87 signing key: its seed, the private key the seed derives,
/// and its public half. The seed and the private key are wiped on drop.
pub struct SigningKey {
    seed: [u8; SEED_LEN],
    secret: [u8; ml_dsa_87::SK_LEN],
    public: [u8; VERIFY_KEY_LEN],
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        oxicrypt_zeroize::zeroize(&mut self.seed);
        oxicrypt_zeroize::zeroize(&mut self.secret);
        #[cfg(test)]
        wipe_witness::record(
            self.seed.iter().all(|&b| b == 0) && self.secret.iter().all(|&b| b == 0),
        );
    }
}

/// What the last `Drop` of a [`SigningKey`] on this thread left in its seed
/// and private key, read by the drop itself while the key is still owned.
/// Reading the memory after the drop would need `unsafe` and would be a read
/// of freed storage; this observes the same fact soundly.
#[cfg(test)]
mod wipe_witness {
    std::thread_local! {
        static LAST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn record(zeroed: bool) {
        LAST.with(|c| c.set(Some(zeroed)));
    }

    /// `Some(true)` when the last drop left the seed and private key all
    /// zero.
    pub(super) fn take() -> Option<bool> {
        LAST.with(std::cell::Cell::take)
    }
}

impl SigningKey {
    /// Derives the key pair from a seed ξ and runs the pairwise consistency
    /// test: a fixed message signed with the private key must verify under
    /// the public key, and must not verify once one bit of the signature is
    /// flipped.
    ///
    /// # Errors
    ///
    /// A description beginning `SigningKeyAbsent` when the module refuses
    /// key generation or the pair fails the consistency test.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, String> {
        crate::start_module()?;
        // Built in place: the seed and the private key are held in the key's
        // own fields, wiped on drop, and the local copy of the private key
        // is wiped once it has been copied in.
        let mut key = Self {
            seed: *seed,
            secret: [0u8; ml_dsa_87::SK_LEN],
            public: [0u8; VERIFY_KEY_LEN],
        };
        let (public, mut secret) = ml_dsa_87::keygen(&key.seed)
            .map_err(|e| format!("SigningKeyAbsent: key generation from the seed failed: {e}"))?;
        key.secret.copy_from_slice(&secret);
        oxicrypt_zeroize::zeroize(&mut secret);
        key.public = public;
        key.consistency_test(ml_dsa_87::verify)?;
        Ok(key)
    }

    /// Signs a fixed message and verifies it with `verify`, then verifies it
    /// with one bit flipped, which must fail.
    fn consistency_test(&self, verify: Verify) -> Result<(), String> {
        let mut signature = self
            .sign(CONSISTENCY_MESSAGE)
            .map_err(|e| format!("SigningKeyAbsent: the consistency test failed: {e}"))?;
        let ctx = oxicrypt_integrity::SIGNATURE_CONTEXT;
        let good = verify(&self.public, CONSISTENCY_MESSAGE, ctx, &signature);
        if let Some(first) = signature.first_mut() {
            *first ^= 0x01;
        }
        let flipped = verify(&self.public, CONSISTENCY_MESSAGE, ctx, &signature);
        // The flipped signature must be refused as a signature that does not
        // verify, which the external interface reports as `InvalidInput`;
        // any other error is the module refusing, not a rejection.
        match (good, flipped) {
            (Ok(()), Err(oxicrypt_module::Error::InvalidInput)) => Ok(()),
            (good, flipped) => Err(format!(
                "SigningKeyAbsent: the key pair failed its pairwise consistency test \
                 (signature: {good:?}, flipped signature: {flipped:?})"
            )),
        }
    }

    /// Reads a signing key from `path`: a file holding exactly the 32-byte
    /// seed ξ.
    ///
    /// # Errors
    ///
    /// A description beginning `SigningKeyAbsent` when the file cannot be
    /// read, is not 32 bytes, names a key store this build does not reach,
    /// or holds a seed whose pair fails the consistency test.
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = path.to_string_lossy();
        if text.starts_with("pkcs11:") || text.contains("://") {
            return Err(format!(
                "SigningKeyAbsent: {text} names a key store; this signer reads a key file"
            ));
        }
        let mut bytes = std::fs::read(path)
            .map_err(|e| format!("SigningKeyAbsent: cannot read {}: {e}", path.display()))?;
        // Copied straight into the one buffer that is wiped below, never
        // through a temporary.
        let len = bytes.len();
        let mut seed = [0u8; SEED_LEN];
        if let Some(src) = bytes.get(..SEED_LEN)
            && len == SEED_LEN
        {
            seed.copy_from_slice(src);
        }
        oxicrypt_zeroize::zeroize(&mut bytes);
        if len != SEED_LEN {
            return Err(format!(
                "SigningKeyAbsent: {} holds {len} bytes; a signing key is a 32-byte ML-DSA-87 \
                 key-generation seed",
                path.display()
            ));
        }
        let key = Self::from_seed(&seed);
        oxicrypt_zeroize::zeroize(&mut seed);
        key
    }

    /// Generates a fresh key from a seed drawn from an approved DRBG seeded
    /// from the operating system.
    ///
    /// # Errors
    ///
    /// A description when the operating system supplies no entropy or the
    /// module refuses.
    pub fn generate() -> Result<Self, String> {
        crate::start_module()?;
        let mut drbg = seeded_drbg()?;
        let mut seed = [0u8; SEED_LEN];
        drbg.generate(None, &mut seed)
            .map_err(|e| format!("key generation failed: the DRBG refused: {e}"))?;
        let key = Self::from_seed(&seed);
        oxicrypt_zeroize::zeroize(&mut seed);
        key
    }

    /// The public half, as a build embeds it.
    #[must_use]
    pub fn public_key(&self) -> &[u8; VERIFY_KEY_LEN] {
        &self.public
    }

    /// SHA-256 of the public half: the `key_id` a slot carries.
    ///
    /// # Errors
    ///
    /// A description when the module refuses the hash.
    pub fn fingerprint(&self) -> Result<[u8; 32], String> {
        oxicrypt_integrity::key_fingerprint(&self.public)
            .map_err(|e| format!("cannot fingerprint the key: {e}"))
    }

    /// Signs `message` with the external `ML-DSA.Sign` (FIPS 204
    /// Algorithm 2) under [`oxicrypt_integrity::SIGNATURE_CONTEXT`].
    ///
    /// The caller passes the unframed signature input `M`; the external
    /// interface frames it as `M′`, the message the module's integrity test
    /// verifies. Signing is deterministic: this module signs with the
    /// all-zero `rnd`, so one key and one message always give the same
    /// signature.
    ///
    /// # Errors
    ///
    /// A description when the module refuses.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIG_LEN], String> {
        ml_dsa_87::sign(&self.secret, message, oxicrypt_integrity::SIGNATURE_CONTEXT)
            .map_err(|e| format!("signing failed: {e}"))
    }
}

/// Generates a key pair and writes it into `dir`, which must lie outside any
/// source tree.
///
/// The seed goes to [`SIGNING_KEY_FILE`], created new with mode
/// `0600` on Unix, and the public key to [`VERIFY_KEY_FILE`]. Existing files
/// are never overwritten. Returns both paths and the key's fingerprint.
///
/// # Errors
///
/// A description when `dir` is inside a git work tree, either file already
/// exists, or a write fails.
pub fn keygen(dir: &Path) -> Result<(PathBuf, PathBuf, [u8; 32]), String> {
    // A `..` component is refused outright: `std::path::absolute` keeps it,
    // so the nearest existing ancestor would not be the directory the path
    // finally names.
    if dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{} contains `..`; name the key directory without it",
            dir.display()
        ));
    }
    // Checked before anything is created, so a refused directory is not left
    // behind inside the tree it was refused for.
    let absolute =
        std::path::absolute(dir).map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?;
    let existing = absolute
        .ancestors()
        .find(|a| a.exists())
        .ok_or_else(|| format!("no part of {} exists", absolute.display()))?
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", absolute.display()))?;
    refuse_work_tree(&existing, &absolute)?;
    std::fs::create_dir_all(&absolute)
        .map_err(|e| format!("cannot create {}: {e}", absolute.display()))?;
    let dir = absolute
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", absolute.display()))?;
    // Again on the resolved directory, which a symbolic link created since
    // the first check could have moved into a tree.
    refuse_work_tree(&dir, &dir)?;

    let private_path = dir.join(SIGNING_KEY_FILE);
    let public_path = dir.join(VERIFY_KEY_FILE);
    for path in [&private_path, &public_path] {
        if path.exists() {
            return Err(format!("{} already exists", path.display()));
        }
    }
    remove_stale_temporaries(&dir);
    let key = SigningKey::generate()?;
    let fingerprint = key.fingerprint()?;

    // Both files are written under temporary names and synced, then linked
    // into place public half first, so an interrupted run leaves no usable
    // key file, the public half alone, or the whole pair: never a truncated
    // private key, and never a private key without its public half.
    let tag = format!(".tmp-{}", std::process::id());
    let private_tmp = dir.join(format!("{SIGNING_KEY_FILE}{tag}"));
    let public_tmp = dir.join(format!("{VERIFY_KEY_FILE}{tag}"));
    let outcome = (|| {
        write_new(&private_tmp, &key.seed, true)?;
        write_new(&public_tmp, key.public_key(), false)?;
        std::fs::hard_link(&public_tmp, &public_path)
            .map_err(|e| format!("cannot create {}: {e}", public_path.display()))?;
        // On Unix the public half's name is durable before the private half
        // is linked, so the order survives a crash and not only a kill. On
        // Windows `sync_dir` forces nothing, so only a kill is covered: a
        // crash can lose either name (see `sync_dir`).
        sync_dir(&dir)?;
        if let Err(e) = std::fs::hard_link(&private_tmp, &private_path) {
            let _ = std::fs::remove_file(&public_path);
            return Err(format!("cannot create {}: {e}", private_path.display()));
        }
        Ok(())
    })();
    if outcome.is_ok() {
        // The seed now has its final name too; only this name goes.
        remove_reporting(&private_tmp);
    } else {
        // Never linked to the final name: the seed is overwritten in place.
        erase_seed_file(&private_tmp, false);
    }
    remove_reporting(&public_tmp);
    outcome?;
    sync_dir(&dir)?;
    Ok((private_path, public_path, fingerprint))
}

/// Removes temporary files an earlier `--keygen` in `dir` left behind when
/// it was killed: `integrity-*.tmp-<pid>` whose process no longer exists,
/// where `/proc` shows that, or that are older than an hour elsewhere. No
/// key generation takes an hour, so an older temporary has no live owner.
fn remove_stale_temporaries(dir: &Path) {
    const STALE: std::time::Duration = std::time::Duration::from_hours(1);
    let proc_fs = Path::new("/proc/self").exists();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            report(&format!(
                "cannot list {} for stale temporaries: {e}",
                dir.display()
            ));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report(&format!(
                    "cannot read an entry of {} for stale temporaries: {e}",
                    dir.display()
                ));
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = name.starts_with(SIGNING_KEY_FILE) || name.starts_with(VERIFY_KEY_FILE);
        let Some((_, pid)) = name.rsplit_once(".tmp-") else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let dead = if proc_fs {
            !Path::new(&format!("/proc/{pid}")).exists()
        } else {
            match entry.metadata().and_then(|m| m.modified()) {
                // A modification time in the future is not stale.
                Ok(t) => t.elapsed().is_ok_and(|age| age > STALE),
                Err(e) => {
                    report(&format!(
                        "cannot read the age of {}: {e}",
                        entry.path().display()
                    ));
                    false
                }
            }
        };
        if ours && pid != std::process::id() && dead {
            let path = entry.path();
            if name.starts_with(SIGNING_KEY_FILE) {
                // A run killed after linking the final name leaves the
                // temporary as a second name of the key now in use.
                erase_seed_file(&path, true);
            } else {
                remove_reporting(&path);
            }
        }
    }
}

/// Overwrites a file that holds or may hold a seed with zeros, in place and
/// without reading it, then removes it.
///
/// When `may_be_linked`, the file is overwritten only where it is shown to
/// have no other name: on Unix a link count of one; elsewhere only when no
/// signing key sits beside it, since the temporary could be its other name.
/// Otherwise it is only unlinked, so a key in use is never overwritten.
/// A file that cannot be overwritten or removed is reported on stderr.
fn erase_seed_file(path: &Path, may_be_linked: bool) {
    let sole_name = !may_be_linked || {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::symlink_metadata(path).is_ok_and(|m| m.nlink() == 1)
        }
        #[cfg(not(unix))]
        {
            path.parent()
                .is_some_and(|dir| !dir.join(SIGNING_KEY_FILE).exists())
        }
    };
    if sole_name && let Err(e) = overwrite_with_zeros(path) {
        report(&format!("could not overwrite {}: {e}", path.display()));
    }
    remove_reporting(path);
}

/// Writes zeros over every byte of `path` without truncating it, then syncs
/// it.
fn overwrite_with_zeros(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let mut left = file.metadata()?.len();
    let zeros = [0u8; 4096];
    while left > 0 {
        let chunk = left.min(4096);
        let n = usize::try_from(chunk).unwrap_or(4096);
        file.write_all(zeros.get(..n).unwrap_or(&zeros))?;
        left = left.saturating_sub(chunk);
    }
    file.sync_all()
}

/// Removes `path`, reporting on stderr when a file that exists could not be
/// removed.
fn remove_reporting(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        report(&format!("could not remove {}: {e}", path.display()));
    }
}

/// One line on stderr: a key file left behind is the operator's to deal
/// with, so it is never dropped silently.
#[allow(clippy::print_stderr, reason = "a leftover key file must be reported")]
fn report(line: &str) {
    eprintln!("oxicrypt-integrity-sign: warning: {line}");
}

/// Refuses `resolved` when it, or an ancestor, is a git work tree.
fn refuse_work_tree(resolved: &Path, named: &Path) -> Result<(), String> {
    match resolved.ancestors().find(|a| a.join(".git").exists()) {
        Some(tree) => Err(format!(
            "{} is inside the work tree at {}; write the key pair outside any source tree",
            named.display(),
            tree.display()
        )),
        None => Ok(()),
    }
}

/// Makes the directory's new entries durable, where the platform allows it.
///
/// # Errors
///
/// A description when the directory cannot be opened or synced.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "one signature; Unix can fail")
)]
pub(crate) fn sync_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|e| format!("cannot sync {}: {e}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        // Not forced on Windows: the directory is not opened (that needs
        // `FILE_FLAG_BACKUP_SEMANTICS`) or flushed, so the new names are
        // NTFS metadata that the journal has not necessarily written to disk.
        // A crash soon after `--keygen` can lose either or both names, and
        // the public-first ordering holds only against a kill. The files'
        // contents were synced before they were linked.
        let _ = dir;
        Ok(())
    }
}

/// Creates `path`, which must not exist, writes `bytes` to it and syncs it.
/// A failed write removes the file, so nothing partial is left behind.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()));
    if written.is_err() {
        if private {
            erase_seed_file(path, false);
        } else {
            remove_reporting(path);
        }
    }
    written
}

/// An HMAC_DRBG instantiated from 48 bytes of operating-system entropy:
/// 32 for the entropy input and 16 for the nonce, the minimums SP 800-90Ar1
/// sets for a 256-bit security strength: §10.1 for the entropy input,
/// §8.6.7 for the nonce.
fn seeded_drbg() -> Result<HmacDrbgSha256, String> {
    let mut seed = [0u8; 48];
    os_entropy(&mut seed)?;
    let mut drbg = HmacDrbgSha256::new();
    let (entropy, nonce) = seed.split_at(32);
    let outcome = drbg
        .instantiate(entropy, nonce, b"oxicrypt-integrity-sign")
        .map_err(|e| format!("the DRBG did not instantiate: {e}"));
    oxicrypt_zeroize::zeroize(&mut seed);
    outcome?;
    Ok(drbg)
}

/// Fills `buf` from the operating system's random device.
///
/// `/dev/urandom` on Unix; on Windows the system-preferred generator through
/// `BCryptGenRandom`, the operating system's CSPRNG.
fn os_entropy(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .map_err(|e| format!("cannot read /dev/urandom: {e}"))
    }
    #[cfg(windows)]
    {
        windows_rng::fill(buf)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = buf;
        Err("this platform has no random device the signer can read".to_owned())
    }
}

/// The Windows system CSPRNG.
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_rng {
    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`: use the system's preferred
    /// generator, with no algorithm handle.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        /// Fills `buffer` with `count` random bytes. Returns an `NTSTATUS`,
        /// zero on success.
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            count: u32,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn fill(buf: &mut [u8]) -> Result<(), String> {
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let count = u32::try_from(chunk.len()).map_err(|_| "request too large".to_owned())?;
            // SAFETY: `chunk` is a live, uniquely borrowed buffer of `count`
            // bytes; a null algorithm handle is what the system-preferred
            // flag requires.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    count,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(format!("BCryptGenRandom failed with status {status:#x}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::unnecessary_wraps)]
mod tests {
    use super::{SigningKey, wipe_witness};

    /// Dropping a key leaves its seed and private key all zero.
    #[test]
    fn dropping_a_signing_key_wipes_its_seed_and_private_key() {
        let key = SigningKey::from_seed(&[0x5a; 32]).unwrap();
        let _ = wipe_witness::take();
        drop(key);
        assert_eq!(wipe_witness::take(), Some(true));
        // Control: nothing dropped, nothing recorded.
        assert_eq!(wipe_witness::take(), None);
    }

    /// The pairwise consistency test refuses a pair whose signature does not
    /// verify, and one whose verification accepts a flipped signature.
    #[test]
    fn the_consistency_test_refuses_a_pair_that_fails_either_check() {
        let key = SigningKey::from_seed(&[0x42; 32]).unwrap();
        let never: super::Verify = |_, _, _, _| Err(oxicrypt_module::Error::InvalidInput);
        let always: super::Verify = |_, _, _, _| Ok(());
        // Accepts the real signature and fails the flipped one with an
        // error that is not a rejection: the module refusing.
        let refusing: super::Verify = |pk, m, ctx, sig| {
            oxicrypt_ml_dsa::ml_dsa_87::verify(pk, m, ctx, sig).map_err(|_| {
                oxicrypt_module::Error::NotOperational {
                    current: oxicrypt_module::State::Error,
                }
            })
        };
        for (what, verify) in [
            ("rejects everything", never),
            ("accepts everything", always),
            (
                "refuses rather than rejects the flipped signature",
                refusing,
            ),
        ] {
            let err = key.consistency_test(verify).unwrap_err();
            assert!(
                err.starts_with("SigningKeyAbsent") && err.contains("consistency"),
                "a verifier that {what}: {err}"
            );
        }
        // Control: the real verifier passes.
        assert!(
            key.consistency_test(oxicrypt_ml_dsa::ml_dsa_87::verify)
                .is_ok()
        );
    }

    #[cfg(unix)]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oxicrypt-erase-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Reads a file's bytes through a second name, which survives the first
    /// name's removal.
    #[cfg(unix)]
    fn through(link: &std::path::Path) -> Vec<u8> {
        std::fs::read(link).unwrap()
    }

    /// A seed file is overwritten in place, every byte zero, before it is
    /// removed; one that may be a second name of a key in use is only
    /// unlinked.
    #[cfg(unix)]
    #[test]
    fn a_seed_file_is_zeroed_in_place_unless_it_is_another_name() {
        use super::{SIGNING_KEY_FILE, erase_seed_file};
        let dir = scratch("seed");
        let tmp = dir.join(format!("{SIGNING_KEY_FILE}.tmp-1"));
        let witness = dir.join("witness");
        std::fs::write(&tmp, [0x5a; 32]).unwrap();
        std::fs::hard_link(&tmp, &witness).unwrap();

        // A temporary that is a second name of a key in place is only
        // unlinked: the key keeps its bytes.
        erase_seed_file(&tmp, true);
        assert!(!tmp.exists());
        assert_eq!(through(&witness), [0x5a; 32]);

        // A temporary that was never linked is overwritten in place. The
        // witness name shares its storage, so it shows the bytes the erase
        // wrote, and the file's length is unchanged.
        std::fs::hard_link(&witness, &tmp).unwrap();
        erase_seed_file(&tmp, false);
        assert!(!tmp.exists());
        assert_eq!(through(&witness), [0u8; 32]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
