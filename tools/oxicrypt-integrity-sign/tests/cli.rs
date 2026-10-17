//! The signer's command line: its refusals, their exit codes, and what
//! `--show` reports.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use oxicrypt_integrity_sign::{SigningKey, embed_verify_key, sign_image};

const SIGNER: &str = env!("CARGO_BIN_EXE_oxicrypt-integrity-sign");

/// A scratch directory, removed with everything in it when the test ends,
/// whether it passed or failed: dropping the guard removes it, and a failing
/// assertion unwinds through the drop.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!("could not remove {}: {e}", self.0.display());
        }
    }
}

fn scratch(tag: &str) -> Scratch {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "oxicrypt-sign-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(SIGNER).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A copy of this test binary, which links the integrity crate and so
/// carries a slot and a key record, embedding `key`.
fn artifact(dir: &Path, key: &SigningKey) -> PathBuf {
    let mut bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    embed_verify_key(&mut bytes, key.public_key()).unwrap();
    let path = dir.join("artifact");
    std::fs::write(&path, &bytes).unwrap();
    path
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn sign_without_a_key_is_signing_key_absent_with_exit_3() {
    let dir = scratch("nokey");
    let key = SigningKey::from_seed(&[0x42; 32]).unwrap();
    let art = artifact(&dir, &key);
    let before = std::fs::read(&art).unwrap();
    let (code, _, err) = run(&["--sign", s(&art)]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("SigningKeyAbsent"), "{err}");
    assert_eq!(before, std::fs::read(&art).unwrap(), "nothing is written");
}

#[test]
fn an_unusable_key_file_is_signing_key_absent_with_exit_3() {
    let dir = scratch("badkey");
    let key = SigningKey::from_seed(&[0x42; 32]).unwrap();
    let art = artifact(&dir, &key);
    // 64 bytes: not a 32-byte ML-DSA-87 seed.
    let bad = dir.join("bad.key");
    std::fs::write(&bad, [0x11u8; 64]).unwrap();
    let (code, _, err) = run(&["--sign", "--key", s(&bad), s(&art)]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("SigningKeyAbsent"), "{err}");
    let (code, _, err) = run(&["--sign", "--key", "pkcs11:token=x", s(&art)]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("key store"), "{err}");
}

#[test]
fn key_outside_sign_or_twice_is_a_usage_error() {
    let dir = scratch("keyflag");
    let k = dir.join("k");
    std::fs::write(&k, [1u8; 32]).unwrap();
    let (code, _, err) = run(&["--verify", "--key", s(&k), s(&k)]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&["--show", "--key", s(&k), s(&k)]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&["--sign", "--key", s(&k), "--key", s(&k), s(&k)]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("twice"), "{err}");
}

/// `--reserved-against` is a usage error with `--keygen` and `--verify`,
/// and a refusal for an artifact that is neither Mach-O nor PE; it is never
/// ignored.
#[test]
fn reserved_against_outside_a_mach_o_or_pe_sign_or_show_is_refused() {
    let dir = scratch("reserved");
    let a = dir.join("a");
    std::fs::write(&a, b"\x7fELF not a Mach-O image").unwrap();
    let (code, out, err) = run(&["--keygen", "--reserved-against", s(&a), s(&dir.join("k"))]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--reserved-against"), "{err}");
    assert!(!dir.join("k").exists(), "{out}");
    let (code, _, err) = run(&["--verify", "--reserved-against", s(&a), s(&a)]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&["--keygen", s(&dir.join("keys"))]);
    assert_eq!(code, 0, "{err}");
    let key = dir.join("keys").join("integrity-signing.key");
    for mode in ["--sign", "--show"] {
        let mut args = vec![mode];
        if mode == "--sign" {
            args.extend(["--key", s(&key)]);
        }
        args.extend(["--reserved-against", s(&a), s(&a)]);
        let (code, _, err) = run(&args);
        assert_eq!(code, 2, "{mode}: {err}");
        assert!(err.contains("applies to Mach-O"), "{mode}: {err}");
    }
}

/// `--loader` takes glibc or bionic, once, and not with `--keygen`.
#[test]
fn loader_unknown_twice_or_with_keygen_is_a_usage_error() {
    let dir = scratch("loaderflag");
    let a = dir.join("a");
    std::fs::write(&a, b"x").unwrap();
    let (code, _, err) = run(&["--keygen", "--loader", "glibc", s(&dir.join("k"))]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&["--show", "--loader", "musl", s(&a)]);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run(&["--show", "--loader", "glibc", "--loader", "bionic", s(&a)]);
    assert_eq!(code, 1, "{err}");
    // Control: a valid loader reaches the artifact, which is then refused
    // for what it is, not for the flag, with --show and --verify alike.
    for mode in ["--show", "--verify"] {
        let (code, _, err) = run(&[mode, "--loader", "bionic", s(&a)]);
        assert_eq!(code, 2, "{err}");
    }
}

#[test]
fn keygen_inside_a_work_tree_exits_4_and_creates_nothing() {
    let dir = scratch("tree");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let target = dir.join("keys");
    let (code, _, err) = run(&["--keygen", s(&target)]);
    assert_eq!(code, 4, "{err}");
    assert!(!target.exists());
    let (code, _, err) = run(&["--keygen", &format!("{}/../keys", s(&dir.join("x")))]);
    assert_eq!(code, 4, "{err}");
}

/// `--show` prints the embedded key's fingerprint, the slot's key id and
/// whether they match, and names a slot defect instead of hiding it.
#[test]
fn show_reports_both_fingerprints_and_their_agreement() {
    let dir = scratch("show");
    let key = SigningKey::from_seed(&[0x42; 32]).unwrap();
    let art = artifact(&dir, &key);
    let fp = oxicrypt_integrity::format_fingerprint(&key.fingerprint().unwrap());

    let (code, out, err) = run(&["--show", s(&art)]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&format!("verify key: {fp}")), "{out}");
    assert!(
        out.contains("slot version 0"),
        "the unsigned slot is named: {out}"
    );

    let mut bytes = std::fs::read(&art).unwrap();
    sign_image(&mut bytes, &key).unwrap();
    std::fs::write(&art, &bytes).unwrap();
    let (code, out, _) = run(&["--show", s(&art)]);
    assert_eq!(code, 0);
    assert!(out.contains(&format!("key id {fp}")), "{out}");
    assert!(out.contains("matches the embedded verifying key"), "{out}");
    // The signature is named by the SHA-256 of the slot's signature field,
    // computed here from the file's bytes.
    let at = oxicrypt_integrity_sign::image::find_slot(&bytes).unwrap();
    let field = &bytes[at + oxicrypt_integrity::slot::OFF_SIG
        ..at + oxicrypt_integrity::slot::OFF_SIG + oxicrypt_integrity::slot::SIG_LEN];
    assert!(field.iter().any(|&b| b != 0), "premise: the slot is signed");
    let digest = oxicrypt_sha::sha256::sha256(field).unwrap();
    let named = format!(
        "signature {}",
        oxicrypt_integrity::format_fingerprint(&digest)
    );
    assert!(out.contains(&named), "{named} not in: {out}");

    let other = SigningKey::from_seed(&[0x24; 32]).unwrap();
    embed_verify_key(&mut bytes, other.public_key()).unwrap();
    std::fs::write(&art, &bytes).unwrap();
    let (_, out, _) = run(&["--show", s(&art)]);
    assert!(out.contains("KeyMismatch"), "{out}");
}

/// `--sign` through the command line signs, verifies and keeps the file's
/// permissions; the artifact verifies afterwards.
#[test]
fn sign_replaces_the_artifact_with_a_verified_copy() {
    let dir = scratch("sign");
    let (code, out, err) = run(&["--keygen", s(&dir.join("keys"))]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("fingerprint: sha256:"), "{out}");
    let key = SigningKey::read(&dir.join("keys/integrity-signing.key")).unwrap();
    let art = artifact(&dir, &key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&art, std::fs::Permissions::from_mode(0o751)).unwrap();
    }
    let (code, _, err) = run(&[
        "--sign",
        "--key",
        s(&dir.join("keys/integrity-signing.key")),
        s(&art),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["--verify", s(&art)]);
    assert_eq!(code, 0, "{err}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&art).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o751);
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".signing-"))
        .collect();
    assert!(leftovers.is_empty(), "no temporary file is left behind");
}

/// An ELF artifact signed with `--loader` for a loader other than the one
/// it declares is signed (the read-back checks it against that loader), and
/// `--verify` names the disagreement unless given the same `--loader`.
#[cfg(target_os = "linux")]
#[test]
fn a_loader_override_is_signed_and_verified_for_that_loader() {
    let dir = scratch("loader");
    let (code, _, err) = run(&["--keygen", s(&dir.join("keys"))]);
    assert_eq!(code, 0, "{err}");
    let key = SigningKey::read(&dir.join("keys/integrity-signing.key")).unwrap();
    let art = artifact(&dir, &key);
    let k = dir.join("keys/integrity-signing.key");
    let (code, _, err) = run(&["--sign", "--key", s(&k), "--loader", "bionic", s(&art)]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["--verify", s(&art)]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("LoaderMismatch"), "{err}");
    let (code, _, err) = run(&["--verify", "--loader", "bionic", s(&art)]);
    assert_eq!(code, 0, "{err}");
}

/// Signing through a symbolic link signs the file it names and leaves the
/// link a link.
#[cfg(unix)]
#[test]
fn signing_through_a_symlink_signs_its_target() {
    let dir = scratch("symlink");
    let (code, _, err) = run(&["--keygen", s(&dir.join("keys"))]);
    assert_eq!(code, 0, "{err}");
    let key_file = dir.join("keys/integrity-signing.key");
    let key = SigningKey::read(&key_file).unwrap();
    let art = artifact(&dir, &key);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&art, &link).unwrap();
    let (code, _, err) = run(&["--sign", "--key", s(&key_file), s(&link)]);
    assert_eq!(code, 0, "{err}");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link must stay a link"
    );
    let (code, _, err) = run(&["--verify", s(&art)]);
    assert_eq!(code, 0, "the link's target must be the signed file: {err}");
}
