//! The verifying key as a build input, end to end.
//!
//! Every other signed-artifact test writes the key into a copy after the
//! link. These build the probe with `OXICRYPT_INTEGRITY_VERIFY_KEY_HEX` and
//! with `OXICRYPT_INTEGRITY_VERIFY_KEY`, check that the artifact embeds
//! exactly that key, sign it against the embedded key without touching the
//! key record, and boot it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use oxicrypt_integrity_sign::{SigningKey, embedded_verify_key, sign_image};

/// Builds the probe with `var=value` set and the other key variable unset,
/// in a target directory of its own, and returns the probe's path.
fn build_probe(var: &str, value: &str) -> PathBuf {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("build-time-key");
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "integrity-probe"])
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("OXICRYPT_INTEGRITY_VERIFY_KEY")
        .env_remove("OXICRYPT_INTEGRITY_VERIFY_KEY_HEX")
        .env(var, value)
        .status()
        .expect("run cargo build");
    assert!(status.success(), "building the probe with {var} set failed");
    let exe = target
        .join("debug")
        .join(format!("integrity-probe{}", std::env::consts::EXE_SUFFIX));
    assert!(exe.is_file(), "the probe is missing at {}", exe.display());
    exe
}

/// Signs a copy of `built` with `key` and boots it.
fn sign_and_boot(built: &Path, key: &SigningKey, tag: &str) {
    let mut bytes = std::fs::read(built).unwrap();
    assert_eq!(
        embedded_verify_key(&bytes).unwrap(),
        Some(*key.public_key()),
        "the build must embed exactly the key it was given"
    );
    sign_image(&mut bytes, key).expect("sign against the embedded key");
    let copy = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("probe-{tag}"));
    std::fs::write(&copy, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = Command::new(&copy).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the signed build must boot: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_build_with_the_key_variables_embeds_and_verifies_that_key() {
    let hex_key = SigningKey::from_seed(&[0x11; 32]).unwrap();
    let hex = hex_key.public_key().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let built = build_probe("OXICRYPT_INTEGRITY_VERIFY_KEY_HEX", &hex);
    sign_and_boot(&built, &hex_key, "hex");

    let file_key = SigningKey::from_seed(&[0x22; 32]).unwrap();
    let pub_file = Path::new(env!("CARGO_TARGET_TMPDIR")).join("build-time-key.pub");
    std::fs::write(&pub_file, file_key.public_key()).unwrap();
    let built = build_probe("OXICRYPT_INTEGRITY_VERIFY_KEY", pub_file.to_str().unwrap());
    sign_and_boot(&built, &file_key, "file");

    // Control: the first build's key does not sign the second build.
    let mut bytes = std::fs::read(&built).unwrap();
    let err = sign_image(&mut bytes, &hex_key).unwrap_err();
    assert!(err.starts_with("SigningKeyAbsent"), "{err}");
}
