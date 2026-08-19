//! Build automation, outside the cryptographic boundary.
//!
//! # Why this exists
//!
//! An artifact that links the module must be signed after it is linked, and
//! nothing in `cargo` runs at that point. Every place that produces a runnable
//! artifact therefore has to build, then sign, then check — and when each place
//! spells that out for itself they drift, which is how one of them ends up
//! shipping an artifact that refuses to start.
//!
//! This is the one implementation. CI calls it and a developer calls the same
//! thing locally, so a mistake in it is visible in both at once rather than in
//! whichever copy was not updated. The release workflow does not call it yet —
//! it signs and publishes `oxi` for every platform in its matrix, each of
//! which can now verify a signed binary at startup.
//!
//! It deliberately does not know how signing works: it shells out to
//! `oxicrypt-integrity-sign`, which owns that.

#![forbid(unsafe_code)]
// A build tool's whole output is its printing, as in the signer beside it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("sign") {
        return match sign(args.get(1..).unwrap_or(&[])) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("xtask sign: {e}");
                ExitCode::FAILURE
            }
        };
    }
    eprintln!("Usage: cargo xtask sign <package> [--release] [--target <triple>]");
    eprintln!();
    eprintln!("Builds the package and the signer, writes the integrity slot into the");
    eprintln!("built artifact, and verifies it. The artifact is runnable afterwards;");
    eprintln!("without the signing step it is not.");
    ExitCode::from(2)
}

/// The workspace root, derived from this crate's own manifest directory.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// Runs a command, failing with its own output rather than a bare status.
fn run(what: &str, cmd: &mut Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("could not run {what}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed with {status}"))
    }
}

fn sign(args: &[String]) -> Result<(), String> {
    let package = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .ok_or("no package named")?;
    let release = args.iter().any(|a| a == "--release");
    let target = match args.iter().position(|a| a == "--target") {
        Some(i) => Some(
            args.get(i.saturating_add(1))
                .ok_or("--target needs a triple after it")?
                .clone(),
        ),
        None => None,
    };
    // Anything unrecognised is refused rather than ignored. `--target=<triple>`
    // is the shape that motivates this: silently dropping it builds for the host
    // and then signs whatever happens to be sitting at the host path, which is a
    // wrong artifact reported as a right one.
    if let Some(unknown) = args
        .iter()
        .skip(1)
        .find(|a| a.starts_with("--") && a.as_str() != "--release" && a.as_str() != "--target")
    {
        return Err(format!(
            "unrecognised argument {unknown}; --target takes its triple as a separate word"
        ));
    }

    let root = workspace_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // The signer is a host tool and is built for the host even when the subject
    // is cross-compiled; a signer built for the target could not be executed.
    let mut build_signer = Command::new(&cargo);
    build_signer
        .current_dir(&root)
        .args(["build", "-p", "oxicrypt-integrity-sign"]);
    if release {
        build_signer.arg("--release");
    }
    run("building the signer", &mut build_signer)?;

    let mut build_subject = Command::new(&cargo);
    build_subject
        .current_dir(&root)
        .args(["build", "-p", package]);
    if release {
        build_subject.arg("--release");
    }
    if let Some(t) = &target {
        build_subject.args(["--target", t]);
    }
    run(&format!("building {package}"), &mut build_subject)?;

    let profile = if release { "release" } else { "debug" };
    // Asked, not guessed. `CARGO_TARGET_DIR` is only one of the ways the target
    // directory moves — `[build] target-dir` in `.cargo/config.toml` and
    // `CARGO_BUILD_TARGET_DIR` do it too — and a relative value resolves against
    // a different directory here than it does inside the child cargo, which runs
    // in the workspace root. Guessing wrong is not loud: a stale artifact from an
    // earlier ordinary build sits at the guessed path, gets signed, and reports
    // success for a file the build never produced.
    let target_dir = cargo_target_directory(&cargo, &root)?;
    let host_dir = target_dir.join(profile);
    let subject_dir = match &target {
        Some(t) => target_dir.join(t).join(profile),
        None => host_dir.clone(),
    };

    let signer = host_dir.join(exe("oxicrypt-integrity-sign"));
    // The binary's file name is the package name for every artifact this signs
    // today. Stated rather than discovered: reading it out of `cargo metadata`
    // would be more general and would also mean parsing JSON in a build tool
    // whose whole value is being short enough to read.
    let subject = subject_dir.join(exe(package_binary(package)));
    if !subject.exists() {
        return Err(format!(
            "{} was not produced by the build. Either {package} names its binary something \
             other than {} and this tool needs teaching about it, or it produces no binary \
             at all — a library or cdylib cannot be signed through `sign`, which addresses \
             artifacts by binary name",
            subject.display(),
            package_binary(package)
        ));
    }

    run("signing", Command::new(&signer).arg("--sign").arg(&subject))?;
    // The signer self-checks, and this checks it again from a separate process
    // against the file as it now sits on disk. The two are not the same claim.
    run(
        "verifying",
        Command::new(&signer).arg("--verify").arg(&subject),
    )?;

    println!("xtask sign: {} is signed and verifies", subject.display());
    Ok(())
}

/// The target directory cargo will actually use.
///
/// Read from `cargo metadata` rather than reconstructed, because the number of
/// ways that path moves is larger than a build tool should try to track. The
/// value is scanned out of the JSON by hand: this crate has no dependencies, and
/// adding one to read a single string would cost more than it saves.
fn cargo_target_directory(cargo: &str, root: &std::path::Path) -> Result<PathBuf, String> {
    const KEY: &str = "\"target_directory\":\"";

    let out = Command::new(cargo)
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|e| format!("could not run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo metadata failed with {}", out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text
        .find(KEY)
        .map(|i| i.saturating_add(KEY.len()))
        .ok_or("cargo metadata did not report a target_directory")?;
    let rest = text.get(start..).ok_or("truncated cargo metadata")?;
    let end = rest
        .find('"')
        .ok_or("cargo metadata's target_directory is unterminated")?;
    let raw = rest.get(..end).ok_or("truncated target_directory")?;
    // JSON escapes: only the separator matters on the platforms this runs on.
    let path = PathBuf::from(raw.replace("\\\\", "/"));
    if !path.is_absolute() {
        return Err(format!(
            "cargo metadata reported a relative target_directory ({}), which cannot be \
             resolved reliably from here",
            path.display()
        ));
    }
    Ok(path)
}

/// The binary a package produces, where it differs from the package name.
const fn package_binary(package: &str) -> &str {
    match package.as_bytes() {
        b"oxicrypt-cli" => "oxi",
        _ => package,
    }
}

/// Adds the host's executable suffix.
fn exe(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}
