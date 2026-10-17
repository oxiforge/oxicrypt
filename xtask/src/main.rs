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
//! whichever copy was not updated. The release workflow signs shared libraries
//! as well as `oxi`, and strips ELF artifacts before signing them, so it runs
//! `scripts/release-sign.sh` instead; both follow the order
//! `docs/integrity-signing.md` gives for each format.
//!
//! It deliberately does not know how signing works: it shells out to
//! `oxicrypt-integrity-sign`, which owns that. Nor does it set link flags: it
//! checks that the caller's environment carries the ones the artifact's format
//! needs, and refuses before building, naming each one missing, when it does
//! not.

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
    eprintln!(
        "Usage: cargo xtask sign <package> --key <signing key> [--release] [--target <triple>]"
    );
    eprintln!();
    eprintln!("Builds the package and the signer, writes the integrity slot into the");
    eprintln!("built artifact, signs it with the key `--key` names, and verifies it.");
    eprintln!("The build embeds the verifying key named by OXICRYPT_INTEGRITY_VERIFY_KEY,");
    eprintln!("which must be the public half of that key; generate a pair with");
    eprintln!("`oxicrypt-integrity-sign --keygen <dir>`. The artifact is runnable");
    eprintln!("afterwards; without the signing step it is not. An artifact for an");
    eprintln!("Apple platform is code signed ad hoc twice with `codesign`, which must be");
    eprintln!("on PATH, signed against the first as --reserved-against, and code signed");
    eprintln!("again. Authenticode signing of a Windows artifact follows separately.");
    eprintln!();
    eprintln!("Each format's link settings must already be in the environment, and the");
    eprintln!("build is refused, naming each one missing, when they are not:");
    eprintln!("  Apple    RUSTFLAGS with -C link-arg=-Wl,-fixup_chains and");
    eprintln!("           -C link-arg=-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss and");
    eprintln!("           -C link-arg=-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common,");
    eprintln!("           on arm64 also -C llvm-args=-aarch64-enable-global-merge=false;");
    eprintln!("           CARGO_PROFILE_<PROFILE>_DEBUG=full and");
    eprintln!("           CARGO_PROFILE_<PROFILE>_SPLIT_DEBUGINFO=packed;");
    eprintln!("           MACOSX_DEPLOYMENT_TARGET at least 12.0 on arm64, 13.0 on x86_64");
    eprintln!("  Windows  RUSTFLAGS with -C link-arg=/MERGE:.bss=.zbss;");
    eprintln!("           CARGO_PROFILE_<PROFILE>_DEBUG=full");
    eprintln!("  Android  RUSTFLAGS with -C link-arg=-Wl,-z,max-page-size=16384");
    eprintln!("RUSTFLAGS is read as cargo reads it: CARGO_ENCODED_RUSTFLAGS, else RUSTFLAGS,");
    eprintln!("else CARGO_TARGET_<TRIPLE>_RUSTFLAGS. <PROFILE> is RELEASE or DEV.");
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

/// One action taken on the built artifact, in the order a [`Plan`] lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Write the integrity slot with `oxicrypt-integrity-sign --sign`.
    Sign,
    /// Keep a copy of the artifact as code signed so far: the reference the
    /// next signing step measures the code signature's locator fields
    /// against.
    Reference,
    /// Write the integrity slot with `--sign --reserved-against` the
    /// reference, after the artifact was code signed again: each locator
    /// field the second code signature changed is a hole.
    SignReserved,
    /// Renew the Apple code signature with `codesign --force --sign -`.
    Codesign,
    /// Check the renewed code signature with `codesign --verify`.
    CodesignVerify,
    /// Re-check the integrity slot from a separate process.
    Verify,
}

/// What `sign` will do, decided before anything is built or written.
#[derive(Debug)]
struct Plan {
    package: String,
    release: bool,
    target: Option<String>,
    /// The signing key passed through to the signer's `--key`.
    key: PathBuf,
    steps: Vec<Step>,
}

/// Parses the arguments to `sign` and decides the steps to take.
///
/// Pure, so the order of the steps is testable without building anything.
/// For an Apple platform: code sign, keep that copy as the reference, code
/// sign again, write the integrity slot against the reference, then the
/// final code signature; elsewhere the slot alone. The slot is verified last
/// against the file as it finally sits.
fn plan(args: &[String], host_is_macos: bool) -> Result<Plan, String> {
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
    // Required: the signer refuses to sign without a key, and refusing here
    // happens before anything is built.
    let key = match args.iter().position(|a| a == "--key") {
        Some(i) => PathBuf::from(
            args.get(i.saturating_add(1))
                .filter(|k| !k.starts_with("--"))
                .ok_or("--key needs the path of a signing key after it")?,
        ),
        None => {
            return Err(
                "no signing key: pass --key <signing key>; generate a pair with \
                 `oxicrypt-integrity-sign --keygen <dir>` and build with \
                 OXICRYPT_INTEGRITY_VERIFY_KEY naming its public half"
                    .to_owned(),
            );
        }
    };
    // Anything unrecognised is refused rather than ignored. `--target=<triple>`
    // is the shape that motivates this: silently dropping it builds for the host
    // and then signs whatever happens to be sitting at the host path, which is a
    // wrong artifact reported as a right one.
    if let Some(unknown) = args
        .iter()
        .skip(1)
        .find(|a| a.starts_with("--") && !matches!(a.as_str(), "--release" | "--target" | "--key"))
    {
        return Err(format!(
            "unrecognised argument {unknown}; --target and --key take their value as a \
             separate word"
        ));
    }

    let steps = if needs_codesign(target.as_deref(), host_is_macos) {
        APPLE_STEPS.to_vec()
    } else {
        vec![Step::Sign, Step::Verify]
    };
    Ok(Plan {
        package: package.clone(),
        release,
        target,
        key,
        steps,
    })
}

/// The steps for an Apple platform, in order.
const APPLE_STEPS: [Step; 7] = [
    Step::Codesign,
    Step::Reference,
    Step::Codesign,
    Step::SignReserved,
    Step::Codesign,
    Step::CodesignVerify,
    Step::Verify,
];

/// Whether `program` can be found on `PATH`.
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear build-sign-check sequence, each step beside its failure"
)]
fn sign(args: &[String]) -> Result<(), String> {
    let Plan {
        package,
        release,
        target,
        key,
        steps,
    } = plan(args, cfg!(target_os = "macos"))?;
    // Checked before building: an artifact built without the verifying key
    // cannot be signed, and the signer would only say so after a full build.
    if std::env::var_os("OXICRYPT_INTEGRITY_VERIFY_KEY").is_none() {
        return Err(
            "OXICRYPT_INTEGRITY_VERIFY_KEY is not set: the artifact must be built with the \
             public half of the signing key embedded. Set it to the integrity-verify.pub \
             that `oxicrypt-integrity-sign --keygen` wrote beside your signing key"
                .to_owned(),
        );
    }
    let package = package.as_str();

    // Checked before building: an artifact linked without its format's
    // settings is refused by the signer after a full build, or signs and
    // then fails to load. The settings are named rather than set here, so
    // what is built is exactly what the caller's environment says.
    let format = format_for(
        target.as_deref(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    let missing = missing_build_settings(format, target.as_deref(), release, &|name| {
        std::env::var(name).ok()
    });
    if !missing.is_empty() {
        return Err(format!(
            "this {} artifact would not be signable as built. Set, in the \
             environment (a .cargo/config.toml is not read):\n  {}",
            format.name(),
            missing.join("\n  ")
        ));
    }

    // Checked before anything is built or written, so a host without
    // `codesign` refuses outright instead of leaving an artifact whose slot is
    // written but whose code signature is stale.
    if steps.contains(&Step::Codesign) && !on_path("codesign") {
        return Err(
            "this artifact is for an Apple platform and needs `codesign` after the integrity \
             slot is written, but `codesign` is not on PATH. Build it on macOS."
                .to_owned(),
        );
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

    // On Apple silicon the operating system refuses a binary whose code
    // signature is stale, and writing the slot leaves any signature stale,
    // so the final code signature comes after the slot. The slot's image
    // ends where the code signature begins, and the load-command fields that
    // locate it are measured against a reference signed the same way, so the
    // final code signature disturbs nothing the integrity signature covers.
    let mut reference_name = subject.file_name().unwrap_or_default().to_os_string();
    reference_name.push(".reference");
    let reference = subject.with_file_name(reference_name);
    for step in &steps {
        match step {
            Step::Sign => run(
                "signing",
                Command::new(&signer)
                    .arg("--sign")
                    .arg("--key")
                    .arg(&key)
                    .arg(&subject),
            )?,
            Step::Reference => {
                std::fs::copy(&subject, &reference).map_err(|e| {
                    format!("could not keep the reference {}: {e}", reference.display())
                })?;
            }
            Step::SignReserved => {
                let outcome = run(
                    "signing",
                    Command::new(&signer)
                        .arg("--sign")
                        .arg("--key")
                        .arg(&key)
                        .arg("--reserved-against")
                        .arg(&reference)
                        .arg(&subject),
                );
                let _ = std::fs::remove_file(&reference);
                outcome?;
            }
            Step::Codesign => run(
                "ad-hoc code signing",
                Command::new("codesign")
                    .args(["--force", "--sign", "-"])
                    .arg(&subject),
            )?,
            Step::CodesignVerify => run(
                "checking the code signature",
                Command::new("codesign").arg("--verify").arg(&subject),
            )?,
            // The signer self-checks, and this checks it again from a separate
            // process against the file as it now sits on disk, after every step
            // that wrote to it. The two are not the same claim.
            Step::Verify => run(
                "verifying",
                Command::new(&signer).arg("--verify").arg(&subject),
            )?,
        }
    }

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

/// The executable format an artifact is linked as, which decides the build
/// settings the signer needs from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// ELF for glibc: signable as linked.
    Elf,
    /// ELF for bionic: linked for 16 KiB pages, or it does not load on a
    /// device that uses them.
    Android,
    /// Mach-O, with `arm64` set for the architecture on which LLVM merges
    /// globals unless told not to.
    MachO {
        /// Whether the target is arm64.
        arm64: bool,
    },
    /// PE32+.
    Pe,
}

impl Format {
    /// The format's name, as a message to the developer gives it.
    const fn name(self) -> &'static str {
        match self {
            Self::Elf => "ELF",
            Self::Android => "Android ELF",
            Self::MachO { arm64: true } => "arm64 Mach-O",
            Self::MachO { arm64: false } => "x86_64 Mach-O",
            Self::Pe => "PE",
        }
    }
}

/// The format `target` produces, or the host's format when no target is
/// named. `host_os` and `host_arch` take the values of
/// `std::env::consts::{OS, ARCH}`.
fn format_for(target: Option<&str>, host_os: &str, host_arch: &str) -> Format {
    match target {
        Some(t) if t.contains("-apple-") => Format::MachO {
            arm64: t.starts_with("aarch64") || t.starts_with("arm64"),
        },
        Some(t) if t.contains("-android") => Format::Android,
        Some(t) if t.contains("-windows") => Format::Pe,
        Some(_) => Format::Elf,
        None => match host_os {
            "macos" | "ios" => Format::MachO {
                arm64: host_arch == "aarch64",
            },
            "windows" => Format::Pe,
            "android" => Format::Android,
            _ => Format::Elf,
        },
    }
}

/// The `RUSTFLAGS` cargo will apply to the artifact, read from the same
/// variables cargo reads and in its order: `CARGO_ENCODED_RUSTFLAGS`, then
/// `RUSTFLAGS`, then `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` when a target is
/// named. Flags in a `.cargo/config.toml` are not read, so a setting made
/// only there is reported missing.
fn effective_rustflags(target: Option<&str>, env: &dyn Fn(&str) -> Option<String>) -> String {
    if let Some(encoded) = env("CARGO_ENCODED_RUSTFLAGS") {
        return encoded.replace('\u{1f}', " ");
    }
    if let Some(flags) = env("RUSTFLAGS") {
        return flags;
    }
    target
        .and_then(|t| {
            let upper: String = t
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            env(&format!("CARGO_TARGET_{upper}_RUSTFLAGS"))
        })
        .unwrap_or_default()
}

/// The build settings `format` needs that the environment does not provide,
/// each named with the value to set. Empty when the artifact will be
/// signable.
///
/// The settings are the ones the signer refuses an artifact without, or
/// without which a signed artifact does not load: for Mach-O chained fixups,
/// the zero-fill sections in a segment of their own, unmerged globals on
/// arm64 and a packed dSYM with full debug information; for PE the
/// zero-initialised data in a section of its own and full debug
/// information; for Android 16 KiB pages. `release` selects the profile
/// whose variables are read.
fn missing_build_settings(
    format: Format,
    target: Option<&str>,
    release: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<String> {
    let rustflags = effective_rustflags(target, env);
    let mut flags: Vec<(&str, &str)> = Vec::new();
    let mut need_full_debug = false;
    let mut need_packed = false;
    // The deployment target below which the linker does not emit chained
    // fixups for the architecture, and the signer refuses the image.
    let mut deployment_floor: Option<(u32, u32)> = None;
    match format {
        Format::Elf => {}
        Format::Android => {
            flags.push((
                "max-page-size=16384",
                "-C link-arg=-Wl,-z,max-page-size=16384",
            ));
        }
        Format::MachO { arm64 } => {
            if arm64 {
                flags.push((
                    "-aarch64-enable-global-merge=false",
                    "-C llvm-args=-aarch64-enable-global-merge=false",
                ));
            }
            flags.push(("-Wl,-fixup_chains", "-C link-arg=-Wl,-fixup_chains"));
            flags.push((
                "-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss",
                "-C link-arg=-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss",
            ));
            flags.push((
                "-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common",
                "-C link-arg=-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common",
            ));
            need_full_debug = true;
            need_packed = true;
            deployment_floor = Some(if arm64 { (12, 0) } else { (13, 0) });
        }
        Format::Pe => {
            flags.push(("/MERGE:.bss=.zbss", "-C link-arg=/MERGE:.bss=.zbss"));
            need_full_debug = true;
        }
    }

    let mut missing: Vec<String> = flags
        .iter()
        .filter(|(needle, _)| !rustflags.contains(needle))
        .map(|(_, flag)| format!("RUSTFLAGS: {flag}"))
        .collect();
    let profile = if release { "RELEASE" } else { "DEV" };
    if need_full_debug {
        let var = format!("CARGO_PROFILE_{profile}_DEBUG");
        // The dev profile's debug information is full unless overridden; the
        // release profile's is off.
        let ok = match env(&var) {
            Some(v) => matches!(v.as_str(), "full" | "2" | "true"),
            None => !release,
        };
        if !ok {
            missing.push(format!("{var}=full"));
        }
    }
    if need_packed {
        let var = format!("CARGO_PROFILE_{profile}_SPLIT_DEBUGINFO");
        if env(&var).as_deref() != Some("packed") {
            missing.push(format!("{var}=packed"));
        }
    }
    if let Some((major, minor)) = deployment_floor {
        let reached = env("MACOSX_DEPLOYMENT_TARGET")
            .as_deref()
            .and_then(parse_version)
            .is_some_and(|v| v >= (major, minor));
        if !reached {
            missing.push(format!("MACOSX_DEPLOYMENT_TARGET={major}.{minor} or later"));
        }
    }
    missing
}

/// A deployment target, `major`, `major.minor` or `major.minor.patch`, as
/// `(major, minor)`; `None` for anything else.
fn parse_version(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = match parts.next() {
        Some(m) => m.parse().ok()?,
        None => 0,
    };
    if let Some(patch) = parts.next() {
        patch.parse::<u32>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

/// Whether the artifact needs an Apple code signature after the integrity slot
/// is written: true for every Apple target (`*-apple-darwin`, `*-apple-ios`,
/// `*-apple-ios-sim`, `*-apple-tvos` and the rest), and for the host when the
/// host is macOS.
fn needs_codesign(target: Option<&str>, host_is_macos: bool) -> bool {
    match target {
        Some(t) => t.contains("-apple-"),
        None => host_is_macos,
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{Format, Step, format_for, missing_build_settings, needs_codesign, plan};
    use std::path::PathBuf;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    const APPLE_SEQUENCE: [Step; 7] = [
        Step::Codesign,
        Step::Reference,
        Step::Codesign,
        Step::SignReserved,
        Step::Codesign,
        Step::CodesignVerify,
        Step::Verify,
    ];

    #[test]
    fn a_parsed_apple_target_is_codesigned_twice_then_signed_then_codesigned() {
        // A non-macOS host, so the codesign step can only come from the
        // parsed `--target`, not from the host.
        let p = plan(
            &args(&[
                "oxicrypt-cli",
                "--key",
                "k",
                "--release",
                "--target",
                "aarch64-apple-darwin",
            ]),
            false,
        )
        .expect("plan");
        assert_eq!(p.package, "oxicrypt-cli");
        assert!(p.release);
        assert_eq!(p.target.as_deref(), Some("aarch64-apple-darwin"));
        assert_eq!(p.steps, APPLE_SEQUENCE);
    }

    #[test]
    fn a_host_build_on_macos_is_codesigned() {
        let p = plan(&args(&["oxicrypt-cli", "--key", "k"]), true).expect("plan");
        assert_eq!(p.target, None);
        assert_eq!(p.steps, APPLE_SEQUENCE);
    }

    #[test]
    fn a_host_build_elsewhere_has_no_codesign_step() {
        let p = plan(&args(&["oxicrypt-cli", "--key", "k", "--release"]), false).expect("plan");
        assert_eq!(p.steps, [Step::Sign, Step::Verify]);
    }

    #[test]
    fn a_non_apple_target_has_no_codesign_step_even_on_macos() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-linux-android",
        ] {
            let p = plan(
                &args(&["oxicrypt-cli", "--key", "k", "--target", target]),
                true,
            )
            .expect("plan");
            assert_eq!(p.steps, [Step::Sign, Step::Verify], "{target}");
        }
    }

    #[test]
    fn every_apple_target_is_codesigned_from_any_host() {
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "arm64e-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-ios-sim",
            "x86_64-apple-ios",
            "aarch64-apple-ios-macabi",
            "aarch64-apple-tvos",
            "aarch64-apple-watchos",
            "aarch64-apple-visionos",
        ] {
            for host_is_macos in [true, false] {
                assert!(needs_codesign(Some(target), host_is_macos), "{target}");
            }
        }
    }

    #[test]
    fn a_target_joined_with_equals_is_refused_rather_than_dropped() {
        let err = plan(
            &args(&[
                "oxicrypt-cli",
                "--key",
                "k",
                "--target=aarch64-apple-darwin",
            ]),
            false,
        )
        .expect_err("must refuse");
        assert!(err.contains("--target=aarch64-apple-darwin"), "{err}");
    }

    #[test]
    fn a_target_without_a_triple_is_refused() {
        assert!(plan(&args(&["oxicrypt-cli", "--key", "k", "--target"]), false).is_err());
        assert!(plan(&args(&["--release"]), false).is_err());
    }

    #[test]
    fn a_missing_signing_key_is_refused() {
        let err = plan(&args(&["oxicrypt-cli", "--release"]), false).expect_err("must refuse");
        assert!(err.contains("--key"), "{err}");
        assert!(plan(&args(&["oxicrypt-cli", "--key"]), false).is_err());
        assert!(plan(&args(&["oxicrypt-cli", "--key", "--release"]), false).is_err());
    }

    #[test]
    fn the_signing_key_is_passed_through() {
        let p = plan(&args(&["oxicrypt-cli", "--key", "/keys/k"]), false).expect("plan");
        assert_eq!(p.key, PathBuf::from("/keys/k"));
    }

    /// An environment holding exactly `vars`.
    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    const MACHO_FLAGS: &str = "-C llvm-args=-aarch64-enable-global-merge=false \
        -C link-arg=-Wl,-fixup_chains \
        -C link-arg=-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss \
        -C link-arg=-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common";

    #[test]
    fn each_target_maps_to_its_format() {
        for (target, want) in [
            ("aarch64-apple-darwin", Format::MachO { arm64: true }),
            ("arm64e-apple-darwin", Format::MachO { arm64: true }),
            ("x86_64-apple-darwin", Format::MachO { arm64: false }),
            ("x86_64-pc-windows-msvc", Format::Pe),
            ("aarch64-pc-windows-msvc", Format::Pe),
            ("aarch64-linux-android", Format::Android),
            ("x86_64-linux-android", Format::Android),
            ("x86_64-unknown-linux-gnu", Format::Elf),
            ("aarch64-unknown-linux-gnu", Format::Elf),
        ] {
            assert_eq!(
                format_for(Some(target), "linux", "x86_64"),
                want,
                "{target}"
            );
        }
        assert_eq!(
            format_for(None, "macos", "aarch64"),
            Format::MachO { arm64: true }
        );
        assert_eq!(
            format_for(None, "macos", "x86_64"),
            Format::MachO { arm64: false }
        );
        assert_eq!(format_for(None, "windows", "x86_64"), Format::Pe);
        assert_eq!(format_for(None, "linux", "aarch64"), Format::Elf);
    }

    #[test]
    fn a_complete_macho_environment_is_accepted() {
        let env = env_of(&[
            ("RUSTFLAGS", MACHO_FLAGS),
            ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
            ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
            ("MACOSX_DEPLOYMENT_TARGET", "13.0"),
        ]);
        let missing = missing_build_settings(Format::MachO { arm64: true }, None, true, &env);
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn each_missing_macho_setting_is_named() {
        // CONTROL for the test above: every required setting, removed alone,
        // is reported by name, so an empty list there means present, not
        // unchecked.
        let needles = [
            "-aarch64-enable-global-merge=false",
            "-Wl,-fixup_chains",
            "-Wl,-rename_section,__DATA,__bss,__ZEROFILL,__bss",
            "-Wl,-rename_section,__DATA,__common,__ZEROFILL,__common",
        ];
        for needle in needles {
            let flags: Vec<&str> = MACHO_FLAGS
                .split(" -C ")
                .filter(|f| !f.contains(needle))
                .collect();
            let flags = flags.join(" -C ");
            assert!(!flags.contains(needle), "{needle} not removed");
            let env = env_of(&[
                ("RUSTFLAGS", &flags),
                ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
                ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
                ("MACOSX_DEPLOYMENT_TARGET", "13.0"),
            ]);
            let missing = missing_build_settings(Format::MachO { arm64: true }, None, true, &env);
            assert_eq!(missing.len(), 1, "{needle}: {missing:?}");
            assert!(missing[0].contains(needle), "{needle}: {missing:?}");
        }
        for (var, value) in [
            ("CARGO_PROFILE_RELEASE_DEBUG", "limited"),
            ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "unpacked"),
            ("MACOSX_DEPLOYMENT_TARGET", "11.0"),
        ] {
            let mut vars = vec![
                ("RUSTFLAGS", MACHO_FLAGS),
                ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
                ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
                ("MACOSX_DEPLOYMENT_TARGET", "13.0"),
            ];
            vars.retain(|(k, _)| *k != var);
            let absent =
                missing_build_settings(Format::MachO { arm64: true }, None, true, &env_of(&vars));
            assert_eq!(absent.len(), 1, "{var} unset: {absent:?}");
            assert!(absent[0].contains(var), "{var} unset: {absent:?}");
            vars.push((var, value));
            let wrong =
                missing_build_settings(Format::MachO { arm64: true }, None, true, &env_of(&vars));
            assert_eq!(wrong.len(), 1, "{var}={value}: {wrong:?}");
            assert!(wrong[0].contains(var), "{var}={value}: {wrong:?}");
        }
    }

    #[test]
    fn the_deployment_target_must_reach_the_chained_fixups_floor() {
        // 12.0 on arm64 and 13.0 on x86_64; the version is compared
        // numerically, so 12.10 is above 12.9.
        for (arm64, target, ok) in [
            (true, "12.0", true),
            (true, "12", true),
            (true, "14.5", true),
            (true, "11.7", false),
            (true, "11", false),
            (false, "13.0", true),
            (false, "13.10", true),
            (false, "12.9", false),
            (false, "12.10", false),
            (true, "", false),
            (true, "twelve", false),
            (true, "12.x", false),
        ] {
            let env = env_of(&[
                ("RUSTFLAGS", MACHO_FLAGS),
                ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
                ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
                ("MACOSX_DEPLOYMENT_TARGET", target),
            ]);
            let missing = missing_build_settings(Format::MachO { arm64 }, None, true, &env);
            if ok {
                assert!(missing.is_empty(), "arm64={arm64} {target}: {missing:?}");
            } else {
                assert_eq!(missing.len(), 1, "arm64={arm64} {target}: {missing:?}");
                assert!(
                    missing[0].contains("MACOSX_DEPLOYMENT_TARGET"),
                    "arm64={arm64} {target}: {missing:?}"
                );
            }
        }
        // Unset is refused too.
        let env = env_of(&[
            ("RUSTFLAGS", MACHO_FLAGS),
            ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
            ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
        ]);
        let missing = missing_build_settings(Format::MachO { arm64: true }, None, true, &env);
        assert_eq!(missing, ["MACOSX_DEPLOYMENT_TARGET=12.0 or later"]);
    }

    #[test]
    fn global_merge_is_required_on_arm64_only() {
        let flags = MACHO_FLAGS.replace("-C llvm-args=-aarch64-enable-global-merge=false ", "");
        assert!(!flags.contains("global-merge"));
        let env = env_of(&[
            ("RUSTFLAGS", &flags),
            ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
            ("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "packed"),
            ("MACOSX_DEPLOYMENT_TARGET", "13.0"),
        ]);
        assert!(
            missing_build_settings(Format::MachO { arm64: false }, None, true, &env).is_empty()
        );
        assert_eq!(
            missing_build_settings(Format::MachO { arm64: true }, None, true, &env).len(),
            1
        );
    }

    #[test]
    fn the_pe_settings_are_required_and_named() {
        let complete = env_of(&[
            ("RUSTFLAGS", "-C link-arg=/MERGE:.bss=.zbss"),
            ("CARGO_PROFILE_RELEASE_DEBUG", "full"),
        ]);
        assert!(missing_build_settings(Format::Pe, None, true, &complete).is_empty());
        let no_merge = env_of(&[("CARGO_PROFILE_RELEASE_DEBUG", "full")]);
        let m = missing_build_settings(Format::Pe, None, true, &no_merge);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("/MERGE:.bss=.zbss"), "{m:?}");
        let no_debug = env_of(&[("RUSTFLAGS", "-C link-arg=/MERGE:.bss=.zbss")]);
        let m = missing_build_settings(Format::Pe, None, true, &no_debug);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("CARGO_PROFILE_RELEASE_DEBUG"), "{m:?}");
    }

    #[test]
    fn the_dev_profile_reads_its_own_variables_and_defaults_to_full_debug() {
        // The dev profile's debug information is full unless overridden, so
        // an unset CARGO_PROFILE_DEV_DEBUG passes, and a release variable
        // says nothing about a dev build.
        let env = env_of(&[
            ("RUSTFLAGS", "-C link-arg=/MERGE:.bss=.zbss"),
            ("CARGO_PROFILE_RELEASE_DEBUG", "none"),
        ]);
        assert!(missing_build_settings(Format::Pe, None, false, &env).is_empty());
        let env = env_of(&[
            ("RUSTFLAGS", "-C link-arg=/MERGE:.bss=.zbss"),
            ("CARGO_PROFILE_DEV_DEBUG", "line-tables-only"),
        ]);
        let m = missing_build_settings(Format::Pe, None, false, &env);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("CARGO_PROFILE_DEV_DEBUG"), "{m:?}");
    }

    #[test]
    fn the_android_page_size_is_required() {
        let env = env_of(&[("RUSTFLAGS", "-C link-arg=-Wl,-z,max-page-size=16384")]);
        assert!(missing_build_settings(Format::Android, None, true, &env).is_empty());
        let m = missing_build_settings(Format::Android, None, true, &env_of(&[]));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("max-page-size=16384"), "{m:?}");
    }

    #[test]
    fn a_glibc_elf_needs_nothing() {
        assert!(missing_build_settings(Format::Elf, None, true, &env_of(&[])).is_empty());
    }

    #[test]
    fn rustflags_are_read_in_cargos_order() {
        // CARGO_ENCODED_RUSTFLAGS outranks RUSTFLAGS, which outranks the
        // per-target variable; a lower source is not read when a higher one
        // is set, because cargo does not read it either.
        let pe = "-C link-arg=/MERGE:.bss=.zbss";
        let target = Some("x86_64-pc-windows-msvc");
        let debug = ("CARGO_PROFILE_RELEASE_DEBUG", "full");
        let encoded = pe.replace(' ', "\u{1f}");
        let by_encoded = env_of(&[("CARGO_ENCODED_RUSTFLAGS", &encoded), debug]);
        assert!(missing_build_settings(Format::Pe, target, true, &by_encoded).is_empty());
        let shadowed = env_of(&[("CARGO_ENCODED_RUSTFLAGS", ""), ("RUSTFLAGS", pe), debug]);
        assert_eq!(
            missing_build_settings(Format::Pe, target, true, &shadowed).len(),
            1
        );
        let by_target = env_of(&[("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS", pe), debug]);
        assert!(missing_build_settings(Format::Pe, target, true, &by_target).is_empty());
        let target_shadowed = env_of(&[
            ("RUSTFLAGS", "-C opt-level=3"),
            ("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS", pe),
            debug,
        ]);
        assert_eq!(
            missing_build_settings(Format::Pe, target, true, &target_shadowed).len(),
            1
        );
        // Without --target there is no per-target variable to read.
        assert_eq!(
            missing_build_settings(Format::Pe, None, true, &by_target).len(),
            1
        );
    }
}
