//! The post-quantum command families: `oxi ml-dsa` (FIPS 204) and
//! `oxi ml-kem` (FIPS 203).
//!
//! | Item | Role |
//! |------|------|
//! | [`cmd_ml_dsa`] | `keygen`, `sign` and `verify` for ML-DSA-44, -65 and -87 |
//! | [`cmd_ml_kem`] | `keygen`, `encaps` and `decaps` for ML-KEM-512, -768 and -1024 |
//! | [`parse`] | the hand-written flag grammar every verb shares |
//! | [`verdict`] | the mapping from a module error to the exit code and stderr line |
//! | [`write_output`] | creates every output file, by temporary, then hard link or rename |

use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use oxicrypt_module::{Error, RbgError};
use oxicrypt_zeroize::Zeroizing;

use super::module_drbg;

/// The ML-DSA grammar, one line per verb.
pub(crate) const ML_DSA_GRAMMAR: [&str; 3] = [
    "oxi ml-dsa keygen <44|65|87>     --pk FILE --sk FILE [--seed HEX | --seed-out FILE]",
    "oxi ml-dsa sign   <44|65|87>     --sk FILE --sig FILE [--ctx HEX] [--] [MESSAGE]",
    "oxi ml-dsa verify <44|65|87>     --pk FILE --sig FILE [--ctx HEX] [--] [MESSAGE]",
];

/// The ML-KEM grammar, one line per verb.
pub(crate) const ML_KEM_GRAMMAR: [&str; 3] = [
    "oxi ml-kem keygen <512|768|1024> --ek FILE --dk FILE [--d HEX --z HEX | --seed-out FILE]",
    "oxi ml-kem encaps <512|768|1024> --ek FILE --ct FILE [--ss FILE]",
    "oxi ml-kem decaps <512|768|1024> --dk FILE --ct FILE [--ss FILE]",
];

/// The line printed on stderr when a well-formed seed is supplied on the
/// command line, before the output files are checked.
pub(crate) const SEED_WARNING: &str =
    "seed supplied: protect this seed as you would the secret key";

/// FIPS 204 §5.2: the context string is at most 255 bytes.
const MAX_CTX_LEN: usize = 255;

const USAGE: u8 = 2;
const FAILURE: u8 = 1;
const SIGNATURE_NOT_VALID: u8 = 5;

/// A command's failure: its exit code and what it prints on stderr.
struct Exit {
    code: u8,
    line: String,
}

impl Exit {
    fn usage(line: impl Into<String>) -> Self {
        Self {
            code: USAGE,
            line: line.into(),
        }
    }

    fn failure(line: impl Into<String>) -> Self {
        Self {
            code: FAILURE,
            line: line.into(),
        }
    }
}

/// The family and verb a command runs as, which prefix its stderr lines.
#[derive(Clone, Copy)]
struct Cmd {
    family: &'static str,
    verb: &'static str,
}

impl Cmd {
    fn usage(self, what: &str) -> Exit {
        Exit::usage(format!("oxi {} {}: {what}", self.family, self.verb))
    }

    fn failure(self, what: &str) -> Exit {
        Exit::failure(format!("oxi {} {}: {what}", self.family, self.verb))
    }
}

fn finish(result: Result<(), Exit>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(exit) => {
            eprintln!("{}", exit.line);
            ExitCode::from(exit.code)
        }
    }
}

fn family_usage(family: &str, grammar: &[&str; 3]) -> Exit {
    let mut line = format!("oxi {family}: usage:");
    for g in grammar {
        line.push_str("\n  ");
        line.push_str(g);
    }
    Exit::usage(line)
}

/// `oxi ml-dsa <verb> <set> ...`, with `args` the arguments after `ml-dsa`.
pub(crate) fn cmd_ml_dsa(args: &[String]) -> ExitCode {
    let usage = || family_usage("ml-dsa", &ML_DSA_GRAMMAR);
    let (Some(verb), Some(set)) = (args.first(), args.get(1)) else {
        return finish(Err(usage()));
    };
    if !matches!(set.as_str(), "44" | "65" | "87") {
        return finish(Err(usage()));
    }
    let rest = args.get(2..).unwrap_or(&[]);
    let cmd = |verb| Cmd {
        family: "ml-dsa",
        verb,
    };
    finish(match verb.as_str() {
        "keygen" => dsa_keygen(cmd("keygen"), set, rest),
        "sign" => dsa_sign(cmd("sign"), set, rest),
        "verify" => dsa_verify(cmd("verify"), set, rest),
        _ => Err(usage()),
    })
}

/// `oxi ml-kem <verb> <set> ...`, with `args` the arguments after `ml-kem`.
pub(crate) fn cmd_ml_kem(args: &[String]) -> ExitCode {
    let usage = || family_usage("ml-kem", &ML_KEM_GRAMMAR);
    let (Some(verb), Some(set)) = (args.first(), args.get(1)) else {
        return finish(Err(usage()));
    };
    if !matches!(set.as_str(), "512" | "768" | "1024") {
        return finish(Err(usage()));
    }
    let rest = args.get(2..).unwrap_or(&[]);
    let cmd = |verb| Cmd {
        family: "ml-kem",
        verb,
    };
    finish(match verb.as_str() {
        "keygen" => kem_keygen(cmd("keygen"), set, rest),
        "encaps" => kem_encaps(cmd("encaps"), set, rest),
        "decaps" => kem_decaps(cmd("decaps"), set, rest),
        _ => Err(usage()),
    })
}

/// Runs `$body` with `$m` naming the ML-DSA parameter-set module for `$set`.
macro_rules! per_dsa_set {
    ($set:expr, $m:ident, $body:block) => {
        match $set {
            "44" => {
                use oxicrypt_ml_dsa::ml_dsa_44 as $m;
                $body
            }
            "65" => {
                use oxicrypt_ml_dsa::ml_dsa_65 as $m;
                $body
            }
            "87" => {
                use oxicrypt_ml_dsa::ml_dsa_87 as $m;
                $body
            }
            _ => Err(family_usage("ml-dsa", &ML_DSA_GRAMMAR)),
        }
    };
}

/// Runs `$body` with `$m` naming the ML-KEM parameter-set module for `$set`.
macro_rules! per_kem_set {
    ($set:expr, $m:ident, $body:block) => {
        match $set {
            "512" => {
                use oxicrypt_ml_kem::ml_kem_512 as $m;
                $body
            }
            "768" => {
                use oxicrypt_ml_kem::ml_kem_768 as $m;
                $body
            }
            "1024" => {
                use oxicrypt_ml_kem::ml_kem_1024 as $m;
                $body
            }
            _ => Err(family_usage("ml-kem", &ML_KEM_GRAMMAR)),
        }
    };
}

/// The flags and the optional `MESSAGE` operand of one invocation, borrowed
/// from the command line.
struct Args<'a> {
    flags: Vec<(&'static str, &'a str)>,
    message: Option<&'a str>,
}

impl<'a> Args<'a> {
    fn get(&self, name: &str) -> Option<&'a str> {
        self.flags
            .iter()
            .find(|(n, _)| *n == name)
            .map(|&(_, value)| value)
    }

    fn required(&self, cmd: Cmd, name: &str) -> Result<&'a str, Exit> {
        self.get(name)
            .ok_or_else(|| cmd.usage(&format!("missing required flag {name}")))
    }
}

/// Parses `[--flag value]... [--] [MESSAGE]`.
///
/// Every flag takes one value and may appear once; `known` lists the flags
/// the verb accepts. `--` ends flag parsing. An argument after a flag that
/// itself begins with `--` is not taken as its value, so a flag followed by
/// another flag is reported as valueless. At most one operand is accepted,
/// and only when `takes_message`.
fn parse<'a>(
    cmd: Cmd,
    rest: &'a [String],
    known: &[&'static str],
    takes_message: bool,
) -> Result<Args<'a>, Exit> {
    let mut flags: Vec<(&'static str, &'a str)> = Vec::new();
    let mut operands: Vec<&'a str> = Vec::new();
    let mut ended = false;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if !ended && arg == "--" {
            ended = true;
        } else if !ended && arg.starts_with("--") {
            let Some(&name) = known.iter().find(|k| **k == arg.as_str()) else {
                return Err(cmd.usage(&format!("unknown flag {arg}")));
            };
            if flags.iter().any(|(n, _)| *n == name) {
                return Err(cmd.usage(&format!("{name} given more than once")));
            }
            match it.next() {
                Some(value) if !value.starts_with("--") => flags.push((name, value.as_str())),
                _ => return Err(cmd.usage(&format!("{name} needs a value"))),
            }
        } else {
            operands.push(arg.as_str());
        }
    }
    match (takes_message, operands.as_slice()) {
        (_, []) => Ok(Args {
            flags,
            message: None,
        }),
        (true, [message]) => Ok(Args {
            flags,
            message: Some(message),
        }),
        (true, _) => Err(cmd.usage("more than one MESSAGE given")),
        (false, [first, ..]) => Err(cmd.usage(&format!("unexpected argument {first}"))),
    }
}

/// Decodes a hex flag value of exactly `N` bytes into zeroizing storage.
fn decode_exact<const N: usize>(
    cmd: Cmd,
    flag: &str,
    hex: &str,
) -> Result<Zeroizing<[u8; N]>, Exit> {
    let expected = || {
        format!(
            "{flag} must be {N} bytes as {} hex characters",
            N.saturating_mul(2)
        )
    };
    let (pairs, odd) = hex.as_bytes().as_chunks::<2>();
    if !odd.is_empty() || pairs.len() != N {
        return Err(cmd.usage(&format!(
            "{}, got {} characters",
            expected(),
            hex.chars().count()
        )));
    }
    let mut out = Zeroizing::new([0u8; N]);
    for (slot, pair) in out.iter_mut().zip(pairs) {
        *slot = hex_byte(*pair).ok_or_else(|| {
            cmd.usage(&format!(
                "{}, and it holds a character that is not hex",
                expected()
            ))
        })?;
    }
    Ok(out)
}

/// Decodes `--ctx`, checking the FIPS 204 §5.2 limit before any module call.
fn decode_ctx(cmd: Cmd, hex: Option<&str>) -> Result<Vec<u8>, Exit> {
    let Some(hex) = hex else {
        return Ok(Vec::new());
    };
    let (pairs, odd) = hex.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return Err(cmd.usage("--ctx must be hex digits in pairs, 0 to 255 bytes"));
    }
    if pairs.len() > MAX_CTX_LEN {
        return Err(cmd.usage(&format!(
            "--ctx is {} bytes; FIPS 204 §5.2 limits the context to {MAX_CTX_LEN} bytes",
            pairs.len()
        )));
    }
    pairs
        .iter()
        .map(|pair| hex_byte(*pair))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| cmd.usage("--ctx holds a character that is not hex"))
}

/// One byte from two ASCII hex digits. The digits are checked first because
/// `u8::from_str_radix` accepts a leading `+`.
fn hex_byte(pair: [u8; 2]) -> Option<u8> {
    if !pair.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::str::from_utf8(&pair)
        .ok()
        .and_then(|s| u8::from_str_radix(s, 16).ok())
}

/// Reads the file at `path` straight into zeroizing storage and checks that
/// it is exactly `N` bytes, reading at most `N + 1`.
fn read_exact<const N: usize>(cmd: Cmd, path: &str) -> Result<Zeroizing<[u8; N]>, Exit> {
    let os_error = |e: io::Error| cmd.usage(&format!("{path}: {e}"));
    let mut file = std::fs::File::open(path).map_err(os_error)?;
    let mut out = Zeroizing::new([0u8; N]);
    let mut filled = 0usize;
    while let Some(rest) = out.get_mut(filled..).filter(|r| !r.is_empty()) {
        match file.read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(os_error(e)),
        }
    }
    let wrong_length = |got: &str| cmd.usage(&format!("{path}: expected {N} bytes, got {got}"));
    if filled < N {
        return Err(wrong_length(&filled.to_string()));
    }
    let mut probe = Zeroizing::new([0u8; 1]);
    loop {
        match file.read(&mut *probe) {
            Ok(0) => return Ok(out),
            Ok(_) => {
                return Err(match file.metadata() {
                    Ok(m) if m.is_file() => wrong_length(&m.len().to_string()),
                    _ => wrong_length(&format!("more than {N}")),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(os_error(e)),
        }
    }
}

/// Reads `MESSAGE` whole: the named file, or stdin when it is absent or `-`.
fn read_message(cmd: Cmd, path: Option<&str>) -> Result<Vec<u8>, Exit> {
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| cmd.usage(&format!("stdin: {e}")))?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p).map_err(|e| cmd.usage(&format!("{p}: {e}"))),
    }
}

/// Refuses, before anything is written: an output path that exists; an
/// output whose temporary `<path>.oxi-partial` exists; an output path that
/// cannot be checked, for any reason other than its absence; two output
/// flags that name the same file; and an output that names another output's
/// temporary.
fn check_outputs(cmd: Cmd, outputs: &[(&str, &str)]) -> Result<(), Exit> {
    let absent = |path: &str| match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(cmd.usage(&format!("{path}: {e}"))),
    };
    for (i, &(flag, path)) in outputs.iter().enumerate() {
        if !absent(path)? {
            return Err(will_not_overwrite(path));
        }
        let temp = partial_path(path);
        if !absent(&temp)? {
            return Err(cmd.usage(&format!(
                "{temp} exists (an interrupted or still-running oxi); delete it once none is \
                 running, or name another output"
            )));
        }
        if let Some(&(other, _)) = outputs
            .get(..i)
            .unwrap_or(&[])
            .iter()
            .find(|&&(_, p)| same_file(p, path))
        {
            return Err(cmd.usage(&format!("{other} and {flag} name the same file {path}")));
        }
        if let Some(&(other, _)) = outputs
            .iter()
            .find(|&&(f, p)| f != flag && same_file(&partial_path(p), path))
        {
            return Err(cmd.usage(&format!(
                "{flag} names {path}, the temporary {other} is written to"
            )));
        }
    }
    Ok(())
}

fn will_not_overwrite(path: &str) -> Exit {
    Exit::usage(format!("oxi will not overwrite {path}: it already exists"))
}

/// Whether two output paths, neither of which exists yet, name the same
/// file: the same text, or the same file name in the same directory.
fn same_file(a: &str, b: &str) -> bool {
    fn key(p: &str) -> Option<(std::path::PathBuf, std::ffi::OsString)> {
        let p = Path::new(p);
        let parent = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Some((
            std::fs::canonicalize(parent).ok()?,
            p.file_name()?.to_owned(),
        ))
    }
    a == b || matches!((key(a), key(b)), (Some(x), Some(y)) if x == y)
}

/// The temporary an output is written to before it is moved into place.
fn partial_path(path: &str) -> String {
    format!("{path}.oxi-partial")
}

/// What writes an output's bytes into its open temporary.
type Sink<'s> = &'s mut dyn FnMut(&mut std::fs::File, &[u8]) -> io::Result<()>;

/// The filesystem calls an install makes by name.
#[derive(Clone, Copy)]
struct Ops {
    link: fn(&Path, &Path) -> io::Result<()>,
    unlink: fn(&Path) -> io::Result<()>,
}

fn os_link(temp: &Path, target: &Path) -> io::Result<()> {
    std::fs::hard_link(temp, target)
}

fn os_unlink(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
}

const OS: Ops = Ops {
    link: os_link,
    unlink: os_unlink,
};

/// Installs `bytes` at `path` without replacing a file there.
///
/// The bytes go to `<path>.oxi-partial`, created exclusively (mode `0o600`
/// on Unix when `secret`) and synced, and [`place`] moves it to `path`; the
/// directory is then synced on Unix. A process killed before that leaves no
/// file at `path`, only the temporary.
///
/// On success, returns the lines to print on stderr: one naming the
/// temporary when it could not be unlinked after the link (the output is in
/// place and the run succeeds; the leftover is a second name for the same
/// file), and one when the directory could not be synced.
///
/// Every failure is exit code 1 naming the path and the error, including a
/// `path` that appeared after [`check_outputs`], except a `path` whose
/// existence could not be checked, which is exit code 2. On failure the
/// temporary is zero-filled through the open handle when `secret` and it has
/// one link, then unlinked; a failure of either is added to the report.
fn write_output(path: &str, bytes: &[u8], secret: bool) -> Result<Vec<String>, Exit> {
    write_output_via(path, bytes, secret, &mut write_payload, OS)
}

/// [`write_output`] with the bytes written by `sink` and the names moved by
/// `ops`.
fn write_output_via(
    path: &str,
    bytes: &[u8],
    secret: bool,
    sink: Sink<'_>,
    ops: Ops,
) -> Result<Vec<String>, Exit> {
    let temp = partial_path(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|e| Exit::failure(format!("oxi: {temp}: {e}")))?;
    if let Err(e) = sink(&mut file, bytes).and_then(|()| file.sync_all()) {
        return Err(discard(
            Exit::failure(format!("oxi: {temp}: {e}")),
            file,
            &temp,
            secret,
            ops,
        ));
    }
    #[cfg(feature = "fault-injection")]
    pause_before_install(path);
    let placed = match place(Path::new(&temp), Path::new(path), ops.link) {
        Err(PlaceError::Exists) if is_installed(&file, path) => Placed::Linked,
        Ok(placed) => placed,
        Err(PlaceError::Exists) => {
            return Err(discard(
                Exit::failure(format!("oxi will not overwrite {path}: it already exists")),
                file,
                &temp,
                secret,
                ops,
            ));
        }
        Err(PlaceError::Unchecked(e)) => {
            return Err(discard(
                Exit::usage(format!("oxi: {path}: {e}")),
                file,
                &temp,
                secret,
                ops,
            ));
        }
        Err(PlaceError::Other(e)) => {
            return Err(discard(
                Exit::failure(format!("oxi: {path}: {e}")),
                file,
                &temp,
                secret,
                ops,
            ));
        }
    };
    drop(file);
    let mut notes = Vec::new();
    if matches!(placed, Placed::Linked)
        && let Err(e) = (ops.unlink)(Path::new(&temp))
    {
        notes.push(format!(
            "oxi: written: {path}; left behind: {temp}; delete it ({e})"
        ));
    }
    notes.extend(sync_parent(path));
    Ok(notes)
}

/// How [`place`] moved the temporary into place.
enum Placed {
    /// Hard-linked: the temporary still exists and is unlinked next.
    Linked,
    /// Renamed, on a filesystem that refused the hard link.
    Renamed,
}

/// Why [`place`] did not move the temporary.
enum PlaceError {
    /// A file exists at the target.
    Exists,
    /// The target's existence could not be checked.
    Unchecked(io::Error),
    /// Any other failure of the link or the rename.
    Other(io::Error),
}

/// Moves the temporary to `target` with `link`, which fails if `target`
/// exists, so the move never replaces a file.
///
/// When `link` fails with an operating-system error in `NO_HARD_LINKS` (the
/// codes a filesystem that refuses hard links reports; the list is matched,
/// not diagnosed), `target` is checked again: absent,
/// the temporary is renamed to it, which replaces a file created between
/// that check and the rename, so there the guarantee is best effort; present,
/// the result is [`PlaceError::Exists`]; any other error checking it is
/// [`PlaceError::Unchecked`]. Any other `link` error is returned as it is.
fn place(
    temp: &Path,
    target: &Path,
    link: fn(&Path, &Path) -> io::Result<()>,
) -> Result<Placed, PlaceError> {
    match link(temp, target) {
        Ok(()) => Ok(Placed::Linked),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(PlaceError::Exists),
        Err(e) if refuses_hard_links(&e) => match std::fs::symlink_metadata(target) {
            Ok(_) => Err(PlaceError::Exists),
            Err(s) if s.kind() == io::ErrorKind::NotFound => std::fs::rename(temp, target)
                .map(|()| Placed::Renamed)
                .map_err(PlaceError::Other),
            Err(s) => Err(PlaceError::Unchecked(s)),
        },
        Err(e) => Err(PlaceError::Other(e)),
    }
}

/// The operating-system error codes taken to mean that the filesystem does
/// not support hard links. On Unix, `link(2)`'s `EPERM`, `EOPNOTSUPP`,
/// `ENOTSUP` where it differs from `EOPNOTSUPP`, and `ENOSYS`, as each
/// platform's `<errno.h>` numbers them; on a Unix platform not named below,
/// `EPERM` only. On Windows, `ERROR_INVALID_FUNCTION` (the code FAT32 and
/// exFAT give a hard-link request) and `ERROR_NOT_SUPPORTED`, as
/// `<winerror.h>` numbers them; `CreateHardLinkW`'s reference names no code
/// for this case, so the list is observed, not documented. A refusal with any
/// other code is reported as the error it is.
#[cfg(any(target_os = "linux", target_os = "android"))]
const NO_HARD_LINKS: &[i32] = &[1, 95, 38];
#[cfg(target_vendor = "apple")]
const NO_HARD_LINKS: &[i32] = &[1, 102, 45, 78];
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const NO_HARD_LINKS: &[i32] = &[1, 45, 78];
#[cfg(target_os = "netbsd")]
const NO_HARD_LINKS: &[i32] = &[1, 45, 86, 78];
#[cfg(target_os = "openbsd")]
const NO_HARD_LINKS: &[i32] = &[1, 45, 91, 78];
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
const NO_HARD_LINKS: &[i32] = &[1];
#[cfg(windows)]
const NO_HARD_LINKS: &[i32] = &[1, 50];

fn refuses_hard_links(e: &io::Error) -> bool {
    e.raw_os_error()
        .is_some_and(|code| NO_HARD_LINKS.contains(&code))
}

/// Whether a `link` that reported `EEXIST` had in fact made `path` a second
/// name for the open temporary, as a retransmitted request over NFS can.
#[cfg(unix)]
fn is_installed(file: &std::fs::File, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(temp), Ok(target)) => {
            temp.nlink() == 2 && temp.dev() == target.dev() && temp.ino() == target.ino()
        }
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_installed(_: &std::fs::File, _: &str) -> bool {
    false
}

/// Syncs the directory that holds `path`, so its new entry is durable; on
/// failure, the stderr line to report.
#[cfg(unix)]
fn sync_parent(path: &str) -> Option<String> {
    let dir = Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .err()
        .map(|e| {
            format!(
                "oxi: written: {path}; its directory {} could not be synced ({e})",
                dir.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_parent(_: &str) -> Option<String> {
    None
}

/// `exit`, after the temporary is zero-filled through `file` when `secret`
/// and unlinked, with any failure of either appended.
fn discard(mut exit: Exit, mut file: std::fs::File, temp: &str, secret: bool, ops: Ops) -> Exit {
    if secret && let Err(e) = zero_fill(&mut file) {
        let _ = write!(exit.line, "\noxi: {temp} could not be zero-filled: {e}");
    }
    drop(file);
    if let Err(e) = (ops.unlink)(Path::new(temp)) {
        let _ = write!(exit.line, "\noxi: {temp} could not be removed: {e}");
    }
    exit
}

/// Overwrites the whole of `file` with zeros and syncs it. Refused on Unix
/// when the file has another name, which may be an installed output.
fn zero_fill(file: &mut std::fs::File) -> io::Result<()> {
    use std::io::Seek as _;
    let meta = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.nlink() != 1 {
            return Err(io::Error::other(format!(
                "it has {} links, so another name may hold it",
                meta.nlink()
            )));
        }
    }
    file.seek(io::SeekFrom::Start(0))?;
    io::copy(&mut io::repeat(0).take(meta.len()), file)?;
    file.sync_all()
}

/// Writes all of `bytes`. Under the `fault-injection` feature with
/// `OXI_FAULT=slow-write`, 64 bytes at a time with a 50 ms pause after each.
fn write_payload(file: &mut std::fs::File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(feature = "fault-injection")]
    if oxicrypt_drbg::seam::slow_write_armed() {
        for chunk in bytes.chunks(64) {
            file.write_all(chunk)?;
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        return Ok(());
    }
    file.write_all(bytes)
}

/// The output whose install pauses, from `OXI_FAULT=install-pause=<path>`.
#[cfg(feature = "fault-injection")]
static INSTALL_PAUSE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Takes the `install-pause=<path>` entries out of an `OXI_FAULT` value and
/// returns the remaining entries, for `oxicrypt_drbg::seam::arm_from_env`.
/// The first such entry is the one that applies.
#[cfg(feature = "fault-injection")]
pub(crate) fn take_install_pause(value: Option<&str>) -> Option<String> {
    let mut rest = Vec::new();
    for entry in value?.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Some(path) = entry.strip_prefix("install-pause=") {
            INSTALL_PAUSE.get_or_init(|| path.to_owned());
        } else {
            rest.push(entry);
        }
    }
    Some(rest.join(","))
}

/// Under the `fault-injection` feature, when `OXI_FAULT=install-pause=<path>`
/// names `path`: creates `<path>.oxi-pause` once the temporary is written,
/// and waits up to 20 s for it to be removed before installing, so a test
/// can create `path` between the existence check and the install.
#[cfg(feature = "fault-injection")]
fn pause_before_install(path: &str) {
    if INSTALL_PAUSE.get().map(String::as_str) != Some(path) {
        return;
    }
    let marker = format!("{path}.oxi-pause");
    if let Err(e) = std::fs::write(&marker, b"") {
        eprintln!("oxi: {marker}: {e}");
        return;
    }
    for _ in 0..2000 {
        if std::fs::symlink_metadata(&marker).is_err() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Writes each output in the order given, printing any notes
/// [`write_output`] returns, and on a failure names what was and was not
/// written. A failure after an output is in place is exit code 1.
fn install(cmd: Cmd, outputs: &[(&str, &[u8], bool)]) -> Result<(), Exit> {
    for (i, &(path, bytes, secret)) in outputs.iter().enumerate() {
        match write_output(path, bytes, secret) {
            Ok(notes) => {
                for note in notes {
                    eprintln!("{note}");
                }
            }
            Err(mut exit) => {
                let (done, left) = outputs.split_at(i);
                if !done.is_empty() {
                    exit.code = FAILURE;
                    let names = |list: &[(&str, &[u8], bool)]| {
                        list.iter().map(|o| o.0).collect::<Vec<_>>().join(", ")
                    };
                    let _ = write!(
                        exit.line,
                        "\noxi {} {}: written: {}; not written: {}",
                        cmd.family,
                        cmd.verb,
                        names(done),
                        names(left)
                    );
                }
                return Err(exit);
            }
        }
    }
    Ok(())
}

/// Prints the shared secret as 64 lowercase hex characters and a newline,
/// built in zeroizing storage and written through [`unbuffered_stdout`], so
/// no buffer outside it holds a copy.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "fixed bounds: 32 bytes into 64 digits; a nibble always indexes 16 digits"
)]
fn print_secret(cmd: Cmd, ss: &[u8; 32]) -> Result<(), Exit> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut line = Zeroizing::new([0u8; 65]);
    for i in 0..32 {
        line[2 * i] = DIGITS[usize::from(ss[i] >> 4)];
        line[2 * i + 1] = DIGITS[usize::from(ss[i] & 0x0f)];
    }
    line[64] = b'\n';
    unbuffered_stdout()
        .and_then(|mut out| out.write_all(&*line))
        .map_err(|e| cmd.failure(&format!("stdout: {e}")))
}

/// A `File` on a duplicate of the process's standard output, which writes
/// straight to it without the standard library's buffer.
fn unbuffered_stdout() -> io::Result<std::fs::File> {
    let stdout = io::stdout();
    #[cfg(unix)]
    let owned = std::os::fd::AsFd::as_fd(&stdout).try_clone_to_owned()?;
    #[cfg(windows)]
    let owned = std::os::windows::io::AsHandle::as_handle(&stdout).try_clone_to_owned()?;
    Ok(std::fs::File::from(owned))
}

/// Maps a module error to the exit code and stderr line the command reports.
fn verdict(cmd: Cmd, e: Error) -> Exit {
    match e {
        Error::ConditionalTestFailed { reason } => cmd.failure(&format!(
            "conditional self-test failed: {reason}; the module is in its error state"
        )),
        Error::Rbg(RbgError::EntropyUnavailable) => {
            Exit::failure("oxi: the module's entropy source is unavailable; restart the process")
        }
        Error::Rbg(RbgError::Busy) => {
            cmd.failure("the module reported Rbg(Busy); retry after a pause")
        }
        other => cmd.failure(&format!("the module reported {}", variant_name(&other))),
    }
}

/// The variant's name as its `Debug` form begins, with any named fields cut
/// off: `NotOperational`, `AlgorithmRestricted`, `Rbg(Busy)`.
fn variant_name(e: &Error) -> String {
    let debug = format!("{e:?}");
    debug
        .split_once(' ')
        .map_or(debug.as_str(), |(name, _)| name)
        .to_owned()
}

/// Copies a secret the module returned by value into zeroizing storage and
/// wipes `plain`. The arrays are `Copy`, so wrapping alone would leave the
/// secret in the binding it arrived in, unwiped.
fn held<const N: usize>(plain: &mut [u8; N]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(plain);
    oxicrypt_zeroize::zeroize(plain);
    out
}

/// The module's HMAC_DRBG-SHA-256, or the command's failure.
fn drbg(cmd: Cmd) -> Result<oxicrypt_drbg::HmacDrbgSha256, Exit> {
    module_drbg().map_err(|e| verdict(cmd, e))
}

fn dsa_keygen(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(cmd, rest, &["--pk", "--sk", "--seed", "--seed-out"], false)?;
    let pk_path = a.required(cmd, "--pk")?;
    let sk_path = a.required(cmd, "--sk")?;
    let seed_out = a.get("--seed-out");
    if seed_out.is_some() && a.get("--seed").is_some() {
        return Err(cmd.usage("--seed-out cannot be combined with --seed"));
    }
    let seed = a
        .get("--seed")
        .map(|hex| decode_exact::<32>(cmd, "--seed", hex))
        .transpose()?;
    if seed.is_some() {
        eprintln!("{SEED_WARNING}");
    }
    let mut outputs = vec![("--pk", pk_path), ("--sk", sk_path)];
    outputs.extend(seed_out.map(|p| ("--seed-out", p)));
    check_outputs(cmd, &outputs)?;

    per_dsa_set!(set, m, {
        let (pk, sk, xi) = if let Some(seed) = &seed {
            let (pk, mut sk) = m::expand_key(seed).map_err(|e| verdict(cmd, e))?;
            (pk, held(&mut sk), None)
        } else if seed_out.is_some() {
            let (xi, pk, mut sk) =
                m::keygen_with_seed(&mut drbg(cmd)?).map_err(|e| verdict(cmd, e))?;
            (pk, held(&mut sk), Some(xi))
        } else {
            let (pk, mut sk) = m::keygen(&mut drbg(cmd)?).map_err(|e| verdict(cmd, e))?;
            (pk, held(&mut sk), None)
        };
        let mut files: Vec<(&str, &[u8], bool)> =
            vec![(pk_path, &pk, false), (sk_path, &*sk, true)];
        if let (Some(path), Some(xi)) = (seed_out, &xi) {
            files.push((path, &**xi, true));
        }
        install(cmd, &files)
    })
}

fn dsa_sign(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(cmd, rest, &["--sk", "--sig", "--ctx"], true)?;
    let sk_path = a.required(cmd, "--sk")?;
    let sig_path = a.required(cmd, "--sig")?;
    let ctx = decode_ctx(cmd, a.get("--ctx"))?;
    check_outputs(cmd, &[("--sig", sig_path)])?;

    per_dsa_set!(set, m, {
        let sk = read_exact::<{ m::SK_LEN }>(cmd, sk_path)?;
        let message = read_message(cmd, a.message)?;
        let sig = m::sign(&sk, &message, &ctx).map_err(|e| verdict(cmd, e))?;
        install(cmd, &[(sig_path, &sig, false)])
    })
}

fn dsa_verify(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(cmd, rest, &["--pk", "--sig", "--ctx"], true)?;
    let pk_path = a.required(cmd, "--pk")?;
    let sig_path = a.required(cmd, "--sig")?;
    let ctx = decode_ctx(cmd, a.get("--ctx"))?;

    per_dsa_set!(set, m, {
        let pk = read_exact::<{ m::PK_LEN }>(cmd, pk_path)?;
        let sig = read_exact::<{ m::SIG_LEN }>(cmd, sig_path)?;
        let message = read_message(cmd, a.message)?;
        match m::verify(&pk, &message, &ctx, &sig) {
            Ok(()) => Ok(()),
            // FIPS 204 §5.3 (Algorithm 3) returns false for a public key or
            // signature of the right length whose content is malformed, so
            // `InvalidInput` is the verdict "not valid", never a usage error.
            Err(Error::InvalidInput) => Err(Exit {
                code: SIGNATURE_NOT_VALID,
                line: "ml-dsa verify: signature not valid".to_owned(),
            }),
            Err(e) => Err(verdict(cmd, e)),
        }
    })
}

fn kem_keygen(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(
        cmd,
        rest,
        &["--ek", "--dk", "--d", "--z", "--seed-out"],
        false,
    )?;
    let ek_path = a.required(cmd, "--ek")?;
    let dk_path = a.required(cmd, "--dk")?;
    let seed_out = a.get("--seed-out");
    let seeded = match (a.get("--d"), a.get("--z")) {
        (Some(d), Some(z)) => Some((d, z)),
        (None, None) => None,
        _ => return Err(cmd.usage("--d and --z are required together")),
    };
    if seed_out.is_some() && seeded.is_some() {
        return Err(cmd.usage("--seed-out cannot be combined with --d and --z"));
    }
    let seed = seeded
        .map(|(d, z)| {
            Ok::<_, Exit>((
                decode_exact::<32>(cmd, "--d", d)?,
                decode_exact::<32>(cmd, "--z", z)?,
            ))
        })
        .transpose()?;
    if seed.is_some() {
        eprintln!("{SEED_WARNING}");
    }
    let mut outputs = vec![("--ek", ek_path), ("--dk", dk_path)];
    outputs.extend(seed_out.map(|p| ("--seed-out", p)));
    check_outputs(cmd, &outputs)?;

    per_kem_set!(set, m, {
        let (ek, dk, d_z) = if let Some((d, z)) = &seed {
            let (ek, mut dk) = m::expand_key(d, z).map_err(|e| verdict(cmd, e))?;
            (ek, held(&mut dk), None)
        } else if seed_out.is_some() {
            let (d_z, ek, mut dk) =
                m::keygen_with_seed(&mut drbg(cmd)?).map_err(|e| verdict(cmd, e))?;
            (ek, held(&mut dk), Some(d_z))
        } else {
            let (ek, mut dk) = m::keygen(&mut drbg(cmd)?).map_err(|e| verdict(cmd, e))?;
            (ek, held(&mut dk), None)
        };
        let mut files: Vec<(&str, &[u8], bool)> =
            vec![(ek_path, &ek, false), (dk_path, &*dk, true)];
        if let (Some(path), Some(d_z)) = (seed_out, &d_z) {
            files.push((path, &**d_z, true));
        }
        install(cmd, &files)
    })
}

fn kem_encaps(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(cmd, rest, &["--ek", "--ct", "--ss"], false)?;
    let ek_path = a.required(cmd, "--ek")?;
    let ct_path = a.required(cmd, "--ct")?;
    let ss_path = a.get("--ss");
    let mut outputs = vec![("--ct", ct_path)];
    outputs.extend(ss_path.map(|p| ("--ss", p)));
    check_outputs(cmd, &outputs)?;

    per_kem_set!(set, m, {
        let ek = read_exact::<{ m::EK_LEN }>(cmd, ek_path)?;
        let invalid_ek = || Exit::usage(format!("{ek_path}: not a valid ML-KEM-{set} key"));
        // FIPS 203 §7.2, checked before the DRBG is instantiated, so a
        // malformed key is a usage error even when entropy cannot start.
        if !m::check_encapsulation_key(&ek).map_err(|e| verdict(cmd, e))? {
            return Err(invalid_ek());
        }
        let (mut plain, ct) = m::encapsulate(&ek, &mut drbg(cmd)?).map_err(|e| match e {
            // Defence in depth: the key passed the FIPS 203 §7.2 check above
            // and its length was checked on reading, so `InvalidInput` here
            // would be that check failing inside the service.
            Error::InvalidInput => invalid_ek(),
            e => verdict(cmd, e),
        })?;
        let ss = held(&mut plain);
        deliver_secret(cmd, &[(ct_path, &ct, false)], ss_path, &ss)
    })
}

fn kem_decaps(cmd: Cmd, set: &str, rest: &[String]) -> Result<(), Exit> {
    let a = parse(cmd, rest, &["--dk", "--ct", "--ss"], false)?;
    let dk_path = a.required(cmd, "--dk")?;
    let ct_path = a.required(cmd, "--ct")?;
    let ss_path = a.get("--ss");
    if let Some(p) = ss_path {
        check_outputs(cmd, &[("--ss", p)])?;
    }

    per_kem_set!(set, m, {
        let dk = read_exact::<{ m::DK_LEN }>(cmd, dk_path)?;
        let ct = read_exact::<{ m::CT_LEN }>(cmd, ct_path)?;
        let mut plain = m::decapsulate(&dk, &ct).map_err(|e| match e {
            // The lengths were checked on reading, so `InvalidInput` is the
            // FIPS 203 §7.3 hash check.
            Error::InvalidInput => Exit::usage(format!("{dk_path}: not a valid ML-KEM-{set} key")),
            e => verdict(cmd, e),
        })?;
        let ss = held(&mut plain);
        deliver_secret(cmd, &[], ss_path, &ss)
    })
}

/// Installs `files`, then the shared secret: to `ss_path` when given, last
/// and owner-only, otherwise on stdout.
fn deliver_secret(
    cmd: Cmd,
    files: &[(&str, &[u8], bool)],
    ss_path: Option<&str>,
    ss: &[u8; 32],
) -> Result<(), Exit> {
    if let Some(path) = ss_path {
        let mut all = files.to_vec();
        all.push((path, ss, true));
        install(cmd, &all)
    } else {
        install(cmd, files)?;
        print_secret(cmd, ss).map_err(|mut exit| {
            if !files.is_empty() {
                let written: Vec<&str> = files.iter().map(|f| f.0).collect();
                let _ = write!(
                    exit.line,
                    "\noxi {} {}: written: {}; not written: the shared secret",
                    cmd.family,
                    cmd.verb,
                    written.join(", ")
                );
            }
            exit
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{
        Cmd, Exit, OS, Ops, discard, partial_path, variant_name, verdict, write_output_via,
    };
    use super::{NO_HARD_LINKS, refuses_hard_links};
    use oxicrypt_module::{Error, RbgError, Service, State};
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    /// A directory of its own under the system temporary directory, removed
    /// when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir =
                std::env::temp_dir().join(format!("oxi-pq-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_str().expect("utf-8 path").to_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if let Err(e) = std::fs::remove_dir_all(&self.0) {
                eprintln!("could not remove {}: {e}", self.0.display());
            }
        }
    }

    #[test]
    fn write_failure_leaves_nothing() {
        let dir = TempDir::new("write-failure");
        let bytes = [0x5a_u8; 300];
        for secret in [false, true] {
            let target = dir.path(&format!("failed-{secret}"));
            let exit = write_output_via(
                &target,
                &bytes,
                secret,
                &mut |f, b| {
                    f.write_all(&b[..100])?;
                    Err(std::io::Error::other("injected after 100 bytes"))
                },
                OS,
            )
            .expect_err("a failing writer must fail the output");
            assert_eq!(exit.code, 1, "{}", exit.line);
            assert!(
                exit.line.contains("injected after 100 bytes"),
                "{}",
                exit.line
            );
            assert!(std::fs::symlink_metadata(&target).is_err(), "no target");
            assert!(
                std::fs::symlink_metadata(partial_path(&target)).is_err(),
                "no temporary: {}",
                exit.line
            );

            let target = dir.path(&format!("completed-{secret}"));
            let notes = write_output_via(&target, &bytes, secret, &mut |f, b| f.write_all(b), OS)
                .map_err(|e| e.line)
                .expect("control: a completing writer installs the output");
            assert!(notes.is_empty(), "{notes:?}");
            assert_eq!(std::fs::read(&target).expect("read target").len(), 300);
            assert!(std::fs::symlink_metadata(partial_path(&target)).is_err());
        }
    }

    /// An open temporary holding `bytes` at `temp`, as `write_output_via`
    /// creates it.
    fn open_temp(temp: &str, bytes: &[u8]) -> std::fs::File {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .expect("create temp");
        file.write_all(bytes).expect("write temp");
        file
    }

    /// A discarded secret temporary is zero-filled through the handle that
    /// wrote it, so a file put at its name afterwards is not touched: the
    /// moved original reads back as zeros and the decoy keeps its bytes until
    /// its name is unlinked.
    #[cfg(unix)]
    #[test]
    fn a_discarded_secret_temporary_is_zero_filled_through_its_handle() {
        let dir = TempDir::new("discard");
        for secret in [true, false] {
            let temp = dir.path(&format!("t-{secret}.oxi-partial"));
            let moved = dir.path(&format!("moved-{secret}"));
            let decoy = dir.path(&format!("decoy-{secret}"));
            let file = open_temp(&temp, &[0xa5_u8; 64]);
            std::fs::rename(&temp, &moved).expect("move the temporary aside");
            std::fs::write(&decoy, [0x3c_u8; 64]).expect("write decoy");
            std::fs::hard_link(&decoy, &temp).expect("put the decoy at the name");
            let exit = discard(Exit::failure("failed"), file, &temp, secret, OS);
            assert_eq!(exit.line, "failed", "no cleanup failure is reported");
            assert!(std::fs::symlink_metadata(&temp).is_err(), "name unlinked");
            let expected = if secret { [0_u8; 64] } else { [0xa5_u8; 64] };
            assert_eq!(std::fs::read(&moved).expect("read moved"), expected);
            assert_eq!(
                std::fs::read(&decoy).expect("read decoy"),
                [0x3c_u8; 64],
                "the file at the name is never opened"
            );
        }
    }

    /// A secret temporary that has a second name is not zero-filled, since
    /// the other name may be an installed output; the failure is reported.
    #[cfg(unix)]
    #[test]
    fn a_temporary_with_another_name_is_not_zero_filled() {
        let dir = TempDir::new("nlink");
        let temp = dir.path("t.oxi-partial");
        let other = dir.path("installed");
        let file = open_temp(&temp, &[0xa5_u8; 64]);
        std::fs::hard_link(&temp, &other).expect("second name");
        let exit = discard(Exit::failure("failed"), file, &temp, true, OS);
        assert_eq!(
            exit.line,
            format!(
                "failed\noxi: {temp} could not be zero-filled: it has 2 links, so another name \
                 may hold it"
            )
        );
        assert_eq!(std::fs::read(&other).expect("read other"), [0xa5_u8; 64]);
        assert!(std::fs::symlink_metadata(&temp).is_err(), "name unlinked");
    }

    /// A link refused with code 1: `EPERM` on Unix, `ERROR_INVALID_FUNCTION`
    /// on Windows, in `NO_HARD_LINKS` on both.
    fn no_hard_links(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(1))
    }

    /// A permission refusal, which is not a filesystem without hard links:
    /// `EACCES` (13) on Unix, `ERROR_ACCESS_DENIED` (5) on Windows.
    fn access_denied(_: &Path, _: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(if cfg!(windows) {
            5
        } else {
            13
        }))
    }

    /// Every code in this platform's `NO_HARD_LINKS` list is recognised and
    /// the platform's permission-refusal code is not, so a code dropped from
    /// the list, or the permission code added to it, fails here.
    #[test]
    fn the_no_hard_links_codes_are_pinned_per_platform() {
        let expected: &[i32] = if cfg!(windows) {
            &[1, 50]
        } else if cfg!(any(target_os = "linux", target_os = "android")) {
            &[1, 95, 38]
        } else if cfg!(target_vendor = "apple") {
            &[1, 102, 45, 78]
        } else {
            NO_HARD_LINKS
        };
        assert_eq!(NO_HARD_LINKS, expected);
        for code in expected {
            assert!(
                refuses_hard_links(&std::io::Error::from_raw_os_error(*code)),
                "{code}"
            );
        }
        let denied = access_denied(Path::new(""), Path::new("")).unwrap_err();
        assert!(!refuses_hard_links(&denied));
    }

    fn unlink_fails(_: &Path) -> std::io::Result<()> {
        Err(std::io::Error::other("injected unlink failure"))
    }

    fn write_all(f: &mut std::fs::File, b: &[u8]) -> std::io::Result<()> {
        f.write_all(b)
    }

    /// A link refused with code 1 (`EPERM` on Unix, `ERROR_INVALID_FUNCTION`
    /// on Windows) falls back to a second existence check: a target that
    /// exists is not replaced and the temporary is discarded; an absent
    /// target is renamed into place, leaving no temporary.
    #[test]
    fn a_filesystem_without_hard_links_falls_back_to_a_checked_rename() {
        let dir = TempDir::new("fallback");
        let ops = Ops {
            link: no_hard_links,
            unlink: OS.unlink,
        };
        let present = dir.path("present");
        std::fs::write(&present, b"keep").expect("write present");
        let exit = write_output_via(&present, &[7; 32], true, &mut write_all, ops)
            .expect_err("an existing target is refused");
        assert_eq!(
            (exit.code, exit.line.as_str()),
            (
                1,
                format!("oxi will not overwrite {present}: it already exists").as_str()
            )
        );
        assert_eq!(std::fs::read(&present).expect("read present"), b"keep");
        assert!(std::fs::symlink_metadata(partial_path(&present)).is_err());

        let absent = dir.path("absent");
        let notes = write_output_via(&absent, &[7; 32], true, &mut write_all, ops)
            .map_err(|e| e.line)
            .expect("an absent target is renamed into place");
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(std::fs::read(&absent).expect("read absent"), [7; 32]);
        assert!(std::fs::symlink_metadata(partial_path(&absent)).is_err());
    }

    /// A permission refusal (`EACCES` on Unix, `ERROR_ACCESS_DENIED` on
    /// Windows) is not a filesystem without hard links: no rename is tried.
    #[test]
    fn a_link_refused_for_permission_is_not_retried_as_a_rename() {
        let dir = TempDir::new("eacces");
        let ops = Ops {
            link: access_denied,
            unlink: OS.unlink,
        };
        let target = dir.path("target");
        let exit = write_output_via(&target, &[7; 32], false, &mut write_all, ops)
            .expect_err("the link failure is the result");
        assert_eq!(exit.code, 1, "{}", exit.line);
        assert!(
            exit.line.starts_with(&format!("oxi: {target}: ")),
            "{}",
            exit.line
        );
        assert!(std::fs::symlink_metadata(&target).is_err(), "no rename");
        assert!(std::fs::symlink_metadata(partial_path(&target)).is_err());
    }

    /// A link that succeeds followed by an unlink that fails leaves the
    /// output in place, succeeds, and returns the note naming the leftover.
    #[test]
    fn an_unremovable_temporary_after_install_is_reported() {
        let dir = TempDir::new("unlink");
        let ops = Ops {
            link: OS.link,
            unlink: unlink_fails,
        };
        let target = dir.path("target");
        let notes = write_output_via(&target, &[7; 32], false, &mut write_all, ops)
            .map_err(|e| e.line)
            .expect("the output is in place");
        let temp = partial_path(&target);
        assert_eq!(
            notes,
            [format!(
                "oxi: written: {target}; left behind: {temp}; delete it (injected unlink failure)"
            )]
        );
        assert_eq!(std::fs::read(&target).expect("read target"), [7; 32]);
        assert!(
            std::fs::symlink_metadata(&temp).is_ok(),
            "the leftover is real"
        );
    }

    #[test]
    fn verdict_names_the_variant() {
        let cmd = Cmd {
            family: "ml-kem",
            verb: "decaps",
        };
        let exit = verdict(
            cmd,
            Error::NotOperational {
                current: State::Error,
            },
        );
        assert_eq!(
            (exit.code, exit.line.as_str()),
            (1, "oxi ml-kem decaps: the module reported NotOperational")
        );
        let exit = verdict(cmd, Error::Rbg(RbgError::Busy));
        assert_eq!(
            (exit.code, exit.line.as_str()),
            (
                1,
                "oxi ml-kem decaps: the module reported Rbg(Busy); retry after a pause"
            )
        );
    }

    /// `pq.rs` outside its tests.
    fn code() -> &'static str {
        let whole = include_str!("pq.rs");
        let code = whole
            .rsplit_once("\n#[cfg(test)]\n")
            .map_or(whole, |(code, _)| code);
        assert!(
            code.len() < whole.len() && code.contains("fn print_secret("),
            "premise failed: pq.rs was not cut at its test module"
        );
        code
    }

    /// The body of `fn <name>(` in `code`.
    fn body<'a>(code: &'a str, name: &str) -> &'a str {
        code.split_once(&format!("fn {name}("))
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map_or("", |(body, _)| body)
    }

    /// Outside its tests, `pq.rs` reaches stdout once: `print_secret` writes
    /// through `unbuffered_stdout`, a `File` on a duplicate of the descriptor,
    /// and nothing prints through the standard library's buffered stdout.
    #[test]
    fn print_secret_is_the_only_stdout_write() {
        let code = code();
        assert_eq!(code.matches("io::stdout()").count(), 1, "one stdout handle");
        assert!(body(code, "unbuffered_stdout").contains("io::stdout()"));
        assert!(body(code, "unbuffered_stdout").contains("try_clone_to_owned()"));
        assert_eq!(code.matches("unbuffered_stdout()").count(), 2, "one caller");
        assert!(body(code, "print_secret").contains("unbuffered_stdout()"));
        assert!(!code.contains("stdout().lock()"), "no buffered handle");
        let without_stderr = code.replace("eprintln!(", "").replace("eprint!(", "");
        assert!(
            code.contains("eprintln!("),
            "premise failed: the stderr prints are not being excluded"
        );
        for forbidden in ["print!(", "println!(", "write!(io::stdout"] {
            assert_eq!(
                without_stderr.matches(forbidden).count(),
                0,
                "{forbidden} in pq.rs"
            );
        }
    }

    /// Outside its tests, `pq.rs` creates files only in `write_output_via`,
    /// and in `pause_before_install`'s marker under the `fault-injection`
    /// feature.
    #[test]
    fn write_output_creates_every_output_file() {
        let code = code();
        assert_eq!(
            code.matches("create_new(").count(),
            1,
            "one exclusive create"
        );
        assert!(body(code, "write_output_via").contains("create_new(true)"));
        assert!(
            code.contains("fs::read("),
            "premise failed: fs:: calls are visible"
        );
        let hook = body(code, "pause_before_install");
        assert_eq!(
            code.matches("fs::write(").count(),
            1,
            "the hook's marker only"
        );
        assert!(hook.contains("fs::write("), "the marker is the hook's");
        for other in ["File::create(", ".create(true)", "fs::copy(", "fs::rename("] {
            let outside = code.matches(other).count();
            let allowed = usize::from(other == "fs::rename(");
            assert_eq!(outside, allowed, "{other} in pq.rs");
        }
        assert!(
            body(code, "place").contains("fs::rename("),
            "the rename is place's"
        );
    }

    #[test]
    fn variant_names_drop_their_fields() {
        assert_eq!(
            variant_name(&Error::NotOperational {
                current: State::Error
            }),
            "NotOperational"
        );
        assert_eq!(
            variant_name(&Error::AlgorithmRestricted {
                service: Service::MlKem512Keygen
            }),
            "AlgorithmRestricted"
        );
        assert_eq!(variant_name(&Error::InvalidInput), "InvalidInput");
        assert_eq!(variant_name(&Error::Rbg(RbgError::Busy)), "Rbg(Busy)");
    }
}
