//! The post-quantum command families: `oxi ml-dsa` (FIPS 204) and
//! `oxi ml-kem` (FIPS 203).
//!
//! | Item | Role |
//! |------|------|
//! | [`cmd_ml_dsa`] | `keygen`, `sign` and `verify` for ML-DSA-44, -65 and -87 |
//! | [`cmd_ml_kem`] | `keygen`, `encaps` and `decaps` for ML-KEM-512, -768 and -1024 |
//! | [`parse`] | the hand-written flag grammar every verb shares |
//! | [`verdict`] | the mapping from a module error to the exit code and stderr line |
//! | [`write_output`] | every file these commands create |

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

/// The line printed on stderr whenever a seed is supplied on the command line.
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
        return Err(cmd.usage(&format!("{}, got {} characters", expected(), hex.len())));
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

/// Reads the file at `path` whole into zeroizing storage and checks that it
/// is exactly `N` bytes.
fn read_exact<const N: usize>(cmd: Cmd, path: &str) -> Result<Zeroizing<[u8; N]>, Exit> {
    let bytes =
        Zeroizing::new(std::fs::read(path).map_err(|e| cmd.usage(&format!("{path}: {e}")))?);
    if bytes.len() != N {
        return Err(cmd.usage(&format!("{path}: expected {N} bytes, got {}", bytes.len())));
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&bytes);
    Ok(out)
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

/// Refuses, before anything is written, an output path that exists and two
/// output flags that name the same file.
fn check_outputs(cmd: Cmd, outputs: &[(&str, &str)]) -> Result<(), Exit> {
    for (i, &(flag, path)) in outputs.iter().enumerate() {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(will_not_overwrite(path));
        }
        if let Some(&(other, _)) = outputs
            .get(..i)
            .unwrap_or(&[])
            .iter()
            .find(|&&(_, p)| same_file(p, path))
        {
            return Err(cmd.usage(&format!("{other} and {flag} name the same file {path}")));
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

/// Creates the file at `path` and writes `bytes` to it.
///
/// The file is created exclusively, so an existing `path` is never
/// replaced: it is refused with exit code 2 and
/// `oxi will not overwrite <path>`, and nothing is written. With `secret`
/// the file is created with mode `0o600` on Unix. Any other failure is exit
/// code 1 with the path and the operating-system error, and a file this call
/// created is removed again. A process killed during the write can leave a
/// partial file at `path`.
///
/// Every file the post-quantum commands write goes through this function.
fn write_output(path: &str, bytes: &[u8], secret: bool) -> Result<(), Exit> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(will_not_overwrite(path)),
        Err(e) => return Err(Exit::failure(format!("oxi: {path}: {e}"))),
    };
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(Exit::failure(format!("oxi: {path}: {e}")));
    }
    Ok(())
}

/// Writes each output in the order given, and on a failure names what was
/// and was not written.
fn install(cmd: Cmd, outputs: &[(&str, &[u8], bool)]) -> Result<(), Exit> {
    for (i, &(path, bytes, secret)) in outputs.iter().enumerate() {
        if let Err(mut exit) = write_output(path, bytes, secret) {
            let (done, left) = outputs.split_at(i);
            if !done.is_empty() {
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
    Ok(())
}

/// Prints the shared secret as 64 lowercase hex characters and a newline,
/// from zeroizing storage.
fn print_secret(cmd: Cmd, ss: &[u8; 32]) -> Result<(), Exit> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut line = Zeroizing::new([0u8; 65]);
    if let Some((newline, digits)) = line.split_last_mut() {
        *newline = b'\n';
        for (pair, &b) in digits.chunks_exact_mut(2).zip(ss) {
            if let ([hi, lo], Some(&h), Some(&l)) = (
                pair,
                DIGITS.get(usize::from(b >> 4)),
                DIGITS.get(usize::from(b & 0x0f)),
            ) {
                *hi = h;
                *lo = l;
            }
        }
    }
    let mut out = io::stdout().lock();
    out.write_all(&*line)
        .and_then(|()| out.flush())
        .map_err(|e| cmd.failure(&format!("stdout: {e}")))
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
/// binding they arrived in holding the secret until it goes out of scope.
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
    let mut outputs = vec![("--pk", pk_path), ("--sk", sk_path)];
    outputs.extend(seed_out.map(|p| ("--seed-out", p)));
    check_outputs(cmd, &outputs)?;

    per_dsa_set!(set, m, {
        let (pk, sk, xi) = if let Some(seed) = &seed {
            eprintln!("{SEED_WARNING}");
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
    let mut outputs = vec![("--ek", ek_path), ("--dk", dk_path)];
    outputs.extend(seed_out.map(|p| ("--seed-out", p)));
    check_outputs(cmd, &outputs)?;

    per_kem_set!(set, m, {
        let (ek, dk, d_z) = if let Some((d, z)) = &seed {
            eprintln!("{SEED_WARNING}");
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
        let (mut plain, ct) = m::encapsulate(&ek, &mut drbg(cmd)?).map_err(|e| match e {
            // The length was checked on reading, so `InvalidInput` is the
            // FIPS 203 §7.2 encapsulation key check.
            Error::InvalidInput => Exit::usage(format!("{ek_path}: not a valid ML-KEM-{set} key")),
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
        print_secret(cmd, ss)
    }
}

#[cfg(test)]
mod tests {
    use super::variant_name;
    use oxicrypt_module::{Error, RbgError, Service, State};

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
