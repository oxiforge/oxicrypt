//! The negative link tests and the external consumer.
//!
//! Each case builds a small consumer package, outside the workspace, that
//! depends on this crate by path and sets its own run-time search path the
//! way the crate documentation says to. The cases cover a directory holding
//! only the static archive, one holding both libraries, no directory with a
//! static archive on the linker's default search path, and no fingerprint.
//! Linux only: the checks read ELF dynamic sections.

#![cfg(all(oxicrypt_lib, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

mod common;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONSUMER_MAIN: &str = r#"
use oxicrypt::{Module, Profile};

fn main() {
    let module = Module::init(Profile::Cnsa2).expect("init");
    let digest = module.sha384(b"abc").expect("sha384");
    println!("consumer ok {:02x}{:02x}", digest[0], digest[47]);
    println!("path {}", Module::library_path().expect("library path").display());
}
"#;

const CONSUMER_BUILD: &str = r#"
fn main() {
    println!("cargo:rerun-if-env-changed=CONSUMER_RPATH");
    if let Ok(dir) = std::env::var("CONSUMER_RPATH") {
        println!("cargo:rustc-link-arg=-Wl,--enable-new-dtags");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
    }
}
"#;

struct Consumer {
    root: PathBuf,
}

impl Consumer {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "oxicrypt-bindings-consumer-{}-{tag}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let manifest = format!(
            "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n\
             [dependencies]\noxicrypt = {{ path = {:?} }}\n\n[workspace]\n",
            env!("CARGO_MANIFEST_DIR")
        );
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        fs::write(root.join("build.rs"), CONSUMER_BUILD).unwrap();
        fs::write(root.join("src/main.rs"), CONSUMER_MAIN).unwrap();
        Self { root }
    }

    fn dir(&self, name: &str, files: &[&Path]) -> PathBuf {
        let dir = self.root.join(name);
        fs::create_dir_all(&dir).unwrap();
        for f in files {
            let name = f.file_name().unwrap();
            if name == "liboxicrypt_ffi.so" {
                // The shared library as a consumer deploys it: the file under
                // its delivered name, and the plain name a link to it.
                let delivered = common::delivered_name();
                fs::copy(f, dir.join(&delivered)).unwrap();
                if delivered != "liboxicrypt_ffi.so" {
                    std::os::unix::fs::symlink(&delivered, dir.join(name)).unwrap();
                }
            } else {
                fs::copy(f, dir.join(name)).unwrap();
            }
        }
        dir
    }

    /// `cargo build` of the consumer with `vars` set and every variable this
    /// crate reads otherwise unset.
    fn build(&self, vars: &[(&str, &OsStr)], fingerprint: bool) -> Output {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| env!("CARGO").to_owned());
        let mut cmd = Command::new(cargo);
        cmd.args(["build", "--offline", "--quiet"])
            .current_dir(&self.root)
            .env("CARGO_TARGET_DIR", self.root.join("target"));
        for var in [
            "OXICRYPT_LIB_DIR",
            "OXICRYPT_LIB_FINGERPRINT",
            "OXICRYPT_LIB_UNPINNED",
            "OXICRYPT_LIB_OPTIONAL",
            "LIBRARY_PATH",
            "CONSUMER_RPATH",
            "RUSTFLAGS",
        ] {
            cmd.env_remove(var);
        }
        for (k, v) in vars {
            cmd.env(k, v);
        }
        if fingerprint {
            cmd.env("OXICRYPT_LIB_FINGERPRINT", common::fixture_fingerprint());
        }
        cmd.output().unwrap()
    }

    fn binary(&self) -> PathBuf {
        self.root.join("target/debug/consumer")
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn tool(program: &str, args: &[&str], file: &Path) -> Output {
    Command::new(program).args(args).arg(file).output().unwrap()
}

/// The checks every successfully linked consumer must pass.
fn assert_outside_the_image(binary: &Path) {
    let dynamic = String::from_utf8_lossy(&tool("readelf", &["-d"], binary).stdout).into_owned();
    assert!(
        dynamic.contains(&format!("Shared library: [{}]", common::delivered_name())),
        "{dynamic}"
    );
    let undefined = tool("nm", &["-D", "--undefined-only"], binary);
    let undefined = String::from_utf8_lossy(&undefined.stdout).into_owned();
    assert!(
        undefined.lines().any(|l| l.ends_with(" oxi_init")),
        "{undefined}"
    );
    let defined = tool("nm", &["--defined-only"], binary);
    let defined = String::from_utf8_lossy(&defined.stdout).into_owned();
    assert!(
        !defined.lines().any(|l| l.contains(" oxi_")),
        "the consumer defines oxi_* symbols"
    );

    let signer = common::fixture_dir().join("bin/oxicrypt-integrity-sign");
    let show = Command::new(&signer)
        .arg("--show")
        .arg(binary)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&show.stdout), stderr(&show));
    assert!(
        !show.status.success(),
        "the signer found a slot in the consumer: {text}"
    );
    assert!(text.contains("no integrity slot found"), "{text}");
    // Positive control: the same probe finds the slot in the library.
    let lib = common::lib_dir().join("liboxicrypt_ffi.so");
    let show = Command::new(&signer)
        .arg("--show")
        .arg(&lib)
        .output()
        .unwrap();
    assert!(show.status.success(), "{}", stderr(&show));
}

#[test]
fn negative_link_tests_and_the_external_consumer() {
    let fixture = common::fixture_dir();
    let shared = common::lib_dir().join("liboxicrypt_ffi.so");
    let archive = fixture.join("archive/liboxicrypt_ffi.a");
    let consumer = Consumer::new("links");
    let archive_only = consumer.dir("archive-only", &[&archive]);
    let both = consumer.dir("both", &[&shared, &archive]);

    // The static archive alone is refused, naming the shared library.
    let out = consumer.build(&[("OXICRYPT_LIB_DIR", archive_only.as_os_str())], true);
    assert!(!out.status.success(), "linked against the archive alone");
    assert!(
        stderr(&out).contains("does not hold liboxicrypt_ffi.so"),
        "{}",
        stderr(&out)
    );

    // No fingerprint and no opt-out is refused.
    let out = consumer.build(&[("OXICRYPT_LIB_DIR", both.as_os_str())], false);
    assert!(!out.status.success());
    for option in [
        "set OXICRYPT_LIB_FINGERPRINT",
        "OXICRYPT_LIB_UNPINNED=1",
        "OXICRYPT_LIB_OPTIONAL=1",
    ] {
        assert!(stderr(&out).contains(option), "{option}: {}", stderr(&out));
    }

    // No directory, with only the archive on the linker's default search
    // path: the exact name finds nothing.
    let out = consumer.build(&[("LIBRARY_PATH", archive_only.as_os_str())], true);
    assert!(
        !out.status.success(),
        "an ambient static archive satisfied the link"
    );
    assert!(
        stderr(&out).contains("liboxicrypt_ffi.so"),
        "{}",
        stderr(&out)
    );

    // No directory, both on the default search path: the shared library.
    let out = consumer.build(&[("LIBRARY_PATH", both.as_os_str())], true);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_outside_the_image(&consumer.binary());

    // Both in the directory, with the consumer's own search path set by the
    // documented recipe: a program outside the image that runs with the
    // loader's environment cleared.
    let out = consumer.build(
        &[
            ("OXICRYPT_LIB_DIR", both.as_os_str()),
            ("CONSUMER_RPATH", both.as_os_str()),
        ],
        true,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let binary = consumer.binary();
    assert_outside_the_image(&binary);
    let dynamic = String::from_utf8_lossy(&tool("readelf", &["-d"], &binary).stdout).into_owned();
    assert!(
        dynamic.contains(&format!("Library runpath: [{}]", both.display())),
        "{dynamic}"
    );
    let run = Command::new(&binary).env_clear().output().unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines[0], "consumer ok cba7");
    assert_eq!(
        lines[1],
        format!("path {}", both.join(common::delivered_name()).display())
    );
}

#[test]
fn build_variables_are_validated() {
    let shared = common::lib_dir().join("liboxicrypt_ffi.so");
    let archive = common::fixture_dir().join("archive/liboxicrypt_ffi.a");
    let consumer = Consumer::new("vars");
    let both = consumer.dir("both", &[&shared, &archive]);
    let dir = ("OXICRYPT_LIB_DIR", both.as_os_str());
    let unpinned = ("OXICRYPT_LIB_UNPINNED", OsStr::new("1"));
    let not_utf8 = OsStr::from_bytes(b"\xff");

    // A pin and the opt-out together are refused.
    let out = consumer.build(&[dir, unpinned], true);
    assert!(!out.status.success(), "built with a pin and the opt-out");
    assert!(stderr(&out).contains("choose one"), "{}", stderr(&out));

    // A value that is not UTF-8 is refused, never read as unset.
    let out = consumer.build(
        &[dir, unpinned, ("OXICRYPT_LIB_FINGERPRINT", not_utf8)],
        false,
    );
    assert!(!out.status.success(), "a non-UTF-8 pin was read as unset");
    assert!(stderr(&out).contains("not valid UTF-8"), "{}", stderr(&out));
    let out = consumer.build(&[("OXICRYPT_LIB_DIR", not_utf8)], true);
    assert!(!out.status.success(), "a non-UTF-8 directory was accepted");
    assert!(stderr(&out).contains("not valid UTF-8"), "{}", stderr(&out));
    let out = consumer.build(&[dir, ("OXICRYPT_LIB_UNPINNED", not_utf8)], true);
    assert!(
        !out.status.success(),
        "a non-UTF-8 opt-out was read as unset"
    );
    assert!(stderr(&out).contains("not valid UTF-8"), "{}", stderr(&out));

    // The build script runs again when a file it inspected changes: with
    // the shared library gone, its refusal names the file.
    let out = consumer.build(&[dir], true);
    assert!(out.status.success(), "{}", stderr(&out));
    fs::remove_file(both.join("liboxicrypt_ffi.so")).unwrap();
    let out = consumer.build(&[dir], true);
    assert!(!out.status.success(), "a stale build passed");
    assert!(
        stderr(&out).contains("does not hold liboxicrypt_ffi.so"),
        "{}",
        stderr(&out)
    );
}

/// In a program that is not position-independent, the address of an
/// imported function is the program's own PLT entry; the reported path must
/// still be the library's.
#[test]
fn library_path_names_the_library_in_a_non_pie_program() {
    let shared = common::lib_dir().join("liboxicrypt_ffi.so");
    let consumer = Consumer::new("nopie");
    let lib = consumer.dir("lib", &[&shared]);
    let out = consumer.build(
        &[
            ("OXICRYPT_LIB_DIR", lib.as_os_str()),
            ("CONSUMER_RPATH", lib.as_os_str()),
            (
                "RUSTFLAGS",
                OsStr::new("-C relocation-model=static -C link-arg=-no-pie"),
            ),
        ],
        true,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let binary = consumer.binary();
    let header = String::from_utf8_lossy(&tool("readelf", &["-h"], &binary).stdout).into_owned();
    assert!(header.contains("EXEC (Executable file)"), "{header}");
    let run = Command::new(&binary).env_clear().output().unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let expected = format!("path {}", lib.join(common::delivered_name()).display());
    assert_eq!(stdout.lines().nth(1), Some(expected.as_str()));
}
