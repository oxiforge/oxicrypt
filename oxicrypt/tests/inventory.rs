//! The export inventory: this binary holds one function pointer per `sys`
//! declaration, so the loader refuses to start it unless the library exports
//! every function the header declares.

#![cfg(all(oxicrypt_lib, target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

#[path = "../src/sys.rs"]
mod sys;

#[path = "../src/sys_inventory.rs"]
mod sys_inventory;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const CHILD: &str = "child_does_nothing";

/// The names `sys.rs` declares, read from its text.
fn declared() -> BTreeSet<String> {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sys.rs")).unwrap();
    src.lines()
        .filter_map(|l| l.trim().strip_prefix("pub(crate) fn "))
        .map(|l| l[..l.find('(').unwrap()].to_owned())
        .collect()
}

/// Spawned by the tests below with the loader pointed elsewhere.
#[test]
fn child_does_nothing() {}

#[test]
fn the_table_holds_every_declaration() {
    let addresses = sys_inventory::INVENTORY.addresses();
    assert_eq!(addresses.len(), declared().len());
    assert_eq!(addresses.len(), 292);
    assert!(addresses.iter().all(|a| *a != 0));
}

#[test]
fn this_binary_imports_every_export() {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("nm")
        .args(["-D", "--undefined-only"])
        .arg(&exe)
        .output()
        .expect("run nm");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let imported: BTreeSet<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|n| n.starts_with("oxi_") || *n == "lama_manifest")
        .map(str::to_owned)
        .collect();
    let declared = declared();
    let missing: Vec<_> = declared.difference(&imported).collect();
    assert!(
        missing.is_empty(),
        "not imported by the final link: {missing:?}"
    );
    assert_eq!(imported.len(), 292);
}

fn spawn_with_library(dir: &Path) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD])
        .env("LD_LIBRARY_PATH", dir)
        .output()
        .unwrap()
}

#[test]
fn a_library_lacking_one_export_does_not_load() {
    let bytes = fs::read(common::lib_dir().join("liboxicrypt_ffi.so")).unwrap();
    let base = std::env::temp_dir().join(format!("oxicrypt-bindings-inv-{}", std::process::id()));
    let (intact, lacking) = (base.join("intact"), base.join("lacking"));
    fs::create_dir_all(&intact).unwrap();
    fs::create_dir_all(&lacking).unwrap();
    fs::write(intact.join("liboxicrypt_ffi.so"), &bytes).unwrap();

    // Rename one dynamic symbol the safe layer never calls, so that only the
    // table references it.
    let needle = b"\0oxi_sha3_512\0";
    let mut patched = bytes.clone();
    let positions: Vec<usize> = patched
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert!(
        !positions.is_empty(),
        "oxi_sha3_512 not in the library's string table"
    );
    for at in positions {
        patched[at + needle.len() - 2] = b'X';
    }
    fs::write(lacking.join("liboxicrypt_ffi.so"), &patched).unwrap();

    let ok = spawn_with_library(&intact);
    let bad = spawn_with_library(&lacking);
    fs::remove_dir_all(&base).unwrap();

    assert!(
        ok.status.success(),
        "positive control: the intact copy must load: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        !bad.status.success(),
        "a library lacking oxi_sha3_512 loaded"
    );
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        stderr.contains("oxi_sha3_512"),
        "unexpected failure: {stderr}"
    );
}
