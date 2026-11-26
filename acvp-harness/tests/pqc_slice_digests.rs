//! Every vendored file a `[acvp_server.pqc]` row of
//! `vendor/nist/MANIFEST.toml` names has the row's `sha256`, and every
//! such row names one of the files compiled in here.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../vendor/nist/MANIFEST.toml"
));

macro_rules! vendored {
    ($($path:literal),* $(,)?) => {
        [$((
            $path,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../vendor/nist/acvp-server/gen-val/json-files/",
                $path
            )) as &[u8],
        )),*]
    };
}

const FILES: [(&str, &[u8]); 11] = vendored![
    "ML-KEM-keyGen-FIPS203/cast-slice.json",
    "ML-KEM-encapDecap-FIPS203/cast-slice.json",
    "ML-KEM-encapDecap-FIPS203/keycheck-slice.json",
    "ML-DSA-keyGen-FIPS204/cast-slice.json",
    "ML-DSA-sigGen-FIPS204/cast-slice.json",
    "ML-DSA-sigGen-FIPS204/kat-slice.json",
    "ML-DSA-sigVer-FIPS204/cast-slice.json",
    "ML-DSA-sigVer-FIPS204/external-sigver-slice.json",
    "SLH-DSA-keyGen-FIPS205/cast-slice.json",
    "SLH-DSA-sigGen-FIPS205/cast-slice.json",
    "LMS-sigVer-1.0/internalProjection.json",
];

/// The value of `name = "..."` in an inline-table row, matched only
/// where `name` starts a key.
fn field<'a>(row: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name} = \"");
    row.split([',', '{']).find_map(|piece| {
        piece
            .trim()
            .trim_end_matches('}')
            .trim_end()
            .strip_prefix(needle.as_str())?
            .strip_suffix('"')
    })
}

fn pqc_rows() -> Vec<(&'static str, String, Option<&'static str>)> {
    let mut rows = Vec::new();
    let mut in_section = false;
    for line in MANIFEST.lines() {
        if line.starts_with('[') {
            in_section = line.trim() == "[acvp_server.pqc]";
            continue;
        }
        if !in_section {
            continue;
        }
        let Some(file) = field(line, "file") else {
            continue;
        };
        let key = line.split('=').next().unwrap().trim();
        let dir = field(line, "dir").unwrap_or_else(|| panic!("{key} has no dir"));
        rows.push((key, format!("{dir}/{file}"), field(line, "sha256")));
    }
    rows
}

#[test]
fn field_matches_only_whole_keys() {
    let row = r#"K = { dir = "D", source = "S", file = "F", sha256 = "H" }"#;
    assert_eq!(field(row, "file"), Some("F"));
    assert_eq!(field(row, "dir"), Some("D"));
    assert_eq!(field(row, "sha256"), Some("H"));
    assert_eq!(field(row, "ource"), None);
}

#[test]
fn pqc_rows_match_their_vendored_files() {
    acvp_harness::ensure_initialized().unwrap();
    let rows = pqc_rows();
    assert!(rows.len() >= FILES.len());

    let named: BTreeSet<&str> = rows.iter().map(|(_, path, _)| path.as_str()).collect();
    let compiled: BTreeSet<&str> = FILES.iter().map(|(path, _)| *path).collect();
    assert_eq!(named, compiled);

    for (key, path, sha256) in &rows {
        let sha256 = sha256.unwrap_or_else(|| panic!("{key} has no sha256"));
        let bytes = FILES.iter().find(|(p, _)| p == path).unwrap().1;
        assert!(!bytes.is_empty(), "{key}: {path} is empty");
        let digest = oxicrypt_sha::sha256::sha256(bytes).unwrap();
        assert_eq!(
            digest.as_slice(),
            acvp_harness::hex::decode(sha256).unwrap(),
            "{key}: {path}"
        );
    }
}
