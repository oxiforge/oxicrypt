//! SP 800-108 counter mode against NIST ACVP cases that span several PRF blocks.
//!
//! Source: usnistgov/ACVP-Server @ 3611942ea10c070dd8bc6afec5682d56c307de8a,
//! `gen-val/json-files/KDF-1.0/internalProjection.json`. Three test cases
//! whose `keyOutLength` exceeds the PRF output length are cut from it into
//! `vendor/nist/acvp-server/gen-val/json-files/KDF-1.0/counter-multiblock-slice.json`,
//! which records the source file's SHA-256, as does the `multiblock` row of
//! `vendor/nist/MANIFEST.toml`.
//!
//! The power-up KATs use 8-bit outputs, a single PRF block, so they cannot
//! tell whether blocks are emitted in counter order. These cases need two to
//! four blocks, one of them ending in a partial block, and are compared byte
//! for byte with the expected `keyOut`.
//!
//! Reference: SP 800-108r1 §4.1.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use std::collections::BTreeMap;

use oxicrypt_kdf::{KdfError, Sp800_108CounterHmacSha256, Sp800_108CounterHmacSha512};

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// Brings the module out of `PowerOff` so that the test can call the
/// `*_internal` functions, which refuse until the self-tests have started.
fn start_module() {
    let _ = oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert_eq!(oxicrypt_module::require_self_test_started(), Ok(()));
}

/// Workspace-relative path of the vendored slice.
const SLICE_PATH: &str =
    "vendor/nist/acvp-server/gen-val/json-files/KDF-1.0/counter-multiblock-slice.json";

/// The test groups the slice must hold, so a case removed from it fails here.
const EXPECTED_TG_IDS: [i64; 3] = [642, 644, 823];

fn read_slice() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(SLICE_PATH);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ── Minimal JSON reader ─────────────────────────────────────────────────────
//
// The workspace carries no JSON dependency. The slice uses only objects,
// arrays, strings without escapes and non-negative integers, which is all
// this reader accepts; anything else panics rather than being skipped.

#[derive(Debug)]
enum Json {
    Obj(BTreeMap<String, Json>),
    Arr(Vec<Json>),
    Str(String),
    Num(i64),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(m) => m.get(key).unwrap_or_else(|| panic!("missing key {key}")),
            other => panic!("not an object: {other:?}"),
        }
    }
    fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }
    fn num(&self) -> i64 {
        match self {
            Json::Num(n) => *n,
            other => panic!("not a number: {other:?}"),
        }
    }
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            other => panic!("not an array: {other:?}"),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn expect(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.b[self.i], c, "unexpected byte at {}", self.i);
        self.i += 1;
    }
    fn value(&mut self) -> Json {
        self.ws();
        match self.b[self.i] {
            b'{' => {
                self.i += 1;
                let mut m = BTreeMap::new();
                loop {
                    let Json::Str(k) = self.value() else {
                        panic!("object key is not a string at {}", self.i)
                    };
                    self.expect(b':');
                    let v = self.value();
                    assert!(m.insert(k, v).is_none(), "duplicate key");
                    self.ws();
                    let c = self.b[self.i];
                    self.i += 1;
                    match c {
                        b',' => {}
                        b'}' => return Json::Obj(m),
                        _ => panic!("bad object separator at {}", self.i),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    a.push(self.value());
                    self.ws();
                    let c = self.b[self.i];
                    self.i += 1;
                    match c {
                        b',' => {}
                        b']' => return Json::Arr(a),
                        _ => panic!("bad array separator at {}", self.i),
                    }
                }
            }
            b'"' => {
                self.i += 1;
                let start = self.i;
                while self.b[self.i] != b'"' {
                    assert_ne!(self.b[self.i], b'\\', "escapes are not expected");
                    self.i += 1;
                }
                let s = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                self.i += 1;
                Json::Str(s.to_string())
            }
            b'0'..=b'9' => {
                let start = self.i;
                while self.b[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                let s = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                Json::Num(s.parse().unwrap())
            }
            c => panic!("unexpected byte {c:#x} at {}", self.i),
        }
    }
}

fn parse(text: &str) -> Json {
    let mut r = Reader {
        b: text.as_bytes(),
        i: 0,
    };
    let v = r.value();
    while r.i < r.b.len() {
        assert!(r.b[r.i].is_ascii_whitespace(), "trailing data");
        r.i += 1;
    }
    v
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Counter-mode derivation through the PRF the group names, with the
/// vector's fixed data passed verbatim after the 32-bit counter. Returns
/// the PRF output length in bytes with the result.
fn derive(
    mac_mode: &str,
    key: &[u8],
    fixed_data: &[u8],
    out: &mut [u8],
) -> (usize, Result<(), KdfError>) {
    match mac_mode {
        "HMAC-SHA2-256" => (
            32,
            Sp800_108CounterHmacSha256::derive_with_fixed_data_internal(key, fixed_data, out),
        ),
        "HMAC-SHA2-512" => (
            64,
            Sp800_108CounterHmacSha512::derive_with_fixed_data_internal(key, fixed_data, out),
        ),
        other => panic!("no counter-mode PRF in this test for {other}"),
    }
}

#[test]
fn kbkdf_counter_matches_nist_multiblock_vectors() {
    start_module();
    let doc = parse(&read_slice());
    assert_eq!(doc.get("algorithm").str(), "KDF");
    assert_eq!(doc.get("revision").str(), "1.0");

    let groups = doc.get("testGroups").arr();
    let tg_ids: Vec<i64> = groups.iter().map(|g| g.get("tgId").num()).collect();
    assert_eq!(tg_ids, EXPECTED_TG_IDS);

    let mut cases = 0;
    for group in groups {
        let tg_id = group.get("tgId").num();
        assert_eq!(group.get("kdfMode").str(), "counter", "tgId {tg_id}");
        assert_eq!(
            group.get("counterLocation").str(),
            "before fixed data",
            "tgId {tg_id}"
        );
        assert_eq!(group.get("counterLength").num(), 32, "tgId {tg_id}");
        assert_eq!(group.get("testType").str(), "AFT", "tgId {tg_id}");
        let mac_mode = group.get("macMode").str();
        let key_out_bits = usize::try_from(group.get("keyOutLength").num()).unwrap();
        assert_eq!(
            key_out_bits % 8,
            0,
            "tgId {tg_id}: output is not whole bytes"
        );

        let tests = group.get("tests").arr();
        assert!(!tests.is_empty(), "tgId {tg_id} has no tests");
        for tc in tests {
            let tc_id = tc.get("tcId").num();
            let key_in = unhex(tc.get("keyIn").str());
            let fixed_data = unhex(tc.get("fixedData").str());
            let expected = unhex(tc.get("keyOut").str());
            assert_eq!(expected.len() * 8, key_out_bits, "tcId {tc_id}");

            let mut out = vec![0u8; expected.len()];
            let (prf_len, result) = derive(mac_mode, &key_in, &fixed_data, &mut out);
            result.unwrap_or_else(|e| panic!("tcId {tc_id}: {e}"));
            assert!(
                out.len() > prf_len,
                "tcId {tc_id}: {} bytes fit in one {mac_mode} block",
                out.len()
            );
            assert_eq!(
                out,
                expected,
                "tcId {tc_id} ({mac_mode}, {} blocks)",
                out.len().div_ceil(prf_len)
            );
            cases += 1;
        }
    }
    assert_eq!(cases, EXPECTED_TG_IDS.len());
}
