//! Every NIST ACVP LMS sigVer test case, against every parameter-set pair.
//!
//! Source: usnistgov/ACVP-Server @ 3611942ea10c070dd8bc6afec5682d56c307de8a,
//! `gen-val/json-files/LMS-sigVer-1.0/internalProjection.json`, vendored
//! byte-for-byte under `vendor/nist/acvp-server/` and pinned with its
//! SHA-256 in `vendor/nist/MANIFEST.toml`.
//!
//! The projection holds one test group per (lmsMode, lmOtsMode) pair, 80 in
//! all, each with four test cases: one NIST marks valid ("no modification")
//! and three it marks invalid ("modify message", "modify signature",
//! "modify signature header"). This test runs all 320 through the matching
//! per-pair `verify_internal` and asserts NIST's `testPassed` verdict for
//! each. Nothing in the file was produced by this crate.
//!
//! Reference: RFC 8554 Algorithm 6; SP 800-208 §4.1–§4.4, §8.2.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

/// Stands in for the pre-operational integrity test, which cannot pass in an
/// unsigned test binary.
const UNSIGNED_TEST_BINARY: &[oxicrypt_module::KatEntry] = &[oxicrypt_module::KatEntry {
    name: "integrity not verifiable in an unsigned test binary",
    run: || Ok(()),
}];

/// Brings the module out of `PowerOff` so that a test can call the
/// `*_internal` functions, which refuse until the self-tests have started.
/// A second call in the same process is a no-op.
fn start_module() {
    let _ = oxicrypt_module::initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
    assert_eq!(oxicrypt_module::require_self_test_started(), Ok(()));
}

use std::collections::BTreeMap;

/// Workspace-relative path of the vendored ACVP sigVer projection.
const PROJECTION_PATH: &str =
    "vendor/nist/acvp-server/gen-val/json-files/LMS-sigVer-1.0/internalProjection.json";

fn read_projection() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PROJECTION_PATH);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ── Minimal JSON reader ─────────────────────────────────────────────────────
//
// The workspace carries no JSON dependency. The projection uses only
// objects, arrays, strings without escapes, integers and booleans, which is
// all this reader accepts; anything else panics rather than being skipped.

#[derive(Debug)]
enum Json {
    Obj(BTreeMap<String, Json>),
    Arr(Vec<Json>),
    Str(String),
    Num(i64),
    Bool(bool),
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
    fn bool(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            other => panic!("not a bool: {other:?}"),
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
                self.ws();
                if self.b[self.i] == b'}' {
                    self.i += 1;
                    return Json::Obj(m);
                }
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
                self.ws();
                if self.b[self.i] == b']' {
                    self.i += 1;
                    return Json::Arr(a);
                }
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
            b't' if self.b[self.i..].starts_with(b"true") => {
                self.i += 4;
                Json::Bool(true)
            }
            b'f' if self.b[self.i..].starts_with(b"false") => {
                self.i += 5;
                Json::Bool(false)
            }
            b'0'..=b'9' | b'-' => {
                let start = self.i;
                self.i += 1;
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

// ── Per-pair routing ────────────────────────────────────────────────────────

/// Verify through the per-pair verifier named by the group's modes.
///
/// `None` means no pair in this crate carries those modes. A public key or
/// signature whose length does not match the pair cannot be valid and is
/// reported as a rejection. The caller first asserts that every signature
/// in a group has one length, so a length mismatch cannot stand in for a
/// verdict on a single case.
macro_rules! router {
    ($($lms:literal, $lmots:literal => $pair:ident;)*) => {
        const PAIRS: usize = [$(stringify!($pair)),*].len();

        fn verify(lms: &str, lmots: &str, pk: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
            match (lms, lmots) {
                $(($lms, $lmots) => {
                    use oxicrypt_lms::$pair as p;
                    let (Ok(pk), Ok(sig)) = (
                        <[u8; p::PUBLIC_KEY_LEN]>::try_from(pk),
                        <[u8; p::SIGNATURE_LEN]>::try_from(sig),
                    ) else {
                        return Some(false);
                    };
                    Some(p::verify_internal(&pk, msg, &sig).unwrap())
                })*
                _ => None,
            }
        }
    };
}

router! {
    "LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W1" => lms_sha256_m32_h5_w1;
    "LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2" => lms_sha256_m32_h5_w2;
    "LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4" => lms_sha256_m32_h5_w4;
    "LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8" => lms_sha256_m32_h5_w8;
    "LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W1" => lms_sha256_m32_h10_w1;
    "LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W2" => lms_sha256_m32_h10_w2;
    "LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4" => lms_sha256_m32_h10_w4;
    "LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W8" => lms_sha256_m32_h10_w8;
    "LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W1" => lms_sha256_m32_h15_w1;
    "LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W2" => lms_sha256_m32_h15_w2;
    "LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4" => lms_sha256_m32_h15_w4;
    "LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W8" => lms_sha256_m32_h15_w8;
    "LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W1" => lms_sha256_m32_h20_w1;
    "LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W2" => lms_sha256_m32_h20_w2;
    "LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4" => lms_sha256_m32_h20_w4;
    "LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W8" => lms_sha256_m32_h20_w8;
    "LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W1" => lms_sha256_m32_h25_w1;
    "LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W2" => lms_sha256_m32_h25_w2;
    "LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W4" => lms_sha256_m32_h25_w4;
    "LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8" => lms_sha256_m32_h25_w8;
    "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1" => lms_sha256_m24_h5_w1;
    "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2" => lms_sha256_m24_h5_w2;
    "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4" => lms_sha256_m24_h5_w4;
    "LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8" => lms_sha256_m24_h5_w8;
    "LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W1" => lms_sha256_m24_h10_w1;
    "LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2" => lms_sha256_m24_h10_w2;
    "LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W4" => lms_sha256_m24_h10_w4;
    "LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W8" => lms_sha256_m24_h10_w8;
    "LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W1" => lms_sha256_m24_h15_w1;
    "LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W2" => lms_sha256_m24_h15_w2;
    "LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W4" => lms_sha256_m24_h15_w4;
    "LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8" => lms_sha256_m24_h15_w8;
    "LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W1" => lms_sha256_m24_h20_w1;
    "LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W2" => lms_sha256_m24_h20_w2;
    "LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4" => lms_sha256_m24_h20_w4;
    "LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W8" => lms_sha256_m24_h20_w8;
    "LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W1" => lms_sha256_m24_h25_w1;
    "LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W2" => lms_sha256_m24_h25_w2;
    "LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W4" => lms_sha256_m24_h25_w4;
    "LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8" => lms_sha256_m24_h25_w8;
    "LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1" => lms_shake_m32_h5_w1;
    "LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2" => lms_shake_m32_h5_w2;
    "LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4" => lms_shake_m32_h5_w4;
    "LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8" => lms_shake_m32_h5_w8;
    "LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W1" => lms_shake_m32_h10_w1;
    "LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W2" => lms_shake_m32_h10_w2;
    "LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W4" => lms_shake_m32_h10_w4;
    "LMS_SHAKE_M32_H10", "LMOTS_SHAKE_N32_W8" => lms_shake_m32_h10_w8;
    "LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W1" => lms_shake_m32_h15_w1;
    "LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W2" => lms_shake_m32_h15_w2;
    "LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W4" => lms_shake_m32_h15_w4;
    "LMS_SHAKE_M32_H15", "LMOTS_SHAKE_N32_W8" => lms_shake_m32_h15_w8;
    "LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W1" => lms_shake_m32_h20_w1;
    "LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W2" => lms_shake_m32_h20_w2;
    "LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W4" => lms_shake_m32_h20_w4;
    "LMS_SHAKE_M32_H20", "LMOTS_SHAKE_N32_W8" => lms_shake_m32_h20_w8;
    "LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W1" => lms_shake_m32_h25_w1;
    "LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W2" => lms_shake_m32_h25_w2;
    "LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W4" => lms_shake_m32_h25_w4;
    "LMS_SHAKE_M32_H25", "LMOTS_SHAKE_N32_W8" => lms_shake_m32_h25_w8;
    "LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1" => lms_shake_m24_h5_w1;
    "LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2" => lms_shake_m24_h5_w2;
    "LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4" => lms_shake_m24_h5_w4;
    "LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8" => lms_shake_m24_h5_w8;
    "LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W1" => lms_shake_m24_h10_w1;
    "LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W2" => lms_shake_m24_h10_w2;
    "LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W4" => lms_shake_m24_h10_w4;
    "LMS_SHAKE_M24_H10", "LMOTS_SHAKE_N24_W8" => lms_shake_m24_h10_w8;
    "LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W1" => lms_shake_m24_h15_w1;
    "LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W2" => lms_shake_m24_h15_w2;
    "LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W4" => lms_shake_m24_h15_w4;
    "LMS_SHAKE_M24_H15", "LMOTS_SHAKE_N24_W8" => lms_shake_m24_h15_w8;
    "LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W1" => lms_shake_m24_h20_w1;
    "LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W2" => lms_shake_m24_h20_w2;
    "LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W4" => lms_shake_m24_h20_w4;
    "LMS_SHAKE_M24_H20", "LMOTS_SHAKE_N24_W8" => lms_shake_m24_h20_w8;
    "LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W1" => lms_shake_m24_h25_w1;
    "LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W2" => lms_shake_m24_h25_w2;
    "LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W4" => lms_shake_m24_h25_w4;
    "LMS_SHAKE_M24_H25", "LMOTS_SHAKE_N24_W8" => lms_shake_m24_h25_w8;
}

#[test]
fn every_acvp_sigver_case_matches_nist_verdict() {
    start_module();
    let projection = read_projection();
    let root = parse(&projection);
    assert_eq!(root.get("algorithm").str(), "LMS");
    assert_eq!(root.get("mode").str(), "sigVer");

    let groups = root.get("testGroups").arr();
    assert_eq!(groups.len(), 80, "one test group per pair");
    assert_eq!(PAIRS, 80, "one route per pair");

    let mut seen_pairs = std::collections::BTreeSet::new();
    let mut verdicts: BTreeMap<(bool, String), usize> = BTreeMap::new();
    let mut failures = Vec::new();

    for group in groups {
        let tg_id = group.get("tgId").num();
        let lms = group.get("lmsMode").str();
        let lmots = group.get("lmOtsMode").str();
        assert!(
            seen_pairs.insert((lms.to_string(), lmots.to_string())),
            "tgId {tg_id}: pair {lms}/{lmots} appears twice"
        );
        let pk = unhex(group.get("publicKey").str());
        let tests = group.get("tests").arr();
        assert_eq!(tests.len(), 4, "tgId {tg_id}: four cases per group");
        let sig_lens: std::collections::BTreeSet<usize> = tests
            .iter()
            .map(|t| t.get("signature").str().len())
            .collect();
        assert_eq!(
            sig_lens.len(),
            1,
            "tgId {tg_id}: signatures differ in length {sig_lens:?}"
        );

        for t in tests {
            let tc_id = t.get("tcId").num();
            let expected = t.get("testPassed").bool();
            let reason = t.get("reason").str().to_string();
            let msg = unhex(t.get("message").str());
            let sig = unhex(t.get("signature").str());
            let got = verify(lms, lmots, &pk, &msg, &sig)
                .unwrap_or_else(|| panic!("tgId {tg_id}: no verifier for {lms}/{lmots}"));
            if got != expected {
                failures.push(format!(
                    "tgId {tg_id} tcId {tc_id} ({lms}/{lmots}, {reason}): expected {expected}, got {got}"
                ));
            }
            *verdicts.entry((expected, reason)).or_default() += 1;
        }
    }

    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(seen_pairs.len(), 80);
    // Every case was counted, and the valid and invalid cases are where NIST
    // puts them: 80 accepts, and 80 rejects for each kind of modification.
    let count = |passed: bool, reason: &str| verdicts.get(&(passed, reason.to_string())).copied();
    assert_eq!(verdicts.values().sum::<usize>(), 320);
    assert_eq!(count(true, "no modification"), Some(80));
    assert_eq!(count(false, "modify message"), Some(80));
    assert_eq!(count(false, "modify signature"), Some(80));
    assert_eq!(count(false, "modify signature header"), Some(80));
}

/// The router fires on what it must: modes naming no pair have no route,
/// and a public key of the wrong length is a rejection.
#[test]
fn router_refuses_unknown_modes() {
    start_module();
    assert!(verify("LMS_SHA256_M32_H30", "LMOTS_SHA256_N32_W4", &[], &[], &[]).is_none());
    assert!(verify("LMS_SHA256_M32_H5", "LMOTS_SHAKE_N32_W4", &[], &[], &[]).is_none());
    assert_eq!(
        verify(
            "LMS_SHA256_M32_H5",
            "LMOTS_SHA256_N32_W4",
            &[0u8; 3],
            &[],
            &[]
        ),
        Some(false)
    );
}
