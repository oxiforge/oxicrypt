//! Shared by the integration tests: initialisation for either build mode,
//! the fixture's directories, and reading published vectors from the
//! repository's vendored ACVP slices.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use oxicrypt::{InitError, Module, Profile};

/// `Module::init`, or `Module::init_unpinned` in a crate built unpinned.
#[allow(clippy::result_large_err)]
pub(crate) fn init(profile: Profile) -> Result<Module, InitError> {
    #[cfg(oxicrypt_pinned)]
    let result = Module::init(profile);
    #[cfg(not(oxicrypt_pinned))]
    let result = Module::init_unpinned(profile);
    result
}

/// The directory the crate was linked against (the fixture's `signed/`).
pub(crate) fn lib_dir() -> PathBuf {
    PathBuf::from(env!("OXICRYPT_BINDINGS_LIB_DIR"))
}

/// The fixture's root: the parent of `signed/`, holding `unsigned/` and
/// `second-key/` beside it.
pub(crate) fn fixture_dir() -> PathBuf {
    lib_dir().parent().unwrap().to_path_buf()
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// SHA-256 (FIPS 180-4 §6.2), computed here because the crate wraps no
/// SHA-256 and the published ML-DSA-44 and ML-DSA-65 key-generation answers
/// are SHA2-256(pk ‖ sk). `sha256_known_answers` in `unrestricted.rs` pins
/// it. The constants and names are FIPS 180-4's, as the standard prints
/// them.
#[allow(clippy::unreadable_literal, clippy::many_single_char_names)]
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

/// The hex field `field` of test case `tc_id` in a vendored ACVP slice,
/// `vendor/nist/acvp-server/gen-val/json-files/<dir>/<file>`. Each slice
/// records its upstream commit and path in its `_source` header.
pub(crate) fn acvp(dir: &str, file: &str, tc_id: u32, field: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vendor/nist/acvp-server/gen-val/json-files")
        .join(dir)
        .join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (this test runs in the workspace)",
            path.display()
        )
    });
    let groups = text.find("\"testGroups\"").expect("testGroups");
    let text = &text[groups..];
    let case = format!("\"tcId\": {tc_id},");
    let start = text
        .find(&case)
        .unwrap_or_else(|| panic!("tcId {tc_id} not in {}", path.display()));
    let rest = &text[start + case.len()..];
    let end = rest.find("\"tcId\"").unwrap_or(rest.len());
    let rest = &rest[..end];
    let key = format!("\"{field}\": \"");
    let at = rest
        .find(&key)
        .unwrap_or_else(|| panic!("{field} not in tcId {tc_id} of {}", path.display()));
    let value = &rest[at + key.len()..];
    unhex(&value[..value.find('"').unwrap()])
}

/// The fingerprint of the signed fixture library's verifying key, as the
/// fixture's signer reports it with `--show`.
pub(crate) fn fixture_fingerprint() -> String {
    let signer = fixture_dir().join("bin/oxicrypt-integrity-sign");
    let out = std::process::Command::new(&signer)
        .arg("--show")
        .arg(lib_dir().join("liboxicrypt_ffi.so"))
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", signer.display()));
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("verify key: "))
        .expect("--show reports the verify key")
        .to_owned()
}

/// The file name the library is delivered under, which the program asks the
/// loader for: the target of the fixture's `liboxicrypt_ffi.so` link
/// (`liboxicrypt_ffi.so.<ABI>`), or the plain name for a library without one.
pub(crate) fn delivered_name() -> String {
    let plain = lib_dir().join("liboxicrypt_ffi.so");
    std::fs::read_link(&plain).map_or_else(
        |_| "liboxicrypt_ffi.so".to_owned(),
        |target| target.to_string_lossy().into_owned(),
    )
}
