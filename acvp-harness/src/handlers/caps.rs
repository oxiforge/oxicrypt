//! ACVP registration capability builders.
//!
//! These helpers produce the `JsonValue` objects that each handler's
//! `acvp_capabilities()` returns.  The ACVP demo server uses these to
//! generate matching vector sets.
//!
//! Only a handful of well-understood algorithms are wired up for the
//! initial transport dry run: SHA-3 hashing, HMAC-SHA-2-256,
//! AES-CBC, AES-GCM, and HMAC_DRBG. The remaining 70+ handlers can
//! be extended incrementally once the transport loop is proven.

use crate::json::JsonValue;

/// Helper: build a JSON integer.
fn num(n: i64) -> JsonValue {
    JsonValue::Number(n)
}

/// Helper: build a JSON string.
fn str_val(s: &str) -> JsonValue {
    JsonValue::String(s.to_string())
}

/// Helper: build a JSON array of integers.
fn num_array(vals: &[i64]) -> JsonValue {
    JsonValue::Array(vals.iter().map(|v| num(*v)).collect())
}

/// Helper: build a JSON object from key-value pairs.
fn obj(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

// ── SHA-3 family ──────────────────────────────────────────────────

/// Build an ACVP registration block for a SHA-3 hash algorithm.
///
/// ```json
/// {
///   "algorithm": "SHA3-256",
///   "revision": "2.0",
///   "messageLength": [{"min": 0, "max": 65536, "increment": 8}]
/// }
/// ```
pub fn sha3_capability(algorithm: &str, _digest_bits: i64) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("2.0")),
        (
            "messageLength",
            JsonValue::Array(vec![obj(vec![
                ("min", num(0)),
                ("max", num(65536)),
                ("increment", num(8)),
            ])]),
        ),
    ])
}

// ── HMAC family ───────────────────────────────────────────────────

/// Build an ACVP registration block for an HMAC algorithm.
///
/// ```json
/// {
///   "algorithm": "HMAC-SHA2-256",
///   "revision": "1.0",
///   "keyLen": [{"min": 8, "max": 524_288, "increment": 8}],
///   "macLen": [{"min": 32, "max": 256, "increment": 8}]
/// }
/// ```
pub fn hmac_capability(algorithm: &str, mac_bits: i64) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        (
            "keyLen",
            JsonValue::Array(vec![obj(vec![
                ("min", num(8)),
                ("max", num(524_288)),
                ("increment", num(8)),
            ])]),
        ),
        (
            "macLen",
            JsonValue::Array(vec![obj(vec![
                ("min", num(32)),
                ("max", num(mac_bits)),
                ("increment", num(8)),
            ])]),
        ),
    ])
}

// ── AES-CBC ───────────────────────────────────────────────────────

/// Build an ACVP registration block for AES-CBC.
pub fn aes_cbc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-CBC")),
        ("revision", str_val("1.0")),
        ("direction", JsonValue::Array(vec![str_val("encrypt"), str_val("decrypt")])),
        ("keyLen", num_array(&[128, 192, 256])),
    ])
}

// ── AES-GCM ──────────────────────────────────────────────────────

/// Build an ACVP registration block for AES-GCM.
pub fn aes_gcm_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-GCM")),
        ("revision", str_val("1.0")),
        ("direction", JsonValue::Array(vec![str_val("encrypt"), str_val("decrypt")])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("ivLen", num_array(&[96])),
        ("ivGen", str_val("external")),
        ("tagLen", num_array(&[128])),
        (
            "payloadLen",
            JsonValue::Array(vec![obj(vec![
                ("min", num(0)),
                ("max", num(65536)),
                ("increment", num(8)),
            ])]),
        ),
        (
            "aadLen",
            JsonValue::Array(vec![obj(vec![
                ("min", num(0)),
                ("max", num(65536)),
                ("increment", num(8)),
            ])]),
        ),
    ])
}

// ── HMAC_DRBG ────────────────────────────────────────────────────

/// Build an ACVP registration block for HMAC_DRBG.
pub fn hmac_drbg_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("hmacDRBG")),
        ("revision", str_val("1.0")),
        (
            "predResistance",
            JsonValue::Array(vec![JsonValue::Bool(true), JsonValue::Bool(false)]),
        ),
        (
            "capabilities",
            JsonValue::Array(vec![
                obj(vec![
                    ("mode", str_val("SHA2-256")),
                    ("derFunc", JsonValue::Bool(false)),
                ]),
                obj(vec![
                    ("mode", str_val("SHA2-384")),
                    ("derFunc", JsonValue::Bool(false)),
                ]),
                obj(vec![
                    ("mode", str_val("SHA2-512")),
                    ("derFunc", JsonValue::Bool(false)),
                ]),
            ]),
        ),
    ])
}
