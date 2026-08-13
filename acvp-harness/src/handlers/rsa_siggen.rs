//! RSA ACVP handler — `sigGen` mode, revision `FIPS186-5`.
//!
//! **SigGen** (`RSA` / `sigGen` / `FIPS186-5`): Given a private key
//! and a message, generate an RSA signature and return it.
//!
//! Supported configurations:
//! - `sigType = "pkcs1v1.5"`, `modulo ∈ {2048, 3072, 4096}`,
//!   `hashAlg = "SHA2-256"` — non-CRT path (group provides `n`, `d`),
//!   or CRT path with `keyMode = "crt"` (group provides CRT components)
//! - `sigType = "pss"`, `modulo ∈ {2048, 3072, 4096}`,
//!   `hashAlg = "SHA2-256"`, `saltLen = 32` — CRT path (group provides
//!   CRT components) or non-CRT path with `keyMode = "standard"`
//!
//! All four combinations of (sigType × keyMode) are supported at each
//! modulus size. The CRT path uses Bellcore verify-after-sign.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// RSA SigGen dispatcher.
pub struct RsaSigGenHandler;

impl AlgorithmHandler for RsaSigGenHandler {
    fn algorithm(&self) -> &'static str {
        "RSA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("sigGen")
    }
    fn revision(&self) -> &'static str {
        "FIPS186-5"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::rsa_siggen_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_siggen_group(group)
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Decode a hex-encoded string field from a JSON object.
fn decode_hex_field(obj: &JsonValue, name: &'static str) -> Result<Vec<u8>, DispatchError> {
    let h = obj
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(name))?;
    Ok(hex::decode(h)?)
}

/// Parse a big-endian hex field into a fixed-size array, left-padding
/// with zeroes if the decoded value is shorter than `LEN`.
fn decode_fixed<const LEN: usize>(
    obj: &JsonValue,
    name: &'static str,
) -> Result<[u8; LEN], DispatchError> {
    let raw = decode_hex_field(obj, name)?;
    if raw.len() > LEN {
        return Err(DispatchError::Crypto("RSA SigGen: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

/// Convert big-endian bytes to `u64`.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, DispatchError> {
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "RSA SigGen: e exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}

// ── Group handler ──────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn handle_siggen_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "GDT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let sig_type = group
        .get("sigType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("sigType"))?;

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;

    let hash_alg = group
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hashAlg"))?;
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "RSA SigGen: only SHA2-256 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    // If keyMode is absent, infer from sigType for backwards
    // compatibility with upstream vectors: pkcs1v1.5 defaults to
    // "standard" (non-CRT, d-only), pss defaults to "crt".
    let key_mode = group
        .get("keyMode")
        .and_then(JsonValue::as_str)
        .unwrap_or(match sig_type {
            "pss" => "crt",
            _ => "standard",
        });

    let (n_hex, e_hex, results) = match modulo {
        2048 => handle_siggen_2048(group, tests, sig_type, key_mode)?,
        3072 => handle_siggen_3072(group, tests, sig_type, key_mode)?,
        4096 => handle_siggen_4096(group, tests, sig_type, key_mode)?,
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only modulo 2048/3072/4096 are supported",
            ));
        }
    };

    // Echo group-level n + e in the response (live GDT requires it
    // because the server has no prior knowledge of the IUT's keypair;
    // offline shape echoes the values from the prompt for consistency
    // — mirrors the ECDSA sigGen response shape).
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("n".to_string(), JsonValue::String(n_hex)),
        ("e".to_string(), JsonValue::String(e_hex)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Per-modulus signing ─────────────────────────────────────────────

/// Sign with RSA-2048 keys.
///
/// Dual-mode per `draft-celi-acvp-rsa §6.2`:
/// - **Offline (vendored kat-slice)**: group carries `n`/`e`/`p`/`q`/
///   `dmp1`/`dmq1`/`iqmp` (CRT) or `n`/`d` (standard); signature is
///   deterministic against the supplied keypair and salt (for PSS).
/// - **Live GDT**: group carries only `modulo`/`hashAlg`/`sigType`;
///   IUT generates its own CRT keypair via `os_entropy`-seeded DRBG
///   and signs every test with it (and a fresh per-test salt for PSS).
///   Server validates each signature with the IUT-emitted `n` + `e`.
///   Mirrors the ECDSA sigGen and KAS-FFC-SSC live-generative shape.
#[allow(clippy::too_many_lines)]
fn handle_siggen_2048(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
    const H: usize = oxicrypt_rsa::RSA_2048_CRT_HALF_BYTES;

    if group.get("n").is_none() {
        return live_siggen_2048(tests, sig_type);
    }

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PKCS#1v1.5 CRT sign failed",
                ))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_internal(&n, &d, &message)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa_pss_sign_2048_sha256_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto("RSA SigGen: PSS CRT sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa_pss_sign_2048_sha256_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    // Offline shape: echo n + e from the prompt (e defaults to 010001
    // when the prompt omits it — standard-keyMode pkcs1v1.5 carries
    // only n + d, so the response echoes the default public exponent).
    let n_bytes: [u8; N] = decode_fixed(group, "n")?;
    let n_hex = hex::encode_upper(&n_bytes);
    let e_hex = group
        .get("e")
        .and_then(JsonValue::as_str)
        .map_or_else(|| "010001".to_string(), str::to_uppercase);
    Ok((n_hex, e_hex, results))
}

/// Live GDT sign with an IUT-generated RSA-2048 keypair.
///
/// Per `draft-celi-acvp-rsa §6.2`: the server emits only
/// `(message, tcId, deferred)` per test and validates the resulting
/// signature against the IUT-emitted group-level `n` + `e`. The IUT
/// samples its own keypair (CRT internal API; the power-up KAT covers
/// the non-CRT sign path) and — for PSS — its own fresh salt
/// per signature via `os_entropy::read_os_entropy`.
#[allow(clippy::similar_names)]
fn live_siggen_2048(
    tests: &[JsonValue],
    sig_type: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
    let mut drbg = super::os_entropy::build_seeded_drbg()?;
    let km = oxicrypt_rsa::keygen::generate_2048(&mut drbg, 65537)
        .map_err(|_| DispatchError::Crypto("RSA SigGen: 2048 key generation failed"))?;
    let n_bytes: [u8; N] = km.n.to_be_bytes();
    let p_bytes = km.p.to_be_bytes();
    let q_bytes = km.q.to_be_bytes();
    let dp_bytes = km.dp.to_be_bytes();
    let dq_bytes = km.dq.to_be_bytes();
    let qinv_bytes = km.qinv.to_be_bytes();

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for tc in tests {
        let tc_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let message = decode_hex_field(tc, "message")?;
        let sig = match sig_type {
            "pkcs1v1.5" => oxicrypt_rsa::rsa_pkcs1_v15_sign_2048_sha256_crt_internal(
                &n_bytes,
                65537,
                &p_bytes,
                &q_bytes,
                &dp_bytes,
                &dq_bytes,
                &qinv_bytes,
                &message,
            )
            .ok_or(DispatchError::Crypto(
                "RSA SigGen: live PKCS#1v1.5 2048 sign failed",
            ))?,
            "pss" => {
                let mut salt = [0u8; 32];
                super::os_entropy::read_os_entropy(&mut salt)?;
                oxicrypt_rsa::rsa_pss_sign_2048_sha256_crt_internal(
                    &n_bytes,
                    65537,
                    &p_bytes,
                    &q_bytes,
                    &dp_bytes,
                    &dq_bytes,
                    &qinv_bytes,
                    &message,
                    &salt,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: live PSS 2048 sign failed",
                ))?
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
                ));
            }
        };
        results.push(sig_result(tc_id, &sig));
    }
    Ok((hex::encode_upper(&n_bytes), "010001".to_string(), results))
}

/// Sign with RSA-3072 keys.
fn handle_siggen_3072(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = 384;
    const H: usize = 192;

    if group.get("n").is_none() {
        return live_siggen_3072(tests, sig_type);
    }

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa3072::pkcs1_v15_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PKCS#1v1.5 CRT 3072 sign failed",
                ))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa3072::pkcs1_v15_sign_internal(&n, &d, &message).ok_or(
                    DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 3072 sign failed"),
                )?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa3072::pss_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PSS CRT 3072 sign failed",
                ))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa3072::pss_sign_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS 3072 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    let n_bytes: [u8; N] = decode_fixed(group, "n")?;
    let n_hex = hex::encode_upper(&n_bytes);
    let e_hex = group
        .get("e")
        .and_then(JsonValue::as_str)
        .map_or_else(|| "010001".to_string(), str::to_uppercase);
    Ok((n_hex, e_hex, results))
}

/// Live GDT sign with an IUT-generated RSA-3072 keypair. See
/// [`live_siggen_2048`] for the dual-mode rationale.
#[allow(clippy::similar_names)]
fn live_siggen_3072(
    tests: &[JsonValue],
    sig_type: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = 384;
    let mut drbg = super::os_entropy::build_seeded_drbg()?;
    let km = oxicrypt_rsa::keygen3072::generate_3072(&mut drbg, 65537)
        .map_err(|_| DispatchError::Crypto("RSA SigGen: 3072 key generation failed"))?;
    let n_bytes: [u8; N] = km.n.to_be_bytes();
    let p_bytes = km.p.to_be_bytes();
    let q_bytes = km.q.to_be_bytes();
    let dp_bytes = km.dp.to_be_bytes();
    let dq_bytes = km.dq.to_be_bytes();
    let qinv_bytes = km.qinv.to_be_bytes();

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for tc in tests {
        let tc_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let message = decode_hex_field(tc, "message")?;
        let sig = match sig_type {
            "pkcs1v1.5" => oxicrypt_rsa::rsa3072::pkcs1_v15_sign_crt_internal(
                &n_bytes,
                65537,
                &p_bytes,
                &q_bytes,
                &dp_bytes,
                &dq_bytes,
                &qinv_bytes,
                &message,
            )
            .ok_or(DispatchError::Crypto(
                "RSA SigGen: live PKCS#1v1.5 3072 sign failed",
            ))?,
            "pss" => {
                let mut salt = [0u8; 32];
                super::os_entropy::read_os_entropy(&mut salt)?;
                oxicrypt_rsa::rsa3072::pss_sign_crt_internal(
                    &n_bytes,
                    65537,
                    &p_bytes,
                    &q_bytes,
                    &dp_bytes,
                    &dq_bytes,
                    &qinv_bytes,
                    &message,
                    &salt,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: live PSS 3072 sign failed",
                ))?
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
                ));
            }
        };
        results.push(sig_result(tc_id, &sig));
    }
    Ok((hex::encode_upper(&n_bytes), "010001".to_string(), results))
}

/// Sign with RSA-4096 keys.
fn handle_siggen_4096(
    group: &JsonValue,
    tests: &[JsonValue],
    sig_type: &str,
    key_mode: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = 512;
    const H: usize = 256;

    if group.get("n").is_none() {
        return live_siggen_4096(tests, sig_type);
    }

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    match (sig_type, key_mode) {
        ("pkcs1v1.5", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa4096::pkcs1_v15_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PKCS#1v1.5 CRT 4096 sign failed",
                ))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pkcs1v1.5", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let sig = oxicrypt_rsa::rsa4096::pkcs1_v15_sign_internal(&n, &d, &message).ok_or(
                    DispatchError::Crypto("RSA SigGen: PKCS#1v1.5 4096 sign failed"),
                )?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", "crt") => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let e_bytes = decode_hex_field(group, "e")?;
            let e = bytes_to_u64(&e_bytes)?;
            let p: [u8; H] = decode_fixed(group, "p")?;
            let q: [u8; H] = decode_fixed(group, "q")?;
            let dp: [u8; H] = decode_fixed(group, "dmp1")?;
            let dq: [u8; H] = decode_fixed(group, "dmq1")?;
            let qinv: [u8; H] = decode_fixed(group, "iqmp")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa4096::pss_sign_crt_internal(
                    &n, e, &p, &q, &dp, &dq, &qinv, &message, &salt,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: PSS CRT 4096 sign failed",
                ))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        ("pss", _) => {
            let n: [u8; N] = decode_fixed(group, "n")?;
            let d: [u8; N] = decode_fixed(group, "d")?;

            for tc in tests {
                let tc_id = tc
                    .get("tcId")
                    .and_then(JsonValue::as_i64)
                    .ok_or(DispatchError::MissingField("tcId"))?;
                let message = decode_hex_field(tc, "message")?;
                let salt: [u8; 32] = decode_fixed(tc, "salt")?;
                let sig = oxicrypt_rsa::rsa4096::pss_sign_internal(&n, &d, &message, &salt)
                    .ok_or(DispatchError::Crypto("RSA SigGen: PSS 4096 sign failed"))?;
                results.push(sig_result(tc_id, &sig));
            }
        }
        _ => {
            return Err(DispatchError::Unsupported(
                "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
            ));
        }
    }
    let n_bytes: [u8; N] = decode_fixed(group, "n")?;
    let n_hex = hex::encode_upper(&n_bytes);
    let e_hex = group
        .get("e")
        .and_then(JsonValue::as_str)
        .map_or_else(|| "010001".to_string(), str::to_uppercase);
    Ok((n_hex, e_hex, results))
}

/// Live GDT sign with an IUT-generated RSA-4096 keypair. See
/// [`live_siggen_2048`] for the dual-mode rationale.
#[allow(clippy::similar_names)]
fn live_siggen_4096(
    tests: &[JsonValue],
    sig_type: &str,
) -> Result<(String, String, Vec<JsonValue>), DispatchError> {
    const N: usize = 512;
    let mut drbg = super::os_entropy::build_seeded_drbg()?;
    let km = oxicrypt_rsa::keygen4096::generate_4096(&mut drbg, 65537)
        .map_err(|_| DispatchError::Crypto("RSA SigGen: 4096 key generation failed"))?;
    let n_bytes: [u8; N] = km.n.to_be_bytes();
    let p_bytes = km.p.to_be_bytes();
    let q_bytes = km.q.to_be_bytes();
    let dp_bytes = km.dp.to_be_bytes();
    let dq_bytes = km.dq.to_be_bytes();
    let qinv_bytes = km.qinv.to_be_bytes();

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for tc in tests {
        let tc_id = tc
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;
        let message = decode_hex_field(tc, "message")?;
        let sig = match sig_type {
            "pkcs1v1.5" => oxicrypt_rsa::rsa4096::pkcs1_v15_sign_crt_internal(
                &n_bytes,
                65537,
                &p_bytes,
                &q_bytes,
                &dp_bytes,
                &dq_bytes,
                &qinv_bytes,
                &message,
            )
            .ok_or(DispatchError::Crypto(
                "RSA SigGen: live PKCS#1v1.5 4096 sign failed",
            ))?,
            "pss" => {
                let mut salt = [0u8; 32];
                super::os_entropy::read_os_entropy(&mut salt)?;
                oxicrypt_rsa::rsa4096::pss_sign_crt_internal(
                    &n_bytes,
                    65537,
                    &p_bytes,
                    &q_bytes,
                    &dp_bytes,
                    &dq_bytes,
                    &qinv_bytes,
                    &message,
                    &salt,
                )
                .ok_or(DispatchError::Crypto(
                    "RSA SigGen: live PSS 4096 sign failed",
                ))?
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "RSA SigGen: only pkcs1v1.5 and pss sigTypes are supported",
                ));
            }
        };
        results.push(sig_result(tc_id, &sig));
    }
    Ok((hex::encode_upper(&n_bytes), "010001".to_string(), results))
}

// ── Result helper ──────────────────────────────────────────────────

fn sig_result(tc_id: i64, sig: &[u8]) -> JsonValue {
    JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "signature".to_string(),
            JsonValue::String(hex::encode_upper(sig)),
        ),
    ])
}
