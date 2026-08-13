//! KTS-IFC ACVP handler — revision `Sp800-56Br2` (no mode).
//!
//! **KTS-IFC** (`KTS-IFC` / `Sp800-56Br2`): RSAES-OAEP key transport
//! per SP 800-56Br2 §7.2.2.2 (KTS-OAEP basic form). The ACVTS demo
//! algorithm catalog registers this algorithm with **no mode field**.
//! The server's lookup key is `KTS-IFC-Sp800-56Br2`; sending a mode
//! segment would mis-key. The `KAS-{ECC,FFC}-SSC` and KMACXOF entries
//! follow the same catalog-mapping pattern.
//!
//! See [`crate::handlers::rsa_oaep`] for the standalone OAEP handler
//! that exercises the same primitive surface over offline KAT-slice
//! replay — its `acvp_capabilities → None` suppresses live
//! advertisement of the catalog-incorrect `RSA-OAEP-RFC8017` triple;
//! `KtsIfcHandler` is its live-grade counterpart.
//!
//! **Test types.** Only `AFT` (Algorithm Functional Test) is
//! supported — KTS is a transport scheme without a candidate-value
//! verification arm, so `VAL` is not defined for KTS schemes in
//! `draft-hammett-acvp-kas-ifc` §6.1 / §9.4 (the example test
//! vectors are AFT-only).
//!
//! **Test group shape (`draft-hammett-acvp-kas-ifc` §9.1 + §9.4).**
//! Each group declares `scheme` (`KTS-OAEP-basic` is the only one we
//! advertise), `kasRole` (`initiator` or `responder`),
//! `keyGenerationMethod`, `modulo` (2048/3072/4096),
//! `l` (key-material length in bits), `iutId`, `serverId`, and a
//! `ktsConfiguration` sub-object with `hashAlg`,
//! `associatedDataPattern`, `encoding`.
//!
//! **Per-test-case shape (`draft-hammett-acvp-kas-ifc` §9.2 + §9.4).**
//! The `kasRole` flag inverts which keypair the IUT operates on:
//! - `kasRole = "initiator"` — IUT holds no keypair; server provides
//!   its public key as `serverN`/`serverE`. IUT samples random
//!   `Z` of `l/8` bytes and an OAEP seed of 32 bytes (SHA-256
//!   HLEN), encrypts `Z` under the server's pubkey, returns
//!   `{tcId, iutC, dkm}` where `dkm = Z`.
//! - `kasRole = "responder"` — server provides the IUT's keypair as
//!   `iutN`/`iutE`/`iutP`/`iutQ`/`iutD` together with a ciphertext
//!   `serverC`. IUT decrypts `serverC` (non-CRT path with
//!   `iutN`/`iutD`) to recover `Z`, returns `{tcId, dkm}` where
//!   `dkm = Z`.
//!
//! For `KTS-OAEP-basic` the derived keying material is the
//! transported secret itself — no KDF, no MAC. The
//! `KTS-OAEP-Party_V-confirmation` variant adds a KDF + MAC step
//! and is explicitly out of scope (see
//! [`crate::handlers::caps::kts_ifc_capability`] for the cap-level
//! exclusion rationale).
//!
//! **Modulus dispatch.** A 6-arm match across
//! (`kasRole` ∈ {initiator, responder}) × (`modulo` ∈ {2048, 3072,
//! 4096}) routes to the matching primitive surface:
//! - 2048: bespoke
//!   `oxicrypt_rsa::rsa_oaep_{encrypt,decrypt_nocrt}_2048_sha256_internal`
//!   (lib.rs).
//! - 3072/4096: macro-generated
//!   `oxicrypt_rsa::rsa{3072,4096}::oaep_{encrypt,decrypt_nocrt}_internal`
//!   (`rsa_wide_impl.rs`).
//!
//! The non-CRT decrypt path uses `iutN`+`iutD` directly. The CRT
//! path would require deriving `dP`/`dQ`/`qInv` from the
//! server-provided `iutP`/`iutQ`/`iutD`, which the spec does not
//! mandate the server include — non-CRT is the load-bearing path
//! for the seeded-keypair shape.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

/// KTS-IFC dispatcher.
pub struct KtsIfcHandler;

impl AlgorithmHandler for KtsIfcHandler {
    fn algorithm(&self) -> &'static str {
        "KTS-IFC"
    }
    fn mode(&self) -> Option<&'static str> {
        None
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Br2"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::kts_ifc_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kts_ifc_group(group)
    }
}

// SHA-256 digest length, which is also the OAEP seed length for
// SHA-256.
const SEED_LEN: usize = 32;

fn handle_kts_ifc_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;

    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;
    if test_type != "AFT" {
        return Err(DispatchError::UnsupportedTestType(test_type.to_string()));
    }

    let scheme = group
        .get("scheme")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("scheme"))?;
    if scheme != "KTS-OAEP-basic" {
        return Err(DispatchError::Unsupported(
            "KTS-IFC: only KTS-OAEP-basic is supported",
        ));
    }

    let kas_role = group
        .get("kasRole")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kasRole"))?;

    let modulo = group
        .get("modulo")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("modulo"))?;

    let l_bits = group
        .get("l")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("l"))?;
    if l_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "KTS-IFC: l must be a multiple of 8 bits",
        ));
    }
    let l_bytes = usize::try_from(l_bits / 8)
        .map_err(|_| DispatchError::Crypto("KTS-IFC: l/8 exceeds usize"))?;

    let kts_config = group
        .get("ktsConfiguration")
        .ok_or(DispatchError::MissingField("ktsConfiguration"))?;
    let hash_alg = kts_config
        .get("hashAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("ktsConfiguration.hashAlg"))?;
    if hash_alg != "SHA2-256" {
        return Err(DispatchError::Unsupported(
            "KTS-IFC: only SHA2-256 is supported",
        ));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());

    for tc in tests {
        let resp = match (kas_role, modulo) {
            ("initiator", 2048) => handle_initiator_2048(tc, l_bytes)?,
            ("initiator", 3072) => handle_initiator_3072(tc, l_bytes)?,
            ("initiator", 4096) => handle_initiator_4096(tc, l_bytes)?,
            ("responder", 2048) => handle_responder_2048(tc)?,
            ("responder", 3072) => handle_responder_3072(tc)?,
            ("responder", 4096) => handle_responder_4096(tc)?,
            ("initiator" | "responder", _) => {
                return Err(DispatchError::Unsupported(
                    "KTS-IFC: only modulo 2048, 3072, or 4096 is supported",
                ));
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "KTS-IFC: kasRole must be initiator or responder",
                ));
            }
        };
        results.push(resp);
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

// ── Initiator (IUT samples Z, encrypts with server's public key) ───

fn handle_initiator_2048(tc: &JsonValue, l_bytes: usize) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "serverN")?;
    let e = decode_e(tc, "serverE")?;
    let (z, seed) = sample_z_and_seed(l_bytes)?;
    let ct = oxicrypt_rsa::rsa_oaep_encrypt_2048_sha256_internal(&n, e, b"", &z, &seed)
        .ok_or(DispatchError::Crypto("KTS-IFC: OAEP encrypt 2048 failed"))?;
    Ok(initiator_response(tc_id, &ct, &z))
}

fn handle_initiator_3072(tc: &JsonValue, l_bytes: usize) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::rsa3072::MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "serverN")?;
    let e = decode_e(tc, "serverE")?;
    let (z, seed) = sample_z_and_seed(l_bytes)?;
    let ct = oxicrypt_rsa::rsa3072::oaep_encrypt_internal(&n, e, b"", &z, &seed)
        .ok_or(DispatchError::Crypto("KTS-IFC: OAEP encrypt 3072 failed"))?;
    Ok(initiator_response(tc_id, &ct, &z))
}

fn handle_initiator_4096(tc: &JsonValue, l_bytes: usize) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::rsa4096::MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "serverN")?;
    let e = decode_e(tc, "serverE")?;
    let (z, seed) = sample_z_and_seed(l_bytes)?;
    let ct = oxicrypt_rsa::rsa4096::oaep_encrypt_internal(&n, e, b"", &z, &seed)
        .ok_or(DispatchError::Crypto("KTS-IFC: OAEP encrypt 4096 failed"))?;
    Ok(initiator_response(tc_id, &ct, &z))
}

// ── Responder (IUT decrypts server's ciphertext) ─────────────────────

fn handle_responder_2048(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::RSA_2048_MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "iutN")?;
    let d: [u8; MB] = decode_fixed::<MB>(tc, "iutD")?;
    let ct: [u8; MB] = decode_fixed::<MB>(tc, "serverC")?;
    // The bespoke 2048 entry point expects a fixed-size out buffer
    // (`oaep::MAX_MSG_LEN` = 190 bytes), unlike the macro-generated
    // 3072/4096 variants which accept a slice.
    let mut out = [0u8; oxicrypt_rsa::oaep::MAX_MSG_LEN];
    let z_len =
        oxicrypt_rsa::rsa_oaep_decrypt_2048_sha256_nocrt_internal(&n, &d, b"", &ct, &mut out)
            .ok_or(DispatchError::Crypto("KTS-IFC: OAEP decrypt 2048 failed"))?;
    Ok(responder_response(tc_id, &out[..z_len]))
}

fn handle_responder_3072(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::rsa3072::MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "iutN")?;
    let d: [u8; MB] = decode_fixed::<MB>(tc, "iutD")?;
    let ct: [u8; MB] = decode_fixed::<MB>(tc, "serverC")?;
    let mut out = [0u8; MB];
    let z_len = oxicrypt_rsa::rsa3072::oaep_decrypt_nocrt_internal(&n, &d, b"", &ct, &mut out)
        .ok_or(DispatchError::Crypto("KTS-IFC: OAEP decrypt 3072 failed"))?;
    Ok(responder_response(tc_id, &out[..z_len]))
}

fn handle_responder_4096(tc: &JsonValue) -> Result<JsonValue, DispatchError> {
    const MB: usize = oxicrypt_rsa::rsa4096::MODULUS_BYTES;
    let tc_id = tc_id(tc)?;
    let n: [u8; MB] = decode_fixed::<MB>(tc, "iutN")?;
    let d: [u8; MB] = decode_fixed::<MB>(tc, "iutD")?;
    let ct: [u8; MB] = decode_fixed::<MB>(tc, "serverC")?;
    let mut out = [0u8; MB];
    let z_len = oxicrypt_rsa::rsa4096::oaep_decrypt_nocrt_internal(&n, &d, b"", &ct, &mut out)
        .ok_or(DispatchError::Crypto("KTS-IFC: OAEP decrypt 4096 failed"))?;
    Ok(responder_response(tc_id, &out[..z_len]))
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Read the test-case id field.
fn tc_id(tc: &JsonValue) -> Result<i64, DispatchError> {
    tc.get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))
}

/// Sample `Z` of `l_bytes` and a 32-byte OAEP seed from a freshly
/// instantiated HMAC-DRBG-SHA-256 seeded from `/dev/urandom`. Two
/// separate `generate` calls so an audit reads the secret material
/// (the transported key `Z`) and the OAEP randomization (the seed)
/// as distinct outputs of the same DRBG instance — matching the
/// per-instance per-output discipline from SP 800-90A §10.1.
fn sample_z_and_seed(l_bytes: usize) -> Result<(Vec<u8>, [u8; SEED_LEN]), DispatchError> {
    let mut drbg = super::os_entropy::build_seeded_drbg()?;
    let mut z = vec![0u8; l_bytes];
    drbg.generate(None, &mut z)
        .map_err(|_| DispatchError::Crypto("KTS-IFC: DRBG generate(Z) failed"))?;
    let mut seed = [0u8; SEED_LEN];
    drbg.generate(None, &mut seed)
        .map_err(|_| DispatchError::Crypto("KTS-IFC: DRBG generate(seed) failed"))?;
    Ok((z, seed))
}

/// Build the initiator-side AFT response object.
fn initiator_response(tc_id: i64, iut_c: &[u8], dkm: &[u8]) -> JsonValue {
    JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "iutC".to_string(),
            JsonValue::String(hex::encode_upper(iut_c)),
        ),
        ("dkm".to_string(), JsonValue::String(hex::encode_upper(dkm))),
    ])
}

/// Build the responder-side AFT response object.
fn responder_response(tc_id: i64, dkm: &[u8]) -> JsonValue {
    JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("dkm".to_string(), JsonValue::String(hex::encode_upper(dkm))),
    ])
}

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
        return Err(DispatchError::Crypto("KTS-IFC: field too large"));
    }
    let mut buf = [0u8; LEN];
    buf[LEN - raw.len()..].copy_from_slice(&raw);
    Ok(buf)
}

/// Decode an RSA public exponent (hex-encoded big-endian) into a
/// `u64`. The spec allows up to modulus-bit-wide `e` in principle,
/// but ACVTS test vectors and FIPS 186-5 §A.1 cap at 2^256, and
/// `oxicrypt_rsa`'s OAEP encrypt path takes `e: u64`; any prompt
/// with a public exponent exceeding the `u64` range is rejected at
/// dispatch time rather than truncated silently.
fn decode_e(obj: &JsonValue, name: &'static str) -> Result<u64, DispatchError> {
    let bytes = decode_hex_field(obj, name)?;
    if bytes.len() > 8 {
        return Err(DispatchError::Crypto(
            "KTS-IFC: public exponent exceeds 8 bytes (u64 range)",
        ));
    }
    let mut val: u64 = 0;
    for &b in &bytes {
        val = (val << 8) | u64::from(b);
    }
    Ok(val)
}
