//! TLS 1.3 KDF handler — `TLS-v1.3 / KDF / RFC8446`.
//!
//! Implements the ACVP test type defined by `draft-hammett-acvp-kdf-tls-v1.3`
//! against the key schedule in RFC 8446 §7.1.
//!
//! The ACVP harness simplifies the TLS 1.3 transcript to four
//! milestone messages — ClientHello, ServerHello, Server Finished,
//! Client Finished — supplied as opaque blobs in the per-test fields
//! `helloClientRandom`, `helloServerRandom`, `finishedServerRandom`,
//! `finishedClientRandom`. The handler concatenates these to form
//! the four transcript hashes that RFC 8446 §7.1 requires:
//!
//! - `H(ClientHello)`                                          → early secrets
//! - `H(ClientHello ‖ ServerHello)`                            → handshake secrets
//! - `H(ClientHello ‖ ServerHello ‖ Server Finished)`          → master / exporter secrets
//! - `H(ClientHello ‖ ServerHello ‖ Server Finished ‖ Client Finished)` → resumption master
//!
//! Running modes per the spec:
//!
//! - `DHE`     — DHE shared secret only (PSK substituted with zeros)
//! - `PSK`     — PSK only (DHE substituted with zeros)
//! - `PSK-DHE` — both PSK and DHE
//!
//! Output: eight derived secrets per RFC 8446 §7.1
//! (`clientEarlyTrafficSecret`, `earlyExporterMasterSecret`,
//! `clientHandshakeTrafficSecret`, `serverHandshakeTrafficSecret`,
//! `clientApplicationTrafficSecret`, `serverApplicationTrafficSecret`,
//! `exporterMasterSecret`, `resumptionMasterSecret`).

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use oxicrypt_hmac::{HmacSha256, HmacSha384};
use oxicrypt_kdf::PrfHmac;
use oxicrypt_sha::{sha256, sha384};
use oxicrypt_tls_kdf::{tls13_derive_secret_internal, tls13_hkdf_expand_label_internal};

/// `TLS-v1.3 / KDF / RFC8446` dispatcher.
pub struct Tls13KdfHandler;

impl AlgorithmHandler for Tls13KdfHandler {
    fn algorithm(&self) -> &'static str {
        "TLS-v1.3"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("KDF")
    }
    fn revision(&self) -> &'static str {
        "RFC8446"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::tls13_kdf_capability())
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_group(group)
    }
}

fn handle_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
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
    let hmac_alg = group
        .get("hmacAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("hmacAlg"))?;
    let running_mode = group
        .get("runningMode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("runningMode"))?;
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let resp = match hmac_alg {
            "SHA2-256" => run_test::<HmacSha256, 32, _>(t, running_mode, sha256_hash)?,
            "SHA2-384" => run_test::<HmacSha384, 48, _>(t, running_mode, sha384_hash)?,
            _ => {
                return Err(DispatchError::Crypto(
                    "TLS-v1.3 KDF: unsupported hmacAlg (expected SHA2-256 or SHA2-384)",
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

fn sha256_hash(data: &[u8]) -> Result<[u8; 32], DispatchError> {
    sha256(data).map_err(|_| DispatchError::Crypto("TLS-v1.3 KDF: sha256 failed"))
}

fn sha384_hash(data: &[u8]) -> Result<[u8; 48], DispatchError> {
    sha384(data).map_err(|_| DispatchError::Crypto("TLS-v1.3 KDF: sha384 failed"))
}

/// HKDF-Extract = HMAC(salt, IKM). Returns a fresh L-byte PRK.
/// `salt` of `None` is interpreted as `L` zero bytes per RFC 5869 §2.2.
fn hkdf_extract<P: PrfHmac<L>, const L: usize>(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; L] {
    let zero_salt = [0u8; L];
    let salt_bytes: &[u8] = salt.unwrap_or(&zero_salt);
    let mut mac = P::prf_new(salt_bytes);
    mac.prf_update(ikm);
    mac.prf_finalize()
}

#[allow(clippy::too_many_lines)]
fn run_test<P, const L: usize, F>(
    t: &JsonValue,
    running_mode: &str,
    hash_fn: F,
) -> Result<JsonValue, DispatchError>
where
    P: PrfHmac<L>,
    F: Fn(&[u8]) -> Result<[u8; L], DispatchError>,
{
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    // Decode the four transcript-message blobs.
    let hello_client = decode_hex(t, "helloClientRandom")?;
    let hello_server = decode_hex(t, "helloServerRandom")?;
    let finished_server = decode_hex(t, "finishedServerRandom")?;
    let finished_client = decode_hex(t, "finishedClientRandom")?;

    // PSK / DHE inputs depend on running mode. Absent inputs become
    // the all-zero string of length L per RFC 8446 §7.1.
    let zero = [0u8; L];
    let psk_bytes;
    let dhe_bytes;
    let psk: &[u8] = match running_mode {
        "PSK" | "PSK-DHE" => {
            psk_bytes = decode_hex(t, "psk")?;
            &psk_bytes
        }
        "DHE" => &zero,
        _ => {
            return Err(DispatchError::Crypto(
                "TLS-v1.3 KDF: unsupported runningMode (expected DHE / PSK / PSK-DHE)",
            ));
        }
    };
    let dhe: &[u8] = match running_mode {
        "DHE" | "PSK-DHE" => {
            dhe_bytes = decode_hex(t, "dhe")?;
            &dhe_bytes
        }
        "PSK" => &zero,
        _ => unreachable!(),
    };

    // Transcript hashes per RFC 8446 §7.1.
    let mut transcript_pre_hello = Vec::new();
    transcript_pre_hello.extend_from_slice(&hello_client);
    let th_client_hello = hash_fn(&transcript_pre_hello)?;

    transcript_pre_hello.extend_from_slice(&hello_server);
    let th_server_hello = hash_fn(&transcript_pre_hello)?;

    transcript_pre_hello.extend_from_slice(&finished_server);
    let th_server_finished = hash_fn(&transcript_pre_hello)?;

    transcript_pre_hello.extend_from_slice(&finished_client);
    let th_client_finished = hash_fn(&transcript_pre_hello)?;

    // Key schedule per RFC 8446 §7.1.
    //
    //             0
    //             |
    //             v
    //   PSK ->  HKDF-Extract = Early Secret
    //             |
    //             +-----> Derive-Secret(., "ext binder" | "res binder", "")
    //             +-----> Derive-Secret(., "c e traffic", ClientHello)
    //             +-----> Derive-Secret(., "e exp master", ClientHello)
    //             |
    //             v
    //   Derive-Secret(., "derived", "")
    //             |
    //             v
    //   (EC)DHE -> HKDF-Extract = Handshake Secret
    //             |
    //             +-----> Derive-Secret(., "c hs traffic", ClientHello..ServerHello)
    //             +-----> Derive-Secret(., "s hs traffic", ClientHello..ServerHello)
    //             |
    //             v
    //   Derive-Secret(., "derived", "")
    //             |
    //             v
    //   0       -> HKDF-Extract = Master Secret
    //             |
    //             +-----> Derive-Secret(., "c ap traffic", ClientHello..server Finished)
    //             +-----> Derive-Secret(., "s ap traffic", ClientHello..server Finished)
    //             +-----> Derive-Secret(., "exp master",   ClientHello..server Finished)
    //             +-----> Derive-Secret(., "res master",   ClientHello..client Finished)
    let early_secret: [u8; L] = hkdf_extract::<P, L>(Some(&zero), psk);

    let mut client_early_traffic_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &early_secret,
        b"c e traffic",
        &th_client_hello,
        &mut client_early_traffic_secret,
    );

    let mut early_exporter_master_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &early_secret,
        b"e exp master",
        &th_client_hello,
        &mut early_exporter_master_secret,
    );

    // Hash of the empty string for the "derived" Derive-Secret calls.
    let th_empty = hash_fn(&[])?;

    let mut handshake_extract_salt = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &early_secret,
        b"derived",
        &th_empty,
        &mut handshake_extract_salt,
    );
    let handshake_secret: [u8; L] = hkdf_extract::<P, L>(Some(&handshake_extract_salt), dhe);

    let mut client_handshake_traffic_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &handshake_secret,
        b"c hs traffic",
        &th_server_hello,
        &mut client_handshake_traffic_secret,
    );

    let mut server_handshake_traffic_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &handshake_secret,
        b"s hs traffic",
        &th_server_hello,
        &mut server_handshake_traffic_secret,
    );

    let mut master_extract_salt = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &handshake_secret,
        b"derived",
        &th_empty,
        &mut master_extract_salt,
    );
    let master_secret: [u8; L] = hkdf_extract::<P, L>(Some(&master_extract_salt), &zero);

    let mut client_application_traffic_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &master_secret,
        b"c ap traffic",
        &th_server_finished,
        &mut client_application_traffic_secret,
    );

    let mut server_application_traffic_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &master_secret,
        b"s ap traffic",
        &th_server_finished,
        &mut server_application_traffic_secret,
    );

    let mut exporter_master_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &master_secret,
        b"exp master",
        &th_server_finished,
        &mut exporter_master_secret,
    );

    let mut resumption_master_secret = [0u8; L];
    tls13_derive_secret_internal::<P, L>(
        &master_secret,
        b"res master",
        &th_client_finished,
        &mut resumption_master_secret,
    );

    // Suppress unused tls13_hkdf_expand_label_internal warning — we
    // route through tls13_derive_secret_internal everywhere here, but
    // the lower-level primitive is still part of the crate's public
    // API and could be invoked directly by future test types.
    let _ = tls13_hkdf_expand_label_internal::<P, L>;

    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "clientEarlyTrafficSecret".to_string(),
            JsonValue::String(hex::encode_upper(&client_early_traffic_secret)),
        ),
        (
            "earlyExporterMasterSecret".to_string(),
            JsonValue::String(hex::encode_upper(&early_exporter_master_secret)),
        ),
        (
            "clientHandshakeTrafficSecret".to_string(),
            JsonValue::String(hex::encode_upper(&client_handshake_traffic_secret)),
        ),
        (
            "serverHandshakeTrafficSecret".to_string(),
            JsonValue::String(hex::encode_upper(&server_handshake_traffic_secret)),
        ),
        (
            "clientApplicationTrafficSecret".to_string(),
            JsonValue::String(hex::encode_upper(&client_application_traffic_secret)),
        ),
        (
            "serverApplicationTrafficSecret".to_string(),
            JsonValue::String(hex::encode_upper(&server_application_traffic_secret)),
        ),
        (
            "exporterMasterSecret".to_string(),
            JsonValue::String(hex::encode_upper(&exporter_master_secret)),
        ),
        (
            "resumptionMasterSecret".to_string(),
            JsonValue::String(hex::encode_upper(&resumption_master_secret)),
        ),
    ]))
}

fn decode_hex(t: &JsonValue, field: &'static str) -> Result<Vec<u8>, DispatchError> {
    let s = t
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(field))?;
    Ok(hex::decode(s)?)
}
