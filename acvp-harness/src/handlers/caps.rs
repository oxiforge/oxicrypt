//! ACVP registration capability builders.
//!
//! These helpers produce the `JsonValue` objects that each handler's
//! `acvp_capabilities()` returns.  The ACVP demo server uses these to
//! generate matching vector sets.
//!
//! All 78 registered handlers declare capabilities via their
//! [`crate::dispatch::AlgorithmHandler::acvp_capabilities`]
//! implementation, which delegates to one of the builder functions in
//! this module.  The transport client collects them into a single
//! registration array for the demo server session.

use crate::json::JsonValue;

// ── Internal helpers ─────────────────────────────────────────────

/// Helper: build a JSON integer.
fn num(n: i64) -> JsonValue {
    JsonValue::Number(n)
}

/// Helper: build a JSON string.
fn str_val(s: &str) -> JsonValue {
    JsonValue::String(s.to_string())
}

/// Helper: build a JSON array of strings.
fn str_array(vals: &[&str]) -> JsonValue {
    JsonValue::Array(vals.iter().map(|v| str_val(v)).collect())
}

/// Helper: build a JSON array of integers.
fn num_array(vals: &[i64]) -> JsonValue {
    JsonValue::Array(vals.iter().map(|v| num(*v)).collect())
}

/// Helper: build a JSON object from key-value pairs.
fn obj(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Helper: a standard byte-aligned range domain.
fn range_domain(min: i64, max: i64, increment: i64) -> JsonValue {
    JsonValue::Array(vec![obj(vec![
        ("min", num(min)),
        ("max", num(max)),
        ("increment", num(increment)),
    ])])
}

/// Helper: boolean pair `[true, false]`.
fn bool_pair() -> JsonValue {
    JsonValue::Array(vec![JsonValue::Bool(true), JsonValue::Bool(false)])
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
        ("messageLength", range_domain(0, 65536, 8)),
    ])
}

// ── SHA-1 / SHA-2 family ──────────────────────────────────────────

/// Build an ACVP registration block for a SHA-1 or SHA-2 hash
/// algorithm.
///
/// ```json
/// {
///   "algorithm": "SHA2-256",
///   "revision": "1.0",
///   "messageLength": [{"min": 0, "max": 65536, "increment": 8}]
/// }
/// ```
///
/// Mirrors [`sha3_capability`]'s message-length domain and shape; the
/// only deltas vs SHA-3 are the algorithm name and the revision
/// string (`"1.0"` for FIPS 180-4 vs `"2.0"` for FIPS 202).
pub fn sha2_capability(algorithm: &str, _digest_bits: i64) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("messageLength", range_domain(0, 65536, 8)),
    ])
}

// ── SHAKE family ─────────────────────────────────────────────────

/// Build an ACVP registration block for a SHAKE XOF algorithm.
///
/// Supports AFT, MCT, VOT, and LDT test types.  `outLen` declares
/// the variable output-length range the IUT supports.
pub fn shake_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("FIPS202")),
        ("messageLength", range_domain(0, 65536, 8)),
        ("outputLen", range_domain(16, 65536, 8)),
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
        ("keyLen", range_domain(8, 524_288, 8)),
        ("macLen", range_domain(32, mac_bits, 8)),
    ])
}

// ── CMAC-AES ─────────────────────────────────────────────────────

/// Build an ACVP registration block for CMAC-AES.
pub fn cmac_aes_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("CMAC-AES")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("direction", str_array(&["gen", "ver"])),
                ("keyLen", num_array(&[128, 192, 256])),
                ("msgLen", range_domain(0, 65536, 8)),
                ("macLen", range_domain(8, 128, 8)),
            ])]),
        ),
    ])
}

// ── KMAC family ──────────────────────────────────────────────────

/// Build an ACVP registration block for a KMAC algorithm.
///
/// ACVP models KMAC's XOF mode as a per-group `xof: bool` flag on the
/// `KMAC-128` / `KMAC-256` algorithm IDs rather than as separate
/// `KMACXOF-*` algorithm names; the demo server rejects the latter
/// with HTTP 400 `Unable to map KMACXOF-*-1.0 to an internal algorithm
/// id`. The capability advertises support for both modes
/// (`xof: [false, true]`); the unified handler reads the per-group
/// flag and dispatches to either the `Kmac{128,256}` or
/// `KmacXof{128,256}` primitive accordingly.
pub fn kmac_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("msgLen", range_domain(0, 65536, 8)),
        ("keyLen", range_domain(128, 524_288, 8)),
        ("macLen", range_domain(32, 65536, 8)),
        (
            "xof",
            JsonValue::Array(vec![JsonValue::Bool(false), JsonValue::Bool(true)]),
        ),
    ])
}

// ── cSHAKE family ────────────────────────────────────────────────

/// Build an ACVP registration block for a cSHAKE algorithm.
pub fn cshake_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("msgLen", range_domain(0, 65536, 8)),
        ("outputLen", range_domain(16, 65536, 8)),
        ("hexCustomization", JsonValue::Bool(true)),
    ])
}

// ── TupleHash family ─────────────────────────────────────────────

/// Build an ACVP registration block for TupleHash or TupleHashXOF.
pub fn tuplehash_capability(algorithm: &str, xof: bool) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("outputLen", range_domain(16, 65536, 8)),
        ("xof", JsonValue::Array(vec![JsonValue::Bool(xof)])),
    ])
}

// ── ParallelHash family ──────────────────────────────────────────

/// Build an ACVP registration block for ParallelHash or ParallelHashXOF.
pub fn parallelhash_capability(algorithm: &str, xof: bool) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("outputLen", range_domain(16, 65536, 8)),
        (
            "blockSize",
            JsonValue::Array(vec![obj(vec![
                ("min", num(1)),
                ("max", num(128)),
                ("increment", num(1)),
            ])]),
        ),
        ("xof", JsonValue::Array(vec![JsonValue::Bool(xof)])),
    ])
}

// ── AES family ───────────────────────────────────────────────────

/// Build an ACVP registration block for AES-ECB.
pub fn aes_ecb_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-ECB")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
    ])
}

/// Build an ACVP registration block for AES-CBC.
pub fn aes_cbc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-CBC")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
    ])
}

/// Build an ACVP registration block for AES-CTR.
pub fn aes_ctr_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-CTR")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("payloadLen", range_domain(8, 128, 8)),
        ("incrementalCounter", JsonValue::Bool(true)),
        ("overflowCounter", JsonValue::Bool(true)),
    ])
}

/// Build an ACVP registration block for AES-GCM.
pub fn aes_gcm_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-GCM")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("ivLen", num_array(&[96])),
        ("ivGen", str_val("external")),
        ("tagLen", num_array(&[128])),
        ("payloadLen", range_domain(0, 65536, 8)),
        ("aadLen", range_domain(0, 65536, 8)),
    ])
}

/// Build an ACVP registration block for AES-CCM.
pub fn aes_ccm_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-CCM")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("payloadLen", range_domain(0, 256, 8)),
        ("ivLen", num_array(&[56, 64, 72, 80, 88, 96, 104])),
        ("tagLen", num_array(&[32, 48, 64, 80, 96, 112, 128])),
        ("aadLen", range_domain(0, 524_288, 8)),
    ])
}

/// Build an ACVP registration block for AES-KW (Key Wrap).
pub fn aes_kw_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-KW")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("kwCipher", str_array(&["cipher", "inverse"])),
        ("payloadLen", range_domain(128, 4096, 64)),
    ])
}

/// Build an ACVP registration block for AES-KWP (Key Wrap with Padding).
pub fn aes_kwp_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ACVP-AES-KWP")),
        ("revision", str_val("1.0")),
        ("direction", str_array(&["encrypt", "decrypt"])),
        ("keyLen", num_array(&[128, 192, 256])),
        ("kwCipher", str_array(&["cipher", "inverse"])),
        ("payloadLen", range_domain(8, 4096, 8)),
    ])
}

// ── DRBG family ──────────────────────────────────────────────────

/// Build an ACVP registration block for CTR_DRBG.
pub fn ctr_drbg_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ctrDRBG")),
        ("revision", str_val("1.0")),
        ("predResistanceEnabled", bool_pair()),
        ("reseedImplemented", JsonValue::Bool(false)),
        (
            "capabilities",
            JsonValue::Array(vec![
                // Entropy / nonce values per ACVP-server validation:
                // entropy = seedlen (security_strength + AES blocklen) and
                // nonce = 0 for ALL (mode, derFunc) entries. The server
                // enforces seedlen-style values uniformly regardless of
                // derFunc — stricter than SP 800-90A Rev 1 Table 3 alone
                // suggests but matches the demo server's per-mode rules
                // (verified empirically 2026-04-28).
                ctr_drbg_mode_entry("AES-128", true, 256, 0),
                ctr_drbg_mode_entry("AES-128", false, 256, 0),
                ctr_drbg_mode_entry("AES-192", true, 320, 0),
                ctr_drbg_mode_entry("AES-192", false, 320, 0),
                ctr_drbg_mode_entry("AES-256", true, 384, 0),
                ctr_drbg_mode_entry("AES-256", false, 384, 0),
            ]),
        ),
    ])
}

/// Build a single ctrDRBG mode entry with its per-(mode, derFunc) domain
/// fields. Entropy / nonce values are spec-mandated per SP 800-90A Rev 1
/// Table 3 and constrained by the demo server's per-mode validation.
fn ctr_drbg_mode_entry(mode: &str, der_func: bool, entropy_len: i64, nonce_len: i64) -> JsonValue {
    obj(vec![
        ("mode", str_val(mode)),
        ("derFunc", JsonValue::Bool(der_func)),
        // Fixed (spec-mandated) values use num_array to produce `[N]`;
        // ranges use range_domain. The server enforces strict min < max
        // on range objects, so single-value entries must use the array
        // form.
        ("entropyInputLen", num_array(&[entropy_len])),
        ("nonceLen", num_array(&[nonce_len])),
        ("persoStringLen", range_domain(0, 256, 8)),
        ("additionalInputLen", range_domain(0, 256, 8)),
        ("returnedBitsLen", num(256)),
    ])
}

/// Build an ACVP registration block for Hash_DRBG.
///
/// Per-mode entropy/nonce values follow the same shape pattern as
/// ctrDRBG (verified empirically 2026-04-28 against the demo server),
/// but the specific values for hashDRBG modes have not been live-
/// verified yet — values match SP 800-90A Rev 1 Table 2 minima
/// (security_strength=256 for all SHA2-{256,384,512}, nonce =
/// security_strength/2 = 128). A live-demo verification follow-up
/// PR will tune these as needed.
pub fn hash_drbg_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("hashDRBG")),
        ("revision", str_val("1.0")),
        ("predResistanceEnabled", bool_pair()),
        ("reseedImplemented", JsonValue::Bool(false)),
        (
            "capabilities",
            JsonValue::Array(vec![
                hash_drbg_mode_entry("SHA2-256", 256, 128),
                hash_drbg_mode_entry("SHA2-384", 256, 128),
                hash_drbg_mode_entry("SHA2-512", 256, 128),
            ]),
        ),
    ])
}

/// Build a single hashDRBG / hmacDRBG mode entry with per-mode domain
/// fields. Hash/HMAC DRBGs do not have a derFunc concept — entropy
/// compression is intrinsic to the algorithm.
fn hash_drbg_mode_entry(mode: &str, entropy_len: i64, nonce_len: i64) -> JsonValue {
    obj(vec![
        ("mode", str_val(mode)),
        ("entropyInputLen", num_array(&[entropy_len])),
        ("nonceLen", num_array(&[nonce_len])),
        ("persoStringLen", range_domain(0, 256, 8)),
        ("additionalInputLen", range_domain(0, 256, 8)),
        ("returnedBitsLen", num(256)),
    ])
}

/// Build an ACVP registration block for HMAC_DRBG.
///
/// Per-mode entropy/nonce values follow the same shape pattern as
/// ctrDRBG (verified empirically 2026-04-28). HMAC_DRBG specific values
/// have not been live-verified yet — see `hash_drbg_capability` for the
/// same caveat.
pub fn hmac_drbg_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("hmacDRBG")),
        ("revision", str_val("1.0")),
        ("predResistanceEnabled", bool_pair()),
        ("reseedImplemented", JsonValue::Bool(false)),
        (
            "capabilities",
            JsonValue::Array(vec![
                hash_drbg_mode_entry("SHA2-256", 256, 128),
                hash_drbg_mode_entry("SHA2-384", 256, 128),
                hash_drbg_mode_entry("SHA2-512", 256, 128),
            ]),
        ),
    ])
}

// ── KDF family ───────────────────────────────────────────────────

/// Build an ACVP registration block for KDA-HKDF (SP 800-56C Rev 2).
///
/// `macSaltMethods`, `encoding`, and (when `usesHybridSharedSecret:
/// true`) `auxSharedSecretLen` are required by the demo server per
/// draft-celi-acvp-kda-1.0; see SP 800-56Cr2 §4.5 (encoding /
/// salt-method) and §5.9.2 (hybrid shared-secret form, where the
/// auxiliary shared secret is concatenated alongside Z).
pub fn kda_hkdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KDA")),
        ("mode", str_val("HKDF")),
        ("revision", str_val("Sp800-56Cr2")),
        (
            "hmacAlg",
            str_array(&[
                "SHA2-224",
                "SHA2-256",
                "SHA2-384",
                "SHA2-512",
                "SHA2-512/224",
                "SHA2-512/256",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
            ]),
        ),
        ("macSaltMethods", str_array(&["default", "random"])),
        ("encoding", str_array(&["concatenation"])),
        ("z", range_domain(224, 65536, 8)),
        ("auxSharedSecretLen", range_domain(112, 65536, 8)),
        ("l", num(2048)),
        ("fixedInfoPattern", str_val("uPartyInfo||vPartyInfo||l")),
        ("usesHybridSharedSecret", JsonValue::Bool(true)),
    ])
}

/// Build an ACVP registration block for SP 800-108r1 KBKDF.
pub fn kbkdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KDF")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![
                kbkdf_mode_entry("counter"),
                kbkdf_mode_entry("feedback"),
                kbkdf_mode_entry("double pipeline iteration"),
            ]),
        ),
    ])
}

/// Build one KBKDF iteration-mode capability entry.
fn kbkdf_mode_entry(kdf_mode: &str) -> JsonValue {
    obj(vec![
        ("kdfMode", str_val(kdf_mode)),
        (
            "macMode",
            str_array(&[
                "HMAC-SHA-1",
                "HMAC-SHA2-224",
                "HMAC-SHA2-256",
                "HMAC-SHA2-384",
                "HMAC-SHA2-512",
                "HMAC-SHA2-512/224",
                "HMAC-SHA2-512/256",
                "HMAC-SHA3-224",
                "HMAC-SHA3-256",
                "HMAC-SHA3-384",
                "HMAC-SHA3-512",
            ]),
        ),
        ("counterLength", num_array(&[8, 16, 24, 32])),
        ("supportedLengths", range_domain(8, 4096, 8)),
    ])
}

/// Build an ACVP registration block for kdf-components / tls (v1.2).
pub fn kdf_comp_tls_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("kdf-components")),
        ("mode", str_val("tls")),
        ("revision", str_val("1.0")),
        ("tlsVersion", str_array(&["v1.2"])),
        ("hashAlg", str_array(&["SHA2-256", "SHA2-384", "SHA2-512"])),
    ])
}

/// Build an ACVP registration block for TLS v1.2 KDF (RFC 7627 EMS).
pub fn tls12_kdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("TLS-v1.2")),
        ("mode", str_val("KDF")),
        ("revision", str_val("RFC7627")),
        ("hashAlg", str_array(&["SHA2-256", "SHA2-384", "SHA2-512"])),
    ])
}

/// Build an ACVP registration block for TLS v1.3 KDF (RFC 8446).
///
/// Capability shape per `draft-hammett-acvp-kdf-tls-v1.3` §7.3.2:
/// ```json
/// {
///   "algorithm": "TLS-v1.3",
///   "mode": "KDF",
///   "revision": "RFC8446",
///   "hmacAlg": ["SHA2-256", "SHA2-384"],
///   "runningMode": ["DHE", "PSK", "PSK-DHE"]
/// }
/// ```
pub fn tls13_kdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("TLS-v1.3")),
        ("mode", str_val("KDF")),
        ("revision", str_val("RFC8446")),
        ("hmacAlg", str_array(&["SHA2-256", "SHA2-384"])),
        ("runningMode", str_array(&["DHE", "PSK", "PSK-DHE"])),
    ])
}

/// Build an ACVP registration block for PBKDF (SP 800-132).
pub fn pbkdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("PBKDF")),
        ("revision", str_val("1.0")),
        (
            "hmacAlg",
            str_array(&[
                "SHA-1",
                "SHA2-224",
                "SHA2-256",
                "SHA2-384",
                "SHA2-512",
                "SHA2-512/224",
                "SHA2-512/256",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
            ]),
        ),
        ("iterationCount", range_domain(1, 10000, 1)),
        ("keyLen", range_domain(112, 4096, 8)),
        ("passwordLen", range_domain(8, 128, 1)),
        ("saltLen", range_domain(128, 4096, 8)),
    ])
}

// ── RSA family ───────────────────────────────────────────────────

/// Build an ACVP registration block for RSA / sigVer.
pub fn rsa_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("FIPS186-5")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        (
            "capabilities",
            JsonValue::Array(vec![
                rsa_sigver_sigtype("pkcs1v1.5"),
                rsa_sigver_sigtype("pss"),
            ]),
        ),
    ])
}

/// Build one RSA sigVer sigType capability entry.
fn rsa_sigver_sigtype(sig_type: &str) -> JsonValue {
    let hash_pairs = JsonValue::Array(vec![obj(vec![
        ("hashAlg", str_val("SHA2-256")),
        ("saltLen", num(32)),
    ])]);
    obj(vec![
        ("sigType", str_val(sig_type)),
        (
            "properties",
            JsonValue::Array(vec![
                obj(vec![
                    ("modulo", num(2048)),
                    ("hashPair", hash_pairs.clone()),
                ]),
                obj(vec![
                    ("modulo", num(3072)),
                    ("hashPair", hash_pairs.clone()),
                ]),
                obj(vec![("modulo", num(4096)), ("hashPair", hash_pairs)]),
            ]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / sigGen.
pub fn rsa_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("FIPS186-5")),
        (
            "capabilities",
            JsonValue::Array(vec![
                rsa_siggen_sigtype("pkcs1v1.5"),
                rsa_siggen_sigtype("pss"),
            ]),
        ),
    ])
}

/// Build one RSA sigGen sigType capability entry.
fn rsa_siggen_sigtype(sig_type: &str) -> JsonValue {
    let hash_pairs = JsonValue::Array(vec![obj(vec![
        ("hashAlg", str_val("SHA2-256")),
        ("saltLen", num(32)),
    ])]);
    obj(vec![
        ("sigType", str_val(sig_type)),
        (
            "properties",
            JsonValue::Array(vec![
                obj(vec![
                    ("modulo", num(2048)),
                    ("hashPair", hash_pairs.clone()),
                ]),
                obj(vec![
                    ("modulo", num(3072)),
                    ("hashPair", hash_pairs.clone()),
                ]),
                obj(vec![("modulo", num(4096)), ("hashPair", hash_pairs)]),
            ]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / keyGen.
pub fn rsa_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS186-5")),
        ("infoGeneratedByServer", JsonValue::Bool(false)),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        (
            "properties",
            JsonValue::Array(vec![
                obj(vec![
                    ("modulo", num(2048)),
                    ("primeTest", str_array(&["tblC2"])),
                ]),
                obj(vec![
                    ("modulo", num(3072)),
                    ("primeTest", str_array(&["tblC2"])),
                ]),
                obj(vec![
                    ("modulo", num(4096)),
                    ("primeTest", str_array(&["tblC2"])),
                ]),
            ]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / OAEP.
pub fn rsa_oaep_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("OAEP")),
        ("revision", str_val("RFC8017")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("modulo", num(2048)),
                ("hashAlg", str_array(&["SHA2-256"])),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / decryptionPrimitive.
pub fn rsa_decprim_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("decryptionPrimitive")),
        ("revision", str_val("Sp800-56Br2")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        ("keyFormat", str_array(&["standard", "crt"])),
    ])
}

/// Build an ACVP registration block for RSA / signaturePrimitive.
pub fn rsa_sigprim_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("signaturePrimitive")),
        ("revision", str_val("2.0")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        ("keyFormat", str_array(&["standard", "crt"])),
    ])
}

// ── ECDSA family ─────────────────────────────────────────────────

/// Build an ACVP registration block for ECDSA / sigVer.
///
/// Each capability block declares one strict (curve, hashAlg) pair
/// matching the FIPS 186-5 §6.4.1 security-strength binding (P-256
/// with SHA2-256, P-384 with SHA2-384). The earlier single-block
/// form `curve: [P-256, P-384] × hashAlg: [SHA2-256, SHA2-384]`
/// declared the cross product and prompted the demo server to
/// generate test cases for all four combinations, including the
/// cross-pairs (P-256, SHA2-384) and (P-384, SHA2-256) that
/// `oxicrypt-ecdsa` does not implement.
pub fn ecdsa_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ECDSA")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("FIPS186-5")),
        (
            "capabilities",
            JsonValue::Array(vec![
                obj(vec![
                    ("curve", str_array(&["P-256"])),
                    ("hashAlg", str_array(&["SHA2-256"])),
                ]),
                obj(vec![
                    ("curve", str_array(&["P-384"])),
                    ("hashAlg", str_array(&["SHA2-384"])),
                ]),
            ]),
        ),
    ])
}

/// Build an ACVP registration block for ECDSA / keyVer.
pub fn ecdsa_keyver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ECDSA")),
        ("mode", str_val("keyVer")),
        ("revision", str_val("FIPS186-5")),
        ("curve", str_array(&["P-256", "P-384"])),
    ])
}

/// Build an ACVP registration block for ECDSA / sigGen.
///
/// Mirrors `ecdsa_sigver_capability`: one capability block per FIPS
/// 186-5 strict (curve, hashAlg) pair to keep registration aligned
/// with the (P-256, SHA2-256) and (P-384, SHA2-384) implementation
/// surface in `oxicrypt-ecdsa`.
pub fn ecdsa_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ECDSA")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("FIPS186-5")),
        (
            "capabilities",
            JsonValue::Array(vec![
                obj(vec![
                    ("curve", str_array(&["P-256"])),
                    ("hashAlg", str_array(&["SHA2-256"])),
                ]),
                obj(vec![
                    ("curve", str_array(&["P-384"])),
                    ("hashAlg", str_array(&["SHA2-384"])),
                ]),
            ]),
        ),
        ("componentTest", JsonValue::Bool(false)),
    ])
}

/// Build an ACVP registration block for ECDSA / keyGen.
pub fn ecdsa_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ECDSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS186-5")),
        ("curve", str_array(&["P-256", "P-384"])),
        ("secretGenerationMode", str_array(&["testing candidates"])),
    ])
}

// ── EdDSA family ─────────────────────────────────────────────────

/// Build an ACVP registration block for EDDSA / sigVer.
pub fn eddsa_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("EDDSA")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
        ("curve", str_array(&["ED-25519"])),
        ("pure", JsonValue::Bool(true)),
        ("preHash", JsonValue::Bool(false)),
    ])
}

/// Build an ACVP registration block for EDDSA / keyVer.
pub fn eddsa_keyver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("EDDSA")),
        ("mode", str_val("keyVer")),
        ("revision", str_val("1.0")),
        ("curve", str_array(&["ED-25519"])),
    ])
}

/// Build an ACVP registration block for EDDSA / sigGen.
pub fn eddsa_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("EDDSA")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        ("curve", str_array(&["ED-25519"])),
        ("pure", JsonValue::Bool(true)),
        ("preHash", JsonValue::Bool(false)),
    ])
}

/// Build an ACVP registration block for EDDSA / keyGen.
pub fn eddsa_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("EDDSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
        ("curve", str_array(&["ED-25519"])),
    ])
}

// ── KAS-ECC-SSC ──────────────────────────────────────────────────

/// Build an ACVP registration block for KAS-ECC-SSC / Component.
pub fn kas_ecc_ssc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KAS-ECC-SSC")),
        ("mode", str_val("Component")),
        ("revision", str_val("Sp800-56Ar3")),
        (
            "scheme",
            obj(vec![(
                "ephemeralUnified",
                obj(vec![("kasRole", str_array(&["initiator", "responder"]))]),
            )]),
        ),
        (
            "domainParameterGenerationMethods",
            str_array(&["P-256", "P-384"]),
        ),
    ])
}

// ── KAS-FFC-SSC ──────────────────────────────────────────────────

/// Build an ACVP registration block for KAS-FFC-SSC / Component.
pub fn kas_ffc_ssc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KAS-FFC-SSC")),
        ("mode", str_val("Component")),
        ("revision", str_val("Sp800-56Ar3")),
        (
            "scheme",
            obj(vec![(
                "dhEphem",
                obj(vec![("kasRole", str_array(&["initiator", "responder"]))]),
            )]),
        ),
        ("domainParameterGenerationMethods", str_array(&["FB"])),
    ])
}

// ── Post-quantum: ML-KEM ─────────────────────────────────────────

/// Build an ACVP registration block for ML-KEM / keyGen.
pub fn ml_kem_keygen_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
    ])
}

/// Build an ACVP registration block for ML-KEM / encaps.
pub fn ml_kem_encaps_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("encaps")),
        ("revision", str_val("1.0")),
    ])
}

/// Build an ACVP registration block for ML-KEM / decaps.
pub fn ml_kem_decaps_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("decaps")),
        ("revision", str_val("1.0")),
    ])
}

// ── Post-quantum: ML-DSA ─────────────────────────────────────────

/// Build an ACVP registration block for ML-DSA / keyGen.
pub fn ml_dsa_keygen_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
    ])
}

/// Build an ACVP registration block for ML-DSA / sigGen.
pub fn ml_dsa_siggen_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        ("deterministic", JsonValue::Bool(true)),
    ])
}

/// Build an ACVP registration block for ML-DSA / sigVer.
pub fn ml_dsa_sigver_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
    ])
}

// ── Post-quantum: SLH-DSA ────────────────────────────────────────

/// Build an ACVP registration block for SLH-DSA / keyGen.
pub fn slh_dsa_keygen_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
    ])
}

/// Build an ACVP registration block for SLH-DSA / sigGen.
pub fn slh_dsa_siggen_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        ("deterministic", JsonValue::Bool(true)),
    ])
}

/// Build an ACVP registration block for SLH-DSA / sigVer.
pub fn slh_dsa_sigver_capability(algorithm: &str) -> JsonValue {
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
    ])
}

// ── Stateful HBS: LMS ────────────────────────────────────────────

/// Build an ACVP registration block for LMS / keyGen.
pub fn lms_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("lmsMode", str_array(&["LMS_SHA256_M32_H10"])),
                ("lmOtsMode", str_array(&["LMOTS_SHA256_N32_W4"])),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for LMS / sigGen.
pub fn lms_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("lmsMode", str_array(&["LMS_SHA256_M32_H10"])),
                ("lmOtsMode", str_array(&["LMOTS_SHA256_N32_W4"])),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for LMS / sigVer.
pub fn lms_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("lmsMode", str_array(&["LMS_SHA256_M32_H10"])),
                ("lmOtsMode", str_array(&["LMOTS_SHA256_N32_W4"])),
            ])]),
        ),
    ])
}

// ── Stateful HBS: XMSS ──────────────────────────────────────────

/// Build an ACVP registration block for XMSS / keyGen.
pub fn xmss_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("XMSS")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
        ("parameterSets", str_array(&["XMSS-SHA2_10_256"])),
    ])
}

/// Build an ACVP registration block for XMSS / sigGen.
pub fn xmss_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("XMSS")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        ("parameterSets", str_array(&["XMSS-SHA2_10_256"])),
    ])
}

/// Build an ACVP registration block for XMSS / sigVer.
pub fn xmss_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("XMSS")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
        ("parameterSets", str_array(&["XMSS-SHA2_10_256"])),
    ])
}
