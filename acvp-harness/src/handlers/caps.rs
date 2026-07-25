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

/// Build an ACVP registration block for TupleHash.
///
/// Per `draft-celi-acvp-xof` §5 + §7.2 Table 3, ACVP recognises only
/// `TupleHash-128` and `TupleHash-256` as algorithm names — the XOF
/// mode is selected via the `xof: [true, false]` capability flag and
/// per-group `xof` boolean. There is no `TupleHashXOF-*` algorithm
/// name in the spec.
pub fn tuplehash_capability(algorithm: &str) -> JsonValue {
    // Required fields per `draft-celi-acvp-xof` §7.2 Table 3 and the
    // Appendix A registration example (page 22): `msgLen` and
    // `hexCustomization` are both required for TupleHash; advertising
    // `hexCustomization: true` exercises both ASCII and hex decode
    // paths (the server picks per-group). Pre-fix cap omitted both
    // fields and the server rejected the registration with HTTP 400
    // `General exception` (no specific complaint surfaced).
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("msgLen", range_domain(0, 65536, 8)),
        ("outputLen", range_domain(16, 65536, 8)),
        (
            "xof",
            JsonValue::Array(vec![JsonValue::Bool(true), JsonValue::Bool(false)]),
        ),
        ("hexCustomization", JsonValue::Bool(true)),
    ])
}

// ── ParallelHash family ──────────────────────────────────────────

/// Build an ACVP registration block for ParallelHash.
///
/// Per `draft-celi-acvp-xof` §5 + §7.2 Table 3, ACVP recognises only
/// `ParallelHash-128` and `ParallelHash-256` as algorithm names — the
/// XOF mode is selected via the `xof: [true, false]` capability flag
/// and per-group `xof` boolean. There is no `ParallelHashXOF-*`
/// algorithm name in the spec.
pub fn parallelhash_capability(algorithm: &str) -> JsonValue {
    // Required fields per `draft-celi-acvp-xof` §7.2 Table 3 and the
    // Appendix A registration example (page 21): `msgLen` and
    // `hexCustomization` are both required (in addition to
    // ParallelHash's `blockSize`). Pre-fix cap omitted msgLen and
    // hexCustomization; the server rejects such registrations with
    // HTTP 400. Same shape as `tuplehash_capability`, plus blockSize.
    obj(vec![
        ("algorithm", str_val(algorithm)),
        ("revision", str_val("1.0")),
        ("msgLen", range_domain(0, 65536, 8)),
        ("outputLen", range_domain(16, 65536, 8)),
        (
            "blockSize",
            JsonValue::Array(vec![obj(vec![
                ("min", num(1)),
                ("max", num(128)),
                ("increment", num(1)),
            ])]),
        ),
        (
            "xof",
            JsonValue::Array(vec![JsonValue::Bool(true), JsonValue::Bool(false)]),
        ),
        ("hexCustomization", JsonValue::Bool(true)),
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
                // Per-mode `returnedBitsLen` equals the hash outlen
                // (= per-mode minimum) per draft-vassilev-acvp-drbg
                // Table 4: SHA2-256 → 256, SHA2-384 → 384, SHA2-512 → 512.
                hash_drbg_mode_entry("SHA2-256", 256, 128, 256),
                hash_drbg_mode_entry("SHA2-384", 256, 128, 384),
                hash_drbg_mode_entry("SHA2-512", 256, 128, 512),
            ]),
        ),
    ])
}

/// Build a single hashDRBG / hmacDRBG mode entry with per-mode domain
/// fields. Hash/HMAC DRBGs do not have a derFunc concept — entropy
/// compression is intrinsic to the algorithm.
fn hash_drbg_mode_entry(
    mode: &str,
    entropy_len: i64,
    nonce_len: i64,
    returned_bits_len: i64,
) -> JsonValue {
    obj(vec![
        ("mode", str_val(mode)),
        ("entropyInputLen", num_array(&[entropy_len])),
        ("nonceLen", num_array(&[nonce_len])),
        ("persoStringLen", range_domain(0, 256, 8)),
        ("additionalInputLen", range_domain(0, 256, 8)),
        ("returnedBitsLen", num(returned_bits_len)),
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
                // Per-mode `returnedBitsLen` equals the hash outlen
                // (= per-mode minimum) per draft-vassilev-acvp-drbg
                // Table 4: SHA2-256 → 256, SHA2-384 → 384, SHA2-512 → 512.
                hash_drbg_mode_entry("SHA2-256", 256, 128, 256),
                hash_drbg_mode_entry("SHA2-384", 256, 128, 384),
                hash_drbg_mode_entry("SHA2-512", 256, 128, 512),
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
///
/// Advertises all three SP 800-108r1 modes — `counter`, `feedback`,
/// and `double pipeline iteration` — at `counterLength = 32`,
/// `fixedDataOrder = "before fixed data"`. Each mode's
/// `counterLocation = "before fixed data"` placement is dispatched
/// via the corresponding `Sp800_108*::derive_with_counter_internal`
/// (counter mode uses the same shape via its built-in 32-bit
/// counter). `counterLength` is intentionally narrowed to `[32]`
/// even though the primitives accept SP 800-108r1 §5.1's full
/// `{8, 16, 24, 32}` set — advertising 8/16/24 prompts the server
/// to emit groups the handler doesn't currently dispatch, per
/// `feedback_caps_match_handler_subset`.
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
///
/// `fixedDataOrder` is the ACVP capability field that maps to the
/// per-prompt `counterLocation` — the position of the iterator
/// within the data input. The handler only dispatches
/// `counterLocation = "before fixed data"` for every mode, so we
/// advertise just that single ordering. Demo registration without
/// this field returns HTTP 400 `KDF-1.0: No Data Orders supplied.`
/// per mode.
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
        // Handler dispatches `counterLength = 32` only — the
        // primitives validate the full `{8, 16, 24, 32}` set per
        // SP 800-108r1 §5.1, but caps narrow what the server prompts
        // so the handler never sees groups it can't dispatch.
        ("counterLength", num_array(&[32])),
        ("supportedLengths", range_domain(8, 4096, 8)),
        ("fixedDataOrder", str_array(&["before fixed data"])),
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
///
/// ACVP nests the per-instantiation parameter set under a
/// `capabilities: [{...}]` array — same shape as KBKDF (see
/// `kbkdf_capability` above). The top level only carries `algorithm`
/// and `revision`; the demo server rejects a flat top-level shape
/// with HTTP 400 `PBKDF-1.0: No Capabilities supplied.`
pub fn pbkdf_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("PBKDF")),
        ("revision", str_val("1.0")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
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
            ])]),
        ),
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
///
/// Two shape rules differ by sigType per `draft-celi-acvp-rsa §7.7.3`
/// Table 11 + the §7.7.3 NOTE block:
///
/// - `saltLen` SHALL only appear inside a `hashPair` entry when
///   `sigType == "pss"`. PKCS#1 v1.5 (RFC 8017 §8.2 / §9.2) is
///   deterministic padding with no salt; the ACVP server rejects
///   registrations carrying `saltLen` on a pkcs1v1.5 sigType with
///   HTTP 400 `SaltLen may not be included within a HashPair for
///   the Pkcs1v15 signature type`.
/// - `maskFunction` is REQUIRED for PSS (RFC 8017 §8.1 / §9.1
///   mandates MGF; FIPS 186-5 §B.7 narrows to MGF1) and SHALL NOT
///   be present for PKCS#1 v1.5. ACVP advertises it as a per-modulo
///   property field alongside `modulo` + `hashPair` (per the §7.7.3
///   example registration on page 33). Valid values are a non-empty
///   subset of `{"mgf1", "shake-128", "shake-256"}` per Table 11;
///   `oxicrypt-rsa` implements MGF1 only.
fn rsa_sigver_sigtype(sig_type: &str) -> JsonValue {
    let is_pss = sig_type == "pss";
    let hash_pair = if is_pss {
        obj(vec![("hashAlg", str_val("SHA2-256")), ("saltLen", num(32))])
    } else {
        obj(vec![("hashAlg", str_val("SHA2-256"))])
    };
    let hash_pairs = JsonValue::Array(vec![hash_pair]);
    let property_for = |modulo_bits: i64| -> JsonValue {
        let mut fields: Vec<(&str, JsonValue)> = vec![("modulo", num(modulo_bits))];
        if is_pss {
            fields.push(("maskFunction", str_array(&["mgf1"])));
        }
        fields.push(("hashPair", hash_pairs.clone()));
        obj(fields)
    };
    obj(vec![
        ("sigType", str_val(sig_type)),
        (
            "properties",
            JsonValue::Array(vec![
                property_for(2048),
                property_for(3072),
                property_for(4096),
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
///
/// Same sigType-conditional shape as `rsa_sigver_sigtype` — sigGen
/// Table 8 (page 22) mirrors sigVer Table 11 (page 31) per
/// `draft-celi-acvp-rsa §7.6.2` / `§7.7.3`:
/// - `saltLen` PSS-only (Table 8 NOTE: "SHALL only be present if the
///   'sigType' is 'pss'")
/// - `maskFunction` PSS-only, valid values `{"mgf1", "shake-128",
///   "shake-256"}`; `oxicrypt-rsa` implements MGF1 only
/// - Per-modulo properties carry the maskFunction sibling field, not
///   the sigType-level entry (per the §7.6.2 example on page 24).
fn rsa_siggen_sigtype(sig_type: &str) -> JsonValue {
    let is_pss = sig_type == "pss";
    let hash_pair = if is_pss {
        obj(vec![("hashAlg", str_val("SHA2-256")), ("saltLen", num(32))])
    } else {
        obj(vec![("hashAlg", str_val("SHA2-256"))])
    };
    let hash_pairs = JsonValue::Array(vec![hash_pair]);
    let property_for = |modulo_bits: i64| -> JsonValue {
        let mut fields: Vec<(&str, JsonValue)> = vec![("modulo", num(modulo_bits))];
        if is_pss {
            fields.push(("maskFunction", str_array(&["mgf1"])));
        }
        fields.push(("hashPair", hash_pairs.clone()));
        obj(fields)
    };
    obj(vec![
        ("sigType", str_val(sig_type)),
        (
            "properties",
            JsonValue::Array(vec![
                property_for(2048),
                property_for(3072),
                property_for(4096),
            ]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / keyGen / FIPS186-5.
///
/// Shape per `draft-celi-acvp-rsa §7.5.1` Table 6 and the §7.5
/// example registration (page 17):
///
/// - **`randPQ`** is a per-capability required field; oxicrypt-rsa
///   generates **probable** primes via FIPS 186-5 §A.1.4 / §B.3.1
///   (random candidate + 5-round Miller-Rabin per Table B.1) — see
///   `crates/oxicrypt-rsa/src/keygen.rs` `gen_probable_prime_1024`
///   plus the keypair driver. The other randPQ modes (provable,
///   *WithProvableAux, *WithProbableAux) are not implemented; we
///   advertise `"probable"` only per the
///   `feedback_caps_match_handler_subset` rule.
/// - **`primeTest`** valid values per Table 6 are
///   `{"2pow100", "2powSecStr"}` (the FIPS186-4 legacy
///   `"tblC2"`/`"tblC3"` naming is NOT valid for FIPS186-5 and the
///   server rejects it). 5 Miller-Rabin rounds yields error ≤ 2^-112
///   per FIPS186-5 Table B.1 — sufficient to claim `"2pow100"` at
///   all advertised moduli; insufficient for `"2powSecStr"` at
///   3072+ where securityStrength=128 would require more rounds.
///   Advertise `"2pow100"` honestly.
/// - **`capabilities`** array wraps each `(randPQ, properties)` group;
///   the pre-fix shape inlined `properties` at the top level (no
///   `capabilities` wrapper, no `randPQ`), so the server emitted no
///   prompts and registration silently produced an empty vector set.
/// - **`keyFormat = "crt"`** — handler returns `(n, d, p, q, dP, dQ, qInv)`
///   per the §A.1.1 / §B.3.1 reference output (see
///   `handlers::rsa_keygen::handle_keygen_group`); the non-CRT
///   "standard" form is reachable via the same keypair but the
///   handler ships the CRT tuple, so advertise CRT only.
pub fn rsa_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS186-5")),
        ("infoGeneratedByServer", JsonValue::Bool(false)),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        ("keyFormat", str_val("crt")),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("randPQ", str_val("probable")),
                (
                    "properties",
                    JsonValue::Array(vec![
                        obj(vec![
                            ("modulo", num(2048)),
                            ("primeTest", str_array(&["2pow100"])),
                        ]),
                        obj(vec![
                            ("modulo", num(3072)),
                            ("primeTest", str_array(&["2pow100"])),
                        ]),
                        obj(vec![
                            ("modulo", num(4096)),
                            ("primeTest", str_array(&["2pow100"])),
                        ]),
                    ]),
                ),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for RSA / OAEP / RFC8017.
///
/// **Not currently called by `RsaOaepHandler::acvp_capabilities`** —
/// the catalog does not register `RSA / OAEP / RFC8017` as a
/// standalone service; OAEP testing is filed under
/// `KTS-IFC / — / Sp800-56Br2` (see `RsaOaepHandler`'s
/// `acvp_capabilities` for the catalog citation). Preserved here as
/// the RFC 8017 cap-shape reference for the future `KtsIfcHandler`
/// migration arc that closes Section 12 RSA at 6/6.
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

/// Build an ACVP registration block for RSA / decryptionPrimitive / Sp800-56Br2.
///
/// Per `draft-celi-acvp-rsa §7.10` (page 38): `modulo` is a REQUIRED
/// top-level array advertising supported moduli (subset of
/// `{2048, 3072, 4096}`). The pre-fix cap omitted it and the server
/// rejects registration with HTTP 400 `No modulo supplied` (same
/// failure mode the `signaturePrimitive` 2.0 cap had).
/// `oxicrypt-rsa` implements only the 2048-bit primitive
/// (`rsa_decryption_primitive_2048_internal` + CRT variant), so we
/// advertise `[2048]` alone per the `feedback_caps_match_handler_subset`
/// rule.
pub fn rsa_decprim_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("decryptionPrimitive")),
        ("revision", str_val("Sp800-56Br2")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        ("keyFormat", str_array(&["standard", "crt"])),
        ("modulo", num_array(&[2048])),
    ])
}

/// Build an ACVP registration block for RSA / signaturePrimitive / 2.0.
///
/// Per `draft-celi-acvp-rsa §7.8` Table 13 (page 36): `modulo` is a
/// REQUIRED top-level array advertising supported moduli (subset of
/// `{2048, 3072, 4096}`). The pre-fix cap omitted it and the server
/// rejected registration with HTTP 400 `No modulo supplied`.
/// `oxicrypt-rsa` implements only the 2048-bit primitive
/// (`rsa_signature_primitive_2048_internal` + CRT), so we advertise
/// `[2048]` alone per the `feedback_caps_match_handler_subset` rule.
pub fn rsa_sigprim_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("RSA")),
        ("mode", str_val("signaturePrimitive")),
        ("revision", str_val("2.0")),
        ("pubExpMode", str_val("fixed")),
        ("fixedPubExp", str_val("010001")),
        ("keyFormat", str_array(&["standard", "crt"])),
        ("modulo", num_array(&[2048])),
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

/// Build an ACVP registration block for KAS-ECC-SSC.
///
/// The ACVTS demo algorithm catalog (`acvts-demo/algorithms-catalog-
/// 2026-04-25.json` row 114) registers `KAS-ECC-SSC` with **no mode
/// field** under revision `Sp800-56Ar3` — unlike `KAS-ECC` (catalog
/// row 133) which carries `mode: "CDH-Component"`. The server
/// constructs its lookup key by concatenating
/// `algorithm-mode-revision`; sending `mode: "Component"` produced
/// `KAS-ECC-SSC-Component-Sp800-56Ar3` which doesn't exist in the
/// catalog and was rejected with HTTP 400 `Unable to map ... to an
/// internal algorithm id`. The actual entry is
/// `KAS-ECC-SSC-Sp800-56Ar3` (no mode segment).
pub fn kas_ecc_ssc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KAS-ECC-SSC")),
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

/// Build an ACVP registration block for KAS-FFC-SSC.
///
/// The ACVTS demo algorithm catalog (`acvts-demo/algorithms-catalog-
/// 2026-04-25.json` row 158) registers `KAS-FFC-SSC` with **no mode
/// field** under revision `Sp800-56Ar3` — paralleling the
/// `KAS-ECC-SSC` entry at row 157 (no mode), and unlike `KAS-FFC`
/// (catalog row 85) which carries `mode: "Component"`. The server
/// constructs its lookup key by concatenating
/// `algorithm-mode-revision`; sending `mode: "Component"` would
/// produce `KAS-FFC-SSC-Component-Sp800-56Ar3` which doesn't exist
/// in the catalog. The actual entry is `KAS-FFC-SSC-Sp800-56Ar3`
/// (no mode segment).
///
/// Spec ground truth: `draft-hammett-acvp-kas-ssc-ffc` §7.3 Table 3
/// (Registration Properties) lists `algorithm`, `revision`,
/// `prereqVals`, `scheme`, `domainParameterGenerationMethods`,
/// `hashFunctionZ` — no `mode` property. The §7.4 Registration
/// Example likewise omits any `mode` field.
///
/// `domainParameterGenerationMethods` advertises **`MODP-3072`**
/// only. Per spec §7.3.2 the recognized identifiers are the fixed-
/// prime groups (`MODP-2048..8192`, `ffdhe2048..8192`) and the
/// per-group-supplied-primes methods (`FB`, `FC`). `oxicrypt-dh`
/// implements RFC 3526 Group 15 (the canonical 3072-bit MODP
/// safe-prime group), so only the matching `MODP-3072` identifier
/// is honest. `FB`/`FC` would imply per-group `p`/`q`/`g` that the
/// primitive cannot consume; advertising them would invite live
/// prompts the IUT cannot satisfy.
pub fn kas_ffc_ssc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KAS-FFC-SSC")),
        ("revision", str_val("Sp800-56Ar3")),
        (
            "scheme",
            obj(vec![(
                "dhEphem",
                obj(vec![("kasRole", str_array(&["initiator", "responder"]))]),
            )]),
        ),
        (
            "domainParameterGenerationMethods",
            str_array(&["MODP-3072"]),
        ),
    ])
}

// ── KTS-IFC ──────────────────────────────────────────────────────

/// Build an ACVP registration block for KTS-IFC (RSAES-OAEP key
/// transport under SP 800-56Br2 §7.2.2.2 / KTS-OAEP-basic scheme).
///
/// The ACVTS demo algorithm catalog (`acvts-demo/algorithms-catalog-
/// 2026-04-25.json` row id 152) registers `KTS-IFC` with **no mode
/// field** under revision `Sp800-56Br2`, paralleling the
/// `KAS-{ECC,FFC}-SSC` entries. The server's lookup key is
/// `KTS-IFC-Sp800-56Br2`; sending a mode segment would mis-key.
/// This is the same catalog-mapping correction pattern resolved in
/// PR #35 (KMACXOF unification) and PR #36 (KAS-ECC-SSC mode-drop).
///
/// Spec ground truth: `draft-hammett-acvp-kas-ifc` §7.3 Table 3
/// (Capabilities JSON Values) — required values are `algorithm`,
/// `revision`, `keyGenerationMethods`, `modulo`, `scheme`;
/// `fixedPubExp` REQUIRED when any `rsakpg1-*` method is advertised.
/// §7.7.1.2 ktsMethod properties (Table 19 at §9.1.2) — `hashAlgs`
/// REQUIRED, `associatedDataPattern` and `encoding` optional;
/// `supportsNullAssociatedData` signals empty-AD support. §7.9
/// carries the canonical KTS-IFC registration example.
///
/// Scope locked to **`KTS-OAEP-basic` only** (the simpler form
/// without Party_V-confirmation MAC) across the full FIPS-approved
/// modulus grid 2048/3072/4096 with SHA-256 hash and empty
/// associated data. `oxicrypt-rsa` exposes seed-deterministic OAEP
/// at all three widths: bespoke
/// `rsa_oaep_{encrypt,decrypt_{crt,nocrt}}_2048_sha256_internal`
/// (lib.rs) and macro-generated
/// `rsa{3072,4096}::oaep_{encrypt,decrypt_{nocrt,crt}}_internal`
/// (`rsa_wide_impl.rs`). Empty label maps to
/// `supportsNullAssociatedData: true` with empty
/// `associatedDataPattern`.
///
/// `l = 256` bits = 32 bytes — comfortably within OAEP-SHA256
/// capacity (k - 2*hLen - 2 = 190 bytes at 2048-bit RSA) and
/// satisfies the §7.7.1 Table 4 minimum of 128 bits without key
/// confirmation. The MAC-confirmation variant
/// (`KTS-OAEP-Party_V-confirmation`) and additional `l` widths /
/// hash algorithms are deferred to follow-up arcs per the
/// scoping in [`prd_rsa_oaep_kts_ifc.md`] §8 non-goals.
///
/// `prereqVals` is omitted to match the surrounding handler
/// convention (KAS-ECC-SSC, KAS-FFC-SSC, every other cap in this
/// module). The ACVTS demo server has tolerated prereqVals
/// omission across all live-graded sessions to date; if a future
/// 400-at-registration surfaces a prereqVals requirement, it is a
/// scoped follow-up that applies uniformly across the cap module.
pub fn kts_ifc_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("KTS-IFC")),
        ("revision", str_val("Sp800-56Br2")),
        ("iutId", str_val("CAFECAFE")),
        ("keyGenerationMethods", str_array(&["rsakpg1-basic"])),
        ("modulo", num_array(&[2048, 3072, 4096])),
        ("fixedPubExp", str_val("010001")),
        (
            "scheme",
            obj(vec![(
                "KTS-OAEP-basic",
                obj(vec![
                    ("kasRole", str_array(&["initiator", "responder"])),
                    (
                        "ktsMethod",
                        obj(vec![
                            ("hashAlgs", str_array(&["SHA2-256"])),
                            ("supportsNullAssociatedData", JsonValue::Bool(true)),
                            ("associatedDataPattern", str_val("")),
                            ("encoding", str_array(&["concatenation"])),
                        ]),
                    ),
                    ("l", num(256)),
                ]),
            )]),
        ),
    ])
}

// ── Post-quantum: ML-KEM ─────────────────────────────────────────

/// Build an ACVP registration block for ML-KEM / keyGen / FIPS203.
///
/// Cap shape mirrors `draft-celi-acvp-ml-kem §7.3.1`. Advertises all
/// three FIPS 203 parameter sets — ML-KEM-512 (k=2), ML-KEM-768 (k=3),
/// and ML-KEM-1024 (k=4). Server tests all advertised parameter sets
/// in a single session; per-group `parameterSet` field selects which
/// variant a test group exercises (see handler dispatch).
pub fn ml_kem_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ML-KEM")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS203")),
        (
            "parameterSets",
            str_array(&["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]),
        ),
    ])
}

/// Build an ACVP registration block for ML-KEM / encapDecap / FIPS203.
///
/// Cap shape mirrors `draft-celi-acvp-ml-kem §7.3.2`. Advertises all
/// three FIPS 203 parameter sets. The catalog uses a single
/// `encapDecap` mode for both encapsulation and decapsulation; the
/// `functions` array selects which the IUT supports. Key-check VAL
/// functions (`encapsulationKeyCheck`/`decapsulationKeyCheck`) are
/// not yet advertised — handler rejects non-AFT/VAL testTypes; the
/// VAL key-check surface is a forward-looking item gated on FIPS 203
/// §7.2/§7.3 key-validation routines being exposed via the public API.
pub fn ml_kem_encapdecap_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ML-KEM")),
        ("mode", str_val("encapDecap")),
        ("revision", str_val("FIPS203")),
        (
            "parameterSets",
            str_array(&["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]),
        ),
        ("functions", str_array(&["encapsulation", "decapsulation"])),
    ])
}

// ── Post-quantum: ML-DSA ─────────────────────────────────────────

/// Build an ACVP registration block for ML-DSA / keyGen / FIPS204.
///
/// Cap shape mirrors `draft-celi-acvp-ml-dsa §7.3.1`. All three
/// FIPS 204 §4 Table 1 parameter sets (`ML-DSA-44`, `ML-DSA-65`,
/// `ML-DSA-87`) are now advertised; `ML-DSA-87` is the CNSA 2.0
/// digital-signature mandate, the other two ship under
/// `AlgorithmProfile::Unrestricted` per the PQ-expansion mandate
/// (`algo-capability-matrix.md` rows 192–194).
pub fn ml_dsa_keygen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ML-DSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS204")),
        (
            "parameterSets",
            str_array(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        ),
    ])
}

/// Build an ACVP registration block for ML-DSA / sigGen / FIPS204.
///
/// Cap shape mirrors `draft-celi-acvp-ml-dsa §7.4.1`, constrained
/// to oxicrypt-ml-dsa's actual handler subset:
/// - `deterministic: [true]` — only deterministic-mode signing is
///   exposed (FIPS 204 §6.2 Algorithm 7 with rho_prime derived
///   from sk only); the randomized variant is intentionally not
///   built (matrix row 194 — hedged mode is a separate post-launch
///   consideration).
/// - `signatureInterfaces: ["internal"]` — the harness invokes
///   `sign_internal`, which does not consume context bytes; the
///   external interface (`Sign(SK, M, ctx)`) is not advertised.
/// - `externalMu: [false]` — `sign_internal(sk, message)` computes
///   mu internally per FIPS 204 §6.2 step 6; the externalMu=true
///   variant (caller pre-computes mu) is not exposed.
/// - `capabilities[].messageLength: 8..=65536 step 8` — full byte-
///   aligned arbitrary-length message range matching the spec
///   example; oxicrypt-ml-dsa accepts arbitrary message lengths.
/// - `preHash`, `hashAlgs`, `contextLength` deliberately omitted —
///   they apply only to the external interface (which accepts a
///   pre-hashed payload, a hash algorithm tag, and context bytes
///   respectively). Per ACVP server validation observed during
///   the SLH-DSA bring-up (PR #60), advertising
///   `signatureInterfaces: ["internal"]` AND `preHash: [...]` is
///   a registration error: *"Expected no pre-hash options with
///   only internal interface"* (HTTP 400). The internal interface
///   (FIPS 204 §6.2 `Sign_internal`) operates on raw messages;
///   pre-hash modes are an external-interface concept by
///   construction.
pub fn ml_dsa_siggen_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ML-DSA")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("FIPS204")),
        (
            "deterministic",
            JsonValue::Array(vec![JsonValue::Bool(true)]),
        ),
        ("signatureInterfaces", str_array(&["internal"])),
        ("externalMu", JsonValue::Array(vec![JsonValue::Bool(false)])),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                (
                    "parameterSets",
                    str_array(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
                ),
                ("messageLength", range_domain(8, 65536, 8)),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for ML-DSA / sigVer / FIPS204.
///
/// Cap shape mirrors `draft-celi-acvp-ml-dsa §7.5.1`, constrained
/// to the same subset rationale as [`ml_dsa_siggen_capability`]
/// above (internal-interface only, single parameter set,
/// `externalMu: [false]`, no pre-hash options per the
/// internal-interface server-side constraint documented there).
/// `deterministic` is not advertised on sigVer because verification
/// is independent of the signer's randomness mode.
pub fn ml_dsa_sigver_capability() -> JsonValue {
    obj(vec![
        ("algorithm", str_val("ML-DSA")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("FIPS204")),
        ("signatureInterfaces", str_array(&["internal"])),
        ("externalMu", JsonValue::Array(vec![JsonValue::Bool(false)])),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                (
                    "parameterSets",
                    str_array(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
                ),
                ("messageLength", range_domain(8, 65536, 8)),
            ])]),
        ),
    ])
}

// ── Post-quantum: SLH-DSA ────────────────────────────────────────

/// FIPS 205 §11 Table 2 — canonical names for the 12 SLH-DSA parameter
/// sets oxicrypt-slh-dsa builds. SHA-2 family (128/192/256, s/f
/// variants) then SHAKE family. Order matches `oxicrypt-slh-dsa`'s
/// per-variant module layout.
pub(crate) const SLH_DSA_PARAMSETS: &[&str] = &[
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
];

/// Returns `true` iff `name` is one of the 12 FIPS 205 §11 Table 2
/// SLH-DSA parameter sets the harness builds. Case-sensitive (per
/// ACVP spec — paramSet names are exact strings).
///
/// Used by `main.rs` to validate `--paramset` arguments before
/// constructing a session, so unknown names produce a clean CLI
/// error rather than a malformed registration.
#[must_use]
pub fn is_slh_dsa_paramset(name: &str) -> bool {
    SLH_DSA_PARAMSETS.contains(&name)
}

/// Build the `parameterSets` JSON array for an SLH-DSA cap.
///
/// `filter` semantics:
/// - `None` → all 12 names (used by tests and the unfiltered
///   `acvp_capabilities()` trait fallback; back-compat with the
///   bundled-cap shape that shipped for ML-DSA before
///   `feedback_single_algo_per_acvts_session` retired that pattern
///   for new multi-variant PQ families).
/// - `Some(name)` where `name` is in [`SLH_DSA_PARAMSETS`] → a
///   single-element array containing just that name. This is the
///   one-vector-set-per-session shape required by the retired-
///   pattern memory.
/// - `Some(name)` where `name` is unknown → panics. Callers must
///   validate via [`is_slh_dsa_paramset`] before reaching here;
///   panicking is the correct response to a programmer error.
fn slh_dsa_paramsets_array(filter: Option<&str>) -> JsonValue {
    match filter {
        None => str_array(SLH_DSA_PARAMSETS),
        Some(name) => {
            assert!(
                is_slh_dsa_paramset(name),
                "unknown SLH-DSA paramset {name:?} (must be one of {SLH_DSA_PARAMSETS:?})"
            );
            str_array(&[name])
        }
    }
}

/// Build an ACVP registration block for SLH-DSA / keyGen / FIPS205.
///
/// Cap shape mirrors `draft-livelsberger-acvp-slh-dsa §7.3.1`.
/// `paramset_filter`:
/// - `None` → bundled 12-paramSet advertisement (back-compat).
/// - `Some(name)` → single-paramSet advertisement, the one-vector-
///   set-per-session shape per
///   `feedback_single_algo_per_acvts_session` (must be validated
///   via [`is_slh_dsa_paramset`] at the CLI layer first).
///
/// The handler in `super::super::slh_dsa::SlhDsaKeyGenHandler`
/// dispatches each test group to the corresponding
/// `oxicrypt_slh_dsa::slh_dsa_*` per-variant module regardless of
/// which subset of paramSets the cap advertises.
pub fn slh_dsa_keygen_capability(paramset_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("SLH-DSA")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("FIPS205")),
        ("parameterSets", slh_dsa_paramsets_array(paramset_filter)),
    ])
}

/// Build an ACVP registration block for SLH-DSA / sigGen / FIPS205.
///
/// Cap shape mirrors `draft-livelsberger-acvp-slh-dsa §7.4.1`,
/// constrained to oxicrypt-slh-dsa's actual handler subset:
/// - `deterministic: [true]` — only deterministic-mode signing is
///   exposed (FIPS 205 §10.2 Algorithm 22 with `opt_rand = PK.seed`),
///   matching the upstream `sign_internal` API; the FIPS 205 §10.2
///   randomized-mode variant is intentionally not built.
/// - `signatureInterfaces: ["internal"]` — the harness invokes
///   `sign_internal`, which does not consume context bytes; the
///   external interface (`Sign(SK, M, ctx)`) is not advertised.
/// - `capabilities[].messageLength: 8..=65536 step 8` — full byte-
///   aligned arbitrary-length message range matching the spec
///   example; oxicrypt-slh-dsa accepts arbitrary message lengths.
/// - `preHash`, `hashAlgs`, `contextLength` deliberately omitted —
///   they apply only to the external interface (which accepts a
///   pre-hashed payload, a hash algorithm tag, and context bytes
///   respectively). Per ACVP server validation, advertising
///   `signatureInterfaces: ["internal"]` AND `preHash: [...]` is
///   a registration error: *"Expected no pre-hash options with only
///   internal interface"* (HTTP 400). The internal interface
///   (FIPS 205 §10.2 `Sign_internal`) operates on raw messages; pre-
///   hash modes are an external-interface concept by construction.
pub fn slh_dsa_siggen_capability(paramset_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("SLH-DSA")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("FIPS205")),
        (
            "deterministic",
            JsonValue::Array(vec![JsonValue::Bool(true)]),
        ),
        ("signatureInterfaces", str_array(&["internal"])),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("parameterSets", slh_dsa_paramsets_array(paramset_filter)),
                ("messageLength", range_domain(8, 65536, 8)),
            ])]),
        ),
    ])
}

/// Build an ACVP registration block for SLH-DSA / sigVer / FIPS205.
///
/// Cap shape mirrors `draft-livelsberger-acvp-slh-dsa §7.5.2`,
/// constrained to the same subset rationale as
/// [`slh_dsa_siggen_capability`] above (internal-interface only,
/// single parameter set, no pre-hash options per the
/// internal-interface server-side constraint documented there).
/// `deterministic` is not advertised on sigVer because verification
/// is independent of the signer's randomness mode.
pub fn slh_dsa_sigver_capability(paramset_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("SLH-DSA")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("FIPS205")),
        ("signatureInterfaces", str_array(&["internal"])),
        (
            "capabilities",
            JsonValue::Array(vec![obj(vec![
                ("parameterSets", slh_dsa_paramsets_array(paramset_filter)),
                ("messageLength", range_domain(8, 65536, 8)),
            ])]),
        ),
    ])
}

// ── Stateful HBS: LMS ────────────────────────────────────────────

/// Build the `specificCapabilities` array for the single
/// LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4 pair the harness
/// implements.
///
/// Per `draft-celi-acvp-lms §7.3` Table 5, `specificCapabilities`
/// is the explicit-pair form: an array of objects, each with
/// scalar `lmsMode` + `lmOtsMode` strings. The alternative
/// `capabilities` object form (Table 4 — `lmsModes` plural,
/// `lmOtsModes` plural, both arrays) is preferred when the IUT
/// supports a wide cartesian product; for a single registered
/// pair, `specificCapabilities` is more explicit-intent and
/// matches `feedback_caps_match_handler_subset` exactly. The two
/// forms cannot be advertised together (spec note above Table 4).
#[allow(clippy::too_many_lines)]
fn lms_specific_capabilities() -> JsonValue {
    JsonValue::Array(vec![
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHA256_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHA256_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M32_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N32_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H5")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H10")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H15")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H20")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W8")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W1")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W2")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W4")),
        ]),
        obj(vec![
            ("lmsMode", str_val("LMS_SHAKE_M24_H25")),
            ("lmOtsMode", str_val("LMOTS_SHAKE_N24_W8")),
        ]),
    ])
}

/// Build an ACVP registration block for LMS / keyGen / 1.0.
///
/// Cap shape per `draft-celi-acvp-lms §7.3.3`. Subset note: only
/// `LMS_SHA256_M32_H10` paired with `LMOTS_SHA256_N32_W4` (RFC 8554
/// §A.1 typecode 0x00000003 / §A.2 typecode 0x00000003) is built
/// in `oxicrypt-lms`; the 19 other LMS types and remaining LMOTS
/// pairings are tracked under the PQ-expansion mandate
/// (`algo-capability-matrix.md` rows 235–240) and will be added
/// to `specificCapabilities` when their primitives ship.
pub fn lms_keygen_capability(caps_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("keyGen")),
        ("revision", str_val("1.0")),
        (
            "specificCapabilities",
            lms_specific_capabilities_filtered(caps_filter),
        ),
    ])
}

/// Read a string-valued field off a `JsonValue::Object`, or `None` if absent /
/// non-object / non-string. Local helper for [`lms_specific_capabilities_filtered`].
fn obj_str_field<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.as_object()?
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, val)| val.as_str())
}

/// Decide whether an LMS `(lmsMode, lmOtsMode)` pair survives a `--caps-filter`
/// value. `None` keeps everything (the default — the full 80-pair grid). A
/// `Some(spec)` is a DNF over case-sensitive substrings of the composite
/// `"{lmsMode} {lmOtsMode}"`: comma-separated CLAUSES are OR-ed, and within a clause
/// `+`-separated TERMS are AND-ed. So `"H25"` keeps every H25 pair, `"H20,H25"` keeps
/// the H20 and H25 pairs, and `"H20+W4,H20+W8,H25+W4,H25+W8"` is exactly the
/// tall-tree H{20,25}×W{4,8} subset. Empty terms/clauses are ignored (a trailing
/// comma is harmless); a spec with no non-empty clause selects nothing.
fn caps_filter_keep(filter: Option<&str>, lms_mode: &str, lmots_mode: &str) -> bool {
    let Some(spec) = filter else {
        return true;
    };
    let hay = format!("{lms_mode} {lmots_mode}");
    spec.split(',').any(|clause| {
        let mut terms = clause
            .split('+')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .peekable();
        terms.peek().is_some() && terms.all(|t| hay.contains(t))
    })
}

/// The LMS `specificCapabilities` array narrowed by a `--caps-filter` value (see
/// [`caps_filter_keep`]). `None` returns the full 80-pair grid unchanged — so the
/// default registration is byte-identical to the pre-filter behaviour.
fn lms_specific_capabilities_filtered(filter: Option<&str>) -> JsonValue {
    let JsonValue::Array(all) = lms_specific_capabilities() else {
        unreachable!("lms_specific_capabilities always builds a JSON array");
    };
    let kept: Vec<JsonValue> = all
        .into_iter()
        .filter(|pair| {
            let lms = obj_str_field(pair, "lmsMode").unwrap_or_default();
            let lmots = obj_str_field(pair, "lmOtsMode").unwrap_or_default();
            caps_filter_keep(filter, lms, lmots)
        })
        .collect();
    JsonValue::Array(kept)
}

/// Build an ACVP registration block for LMS / sigGen / 1.0.
///
/// Cap shape per `draft-celi-acvp-lms §7.3.4`. Same subset
/// rationale as [`lms_keygen_capability`].
///
/// LMS sigGen has an inverted ACVP protocol model vs ML-DSA /
/// SLH-DSA: per `§9.2` Table 16 the IUT supplies its own
/// `publicKey` at group level in the response (the server prompt
/// has no key information per §8.2.1 Table 9 / §8.2.2 Table 10).
/// This is structural for stateful HBS — the server can't dictate
/// a key for a one-time-leaf scheme. The handler in `lms.rs`
/// generates a deterministic per-group key from `tgId` so prompt
/// replays produce identical responses.
pub fn lms_siggen_capability(caps_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("1.0")),
        (
            "specificCapabilities",
            lms_specific_capabilities_filtered(caps_filter),
        ),
    ])
}

/// Build an ACVP registration block for LMS / sigVer / 1.0.
///
/// Cap shape per `draft-celi-acvp-lms §7.3.5`. Same subset
/// rationale as [`lms_keygen_capability`].
pub fn lms_sigver_capability(caps_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("1.0")),
        (
            "specificCapabilities",
            lms_specific_capabilities_filtered(caps_filter),
        ),
    ])
}

/// Message lengths (bits) declared for the `SP800-208` LMS revision.
///
/// 16, 128 and 1024 bytes: byte-aligned, spanning roughly two orders of
/// magnitude so the variable-length path is exercised rather than
/// nominally declared. Deliberately not characterised in hash-block
/// terms — this one array serves every family in the grid, whose block
/// or rate sizes differ (SHA-256 64 B, SHAKE256 136 B, SHAKE128 168 B),
/// so no single value sits at the same block boundary for all of them.
/// 16 B is sub-block everywhere and 1024 B is multi-block everywhere;
/// 128 B straddles (multi-block for SHA-256, sub-rate for both SHAKEs).
/// LMS hashes the message, so length is not cryptographically
/// constrained.
const LMS_SP800_208_MESSAGE_LENGTHS: &[i64] = &[128, 1024, 8192];

/// Build an ACVP registration block for LMS / sigGen / `SP800-208`.
///
/// The `SP800-208` counterpart to [`lms_siggen_capability`], adding the
/// top-level `messageLength` domain that revision `1.0` lacks. The
/// inverted key model is unchanged from revision `1.0` — the IUT still
/// supplies its own group-level `publicKey` in the response — so this
/// shares `handle_siggen_group`, which decodes each test's `message`
/// with no fixed-size assumption.
pub fn lms_siggen_sp800_208_capability(caps_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigGen")),
        ("revision", str_val("SP800-208")),
        (
            "specificCapabilities",
            lms_specific_capabilities_filtered(caps_filter),
        ),
        ("messageLength", num_array(LMS_SP800_208_MESSAGE_LENGTHS)),
    ])
}

/// Build an ACVP registration block for LMS / sigVer / `SP800-208`.
///
/// Distinct from [`lms_sigver_capability`] (revision `1.0`), not a
/// relabel: per `draft-celi-acvp-lms §5` the `SP800-208` revision adds
/// a top-level `messageLength` field — "The `messageLength` field is
/// only applicable to LMS / sigGen / SP800-208, and LMS / sigVer /
/// SP800-208" — which revision `1.0` does not carry. Verification
/// itself is unchanged, so this shares `handle_sigver_group`; the
/// handler already decodes `message` to a `Vec<u8>` with no fixed-size
/// assumption.
///
/// `messageLength` sits at the TOP level of the capability object, not
/// inside `specificCapabilities`. The registration declares
/// `specificCapabilities` only — per the draft a registration must not
/// carry both `capabilities` and `specificCapabilities`.
///
/// There is deliberately no keyGen counterpart: key generation has no
/// message, so the server advertises `SP800-208` for sigGen/sigVer only.
pub fn lms_sigver_sp800_208_capability(caps_filter: Option<&str>) -> JsonValue {
    obj(vec![
        ("algorithm", str_val("LMS")),
        ("mode", str_val("sigVer")),
        ("revision", str_val("SP800-208")),
        (
            "specificCapabilities",
            lms_specific_capabilities_filtered(caps_filter),
        ),
        ("messageLength", num_array(LMS_SP800_208_MESSAGE_LENGTHS)),
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

// ── Tests: SLH-DSA paramset filter (B7 precursor) ───────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::uninlined_format_args)]
mod tests {
    use super::*;

    /// Helper: find `parameterSets` array on a keyGen-shaped cap
    /// (top-level field).
    fn keygen_paramsets(cap: &JsonValue) -> Vec<&str> {
        let pairs = cap.as_object().unwrap();
        let v = pairs
            .iter()
            .find(|(k, _)| k == "parameterSets")
            .map(|(_, v)| v)
            .unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect()
    }

    /// Helper: find `parameterSets` array on a sigGen/sigVer-shaped
    /// cap (nested under `capabilities[0].parameterSets`).
    fn nested_paramsets(cap: &JsonValue) -> Vec<&str> {
        let pairs = cap.as_object().unwrap();
        let caps_arr = pairs
            .iter()
            .find(|(k, _)| k == "capabilities")
            .map(|(_, v)| v)
            .unwrap()
            .as_array()
            .unwrap();
        let first = caps_arr.first().unwrap();
        let inner = first.as_object().unwrap();
        let ps = inner
            .iter()
            .find(|(k, _)| k == "parameterSets")
            .map(|(_, v)| v)
            .unwrap();
        ps.as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect()
    }

    #[test]
    fn slh_dsa_keygen_unfiltered_advertises_all_12_paramsets() {
        let cap = slh_dsa_keygen_capability(None);
        let sets = keygen_paramsets(&cap);
        assert_eq!(sets.len(), 12, "expected 12 paramSets, got {sets:?}");
        assert!(sets.contains(&"SLH-DSA-SHA2-128s"));
        assert!(sets.contains(&"SLH-DSA-SHAKE-256f"));
    }

    #[test]
    fn slh_dsa_keygen_filtered_emits_exactly_one_paramset() {
        let cap = slh_dsa_keygen_capability(Some("SLH-DSA-SHA2-128s"));
        let sets = keygen_paramsets(&cap);
        assert_eq!(sets, vec!["SLH-DSA-SHA2-128s"]);
    }

    #[test]
    fn slh_dsa_siggen_filtered_emits_exactly_one_paramset_nested() {
        let cap = slh_dsa_siggen_capability(Some("SLH-DSA-SHAKE-192f"));
        let sets = nested_paramsets(&cap);
        assert_eq!(sets, vec!["SLH-DSA-SHAKE-192f"]);
    }

    #[test]
    fn slh_dsa_sigver_filtered_emits_exactly_one_paramset_nested() {
        let cap = slh_dsa_sigver_capability(Some("SLH-DSA-SHA2-256f"));
        let sets = nested_paramsets(&cap);
        assert_eq!(sets, vec!["SLH-DSA-SHA2-256f"]);
    }

    #[test]
    fn slh_dsa_siggen_unfiltered_still_bundles_all_12() {
        let cap = slh_dsa_siggen_capability(None);
        let sets = nested_paramsets(&cap);
        assert_eq!(sets.len(), 12);
    }

    #[test]
    fn slh_dsa_sigver_unfiltered_still_bundles_all_12() {
        let cap = slh_dsa_sigver_capability(None);
        let sets = nested_paramsets(&cap);
        assert_eq!(sets.len(), 12);
    }

    #[test]
    fn is_slh_dsa_paramset_accepts_each_of_12() {
        for name in [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ] {
            assert!(is_slh_dsa_paramset(name), "expected {name} to be valid");
        }
    }

    #[test]
    fn is_slh_dsa_paramset_rejects_unknown_names() {
        assert!(!is_slh_dsa_paramset("SLH-DSA-NOT-A-THING"));
        assert!(!is_slh_dsa_paramset("slh-dsa-sha2-128s")); // case-sensitive
        assert!(!is_slh_dsa_paramset(""));
        assert!(!is_slh_dsa_paramset("SLH-DSA-SHA2-128")); // missing s/f suffix
    }

    #[test]
    #[should_panic(expected = "unknown SLH-DSA paramset")]
    fn slh_dsa_keygen_panics_on_unknown_paramset() {
        let _ = slh_dsa_keygen_capability(Some("not-a-real-name"));
    }

    // ── LMS --caps-filter (the runtime tall-tree subset) ────────────

    /// Helper: the `(lmsMode, lmOtsMode)` pairs of an LMS cap's
    /// `specificCapabilities` array.
    fn lms_pairs(cap: &JsonValue) -> Vec<(&str, &str)> {
        let sc = cap
            .as_object()
            .unwrap()
            .iter()
            .find(|(k, _)| k == "specificCapabilities")
            .map(|(_, v)| v)
            .unwrap();
        sc.as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let o = p.as_object().unwrap();
                let get = |key: &str| {
                    o.iter()
                        .find(|(k, _)| k == key)
                        .and_then(|(_, v)| v.as_str())
                        .unwrap()
                };
                (get("lmsMode"), get("lmOtsMode"))
            })
            .collect()
    }

    #[test]
    fn lms_caps_unfiltered_advertises_the_full_80_grid() {
        // No filter == the full grid, byte-identical to the pre-filter behaviour.
        assert_eq!(
            lms_pairs(&lms_keygen_capability(None)).len(),
            80,
            "the full LMS grid is 80 (lmsMode, lmOtsMode) pairs"
        );
        assert_eq!(lms_pairs(&lms_siggen_capability(None)).len(), 80);
        assert_eq!(lms_pairs(&lms_sigver_capability(None)).len(), 80);
    }

    #[test]
    fn lms_sp800_208_cap_shape() {
        for (mode, cap) in [
            ("sigGen", lms_siggen_sp800_208_capability(None)),
            ("sigVer", lms_sigver_sp800_208_capability(None)),
        ] {
            check_sp800_208_cap(mode, &cap);
        }
    }

    /// Shared assertions for both SP800-208 LMS capability blocks.
    fn check_sp800_208_cap(mode: &str, cap: &JsonValue) {
        assert_eq!(obj_str_field(cap, "algorithm"), Some("LMS"));
        assert_eq!(obj_str_field(cap, "mode"), Some(mode));
        assert_eq!(
            obj_str_field(cap, "revision"),
            Some("SP800-208"),
            "{mode} must register under the new revision, not 1.0"
        );

        // Same 80-pair grid as revision 1.0 — the revision changes the
        // message-length dimension, not which (lmsMode, lmOtsMode) pairs exist.
        assert_eq!(lms_pairs(cap).len(), 80);

        // messageLength is TOP-level per draft-celi-acvp-lms, not nested
        // inside specificCapabilities.
        let JsonValue::Object(fields) = cap else {
            panic!("capability is a JSON object");
        };
        let Some((_, msg_len)) = fields.iter().find(|(k, _)| k == "messageLength") else {
            panic!("SP800-208 declares a top-level messageLength");
        };
        let JsonValue::Array(lengths) = msg_len else {
            panic!("messageLength is a JSON array of integers");
        };
        assert!(!lengths.is_empty(), "at least one message length");
        assert!(
            lengths.len() > 1,
            "declare a spread of lengths so the variable-length path is exercised"
        );

        // A registration must not carry both `capabilities` and
        // `specificCapabilities`; the server rejects that outright.
        assert!(
            !fields.iter().any(|(k, _)| k == "capabilities"),
            "specificCapabilities and capabilities are mutually exclusive"
        );

        // The matching revision-1.0 block must NOT sprout a messageLength.
        let v1 = if mode == "sigGen" {
            lms_siggen_capability(None)
        } else {
            lms_sigver_capability(None)
        };
        let JsonValue::Object(v1_fields) = v1 else {
            panic!("capability is a JSON object");
        };
        assert!(
            !v1_fields.iter().any(|(k, _)| k == "messageLength"),
            "messageLength applies only to the SP800-208 revision ({mode})"
        );
    }

    #[test]
    fn lms_caps_filter_scopes_to_the_tall_tree_subset() {
        // Tall-tree H{20,25} × W{4,8} across the four hash/length families.
        let cap = lms_keygen_capability(Some("H20+W4,H20+W8,H25+W4,H25+W8"));
        let pairs = lms_pairs(&cap);
        assert_eq!(pairs.len(), 16, "2 heights × 2 widths × 4 families");
        for (lms, lmots) in &pairs {
            let hay = format!("{lms} {lmots}");
            assert!(
                hay.contains("H20") || hay.contains("H25"),
                "only tall trees survive: {hay}"
            );
            assert!(
                hay.contains("W4") || hay.contains("W8"),
                "only W4/W8 survive: {hay}"
            );
        }
    }

    #[test]
    fn lms_caps_filter_or_clause_keeps_every_h25() {
        let cap = lms_siggen_capability(Some("H25"));
        let pairs = lms_pairs(&cap);
        assert_eq!(pairs.len(), 16, "H25 across 4 widths × 4 families");
        assert!(pairs.iter().all(|(lms, _)| lms.contains("H25")));
    }

    #[test]
    fn lms_caps_filter_and_terms_pin_one_pair() {
        let cap = lms_sigver_capability(Some("H25+W8+SHA256_M32"));
        let pairs = lms_pairs(&cap);
        assert_eq!(pairs.len(), 1, "a fully-qualified clause pins one pair");
        assert_eq!(pairs[0], ("LMS_SHA256_M32_H25", "LMOTS_SHA256_N32_W8"));
    }

    #[test]
    fn lms_caps_filter_separators_only_selects_nothing() {
        // A spec with no non-empty clause keeps no pair (rather than everything).
        let cap = lms_keygen_capability(Some(",,"));
        assert_eq!(lms_pairs(&cap).len(), 0);
    }
}
