//! Algorithm-handler registry and the top-level [`process`] entry point.
//!
//! The dispatcher is intentionally tiny: a [`Registry`] holds a flat
//! list of [`AlgorithmHandler`] trait objects keyed on
//! `(algorithm, mode, revision)`, and [`process`] looks up the right
//! handler for the prompt's envelope and forwards each test group to
//! it. The `mode` slot is `Option<&str>` so that single-field families
//! (SHA-3, SHAKE, HMAC) key on `(algorithm, None, revision)` and
//! dual-field families (KDA-HKDF, KDA-OneStep, KDA-TwoStep) key on
//! `(algorithm, Some(mode), revision)` on the same trait object and
//! the same `find` path.
//!
//! # Module gating
//!
//! Every call to [`process`] starts with
//! `oxicrypt_module::require_operational()`. The harness binary has
//! already run the power-up KAT set by the time this code is reached,
//! but a defensive re-check here means that *any* code path leading
//! into the dispatcher — integration tests, future REST front-ends,
//! standalone fuzz harnesses — gets the same gate without having to
//! remember it.

use crate::envelope::{EnvelopeError, VectorSet};
use crate::handlers;
use crate::hex::HexError;
use crate::json::JsonValue;
use core::fmt;

/// Errors produced by [`process`] and the per-algorithm handlers.
#[derive(Debug)]
pub enum DispatchError {
    /// Failed to peel the ACVP envelope.
    Envelope(EnvelopeError),
    /// The oxicrypt module is not in the operational state.
    Module(oxicrypt_module::Error),
    /// A primitive returned an error or produced an unexpected shape.
    Crypto(&'static str),
    /// A hex-encoded data field could not be decoded.
    Hex(HexError),
    /// A required ACVP field is missing from a test case or group.
    MissingField(&'static str),
    /// No handler is registered for the prompt's algorithm/revision.
    UnsupportedAlgorithm {
        /// Algorithm name as it appears in the prompt.
        algorithm: String,
        /// Mode string as it appears in the prompt (if present).
        mode: Option<String>,
        /// Revision string as it appears in the prompt.
        revision: String,
    },
    /// The handler does not implement the requested `testType`.
    UnsupportedTestType(String),
    /// The handler does not yet support a feature the test exercises.
    Unsupported(&'static str),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "envelope: {e}"),
            Self::Module(e) => write!(f, "module: {e}"),
            Self::Crypto(s) => write!(f, "crypto: {s}"),
            Self::Hex(e) => write!(f, "hex: {e}"),
            Self::MissingField(name) => write!(f, "missing field {name:?}"),
            Self::UnsupportedAlgorithm {
                algorithm,
                mode,
                revision,
            } => match mode {
                Some(m) => write!(
                    f,
                    "no handler registered for algorithm {algorithm:?} mode {m:?} revision {revision:?}"
                ),
                None => write!(
                    f,
                    "no handler registered for algorithm {algorithm:?} revision {revision:?}"
                ),
            },
            Self::UnsupportedTestType(t) => write!(f, "unsupported testType {t:?}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl From<EnvelopeError> for DispatchError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl From<HexError> for DispatchError {
    fn from(e: HexError) -> Self {
        Self::Hex(e)
    }
}

/// Trait implemented by every per-algorithm AFT dispatcher.
///
/// Handlers are stateless: the `&self` receiver lets the registry
/// store them as `Box<dyn AlgorithmHandler>` while keeping the
/// dispatch path branchless on the trait-object call.
pub trait AlgorithmHandler: Send + Sync {
    /// ACVP algorithm name (e.g. `"SHA3-256"`, `"KDA"`).
    fn algorithm(&self) -> &'static str;

    /// Optional ACVP `mode` string (e.g. `Some("HKDF")` for
    /// `KDA-HKDF-Sp800-56Cr2`). Single-field families return the
    /// default `None`.
    fn mode(&self) -> Option<&'static str> {
        None
    }

    /// ACVP revision string (e.g. `"2.0"`, `"Sp800-56Cr2"`).
    fn revision(&self) -> &'static str;

    /// Process a single test group, returning the response group.
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError>;

    /// Return the ACVP registration capability block for this handler,
    /// or `None` if the handler has not yet declared its capabilities.
    ///
    /// When implemented, this should return a `JsonValue::Object` with
    /// at least `algorithm`, `revision`, and enough capability detail
    /// for the ACVP demo server to generate matching vector sets.
    ///
    /// Default is `None` — handlers opt in one at a time as we wire
    /// up the transport client.
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        None
    }
}

/// Mutable handler registry. Constructed with
/// [`with_default_handlers`] for normal use.
pub struct Registry {
    handlers: Vec<Box<dyn AlgorithmHandler>>,
}

impl Registry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a handler. Last-write-wins is the caller's
    /// responsibility — `find` returns the first match.
    pub fn register(&mut self, h: Box<dyn AlgorithmHandler>) {
        self.handlers.push(h);
    }

    /// Look up a handler by algorithm/mode/revision. `mode` is
    /// `None` for single-field families (SHA-3, SHAKE, HMAC) and
    /// `Some(mode)` for dual-field families (KDA-HKDF, KDA-OneStep,
    /// KDA-TwoStep). The match is exact on all three components, so
    /// `(SHA3-256, None, 2.0)` will not collide with a future
    /// `(SHA3-256, Some("something"), 2.0)`.
    #[must_use]
    pub fn find(
        &self,
        algorithm: &str,
        mode: Option<&str>,
        revision: &str,
    ) -> Option<&dyn AlgorithmHandler> {
        self.handlers
            .iter()
            .find(|h| h.algorithm() == algorithm && h.mode() == mode && h.revision() == revision)
            .map(AsRef::as_ref)
    }

    /// Number of registered handlers (used by the CLI banner and tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether any handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Iterate over all registered handlers, calling `f` on each one.
    ///
    /// Used by the transport client to collect ACVP registration
    /// capabilities from every handler that has declared them.
    pub fn for_each_handler(&self, mut f: impl FnMut(&dyn AlgorithmHandler)) {
        for h in &self.handlers {
            f(h.as_ref());
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct a [`Registry`] populated with every algorithm handler
/// the harness currently knows how to dispatch.
///
/// R10 wired the first two handlers — SHA3-256 AFT and HMAC-SHA2-256
/// AFT — end-to-end. R12-A expanded the SHA-3 hashing family, both
/// SHAKE XOFs, and every HMAC variant except HMAC-SHA2-256 (which
/// stays in its R10 module), bringing the total to seventeen
/// AFT handlers; R13 then added the first KDF family handler,
/// `KDA-HKDF-Sp800-56Cr2`, as the eighteenth. That is also the first
/// handler to live in a `(algorithm, mode, revision)` registry slot
/// rather than `(algorithm, None, revision)`:
///
/// - `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512` (revision `2.0`)
/// - `SHAKE-128`, `SHAKE-256` (revision `FIPS202`)
/// - `HMAC-SHA-1` (revision `1.0`)
/// - `HMAC-SHA2-{224,256,384,512}` and the two truncated
///   `HMAC-SHA2-512/{224,256}` variants (revision `1.0`)
/// - `HMAC-SHA3-{224,256,384,512}` (revision `1.0`)
/// - `KDA` mode `HKDF` revision `Sp800-56Cr2` — SP 800-56C Rev 2 §5
///   two-step KDF (hybrid form, ten HMAC instantiations)
/// - `ACVP-AES-ECB`, `ACVP-AES-CBC`, `ACVP-AES-CTR` (revision `1.0`)
///   — R14-A AFT across 128/192/256-bit keys, encrypt + decrypt
/// - `ACVP-AES-GCM`, `ACVP-AES-CCM`, `ACVP-AES-KW`, `ACVP-AES-KWP`
///   (revision `1.0`) — R14-B AFT with AEAD `testPassed` verification
///
/// R15 adds the MCT (Monte Carlo Test) engine for ECB and CBC
/// (100×1000 iteration loop, key-schedule update, direction-aware
/// CBC IV feedback). The same handler structs serve both AFT and MCT
/// test types — the `handle_group` impl routes on `testType`.
///
/// R16 adds `CMAC-AES` revision `1.0` — SP 800-38B CMAC with gen
/// (compute MAC) and ver (verify MAC / `testPassed`) directions over
/// all three AES key sizes.
///
/// R17 adds three DRBG family handlers — `ctrDRBG`, `hashDRBG`, and
/// `hmacDRBG` (all revision `1.0`) — covering CTR_DRBG AES-128/192/256
/// with and without derivation function, Hash_DRBG SHA2-256/384/512,
/// and HMAC_DRBG SHA2-256/384/512, each with and without prediction
/// resistance.
///
/// R18 adds five asymmetric signature-verification and key-validation
/// handlers — `ECDSA` sigVer + keyVer (P-256/SHA2-256), `EDDSA`
/// sigVer + keyVer (ED-25519, pure), and `RSA` sigVer
/// (RSA-2048/PKCS#1v1.5/SHA2-256, GDT).
///
/// R19 adds two SigGen handlers — `ECDSA` sigGen (P-256/SHA2-256,
/// deterministic via caller-supplied `k`) and `EDDSA` sigGen
/// (ED-25519, pure, naturally deterministic).
///
/// R20 adds the SP 800-108r1 KBKDF handler (`KDF` revision `1.0`)
/// covering counter, feedback, and double-pipeline iteration modes
/// across all eleven HMAC instantiations — reaching thirty-seven
/// registered handlers.
#[must_use]
pub fn with_default_handlers() -> Registry {
    let mut r = Registry::new();
    // SHA-3 family (fixed-output hashing, revision 2.0)
    r.register(Box::new(handlers::sha3::Sha3_224Handler));
    r.register(Box::new(handlers::sha3_256::Sha3_256Handler));
    r.register(Box::new(handlers::sha3::Sha3_384Handler));
    r.register(Box::new(handlers::sha3::Sha3_512Handler));
    // SHAKE XOFs (revision FIPS202)
    r.register(Box::new(handlers::shake::Shake128Handler));
    r.register(Box::new(handlers::shake::Shake256Handler));
    // HMAC-SHA-1 (legacy, revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha1Handler));
    // HMAC-SHA-2 family (revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha2_224Handler));
    r.register(Box::new(handlers::hmac_sha2_256::HmacSha2_256Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_384Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512_224Handler));
    r.register(Box::new(handlers::hmac::HmacSha2_512_256Handler));
    // HMAC-SHA-3 family (revision 1.0)
    r.register(Box::new(handlers::hmac::HmacSha3_224Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_256Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_384Handler));
    r.register(Box::new(handlers::hmac::HmacSha3_512Handler));
    // CMAC-AES (SP 800-38B, revision 1.0)
    r.register(Box::new(handlers::cmac::CmacAesHandler));
    // SP 800-108r1 KBKDF (counter / feedback / double pipeline, revision 1.0)
    r.register(Box::new(handlers::kbkdf::KbkdfHandler));
    // KDA-HKDF (SP 800-56Cr2, mode-keyed)
    r.register(Box::new(handlers::kda_hkdf::KdaHkdfHandler));
    // AES block-cipher modes (R14-A: ECB/CBC/CTR AFT)
    r.register(Box::new(handlers::aes::AesEcbHandler));
    r.register(Box::new(handlers::aes::AesCbcHandler));
    r.register(Box::new(handlers::aes::AesCtrHandler));
    // AES AEAD / key-wrap modes (R14-B: GCM/CCM/KW/KWP AFT)
    r.register(Box::new(handlers::aes::AesGcmHandler));
    r.register(Box::new(handlers::aes::AesCcmHandler));
    r.register(Box::new(handlers::aes::AesKwHandler));
    r.register(Box::new(handlers::aes::AesKwpHandler));
    // DRBG families (R17: ctrDRBG / hashDRBG / hmacDRBG)
    r.register(Box::new(handlers::drbg::CtrDrbgHandler));
    r.register(Box::new(handlers::drbg::HashDrbgHandler));
    r.register(Box::new(handlers::drbg::HmacDrbgHandler));
    // ECDSA sigVer + keyVer + sigGen + keyGen (R18/R19/R29: P-256 / SHA2-256, FIPS186-5)
    r.register(Box::new(handlers::ecdsa::EcdsaSigVerHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaKeyVerHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaSigGenHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaKeyGenHandler));
    // EdDSA sigVer + keyVer + sigGen + keyGen (R18/R19/R28: ED-25519, pure, 1.0)
    r.register(Box::new(handlers::eddsa::EddsaSigVerHandler));
    r.register(Box::new(handlers::eddsa::EddsaKeyVerHandler));
    r.register(Box::new(handlers::eddsa::EddsaSigGenHandler));
    r.register(Box::new(handlers::eddsa::EddsaKeyGenHandler));
    // RSA sigVer (R18: RSA-2048 / PKCS#1v1.5 / SHA2-256, FIPS186-5)
    r.register(Box::new(handlers::rsa::RsaSigVerHandler));
    r.register(Box::new(handlers::rsa_decprim::RsaDecPrimHandler));
    // TLS v1.2 KDF (R22: RFC 7627 Extended Master Secret)
    r.register(Box::new(handlers::tls12_kdf::Tls12KdfRfc7627Handler));
    // kdf-components / tls (R23: standard TLS 1.2 KDF, non-EMS)
    r.register(Box::new(handlers::kdf_comp_tls::KdfComponentsTlsHandler));
    // RSA signaturePrimitive (R24: RSASP1 with CRT + Bellcore)
    r.register(Box::new(handlers::rsa_sigprim::RsaSigPrimHandler));
    // RSA sigGen (R25: PKCS#1v1.5 non-CRT + PSS CRT, FIPS186-5)
    r.register(Box::new(handlers::rsa_siggen::RsaSigGenHandler));
    // KAS-ECC-SSC (R26: P-256 ECDH shared secret, Sp800-56Ar3; R59: add P-384)
    r.register(Box::new(handlers::kas_ecc_ssc::KasEccSscHandler));
    // KAS-FFC-SSC (R59: DH-3072 shared secret computation, Sp800-56Ar3)
    r.register(Box::new(handlers::kas_ffc_ssc::KasFfcSscHandler));
    // RSA OAEP (R27: encrypt/decrypt, RFC8017, RSA-2048/SHA2-256)
    r.register(Box::new(handlers::rsa_oaep::RsaOaepHandler));
    // RSA KeyGen (R32: FIPS186-5, RSA-2048, e=65537, DRBG-seeded)
    r.register(Box::new(handlers::rsa_keygen::RsaKeyGenHandler));
    // SP 800-185 derived functions (R55: self-generated vectors)
    r.register(Box::new(handlers::cshake::CShake128Handler));
    r.register(Box::new(handlers::cshake::CShake256Handler));
    r.register(Box::new(handlers::kmac::Kmac128Handler));
    r.register(Box::new(handlers::kmac::Kmac256Handler));
    r.register(Box::new(handlers::tuplehash::TupleHash128Handler));
    r.register(Box::new(handlers::tuplehash::TupleHash256Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHash128Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHash256Handler));
    // SP 800-185 XOF variants (R56: self-generated vectors)
    r.register(Box::new(handlers::kmac::KmacXof128Handler));
    r.register(Box::new(handlers::kmac::KmacXof256Handler));
    r.register(Box::new(handlers::tuplehash::TupleHashXof128Handler));
    r.register(Box::new(handlers::tuplehash::TupleHashXof256Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHashXof128Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHashXof256Handler));
    // PBKDF2 (SP 800-132 / RFC 8018, R55: self-generated vectors)
    r.register(Box::new(handlers::pbkdf2::Pbkdf2Handler));
    // ML-KEM-1024 (R59: keyGen / encaps / decaps, FIPS 203, post-quantum)
    r.register(Box::new(handlers::ml_kem::MlKem1024KeyGenHandler));
    r.register(Box::new(handlers::ml_kem::MlKem1024EncapsHandler));
    r.register(Box::new(handlers::ml_kem::MlKem1024DecapsHandler));
    // ML-DSA-87 (R60: keyGen / sigGen / sigVer, FIPS 204, post-quantum)
    r.register(Box::new(handlers::ml_dsa::MlDsa87KeyGenHandler));
    r.register(Box::new(handlers::ml_dsa::MlDsa87SigGenHandler));
    r.register(Box::new(handlers::ml_dsa::MlDsa87SigVerHandler));
    // SLH-DSA-SHA2-256s (R61: keyGen / sigGen / sigVer, FIPS 205, post-quantum)
    r.register(Box::new(handlers::slh_dsa::SlhDsaKeyGenHandler));
    r.register(Box::new(handlers::slh_dsa::SlhDsaSigGenHandler));
    r.register(Box::new(handlers::slh_dsa::SlhDsaSigVerHandler));
    // LMS (R62: keyGen / sigGen / sigVer, SP 800-208 / RFC 8554)
    r.register(Box::new(handlers::lms::LmsKeyGenHandler));
    r.register(Box::new(handlers::lms::LmsSigGenHandler));
    r.register(Box::new(handlers::lms::LmsSigVerHandler));
    // XMSS (R62: keyGen / sigGen / sigVer, SP 800-208 / RFC 8391)
    r.register(Box::new(handlers::xmss::XmssKeyGenHandler));
    r.register(Box::new(handlers::xmss::XmssSigGenHandler));
    r.register(Box::new(handlers::xmss::XmssSigVerHandler));
    r
}

/// Top-level dispatcher: take an ACVP prompt as a `JsonValue`,
/// produce a response as a `JsonValue`.
///
/// On success, the response object preserves the prompt's `algorithm`
/// and `revision` fields and contains a `testGroups` array whose
/// shape is determined by the per-algorithm handler.
pub fn process(prompt: &JsonValue, registry: &Registry) -> Result<JsonValue, DispatchError> {
    oxicrypt_module::require_operational().map_err(DispatchError::Module)?;
    let vs = VectorSet::new(prompt)?;
    let algorithm = vs.algorithm()?;
    let mode = vs.mode()?;
    let revision = vs.revision()?;
    let handler = registry.find(algorithm, mode, revision).ok_or_else(|| {
        DispatchError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            mode: mode.map(str::to_string),
            revision: revision.to_string(),
        }
    })?;
    let groups = vs.test_groups()?;
    let mut response_groups: Vec<JsonValue> = Vec::with_capacity(groups.len());
    for g in groups {
        response_groups.push(handler.handle_group(g)?);
    }
    let mut response: Vec<(String, JsonValue)> = Vec::with_capacity(4);
    response.push((
        "algorithm".to_string(),
        JsonValue::String(algorithm.to_string()),
    ));
    if let Some(m) = mode {
        response.push(("mode".to_string(), JsonValue::String(m.to_string())));
    }
    response.push((
        "revision".to_string(),
        JsonValue::String(revision.to_string()),
    ));
    response.push(("testGroups".to_string(), JsonValue::Array(response_groups)));
    Ok(JsonValue::Object(response))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn registry_lookup() {
        let r = with_default_handlers();
        // R10 handlers
        assert!(r.find("SHA3-256", None, "2.0").is_some());
        assert!(r.find("HMAC-SHA2-256", None, "1.0").is_some());
        // R12-A SHA-3 family
        assert!(r.find("SHA3-224", None, "2.0").is_some());
        assert!(r.find("SHA3-384", None, "2.0").is_some());
        assert!(r.find("SHA3-512", None, "2.0").is_some());
        // R12-A SHAKE XOFs
        assert!(r.find("SHAKE-128", None, "FIPS202").is_some());
        assert!(r.find("SHAKE-256", None, "FIPS202").is_some());
        // R12-A HMAC family
        assert!(r.find("HMAC-SHA-1", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-384", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512/224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA2-512/256", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-224", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-256", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-384", None, "1.0").is_some());
        assert!(r.find("HMAC-SHA3-512", None, "1.0").is_some());
        // R13 KDA-HKDF (mode-keyed)
        assert!(r.find("KDA", Some("HKDF"), "Sp800-56Cr2").is_some());
        // R14-A AES AFT modes
        assert!(r.find("ACVP-AES-ECB", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CBC", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CTR", None, "1.0").is_some());
        // R14-B AES AEAD / key-wrap modes
        assert!(r.find("ACVP-AES-GCM", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CCM", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-KW", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-KWP", None, "1.0").is_some());
        // R16 CMAC-AES
        assert!(r.find("CMAC-AES", None, "1.0").is_some());
        // R17 DRBG families
        assert!(r.find("ctrDRBG", None, "1.0").is_some());
        assert!(r.find("hashDRBG", None, "1.0").is_some());
        assert!(r.find("hmacDRBG", None, "1.0").is_some());
        // R18 ECDSA / EdDSA / RSA verification
        assert!(r.find("ECDSA", Some("sigVer"), "FIPS186-5").is_some());
        assert!(r.find("ECDSA", Some("keyVer"), "FIPS186-5").is_some());
        assert!(r.find("EDDSA", Some("sigVer"), "1.0").is_some());
        assert!(r.find("EDDSA", Some("keyVer"), "1.0").is_some());
        assert!(r.find("RSA", Some("sigVer"), "FIPS186-5").is_some());
        // R19 ECDSA / EdDSA SigGen
        assert!(r.find("ECDSA", Some("sigGen"), "FIPS186-5").is_some());
        assert!(r.find("EDDSA", Some("sigGen"), "1.0").is_some());
        // R28 EdDSA KeyGen
        assert!(r.find("EDDSA", Some("keyGen"), "1.0").is_some());
        // R29 ECDSA KeyGen
        assert!(r.find("ECDSA", Some("keyGen"), "FIPS186-5").is_some());
        // R20 KBKDF (SP 800-108r1)
        assert!(r.find("KDF", None, "1.0").is_some());
        // R21 RSA DecryptionPrimitive (SP 800-56Br2)
        assert!(r
            .find("RSA", Some("decryptionPrimitive"), "Sp800-56Br2")
            .is_some());
        // R22 TLS v1.2 KDF (RFC 7627)
        assert!(r.find("TLS-v1.2", Some("KDF"), "RFC7627").is_some());
        // R23 kdf-components / tls
        assert!(r.find("kdf-components", Some("tls"), "1.0").is_some());
        // R24 RSA SignaturePrimitive
        assert!(r.find("RSA", Some("signaturePrimitive"), "2.0").is_some());
        // R25 RSA SigGen
        assert!(r.find("RSA", Some("sigGen"), "FIPS186-5").is_some());
        // R26 KAS-ECC-SSC
        assert!(r
            .find("KAS-ECC-SSC", Some("Component"), "Sp800-56Ar3")
            .is_some());
        // R59 KAS-FFC-SSC
        assert!(r
            .find("KAS-FFC-SSC", Some("Component"), "Sp800-56Ar3")
            .is_some());
        // R27 RSA OAEP
        assert!(r.find("RSA", Some("OAEP"), "RFC8017").is_some());
        // R55 SP 800-185 derived functions + PBKDF2
        assert!(r.find("cSHAKE-128", None, "1.0").is_some());
        assert!(r.find("cSHAKE-256", None, "1.0").is_some());
        assert!(r.find("KMAC-128", None, "1.0").is_some());
        assert!(r.find("KMAC-256", None, "1.0").is_some());
        assert!(r.find("TupleHash-128", None, "1.0").is_some());
        assert!(r.find("TupleHash-256", None, "1.0").is_some());
        assert!(r.find("ParallelHash-128", None, "1.0").is_some());
        assert!(r.find("ParallelHash-256", None, "1.0").is_some());
        // R55 PBKDF2
        assert!(r.find("PBKDF", None, "1.0").is_some());
        // R56 SP 800-185 XOF variants
        assert!(r.find("KMACXOF-128", None, "1.0").is_some());
        assert!(r.find("KMACXOF-256", None, "1.0").is_some());
        assert!(r.find("TupleHashXOF-128", None, "1.0").is_some());
        assert!(r.find("TupleHashXOF-256", None, "1.0").is_some());
        assert!(r.find("ParallelHashXOF-128", None, "1.0").is_some());
        assert!(r.find("ParallelHashXOF-256", None, "1.0").is_some());
        // R59 ML-KEM-1024 (post-quantum)
        assert!(r.find("ML-KEM-1024", Some("keyGen"), "1.0").is_some());
        assert!(r.find("ML-KEM-1024", Some("encaps"), "1.0").is_some());
        assert!(r.find("ML-KEM-1024", Some("decaps"), "1.0").is_some());
        // R60 ML-DSA-87 (FIPS 204, post-quantum)
        assert!(r.find("ML-DSA-87", Some("keyGen"), "1.0").is_some());
        assert!(r.find("ML-DSA-87", Some("sigGen"), "1.0").is_some());
        assert!(r.find("ML-DSA-87", Some("sigVer"), "1.0").is_some());
        // R61 SLH-DSA-SHA2-256s (FIPS 205, post-quantum)
        assert!(r.find("SLH-DSA-SHA2-256s", Some("keyGen"), "1.0").is_some());
        assert!(r.find("SLH-DSA-SHA2-256s", Some("sigGen"), "1.0").is_some());
        assert!(r.find("SLH-DSA-SHA2-256s", Some("sigVer"), "1.0").is_some());
        // R62 LMS (SP 800-208)
        assert!(r.find("LMS", Some("keyGen"), "1.0").is_some());
        assert!(r.find("LMS", Some("sigGen"), "1.0").is_some());
        assert!(r.find("LMS", Some("sigVer"), "1.0").is_some());
        // R62 XMSS (SP 800-208)
        assert!(r.find("XMSS", Some("keyGen"), "1.0").is_some());
        assert!(r.find("XMSS", Some("sigGen"), "1.0").is_some());
        assert!(r.find("XMSS", Some("sigVer"), "1.0").is_some());
        // Negative lookups
        assert!(r.find("SHA3-256", None, "9.9").is_none());
        assert!(r.find("UNKNOWN", None, "1.0").is_none());
        assert!(r.find("KDA", None, "Sp800-56Cr2").is_none());
        assert!(r.find("KDA", Some("HKDF"), "1.0").is_none());
        assert_eq!(r.len(), 78);
        assert!(!r.is_empty());
    }

    #[test]
    fn unsupported_algorithm_error() {
        let _ = crate::ensure_initialized();
        let prompt =
            json::parse(r#"{"algorithm":"NOPE","revision":"1.0","testGroups":[]}"#).unwrap();
        let r = with_default_handlers();
        let err = process(&prompt, &r).unwrap_err();
        assert!(matches!(err, DispatchError::UnsupportedAlgorithm { .. }));
    }
}
