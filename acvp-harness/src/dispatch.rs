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

    /// Filtered variant of [`Self::acvp_capabilities`] for multi-
    /// variant PQ families that advertise a `parameterSets` array.
    ///
    /// Default impl ignores the filter and delegates to
    /// [`Self::acvp_capabilities`]. Override only when the
    /// underlying cap-builder supports per-paramSet filtering — at
    /// time of writing, only the SLH-DSA family does, per
    /// `feedback_single_algo_per_acvts_session`'s
    /// one-vector-set-per-session rule for new multi-variant PQ
    /// families.
    fn acvp_capabilities_filtered(&self, _paramset_filter: Option<&str>) -> Option<JsonValue> {
        self.acvp_capabilities()
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
/// The registered set is the sequence of `register` calls in this
/// function. It is deliberately not restated here: a second copy of the
/// list drifts from the first, and the two counts this doc block used to
/// carry had both gone stale.
///
/// Two structural facts do belong here. A handler occupies either an
/// `(algorithm, None, revision)` slot or an `(algorithm, mode, revision)`
/// one — `KDA` mode `HKDF` revision `Sp800-56Cr2` is why the moded form
/// exists. And the same handler structs serve both AFT and MCT test
/// types: the `handle_group` impl routes on `testType` rather than the
/// registry carrying separate entries.
#[must_use]
pub fn with_default_handlers() -> Registry {
    let mut r = Registry::new();
    // SHA-1 + SHA-2 family (FIPS 180-4 hashing, revision 1.0)
    r.register(Box::new(handlers::sha2::Sha1Handler));
    r.register(Box::new(handlers::sha2::Sha2_224Handler));
    r.register(Box::new(handlers::sha2::Sha2_256Handler));
    r.register(Box::new(handlers::sha2::Sha2_384Handler));
    r.register(Box::new(handlers::sha2::Sha2_512Handler));
    r.register(Box::new(handlers::sha2::Sha2_512_224Handler));
    r.register(Box::new(handlers::sha2::Sha2_512_256Handler));
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
    // AES block-cipher modes (ECB/CBC/CTR AFT)
    r.register(Box::new(handlers::aes::AesEcbHandler));
    r.register(Box::new(handlers::aes::AesCbcHandler));
    r.register(Box::new(handlers::aes::AesCtrHandler));
    // AES AEAD / key-wrap modes (GCM/CCM/KW/KWP AFT)
    r.register(Box::new(handlers::aes::AesGcmHandler));
    r.register(Box::new(handlers::aes::AesCcmHandler));
    r.register(Box::new(handlers::aes::AesKwHandler));
    r.register(Box::new(handlers::aes::AesKwpHandler));
    // DRBG families (ctrDRBG / hashDRBG / hmacDRBG)
    r.register(Box::new(handlers::drbg::CtrDrbgHandler));
    r.register(Box::new(handlers::drbg::HashDrbgHandler));
    r.register(Box::new(handlers::drbg::HmacDrbgHandler));
    // ECDSA sigVer + keyVer + sigGen + keyGen (P-256 / SHA2-256, FIPS186-5)
    r.register(Box::new(handlers::ecdsa::EcdsaSigVerHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaKeyVerHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaSigGenHandler));
    r.register(Box::new(handlers::ecdsa::EcdsaKeyGenHandler));
    // EdDSA sigVer + keyVer + sigGen + keyGen (ED-25519, pure, 1.0)
    r.register(Box::new(handlers::eddsa::EddsaSigVerHandler));
    r.register(Box::new(handlers::eddsa::EddsaKeyVerHandler));
    r.register(Box::new(handlers::eddsa::EddsaSigGenHandler));
    r.register(Box::new(handlers::eddsa::EddsaKeyGenHandler));
    // RSA sigVer (RSA-2048 / PKCS#1v1.5 / SHA2-256, FIPS186-5)
    r.register(Box::new(handlers::rsa::RsaSigVerHandler));
    r.register(Box::new(handlers::rsa_decprim::RsaDecPrimHandler));
    // TLS v1.2 KDF (RFC 7627 Extended Master Secret)
    r.register(Box::new(handlers::tls12_kdf::Tls12KdfRfc7627Handler));
    // TLS v1.3 KDF (RFC 8446 §7.1) — first PR under feat/tls-1.3-kdf
    r.register(Box::new(handlers::tls13_kdf::Tls13KdfHandler));
    // kdf-components / tls (standard TLS 1.2 KDF, non-EMS)
    r.register(Box::new(handlers::kdf_comp_tls::KdfComponentsTlsHandler));
    // RSA signaturePrimitive (RSASP1 with CRT + Bellcore)
    r.register(Box::new(handlers::rsa_sigprim::RsaSigPrimHandler));
    // RSA sigGen (PKCS#1v1.5 non-CRT + PSS CRT, FIPS186-5)
    r.register(Box::new(handlers::rsa_siggen::RsaSigGenHandler));
    // KAS-ECC-SSC (P-256 and P-384 ECDH shared secret, Sp800-56Ar3)
    r.register(Box::new(handlers::kas_ecc_ssc::KasEccSscHandler));
    // KAS-FFC-SSC (MODP-3072 shared secret computation, Sp800-56Ar3)
    r.register(Box::new(handlers::kas_ffc_ssc::KasFfcSscHandler));
    // KTS-IFC (RSAES-OAEP key transport KTS-OAEP-basic, Sp800-56Br2;
    // full FIPS-approved modulus grid 2048/3072/4096; closes Section 12)
    r.register(Box::new(handlers::kts_ifc::KtsIfcHandler));
    // RSA OAEP (encrypt/decrypt, RFC8017, RSA-2048/SHA2-256)
    r.register(Box::new(handlers::rsa_oaep::RsaOaepHandler));
    // RSA KeyGen (FIPS186-5, RSA-2048, e=65537, DRBG-seeded)
    r.register(Box::new(handlers::rsa_keygen::RsaKeyGenHandler));
    // SP 800-185 derived functions (self-generated vectors)
    r.register(Box::new(handlers::cshake::CShake128Handler));
    r.register(Box::new(handlers::cshake::CShake256Handler));
    r.register(Box::new(handlers::kmac::Kmac128Handler));
    r.register(Box::new(handlers::kmac::Kmac256Handler));
    r.register(Box::new(handlers::tuplehash::TupleHash128Handler));
    r.register(Box::new(handlers::tuplehash::TupleHash256Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHash128Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHash256Handler));
    // SP 800-185 XOF variants (self-generated vectors)
    r.register(Box::new(handlers::kmac::KmacXof128Handler));
    r.register(Box::new(handlers::kmac::KmacXof256Handler));
    r.register(Box::new(handlers::tuplehash::TupleHashXof128Handler));
    r.register(Box::new(handlers::tuplehash::TupleHashXof256Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHashXof128Handler));
    r.register(Box::new(handlers::parallelhash::ParallelHashXof256Handler));
    // PBKDF2 (SP 800-132 / RFC 8018; vectors are self-generated)
    r.register(Box::new(handlers::pbkdf2::Pbkdf2Handler));
    // ML-KEM (keyGen / encapDecap, FIPS 203, post-quantum;
    //         parameterSets advertise ML-KEM-1024 only)
    r.register(Box::new(handlers::ml_kem::MlKemKeyGenHandler));
    r.register(Box::new(handlers::ml_kem::MlKemEncapDecapHandler));
    // ML-DSA (keyGen / sigGen / sigVer, FIPS 204, post-quantum;
    //         parameterSets advertise ML-DSA-44 / ML-DSA-65 / ML-DSA-87)
    r.register(Box::new(handlers::ml_dsa::MlDsaKeyGenHandler));
    r.register(Box::new(handlers::ml_dsa::MlDsaSigGenHandler));
    r.register(Box::new(handlers::ml_dsa::MlDsaSigVerHandler));
    // SLH-DSA (keyGen / sigGen / sigVer, FIPS 205, post-quantum;
    //          parameterSets advertise SLH-DSA-SHA2-256s only)
    r.register(Box::new(handlers::slh_dsa::SlhDsaKeyGenHandler));
    r.register(Box::new(handlers::slh_dsa::SlhDsaSigGenHandler));
    r.register(Box::new(handlers::slh_dsa::SlhDsaSigVerHandler));
    // LMS (keyGen / sigGen / sigVer, SP 800-208 / RFC 8554)
    r.register(Box::new(handlers::lms::LmsKeyGenHandler));
    r.register(Box::new(handlers::lms::LmsSigGenHandler));
    r.register(Box::new(handlers::lms::LmsSigGenSp800208Handler));
    r.register(Box::new(handlers::lms::LmsSigVerHandler));
    r.register(Box::new(handlers::lms::LmsSigVerSp800208Handler));
    // XMSS (keyGen / sigGen / sigVer, SP 800-208 / RFC 8391)
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
        // SHA3-256 and HMAC-SHA2-256
        assert!(r.find("SHA3-256", None, "2.0").is_some());
        assert!(r.find("HMAC-SHA2-256", None, "1.0").is_some());
        // SHA-1 + SHA-2 family (FIPS 180-4)
        assert!(r.find("SHA-1", None, "1.0").is_some());
        assert!(r.find("SHA2-224", None, "1.0").is_some());
        assert!(r.find("SHA2-256", None, "1.0").is_some());
        assert!(r.find("SHA2-384", None, "1.0").is_some());
        assert!(r.find("SHA2-512", None, "1.0").is_some());
        assert!(r.find("SHA2-512/224", None, "1.0").is_some());
        assert!(r.find("SHA2-512/256", None, "1.0").is_some());
        // SHA-3 family
        assert!(r.find("SHA3-224", None, "2.0").is_some());
        assert!(r.find("SHA3-384", None, "2.0").is_some());
        assert!(r.find("SHA3-512", None, "2.0").is_some());
        // SHAKE XOFs
        assert!(r.find("SHAKE-128", None, "FIPS202").is_some());
        assert!(r.find("SHAKE-256", None, "FIPS202").is_some());
        // HMAC family
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
        // KDA-HKDF (mode-keyed)
        assert!(r.find("KDA", Some("HKDF"), "Sp800-56Cr2").is_some());
        // AES AFT modes
        assert!(r.find("ACVP-AES-ECB", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CBC", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CTR", None, "1.0").is_some());
        // AES AEAD / key-wrap modes
        assert!(r.find("ACVP-AES-GCM", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-CCM", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-KW", None, "1.0").is_some());
        assert!(r.find("ACVP-AES-KWP", None, "1.0").is_some());
        // CMAC-AES
        assert!(r.find("CMAC-AES", None, "1.0").is_some());
        // DRBG families
        assert!(r.find("ctrDRBG", None, "1.0").is_some());
        assert!(r.find("hashDRBG", None, "1.0").is_some());
        assert!(r.find("hmacDRBG", None, "1.0").is_some());
        // ECDSA / EdDSA / RSA verification
        assert!(r.find("ECDSA", Some("sigVer"), "FIPS186-5").is_some());
        assert!(r.find("ECDSA", Some("keyVer"), "FIPS186-5").is_some());
        assert!(r.find("EDDSA", Some("sigVer"), "1.0").is_some());
        assert!(r.find("EDDSA", Some("keyVer"), "1.0").is_some());
        assert!(r.find("RSA", Some("sigVer"), "FIPS186-5").is_some());
        // ECDSA / EdDSA SigGen
        assert!(r.find("ECDSA", Some("sigGen"), "FIPS186-5").is_some());
        assert!(r.find("EDDSA", Some("sigGen"), "1.0").is_some());
        // EdDSA KeyGen
        assert!(r.find("EDDSA", Some("keyGen"), "1.0").is_some());
        // ECDSA KeyGen
        assert!(r.find("ECDSA", Some("keyGen"), "FIPS186-5").is_some());
        // KBKDF (SP 800-108r1)
        assert!(r.find("KDF", None, "1.0").is_some());
        // RSA DecryptionPrimitive (SP 800-56Br2)
        assert!(
            r.find("RSA", Some("decryptionPrimitive"), "Sp800-56Br2")
                .is_some()
        );
        // TLS v1.2 KDF (RFC 7627)
        assert!(r.find("TLS-v1.2", Some("KDF"), "RFC7627").is_some());
        // TLS v1.3 KDF (RFC 8446 §7.1)
        assert!(r.find("TLS-v1.3", Some("KDF"), "RFC8446").is_some());
        // kdf-components / tls
        assert!(r.find("kdf-components", Some("tls"), "1.0").is_some());
        // RSA SignaturePrimitive
        assert!(r.find("RSA", Some("signaturePrimitive"), "2.0").is_some());
        // RSA SigGen
        assert!(r.find("RSA", Some("sigGen"), "FIPS186-5").is_some());
        // KAS-ECC-SSC — registered with no mode
        assert!(r.find("KAS-ECC-SSC", None, "Sp800-56Ar3").is_some());
        // KAS-FFC-SSC — registered with no mode
        assert!(r.find("KAS-FFC-SSC", None, "Sp800-56Ar3").is_some());
        // KTS-IFC — registered with no mode for
        // RSAES-OAEP key transport under SP 800-56Br2 §7.2.2.2.
        assert!(r.find("KTS-IFC", None, "Sp800-56Br2").is_some());
        // RSA OAEP
        assert!(r.find("RSA", Some("OAEP"), "RFC8017").is_some());
        // SP 800-185 derived functions + PBKDF2
        assert!(r.find("cSHAKE-128", None, "1.0").is_some());
        assert!(r.find("cSHAKE-256", None, "1.0").is_some());
        assert!(r.find("KMAC-128", None, "1.0").is_some());
        assert!(r.find("KMAC-256", None, "1.0").is_some());
        assert!(r.find("TupleHash-128", None, "1.0").is_some());
        assert!(r.find("TupleHash-256", None, "1.0").is_some());
        assert!(r.find("ParallelHash-128", None, "1.0").is_some());
        assert!(r.find("ParallelHash-256", None, "1.0").is_some());
        // PBKDF2
        assert!(r.find("PBKDF", None, "1.0").is_some());
        // SP 800-185 XOF variants
        assert!(r.find("KMACXOF-128", None, "1.0").is_some());
        assert!(r.find("KMACXOF-256", None, "1.0").is_some());
        assert!(r.find("TupleHashXOF-128", None, "1.0").is_some());
        assert!(r.find("TupleHashXOF-256", None, "1.0").is_some());
        assert!(r.find("ParallelHashXOF-128", None, "1.0").is_some());
        assert!(r.find("ParallelHashXOF-256", None, "1.0").is_some());
        // ML-KEM (FIPS 203, post-quantum; parameterSets advertise ML-KEM-1024 only)
        assert!(r.find("ML-KEM", Some("keyGen"), "FIPS203").is_some());
        assert!(r.find("ML-KEM", Some("encapDecap"), "FIPS203").is_some());
        // ML-DSA (FIPS 204, post-quantum; parameterSets advertise ML-DSA-87 only)
        assert!(r.find("ML-DSA", Some("keyGen"), "FIPS204").is_some());
        assert!(r.find("ML-DSA", Some("sigGen"), "FIPS204").is_some());
        assert!(r.find("ML-DSA", Some("sigVer"), "FIPS204").is_some());
        // SLH-DSA (FIPS 205, post-quantum; parameterSets advertise SLH-DSA-SHA2-256s only)
        assert!(r.find("SLH-DSA", Some("keyGen"), "FIPS205").is_some());
        assert!(r.find("SLH-DSA", Some("sigGen"), "FIPS205").is_some());
        assert!(r.find("SLH-DSA", Some("sigVer"), "FIPS205").is_some());
        // LMS (SP 800-208)
        assert!(r.find("LMS", Some("keyGen"), "1.0").is_some());
        assert!(r.find("LMS", Some("sigGen"), "1.0").is_some());
        assert!(r.find("LMS", Some("sigVer"), "1.0").is_some());
        // LMS sigGen/sigVer also register under the SP800-208 revision, which
        // the demo server advertises alongside 1.0 (catalog ids 218/219). Both
        // must resolve — the registry keys on (algorithm, mode, revision).
        assert!(r.find("LMS", Some("sigGen"), "SP800-208").is_some());
        assert!(r.find("LMS", Some("sigVer"), "SP800-208").is_some());
        // No keyGen under SP800-208: key generation has no message, so the
        // server advertises the revision for the signing modes only.
        assert!(r.find("LMS", Some("keyGen"), "SP800-208").is_none());
        // XMSS (SP 800-208)
        assert!(r.find("XMSS", Some("keyGen"), "1.0").is_some());
        assert!(r.find("XMSS", Some("sigGen"), "1.0").is_some());
        assert!(r.find("XMSS", Some("sigVer"), "1.0").is_some());
        // Negative lookups
        assert!(r.find("SHA3-256", None, "9.9").is_none());
        assert!(r.find("UNKNOWN", None, "1.0").is_none());
        assert!(r.find("KDA", None, "Sp800-56Cr2").is_none());
        assert!(r.find("KDA", Some("HKDF"), "1.0").is_none());
        assert_eq!(r.len(), 88);
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
