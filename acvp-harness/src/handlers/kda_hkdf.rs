//! `KDA-HKDF-Sp800-56Cr2` AFT handler — SP 800-56C Rev. 2 §5 two-step
//! KDF, §5.9.2 hybrid form, HKDF instantiation.
//!
//! The ACVP `KDA` family publishes across two envelope fields rather
//! than one: `algorithm = "KDA"`, `mode = "HKDF"`,
//! `revision = "Sp800-56Cr2"`. The dispatcher keys handlers on the
//! tuple `(algorithm, mode, revision)` since R13 so one registry slot
//! covers this family cleanly; single-field handlers keep `mode =
//! None`.
//!
//! # Construction
//!
//! Each AFT test case carries:
//!
//! ```text
//! kdfParameter {
//!     salt,                  hex bytes — HKDF-Extract salt
//!     z,                     hex bytes — shared secret Z
//!     t,                     hex bytes — auxiliary shared secret T
//!     l,                     integer — output length in bits
//!     fixedInfoPattern,      string — evaluated per §5.8
//!     fixedInputEncoding,    string — must be "concatenation"
//!     hmacAlg                string — e.g. "SHA2-256"
//! },
//! fixedInfoPartyU { partyId, ephemeralData? },
//! fixedInfoPartyV { partyId, ephemeralData? },
//! dkm                    hex bytes — expected output
//! ```
//!
//! The handler computes
//!
//! ```text
//! IKM        = Z || T
//! PRK        = HMAC(salt, IKM)              — HKDF-Extract
//! fixedInfo  = encode(pattern, partyU, partyV, l)
//! OKM        = HKDF-Expand(PRK, fixedInfo, l / 8)
//! dkm        = OKM
//! ```
//!
//! and emits `{ tcId, dkm }` in the response per test case, preserving
//! `tgId` at the group level.
//!
//! # Supported pattern tokens
//!
//! The `fixedInfoPattern` in all ten `KDA-HKDF-Sp800-56Cr2` vendored
//! groups at pinned commit `3611942ea10c070dd8bc6afec5682d56c307de8a`
//! is `"uPartyInfo||vPartyInfo||l"`. The encoder accepts the wider
//! set the `tools/acvp-gen/generate.py` script already validates
//! against NIST's reference — `uPartyInfo`, `vPartyInfo`, `l` (32-bit
//! big-endian output length in bits per §5.8), plus `algorithmId`,
//! `context`, and `label` passthrough from `kdfConfiguration`, plus
//! `literal[HEX]` — so any future KDA-HKDF slice that uses a
//! different pattern will either succeed or return an
//! `Unsupported("KDA-HKDF fixedInfoPattern token")` error without
//! producing a silently mis-encoded response.
//!
//! # Hybrid shared secret
//!
//! Every vendored test group ships `usesHybridSharedSecret = true`
//! and supplies both `z` and `t`, so `IKM = Z || T`. A single-secret
//! form (`usesHybridSharedSecret = false`) would set `IKM = Z` alone
//! — the handler supports that too, but the current slice never
//! exercises it.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_kdf::{
    HkdfSha224, HkdfSha256, HkdfSha384, HkdfSha3_224, HkdfSha3_256, HkdfSha3_384, HkdfSha3_512,
    HkdfSha512, HkdfSha512_224, HkdfSha512_256,
};

/// `KDA-HKDF-Sp800-56Cr2` AFT dispatcher.
pub struct KdaHkdfHandler;

impl AlgorithmHandler for KdaHkdfHandler {
    fn algorithm(&self) -> &'static str {
        "KDA"
    }
    fn mode(&self) -> Option<&'static str> {
        Some("HKDF")
    }
    fn revision(&self) -> &'static str {
        "Sp800-56Cr2"
    }
    fn handle_group(&self, g: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_kda_hkdf_group(g)
    }
}

// ----------------------------------------------------------------------
// Group driver
// ----------------------------------------------------------------------

fn handle_kda_hkdf_group(group: &JsonValue) -> Result<JsonValue, DispatchError> {
    let group_id = group
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

    let kdf_cfg = group
        .get("kdfConfiguration")
        .ok_or(DispatchError::MissingField("kdfConfiguration"))?;
    let kdf_type = kdf_cfg
        .get("kdfType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kdfConfiguration.kdfType"))?;
    if kdf_type != "hkdf" {
        return Err(DispatchError::Unsupported(
            "KDA-HKDF group with kdfType != \"hkdf\"",
        ));
    }
    let encoding = kdf_cfg
        .get("fixedInfoEncoding")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(
            "kdfConfiguration.fixedInfoEncoding",
        ))?;
    if encoding != "concatenation" {
        return Err(DispatchError::Unsupported(
            "KDA-HKDF group with fixedInfoEncoding != \"concatenation\"",
        ));
    }
    let pattern = kdf_cfg
        .get("fixedInfoPattern")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField(
            "kdfConfiguration.fixedInfoPattern",
        ))?;
    let hmac_alg = kdf_cfg
        .get("hmacAlg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kdfConfiguration.hmacAlg"))?;
    let variant = HkdfVariant::from_ascii(hmac_alg)?;
    let group_l_bits = kdf_cfg
        .get("l")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("kdfConfiguration.l"))?;
    if !group_l_bits.is_multiple_of(8) || group_l_bits == 0 {
        return Err(DispatchError::Unsupported(
            "KDA-HKDF group with non-byte-aligned or zero `l`",
        ));
    }

    let uses_hybrid = group
        .get("usesHybridSharedSecret")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if group
        .get("multiExpansion")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        return Err(DispatchError::Unsupported("KDA-HKDF multi-expansion"));
    }

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        results.push(handle_kda_hkdf_test(
            t,
            kdf_cfg,
            pattern,
            variant,
            uses_hybrid,
            group_l_bits,
        )?);
    }
    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(group_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Handle a single KDA-HKDF AFT test case.
///
/// Split out from [`handle_kda_hkdf_group`] so the group driver stays
/// small; all per-test parsing, hybrid `Z || T` assembly, `l` override
/// handling, fixedInfo encoding, and the HKDF derive call live here.
fn handle_kda_hkdf_test(
    test: &JsonValue,
    kdf_cfg: &JsonValue,
    pattern: &str,
    variant: HkdfVariant,
    uses_hybrid: bool,
    group_l_bits: u64,
) -> Result<JsonValue, DispatchError> {
    let tc_id = test
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let kdf_param = test
        .get("kdfParameter")
        .ok_or(DispatchError::MissingField("kdfParameter"))?;
    let salt_hex = kdf_param
        .get("salt")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kdfParameter.salt"))?;
    let z_hex = kdf_param
        .get("z")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("kdfParameter.z"))?;
    let salt = hex::decode(salt_hex)?;
    let mut ikm = hex::decode(z_hex)?;
    if uses_hybrid {
        let t_hex = kdf_param
            .get("t")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("kdfParameter.t"))?;
        let t_bytes = hex::decode(t_hex)?;
        ikm.extend_from_slice(&t_bytes);
    }
    // `l` is allowed to be overridden per-test but in practice the
    // vendored KDA-HKDF-Sp800-56Cr2 groups repeat the group `l` at
    // each test. Defer to the per-test value when present so we
    // stay faithful to any future slice that varies it.
    let l_bits = kdf_param
        .get("l")
        .and_then(JsonValue::as_u64)
        .unwrap_or(group_l_bits);
    if !l_bits.is_multiple_of(8) || l_bits == 0 {
        return Err(DispatchError::Unsupported(
            "KDA-HKDF test with non-byte-aligned or zero `l`",
        ));
    }
    let l_bytes = usize::try_from(l_bits / 8)
        .map_err(|_| DispatchError::Crypto("KDA-HKDF: `l` does not fit in usize"))?;

    let fixed_info = encode_fixed_info(pattern, test, kdf_cfg, l_bits)?;
    let dkm = variant.derive(&salt, &ikm, &fixed_info, l_bytes)?;

    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        (
            "dkm".to_string(),
            JsonValue::String(hex::encode_upper(&dkm)),
        ),
    ]))
}

// ----------------------------------------------------------------------
// FixedInfo encoder (SP 800-56Cr2 §5.8)
// ----------------------------------------------------------------------

fn encode_fixed_info(
    pattern: &str,
    test: &JsonValue,
    kdf_cfg: &JsonValue,
    l_bits: u64,
) -> Result<Vec<u8>, DispatchError> {
    let mut out: Vec<u8> = Vec::new();
    for raw_token in pattern.split("||") {
        let token = raw_token.trim();
        if token.is_empty() {
            continue;
        }
        if token == "uPartyInfo" {
            let party = test.get("fixedInfoPartyU").ok_or(DispatchError::MissingField(
                "fixedInfoPartyU",
            ))?;
            encode_party_info(party, &mut out)?;
        } else if token == "vPartyInfo" {
            let party = test.get("fixedInfoPartyV").ok_or(DispatchError::MissingField(
                "fixedInfoPartyV",
            ))?;
            encode_party_info(party, &mut out)?;
        } else if token == "l" {
            // §5.8: `l` is the derived-key length in bits encoded as a
            // 32-bit unsigned big-endian integer.
            let l_u32 = u32::try_from(l_bits)
                .map_err(|_| DispatchError::Crypto("KDA-HKDF: `l` does not fit in u32"))?;
            out.extend_from_slice(&l_u32.to_be_bytes());
        } else if token == "algorithmId" {
            let s = kdf_cfg
                .get("algorithmId")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            out.extend_from_slice(&hex::decode(s)?);
        } else if token == "context" {
            let s = kdf_cfg
                .get("context")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            out.extend_from_slice(&hex::decode(s)?);
        } else if token == "label" {
            let s = kdf_cfg
                .get("label")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            out.extend_from_slice(&hex::decode(s)?);
        } else if let Some(stripped) = token
            .strip_prefix("literal[")
            .and_then(|s| s.strip_suffix(']'))
        {
            out.extend_from_slice(&hex::decode(stripped)?);
        } else {
            return Err(DispatchError::Unsupported(
                "KDA-HKDF fixedInfoPattern token",
            ));
        }
    }
    Ok(out)
}

fn encode_party_info(party: &JsonValue, out: &mut Vec<u8>) -> Result<(), DispatchError> {
    let party_id_hex = party
        .get("partyId")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("fixedInfoPartyX.partyId"))?;
    out.extend_from_slice(&hex::decode(party_id_hex)?);
    if let Some(eph) = party.get("ephemeralData").and_then(JsonValue::as_str) {
        if !eph.is_empty() {
            out.extend_from_slice(&hex::decode(eph)?);
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// HKDF variant dispatch
// ----------------------------------------------------------------------

/// Which HKDF instantiation a KDA-HKDF group targets.
///
/// SHA-1 is out of scope for SP 800-56C Rev 2 (see the note in
/// `fips_kdf::hkdf_self_test_sha1`); the ACVP-Server slice does not
/// ship a SHA-1 group, and the dispatcher refuses one if one ever
/// appears in a future re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HkdfVariant {
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HkdfVariant {
    fn from_ascii(s: &str) -> Result<Self, DispatchError> {
        match s {
            "SHA2-224" => Ok(Self::Sha2_224),
            "SHA2-256" => Ok(Self::Sha2_256),
            "SHA2-384" => Ok(Self::Sha2_384),
            "SHA2-512" => Ok(Self::Sha2_512),
            "SHA2-512/224" => Ok(Self::Sha2_512_224),
            "SHA2-512/256" => Ok(Self::Sha2_512_256),
            "SHA3-224" => Ok(Self::Sha3_224),
            "SHA3-256" => Ok(Self::Sha3_256),
            "SHA3-384" => Ok(Self::Sha3_384),
            "SHA3-512" => Ok(Self::Sha3_512),
            _ => Err(DispatchError::Unsupported(
                "KDA-HKDF hmacAlg (SHA-1 out of scope for SP 800-56Cr2)",
            )),
        }
    }

    fn derive(
        self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        out_bytes: usize,
    ) -> Result<Vec<u8>, DispatchError> {
        let mut okm = vec![0u8; out_bytes];
        match self {
            Self::Sha2_224 => {
                let hk = HkdfSha224::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha224::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha224::expand"))?;
            }
            Self::Sha2_256 => {
                let hk = HkdfSha256::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha256::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha256::expand"))?;
            }
            Self::Sha2_384 => {
                let hk = HkdfSha384::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha384::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha384::expand"))?;
            }
            Self::Sha2_512 => {
                let hk = HkdfSha512::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512::expand"))?;
            }
            Self::Sha2_512_224 => {
                let hk = HkdfSha512_224::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512_224::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512_224::expand"))?;
            }
            Self::Sha2_512_256 => {
                let hk = HkdfSha512_256::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512_256::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha512_256::expand"))?;
            }
            Self::Sha3_224 => {
                let hk = HkdfSha3_224::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_224::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_224::expand"))?;
            }
            Self::Sha3_256 => {
                let hk = HkdfSha3_256::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_256::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_256::expand"))?;
            }
            Self::Sha3_384 => {
                let hk = HkdfSha3_384::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_384::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_384::expand"))?;
            }
            Self::Sha3_512 => {
                let hk = HkdfSha3_512::extract(Some(salt), ikm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_512::extract"))?;
                hk.expand(info, &mut okm)
                    .map_err(|_| DispatchError::Crypto("HkdfSha3_512::expand"))?;
            }
        }
        Ok(okm)
    }
}
