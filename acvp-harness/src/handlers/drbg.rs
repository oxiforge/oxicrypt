//! DRBG AFT handlers (`ctrDRBG`, `hashDRBG`, `hmacDRBG`, revision `1.0`).
//!
//! Three handler structs — [`CtrDrbgHandler`], [`HashDrbgHandler`], and
//! [`HmacDrbgHandler`] — each register as a single-field
//! `(algorithm, revision)` entry in the dispatch registry.
//!
//! ACVP DRBG test groups carry group-level `mode`, `derFunc` (CTR only),
//! and `predResistance` flags; each test case provides an `otherInput`
//! array whose entries sequence the `reSeed` and `generate` operations
//! the handler must execute in order. The last `generate` call's
//! output becomes `returnedBits` in the response.
//!
//! Supported modes:
//!
//! - CTR: `AES-128`, `AES-192`, `AES-256` (with and without derivation
//!   function, with and without prediction resistance)
//! - Hash: `SHA2-256`, `SHA2-384`, `SHA2-512`
//! - HMAC: `SHA2-256`, `SHA2-384`, `SHA2-512`

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;
use fips_drbg::ctr::{CtrDrbgAes128, CtrDrbgAes192, CtrDrbgAes256};
use fips_drbg::hash::{HashDrbgSha256, HashDrbgSha384, HashDrbgSha512};
use fips_drbg::hmac::{HmacDrbgSha256, HmacDrbgSha384, HmacDrbgSha512};

// ── Handler structs ─────────────────────────────────────────────────

/// CTR_DRBG AFT handler (AES-128/192/256, with/without DF, with/without PR).
pub struct CtrDrbgHandler;

impl AlgorithmHandler for CtrDrbgHandler {
    fn algorithm(&self) -> &'static str {
        "ctrDRBG"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_drbg_group(DrbgFamily::Ctr, group)
    }
}

/// Hash_DRBG AFT handler (SHA2-256/384/512).
pub struct HashDrbgHandler;

impl AlgorithmHandler for HashDrbgHandler {
    fn algorithm(&self) -> &'static str {
        "hashDRBG"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_drbg_group(DrbgFamily::Hash, group)
    }
}

/// HMAC_DRBG AFT handler (SHA2-256/384/512).
pub struct HmacDrbgHandler;

impl AlgorithmHandler for HmacDrbgHandler {
    fn algorithm(&self) -> &'static str {
        "hmacDRBG"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_drbg_group(DrbgFamily::Hmac, group)
    }
}

// ── Internal dispatch ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum DrbgFamily {
    Ctr,
    Hash,
    Hmac,
}

/// Decode a hex field from a test case, returning an empty vec if the
/// field is missing or the empty string.
fn decode_hex_field_or_empty(
    obj: &JsonValue,
    field: &'static str,
) -> Result<Vec<u8>, DispatchError> {
    match obj.get(field).and_then(JsonValue::as_str) {
        Some(s) if !s.is_empty() => Ok(hex::decode(s)?),
        _ => Ok(Vec::new()),
    }
}

/// Process one ACVP DRBG test group.
fn handle_drbg_group(
    family: DrbgFamily,
    group: &JsonValue,
) -> Result<JsonValue, DispatchError> {
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

    let mode = group
        .get("mode")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("mode"))?;

    let pred_resistance = group
        .get("predResistance")
        .and_then(JsonValue::as_bool)
        .ok_or(DispatchError::MissingField("predResistance"))?;

    // derFunc is only present (and meaningful) for ctrDRBG.
    let use_df = match family {
        DrbgFamily::Ctr => group
            .get("derFunc")
            .and_then(JsonValue::as_bool)
            .ok_or(DispatchError::MissingField("derFunc"))?,
        DrbgFamily::Hash | DrbgFamily::Hmac => false,
    };

    let returned_bits_len = group
        .get("returnedBitsLen")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("returnedBitsLen"))?;
    if returned_bits_len == 0 || returned_bits_len % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "DRBG: returnedBitsLen must be >0 and byte-aligned",
        ));
    }
    let ret_bytes = (returned_bits_len / 8) as usize;

    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;

    let cfg = DrbgGroupConfig {
        family,
        mode,
        use_df,
        pred_resistance,
        ret_bytes,
    };

    let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
    for t in tests {
        let test_case_id = t
            .get("tcId")
            .and_then(JsonValue::as_i64)
            .ok_or(DispatchError::MissingField("tcId"))?;

        let returned_bits = run_drbg_test(&cfg, t)?;

        results.push(JsonValue::Object(vec![
            ("tcId".to_string(), JsonValue::Number(test_case_id)),
            (
                "returnedBits".to_string(),
                JsonValue::String(hex::encode_upper(&returned_bits)),
            ),
        ]));
    }

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(results)),
    ]))
}

/// Group-level config parsed once and passed to every test case in
/// the group.
struct DrbgGroupConfig<'a> {
    family: DrbgFamily,
    mode: &'a str,
    use_df: bool,
    pred_resistance: bool,
    ret_bytes: usize,
}

/// Execute a single DRBG test case: instantiate, walk `otherInput`,
/// return the output of the last `generate`.
fn run_drbg_test(
    cfg: &DrbgGroupConfig<'_>,
    test: &JsonValue,
) -> Result<Vec<u8>, DispatchError> {
    let entropy = hex::decode(
        test.get("entropyInput")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("entropyInput"))?,
    )?;
    let nonce = decode_hex_field_or_empty(test, "nonce")?;
    let perso = decode_hex_field_or_empty(test, "persoString")?;

    let other_input = test
        .get("otherInput")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("otherInput"))?;

    match cfg.family {
        DrbgFamily::Ctr => run_ctr_drbg_test(cfg, &entropy, &nonce, &perso, other_input),
        DrbgFamily::Hash => run_hash_drbg_test(cfg, &entropy, &nonce, &perso, other_input),
        DrbgFamily::Hmac => run_hmac_drbg_test(cfg, &entropy, &nonce, &perso, other_input),
    }
}

// ── CTR_DRBG ────────────────────────────────────────────────────────

/// XOR `a` with `b` (truncated/padded to `a.len()`), writing the
/// result in-place into `a`. Used for CTR_DRBG no-df seed_material
/// construction per SP 800-90A §10.2.1.3.1.
fn xor_into(a: &mut [u8], b: &[u8]) {
    for (i, byte) in a.iter_mut().enumerate() {
        if i < b.len() {
            *byte ^= b[i];
        }
    }
}

/// Run a single CTR_DRBG ACVP test case.
fn run_ctr_drbg_test(
    cfg: &DrbgGroupConfig<'_>,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    other_input: &[JsonValue],
) -> Result<Vec<u8>, DispatchError> {
    match cfg.mode {
        "AES-128" => {
            let mut drbg = CtrDrbgAes128::new();
            ctr_instantiate(&mut drbg, cfg.use_df, entropy, nonce, perso, 32)?;
            ctr_walk_other_input(&mut drbg, cfg, other_input, 32)
        }
        "AES-192" => {
            let mut drbg = CtrDrbgAes192::new();
            ctr_instantiate(&mut drbg, cfg.use_df, entropy, nonce, perso, 40)?;
            ctr_walk_other_input(&mut drbg, cfg, other_input, 40)
        }
        "AES-256" => {
            let mut drbg = CtrDrbgAes256::new();
            ctr_instantiate(&mut drbg, cfg.use_df, entropy, nonce, perso, 48)?;
            ctr_walk_other_input(&mut drbg, cfg, other_input, 48)
        }
        _ => Err(DispatchError::Unsupported("ctrDRBG: unsupported mode")),
    }
}

/// Trait helper so we can be generic over AES key size for CTR_DRBG.
trait CtrDrbgOps {
    fn do_instantiate_df(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        perso: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_instantiate_no_df(&mut self, seed_material: &[u8]) -> Result<(), DispatchError>;
    fn do_reseed_df(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_reseed_no_df(&mut self, seed_material: &[u8]) -> Result<(), DispatchError>;
    fn do_generate_df(
        &mut self,
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
    fn do_generate_no_df(
        &mut self,
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
}

macro_rules! impl_ctr_drbg_ops {
    ($ty:ty) => {
        impl CtrDrbgOps for $ty {
            fn do_instantiate_df(
                &mut self,
                entropy: &[u8],
                nonce: &[u8],
                perso: &[u8],
            ) -> Result<(), DispatchError> {
                self.instantiate_df(entropy, nonce, perso)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: instantiate_df failed"))
            }
            fn do_instantiate_no_df(&mut self, seed_material: &[u8]) -> Result<(), DispatchError> {
                self.instantiate_no_df(seed_material)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: instantiate_no_df failed"))
            }
            fn do_reseed_df(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
            ) -> Result<(), DispatchError> {
                self.reseed_df(entropy, additional)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: reseed_df failed"))
            }
            fn do_reseed_no_df(&mut self, seed_material: &[u8]) -> Result<(), DispatchError> {
                self.reseed_no_df(seed_material)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: reseed_no_df failed"))
            }
            fn do_generate_df(
                &mut self,
                additional: Option<&[u8]>,
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate_df(additional, out)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: generate_df failed"))
            }
            fn do_generate_no_df(
                &mut self,
                additional: Option<&[u8]>,
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate_no_df(additional, out)
                    .map_err(|_| DispatchError::Crypto("ctrDRBG: generate_no_df failed"))
            }
        }
    };
}

impl_ctr_drbg_ops!(CtrDrbgAes128);
impl_ctr_drbg_ops!(CtrDrbgAes192);
impl_ctr_drbg_ops!(CtrDrbgAes256);

/// Instantiate a CTR_DRBG instance from ACVP test-case fields.
fn ctr_instantiate<D: CtrDrbgOps>(
    drbg: &mut D,
    use_df: bool,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    seed_len: usize,
) -> Result<(), DispatchError> {
    if use_df {
        drbg.do_instantiate_df(entropy, nonce, perso)
    } else {
        // §10.2.1.3.1: seed_material = entropy_input XOR (personalization || 0…)
        let mut sm = vec![0u8; seed_len];
        sm[..entropy.len().min(seed_len)].copy_from_slice(&entropy[..entropy.len().min(seed_len)]);
        xor_into(&mut sm, perso);
        drbg.do_instantiate_no_df(&sm)
    }
}

/// Walk the `otherInput` array for a CTR_DRBG test, returning the
/// output of the last generate call.
fn ctr_walk_other_input<D: CtrDrbgOps>(
    drbg: &mut D,
    cfg: &DrbgGroupConfig<'_>,
    other_input: &[JsonValue],
    seed_len: usize,
) -> Result<Vec<u8>, DispatchError> {
    let mut output = vec![0u8; cfg.ret_bytes];
    let use_df = cfg.use_df;
    let pred_resistance = cfg.pred_resistance;

    for step in other_input {
        let intended_use = step
            .get("intendedUse")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("intendedUse"))?;
        let step_entropy = decode_hex_field_or_empty(step, "entropyInput")?;
        let step_addl = decode_hex_field_or_empty(step, "additionalInput")?;

        match intended_use {
            "reSeed" => {
                if use_df {
                    drbg.do_reseed_df(&step_entropy, &step_addl)?;
                } else {
                    // §10.2.1.4.1: seed_material = entropy XOR (addl || 0…)
                    let mut sm = vec![0u8; seed_len];
                    sm[..step_entropy.len().min(seed_len)]
                        .copy_from_slice(&step_entropy[..step_entropy.len().min(seed_len)]);
                    xor_into(&mut sm, &step_addl);
                    drbg.do_reseed_no_df(&sm)?;
                }
            }
            "generate" => {
                if pred_resistance {
                    // PR generate = reseed(entropy, addl) + generate(None)
                    if use_df {
                        drbg.do_reseed_df(&step_entropy, &step_addl)?;
                        drbg.do_generate_df(None, &mut output)?;
                    } else {
                        // §9.3.1 step 7: reseed first, then generate.
                        // no-df reseed: seed_material = entropy XOR (addl || 0…)
                        let mut sm = vec![0u8; seed_len];
                        sm[..step_entropy.len().min(seed_len)]
                            .copy_from_slice(&step_entropy[..step_entropy.len().min(seed_len)]);
                        xor_into(&mut sm, &step_addl);
                        drbg.do_reseed_no_df(&sm)?;
                        drbg.do_generate_no_df(None, &mut output)?;
                    }
                } else {
                    // Non-PR generate: pass additionalInput.
                    let addl_opt = if step_addl.is_empty() {
                        None
                    } else if use_df {
                        Some(step_addl.as_slice())
                    } else {
                        // no-df generate: additional_input must be exactly seed_len.
                        // ACVP vectors provide it at that length already.
                        Some(step_addl.as_slice())
                    };
                    if use_df {
                        drbg.do_generate_df(addl_opt, &mut output)?;
                    } else {
                        drbg.do_generate_no_df(addl_opt, &mut output)?;
                    }
                }
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "DRBG: unknown intendedUse in otherInput",
                ));
            }
        }
    }

    Ok(output)
}

// ── Hash_DRBG ───────────────────────────────────────────────────────

/// Run a single Hash_DRBG ACVP test case.
fn run_hash_drbg_test(
    cfg: &DrbgGroupConfig<'_>,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    other_input: &[JsonValue],
) -> Result<Vec<u8>, DispatchError> {
    match cfg.mode {
        "SHA2-256" => {
            let mut drbg = HashDrbgSha256::new();
            hash_instantiate(&mut drbg, entropy, nonce, perso)?;
            hash_walk_other_input(&mut drbg, cfg, other_input)
        }
        "SHA2-384" => {
            let mut drbg = HashDrbgSha384::new();
            hash_instantiate(&mut drbg, entropy, nonce, perso)?;
            hash_walk_other_input(&mut drbg, cfg, other_input)
        }
        "SHA2-512" => {
            let mut drbg = HashDrbgSha512::new();
            hash_instantiate(&mut drbg, entropy, nonce, perso)?;
            hash_walk_other_input(&mut drbg, cfg, other_input)
        }
        _ => Err(DispatchError::Unsupported("hashDRBG: unsupported mode")),
    }
}

/// Trait helper for Hash_DRBG generic dispatch.
trait HashDrbgOps {
    fn do_instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        perso: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_reseed(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_generate(
        &mut self,
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
    fn do_generate_pr(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
}

macro_rules! impl_hash_drbg_ops {
    ($ty:ty) => {
        impl HashDrbgOps for $ty {
            fn do_instantiate(
                &mut self,
                entropy: &[u8],
                nonce: &[u8],
                perso: &[u8],
            ) -> Result<(), DispatchError> {
                self.instantiate(entropy, nonce, perso)
                    .map_err(|_| DispatchError::Crypto("hashDRBG: instantiate failed"))
            }
            fn do_reseed(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
            ) -> Result<(), DispatchError> {
                self.reseed(entropy, additional)
                    .map_err(|_| DispatchError::Crypto("hashDRBG: reseed failed"))
            }
            fn do_generate(
                &mut self,
                additional: Option<&[u8]>,
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate(additional, out)
                    .map_err(|_| DispatchError::Crypto("hashDRBG: generate failed"))
            }
            fn do_generate_pr(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate_pr(entropy, additional, out)
                    .map_err(|_| DispatchError::Crypto("hashDRBG: generate_pr failed"))
            }
        }
    };
}

impl_hash_drbg_ops!(HashDrbgSha256);
impl_hash_drbg_ops!(HashDrbgSha384);
impl_hash_drbg_ops!(HashDrbgSha512);

fn hash_instantiate<D: HashDrbgOps>(
    drbg: &mut D,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
) -> Result<(), DispatchError> {
    drbg.do_instantiate(entropy, nonce, perso)
}

fn hash_walk_other_input<D: HashDrbgOps>(
    drbg: &mut D,
    cfg: &DrbgGroupConfig<'_>,
    other_input: &[JsonValue],
) -> Result<Vec<u8>, DispatchError> {
    let pred_resistance = cfg.pred_resistance;
    let mut output = vec![0u8; cfg.ret_bytes];

    for step in other_input {
        let intended_use = step
            .get("intendedUse")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("intendedUse"))?;
        let step_entropy = decode_hex_field_or_empty(step, "entropyInput")?;
        let step_addl = decode_hex_field_or_empty(step, "additionalInput")?;

        match intended_use {
            "reSeed" => {
                drbg.do_reseed(&step_entropy, &step_addl)?;
            }
            "generate" => {
                if pred_resistance {
                    drbg.do_generate_pr(&step_entropy, &step_addl, &mut output)?;
                } else {
                    let addl_opt = if step_addl.is_empty() {
                        None
                    } else {
                        Some(step_addl.as_slice())
                    };
                    drbg.do_generate(addl_opt, &mut output)?;
                }
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "DRBG: unknown intendedUse in otherInput",
                ));
            }
        }
    }

    Ok(output)
}

// ── HMAC_DRBG ───────────────────────────────────────────────────────

/// Run a single HMAC_DRBG ACVP test case.
fn run_hmac_drbg_test(
    cfg: &DrbgGroupConfig<'_>,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    other_input: &[JsonValue],
) -> Result<Vec<u8>, DispatchError> {
    match cfg.mode {
        "SHA2-256" => {
            let mut drbg = HmacDrbgSha256::new();
            hmac_instantiate(&mut drbg, entropy, nonce, perso)?;
            hmac_walk_other_input(&mut drbg, cfg, other_input)
        }
        "SHA2-384" => {
            let mut drbg = HmacDrbgSha384::new();
            hmac_instantiate(&mut drbg, entropy, nonce, perso)?;
            hmac_walk_other_input(&mut drbg, cfg, other_input)
        }
        "SHA2-512" => {
            let mut drbg = HmacDrbgSha512::new();
            hmac_instantiate(&mut drbg, entropy, nonce, perso)?;
            hmac_walk_other_input(&mut drbg, cfg, other_input)
        }
        _ => Err(DispatchError::Unsupported("hmacDRBG: unsupported mode")),
    }
}

/// Trait helper for HMAC_DRBG generic dispatch.
trait HmacDrbgOps {
    fn do_instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        perso: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_reseed(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<(), DispatchError>;
    fn do_generate(
        &mut self,
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
    fn do_generate_pr(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
        out: &mut [u8],
    ) -> Result<(), DispatchError>;
}

macro_rules! impl_hmac_drbg_ops {
    ($ty:ty) => {
        impl HmacDrbgOps for $ty {
            fn do_instantiate(
                &mut self,
                entropy: &[u8],
                nonce: &[u8],
                perso: &[u8],
            ) -> Result<(), DispatchError> {
                self.instantiate(entropy, nonce, perso)
                    .map_err(|_| DispatchError::Crypto("hmacDRBG: instantiate failed"))
            }
            fn do_reseed(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
            ) -> Result<(), DispatchError> {
                self.reseed(entropy, additional)
                    .map_err(|_| DispatchError::Crypto("hmacDRBG: reseed failed"))
            }
            fn do_generate(
                &mut self,
                additional: Option<&[u8]>,
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate(additional, out)
                    .map_err(|_| DispatchError::Crypto("hmacDRBG: generate failed"))
            }
            fn do_generate_pr(
                &mut self,
                entropy: &[u8],
                additional: &[u8],
                out: &mut [u8],
            ) -> Result<(), DispatchError> {
                self.generate_pr(entropy, additional, out)
                    .map_err(|_| DispatchError::Crypto("hmacDRBG: generate_pr failed"))
            }
        }
    };
}

impl_hmac_drbg_ops!(HmacDrbgSha256);
impl_hmac_drbg_ops!(HmacDrbgSha384);
impl_hmac_drbg_ops!(HmacDrbgSha512);

fn hmac_instantiate<D: HmacDrbgOps>(
    drbg: &mut D,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
) -> Result<(), DispatchError> {
    drbg.do_instantiate(entropy, nonce, perso)
}

fn hmac_walk_other_input<D: HmacDrbgOps>(
    drbg: &mut D,
    cfg: &DrbgGroupConfig<'_>,
    other_input: &[JsonValue],
) -> Result<Vec<u8>, DispatchError> {
    let pred_resistance = cfg.pred_resistance;
    let mut output = vec![0u8; cfg.ret_bytes];

    for step in other_input {
        let intended_use = step
            .get("intendedUse")
            .and_then(JsonValue::as_str)
            .ok_or(DispatchError::MissingField("intendedUse"))?;
        let step_entropy = decode_hex_field_or_empty(step, "entropyInput")?;
        let step_addl = decode_hex_field_or_empty(step, "additionalInput")?;

        match intended_use {
            "reSeed" => {
                drbg.do_reseed(&step_entropy, &step_addl)?;
            }
            "generate" => {
                if pred_resistance {
                    drbg.do_generate_pr(&step_entropy, &step_addl, &mut output)?;
                } else {
                    let addl_opt = if step_addl.is_empty() {
                        None
                    } else {
                        Some(step_addl.as_slice())
                    };
                    drbg.do_generate(addl_opt, &mut output)?;
                }
            }
            _ => {
                return Err(DispatchError::Unsupported(
                    "DRBG: unknown intendedUse in otherInput",
                ));
            }
        }
    }

    Ok(output)
}
