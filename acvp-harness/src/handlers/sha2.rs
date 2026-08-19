//! SHA-1 and SHA-2 family ACVP handlers.
//!
//! Targets ACVP `algorithm ∈ {"SHA-1", "SHA2-224", "SHA2-256",
//! "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256"}`,
//! `revision = "1.0"`, `testType ∈ {"AFT", "MCT", "LDT"}`.
//!
//! These handlers ride the ACVP `internalProjection.json` envelope
//! (the same shape `handlers::sha3` uses); the second envelope —
//! CAVP-shape `.rsp` byte vectors — is handled separately by
//! [`crate::shs`] / [`super::shs`] and does NOT register in the
//! `AlgorithmHandler` registry. The two surfaces coexist by design:
//! ACVP for live demo-server / NIST grading, CAVP for offline lab
//! short-message reproduction.
//!
//! SHA-1 is wired alongside SHA-2 because the upstream ACVP catalog
//! groups them in the same family bucket (parallel to how
//! [`super::shs`] already wires SHA-1 with SHA-2 for the CAVP surface).
//! Its FIPS-approval status is governed by the security policy, not
//! by whether a handler exists here.
//!
//! # Driver shape vs SHA-3
//!
//! The AFT case shape and LDT case shape match SHA-3 exactly: each
//! AFT case carries a bit-length `len` and a hex-encoded `msg` and
//! produces a hex-encoded `md`; LDT carries a `largeMsg` object with
//! `content`, `contentLength`, `fullLength`, and `expansionTechnique`.
//!
//! The MCT shape DIFFERS from SHA-3. SHA-3 §6.2 defines an iterative
//! `MD[j+1] = SHA3(MD[j])` form. SHA-1/SHA-2 use the classic CAVS
//! 3-message sliding-window form (replicated in the ACVP-Server SHA
//! generator):
//!
//! ```text
//! Seed = initial msg
//! For j = 0..MCT_OUTER:                   // 100 iterations
//!     A = B = C = Seed
//!     For i = 0..MCT_INNER:               // 1000 iterations
//!         msg_i = A || B || C
//!         md_i  = SHA(msg_i)
//!         A = B; B = C; C = md_i          // sliding window
//!     Output[j] = C   (= md at i = MCT_INNER - 1)
//!     Seed      = C
//! ```
//!
//! Because the inner-loop body differs, this module ships its own
//! group driver and MCT engine rather than reusing
//! `super::sha3::handle_hash_group`. The sha3 driver is intentionally
//! left untouched (per `feedback_refinements_only_as_needed`); a
//! generalization across hash families is deferred until a third
//! family with a different MCT shape lands.
//!
//! # Streaming hasher API
//!
//! oxicrypt-sha's SHA-1/SHA-2 streaming hashers expose
//! `new() -> Result<Self, Error>` (vs sha3's infallible
//! `new_internal()`), so the LDT helpers handle the `Result` via `?`
//! and map the error into `DispatchError::Crypto`.

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::hex;
use crate::json::JsonValue;

// ── Per-variant handlers ────────────────────────────────────────────

/// SHA-1 ACVP handler.
pub struct Sha1Handler;

/// SHA2-224 ACVP handler.
pub struct Sha2_224Handler;

/// SHA2-256 ACVP handler.
pub struct Sha2_256Handler;

/// SHA2-384 ACVP handler.
pub struct Sha2_384Handler;

/// SHA2-512 ACVP handler.
pub struct Sha2_512Handler;

/// SHA2-512/224 ACVP handler.
pub struct Sha2_512_224Handler;

/// SHA2-512/256 ACVP handler.
pub struct Sha2_512_256Handler;

impl AlgorithmHandler for Sha1Handler {
    fn algorithm(&self) -> &'static str {
        "SHA-1"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA-1", 160))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA-1",
            |msg| {
                oxicrypt_sha::sha1::sha1(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha1::sha1 returned Err"))
            },
            ldt_stream_sha1,
        )
    }
}

impl AlgorithmHandler for Sha2_224Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-224"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-224", 224))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-224",
            |msg| {
                oxicrypt_sha::sha224::sha224(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha224::sha224 returned Err"))
            },
            ldt_stream_sha224,
        )
    }
}

impl AlgorithmHandler for Sha2_256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-256", 256))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-256",
            |msg| {
                oxicrypt_sha::sha256::sha256(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha256::sha256 returned Err"))
            },
            ldt_stream_sha256,
        )
    }
}

impl AlgorithmHandler for Sha2_384Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-384"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-384", 384))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-384",
            |msg| {
                oxicrypt_sha::sha384::sha384(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha384::sha384 returned Err"))
            },
            ldt_stream_sha384,
        )
    }
}

impl AlgorithmHandler for Sha2_512Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-512"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-512", 512))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-512",
            |msg| {
                oxicrypt_sha::sha512::sha512(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha512::sha512 returned Err"))
            },
            ldt_stream_sha512,
        )
    }
}

impl AlgorithmHandler for Sha2_512_224Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-512/224"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-512/224", 224))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-512/224",
            |msg| {
                oxicrypt_sha::sha512_t::sha512_224(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| {
                        DispatchError::Crypto("oxicrypt_sha::sha512_t::sha512_224 returned Err")
                    })
            },
            ldt_stream_sha512_224,
        )
    }
}

impl AlgorithmHandler for Sha2_512_256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA2-512/256"
    }
    fn revision(&self) -> &'static str {
        "1.0"
    }
    fn acvp_capabilities(&self) -> Option<JsonValue> {
        Some(super::caps::sha2_capability("SHA2-512/256", 256))
    }
    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        handle_sha2_group(
            group,
            "SHA2-512/256",
            |msg| {
                oxicrypt_sha::sha512_t::sha512_256(msg)
                    .map(|d| d.to_vec())
                    .map_err(|_| {
                        DispatchError::Crypto("oxicrypt_sha::sha512_t::sha512_256 returned Err")
                    })
            },
            ldt_stream_sha512_256,
        )
    }
}

// ── Shared group driver ─────────────────────────────────────────────

/// Dispatches AFT, MCT, and LDT groups for a SHA-1/SHA-2 variant.
///
/// `compute` is the one-shot hash function (used by AFT and MCT).
/// `ldt_compute` is the streaming LDT hasher: takes a content pattern
/// and a total byte count, returns the digest of `pattern` repeated to
/// fill `full_bytes`.
fn handle_sha2_group<F, L>(
    group: &JsonValue,
    label: &'static str,
    mut compute: F,
    mut ldt_compute: L,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
    L: FnMut(&[u8], u64) -> Result<Vec<u8>, DispatchError>,
{
    let tg_id = group
        .get("tgId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tgId"))?;
    let test_type = group
        .get("testType")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("testType"))?;

    match test_type {
        "AFT" => {
            let tests = group
                .get("tests")
                .and_then(JsonValue::as_array)
                .ok_or(DispatchError::MissingField("tests"))?;
            let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
            for t in tests {
                results.push(run_aft_case(t, label, &mut compute)?);
            }
            Ok(JsonValue::Object(vec![
                ("tgId".to_string(), JsonValue::Number(tg_id)),
                ("tests".to_string(), JsonValue::Array(results)),
            ]))
        }
        "MCT" => handle_mct_group(tg_id, group, &mut compute),
        "LDT" => {
            let tests = group
                .get("tests")
                .and_then(JsonValue::as_array)
                .ok_or(DispatchError::MissingField("tests"))?;
            let mut results: Vec<JsonValue> = Vec::with_capacity(tests.len());
            for t in tests {
                results.push(run_ldt_case(t, &mut ldt_compute)?);
            }
            Ok(JsonValue::Object(vec![
                ("tgId".to_string(), JsonValue::Number(tg_id)),
                ("tests".to_string(), JsonValue::Array(results)),
            ]))
        }
        _ => Err(DispatchError::UnsupportedTestType(test_type.to_string())),
    }
}

fn run_aft_case<F>(
    t: &JsonValue,
    label: &'static str,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
{
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let len_bits = t
        .get("len")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("len"))?;
    if !len_bits.is_multiple_of(8) {
        let _ = label; // label kept for future diagnostic plumbing
        return Err(DispatchError::Unsupported(
            "SHA-1/SHA-2 AFT with non-byte-aligned `len`",
        ));
    }
    let expected_bytes: usize = (len_bits / 8) as usize;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let msg = hex::decode(msg_hex)?;
    if msg.len() < expected_bytes {
        return Err(DispatchError::Crypto(
            "SHA-1/SHA-2 AFT: hex `msg` shorter than declared `len`",
        ));
    }
    let used = msg
        .get(..expected_bytes)
        .ok_or(DispatchError::Crypto("SHA-1/SHA-2 AFT: slicing failed"))?;
    let md = compute(used)?;
    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
    ]))
}

// ── MCT engine (SHA-1 / SHA-2 — classic 3-message sliding-window) ────

/// Number of outer iterations in a SHA-1/SHA-2 MCT test.
const MCT_OUTER: usize = 100;
/// Number of inner iterations per outer iteration.
const MCT_INNER: usize = 1000;

/// Handle a complete SHA-1/SHA-2 MCT group. Each group has exactly
/// one test carrying an initial `msg` (the seed). Runs the classic
/// CAVS 3-message sliding-window MCT and emits a `resultsArray` with
/// `MCT_OUTER` entries.
#[allow(clippy::similar_names)] // tg_id vs tc_id
fn handle_mct_group<F>(
    tg_id: i64,
    group: &JsonValue,
    compute: &mut F,
) -> Result<JsonValue, DispatchError>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>, DispatchError>,
{
    let tests = group
        .get("tests")
        .and_then(JsonValue::as_array)
        .ok_or(DispatchError::MissingField("tests"))?;
    if tests.len() != 1 {
        return Err(DispatchError::Crypto(
            "SHA-1/SHA-2 MCT: expected exactly one test",
        ));
    }
    let t = &tests[0];
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;
    let msg_hex = t
        .get("msg")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("msg"))?;
    let seed = hex::decode(msg_hex)?;

    let mut current = seed;
    let mut results_array: Vec<JsonValue> = Vec::with_capacity(MCT_OUTER);

    for _j in 0..MCT_OUTER {
        // Initialise sliding window: A = B = C = current seed.
        let mut a = current.clone();
        let mut b = current.clone();
        let mut c = current.clone();

        for _i in 0..MCT_INNER {
            let mut concat = Vec::with_capacity(a.len() + b.len() + c.len());
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            concat.extend_from_slice(&c);
            let md = compute(&concat)?;
            a = b;
            b = c;
            c = md;
        }

        // C now holds md_(MCT_INNER-1); record and feed into next outer.
        results_array.push(JsonValue::Object(vec![(
            "md".to_string(),
            JsonValue::String(hex::encode_upper(&c)),
        )]));
        current = c;
    }

    let test_result = JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("resultsArray".to_string(), JsonValue::Array(results_array)),
    ]);

    Ok(JsonValue::Object(vec![
        ("tgId".to_string(), JsonValue::Number(tg_id)),
        ("tests".to_string(), JsonValue::Array(vec![test_result])),
    ]))
}

// ── LDT engine ──────────────────────────────────────────────────────

/// Handle a single LDT test case. Parses the `largeMsg` object to
/// extract `content`, `contentLength`, `fullLength`, and
/// `expansionTechnique`, then delegates to `ldt_compute`.
fn run_ldt_case<L>(t: &JsonValue, ldt_compute: &mut L) -> Result<JsonValue, DispatchError>
where
    L: FnMut(&[u8], u64) -> Result<Vec<u8>, DispatchError>,
{
    let tc_id = t
        .get("tcId")
        .and_then(JsonValue::as_i64)
        .ok_or(DispatchError::MissingField("tcId"))?;

    let large_msg = t
        .get("largeMsg")
        .ok_or(DispatchError::MissingField("largeMsg"))?;

    let content_hex = large_msg
        .get("content")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("largeMsg.content"))?;
    let content_length_bits = large_msg
        .get("contentLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("largeMsg.contentLength"))?;
    let full_length_bits = large_msg
        .get("fullLength")
        .and_then(JsonValue::as_u64)
        .ok_or(DispatchError::MissingField("largeMsg.fullLength"))?;
    let technique = large_msg
        .get("expansionTechnique")
        .and_then(JsonValue::as_str)
        .ok_or(DispatchError::MissingField("largeMsg.expansionTechnique"))?;

    if technique != "repeating" {
        return Err(DispatchError::Unsupported(
            "LDT: only 'repeating' expansion technique is supported",
        ));
    }
    if content_length_bits % 8 != 0 || full_length_bits % 8 != 0 {
        return Err(DispatchError::Unsupported(
            "LDT: non-byte-aligned lengths are not supported",
        ));
    }

    let content = hex::decode(content_hex)?;
    let content_bytes = (content_length_bits / 8) as usize;
    if content.len() < content_bytes {
        return Err(DispatchError::Crypto(
            "LDT: content hex shorter than declared contentLength",
        ));
    }
    let pattern = &content[..content_bytes];

    let full_bytes = full_length_bits / 8;
    let md = ldt_compute(pattern, full_bytes)?;

    Ok(JsonValue::Object(vec![
        ("tcId".to_string(), JsonValue::Number(tc_id)),
        ("md".to_string(), JsonValue::String(hex::encode_upper(&md))),
    ]))
}

// Per-variant LDT streaming functions. SHA-1/SHA-2 hashers share an
// `update(&[u8])` + `finalize() -> [u8; N]` shape but their `new()`
// returns `Result<Self, Error>`, so the `?` short-circuits power-up
// state failures.

fn ldt_stream_sha1(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha1::Sha1::new()
        .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha1::Sha1::new returned Err"))?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha224(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha224::Sha224::new()
        .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha224::Sha224::new returned Err"))?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha256(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha256::Sha256::new()
        .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha256::Sha256::new returned Err"))?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha384(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha384::Sha384::new()
        .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha384::Sha384::new returned Err"))?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha512(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha512::Sha512::new()
        .map_err(|_| DispatchError::Crypto("oxicrypt_sha::sha512::Sha512::new returned Err"))?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha512_224(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha512_t::Sha512_224::new().map_err(|_| {
        DispatchError::Crypto("oxicrypt_sha::sha512_t::Sha512_224::new returned Err")
    })?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}

fn ldt_stream_sha512_256(pattern: &[u8], full_bytes: u64) -> Result<Vec<u8>, DispatchError> {
    if pattern.is_empty() {
        return Err(DispatchError::Crypto("LDT: empty content pattern"));
    }
    let mut hasher = oxicrypt_sha::sha512_t::Sha512_256::new().map_err(|_| {
        DispatchError::Crypto("oxicrypt_sha::sha512_t::Sha512_256::new returned Err")
    })?;
    let pat_len = pattern.len() as u64;
    let mut remaining = full_bytes;
    while remaining >= pat_len {
        hasher.update(pattern);
        remaining -= pat_len;
    }
    if remaining > 0 {
        let tail = usize::try_from(remaining)
            .map_err(|_| DispatchError::Crypto("LDT: remaining overflows usize"))?;
        hasher.update(&pattern[..tail]);
    }
    Ok(hasher.finalize().to_vec())
}
