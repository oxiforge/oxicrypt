//! SHA3-256 AFT + MCT handler.
//!
//! Targets ACVP `algorithm = "SHA3-256"`, `revision = "2.0"`. The
//! handler implements `testType = "AFT"` and `testType = "MCT"`.
//!
//! ACVP SHA3 AFT test cases have the shape:
//!
//! ```text
//! { "tcId": 87, "len": 8, "msg": "08", "md": "..." }
//! ```
//!
//! where `len` is the message length **in bits** and `msg` is the
//! hex-encoded message padded out to the nearest byte. pqclib's
//! `fips_sha::sha3` API is byte-oriented, so this handler only
//! supports byte-aligned `len` values and errors out otherwise — the
//! ACVP vector set vendored at commit
//! `3611942ea10c070dd8bc6afec5682d56c307de8a` uses byte-aligned
//! lengths exclusively for AFT, so this is not a functional gap.
//!
//! MCT support (R30) delegates to the shared MCT engine in
//! [`super::sha3::handle_hash_group`].

use crate::dispatch::{AlgorithmHandler, DispatchError};
use crate::json::JsonValue;

/// SHA3-256 AFT + MCT dispatcher.
pub struct Sha3_256Handler;

impl AlgorithmHandler for Sha3_256Handler {
    fn algorithm(&self) -> &'static str {
        "SHA3-256"
    }

    fn revision(&self) -> &'static str {
        "2.0"
    }

    fn handle_group(&self, group: &JsonValue) -> Result<JsonValue, DispatchError> {
        super::sha3::handle_hash_group(group, "SHA3-256", |msg| {
            fips_sha::sha3::sha3_256(msg)
                .map(|d| d.to_vec())
                .map_err(|_| DispatchError::Crypto("fips_sha::sha3::sha3_256 returned Err"))
        })
    }
}
