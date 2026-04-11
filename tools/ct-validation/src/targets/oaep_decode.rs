//! ct-validation target: [`fips_rsa::oaep::emsa_oaep_decode`].
//!
//! This validates the Manger-resistance claim of §12.1 of the
//! security policy: the decoder must take indistinguishable time
//! across *different* inputs in the same threat class, regardless
//! of where a structural check would fail or what plaintext is
//! recovered on success.
//!
//! # Harness design
//!
//! The Manger attack recovers the plaintext by distinguishing
//! between *kinds* of failure ("`Y ≠ 0`" vs. "`lHash' ≠ lHash`" vs.
//! "malformed PS"), not by distinguishing success from failure. A
//! naive harness that compares a valid ciphertext (fixed class)
//! against random garbage (random class) would instead measure the
//! size of the success-path `copy_from_slice` minus the fail-path
//! early return — a timing gap that is real but *does not matter*
//! for the Manger claim, because real callers see only the generic
//! `None` error and never fall off the success path in a way an
//! attacker can observe.
//!
//! So we build a valid OAEP encoding on every measurement — fixed
//! class uses a pinned `(msg, seed)` pair, random class derives
//! `(msg, seed)` deterministically from the 256-byte PRNG draw —
//! and decode that. Both classes therefore:
//!
//! - always reach the success path,
//! - recover a plaintext of the same fixed length,
//! - run the same `mgf1_sha256` work and the same Y / lHash / PS
//!   accumulator loop.
//!
//! A |t| spike on this target would mean the decoder's timing
//! depends on the plaintext bytes themselves — which is the actual
//! Manger failure mode.

#![allow(clippy::panic)]

use crate::measure::{run_target, RunConfig};
use crate::stats::VerdictReport;
use fips_rsa::oaep::{emsa_oaep_decode, emsa_oaep_encode, HLEN, K, MAX_MSG_LEN};

/// Number of plaintext bytes carried by each probe encoding. Pinning
/// this to a single value keeps the success-path copy length constant
/// across both classes, so the `db[msg_start..]` copy contributes the
/// same cycles on every call.
const PROBE_MSG_LEN: usize = 64;

/// Size of the per-call "secret" buffer the harness feeds us:
/// `HLEN` (seed) + `PROBE_MSG_LEN` (plaintext). Chosen so that one
/// PRNG draw can fill seed and plaintext directly.
const SECRET_LEN: usize = HLEN + PROBE_MSG_LEN;

/// Build a valid EM from the first `HLEN + PROBE_MSG_LEN` bytes of
/// `secret`. Fails loudly at fixture time only; every runtime call
/// must succeed because we control all the inputs.
fn build_em(label: &[u8], secret: &[u8], em: &mut [u8; K]) {
    debug_assert!(secret.len() >= SECRET_LEN);
    let mut seed = [0u8; HLEN];
    seed.copy_from_slice(&secret[..HLEN]);
    let msg = &secret[HLEN..HLEN + PROBE_MSG_LEN];
    assert!(
        emsa_oaep_encode(label, msg, &seed, em).is_some(),
        "ct-validation: oaep_decode probe encode failed"
    );
}

/// Measure [`emsa_oaep_decode`] under the paired-class protocol
/// and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    // Pinned fixed "secret" = one specific (seed, msg) pair. Values
    // chosen to have no special structure.
    let mut fixed_secret = [0u8; SECRET_LEN];
    for (i, b) in fixed_secret.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x9d).wrapping_add(0x4a);
    }

    let label_owned: Vec<u8> = b"ct-validation".to_vec();
    let label_for_target = label_owned.clone();

    let target = Box::new(move |secret: &[u8]| {
        let mut em = [0u8; K];
        build_em(&label_for_target, secret, &mut em);
        let mut out = [0u8; MAX_MSG_LEN];
        let r = emsa_oaep_decode(&label_for_target, &em, &mut out);
        std::hint::black_box(r);
    });

    run_target("rsa_oaep_decode", &fixed_secret, target, cfg)
}
