//! Control target for [`super::cmac_verify`]: the same classes and the
//! same call through a `VerifyFn`, to a verification that differs
//! from [`oxicrypt_cmac::cmac_verify`] only in comparing the tag with a
//! loop that stops at the first differing byte. The harness must report
//! it as not constant-time; built only with the `fixture` feature.

use super::cmac_verify::{VerifyFn, run_verify};
use crate::measure::RunConfig;
use crate::stats::VerdictReport;
use oxicrypt_aes::ModeError;
use oxicrypt_cmac::{BLOCK_SIZE, CmacKey, cmac};

/// [`oxicrypt_cmac::cmac_verify`] with an early-exit comparison.
/// `black_box` on each byte keeps the loop from becoming a fixed-length
/// library comparison.
fn verify_early_exit(key: &CmacKey, message: &[u8], mac: &[u8]) -> Result<(), ModeError> {
    let mut recomputed = [0u8; BLOCK_SIZE];
    let recomputed = recomputed
        .get_mut(..mac.len())
        .ok_or(ModeError::InvalidTagLength)?;
    cmac(key, message, recomputed)?;
    for (a, b) in recomputed.iter().zip(mac) {
        if std::hint::black_box(*a) != *b {
            return Err(ModeError::TagMismatch);
        }
    }
    Ok(())
}

/// Measure the early-exit verification under the paired-class protocol
/// and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let verify: VerifyFn = verify_early_exit;
    run_verify("cmac_verify_leaky", verify, cfg)
}
