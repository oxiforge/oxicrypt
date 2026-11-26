//! A/A control target: both classes verify the correct tag of the
//! [`super::cmac_verify`] message through [`oxicrypt_cmac::cmac_verify`],
//! so the two classes run the same instructions on the same data and
//! the target reads the secret byte without using it. A `LEAK` here is a
//! difference the harness or the host makes between the classes, the
//! baseline against which a `--strict` `LEAK` elsewhere is read. Built
//! only with the `fixture` feature.
//!
//! Fixed class = the correct tag, every call.
//! Random class = the correct tag, every call.

use super::cmac_verify::{KEY, MAC_LEN, MESSAGE};
use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_cmac::{CmacKey, cmac, cmac_verify};

/// Measure the A/A control under the paired-class protocol and return
/// the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let key = CmacKey::new(&KEY, MAC_LEN).expect("CMAC key");
    let mut tag = [0u8; MAC_LEN];
    cmac(&key, &MESSAGE, &mut tag).expect("CMAC tag");
    assert_eq!(
        cmac_verify(&key, &MESSAGE, &tag),
        Ok(()),
        "ct-validation: aa refused the correct tag"
    );

    let target = Box::new(move |secret: &[u8]| {
        std::hint::black_box(secret[0]);
        let r = cmac_verify(&key, &MESSAGE, std::hint::black_box(&tag));
        std::hint::black_box(&r);
    });

    run_target("aa", &[0u8], target, cfg)
}
