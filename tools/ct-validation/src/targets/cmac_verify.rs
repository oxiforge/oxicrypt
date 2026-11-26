//! ct-validation target: [`oxicrypt_cmac::cmac_verify`] (SP 800-38B
//! §6.3).
//!
//! The claim is that the comparison of the recomputed tag with the
//! received MAC reads every byte, so the time does not show where the
//! MAC differs from the tag. Both classes are refused: each MAC is the
//! correct tag with one byte inverted, so the measurement is of the
//! position of the difference, not of acceptance against refusal. The
//! MAC length is the key's fixed 16 bytes and the message is fixed. The
//! secret is one byte whose low four bits give the inverted position,
//! which is applied by a mask over all sixteen bytes rather than by an
//! index or a branch.
//!
//! Fixed class = the tag with byte 0 inverted, every call.
//! Random class = the tag with a byte at a random position inverted,
//! position 0 in one call in 16.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_aes::ModeError;
use oxicrypt_cmac::{CmacKey, cmac, cmac_verify};

/// The AES-128 key of SP 800-38B §D.1.
pub(crate) const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

/// The fixed message, two blocks.
pub(crate) const MESSAGE: [u8; 32] = [0x6b; 32];

/// MAC length of the key, the full tag.
pub(crate) const MAC_LEN: usize = 16;

/// A verification with the signature of [`cmac_verify`].
pub(crate) type VerifyFn = fn(&CmacKey, &[u8], &[u8]) -> Result<(), ModeError>;

/// `tag` with the byte at `secret[0] % 16` inverted. Every byte is
/// XORed with a mask that is all ones only at that position.
fn invert_at(tag: &[u8; MAC_LEN], secret: &[u8]) -> [u8; MAC_LEN] {
    let position = secret[0] & 0x0f;
    let mut mac = *tag;
    for (i, b) in mac.iter_mut().enumerate() {
        let d = u16::from((i as u8) ^ position);
        let hit = (d.wrapping_sub(1) >> 8) as u8 & 1;
        *b ^= std::hint::black_box(0u8.wrapping_sub(hit));
    }
    mac
}

/// Measure `verify` on the classes of this module under the paired-class
/// protocol, reported as `name`.
pub(crate) fn run_verify(name: &'static str, verify: VerifyFn, cfg: &RunConfig) -> VerdictReport {
    let key = CmacKey::new(&KEY, MAC_LEN).expect("CMAC key");
    let mut tag = [0u8; MAC_LEN];
    cmac(&key, &MESSAGE, &mut tag).expect("CMAC tag");
    for p in 0..16u8 {
        assert_eq!(
            verify(&key, &MESSAGE, &invert_at(&tag, &[p])),
            Err(ModeError::TagMismatch),
            "ct-validation: {name} accepted a MAC with byte {p} inverted"
        );
    }

    let verify = std::hint::black_box(verify);
    let target = Box::new(move |secret: &[u8]| {
        let mac = invert_at(&tag, secret);
        let r = verify(&key, &MESSAGE, &mac);
        std::hint::black_box(&r);
    });

    run_target(name, &[0u8], target, cfg)
}

/// Measure [`cmac_verify`] under the paired-class protocol and return
/// the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    run_verify("cmac_verify", cmac_verify, cfg)
}
