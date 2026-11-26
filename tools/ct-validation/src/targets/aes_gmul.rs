//! ct-validation target: the GF(2^8) multiplication of the portable AES
//! round, through [`oxicrypt_aes::block::mix_columns_internal`] and
//! [`oxicrypt_aes::block::inv_mix_columns_internal`].
//!
//! The secret is a 16-byte cipher state. Each call runs MixColumns and
//! then InvMixColumns, which restores the state, `ROUNDS` times, so the
//! `xtime` reductions run on the state bytes and on their multiples.
//!
//! Fixed class = one state, the same every call.
//! Random class = a fresh state per call.

use crate::measure::{RunConfig, run_target};
use crate::stats::VerdictReport;
use oxicrypt_aes::block::{inv_mix_columns_internal, mix_columns_internal};

/// MixColumns and InvMixColumns pairs per measured call.
const ROUNDS: usize = 8;

/// Fixed state, with the high bit set in half of its bytes.
///
/// A fixed state whose bytes all lie below `0x80` was told apart from
/// random states even by a loop of shifts and XORs with no branch, so
/// that choice measures operand values rather than the code.
const FIXED_STATE: [u8; 16] = [
    0xc1, 0x12, 0xa3, 0x34, 0xe5, 0x56, 0x87, 0x78, 0x99, 0x1a, 0xab, 0x3c, 0xcd, 0x5e, 0xef, 0x70,
];

/// The round 1 state of FIPS 197 Appendix B after ShiftRows, in input
/// byte order (column by column).
const APPENDIX_B_SHIFTED: [u8; 16] = [
    0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5,
];

/// The same state after MixColumns (FIPS 197 Appendix B, round 1).
const APPENDIX_B_MIXED: [u8; 16] = [
    0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c,
];

/// Panics unless both calls are accepted, MixColumns gives the FIPS 197
/// Appendix B round 1 answer and InvMixColumns restores the state, so
/// that a refused call, which would take the same time in both classes,
/// is never measured as clean.
pub(crate) fn preflight() {
    let mut state = APPENDIX_B_SHIFTED;
    assert_eq!(
        mix_columns_internal(&mut state),
        Ok(()),
        "ct-validation: aes_gmul refused MixColumns"
    );
    assert_eq!(
        state, APPENDIX_B_MIXED,
        "ct-validation: aes_gmul MixColumns gave a wrong state"
    );
    assert_eq!(
        inv_mix_columns_internal(&mut state),
        Ok(()),
        "ct-validation: aes_gmul refused InvMixColumns"
    );
    assert_eq!(
        state, APPENDIX_B_SHIFTED,
        "ct-validation: aes_gmul InvMixColumns did not restore the state"
    );
}

/// Measure the MixColumns pair under the paired-class protocol and
/// return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    preflight();
    let target = Box::new(|secret: &[u8]| {
        let mut state = [0u8; 16];
        state.copy_from_slice(secret);
        for _ in 0..ROUNDS {
            let a = mix_columns_internal(&mut state);
            let b = inv_mix_columns_internal(&mut state);
            std::hint::black_box(&(a, b));
        }
        std::hint::black_box(state);
    });

    run_target("aes_gmul", &FIXED_STATE, target, cfg)
}

#[cfg(test)]
#[test]
fn preflight_passes() {
    super::start_module();
    preflight();
}
