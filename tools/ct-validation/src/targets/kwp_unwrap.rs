//! ct-validation target: the integrity check of
//! [`oxicrypt_aes::kwp_unwrap`] (SP 800-38F §6.3 Algorithm 6 steps 4 to
//! 9), through [`oxicrypt_aes::kw::kwp_check_internal`].
//!
//! The unwrap refuses a ciphertext whose decrypted ICV prefix is wrong,
//! whose length indicator is out of range, or whose padding is non-zero,
//! all with the same error, and the check after the inverse-cipher pass
//! is where these refusals could be told apart. The claim is that its
//! timing does not tell them apart. Success against refusal is not
//! compared: the caller sees which it was.
//!
//! The AES decryption before the check is left out. Its table lookups
//! depend on the ciphertext, and the refusals need different
//! ciphertexts, so through the full unwrap the comparison would also
//! measure those lookups.
//!
//! The secret is three probes, each a decrypted initial value followed
//! by a padded plaintext of one, two and three semiblocks, so that the
//! scan of the last seven octets starts at a different offset in each.
//! Each call checks every probe. The random-class probes are chosen
//! before the counter is read, so the measured call does not index by
//! the secret.
//!
//! Fixed class = the ICV fault in every probe, every call.
//! Random class = in each probe, one of: an indicator above the
//! plaintext, an indicator at or below the semiblock before the last
//! (two and three semiblocks), an indicator of 0, an indicator of 2^31
//! or more, or a non-zero padding octet, chosen per call. The ICV fault
//! is not among them.

#![allow(clippy::panic)]

use crate::measure::{DrawFn, RunConfig, run_target_drawn};
use crate::stats::VerdictReport;
use oxicrypt_aes::ModeError;
use oxicrypt_aes::kw::kwp_check_internal;

/// Semiblock size in octets.
const SEMI: usize = 8;

/// Semiblocks of padded plaintext in each probe.
const BLOCKS: [usize; 3] = [1, 2, 3];

/// Passes over the probes per measured call.
const ROUNDS: usize = 3;

/// The decrypted initial value of a KWP unwrap with indicator `mli`.
fn aiv(mli: u32) -> [u8; SEMI] {
    let m = mli.to_be_bytes();
    [0xa6, 0x59, 0x59, 0xa6, m[0], m[1], m[2], m[3]]
}

/// The key length of the valid probe of `n` semiblocks, five octets into
/// the last semiblock so that three octets are padding.
fn key_len(n: usize) -> usize {
    SEMI * (n - 1) + 5
}

/// The valid probe of `n` semiblocks: initial value then padded
/// plaintext.
fn valid(n: usize) -> Vec<u8> {
    let len = key_len(n);
    let mut probe = aiv(len as u32).to_vec();
    probe.extend((0..SEMI * n).map(|i| if i < len { 0x11 } else { 0 }));
    probe
}

/// `probe` with the indicator replaced by `mli`.
fn with_mli(mut probe: Vec<u8>, mli: u32) -> Vec<u8> {
    probe[..SEMI].copy_from_slice(&aiv(mli));
    probe
}

/// The ICV fault of `n` semiblocks, the fixed class.
fn icv_fault(n: usize) -> Vec<u8> {
    let mut probe = valid(n);
    probe[3] ^= 1;
    probe
}

/// The faults of `n` semiblocks the random class draws from.
fn random_faults(n: usize) -> Vec<Vec<u8>> {
    let len = key_len(n) as u32;
    let mut faults = vec![
        with_mli(valid(n), (SEMI * n) as u32 + 1),
        with_mli(valid(n), 0),
        with_mli(valid(n), 0x8000_0000 + len),
    ];
    if n >= 2 {
        faults.push(with_mli(valid(n), (SEMI * (n - 1)) as u32));
    }
    let mut pad = valid(n);
    let last = pad.len() - 1;
    pad[last] = 1;
    faults.push(pad);
    faults
}

/// The checks of each probe in `secret`, laid out as [`BLOCKS`] gives.
fn check_all(secret: &[u8]) -> [Result<usize, ModeError>; BLOCKS.len()] {
    let mut offset = 0;
    BLOCKS.map(|n| {
        let aiv: &[u8; SEMI] = secret[offset..offset + SEMI].try_into().unwrap();
        let padded = &secret[offset + SEMI..offset + SEMI * (n + 1)];
        offset += SEMI * (n + 1);
        kwp_check_internal(aiv, padded)
    })
}

/// Measure the KWP integrity check across its refusals under the
/// paired-class protocol and return the cropped t-test report.
pub fn run(cfg: &RunConfig) -> VerdictReport {
    let valid_probes: Vec<u8> = BLOCKS.iter().flat_map(|&n| valid(n)).collect();
    let expected = BLOCKS.map(|n| Ok(key_len(n)));
    assert_eq!(
        check_all(&valid_probes),
        expected,
        "ct-validation: valid KWP probe refused"
    );
    let fixed: Vec<u8> = BLOCKS.iter().flat_map(|&n| icv_fault(n)).collect();
    let faults: Vec<Vec<Vec<u8>>> = BLOCKS.iter().map(|&n| random_faults(n)).collect();
    let refused = BLOCKS.map(|_| Err(ModeError::TagMismatch));
    assert_eq!(
        check_all(&fixed),
        refused,
        "ct-validation: KWP ICV fault accepted"
    );
    for (p, &n) in BLOCKS.iter().enumerate() {
        for fault in &faults[p] {
            let mut probes = valid_probes.clone();
            let offset: usize = BLOCKS[..p].iter().map(|m| SEMI * (m + 1)).sum();
            probes[offset..offset + SEMI * (n + 1)].copy_from_slice(fault);
            assert_eq!(
                check_all(&probes)[p],
                Err(ModeError::TagMismatch),
                "ct-validation: KWP fault probe accepted"
            );
        }
    }

    let draw: DrawFn<'_> = Box::new(move |raw, input| {
        let mut offset = 0;
        for (p, kinds) in faults.iter().enumerate() {
            let fault = &kinds[usize::from(raw[p]) % kinds.len()];
            input[offset..offset + fault.len()].copy_from_slice(fault);
            offset += fault.len();
        }
    });
    let target = Box::new(|secret: &[u8]| {
        for _ in 0..ROUNDS {
            let r = check_all(secret);
            std::hint::black_box(&r);
        }
    });

    run_target_drawn("kwp_unwrap", &fixed, draw, target, cfg)
}
