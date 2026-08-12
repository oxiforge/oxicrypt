//! Power-up known-answer tests for oxicrypt-cmac.
//!
//! # Source traceability
//!
//! All vectors in this module are reproduced verbatim from NIST
//! SP 800-38B "Recommendation for Block Cipher Modes of Operation:
//! The CMAC Mode for Authentication", Appendix D "Examples". Each
//! KAT entry names its source example inline.
//!
//!   * **AES-128**: Mlen = 128 (single full block — exercises the K1
//!     subkey path) and Mlen = 320 (two full blocks + partial —
//!     exercises the K2 subkey padding path).
//!   * **AES-192**: the same two message lengths, different published
//!     expected tags.
//!   * **AES-256**: the same two message lengths.
//!
//! Testing one K1-path KAT and one K2-path KAT per key size ensures
//! every AES width drives every CMAC subkey path through the block
//! cipher at power-up.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use oxicrypt_module::{KatEntry, SelfTestFailure};

use crate::cmac::{cmac_aes128_internal, cmac_aes192_internal, cmac_aes256_internal};

// ----------------------------------------------------------------------
// Shared message (the same four 16-byte blocks SP 800-38A uses —
// first 16 bytes = the Mlen=128 message, first 40 bytes = the
// Mlen=320 message).
// ----------------------------------------------------------------------

const D_MSG: [u8; 64] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
];

// ----------------------------------------------------------------------
// AES-128 — NIST CMAC examples
// ----------------------------------------------------------------------

const D1_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

// AES-128, Mlen = 128. Tag = 070a16b4 6b4d4144 f79bdd9d d04a287c
const D1_EX2_TAG: [u8; 16] = [
    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
];

// AES-128, Mlen = 320. Tag = dfa66747 de9ae630 30ca3261 1497c827
const D1_EX3_TAG: [u8; 16] = [
    0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
];

fn kat_aes128_example2() -> Result<(), SelfTestFailure> {
    let got = cmac_aes128_internal(&D1_KEY, &D_MSG[..16]);
    if got == D1_EX2_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

fn kat_aes128_example3() -> Result<(), SelfTestFailure> {
    let got = cmac_aes128_internal(&D1_KEY, &D_MSG[..40]);
    if got == D1_EX3_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ----------------------------------------------------------------------
// AES-192 — NIST CMAC examples
// ----------------------------------------------------------------------

const D2_KEY: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];

// AES-192, Mlen = 128. Tag = 9e99a7bf 31e71090 0662f65e 617c5184
const D2_EX2_TAG: [u8; 16] = [
    0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90, 0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84,
];

// AES-192, Mlen = 320. Tag = 8a1de5be 2eb31aad 089a82e6 ee908b0e
const D2_EX3_TAG: [u8; 16] = [
    0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad, 0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e,
];

fn kat_aes192_example2() -> Result<(), SelfTestFailure> {
    let got = cmac_aes192_internal(&D2_KEY, &D_MSG[..16]);
    if got == D2_EX2_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

fn kat_aes192_example3() -> Result<(), SelfTestFailure> {
    let got = cmac_aes192_internal(&D2_KEY, &D_MSG[..40]);
    if got == D2_EX3_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ----------------------------------------------------------------------
// AES-256 — NIST CMAC examples
// ----------------------------------------------------------------------

const D3_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

// AES-256, Mlen = 128. Tag = 28a7023f 452e8f82 bd4bf28d 8c37c35c
const D3_EX2_TAG: [u8; 16] = [
    0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82, 0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c,
];

// AES-256, Mlen = 320. Tag = aaf3d8f1 de5640c2 32f5b169 b9c911e6
const D3_EX3_TAG: [u8; 16] = [
    0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6,
];

fn kat_aes256_example2() -> Result<(), SelfTestFailure> {
    let got = cmac_aes256_internal(&D3_KEY, &D_MSG[..16]);
    if got == D3_EX2_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

fn kat_aes256_example3() -> Result<(), SelfTestFailure> {
    let got = cmac_aes256_internal(&D3_KEY, &D_MSG[..40]);
    if got == D3_EX3_TAG {
        Ok(())
    } else {
        Err(SelfTestFailure)
    }
}

// ----------------------------------------------------------------------
// Public KAT slice
// ----------------------------------------------------------------------

/// Power-up KAT entries for this crate. Consumed by `acvp-harness`.
pub const KATS: &[KatEntry] = &[
    KatEntry {
        name: "AES-128-CMAC KAT (SP 800-38B Appendix D.1 Example 2, Mlen=128, K1 path)",
        run: kat_aes128_example2,
    },
    KatEntry {
        name: "AES-128-CMAC KAT (SP 800-38B Appendix D.1 Example 3, Mlen=320, K2 path)",
        run: kat_aes128_example3,
    },
    KatEntry {
        name: "AES-192-CMAC KAT (SP 800-38B Appendix D.2 Example 2, Mlen=128, K1 path)",
        run: kat_aes192_example2,
    },
    KatEntry {
        name: "AES-192-CMAC KAT (SP 800-38B Appendix D.2 Example 3, Mlen=320, K2 path)",
        run: kat_aes192_example3,
    },
    KatEntry {
        name: "AES-256-CMAC KAT (SP 800-38B Appendix D.3 Example 2, Mlen=128, K1 path)",
        run: kat_aes256_example2,
    },
    KatEntry {
        name: "AES-256-CMAC KAT (SP 800-38B Appendix D.3 Example 3, Mlen=320, K2 path)",
        run: kat_aes256_example3,
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::KATS;

    #[test]
    fn all_kats_pass() {
        for kat in KATS {
            (kat.run)().unwrap_or_else(|_| panic!("KAT failed: {}", kat.name));
        }
    }
}
