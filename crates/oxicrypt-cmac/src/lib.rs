//! AES-CMAC per NIST SP 800-38B.
//!
//! # Approved services
//!
//! | Service | Standard | Key | Entry point |
//! |---------|----------|-----|-------------|
//! | AES-128/192/256-CMAC tag generation and verification | SP 800-38B §6.2, §6.3 | [`CmacKey`], MAC length fixed at 8 to 16 bytes | [`cmac()`], [`cmac_verify()`] |
//!
//! A [`CmacKey`] accepts a 16-, 24- or 32-byte key (AES-128, AES-192 or
//! AES-256), is not `Clone`, and fixes its MAC length at construction,
//! from 8 to 16 bytes, refusing any other with `InvalidInput`; [`cmac()`]
//! returns the 128-bit tag truncated to it, and [`cmac_verify()`] accepts
//! a MAC of exactly that length.
//!
//! SP 800-38B Appendix B recommends authenticating at most 2^48 messages
//! under one key. A [`CmacKey`] does not count its messages: the operator
//! keeps to that limit.
//!
//! The implementation is layered over `oxicrypt-aes::BlockCipher`, so it
//! runs against the same AES primitive that the rest of the module
//! uses — there is no second AES core to keep in sync. The pure-Rust
//! implementation is inherited from `oxicrypt-aes`; see that crate's
//! lib.rs header for its side-channel rationale.
//!
//! # Power-up self-tests
//!
//! [`KATS`] exposes two KATs per AES key size (six entries total),
//! drawn from NIST's CMAC examples (linked from SP 800-38B Appendix D).
//!
//! # Sensitive security parameters
//!
//! - **CMAC key** — CSP. A [`CmacKey`] holds the AES round-key schedule
//!   and the subkeys K1/K2 derived from it at construction, and zeroizes
//!   them when dropped, the schedule by the `Drop` of the `oxicrypt-aes`
//!   round-key types (`block.rs`). The intermediate L is wiped when
//!   `derive_subkeys` returns, on error too. The hidden constructor
//!   `CmacKey::new_in_place` builds the key in a `MaybeUninit` slot the
//!   caller provides and derives the schedule, K1 and K2 there, so the key
//!   is never moved. A `MaybeUninit` runs no destructor, so the caller must
//!   run the key's destructor in place, as the C key handle's free does,
//!   for the zeroize-on-drop to cover the one copy that exists; a slot
//!   left without its destructor run leaves the key unwiped.
//!   [`CmacKey::new`] returns the key by value, and a copy that
//!   the move leaves behind is not zeroized. A copy the compiler makes
//!   under optimisation is outside what the module can observe.
//! - **Tag computation intermediates** — the CBC-MAC state, which ends as
//!   the full 128-bit tag, and the final block masked with K1 or K2 are
//!   wiped on every exit of [`cmac()`] and [`cmac_verify()`], and the
//!   XOR of the tag with the received MAC on every exit of its
//!   comparison in [`cmac_verify()`].
//! - **Message / tag** — public. [`cmac_verify()`] compares a received
//!   MAC with every byte read and no early exit. The `cmac_verify` target
//!   of the constant-time harness `tools/ct-validation` measures that the
//!   time of a refused MAC does not depend on where it differs from the
//!   tag; nothing else about the comparison's timing is measured.
//!
//! # FIPS module gating
//!
//! Every public entry point, [`CmacKey::new`], [`cmac()`] and
//! [`cmac_verify()`], calls
//! [`oxicrypt_module::require_operational`] and then
//! [`oxicrypt_module::require_allowed`] for `Service::CmacAes128`,
//! `CmacAes192` or `CmacAes256` by the key's size. The KAT runners use a
//! crate-private ungated constructor and core, which call
//! [`oxicrypt_module::require_self_test_started`] instead, so the
//! self-tests run during `SelfTest` and nothing runs in any state other
//! than `SelfTest` and `Operational`. The AES block cipher underneath is
//! the hidden non-service `oxicrypt_aes::EcbKey`.

#![no_std]
#![forbid(unsafe_code)]

pub mod cmac;
pub mod kat;
mod wipe;

/// A failure injected into key derivation, for tests in this and other
/// crates, with the `fault-injection` feature.
#[cfg(feature = "fault-injection")]
#[doc(hidden)]
pub mod seam {
    use core::sync::atomic::{AtomicBool, Ordering};

    static ERROR_AFTER_EXPANSION: AtomicBool = AtomicBool::new(false);

    /// Makes the next CMAC key derivation put the module into its error
    /// state after the AES schedule is expanded and before K1 and K2 are
    /// derived, so the derivation fails with key material in the key. The
    /// error state is permanent for the process.
    pub fn error_after_next_expansion() {
        ERROR_AFTER_EXPANSION.store(true, Ordering::SeqCst);
    }

    pub(crate) fn after_expansion() {
        if ERROR_AFTER_EXPANSION.swap(false, Ordering::SeqCst) {
            oxicrypt_module::enter_error_state("CMAC key derivation failure injected");
        }
    }
}

pub use cmac::{BLOCK_SIZE, CmacKey, cmac, cmac_verify};
pub use kat::KATS;

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod test_support {
    use oxicrypt_module::{KatEntry, initialize_with_tests, require_self_test_started};
    use std::string::String;

    /// Set in a child process that runs one test on its own; the value is
    /// the setting the test body runs under.
    const CHILD: &str = "OXICRYPT_CMAC_TEST_CHILD";

    /// Runs `body` in a fresh process of its own once for each entry of
    /// `settings`, passing the entry.
    ///
    /// The module state and profile are process-global and each
    /// transition is one-way, so a test that sets either must run where
    /// no other test observes it. The test re-executes this binary for
    /// itself alone, `name` being its full path, and checks that exactly
    /// that test ran and passed there.
    pub(crate) fn isolated(name: &str, settings: &[&str], body: impl Fn(&str)) {
        if let Some(setting) = std::env::var_os(CHILD) {
            body(&setting.to_string_lossy());
            return;
        }
        for setting in settings {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([name, "--exact", "--test-threads=1"])
                .env(CHILD, setting)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("test result: ok. 1 passed"),
                "{name} under {setting} did not pass in its own process:\n{stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    pub(crate) const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Brings the module to `Operational` under the unrestricted profile,
    /// so that a test can build keys and call [`crate::cmac()`]. A second
    /// call in the same process is a no-op.
    pub(crate) fn start_module() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        assert_eq!(require_self_test_started(), Ok(()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod gate_tests {
    use crate::test_support::{UNSIGNED_TEST_BINARY, isolated, start_module};
    use crate::{CmacKey, cmac, cmac_verify};
    use oxicrypt_aes::ModeError;
    use oxicrypt_module::{AlgorithmProfile, Error, initialize_with_profile};

    /// An AES-128 key, which the CNSA 2.0 profile refuses.
    const KEY128: [u8; 16] = [0x2b; 16];

    /// Under the CNSA 2.0 profile the constructor, [`cmac()`] and
    /// [`cmac_verify()`] refuse an AES-128 key with `AlgorithmRestricted`;
    /// under the unrestricted profile all three succeed.
    #[test]
    fn forbidden_mode_refused_under_cnsa_profile() {
        isolated(
            "gate_tests::forbidden_mode_refused_under_cnsa_profile",
            &["cnsa2", "unrestricted"],
            |setting| {
                let profile = match setting {
                    "cnsa2" => AlgorithmProfile::Cnsa2,
                    _ => AlgorithmProfile::Unrestricted,
                };
                initialize_with_profile(UNSIGNED_TEST_BINARY, &[], profile).unwrap();
                // Built without the constructor's gate, and the tag computed
                // without the service gates, so that the gates of `cmac` and
                // `cmac_verify` themselves are the ones under test.
                let key = CmacKey::new_ungated(&KEY128, 16).unwrap();
                let tag = crate::cmac::full_tag(&KEY128, b"message").unwrap();
                let mut mac = [0u8; 16];
                let results = [
                    (
                        "CmacKey::new",
                        CmacKey::new(&KEY128, 16)
                            .map(|_| ())
                            .map_err(ModeError::from),
                    ),
                    ("cmac", cmac(&key, b"message", &mut mac)),
                    ("cmac_verify", cmac_verify(&key, b"message", &tag)),
                ];
                for (name, result) in results {
                    if profile == AlgorithmProfile::Cnsa2 {
                        assert!(
                            matches!(
                                result,
                                Err(ModeError::Module(Error::AlgorithmRestricted { .. }))
                            ),
                            "{name} under CNSA 2.0 returned {result:?}"
                        );
                    } else {
                        assert_eq!(result, Ok(()), "{name} without a profile");
                    }
                }
            },
        );
    }

    /// The key accepts a 16-, 24- or 32-byte key and refuses any other
    /// length with `InvalidInput`.
    #[test]
    fn key_lengths_accepted() {
        start_module();
        let bytes = [0x5au8; 33];
        for len in [16, 24, 32] {
            assert!(
                CmacKey::new(&bytes[..len], 16).is_ok(),
                "refused {len} bytes"
            );
        }
        for len in [0, 15, 17, 31, 33] {
            assert!(
                matches!(CmacKey::new(&bytes[..len], 16), Err(Error::InvalidInput)),
                "accepted {len} bytes"
            );
        }
    }

    /// The MAC length is fixed at construction to 8..=16 bytes, and
    /// [`cmac()`] writes exactly that many bytes, the leftmost of the full
    /// tag.
    #[test]
    fn cmac_key_fixes_mac_length() {
        start_module();
        for mac_len in [7, 17] {
            assert!(
                matches!(CmacKey::new(&KEY128, mac_len), Err(Error::InvalidInput)),
                "accepted a MAC length of {mac_len}"
            );
        }
        for mac_len in 0..=17 {
            assert_eq!(
                CmacKey::new(&KEY128, mac_len).is_ok(),
                (8..=16).contains(&mac_len),
                "{mac_len}"
            );
        }
        let full_key = CmacKey::new(&KEY128, 16).unwrap();
        let mut full = [0u8; 16];
        cmac(&full_key, b"message", &mut full).unwrap();
        let short_key = CmacKey::new(&KEY128, 8).unwrap();
        let mut short = [0u8; 8];
        cmac(&short_key, b"message", &mut short).unwrap();
        assert_eq!(short, full[..8]);
        let mut wrong = [0u8; 16];
        assert_eq!(
            cmac(&short_key, b"message", &mut wrong),
            Err(ModeError::LengthMismatch)
        );
    }

    /// At each MAC length the tag verifies, every single-bit flip of it is
    /// rejected with `TagMismatch`, and a MAC one byte short or long is
    /// `InvalidTagLength`.
    #[test]
    fn cmac_verify_rejects_one_bit_flip() {
        start_module();
        for mac_len in [8, 16] {
            let key = CmacKey::new(&KEY128, mac_len).unwrap();
            let mut tag = [0u8; 17];
            cmac(&key, b"message", &mut tag[..mac_len]).unwrap();
            assert_eq!(cmac_verify(&key, b"message", &tag[..mac_len]), Ok(()));
            for byte in 0..mac_len {
                for bit in 0..8 {
                    let mut flipped = tag;
                    flipped[byte] ^= 1 << bit;
                    assert_eq!(
                        cmac_verify(&key, b"message", &flipped[..mac_len]),
                        Err(ModeError::TagMismatch),
                        "bit {bit} of byte {byte} at MAC length {mac_len}"
                    );
                }
            }
            for len in [mac_len - 1, mac_len + 1] {
                assert_eq!(
                    cmac_verify(&key, b"message", &tag[..len]),
                    Err(ModeError::InvalidTagLength),
                    "a {len}-byte MAC at MAC length {mac_len}"
                );
            }
        }
    }
}
