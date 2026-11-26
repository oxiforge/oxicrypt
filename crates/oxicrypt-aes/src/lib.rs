//! AES block cipher and modes per FIPS 197 / SP 800-38A-F.
//!
//! # Approved services
//!
//! | Service | Standard | Key | Entry point |
//! |---------|----------|-----|-------------|
//! | ECB encrypt/decrypt     | SP 800-38A §6.1 | `EcbKey` | [`ecb_encrypt`] / [`ecb_decrypt`] |
//! | CBC encrypt/decrypt     | SP 800-38A §6.2 | [`CbcKey`] | [`cbc_encrypt`] / [`cbc_decrypt`] |
//! | CTR mode                | SP 800-38A §6.5 | [`CtrKey`] | [`ctr`] |
//! | GCM authenticated encrypt/decrypt | SP 800-38D (96-bit IV, 128-bit tag); encryption draws the whole IV from a caller-owned DRBG (§8.2.2) and returns it with the tag in [`GcmSealed`], the approved sources being the DRBG types of the `oxicrypt-drbg` crate, any other [`oxicrypt_module::Rbg`] implementation being outside the approved service; decryption takes the IV the encrypting party returned | [`GcmKey`] | [`gcm_encrypt`] (key, [`oxicrypt_module::Rbg`], AAD, plaintext, `ciphertext_out`) / [`gcm_decrypt`] (key, IV, AAD, ciphertext, tag, `plaintext_out`) |
//! | CCM authenticated encrypt/decrypt | SP 800-38C | [`CcmKey`] | [`ccm_encrypt`] / [`ccm_decrypt`] |
//! | Key Wrap (KW)           | SP 800-38F §6.2 / RFC 3394 | [`KwKey`] | [`kw_wrap`] / [`kw_unwrap`] (forward cipher), [`kw_wrap_inverse`] / [`kw_unwrap_inverse`] (inverse cipher) |
//! | Key Wrap with Padding (KWP) | SP 800-38F §6.3 / RFC 5649 | [`KwKey`] | [`kwp_wrap`] / [`kwp_unwrap`] (forward cipher), [`kwp_wrap_inverse`] / [`kwp_unwrap_inverse`] (inverse cipher) |
//!
//! Each key type is bound to one mode, accepts a 16-, 24- or 32-byte key
//! (AES-128, AES-192 or AES-256), and is not `Clone`.
//!
//! CCM decryption accepts a ciphertext that is the tag alone
//! (`Clen = Tlen`) and decrypts it to an empty payload once the tag
//! verifies, departing from SP 800-38C §6.2 step 1, which rejects
//! `Clen ≤ Tlen`, because this crate's encryption of an empty payload
//! produces `C = T`. CCM accepts associated data of at most
//! [`ccm::CCM_MAX_AAD_LEN`] bytes, 2^64 − 2^16 − 1, within the
//! `Alen < 2^64` of SP 800-38C Appendix A.1.
//!
//! ```
//! assert_eq!(oxicrypt_aes::ccm::CCM_MAX_AAD_LEN, u64::MAX - (1 << 16));
//! ```
//!
//! KW wrap refuses a plaintext of 2^54 semiblocks or more and KW unwrap a
//! ciphertext of more than 2^54 semiblocks (SP 800-38F §5.3.1 Table 1),
//! in both cipher directions. Every KW and KWP unwrap that fails after the
//! service gates zeroizes the caller's output buffer before it returns,
//! and every wrap that fails after them zeroizes what it wrote there.
//!
//! ECB is exposed so the ACVP harness can drive the per-block CAVP
//! KATs. CTR_DRBG and AES-CMAC do not call it: they run the raw block
//! cipher of the hidden `EcbKey` through [`BlockCipher`]. It is **not**
//! intended for direct use as a confidentiality mode by application
//! callers.
//!
//! # Power-up self-tests
//!
//! [`KATS`] holds 31 entries, 28 positive and 3 negative:
//!
//! | Mode | AES-128 | AES-192 | AES-256 | Entries |
//! |------|---------|---------|---------|---------|
//! | ECB | 1 | 1 | 1 | 3 |
//! | CBC | 1 | 1 | 1 | 3 |
//! | CTR | 1 | 1 | 2 | 4 |
//! | GCM | 1 | 1 | 2 + 1 negative | 5 |
//! | CCM | 1 | 1 | 2 + 1 negative | 5 |
//! | KW  | 1 | 2 | 4 + 1 negative | 8 |
//! | KWP | 0 | 2 | 1 | 3 |
//!
//! Each positive entry encrypts (or wraps) the published plaintext,
//! checks the ciphertext, then decrypts (or unwraps) it and checks the
//! plaintext, so a failure in either direction fails the entry
//! (FIPS 140-3 IG 10.3.A). The second AES-256 CTR entry ends inside a
//! block, the second AES-256 GCM entry has a 20-byte AAD and a plaintext
//! that ends inside a block, and the second AES-256 CCM entry has a
//! 7-byte nonce and a payload that ends inside a block. The KW entries at AES-256 are three
//! RFC 3394 vectors and one inverse-cipher vector, and the AES-256 KWP
//! entry is an inverse-cipher vector. The three negative entries pass
//! only on [`ModeError::TagMismatch`]: the KW one unwraps the
//! inverse-cipher KW vector with byte 0 of its ciphertext flipped and
//! requires the output zeroed, the GCM one decrypts the 20-byte-AAD
//! vector with byte 0 of its tag flipped and requires the output
//! unwritten, and the CCM one decrypts the 7-byte-nonce vector with
//! byte 0 of its tag flipped and requires the output unwritten.
//!
//! Vectors come from the NIST AES example vectors that FIPS 197
//! Appendix C points to, SP 800-38A Appendix F.2 / F.5, the
//! McGrew-Viega GCM Appendix B test cases, the NIST CAVP CCM vectors,
//! RFC 3394 and RFC 5649, and the NIST ACVP-Server KW and KWP sample
//! vectors.
//!
//! ```
//! assert_eq!(oxicrypt_aes::KATS.len(), 31);
//! ```
//!
//! # Sensitive security parameters
//!
//! - **AES key** ([`GcmKey`], [`CcmKey`], [`CbcKey`], [`CtrKey`],
//!   [`KwKey`], `EcbKey`) — CSP.
//!   The key struct stores the expanded round-key schedule; the
//!   caller's original key bytes are not retained beyond the
//!   `new(...)` call. The round-key schedule is zeroized via
//!   [`oxicrypt_zeroize`] when the key is dropped, and the wipe is
//!   recorded under the wipe identity `RoundKeys`. The schedule is a key,
//!   not one of the intermediates in the table below. Each key type also has
//!   a hidden constructor, `new_in_place` (with `new_with_count_in_place`
//!   for [`GcmKey`] and [`CcmKey`], and `new_with_limit_in_place` for
//!   [`GcmKey`]), that builds the key in a `MaybeUninit` slot the caller
//!   provides and expands the schedule there, so the key is never moved.
//!   A `MaybeUninit` runs no destructor, so the caller must run the key's
//!   destructor in place, as the C key handle's free does, for the
//!   zeroize-on-drop to cover the one copy that exists; a slot left
//!   without its destructor run leaves the schedule unwiped. The public
//!   `new` constructors return the key by value, and a copy of the
//!   schedule that the move leaves behind is not zeroized. A copy the
//!   compiler makes under optimisation is outside what the module can
//!   observe.
//! - **GCM IV of an encryption** — CSP from its draw inside
//!   [`gcm_encrypt`] until the authenticated encryption consumes it, and
//!   PSP after (SP 800-38D §9.1 item 2; FIPS 140-3 IG C.H Additional
//!   Comment 10). While it is a CSP it has the protection of the other
//!   CSPs: it is held in storage that is zeroized on every exit of
//!   [`gcm_encrypt`], and it leaves the module only in [`GcmSealed`],
//!   after the encryption has run.
//! - **Other IVs, counters and nonces** — public parameters: the IV
//!   passed to [`gcm_decrypt`], the CBC IV, the CTR initial counter block
//!   and the CCM nonce. The caller keeps the CCM nonce unique under a key
//!   and every CTR counter block unique across all messages under a key
//!   (SP 800-38A Appendix B), and makes each CBC IV unpredictable to an
//!   adversary before its message is encrypted (SP 800-38A Appendix C).
//!   Reusing a GCM IV or a CCM nonce under one key breaks authenticity.
//! - **GCM/CCM authentication tags** — public outputs; `*_decrypt`
//!   entry points return a single error variant on any mismatch (no early-return
//!   distinguisher between "wrong tag" and "wrong ciphertext").
//!
//! The secret intermediates are zeroized as follows:
//!
//! | Intermediate | Zeroized |
//! |--------------|----------|
//! | GCM: the GHASH subkey H, the pre-counter block J0, the counter block, the keystream block, the GHASH accumulator S, CIPH_K(J0) and the computed tag | on every exit of [`gcm_encrypt`] and [`gcm_decrypt`] |
//! | GCM encryption: the tag between the core writing it and its copy into [`GcmSealed`] (`GcmSealTag`) | on every exit of [`gcm_encrypt`] after the IV draw |
//! | GCM decryption: the caller's output buffer | on a module error after the tag has verified |
//! | GHASH multiplication: the operands V and Z, and the product of the accelerated path | on every exit of each multiplication |
//! | ECB: the 16-byte working block (`EcbBlock`) | on every exit of [`ecb_encrypt`] and [`ecb_decrypt`] |
//! | CBC: the 16-byte working block (`CbcBlock`) | on every exit of [`cbc_encrypt`] and [`cbc_decrypt`] |
//! | CTR: the counter block T_j and the output block O_j | on every exit of [`ctr`] |
//! | ECB and CBC decryption and CTR: the caller's output buffer | on a module error partway through |
//! | CCM encryption: the CBC-MAC state Y, S0, the keystream block and the block holding a plaintext block for the CBC-MAC (`CcmPlaintextBlock`) | on every exit of [`ccm_encrypt`] |
//! | CCM decryption: the CBC-MAC state and the 16-byte locals holding a keystream block, a decrypted payload block, S0 or the recomputed tag | on every exit of [`ccm_decrypt`] |
//! | KW and KWP: the register A and the 16-byte working block, in wrap and unwrap | on every exit of each wrap and unwrap |
//! | KW and KWP wrap: the caller's output buffer (`KwWrapOutput`), which holds the key being wrapped before W runs | every byte the wrap wrote, on an error after the service gates |
//! | KW and KWP unwrap: the caller's output buffer | on every refusal after the service gates |
//! | Key expansion: the word `temp` (FIPS 197 §5.2) | after each expansion step |
//!
//! # FIPS module gating
//!
//! Every public key constructor and mode function calls
//! [`oxicrypt_module::require_operational`] and then
//! [`oxicrypt_module::require_allowed`] for its own mode's
//! [`oxicrypt_module::Service`] at the key's size: the key constructors
//! [`GcmKey::new`], [`GcmKey::new_with_count`], [`GcmKey::new_with_limit`],
//! [`CcmKey::new`], [`CcmKey::new_with_count`], [`CbcKey::new`],
//! [`CtrKey::new`] and [`KwKey::new`], and every mode function. The
//! accessors [`GcmKey::invocations`] and [`CcmKey::invocations`] are reads
//! with no cryptographic effect and apply neither gate. The KWP functions gate on the
//! KWP service although their key is a [`KwKey`], built under the KW
//! service. Each mode function calls an ungated crate-private core, which
//! the power-up self-tests in [`KATS`] call directly during `SelfTest`.
//!
//! The hidden constructor `EcbKey::new` is a non-service interface: it
//! applies no algorithm-profile gate and admits the self-test state, for
//! the self-tests, CTR_DRBG and CMAC. The only service over an `EcbKey` is
//! ECB, which is gated. The hidden per-block methods of [`BlockCipher`]
//! check the module state again on every block, so a self-test proof held
//! across a transition to the error state drives no further blocks.
//!
//! # Side-channel posture
//!
//! The portable AES uses a byte-wise S-box with no T-tables. Its
//! 256-byte S-box is indexed by secret data, the single residual
//! data-dependent memory access. GHASH multiplication (SP 800-38D §6.3
//! Algorithm 1), the GF(2^8) multiplication of MixColumns and
//! InvMixColumns, the KWP unwrap integrity scan (SP 800-38F §6.3
//! Algorithm 6) and the CMAC subkey derivation of `oxicrypt-cmac`
//! (SP 800-38B §6.1) are branch-free on secret data at the source level,
//! on the portable path only: each conditional step is applied under a
//! mask of all ones or all zeros, and the masks of GHASH, MixColumns and
//! the CMAC subkey derivation pass through `core::hint::black_box`. That
//! the compiled code keeps the property is not guaranteed; the
//! constant-time harness `tools/ct-validation` measures it with its
//! targets `ghash`, `aes_gmul`, `kwp_unwrap` and `cmac_subkey`. Its target
//! `cmac_verify` measures that the time of a refused MAC in
//! `oxicrypt-cmac`'s `cmac_verify` does not depend on where the MAC
//! differs from the tag.
//!
//! The optional `accel-aes` feature (default off) dispatches to AES-NI
//! and PCLMULQDQ with a portable fallback. A bitsliced or computed-S-box
//! portable AES would remove the S-box residual; none is implemented.
//! FIPS 140-3 Level 1 does not mandate side-channel resistance.

#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod ccm;
pub mod kat;
pub mod kw;
pub mod modes;
mod observe;
mod wipe;

/// Wipe counts for tests in other crates, with the `fault-injection`
/// feature.
#[cfg(feature = "fault-injection")]
#[doc(hidden)]
pub mod seam {
    /// The number of AES round-key schedules dropped in this process so
    /// far, each wiped by its key's `Drop`, every key type and every key
    /// size counted. The count includes the schedule of a key its
    /// constructor refused, which is dropped zeroed and unexpanded, so it
    /// counts schedules dropped, not populated schedules wiped.
    pub fn schedule_wipes() -> u64 {
        crate::wipe::seam::wipes(crate::wipe::WipedBuffer::RoundKeys)
    }
}

pub use block::{BLOCK_SIZE, EcbKey};
pub use ccm::{CcmKey, ccm_decrypt, ccm_encrypt};
pub use kat::KATS;
pub use kw::{
    KW_DEFAULT_IV, KWP_IV_PREFIX, KwKey, kw_unwrap, kw_unwrap_inverse, kw_wrap, kw_wrap_inverse,
    kwp_unwrap, kwp_unwrap_inverse, kwp_wrap, kwp_wrap_inverse,
};
pub use modes::{
    BlockCipher, CbcKey, CtrKey, GcmKey, GcmSealed, ModeError, cbc_decrypt, cbc_encrypt, ctr,
    ecb_decrypt, ecb_encrypt, gcm_decrypt, gcm_encrypt, mode_error_variants,
};

#[cfg(test)]
extern crate std;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
pub(crate) mod test_support {
    use crate::{BlockCipher, EcbKey};
    use core::cell::Cell;
    use oxicrypt_module::{
        Error, KatEntry, SelfTestStarted, State, initialize_with_tests, require_self_test_started,
    };
    use std::string::String;

    /// Stands in for the pre-operational integrity test, which cannot pass
    /// in an unsigned test binary.
    pub(crate) const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    /// Brings the module to `Operational` under the unrestricted profile,
    /// so that a test can build keys and call the gated functions. A
    /// second call in the same process is a no-op.
    pub(crate) fn start_module() {
        let _ = initialize_with_tests(UNSIGNED_TEST_BINARY, &[]);
        assert_eq!(require_self_test_started(), Ok(()));
    }

    /// The error a block call returns once the module is in its error
    /// state, which [`FailAt`] returns for its refused call.
    pub(crate) const FAILED: Error = Error::NotOperational {
        current: State::Error,
    };

    /// A cipher that refuses its `refused_call`-th block call with
    /// [`FAILED`] and passes every other call to an AES-256 key of
    /// `0x66` bytes.
    pub(crate) struct FailAt {
        inner: EcbKey,
        pub(crate) calls: Cell<u64>,
        refused_call: u64,
    }

    impl FailAt {
        pub(crate) fn new(refused_call: u64) -> Self {
            Self {
                inner: EcbKey::new(&[0x66; 32]).unwrap(),
                calls: Cell::new(0),
                refused_call,
            }
        }

        fn call(&self) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == self.refused_call {
                Err(FAILED)
            } else {
                Ok(())
            }
        }
    }

    impl BlockCipher for FailAt {
        fn encrypt_block_with(
            &self,
            started: &SelfTestStarted,
            block: &mut [u8; 16],
        ) -> Result<(), Error> {
            self.call()?;
            self.inner.encrypt_block_with(started, block)
        }
        fn decrypt_block_with(
            &self,
            started: &SelfTestStarted,
            block: &mut [u8; 16],
        ) -> Result<(), Error> {
            self.call()?;
            self.inner.decrypt_block_with(started, block)
        }
    }

    /// Set in a child process that runs one test on its own; the value is
    /// the setting the test body runs under.
    const CHILD: &str = "OXICRYPT_AES_TEST_CHILD";

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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod gate_tests {
    use crate::block::KeySchedule;
    use crate::test_support::{UNSIGNED_TEST_BINARY, isolated, start_module};
    use crate::{
        BlockCipher, CbcKey, CcmKey, CtrKey, EcbKey, GcmKey, KwKey, ModeError, cbc_decrypt,
        cbc_encrypt, ccm_decrypt, ccm_encrypt, ctr, ecb_decrypt, ecb_encrypt, gcm_decrypt,
        gcm_encrypt, kw_unwrap, kw_unwrap_inverse, kw_wrap, kw_wrap_inverse, kwp_unwrap,
        kwp_unwrap_inverse, kwp_wrap, kwp_wrap_inverse,
    };
    use oxicrypt_module::{
        AlgorithmProfile, Error, State, enter_error_state, initialize_with_profile,
        initialize_with_tests, require_self_test_started_token,
    };
    use std::vec::Vec;

    /// An AES-128 key, which the CNSA 2.0 profile refuses in every mode.
    const KEY128: [u8; 16] = [0x2b; 16];

    /// A generator of one fixed byte value, reporting 256 bits.
    struct FixedRbg;

    impl oxicrypt_module::Rbg for FixedRbg {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), oxicrypt_module::RbgError> {
            out.fill(0x5a);
            Ok(())
        }

        fn strength_bits(&self) -> u32 {
            256
        }
    }

    /// The schedule of `key`, built without any constructor's gate so that
    /// a mode function's own gate is the one under test.
    fn schedule(key: &[u8]) -> KeySchedule {
        let mut s = KeySchedule::zeroed(key.len()).unwrap();
        s.expand(key);
        s
    }

    /// A constructor's result in the form [`every_entry_point`] records.
    fn built<K>(r: Result<K, Error>) -> Result<(), ModeError> {
        r.map(|_| ()).map_err(ModeError::from)
    }

    /// Calls every public constructor and mode function once with an
    /// AES-128 key and records each result by name. A decryption takes the
    /// output of the matching encryption, so each succeeds when its gates
    /// pass.
    fn every_entry_point() -> Vec<(&'static str, Result<(), ModeError>)> {
        let mut r: Vec<(&'static str, Result<(), ModeError>)> = std::vec![
            (
                "GcmKey::new",
                GcmKey::new(&KEY128).map(|_| ()).map_err(ModeError::from)
            ),
            (
                "GcmKey::new_with_count",
                built(GcmKey::new_with_count(&KEY128, 1))
            ),
            (
                "GcmKey::new_with_limit",
                built(GcmKey::new_with_limit(&KEY128, 1))
            ),
            ("CcmKey::new", built(CcmKey::new(&KEY128, 16))),
            (
                "CcmKey::new_with_count",
                built(CcmKey::new_with_count(&KEY128, 16, 1))
            ),
            (
                "CbcKey::new",
                CbcKey::new(&KEY128).map(|_| ()).map_err(ModeError::from)
            ),
            (
                "CtrKey::new",
                CtrKey::new(&KEY128).map(|_| ()).map_err(ModeError::from)
            ),
            (
                "KwKey::new",
                KwKey::new(&KEY128).map(|_| ()).map_err(ModeError::from)
            ),
        ];

        let pt = [0x11u8; 32];
        let mut ct = [0u8; 32];
        let mut back = [0u8; 32];

        let ecb = EcbKey {
            schedule: schedule(&KEY128),
        };
        r.push(("ecb_encrypt", ecb_encrypt(&ecb, &pt, &mut ct)));
        r.push(("ecb_decrypt", ecb_decrypt(&ecb, &ct, &mut back)));

        let cbc = CbcKey {
            schedule: schedule(&KEY128),
        };
        r.push(("cbc_encrypt", cbc_encrypt(&cbc, &[0u8; 16], &pt, &mut ct)));
        r.push(("cbc_decrypt", cbc_decrypt(&cbc, &[0u8; 16], &ct, &mut back)));

        let ctr_key = CtrKey {
            schedule: schedule(&KEY128),
        };
        r.push(("ctr", ctr(&ctr_key, &[0u8; 16], &pt, &mut ct)));

        let gcm = GcmKey {
            schedule: schedule(&KEY128),
            invocations: core::sync::atomic::AtomicU64::new(0),
            limit: 1 << 32,
        };
        let sealed = gcm_encrypt(&gcm, &mut FixedRbg, b"", &pt, &mut ct);
        let (iv, tag) = sealed.map_or(([0u8; 12], [0u8; 16]), |s| (s.iv, s.tag));
        r.push(("gcm_encrypt", sealed.map(|_| ())));
        r.push((
            "gcm_decrypt",
            gcm_decrypt(&gcm, &iv, b"", &ct, &tag, &mut back),
        ));

        let ccm = CcmKey {
            schedule: schedule(&KEY128),
            tag_len: 16,
            invocations: core::sync::atomic::AtomicU64::new(0),
        };
        let mut tag = [0u8; 16];
        r.push((
            "ccm_encrypt",
            ccm_encrypt(&ccm, &[0u8; 13], b"", &pt, &mut ct, &mut tag),
        ));
        r.push((
            "ccm_decrypt",
            ccm_decrypt(&ccm, &[0u8; 13], b"", &ct, &tag, &mut back),
        ));

        let kw = KwKey {
            schedule: schedule(&KEY128),
        };
        let mut wrapped = [0u8; 40];
        let mut unwrapped = [0u8; 32];
        r.push(("kw_wrap", kw_wrap(&kw, &pt, &mut wrapped)));
        r.push(("kw_unwrap", kw_unwrap(&kw, &wrapped, &mut unwrapped)));
        r.push(("kw_wrap_inverse", kw_wrap_inverse(&kw, &pt, &mut wrapped)));
        r.push((
            "kw_unwrap_inverse",
            kw_unwrap_inverse(&kw, &wrapped, &mut unwrapped),
        ));
        r.push(("kwp_wrap", kwp_wrap(&kw, &pt, &mut wrapped).map(|_| ())));
        r.push((
            "kwp_unwrap",
            kwp_unwrap(&kw, &wrapped, &mut unwrapped).map(|_| ()),
        ));
        r.push((
            "kwp_wrap_inverse",
            kwp_wrap_inverse(&kw, &pt, &mut wrapped).map(|_| ()),
        ));
        r.push((
            "kwp_unwrap_inverse",
            kwp_unwrap_inverse(&kw, &wrapped, &mut unwrapped).map(|_| ()),
        ));
        r
    }

    /// Under the CNSA 2.0 profile every entry point refuses an AES-128 key
    /// with `AlgorithmRestricted`; under the unrestricted profile each
    /// succeeds.
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
                let results = every_entry_point();
                assert_eq!(results.len(), 25);
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

    /// A self-test proof obtained while operational drives the hidden block
    /// methods until the module enters the error state, and none after.
    #[test]
    fn held_token_refused_after_error_state() {
        isolated(
            "gate_tests::held_token_refused_after_error_state",
            &["operational"],
            |_| {
                initialize_with_tests(UNSIGNED_TEST_BINARY, &[]).unwrap();
                let started = require_self_test_started_token().unwrap();
                let key = EcbKey::new(&KEY128).unwrap();
                let mut block = [0u8; 16];
                assert_eq!(key.encrypt_block_with(&started, &mut block), Ok(()));
                assert_ne!(block, [0u8; 16]);
                assert_eq!(key.decrypt_block_with(&started, &mut block), Ok(()));
                assert_eq!(block, [0u8; 16]);

                enter_error_state("held-token refusal test");
                let refused = Err(Error::NotOperational {
                    current: State::Error,
                });
                assert_eq!(key.encrypt_block_with(&started, &mut block), refused);
                assert_eq!(key.decrypt_block_with(&started, &mut block), refused);
                assert_eq!(block, [0u8; 16]);
            },
        );
    }

    /// A key type's constructor, with any further parameter fixed.
    type Constructor = fn(&[u8]) -> Result<(), Error>;

    /// Every key type accepts a 16-, 24- or 32-byte key and refuses any
    /// other length with `InvalidInput`.
    #[test]
    fn key_lengths_accepted() {
        start_module();
        let bytes = [0x5au8; 33];
        let constructors: [(&str, Constructor); 9] = [
            ("GcmKey", |k| GcmKey::new(k).map(|_| ())),
            ("GcmKey::new_with_count", |k| {
                GcmKey::new_with_count(k, 1).map(|_| ())
            }),
            ("GcmKey::new_with_limit", |k| {
                GcmKey::new_with_limit(k, 1).map(|_| ())
            }),
            ("CcmKey", |k| CcmKey::new(k, 16).map(|_| ())),
            ("CcmKey::new_with_count", |k| {
                CcmKey::new_with_count(k, 16, 1).map(|_| ())
            }),
            ("CbcKey", |k| CbcKey::new(k).map(|_| ())),
            ("CtrKey", |k| CtrKey::new(k).map(|_| ())),
            ("KwKey", |k| KwKey::new(k).map(|_| ())),
            ("EcbKey", |k| EcbKey::new(k).map(|_| ())),
        ];
        for (name, new) in constructors {
            for len in [16, 24, 32] {
                assert_eq!(new(&bytes[..len]), Ok(()), "{name} refused {len} bytes");
            }
            for len in [0, 15, 17, 31, 33] {
                assert_eq!(
                    new(&bytes[..len]),
                    Err(Error::InvalidInput),
                    "{name} accepted {len} bytes"
                );
            }
        }
    }

    /// A CCM key accepts the tag lengths 8, 10, 12, 14 and 16 and refuses
    /// every other.
    #[test]
    fn ccm_tag_lengths_accepted() {
        start_module();
        for tag_len in 0..=17 {
            let accepted = CcmKey::new(&KEY128, tag_len).is_ok();
            assert_eq!(
                accepted,
                matches!(tag_len, 8 | 10 | 12 | 14 | 16),
                "{tag_len}"
            );
        }
    }
}
