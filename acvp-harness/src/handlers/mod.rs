//! Per-algorithm ACVP dispatch handlers.
//!
//! Each submodule implements [`crate::dispatch::AlgorithmHandler`]
//! for one or more ACVP `(algorithm, revision)` pairs.
//!
//! # Module layout
//!
//! R10 shipped two handlers in their own files — [`sha3_256`] and
//! [`hmac_sha2_256`] — so the pre-R12-A git history stays readable.
//! R12-A adds the rest of the SHA-3 hashing family, both SHAKE XOFs,
//! and every HMAC variant other than HMAC-SHA2-256 in family modules
//! that share a private group driver per shape:
//!
//! - [`sha3`] — `SHA3-224`, `SHA3-384`, `SHA3-512`
//! - [`shake`] — `SHAKE-128`, `SHAKE-256`
//! - [`hmac`] — `HMAC-SHA-1`, the remaining five HMAC-SHA-2 variants,
//!   and all four HMAC-SHA-3 variants
//!
//! R12-B adds a *second envelope shape* — CAVP SHS `.rsp` byte vectors
//! rather than ACVP `internalProjection.json` — with its own
//! [`crate::shs::ShsHandler`] trait. The seven handlers implementing
//! that trait live alongside the ACVP ones, in [`shs`]:
//!
//! - [`shs`] — `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`,
//!   `SHA-512/224`, `SHA-512/256` (all via the byte-oriented
//!   entry points in `oxicrypt_sha`)
//!
//! R13 adds the first KDF family handler and, with it, the first
//! use of the optional ACVP `mode` field on the dispatch key. The
//! `KDA-HKDF-Sp800-56Cr2` envelope publishes across two top-level
//! fields (`algorithm = "KDA"`, `mode = "HKDF"`), so
//! [`crate::dispatch::Registry`] now keys handlers on
//! `(algorithm, mode, revision)`; single-field families return the
//! default `mode = None` and keep their existing shape.
//!
//! - [`kda_hkdf`] — `KDA-HKDF` revision `Sp800-56Cr2`, covering
//!   `SHA2-{224,256,384,512,512/224,512/256}` and
//!   `SHA3-{224,256,384,512}` HMAC instantiations over the
//!   SP 800-56C Rev 2 §5.9.2 hybrid shared-secret form
//!
//! R14-A/R14-B landed all seven AES block-cipher / AEAD / key-wrap
//! AFT handlers in [`aes`]. R15 added the MCT engine for ECB and CBC.
//! R16 added [`cmac`] — CMAC-AES gen/ver (SP 800-38B).
//!
//! R17 adds the three DRBG family handlers — [`drbg`] — covering
//! `ctrDRBG` (AES-128/192/256, with/without DF, with/without PR),
//! `hashDRBG` (SHA2-256/384/512), and `hmacDRBG` (SHA2-256/384/512).
//!
//! R18 adds asymmetric signature-verification and key-validation
//! handlers:
//!
//! - [`ecdsa`] — `ECDSA` / `sigVer` and `keyVer`, revision `FIPS186-5`
//!   (P-256 / SHA2-256)
//! - [`eddsa`] — `EDDSA` / `sigVer` and `keyVer`, revision `1.0`
//!   (ED-25519, pure Ed25519 only — no prehash)
//! - [`rsa`] — `RSA` / `sigVer`, revision `FIPS186-5`
//!   (RSA-2048 PKCS#1 v1.5 / SHA2-256, GDT test type)
//!
//! R19 adds SigGen handlers for deterministic round-trip testing:
//!
//! - [`ecdsa`] — `ECDSA` / `sigGen` (P-256 / SHA2-256, deterministic
//!   via caller-supplied `k`)
//! - [`eddsa`] — `EDDSA` / `sigGen` (ED-25519, pure, naturally
//!   deterministic)
//!
//! R20 adds the SP 800-108r1 KBKDF handler:
//!
//! - [`kbkdf`] — `KDF` revision `1.0`, counter / feedback /
//!   double-pipeline iteration modes across all eleven HMAC
//!   instantiations
//!
//! R21 adds the RSA DecryptionPrimitive handler:
//!
//! - [`rsa_decprim`] — `RSA` / `decryptionPrimitive` revision
//!   `Sp800-56Br2`, raw RSADP with SP 800-56Br2 §7.1.2.1 range
//!   check, both `standard` (non-CRT) and `crt` (Bellcore) key
//!   modes
//!
//! R22 adds the TLS v1.2 KDF (Extended Master Secret) handler:
//!
//! - [`tls12_kdf`] — `TLS-v1.2` / `KDF` revision `RFC7627`,
//!   RFC 7627 Extended Master Secret derivation via the TLS 1.2 PRF
//!   (RFC 5246 §5) over SHA2-{256,384,512}
//!
//! R23 adds the standard (non-EMS) TLS 1.2 KDF handler:
//!
//! - [`kdf_comp_tls`] — `kdf-components` / `tls` revision `1.0`,
//!   standard TLS 1.2 master-secret + key-expansion (v1.2 groups
//!   only; v1.0/1.1 filtered — MD5 not FIPS-approved)
//!
//! R24 adds the RSA SignaturePrimitive handler:
//!
//! - [`rsa_sigprim`] — `RSA` / `signaturePrimitive` revision `2.0`,
//!   raw RSASP1 (RFC 8017 §5.2.1) with range check `0 ≤ msg < n`,
//!   both non-CRT (`d`) and CRT (Bellcore verify-after-sign) key
//!   modes
//!
//! R25 adds RSA SigGen (both padding modes) and PSS SigVer coverage:
//!
//! - [`rsa_siggen`] — `RSA` / `sigGen` revision `FIPS186-5`,
//!   PKCS#1v1.5 (non-CRT, `d`) and PSS (CRT + Bellcore,
//!   `sLen = hLen = 32`) over SHA2-256 / RSA-2048
//! - [`rsa`] — extended RSA SigVer coverage with PSS groups
//!   (`pss-kat-slice.json`), exercising both valid and invalid
//!   (bit-flipped) PSS signatures
//!
//! R26 adds the ECDH shared-secret computation handler:
//!
//! - [`kas_ecc_ssc`] — `KAS-ECC-SSC` / `Component` revision
//!   `Sp800-56Ar3`, P-256 ECDH shared secret `Z = x(d * Q)` per
//!   SP 800-56Ar3 §5.7.1.2
//!
//! R27 adds the RSA OAEP encrypt/decrypt handler:
//!
//! - [`rsa_oaep`] — `RSA` / `OAEP` revision `RFC8017`,
//!   RSAES-OAEP encrypt (RFC 8017 §7.1.1, deterministic with
//!   caller-supplied seed) and decrypt (§7.1.2, non-CRT) over
//!   RSA-2048 / SHA2-256 with empty label
//!
//! R28 adds EdDSA key generation:
//!
//! - [`eddsa`] — `EDDSA` / `keyGen` revision `1.0`, derives the
//!   Ed25519 public key from a 32-byte seed via `keygen_internal`
//!
//! R29 adds ECDSA key generation:
//!
//! - [`ecdsa`] — `ECDSA` / `keyGen` revision `FIPS186-5`, derives the
//!   P-256 public key `(qx, qy)` from a 32-byte scalar `d` via
//!   `derive_public_key_internal`
//!
//! R30 adds SHA-3 Monte Carlo Test (MCT) support:
//!
//! - [`sha3`] and [`sha3_256`] — `SHA3-{224,256,384,512}` / `MCT`
//!   revision `2.0`, 100×1000 iteration chained-hash loop per
//!   ACVP SHA-3 §6.2
//!
//! R31 adds RSA OAEP CRT decrypt coverage:
//!
//! - [`rsa_oaep`] — `RSA` / `OAEP` revision `RFC8017`, extended
//!   decrypt arm to support `keyMode = "crt"` dispatching through
//!   the Bellcore-protected CRT private-exponent primitive per
//!   IG D.G, with self-generated CRT KAT vectors
//!
//! R32 adds RSA key generation:
//!
//! - [`rsa_keygen`] — `RSA` / `keyGen` revision `FIPS186-5`,
//!   DRBG-seeded RSA-2048 probable-prime key generation per
//!   FIPS 186-5 §A.1.1/§B.3.1, returning `(n, d, e, p, q, dP,
//!   dQ, qInv)`, with self-generated vectors
//!
//! R33 adds RSA SigGen cross-product coverage:
//!
//! - [`rsa_siggen`] — extended to support `keyMode` dispatch:
//!   `pkcs1v1.5` + CRT (Bellcore-protected PKCS#1v1.5 sign)
//!   and `pss` + standard (non-CRT PSS sign), completing the
//!   full (sigType × keyMode) cross-product
//!
//! R34 adds a combined RSA OAEP path-equivalence slice:
//!
//! - [`rsa_oaep`] — `RSA` / `OAEP` revision `RFC8017`, combined
//!   three-group vector file (encrypt + CRT decrypt + non-CRT
//!   decrypt) sharing one key, proving both private-key paths
//!   produce identical plaintext from the same ciphertexts
//!
//! R35 adds EdDSA lifecycle cross-validation slices:
//!
//! - [`eddsa`] — three self-generated lifecycle vector files
//!   sharing the same five Ed25519 seeds across `keyGen`,
//!   `sigGen`, and `sigVer` modes, proving the full
//!   keyGen→sigGen→sigVer pipeline is consistent per key
//!
//! R36 adds ECDSA lifecycle cross-validation slices:
//!
//! - [`ecdsa`] — three self-generated lifecycle vector files
//!   sharing the same five DRBG-generated P-256 private keys
//!   across `keyGen`, `sigGen`, and `sigVer` modes, proving
//!   the full keyGen→sigGen→sigVer pipeline is consistent
//!
//! R37 adds RSA lifecycle cross-validation slices:
//!
//! - [`rsa_siggen`] and [`rsa`] — two self-generated lifecycle vector
//!   files sharing one DRBG-generated RSA-2048 key across `sigGen`
//!   (PKCS#1v1.5/standard + PSS/crt) and `sigVer` (valid + invalid
//!   for each sig type), proving the sigGen→sigVer pipeline is
//!   consistent across both padding modes and key representations
//!
//! R38 adds SHA-3 Large Data Test (LDT) support:
//!
//! - [`sha3`] and [`sha3_256`] — `SHA3-{224,256,384,512}` / `LDT`
//!   revision `2.0`, streaming hash over repeating-pattern expanded
//!   messages (up to multi-MB), using the incremental `Sha3::update`
//!   API to avoid materializing the full message in memory
//!
//! R39 completes the RSA lifecycle trifecta:
//!
//! - [`rsa_keygen`] — self-generated `RSA` / `keyGen` lifecycle
//!   slice sharing the same DRBG seed as the R37 sigGen/sigVer
//!   slices, proving keyGen→sigGen→sigVer consistency across
//!   the full RSA pipeline
//!
//! R40 adds a KAS-ECC-SSC lifecycle slice:
//!
//! - [`kas_ecc_ssc`] — self-generated P-256 ECDH lifecycle vectors
//!   reusing the same DRBG-generated private keys from the ECDSA
//!   lifecycle (R36), paired with fresh peer keys, proving that
//!   ECDSA-generated keys also work correctly for ECDH shared
//!   secret computation
//!
//! R41 adds AES encrypt-decrypt lifecycle slices for all seven modes:
//!
//! - [`aes`] — self-generated AES-256 lifecycle vector files for
//!   ECB, CBC, CTR, GCM, CCM, KW, and KWP, each sharing a single
//!   DRBG-generated key and proving encrypt→decrypt path consistency.
//!   Authenticated/wrap modes include an additional invalid-tag/ICV
//!   decrypt group proving `testPassed = false` detection.
//!
//! R42 adds a CMAC-AES gen→ver lifecycle slice:
//!
//! - [`cmac`] — self-generated AES-256 CMAC lifecycle vectors sharing
//!   a single DRBG-generated key across gen (compute) and ver (verify)
//!   groups, with both valid and invalid (bit-flipped MAC) ver cases
//!
//! R43 adds an RSA OAEP lifecycle slice:
//!
//! - [`rsa_oaep`] — self-generated RSA OAEP lifecycle vectors reusing
//!   the same DRBG-generated RSA-2048 key from the RSA lifecycle
//!   (R37/R39), with encrypt + CRT decrypt + non-CRT decrypt groups
//!   proving keyGen→OAEP encrypt→decrypt pipeline consistency
//!
//! R44 adds RSA primitive lifecycle slices:
//!
//! - [`rsa_sigprim`] — self-generated `RSA` / `signaturePrimitive`
//!   lifecycle vectors reusing the RSA lifecycle DRBG-generated key,
//!   with standard (`d`) and CRT (Bellcore) groups proving
//!   keyGen→signaturePrimitive consistency across key representations
//! - [`rsa_decprim`] — self-generated `RSA` / `decryptionPrimitive`
//!   lifecycle vectors sharing the same key and input message
//!   representatives as the sigPrim slice, proving sigPrim/decPrim
//!   cross-handler agreement (both compute `input^d mod n`)
//!
//! R45 adds SHAKE MCT and VOT test type coverage:
//!
//! - [`shake`] — `SHAKE-{128,256}` / `MCT` revision `FIPS202`,
//!   XOF Monte Carlo Test implementing the ACVP XOF MCT algorithm
//!   (draft-celi-acvp-xof §6.2): 100×1000 iterations with variable
//!   output length, self-generated vectors with 5 resultsArray entries
//! - [`shake`] — `SHAKE-{128,256}` / `VOT` revision `FIPS202`,
//!   Variable Output Test using the same envelope as AFT with varying
//!   `outLen` per test case, self-generated vectors with 5 tests each
//!
//! R46 adds SHAKE Large Data Test (LDT) support:
//!
//! - [`shake`] — `SHAKE-{128,256}` / `LDT` revision `FIPS202`,
//!   streaming XOF absorption of repeating-pattern expanded messages
//!   (up to multi-MB) via the incremental `Shake{128,256}::update`
//!   API, with per-test `outLen` for variable-length squeeze
//!
//! R55 adds SP 800-185 derived-function handlers — cSHAKE, KMAC,
//! TupleHash, and ParallelHash — plus the PBKDF2 handler:
//!
//! - [`cshake`] — `cSHAKE-128`, `cSHAKE-256` revision `1.0`, AFT
//!   with variable-length output and hex-encoded customization string S
//! - [`kmac`] — `KMAC-128`, `KMAC-256` revision `1.0`, AFT with
//!   keyed MAC computation and customization string S
//! - [`tuplehash`] — `TupleHash-128`, `TupleHash-256` revision `1.0`,
//!   AFT with tuple-element array and customization string S
//! - [`parallelhash`] — `ParallelHash-128`, `ParallelHash-256`
//!   revision `1.0`, AFT with configurable block size B and
//!   customization string S
//!
//! - [`pbkdf2`] — `PBKDF` revision `1.0`, AFT with group-level
//!   `hmacAlg` selection across SHA-1, SHA2, and SHA3 HMAC
//!   instantiations, per SP 800-132 / RFC 8018 §5.2
//!
//! R56 adds SP 800-185 XOF variant handlers — KMACXOF, TupleHashXOF,
//! and ParallelHashXOF — completing the SP 800-185 derived-function
//! coverage:
//!
//! - [`kmac`] — `KMACXOF-128`, `KMACXOF-256` revision `1.0`, AFT with
//!   keyed XOF output via `finalize()` + `squeeze()` pattern
//! - [`tuplehash`] — `TupleHashXOF-128`, `TupleHashXOF-256` revision
//!   `1.0`, AFT with tuple-element array and XOF squeeze output
//! - [`parallelhash`] — `ParallelHashXOF-128`, `ParallelHashXOF-256`
//!   revision `1.0`, AFT with configurable block size B and XOF output
//!
//! R57 adds KMAC / KMACXOF MVT (MAC Verification Test) support:
//!
//! - [`kmac`] — `KMAC-128`, `KMAC-256`, `KMACXOF-128`, `KMACXOF-256`
//!   revision `1.0`, MVT with `testPassed` boolean response. The shared
//!   `handle_kmac_group` driver now accepts both AFT and MVT test types;
//!   per-test input parsing is extracted into `parse_kmac_test`. MVT
//!   vectors include both valid and bit-flipped (invalid) MAC groups.
//!
//! R58 adds HMAC MVT (MAC Verification Test) support across all 11
//! HMAC variants and accepts the AES-CTR `"CTR"` test type:
//!
//! - [`hmac`] — all 10 HMAC handlers (`HMAC-SHA-1`, `HMAC-SHA2-224`,
//!   `HMAC-SHA2-384`, `HMAC-SHA2-512`, `HMAC-SHA2-512/224`,
//!   `HMAC-SHA2-512/256`, `HMAC-SHA3-224`, `HMAC-SHA3-256`,
//!   `HMAC-SHA3-384`, `HMAC-SHA3-512`) now support both AFT and MVT.
//!   The shared `handle_hmac_group` driver accepts `"MVT"` test type;
//!   per-test parsing is in `parse_hmac_test`. MVT vectors include
//!   valid and bit-flipped (invalid) MAC groups.
//! - [`hmac_sha2_256`] — standalone `HMAC-SHA2-256` handler also gains
//!   MVT support via the same AFT/MVT `TestType` enum pattern.
//! - [`aes`] — AES-CTR mode now accepts the `"CTR"` test type in
//!   addition to `"AFT"`. The ACVP `CTR` test type is processed
//!   identically to AFT from the IUT's perspective — the ACVP server
//!   performs counter-overflow / counter-uniqueness verification
//!   server-side.
//!
//! All SP 800-185 and PBKDF vectors are self-generated because the
//! NIST ACVP-Server at the pinned commit ships no cSHAKE/KMAC/
//! TupleHash/ParallelHash/PBKDF vector directories. HMAC MVT vectors
//! are also self-generated (computed with Python `hmac` module, then
//! first nibble flipped for invalid-MAC groups).
//!
//! Later chunks will add additional modes (larger key sizes).

pub mod aes;
pub mod cmac;
pub mod cshake;
pub mod drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod kas_ecc_ssc;
pub mod kas_ffc_ssc;
pub mod hmac_sha2_256;
pub mod kdf_comp_tls;
pub mod kbkdf;
pub mod kda_hkdf;
pub mod kmac;
pub mod ml_kem;
pub mod parallelhash;
pub mod pbkdf2;
pub mod rsa;
pub mod rsa_decprim;
pub mod rsa_keygen;
pub mod rsa_oaep;
pub mod rsa_siggen;
pub mod rsa_sigprim;
pub mod sha3;
pub mod sha3_256;
pub mod shake;
pub mod shs;
pub mod tls12_kdf;
pub mod tuplehash;
