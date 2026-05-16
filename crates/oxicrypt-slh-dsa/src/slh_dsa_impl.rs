//! Declarative macro generating a full SLH-DSA parameter-set
//! implementation (FIPS 205 §9 internal primitives + §9.2 / §9.3
//! external `ctx`-framing wrappers + power-up KAT) from a per-variant
//! parameter tuple.
//!
//! Mirrors the
//! [`ml_dsa_impl!`](../../oxicrypt-ml-dsa/src/ml_dsa_impl.rs) macro
//! shipped in PR #75; descends from the `define_rsa_wide!` /
//! `ml_kem_impl!` family pattern.
//!
//! # Macro inputs
//!
//! Per-variant parameters from FIPS 205 §11 Table 2:
//!
//! | Parameter | Meaning |
//! |-----------|---------|
//! | `hash_family` | `sha2` or `shake` discriminant — dispatched at instantiation time |
//! | `n` | Hash output / security parameter (bytes): 16, 24, or 32 |
//! | `h` | Total hyper-tree height |
//! | `d` | Number of hyper-tree layers |
//! | `a` | FORS tree height |
//! | `k` | Number of FORS trees |
//! | `lg_w` | log₂ of Winternitz parameter (= 4 for all FIPS 205 variants) |
//!
//! Derived constants emitted by the macro:
//!
//! | Constant | Derivation |
//! |----------|-----------|
//! | `H_PRIME` | `H / D` (tree height per hyper-tree layer) |
//! | `W` | `1 << LG_W` (Winternitz parameter; = 16 for FIPS 205) |
//! | `LEN1` | `(8 · N) / LG_W` |
//! | `LEN2` | `3` for `LG_W = 4` family (constant across FIPS 205) |
//! | `LEN` | `LEN1 + LEN2` |
//! | `PK_LEN` | `2 · N` |
//! | `SK_LEN` | `4 · N` |
//! | `FORS_SIG_LEN` | `K · (1 + A) · N` |
//! | `WOTS_SIG_LEN` | `LEN · N` |
//! | `XMSS_SIG_LEN` | `WOTS_SIG_LEN + H_PRIME · N` |
//! | `HT_SIG_LEN` | `D · XMSS_SIG_LEN` |
//! | `SIG_LEN` | `N + FORS_SIG_LEN + HT_SIG_LEN` |
//!
//! # Generated items
//!
//! Each variant module gets a full self-contained instantiation:
//!
//! | Item | Visibility | Purpose |
//! |------|-----------|---------|
//! | `N`, `H`, `D`, `H_PRIME`, `A`, `K`, `LG_W`, `W`, `LEN1`, `LEN2`, `LEN` | `pub const` | Parameter constants |
//! | `PK_LEN`, `SK_LEN`, `SIG_LEN` | `pub const` | Output sizes |
//! | `FORS_SIG_LEN`, `WOTS_SIG_LEN`, `XMSS_SIG_LEN`, `HT_SIG_LEN` | `pub(crate) const` | Intermediate sizes |
//! | `Adrs`, `AdrsType` | `pub(crate)` | 32-byte address struct + type tag |
//! | `f`, `h`, `t`, `prf`, `prf_msg`, `h_msg`, `fors_index` | `pub(crate)` | Tweakable hashes (SHA-2 or SHAKE-256 per `hash_family`) |
//! | `wots_pkgen`, `wots_sign`, `wots_pk_from_sig` | `pub(crate)` | WOTS+ (FIPS 205 §5) |
//! | `fors_sign`, `fors_pk_from_sig` | `pub(crate)` | FORS (FIPS 205 §8) |
//! | `xmss_node` | `pub(crate)` | XMSS subtree (FIPS 205 §6.1) |
//! | `keygen`, `sign`, `verify` | `pub` | Module-gated FIPS 205 §9.2/§9.3 external API |
//! | `keygen_internal`, `sign_internal`, `verify_internal` | `pub` (hidden) | Gate-free §9.1 mirrors for CAVP/ACVP |
//! | `KATS`, `self_test` | `pub`, private | Power-up self-test |
//!
//! # Architectural note (CMVP gem candidate)
//!
//! The macro is the **single source of truth for every parameter-set
//! divergence** in SLH-DSA. There is no parallel hand-written
//! implementation per variant — every byte of `F`/`H`/`T_l`/`PRF`,
//! the WOTS+ chain, the FORS leaf/auth-path tree-hash, the XMSS
//! tree-hash, and the hyper-tree layered signing is generated from
//! one macro body. A bug fix in the macro body fixes every
//! instantiating variant in lock-step, and the only way to introduce
//! a per-variant divergence is to add a conditional branch on a macro
//! parameter inside the macro body — visible at the single audit
//! site. The intra-macro branches that emerge later (hash family
//! `sha2` vs `shake` in Batch 3; `n = 16` vs `n ∈ {24, 32}` SHA-2
//! sub-variants in Batch 2) are evaluated at instantiation time so
//! each variant monomorphises to one path.
//!
//! # Current scope (Batch 3 of 8)
//!
//! The macro body emits both FIPS 205 hash families: SHA-2 (across all
//! `n ∈ {16, 24, 32}`) and SHAKE (across the same `n` set).
//!
//! Hash-family dispatch is realised by `__hash_family_setup!($hash_family,
//! $n)` plus seven per-construct sub-macros — `__emit_adrs_compress!`,
//! `__emit_f!`, `__emit_h!`, `__emit_t!`, `__emit_prf!`, `__emit_prf_msg!`,
//! `__emit_h_msg!` — each with `(sha2)` and `(shake)` arms. Every
//! per-family divergence lives at exactly one audit site (the arm pair
//! inside the sub-macro), and the main `slh_dsa_impl!` body invokes the
//! sub-macros parameterised by `$hash_family`.
//!
//! The SHA-2 arms encode FIPS 205 §10.1: `F`/`PRF` use SHA-256 at every
//! `n`; `H`/`T_l`/`PRF_msg`/`H_msg` use the `__sha2_long_setup!`-emitted
//! `ShaLong` alias (Sha256 at `n = 16`, Sha512 truncated at `n ∈ {24, 32}`)
//! and the `LONG_BLOCK`/`LONG_OUT`/`LONG_PAD` constants from the same
//! sub-macro. `H_msg` MGF1-expands via a counter-block loop.
//!
//! The SHAKE arms encode FIPS 205 §10.2: every tweakable hash is
//! `SHAKE256(prefix || ADRS || message, 8 · n)` with the full 32-byte
//! ADRS — `__emit_adrs_compress!(shake)` returns `self.bytes`
//! unchanged — so `ADRS_COMPRESSED_LEN` is family-conditional (22 for
//! sha2, 32 for shake). `H_msg` produces variable-length output in one
//! `Shake256::squeeze` call; no MGF1 wrapping is required because the
//! XOF already provides arbitrary output length.

#![allow(unused_macros)]

/// Family-and-`n`-conditional setup for SHA-2 tweakable hashes.
///
/// FIPS 205 §10.1 prescribes two SHA-2 instantiations: at `n = 16` every
/// tweakable hash uses SHA-256; at `n ∈ {24, 32}` the short hashes `F`/`PRF`
/// stay on SHA-256 while the long hashes `H`/`T_l`/`PRF_msg`/`H_msg` move to
/// SHA-512 (truncated to `n` for `H`/`T_l`, HMAC-SHA-512 for `PRF_msg`,
/// MGF1-SHA-512 for `H_msg`). This sub-macro aliases the long-input hasher
/// as `ShaLong` and emits the corresponding `LONG_BLOCK` (HMAC block size),
/// `LONG_OUT` (digest size), and `LONG_PAD` (zero padding to fill a single
/// block after `PK.seed`).
macro_rules! __sha2_long_setup {
    (16) => {
        use oxicrypt_sha::sha256::Sha256 as ShaLong;
        const LONG_BLOCK: usize = 64;
        const LONG_OUT: usize = 32;
        const LONG_PAD: usize = 64 - N;
    };
    ($_:literal) => {
        use oxicrypt_sha::sha512::Sha512 as ShaLong;
        const LONG_BLOCK: usize = 128;
        const LONG_OUT: usize = 64;
        const LONG_PAD: usize = 128 - N;
    };
}
pub(crate) use __sha2_long_setup;

/// Hash-family setup: imports the hash function(s), emits the
/// family-conditional `ADRS_COMPRESSED_LEN` (22 for SHA-2 per FIPS 205
/// §10.1 Table 5, 32 for SHAKE per FIPS 205 §10.2), and emits any
/// short-hash padding constants that only the SHA-2 family needs.
///
/// The `sha2` arm forwards `$n` to `__sha2_long_setup!` so the
/// SHA-2-instantiation-specific `ShaLong` alias and `LONG_*` constants
/// land in the variant module scope before any tweakable hash is emitted.
/// The `shake` arm imports `Shake256` and emits the 32-byte
/// `ADRS_COMPRESSED_LEN`; SHAKE needs no padding or block-size constants
/// because every SHAKE-family tweakable hash is a one-shot XOF.
macro_rules! __hash_family_setup {
    (sha2, $n:tt) => {
        use oxicrypt_sha::sha256::Sha256;
        crate::slh_dsa_impl::__sha2_long_setup!($n);
        /// Compressed-address length (FIPS 205 §10.1 Table 5).
        pub(crate) const ADRS_COMPRESSED_LEN: usize = 22;
        /// SHA-256 zero padding so `PK.seed ‖ padding` fills one 64-byte block.
        const PAD256: usize = 64 - N;
    };
    (shake, $n:tt) => {
        use oxicrypt_xof::Shake256;
        // `$n` is captured for arm-disambiguation parity with the `sha2`
        // arm; SHAKE family is `n`-uniform so no `__sha2_long_setup!`
        // analog is needed.
        const _: usize = $n;
        /// Address length for the SHAKE instantiation (FIPS 205 §10.2
        /// — full uncompressed 32-byte ADRS). The constant retains
        /// the `_COMPRESSED_` name across both families to keep
        /// downstream `[u8; ADRS_COMPRESSED_LEN]` callers single-source;
        /// reviewers should read this as "ADRS bytes fed to the
        /// tweakable hash" rather than literal compression.
        pub(crate) const ADRS_COMPRESSED_LEN: usize = 32;
    };
}
pub(crate) use __hash_family_setup;

/// Emits the `compress()` method body on `impl Adrs`.
///
/// SHA-2 (`compress(sha2)`) — FIPS 205 §10.1 Table 5 22-byte projection:
/// low byte of layer || low 8 bytes of tree || type byte ||
/// keypair-or-hash-address (4) || chain-or-tree-height (4) ||
/// hash-or-tree-index (4).
///
/// SHAKE (`compress(shake)`) — FIPS 205 §10.2 identity: returns the full
/// 32-byte address unchanged so the variant module's `[u8;
/// ADRS_COMPRESSED_LEN]` callers see a 32-byte slice.
macro_rules! __emit_adrs_compress {
    (sha2) => {
        /// Compress to the 22-byte `ADRSc` used by the SHA-2 family
        /// (FIPS 205 §10.1 Table 5).
        pub(crate) fn compress(&self) -> [u8; ADRS_COMPRESSED_LEN] {
            let mut c = [0u8; ADRS_COMPRESSED_LEN];
            c[0] = self.bytes[3];
            c[1..9].copy_from_slice(&self.bytes[8..16]);
            c[9] = self.bytes[19];
            c[10..14].copy_from_slice(&self.bytes[20..24]);
            c[14..18].copy_from_slice(&self.bytes[24..28]);
            c[18..22].copy_from_slice(&self.bytes[28..32]);
            c
        }
    };
    (shake) => {
        /// Return the full 32-byte ADRS used by the SHAKE family
        /// (FIPS 205 §10.2 — no compression).
        pub(crate) fn compress(&self) -> [u8; ADRS_COMPRESSED_LEN] {
            self.bytes
        }
    };
}
pub(crate) use __emit_adrs_compress;

/// `F(PK.seed, ADRS, M₁)` — FIPS 205 §10.1 / §10.2.
///
/// SHA-2: SHA-256 of `PK.seed ‖ pad ‖ ADRSc ‖ M₁` truncated to `N`.
/// SHAKE: `SHAKE256(PK.seed ‖ ADRS ‖ M₁, 8N)`.
macro_rules! __emit_f {
    (sha2) => {
        /// `F(PK.seed, ADRS, M₁)` — FIPS 205 §10.1 (SHA-2 instantiation).
        pub(crate) fn f(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut hasher = Sha256::new_internal();
            hasher.update(pk_seed);
            hasher.update(&[0u8; PAD256]);
            hasher.update(&adrsc);
            hasher.update(m1);
            let full = hasher.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        }
    };
    (shake) => {
        /// `F(PK.seed, ADRS, M₁)` — FIPS 205 §10.2 (SHAKE-256 instantiation).
        pub(crate) fn f(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut x = Shake256::new_internal();
            x.update(pk_seed);
            x.update(&adrsc);
            x.update(m1);
            x.finalize();
            let mut out = [0u8; N];
            x.squeeze(&mut out);
            out
        }
    };
}
pub(crate) use __emit_f;

/// `H(PK.seed, ADRS, M₁, M₂)` — FIPS 205 §10.1 / §10.2.
///
/// SHA-2: `ShaLong` of `PK.seed ‖ LONG_PAD ‖ ADRSc ‖ M₁ ‖ M₂` truncated to `N`.
/// SHAKE: `SHAKE256(PK.seed ‖ ADRS ‖ M₁ ‖ M₂, 8N)`.
macro_rules! __emit_h {
    (sha2) => {
        /// `H(PK.seed, ADRS, M₁, M₂)` — FIPS 205 §10.1
        /// (SHA-256 at n=16, SHA-512 truncated at n∈{24,32}).
        pub(crate) fn h(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N], m2: &[u8; N]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut hasher = ShaLong::new_internal();
            hasher.update(pk_seed);
            hasher.update(&[0u8; LONG_PAD]);
            hasher.update(&adrsc);
            hasher.update(m1);
            hasher.update(m2);
            let full = hasher.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        }
    };
    (shake) => {
        /// `H(PK.seed, ADRS, M₁, M₂)` — FIPS 205 §10.2 (SHAKE-256 instantiation).
        pub(crate) fn h(pk_seed: &[u8; N], adrs: &Adrs, m1: &[u8; N], m2: &[u8; N]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut x = Shake256::new_internal();
            x.update(pk_seed);
            x.update(&adrsc);
            x.update(m1);
            x.update(m2);
            x.finalize();
            let mut out = [0u8; N];
            x.squeeze(&mut out);
            out
        }
    };
}
pub(crate) use __emit_h;

/// `T_l(PK.seed, ADRS, M)` — FIPS 205 §10.1 / §10.2.
///
/// `M` is the concatenation of `l` consecutive `N`-byte values (WOTS+
/// public-key compression or FORS roots compression); the byte slice is
/// passed directly. SHA-2 absorbs through `ShaLong`; SHAKE absorbs
/// through SHAKE-256 in one pass.
macro_rules! __emit_t {
    (sha2) => {
        /// `T_l(PK.seed, ADRS, M)` — FIPS 205 §10.1
        /// (SHA-256 at n=16, SHA-512 truncated at n∈{24,32}).
        pub(crate) fn t(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut hasher = ShaLong::new_internal();
            hasher.update(pk_seed);
            hasher.update(&[0u8; LONG_PAD]);
            hasher.update(&adrsc);
            hasher.update(m);
            let full = hasher.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        }
    };
    (shake) => {
        /// `T_l(PK.seed, ADRS, M)` — FIPS 205 §10.2 (SHAKE-256 instantiation).
        pub(crate) fn t(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut x = Shake256::new_internal();
            x.update(pk_seed);
            x.update(&adrsc);
            x.update(m);
            x.finalize();
            let mut out = [0u8; N];
            x.squeeze(&mut out);
            out
        }
    };
}
pub(crate) use __emit_t;

/// `PRF(PK.seed, SK.seed, ADRS)` — FIPS 205 §10.1 / §10.2.
///
/// Note FIPS 205 specifies the input order as `PK.seed ‖ ADRS ‖ SK.seed`
/// for both families; only the hash function and the ADRS form differ.
macro_rules! __emit_prf {
    (sha2) => {
        /// `PRF(PK.seed, SK.seed, ADRS)` — FIPS 205 §10.1.
        pub(crate) fn prf(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut hasher = Sha256::new_internal();
            hasher.update(pk_seed);
            hasher.update(&[0u8; PAD256]);
            hasher.update(&adrsc);
            hasher.update(sk_seed);
            let full = hasher.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        }
    };
    (shake) => {
        /// `PRF(PK.seed, SK.seed, ADRS)` — FIPS 205 §10.2
        /// (SHAKE-256 instantiation; input order `PK.seed ‖ ADRS ‖ SK.seed`).
        pub(crate) fn prf(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
            let adrsc = adrs.compress();
            let mut x = Shake256::new_internal();
            x.update(pk_seed);
            x.update(&adrsc);
            x.update(sk_seed);
            x.finalize();
            let mut out = [0u8; N];
            x.squeeze(&mut out);
            out
        }
    };
}
pub(crate) use __emit_prf;

/// `PRF_msg(SK.prf, opt_rand, M)` — FIPS 205 §10.1 / §10.2.
///
/// SHA-2 uses HMAC-`ShaLong` (HMAC-SHA-256 at n=16, HMAC-SHA-512
/// truncated at n∈{24,32}). SHAKE uses plain concatenation through
/// SHAKE-256: `SHAKE256(SK.prf ‖ opt_rand ‖ m_prefix ‖ msg, 8N)`. The
/// SHA-2 path requires HMAC because SHA-2 lacks domain separation;
/// SHAKE provides domain separation natively, so concatenation
/// suffices — this is the FIPS 205 design choice.
macro_rules! __emit_prf_msg {
    (sha2) => {
        /// `PRF_msg(SK.prf, opt_rand, M)` — FIPS 205 §10.1
        /// (HMAC-SHA-256 at n=16, HMAC-SHA-512 truncated at n∈{24,32}).
        pub(crate) fn prf_msg(
            sk_prf: &[u8; N],
            opt_rand: &[u8; N],
            m_prefix: &[u8],
            msg: &[u8],
        ) -> [u8; N] {
            const IPAD: u8 = 0x36;
            const OPAD: u8 = 0x5c;

            let mut ipad_key = [0u8; LONG_BLOCK];
            let mut opad_key = [0u8; LONG_BLOCK];
            for i in 0..N {
                ipad_key[i] = sk_prf[i] ^ IPAD;
                opad_key[i] = sk_prf[i] ^ OPAD;
            }
            for i in N..LONG_BLOCK {
                ipad_key[i] = IPAD;
                opad_key[i] = OPAD;
            }

            let mut inner = ShaLong::new_internal();
            inner.update(&ipad_key);
            inner.update(opt_rand);
            inner.update(m_prefix);
            inner.update(msg);
            let inner_hash = inner.finalize();

            let mut outer = ShaLong::new_internal();
            outer.update(&opad_key);
            outer.update(&inner_hash);
            let full = outer.finalize();

            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        }
    };
    (shake) => {
        /// `PRF_msg(SK.prf, opt_rand, M)` — FIPS 205 §10.2
        /// (SHAKE-256 instantiation; plain concatenation, no HMAC wrap).
        pub(crate) fn prf_msg(
            sk_prf: &[u8; N],
            opt_rand: &[u8; N],
            m_prefix: &[u8],
            msg: &[u8],
        ) -> [u8; N] {
            let mut x = Shake256::new_internal();
            x.update(sk_prf);
            x.update(opt_rand);
            x.update(m_prefix);
            x.update(msg);
            x.finalize();
            let mut out = [0u8; N];
            x.squeeze(&mut out);
            out
        }
    };
}
pub(crate) use __emit_prf_msg;

/// `H_msg(R, PK.seed, PK.root, M)` — FIPS 205 §10.1 / §10.2.
///
/// SHA-2: two-step construction with `ShaLong` seed + MGF1-`ShaLong`
/// counter-block stretch to `FORS_DIGEST_BYTES + TREE_BYTES + 1` bytes.
/// SHAKE: single-shot XOF squeeze to the same total length — no MGF1
/// wrapping needed because SHAKE provides arbitrary output length
/// natively. Both paths decompose the expanded bytes identically into
/// `md` (right-aligned in a 64-byte buffer), `tree_idx` (masked to
/// `H - H_PRIME` bits), and `leaf_idx` (masked to `H_PRIME` bits).
macro_rules! __emit_h_msg {
    (sha2) => {
        /// Output of `H_msg`: FORS digest, hyper-tree index, and leaf index.
        pub(crate) struct HMsgOutput {
            pub md: [u8; 64],
            pub tree_idx: u64,
            pub leaf_idx: u32,
        }

        /// `H_msg(R, PK.seed, PK.root, M)` — FIPS 205 §10.1.
        ///
        /// Two-step construction: `ShaLong` produces a fixed-size seed
        /// (`LONG_OUT` bytes), then MGF1-`ShaLong` stretches it to
        /// `FORS_DIGEST_BYTES + TREE_BYTES + 1` bytes via a counter-block
        /// loop. At n∈{24,32} `LONG_OUT = 64` covers every variant's
        /// requirement in a single block; at n=16 `LONG_OUT = 32` and the
        /// loop runs once or twice depending on `FORS` size.
        pub(crate) fn h_msg(
            r: &[u8; N],
            pk_seed: &[u8; N],
            pk_root: &[u8; N],
            m_prefix: &[u8],
            msg: &[u8],
        ) -> HMsgOutput {
            const FORS_DIGEST_BYTES: usize = (K * A + 7) / 8;
            const TREE_BYTES: usize = (H - H_PRIME + 7) / 8;
            // FIPS 205 §10.1 footnote: m = ⌈k·a/8⌉ + ⌈(h-h')/8⌉ + ⌈h'/8⌉.
            // The third term is `LEAF_BYTES = (H_PRIME + 7) / 8`, NOT a
            // hardcoded 1. For H_PRIME ∈ {3, 4, 8} (128f/192f/256f and
            // 256s) this is 1 byte; for H_PRIME = 9 (128s and 192s) this
            // is 2 bytes. A prior hardcoded `+ 1` produced wrong leaf-idx
            // for 128s/192s because the high bit of `leaf_idx` was
            // truncated before masking. Surfaced 2026-05-16 in B7 ACVTS
            // session 730838 (SLH-DSA-SHA2-128s sigGen graded `Incorrect
            // signature`); see CMVP gem in security-policy.md.
            const LEAF_BYTES: usize = (H_PRIME + 7) / 8;
            const REQUIRED_BYTES: usize = FORS_DIGEST_BYTES + TREE_BYTES + LEAF_BYTES;

            let mut h_inner = ShaLong::new_internal();
            h_inner.update(r);
            h_inner.update(pk_seed);
            h_inner.update(pk_root);
            h_inner.update(m_prefix);
            h_inner.update(msg);
            let seed_inner = h_inner.finalize();

            // Buffer dimensioned for any FIPS 205 parameter set: max
            // REQUIRED_BYTES across all variants is well under 64.
            let mut expanded = [0u8; 64];
            let mut counter: u32 = 0;
            let mut offset: usize = 0;
            while offset < REQUIRED_BYTES {
                let mut mgf = ShaLong::new_internal();
                mgf.update(r);
                mgf.update(pk_seed);
                mgf.update(&seed_inner);
                mgf.update(&counter.to_be_bytes());
                let block = mgf.finalize();
                let remaining = REQUIRED_BYTES - offset;
                let take = if remaining < LONG_OUT {
                    remaining
                } else {
                    LONG_OUT
                };
                expanded[offset..offset + take].copy_from_slice(&block[..take]);
                offset += take;
                counter += 1;
            }

            let mut md = [0u8; 64];
            md[64 - FORS_DIGEST_BYTES..].copy_from_slice(&expanded[..FORS_DIGEST_BYTES]);

            let mut tree_raw = 0u64;
            for b in &expanded[FORS_DIGEST_BYTES..FORS_DIGEST_BYTES + TREE_BYTES] {
                tree_raw = (tree_raw << 8) | u64::from(*b);
            }
            let tree_bits = H - H_PRIME;
            let tree_mask = if tree_bits >= 64 {
                u64::MAX
            } else {
                (1u64 << tree_bits) - 1
            };
            let tree_idx = tree_raw & tree_mask;

            // Read all LEAF_BYTES (1 or 2) and pack big-endian; mask to
            // H_PRIME bits. Reading only the final byte before this fix
            // truncated the high bit when H_PRIME = 9.
            let mut leaf_raw: u32 = 0;
            for b in &expanded
                [FORS_DIGEST_BYTES + TREE_BYTES..FORS_DIGEST_BYTES + TREE_BYTES + LEAF_BYTES]
            {
                leaf_raw = (leaf_raw << 8) | u32::from(*b);
            }
            let leaf_mask = (1u32 << H_PRIME) - 1;
            let leaf_idx = leaf_raw & leaf_mask;

            HMsgOutput {
                md,
                tree_idx,
                leaf_idx,
            }
        }
    };
    (shake) => {
        /// Output of `H_msg`: FORS digest, hyper-tree index, and leaf index.
        pub(crate) struct HMsgOutput {
            pub md: [u8; 64],
            pub tree_idx: u64,
            pub leaf_idx: u32,
        }

        /// `H_msg(R, PK.seed, PK.root, M)` — FIPS 205 §10.2.
        ///
        /// Single-shot SHAKE-256 XOF stretched to `FORS_DIGEST_BYTES +
        /// TREE_BYTES + 1` bytes in one `squeeze` call. SHAKE provides
        /// arbitrary-length output natively, so no MGF1 wrapping is
        /// needed. The downstream decomposition (md, tree_idx, leaf_idx)
        /// is byte-identical to the SHA-2 path.
        pub(crate) fn h_msg(
            r: &[u8; N],
            pk_seed: &[u8; N],
            pk_root: &[u8; N],
            m_prefix: &[u8],
            msg: &[u8],
        ) -> HMsgOutput {
            const FORS_DIGEST_BYTES: usize = (K * A + 7) / 8;
            const TREE_BYTES: usize = (H - H_PRIME + 7) / 8;
            // FIPS 205 §10.2 footnote: m = ⌈k·a/8⌉ + ⌈(h-h')/8⌉ + ⌈h'/8⌉.
            // See SHA-2 arm above for the rationale.
            const LEAF_BYTES: usize = (H_PRIME + 7) / 8;
            const REQUIRED_BYTES: usize = FORS_DIGEST_BYTES + TREE_BYTES + LEAF_BYTES;

            let mut x = Shake256::new_internal();
            x.update(r);
            x.update(pk_seed);
            x.update(pk_root);
            x.update(m_prefix);
            x.update(msg);
            x.finalize();

            // Buffer dimensioned for any FIPS 205 parameter set: max
            // REQUIRED_BYTES across all variants is well under 64.
            let mut expanded = [0u8; 64];
            x.squeeze(&mut expanded[..REQUIRED_BYTES]);

            let mut md = [0u8; 64];
            md[64 - FORS_DIGEST_BYTES..].copy_from_slice(&expanded[..FORS_DIGEST_BYTES]);

            let mut tree_raw = 0u64;
            for b in &expanded[FORS_DIGEST_BYTES..FORS_DIGEST_BYTES + TREE_BYTES] {
                tree_raw = (tree_raw << 8) | u64::from(*b);
            }
            let tree_bits = H - H_PRIME;
            let tree_mask = if tree_bits >= 64 {
                u64::MAX
            } else {
                (1u64 << tree_bits) - 1
            };
            let tree_idx = tree_raw & tree_mask;

            let mut leaf_raw: u32 = 0;
            for b in &expanded
                [FORS_DIGEST_BYTES + TREE_BYTES..FORS_DIGEST_BYTES + TREE_BYTES + LEAF_BYTES]
            {
                leaf_raw = (leaf_raw << 8) | u32::from(*b);
            }
            let leaf_mask = (1u32 << H_PRIME) - 1;
            let leaf_idx = leaf_raw & leaf_mask;

            HMsgOutput {
                md,
                tree_idx,
                leaf_idx,
            }
        }
    };
}
pub(crate) use __emit_h_msg;

macro_rules! slh_dsa_impl {
    (
        hash_family = $hash_family:ident;
        n = $n:tt;
        h = $h:expr;
        d = $d:expr;
        a = $a:expr;
        k = $k:expr;
        lg_w = $lg_w:expr;
        svc_keygen = $svc_keygen:expr;
        svc_sign = $svc_sign:expr;
        svc_verify = $svc_verify:expr;
        kat_seed_offset = $kat_seed_offset:expr;
        kat_msg = $kat_msg:expr;
        kat_name = $kat_name:expr;
    ) => {
        use oxicrypt_module::{Error, KatEntry, Service};
        crate::slh_dsa_impl::__hash_family_setup!($hash_family, $n);

        // ── Parameter constants (FIPS 205 §11 Table 2) ──────────────────

        /// Hash output / security parameter in bytes.
        pub const N: usize = $n;

        /// Total hyper-tree height.
        pub const H: usize = $h;

        /// Number of hyper-tree layers.
        pub const D: usize = $d;

        /// Tree height per hyper-tree layer (`H / D`).
        pub const H_PRIME: usize = H / D;

        /// FORS tree height (each FORS tree has 2^A leaves).
        pub const A: usize = $a;

        /// Number of FORS trees.
        pub const K: usize = $k;

        /// log₂ of the Winternitz parameter.
        pub const LG_W: usize = $lg_w;

        /// Winternitz parameter (= 16 for FIPS 205 variants).
        pub const W: usize = 1 << LG_W;

        // ── WOTS+ chain lengths ─────────────────────────────────────────

        /// WOTS+ chain count for message digits.
        pub const LEN1: usize = (8 * N) / LG_W;

        /// WOTS+ chain count for checksum digits. For `LG_W = 4` (the
        /// only value used by FIPS 205 variants) this is 3 across all
        /// parameter sets. Generalises in Batch 2+ if `lg_w` ever varies.
        pub const LEN2: usize = 3;

        /// Total WOTS+ chain count.
        pub const LEN: usize = LEN1 + LEN2;

        // ── Output sizes ────────────────────────────────────────────────

        /// Public key length (`PK.seed ‖ PK.root`).
        pub const PK_LEN: usize = 2 * N;

        /// Secret key length (`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`).
        pub const SK_LEN: usize = 4 * N;

        /// FORS signature: `K` trees × (1 secret + `A` auth-path nodes) × `N` bytes.
        pub(crate) const FORS_SIG_LEN: usize = K * (1 + A) * N;

        /// WOTS+ signature: `LEN` chain values, each `N` bytes.
        pub(crate) const WOTS_SIG_LEN: usize = LEN * N;

        /// XMSS signature: WOTS+ signature + `H_PRIME`-node authentication path.
        pub(crate) const XMSS_SIG_LEN: usize = WOTS_SIG_LEN + H_PRIME * N;

        /// Hyper-tree signature: `D` XMSS signatures.
        pub(crate) const HT_SIG_LEN: usize = D * XMSS_SIG_LEN;

        /// Total signature length: randomness + FORS sig + hyper-tree sig.
        pub const SIG_LEN: usize = N + FORS_SIG_LEN + HT_SIG_LEN;

        // Compile-time sanity check.
        const _: () = assert!(H_PRIME * D == H);

        // ── ADRS (FIPS 205 §4) ──────────────────────────────────────────
        //
        // `ADRS_COMPRESSED_LEN` is emitted by `__hash_family_setup!` —
        // 22 for SHA-2 (FIPS 205 §10.1 Table 5), 32 for SHAKE (§10.2).

        /// Address type tags (FIPS 205 §4 Table 2).
        #[derive(Clone, Copy, PartialEq, Eq)]
        #[repr(u32)]
        pub(crate) enum AdrsType {
            WotsHash = 0,
            WotsPk = 1,
            Tree = 2,
            ForsTree = 3,
            ForsRoots = 4,
            WotsPrf = 5,
            ForsPrf = 6,
        }

        /// 32-byte SLH-DSA address.
        #[derive(Clone, Copy)]
        pub(crate) struct Adrs {
            bytes: [u8; 32],
        }

        #[allow(dead_code)]
        impl Adrs {
            pub(crate) const fn zero() -> Self {
                Self { bytes: [0u8; 32] }
            }

            pub(crate) fn set_layer_address(&mut self, layer: u32) {
                self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
            }
            pub(crate) fn layer_address(&self) -> u32 {
                u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]])
            }

            pub(crate) fn set_tree_address(&mut self, tree: u64) {
                self.bytes[4..8].copy_from_slice(&[0u8; 4]);
                self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
            }
            pub(crate) fn tree_address(&self) -> u64 {
                u64::from_be_bytes([
                    self.bytes[8],
                    self.bytes[9],
                    self.bytes[10],
                    self.bytes[11],
                    self.bytes[12],
                    self.bytes[13],
                    self.bytes[14],
                    self.bytes[15],
                ])
            }

            pub(crate) fn set_type(&mut self, t: AdrsType) {
                self.bytes[16..20].copy_from_slice(&(t as u32).to_be_bytes());
                self.bytes[20..32].copy_from_slice(&[0u8; 12]);
            }

            pub(crate) fn set_keypair_address(&mut self, kp: u32) {
                self.bytes[20..24].copy_from_slice(&kp.to_be_bytes());
            }
            pub(crate) fn keypair_address(&self) -> u32 {
                u32::from_be_bytes([
                    self.bytes[20],
                    self.bytes[21],
                    self.bytes[22],
                    self.bytes[23],
                ])
            }

            pub(crate) fn set_chain_address(&mut self, chain: u32) {
                self.bytes[24..28].copy_from_slice(&chain.to_be_bytes());
            }

            pub(crate) fn set_hash_address(&mut self, hash: u32) {
                self.bytes[28..32].copy_from_slice(&hash.to_be_bytes());
            }

            pub(crate) fn set_tree_height(&mut self, height: u32) {
                self.bytes[24..28].copy_from_slice(&height.to_be_bytes());
            }
            pub(crate) fn tree_height(&self) -> u32 {
                u32::from_be_bytes([
                    self.bytes[24],
                    self.bytes[25],
                    self.bytes[26],
                    self.bytes[27],
                ])
            }

            pub(crate) fn set_tree_index(&mut self, idx: u32) {
                self.bytes[28..32].copy_from_slice(&idx.to_be_bytes());
            }
            pub(crate) fn tree_index(&self) -> u32 {
                u32::from_be_bytes([
                    self.bytes[28],
                    self.bytes[29],
                    self.bytes[30],
                    self.bytes[31],
                ])
            }

            pub(crate) fn as_bytes(&self) -> &[u8; 32] {
                &self.bytes
            }

            crate::slh_dsa_impl::__emit_adrs_compress!($hash_family);
        }

        // ── Tweakable hashes (FIPS 205 §10.1 / §10.2) ───────────────────
        //
        // Every per-family divergence is emitted by a per-construct
        // sub-macro defined in this file. The `(sha2)` arms encode
        // FIPS 205 §10.1 (with the `__sha2_long_setup!`-emitted
        // `ShaLong` alias + `LONG_*` constants handling the n-keyed
        // SHA-256/SHA-512 split); the `(shake)` arms encode FIPS 205
        // §10.2 (SHAKE-256 via one-shot XOF, full 32-byte ADRS, no
        // MGF1 wrapping). See the module header for the dispatch
        // architecture and the const doc for `ADRS_COMPRESSED_LEN`.

        crate::slh_dsa_impl::__emit_f!($hash_family);
        crate::slh_dsa_impl::__emit_h!($hash_family);
        crate::slh_dsa_impl::__emit_t!($hash_family);
        crate::slh_dsa_impl::__emit_prf!($hash_family);
        crate::slh_dsa_impl::__emit_prf_msg!($hash_family);
        crate::slh_dsa_impl::__emit_h_msg!($hash_family);

        /// Extract a single `A`-bit FORS index from the message digest.
        pub(crate) fn fors_index(md: &[u8; 64], i: usize) -> u32 {
            let total_bits = K * A;
            let fors_bytes = (total_bits + 7) / 8;
            let base_offset = 64 * 8 - fors_bytes * 8;
            let bit_offset = base_offset + i * A;
            let mut val: u32 = 0;
            for b in 0..A {
                let byte_idx = (bit_offset + b) / 8;
                let bit_idx = 7 - ((bit_offset + b) % 8);
                let bit = u32::from((md[byte_idx] >> bit_idx) & 1);
                val = (val << 1) | bit;
            }
            val
        }

        // ── WOTS+ (FIPS 205 §5) ─────────────────────────────────────────

        fn chain(
            pk_seed: &[u8; N],
            adrs: &mut Adrs,
            x: &[u8; N],
            start: u32,
            steps: u32,
        ) -> [u8; N] {
            debug_assert!(start + steps <= W as u32);
            let mut tmp = *x;
            for j in start..start + steps {
                adrs.set_hash_address(j);
                tmp = f(pk_seed, adrs, &tmp);
            }
            tmp
        }

        fn base_w_with_checksum(m: &[u8; N]) -> [u8; LEN] {
            let mut msg = [0u8; LEN];
            for i in 0..LEN1 {
                let byte = m[i / 2];
                if i % 2 == 0 {
                    msg[i] = byte >> LG_W as u8;
                } else {
                    msg[i] = byte & ((W as u8) - 1);
                }
            }
            let mut csum: u32 = 0;
            for i in 0..LEN1 {
                csum += (W as u32) - 1 - u32::from(msg[i]);
            }
            csum <<= 4;
            let csum_bytes = (csum as u16).to_be_bytes();
            for i in 0..LEN2 {
                let total_idx = LEN1 + i;
                let bit_offset = i * LG_W;
                let byte_idx = bit_offset / 8;
                let shift = 8 - LG_W - (bit_offset % 8);
                msg[total_idx] = (csum_bytes[byte_idx] >> shift as u8) & ((W as u8) - 1);
            }
            msg
        }

        pub(crate) fn wots_pkgen(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
            let mut tmp = [0u8; LEN * N];
            let mut sk_adrs = *adrs;
            sk_adrs.set_type(AdrsType::WotsPrf);
            sk_adrs.set_keypair_address(adrs.keypair_address());
            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AdrsType::WotsHash);
            chain_adrs.set_keypair_address(adrs.keypair_address());
            for i in 0..LEN {
                sk_adrs.set_chain_address(i as u32);
                let sk_i = prf(pk_seed, sk_seed, &sk_adrs);
                chain_adrs.set_chain_address(i as u32);
                let pk_i = chain(pk_seed, &mut chain_adrs, &sk_i, 0, (W - 1) as u32);
                tmp[i * N..(i + 1) * N].copy_from_slice(&pk_i);
            }
            let mut pk_adrs = *adrs;
            pk_adrs.set_type(AdrsType::WotsPk);
            pk_adrs.set_keypair_address(adrs.keypair_address());
            t(pk_seed, &pk_adrs, &tmp)
        }

        pub(crate) fn wots_sign(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            adrs: &Adrs,
            m: &[u8; N],
        ) -> [u8; WOTS_SIG_LEN] {
            let msg = base_w_with_checksum(m);
            let mut sig = [0u8; WOTS_SIG_LEN];
            let mut sk_adrs = *adrs;
            sk_adrs.set_type(AdrsType::WotsPrf);
            sk_adrs.set_keypair_address(adrs.keypair_address());
            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AdrsType::WotsHash);
            chain_adrs.set_keypair_address(adrs.keypair_address());
            for i in 0..LEN {
                sk_adrs.set_chain_address(i as u32);
                let sk_i = prf(pk_seed, sk_seed, &sk_adrs);
                chain_adrs.set_chain_address(i as u32);
                let sig_i = chain(pk_seed, &mut chain_adrs, &sk_i, 0, u32::from(msg[i]));
                sig[i * N..(i + 1) * N].copy_from_slice(&sig_i);
            }
            sig
        }

        pub(crate) fn wots_pk_from_sig(
            pk_seed: &[u8; N],
            adrs: &Adrs,
            sig: &[u8],
            m: &[u8; N],
        ) -> [u8; N] {
            let msg = base_w_with_checksum(m);
            let mut tmp = [0u8; LEN * N];
            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AdrsType::WotsHash);
            chain_adrs.set_keypair_address(adrs.keypair_address());
            for i in 0..LEN {
                chain_adrs.set_chain_address(i as u32);
                let mut sig_i = [0u8; N];
                sig_i.copy_from_slice(&sig[i * N..(i + 1) * N]);
                let steps = (W as u32) - 1 - u32::from(msg[i]);
                let pk_i = chain(pk_seed, &mut chain_adrs, &sig_i, u32::from(msg[i]), steps);
                tmp[i * N..(i + 1) * N].copy_from_slice(&pk_i);
            }
            let mut pk_adrs = *adrs;
            pk_adrs.set_type(AdrsType::WotsPk);
            pk_adrs.set_keypair_address(adrs.keypair_address());
            t(pk_seed, &pk_adrs, &tmp)
        }

        // ── FORS (FIPS 205 §8) ──────────────────────────────────────────

        fn fors_sk_gen(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs, idx: u32) -> [u8; N] {
            let mut sk_adrs = *adrs;
            sk_adrs.set_type(AdrsType::ForsPrf);
            sk_adrs.set_keypair_address(adrs.keypair_address());
            sk_adrs.set_tree_index(idx);
            prf(pk_seed, sk_seed, &sk_adrs)
        }

        fn fors_node(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            node_idx: u32,
            node_height: u32,
            adrs: &Adrs,
            tree_base: u32,
        ) -> [u8; N] {
            if node_height == 0 {
                let sk = fors_sk_gen(pk_seed, sk_seed, adrs, tree_base + node_idx);
                let mut leaf_adrs = *adrs;
                leaf_adrs.set_type(AdrsType::ForsTree);
                leaf_adrs.set_keypair_address(adrs.keypair_address());
                leaf_adrs.set_tree_height(0);
                leaf_adrs.set_tree_index(tree_base + node_idx);
                return f(pk_seed, &leaf_adrs, &sk);
            }
            let left = fors_node(
                pk_seed,
                sk_seed,
                2 * node_idx,
                node_height - 1,
                adrs,
                tree_base,
            );
            let right = fors_node(
                pk_seed,
                sk_seed,
                2 * node_idx + 1,
                node_height - 1,
                adrs,
                tree_base,
            );
            let mut node_adrs = *adrs;
            node_adrs.set_type(AdrsType::ForsTree);
            node_adrs.set_keypair_address(adrs.keypair_address());
            node_adrs.set_tree_height(node_height);
            node_adrs.set_tree_index(tree_base / (1 << node_height) + node_idx);
            h(pk_seed, &node_adrs, &left, &right)
        }

        pub(crate) fn fors_sign(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            md: &[u8; 64],
            adrs: &Adrs,
        ) -> [u8; FORS_SIG_LEN] {
            let mut sig = [0u8; FORS_SIG_LEN];
            let entry_size = (1 + A) * N;
            for i in 0..K {
                let idx = fors_index(md, i);
                let tree_base = (i as u32) * (1 << A);
                let sig_offset = i * entry_size;
                let sk = fors_sk_gen(pk_seed, sk_seed, adrs, tree_base + idx);
                sig[sig_offset..sig_offset + N].copy_from_slice(&sk);
                for j in 0..A {
                    let sibling = (idx >> j) ^ 1;
                    let node = fors_node(pk_seed, sk_seed, sibling, j as u32, adrs, tree_base);
                    let auth_offset = sig_offset + N + j * N;
                    sig[auth_offset..auth_offset + N].copy_from_slice(&node);
                }
            }
            sig
        }

        pub(crate) fn fors_pk_from_sig(
            pk_seed: &[u8; N],
            md: &[u8; 64],
            sig: &[u8],
            adrs: &Adrs,
        ) -> [u8; N] {
            let entry_size = (1 + A) * N;
            let mut roots = [0u8; K * N];
            for i in 0..K {
                let idx = fors_index(md, i);
                let tree_base = (i as u32) * (1 << A);
                let sig_offset = i * entry_size;
                let mut sk = [0u8; N];
                sk.copy_from_slice(&sig[sig_offset..sig_offset + N]);
                let mut leaf_adrs = *adrs;
                leaf_adrs.set_type(AdrsType::ForsTree);
                leaf_adrs.set_keypair_address(adrs.keypair_address());
                leaf_adrs.set_tree_height(0);
                leaf_adrs.set_tree_index(tree_base + idx);
                let mut node = f(pk_seed, &leaf_adrs, &sk);
                for j in 0..A {
                    let auth_offset = sig_offset + N + j * N;
                    let mut auth = [0u8; N];
                    auth.copy_from_slice(&sig[auth_offset..auth_offset + N]);
                    let mut tree_adrs = *adrs;
                    tree_adrs.set_type(AdrsType::ForsTree);
                    tree_adrs.set_keypair_address(adrs.keypair_address());
                    tree_adrs.set_tree_height((j + 1) as u32);
                    if (idx >> j) & 1 == 0 {
                        tree_adrs.set_tree_index(tree_base / (1 << (j + 1)) + (idx >> (j + 1)));
                        node = h(pk_seed, &tree_adrs, &node, &auth);
                    } else {
                        tree_adrs.set_tree_index(tree_base / (1 << (j + 1)) + (idx >> (j + 1)));
                        node = h(pk_seed, &tree_adrs, &auth, &node);
                    }
                }
                roots[i * N..(i + 1) * N].copy_from_slice(&node);
            }
            let mut pk_adrs = *adrs;
            pk_adrs.set_type(AdrsType::ForsRoots);
            pk_adrs.set_keypair_address(adrs.keypair_address());
            t(pk_seed, &pk_adrs, &roots)
        }

        // ── XMSS (FIPS 205 §6.1) ────────────────────────────────────────

        pub(crate) fn xmss_node(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            target_idx: u32,
            target_height: u32,
            adrs: &Adrs,
        ) -> [u8; N] {
            debug_assert!(target_height <= H_PRIME as u32);
            if target_height == 0 {
                let mut leaf_adrs = *adrs;
                leaf_adrs.set_type(AdrsType::WotsHash);
                leaf_adrs.set_keypair_address(target_idx);
                return wots_pkgen(pk_seed, sk_seed, &leaf_adrs);
            }
            let left = xmss_node(pk_seed, sk_seed, 2 * target_idx, target_height - 1, adrs);
            let right = xmss_node(
                pk_seed,
                sk_seed,
                2 * target_idx + 1,
                target_height - 1,
                adrs,
            );
            let mut node_adrs = *adrs;
            node_adrs.set_type(AdrsType::Tree);
            node_adrs.set_tree_height(target_height);
            node_adrs.set_tree_index(target_idx);
            h(pk_seed, &node_adrs, &left, &right)
        }

        fn xmss_sign(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            idx: u32,
            m: &[u8; N],
            adrs: &Adrs,
        ) -> [u8; XMSS_SIG_LEN] {
            let mut sig = [0u8; XMSS_SIG_LEN];
            let mut wots_adrs = *adrs;
            wots_adrs.set_type(AdrsType::WotsHash);
            wots_adrs.set_keypair_address(idx);
            let wots_sig = wots_sign(pk_seed, sk_seed, &wots_adrs, m);
            sig[..WOTS_SIG_LEN].copy_from_slice(&wots_sig);
            for j in 0..H_PRIME {
                let sibling_idx = (idx >> j) ^ 1;
                let node = xmss_node(pk_seed, sk_seed, sibling_idx, j as u32, adrs);
                let offset = WOTS_SIG_LEN + j * N;
                sig[offset..offset + N].copy_from_slice(&node);
            }
            sig
        }

        fn xmss_pk_from_sig(
            pk_seed: &[u8; N],
            idx: u32,
            sig: &[u8],
            m: &[u8; N],
            adrs: &Adrs,
        ) -> [u8; N] {
            let wots_sig = &sig[..WOTS_SIG_LEN];
            let mut wots_adrs = *adrs;
            wots_adrs.set_type(AdrsType::WotsHash);
            wots_adrs.set_keypair_address(idx);
            let mut node = wots_pk_from_sig(pk_seed, &wots_adrs, wots_sig, m);
            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AdrsType::Tree);
            tree_adrs.set_tree_index(idx);
            for j in 0..H_PRIME {
                let auth_offset = WOTS_SIG_LEN + j * N;
                let mut auth_node = [0u8; N];
                auth_node.copy_from_slice(&sig[auth_offset..auth_offset + N]);
                tree_adrs.set_tree_height((j + 1) as u32);
                if (idx >> j) & 1 == 0 {
                    tree_adrs.set_tree_index((idx >> (j + 1)) as u32);
                    node = h(pk_seed, &tree_adrs, &node, &auth_node);
                } else {
                    tree_adrs.set_tree_index((idx >> (j + 1)) as u32);
                    node = h(pk_seed, &tree_adrs, &auth_node, &node);
                }
            }
            node
        }

        // ── Hyper-tree (FIPS 205 §6.2) ──────────────────────────────────

        fn ht_sign(
            pk_seed: &[u8; N],
            sk_seed: &[u8; N],
            m: &[u8; N],
            tree_idx: u64,
            leaf_idx: u32,
        ) -> [u8; HT_SIG_LEN] {
            let mut sig = [0u8; HT_SIG_LEN];
            let mut adrs = Adrs::zero();
            adrs.set_layer_address(0);
            adrs.set_tree_address(tree_idx);
            let sig_0 = xmss_sign(pk_seed, sk_seed, leaf_idx, m, &adrs);
            sig[..XMSS_SIG_LEN].copy_from_slice(&sig_0);
            let mut root = xmss_pk_from_sig(pk_seed, leaf_idx, &sig_0, m, &adrs);
            let mut current_tree = tree_idx;
            for layer in 1..D as u32 {
                let idx = (current_tree & ((1u64 << H_PRIME) - 1)) as u32;
                current_tree >>= H_PRIME;
                adrs.set_layer_address(layer);
                adrs.set_tree_address(current_tree);
                let sig_layer = xmss_sign(pk_seed, sk_seed, idx, &root, &adrs);
                let offset = layer as usize * XMSS_SIG_LEN;
                sig[offset..offset + XMSS_SIG_LEN].copy_from_slice(&sig_layer);
                root = xmss_pk_from_sig(pk_seed, idx, &sig_layer, &root, &adrs);
            }
            sig
        }

        fn ht_verify(
            pk_seed: &[u8; N],
            pk_root: &[u8; N],
            m: &[u8; N],
            sig: &[u8],
            tree_idx: u64,
            leaf_idx: u32,
        ) -> bool {
            let mut adrs = Adrs::zero();
            adrs.set_layer_address(0);
            adrs.set_tree_address(tree_idx);
            let sig_0 = &sig[..XMSS_SIG_LEN];
            let mut root = xmss_pk_from_sig(pk_seed, leaf_idx, sig_0, m, &adrs);
            let mut current_tree = tree_idx;
            for layer in 1..D as u32 {
                let idx = (current_tree & ((1u64 << H_PRIME) - 1)) as u32;
                current_tree >>= H_PRIME;
                adrs.set_layer_address(layer);
                adrs.set_tree_address(current_tree);
                let offset = layer as usize * XMSS_SIG_LEN;
                let sig_layer = &sig[offset..offset + XMSS_SIG_LEN];
                root = xmss_pk_from_sig(pk_seed, idx, sig_layer, &root, &adrs);
            }
            root == *pk_root
        }

        // ── External API (FIPS 205 §9) ──────────────────────────────────

        /// Maximum size of the external API framing prefix: 2 header
        /// bytes plus the 255-byte ctx cap.
        const EXT_PREFIX_MAX: usize = 2 + 255;

        struct ExternalPrefix {
            buf: [u8; EXT_PREFIX_MAX],
            len: usize,
        }

        impl ExternalPrefix {
            #[allow(clippy::indexing_slicing)]
            fn as_slice(&self) -> &[u8] {
                &self.buf[..self.len]
            }
        }

        #[allow(
            clippy::arithmetic_side_effects,
            clippy::cast_possible_truncation,
            clippy::indexing_slicing
        )]
        fn build_external_prefix(ctx: &[u8]) -> Result<ExternalPrefix, Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidInput);
            }
            let mut buf = [0u8; EXT_PREFIX_MAX];
            buf[0] = 0x00;
            buf[1] = ctx.len() as u8;
            buf[2..2 + ctx.len()].copy_from_slice(ctx);
            Ok(ExternalPrefix {
                buf,
                len: 2 + ctx.len(),
            })
        }

        /// Generate a key pair (FIPS 205 §9.2 Algorithm 21).
        pub fn keygen(xi: &[u8]) -> Result<([u8; PK_LEN], [u8; SK_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_keygen)?;
            if xi.len() != 3 * N {
                return Err(Error::InvalidInput);
            }
            let mut seed = [0u8; 3 * N];
            seed.copy_from_slice(xi);
            let (pk, sk) = keygen_internal(&seed);
            Ok((pk, sk))
        }

        /// Gate-free keygen for CAVP/ACVP harnesses (FIPS 205 §9.1 Algorithm 17).
        #[doc(hidden)]
        pub fn keygen_internal(xi: &[u8; 3 * N]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
            let sk_seed: &[u8; N] = xi[..N].try_into().unwrap();
            let sk_prf: &[u8; N] = xi[N..2 * N].try_into().unwrap();
            let pk_seed: &[u8; N] = xi[2 * N..3 * N].try_into().unwrap();
            let adrs = Adrs::zero();
            let mut top_adrs = adrs;
            top_adrs.set_layer_address((D - 1) as u32);
            let pk_root = xmss_node(pk_seed, sk_seed, 0, H_PRIME as u32, &top_adrs);
            let mut pk = [0u8; PK_LEN];
            pk[..N].copy_from_slice(pk_seed);
            pk[N..].copy_from_slice(&pk_root);
            let mut sk = [0u8; SK_LEN];
            sk[..N].copy_from_slice(sk_seed);
            sk[N..2 * N].copy_from_slice(sk_prf);
            sk[2 * N..3 * N].copy_from_slice(pk_seed);
            sk[3 * N..].copy_from_slice(&pk_root);
            (pk, sk)
        }

        /// Sign a message (FIPS 205 §9.2 Algorithm 22), deterministic mode.
        pub fn sign(sk: &[u8], message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_sign)?;
            let sk_arr: &[u8; SK_LEN] = sk.try_into().map_err(|_| Error::InvalidInput)?;
            let prefix = build_external_prefix(ctx)?;
            Ok(sign_with_prefix(sk_arr, prefix.as_slice(), message))
        }

        /// Gate-free signing for CAVP/ACVP harnesses (FIPS 205 §9.1 Algorithm 19).
        #[doc(hidden)]
        pub fn sign_internal(sk: &[u8; SK_LEN], message: &[u8]) -> [u8; SIG_LEN] {
            sign_with_prefix(sk, &[], message)
        }

        fn sign_with_prefix(sk: &[u8; SK_LEN], m_prefix: &[u8], message: &[u8]) -> [u8; SIG_LEN] {
            let sk_seed: &[u8; N] = sk[..N].try_into().unwrap();
            let sk_prf: &[u8; N] = sk[N..2 * N].try_into().unwrap();
            let pk_seed: &[u8; N] = sk[2 * N..3 * N].try_into().unwrap();
            let pk_root: &[u8; N] = sk[3 * N..4 * N].try_into().unwrap();
            let mut sig = [0u8; SIG_LEN];
            let opt_rand = pk_seed;
            let r = prf_msg(sk_prf, opt_rand, m_prefix, message);
            sig[..N].copy_from_slice(&r);
            let h_out = h_msg(&r, pk_seed, pk_root, m_prefix, message);
            let mut fors_adrs = Adrs::zero();
            fors_adrs.set_layer_address(0);
            fors_adrs.set_tree_address(h_out.tree_idx);
            fors_adrs.set_type(AdrsType::ForsTree);
            fors_adrs.set_keypair_address(h_out.leaf_idx);
            let fors_sig = fors_sign(pk_seed, sk_seed, &h_out.md, &fors_adrs);
            sig[N..N + FORS_SIG_LEN].copy_from_slice(&fors_sig);
            let fors_pk = fors_pk_from_sig(pk_seed, &h_out.md, &fors_sig, &fors_adrs);
            let ht_sig = ht_sign(pk_seed, sk_seed, &fors_pk, h_out.tree_idx, h_out.leaf_idx);
            sig[N + FORS_SIG_LEN..].copy_from_slice(&ht_sig);
            sig
        }

        /// Verify a signature (FIPS 205 §9.3 Algorithm 24).
        pub fn verify(
            pk: &[u8],
            message: &[u8],
            ctx: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_verify)?;
            let pk_arr: &[u8; PK_LEN] = pk.try_into().map_err(|_| Error::InvalidInput)?;
            let sig_arr: &[u8; SIG_LEN] = signature.try_into().map_err(|_| Error::InvalidInput)?;
            let prefix = build_external_prefix(ctx)?;
            if verify_with_prefix(pk_arr, prefix.as_slice(), message, sig_arr) {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        /// Gate-free verification for CAVP/ACVP harnesses (FIPS 205 §9.1 Algorithm 20).
        #[doc(hidden)]
        pub fn verify_internal(pk: &[u8; PK_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
            verify_with_prefix(pk, &[], message, sig)
        }

        fn verify_with_prefix(
            pk: &[u8; PK_LEN],
            m_prefix: &[u8],
            message: &[u8],
            sig: &[u8; SIG_LEN],
        ) -> bool {
            let pk_seed: &[u8; N] = pk[..N].try_into().unwrap();
            let pk_root: &[u8; N] = pk[N..2 * N].try_into().unwrap();
            let r: &[u8; N] = sig[..N].try_into().unwrap();
            let h_out = h_msg(r, pk_seed, pk_root, m_prefix, message);
            let mut fors_adrs = Adrs::zero();
            fors_adrs.set_layer_address(0);
            fors_adrs.set_tree_address(h_out.tree_idx);
            fors_adrs.set_type(AdrsType::ForsTree);
            fors_adrs.set_keypair_address(h_out.leaf_idx);
            let fors_sig = &sig[N..N + FORS_SIG_LEN];
            let fors_pk = fors_pk_from_sig(pk_seed, &h_out.md, fors_sig, &fors_adrs);
            let ht_sig = &sig[N + FORS_SIG_LEN..];
            ht_verify(
                pk_seed,
                pk_root,
                &fors_pk,
                ht_sig,
                h_out.tree_idx,
                h_out.leaf_idx,
            )
        }

        // ── Power-up self-test (KAT) ────────────────────────────────────

        /// Power-up KAT entries.
        pub const KATS: &[KatEntry] = &[KatEntry {
            name: $kat_name,
            run: self_test,
        }];

        fn self_test() -> Result<(), oxicrypt_module::SelfTestFailure> {
            let offset: u8 = $kat_seed_offset;
            let mut xi = [0u8; 3 * N];
            for (i, b) in xi.iter_mut().enumerate() {
                *b = ((i & 0xFF) as u8)
                    .wrapping_mul(37)
                    .wrapping_add(7)
                    .wrapping_add(offset);
            }
            let (pk, sk) = keygen_internal(&xi);
            let msg = $kat_msg;
            let sig = sign_internal(&sk, msg);
            if !verify_internal(&pk, msg, &sig) {
                return Err(oxicrypt_module::SelfTestFailure);
            }
            let bad_msg = b"tampered message";
            if verify_internal(&pk, bad_msg, &sig) {
                return Err(oxicrypt_module::SelfTestFailure);
            }
            Ok(())
        }

        #[cfg(test)]
        #[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
        mod tests {
            use super::*;

            fn deterministic_seed() -> [u8; 3 * N] {
                let offset: u8 = $kat_seed_offset;
                let mut xi = [0u8; 3 * N];
                for (i, b) in xi.iter_mut().enumerate() {
                    *b = ((i & 0xFF) as u8)
                        .wrapping_mul(37)
                        .wrapping_add(7)
                        .wrapping_add(offset);
                }
                xi
            }

            #[test]
            fn round_trip() {
                let xi = deterministic_seed();
                let (pk, sk) = keygen_internal(&xi);
                assert_eq!(pk.len(), PK_LEN);
                assert_eq!(sk.len(), SK_LEN);
                let msg = b"variant round-trip test";
                let sig = sign_internal(&sk, msg);
                assert_eq!(sig.len(), SIG_LEN);
                assert!(verify_internal(&pk, msg, &sig));
                assert!(!verify_internal(&pk, b"wrong", &sig));
            }

            #[test]
            fn different_messages() {
                let xi = deterministic_seed();
                let (_pk, sk) = keygen_internal(&xi);
                let sig1 = sign_internal(&sk, b"message A");
                let sig2 = sign_internal(&sk, b"message B");
                assert_ne!(sig1[..N], sig2[..N]);
            }

            #[test]
            fn kat_passes() {
                self_test().expect("KAT failed");
            }
        }
    };
}

pub(crate) use slh_dsa_impl;
