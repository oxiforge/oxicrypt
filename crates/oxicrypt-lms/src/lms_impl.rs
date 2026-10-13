//! Declarative macro `lms_impl!` generating an LMS / LM-OTS
//! signature verifier for one parameter set from one parameter tuple.
//!
//! The macro is the single source of truth for every (LMS, LM-OTS)
//! pair in the SP 800-208 grid — verification, the LM-OTS public-key
//! candidate computation from RFC 8554 §4.6, and the Merkle
//! authentication-path walk from RFC 8554 §5.4.
//!
//! # Macro shape (single-layer, `:expr` for numerics, `:path` for types)
//!
//! This macro avoids the audit-prone pattern of nested sub-macros that
//! dispatch on `:literal` arms (the SLH-DSA `__sha2_long_setup!(16)`
//! shape, whose hygiene hazard `slh_dsa_sha2_128f::variant_tests` pins).
//! Family-and-`N` divergence is realised by a hash-adapter `:path`
//! captured in `$hasher` — every per-family branch lives in
//! [`crate::hash`], one concrete adapter per (family, N) shape, and the
//! macro body simply calls `<$hasher>::new_internal()`. There is no
//! `__hash_setup!(N)` sub-macro and no inner `(N) =>` arm.
//!
//! # Inputs
//!
//! | Field        | Type    | Source                              |
//! |--------------|---------|-------------------------------------|
//! | `hasher`     | `:path` | Adapter from [`crate::hash`]        |
//! | `n`          | `:expr` | Digest output length (24 or 32)     |
//! | `h`          | `:expr` | Tree height (5, 10, 15, 20, 25)     |
//! | `w`          | `:expr` | Winternitz parameter (1, 2, 4, 8)   |
//! | `u`          | `:expr` | `⌈8·N/W⌉` — message-digit count     |
//! | `v`          | `:expr` | `⌈(⌊lg((2^W-1)·U)⌋ + 1) / W⌉`       |
//! | `p`          | `:expr` | `U + V` — total chains              |
//! | `ls`         | `:expr` | `16 - V·W` — checksum left-shift    |
//! | `lms_type`   | `:expr` | Typecode (SP 800-208 §4)            |
//! | `lmots_type` | `:expr` | Typecode (SP 800-208 §4)            |
//! | `svc_verify` | `:path` | `Service::…Verify` discriminant     |
//!
//! No `:literal` captures. No nested macros. No inner `(N) =>` arms.
//!
//! # Emitted items (per instantiation)
//!
//! | Item                                         | Visibility |
//! |----------------------------------------------|------------|
//! | `N`, `H`, `W`, `U`, `V`, `P`, `LS`           | `pub const`|
//! | `LMS_TYPE`, `LMOTS_TYPE`                     | `pub const`|
//! | `MAX_SIGNATURES`, `OTS_SIG_LEN`, `SIGNATURE_LEN`, `PUBLIC_KEY_LEN` | `pub const` |
//! | `verify`                                     | `pub`      |
//! | `verify_internal`                            | `pub` (doc-hidden) |

/// See module-level docs for the full input table and emitted item list.
macro_rules! lms_impl {
    (
        hasher = $hasher:path;
        n = $n:expr;
        h = $h:expr;
        w = $w:expr;
        u = $u:expr;
        v = $v:expr;
        p = $p:expr;
        ls = $ls:expr;
        lms_type = $lms_type:expr;
        lmots_type = $lmots_type:expr;
        svc_verify = $svc_verify:path;
    ) => {
        use oxicrypt_module::Error;

        // ── Parameter constants ────────────────────────────────────

        /// Hash output length (bytes).
        pub const N: usize = $n;
        /// Tree height.
        pub const H: usize = $h;
        /// Winternitz parameter.
        pub const W: u32 = $w;
        /// Message-digit count: `⌈8·N/W⌉`.
        pub const U: usize = $u;
        /// Checksum-digit count.
        pub const V: usize = $v;
        /// Total hash chains: `U + V`.
        pub const P: usize = $p;
        /// Checksum left-shift: `16 - V·W`.
        pub const LS: u32 = $ls;
        /// LMS typecode (SP 800-208 §4, IANA-assigned).
        pub const LMS_TYPE: u32 = $lms_type;
        /// LM-OTS typecode (SP 800-208 §4, IANA-assigned).
        pub const LMOTS_TYPE: u32 = $lmots_type;

        /// Maximum chain steps: `2^W - 1`.
        ///
        /// `W ∈ {1, 2, 4, 8}` per the SP 800-208 grid, so `(1 << W) - 1`
        /// is at most 255 — the `u8` cast is bounded by construction.
        #[allow(clippy::cast_possible_truncation)]
        const MAX_CHAIN: u8 = ((1u32 << W) - 1) as u8;
        /// Diversifier for public key generation (RFC 8554 §4.3).
        const D_PBLC: u16 = 0x8080;
        /// Diversifier for message hashing (RFC 8554 §4.5).
        const D_MESG: u16 = 0x8181;
        /// Diversifier for leaf node hashing (RFC 8554 §5.3).
        const D_LEAF: u16 = 0x8282;
        /// Diversifier for internal node hashing (RFC 8554 §5.3).
        const D_INTR: u16 = 0x8383;

        /// Number of leaves, `2^H`: the bound on the leaf index `q` a
        /// signature carries. Verification rejects any `q` at or above it.
        pub const MAX_SIGNATURES: u32 = 1u32 << H;
        /// LM-OTS signature length: `4 + N + P·N`.
        pub const OTS_SIG_LEN: usize = 4 + N + P * N;
        /// LMS signature length: `4 + OTS_SIG_LEN + 4 + H·N`.
        pub const SIGNATURE_LEN: usize = 4 + OTS_SIG_LEN + 4 + H * N;
        /// LMS public key length: `4 + 4 + 16 + N`.
        pub const PUBLIC_KEY_LEN: usize = 4 + 4 + 16 + N;

        // ── LM-OTS internals (RFC 8554 §4) ─────────────────────────

        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::integer_division,
            clippy::cast_possible_truncation,
            clippy::needless_range_loop
        )]
        mod lmots_internals {
            use super::*;

            /// Extract the `i`-th `W`-bit digit from byte string `s`,
            /// big-endian per RFC 8554 §3.1.3.
            pub(super) fn coef(s: &[u8], i: usize) -> u8 {
                let bits_per_byte: usize = 8;
                let w = W as usize;
                let bit_pos = i * w;
                let byte_idx = bit_pos / bits_per_byte;
                let shift = bits_per_byte - w - (bit_pos % bits_per_byte);
                (s[byte_idx] >> shift) & (MAX_CHAIN)
            }

            /// LM-OTS checksum over message hash `q_hash`.
            ///
            /// `Cksm(Q) = sum_{i=0}^{u-1} ((2^w - 1) - coef(Q, i, w))`.
            pub(super) fn checksum(q_hash: &[u8; N]) -> u16 {
                let mut sum: u32 = 0;
                for i in 0..U {
                    sum += u32::from(MAX_CHAIN) - u32::from(coef(q_hash, i));
                }
                sum as u16
            }

            /// Extract the `i`-th digit from the concatenation
            /// `Q || u16str(Cksm(Q) << ls)`.
            pub(super) fn coef_q_cksm(q_hash: &[u8; N], i: usize) -> u8 {
                if i < U {
                    coef(q_hash, i)
                } else {
                    let cksm = checksum(q_hash);
                    let cksm_bytes = (cksm << LS).to_be_bytes();
                    coef(&cksm_bytes, i - U)
                }
            }

            /// One step of the hash chain.
            pub(super) fn chain_step(
                i_val: &[u8; 16],
                q: u32,
                chain_idx: u16,
                j: u8,
                tmp: &[u8; N],
            ) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&q.to_be_bytes());
                h.update(&chain_idx.to_be_bytes());
                h.update(&[j]);
                h.update(tmp);
                h.finalize()
            }

            /// Iterate `count` chain steps starting at `start_j`.
            pub(super) fn chain(
                i_val: &[u8; 16],
                q: u32,
                chain_idx: u16,
                start_j: u8,
                count: u8,
                start_val: &[u8; N],
            ) -> [u8; N] {
                let mut tmp = *start_val;
                for step in 0..count {
                    tmp = chain_step(i_val, q, chain_idx, start_j + step, &tmp);
                }
                tmp
            }

            /// Message hash: `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)`.
            pub(super) fn compute_q(
                i_val: &[u8; 16],
                q: u32,
                c: &[u8; N],
                message: &[u8],
            ) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&q.to_be_bytes());
                h.update(&D_MESG.to_be_bytes());
                h.update(c);
                h.update(message);
                h.finalize()
            }

            /// Recompute the OTS public-key candidate `Kc` from a signature
            /// (RFC 8554 §4.6 Algorithm 4b). `None` on parse-format failure.
            pub(super) fn ots_verify_candidate(
                i_val: &[u8; 16],
                q: u32,
                message: &[u8],
                ots_sig: &[u8],
            ) -> Option<[u8; N]> {
                if ots_sig.len() != OTS_SIG_LEN {
                    return None;
                }

                let sig_type = u32::from_be_bytes([ots_sig[0], ots_sig[1], ots_sig[2], ots_sig[3]]);
                if sig_type != LMOTS_TYPE {
                    return None;
                }

                let mut c = [0u8; N];
                c.copy_from_slice(&ots_sig[4..4 + N]);

                let q_hash = compute_q(i_val, q, &c, message);

                let mut kc = <$hasher>::new_internal();
                kc.update(i_val);
                kc.update(&q.to_be_bytes());
                kc.update(&D_PBLC.to_be_bytes());

                for i in 0..P {
                    let a = coef_q_cksm(&q_hash, i);
                    let remaining = MAX_CHAIN - a;
                    let off = 4 + N + i * N;
                    let mut y_i = [0u8; N];
                    y_i.copy_from_slice(&ots_sig[off..off + N]);
                    let z_i = chain(i_val, q, i as u16, a, remaining, &y_i);
                    kc.update(&z_i);
                }

                Some(kc.finalize())
            }
        }

        // ── Merkle tree (RFC 8554 §5) ──────────────────────────────

        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::integer_division,
            clippy::cast_possible_truncation
        )]
        mod tree_internals {
            use super::*;

            /// Leaf hash: `H(I || u32str(r) || u16str(D_LEAF) || Kc)`.
            pub(super) fn hash_leaf(i_val: &[u8; 16], r: u32, kc: &[u8; N]) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&r.to_be_bytes());
                h.update(&D_LEAF.to_be_bytes());
                h.update(kc);
                h.finalize()
            }

            /// Internal-node hash: `H(I || u32str(r) || u16str(D_INTR) || left || right)`.
            pub(super) fn hash_internal(
                i_val: &[u8; 16],
                r: u32,
                left: &[u8; N],
                right: &[u8; N],
            ) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&r.to_be_bytes());
                h.update(&D_INTR.to_be_bytes());
                h.update(left);
                h.update(right);
                h.finalize()
            }

            /// Walk the authentication path from a candidate leaf hash
            /// up to the root (RFC 8554 §5.4).
            pub(super) fn walk_auth_path(
                i_val: &[u8; 16],
                candidate_k: &[u8; N],
                q: u32,
                auth: &[[u8; N]; H],
            ) -> [u8; N] {
                let mut node_idx = MAX_SIGNATURES + q;
                let mut tmp = hash_leaf(i_val, node_idx, candidate_k);
                for sibling in auth {
                    let parent = node_idx >> 1;
                    if node_idx & 1 == 0 {
                        tmp = hash_internal(i_val, parent, &tmp, sibling);
                    } else {
                        tmp = hash_internal(i_val, parent, sibling, &tmp);
                    }
                    node_idx = parent;
                }
                tmp
            }
        }

        // ── Verification ───────────────────────────────────────────

        /// Verify an LMS signature.
        ///
        /// # Errors
        ///
        /// [`Error::InvalidInput`] when the signature does not verify:
        /// a malformed public key or signature (a typecode that is not this
        /// pair's, or a leaf index `q` at or above [`MAX_SIGNATURES`]) as
        /// well as a signature that fails to match;
        /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
        /// from the module gate.
        pub fn verify(
            public_key: &[u8; PUBLIC_KEY_LEN],
            message: &[u8],
            signature: &[u8; SIGNATURE_LEN],
        ) -> ::core::result::Result<(), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_verify)?;
            if verify_internal(public_key, message, signature) {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        }

        /// Gate-free verify — returns the boolean outcome directly.
        ///
        /// `false` covers a malformed public key or signature (a typecode
        /// that is not this pair's, or a leaf index `q` at or above
        /// [`MAX_SIGNATURES`]) as well as a signature that fails to match.
        #[doc(hidden)]
        pub fn verify_internal(
            public_key: &[u8; PUBLIC_KEY_LEN],
            message: &[u8],
            signature: &[u8; SIGNATURE_LEN],
        ) -> bool {
            #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

            let pk_lms_type =
                u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
            if pk_lms_type != LMS_TYPE {
                return false;
            }
            let pk_ots_type =
                u32::from_be_bytes([public_key[4], public_key[5], public_key[6], public_key[7]]);
            if pk_ots_type != LMOTS_TYPE {
                return false;
            }
            let mut i_val = [0u8; 16];
            i_val.copy_from_slice(&public_key[8..24]);
            let mut expected_root = [0u8; N];
            expected_root.copy_from_slice(&public_key[24..24 + N]);

            let q = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
            if q >= MAX_SIGNATURES {
                return false;
            }

            let ots_sig = &signature[4..4 + OTS_SIG_LEN];

            let sig_lms_type = u32::from_be_bytes([
                signature[4 + OTS_SIG_LEN],
                signature[4 + OTS_SIG_LEN + 1],
                signature[4 + OTS_SIG_LEN + 2],
                signature[4 + OTS_SIG_LEN + 3],
            ]);
            if sig_lms_type != LMS_TYPE {
                return false;
            }

            let auth_start = 4 + OTS_SIG_LEN + 4;
            let mut auth = [[0u8; N]; H];
            for (level, slot) in auth.iter_mut().enumerate() {
                let off = auth_start + level * N;
                slot.copy_from_slice(&signature[off..off + N]);
            }

            let Some(candidate_k) =
                lmots_internals::ots_verify_candidate(&i_val, q, message, ots_sig)
            else {
                return false;
            };

            let computed_root = tree_internals::walk_auth_path(&i_val, &candidate_k, q, &auth);

            let mut diff = 0u8;
            for i in 0..N {
                diff |= computed_root[i] ^ expected_root[i];
            }
            diff == 0
        }
    };
}

pub(crate) use lms_impl;
