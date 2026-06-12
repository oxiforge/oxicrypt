//! Declarative macro `lms_impl!` generating a full LMS / LM-OTS
//! parameter-set implementation from one parameter tuple.
//!
//! The macro is the single source of truth for every (LMS, LM-OTS)
//! pair in the SP 800-208 grid — keygen, sign, verify, the LM-OTS
//! one-time-signature internals from RFC 8554 §4, the Merkle-tree
//! traversal from RFC 8554 §5, and the power-up KAT.
//!
//! # Macro shape (single-layer, `:expr` for numerics, `:path` for types)
//!
//! Per [[feedback_macro_audit_triage_rule]], this macro avoids the
//! audit-prone pattern of nested sub-macros that dispatch on `:literal`
//! arms (the SLH-DSA `__sha2_long_setup!(16)` shape that produced the
//! literal-hygiene incident captured in `slh_dsa_sha2_128f::variant_tests`).
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
//! | `lms_type`   | `:expr` | IANA typecode (RFC 8554 §A / 8708)  |
//! | `lmots_type` | `:expr` | IANA typecode (RFC 8554 §A / 8708)  |
//! | `svc_sign`   | `:path` | `Service::…Sign` discriminant       |
//! | `svc_verify` | `:path` | `Service::…Verify` discriminant     |
//! | `kat_xi`     | `:expr` | 32-byte KAT seed                    |
//! | `kat_msg`    | `:expr` | KAT message bytes                   |
//! | `kat_name`   | `:expr` | KAT name string (rustdoc / logs)    |
//!
//! No `:literal` captures. No nested macros. No inner `(N) =>` arms.
//!
//! # Emitted items (per instantiation)
//!
//! | Item                                         | Visibility |
//! |----------------------------------------------|------------|
//! | `N`, `H`, `W`, `U`, `V`, `P`, `LS`           | `pub const`|
//! | `LMS_TYPE`, `LMOTS_TYPE`                     | `pub const`|
//! | `MAX_SIGNATURES`, `OTS_SIG_LEN`, `SIGNATURE_LEN`, `PUBLIC_KEY_LEN`, `PRIVATE_KEY_LEN` | `pub const` |
//! | `LmsPrivateKey`                              | `pub`      |
//! | `LmsSigningKey` (feature `alloc`)            | `pub`      |
//! | `keygen`, `sign`, `verify`                   | `pub`      |
//! | `keygen_internal`, `keygen_from_parts`, `sign_internal`, `verify_internal` | `pub` (doc-hidden) |
//! | `KATS`, `self_test`                          | `pub`, private |

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
        svc_sign = $svc_sign:path;
        svc_verify = $svc_verify:path;
        kat_xi = $kat_xi:expr;
        kat_msg = $kat_msg:expr;
        kat_name = $kat_name:expr;
    ) => {
        use oxicrypt_module::{Error, KatEntry, SelfTestFailure};

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
        /// LMS typecode (RFC 8554 §A / RFC 8708, IANA-assigned).
        pub const LMS_TYPE: u32 = $lms_type;
        /// LM-OTS typecode (RFC 8554 §A / RFC 8708, IANA-assigned).
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
        /// Deterministic randomizer diversifier (RFC 8554 §4.5).
        const D_C: u16 = 0xFFFD;

        /// Number of leaves: `2^H`.
        pub const MAX_SIGNATURES: u32 = 1u32 << H;
        /// LM-OTS signature length: `4 + N + P·N`.
        pub const OTS_SIG_LEN: usize = 4 + N + P * N;
        /// LMS signature length: `4 + OTS_SIG_LEN + 4 + H·N`.
        pub const SIGNATURE_LEN: usize = 4 + OTS_SIG_LEN + 4 + H * N;
        /// LMS public key length: `4 + 4 + 16 + N`.
        pub const PUBLIC_KEY_LEN: usize = 4 + 4 + 16 + N;
        /// LMS private-key serialized length: `N + 16 + 4`.
        pub const PRIVATE_KEY_LEN: usize = N + 16 + 4;

        // ── Private key ────────────────────────────────────────────

        /// LMS private key with stateful leaf counter.
        ///
        /// The caller must persist the key (including the updated
        /// `leaf_index`) after every call to [`sign`] / [`sign_internal`]
        /// — failure to persist before a crash can lead to one-time-key
        /// reuse, which is a catastrophic security failure for any
        /// stateful hash-based signature scheme.
        pub struct LmsPrivateKey {
            seed: [u8; N],
            identifier: [u8; 16],
            leaf_index: u32,
        }

        impl Drop for LmsPrivateKey {
            fn drop(&mut self) {
                oxicrypt_zeroize::zeroize(&mut self.seed);
                oxicrypt_zeroize::zeroize(&mut self.identifier);
            }
        }

        impl LmsPrivateKey {
            /// Number of signatures issued so far (= index of next unused leaf).
            pub fn leaf_index(&self) -> u32 {
                self.leaf_index
            }

            /// `true` once every leaf has been consumed.
            pub fn is_exhausted(&self) -> bool {
                self.leaf_index >= MAX_SIGNATURES
            }

            /// Serialize the private key to bytes for persistence.
            ///
            /// Layout: `seed(N) || I(16) || leaf_index(4)` = `PRIVATE_KEY_LEN` bytes.
            pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_LEN] {
                #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
                let mut out = [0u8; PRIVATE_KEY_LEN];
                out[..N].copy_from_slice(&self.seed);
                out[N..N + 16].copy_from_slice(&self.identifier);
                out[N + 16..N + 20].copy_from_slice(&self.leaf_index.to_be_bytes());
                out
            }

            /// Deserialize a private key. Returns `None` on wrong length.
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
                if bytes.len() != PRIVATE_KEY_LEN {
                    return None;
                }
                let mut seed = [0u8; N];
                seed.copy_from_slice(&bytes[..N]);
                let mut identifier = [0u8; 16];
                identifier.copy_from_slice(&bytes[N..N + 16]);
                let leaf_index = u32::from_be_bytes([
                    bytes[N + 16],
                    bytes[N + 17],
                    bytes[N + 18],
                    bytes[N + 19],
                ]);
                Some(Self {
                    seed,
                    identifier,
                    leaf_index,
                })
            }
        }

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

            /// Derive `x_q[chain_idx] = H(I || u32str(q) || u16str(i) || 0xff || SEED)`.
            pub(super) fn derive_x(
                seed: &[u8; N],
                i_val: &[u8; 16],
                q: u32,
                chain_idx: u16,
            ) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&q.to_be_bytes());
                h.update(&chain_idx.to_be_bytes());
                h.update(&[0xff]);
                h.update(seed);
                h.finalize()
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

            /// Deterministic randomizer: `C = H(I || u32str(q) || u16str(0xFFFD) || SEED || message)`.
            pub(super) fn compute_c(
                seed: &[u8; N],
                i_val: &[u8; 16],
                q: u32,
                message: &[u8],
            ) -> [u8; N] {
                let mut h = <$hasher>::new_internal();
                h.update(i_val);
                h.update(&q.to_be_bytes());
                h.update(&D_C.to_be_bytes());
                h.update(seed);
                h.update(message);
                h.finalize()
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

            /// Compute the LM-OTS public-key hash `K` for leaf `q` (RFC 8554 §4.3 Algorithm 1).
            pub(super) fn compute_public_key(seed: &[u8; N], i_val: &[u8; 16], q: u32) -> [u8; N] {
                let mut kc = <$hasher>::new_internal();
                kc.update(i_val);
                kc.update(&q.to_be_bytes());
                kc.update(&D_PBLC.to_be_bytes());

                for i in 0..P {
                    let x_i = derive_x(seed, i_val, q, i as u16);
                    let y_i = chain(i_val, q, i as u16, 0, MAX_CHAIN, &x_i);
                    kc.update(&y_i);
                }
                kc.finalize()
            }

            /// Sign `message` for leaf `q` (RFC 8554 §4.5 Algorithm 3).
            pub(super) fn ots_sign(
                seed: &[u8; N],
                i_val: &[u8; 16],
                q: u32,
                message: &[u8],
            ) -> [u8; OTS_SIG_LEN] {
                let c = compute_c(seed, i_val, q, message);
                let q_hash = compute_q(i_val, q, &c, message);

                let mut sig = [0u8; OTS_SIG_LEN];
                sig[..4].copy_from_slice(&LMOTS_TYPE.to_be_bytes());
                sig[4..4 + N].copy_from_slice(&c);
                for i in 0..P {
                    let a = coef_q_cksm(&q_hash, i);
                    let x_i = derive_x(seed, i_val, q, i as u16);
                    let y_i = chain(i_val, q, i as u16, 0, a, &x_i);
                    let off = 4 + N + i * N;
                    sig[off..off + N].copy_from_slice(&y_i);
                }
                sig
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

            /// Compute the hash of tree node `node_idx`.
            ///
            /// Indexing per RFC 8554: root = 1, children of `r` are
            /// `2r` (left) and `2r + 1` (right), leaves at indices
            /// `MAX_SIGNATURES .. 2·MAX_SIGNATURES`. Maximum recursion
            /// depth is `H`; each frame is small (a `[u8; N]` pair plus
            /// locals).
            pub(super) fn compute_node(seed: &[u8; N], i_val: &[u8; 16], node_idx: u32) -> [u8; N] {
                if node_idx >= MAX_SIGNATURES {
                    let q = node_idx - MAX_SIGNATURES;
                    let k = super::lmots_internals::compute_public_key(seed, i_val, q);
                    hash_leaf(i_val, node_idx, &k)
                } else {
                    let left = compute_node(seed, i_val, node_idx * 2);
                    let right = compute_node(seed, i_val, node_idx * 2 + 1);
                    hash_internal(i_val, node_idx, &left, &right)
                }
            }

            /// Compute the Merkle root `T[1]`.
            pub(super) fn compute_root(seed: &[u8; N], i_val: &[u8; 16]) -> [u8; N] {
                compute_node(seed, i_val, 1)
            }

            /// Compute the authentication path for leaf `q`.
            pub(super) fn compute_auth_path(
                seed: &[u8; N],
                i_val: &[u8; 16],
                q: u32,
            ) -> [[u8; N]; H] {
                let mut path = [[0u8; N]; H];
                let mut node = MAX_SIGNATURES + q;
                for slot in &mut path {
                    let sibling = node ^ 1;
                    *slot = compute_node(seed, i_val, sibling);
                    node >>= 1;
                }
                path
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

        // ── Key generation ─────────────────────────────────────────

        /// Generate an LMS key pair from a 32-byte seed `xi`.
        ///
        /// Tree seed and identifier are deterministically derived as
        /// `SEED = H(xi || 0x00)` and `I = H(xi || 0x01)[..16]` using
        /// the per-pair hasher.
        ///
        /// # Errors
        ///
        /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
        /// when the module gate denies the service.
        pub fn keygen(
            xi: &[u8; 32],
        ) -> ::core::result::Result<(LmsPrivateKey, [u8; PUBLIC_KEY_LEN]), Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_sign)?;
            Ok(keygen_internal(xi))
        }

        /// Derive the private seed and 16-byte identifier `I` from the
        /// 32-byte input `xi` — the domain-separated construction shared
        /// by `keygen_internal` and the cached `LmsSigningKey` path.
        fn derive_seed_identifier(xi: &[u8; 32]) -> ([u8; N], [u8; 16]) {
            #![allow(clippy::indexing_slicing)]

            let mut h = <$hasher>::new_internal();
            h.update(xi);
            h.update(&[0x00]);
            let seed = h.finalize();

            let mut h = <$hasher>::new_internal();
            h.update(xi);
            h.update(&[0x01]);
            let i_full = h.finalize();
            let mut identifier = [0u8; 16];
            identifier.copy_from_slice(&i_full[..16]);
            (seed, identifier)
        }

        /// Gate-free keygen — for self-tests and ACVP harness use.
        #[doc(hidden)]
        pub fn keygen_internal(xi: &[u8; 32]) -> (LmsPrivateKey, [u8; PUBLIC_KEY_LEN]) {
            #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

            let (seed, identifier) = derive_seed_identifier(xi);

            let root = tree_internals::compute_root(&seed, &identifier);

            let mut pk = [0u8; PUBLIC_KEY_LEN];
            pk[..4].copy_from_slice(&LMS_TYPE.to_be_bytes());
            pk[4..8].copy_from_slice(&LMOTS_TYPE.to_be_bytes());
            pk[8..24].copy_from_slice(&identifier);
            pk[24..24 + N].copy_from_slice(&root);

            let sk = LmsPrivateKey {
                seed,
                identifier,
                leaf_index: 0,
            };
            (sk, pk)
        }

        /// Gate-free keygen from explicit `(seed, I)` — for ACVP keyGen,
        /// which supplies both fields directly rather than via `xi`.
        #[doc(hidden)]
        pub fn keygen_from_parts(
            seed: &[u8; N],
            identifier: &[u8; 16],
        ) -> (LmsPrivateKey, [u8; PUBLIC_KEY_LEN]) {
            #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

            let root = tree_internals::compute_root(seed, identifier);

            let mut pk = [0u8; PUBLIC_KEY_LEN];
            pk[..4].copy_from_slice(&LMS_TYPE.to_be_bytes());
            pk[4..8].copy_from_slice(&LMOTS_TYPE.to_be_bytes());
            pk[8..24].copy_from_slice(identifier);
            pk[24..24 + N].copy_from_slice(&root);

            let sk = LmsPrivateKey {
                seed: *seed,
                identifier: *identifier,
                leaf_index: 0,
            };
            (sk, pk)
        }

        // ── Signing ────────────────────────────────────────────────

        /// Sign `message` and advance the leaf index.
        ///
        /// # Errors
        ///
        /// [`Error::InvalidInput`] if the key is exhausted;
        /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
        /// from the module gate.
        pub fn sign(
            key: &mut LmsPrivateKey,
            message: &[u8],
        ) -> ::core::result::Result<[u8; SIGNATURE_LEN], Error> {
            oxicrypt_module::require_operational()?;
            oxicrypt_module::require_allowed($svc_sign)?;
            sign_internal(key, message).ok_or(Error::InvalidInput)
        }

        /// Gate-free sign — `None` on exhausted key.
        #[doc(hidden)]
        pub fn sign_internal(
            key: &mut LmsPrivateKey,
            message: &[u8],
        ) -> Option<[u8; SIGNATURE_LEN]> {
            #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

            if key.is_exhausted() {
                return None;
            }

            let q = key.leaf_index;
            let ots_sig = lmots_internals::ots_sign(&key.seed, &key.identifier, q, message);
            let auth = tree_internals::compute_auth_path(&key.seed, &key.identifier, q);

            let mut sig = [0u8; SIGNATURE_LEN];
            let mut pos = 0;
            sig[pos..pos + 4].copy_from_slice(&q.to_be_bytes());
            pos += 4;
            sig[pos..pos + OTS_SIG_LEN].copy_from_slice(&ots_sig);
            pos += OTS_SIG_LEN;
            sig[pos..pos + 4].copy_from_slice(&LMS_TYPE.to_be_bytes());
            pos += 4;
            for node in &auth {
                sig[pos..pos + N].copy_from_slice(node);
                pos += N;
            }

            key.leaf_index = q + 1;
            Some(sig)
        }

        // ── Cached signing (feature `alloc`) ───────────────────────

        /// Cached LMS signing key — the private key plus the full
        /// precomputed Merkle node table.
        ///
        /// The free [`sign`](self::sign) on the plain [`LmsPrivateKey`]
        /// recomputes the whole 2^H-leaf tree per signature; this
        /// wrapper builds the tree **once** at construction (cost ≈
        /// one keygen) and thereafter reads the H authentication-path
        /// nodes straight from the table, taking per-signature tree
        /// cost from O(2^H) to O(H). Signatures are **byte-identical**
        /// to the uncached path for the same key state and message.
        ///
        /// # Memory
        ///
        /// The table holds every tree node in RFC 8554 numbering
        /// (root = 1, leaves at `2^H .. 2^(H+1)`): `2^(H+1)` slots of
        /// N bytes (slot 0 unused) — 64 KiB at H = 10, 2 MiB at
        /// H = 15, 64 MiB at H = 20, 2 GiB at H = 25 (N = 32).
        /// Intended for desktop/server signers; requires the crate's
        /// `alloc` feature (on by default).
        ///
        /// # Security
        ///
        /// Merkle node hashes are **public** data — every node is
        /// derived from the LM-OTS public keys and is exposed in
        /// signatures (authentication paths) and the public key
        /// (root). The node table therefore carries **no zeroization
        /// requirement** and is deliberately not zeroized on drop.
        /// The wrapped [`LmsPrivateKey`] keeps its existing
        /// zeroize-on-Drop semantics for the tree seed and identifier.
        ///
        /// # Statefulness
        ///
        /// The one-leaf-per-signature contract is unchanged:
        /// [`sign`](Self::sign) advances `leaf_index` exactly as the
        /// free [`sign`](self::sign) does and refuses once the tree is
        /// exhausted.
        /// The caller must persist the underlying private-key state
        /// (via [`private_key`](Self::private_key) /
        /// [`LmsPrivateKey::to_bytes`]) after every signature —
        /// failure to persist before a crash can lead to one-time-key
        /// reuse, which is a catastrophic security failure for any
        /// stateful hash-based signature scheme.
        #[cfg(feature = "alloc")]
        pub struct LmsSigningKey {
            key: LmsPrivateKey,
            nodes: ::alloc::vec::Vec<[u8; N]>,
        }

        /// Tree-cache construction internals (feature `alloc`).
        #[cfg(feature = "alloc")]
        #[allow(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            clippy::cast_possible_truncation
        )]
        mod cached_internals {
            use super::*;

            /// Build the full Merkle node table in RFC 8554 numbering:
            /// slot 0 unused, root at 1, leaves at
            /// `MAX_SIGNATURES .. 2·MAX_SIGNATURES`. One bottom-up
            /// pass: 2^H leaf computations (the keygen-dominating
            /// cost) plus 2^H − 1 internal-node hashes.
            pub(super) fn build_node_table(
                seed: &[u8; N],
                i_val: &[u8; 16],
            ) -> ::alloc::vec::Vec<[u8; N]> {
                let total = 2 * (MAX_SIGNATURES as usize);
                let mut nodes = ::alloc::vec::Vec::with_capacity(total);
                nodes.resize(total, [0u8; N]);

                // Leaf sweep: each leaf at index `r = MAX_SIGNATURES + q`
                // is `hash_leaf(I, r, compute_public_key(seed, I, q))` — a
                // pure function of `(seed, I, q)` with no cross-leaf
                // dependency. The two builds below are byte-identical by
                // construction (R75): the parallel form is an indexed
                // disjoint-slice `par_iter_mut` writing each leaf to its
                // own slot, recombined by index, never by completion
                // order or thread count.
                #[cfg(not(feature = "parallel"))]
                for q in 0..MAX_SIGNATURES {
                    let r = MAX_SIGNATURES + q;
                    let k = super::lmots_internals::compute_public_key(seed, i_val, q);
                    nodes[r as usize] = super::tree_internals::hash_leaf(i_val, r, &k);
                }
                #[cfg(feature = "parallel")]
                {
                    use ::rayon::iter::{
                        IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
                    };
                    nodes[MAX_SIGNATURES as usize..]
                        .par_iter_mut()
                        .enumerate()
                        .for_each(|(q, slot)| {
                            let q = q as u32;
                            let r = MAX_SIGNATURES + q;
                            let k = super::lmots_internals::compute_public_key(seed, i_val, q);
                            *slot = super::tree_internals::hash_leaf(i_val, r, &k);
                        });
                }

                // Internal-node bottom-up pass — intentionally sequential
                // (each node depends on its two children); out of scope
                // for parallelization.
                for r in (1..MAX_SIGNATURES).rev() {
                    let left = nodes[(r * 2) as usize];
                    let right = nodes[(r * 2 + 1) as usize];
                    nodes[r as usize] =
                        super::tree_internals::hash_internal(i_val, r, &left, &right);
                }
                nodes
            }

            /// Sequential reference build of the Merkle node table — the
            /// always-single-threaded form, compiled regardless of the
            /// `parallel` feature. Exists only so the determinism oracle
            /// (R75) can assert the `parallel` `build_node_table` output is
            /// byte-identical to the sequential build for the same
            /// `(seed, I)`. Never on the production path. Compiled only
            /// for the `parallel`-feature determinism tests — its sole
            /// callers are those `#[cfg(feature = "parallel")]` tests.
            /// The macro emits this for all 80 pairs but only the H = 5
            /// and H = 10 baseline pairs call it, so the other expansions
            /// see it unused.
            #[cfg(all(test, feature = "parallel"))]
            #[allow(dead_code)]
            pub(super) fn build_node_table_sequential(
                seed: &[u8; N],
                i_val: &[u8; 16],
            ) -> ::alloc::vec::Vec<[u8; N]> {
                let total = 2 * (MAX_SIGNATURES as usize);
                let mut nodes = ::alloc::vec::Vec::with_capacity(total);
                nodes.resize(total, [0u8; N]);
                for q in 0..MAX_SIGNATURES {
                    let r = MAX_SIGNATURES + q;
                    let k = super::lmots_internals::compute_public_key(seed, i_val, q);
                    nodes[r as usize] = super::tree_internals::hash_leaf(i_val, r, &k);
                }
                for r in (1..MAX_SIGNATURES).rev() {
                    let left = nodes[(r * 2) as usize];
                    let right = nodes[(r * 2 + 1) as usize];
                    nodes[r as usize] =
                        super::tree_internals::hash_internal(i_val, r, &left, &right);
                }
                nodes
            }
        }

        #[cfg(feature = "alloc")]
        impl LmsSigningKey {
            /// Generate a fresh key pair and build the Merkle node
            /// table (cost ≈ one [`keygen`]). Returns the cached
            /// signing key and the public key.
            ///
            /// # Errors
            ///
            /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
            /// when the module gate denies the service.
            pub fn new(
                xi: &[u8; 32],
            ) -> ::core::result::Result<(Self, [u8; PUBLIC_KEY_LEN]), Error> {
                oxicrypt_module::require_operational()?;
                oxicrypt_module::require_allowed($svc_sign)?;
                Ok(Self::new_internal(xi))
            }

            /// Gate-free constructor — for self-tests and harness use.
            ///
            /// Builds the Merkle node table once and assembles the public
            /// key from its cached root (`nodes[1]`) instead of walking
            /// the full tree a second time through `compute_root`. The
            /// table is proven byte-identical to the recursive walk by
            /// the cached-vs-uncached determinism oracle, so the public
            /// key is unchanged — at half the construction cost, with the
            /// tree build on the (feature-gated) parallel leaf sweep.
            #[doc(hidden)]
            pub fn new_internal(xi: &[u8; 32]) -> (Self, [u8; PUBLIC_KEY_LEN]) {
                let (seed, identifier) = derive_seed_identifier(xi);
                let key = LmsPrivateKey {
                    seed,
                    identifier,
                    leaf_index: 0,
                };
                let nodes = cached_internals::build_node_table(&key.seed, &key.identifier);
                let signing_key = Self { key, nodes };
                let pk = signing_key.public_key();
                (signing_key, pk)
            }

            /// Wrap an existing private key (e.g. one resumed from
            /// persisted state via [`LmsPrivateKey::from_bytes`]),
            /// rebuilding the Merkle node table from its seed (cost ≈
            /// one [`keygen`]). The key's current `leaf_index` is
            /// preserved.
            ///
            /// # Errors
            ///
            /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
            /// when the module gate denies the service.
            pub fn from_private_key(key: LmsPrivateKey) -> ::core::result::Result<Self, Error> {
                oxicrypt_module::require_operational()?;
                oxicrypt_module::require_allowed($svc_sign)?;
                Ok(Self::from_private_key_internal(key))
            }

            /// Gate-free [`Self::from_private_key`].
            #[doc(hidden)]
            pub fn from_private_key_internal(key: LmsPrivateKey) -> Self {
                let nodes = cached_internals::build_node_table(&key.seed, &key.identifier);
                Self { key, nodes }
            }

            /// Sign `message` and advance the leaf index, reading the
            /// authentication path from the cached node table. Output
            /// is byte-identical to the free [`sign`](self::sign) for
            /// the same key state and message.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidInput`] if the key is exhausted;
            /// [`Error::NotOperational`] / [`Error::AlgorithmRestricted`]
            /// from the module gate.
            pub fn sign(
                &mut self,
                message: &[u8],
            ) -> ::core::result::Result<[u8; SIGNATURE_LEN], Error> {
                oxicrypt_module::require_operational()?;
                oxicrypt_module::require_allowed($svc_sign)?;
                self.sign_internal(message).ok_or(Error::InvalidInput)
            }

            /// Gate-free cached sign — `None` on exhausted key.
            #[doc(hidden)]
            pub fn sign_internal(&mut self, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
                #![allow(
                    clippy::indexing_slicing,
                    clippy::arithmetic_side_effects,
                    clippy::cast_possible_truncation
                )]

                if self.key.is_exhausted() {
                    return None;
                }

                let q = self.key.leaf_index;
                let ots_sig =
                    lmots_internals::ots_sign(&self.key.seed, &self.key.identifier, q, message);

                let mut sig = [0u8; SIGNATURE_LEN];
                let mut pos = 0;
                sig[pos..pos + 4].copy_from_slice(&q.to_be_bytes());
                pos += 4;
                sig[pos..pos + OTS_SIG_LEN].copy_from_slice(&ots_sig);
                pos += OTS_SIG_LEN;
                sig[pos..pos + 4].copy_from_slice(&LMS_TYPE.to_be_bytes());
                pos += 4;
                let mut node = MAX_SIGNATURES + q;
                for _level in 0..H {
                    let sibling = node ^ 1;
                    sig[pos..pos + N].copy_from_slice(&self.nodes[sibling as usize]);
                    pos += N;
                    node >>= 1;
                }

                self.key.leaf_index = q + 1;
                Some(sig)
            }

            /// Number of signatures issued so far (= index of next unused leaf).
            pub fn leaf_index(&self) -> u32 {
                self.key.leaf_index()
            }

            /// `true` once every leaf has been consumed.
            pub fn is_exhausted(&self) -> bool {
                self.key.is_exhausted()
            }

            /// Borrow the wrapped private key — e.g. to persist its
            /// state via [`LmsPrivateKey::to_bytes`] after a signature.
            pub fn private_key(&self) -> &LmsPrivateKey {
                &self.key
            }

            /// Unwrap into the plain private key, dropping the node
            /// table. Leaf state is preserved.
            pub fn into_private_key(self) -> LmsPrivateKey {
                let Self { key, nodes } = self;
                drop(nodes);
                key
            }

            /// Reassemble the public key from the cached root node.
            pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
                #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
                let mut pk = [0u8; PUBLIC_KEY_LEN];
                pk[..4].copy_from_slice(&LMS_TYPE.to_be_bytes());
                pk[4..8].copy_from_slice(&LMOTS_TYPE.to_be_bytes());
                pk[8..24].copy_from_slice(&self.key.identifier);
                pk[24..24 + N].copy_from_slice(&self.nodes[1]);
                pk
            }

            /// Raw node table (RFC 8554 numbering; slot 0 unused) —
            /// public Merkle data, exposed for determinism tests.
            #[doc(hidden)]
            pub fn node_table(&self) -> &[[u8; N]] {
                &self.nodes
            }
        }

        // ── Verification ───────────────────────────────────────────

        /// Verify an LMS signature.
        ///
        /// # Errors
        ///
        /// [`Error::InvalidInput`] on signature mismatch;
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

        // ── Power-up self-test ─────────────────────────────────────

        /// Power-up KATs for this LMS parameter set.
        pub const KATS: &[KatEntry] = &[KatEntry {
            name: $kat_name,
            run: self_test,
        }];

        /// Deterministic KAT seed (32 bytes — same across all pairs;
        /// the per-pair pair-id is baked into the hashing context, so
        /// the resulting public key still diverges per pair).
        const KAT_XI: [u8; 32] = $kat_xi;

        /// KAT message.
        const KAT_MSG: &[u8] = $kat_msg;

        /// Power-up self-test: keygen → sign → verify round trip plus
        /// two negative-verification assertions.
        fn self_test() -> ::core::result::Result<(), SelfTestFailure> {
            let (mut sk, pk) = keygen_internal(&KAT_XI);

            let Some(sig) = sign_internal(&mut sk, KAT_MSG) else {
                return Err(SelfTestFailure);
            };

            if !verify_internal(&pk, KAT_MSG, &sig) {
                return Err(SelfTestFailure);
            }

            if verify_internal(&pk, b"wrong message", &sig) {
                return Err(SelfTestFailure);
            }

            let mut sig_bad = sig;
            #[allow(clippy::indexing_slicing)]
            {
                sig_bad[100] ^= 0x01;
            }
            if verify_internal(&pk, KAT_MSG, &sig_bad) {
                return Err(SelfTestFailure);
            }

            Ok(())
        }
    };
}

pub(crate) use lms_impl;
