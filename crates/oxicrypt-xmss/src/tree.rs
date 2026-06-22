//! XMSS Merkle tree operations per RFC 8391 section 4.
//!
//! Builds and traverses the XMSS tree using randomized hashing
//! (RAND_HASH) with bitmasks derived from the public seed. Leaf
//! computation includes WOTS+ public key generation followed by
//! L-tree compression.
//!
//! All tree computation is recursive from the seed — no full-tree
//! storage is required.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::many_single_char_names
)]

use oxicrypt_sha::sha256::Sha256;

use crate::adrs::Adrs;
use crate::wots;

/// Hash output size (n = 32).
const N: usize = wots::N;

/// Tree height for XMSS-SHA2_10_256.
pub(crate) const H: usize = 10;

/// Number of leaves: 2^H = 1024.
pub(crate) const NUM_LEAVES: u32 = 1 << H;

/// OID for XMSS-SHA2_10_256 (RFC 8391 §5.3).
pub(crate) const XMSS_OID: u32 = 0x0000_0001;

// ── Hash abstractions ───────────────────────────────────────────

/// Domain separation for H (tree/L-tree hashing).
const PAD_H: [u8; N] = {
    let mut buf = [0u8; N];
    buf[N - 1] = 1;
    buf
};

/// Domain separation for PRF.
const PAD_PRF: [u8; N] = {
    let mut buf = [0u8; N];
    buf[N - 1] = 3;
    buf
};

/// PRF(KEY, M) = SHA-256(toByte(3,32) || KEY || M)
fn prf(key: &[u8; N], m: &[u8]) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(&PAD_PRF);
    h.update(key);
    h.update(m);
    h.finalize()
}

/// RAND_HASH(left, right, pub_seed, adrs).
///
/// KEY = PRF(pub_seed, ADRS{keyAndMask=0})
/// BM_0 = PRF(pub_seed, ADRS{keyAndMask=1})
/// BM_1 = PRF(pub_seed, ADRS{keyAndMask=2})
/// return H(KEY, (left XOR BM_0) || (right XOR BM_1))
fn rand_hash(left: &[u8; N], right: &[u8; N], pub_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    adrs.set_key_and_mask(0);
    let key = prf(pub_seed, &adrs.bytes());

    adrs.set_key_and_mask(1);
    let bm_0 = prf(pub_seed, &adrs.bytes());

    adrs.set_key_and_mask(2);
    let bm_1 = prf(pub_seed, &adrs.bytes());

    // H(KEY, (left XOR BM_0) || (right XOR BM_1))
    let mut hasher = Sha256::new_internal();
    hasher.update(&PAD_H);
    hasher.update(&key);
    // First n bytes: left XOR BM_0
    let mut tmp = [0u8; N];
    for i in 0..N {
        tmp[i] = left[i] ^ bm_0[i];
    }
    hasher.update(&tmp);
    // Second n bytes: right XOR BM_1
    for i in 0..N {
        tmp[i] = right[i] ^ bm_1[i];
    }
    hasher.update(&tmp);
    hasher.finalize()
}

// ── L-tree (RFC 8391 §4.1.5) ───────────────────────────────────

/// Compress `len` WOTS+ public key elements into a single n-byte
/// value using a binary tree (L-tree).
///
/// The L-tree uses RAND_HASH at each level, with an L-tree ADRS
/// encoding the leaf index and tree height.
fn ltree(pk: &[[u8; N]; wots::LEN], pub_seed: &[u8; N], leaf_idx: u32) -> [u8; N] {
    // Copy into a working buffer. Max 67 elements.
    let mut buf = [[0u8; N]; wots::LEN];
    buf.copy_from_slice(pk);
    let mut len_prime = wots::LEN;

    let mut adrs = Adrs::new();
    adrs.set_type(Adrs::L_TREE);
    adrs.set_ltree_address(leaf_idx);
    let mut height: u32 = 0;

    while len_prime > 1 {
        let half = len_prime / 2;
        for i in 0..half {
            adrs.set_tree_height(height);
            adrs.set_tree_index(i as u32);
            buf[i] = rand_hash(&buf[2 * i], &buf[2 * i + 1], pub_seed, &mut adrs);
        }
        if len_prime % 2 == 1 {
            buf[half] = buf[len_prime - 1];
        }
        len_prime = len_prime.div_ceil(2);
        height += 1;
    }
    buf[0]
}

// ── Leaf computation ────────────────────────────────────────────

/// Compute a tree leaf: WOTS+ keygen → L-tree compression.
fn compute_leaf(sk_seed: &[u8; N], pub_seed: &[u8; N], leaf_idx: u32) -> [u8; N] {
    let pk = wots::wots_pk_gen(sk_seed, pub_seed, leaf_idx);
    ltree(&pk, pub_seed, leaf_idx)
}

/// Compute a leaf from a WOTS+ signature (for verification).
fn compute_leaf_from_sig(
    msg_hash: &[u8; N],
    sig: &[[u8; N]; wots::LEN],
    pub_seed: &[u8; N],
    leaf_idx: u32,
) -> [u8; N] {
    let pk = wots::wots_pk_from_sig(msg_hash, sig, pub_seed, leaf_idx);
    ltree(&pk, pub_seed, leaf_idx)
}

// ── Tree node computation ───────────────────────────────────────

/// Hash tree internal node using RAND_HASH with tree-hash ADRS.
fn hash_tree_node(
    left: &[u8; N],
    right: &[u8; N],
    pub_seed: &[u8; N],
    height: u32,
    index: u32,
) -> [u8; N] {
    let mut adrs = Adrs::new();
    adrs.set_type(Adrs::TREE_HASH);
    adrs.set_tree_height(height);
    adrs.set_tree_index(index);
    rand_hash(left, right, pub_seed, &mut adrs)
}

/// Recursively compute the hash of tree node at (`height`, `index`).
///
/// Height 0 = leaf level. Height H = root. Index is the position
/// at the given height (0-indexed from the left).
///
/// Sequential build (default, `no_std`): the two child sub-trees are
/// computed in order and combined `(left, right)`.
#[cfg(not(feature = "parallel"))]
fn compute_node(sk_seed: &[u8; N], pub_seed: &[u8; N], height: u32, index: u32) -> [u8; N] {
    if height == 0 {
        compute_leaf(sk_seed, pub_seed, index)
    } else {
        let left = compute_node(sk_seed, pub_seed, height - 1, 2 * index);
        let right = compute_node(sk_seed, pub_seed, height - 1, 2 * index + 1);
        hash_tree_node(&left, &right, pub_seed, height, index)
    }
}

/// Height above which the two child sub-trees are forked across rayon;
/// at or below it the recursion stays sequential to cap task-spawn
/// overhead near the leaves (where sub-trees are tiny). The cutoff only
/// chooses *where* work runs — both branches compute the identical pure
/// function of `(height, index)` and the seeds — so it never changes the
/// output (only `H == 10` here, so the top ~6 levels fork).
#[cfg(feature = "parallel")]
const PAR_HEIGHT_CUTOFF: u32 = 3;

/// Recursively compute the hash of tree node at (`height`, `index`).
///
/// Height 0 = leaf level. Height H = root. Index is the position
/// at the given height (0-indexed from the left).
///
/// Parallel build: above [`PAR_HEIGHT_CUTOFF`] the two child sub-trees
/// are computed concurrently via [`rayon::join`]. Each closure computes
/// one child sub-tree — a pure function of its `(height, index)` plus
/// the immutable seeds, touching no shared mutable state — and the
/// parent recombines them *by position* as `(left, right)`, never by
/// completion order. The result is therefore byte-identical to the
/// sequential build regardless of which child finishes first.
#[cfg(feature = "parallel")]
fn compute_node(sk_seed: &[u8; N], pub_seed: &[u8; N], height: u32, index: u32) -> [u8; N] {
    if height == 0 {
        compute_leaf(sk_seed, pub_seed, index)
    } else if height > PAR_HEIGHT_CUTOFF {
        let (left, right) = rayon::join(
            || compute_node(sk_seed, pub_seed, height - 1, 2 * index),
            || compute_node(sk_seed, pub_seed, height - 1, 2 * index + 1),
        );
        hash_tree_node(&left, &right, pub_seed, height, index)
    } else {
        let left = compute_node(sk_seed, pub_seed, height - 1, 2 * index);
        let right = compute_node(sk_seed, pub_seed, height - 1, 2 * index + 1);
        hash_tree_node(&left, &right, pub_seed, height, index)
    }
}

// ── Public API ──────────────────────────────────────────────────

/// Compute the tree root.
pub(crate) fn compute_root(sk_seed: &[u8; N], pub_seed: &[u8; N]) -> [u8; N] {
    compute_node(sk_seed, pub_seed, H as u32, 0)
}

/// Compute the authentication path for leaf `q`.
///
/// Returns H sibling hashes from leaf level (index 0) to the
/// root's child level (index H-1).
pub(crate) fn compute_auth_path(sk_seed: &[u8; N], pub_seed: &[u8; N], q: u32) -> [[u8; N]; H] {
    let mut path = [[0u8; N]; H];
    let mut idx = q;
    for height in 0..H {
        // Sibling index at this height.
        let sibling = idx ^ 1;
        path[height] = compute_node(sk_seed, pub_seed, height as u32, sibling);
        idx >>= 1;
    }
    path
}

/// Walk the authentication path from a candidate leaf hash
/// up to the root and return the computed root.
pub(crate) fn walk_auth_path(
    candidate_leaf: &[u8; N],
    pub_seed: &[u8; N],
    q: u32,
    auth: &[[u8; N]; H],
) -> [u8; N] {
    let mut tmp = *candidate_leaf;
    let mut idx = q;
    for height in 0..H {
        let parent_idx = idx >> 1;
        if idx & 1 == 0 {
            tmp = hash_tree_node(
                &tmp,
                &auth[height],
                pub_seed,
                (height + 1) as u32,
                parent_idx,
            );
        } else {
            tmp = hash_tree_node(
                &auth[height],
                &tmp,
                pub_seed,
                (height + 1) as u32,
                parent_idx,
            );
        }
        idx = parent_idx;
    }
    tmp
}

/// Compute a candidate leaf from a WOTS+ signature and walk the
/// auth path to the root (verification helper).
pub(crate) fn root_from_sig(
    msg_hash: &[u8; N],
    wots_sig: &[[u8; N]; wots::LEN],
    pub_seed: &[u8; N],
    q: u32,
    auth: &[[u8; N]; H],
) -> [u8; N] {
    let leaf = compute_leaf_from_sig(msg_hash, wots_sig, pub_seed, q);
    walk_auth_path(&leaf, pub_seed, q, auth)
}

// ── Determinism oracle (parallel feature only) ──────────────────

/// Determinism property tests for the `parallel` Merkle tree build.
///
/// Oracle choice: `compute_node` is cfg-gated, so there is no second
/// runtime function to diff against within one build. Instead we provide
/// a self-contained *iterative*, leaf-by-leaf sequential root
/// reconstruction (`sequential_root_reference`) that never calls the
/// cfg-gated recursive `compute_node` — it materializes all 1024 leaves
/// and folds them up level by level using the same `compute_leaf` /
/// `hash_tree_node` primitives. In the parallel build we assert the
/// fork-join `compute_root` equals this independent sequential
/// reconstruction across several deterministic seeds. We additionally
/// assert the auth path verifies back to the same root — an internal
/// consistency check of `compute_auth_path` then `walk_auth_path` — for
/// several leaf indices, so both public entry points the parallel split
/// touches are pinned. Seeds are derived from a loop counter (no rand)
/// so the test is reproducible.
#[cfg(all(test, feature = "parallel"))]
mod parallel_determinism {
    extern crate alloc;

    use super::*;

    /// Iterative sequential root: build all `NUM_LEAVES` leaves, then
    /// fold pairs upward. Does NOT use the recursive `compute_node`, so
    /// it is an independent oracle for the fork-join build.
    fn sequential_root_reference(sk_seed: &[u8; N], pub_seed: &[u8; N]) -> [u8; N] {
        let mut level: alloc::vec::Vec<[u8; N]> = (0..NUM_LEAVES)
            .map(|i| compute_leaf(sk_seed, pub_seed, i))
            .collect();
        let mut height: u32 = 1;
        while level.len() > 1 {
            let half = level.len() / 2;
            let mut next = alloc::vec::Vec::with_capacity(half);
            for i in 0..half {
                next.push(hash_tree_node(
                    &level[2 * i],
                    &level[2 * i + 1],
                    pub_seed,
                    height,
                    i as u32,
                ));
            }
            level = next;
            height += 1;
        }
        level[0]
    }

    fn seed_pair(k: u8) -> ([u8; N], [u8; N]) {
        let mut sk = [0u8; N];
        let mut ps = [0u8; N];
        for i in 0..N {
            sk[i] = k.wrapping_add(i as u8);
            ps[i] = k.wrapping_mul(3).wrapping_add(i as u8).wrapping_add(0x5a);
        }
        (sk, ps)
    }

    #[test]
    fn parallel_root_matches_sequential_reference() {
        for k in 0u8..6 {
            let (sk, ps) = seed_pair(k);
            let par = compute_root(&sk, &ps);
            let seq = sequential_root_reference(&sk, &ps);
            assert_eq!(par, seq, "root mismatch at seed k={k}");
        }
    }

    #[test]
    fn parallel_auth_path_verifies_to_root() {
        for k in 0u8..4 {
            let (sk, ps) = seed_pair(k);
            let root = compute_root(&sk, &ps);
            // Sample several leaves (both parities, spread across the tree).
            for &q in &[0u32, 1, 2, 511, 512, NUM_LEAVES - 1] {
                let leaf = compute_leaf(&sk, &ps, q);
                let auth = compute_auth_path(&sk, &ps, q);
                let walked = walk_auth_path(&leaf, &ps, q, &auth);
                assert_eq!(walked, root, "auth path mismatch at seed k={k}, q={q}");
            }
        }
    }
}
