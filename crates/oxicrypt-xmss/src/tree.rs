//! XMSS Merkle tree operations per RFC 8391 section 4.
//!
//! Walks the XMSS tree using randomized hashing (RAND_HASH) with
//! bitmasks derived from the public seed. A candidate leaf is
//! recovered from the WOTS+ signature and compressed by the L-tree,
//! then the authentication path carries it to a root.
//!
//! Verification never builds the tree: it walks one authentication
//! path, so no node storage is required.
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

/// OID for XMSS-SHA2_10_256 (RFC 8391 §8; parameters in §5.3).
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

// ── Public API ──────────────────────────────────────────────────

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
        // RFC 8391 Algorithm 13 sets the tree height to `k`, the height of
        // the pair being combined, not the height of their parent.
        if idx & 1 == 0 {
            tmp = hash_tree_node(&tmp, &auth[height], pub_seed, height as u32, parent_idx);
        } else {
            tmp = hash_tree_node(&auth[height], &tmp, pub_seed, height as u32, parent_idx);
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

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    /// The tree index must reach the hash. RFC 8391 §2.5 puts the index in
    /// ADRS word 6 and `keyAndMask` in word 7; writing the index into word
    /// 7 leaves it with no effect, because `rand_hash` overwrites that word
    /// on every call. Two nodes differing only in index then hash
    /// identically, and the authentication path stops binding a leaf to its
    /// position — the defect this crate was rebuilt to repair.
    ///
    /// The external vectors cannot catch this on their own: every valid one
    /// signs leaf 0, where the index is zero and the bug is invisible.
    #[test]
    fn tree_index_reaches_the_hash() {
        let l = [0x11u8; N];
        let r = [0x22u8; N];
        let seed = [0x33u8; N];
        assert_ne!(
            hash_tree_node(&l, &r, &seed, 3, 0),
            hash_tree_node(&l, &r, &seed, 3, 999),
            "index 0 and index 999 hashed identically"
        );
    }

    /// Control for the probe above. The height demonstrably reaches the
    /// hash, so if this fails too, the harness is broken rather than the
    /// address encoding.
    #[test]
    fn tree_height_reaches_the_hash() {
        let l = [0x11u8; N];
        let r = [0x22u8; N];
        let seed = [0x33u8; N];
        assert_ne!(
            hash_tree_node(&l, &r, &seed, 3, 0),
            hash_tree_node(&l, &r, &seed, 4, 0),
            "height 3 and height 4 hashed identically"
        );
    }
}
