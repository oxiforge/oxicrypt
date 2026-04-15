//! LMS Merkle tree operations per RFC 8554 section 5.
//!
//! Builds and traverses the binary hash tree whose leaves are
//! LM-OTS public key hashes. Supports root computation (for
//! keygen) and authentication-path extraction (for signing)
//! via recursive tree traversal from a seed — no full-tree
//! storage is needed.
//!
//! Lints: indices are bounded by compile-time constants (tree
//! height H, node count). Arithmetic is on small tree-index
//! values that cannot overflow.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::cast_possible_truncation
)]

use oxicrypt_sha::sha256::Sha256;

use crate::lmots;

/// Tree height for LMS_SHA256_M32_H10.
pub(crate) const H: usize = 10;

/// Number of leaves: 2^H = 1024.
pub(crate) const NUM_LEAVES: u32 = 1 << H;

/// RFC 8554 type code for LMS_SHA256_M32_H10.
pub(crate) const LMS_TYPE: u32 = 0x0000_0006;

/// Diversifier for leaf node hashing (RFC 8554 §5.3).
const D_LEAF: u16 = 0x8282;

/// Diversifier for internal node hashing (RFC 8554 §5.3).
const D_INTR: u16 = 0x8383;

/// Hash output length (n = 32).
const N: usize = lmots::N;

// ── Node hashing ────────────────────────────────────────────────

/// Hash a leaf node.
///
/// T\[r\] = H(I || u32str(r) || u16str(D_LEAF) || Kc)
/// where r = `NUM_LEAVES` + q.
fn hash_leaf(i_val: &[u8; 16], r: u32, kc: &[u8; N]) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&r.to_be_bytes());
    h.update(&D_LEAF.to_be_bytes());
    h.update(kc);
    h.finalize()
}

/// Hash an internal node.
///
/// T\[r\] = H(I || u32str(r) || u16str(D_INTR) || T\[2r\] || T\[2r+1\])
fn hash_internal(i_val: &[u8; 16], r: u32, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    let mut h = Sha256::new_internal();
    h.update(i_val);
    h.update(&r.to_be_bytes());
    h.update(&D_INTR.to_be_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

// ── Recursive tree computation ──────────────────────────────────

/// Compute the hash value of tree node `node_idx`.
///
/// Tree indexing follows RFC 8554: root = 1, children of node r
/// are 2r (left) and 2r+1 (right), leaves are at indices
/// `num_leaves` to `2 * num_leaves - 1`.
///
/// Maximum recursion depth is H = 10 (root to leaf). Each frame
/// holds two `[u8; 32]` children plus locals — roughly 100 bytes,
/// so total stack usage is ~1 KB.
fn compute_node(seed: &[u8; N], i_val: &[u8; 16], node_idx: u32) -> [u8; N] {
    if node_idx >= NUM_LEAVES {
        // Leaf: compute the LM-OTS public key K and hash it.
        let q = node_idx - NUM_LEAVES;
        let k = lmots::compute_public_key(seed, i_val, q);
        hash_leaf(i_val, node_idx, &k)
    } else {
        // Internal: recursively compute children.
        let left = compute_node(seed, i_val, node_idx * 2);
        let right = compute_node(seed, i_val, node_idx * 2 + 1);
        hash_internal(i_val, node_idx, &left, &right)
    }
}

// ── Public API ──────────────────────────────────────────────────

/// Compute the Merkle tree root T\[1\].
///
/// This hashes all 2^H = 1024 leaves (each requiring a full
/// LM-OTS public key computation) and builds the tree bottom-up
/// via recursion. Runtime is dominated by ~1 million SHA-256
/// invocations — expected ~0.5 s on modern hardware.
pub(crate) fn compute_root(seed: &[u8; N], i_val: &[u8; 16]) -> [u8; N] {
    compute_node(seed, i_val, 1)
}

/// Compute the authentication path for leaf `q`.
///
/// Returns H = 10 sibling hashes, from the leaf's sibling (index 0)
/// up to the root's child sibling (index H-1).
///
/// Each sibling node requires computing its entire subtree,
/// totalling ~1023 leaf computations in aggregate.
pub(crate) fn compute_auth_path(seed: &[u8; N], i_val: &[u8; 16], q: u32) -> [[u8; N]; H] {
    let mut path = [[0u8; N]; H];
    let mut node = NUM_LEAVES + q;
    for slot in &mut path {
        let sibling = node ^ 1;
        *slot = compute_node(seed, i_val, sibling);
        node >>= 1;
    }
    path
}

/// Walk the authentication path from a candidate leaf hash
/// up to the root and return the computed root.
///
/// Used during verification. RFC 8554 §5.4.
pub(crate) fn walk_auth_path(
    i_val: &[u8; 16],
    candidate_k: &[u8; N],
    q: u32,
    auth: &[[u8; N]; H],
) -> [u8; N] {
    let mut node_idx = NUM_LEAVES + q;
    // Leaf hash.
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
