//! XMSS tree operations within a single hyper-tree layer — FIPS 205 §6.
//!
//! Each hyper-tree layer is an XMSS tree of height `H' = 8`.  The
//! leaves are WOTS+ public keys; internal nodes are computed with the
//! tweakable hash `H`.
//!
//! This module provides:
//! - `xmss_node` — compute an internal node (Algorithm 8).
//! - `xmss_sign` — XMSS signature (WOTS+ sig + auth path, Algorithm 9).
//! - `xmss_pk_from_sig` — reconstruct root from signature (Algorithm 10).

use crate::adrs::{Adrs, AdrsType};
use crate::params::{H_PRIME, N};
use crate::thash;
use crate::wots;

/// Size of an XMSS signature: WOTS+ signature + authentication path.
pub(crate) const XMSS_SIG_LEN: usize = wots::WOTS_SIG_LEN + H_PRIME * N; // 2400

// ── xmss_node (Algorithm 8) ────────────────────────────────────────

/// Compute the root of the subtree of height `target_height` whose
/// leftmost leaf is at index `target_idx × 2^target_height`.
///
/// This is the recursive tree-hash: leaves are WOTS+ public keys,
/// internal nodes use `H`.  For efficiency we compute iteratively
/// using a stack.
pub(crate) fn xmss_node(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    target_idx: u32,
    target_height: u32,
    adrs: &Adrs,
) -> [u8; N] {
    debug_assert!(target_height <= H_PRIME as u32);

    if target_height == 0 {
        // Leaf: WOTS+ public key at index `target_idx`.
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(AdrsType::WotsHash);
        leaf_adrs.set_keypair_address(target_idx);
        return wots::wots_pkgen(pk_seed, sk_seed, &leaf_adrs);
    }

    // Recursive computation (iterative via binary recursion).
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
    thash::h(pk_seed, &node_adrs, &left, &right)
}

// ── xmss_sign (Algorithm 9) ────────────────────────────────────────

/// Generate an XMSS signature for message `m` at leaf index `idx`.
///
/// Returns `(sig, auth_path)` packed into `XMSS_SIG_LEN` bytes:
/// the WOTS+ signature followed by `H'` authentication-path nodes.
pub(crate) fn xmss_sign(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    idx: u32,
    m: &[u8; N],
    adrs: &Adrs,
) -> [u8; XMSS_SIG_LEN] {
    let mut sig = [0u8; XMSS_SIG_LEN];

    // WOTS+ signature on `m`.
    let mut wots_adrs = *adrs;
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_keypair_address(idx);
    let wots_sig = wots::wots_sign(pk_seed, sk_seed, &wots_adrs, m);
    sig[..wots::WOTS_SIG_LEN].copy_from_slice(&wots_sig);

    // Authentication path: for each level j, the sibling of the
    // ancestor of leaf `idx` at height j.
    for j in 0..H_PRIME {
        let sibling_idx = (idx >> j) ^ 1;
        let node = xmss_node(pk_seed, sk_seed, sibling_idx, j as u32, adrs);
        let offset = wots::WOTS_SIG_LEN + j * N;
        sig[offset..offset + N].copy_from_slice(&node);
    }

    sig
}

// ── xmss_pk_from_sig (Algorithm 10) ────────────────────────────────

/// Reconstruct the XMSS tree root from an XMSS signature and message.
///
/// `sig` must be exactly `XMSS_SIG_LEN` bytes.
pub(crate) fn xmss_pk_from_sig(
    pk_seed: &[u8; N],
    idx: u32,
    sig: &[u8],
    m: &[u8; N],
    adrs: &Adrs,
) -> [u8; N] {
    // Recover WOTS+ public key from the WOTS+ portion.
    let wots_sig = &sig[..wots::WOTS_SIG_LEN];
    let mut wots_adrs = *adrs;
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_keypair_address(idx);
    let mut node = wots::wots_pk_from_sig(pk_seed, &wots_adrs, wots_sig, m);

    // Walk up the tree using the authentication path.
    let mut tree_adrs = *adrs;
    tree_adrs.set_type(AdrsType::Tree);
    tree_adrs.set_tree_index(idx);

    for j in 0..H_PRIME {
        let auth_offset = wots::WOTS_SIG_LEN + j * N;
        let mut auth_node = [0u8; N];
        auth_node.copy_from_slice(&sig[auth_offset..auth_offset + N]);

        tree_adrs.set_tree_height((j + 1) as u32);

        if (idx >> j) & 1 == 0 {
            // Current node is the left child.
            tree_adrs.set_tree_index((idx >> (j + 1)) as u32);
            node = thash::h(pk_seed, &tree_adrs, &node, &auth_node);
        } else {
            // Current node is the right child.
            tree_adrs.set_tree_index((idx >> (j + 1)) as u32);
            node = thash::h(pk_seed, &tree_adrs, &auth_node, &node);
        }
    }

    node
}
