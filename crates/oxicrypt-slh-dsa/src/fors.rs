//! FORS (Forest of Random Subsets) — FIPS 205 §8.
//!
//! FORS is a few-time signature scheme used as the bottom layer of
//! SLH-DSA.  It signs a message digest by selecting one leaf from
//! each of `K = 22` binary trees of height `A = 14`.  The signature
//! consists of the `K` secret leaf values plus their authentication
//! paths; the public key is the hash of the `K` tree roots.

use crate::adrs::{Adrs, AdrsType};
use crate::params::{A, K, N};
use crate::thash;

/// Size of a FORS signature: K × (1 secret + A auth-path nodes) × N.
pub(crate) const FORS_SIG_LEN: usize = K * (1 + A) * N; // 10560

// ── fors_sk_gen (Algorithm 13 helper) ───────────────────────────────

/// Generate a single FORS secret-key value.
///
/// `idx` identifies the leaf across all K trees (0 ≤ idx < K × 2^A).
fn fors_sk_gen(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs, idx: u32) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type(AdrsType::ForsPrf);
    sk_adrs.set_keypair_address(adrs.keypair_address());
    sk_adrs.set_tree_index(idx);
    thash::prf(pk_seed, sk_seed, &sk_adrs)
}

// ── fors_node (Algorithm 14) ────────────────────────────────────────

/// Compute a node in a single FORS tree.
///
/// `tree_base` is the offset of this tree's leaves in the global
/// leaf index space (i.e. `tree_idx × 2^A` where `tree_idx ∈ 0..K`).
fn fors_node(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    node_idx: u32,
    node_height: u32,
    adrs: &Adrs,
    tree_base: u32,
) -> [u8; N] {
    if node_height == 0 {
        // Leaf: hash the secret value.
        let sk = fors_sk_gen(pk_seed, sk_seed, adrs, tree_base + node_idx);
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(AdrsType::ForsTree);
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(tree_base + node_idx);
        return thash::f(pk_seed, &leaf_adrs, &sk);
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
    node_adrs.set_tree_height(node_height);
    node_adrs.set_tree_index(tree_base / (1 << node_height) + node_idx);
    thash::h(pk_seed, &node_adrs, &left, &right)
}

// ── fors_sign (Algorithm 15) ────────────────────────────────────────

/// Sign a FORS message digest.
///
/// `md` is the packed message digest from `H_msg`; we extract K
/// A-bit indices via [`thash::fors_index`].
///
/// `adrs` must have `keypair_address` set to the FORS instance index.
pub(crate) fn fors_sign(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    md: &[u8; 64],
    adrs: &Adrs,
) -> [u8; FORS_SIG_LEN] {
    let mut sig = [0u8; FORS_SIG_LEN];
    let entry_size = (1 + A) * N; // bytes per FORS tree in the signature

    for i in 0..K {
        let idx = thash::fors_index(md, i);
        let tree_base = (i as u32) * (1 << A);
        let sig_offset = i * entry_size;

        // Secret leaf value.
        let sk = fors_sk_gen(pk_seed, sk_seed, adrs, tree_base + idx);
        sig[sig_offset..sig_offset + N].copy_from_slice(&sk);

        // Authentication path.
        for j in 0..A {
            let sibling = (idx >> j) ^ 1;
            let node = fors_node(pk_seed, sk_seed, sibling, j as u32, adrs, tree_base);
            let auth_offset = sig_offset + N + j * N;
            sig[auth_offset..auth_offset + N].copy_from_slice(&node);
        }
    }

    sig
}

// ── fors_pk_from_sig (Algorithm 16) ─────────────────────────────────

/// Reconstruct the FORS public key from a signature and message digest.
pub(crate) fn fors_pk_from_sig(
    pk_seed: &[u8; N],
    md: &[u8; 64],
    sig: &[u8],
    adrs: &Adrs,
) -> [u8; N] {
    let entry_size = (1 + A) * N;
    // Buffer to hold K tree roots.
    let mut roots = [0u8; K * N];

    for i in 0..K {
        let idx = thash::fors_index(md, i);
        let tree_base = (i as u32) * (1 << A);
        let sig_offset = i * entry_size;

        // Reconstruct leaf from the secret value.
        let mut sk = [0u8; N];
        sk.copy_from_slice(&sig[sig_offset..sig_offset + N]);
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(AdrsType::ForsTree);
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(tree_base + idx);
        let mut node = thash::f(pk_seed, &leaf_adrs, &sk);

        // Walk up using the authentication path.
        for j in 0..A {
            let auth_offset = sig_offset + N + j * N;
            let mut auth = [0u8; N];
            auth.copy_from_slice(&sig[auth_offset..auth_offset + N]);

            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AdrsType::ForsTree);
            tree_adrs.set_tree_height((j + 1) as u32);

            if (idx >> j) & 1 == 0 {
                tree_adrs.set_tree_index(tree_base / (1 << (j + 1)) + (idx >> (j + 1)));
                node = thash::h(pk_seed, &tree_adrs, &node, &auth);
            } else {
                tree_adrs.set_tree_index(tree_base / (1 << (j + 1)) + (idx >> (j + 1)));
                node = thash::h(pk_seed, &tree_adrs, &auth, &node);
            }
        }

        roots[i * N..(i + 1) * N].copy_from_slice(&node);
    }

    // Compress K roots into a single public key.
    let mut pk_adrs = *adrs;
    pk_adrs.set_type(AdrsType::ForsRoots);
    pk_adrs.set_keypair_address(adrs.keypair_address());
    thash::t(pk_seed, &pk_adrs, &roots)
}
