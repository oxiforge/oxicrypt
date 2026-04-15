//! Hyper-tree signing and verification — FIPS 205 §6.2.
//!
//! The hyper-tree is a `D`-layer tower of XMSS trees.  Layer 0 is
//! closest to the FORS trees; layer `D − 1` holds the tree whose
//! root is the public key.  Each layer's tree has height `H' = 8`,
//! giving a total tree height of `H = D × H' = 64`.
//!
//! - `ht_sign`   — Algorithm 11.
//! - `ht_verify` — Algorithm 12.

use crate::adrs::Adrs;
use crate::params::{D, H_PRIME, N};
use crate::xmss;

/// Size of a hyper-tree signature: `D` XMSS signatures.
pub(crate) const HT_SIG_LEN: usize = D * xmss::XMSS_SIG_LEN; // 19200

// ── ht_sign (Algorithm 11) ──────────────────────────────────────────

/// Sign an N-byte message `m` under the hyper-tree.
///
/// `tree_idx` and `leaf_idx` identify where in the hyper-tree the
/// FORS instance lives.
pub(crate) fn ht_sign(
    pk_seed: &[u8; N],
    sk_seed: &[u8; N],
    m: &[u8; N],
    tree_idx: u64,
    leaf_idx: u32,
) -> [u8; HT_SIG_LEN] {
    let mut sig = [0u8; HT_SIG_LEN];

    let mut adrs = Adrs::zero();

    // Layer 0: sign `m` in the XMSS tree at (layer=0, tree=tree_idx).
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree_idx);

    let sig_0 = xmss::xmss_sign(pk_seed, sk_seed, leaf_idx, m, &adrs);
    sig[..xmss::XMSS_SIG_LEN].copy_from_slice(&sig_0);

    // Compute the root of the layer-0 tree to pass up.
    let mut root = xmss::xmss_pk_from_sig(pk_seed, leaf_idx, &sig_0, m, &adrs);

    // Layers 1..D-1: each layer signs the root of the layer below.
    let mut current_tree = tree_idx;
    for layer in 1..D as u32 {
        // The leaf index in this layer is the low H' bits of the
        // tree index from the layer below.
        let idx = (current_tree & ((1u64 << H_PRIME) - 1)) as u32;
        current_tree >>= H_PRIME;

        adrs.set_layer_address(layer);
        adrs.set_tree_address(current_tree);

        let sig_layer = xmss::xmss_sign(pk_seed, sk_seed, idx, &root, &adrs);
        let offset = layer as usize * xmss::XMSS_SIG_LEN;
        sig[offset..offset + xmss::XMSS_SIG_LEN].copy_from_slice(&sig_layer);

        root = xmss::xmss_pk_from_sig(pk_seed, idx, &sig_layer, &root, &adrs);
    }

    sig
}

// ── ht_verify (Algorithm 12) ────────────────────────────────────────

/// Verify a hyper-tree signature, returning `true` if the
/// reconstructed root matches `pk_root`.
pub(crate) fn ht_verify(
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    m: &[u8; N],
    sig: &[u8],
    tree_idx: u64,
    leaf_idx: u32,
) -> bool {
    let mut adrs = Adrs::zero();

    // Layer 0.
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree_idx);

    let sig_0 = &sig[..xmss::XMSS_SIG_LEN];
    let mut root = xmss::xmss_pk_from_sig(pk_seed, leaf_idx, sig_0, m, &adrs);

    // Layers 1..D-1.
    let mut current_tree = tree_idx;
    for layer in 1..D as u32 {
        let idx = (current_tree & ((1u64 << H_PRIME) - 1)) as u32;
        current_tree >>= H_PRIME;

        adrs.set_layer_address(layer);
        adrs.set_tree_address(current_tree);

        let offset = layer as usize * xmss::XMSS_SIG_LEN;
        let sig_layer = &sig[offset..offset + xmss::XMSS_SIG_LEN];
        root = xmss::xmss_pk_from_sig(pk_seed, idx, sig_layer, &root, &adrs);
    }

    root == *pk_root
}
