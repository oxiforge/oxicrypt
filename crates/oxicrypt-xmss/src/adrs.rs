//! ADRS (Address) structure per RFC 8391 section 2.5.
//!
//! The 32-byte address encodes position and purpose for every
//! hash call in XMSS, providing domain separation without
//! requiring per-call diversifiers like the D_ constants in LMS.
//!
//! Layout (8 × 32-bit words):
//!
//! | Word | Bytes   | Field           |
//! |------|---------|-----------------|
//! | 0    | 0–3     | layer address   |
//! | 1–2  | 4–11    | tree address    |
//! | 3    | 12–15   | type            |
//! | 4    | 16–19   | (type-specific) |
//! | 5    | 20–23   | (type-specific) |
//! | 6    | 24–27   | (type-specific) |
//! | 7    | 28–31   | key and mask    |
//!
//! Words 4–7 are zeroed whenever the type field changes.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// 32-byte address structure.
#[derive(Clone, Copy)]
pub(crate) struct Adrs {
    data: [u8; 32],
}

impl Adrs {
    /// Type code: OTS hash address.
    pub(crate) const OTS_HASH: u32 = 0;
    /// Type code: L-tree address.
    pub(crate) const L_TREE: u32 = 1;
    /// Type code: hash tree address.
    pub(crate) const TREE_HASH: u32 = 2;

    /// Create a zeroed address.
    pub(crate) const fn new() -> Self {
        Self { data: [0u8; 32] }
    }

    /// Return a copy of the raw 32-byte encoding.
    pub(crate) fn bytes(&self) -> [u8; 32] {
        self.data
    }

    // ── Type field (word 3) ──────────────────────────────────

    /// Set the address type, zeroing words 4–7.
    pub(crate) fn set_type(&mut self, t: u32) {
        self.data[12..16].copy_from_slice(&t.to_be_bytes());
        // Zero the type-specific portion.
        let zeros = [0u8; 16];
        self.data[16..32].copy_from_slice(&zeros);
    }

    // ── OTS Hash Address fields ──────────────────────────────

    /// Word 4: which OTS key pair (leaf index).
    pub(crate) fn set_ots_address(&mut self, addr: u32) {
        self.data[16..20].copy_from_slice(&addr.to_be_bytes());
    }

    /// Word 5: which chain within the OTS key pair.
    pub(crate) fn set_chain_address(&mut self, addr: u32) {
        self.data[20..24].copy_from_slice(&addr.to_be_bytes());
    }

    /// Word 6: position within the chain.
    pub(crate) fn set_hash_address(&mut self, addr: u32) {
        self.data[24..28].copy_from_slice(&addr.to_be_bytes());
    }

    /// Word 7: key-and-mask selector (0 = key, 1 = bitmask left,
    /// 2 = bitmask right).
    pub(crate) fn set_key_and_mask(&mut self, val: u32) {
        self.data[28..32].copy_from_slice(&val.to_be_bytes());
    }

    // ── L-tree Address fields ────────────────────────────────

    /// Word 4: which L-tree (same as OTS address / leaf index).
    pub(crate) fn set_ltree_address(&mut self, addr: u32) {
        self.data[16..20].copy_from_slice(&addr.to_be_bytes());
    }

    /// Word 6: tree height within the L-tree.
    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.data[24..28].copy_from_slice(&height.to_be_bytes());
    }

    /// Word 7: tree index within the current height.
    pub(crate) fn set_tree_index(&mut self, idx: u32) {
        self.data[28..32].copy_from_slice(&idx.to_be_bytes());
    }
}
