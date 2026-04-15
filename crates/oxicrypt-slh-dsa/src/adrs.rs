//! ADRS (address) scheme — FIPS 205 §4.
//!
//! Every SLH-DSA hash call incorporates a 32-byte address for domain
//! separation.  The address encodes the position in the hyper-tree
//! (layer, tree index, chain/hash/tree-height/tree-index within that
//! subtree) plus a type tag.
//!
//! Uncompressed layout (all big-endian, 32 bytes):
//!
//! | Bytes  | Field            |
//! |--------|------------------|
//! | 0..4   | layer address    |
//! | 4..16  | tree address     |
//! | 16..20 | type             |
//! | 20..24 | type-specific 1  |
//! | 24..28 | type-specific 2  |
//! | 28..32 | type-specific 3  |
//!
//! Compressed layout for SHA-256 (`ADRSc`, 22 bytes):
//!
//! | Bytes  | Source           |
//! |--------|------------------|
//! | 0      | layer (low byte) |
//! | 1..9   | tree (low 64b)  |
//! | 9      | type (low byte) |
//! | 10..14 | type-specific 1 |
//! | 14..18 | type-specific 2 |
//! | 18..22 | type-specific 3 |

/// Compressed address length for SHA-256 variant.
pub(crate) const ADRS_COMPRESSED_LEN: usize = 22;

/// Address types (FIPS 205 §4, Table 2).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum AdrsType {
    /// WOTS+ hash address.
    WotsHash = 0,
    /// WOTS+ public-key compression.
    WotsPk = 1,
    /// Merkle tree address.
    Tree = 2,
    /// FORS tree address.
    ForsTree = 3,
    /// FORS roots compression.
    ForsRoots = 4,
    /// WOTS+ PRF key generation.
    WotsPrf = 5,
    /// FORS PRF key generation.
    ForsPrf = 6,
}

/// 32-byte SLH-DSA address structure.
#[derive(Clone, Copy)]
pub(crate) struct Adrs {
    bytes: [u8; 32],
}

#[allow(dead_code)]
impl Adrs {
    /// Create a zeroed address.
    pub(crate) const fn zero() -> Self {
        Self { bytes: [0u8; 32] }
    }

    // ── Layer address (bytes 0..4) ──

    /// Set the layer address.
    pub(crate) fn set_layer_address(&mut self, layer: u32) {
        self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// Get the layer address.
    pub(crate) fn layer_address(&self) -> u32 {
        u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]])
    }

    // ── Tree address (bytes 4..16, 96-bit / 12 bytes) ──

    /// Set the tree address (up to 64 bits; upper 32 bits stay zero).
    pub(crate) fn set_tree_address(&mut self, tree: u64) {
        // Upper 4 bytes zero (we only need ≤64 bits for our params).
        self.bytes[4..8].copy_from_slice(&[0u8; 4]);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Get the tree address as u64 (lower 64 bits).
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

    // ── Type (bytes 16..20) ──

    /// Set the address type, zeroing the type-specific fields.
    pub(crate) fn set_type(&mut self, t: AdrsType) {
        self.bytes[16..20].copy_from_slice(&(t as u32).to_be_bytes());
        // Zero the type-specific area (bytes 20..32).
        self.bytes[20..32].copy_from_slice(&[0u8; 12]);
    }

    // ── Type-specific fields (bytes 20..32) ──

    // --- Key-pair address (bytes 20..24) ---
    // Used by: WotsHash, WotsPk, WotsPrf, ForsTree, ForsRoots, ForsPrf

    /// Set the key-pair address (bytes 20..24).
    pub(crate) fn set_keypair_address(&mut self, kp: u32) {
        self.bytes[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    /// Get the key-pair address.
    pub(crate) fn keypair_address(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[20],
            self.bytes[21],
            self.bytes[22],
            self.bytes[23],
        ])
    }

    // --- Chain address (bytes 24..28) ---
    // Used by: WotsHash, WotsPrf

    /// Set the chain address (bytes 24..28).
    pub(crate) fn set_chain_address(&mut self, chain: u32) {
        self.bytes[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    // --- Hash address (bytes 28..32) ---
    // Used by: WotsHash

    /// Set the hash address (bytes 28..32).
    pub(crate) fn set_hash_address(&mut self, hash: u32) {
        self.bytes[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    // --- Tree height (bytes 24..28) ---
    // Used by: Tree, ForsTree

    /// Set the tree height (bytes 24..28).
    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.bytes[24..28].copy_from_slice(&height.to_be_bytes());
    }

    /// Get the tree height.
    pub(crate) fn tree_height(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[24],
            self.bytes[25],
            self.bytes[26],
            self.bytes[27],
        ])
    }

    // --- Tree index (bytes 28..32) ---
    // Used by: Tree, ForsTree, ForsRoots, WotsPk

    /// Set the tree index (bytes 28..32).
    pub(crate) fn set_tree_index(&mut self, idx: u32) {
        self.bytes[28..32].copy_from_slice(&idx.to_be_bytes());
    }

    /// Get the tree index.
    pub(crate) fn tree_index(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[28],
            self.bytes[29],
            self.bytes[30],
            self.bytes[31],
        ])
    }

    /// Borrow the raw 32-byte representation.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Compress to 22-byte `ADRSc` for the SHA-256 variant.
    ///
    /// Per FIPS 205 §10.1, the compressed address keeps only the
    /// significant bytes from each field:
    ///
    /// - layer (4 → 1 byte)
    /// - tree  (12 → 8 bytes, lower 64 bits)
    /// - type  (4 → 1 byte)
    /// - three type-specific words (4 bytes each, kept in full)
    pub(crate) fn compress(&self) -> [u8; ADRS_COMPRESSED_LEN] {
        let mut c = [0u8; ADRS_COMPRESSED_LEN];
        c[0] = self.bytes[3]; // layer low byte
        c[1..9].copy_from_slice(&self.bytes[8..16]); // tree low 64 bits
        c[9] = self.bytes[19]; // type low byte
        c[10..14].copy_from_slice(&self.bytes[20..24]); // word 1
        c[14..18].copy_from_slice(&self.bytes[24..28]); // word 2
        c[18..22].copy_from_slice(&self.bytes[28..32]); // word 3
        c
    }
}
