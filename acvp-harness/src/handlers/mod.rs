//! Per-algorithm ACVP dispatch handlers.
//!
//! Each submodule implements [`crate::dispatch::AlgorithmHandler`] for
//! a single ACVP `(algorithm, revision)` pair. R10 ships two handlers;
//! later chunks extend the list without touching the dispatch or
//! envelope layers.

pub mod hmac_sha2_256;
pub mod sha3_256;
