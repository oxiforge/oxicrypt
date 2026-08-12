//! Compile host for the quickstart examples carried in `lama.yaml`.
//!
//! The LAMA specification requires each quickstart to compile and run without
//! modification. A manifest can assert that and be wrong, because nothing in a
//! YAML file is compiled.
//!
//! So the examples live in `examples/` as real Rust, are built by the ordinary
//! `--all-targets` gate, and `tests/manifest_matches_examples.rs` asserts the
//! manifest's copy is byte-identical to the file. Neither can drift without
//! the other failing.
